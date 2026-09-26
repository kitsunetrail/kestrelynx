package sensor

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// cgroupHostRoot is where the host's own cgroup2 hierarchy is mounted inside
// the Sensor container (cgroup: host in the compose definition) — the root
// scanCgroupTree walks at startup and the base every cgroup_mkdir event's
// own path is relative to.
const cgroupHostRoot = "/sys/fs/cgroup"

// maxCgroupScanDirs bounds how many directories scanCgroupTree will visit
// under the host cgroup2 hierarchy at Sensor startup. The host's own
// /sys/fs/cgroup tree is not attacker-controlled the way a container's own
// rootfs is, but a container that has been delegated its own cgroup
// subtree (e.g. running its own systemd, or Docker-in-Docker) can still
// create an arbitrary number of nested cgroups, so this bound exists as a
// defensive cap rather than a trust decision either way. ASSUMED: no real
// deployment needs more than this many cgroup directories to fully cover
// every running container's own scope and its descendants; revisit once
// real-world dogfooding shows otherwise.
const maxCgroupScanDirs = 50_000

// maxCgroupRouteEntries bounds the total size of a cgroupRoute's two maps
// combined (they always grow together — see set). A long-running Sensor
// session sees a steady trickle of short-lived cgroups (docker exec
// sessions, a container's own nested cgroups) that are never explicitly
// removed from this table (nothing currently prunes an ended container's
// own entries — see cgroupRoute's own doc comment), so this cap, evicting
// the oldest-inserted entries once crossed, exists to keep that growth
// bounded over a session lasting weeks rather than hours. ASSUMED: a value
// this large is never reached by legitimate cgroup churn on a single host
// within one Sensor session; revisit once real-world dogfooding shows
// otherwise.
const maxCgroupRouteEntries = 65_536

// cgroupRoute maps eBPF's numeric cgroup IDs (kernfs directory inode
// numbers under /sys/fs/cgroup) to the Docker container ID that cgroup (or
// its nearest matched ancestor) belongs to — or, just as importantly,
// records that a cgroup ID is *not* part of any container at all. It exists
// because every eBPF event this Sensor receives carries a cgroup ID, never
// a container ID or a path: resolving one to the other, or determining that
// there is nothing to resolve it to, is this type's whole job.
//
// idToContainer and pathToContainer both use the empty string as a
// meaningful, deliberately recorded value distinct from the key being
// absent altogether: an absent key means "not yet classified at all" (still
// worth holding an event for, in case a later cgroup_mkdir or discovery
// pass classifies it); an empty-string value means "confirmed to be outside
// any container" (a host process's own cgroup, or descends from one) — an
// event naming it is discarded outright, never queued or counted as a loss.
// See lookup's own doc comment.
//
// Seeded once at Sensor startup by scanCgroupTree (covering every cgroup
// that already exists when eBPF attached, container or not) and grown
// afterward by applyCgroupMkdir, one new cgroup at a time, as
// tp_btf/cgroup_mkdir events arrive for cgroups created after that. Every
// field is read and written only by loop's own goroutine, exactly like
// generationState — nothing here needs its own synchronization.
//
// A container entry is never removed when the container is merely
// restarted: a restarted container (the common case a Docker "restart"
// produces) keeps the same underlying cgroup, so a mapping this table
// already holds stays correct across it. pruneContainer removes it once the
// container is confirmed gone entirely instead (see that method's own doc
// comment); a non-container entry is never pruned at all (nothing calls
// pruneContainer for a container ID that was never one), relying on
// maxCgroupRouteEntries as its own bound instead.
type cgroupRoute struct {
	idToContainer   map[uint64]string
	pathToContainer map[string]string
	// insertOrder is every (cgroup ID, path, container ID) ever inserted, in
	// insertion order, used only to decide which entries to evict from both
	// maps together once maxCgroupRouteEntries is crossed (a plain FIFO,
	// not a true LRU: an entry looked up often but inserted long ago is
	// evicted exactly the same as one never looked up again — acceptable
	// for a bound that only exists to cap unbounded growth, not to keep the
	// most useful entries specifically). The container ID recorded here is
	// what evictIfNeeded compares against pathToContainer's own *current*
	// value at eviction time, so that a path whose mapping was since
	// overwritten by a newer cgroup ID (a deleted-and-recreated cgroup
	// reusing the same path) is not deleted out from under that newer
	// entry.
	insertOrder []cgroupRouteEntry
}

// cgroupRouteEntry is one (cgroup ID, path, container ID) triple as recorded
// in insertOrder.
type cgroupRouteEntry struct {
	id          uint64
	path        string
	containerID string
}

// lookup returns what this table currently knows about cgroupID: known is
// false if cgroupID has never been classified at all (still a candidate for
// classification later); known is true with an empty containerID if it has
// been confirmed to belong to no container (a host process, or a
// descendant of one); known is true with a non-empty containerID if it
// belongs to that container.
func (r *cgroupRoute) lookup(cgroupID uint64) (containerID string, known bool) {
	containerID, known = r.idToContainer[cgroupID]
	return containerID, known
}

// set records that cgroupID (found at path) belongs to containerID —
// containerID may be "" to record a confirmed non-container classification
// — evicting the oldest-inserted entries first if this would cross
// maxCgroupRouteEntries. Re-setting an already-known cgroupID (set itself
// does not assume this never happens, though normal callers only ever set a
// given cgroup ID once) does not duplicate its insertOrder entry, but also
// does not update that entry's own recorded containerID — cgroup IDs are
// not reassigned to a different container in practice, so this is not a
// real-world concern.
func (r *cgroupRoute) set(cgroupID uint64, path, containerID string) {
	if r.idToContainer == nil {
		r.idToContainer = map[uint64]string{}
	}
	if r.pathToContainer == nil {
		r.pathToContainer = map[string]string{}
	}
	if _, exists := r.idToContainer[cgroupID]; !exists {
		r.insertOrder = append(r.insertOrder, cgroupRouteEntry{id: cgroupID, path: path, containerID: containerID})
	}
	r.idToContainer[cgroupID] = containerID
	r.pathToContainer[path] = containerID
	r.evictIfNeeded()
}

// evictIfNeeded removes the oldest-inserted entries until idToContainer (one
// entry per cgroup ID ever seen, the dimension that actually grows without
// bound — a path can be reused by many different cgroup IDs over time,
// while pathToContainer only ever holds one entry per distinct path) is at
// or under maxCgroupRouteEntries.
func (r *cgroupRoute) evictIfNeeded() {
	for len(r.idToContainer) > maxCgroupRouteEntries && len(r.insertOrder) > 0 {
		oldest := r.insertOrder[0]
		r.insertOrder = r.insertOrder[1:]
		delete(r.idToContainer, oldest.id)
		// Only remove the path->container entry if it still holds exactly
		// the mapping being evicted here — a later set() call for a
		// different cgroup ID reusing the same path (a deleted and
		// recreated cgroup) has already overwritten it, and that newer
		// mapping must survive this older id's own eviction.
		if r.pathToContainer[oldest.path] == oldest.containerID {
			delete(r.pathToContainer, oldest.path)
		}
	}
}

// scanCgroupTree walks the host cgroup2 hierarchy rooted at root (in
// production, /sys/fs/cgroup — host-visible because the Sensor container
// runs with cgroup: host), classifying every directory it visits: a
// container's own scope directory (matched the same way
// procfs.ContainerIDFromCgroup matches a /proc/<pid>/cgroup line) and every
// descendant of it are recorded as belonging to that container; every other
// directory is recorded as a confirmed non-container cgroup (see
// cgroupRoute's own doc comment on why "" is itself a meaningful, recorded
// value here, not merely skipped) — the whole point being that after a
// clean scan, no directory under root is left unclassified at all. It is
// the startup-time counterpart to applyCgroupMkdir, covering every cgroup
// that already exists before eBPF ever attached — one that came and went
// entirely before this scan runs is missed the same way a short-lived
// process is missed by procfs sampling, and is not this function's concern.
//
// truncated is true if maxCgroupScanDirs was reached before the whole tree
// was visited. failed is true if reading any directory's own contents
// failed for a reason other than it having simply vanished since being
// listed (os.IsNotExist — ordinary churn, not a scan defect): a permission
// error or an I/O error partway through leaves the classification this scan
// produces incomplete in a way this Sensor cannot itself tell apart from
// "there was nothing more to find" without this signal. Both are reported
// to the caller (session.go's own startup sequence), which must not report
// events.status as ok over a scan that could not fully classify the host's
// own cgroup tree: ok is only warranted once this table's own initial build
// has actually succeeded.
func scanCgroupTree(root string) (rt cgroupRoute, truncated, failed bool) {
	visited := 0
	var walk func(dir, relPath, inherited string)
	walk = func(dir, relPath, inherited string) {
		if visited >= maxCgroupScanDirs {
			truncated = true
			return
		}
		visited++

		containerID := inherited
		if containerID == "" {
			if id, ok := procfs.ContainerIDFromCgroup([]byte(relPath)); ok {
				containerID = id
			}
		}
		if ino, err := statDirInode(dir); err == nil {
			rt.set(ino, relPath, containerID)
		} else if !os.IsNotExist(err) {
			failed = true
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				failed = true
			}
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if visited >= maxCgroupScanDirs {
				truncated = true
				return
			}
			walk(filepath.Join(dir, e.Name()), relPath+"/"+e.Name(), containerID)
		}
	}
	walk(root, "", "")
	return rt, truncated, failed
}

// statDirInode returns dir's own inode number — the kernfs ID
// bpf_get_current_cgroup_id() would report for a process placed directly in
// it, the same quantity StatCgroupDirInode (startup.go) computes for the
// observer's own cgroup.
func statDirInode(dir string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// applyCgroupMkdir records a newly created cgroup (cgroupID, at path) in
// the route table: path itself may be a container's own scope (a brand-new
// container starting), or a descendant of one already known (a cgroup
// nested inside a container this table already knows about — the "子
// cgroup は祖先のコンテナへ対応付ける" rule) — either way containerID is
// non-empty. If neither, but some ancestor of path has already been
// classified as a confirmed non-container cgroup, path is recorded the same
// way (containerID "", known true): a host process's own cgroup nested
// under another host cgroup is exactly as classifiable as one nested under
// a container. Only when no ancestor at all has been classified yet — path
// is itself unclassifiable and nothing above it is either — does this
// return known=false, leaving path unrecorded until a later cgroup_mkdir or
// discovery pass can classify it (see events.go's pending-route-event queue
// for what happens to an event naming a cgroup ID this returns false for).
//
// An empty path is refused outright, returning known=false without ever
// calling ancestorLookup: ancestorLookup climbs an unrecognized path's own
// prefixes down to and including the cgroup root itself (path ""), which a
// clean scanCgroupTree always classifies as a confirmed non-container — an
// empty path (this cgroup's own real path could not be read at all; see
// applyCgroupMkdirEvent's own doc comment on why events.go already refuses
// to call this method for one, kept here too as this method's own defense
// regardless of caller) would otherwise ancestor-match that same root entry
// and wrongly confirm this cgroup non-container.
func (r *cgroupRoute) applyCgroupMkdir(cgroupID uint64, path string) (containerID string, known bool) {
	if path == "" {
		return "", false
	}
	if id, ok := procfs.ContainerIDFromCgroup([]byte(path)); ok {
		r.set(cgroupID, path, id)
		return id, true
	}
	if id, known := r.ancestorLookup(path); known {
		r.set(cgroupID, path, id)
		return id, true
	}
	return "", false
}

// pruneContainer removes every entry recorded for containerID from both
// maps together, along with their insertOrder bookkeeping. Called only once
// a container is confirmed gone entirely (reconcileGenerations' own "no
// longer present in groups at all" branch) — never for a same-ID restart,
// which keeps the same underlying cgroup and whose mapping must survive the
// old generation ending. This is this table's own routine cleanup, working
// alongside (not replacing) maxCgroupRouteEntries' own safety-net cap: a
// container whose cgroup mapping was never explicitly pruned for some
// reason (a bug, or a code path this method is not wired into) is still
// bounded by that cap.
func (r *cgroupRoute) pruneContainer(containerID string) {
	if len(r.idToContainer) == 0 {
		return
	}
	for id, cid := range r.idToContainer {
		if cid == containerID {
			delete(r.idToContainer, id)
		}
	}
	for path, cid := range r.pathToContainer {
		if cid == containerID {
			delete(r.pathToContainer, path)
		}
	}
	kept := r.insertOrder[:0]
	for _, e := range r.insertOrder {
		if _, ok := r.idToContainer[e.id]; ok {
			kept = append(kept, e)
		}
	}
	r.insertOrder = kept
}

// ancestorLookup looks up the nearest ancestor of path (path itself, then
// each successively shorter prefix, down to and including the cgroup root
// itself, recorded as path "" — see scanCgroupTree's own walk, which
// classifies the root the same way as any other directory) already
// recorded in pathToContainer.
func (r *cgroupRoute) ancestorLookup(path string) (containerID string, known bool) {
	for {
		if id, ok := r.pathToContainer[path]; ok {
			return id, true
		}
		if path == "" {
			return "", false
		}
		if idx := strings.LastIndexByte(path, '/'); idx > 0 {
			path = path[:idx]
		} else {
			path = ""
		}
	}
}
