package sensor

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// firstLiveMapEntry returns the first non-deleted, non-empty-path entry in
// this test process's own /proc/self/maps — used as a real, known-good
// (dev, inode, path) triple resolveMapsPath's own tests confirm against,
// without needing to fabricate a mapping of its own.
func firstLiveMapEntry(t *testing.T) procfs.MapEntry {
	t.Helper()
	h, err := procfs.Open(os.Getpid())
	if err != nil {
		t.Fatalf("procfs.Open(self): %v", err)
	}
	defer h.Close()
	maps, _, err := h.Maps()
	if err != nil {
		t.Fatalf("Maps: %v", err)
	}
	for _, m := range maps {
		if !m.Deleted && m.Path != "" {
			return m
		}
	}
	t.Fatal("this process's own maps have no usable (non-deleted, named) entry to test against")
	return procfs.MapEntry{}
}

// selfIdentityForPathResolveTest returns this test process's own
// start_boottime_ns (derived from its real starttime, in the same
// boot-relative ticks resolveMapsPath itself converts from) and mount
// namespace inode — the two facts resolveMapsPath requires to already
// match before it will even look at a process's maps.
func selfIdentityForPathResolveTest(t *testing.T) (startBoottimeNs uint64, mntNsID uint32) {
	t.Helper()
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)
	h, err := procfs.Open(pid)
	if err != nil {
		t.Fatalf("procfs.Open(self): %v", err)
	}
	defer h.Close()
	mnt, err := h.NSLink("mnt")
	if err != nil {
		t.Fatalf("NSLink(mnt): %v", err)
	}
	id, ok := parseMntNSInode(mnt)
	if !ok {
		t.Fatalf("parseMntNSInode(%q) failed", mnt)
	}
	return uint64(starttime) * nsPerClockTick, id
}

func TestResolveMapsPathFindsLiveMapping(t *testing.T) {
	want := firstLiveMapEntry(t)
	startBoottimeNs, mntNsID := selfIdentityForPathResolveTest(t)
	path, ok := resolveMapsPath(os.Getpid(), want.Dev, want.Inode, startBoottimeNs, mntNsID)
	if !ok || path != want.Path {
		t.Errorf("resolveMapsPath(self, %q, %d) = (%q, %v), want (%q, true)", want.Dev, want.Inode, path, ok, want.Path)
	}
}

func TestResolveMapsPathNotFoundForUnmatchedIdentity(t *testing.T) {
	startBoottimeNs, mntNsID := selfIdentityForPathResolveTest(t)
	if _, ok := resolveMapsPath(os.Getpid(), "ff:ff", 999_999_999, startBoottimeNs, mntNsID); ok {
		t.Error("resolveMapsPath matched a (dev, inode) pair that is not actually mapped, want false")
	}
}

func TestResolveMapsPathProcessGone(t *testing.T) {
	startBoottimeNs, mntNsID := selfIdentityForPathResolveTest(t)
	// A very large PID is virtually never a live process at all.
	if _, ok := resolveMapsPath(1<<30, "1:1", 1, startBoottimeNs, mntNsID); ok {
		t.Error("resolveMapsPath resolved a mapping for a PID that should not exist, want false")
	}
}

func TestResolveMapsPathRejectsNonPositivePID(t *testing.T) {
	startBoottimeNs, mntNsID := selfIdentityForPathResolveTest(t)
	if _, ok := resolveMapsPath(0, "1:1", 1, startBoottimeNs, mntNsID); ok {
		t.Error("resolveMapsPath(0, ...) = ok, want false")
	}
	if _, ok := resolveMapsPath(-1, "1:1", 1, startBoottimeNs, mntNsID); ok {
		t.Error("resolveMapsPath(-1, ...) = ok, want false")
	}
}

// TestResolveMapsPathRejectsWrongStarttime confirms that even though pid
// is this test's own, very real process, a starttime that does not match
// its actual one (simulating a PID reused by an unrelated process between
// the event firing and this lookup running) must refuse the whole lookup,
// never search that process's maps under the wrong identity.
func TestResolveMapsPathRejectsWrongStarttime(t *testing.T) {
	want := firstLiveMapEntry(t)
	_, mntNsID := selfIdentityForPathResolveTest(t)
	wrongStartBoottimeNs := uint64(1) // certainly not this process's real starttime
	if _, ok := resolveMapsPath(os.Getpid(), want.Dev, want.Inode, wrongStartBoottimeNs, mntNsID); ok {
		t.Error("resolveMapsPath matched despite a starttime that does not belong to this process, want false")
	}
}

// TestResolveMapsPathRejectsWrongMountNamespace confirms the other half of
// the same check: a mismatched (or zero/unconfirmed) mount namespace must also refuse the
// lookup outright.
func TestResolveMapsPathRejectsWrongMountNamespace(t *testing.T) {
	want := firstLiveMapEntry(t)
	startBoottimeNs, mntNsID := selfIdentityForPathResolveTest(t)
	if _, ok := resolveMapsPath(os.Getpid(), want.Dev, want.Inode, startBoottimeNs, mntNsID+1); ok {
		t.Error("resolveMapsPath matched despite a mismatched mount namespace, want false")
	}
	if _, ok := resolveMapsPath(os.Getpid(), want.Dev, want.Inode, startBoottimeNs, 0); ok {
		t.Error("resolveMapsPath matched with mntNsID=0 (unconfirmed), want false")
	}
}

// rawKernelDevFor converts a "MM:mm" formatted device string (as
// MapEntry.Dev and formatKernelDev both use) back into the raw
// kernel-internal dev_t (major<<20|minor) an ebpf.Event.Dev field carries,
// so a test can construct an Event that formatKernelDev will format right
// back to the same string — never unix.Mkdev, which builds the unrelated
// userspace/glibc encoding (see kerneldev.go's own doc comment).
func rawKernelDevFor(t *testing.T, formatted string) uint64 {
	t.Helper()
	var maj, min uint32
	if _, err := fmt.Sscanf(formatted, "%x:%x", &maj, &min); err != nil {
		t.Fatalf("parsing device string %q: %v", formatted, err)
	}
	return (uint64(maj) << kernelDevMinorBits) | uint64(min)
}

// TestApplyUsageEvent_FallsBackToLiveMapsWhenPathUnknown exercises the whole
// async wiring end to end: applyUsageEvent (via applyEvent) dispatches a
// maps-fallback lookup when s.pathIdx has no entry for the event's own
// (mount namespace, dev, inode) and the event carries a live TGID; the test
// reads the goroutine's own answer off s.pathResolveCh and applies it, then
// confirms the resolved path was attributed exactly the way an ordinarily-
// resolved path would be.
func TestApplyUsageEvent_FallsBackToLiveMapsWhenPathUnknown(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('u')
	g := newReadyGeneration(s, 70, cid)

	want := firstLiveMapEntry(t)
	startBoottimeNs, mntNsID := selfIdentityForPathResolveTest(t)
	g.mntNsID = mntNsID // matchesMountView must agree with this real process's own namespace
	// g.init is set to this test process's own real PID/starttime, and the
	// event's own TGID/StartBoottimeNs name that exact same process at that
	// exact same starttime tick — this event's process *is* g's own init
	// itself, provably so (resolveEventGeneration's own doc comment), so it
	// resolves outright with no genconfirm.go liveness check needed at all.
	g.init = InitProcess{PID: os.Getpid(), Starttime: mustStarttime(t, os.Getpid())}
	ev := ebpf.Event{
		Kind: ebpf.EventExecSuccess, CgroupID: 70,
		TGID: uint64(os.Getpid()), Dev: rawKernelDevFor(t, want.Dev), Ino: want.Inode,
		StartBoottimeNs: startBoottimeNs, MountNamespaceID: uint64(mntNsID),
		RootDev: testRootDevRaw, RootIno: testRootIno,
	}
	s.applyEvent(ev)

	select {
	case res := <-s.pathResolveCh:
		if !res.resolved || res.path != want.Path {
			t.Fatalf("pathResolveResult = %+v, want resolved=true path=%q", res, want.Path)
		}
		s.applyPathResolveResult(res)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for resolvePathAsync's own answer")
	}

	// applyPathResolveResult re-resolves the generation fresh (a restart
	// could have happened while the maps lookup was in flight — see that
	// function's own doc comment); the event's own TGID/start tick still
	// prove it is g's own init itself, so this re-resolution is proven
	// directly again with no liveness confirmation needed.
	exe, ok := g.executables[want.Path]
	if !ok {
		t.Fatalf("executables[%q] not recorded after the maps-fallback resolution", want.Path)
	}
	if _, ok := exe.Kinds[evidence.KindExecEvent]; !ok {
		t.Error("executable's Kinds missing KindExecEvent")
	}
	select {
	case job := <-s.dbJobCh:
		if len(job.paths) != 1 || job.paths[0] != want.Path {
			t.Errorf("submitted dbJob.paths = %v, want [%q]", job.paths, want.Path)
		}
	default:
		t.Fatal("no dbJob submitted for the maps-fallback-resolved path")
	}
	if g.pendingMapsLookups != 0 {
		t.Errorf("pendingMapsLookups = %d, want 0 after the result was applied", g.pendingMapsLookups)
	}
}

// TestApplyUsageEvent_MapsFallbackUnresolvedRecordsLoss confirms a process
// whose maps genuinely have no matching (dev, inode) at all (it is alive,
// just never had this particular file mapped) still ends up counted as a
// loss, not silently ignored.
func TestApplyUsageEvent_MapsFallbackUnresolvedRecordsLoss(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('v')
	g := newReadyGeneration(s, 71, cid)

	startBoottimeNs, mntNsID := selfIdentityForPathResolveTest(t)
	g.mntNsID = mntNsID
	// g.init is set to this test process's own real PID/starttime, and the
	// event's own TGID/StartBoottimeNs name that exact same process at that
	// exact same starttime tick — this event's process *is* g's own init
	// itself, provably so, so it resolves outright with no genconfirm.go
	// liveness check needed at all (see the sibling test's own comment).
	g.init = InitProcess{PID: os.Getpid(), Starttime: mustStarttime(t, os.Getpid())}
	ev := ebpf.Event{
		Kind: ebpf.EventExecSuccess, CgroupID: 71,
		TGID: uint64(os.Getpid()), Dev: rawKernelDevFor(t, "ff:ff"), Ino: 999_999_999,
		StartBoottimeNs: startBoottimeNs, MountNamespaceID: uint64(mntNsID),
		RootDev: testRootDevRaw, RootIno: testRootIno,
	}
	s.applyEvent(ev)

	select {
	case res := <-s.pathResolveCh:
		if res.resolved {
			t.Fatalf("pathResolveResult = %+v, want resolved=false", res)
		}
		s.applyPathResolveResult(res)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for resolvePathAsync's own answer")
	}

	// applyPathResolveResult re-resolves fresh, but the event's own TGID/
	// start tick still prove it is g's own init itself, so the now-lossOnly
	// item is proven directly and the loss is charged immediately.
	if g.eventsLost != 1 || !g.incomplete {
		t.Errorf("eventsLost=%d incomplete=%v, want 1/true", g.eventsLost, g.incomplete)
	}
	if g.pendingMapsLookups != 0 {
		t.Errorf("pendingMapsLookups = %d, want 0 after the result was applied", g.pendingMapsLookups)
	}
}

// TestApplyPathResolveResult_GenerationGoneRequeuesRatherThanDrops confirms
// that a resolved path whose own generation cannot yet be resolved at
// all (its cgroup mapping was itself evicted, or it never resolves to
// anything live) must never be dropped silently — it is queued back through
// the ordinary pendingRouteEvent path instead, with its own resolved path
// carried along (pendingRouteEvent.path), so a later retry can still dispatch
// it without repeating the maps-fallback lookup this result already paid
// for. Regardless of whether the generation could be resolved,
// res.originGen's own pendingMapsLookups (the generation the request was
// actually dispatched against, which can legitimately differ once a restart
// has happened) is always decremented.
func TestApplyPathResolveResult_GenerationGoneRequeuesRatherThanDrops(t *testing.T) {
	s := newTestSessionForEvents()
	origin := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('q')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	origin.pendingMapsLookups = 1
	// Deliberately not registered on s.generations and no cgroup route
	// entry for CgroupID 999 either: this generation is not resolvable via
	// resolveEventGeneration at all by the time the result is applied.
	res := pathResolveResult{
		originGen:  origin,
		ev:         ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 999},
		kind:       evidence.KindExecEvent,
		isExec:     true,
		path:       "/usr/bin/whatever",
		resolved:   true,
		receivedAt: s.now(),
	}
	s.applyPathResolveResult(res) // must not panic
	if len(s.generations) != 0 {
		t.Errorf("generations = %v, want none created as a side effect", s.generations)
	}
	if origin.pendingMapsLookups != 0 {
		t.Errorf("origin.pendingMapsLookups = %d, want 0 (decremented regardless of whether the generation could still be resolved)", origin.pendingMapsLookups)
	}
	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1 -- an unresolvable generation must requeue the event, never drop it", len(s.pendingRouteEvents))
	}
	if got := s.pendingRouteEvents[0]; got.path != "/usr/bin/whatever" || got.lossOnly {
		t.Errorf("requeued item = %+v, want path=%q lossOnly=false (the maps lookup already found this path)", got, "/usr/bin/whatever")
	}
}

// TestSubmitPathResolveRequest_ConcurrencyAndQueueBounded confirms this
// pool's own resource bound: at most maxConcurrentPathResolves requests run at once, up to
// maxQueuedPathResolves more wait, and anything beyond that is dropped and
// counted as an immediate, generation-attributed loss rather than left to
// grow the goroutine count or the queue without bound.
func TestSubmitPathResolveRequest_ConcurrencyAndQueueBounded(t *testing.T) {
	s := newTestSessionForEvents()
	// Large enough that the maxConcurrentPathResolves real goroutines this
	// test's own accepted requests dispatch (each a quick, doomed
	// resolveMapsPath(1, …) call against PID 1 with a starttime that will
	// never match) can all send their answer without blocking, so none of
	// them are left running past this test's own return.
	s.pathResolveCh = make(chan pathResolveResult, maxConcurrentPathResolves)
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('r')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)

	total := maxConcurrentPathResolves + maxQueuedPathResolves
	for i := 0; i < total; i++ {
		s.submitPathResolveRequest(pathResolveRequest{g: g, ev: ebpf.Event{TGID: 1, StartBoottimeNs: 1}, kind: evidence.KindExecEvent, isExec: true})
	}
	if s.pathResolveInFlight != maxConcurrentPathResolves {
		t.Errorf("pathResolveInFlight = %d, want %d", s.pathResolveInFlight, maxConcurrentPathResolves)
	}
	if len(s.pathResolveQueue) != maxQueuedPathResolves {
		t.Errorf("len(pathResolveQueue) = %d, want %d", len(s.pathResolveQueue), maxQueuedPathResolves)
	}
	if g.pendingMapsLookups != total {
		t.Errorf("pendingMapsLookups = %d, want %d (every accepted request counted)", g.pendingMapsLookups, total)
	}
	if g.eventsLost != 0 {
		t.Errorf("eventsLost = %d, want 0 so far (nothing has overflowed the queue yet)", g.eventsLost)
	}

	// One more request, past both bounds, must be dropped and counted as an
	// immediate loss rather than accepted.
	s.submitPathResolveRequest(pathResolveRequest{g: g, ev: ebpf.Event{TGID: 1, StartBoottimeNs: 1}, kind: evidence.KindExecEvent, isExec: true})
	if s.pathResolveInFlight != maxConcurrentPathResolves {
		t.Errorf("pathResolveInFlight = %d, want unchanged at %d", s.pathResolveInFlight, maxConcurrentPathResolves)
	}
	if len(s.pathResolveQueue) != maxQueuedPathResolves {
		t.Errorf("len(pathResolveQueue) = %d, want unchanged at %d", len(s.pathResolveQueue), maxQueuedPathResolves)
	}
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (the request that overflowed both bounds)", g.eventsLost)
	}
}
