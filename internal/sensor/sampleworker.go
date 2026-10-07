package sensor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/rootfs"
)

// mountBasis is init's own mount-namespace identity and root filesystem
// identity, resolved once per sample by the sample worker itself (never by
// loop, which must never read procfs/rootfs directly — see runSampleWorker's
// own doc comment) and reported back in sampleResult so loop can compare it
// against the identity the generation's currently-built index actually
// came from (generationState.idxBasis). A process is only ever attributed
// to this generation at all when both its own ns/mnt link and its own
// root's (dev, inode) match this basis exactly — matching mount namespace
// alone is not enough, since a process can chroot within the same mount
// namespace and see a different root than init's.
type mountBasis struct {
	mntNS   string
	rootDev string
	rootIno uint64
	// ok is false when init's own basis could not be resolved this round at
	// all (init unreadable, its starttime no longer matches, or its own
	// root could not be opened/stat'd) — every process in the job,
	// including init itself, is then unattributable, and the generation
	// becomes incomplete rather than guessing.
	ok bool
}

// sameMountBasis reports whether a and b name the exact same mount
// namespace and root object — used to tell whether the package-database
// index currently built for a generation still describes the same root its
// own init process actually has right now (see generationState.idxBasis's
// own doc comment). Both must be ok; an unresolved basis is never treated
// as matching or mismatching anything.
func sameMountBasis(a, b mountBasis) bool {
	return a.ok && b.ok && a.mntNS == b.mntNS && a.rootDev == b.rootDev && a.rootIno == b.rootIno
}

// openRootWithBasis opens init's own root exactly once, deriving basis (its
// mount-namespace link and its root's own (dev, inode)) from that same fd —
// never a separate, later reopen. An earlier version of this Sensor
// resolved basis through its own independent open/fstat/close and then
// reopened root separately for whatever real read followed: between those
// two opens, init could chroot or unshare(CLONE_NEWNS), leaving the basis
// describing one root while the actual read silently went through a
// different one, with nothing left to notice the mismatch (see
// generationState.idxBasis's own doc comment on why that comparison exists
// at all). Binding both to one open closes that window. The returned
// *rootfs.Reader is non-nil, and must be Closed by the caller, only when
// basis.ok is true; on any failure (init unreadable, its starttime no
// longer matches, its mnt namespace link or root could not be read) it is
// nil and basis is the zero value.
//
// Called both from a sample worker's own goroutine (runSampleWorker, once
// per sample) and from the dbworker goroutine (handleBuildJob, once per
// build) — never from loop, which must never read procfs/rootfs directly.
func openRootWithBasis(init InitProcess) (r *rootfs.Reader, basis mountBasis) {
	h, err := procfs.Open(init.PID)
	if err != nil {
		return nil, mountBasis{}
	}
	defer h.Close()
	if h.Starttime() != init.Starttime {
		return nil, mountBasis{}
	}
	// A zombie or already-dead task still reports its own original,
	// unchanged starttime (proc_pid_stat(5)) right up until its parent
	// actually reaps it — the Starttime match above is not by itself proof
	// init is still genuinely running. See confirmGenerationAlive's own doc
	// comment for the identical concern on genconfirm.go's own side of this
	// same check.
	if state, err := h.State(); err != nil || isDeadOrZombieState(state) {
		return nil, mountBasis{}
	}
	mnt, err := h.NSLink("mnt")
	if err != nil {
		return nil, mountBasis{}
	}
	rootFD, err := h.OpenRoot()
	if err != nil {
		return nil, mountBasis{}
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(rootFD.Fd()), &st); err != nil {
		rootFD.Close()
		return nil, mountBasis{}
	}
	return rootfs.Open(rootFD), mountBasis{mntNS: mnt, rootDev: formatDevForCompare(st.Dev), rootIno: st.Ino, ok: true}
}

// sampleJob is the sole, immutable input a sample worker goroutine receives.
// It carries every fact the worker needs (the process list already carries
// each entry's own starttime, guarding against a PID discovery reported
// having since been reused by an unrelated process) and nothing it could
// use to reach back into shared state: a sample worker never sends an IPC
// request and never holds a pointer any other goroutine also holds.
type sampleJob struct {
	genKey     string
	init       InitProcess
	processes  []InitProcess
	indexReady bool
	ownUserNS  string
	now        time.Time
	// pendingEvents is this generation's own generationState.pendingEvents
	// snapshot at dispatch time — only ever non-empty when indexReady is
	// also true (loop only ever hands these to a worker once there is an
	// index to re-verify them against; see startSampleWorker). Each one
	// already carries a resolved path and the (dev, inode) the kernel
	// reported for it at the moment the eBPF event fired; this worker's own
	// job is only to confirm that path still resolves to the same file
	// right now, using the same root it already opened for this sample's
	// ordinary candidate resolution (see runSampleWorker's own doc comment
	// on why events.go's applyUsageEvent never does this re-verification
	// itself).
	pendingEvents []pendingEventItem
}

// executableObs is one executable path observed for a process whose own
// root matched the job's mountBasis, carried in sampleResult for loop to
// fold into that generation's recordExecutable bookkeeping.
type executableObs struct {
	path  string
	dev   string
	inode uint64
	kind  evidence.EvidenceKind
	obs   evidence.ProcessObservation
}

// sampleResult is a sample worker's entire output: never a package
// attribution verdict (an OS package name/version), only the raw material
// loop needs to produce one — verified/replaced candidate paths, plus their
// contributing sampleCandidate entries — because attribution requires a
// parser lookup, and a sample worker never performs IPC at all. loop
// forwards candidates/verified/replaced to the dbworker as a "lookup" job
// and applies the eventual owner answer itself (see pendingLookup).
type sampleResult struct {
	genKey    string
	attempted int
	denied    int
	succeeded int
	// incomplete is set whenever some process's contribution had to be
	// withdrawn entirely rather than trusted: a denied read, a mount-basis
	// mismatch or unreadable identity, or resolveCandidatesWithRoot's own
	// "candidate unknown" cases.
	incomplete bool
	// reasons records, bounded, why incomplete was set — diagnostic only,
	// reported by loop (applySampleResult) and never consulted for any
	// decision.
	reasons   incompleteReasons
	truncated bool

	executables []executableObs

	candidates    map[string][]sampleCandidate
	verified      []string
	replaced      []string
	mergedUsrDirs map[string]bool

	// basis is init's own mount-namespace/root identity as this worker
	// itself resolved it (see resolveMountBasis) — reported back so loop
	// can compare it against generationState.idxBasis (the identity the
	// currently-ready index was actually built from) without loop ever
	// having to read procfs/rootfs itself.
	basis mountBasis

	// initAliveNs is the boot-relative CLOCK_BOOTTIME *nanosecond* (never
	// rounded to a clock tick), captured by this worker itself immediately
	// before it confirmed job.init was still alive — with its own recorded
	// Starttime, and not a zombie/dead task merely awaiting reaping —
	// (openRootWithBasis, whose own success is exactly basis.ok) —
	// meaningful only when initAliveNsOK is true (basis.ok, and this
	// worker's own bootNsNow call itself did not fail). loop folds this into
	// generationState.lastAliveNs (applySampleResult) — see that field's own
	// doc comment for what it proves and why an ordinary sample is already
	// exactly the check this needs, at no extra cost.
	initAliveNs   uint64
	initAliveNsOK bool

	// indexReadyAtStart carries job.indexReady through unchanged — whether
	// the package-database index this generation reports was already ready
	// at the moment loop dispatched this very sample, not whatever idxState
	// happens to read by the time this result is applied. loop uses this to
	// refuse ever attributing OS candidates from, or letting
	// postIndexConfirmed be set by, a sample that started before the index
	// was ready: a build completing in between must not retroactively make
	// an already-in-flight sample's own candidates count as having
	// confirmed the freshly-built index (see postIndexConfirmed's own doc
	// comment).
	indexReadyAtStart bool

	// verifiedEvents is every job.pendingEvents entry whose recorded path
	// still resolves, right now, to the same (dev, inode) the eBPF event
	// itself reported — eligible to be attributed the same way a fresh
	// event is (see events.go's applyUsageEvent). lostEventItems is every
	// entry that did not (the file was replaced, deleted, or could not be
	// resolved at all) — accepted as a known limit of this re-verification: a
	// mismatch here is simply counted as lost, never reported as a
	// file_replaced verdict the way a sampling candidate's own replacement
	// is. Both are reported as the
	// actual items (not just counts) so loop can remove exactly these from
	// generationState.pendingEvents — never a wholesale replacement, since
	// a new event can arrive and be queued while this very sample worker is
	// in flight (see loop's own doc comment on applySampleResult).
	// stillPendingEvents carries job.pendingEvents through unchanged, for
	// tests to confirm nothing here is dropped, when this sample could not
	// open a root to check them against at all (basis.ok false) — those
	// items are never actually removed from generationState.pendingEvents
	// in the first place (dispatch only ever copies it), so loop itself has
	// nothing to do with this field beyond what verifiedEvents/
	// lostEventItems already account for.
	verifiedEvents     []pendingEventItem
	lostEventItems     []pendingEventItem
	stillPendingEvents []pendingEventItem
}

// runSampleWorker is the whole body of one sample worker goroutine: read
// every process in job.processes, decide which of them share init's own
// root (see mountBasis's own doc comment — same mount namespace is checked
// first, but is not by itself sufficient: a chroot within that namespace
// still gives a process a different root, so this function also compares
// each process's own root (dev, inode) fstat against the basis), and
// resolve every candidate path (exe, mapped libraries) those processes
// contributed against the container's own root — but never against the
// package database itself, which requires a parser round trip this
// function never performs.
//
// A process whose own root does not match the basis exactly, or whose own
// identity could not be read at all (a denied read, a changed starttime),
// contributes nothing: not even its own exe path is recorded — see
// sampleResult's own Incomplete field, which is set instead, so the
// generation's not-observed verdicts stay withdrawn rather than risk
// crediting an executable to the wrong filesystem view.
func runSampleWorker(job sampleJob) sampleResult {
	res := sampleResult{genKey: job.genKey, candidates: map[string][]sampleCandidate{}, indexReadyAtStart: job.indexReady}

	// Resolved here, by the worker itself, rather than by loop before
	// dispatching this job: loop's own goroutine must never read
	// procfs/rootfs directly (see loop's own doc comment on why every
	// other goroutine exchanges only immutable values with it), and this
	// is exactly such a read. root, once opened, is held for this whole
	// function (closed only on return) and reused unchanged for
	// resolveCandidatesWithRoot below — never reopened — so the identity
	// basis reports and the root every candidate is actually resolved
	// against can never drift apart (see openRootWithBasis's own doc
	// comment).
	// Captured immediately before openRootWithBasis's own init-alive check
	// (procfs.Open(job.init.PID), a Starttime comparison, and a zombie/dead
	// state check) — if that check succeeds (basis.ok), this nanosecond is
	// proof g.init was still alive at least this recently; see
	// sampleResult.initAliveNs' own doc comment. Captured at full nanosecond
	// precision, not rounded to a clock tick, since resolveEventGeneration's
	// own proof compares it directly against an eBPF event's own
	// start_boottime_ns. A bootNsNow failure (never expected on a running
	// kernel, but not assumed) simply leaves initAliveNs unset — this sample
	// then contributes nothing to lastAliveNs, exactly as if basis.ok were
	// false, rather than reporting a wrong instant.
	preBasisNs, nsErr := bootNsNow()
	root, basis := openRootWithBasis(job.init)
	if root != nil {
		defer root.Close()
	}
	res.basis = basis
	if basis.ok && nsErr == nil {
		res.initAliveNs = preBasisNs
		res.initAliveNsOK = true
	}

	for _, proc := range job.processes {
		res.attempted++
		h, err := procfs.Open(proc.PID)
		if err != nil {
			if procfs.Classify(err) == procfs.OutcomeDenied {
				res.denied++
				res.incomplete = true
				res.reasons.add("sample_procfs_denied", fmt.Sprintf("pid=%d open %s", proc.PID, errDiag(err)))
			}
			continue
		}
		if h.Starttime() != proc.Starttime {
			// The PID discovery reported has since been reused by an
			// unrelated process; this is not the process this sample meant
			// to read at all.
			h.Close()
			continue
		}

		exePath, exeDeleted, exeErr := h.Exe()
		maps, mapsTruncated, mapsErr := h.Maps()
		effUID, capEff, statusErr := h.Status()
		if exeErr != nil || mapsErr != nil || statusErr != nil {
			if isDeniedAny(exeErr, mapsErr, statusErr) {
				res.denied++
				res.incomplete = true
				res.reasons.add("sample_procfs_denied", fmt.Sprintf("pid=%d exe: %s maps: %s status: %s", proc.PID, errDiag(exeErr), errDiag(mapsErr), errDiag(statusErr)))
			}
			h.Close()
			continue
		}
		if mapsTruncated {
			res.truncated = true
		}

		listeners := ownedListeners(h)
		userns := h.PID() != 0 && ownsDistinctUserNS(h, job.ownUserNS)
		mnt, mntErr := h.NSLink("mnt")

		sameRoot := false
		// notSameRoot is the diagnostic-only counterpart of sameRoot: why
		// this process's root could not be confirmed identical to init's.
		notSameRoot := incompleteReason{code: "sample_basis_unknown"}
		switch {
		case !basis.ok:
		case mntErr != nil:
			notSameRoot = incompleteReason{code: "sample_mnt_ns_unreadable", detail: fmt.Sprintf("pid=%d %s", proc.PID, errDiag(mntErr))}
		case mnt != basis.mntNS:
			notSameRoot = incompleteReason{code: "sample_not_same_root", detail: fmt.Sprintf("pid=%d mntns=%s init_mntns=%s", proc.PID, quoteDiag(mnt), quoteDiag(basis.mntNS))}
		default:
			notSameRoot = incompleteReason{code: "sample_root_unreadable", detail: fmt.Sprintf("pid=%d", proc.PID)}
			rootFD, rerr := h.OpenRoot()
			if rerr != nil {
				notSameRoot.detail += " open root: " + errDiag(rerr)
			} else {
				var st unix.Stat_t
				if ferr := unix.Fstat(int(rootFD.Fd()), &st); ferr != nil {
					notSameRoot.detail += " fstat root: " + errDiag(ferr)
				} else if formatDevForCompare(st.Dev) == basis.rootDev && st.Ino == basis.rootIno {
					sameRoot = true
				} else {
					notSameRoot = incompleteReason{code: "sample_not_same_root", detail: fmt.Sprintf("pid=%d root=%s:%d init_root=%s:%d", proc.PID, formatDevForCompare(st.Dev), st.Ino, basis.rootDev, basis.rootIno)}
				}
				rootFD.Close()
			}
		}

		if err := h.Recheck(); err != nil {
			// The process behind this pid changed identity mid-read:
			// discard everything just read for it.
			h.Close()
			continue
		}
		h.Close()
		res.succeeded++

		if !sameRoot {
			// Either the basis itself was unknown, this process's own
			// mount namespace or root could not be confirmed identical to
			// init's, or reading either failed outright: nothing about
			// this process is trustworthy to attribute to this
			// generation's own filesystem view, so nothing is recorded for
			// it at all, not even its exe path.
			res.incomplete = true
			res.reasons.add(notSameRoot.code, notSameRoot.detail)
			continue
		}

		obs := evidence.ProcessObservation{
			EffectiveUID: effUID, Userns: userns, CapEff: capEff,
			Listeners: listeners, LastSeen: job.now,
		}

		var exeDev string
		var exeInode uint64
		if exePath != "" {
			obs.Exe = exePath
			exeDev, exeInode = findMapEntry(maps, exePath)
			if !exeDeleted {
				res.executables = append(res.executables, executableObs{
					path: exePath, dev: exeDev, inode: exeInode, kind: evidence.KindExe, obs: obs,
				})
			}
			res.candidates[exePath] = append(res.candidates[exePath], sampleCandidate{
				kind: evidence.KindExe, dev: exeDev, inode: exeInode, deleted: exeDeleted, obs: obs,
			})
		}
		for _, m := range maps {
			if m.Path == exePath {
				continue
			}
			res.candidates[m.Path] = append(res.candidates[m.Path], sampleCandidate{
				kind: evidence.KindMappedLibrary, dev: m.Dev, inode: m.Inode, deleted: m.Deleted, obs: obs,
			})
		}
	}

	switch {
	case len(res.candidates) == 0:
		// Nothing sampled this round contributed a candidate — normal for a
		// container with no live processes matching init's own root this
		// sample — but pendingEvents (below) still needs its own chance to
		// verify against root/basis regardless.
	case !basis.ok:
		res.incomplete = true
		res.reasons.add("sample_basis_unknown", fmt.Sprintf("candidates=%d", len(res.candidates)))
	default:
		// root was already opened above, together with basis, from the same
		// fd basis itself was derived from — reused here unchanged, never
		// reopened (see openRootWithBasis's own doc comment).
		resolution := resolveCandidatesWithRoot(root, res.candidates)
		if resolution.incomplete {
			res.incomplete = true
			res.reasons.merge(resolution.reasons)
		}
		res.verified = resolution.verified
		res.replaced = resolution.replaced
		res.mergedUsrDirs = resolution.mergedUsrDirs
	}

	if len(job.pendingEvents) > 0 {
		if !basis.ok {
			// Nothing could be checked against a root this round; loop keeps
			// waiting on the same items next round (see
			// pendingEventTTL for how long).
			res.stillPendingEvents = job.pendingEvents
		} else {
			for _, item := range job.pendingEvents {
				statDev, statIno, err := root.Stat(item.path)
				if err == nil && statDev == item.dev && statIno == item.inode {
					res.verifiedEvents = append(res.verifiedEvents, item)
				} else {
					res.lostEventItems = append(res.lostEventItems, item)
				}
			}
		}
	}

	return res
}

// sampleCandidate is one process's contribution toward one observed path
// (its own exe, or one executable mapping) within a single sample: which
// evidence kind it represents, the dev/inode the kernel reported for it at
// that moment (empty/zero when none was available, e.g. an exe path that
// never showed up among that process's own maps entries), whether the
// kernel already told us this mapping's underlying file was deleted, and
// the same-sample/same-process facts to attach if the path turns out to
// belong to an OS package.
type sampleCandidate struct {
	kind    evidence.EvidenceKind
	dev     string
	inode   uint64
	deleted bool
	obs     evidence.ProcessObservation
}

// candidateResolution is resolveCandidatesWithRoot's result: every unique
// candidate path sorted into exactly one of two buckets, plus whether any
// candidate could not be resolved at all. verified paths are confirmed,
// right now, to still be the same file the kernel reported (present, on an
// allowed filesystem, and — when a recorded dev/inode was available to
// compare against — still matching it): these are eligible to become "in
// use". replaced paths are ones this generation positively knows are gone
// or swapped for a different file (the kernel's own "(deleted)" marker, or
// a dev/inode mismatch against a fresh stat): these are only ever eligible
// to become an unavailable(file_replaced) verdict, never "in use". A path
// that is neither — its state could not be determined at all (the read
// contract itself refused it, a symlink cycle, a disallowed filesystem, a
// reopen mismatch) — appears in neither bucket, and sets incomplete
// instead: see this function's own doc comment on why that has to withdraw
// not-observed from the whole generation rather than just that one path.
type candidateResolution struct {
	verified      []string
	replaced      []string
	incomplete    bool
	mergedUsrDirs map[string]bool
	// reasons records, bounded, why incomplete was set (diagnostic only).
	reasons incompleteReasons
}

// resolveCandidatesWithRoot classifies every unique path in candidates
// against r, an already-open Reader for the generation's own container
// root.
//
// The failure-propagation rule this function implements: a candidate whose
// identity is known — deleted, or confirmed replaced by calibration — only
// withdraws that one path's own verdict, becoming
// "unavailable(file_replaced)" for whichever package a lookup still
// resolves it to; a candidate whose identity cannot be determined at all
// withdraws not-observed from every package in the whole generation, via
// Incomplete. A failure this function itself cannot classify confidently is
// always resolved to the safe side: not verified, and incomplete.
func resolveCandidatesWithRoot(r *rootfs.Reader, candidates map[string][]sampleCandidate) candidateResolution {
	var res candidateResolution
	res.mergedUsrDirs = detectMergedUsrDirs(r)

	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		entries := candidates[path]

		// A path this sample knows is deleted for any contributing process
		// is treated as deleted for all of them: crediting "in use" from a
		// possibly-stale non-deleted observation of the very same
		// underlying file, alongside another that says it is gone, is not
		// the safe reading — see this function's doc comment.
		anyDeleted := false
		for _, c := range entries {
			if c.deleted {
				anyDeleted = true
				break
			}
		}
		if anyDeleted {
			res.replaced = append(res.replaced, path)
			continue
		}

		f, err := r.OpenFile(path)
		if err != nil {
			// The candidate's own identity could not be determined at all
			// (gone by the time this ran without ever being marked
			// deleted, a symlink cycle, a disallowed filesystem, a reopen
			// mismatch, ...): this is a "candidate unknown" failure, which
			// withdraws not-observed from the whole generation rather than
			// only this path.
			res.incomplete = true
			res.reasons.add("sample_open_failed", "path="+quoteDiag(path)+" "+errDiag(err))
			continue
		}
		var st unix.Stat_t
		ferr := unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if ferr != nil {
			res.incomplete = true
			res.reasons.add("sample_fstat_failed", "path="+quoteDiag(path)+" "+errDiag(ferr))
			continue
		}

		recordedDev, recordedInode := firstRecordedIdentity(entries)
		if recordedDev == "" {
			// No maps-recorded dev/inode was ever available for this path
			// (an exe path absent from its own process's maps entries) —
			// there is nothing to compare a fresh stat against, so presence
			// alone is treated as confirmation, not a replacement.
			res.verified = append(res.verified, path)
			continue
		}
		statDev := formatDevForCompare(st.Dev)
		if rootfs.ClassifyCalibration(recordedDev, recordedInode, statDev, st.Ino) == rootfs.CalibrationUnknown {
			res.replaced = append(res.replaced, path)
			continue
		}
		res.verified = append(res.verified, path)
	}

	return res
}

// firstRecordedIdentity returns the first non-empty (dev, inode) pair among
// entries — every sampleCandidate for the same path is expected to agree
// (they describe the same underlying file observed by different
// processes/kinds within the same sample), so the first one is
// representative.
func firstRecordedIdentity(entries []sampleCandidate) (dev string, inode uint64) {
	for _, e := range entries {
		if e.dev != "" {
			return e.dev, e.inode
		}
	}
	return "", 0
}

// formatDevForCompare renders a raw stat dev_t in the "MM:mm" hex form
// /proc/<pid>/maps uses, matching MapEntry.Dev's own format (mirrors
// rootfs's unexported formatDev, kept independent since dev/inode
// calibration here is done inline against a fstat this package already
// performed, not through rootfs.Calibrate's own single-first-candidate
// shape).
func formatDevForCompare(dev uint64) string {
	return fmt.Sprintf("%02x:%02x", unix.Major(dev), unix.Minor(dev))
}

// detectMergedUsrDirs confirms, for each usrmergeDirs pair, whether this
// generation's own container root actually has the pre-merge directory
// (e.g. /bin) and its merged counterpart (/usr/bin) resolve to the exact
// same object — the only basis on which treating a path under one as an
// alias of the same path under the other is safe. A pair this cannot
// confirm (either side fails to resolve, or they resolve to different
// objects) is simply absent from the result, never assumed.
func detectMergedUsrDirs(r *rootfs.Reader) map[string]bool {
	merged := map[string]bool{}
	for _, pair := range usrmergeDirs {
		oldDir := strings.TrimSuffix(pair[0], "/")
		newDir := strings.TrimSuffix(pair[1], "/")
		oldDev, oldIno, oldErr := r.Stat(oldDir)
		newDev, newIno, newErr := r.Stat(newDir)
		if oldErr == nil && newErr == nil && oldDev == newDev && oldIno == newIno {
			merged[pair[0]] = true
		}
	}
	return merged
}

// usrmergeDirs pairs each merged-/usr directory with its pre-merge name
// (Debian's usrmerge, and the same layout on most other modern
// distributions): /bin, /sbin, /lib and /lib64 are each a symlink to their
// /usr/... counterpart, so the kernel's canonical path for a file placed in
// any of them resolves to the /usr/... form regardless of which one a
// package database happened to record.
var usrmergeDirs = [][2]string{
	{"/bin/", "/usr/bin/"},
	{"/sbin/", "/usr/sbin/"},
	{"/lib64/", "/usr/lib64/"},
	{"/lib/", "/usr/lib/"}, // checked after /lib64/, which also starts with "/lib"
}

// usrmergeAlias returns the other spelling of path under the usrmerge
// aliasing above, in whichever direction applies (pre-merge -> merged, or
// merged -> pre-merge) — never both at once, since path can only start with
// one side of one pair — but only for a pair merged reports as confirmed
// (see detectMergedUsrDirs): a path that happens to start with "/bin/" in a
// container that never merged /bin into /usr is not given a fabricated
// /usr/bin alias.
func usrmergeAlias(path string, merged map[string]bool) (alias string, ok bool) {
	for _, pair := range usrmergeDirs {
		if !merged[pair[0]] {
			continue
		}
		if rest, ok := strings.CutPrefix(path, pair[0]); ok {
			return pair[1] + rest, true
		}
		if rest, ok := strings.CutPrefix(path, pair[1]); ok {
			return pair[0] + rest, true
		}
	}
	return "", false
}

// findMapEntry returns the (dev, inode) of the maps entry matching path, if
// any — used to give an exe path's ExecutableEvidence a confirmed dev/inode
// when the same path also appears among the process's own executable
// mappings (routinely true: the main binary's own text segment).
func findMapEntry(maps []procfs.MapEntry, path string) (dev string, inode uint64) {
	for _, m := range maps {
		if m.Path == path && !m.Deleted {
			return m.Dev, m.Inode
		}
	}
	return "", 0
}

// ownedListeners returns the sorted "tcp:<addr>:<port>" strings for every
// LISTEN-state socket h's own process actually holds an fd for — not merely
// every listener visible in its network namespace, which every other
// process sharing that namespace would see identically. A listener is
// attributed to this process only when one of its own fds names
// "socket:[<same inode>]".
func ownedListeners(h *procfs.Handle) []string {
	fdNames, err := h.FDNames()
	if err != nil {
		return nil
	}
	ownedInodes := map[uint64]bool{}
	for _, name := range fdNames {
		target, err := h.FDTarget(name)
		if err != nil {
			continue
		}
		var inode uint64
		if _, err := fmt.Sscanf(target, "socket:[%d]", &inode); err == nil {
			ownedInodes[inode] = true
		}
	}
	if len(ownedInodes) == 0 {
		return nil
	}

	var out []string
	for _, kind := range []string{"tcp", "tcp6"} {
		listens, err := h.NetTCPListens(kind)
		if err != nil {
			continue
		}
		for _, l := range listens {
			if ownedInodes[l.Inode] {
				out = append(out, fmt.Sprintf("%s:%s:%d", kind, l.LocalAddr, l.LocalPort))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ownsDistinctUserNS reports whether h's process is in a different user
// namespace than ownUserNS (this observer's own, captured once at startup):
// a process sharing the observer's own (the host's initial) user namespace
// is not "in a user namespace" in the sense the main body's high-privilege
// judgement cares about; one that does not is (a container run with
// --userns-remap, or one that called unshare(CLONE_NEWUSER) itself).
func ownsDistinctUserNS(h *procfs.Handle, ownUserNS string) bool {
	if ownUserNS == "" {
		return false // could not determine our own namespace; do not guess
	}
	link, err := h.NSLink("user")
	if err != nil {
		return false
	}
	return link != ownUserNS
}

// ownNamespaceLink reads this observer process's own /proc/self/ns/<kind>
// link, for the Session's own ownUserNS.
func ownNamespaceLink(kind string) (string, error) {
	h, err := procfs.Open(unix.Getpid())
	if err != nil {
		return "", err
	}
	defer h.Close()
	return h.NSLink(kind)
}

func isDeniedAny(errs ...error) bool {
	for _, e := range errs {
		if e != nil && procfs.Classify(e) == procfs.OutcomeDenied {
			return true
		}
	}
	return false
}

// containsString reports whether s appears anywhere in list.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
