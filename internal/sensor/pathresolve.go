package sensor

import (
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// pathResolveChCapacity bounds how many outstanding maps-fallback lookups
// (resolvePathAsync) may have answered but not yet been applied by loop.
// Sized generously relative to how rarely this fallback should actually be
// needed at all (only when a success event's own path-correlation lookup
// misses entirely — see resolvePathAndDispatch), not to how often ordinary
// events arrive.
const pathResolveChCapacity = 1024

// maxConcurrentPathResolves and maxQueuedPathResolves bound the maps-
// fallback worker pool: at most maxConcurrentPathResolves goroutines run at
// once (each one a single, bounded /proc/<pid>/maps read — see
// resolveMapsPath), and at most maxQueuedPathResolves requests wait for a
// slot to free up; a request that would exceed the queue is dropped and
// counted as an immediate loss (submitPathResolveRequest) rather than let
// either the goroutine count or the queue grow without bound under a burst
// of many distinct path-unknown events or a slow /proc read. ASSUMED
// values, the same order of magnitude as maxConcurrentSampleWorkers: this
// fallback is meant to be a rare path, not a primary one, so a modest
// concurrency budget is deliberate.
const (
	maxConcurrentPathResolves = 8
	maxQueuedPathResolves     = 512
)

// pathResolveRequest is one queued-or-in-flight maps-fallback lookup —
// everything dispatchPathResolve's own goroutine needs, plus the
// generationState (g) it was submitted against, so pendingMapsLookups can
// be decremented on the exact generation it was incremented on regardless
// of where (or whether) the resolved path eventually gets attributed.
// receivedAt is the original event's own first-received time (never
// re-stamped here or anywhere downstream — see pendingRouteEvent's own doc
// comment on why receivedAt must survive every async hop unchanged), carried
// through so applyPathResolveResult's own TTL check still measures against
// when this event actually first arrived, not when this particular lookup
// happened to be dispatched or answered.
type pathResolveRequest struct {
	g          *generationState
	ev         ebpf.Event
	kind       evidence.EvidenceKind
	isExec     bool
	receivedAt time.Time
}

// pathResolveResult is resolvePathAsync's own answer, carrying every fact
// applyPathResolveResult needs to finish handling the original event — there
// is no separate bookkeeping table keyed by the event on the Session side;
// the goroutine's own closure carries it through instead, the same shape
// sampleEnvelope/dbResult already use for a sample worker/the dbworker.
// originGen is the same generationState pathResolveRequest.g named — kept
// separate from re-resolving the event's own generation on the way back in
// (which can legitimately answer differently after a restart) purely so
// pendingMapsLookups is decremented on the generation it was actually
// incremented on. receivedAt is pathResolveRequest.receivedAt carried
// through unchanged.
type pathResolveResult struct {
	originGen  *generationState
	ev         ebpf.Event
	kind       evidence.EvidenceKind
	isExec     bool
	path       string
	resolved   bool
	receivedAt time.Time
}

// resolvePathAndDispatch resolves ev's own (mount namespace, root identity,
// dev, inode) to a path via s.pathIdx, falling back to a bounded, targeted
// read of ev's own process's live /proc/<pid>/maps (submitPathResolveRequest)
// if the correlation table has no entry for it at all, before dispatching to
// dispatchUsageEvent. Looking up by ev's own root (not just its mount
// namespace) is what refuses a path recorded from a different root than the
// one this exact success event's own root actually confirms — see pathKey's
// own doc comment. Shared by both a freshly arrived event (applyUsageEvent)
// and a route-resolved pending event (retryPendingRouteEvents/
// applyPathResolveResult); receivedAt is always the event's own original
// first-received time (see pathResolveRequest's own doc comment), never
// s.now() at this exact call.
func (s *Session) resolvePathAndDispatch(g *generationState, ev ebpf.Event, kind evidence.EvidenceKind, isExec bool, receivedAt time.Time) {
	if path, ok := s.pathIdx.lookup(uint32(ev.MountNamespaceID), formatKernelDev(ev.RootDev), ev.RootIno, ev.Dev, ev.Ino); ok {
		s.dispatchUsageEvent(g, path, ev, kind, isExec)
		return
	}
	if ev.TGID == 0 {
		// No process to read a fallback maps entry from at all — never
		// expected from kl_exec_success/kl_mmap_success, which always set
		// tgid, but handled defensively rather than passed to
		// resolveMapsPath(0, …), which would misread /proc/0.
		g.recordEventLoss(1)
		return
	}
	s.submitPathResolveRequest(pathResolveRequest{g: g, ev: ev, kind: kind, isExec: isExec, receivedAt: receivedAt})
}

// submitPathResolveRequest either starts req's own maps-fallback lookup
// immediately (a concurrency slot is free) or queues it (a slot is not, but
// the queue itself is not yet full) or drops it as an immediate,
// generation-attributed loss (the queue is also full) — see
// maxConcurrentPathResolves/maxQueuedPathResolves. Either way that a request
// is actually accepted (started or queued), req.g's own pendingMapsLookups
// is incremented here, exactly once, and only ever decremented by
// applyPathResolveResult once this exact request's own goroutine answers.
func (s *Session) submitPathResolveRequest(req pathResolveRequest) {
	if s.pathResolveInFlight >= maxConcurrentPathResolves {
		if len(s.pathResolveQueue) >= maxQueuedPathResolves {
			req.g.recordEventLoss(1)
			return
		}
		req.g.pendingMapsLookups++
		s.pathResolveQueue = append(s.pathResolveQueue, req)
		return
	}
	req.g.pendingMapsLookups++
	s.pathResolveInFlight++
	s.dispatchPathResolve(req)
}

// dispatchPathResolve starts req's own maps-fallback lookup as its own
// goroutine — loop itself must never read procfs directly, the same rule a
// sample worker's own goroutine exists to honor — reporting back over
// s.pathResolveCh. It never touches Session/generationState itself (every
// value it needs is copied into local variables before the goroutine
// starts), so nothing here needs synchronization; the concurrency
// bookkeeping (pathResolveInFlight) is entirely the caller's
// (submitPathResolveRequest/applyPathResolveResult) responsibility.
func (s *Session) dispatchPathResolve(req pathResolveRequest) {
	dev := formatKernelDev(req.ev.Dev)
	tgid := int(req.ev.TGID)
	ino := req.ev.Ino
	startBoottimeNs := req.ev.StartBoottimeNs
	mntNsID := uint32(req.ev.MountNamespaceID)
	g, ev, kind, isExec, receivedAt := req.g, req.ev, req.kind, req.isExec, req.receivedAt
	go func() {
		path, ok := resolveMapsPath(tgid, dev, ino, startBoottimeNs, mntNsID)
		s.pathResolveCh <- pathResolveResult{originGen: g, ev: ev, kind: kind, isExec: isExec, path: path, resolved: ok, receivedAt: receivedAt}
	}()
}

// resolveMapsPath opens pid, confirms it is still exactly the process the
// event named (its own starttime, converted from startBoottimeNs, matching
// what procfs.Open captured at open time, and its own mount namespace
// matching mntNsID), and only then searches its maps (procfs.Handle.Maps,
// the same read a sample worker already performs for every process it
// samples) for the path of the first non-deleted entry whose own recorded
// (dev, inode) matches — the file this specific process still has mapped,
// even though this Sensor never saw a file_open/exec_open event resolve its
// path.
//
// The starttime check happens before anything else is read: procfs.Open
// only protects against the PID being reused *after* Open returns (every
// later read goes through the descriptor it captured, not a fresh path), so
// without this check up front, a PID already reused by an unrelated process
// by the time this function even opens it would have that unrelated
// process's own maps searched under the original event's identity. The
// mount-namespace check guards the same kind of substitution one level
// higher: a process that exists and matches the event's own starttime but
// has since moved into (or was itself in) a different mount namespace than
// the event described is not the view this generation's own package
// database describes. h.Recheck() after reading maps closes the remaining
// window — the PID reused for an unrelated process while the read itself
// was in flight.
//
// mntNsID of 0 (the event's own mount namespace could not be determined at
// all) refuses the lookup outright rather than skipping the check: nothing
// here should ever attribute a maps entry to an event whose own view cannot
// be positively confirmed. A process that has since exited, whose identity
// has changed, or whose maps no longer contain a matching entry at all,
// reports ok=false: the caller counts this as an unattributed loss rather
// than guessing.
//
// pid is always ev.TGID — the thread-group leader's own PID, since
// /proc/<pid>/stat's starttime column always reports the leader's own
// start_boottime for every thread in the group (fs/proc/array.c), never an
// individual thread's — and startBoottimeNs is always the same leader's own
// start_boottime too (kl_task_start_boottime in bpf/kestrelynx.c), for
// exactly this reason: a success event triggered by any thread other than
// the leader itself still compares correctly here, since both sides of this
// check are pinned to the same task regardless of which thread actually
// executed or mapped the file.
func resolveMapsPath(pid int, dev string, ino uint64, startBoottimeNs uint64, mntNsID uint32) (path string, ok bool) {
	if pid <= 0 || startBoottimeNs == 0 || mntNsID == 0 {
		return "", false
	}
	h, err := procfs.Open(pid)
	if err != nil {
		return "", false
	}
	defer h.Close()

	if h.Starttime() != bootNsToTicks(startBoottimeNs) {
		return "", false
	}
	mnt, err := h.NSLink("mnt")
	if err != nil {
		return "", false
	}
	if id, ok := parseMntNSInode(mnt); !ok || id != mntNsID {
		return "", false
	}

	maps, _, err := h.Maps()
	if err != nil {
		return "", false
	}
	if err := h.Recheck(); err != nil {
		// The PID was reused for an unrelated process while maps was being
		// read; nothing just read can be trusted as belonging to the
		// process the event actually named.
		return "", false
	}

	for _, m := range maps {
		if m.Deleted || m.Path == "" {
			continue
		}
		if m.Dev == dev && m.Inode == ino {
			return m.Path, true
		}
	}
	return "", false
}

// applyPathResolveResult is loop's own handling of one resolvePathAsync
// answer: res.originGen's own pendingMapsLookups is decremented first (this
// always happens, regardless of what follows), a queued request (if any) is
// promoted to take the freed concurrency slot, and only then is the
// generation res.ev actually belongs to resolved — never carried over from
// before the async lookup was dispatched, since by the time it returns, a
// restart could have changed which generation is correct — using the exact
// same match resolveEventGeneration always applies, and routed through
// finalizeRoutedItem exactly like a retried pendingRouteEvent: routeResolved
// dispatches immediately, routeUnconfirmed waits on genconfirm.go's own
// liveness check first, and routeUnresolved/routePending re-queue res's own
// event rather than dropping it — a generation this session cannot yet
// vouch for might still be confirmed (or discovered) on a later retry (see
// retryPendingRouteEvents) — all subject to res.receivedAt's own TTL, the
// event's own original first-received time, never reset to s.now() here (see
// pathResolveRequest's own doc comment): a lookup that takes long enough to
// answer after its own event's pendingRouteEventTTL has already passed must
// not have its answer adopted as if it were still fresh.
//
// res.resolved being false (the live /proc/<pid>/maps read itself found no
// matching entry at all — the process exited, or never actually had this
// file mapped) is carried through as item.lossOnly rather than acted on
// immediately: there is no path to ever dispatch either way, but which
// generation's own events_lost that loss belongs to is exactly as much in
// question as it would be for any other not-yet-routed event, so it goes
// through the same routing (and, if warranted, the same liveness
// confirmation) before being charged — see dispatchRoutedEvent.
func (s *Session) applyPathResolveResult(res pathResolveResult) {
	res.originGen.pendingMapsLookups--
	s.pathResolveInFlight--
	if len(s.pathResolveQueue) > 0 {
		next := s.pathResolveQueue[0]
		s.pathResolveQueue = s.pathResolveQueue[1:]
		s.pathResolveInFlight++
		s.dispatchPathResolve(next)
	}

	item := pendingRouteEvent{
		ev: res.ev, kind: res.kind, isExec: res.isExec,
		path: res.path, lossOnly: !res.resolved, receivedAt: res.receivedAt,
	}
	g, outcome := s.resolveEventGeneration(res.ev.CgroupID, res.ev.StartBoottimeNs, res.ev.TGID, uint32(res.ev.MountNamespaceID))
	s.finalizeRoutedItem(g, outcome, item, s.now())
}
