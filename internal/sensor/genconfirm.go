// This file is loop's own generation-liveness confirmation pool: the
// dedicated, procfs-only check resolveEventGeneration's own routeUnconfirmed
// outcome (events.go) exists to require before an eBPF event is ever
// attributed to a boot-tick-matched candidate generation. A same-container-
// ID restart this session's own discovery has not yet noticed is exactly
// what a tick match alone cannot rule out; this is what actually rules it
// out, the same way a sample worker's own procfs read already does for an
// ordinary sample, just for a single PID rather than a whole container's
// worth of processes.
package sensor

import (
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// genConfirmChCapacity bounds how many outstanding confirmGenerationAlive
// answers may have completed but not yet been applied by loop — the same
// role pathResolveChCapacity plays for the maps-fallback pool.
const genConfirmChCapacity = 1024

// maxConcurrentGenConfirms and maxQueuedGenConfirms bound the generation-
// confirmation worker pool the same way maxConcurrentPathResolves/
// maxQueuedPathResolves bound the maps-fallback pool (pathresolve.go): at
// most maxConcurrentGenConfirms goroutines run at once (each one a single,
// bounded procfs read — see confirmGenerationAlive), and at most
// maxQueuedGenConfirms requests wait for a slot; past that, the request is
// counted as an unattributable loss instead (see submitGenConfirmRequest's
// own doc comment on why this pool's own overflow is a Sensor-side capacity
// failure, unlike a pendingRouteEvent that simply expires still in the
// routePending state). ASSUMED, the same order of magnitude as the
// maps-fallback pool: confirmation is meant to be a rare disambiguation step
// (one per distinct restart race, since a boot-tick-matched candidate
// already bounded by a known successor never needs confirming at all — see
// resolveEventGeneration), not a cost paid at the usual volume of successful
// usage events, since kl_dedup_usage's own 10-minute suppression window
// already caps how often the same file from the same cgroup can even reach
// here at all.
const (
	maxConcurrentGenConfirms = 8
	maxQueuedGenConfirms     = 512
)

// genConfirmRequest is one queued-or-in-flight "is this candidate generation
// still actually alive, right now" check. g is the exact generationState
// resolveEventGeneration named as its own boot-tick-matched candidate (see
// that function's own doc comment); item is the pendingRouteEvent this
// confirmation exists to unblock.
type genConfirmRequest struct {
	g    *generationState
	item pendingRouteEvent
}

// genConfirmResult is confirmGenerationAlive's own answer, carrying every
// fact applyGenConfirmResult needs — the same closure-carries-context shape
// pathResolveResult already uses for the maps-fallback pool (pathresolve.go).
// checkNs is the boot-relative CLOCK_BOOTTIME *nanosecond* (never rounded to
// a clock tick — see bootNsNow's own doc comment) this exact check was
// actually performed at (captured immediately before confirmFn ran, in
// dispatchGenConfirm) — meaningful only when checkNsOK is true (a bootNsNow
// failure, never expected on a running kernel but not assumed, leaves it
// unset rather than reporting a wrong instant). When confirmed is true,
// checkNs is proof g's own init was alive at that exact nanosecond — see
// generationState.lastAliveNs' own doc comment for what this proves and how
// applyGenConfirmResult uses it.
type genConfirmResult struct {
	g         *generationState
	item      pendingRouteEvent
	confirmed bool
	checkNs   uint64
	checkNsOK bool
}

// maxGenConfirmWaiters bounds genConfirmWaiters per generation
// (generationState) the same way maxQueuedGenConfirms bounds the pool as a
// whole: past this, a coalesced item is counted as an unattributable loss
// instead of waiting indefinitely for an answer that, once it arrives, would
// still only ever apply to it once anyway.
const maxGenConfirmWaiters = 4096

// submitGenConfirmRequest either coalesces req.item onto an already-
// outstanding confirmation for the exact same generation (req.g's own
// pendingConfirms is already nonzero — see generationState.genConfirmWaiters'
// own doc comment for why a second, redundant procfs read for the same
// (PID, starttime) is never dispatched), starts req's own liveness check
// immediately (no confirmation outstanding for req.g, and a concurrency slot
// is free), queues it (a slot is not, but the pool's own queue is not yet
// full), or — every one of the above is unavailable — counts req.item as an
// unattributable loss (recordUnattributableEventLoss) instead of ever
// dispatching it. req.g is, by construction, a real, boot-tick-matched
// candidate for a real, already-classified, non-excluded container (see
// resolveEventGeneration's own routeUnconfirmed) — never a container this
// session has simply never discovered at all (that case is routePending,
// which never even reaches this pool) — so dropping it here for want of a
// confirmation slot (or a waiter slot) is exactly the kind of Sensor-side
// capacity failure recordUnattributableEventLoss exists to count, not a
// "too short-lived to observe" case to discard silently. Whenever a fresh
// confirmation is actually accepted (immediately or queued, never
// coalesced), req.g's own pendingConfirms is incremented here, exactly
// once, and only ever decremented by applyGenConfirmResult once this exact
// request's own goroutine answers — at which point every coalesced waiter
// receives the exact same answer. See maxConcurrentGenConfirms/
// maxQueuedGenConfirms/maxGenConfirmWaiters for this pool's own bounds.
func (s *Session) submitGenConfirmRequest(req genConfirmRequest) {
	if req.g.pendingConfirms > 0 {
		// A confirmation for this exact generation is already outstanding;
		// its own eventual answer (confirmed or not) applies equally to
		// req.item, so this never dispatches its own separate procfs read.
		// This is what keeps a burst of many distinct usage events all
		// naming the same still-unconfirmed candidate (e.g. many short-lived,
		// distinct executables in one container with no known successor
		// generation yet) from saturating this pool's own concurrency/queue
		// bound on their own.
		if len(req.g.genConfirmWaiters) >= maxGenConfirmWaiters {
			s.recordUnattributableEventLoss(1)
			return
		}
		req.g.genConfirmWaiters = append(req.g.genConfirmWaiters, req.item)
		return
	}
	if s.genConfirmInFlight >= maxConcurrentGenConfirms {
		if len(s.genConfirmQueue) >= maxQueuedGenConfirms {
			s.recordUnattributableEventLoss(1)
			return
		}
		req.g.pendingConfirms++
		s.genConfirmQueue = append(s.genConfirmQueue, req)
		return
	}
	req.g.pendingConfirms++
	s.genConfirmInFlight++
	s.dispatchGenConfirm(req)
}

// dispatchGenConfirm starts req's own liveness check as its own goroutine —
// loop itself must never read procfs directly, the same rule a sample
// worker and resolvePathAsync already exist to honor — reporting back over
// s.genConfirmCh. Every value the goroutine needs (req.g's own init PID and
// starttime) is copied into local variables before it starts, so nothing
// here needs synchronization; the concurrency bookkeeping
// (genConfirmInFlight) is entirely the caller's (submitGenConfirmRequest/
// applyGenConfirmResult) responsibility.
func (s *Session) dispatchGenConfirm(req genConfirmRequest) {
	pid := req.g.init.PID
	starttime := req.g.init.Starttime
	confirmFn := s.genConfirmFn
	if confirmFn == nil {
		confirmFn = confirmGenerationAlive
	}
	g, item := req.g, req.item
	go func() {
		// checkNs is captured immediately before confirmFn runs: if it
		// reports confirmed, this is the boot-relative nanosecond that
		// answer is proof for (see genConfirmResult.checkNs' own doc
		// comment). Captured at full nanosecond precision, not rounded to a
		// clock tick, since resolveEventGeneration's own proof compares it
		// directly against an eBPF event's own start_boottime_ns.
		checkNs, nsErr := bootNsNow()
		confirmed := confirmFn(pid, starttime)
		s.genConfirmCh <- genConfirmResult{g: g, item: item, confirmed: confirmed, checkNs: checkNs, checkNsOK: nsErr == nil}
	}()
}

// confirmGenerationAlive reports whether pid is still running right now,
// with exactly starttime as its own recorded start time, and not a zombie or
// already-dead task merely still waiting to be reaped — the same
// PID-reuse-proof identity check procfs.Open/Starttime already gives a
// sample worker for the same init PID (openRootWithBasis), performed here as
// a single, standalone read instead of a full sample. There is deliberately
// no time-window shortcut: this is always a fresh read, taken at the moment
// this exact request is dispatched, never a reuse of an earlier sample's own
// confirmation no matter how recent it was (see resolveEventGeneration's own
// doc comment for why).
//
// The state check matters on its own, separately from the starttime match:
// per proc_pid_stat(5), a zombie task's own /proc/<pid>/stat still reports
// its original, unchanged starttime right up until its parent actually
// reaps it — a starttime match alone would let an already-exited init that
// simply has not been reaped yet (its own parent stuck, or slow to call
// wait) pass as "still alive", advancing lastAliveNs (see
// applyGenConfirmResult) past the instant it actually stopped running.
func confirmGenerationAlive(pid int, starttime int64) bool {
	if pid <= 0 {
		return false
	}
	h, err := procfs.Open(pid)
	if err != nil {
		return false
	}
	defer h.Close()
	if h.Starttime() != starttime {
		return false
	}
	state, err := h.State()
	if err != nil {
		return false
	}
	return !isDeadOrZombieState(state)
}

// isDeadOrZombieState reports whether state (one of proc_pid_stat(5)'s own
// single-character process state codes) means the task is no longer
// actually running, even though /proc/<pid> may still exist and still
// report its original starttime: 'Z' (zombie, exited but not yet reaped by
// its parent) and 'X'/'x' (dead — 'x' is the same state on kernels new
// enough to distinguish it from 'X', per proc_pid_stat(5); both are treated
// identically here).
func isDeadOrZombieState(state byte) bool {
	return state == 'Z' || state == 'X' || state == 'x'
}

// applyGenConfirmResult is loop's own handling of one confirmGenerationAlive
// answer, for res.item and every item coalesced onto the same confirmation
// (res.g.genConfirmWaiters — see submitGenConfirmRequest's own doc comment).
//
// A confirmed answer first advances res.g.lastAliveNs to res.checkNs (never
// backward — see that field's own doc comment) if this checkNs reading
// itself succeeded (res.checkNsOK): res.checkNs is now proof res.g's own
// init was alive at that exact nanosecond. Every item is then re-resolved
// fresh via resolveEventGeneration, never trusted directly against
// res.confirmed alone — this is what makes coalescing safe against a
// restart race (a confirmation dispatched against the old init, answering
// after a restart has already produced a newer, still uncoalesced item, or
// even a newer, now-known generation): only an item whose own process start
// nanosecond s_ns satisfies s_ns <= res.checkNs is actually proven by this
// exact confirmation (resolveEventGeneration's own step 1, against the
// now-updated lastAliveNs, at full nanosecond precision — never rounded to
// a shared clock tick the way an earlier version of this check was, which
// could not tell a confirmation and a post-restart event apart if both
// happened to fall in the same 10ms tick); an item with a later s_ns is left
// exactly where it was — routeUnconfirmed again (coalesced onto whatever
// confirmation answers it next), or, if a real successor generation has
// meanwhile been discovered, resolved or gap-lost on its own merits — never
// misattributed to res.g on the strength of an answer that does not
// actually cover it. finalizeRoutedItem is what honors each item's own
// receivedAt-based TTL throughout (see that function's own doc comment).
//
// An unconfirmed answer means res.g's own init has since exited, or now has
// a different starttime — a restart this session's own discovery has not
// yet noticed. Every item is requeued (pendingRouteEventTTL applies to each
// from here on, checked here directly since queuePendingRouteEvent itself
// is not TTL-aware), and an early discovery pass is requested exactly once
// so the restart this confirmation just caught is noticed as soon as
// possible.
func (s *Session) applyGenConfirmResult(res genConfirmResult) {
	res.g.pendingConfirms--
	s.genConfirmInFlight--
	if len(s.genConfirmQueue) > 0 {
		next := s.genConfirmQueue[0]
		s.genConfirmQueue = s.genConfirmQueue[1:]
		s.genConfirmInFlight++
		s.dispatchGenConfirm(next)
	}

	waiters := res.g.genConfirmWaiters
	res.g.genConfirmWaiters = nil
	items := make([]pendingRouteEvent, 0, 1+len(waiters))
	items = append(items, res.item)
	items = append(items, waiters...)

	now := s.now()
	if !res.confirmed {
		s.requestEarlyDiscovery(now)
		for _, item := range items {
			if now.Sub(item.receivedAt) > pendingRouteEventTTL {
				s.recordUnattributableEventLoss(1)
				continue
			}
			s.queuePendingRouteEvent(item)
		}
		return
	}

	if res.checkNsOK && (!res.g.lastAliveNsOK || res.checkNs > res.g.lastAliveNs) {
		res.g.lastAliveNs = res.checkNs
		res.g.lastAliveNsOK = true
	}
	for _, item := range items {
		g2, outcome2 := s.resolveEventGeneration(item.ev.CgroupID, item.ev.StartBoottimeNs, item.ev.TGID)
		s.finalizeRoutedItem(g2, outcome2, item, now)
	}
}
