// This file is the observer loop's own consumer of decoded eBPF events (see
// eventreader.go for how one reaches loop's own eventCh at all): resolving
// an event's cgroup ID to a generation, confirming its own mount namespace
// actually matches that generation's own confirmed mount view, resolving a
// success event's (mount namespace, dev, inode) to a path via the events
// this Sensor correlates them from, and folding the result into the same
// recordExecutable/recordOSPackage-lookup machinery sampling already uses —
// nothing here invents a second attribution pipeline.
package sensor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
)

// pathKey identifies "the same file, seen from the same root" for path-
// correlation purposes: a (mount namespace, root identity, dev, inode)
// quadruple. Root identity is part of this key, not just mount namespace,
// because the path a fentry/security_file_open event reports (bpf_d_path)
// is rendered relative to the *opening task's own root* at that exact
// moment — two tasks in the same mount namespace can still see different
// roots via chroot(2), and would get two different, both individually
// correct, path strings for the exact same (dev, inode). Without root in
// this key, a path recorded from inside a chroot could be handed back to a
// later success event confirmed under a completely different (e.g. init's
// own, unchrooted) root, crediting that event's own package attribution to
// a path string that never actually named that file from that root's own
// point of view.
type pathKey struct {
	mntNsID uint32
	rootDev string
	rootIno uint64
	dev     uint64
	ino     uint64
}

// maxPathIndexEntries bounds pathIndex's size the same way
// maxCgroupRouteEntries bounds cgroupRoute's: a defensive cap against
// unbounded growth over a long session, evicting the oldest-inserted entry
// first (a plain FIFO — see cgroupRoute's own doc comment on why that is
// an acceptable trade for this purpose). ASSUMED, same basis as
// maxCgroupRouteEntries.
const maxPathIndexEntries = 65_536

// pathIndex is loop's own correlation table from pathKey to the path a
// fentry/security_file_open event most recently reported for it — what
// lets an exec_success/mmap_success event (which carries a numeric dev/inode
// but never a path; see bpf/kestrelynx.c's own header comment) be resolved
// to a container-relative path at all. Read and written only by loop's own
// goroutine.
type pathIndex struct {
	byKey       map[pathKey]string
	insertOrder []pathKey
}

func (p *pathIndex) record(mntNsID uint32, rootDev string, rootIno, dev, ino uint64, path string) {
	if path == "" {
		return
	}
	if p.byKey == nil {
		p.byKey = map[pathKey]string{}
	}
	key := pathKey{mntNsID: mntNsID, rootDev: rootDev, rootIno: rootIno, dev: dev, ino: ino}
	if _, exists := p.byKey[key]; !exists {
		p.insertOrder = append(p.insertOrder, key)
	}
	p.byKey[key] = path
	for len(p.byKey) > maxPathIndexEntries && len(p.insertOrder) > 0 {
		oldest := p.insertOrder[0]
		p.insertOrder = p.insertOrder[1:]
		delete(p.byKey, oldest)
	}
}

func (p *pathIndex) lookup(mntNsID uint32, rootDev string, rootIno, dev, ino uint64) (string, bool) {
	path, ok := p.byKey[pathKey{mntNsID: mntNsID, rootDev: rootDev, rootIno: rootIno, dev: dev, ino: ino}]
	return path, ok
}

// pruneMountNamespace removes every entry keyed under mntNsID, along with
// their insertOrder bookkeeping — this table's own routine cleanup once a
// generation whose mount namespace this is has ended (see
// reconcileGenerations' own call site), working alongside (not replacing)
// maxPathIndexEntries' own safety-net cap.
func (p *pathIndex) pruneMountNamespace(mntNsID uint32) {
	if len(p.byKey) == 0 {
		return
	}
	for key := range p.byKey {
		if key.mntNsID == mntNsID {
			delete(p.byKey, key)
		}
	}
	kept := p.insertOrder[:0]
	for _, key := range p.insertOrder {
		if _, ok := p.byKey[key]; ok {
			kept = append(kept, key)
		}
	}
	p.insertOrder = kept
}

// pendingRouteEvent is one usage-evidence eBPF event (exec_success or
// mmap_success) this Sensor could not yet place in any generation at all —
// its cgroup ID is not yet classified at all, or it names a container this
// session has not yet registered any generation for, or the generation a
// candidate search finds has not yet been confirmed alive (see
// resolveEventGeneration's own doc comment for all three). Held at the
// Session level (not per-generation — which generation it belongs to is
// exactly what is unknown) until retryPendingRouteEvents resolves it,
// discards it (a confirmed non-container/excluded cgroup, or a container
// this session has never once registered a generation for — see
// eventRouteOutcome's own doc comment), or pendingRouteEventTTL expires it.
//
// path and lossOnly both default to their zero values for a freshly arrived
// event (the ordinary case: path resolution has not even been attempted
// yet, and dispatchRoutedEvent must still run the full
// resolvePathAndDispatch path-then-dispatch sequence once a generation is
// confirmed). applyPathResolveResult sets one or the other instead, for an
// event whose maps-fallback lookup already completed before route
// resolution could: path non-empty means the lookup already found this
// event's own path, so dispatchRoutedEvent goes straight to
// dispatchUsageEvent with it rather than repeating a resolvePathAndDispatch
// that would just miss the correlation table again and redo the same maps
// read; lossOnly true means the lookup itself found no matching entry at
// all, so there is nothing left to ever dispatch — only a loss to charge to
// whichever generation this event is eventually confirmed to belong to (see
// dispatchRoutedEvent).
type pendingRouteEvent struct {
	ev         ebpf.Event
	kind       evidence.EvidenceKind
	isExec     bool
	path       string
	lossOnly   bool
	receivedAt time.Time
}

// maxPendingRouteEvents and pendingRouteEventTTL bound the Session-wide
// pending-route queue: past either, an event still in the routeUnresolved or
// routeUnconfirmed state (see eventRouteOutcome) is dropped and counted via
// recordUnattributableEventLoss — which generation it belongs to is exactly
// the fact that never resolved, so the loss is folded into the Sensor-wide
// total and every generation observed at that point is downgraded to
// partial, but no single generation's own events_lost is advanced: guessing
// which one to charge would risk being wrong in exactly the restart case
// this queue exists to get right. An event stuck in the routePending state
// (a real, non-excluded container this session has simply never registered
// a generation for at all) is instead discarded with no loss counted at
// all once its own TTL passes — seeing an event for a container this
// session never once discovered is treated as that container having been
// too short-lived for this stage to observe at all (the main body does not
// scan such a container's own image either), not as a Sensor-side failure.
// ASSUMED values: generous enough for the startup race (a discovery pass
// completing, a cgroup_mkdir being processed, or this generation's own
// candidate being confirmed alive by genconfirm.go, all ordinarily well
// under this) without holding events indefinitely for a cgroup this Sensor
// will never resolve.
const (
	maxPendingRouteEvents = 4096
	pendingRouteEventTTL  = 30 * time.Second
)

// initialEventsCoverage reports the events_coverage value a generation
// discovered right now, with the given init starttime (boot-relative clock
// ticks — InitProcess.Starttime's own unit), should start at:
//
//   - CoverageNone when this session's own eBPF never attached at all.
//   - CoverageSinceStart when eBPF is attached and this container's own
//     init started *after* the boot-relative instant eBPF attached
//     (s.attachedAtBootTicks, captured once at startup — see that field's
//     own doc comment): eBPF was already watching before this container
//     could have done anything at all.
//   - CoveragePartial when eBPF is attached but this container's own init
//     started at or before that instant: the container was already running
//     when eBPF attached, so whatever it did between its own real start and
//     eBPF's attach could not have been observed — discovery merely
//     noticing the container just now (which is when this function actually
//     runs) says nothing about when it actually started.
func (s *Session) initialEventsCoverage(initStarttime int64) evidence.EventsCoverage {
	if s.eventsStatus != evidence.EventsOK {
		return evidence.CoverageNone
	}
	if initStarttime > s.attachedAtBootTicks {
		return evidence.CoverageSinceStart
	}
	return evidence.CoveragePartial
}

// applyEvent is the sole entry point loop uses to fold one decoded eBPF
// event into Session/generationState. It is never called from any goroutine
// but loop's own.
func (s *Session) applyEvent(ev ebpf.Event) {
	switch ev.Kind {
	case ebpf.EventCgroupMkdir:
		s.applyCgroupMkdirEvent(ev)
	case ebpf.EventFileOpen, ebpf.EventExecOpen:
		s.pathIdx.record(uint32(ev.MountNamespaceID), formatKernelDev(ev.RootDev), ev.RootIno, ev.Dev, ev.Ino, ev.Path)
	case ebpf.EventMmapOpen:
		// An attempt, not usage evidence, and it carries no path
		// (security_mmap_file cannot call bpf_d_path) — nothing to
		// correlate or attribute (see bpf/kestrelynx.c's own comment on
		// this attach point).
	case ebpf.EventExecSuccess:
		s.applyUsageEvent(ev, evidence.KindExecEvent, true)
	case ebpf.EventMmapSuccess:
		s.applyUsageEvent(ev, evidence.KindLibraryLoadEvent, false)
	}
}

// applyCgroupMkdirEvent records a newly created cgroup in s.cgroupRoute (see
// cgroupRoute.applyCgroupMkdir — this classifies the cgroup one way or
// another once its own ancestry is known) and, only once it actually became
// classified, gives every event still waiting in the pending-route queue a
// chance to resolve against the newly grown table, since one of them may
// have been waiting on exactly this cgroup ID or one of its now-known
// descendants.
//
// ev.Path being empty or ev.PathTruncated being true (bpf_probe_read_kernel_str
// failed outright, or the cgroup's own path did not fit kl_cgroup_mkdir's
// fixed 256-byte buffer — see bpf/kestrelynx.c) is never treated as this
// cgroup's own real path: cgroupRoute.ancestorLookup climbs an unrecognized
// path's prefixes down to and including the cgroup root itself (path ""),
// which scanCgroupTree's own initial walk always classifies as a confirmed
// non-container — an empty or truncated path would therefore ancestor-match
// that same root entry and wrongly confirm this cgroup non-container, purely
// because its own real path could not be read, rather than because it
// actually is one. This cgroup is left entirely unclassified instead: any
// pendingRouteEvent already naming it keeps waiting (routeUnresolved) the
// same as any other cgroup ID this Sensor has simply not classified yet at
// all, until either a later, non-truncated cgroup_mkdir/scan classifies it
// or its own pendingRouteEventTTL expires it as an unattributable loss.
func (s *Session) applyCgroupMkdirEvent(ev ebpf.Event) {
	if ev.Path == "" || ev.PathTruncated {
		return
	}
	if _, known := s.cgroupRoute.applyCgroupMkdir(ev.CgroupID, ev.Path); known {
		s.retryPendingRouteEvents(s.now())
	}
}

// applyUsageEvent handles an exec_success or mmap_success event: resolve it
// to a generation and route it accordingly (see routeEvent) — queuing it,
// dispatching a liveness confirmation, dispatching it outright, or
// discarding it, depending on eventRouteOutcome.
func (s *Session) applyUsageEvent(ev ebpf.Event, kind evidence.EvidenceKind, isExec bool) {
	item := pendingRouteEvent{ev: ev, kind: kind, isExec: isExec, receivedAt: s.now()}
	g, outcome := s.resolveEventGeneration(ev.CgroupID, ev.StartBoottimeNs, ev.TGID)
	s.routeEvent(g, outcome, item)
}

// routeEvent is resolveEventGeneration's own common dispatch tail, shared by
// every call site that resolves an event (or a queued pendingRouteEvent, or
// a maps-fallback answer) to an outcome: dispatch it now (routeResolved),
// start confirming its candidate's liveness (routeUnconfirmed), discard it
// silently (routeDiscard, routeGapLoss — the latter already fully recorded
// by resolveEventGeneration itself), or queue it for a later retry
// (routeUnresolved, routePending). Never TTL-aware on its own — see
// finalizeRoutedItem for the wrapper every call site handling an
// already-queued or already-async-answered item must use instead.
func (s *Session) routeEvent(g *generationState, outcome eventRouteOutcome, item pendingRouteEvent) {
	switch outcome {
	case routeResolved:
		s.dispatchRoutedEvent(g, item)
	case routeDiscard, routeGapLoss:
		// routeDiscard: a confirmed non-container cgroup, or one belonging
		// to an operator-excluded container. routeGapLoss: already counted
		// and its own bounding generations already marked partial by
		// resolveEventGeneration itself (see that outcome's own doc
		// comment). Neither is ever queued.
	case routeUnconfirmed:
		s.submitGenConfirmRequest(genConfirmRequest{g: g, item: item})
	default: // routeUnresolved, routePending
		s.queuePendingRouteEvent(item)
	}
}

// finalizeRoutedItem is the TTL-aware wrapper every call site acting on an
// already-queued pendingRouteEvent or an already-answered async result
// (genconfirm.go's applyGenConfirmResult, pathresolve.go's
// applyPathResolveResult) must use instead of routeEvent directly: item's
// own original receivedAt (never re-stamped by any of these — see
// pendingRouteEvent's own doc comment) is checked against
// pendingRouteEventTTL here, so an item is never dispatched, confirmed, or
// kept waiting purely because whichever async answer or retry happens to
// notice it is already past its own age limit — the same discipline
// routeEvent's own callers used to each reimplement individually.
// routeDiscard and routeGapLoss are age-independent (routeEvent's own doc
// comment) and always pass straight through regardless.
func (s *Session) finalizeRoutedItem(g *generationState, outcome eventRouteOutcome, item pendingRouteEvent, now time.Time) {
	if outcome == routeDiscard || outcome == routeGapLoss {
		s.routeEvent(g, outcome, item)
		return
	}
	if now.Sub(item.receivedAt) <= pendingRouteEventTTL {
		s.routeEvent(g, outcome, item)
		return
	}
	// Expired. Age is checked regardless of whether resolution itself would
	// have succeeded this round — an item is not kept alive, or dispatched,
	// indefinitely purely because it happens to resolve on whichever async
	// answer or retry finally notices it is already too old.
	switch outcome {
	case routeResolved:
		// The correct generation is actually known; charge the loss to it
		// specifically rather than treating it as unattributable.
		g.recordEventLoss(1)
	case routeUnresolved, routeUnconfirmed:
		s.recordUnattributableEventLoss(1)
	case routePending:
		// Discarded silently, out of this stage's own scope — see
		// pendingRouteEvent's own doc comment.
	}
}

// dispatchRoutedEvent is the common tail every route to a *confirmed*
// generation shares, once resolveEventGeneration (directly, or via
// genconfirm.go's own liveness check) has actually vouched for it: a
// lossOnly item (applyPathResolveResult's own maps-fallback-found-nothing
// case) only ever charges the loss, since there was never a path to
// dispatch in the first place; an item with a path already resolved
// (likewise from applyPathResolveResult, but this time the maps-fallback
// lookup already succeeded before the generation itself could be confirmed)
// goes straight to dispatchUsageEvent instead of re-attempting path
// resolution from scratch; every other item — a freshly arrived event, or
// one that only just got past the pending-route queue — still needs its own
// path resolved first, via resolvePathAndDispatch.
func (s *Session) dispatchRoutedEvent(g *generationState, item pendingRouteEvent) {
	if item.lossOnly {
		g.recordEventLoss(1)
		return
	}
	if item.path != "" {
		s.dispatchUsageEvent(g, item.path, item.ev, item.kind, item.isExec)
		return
	}
	s.resolvePathAndDispatch(g, item.ev, item.kind, item.isExec, item.receivedAt)
}

// eventRouteOutcome is resolveEventGeneration's own answer, distinguishing
// six cases a caller must treat differently:
//
//   - routeResolved: a specific generation was found, and this event's own
//     process start nanosecond s_ns is directly *proven* to fall within
//     that generation's own confirmed-alive window
//     (generationState.lastAliveNs) — see this function's own doc comment
//     for what that proves, why it needs no further confirmation at all
//     even for an already-ended generation, and why this comparison never
//     rounds s_ns down to a clock tick the way an earlier version of this
//     function did. Also used for the zero-startBoottimeNs aggregate case.
//     The accompanying *generationState is non-nil.
//   - routeUnconfirmed: this event's own container ID has a known generation
//     (the *latest* one this session knows of for it) whose own start is not
//     later than s_ns, but no generation's own proven-alive window
//     (routeResolved's own condition) covers s_ns — this session has not yet
//     confirmed, via a live procfs read right now (not by trusting an
//     earlier one; see genconfirm.go), that this candidate's own init PID is
//     still actually alive at or after s_ns. The accompanying
//     *generationState is non-nil and names the candidate to confirm, not
//     (yet) a generation safe to attribute anything to.
//   - routeDiscard: cgroupID is confirmed to name no container evidence
//     should ever be attributed through at all (a host process's own
//     cgroup, or one belonging to an operator-excluded container ID) —
//     never queued, never counted as a loss.
//   - routeUnresolved: cgroupID names a real, non-excluded container this
//     session has registered at least one generation for, but none of them
//     could even be a candidate at all right now (s_ns is older than every
//     known generation's own start). Worth continuing to wait for (an
//     earlier generation than any currently known might still be
//     discovered); counted as an unattributable loss if pendingRouteEventTTL
//     passes first.
//   - routePending: cgroupID names a real, non-excluded container, but this
//     session has never registered even one generation for it at all — out
//     of this stage's own scope (see pendingRouteEvent's own doc comment on
//     why this is discarded, not counted, once its own TTL passes).
//   - routeGapLoss: s_ns can be proven to belong to no generation this
//     session knows about at all — either it falls strictly between two
//     known generations' own proof (an intermediate generation this session
//     never discovered at all could have parented it instead), or it falls
//     inside some candidate generation's own starttime tick without
//     independent proof that this event's own process is that generation's
//     own init itself (see this function's own doc comment on the
//     tick-boundary case). Already fully recorded (as a loss, downgrading
//     only this one container's own generations to partial) by
//     resolveEventGeneration itself before returning, the only place with
//     the exact bounding generations in hand; the caller does nothing
//     further with it. Never resolvable on a later retry, so a caller must
//     never re-queue it, and must never count it as a loss a second time
//     (see queuePendingRouteEvent's own doc comment on why its own eviction
//     path excludes this outcome specifically).
type eventRouteOutcome int

const (
	routeResolved eventRouteOutcome = iota
	routeUnconfirmed
	routeDiscard
	routeUnresolved
	routePending
	routeGapLoss
)

// resolveEventGeneration resolves cgroupID to the container ID it belongs
// to (or confirms it belongs to none, or is excluded — see eventRouteOutcome),
// then decides which of this session's own generations for that container ID
// (live or recently ended, within the 7-day retention window —
// endedRetention) this event's own process — identified only by its start
// nanosecond s_ns (startBoottimeNs itself, the raw boot-relative nanosecond
// bpf/kestrelynx.c's kl_exec_success/kl_mmap_success report via
// task_struct's start_boottime, never rounded to a clock tick) — can be
// *proven*, not guessed, to belong to.
//
// Exactly one generation is ever alive for a given container ID at a time
// (a same-ID restart always ends the old one first — see
// reconcileGenerations), so the proof this function relies on is: if some
// generation G's own init was confirmed alive (by an ordinary sample, or by
// genconfirm.go's own dedicated check) at some boot-relative nanosecond t,
// then it was certainly still alive at every earlier nanosecond back to its
// own start too — s_ns <= t is proof this exact process could have been
// (and, since only one generation is ever alive for this container ID at
// once, must have been) G's own. lastAliveNs holds the highest such t this
// session has ever confirmed for G (see that field's own doc comment);
// checking s_ns <= G.lastAliveNs is exactly this proof, entirely at
// nanosecond precision — an earlier version of this function instead
// rounded both sides down to a shared 10ms clock tick (bootNsToTicks) before
// comparing, which could not tell a confirmation and a process that started
// after it apart if both merely happened to round into the same tick (e.g.
// a confirmation at 10.001s and a post-restart process at 10.009s both
// floor to tick 1000) — and it applies equally to an already-ended G: ending
// does not un-confirm a fact this session already established while it was
// still alive.
//
// The lower bound — s_ns must not be older than G's own start — has the
// opposite precision problem: InitProcess.Starttime is only ever available
// in clock ticks at all (/proc/<pid>/stat has no finer unit), so the
// earliest G could possibly have started is ticksToNs(G.init.Starttime), a
// floor that may understate G's own real start by up to one whole tick. An
// s_ns that falls inside G's own starttime tick
// (ticksToNs(G.init.Starttime) <= s_ns < ticksToNs(G.init.Starttime+1)) is
// therefore never resolved to G by default, even when no other generation is
// in the picture at all: an earlier version of this function tried to prove
// the absence of an overlapping predecessor instead, by checking whether the
// generation immediately before G (for this same container ID) had its own
// lastAliveNs already short of that tick's own start — but a generation's
// lastAliveNs falling short of some instant is only the highest nanosecond
// this session happened to confirm it alive at, never proof it had actually
// ended by then; it could easily have kept running, uninterrupted and simply
// unconfirmed, right up to (or into) G's own starttime tick, without
// contradicting "only one generation is ever alive for a given container ID
// at a time" at all. That check is gone.
//
// The one exception this function still accepts inside G's own starttime
// tick is independent proof that this event's own process *is* G's own init
// itself, not merely some other process that happens to share that same
// 10ms window: the event's own TGID equals G.init.PID, and the event's own
// s_ns, floored to a clock tick, equals G.init.Starttime. Two distinct
// processes can never share both the same PID and the same starttime tick,
// so this is exact proof, independent of any other generation's own state —
// and it is the one thing that keeps a container's own main program from
// permanently registering as an unattributable loss purely because its own
// first exec/mmap necessarily lands in its own init's own starttime tick.
// Every other process that merely starts within that same 10ms window — a
// short-lived helper forked moments after the container's own init, say —
// is counted as a gap loss instead (see routeGapLoss): this is deliberately
// conservative, never guessed.
//
// If no known generation's own proof already covers s_ns, only one further
// possibility can still be resolved without guessing: s_ns might belong to
// the *latest* generation this session knows of for this container ID,
// sometime after the last instant that generation was actually confirmed
// alive — but only if s_ns is not older than that generation's own start
// tick. This is routeUnconfirmed: the caller must dispatch a live procfs
// check (genconfirm.go) before trusting it, since an unnoticed restart could
// have already superseded it.
//
// Critically, a *known, later* generation existing is never enough on its
// own to resolve an s_ns that falls before it and after every other known
// generation's own proof: it proves a restart happened at some point before
// that later generation's own start, but not that no *other*, still
// undiscovered generation existed in between (a container that restarted
// twice in quick succession between two of this session's own discovery
// passes, say). Such an s_ns can never be proven to belong to any generation
// this session knows about — see routeGapLoss.
//
// This is exact, boot-relative-only arithmetic; it deliberately never
// projects into wall-clock time to compare against a generation's own
// startedAt/endedAt. Those two fields are recorded only once a discovery
// pass actually notices the container — which can lag the container's own
// real start (and therefore this exact process's own real start) by up to
// one whole --interval — so filtering candidates by that wall-clock window
// instead would routinely, and incorrectly, reject the very generation this
// match exists to find.
//
// A zero startBoottimeNs (never expected from kl_exec_success/
// kl_mmap_success, which always set it, but not asserted here; used by
// reconcileEventLossCounters' own per-cgroup aggregate attribution, which
// has no single event to take a process start time from) skips this whole
// proof procedure, falling back to whichever generation for this container
// ID is currently live and returning it as routeResolved directly: an
// aggregate ring-buffer counter increase is already an approximate signal,
// not a specific process's own usage evidence, so the same precision this
// function otherwise insists on would buy nothing here.
func (s *Session) resolveEventGeneration(cgroupID uint64, startBoottimeNs uint64, tgid uint64) (*generationState, eventRouteOutcome) {
	containerID, known := s.cgroupRoute.lookup(cgroupID)
	if !known {
		return nil, routeUnresolved
	}
	if containerID == "" || matchesExcludedID(containerID, s.cfg.ExcludeIDs) {
		return nil, routeDiscard
	}

	if startBoottimeNs == 0 {
		for _, g := range s.generations {
			if !g.ended && g.container.ID == containerID {
				return g, routeResolved
			}
		}
		return nil, routeUnresolved
	}

	eventNs := startBoottimeNs
	var gens []*generationState
	for _, g := range s.generations {
		if g.container.ID == containerID {
			gens = append(gens, g)
		}
	}
	if len(gens) == 0 {
		return nil, routePending
	}

	// withinOwnStartTick reports whether eventNs falls inside g's own
	// starttime tick — the one clock tick /proc's own reporting cannot place
	// g's own real start any more precisely within (see this function's own
	// doc comment on the lower bound).
	withinOwnStartTick := func(g *generationState) bool {
		tickStart := ticksToNs(g.init.Starttime)
		return eventNs >= tickStart && eventNs < tickStart+nsPerClockTick
	}

	// provenToBeInitItself reports whether this event's own TGID and start
	// time together are independent proof that this event's own process *is*
	// g's own init, not merely some other process that happens to share g's
	// own starttime tick: the event's own TGID names exactly g.init.PID, and
	// eventNs, floored to a clock tick, equals g.init.Starttime exactly. Two
	// distinct processes can never share both the same PID and the same
	// starttime tick, so this holds regardless of g.lastAliveNsOK and
	// regardless of any other generation's own state — see this function's
	// own doc comment for why this is the one exception accepted inside a
	// candidate's own starttime tick.
	provenToBeInitItself := func(g *generationState) bool {
		return int(tgid) == g.init.PID && bootNsToTicks(eventNs) == g.init.Starttime
	}

	// 1. Direct proof, per candidate g:
	//   - eventNs inside g's own starttime tick: only provenToBeInitItself
	//     resolves it (see this function's own doc comment); anything else
	//     in that same 10ms window falls through to routeGapLoss below,
	//     never guessed from any other generation's own confirmed state.
	//   - eventNs at or after the tick following g's own start: g's own
	//     confirmed-alive window (lastAliveNs, ns-precision) resolves it,
	//     the only case this function ever trusts without a fresh liveness
	//     check, and the only one that can resolve an already-ended
	//     generation.
	for _, g := range gens {
		if withinOwnStartTick(g) {
			if provenToBeInitItself(g) {
				return g, routeResolved
			}
			continue
		}
		if g.lastAliveNsOK && eventNs >= ticksToNs(g.init.Starttime) && eventNs <= g.lastAliveNs {
			return g, routeResolved
		}
	}

	// 2. No generation's own window covers it. Find best (the highest-
	// Starttime generation that could still chronologically have parented
	// this process at all, i.e. its own starttime tick starts at or before
	// eventNs) and latest (the highest-Starttime generation known at all,
	// regardless of eventNs) — these coincide exactly when the only
	// candidate whose own start doesn't already rule it out is also the
	// newest generation this session knows of for this container ID.
	var best, latest *generationState
	for _, g := range gens {
		if latest == nil || g.init.Starttime > latest.init.Starttime {
			latest = g
		}
		if ticksToNs(g.init.Starttime) <= eventNs && (best == nil || g.init.Starttime > best.init.Starttime) {
			best = g
		}
	}

	if best == nil {
		// eventNs predates every known generation's own start tick for this
		// container ID — an earlier generation this session has simply not
		// discovered yet could still be found (and, if it is still alive,
		// confirmed) by a future discovery pass; unlike routeGapLoss below,
		// this is genuinely worth waiting for.
		s.requestEarlyDiscovery(s.now())
		return nil, routeUnresolved
	}

	// eventNs inside best's own starttime tick was already checked for
	// provenToBeInitItself by step 1's own loop above (best is drawn from
	// gens, which that loop ran over in full); reaching this point means
	// that proof did not hold, so this event's own process cannot be told
	// apart from a short-lived, non-init process that merely started within
	// 10ms of best's own startup — never resolvable to best, and never
	// resolvable on a later retry either, since best's own starttime tick is
	// fixed forever.
	if withinOwnStartTick(best) {
		s.recordContainerGapLoss(gens)
		return nil, routeGapLoss
	}

	if best == latest {
		// best is the latest generation known at all for this container ID,
		// and eventNs is past its own starttime tick: still potentially its
		// current instance, just not yet proven alive this recently.
		return best, routeUnconfirmed
	}

	// best != latest: a known, strictly later generation already exists,
	// proving a restart happened at some point after best's own last
	// confirmed-alive nanosecond and before latest's own start — but not
	// that no *other*, still undiscovered generation existed in between (a
	// container restarted twice between two of this session's own
	// discovery passes, say). eventNs cannot be proven to belong to best,
	// to latest, or to anything else this session knows about. This can
	// never be resolved on a later retry either: best has already ended (a
	// later generation is known to exist), so its own lastAliveNs can never
	// advance again. Recorded once, right here — the only place with the
	// exact bounding generations for this one container in hand — and
	// never queued.
	s.recordContainerGapLoss(gens)
	return nil, routeGapLoss
}

// recordContainerGapLoss counts one event lost to a routeGapLoss gap (see
// resolveEventGeneration's own doc comment): added to the Sensor-wide
// unattributable total, same as any other unattributable loss, but
// downgrading only gens — every generation this session has ever held for
// the one container ID the gap belongs to (its current live one, if any,
// and every one observed spanning the gap) — to partial, never every
// generation this session holds the way markAllGenerationsPartial's own
// global downgrade does: no other container's own events are in question
// here at all.
func (s *Session) recordContainerGapLoss(gens []*generationState) {
	s.unattributedEventsLost++
	for _, g := range gens {
		if g.eventsCoverage == evidence.CoverageSinceStart {
			g.eventsCoverage = evidence.CoveragePartial
		}
	}
}

// dispatchUsageEvent is the common tail every route to a confirmed
// generation shares (a freshly resolved event, a pending-route event that
// just resolved, or an async maps-fallback answer) once a generation and a
// path are both known.
//
// The mount-view check runs first, before anything else is recorded: an
// event whose own mount namespace and root filesystem identity do not both
// match this generation's own confirmed ones (g.mntNsID/g.rootDev/g.rootIno,
// populated once a real sample resolves them — see applySampleResult) — or
// that cannot be checked at all because this generation has not confirmed
// either yet — is never used to attribute anything. A different mount
// namespace, or a chroot within the very same one, can make the same
// numeric (dev, inode) name a completely different file than the one init's
// own package-database index describes; recording it as evidence either for
// a language-package executable or for an OS-package candidate would risk
// crediting the wrong file's package. The generation is marked incomplete
// instead, withdrawing not_observed the same way any other discarded
// observation does, without guessing.
//
// recordExecutable happens next, unconditionally (when isExec), regardless
// of whether this generation's own package-database index is ready yet:
// language-package judgement reads gen.Executables directly and does not
// depend on the OS index at all, so nothing about it should ever wait on
// OS index readiness. Only the OS-package candidate submission that follows
// depends on index state — queued (recordPendingEvent) if the index is not
// ready yet, submitted immediately otherwise.
func (s *Session) dispatchUsageEvent(g *generationState, path string, ev ebpf.Event, kind evidence.EvidenceKind, isExec bool) {
	if !g.matchesMountView(uint32(ev.MountNamespaceID), formatKernelDev(ev.RootDev), ev.RootIno) {
		g.incomplete = true
		return
	}

	now := s.now()
	dev := formatKernelDev(ev.Dev)
	obs := s.eventObservation(ev, path, now)

	if isExec {
		g.recordExecutable(path, dev, ev.Ino, kind, now, &obs)
	}

	if g.idxState != indexReady {
		g.recordPendingEvent(pendingEventItem{
			path: path, dev: dev, inode: ev.Ino, kind: kind,
			obs: obs, receivedAt: now,
		})
		return
	}

	s.submitEventCandidate(g, path, dev, ev.Ino, kind, obs, now)
}

// submitEventCandidate builds the one-path candidateBatch a single eBPF
// usage event contributes and submits it exactly the way
// applySampleResult/submitCandidateBatches already submits a sample's own
// candidates — including g's own cached usrmerge-alias table
// (g.mergedUsrDirs, populated by the same detectMergedUsrDirs call a sample
// worker already performs; see applySampleResult), so a path recorded under
// one usrmerge spelling still resolves against a package database that
// recorded the other, exactly as the sampling path already does — and
// queuing behind an already-outstanding lookup (g.pendingLookup) rather
// than ever issuing a second one concurrently, per the same rule
// submitCandidateBatches' own callers already follow.
func (s *Session) submitEventCandidate(g *generationState, path, dev string, inode uint64, kind evidence.EvidenceKind, obs evidence.ProcessObservation, now time.Time) {
	batch := candidateBatch{
		candidates: map[string][]sampleCandidate{
			path: {{kind: kind, dev: dev, inode: inode, obs: obs}},
		},
		mergedUsrDirs: g.mergedUsrDirs,
		verified:      []string{path},
		observedAt:    now,
		epoch:         g.idxEpoch,
		basis:         g.idxBasis,
	}
	if g.pendingLookup != nil {
		if len(g.queuedCandidates) >= maxQueuedCandidateBatches {
			g.candidatesLostPermanently = true
			return
		}
		g.queuedCandidates = append(g.queuedCandidates, batch)
		return
	}
	s.submitCandidateBatches(g, g.idxEpoch, []candidateBatch{batch})
}

// eventObservation builds the ProcessObservation a usage event contributes:
// Exe is the resolved path itself (the executed or mapped file, matching
// what a sampling-derived observation's own Exe already means for its
// candidate), EffectiveUID/CapEff come straight from the event's own
// kernel-reported identity, Userns compares the event's user namespace ID
// against this observer's own, and Listeners is always empty — an event
// alone never observes a listening socket, which the main body's own
// exposure judgement already reads an empty Listeners as unknown for.
func (s *Session) eventObservation(ev ebpf.Event, path string, now time.Time) evidence.ProcessObservation {
	return evidence.ProcessObservation{
		Exe:          path,
		EffectiveUID: int(ev.EUID),
		Userns:       s.eventInDistinctUserNS(ev),
		CapEff:       formatCapEff(ev.CapEffective),
		LastSeen:     now,
	}
}

// formatCapEff renders a raw cap_effective bitmask the same fixed-width,
// zero-padded lowercase hex form /proc/<pid>/status's own "CapEff:" line
// uses (procfs.ParseStatus reports that string verbatim), so an event-
// derived ProcessObservation's CapEff compares equal to a sampling-derived
// one for the exact same capability set (see mergeProcessObservation's own
// same-sample/same-process dedup, which compares CapEff as a plain string).
func formatCapEff(capEffective uint64) string {
	return fmt.Sprintf("%016x", capEffective)
}

// eventInDistinctUserNS reports whether ev's own user namespace ID differs
// from this observer's own — the event-derived equivalent of
// ownsDistinctUserNS, which compares the same fact for a sampled process
// via its /proc/<pid>/ns/user link instead. ev.UserNamespaceID is 0 when the
// BPF side could not resolve it at all (bpf/kestrelynx.c's
// kl_current_user_ns_id); treated as "could not determine", never as "same
// namespace" or "different namespace" — the same conservative default
// ownsDistinctUserNS applies when its own input is unavailable.
func (s *Session) eventInDistinctUserNS(ev ebpf.Event) bool {
	if ev.UserNamespaceID == 0 || s.ownUserNSInode == 0 {
		return false
	}
	return uint32(ev.UserNamespaceID) != s.ownUserNSInode
}

// parseUserNSInode extracts the numeric inode from a /proc/<pid>/ns/user
// symlink target of the form "user:[<inode>]" (ownNamespaceLink("user")'s
// own return shape), for comparison against an eBPF event's
// UserNamespaceID (a bare inode number, not a link string).
func parseUserNSInode(link string) (uint32, bool) {
	return parseNSLinkInode("user:[", link)
}

// parseMntNSInode extracts the numeric inode from a /proc/<pid>/ns/mnt
// symlink target of the form "mnt:[<inode>]" (mountBasis.mntNS's own shape,
// via procfs.Handle.NSLink("mnt")), for recording on a generationState (see
// generationState.mntNsID) and later pruning s.pathIdx by it once that
// generation ends.
func parseMntNSInode(link string) (uint32, bool) {
	return parseNSLinkInode("mnt:[", link)
}

// parseNSLinkInode extracts the numeric inode from a /proc/<pid>/ns/<kind>
// symlink target of the form "<prefix><inode>]" — prefix already includes
// the opening "[" (e.g. "user:[", "mnt:["), so only the closing "]" needs
// checking separately.
func parseNSLinkInode(prefix, link string) (uint32, bool) {
	const suffix = "]"
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, suffix) {
		return 0, false
	}
	n, err := strconv.ParseUint(link[len(prefix):len(link)-len(suffix)], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// queuePendingRouteEvent appends item to s.pendingRouteEvents, evicting the
// oldest entry first if the queue is already at maxPendingRouteEvents. The
// evicted entry is re-resolved before deciding whether it counts as a loss
// at all: one that would resolve to routePending (a real, non-excluded
// container this session has simply never registered a generation for) or
// routeDiscard (a host cgroup, or an operator-excluded container) is
// discarded silently, exactly as either already is everywhere else in this
// file (see pendingRouteEvent's own doc comment and retryPendingRouteEvents)
// — an eviction happening early, under queue pressure, rather than late, at
// its own TTL, is not itself a reason to treat these two differently.
// routeGapLoss is likewise excluded here, but for a different reason: unlike
// routePending/routeDiscard, it is *not* loss-free — but resolveEventGeneration
// itself already recorded that loss (scoped to only the one container's own
// generations — see recordContainerGapLoss) the moment it produced this
// outcome, so counting it again here would both double the loss and, via
// recordUnattributableEventLoss's own global downgrade, incorrectly spread
// partial to every generation this session holds rather than just that one
// container's own. Everything else evicted this way is counted via
// recordUnattributableEventLoss, same as before.
func (s *Session) queuePendingRouteEvent(item pendingRouteEvent) {
	if len(s.pendingRouteEvents) >= maxPendingRouteEvents {
		oldest := s.pendingRouteEvents[0]
		s.pendingRouteEvents = s.pendingRouteEvents[1:]
		_, outcome := s.resolveEventGeneration(oldest.ev.CgroupID, oldest.ev.StartBoottimeNs, oldest.ev.TGID)
		if outcome != routePending && outcome != routeDiscard && outcome != routeGapLoss {
			s.recordUnattributableEventLoss(1)
		}
	}
	s.pendingRouteEvents = append(s.pendingRouteEvents, item)
}

// retryPendingRouteEvents attempts to resolve every still-queued
// pendingRouteEvent again. A confirmed-discardable one (routeDiscard) is
// dropped immediately, at any age, and never counted. Otherwise, TTL is
// checked before resolution is allowed to win: a still-fresh item that
// resolves outright (routeResolved) is dispatched via dispatchRoutedEvent, a
// still-fresh one that only reaches routeUnconfirmed is handed to
// genconfirm.go's own liveness check instead of being dispatched yet, but an
// item is never dispatched purely because it happens to resolve (or even
// become confirmable) on whichever retry finally notices it is already past
// pendingRouteEventTTL — age is checked regardless of the resolution outcome
// that same round. Once expired, routeResolved charges the loss to the
// now-known generation specifically (its identity is not in doubt, only
// whether attributing to it this late is still warranted); routeUnresolved
// and routeUnconfirmed (a container this session does know of, but could not
// yet confirm the right, still-alive generation for) are counted via
// recordUnattributableEventLoss instead; routePending (a real, non-excluded
// container this session has never once registered a generation for) is
// discarded with no loss counted at all — see pendingRouteEvent's own doc
// comment. Everything still within its own TTL and not yet resolved or
// confirmable stays queued for the next retry.
func (s *Session) retryPendingRouteEvents(now time.Time) {
	if len(s.pendingRouteEvents) == 0 {
		return
	}
	pending := s.pendingRouteEvents
	s.pendingRouteEvents = nil
	for _, item := range pending {
		g, outcome := s.resolveEventGeneration(item.ev.CgroupID, item.ev.StartBoottimeNs, item.ev.TGID)
		s.finalizeRoutedItem(g, outcome, item, now)
	}
}

// recordUnattributableEventLoss counts n eBPF events lost without ever
// having been attributed to any specific generation at all — a
// pendingRouteEvent dropped for exceeding maxPendingRouteEvents, or one that
// expired still in the routeUnresolved state (see retryPendingRouteEvents'
// own doc comment; a routePending expiry is not counted at all). This still
// counts toward the Sensor-wide total (folded into s.eventsLost by
// buildSnapshot) and downgrades every generation this session currently
// holds (live or recently ended — see markAllGenerationsPartial) to
// partial, since which generation(s) this loss actually belongs to is
// exactly the fact that never resolved, and guessing wrongly would
// misattribute it worse than not attributing it at all. Deliberately never
// advances any one generation's own events_lost.
func (s *Session) recordUnattributableEventLoss(n int64) {
	if n <= 0 {
		return
	}
	s.unattributedEventsLost += n
	markAllGenerationsPartial(s.generations)
}

// reconcileEventLossCounters reads the eBPF ring buffer's own loss counters
// (kl_lost_by_cgroup, kl_lost_events) and attributes the increase since the
// last call: a per-cgroup counter's own increase is charged to whichever
// generation that cgroup ID currently resolves to (recordEventLoss,
// advancing that generation's own events_lost) when resolve confirms one
// outright (routeResolved). An increase belonging to a cgroup resolve
// confirms is discardable (routeDiscard — a host process's own cgroup, or an
// operator-excluded container) is not this session's own observation being
// affected at all, so it is not counted anywhere at all. Every other
// increase (genuinely unresolved, still-unconfirmed, or naming a container
// this session has never registered a generation for) is folded into
// s.unattributedEventsLost — the same running total a stuck
// pendingRouteEvent or pendingEventItem already contributes to — and
// downgrades every generation this session currently holds to partial.
//
// Unlike an earlier version of this method, there is no return value: the
// Sensor-wide total (SensorInfo.Events.Lost) is never derived from the
// kernel's own counters directly. See buildSnapshot, which instead sums
// every generation's own events_lost plus s.unattributedEventsLost once this
// call returns — so a path-resolution failure, a pending-route TTL expiry
// and a maps-fallback queue overflow all count toward the same total a
// ring-buffer reservation failure does, rather than two parallel,
// occasionally-mismatched totals.
func (s *Session) reconcileEventLossCounters() {
	if s.ebpfHandle == nil {
		return
	}
	byCgroup, err := s.ebpfHandle.LostEventsByCgroup()
	if err != nil {
		byCgroup = nil
	}
	fallback, err := s.ebpfHandle.LostEvents()
	if err != nil {
		fallback = s.lastLostFallback
	}

	// No specific process/event context is available for an aggregate
	// per-cgroup ring-buffer counter (it is not any one event), so
	// resolveEventGeneration is called with startBoottimeNs=0: its own
	// simpler live-generation fallback, not the tick-based disambiguation a
	// specific process's own start time would otherwise support.
	resolve := func(cgroupID uint64) (*generationState, eventRouteOutcome) {
		return s.resolveEventGeneration(cgroupID, 0, 0)
	}
	s.unattributedEventsLost += attributeEventLossDeltas(byCgroup, fallback, s.lastLostByCgroup, s.lastLostFallback, resolve, s.generations)

	// Logged only when either counter's own current value has actually
	// changed since the last call — the evidence file's own events_lost is
	// deliberately a single blended total (see buildSnapshot's own doc
	// comment), with no field distinguishing a kernel-side ring-buffer
	// reservation failure from a Sensor-side (userspace) one; this line is
	// the only place that distinction survives at all, for an operator (or
	// an integration test, which has no other way to read this Sensor's own
	// BPF maps directly, running as a separate process in a separate
	// container) reading this Sensor's own stderr.
	var byCgroupTotal, prevByCgroupTotal uint64
	for _, c := range byCgroup {
		byCgroupTotal += c
	}
	for _, c := range s.lastLostByCgroup {
		prevByCgroupTotal += c
	}
	if byCgroupTotal != prevByCgroupTotal || fallback != s.lastLostFallback {
		fmt.Fprintf(os.Stderr, "kestrelynx sensor: ebpf kernel loss counters: by_cgroup_total=%d fallback=%d\n", byCgroupTotal, fallback)
	}

	if s.lastLostByCgroup == nil && len(byCgroup) > 0 {
		s.lastLostByCgroup = map[uint64]uint64{}
	}
	for cgroupID, count := range byCgroup {
		s.lastLostByCgroup[cgroupID] = count
	}
	s.lastLostFallback = fallback
}

// attributeEventLossDeltas is reconcileEventLossCounters' own pure
// attribution logic, factored out so it can be exercised directly with
// fabricated counters and a fake resolve function, without a real
// *ebpf.Handle (which needs CAP_BPF/CAP_PERFMON to construct at all). See
// reconcileEventLossCounters' own doc comment for what it computes and why.
// Returns the total delta that could not be attributed to any specific
// generation this round (for the caller to add to its own running
// s.unattributedEventsLost) — never the sum of the counters' own raw current
// values, which would double-count everything already attributed via
// recordEventLoss above. A routeDiscard delta contributes to neither this
// return value nor markAllGenerationsPartial: it is deliberately excluded
// from both, since it is not this session's own observation being affected
// at all, and must not make an otherwise-healthy container's own evidence
// look less complete than it actually is.
func attributeEventLossDeltas(
	byCgroup map[uint64]uint64, fallback uint64,
	prevByCgroup map[uint64]uint64, prevFallback uint64,
	resolve func(cgroupID uint64) (*generationState, eventRouteOutcome),
	generations map[string]*generationState,
) int64 {
	var unattributed int64
	for cgroupID, count := range byCgroup {
		prev := prevByCgroup[cgroupID]
		if count <= prev {
			continue
		}
		delta := int64(count - prev)
		g, outcome := resolve(cgroupID)
		switch outcome {
		case routeResolved:
			g.recordEventLoss(delta)
		case routeDiscard:
			// Not this session's own observation at all — see this
			// function's own doc comment.
		default:
			unattributed += delta
		}
	}

	if fallback > prevFallback {
		unattributed += int64(fallback - prevFallback)
	}
	if unattributed > 0 {
		markAllGenerationsPartial(generations)
	}
	return unattributed
}

// applyEventVerificationResult folds one sample worker's own
// verifiedEvents/lostEventItems (see sampleResult's own doc comment) into g:
// a verified item's own OS-package candidate is submitted exactly the way a
// freshly arrived event's is (submitEventCandidate — the index is known
// ready, or the worker would never have been given these items at all, see
// startSampleWorker; recordExecutable already happened when the event was
// first dispatched, per dispatchUsageEvent's own doc comment, so it is not
// repeated here), a lost one advances eventsLost/downgrades eventsCoverage.
// Either way it is removed from g.pendingEvents by seq — never a wholesale
// replacement, since a new event can arrive (and be queued) while this
// exact sample worker was in flight.
//
// Every item is checked against g.pendingEvents' own *current* contents
// (stillPending) before being applied at all: the worker that produced res
// was dispatched against a snapshot of g.pendingEvents taken at that time
// (sampleJob.pendingEvents), and loop's own expirePendingEvents can have
// already aged an item out of it — counting it as lost there — while this
// exact worker was still in flight. Applying a verification answer for an
// item no longer in g.pendingEvents at all would either resurrect one loop
// already gave up on, or double-count a loss already charged once.
// stillPending also excludes an item still physically present in
// g.pendingEvents but already past its own pendingEventTTL as of right
// now, even though expirePendingEvents has not swept it yet — a worker
// started just before an item's own TTL, but only answering after crossing
// it, must not have its answer adopted as if it arrived in time; the next
// expirePendingEvents sweep counts that item as lost instead.
//
// Called only from applySampleResult, and only once that caller has already
// confirmed res's own basis still matches g's currently-ready index (see
// applySampleResult's own doc comment on why that check must run first) —
// never for a sample whose root has since been invalidated.
func (s *Session) applyEventVerificationResult(g *generationState, res sampleResult) {
	if len(res.verifiedEvents) == 0 && len(res.lostEventItems) == 0 {
		return
	}
	now := s.now()
	stillPending := make(map[uint64]bool, len(g.pendingEvents))
	for _, item := range g.pendingEvents {
		if now.Sub(item.receivedAt) > pendingEventTTL {
			// Still physically present in g.pendingEvents (the periodic
			// expirePendingEvents sweep, once per discovery pass, has not
			// reached it yet), but already past its own TTL as of right now:
			// a verification result answering for this exact item — dispatched
			// against a snapshot taken before it expired, but only returning
			// after crossing that TTL itself — must not be applied as if it
			// were still timely. Leaving it out of stillPending here defers
			// it to the next expirePendingEvents sweep, which will count it
			// as lost exactly once, rather than adopting a stale result now.
			continue
		}
		stillPending[item.seq] = true
	}

	processed := make(map[uint64]bool, len(res.verifiedEvents)+len(res.lostEventItems))
	for _, item := range res.verifiedEvents {
		if !stillPending[item.seq] {
			continue
		}
		processed[item.seq] = true
		s.submitEventCandidate(g, item.path, item.dev, item.inode, item.kind, item.obs, now)
	}
	var lost int64
	for _, item := range res.lostEventItems {
		if !stillPending[item.seq] {
			continue
		}
		processed[item.seq] = true
		lost++
	}
	if lost > 0 {
		g.recordEventLoss(lost)
	}
	if len(processed) == 0 {
		return
	}

	kept := g.pendingEvents[:0]
	for _, item := range g.pendingEvents {
		if !processed[item.seq] {
			kept = append(kept, item)
		}
	}
	g.pendingEvents = kept
}

// markAllGenerationsPartial downgrades eventsCoverage (never events_lost
// itself — see reconcileEventLossCounters' own doc comment on why an
// unattributable loss cannot advance any one generation's own counter) for
// every generation this session currently holds, live or recently ended
// (within the 7-day retention window; see endedRetention) — an
// unattributable loss's own interval could have included a generation that
// ended moments before this reconciliation ran, and its own evidence is
// still shown (and therefore still able to overstate its own confidence)
// until it is pruned.
func markAllGenerationsPartial(generations map[string]*generationState) {
	for _, g := range generations {
		if g.eventsCoverage == evidence.CoverageSinceStart {
			g.eventsCoverage = evidence.CoveragePartial
		}
	}
}
