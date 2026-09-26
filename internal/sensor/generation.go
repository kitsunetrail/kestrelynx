package sensor

import (
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// indexState is one container generation's own package-database index
// state machine, transitioned only by the loop goroutine (never by the
// dbworker goroutine that actually performs a build, and never by a sample
// worker, which never touches the index at all):
//
//	idle    -> queued   loop decided this generation needs its first build
//	           (or a retry after failed) and is waiting for a jobCh slot
//	queued  -> building dbworker accepted the build job and is working it
//	building-> ready    the build completed with every file resolved
//	building-> failed   the build could not complete (see indexRetryAfter)
//	failed  -> queued   loop retries a failed generation every sample (see
//	           runDBWorker's own per-file backoff check, which is what
//	           actually decides whether anything is sent to the parser)
//
// ready and idle are never re-entered once building has started: a
// generation whose database has been fully resolved is never rebuilt
// (packages do not change while a container runs), and an absent/
// unsupported database is exactly as permanent — both settle into ready.
type indexState int

const (
	indexIdle indexState = iota
	indexQueued
	indexBuilding
	indexReady
	indexFailed
)

// generationState is the daemon's own in-memory bookkeeping for one
// container generation, kept across samples. Its OSPackages/Unavailable/
// Executables are indexed by key for O(1) upsert during a sample; toEvidence
// converts them to the slice shape evidence.Generation (and, ultimately, the
// evidence file) uses.
//
// Every field here is read and written only by the loop goroutine. A sample
// worker or the dbworker goroutine never holds a pointer to a
// generationState at all — they exchange immutable job/result values with
// loop instead (see sampleJob/sampleResult and dbJob/dbResult) — so nothing
// in this type needs its own synchronization.
type generationState struct {
	container      evidence.ContainerRef
	init           InitProcess
	startedAt      time.Time
	endedAt        *time.Time
	lastVerifiedAt time.Time
	// lastAliveNs is the highest boot-relative CLOCK_BOOTTIME *nanosecond*
	// (never rounded to a clock tick — see bootNsNow's own doc comment) this
	// session has ever positively confirmed g.init (this exact PID, with
	// this exact Starttime, and not a zombie/dead process still reporting
	// that same starttime — see confirmGenerationAlive/runSampleWorker's own
	// doc comments) was still alive at — never decreased once advanced, and
	// meaningful only when lastAliveNsOK is true (see that field's own doc
	// comment for why "never yet confirmed" must not be confused with "0
	// nanoseconds since boot"). It is what makes resolveEventGeneration's
	// own attribution provable rather than a guess: an eBPF event whose own
	// process start nanosecond s_ns satisfies s_ns <= lastAliveNs is proof
	// this generation's own init was still running at s_ns (it was confirmed
	// alive at some later or equal nanosecond, lastAliveNs, so it must also
	// have still existed at every earlier nanosecond back to its own start)
	// — true regardless of whether this generation has since ended.
	// Advanced by two sources: every ordinary sample that successfully
	// resolves this generation's own mountBasis (applySampleResult, from
	// sampleResult.initAliveNs — an ordinary sample already performs exactly
	// this same init-alive-with-matching-starttime check via
	// openRootWithBasis, so it costs nothing extra to also report the
	// boot-relative nanosecond it did so at), and genconfirm.go's own
	// dedicated liveness check (applyGenConfirmResult, from
	// genConfirmResult.checkNs) for the one case ordinary sampling has not
	// yet caught up to.
	lastAliveNs uint64
	// lastAliveNsOK is false until lastAliveNs is set for the first time
	// (see newGenerationState) — a generation this session has registered
	// (its own init.Starttime is known, from discovery) but has not yet
	// actually sampled or confirmed alive even once. init.Starttime alone is
	// never used as an initial lastAliveNs: the real instant a process
	// started is somewhere within its own starttime's 10ms-wide clock tick
	// (ticksToNs's own floor), never provably at that tick's exact start, so
	// treating "started" as "confirmed alive at the start of its own tick"
	// would itself be exactly the kind of unproven guess this field exists
	// to rule out.
	lastAliveNsOK bool

	// ended, sampleStalled, lastSampleDenied, parseFailed (len > 0) and
	// forceParseFailed are the raw facts derivePublishedState combines into
	// the one evidence.GenerationState this generation reports — nothing
	// else ever sets a published state directly; see that function's own
	// doc comment for the priority order and why it exists as a single
	// place at all (a DB-side parse failure must never silently overwrite a
	// sample-side stalled verdict, for one).
	ended bool
	// lastSampleDenied is true when the most recently *completed* sample
	// (never a stalled/abandoned one) found every process it attempted
	// denied — see lastGoodSample's own doc comment.
	lastSampleDenied bool
	// forceParseFailed is set only by writeParseFailedAndExit: the parser
	// itself died, so every generation this session was still tracking
	// must report parse_failed from now on, regardless of whether that
	// particular generation's own parseFailed list happens to be empty
	// (its index may already have been built successfully; the point is
	// that nothing more can ever be confirmed about it this session).
	forceParseFailed bool

	packageDB     evidence.PackageDBInfo
	idxState      indexState
	idxRetryAfter time.Time // meaningful only while idxState == indexFailed
	// idxBasis is the mount-namespace/root identity (see mountBasis's own
	// doc comment) the currently-ready index was actually built from —
	// captured once, when a build succeeds (see applyBuildResult) — so a
	// later sample can tell whether init's own root has since changed out
	// from under it (e.g. a chroot with no new PID/starttime, which the
	// ordinary starttime check alone cannot catch) without needing a
	// completely new generation to notice.
	idxBasis mountBasis
	// idxEpoch counts every index rebuild this generation has ever been
	// forced into (see applySampleResult's own mount-basis-mismatch
	// branch) — incremented exactly once per detected mismatch, never
	// reverted, and never incremented merely because a build attempt ran
	// (only because the previous index was invalidated). candidateBatch,
	// pendingLookup and dbJob/dbResult (lookup and build) all carry the
	// epoch a candidate was observed under or a job was submitted for, so
	// a candidate observed against one root can never be matched against
	// an index later rebuilt from a different one — see
	// flushQueuedCandidates and runDBWorker's own epoch check for the two
	// places this is actually enforced, on the loop side and the dbworker
	// side respectively.
	idxEpoch int
	// postIndexConfirmed is false from the moment idxState first becomes
	// indexReady (see applyBuildResult) until a sample taken *after* that —
	// never one whose own candidates were resolved against a not-yet-ready
	// index, which this Sensor never retroactively reattributes — has had
	// its own candidates, if any, fully attributed (its lookup answered,
	// not merely submitted; see applySampleResult/applyLookupResult). Until
	// then, derivePublishedState reports StateInitializing even though
	// idxState itself already reports ready: a generation whose
	// lastVerifiedAt already advanced (a pre-ready sample can still confirm
	// processes ran, just not attribute anything to a package) but whose
	// OSPackages are still empty purely because no sample has used the
	// newly-ready index yet must never be mistaken for one that positively
	// confirmed it has no OS packages in use at all.
	postIndexConfirmed bool
	// idxQueuedAt is when this generation's currently outstanding build job
	// (idxState queued or building) was handed to the dbworker's jobCh —
	// used to detect a build queue that has stopped making progress at all
	// (the oldest still-outstanding job waiting more than 5 minutes; see
	// the loop's own queue-health check).
	idxQueuedAt time.Time

	incomplete bool
	truncated  bool

	// pendingProcesses is the most recent discovery pass's own process list
	// (with starttimes) for this generation's container — refreshed by
	// reconcileGenerations every discovery pass, and read by
	// dispatchWork/startSampleWorker when this generation's next sample
	// worker is dispatched. It is a plain snapshot value, never mutated by
	// a worker (sampleJob carries its own copy of the slice header, which
	// is enough: neither side ever appends to or writes through it).
	pendingProcesses []InitProcess

	eventsCoverage evidence.EventsCoverage
	// mntNsID is this generation's own mount namespace's numeric inode,
	// recorded the first time any sample resolves a mountBasis for it
	// (applySampleResult, from res.basis.mntNS) — 0 until then. Two things
	// depend on it: matchesMountView gates every eBPF event this generation
	// is ever allowed to attribute anything from (an event whose own mount
	// namespace does not match, or that arrives before this is even known,
	// is never used — see that method's own doc comment), and, separately,
	// it is what events.go's pathIndex.pruneMountNamespace is keyed on once
	// this generation ends. It is never updated once set — a mount-
	// namespace change this Sensor cannot detect from this field alone (see
	// idxBasis's own doc comment on chroot/unshare) is not a correctness
	// concern for either use: matchesMountView only ever needs to confirm
	// an event still agrees with the *original* confirmed view, and a
	// later, undetected change would just make every subsequent event fail
	// that same check instead of succeeding wrongly.
	mntNsID uint32
	// rootDev/rootIno are this generation's own confirmed root filesystem
	// identity — init's own root (dev, inode), recorded the first time any
	// sample resolves a mountBasis for it (applySampleResult, from
	// res.basis.rootDev/rootIno), the same way mntNsID is. Checked by
	// matchesMountView alongside mntNsID: a mount namespace match alone
	// cannot tell a chroot(2) apart from init's own unchanged root, since
	// chroot never changes which mount namespace a task is in. Never
	// updated once set, for the same reason mntNsID never is — see that
	// field's own doc comment.
	rootDev string
	rootIno uint64
	// mergedUsrDirs is this generation's own cached usrmerge-alias table
	// (detectMergedUsrDirs's result), refreshed whenever a sample resolves
	// one (applySampleResult, from res.mergedUsrDirs) — nil until the first
	// sample that has any candidate to resolve at all. events.go's own
	// submitEventCandidate reads this directly (an eBPF event never opens
	// rootfs itself to compute one fresh), so a path recorded under one
	// usrmerge spelling by an event still resolves against a package
	// database that recorded the other, exactly as the sampling path does.
	mergedUsrDirs map[string]bool
	// eventsLost is this generation's own share of every eBPF event this
	// session could not attribute with confidence: a path-unknown success
	// event (correlation table had no matching (mount ns, dev, inode)) that
	// also could not be resolved via a live /proc/<pid>/maps read, a
	// pending-for-index event that expired or failed its re-verification
	// (recordEventLoss's callers), and this generation's own cgroup ID's
	// share of the ring buffer's reservation-failure counter (see
	// reconcileEventLossCounters). It is never decremented.
	eventsLost int64

	// pendingEvents holds every resolved-path eBPF success event
	// (exec_success, mmap_success) received while this generation's own
	// package-database index was not yet ready to attribute it against —
	// see recordPendingEvent's own doc comment for the cap/expiry this
	// queue is held to, and sampleworker.go's own pending-event
	// verification (piggybacked onto this generation's regular sample
	// worker once idxState reaches indexReady) for how it eventually
	// drains. Included in toEvidence's own Incomplete computation: an
	// executable or OS-package fact this generation has already received
	// but not yet finished attributing must never let a not_observed
	// verdict be published in the meantime.
	pendingEvents []pendingEventItem
	// nextEventSeq allocates pendingEventItem.seq, one higher each call —
	// never reused within this generation's lifetime.
	nextEventSeq uint64
	// pendingMapsLookups counts outstanding resolvePathAsync calls
	// dispatched against this generation (pathresolve.go) that have not yet
	// answered — an eBPF success event whose path-correlation lookup missed
	// and is now waiting on a live /proc/<pid>/maps read. Included in
	// toEvidence's own Incomplete computation for the same reason
	// pendingEvents is: a "was this file used" answer that could still
	// resolve to "yes" must never be preempted by a not_observed verdict.
	pendingMapsLookups int
	// pendingConfirms is 1 while a genConfirmRequest (genconfirm.go) is
	// outstanding (in flight or queued) against this generation — a
	// ticks-matched candidate (resolveEventGeneration's own routeUnconfirmed)
	// whose init PID has not yet been confirmed still alive with that exact
	// starttime — 0 otherwise. Included in toEvidence's own Incomplete
	// computation for the same reason pendingMapsLookups is: a candidate
	// that could still turn out to be the right generation for a "was this
	// file used" event must never let a not_observed verdict be published
	// while its own confirmation is still outstanding.
	pendingConfirms int
	// genConfirmWaiters holds every pendingRouteEvent whose own routing
	// named this exact generation as an unconfirmed candidate while a
	// confirmation for it was already outstanding (pendingConfirms > 0) —
	// see submitGenConfirmRequest's own doc comment for why a second,
	// redundant procfs read for the same (PID, starttime) is never
	// dispatched. Every one of these receives the exact same
	// confirmed/unconfirmed answer the one outstanding request eventually
	// gets (applyGenConfirmResult), alongside that request's own primary
	// item.
	genConfirmWaiters []pendingRouteEvent

	osPackages  map[pkgKey]*evidence.OSPackageEvidence
	unavailable map[pkgKey]*evidence.UnavailablePackage
	executables map[string]*evidence.ExecutableEvidence // key: path

	parseFailed []evidence.ParseFailure

	// sampleAlive is true from the moment loop starts this generation's
	// sample worker until that worker's goroutine actually returns —
	// whether or not loop is still waiting for it (see sampleStalled).
	// loop must never start a second sample worker for the same generation
	// while sampleAlive is true: two workers reading the same processes
	// concurrently would double-count observations, and two builds racing
	// the same parser-side index key at once could interleave their file
	// uploads into a single corrupted build.
	sampleAlive bool
	// sampleStalled is true once loop has given up waiting for this
	// generation's sample worker within its own 5-second budget. The
	// worker may still be running; sampleAlive stays true until it actually
	// exits, at which point sampleAlive and sampleStalled both clear.
	// Nothing about the worker's own (necessarily discarded) result is kept.
	sampleStalled bool

	// pendingLookup holds every not-yet-answered sample's worth of
	// resolved-but-not-yet-attributed candidates while loop waits for the
	// matching dbworker lookup job to answer — see sampleResult's own doc
	// comment for why package attribution happens only after that answer
	// arrives, never inside the sample worker itself.
	pendingLookup *pendingLookup
	// queuedCandidates holds every sample's own candidateBatch that arrived
	// while pendingLookup was already outstanding — merged into it (never
	// discarded) once that lookup answers, so it can be submitted as the
	// very next lookup instead of being lost. See applySampleResult's own
	// doc comment for why a sample's candidates are never simply dropped on
	// top of an outstanding lookup, and maxQueuedCandidateBatches for the
	// cap this queue is held to.
	queuedCandidates []candidateBatch
	// candidatesLostPermanently is set, permanently for the rest of this
	// generation's session, the moment a batch of candidates is discarded
	// with no way to ever recover it — either queuedCandidates would have
	// exceeded maxQueuedCandidateBatches and the new batch had to be
	// dropped outright instead of queued, or a queued batch's own epoch no
	// longer matches the current index by the time flushQueuedCandidates
	// gets to it (see candidateBatch's own doc comment on epoch). Unlike an
	// ordinary queued batch (recovered once its own lookup answers), one
	// lost this way is gone for good, so this generation can never again
	// claim the confidence not_observed needs — see toEvidence's own
	// Incomplete computation.
	candidatesLostPermanently bool
}

// candidateBatch is one sample's own worth of resolved-but-not-yet-
// attributed candidates: the shape sampleResult itself reports, plus the
// one timestamp that sample was confirmed at.
type candidateBatch struct {
	candidates    map[string][]sampleCandidate
	mergedUsrDirs map[string]bool
	verified      []string
	replaced      []string
	// observedAt is the single timestamp the sample that produced this
	// batch was itself confirmed at (the same value passed to
	// lastGoodSample for this same sample) — carried through so that
	// whatever gets recorded once the lookup answer finally arrives is
	// attributed to when the observation actually happened, not to
	// whatever moment the lookup happens to complete at (which can be
	// meaningfully later, and would otherwise let multiple packages/
	// libraries confirmed by the very same sample each advance
	// KindObservation.Samples on their own, since mergeKindObservation
	// counts by distinct timestamp) — and so that two different batches
	// folded into the same lookup round trip (see pendingLookup's own doc
	// comment) still count as two distinct samples against that rule, not
	// one.
	observedAt time.Time
	// epoch is g.idxEpoch at the moment this batch's own sample was
	// confirmed — the index this batch's own candidates are eligible to be
	// matched against. basis is res.basis from that same sample, an
	// independent cross-check of the same fact. A batch queued behind an
	// outstanding lookup can sit for a while before it is ever submitted
	// (see queuedCandidates' own doc comment); if the index is rebuilt in
	// the meantime (idxEpoch bumped), this batch's own candidates describe
	// a root that index was never built from, and flushQueuedCandidates
	// must never submit it against the new one regardless.
	epoch int
	basis mountBasis
}

// maxQueuedCandidateBatches bounds how many samples' worth of candidates
// this Sensor holds in generationState.queuedCandidates while a lookup for
// an earlier one is still outstanding — a lookup round trip normally
// resolves within a small fraction of one sample interval, so queuing more
// than a handful of samples' worth at once means something is genuinely
// stuck (the dbworker itself stalled, most likely), not merely a slow
// round trip. Once exceeded, the newest batch is dropped outright and
// candidatesLostPermanently is set — recorded as an unrecoverable gap
// rather than let the queue itself grow without bound.
const maxQueuedCandidateBatches = 32

// pendingLookup is what a generationState.pendingLookup holds between one
// or more samples' own candidateBatch arriving (each resolves its own
// observed paths to "verified" or "replaced", but not yet to an owning
// package) and the corresponding dbworker lookup job's own dbResult (which
// resolves each path to zero, one or more than one owning package).
// Ordinarily holds exactly one batch; more than one only when
// queuedCandidates had accumulated batches to fold in at the moment the
// previous lookup answered and this one was submitted in its place (see
// applyLookupResult).
type pendingLookup struct {
	batches []candidateBatch
	// epoch is the one idxEpoch every batch in batches was confirmed to
	// share before this lookup was ever submitted (see
	// submitCandidateBatches) — carried on the dbJob this lookup becomes
	// and echoed back on its own dbResult, so the dbworker goroutine can
	// refuse to match it against an index it already knows was rebuilt out
	// from under it (see runDBWorker's own epoch check) even if that
	// rebuild finishes before this lookup is actually processed.
	epoch int
}

// pkgKey identifies one OS package entity within a generation, by exact name
// and version — the same identity JudgeOSPackage matches a Finding against.
type pkgKey struct{ Name, Version string }

// pendingEventItem is one eBPF success event (exec_success or
// mmap_success) whose path was already resolved (via the Session's own
// path-correlation table, or its live-/proc/<pid>/maps fallback; see
// events.go/pathresolve.go) but whose generation's own package-database
// index was not yet ready to attribute it against a package. Any
// recordExecutable call this event's own kind warrants already happened
// when it was first dispatched (see dispatchUsageEvent's own doc comment on
// why that never waits on OS index readiness) — this queue exists purely
// to hold the OS-package candidate submission until the index is ready.
type pendingEventItem struct {
	// seq identifies this exact queued item so loop can remove precisely
	// this one from generationState.pendingEvents once a sample worker's
	// own verification result names it (evidence.ProcessObservation embeds
	// a slice, so pendingEventItem is not a comparable type Go could use
	// for a value-equality set on its own).
	seq        uint64
	path       string
	dev        string
	inode      uint64
	kind       evidence.EvidenceKind
	obs        evidence.ProcessObservation
	receivedAt time.Time
}

// matchesMountView reports whether an event's own mount namespace
// (eventMntNsID) AND root filesystem identity (eventRootDev, eventRootIno)
// both match this generation's own confirmed ones (g.mntNsID/g.rootDev/
// g.rootIno, populated once a real sample resolves them — see
// applySampleResult). Zero on either side of either pair means "not yet
// confirmed" and is treated the same as a mismatch: an event is never used
// to attribute anything — recording an executable or submitting an
// OS-package candidate alike — without a positive confirmation that it
// describes init's own filesystem view.
//
// Mount namespace alone is not enough: chroot(2) replaces a task's own root
// without changing which mount namespace it is in, so a process chrooted
// into a completely different filesystem view than init's own would still
// pass a namespace-only check, crediting its own numeric (dev, inode) to a
// file this generation's package-database index does not actually describe
// at that same (dev, inode) at all. Root identity closes that gap the same
// way mount namespace closes the cross-container one.
func (g *generationState) matchesMountView(eventMntNsID uint32, eventRootDev string, eventRootIno uint64) bool {
	if g.mntNsID == 0 || eventMntNsID == 0 || g.mntNsID != eventMntNsID {
		return false
	}
	return g.rootDev != "" && eventRootDev != "" && g.rootIno != 0 && eventRootIno != 0 &&
		g.rootDev == eventRootDev && g.rootIno == eventRootIno
}

// maxPendingEventsPerGeneration bounds how many resolved-but-not-yet-
// attributed eBPF events one generation holds while its own package index
// is still building — deliberately generous (a container's own startup
// burst of short-lived execs is exactly the case this queue exists for),
// but not unbounded: past this, the newest arrival is dropped and counted
// as lost rather than let the queue grow without bound for a generation
// whose index build is stuck.
const maxPendingEventsPerGeneration = 4096

// pendingEventTTL bounds how long a pendingEventItem waits for its
// generation's index to become ready before it is dropped and counted as
// lost. ASSUMED: this value needs tuning once real indexing latency is
// measured in production; chosen to comfortably exceed the several-second
// index-build times observed so far, without staying stale long enough
// that a re-verification against the eventually-ready index would be
// comparing against a container long since finished starting up.
const pendingEventTTL = 60 * time.Second

// recordPendingEvent appends item to g.pendingEvents, dropping and counting
// it as lost immediately if the queue is already at its cap — never
// blocking or growing past maxPendingEventsPerGeneration.
func (g *generationState) recordPendingEvent(item pendingEventItem) {
	if len(g.pendingEvents) >= maxPendingEventsPerGeneration {
		g.recordEventLoss(1)
		return
	}
	g.nextEventSeq++
	item.seq = g.nextEventSeq
	g.pendingEvents = append(g.pendingEvents, item)
}

// expirePendingEvents removes every pendingEvents entry older than
// pendingEventTTL as of now, counting each as lost — called once per
// discovery pass (dispatchWork) so a generation whose index build never
// completes does not hold onto stale events indefinitely.
func (g *generationState) expirePendingEvents(now time.Time) {
	if len(g.pendingEvents) == 0 {
		return
	}
	kept := g.pendingEvents[:0]
	var expired int64
	for _, item := range g.pendingEvents {
		if now.Sub(item.receivedAt) > pendingEventTTL {
			expired++
			continue
		}
		kept = append(kept, item)
	}
	g.pendingEvents = kept
	if expired > 0 {
		g.recordEventLoss(expired)
	}
}

// recordEventLoss counts n eBPF events this generation could not attribute
// with confidence (a path-unknown success event, an expired or
// failed-re-verification pendingEventItem, or this generation's own share
// of the ring buffer's reservation-failure counter): eventsLost advances,
// incomplete is set (an event this generation could not place might have
// been the missing evidence — the same rule recordOSPackage/recordExecutable
// already apply to a discarded observation), and eventsCoverage downgrades
// from since_start to partial (never upgraded back, and left alone if
// already none: an eBPF-less generation has nothing to downgrade from).
func (g *generationState) recordEventLoss(n int64) {
	if n <= 0 {
		return
	}
	g.eventsLost += n
	g.incomplete = true
	if g.eventsCoverage == evidence.CoverageSinceStart {
		g.eventsCoverage = evidence.CoveragePartial
	}
}

// mirrorMaxStringBytes and validRecordString mirror evidence's own
// per-string validation (validString, unexported there) so a record this
// Sensor accumulates is checked against the exact same rule its own reader
// will eventually apply — never merely relying on that later pass to drop
// what was accumulated here silently.
const mirrorMaxStringBytes = 512

func validRecordString(s string) bool {
	if len(s) > mirrorMaxStringBytes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// validObservation reports whether every string obs itself carries (Exe,
// each Listeners entry) passes validRecordString. A nil obs is always valid
// (there is nothing to check).
func validObservation(obs *evidence.ProcessObservation) bool {
	if obs == nil {
		return true
	}
	if !validRecordString(obs.Exe) {
		return false
	}
	for _, l := range obs.Listeners {
		if !validRecordString(l) {
			return false
		}
	}
	return true
}

// maxEntitiesPerGenerationAccum bounds how many distinct OS-package/
// unavailable/executable entities one generation accumulates in memory —
// deliberately lower than evidence's own per-generation limit
// (maxEntitiesPerGeneration, 50,000, unexported there), so a generation
// that would otherwise approach that ceiling is capped, and marked
// Truncated, well before writeSnapshot's own enforceWriteLimits ever has to
// intervene. Updating an already-recorded entity is never refused by this
// cap — only creating a new one is; a generation that reaches this many
// distinct entities keeps updating what it already has.
const maxEntitiesPerGenerationAccum = 40000

// entityCount returns how many distinct OS-package/unavailable/executable
// entities g currently holds.
func (g *generationState) entityCount() int {
	return len(g.osPackages) + len(g.unavailable) + len(g.executables)
}

// newGenerationState creates a fresh generationState. initialCoverage is the
// events_coverage value this generation starts at: evidence.CoverageSinceStart
// when the caller's Session already has eBPF attached and delivering events
// at the moment this generation is first discovered (eBPF is loaded once,
// at Sensor startup, strictly before the first discovery pass that could
// ever create a generation — so "attached before this generation started"
// is trivially true whenever events are attached at all), or
// evidence.CoverageNone when they are not. It only ever downgrades to
// CoveragePartial afterward (see recordEventLoss); nothing upgrades it back.
func newGenerationState(container evidence.ContainerRef, init InitProcess, now time.Time, initialCoverage evidence.EventsCoverage) *generationState {
	return &generationState{
		container:      container,
		init:           init,
		startedAt:      now,
		osPackages:     map[pkgKey]*evidence.OSPackageEvidence{},
		unavailable:    map[pkgKey]*evidence.UnavailablePackage{},
		executables:    map[string]*evidence.ExecutableEvidence{},
		eventsCoverage: initialCoverage,
		// lastAliveNsOK starts false (the zero value) — see that field's own
		// doc comment for why init.Starttime itself is never used as an
		// initial lastAliveNs.
	}
}

// genKey formats the generation key dbworker/dbHandler use on the wire —
// container ID, init host PID and init starttime — as one opaque, printable
// string (never parsed back apart; only ever compared for equality).
func genKey(containerID string, init InitProcess) string {
	return fmt.Sprintf("%s:%d:%d", containerID, init.PID, init.Starttime)
}

func (g *generationState) key() string { return genKey(g.container.ID, g.init) }

// lastGoodSample records that this generation completed a sample cycle
// without a fatal error at t: lastVerifiedAt advances, and lastSampleDenied
// records whether every process read attempted for this generation this
// sample was refused (procfs.OutcomeDenied) — a permission problem specific
// to this one container (e.g. an AppArmor policy mismatch), as opposed to a
// Sensor-wide one. Neither of these decides the published state by
// themselves; see derivePublishedState for how they combine with idxState,
// parseFailed and sampleStalled into evidence.GenerationState.
func (g *generationState) lastGoodSample(t time.Time, denied bool) {
	g.lastVerifiedAt = t
	g.lastSampleDenied = denied
}

// derivePublishedState is the one place that decides the
// evidence.GenerationState this generation currently reports, from the raw
// facts loop and the dbworker/sample-worker results it applies record on
// this type — nothing else ever sets a published state directly. Checked in
// priority order (most urgent first), since more than one condition can
// hold at once:
//
//  1. ended — terminal; nothing overrides it.
//  2. sampleStalled — this generation's own sample worker has overrun its
//     budget and loop is no longer waiting for it. This must never be
//     silently overwritten by an unrelated DB-side result (a build
//     succeeding or failing) that happens to be applied while it holds:
//     the reader treats StateStalled as withdrawing not-observed for
//     language packages the same way Incomplete does, which
//     StateParseFailed alone does not, so letting a DB result downgrade a
//     stalled generation to parse_failed would let it claim not_observed
//     verdicts this generation's own state does not actually support yet.
//  3. lastSampleDenied — a per-container permission problem (see
//     lastGoodSample's own doc comment).
//  4. len(parseFailed) > 0, or forceParseFailed (the parser itself died;
//     see that field's own doc comment) — this generation's own
//     package-database index has an outstanding failure.
//  5. idxState != indexReady, or (idxState == indexReady but
//     !postIndexConfirmed) — the index has not been resolved at all yet
//     (built, or confirmed absent/unsupported), or it has, but no sample
//     taken since has yet had its own candidates fully attributed against
//     it (see postIndexConfirmed's own doc comment) — either way, this
//     generation's own OSPackages cannot yet be trusted as a complete
//     picture, so it must not report observing, which is what tells a
//     reader an empty OSPackages list is itself confirmation of nothing in
//     use, not merely "not yet checked".
//  6. Otherwise, observing.
func derivePublishedState(g *generationState) evidence.GenerationState {
	switch {
	case g.ended:
		return evidence.StateEnded
	case g.sampleStalled:
		return evidence.StateStalled
	case g.lastSampleDenied:
		return evidence.StateDenied
	case len(g.parseFailed) > 0 || g.forceParseFailed:
		return evidence.StateParseFailed
	case g.idxState != indexReady || !g.postIndexConfirmed:
		return evidence.StateInitializing
	default:
		return evidence.StateObserving
	}
}

// recordOSPackage upserts kind into the OS package identified by (name,
// version), merging FirstSeen/LastSeen/Samples or Count as
// mergeKindObservation documents, and folds obs into that entity's
// same-sample/same-process observation list (capped, deduped) per
// mergeProcessObservation.
//
// A name, version or observation string that fails validRecordString/
// validObservation drops the whole call (name/version) or just the
// observation (obs) and marks the generation Incomplete instead — the same
// choice evidence's own reader makes for a record it decodes with a bad
// string (see filterOSPackageStrings there), applied here at the source so
// this Sensor never accumulates a record its own reader would later have
// silently dropped anyway. A generation that has already reached
// maxEntitiesPerGenerationAccum distinct entities refuses to create a new
// one (marking Truncated), but still updates one it already has.
func (g *generationState) recordOSPackage(name, version string, kind evidence.EvidenceKind, now time.Time, obs *evidence.ProcessObservation) {
	if !validRecordString(name) || !validRecordString(version) {
		g.incomplete = true
		return
	}
	if !validObservation(obs) {
		g.incomplete = true
		obs = nil
	}
	key := pkgKey{Name: name, Version: version}
	// A name+version that a previous sample recorded as ambiguous/replaced
	// (Unavailable) and this sample now resolves unambiguously replaces that
	// entry outright: an unavailable verdict for a version this generation
	// has since positively observed in use would be strictly wrong, not
	// merely stale.
	delete(g.unavailable, key)
	p, ok := g.osPackages[key]
	if !ok {
		if g.entityCount() >= maxEntitiesPerGenerationAccum {
			g.truncated = true
			return
		}
		p = &evidence.OSPackageEvidence{Name: name, Version: version, Kinds: map[evidence.EvidenceKind]evidence.KindObservation{}}
		g.osPackages[key] = p
	}
	mergeKindObservation(p.Kinds, kind, now, sampleKindOf(kind))
	if obs != nil {
		p.Observations = mergeProcessObservation(p.Observations, *obs)
	}
}

// recordUnavailableOSPackage records that (name, version) could not be
// judged this generation — an ambiguous owner, most commonly — unless a
// resolved OSPackageEvidence for the exact same key already exists (an
// in-use verdict from another observation this same generation must never
// be shadowed by a later ambiguous one for the same key). See
// recordOSPackage's own doc comment for the string-validation and
// entity-count rules applied identically here.
func (g *generationState) recordUnavailableOSPackage(name, version string, reason evidence.UnavailableReason) {
	if !validRecordString(name) || !validRecordString(version) {
		g.incomplete = true
		return
	}
	key := pkgKey{Name: name, Version: version}
	if _, ok := g.osPackages[key]; ok {
		return
	}
	if _, ok := g.unavailable[key]; !ok && g.entityCount() >= maxEntitiesPerGenerationAccum {
		g.truncated = true
		return
	}
	g.unavailable[key] = &evidence.UnavailablePackage{Name: name, Version: version, Reason: reason}
}

// recordExecutable upserts one observed executable (a process's own exe
// path), independent of whether it belongs to any OS package — see
// evidence.ExecutableEvidence's doc comment for why every observed
// executable is recorded here. See recordOSPackage's own doc comment for
// the string-validation and entity-count rules applied identically here.
func (g *generationState) recordExecutable(path, dev string, inode uint64, kind evidence.EvidenceKind, now time.Time, obs *evidence.ProcessObservation) {
	if !validRecordString(path) || !validRecordString(dev) {
		g.incomplete = true
		return
	}
	if !validObservation(obs) {
		g.incomplete = true
		obs = nil
	}
	e, ok := g.executables[path]
	if !ok {
		if g.entityCount() >= maxEntitiesPerGenerationAccum {
			g.truncated = true
			return
		}
		e = &evidence.ExecutableEvidence{Path: path, Kinds: map[evidence.EvidenceKind]evidence.KindObservation{}}
		g.executables[path] = e
	}
	if dev != "" {
		e.Dev = dev
		e.Inode = inode
	}
	mergeKindObservation(e.Kinds, kind, now, sampleKindOf(kind))
	if obs != nil {
		e.Observations = mergeProcessObservation(e.Observations, *obs)
	}
}

// sampleKindOf reports whether kind is sampling-derived (KindObservation.
// Samples) as opposed to event-derived (KindObservation.Count) — see
// events.go's applyUsageEvent for where an eBPF success event turns into a
// KindExecEvent/KindLibraryLoadEvent recordOSPackage/recordExecutable call.
// The distinction is centralized in this one function so every call site
// that merges a kind into an entity shares the same answer.
func sampleKindOf(kind evidence.EvidenceKind) bool {
	switch kind {
	case evidence.KindExe, evidence.KindMappedLibrary:
		return true
	default:
		return false
	}
}

// mergeKindObservation folds one occurrence of kind, seen at now, into
// kinds. sampling selects whether this occurrence increments Samples (once
// per distinct now — see maxOncePerInstant's doc comment) or Count.
func mergeKindObservation(kinds map[evidence.EvidenceKind]evidence.KindObservation, kind evidence.EvidenceKind, now time.Time, sampling bool) {
	k, ok := kinds[kind]
	if !ok {
		k = evidence.KindObservation{FirstSeen: now}
	}
	if sampling {
		// Incrementing only when LastSeen actually advances keeps Samples
		// meaning "how many distinct sampling passes observed this", not
		// "how many processes in one pass did" — recordOSPackage/
		// recordExecutable may be called more than once for the same entity
		// within a single sample (once per contributing process).
		if now.After(k.LastSeen) {
			k.Samples++
		}
	} else {
		k.Count++
	}
	if now.After(k.LastSeen) {
		k.LastSeen = now
	}
	kinds[kind] = k
}

// maxProcessObservations mirrors evidence's own per-entity cap
// (maxObservationsPerEntity, unexported there) so a live-built snapshot
// never has to be trimmed at write time to pass the reader's own validation.
const maxProcessObservations = 8

// mergeProcessObservation appends obs to existing, deduplicating an
// observation whose exposure/identity facts exactly match one already
// present (keeping the newer LastSeen), and capping the result at
// maxProcessObservations — dropping the oldest (by LastSeen) once the cap
// would be exceeded, so a very long-lived generation does not favor whichever
// eight combinations happened to occur first over ones seen more recently.
func mergeProcessObservation(existing []evidence.ProcessObservation, obs evidence.ProcessObservation) []evidence.ProcessObservation {
	for i, e := range existing {
		if sameProcessObservation(e, obs) {
			if obs.LastSeen.After(e.LastSeen) {
				existing[i].LastSeen = obs.LastSeen
			}
			return existing
		}
	}
	existing = append(existing, obs)
	if len(existing) <= maxProcessObservations {
		return existing
	}
	oldest := 0
	for i := 1; i < len(existing); i++ {
		if existing[i].LastSeen.Before(existing[oldest].LastSeen) {
			oldest = i
		}
	}
	return append(existing[:oldest], existing[oldest+1:]...)
}

func sameProcessObservation(a, b evidence.ProcessObservation) bool {
	if a.Exe != b.Exe || a.EffectiveUID != b.EffectiveUID || a.Userns != b.Userns || a.CapEff != b.CapEff {
		return false
	}
	if len(a.Listeners) != len(b.Listeners) {
		return false
	}
	for i := range a.Listeners {
		if a.Listeners[i] != b.Listeners[i] {
			return false
		}
	}
	return true
}

// maxParseRetryBackoff is the 24-hour cap the backoff schedule never
// exceeds, regardless of how many times the same input has failed.
const maxParseRetryBackoff = 24 * time.Hour

// parseFailureIn looks up an existing ParseFailure entry identified by
// (input, path) within failures, regardless of what content identity it
// currently records. A free function (not a generationState method) so
// runDBWorker (a different goroutine, working from an immutable snapshot of
// a generation's own failures handed to it in a dbJob) can apply the exact
// same lookup loop's own methods below use.
func parseFailureIn(failures []evidence.ParseFailure, input, path string) (evidence.ParseFailure, bool) {
	for _, pf := range failures {
		if pf.Input == input && pf.Path == path {
			return pf, true
		}
	}
	return evidence.ParseFailure{}, false
}

// shouldSkipForBackoff reports whether a file at (input, path) with the
// given content identity (dev, inode, size — the observer's own fstat of it
// right now) must not be sent to the parser yet, because the exact same
// input already failed and its retry_after has not arrived. A path whose
// current identity differs from whatever failed before is never skipped:
// a changed dev, inode or size means a different file replaced the one
// that failed, which is a new input to try immediately, not a continuation
// of the old backoff.
func shouldSkipForBackoff(failures []evidence.ParseFailure, input, path, dev string, inode uint64, size int64, now time.Time) bool {
	pf, ok := parseFailureIn(failures, input, path)
	if !ok {
		return false
	}
	if pf.Dev != dev || pf.Inode != inode || pf.Size != size {
		return false
	}
	return now.Before(pf.RetryAfter)
}

// recordParseFailure upserts a ParseFailure for one file rejected while
// building a package-database index, identified by (input, path) with the
// content identity (dev, inode, size) the observer's own fstat reported for
// it at open time. A repeat failure of the exact same identity doubles the
// previous backoff (FailedAt to RetryAfter), capped at maxParseRetryBackoff;
// any other case (first failure at this (input, path), or the same path now
// holding different content) starts a fresh schedule at 10x interval.
// failures is a pointer so both loop (applying a dbResult) and tests can
// update a generationState's own parseFailed slice in place.
func recordParseFailure(failures *[]evidence.ParseFailure, input, path, dev string, inode uint64, size int64, now time.Time, interval time.Duration) {
	for i := range *failures {
		pf := &(*failures)[i]
		if pf.Input != input || pf.Path != path {
			continue
		}
		if pf.Dev == dev && pf.Inode == inode && pf.Size == size {
			prevBackoff := pf.RetryAfter.Sub(pf.FailedAt)
			if prevBackoff <= 0 {
				prevBackoff = 10 * interval
			}
			backoff := prevBackoff * 2
			if backoff > maxParseRetryBackoff {
				backoff = maxParseRetryBackoff
			}
			pf.Count++
			pf.FailedAt = now
			pf.RetryAfter = now.Add(backoff)
			return
		}
		// A different file now sits at the same path: a new input,
		// discarding the old failure's count and schedule entirely.
		*pf = evidence.ParseFailure{
			Input: input, Path: path, Dev: dev, Inode: inode, Size: size,
			FailedAt: now, Count: 1, RetryAfter: now.Add(10 * interval),
		}
		return
	}
	*failures = append(*failures, evidence.ParseFailure{
		Input: input, Path: path, Dev: dev, Inode: inode, Size: size,
		FailedAt: now, Count: 1, RetryAfter: now.Add(10 * interval),
	})
}

// recordParseSuccess removes any outstanding ParseFailure for (input,
// path): this file was included in a build attempt and was not reported as
// failed this time.
func recordParseSuccess(failures *[]evidence.ParseFailure, input, path string) {
	if len(*failures) == 0 {
		return
	}
	out := (*failures)[:0]
	for _, pf := range *failures {
		if pf.Input == input && pf.Path == path {
			continue
		}
		out = append(out, pf)
	}
	*failures = out
}

// nextRetryTime returns the earliest RetryAfter among failures, or the zero
// Time when there are none.
func nextRetryTime(failures []evidence.ParseFailure) time.Time {
	var next time.Time
	for _, pf := range failures {
		if next.IsZero() || pf.RetryAfter.Before(next) {
			next = pf.RetryAfter
		}
	}
	return next
}

// The methods below bind the free functions above to this generationState's
// own parseFailed slice, for loop's own call sites and for tests.

func (g *generationState) parseFailureFor(input, path string) (evidence.ParseFailure, bool) {
	return parseFailureIn(g.parseFailed, input, path)
}

func (g *generationState) shouldSkipForBackoff(input, path, dev string, inode uint64, size int64, now time.Time) bool {
	return shouldSkipForBackoff(g.parseFailed, input, path, dev, inode, size, now)
}

func (g *generationState) recordParseFailure(input, path, dev string, inode uint64, size int64, now time.Time, interval time.Duration) {
	recordParseFailure(&g.parseFailed, input, path, dev, inode, size, now, interval)
}

func (g *generationState) recordParseSuccess(input, path string) {
	recordParseSuccess(&g.parseFailed, input, path)
}

func (g *generationState) nextRetryTime() time.Time {
	return nextRetryTime(g.parseFailed)
}

// toEvidence converts g's live, map-indexed bookkeeping into the slice shape
// evidence.Generation carries. Keys are not sorted here for determinism —
// notify/state consumers key on (name, version)/path themselves, and the
// evidence file's own reader never depends on array order — but tests that
// compare a whole Generation value do their own sorting.
func (g *generationState) toEvidence(hasPendingRouteEvent bool) evidence.Generation {
	gen := evidence.Generation{
		Container:      g.container,
		Init:           evidence.InitProcess{PID: g.init.PID, Starttime: g.init.Starttime},
		StartedAt:      g.startedAt,
		EndedAt:        g.endedAt,
		LastVerifiedAt: g.lastVerifiedAt,
		State:          derivePublishedState(g),
		PackageDB: evidence.PackageDBInfo{
			Kind:       g.packageDB.Kind,
			Status:     g.packageDB.Status,
			NoFileList: append([]string(nil), g.packageDB.NoFileList...),
		},
		// g.incomplete and g.candidatesLostPermanently are both sticky
		// (once true, this generation never claims full confidence again
		// this session); g.pendingLookup != nil, len(g.queuedCandidates) > 0,
		// len(g.pendingEvents) > 0, g.pendingMapsLookups > 0 and
		// g.pendingConfirms > 0 are all transient, but only clear once every
		// sample's own candidates (or every outstanding eBPF event) have
		// actually been looked up/verified/confirmed and had their answer
		// applied — a batch queued behind an outstanding lookup is folded
		// into the next one rather than dropped (see queuedCandidates' own
		// doc comment), and an event still sitting in pendingEvents, still
		// in flight via a maps fallback lookup, or still waiting on its own
		// candidate generation's liveness to be confirmed (genconfirm.go) is
		// exactly a "was this file used" answer that could still resolve to
		// "yes" — so this write must not claim full attribution confidence
		// while any of these seven still holds, even though one may already
		// have cleared by the time the *next* snapshot is built.
		//
		// hasPendingRouteEvent (pendingRouteEventGating, computed once per
		// snapshot in buildSnapshot) covers the one gap none of g's own
		// fields can: an eBPF event this session has not yet even been able
		// to place in any specific generation at all — still sitting in the
		// Session-wide pendingRouteEvents queue — but that either names this
		// generation's own container ID specifically, or cannot be
		// classified to any container at all right now (in which case it
		// could still turn out to belong to *any* live generation, this one
		// included — see pendingRouteEventGating's own doc comment). Such an
		// event could still turn out, once resolved, to belong to exactly
		// this generation; a not_observed verdict published in the meantime
		// would understate what this generation may yet turn out to have
		// used.
		Incomplete: g.incomplete || g.pendingLookup != nil || len(g.queuedCandidates) > 0 ||
			g.candidatesLostPermanently || len(g.pendingEvents) > 0 || g.pendingMapsLookups > 0 ||
			g.pendingConfirms > 0 || hasPendingRouteEvent,
		Truncated:      g.truncated,
		EventsCoverage: g.eventsCoverage,
		EventsLost:     g.eventsLost,
		ParseFailed:    append([]evidence.ParseFailure(nil), g.parseFailed...),
	}
	// Every field copied below is deep, not shallow: loop keeps mutating
	// g's own osPackages/executables (their Kinds maps via
	// mergeKindObservation, their Observations slices via
	// mergeProcessObservation) on later samples, concurrently with the
	// writer goroutine this Generation value is handed to marshaling it —
	// a shallow *p/*e copy would still share those two fields' own backing
	// map/array with the live generationState, which is exactly the
	// "concurrent map read and map write"/data-race shape toEvidence
	// exists to avoid. UnavailablePackage carries no map or slice field, so
	// a plain value copy is already independent.
	for _, p := range g.osPackages {
		gen.OSPackages = append(gen.OSPackages, cloneOSPackage(*p))
	}
	for _, u := range g.unavailable {
		gen.Unavailable = append(gen.Unavailable, *u)
	}
	for _, e := range g.executables {
		gen.Executables = append(gen.Executables, cloneExecutable(*e))
	}
	return gen
}

// cloneOSPackage returns p with its own Kinds map and Observations slice
// replaced by independent copies — see toEvidence's own doc comment.
func cloneOSPackage(p evidence.OSPackageEvidence) evidence.OSPackageEvidence {
	p.Kinds = cloneKindsMap(p.Kinds)
	p.Observations = cloneObservations(p.Observations)
	return p
}

// cloneExecutable returns e with its own Kinds map and Observations slice
// replaced by independent copies — see toEvidence's own doc comment.
func cloneExecutable(e evidence.ExecutableEvidence) evidence.ExecutableEvidence {
	e.Kinds = cloneKindsMap(e.Kinds)
	e.Observations = cloneObservations(e.Observations)
	return e
}

func cloneKindsMap(kinds map[evidence.EvidenceKind]evidence.KindObservation) map[evidence.EvidenceKind]evidence.KindObservation {
	if kinds == nil {
		return nil
	}
	out := make(map[evidence.EvidenceKind]evidence.KindObservation, len(kinds))
	for k, v := range kinds {
		out[k] = v
	}
	return out
}

// cloneObservations copies obs itself and, since ProcessObservation's own
// Listeners field is a slice, each entry's Listeners too.
func cloneObservations(obs []evidence.ProcessObservation) []evidence.ProcessObservation {
	if obs == nil {
		return nil
	}
	out := make([]evidence.ProcessObservation, len(obs))
	copy(out, obs)
	for i := range out {
		out[i].Listeners = append([]string(nil), out[i].Listeners...)
	}
	return out
}
