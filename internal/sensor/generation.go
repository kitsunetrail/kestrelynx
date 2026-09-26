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

func newGenerationState(container evidence.ContainerRef, init InitProcess, now time.Time) *generationState {
	return &generationState{
		container:   container,
		init:        init,
		startedAt:   now,
		osPackages:  map[pkgKey]*evidence.OSPackageEvidence{},
		unavailable: map[pkgKey]*evidence.UnavailablePackage{},
		executables: map[string]*evidence.ExecutableEvidence{},
		// Explicit, not the zero value: eBPF event consumption does not
		// exist in this package yet (see sampleKindOf's own doc comment), so
		// no generation can claim any degree of event coverage — it is
		// always exactly "none", never merely unset.
		eventsCoverage: evidence.CoverageNone,
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
// Samples) as opposed to event-derived (KindObservation.Count). Nothing in
// this package produces an event kind (exec_event, library_load_event) yet:
// no code here reads eBPF events at all. The distinction is centralized in
// this one function so that whatever eventually turns an eBPF event into
// evidence only has to add cases here, not touch every call site that
// already merges a kind into an entity.
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
func (g *generationState) toEvidence() evidence.Generation {
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
		// this session); g.pendingLookup != nil and len(g.queuedCandidates)
		// > 0 are transient, but only clear once every sample's own
		// candidates have actually been looked up and had their answer
		// applied — a batch queued behind an outstanding lookup is folded
		// into the next one rather than dropped (see queuedCandidates' own
		// doc comment), so this write must not claim full attribution
		// confidence while any of the four still holds, even though one may
		// already have cleared by the time the *next* snapshot is built.
		Incomplete:     g.incomplete || g.pendingLookup != nil || len(g.queuedCandidates) > 0 || g.candidatesLostPermanently,
		Truncated:      g.truncated,
		EventsCoverage: g.eventsCoverage,
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
