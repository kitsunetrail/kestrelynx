package sensor

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// newWriteGateTestSession builds a Session ready to exercise
// requestWrite/resumeDeferredWrite through handleSampleEnvelope/applyDBResult
// exactly the way loop's own select does, without needing a real dbworker or
// writer goroutine: dbJobCh only ever needs to accept the one lookup job
// submitCandidateBatches sends (nothing in these tests ever drains it), and
// writerCh only ever needs to hold the one snapshot a given assertion checks.
func newWriteGateTestSession() *Session {
	return &Session{
		cfg:              Config{Interval: time.Hour},
		now:              time.Now,
		generations:      map[string]*generationState{},
		dbJobCh:          make(chan dbJob, 8),
		writerCh:         make(chan writerJob, 1),
		writerReportCh:   make(chan writeReport, 1),
		lookupWaitBudget: time.Hour, // long enough to never fire during a test that expects to resolve via the answer path instead
	}
}

// newLookupReadyGeneration returns a generationState already past its own
// package-database build, the same starting point
// TestApplySampleResult_OutstandingLookupWithholdsIncompleteNotObserved and
// TestPostIndexConfirmed_WithholdsNotObservedUntilFirstPostReadyLookup both
// use, registered on s.
func newLookupReadyGeneration(s *Session, containerByte byte) *generationState {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64(containerByte)}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	g.idxState = indexReady
	g.postIndexConfirmed = true
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}
	s.generations[g.key()] = g
	return g
}

func candidateSample(genKey, path string) sampleResult {
	return sampleResult{
		genKey: genKey, attempted: 1, succeeded: 1, indexReadyAtStart: true,
		candidates: map[string][]sampleCandidate{path: {{kind: evidence.KindMappedLibrary}}},
		verified:   []string{path},
	}
}

// TestRequestWrite_NoCandidatesWritesImmediately covers requestWrite's own
// fast path: a sample result that produced no package-database lookup at
// all (applySampleResult never sets g.pendingLookup) must be written right
// away, exactly as if requestWrite did not exist.
func TestRequestWrite_NoCandidatesWritesImmediately(t *testing.T) {
	s := newWriteGateTestSession()
	g := newLookupReadyGeneration(s, 'a')

	s.handleSampleEnvelope(sampleEnvelope{kind: sampleEnvResult, genKey: g.key(), result: sampleResult{genKey: g.key(), attempted: 1, succeeded: 1}})

	select {
	case <-s.writerCh:
	default:
		t.Fatalf("no snapshot was written for a sample result with no candidates at all")
	}
	if s.writePending {
		t.Errorf("writePending = true after a no-candidate sample result, want false — there was never anything to wait for")
	}
}

// TestRequestWrite_DefersSampleTriggeredWriteUntilLookupAnswers is this
// round's own central regression test: a sample that produces a candidate
// must not have its own triggered write happen before that candidate's
// lookup has actually answered — writing at that exact moment, every time,
// is what previously made every steady-state write report Incomplete=true.
// Once the lookup answers and loop's own dbResultCh case calls
// resumeDeferredWrite (exercised directly here, the same way loop's real
// select does), exactly one snapshot is written, and it already reflects the
// resolved package — not a second, earlier write left showing the gap.
func TestRequestWrite_DefersSampleTriggeredWriteUntilLookupAnswers(t *testing.T) {
	s := newWriteGateTestSession()
	g := newLookupReadyGeneration(s, 'a')
	const path = "/usr/lib/libssl.so.3"

	s.handleSampleEnvelope(sampleEnvelope{kind: sampleEnvResult, genKey: g.key(), result: candidateSample(g.key(), path)})

	select {
	case <-s.writerCh:
		t.Fatalf("a snapshot was written before the sample's own lookup answered, want it held back")
	default:
	}
	if !s.writePending {
		t.Fatalf("writePending = false while a lookup is outstanding, want true")
	}
	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil, want the sample's own lookup outstanding")
	}

	// The lookup answers — loop's own dbResultCh case would call exactly
	// these two methods, in this order.
	if fatal := s.applyDBResult(dbResult{
		kind: dbJobLookup, genKey: g.key(), seq: g.pendingLookup.seq,
		owners: map[string]lookupOutcome{path: {owners: []lookupOwner{{Name: "openssl", Version: "3.0.11"}}}},
	}); fatal != nil {
		t.Fatalf("applyDBResult: %v", fatal)
	}
	s.resumeDeferredWrite()

	if s.writePending {
		t.Errorf("writePending = true after the only outstanding lookup answered, want false")
	}
	select {
	case job := <-s.writerCh:
		if len(job.snap.Generations) != 1 {
			t.Fatalf("snapshot has %d generations, want 1", len(job.snap.Generations))
		}
		gen := job.snap.Generations[0]
		if gen.Incomplete {
			t.Errorf("Incomplete = true once the sample's own lookup has answered, want false")
		}
		if len(gen.OSPackages) != 1 || gen.OSPackages[0].Name != "openssl" {
			t.Errorf("OSPackages = %+v, want exactly one entry for openssl", gen.OSPackages)
		}
	default:
		t.Fatal("no snapshot was written after the outstanding lookup answered")
	}
}

// TestRequestWrite_BudgetExceededForcesWriteThenRecoversOnNextWrite covers
// the fallback half of requestWrite: a lookup that has not answered within
// lookupWaitBudget must not hold a write back forever — the deferred write
// happens anyway once the budget elapses, and that one write (only that one)
// reports Incomplete=true for the generation whose lookup is still
// outstanding. Once the answer does arrive, Incomplete is not corrected
// retroactively (the write already happened) but the *next* write reflects
// it — see resumeDeferredWrite's own doc comment for why a late answer, on
// its own, never triggers a write by itself once nothing is pending anymore.
func TestRequestWrite_BudgetExceededForcesWriteThenRecoversOnNextWrite(t *testing.T) {
	s := newWriteGateTestSession()
	s.lookupWaitBudget = 20 * time.Millisecond
	g := newLookupReadyGeneration(s, 'a')
	const path = "/usr/lib/libssl.so.3"

	// requestWrite is exactly what loop's own heartbeatTicker case calls —
	// exercised directly here to cover "a heartbeat arrives while a
	// sample-triggered lookup is still outstanding" without needing a real
	// loop goroutine.
	s.handleSampleEnvelope(sampleEnvelope{kind: sampleEnvResult, genKey: g.key(), result: candidateSample(g.key(), path)})
	s.requestWrite() // standing in for a heartbeat tick landing mid-wait; must not start a second, independent wait

	select {
	case <-s.writeDelayCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("writeDelayCh never fired within lookupWaitBudget (%s)", s.lookupWaitBudget)
	}
	// loop's own writeDelayCh case does exactly this.
	s.writePending = false
	s.writeDelayCh = nil
	s.writeSnapshotNow(s.computeStatus())

	select {
	case job := <-s.writerCh:
		if len(job.snap.Generations) != 1 || !job.snap.Generations[0].Incomplete {
			t.Fatalf("forced write's own generation = %+v, want exactly one generation with Incomplete=true (the still-outstanding lookup)", job.snap.Generations)
		}
	default:
		t.Fatal("no snapshot was written once the budget elapsed")
	}

	// The answer finally arrives — late, but not lost: resumeDeferredWrite
	// itself is a no-op now (writePending is already false, nothing left to
	// resume), so this alone must not write a second snapshot.
	if fatal := s.applyDBResult(dbResult{
		kind: dbJobLookup, genKey: g.key(), seq: g.pendingLookup.seq,
		owners: map[string]lookupOutcome{path: {owners: []lookupOwner{{Name: "openssl", Version: "3.0.11"}}}},
	}); fatal != nil {
		t.Fatalf("applyDBResult: %v", fatal)
	}
	s.resumeDeferredWrite()
	select {
	case <-s.writerCh:
		t.Fatalf("resumeDeferredWrite wrote a snapshot with nothing pending, want it to stay a no-op until the next real write")
	default:
	}

	// The next write (a later heartbeat, in production) finally reports the
	// now-resolved generation as complete.
	s.writeSnapshotNow(s.computeStatus())
	select {
	case job := <-s.writerCh:
		if len(job.snap.Generations) != 1 || job.snap.Generations[0].Incomplete {
			t.Errorf("next write's own generation = %+v, want Incomplete=false now that the late answer has been applied", job.snap.Generations)
		}
	default:
		t.Fatal("no snapshot was written for the next write")
	}
}

// TestExpirePendingLookup_WithinTTLLeavesItAlone confirms
// expirePendingLookup is a no-op for a lookup that is merely slow, not lost
// — the counterpart to TestExpirePendingLookup_ExceedsTTLDropsItSticky below.
func TestExpirePendingLookup_WithinTTLLeavesItAlone(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	submittedAt := time.Unix(1000, 0)
	g.pendingLookup = &pendingLookup{epoch: 0, submittedAt: submittedAt}

	g.expirePendingLookup(submittedAt.Add(pendingLookupTTL - time.Second))

	if g.pendingLookup == nil {
		t.Errorf("pendingLookup = nil before its own TTL elapsed, want it left alone")
	}
	if g.candidatesLostPermanently {
		t.Errorf("candidatesLostPermanently = true before the TTL elapsed, want false")
	}
}

// TestExpirePendingLookup_ExceedsTTLDropsItSticky covers invariant 3 of this
// round's own fix: a lookup answer that is genuinely never coming back (the
// dbworker goroutine gone, or its result otherwise lost) must not leave
// pendingLookup set forever — once pendingLookupTTL has elapsed,
// pendingLookup and any batches queued behind it are given up on for good
// (candidatesLostPermanently, sticky), and a subsequent answer for that
// exact lookup (applyLookupResult, keyed only by g.pendingLookup being
// non-nil) is silently discarded rather than resurrecting it.
func TestExpirePendingLookup_ExceedsTTLDropsItSticky(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	submittedAt := time.Unix(1000, 0)
	const path = "/usr/lib/libssl.so.3"
	g.pendingLookup = &pendingLookup{
		epoch:       0,
		submittedAt: submittedAt,
		batches: []candidateBatch{{
			candidates: map[string][]sampleCandidate{path: {{kind: evidence.KindMappedLibrary}}},
			verified:   []string{path},
		}},
	}
	g.queuedCandidates = []candidateBatch{{verified: []string{"/usr/lib/libother.so"}}}

	g.expirePendingLookup(submittedAt.Add(pendingLookupTTL + time.Second))

	if g.pendingLookup != nil {
		t.Errorf("pendingLookup = %+v after exceeding its own TTL, want nil", g.pendingLookup)
	}
	if len(g.queuedCandidates) != 0 {
		t.Errorf("queuedCandidates = %+v after the lookup they were waiting behind expired, want empty (lost, not left stranded)", g.queuedCandidates)
	}
	if !g.candidatesLostPermanently {
		t.Errorf("candidatesLostPermanently = false after the TTL elapsed, want true (sticky)")
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false after candidatesLostPermanently was set, want true")
	}

	// A late answer for the exact lookup that just expired must not be
	// adopted — applyLookupResult's own pl == nil guard already covers this
	// (pendingLookup is nil now), exercised here end to end.
	s := newWriteGateTestSession()
	s.generations[g.key()] = g
	s.applyLookupResult(g, dbResult{
		genKey: g.key(),
		owners: map[string]lookupOutcome{path: {owners: []lookupOwner{{Name: "openssl", Version: "3.0.11"}}}},
	})
	if len(g.osPackages) != 0 {
		t.Errorf("osPackages = %+v after a late answer for an already-expired lookup, want it discarded, not adopted", g.osPackages)
	}
}

// TestApplyLookupResult_ExpiredLookupsDelayedAnswerNeverAppliesToItsReplacement
// covers a narrower race than TestExpirePendingLookup_ExceedsTTLDropsItSticky
// above: there, the abandoned lookup's own late answer arrives with nothing
// else outstanding (pendingLookup already nil, so pl == nil already refuses
// it). Here, a *fresh* lookup has already been submitted in the expired
// one's place by the time the expired one's own delayed answer shows up —
// exactly the shape pendingLookupTTL exists to survive: the TTL only bounds
// how long loop waits, never what the dbworker goroutine is still actually
// doing with the abandoned job already in flight to the parser. Without
// res.seq, applyLookupResult would match on g.pendingLookup being non-nil
// alone and wrongly adopt the abandoned lookup's own answer as the fresh
// one's, corrupting the fresh lookup's own attribution and clearing
// g.pendingLookup out from under its own still-outstanding answer.
func TestApplyLookupResult_ExpiredLookupsDelayedAnswerNeverAppliesToItsReplacement(t *testing.T) {
	s := newWriteGateTestSession()
	g := newLookupReadyGeneration(s, 'a')
	const pathA = "/usr/lib/libssl.so.3"
	const pathB = "/usr/lib/libcrypto.so.3"

	// Lookup A is submitted, then abandoned by expirePendingLookup once
	// pendingLookupTTL has elapsed.
	s.handleSampleEnvelope(sampleEnvelope{kind: sampleEnvResult, genKey: g.key(), result: candidateSample(g.key(), pathA)})
	if g.pendingLookup == nil {
		t.Fatalf("setup: pendingLookup = nil after submitting lookup A, want it outstanding")
	}
	seqA := g.pendingLookup.seq
	g.expirePendingLookup(g.pendingLookup.submittedAt.Add(pendingLookupTTL + time.Second))
	if g.pendingLookup != nil {
		t.Fatalf("setup: pendingLookup = %+v after lookup A's own TTL elapsed, want nil", g.pendingLookup)
	}

	// A fresh lookup B is submitted in A's place, for a different path —
	// exactly what a later sample's own candidate would trigger.
	s.handleSampleEnvelope(sampleEnvelope{kind: sampleEnvResult, genKey: g.key(), result: candidateSample(g.key(), pathB)})
	if g.pendingLookup == nil {
		t.Fatalf("setup: pendingLookup = nil after submitting lookup B, want it outstanding")
	}
	seqB := g.pendingLookup.seq
	if seqB == seqA {
		t.Fatalf("setup: lookup B's own seq (%d) equals abandoned lookup A's (%d), want them distinct", seqB, seqA)
	}

	// Lookup A's own delayed answer finally arrives from the dbworker,
	// naming A's own (now-abandoned) seq.
	if fatal := s.applyDBResult(dbResult{
		kind: dbJobLookup, genKey: g.key(), seq: seqA,
		owners: map[string]lookupOutcome{pathA: {owners: []lookupOwner{{Name: "openssl", Version: "3.0.11"}}}},
	}); fatal != nil {
		t.Fatalf("applyDBResult(A): %v", fatal)
	}
	if len(g.osPackages) != 0 {
		t.Errorf("osPackages = %+v after lookup A's own delayed answer, want it discarded entirely (never adopted as lookup B's)", g.osPackages)
	}
	if g.pendingLookup == nil || g.pendingLookup.seq != seqB {
		t.Fatalf("pendingLookup = %+v after lookup A's own delayed answer, want lookup B (seq=%d) left untouched and still outstanding", g.pendingLookup, seqB)
	}

	// Lookup B's own real answer arrives next, correctly naming its own seq
	// — this one must resolve normally.
	if fatal := s.applyDBResult(dbResult{
		kind: dbJobLookup, genKey: g.key(), seq: seqB,
		owners: map[string]lookupOutcome{pathB: {owners: []lookupOwner{{Name: "openssl", Version: "3.0.11"}}}},
	}); fatal != nil {
		t.Fatalf("applyDBResult(B): %v", fatal)
	}
	if _, ok := g.osPackages[pkgKey{Name: "openssl", Version: "3.0.11"}]; !ok {
		t.Errorf("osPackages = %+v after lookup B's own correctly-seq'd answer, want openssl recorded", g.osPackages)
	}
	if g.pendingLookup != nil {
		t.Errorf("pendingLookup = %+v after lookup B's own answer was applied, want nil", g.pendingLookup)
	}
}
