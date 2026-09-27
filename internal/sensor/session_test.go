package sensor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func newTestSession() *Session {
	return &Session{
		cfg:            Config{Interval: 30 * time.Second},
		now:            time.Now,
		heartbeatEvery: heartbeatInterval,
		generations:    map[string]*generationState{},
		dbJobCh:        make(chan dbJob, 8), // reconcileGenerations' endGeneration calls submitDBJob; must not block
	}
}

func TestReconcileGenerations_CreatesNewGeneration(t *testing.T) {
	s := newTestSession()
	now := time.Unix(1000, 0)
	groups := map[string]containerGroup{
		strings64('a'): {ContainerID: strings64('a'), Processes: []InitProcess{{PID: 10, Starttime: 5}}, Init: InitProcess{PID: 10, Starttime: 5}},
	}
	s.reconcileGenerations(groups, now)

	if len(s.generations) != 1 {
		t.Fatalf("len(generations) = %d, want 1", len(s.generations))
	}
	for _, g := range s.generations {
		if derivePublishedState(g) != evidence.StateInitializing {
			t.Errorf("new generation state = %q, want initializing", derivePublishedState(g))
		}
		if g.init.PID != 10 {
			t.Errorf("init.PID = %d, want 10", g.init.PID)
		}
	}
}

func TestReconcileGenerations_RestartCreatesNewGenerationAndEndsOld(t *testing.T) {
	s := newTestSession()
	now := time.Unix(1000, 0)
	cid := strings64('a')
	groups := map[string]containerGroup{
		cid: {ContainerID: cid, Processes: []InitProcess{{PID: 10, Starttime: 5}}, Init: InitProcess{PID: 10, Starttime: 5}},
	}
	s.reconcileGenerations(groups, now)
	var firstKey string
	for k := range s.generations {
		firstKey = k
	}

	// The container restarted: same ID, new init (different PID/starttime).
	later := now.Add(time.Minute)
	groups[cid] = containerGroup{ContainerID: cid, Processes: []InitProcess{{PID: 20, Starttime: 999}}, Init: InitProcess{PID: 20, Starttime: 999}}
	s.reconcileGenerations(groups, later)

	if len(s.generations) != 2 {
		t.Fatalf("len(generations) = %d, want 2 (old ended, new created)", len(s.generations))
	}
	old := s.generations[firstKey]
	if !old.ended {
		t.Errorf("old generation ended = false, want true")
	}
	if old.endedAt == nil || !old.endedAt.Equal(later) {
		t.Errorf("old generation endedAt = %v, want %v", old.endedAt, later)
	}
}

func TestReconcileGenerations_ContainerGoneEndsGeneration(t *testing.T) {
	s := newTestSession()
	now := time.Unix(1000, 0)
	cid := strings64('a')
	groups := map[string]containerGroup{
		cid: {ContainerID: cid, Processes: []InitProcess{{PID: 10, Starttime: 5}}, Init: InitProcess{PID: 10, Starttime: 5}},
	}
	s.reconcileGenerations(groups, now)

	s.reconcileGenerations(map[string]containerGroup{}, now.Add(time.Minute))

	for _, g := range s.generations {
		if !g.ended {
			t.Errorf("generation ended = false, want true once its container disappears")
		}
	}
}

func TestReconcileGenerations_SameInitDoesNotChurn(t *testing.T) {
	s := newTestSession()
	now := time.Unix(1000, 0)
	cid := strings64('a')
	groups := map[string]containerGroup{
		cid: {ContainerID: cid, Processes: []InitProcess{{PID: 10, Starttime: 5}}, Init: InitProcess{PID: 10, Starttime: 5}},
	}
	s.reconcileGenerations(groups, now)
	s.generations[genKey(cid, InitProcess{PID: 10, Starttime: 5})].idxState = indexReady // simulate progress

	s.reconcileGenerations(groups, now.Add(30*time.Second))

	if len(s.generations) != 1 {
		t.Fatalf("len(generations) = %d, want 1 (same generation continues)", len(s.generations))
	}
	g := s.generations[genKey(cid, InitProcess{PID: 10, Starttime: 5})]
	if g.idxState != indexReady {
		t.Errorf("idxState was reset even though the generation did not change")
	}
}

func TestPruneEndedGenerations_RemovesOnlyAfterRetention(t *testing.T) {
	s := newTestSession()
	now := time.Unix(1000, 0)
	old := now.Add(-endedRetention - time.Hour)
	recent := now.Add(-time.Hour)

	g1 := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, now, evidence.CoverageNone)
	g1.ended = true
	g1.endedAt = &old
	s.generations[g1.key()] = g1

	g2 := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('b')}, InitProcess{PID: 2, Starttime: 2}, now, evidence.CoverageNone)
	g2.ended = true
	g2.endedAt = &recent
	s.generations[g2.key()] = g2

	s.pruneEndedGenerations(now)

	if _, ok := s.generations[g1.key()]; ok {
		t.Errorf("generation ended beyond the retention window was not pruned")
	}
	if _, ok := s.generations[g2.key()]; !ok {
		t.Errorf("generation ended recently was pruned too early")
	}
}

// TestComputeStatus exercises every documented permission/failure condition
// that has a SensorInfo.Status value at all — see (*Session).computeStatus's
// own doc comment for exactly which ones those are and in what priority
// order.
func TestComputeStatus(t *testing.T) {
	newSessionWith := func(isolation evidence.SensorStatus, sysptrace, dac bool) *Session {
		return &Session{
			isolationStatus: isolation, capSysPtraceOK: sysptrace, capDacReadSearchOK: dac,
			generations: map[string]*generationState{},
		}
	}
	addGen := func(s *Session, id string, state evidence.GenerationState, sampled bool) {
		g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: id}, InitProcess{PID: 1}, time.Unix(0, 0), evidence.CoverageNone)
		switch state {
		case evidence.StateDenied:
			g.lastSampleDenied = true
		case evidence.StateObserving:
			g.idxState = indexReady
			g.postIndexConfirmed = true
		case evidence.StateInitializing:
			// the zero-value idxState (indexIdle) already reports initializing
		default:
			t.Fatalf("addGen: unsupported state %q for this test's own helper", state)
		}
		if sampled {
			g.lastVerifiedAt = time.Unix(1, 0)
		}
		s.generations[id] = g
	}

	t.Run("isolation_failed sticks regardless of everything else", func(t *testing.T) {
		s := newSessionWith(evidence.SensorIsolationFailed, true, true)
		if got := s.computeStatus(); got != evidence.SensorIsolationFailed {
			t.Errorf("computeStatus() = %q, want isolation_failed", got)
		}
	})
	t.Run("isolation_degraded sticks", func(t *testing.T) {
		s := newSessionWith(evidence.SensorIsolationDegraded, true, true)
		if got := s.computeStatus(); got != evidence.SensorIsolationDegraded {
			t.Errorf("computeStatus() = %q, want isolation_degraded", got)
		}
	})
	t.Run("CAP_SYS_PTRACE missing at startup -> permission_denied, even with no generations at all", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, false, true)
		if got := s.computeStatus(); got != evidence.SensorPermissionDenied {
			t.Errorf("computeStatus() = %q, want permission_denied", got)
		}
	})
	t.Run("every sampled live generation denied -> permission_denied", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, true)
		addGen(s, strings64('a'), evidence.StateDenied, true)
		addGen(s, strings64('b'), evidence.StateDenied, true)
		if got := s.computeStatus(); got != evidence.SensorPermissionDenied {
			t.Errorf("computeStatus() = %q, want permission_denied", got)
		}
	})
	t.Run("a partial denial rate is not a blanket permission problem", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, true)
		addGen(s, strings64('a'), evidence.StateDenied, true)
		addGen(s, strings64('b'), evidence.StateObserving, true)
		if got := s.computeStatus(); got != evidence.SensorOK {
			t.Errorf("computeStatus() = %q, want ok", got)
		}
	})
	t.Run("a generation never yet sampled does not count either way", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, true)
		addGen(s, strings64('a'), evidence.StateInitializing, false)
		if got := s.computeStatus(); got != evidence.SensorOK {
			t.Errorf("computeStatus() = %q, want ok", got)
		}
	})
	t.Run("CAP_DAC_READ_SEARCH missing -> degraded", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, false)
		if got := s.computeStatus(); got != evidence.SensorDegraded {
			t.Errorf("computeStatus() = %q, want degraded", got)
		}
	})
	t.Run("build queue stalled -> degraded", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, true)
		s.buildQueueStalled = true
		if got := s.computeStatus(); got != evidence.SensorDegraded {
			t.Errorf("computeStatus() = %q, want degraded", got)
		}
	})
	t.Run("consecutive write failures -> degraded", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, true)
		s.writeFailureStreak = writeFailureDegradeThreshold
		if got := s.computeStatus(); got != evidence.SensorDegraded {
			t.Errorf("computeStatus() = %q, want degraded", got)
		}
	})
	t.Run("the last write needed trimming -> degraded", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, true)
		s.lastWriteModified = true
		if got := s.computeStatus(); got != evidence.SensorDegraded {
			t.Errorf("computeStatus() = %q, want degraded", got)
		}
	})
	t.Run("isolation_failed outranks a capability signal", func(t *testing.T) {
		s := newSessionWith(evidence.SensorIsolationFailed, false, false)
		if got := s.computeStatus(); got != evidence.SensorIsolationFailed {
			t.Errorf("computeStatus() = %q, want isolation_failed", got)
		}
	})
	t.Run("permission_denied outranks a mere degradation", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, false, false)
		if got := s.computeStatus(); got != evidence.SensorPermissionDenied {
			t.Errorf("computeStatus() = %q, want permission_denied", got)
		}
	})
	t.Run("nothing wrong at all -> ok", func(t *testing.T) {
		s := newSessionWith(evidence.SensorOK, true, true)
		if got := s.computeStatus(); got != evidence.SensorOK {
			t.Errorf("computeStatus() = %q, want ok", got)
		}
	})
}

// TestLastGoodSample_PerContainerDenialSetsStateDenied covers a permission
// problem specific to one container (e.g. an AppArmor policy mismatch): a
// generation whose reads were all refused this sample becomes StateDenied —
// a per-generation signal distinct from computeStatus's Sensor-wide
// SensorPermissionDenied, so one such container does not make every other,
// unaffected container look denied too.
func TestLastGoodSample_PerContainerDenialSetsStateDenied(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	g.idxState = indexReady
	g.postIndexConfirmed = true // would otherwise progress to StateObserving; this test is about denial, not the separate post-ready confirmation window
	g.lastGoodSample(time.Unix(100, 0), true)
	if derivePublishedState(g) != evidence.StateDenied {
		t.Errorf("state = %q, want denied", derivePublishedState(g))
	}

	// A later sample that is no longer fully denied recovers normally.
	g.lastGoodSample(time.Unix(200, 0), false)
	if derivePublishedState(g) != evidence.StateObserving {
		t.Errorf("state = %q, want observing once reads succeed again", derivePublishedState(g))
	}
}

// TestWriteParseFailedAndExit_MarksActiveGenerationsParseFailed covers the
// parser process dying: every generation that had not already ended is
// marked StateParseFailed before this Sensor session's own final evidence
// write, so the main body's own display picks up parse_failed for every
// generation this session was still tracking.
func TestWriteParseFailedAndExit_MarksActiveGenerationsParseFailed(t *testing.T) {
	s := newTestSession()
	f, err := os.CreateTemp(t.TempDir(), "procfs.json")
	if err != nil {
		t.Fatalf("create temp evidence file: %v", err)
	}
	defer f.Close()
	s.evidenceFD = int(f.Fd())
	s.writerCh = make(chan writerJob, 1)
	s.writerReportCh = make(chan writeReport, 1)
	go runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)

	active := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	active.idxState = indexReady
	s.generations[active.key()] = active

	endedAt := time.Unix(1, 0)
	ended := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('b')}, InitProcess{PID: 2, Starttime: 2}, time.Unix(0, 0), evidence.CoverageNone)
	ended.ended = true
	ended.endedAt = &endedAt
	s.generations[ended.key()] = ended

	// No separate wait on s.writerReportCh here, deliberately: unlike an
	// earlier version of this test, which could not have told a genuinely
	// synchronous writeParseFailedAndExit apart from one that only queues
	// the write and returns immediately (both would pass a test that
	// merely waited on the write itself afterward), writeParseFailedAndExit
	// now blocks internally until its own write actually lands (see
	// writeFinalSnapshotAndWait) — so reading the underlying file's own
	// bytes back immediately after this call returns, with nothing else in
	// between, is what actually exercises that guarantee.
	s.writeParseFailedAndExit(errors.New("parser connection lost"))

	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek evidence file: %v", err)
	}
	written, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read back evidence file: %v", err)
	}
	if !strings.Contains(string(written), string(evidence.StateParseFailed)) {
		t.Fatalf("evidence file does not yet contain %q immediately after writeParseFailedAndExit returned — the write must be complete by then, not merely queued", evidence.StateParseFailed)
	}

	if derivePublishedState(active) != evidence.StateParseFailed {
		t.Errorf("active generation state = %q, want parse_failed", derivePublishedState(active))
	}
	if !ended.ended {
		t.Errorf("already-ended generation ended = false, want it left as ended")
	}
}

// TestLoop_HeartbeatTickerUpdatesWithoutSampling confirms heartbeat_at is
// updated at least every heartbeatEvery even when nothing else has
// changed: with --interval much longer than the (test-shortened)
// heartbeatEvery, the evidence file's heartbeat_at keeps advancing well
// before the next sample would ever run, and no additional sampling
// happens in between (the set of generations recorded — empty here — never
// changes between the heartbeat-only writes).
func TestLoop_HeartbeatTickerUpdatesWithoutSampling(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/" + evidence.FileName
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	s := &Session{
		cfg:              Config{EvidenceDir: dir, Interval: 300 * time.Second, ExcludeIDs: []string{"nonexistent-container-id-prefix"}},
		now:              time.Now,
		evidenceFD:       int(f.Fd()),
		sessionID:        "test",
		sessionStartedAt: time.Now(),
		generations:      map[string]*generationState{},
		dbJobCh:          make(chan dbJob, dbJobChCapacity),
		dbResultCh:       make(chan dbResult, dbJobChCapacity),
		sampleResCh:      make(chan sampleEnvelope, maxConcurrentSampleWorkers*2),
		writerCh:         make(chan writerJob, 1),
		writerReportCh:   make(chan writeReport, 1),
		heartbeatEvery:   20 * time.Millisecond,
		// This test drives loop() directly, skipping run()'s own startup
		// self-check and eBPF-attach steps that a real session always
		// performs first (they set isolationStatus and eventsStatus
		// respectively) — both are set here to what a clean, fully-isolated
		// run with no eBPF attach attempted would have left them at, since
		// computeStatus() otherwise treats the zero value of isolationStatus
		// as "not ok" and reports it verbatim.
		isolationStatus: evidence.SensorOK,
		eventsStatus:    evidence.EventsUnavailable,
		eventsReason:    evidence.EventsReasonKernelUnsupported,
	}
	go runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.loop(ctx, evidence.SensorOK) }()
	if err := <-done; err != nil {
		t.Fatalf("loop: %v", err)
	}

	r := evidence.NewReader(dir)
	snap, err := r.Read(time.Now(), nil)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	elapsed := snap.Sensor.HeartbeatAt.Sub(s.sessionStartedAt)
	if elapsed < 3*s.heartbeatEvery {
		t.Errorf("final heartbeat_at is only %v after session start, want at least a few heartbeat intervals (~%v) — the heartbeat ticker does not appear to have fired repeatedly", elapsed, 3*s.heartbeatEvery)
	}
}

// TestLoop_FatalDBResultWritesEvidenceBeforeReturning covers the whole
// loop() wiring for a parser that has died, end to end (unlike
// TestWriteParseFailedAndExit_MarksActiveGenerationsParseFailed, which
// calls writeParseFailedAndExit directly): a fatal dbResult arriving on
// dbResultCh must make loop() call writeParseFailedAndExit and only then
// return — never the other way around — so the evidence file already
// carries parse_failed for this session's own tracked generation the
// moment loop() hands back control, with no separate wait needed.
func TestLoop_FatalDBResultWritesEvidenceBeforeReturning(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/" + evidence.FileName
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	s := &Session{
		cfg:              Config{EvidenceDir: dir, Interval: 300 * time.Second, ExcludeIDs: []string{"nonexistent-container-id-prefix"}},
		now:              time.Now,
		evidenceFD:       int(f.Fd()),
		sessionID:        "test",
		sessionStartedAt: time.Now(),
		generations:      map[string]*generationState{},
		dbJobCh:          make(chan dbJob, dbJobChCapacity),
		dbResultCh:       make(chan dbResult, dbJobChCapacity),
		sampleResCh:      make(chan sampleEnvelope, maxConcurrentSampleWorkers*2),
		writerCh:         make(chan writerJob, 1),
		writerReportCh:   make(chan writeReport, 1),
		heartbeatEvery:   time.Hour, // must not fire and race the fatal write below
	}
	active := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	active.idxState = indexReady
	s.generations[active.key()] = active

	go runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.loop(ctx, evidence.SensorOK) }()

	s.dbResultCh <- dbResult{fatalErr: errors.New("parser connection lost")}

	loopErr := <-done
	if loopErr == nil {
		t.Fatalf("loop returned nil, want the fatal parser error")
	}

	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek evidence file: %v", err)
	}
	written, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read back evidence file: %v", err)
	}
	if !strings.Contains(string(written), string(evidence.StateParseFailed)) {
		t.Fatalf("evidence file does not yet contain %q immediately after loop() returned — the fatal write must be complete by then, not merely queued", evidence.StateParseFailed)
	}
}

// TestLoadPreviousEvidence_CarriesOverIncompleteAndTruncated covers a
// Sensor restart: it must not silently forget that a generation's evidence
// already had gaps in it (a withdrawn not-observed verdict, a cut-short
// directory listing) — starting the restored generationState with
// Incomplete/Truncated both reset to false would claim more confidence in
// the carried-over OSPackages/Executables than a fresh session has any
// right to.
func TestLoadPreviousEvidence_CarriesOverIncompleteAndTruncated(t *testing.T) {
	dir := t.TempDir()
	snap := evidence.Snapshot{
		Schema: evidence.Schema,
		Sensor: evidence.SensorInfo{
			SessionID: "prev", HeartbeatAt: time.Unix(100, 0), IntervalSeconds: 30,
			Status: evidence.SensorOK,
			Events: evidence.EventsInfo{Status: evidence.EventsUnavailable, Reason: evidence.EventsReasonKernelUnsupported},
		},
		Generations: []evidence.Generation{
			{
				Container:      evidence.ContainerRef{Runtime: "docker", ID: strings64('a')},
				Init:           evidence.InitProcess{PID: 1, Starttime: 1},
				State:          evidence.StateObserving,
				StartedAt:      time.Unix(0, 0),
				LastVerifiedAt: time.Unix(50, 0),
				Incomplete:     true,
				Truncated:      true,
				EventsCoverage: evidence.CoverageNone,
			},
		},
	}
	f, err := os.OpenFile(filepath.Join(dir, evidence.FileName), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()
	if err := evidence.WriteTo(f, snap); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	s := &Session{cfg: Config{EvidenceDir: dir}, now: time.Now, generations: map[string]*generationState{}}
	s.loadPreviousEvidence()

	if len(s.generations) != 1 {
		t.Fatalf("len(generations) = %d, want 1", len(s.generations))
	}
	for _, g := range s.generations {
		if !g.incomplete {
			t.Errorf("incomplete = false after restart, want true (carried over)")
		}
		if !g.truncated {
			t.Errorf("truncated = false after restart, want true (carried over)")
		}
	}
}

// TestApplySampleResult_OutstandingLookupWithholdsIncompleteNotObserved
// covers the window between a sample producing candidates and their owner
// lookup actually answering: for as long as that lookup is outstanding
// (deliberately never answered in this test, standing in for a lookup the
// dbworker simply has not gotten to yet), toEvidence's own Incomplete must
// already read true — the one signal a downstream reader (JudgeOSPackage's
// own caller) uses to withhold a not_observed verdict rather than assume a
// candidate that never got its owner resolved must not be an OS package at
// all.
func TestApplySampleResult_OutstandingLookupWithholdsIncompleteNotObserved(t *testing.T) {
	s := newTestSession()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	g.idxState = indexReady
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}
	s.generations[g.key()] = g

	res := sampleResult{
		genKey: g.key(), attempted: 1, succeeded: 1, indexReadyAtStart: true,
		candidates: map[string][]sampleCandidate{
			"/usr/lib/libssl.so.3": {{kind: evidence.KindMappedLibrary}},
		},
		verified: []string{"/usr/lib/libssl.so.3"},
		basis:    mountBasis{}, // zero value (ok == false): never compared against an unset g.idxBasis
	}
	s.applySampleResult(g, res)

	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil, want a lookup outstanding for the one verified candidate")
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false while a lookup is still outstanding, want true — a reader must not draw not_observed from an unresolved candidate")
	}

	// The lookup answering later (applyLookupResult, exercised elsewhere)
	// is what clears this — not simulated here, since this test's own
	// point is the withheld window before that ever happens.
}

// TestApplyDiscoveryResult_DiscardsStaleOutOfOrderCompletion covers
// discoveryGen's whole reason for existing: a discovery abandoned as stale
// (see discoveryStaleAfter) can still complete later, in the background,
// after a newer discovery has already started and even already been
// applied — completing out of order. That stale straggler must be
// discarded outright, never reconciled against, and must not disturb
// discoveryInFlight if a still-newer discovery is presumed to be the one
// actually in flight by the time it arrives.
func TestApplyDiscoveryResult_DiscardsStaleOutOfOrderCompletion(t *testing.T) {
	s := &Session{
		now: time.Now, cfg: Config{Interval: time.Hour},
		generations: map[string]*generationState{},
		dbJobCh:     make(chan dbJob, 8),
		sampleResCh: make(chan sampleEnvelope, 8),
		sampleFn:    func(job sampleJob) sampleResult { return sampleResult{genKey: job.genKey} },
	}
	s.discoveryGen = 2 // as if discovery #1 already went stale and #2 was started in its place

	// Discovery #2 (the current one) completes first and is applied.
	groupsV2 := map[string]containerGroup{
		strings64('b'): {ContainerID: strings64('b'), Processes: []InitProcess{{PID: 20, Starttime: 9}}, Init: InitProcess{PID: 20, Starttime: 9}},
	}
	if applied := s.applyDiscoveryResult(discoveryResult{groups: groupsV2, now: time.Unix(200, 0), gen: 2}); !applied {
		t.Fatalf("applyDiscoveryResult(gen 2) = false, want true (it matches the current discoveryGen)")
	}
	if s.discoveryInFlight {
		t.Errorf("discoveryInFlight = true after the current discovery's own result was applied, want false")
	}
	if len(s.generations) != 1 {
		t.Fatalf("len(generations) = %d after discovery #2, want 1", len(s.generations))
	}

	// Discovery #1 — started earlier, abandoned as stale, but still running
	// in the background — now finally completes, out of order, naming a
	// completely different container set. It must be discarded outright.
	s.discoveryInFlight = true // as if a still-newer discovery (#3) had since started
	groupsV1 := map[string]containerGroup{
		strings64('a'): {ContainerID: strings64('a'), Processes: []InitProcess{{PID: 10, Starttime: 5}}, Init: InitProcess{PID: 10, Starttime: 5}},
	}
	if applied := s.applyDiscoveryResult(discoveryResult{groups: groupsV1, now: time.Unix(100, 0), gen: 1}); applied {
		t.Errorf("applyDiscoveryResult(gen 1) = true, want false — gen 1 is stale, discoveryGen has moved on to 2")
	}
	if !s.discoveryInFlight {
		t.Errorf("discoveryInFlight = false after discarding a stale result, want it left untouched (true, standing in for a still-newer discovery in flight)")
	}
	if len(s.generations) != 1 {
		t.Fatalf("len(generations) = %d after the stale discovery was discarded, want still 1 (from discovery #2, unaffected)", len(s.generations))
	}
	for _, g := range s.generations {
		if g.container.ID != strings64('b') {
			t.Errorf("generation container = %s, want %s — the stale discovery #1 must not have reintroduced its own container set", g.container.ID, strings64('b'))
		}
	}
}

// TestApplySampleResult_QueuedCandidatesAreResolvedNotLost covers the whole
// reason queuedCandidates exists: a sample's own candidates observed while
// an earlier lookup is still outstanding are queued, never dropped, and
// get their own turn — folded into a fresh lookup — the moment that
// earlier lookup answers, even when yet another sample arrives in between
// and has to queue behind that fresh lookup in turn. Exercised through
// three chained samples (A, then B while A is pending, then C while B's
// own follow-up lookup is pending) and confirmed all the way to the
// reader's own verdict (evidence.JudgeOSPackage), not merely this
// package's own Incomplete field.
func TestApplySampleResult_QueuedCandidatesAreResolvedNotLost(t *testing.T) {
	s := newTestSession()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	g.idxState = indexReady
	g.postIndexConfirmed = true
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}
	s.generations[g.key()] = g

	const pathA = "/usr/lib/libA.so"
	const pathB = "/usr/lib/libB.so"
	const pathC = "/usr/lib/libC.so"
	refB := inventory.PackageRef{Class: inventory.ClassOS, Name: "pkgB", Version: "1.0"}

	sample := func(path string) sampleResult {
		return sampleResult{
			genKey: g.key(), attempted: 1, succeeded: 1, indexReadyAtStart: true,
			candidates: map[string][]sampleCandidate{path: {{kind: evidence.KindMappedLibrary}}},
			verified:   []string{path},
		}
	}

	// Sample 1: observes A, submits a lookup, left outstanding.
	s.applySampleResult(g, sample(pathA))
	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil after sample 1, want A's lookup outstanding")
	}

	// Sample 2: observes B while A's lookup is still outstanding — B must
	// be queued, not dropped.
	s.applySampleResult(g, sample(pathB))
	if len(g.queuedCandidates) != 1 {
		t.Fatalf("len(queuedCandidates) = %d after sample 2, want 1 (B queued behind A's own outstanding lookup)", len(g.queuedCandidates))
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false with B queued and A's lookup outstanding, want true")
	}
	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), refB); verdict.Usage != evidence.UsageUnavailable {
		t.Errorf("JudgeOSPackage(B) = %+v while B is still queued, want Unavailable — not_observed must stay withheld", verdict)
	}

	// A's lookup answers: pendingLookup clears, but flushQueuedCandidates
	// (deferred inside applyLookupResult) must immediately resubmit B's own
	// queued batch as the new pendingLookup — never left waiting.
	s.applyLookupResult(g, dbResult{
		genKey: g.key(),
		owners: map[string]lookupOutcome{pathA: {owners: []lookupOwner{{Name: "pkgA", Version: "1.0"}}}},
	})
	if len(g.queuedCandidates) != 0 {
		t.Fatalf("len(queuedCandidates) = %d after A's lookup answered, want 0 (flushed into a new lookup)", len(g.queuedCandidates))
	}
	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil after A's lookup answered, want B's own follow-up lookup now outstanding")
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false with B's own follow-up lookup now outstanding, want true — B has still not actually been resolved")
	}

	// Sample 3: observes C while B's own follow-up lookup (not A's
	// original one) is the one now outstanding — C must queue behind it in
	// turn, the same as B did behind A.
	s.applySampleResult(g, sample(pathC))
	if len(g.queuedCandidates) != 1 {
		t.Fatalf("len(queuedCandidates) = %d after sample 3, want 1 (C queued behind B's own outstanding lookup)", len(g.queuedCandidates))
	}

	// B's lookup now answers: B is finally attributed — a real package,
	// resolved despite having been queued and carried through two
	// intervening samples (A's own completion and C's own observation) —
	// and C's own queued batch is flushed into yet another new lookup.
	s.applyLookupResult(g, dbResult{
		genKey: g.key(),
		owners: map[string]lookupOutcome{pathB: {owners: []lookupOwner{{Name: "pkgB", Version: "1.0"}}}},
	})
	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), refB); verdict.Usage != evidence.UsageInUse {
		t.Fatalf("JudgeOSPackage(B) = %+v after B's own (queued, then resubmitted) lookup answered, want InUse — B must not have been lost", verdict)
	}
	if len(g.queuedCandidates) != 0 {
		t.Fatalf("len(queuedCandidates) = %d after B's lookup answered, want 0 (C flushed into a new lookup)", len(g.queuedCandidates))
	}
	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil after B's lookup answered, want C's own follow-up lookup now outstanding")
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false with C's own follow-up lookup still outstanding, want true")
	}

	// C's lookup answers: nothing left queued or outstanding anywhere —
	// only now does Incomplete finally clear.
	s.applyLookupResult(g, dbResult{
		genKey: g.key(),
		owners: map[string]lookupOutcome{pathC: {owners: []lookupOwner{{Name: "pkgC", Version: "1.0"}}}},
	})
	if got := g.toEvidence(false).Incomplete; got {
		t.Errorf("Incomplete = true after every queued/outstanding batch was eventually resolved, want false")
	}
}

// TestApplySampleResult_QueueOverflowIsUnrecoverable covers
// maxQueuedCandidateBatches' own cap: once queuedCandidates is already at
// capacity, the next sample's own candidates cannot be queued either —
// there is nowhere left to put them — and unlike an ordinary queued batch
// (recovered once its own lookup answers), a batch dropped for capacity is
// lost for good, so this generation must never again claim the confidence
// not_observed needs, even once every actually-queued batch eventually
// resolves cleanly.
func TestApplySampleResult_QueueOverflowIsUnrecoverable(t *testing.T) {
	s := newTestSession()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	g.idxState = indexReady
	g.postIndexConfirmed = true
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}
	s.generations[g.key()] = g

	sample := func(path string) sampleResult {
		return sampleResult{
			genKey: g.key(), attempted: 1, succeeded: 1, indexReadyAtStart: true,
			candidates: map[string][]sampleCandidate{path: {{kind: evidence.KindMappedLibrary}}},
			verified:   []string{path},
		}
	}

	// Sample 0 submits the one outstanding lookup every later sample below
	// queues behind.
	s.applySampleResult(g, sample("/usr/lib/lib0.so"))
	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil after sample 0, want it outstanding")
	}

	for i := 0; i < maxQueuedCandidateBatches; i++ {
		s.applySampleResult(g, sample(fmt.Sprintf("/usr/lib/queued%d.so", i)))
	}
	if len(g.queuedCandidates) != maxQueuedCandidateBatches {
		t.Fatalf("len(queuedCandidates) = %d, want exactly the cap (%d)", len(g.queuedCandidates), maxQueuedCandidateBatches)
	}
	if g.candidatesLostPermanently {
		t.Fatalf("candidatesLostPermanently = true before the cap was ever exceeded")
	}

	// One more sample: the queue is already full, so this one's own
	// candidates cannot be queued at all.
	s.applySampleResult(g, sample("/usr/lib/overflow.so"))
	if len(g.queuedCandidates) != maxQueuedCandidateBatches {
		t.Errorf("len(queuedCandidates) = %d after the overflowing sample, want it to stay at the cap (%d), not grow past it", len(g.queuedCandidates), maxQueuedCandidateBatches)
	}
	if !g.candidatesLostPermanently {
		t.Fatalf("candidatesLostPermanently = false after exceeding the cap, want true")
	}

	// Resolve every batch that was actually queued or outstanding, cleanly
	// — round 1 answers sample 0's own original lookup (which triggers
	// flushQueuedCandidates to resubmit everything still queued as one new
	// lookup together); round 2 answers that one. The overflowed sample's
	// own batch was never queued at all, so no round ever covers it —
	// Incomplete must never clear again for this generation regardless.
	for i := 0; i < 2; i++ {
		pl := g.pendingLookup
		if pl == nil {
			t.Fatalf("pendingLookup = nil while draining round %d, want one outstanding", i)
		}
		owners := map[string]lookupOutcome{}
		for _, batch := range pl.batches {
			for _, p := range batch.verified {
				owners[p] = lookupOutcome{owners: []lookupOwner{{Name: "pkg", Version: "1.0"}}}
			}
		}
		s.applyLookupResult(g, dbResult{genKey: g.key(), owners: owners})
	}
	if g.pendingLookup != nil || len(g.queuedCandidates) != 0 {
		t.Fatalf("pendingLookup/queuedCandidates = %+v/%+v after draining every round, want both empty", g.pendingLookup, g.queuedCandidates)
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false after every queued batch resolved cleanly, want true — the overflowed batch can never be recovered this session")
	}
}

// TestPostIndexConfirmed_WithholdsNotObservedUntilFirstPostReadyLookup
// follows "index not ready -> ready -> first post-ready lookup completes"
// all the way to the reader's own verdict (evidence.JudgeOSPackage), not
// merely this package's own State field: a sample taken before the index
// was ready still advances LastVerifiedAt (it read processes successfully,
// just could not attribute anything to a package yet), and the index
// becoming ready is not by itself proof that a sample has ever used it —
// only a subsequent sample whose own candidates (if any) were actually
// looked up against it is. Until that happens, JudgeOSPackage must not
// reach not_observed for this generation at all.
func TestPostIndexConfirmed_WithholdsNotObservedUntilFirstPostReadyLookup(t *testing.T) {
	s := newTestSession()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	s.generations[g.key()] = g

	ref := inventory.PackageRef{Class: inventory.ClassOS, Name: "never-mentioned-pkg", Version: "1.0"}

	// Sample 1: index not built yet at all. Still advances LastVerifiedAt
	// (a real, successful read), but nothing can be attributed.
	s.applySampleResult(g, sampleResult{genKey: g.key(), attempted: 1, succeeded: 1})
	if g.lastVerifiedAt.IsZero() {
		t.Fatalf("lastVerifiedAt is still zero after a successful pre-index sample")
	}
	if derivePublishedState(g) != evidence.StateInitializing {
		t.Fatalf("state = %q before any build at all, want initializing", derivePublishedState(g))
	}

	// The index finishes building — settles ready — but no sample has used
	// it yet.
	s.applyBuildResult(g, dbResult{
		genKey: g.key(), dbKind: evidence.DBKindDpkg, dbStatus: evidence.DBStatusOK, buildOK: true,
	})
	if g.idxState != indexReady {
		t.Fatalf("idxState = %v after a successful build, want ready", g.idxState)
	}
	if derivePublishedState(g) != evidence.StateInitializing {
		t.Fatalf("state = %q right after the index became ready but before any post-ready sample, want still initializing", derivePublishedState(g))
	}
	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), ref); verdict.Usage != evidence.UsageUnavailable || verdict.Reason != evidence.ReasonInitializing {
		t.Errorf("JudgeOSPackage = %+v, want Unavailable/ReasonInitializing — the reader must not reach not_observed on a freshly-ready, never-sampled index", verdict)
	}

	// Sample 2, post-ready: observes a library, submits its lookup.
	const path = "/usr/lib/libX.so"
	s.applySampleResult(g, sampleResult{
		genKey: g.key(), attempted: 1, succeeded: 1, indexReadyAtStart: true,
		candidates: map[string][]sampleCandidate{path: {{kind: evidence.KindMappedLibrary}}},
		verified:   []string{path},
	})
	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil after the first post-ready sample, want its own lookup outstanding")
	}
	if derivePublishedState(g) != evidence.StateInitializing {
		t.Fatalf("state = %q with the first post-ready lookup still outstanding, want still initializing", derivePublishedState(g))
	}
	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), ref); verdict.Usage != evidence.UsageUnavailable {
		t.Errorf("JudgeOSPackage = %+v, want Unavailable while the first post-ready lookup is still outstanding (Incomplete, from pendingLookup != nil, outranks the State-level reason here)", verdict)
	}

	// That lookup answers (empty: no owner for this made-up path) — only
	// now has a sample's own candidates actually been resolved against the
	// ready index.
	s.applyLookupResult(g, dbResult{genKey: g.key(), owners: map[string]lookupOutcome{path: {}}})
	if derivePublishedState(g) != evidence.StateObserving {
		t.Fatalf("state = %q once the first post-ready lookup has answered, want observing", derivePublishedState(g))
	}
	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), ref); verdict.Usage != evidence.UsageNotObserved {
		t.Errorf("JudgeOSPackage = %+v, want NotObserved now that a real post-ready observe-and-lookup round trip has completed", verdict)
	}
}

// TestFlushQueuedCandidates_DiscardsBatchFromBeforeIndexRebuild is the
// regression test for the race this Sensor's own epoch tracking exists to
// close: a batch queued behind an outstanding lookup, both observed
// against the old root, must never be matched against an index later
// rebuilt from a different root — exercised end to end, up to the reader's
// own verdict (evidence.JudgeOSPackage), in exactly the order that could
// otherwise let it happen:
//
//  1. sample 1 observes A against the old root; its own lookup is
//     submitted and left outstanding (epoch 0).
//  2. sample 2 observes B, also against the old root, while A's lookup is
//     still outstanding — B's own batch queues behind it (epoch 0, same as
//     A, since the index has not been invalidated yet).
//  3. sample 3 detects init's own root has changed (a chroot/unshare, no
//     PID/starttime change) — idxEpoch bumps to 1 and a rebuild is forced.
//  4. A's lookup answers (it was submitted, and answered, entirely before
//     the mismatch was ever detected — correctly resolved against the old
//     index) — applying it flushes the queue, which must discard B's own
//     batch (still tagged epoch 0) rather than resubmit it once the
//     rebuilt index (epoch 1) exists.
//  5. the rebuild itself completes.
//
// B's own path must never be recorded as in_use for whatever package the
// rebuilt index says owns it, and the generation must stay Incomplete for
// the rest of the session — B's own observation is lost for good, not
// merely delayed.
func TestFlushQueuedCandidates_DiscardsBatchFromBeforeIndexRebuild(t *testing.T) {
	s := newTestSession()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	g.idxState = indexReady
	g.postIndexConfirmed = true
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}
	oldBasis := mountBasis{ok: true, mntNS: "mnt:[1]", rootDev: "8:1", rootIno: 100}
	g.idxBasis = oldBasis
	s.generations[g.key()] = g

	const pathA = "/usr/lib/libA.so"
	const pathB = "/usr/lib/libB.so"
	refBUnderNewRoot := inventory.PackageRef{Class: inventory.ClassOS, Name: "pkgB-new-root", Version: "1.0"}

	// Sample 1: observe A against the old root. Its own lookup is
	// submitted and left outstanding, at epoch 0.
	s.applySampleResult(g, sampleResult{
		genKey: g.key(), attempted: 1, succeeded: 1, indexReadyAtStart: true,
		candidates: map[string][]sampleCandidate{pathA: {{kind: evidence.KindMappedLibrary}}},
		verified:   []string{pathA},
		basis:      oldBasis,
	})
	if g.pendingLookup == nil {
		t.Fatalf("pendingLookup = nil after sample 1, want A's lookup outstanding")
	}
	if g.pendingLookup.epoch != 0 {
		t.Fatalf("pendingLookup.epoch = %d, want 0", g.pendingLookup.epoch)
	}

	// Sample 2: observe B, also against the old root, while A's lookup is
	// still outstanding — B's own batch queues behind it, at the same
	// epoch (0), since the index has not been invalidated yet.
	s.applySampleResult(g, sampleResult{
		genKey: g.key(), attempted: 1, succeeded: 1, indexReadyAtStart: true,
		candidates: map[string][]sampleCandidate{pathB: {{kind: evidence.KindMappedLibrary}}},
		verified:   []string{pathB},
		basis:      oldBasis,
	})
	if len(g.queuedCandidates) != 1 || g.queuedCandidates[0].epoch != 0 {
		t.Fatalf("queuedCandidates = %+v, want exactly one batch at epoch 0 (B, queued behind A)", g.queuedCandidates)
	}

	// Sample 3: init's own root has changed — detected via the mount-basis
	// mismatch (a candidate is required to reach that check at all), which
	// forces a rebuild and bumps idxEpoch to 1.
	newBasis := mountBasis{ok: true, mntNS: "mnt:[2]", rootDev: "8:1", rootIno: 200}
	s.applySampleResult(g, sampleResult{
		genKey: g.key(), attempted: 1, succeeded: 1, indexReadyAtStart: true,
		candidates: map[string][]sampleCandidate{pathA: {{kind: evidence.KindMappedLibrary}}},
		verified:   []string{pathA},
		basis:      newBasis,
	})
	if g.idxState != indexIdle {
		t.Fatalf("idxState = %v after the mount-basis mismatch, want idle (rebuild forced)", g.idxState)
	}
	if g.idxEpoch != 1 {
		t.Fatalf("idxEpoch = %d after the mismatch, want 1", g.idxEpoch)
	}
	if len(g.queuedCandidates) != 1 {
		t.Fatalf("queuedCandidates = %+v, want B still queued at this point (only flushed once A answers)", g.queuedCandidates)
	}

	// A's own lookup now answers — resolved normally, entirely before the
	// mismatch was ever detected. Applying it flushes the queue, which
	// must discard B's own batch (epoch 0) rather than resubmit it against
	// idxEpoch 1.
	s.applyLookupResult(g, dbResult{
		genKey: g.key(), epoch: 0,
		owners: map[string]lookupOutcome{pathA: {owners: []lookupOwner{{Name: "pkgA", Version: "1.0"}}}},
	})
	if len(g.queuedCandidates) != 0 {
		t.Fatalf("queuedCandidates = %+v after A answered, want empty", g.queuedCandidates)
	}
	if g.pendingLookup != nil {
		t.Fatalf("pendingLookup = %+v after A answered, want nil — B's own batch must never have been resubmitted as a new lookup", g.pendingLookup)
	}
	if !g.candidatesLostPermanently {
		t.Fatalf("candidatesLostPermanently = false after B's own batch was discarded for a stale epoch, want true")
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false after B's own observation was permanently lost, want true")
	}

	// R (the rebuild) completes, replacing the index with one built from
	// the new root.
	s.applyBuildResult(g, dbResult{
		genKey: g.key(), dbKind: evidence.DBKindDpkg, dbStatus: evidence.DBStatusOK, buildOK: true,
		basis: newBasis,
	})
	if g.idxState != indexReady {
		t.Fatalf("idxState = %v after the rebuild completed, want ready", g.idxState)
	}

	// The reader's own verdict: pathB's own owner under the new root must
	// never have been recorded as in_use — B's own pre-rebuild candidate
	// was discarded before it was ever looked up against any index at all.
	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), refBUnderNewRoot); verdict.Usage == evidence.UsageInUse {
		t.Fatalf("JudgeOSPackage(pkgB-new-root) = %+v, want anything but InUse — B's own pre-rebuild candidate must never be matched against the rebuilt index", verdict)
	}
	if !g.toEvidence(false).Incomplete {
		t.Errorf("Incomplete = false once the rebuild has completed, want it to stay true — B's own observation is lost for the rest of this session")
	}
}

// TestRunDBWorker_RejectsLookupSubmittedAgainstASupersededEpoch covers the
// dbworker-side half of the same protection flushQueuedCandidates provides
// on the loop side: a lookup job can still be sitting in the dbworker's own
// jobCh, already stale, behind a build job for the same genKey that was
// submitted afterward (see runDBWorker's own epoch check) — the build
// completing before the lookup is even dequeued must not let the lookup's
// own answer come from a package database describing a different root.
func TestRunDBWorker_RejectsLookupSubmittedAgainstASupersededEpoch(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	jobCh := make(chan dbJob, 8)
	resultCh := make(chan dbResult, 8)
	go runDBWorker(sockFD, jobCh, resultCh)
	defer close(jobCh)

	const gen = "test-gen-epoch"

	// A build job at epoch 0 — runDBWorker records epoch 0 as current for
	// this genKey the instant it dequeues this job, regardless of the
	// build's own outcome (a root that cannot even be opened here, so it
	// settles as noChange — the point is only that epoch bookkeeping
	// happens before the build itself is even attempted).
	jobCh <- dbJob{kind: dbJobBuild, genKey: gen, rootPID: -1, starttime: 1, epoch: 0}
	res0 := <-resultCh
	if res0.kind != dbJobBuild {
		t.Fatalf("first result kind = %v, want dbJobBuild", res0.kind)
	}

	// A lookup job still tagged with that same epoch (0) is answered
	// normally — the parser is asked, even though nothing was ever
	// actually indexed for this genKey (an empty, harmless answer).
	jobCh <- dbJob{kind: dbJobLookup, genKey: gen, paths: []string{"/usr/lib/x.so"}, epoch: 0}
	res1 := <-resultCh
	if res1.epochStale {
		t.Fatalf("epochStale = true for a lookup at the current epoch, want false")
	}

	// A build job for the SAME genKey at epoch 1 — as if idxEpoch had
	// since been bumped and a rebuild submitted.
	jobCh <- dbJob{kind: dbJobBuild, genKey: gen, rootPID: -1, starttime: 1, epoch: 1}
	<-resultCh

	// A lookup job still carrying the OLD epoch (0) — as if it had been
	// submitted before the mismatch was ever detected, and only reaches
	// the front of this FIFO now, after the epoch-1 build job above.
	jobCh <- dbJob{kind: dbJobLookup, genKey: gen, paths: []string{"/usr/lib/x.so"}, epoch: 0}
	res3 := <-resultCh
	if !res3.epochStale {
		t.Fatalf("epochStale = false for a lookup at a superseded epoch, want true")
	}
	if res3.epoch != 0 {
		t.Errorf("epoch = %d, want 0 (echoing the lookup job's own epoch, not the current one)", res3.epoch)
	}
	if len(res3.owners) != 0 {
		t.Errorf("owners = %+v, want none — a stale-epoch lookup must never even ask the parser", res3.owners)
	}
}

// TestApplySampleResult_BasisMismatchInvalidatesIndexEvenWithZeroCandidates
// pins that the
// mount-basis check must run before candidate count is ever considered, not
// only when a sample happens to produce at least one candidate. Exercised
// in exactly the order that could otherwise leave a stale confirmation in
// place:
//
//  1. the generation already reports observing (idxState ready,
//     postIndexConfirmed true), Incomplete false, with a recent
//     LastVerifiedAt — i.e. everything a reader needs to reach not_observed
//     for some package this generation never actually recorded.
//  2. the sample worker resolves init's own basis against the *changed*
//     root (a chroot/unshare, no PID/starttime change).
//  3. every process this sample attempted vanished mid-read (see
//     runSampleWorker's own per-process discard cases) — candidates is
//     empty, succeeded is 0, denied is 0 — so applySampleResult has
//     nothing to attribute and does not advance LastVerifiedAt either.
//
// Despite (3) giving applySampleResult no candidates to reason about at
// all, the basis mismatch from (2) must still be caught: the index is
// invalidated, postIndexConfirmed is lowered, incomplete is set, and the
// reader must not reach not_observed for any package this generation had
// no chance to actually re-confirm against the new root.
func TestApplySampleResult_BasisMismatchInvalidatesIndexEvenWithZeroCandidates(t *testing.T) {
	s := newTestSession()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
	oldBasis := mountBasis{ok: true, mntNS: "mnt:[1]", rootDev: "8:1", rootIno: 100}
	g.idxState = indexReady
	g.idxBasis = oldBasis
	g.postIndexConfirmed = true
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}
	g.lastVerifiedAt = time.Unix(1000, 0) // "valid" — recent, well within any staleness threshold
	s.generations[g.key()] = g

	ref := inventory.PackageRef{Class: inventory.ClassOS, Name: "never-actually-recorded-pkg", Version: "1.0"}
	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), ref); verdict.Usage != evidence.UsageNotObserved {
		t.Fatalf("test precondition: JudgeOSPackage = %+v before the sample below, want NotObserved (confirming the initial state really is reader-eligible)", verdict)
	}

	newBasis := mountBasis{ok: true, mntNS: "mnt:[2]", rootDev: "8:1", rootIno: 200}
	s.applySampleResult(g, sampleResult{
		genKey: g.key(), attempted: 1, succeeded: 0, denied: 0, indexReadyAtStart: true,
		basis: newBasis,
		// candidates deliberately nil/empty: every process this sample
		// attempted vanished mid-read.
	})

	if g.idxState != indexIdle {
		t.Errorf("idxState = %v after the basis mismatch, want idle — the stale index must be invalidated even with zero candidates", g.idxState)
	}
	if g.postIndexConfirmed {
		t.Errorf("postIndexConfirmed = true after the basis mismatch, want false — the old confirmation does not carry over to whatever gets rebuilt")
	}
	if !g.incomplete {
		t.Errorf("incomplete = false after the basis mismatch, want true")
	}
	if g.idxEpoch != 1 {
		t.Errorf("idxEpoch = %d after the basis mismatch, want 1", g.idxEpoch)
	}
	if !g.lastVerifiedAt.Equal(time.Unix(1000, 0)) {
		t.Errorf("lastVerifiedAt = %v, want unchanged at unix(1000) — nothing was actually confirmed this round (succeeded=0, denied=0)", g.lastVerifiedAt)
	}

	if verdict := evidence.JudgeOSPackage(g.toEvidence(false), ref); verdict.Usage == evidence.UsageNotObserved {
		t.Errorf("JudgeOSPackage = %+v after the basis mismatch, want anything but NotObserved — the old index's own confirmation must not survive a root nothing this sample actually re-confirmed", verdict)
	}
}
