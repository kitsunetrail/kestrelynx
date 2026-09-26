package sensor

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// TestStartSampleWorker_StalledWorkerDoesNotBlockOthersOrHeartbeat covers
// the whole point of running each generation's sample under its own
// goroutine: a worker stalled well past its own budget must not delay
// either another generation's own (in-time) result or the heartbeat
// ticker's own fixed-schedule snapshot writes. sampleFn/heartbeatEvery/
// sampleTimeout are all scaled down from their production values
// (5s/60s) by the same ratio this test's own artificial delay is scaled
// down from the "10s stall" this is modeling, so the same mechanism is
// exercised without a real 60-second test.
func TestStartSampleWorker_StalledWorkerDoesNotBlockOthersOrHeartbeat(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(dir+"/"+evidence.FileName, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	const (
		sampleTimeout = 60 * time.Millisecond  // stands in for the production 5s budget
		stallFor      = 400 * time.Millisecond // stands in for a "~10s" real stall (well past the budget)
		heartbeatFast = 25 * time.Millisecond  // stands in for the production 60s heartbeat
	)

	var slowStarted, slowFinished int32

	gSlow := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1}, time.Now())
	gFast := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('b')}, InitProcess{PID: 2}, time.Now())
	realSlowKey, realFastKey := gSlow.key(), gFast.key()

	s := &Session{
		now: time.Now, cfg: Config{Interval: time.Hour},
		evidenceFD: int(f.Fd()), heartbeatEvery: heartbeatFast, sampleTimeout: sampleTimeout,
		generations:    map[string]*generationState{realSlowKey: gSlow, realFastKey: gFast},
		dbJobCh:        make(chan dbJob, 8),
		dbResultCh:     make(chan dbResult, 8),
		sampleResCh:    make(chan sampleEnvelope, 8),
		writerCh:       make(chan writerJob, 1),
		writerReportCh: make(chan writeReport, 1),
		sampleFn: func(job sampleJob) sampleResult {
			if job.genKey == realSlowKey {
				atomic.AddInt32(&slowStarted, 1)
				time.Sleep(stallFor)
				atomic.AddInt32(&slowFinished, 1)
			}
			return sampleResult{genKey: job.genKey, attempted: 1, succeeded: 1}
		},
	}
	go runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)
	// Closing writerCh lets the writer goroutine exit cleanly before this
	// test's own deferred f.Close() runs (defers unwind in reverse
	// declaration order) — otherwise a write still in flight against an
	// already-closed fd logs a harmless but noisy fsync error to stderr.
	defer close(s.writerCh)

	now := time.Now()
	s.startSampleWorker(gSlow, now)
	s.startSampleWorker(gFast, now)

	ctx, cancel := context.WithTimeout(context.Background(), stallFor+300*time.Millisecond)
	defer cancel()

	heartbeats := 0
	var sawFastResult, sawSlowTimeout, sawSlowFinished bool
	heartbeatTicker := time.NewTicker(s.heartbeatEvery)
	defer heartbeatTicker.Stop()

drain:
	for {
		select {
		case <-ctx.Done():
			break drain
		case env := <-s.sampleResCh:
			switch {
			case env.genKey == realFastKey && env.kind == sampleEnvResult:
				sawFastResult = true
			case env.genKey == realSlowKey && env.kind == sampleEnvTimeout:
				sawSlowTimeout = true
			case env.genKey == realSlowKey && env.kind == sampleEnvFinished:
				sawSlowFinished = true
			}
			s.handleSampleEnvelope(env)
		case <-heartbeatTicker.C:
			heartbeats++
			s.writeSnapshotNow(evidence.SensorOK)
		case <-s.writerReportCh:
		}
		if sawFastResult && sawSlowTimeout && sawSlowFinished && heartbeats >= 3 {
			break drain
		}
	}

	if !sawFastResult {
		t.Errorf("the fast generation's own in-time result never arrived — a stalled sibling worker must not block it")
	}
	if !sawSlowTimeout {
		t.Errorf("the slow generation's sampleEnvTimeout never arrived within its own budget (%v)", sampleTimeout)
	}
	if !sawSlowFinished {
		t.Errorf("the slow generation's sampleEnvFinished (the abandoned worker's own eventual completion) never arrived")
	}
	if heartbeats < 3 {
		t.Errorf("heartbeat fired %d times during the slow worker's own %v stall, want at least 3 — the heartbeat ticker must keep firing on its own fixed schedule regardless", heartbeats, stallFor)
	}
	if derivePublishedState(gSlow) != evidence.StateStalled {
		t.Errorf("slow generation state = %q, want stalled", derivePublishedState(gSlow))
	}
	if gSlow.sampleAlive {
		t.Errorf("slow generation sampleAlive = true after sampleEnvFinished, want false")
	}
	if atomic.LoadInt32(&slowStarted) != 1 {
		t.Errorf("the slow sampleFn was never actually started")
	}
	if atomic.LoadInt32(&slowFinished) != 1 {
		t.Errorf("the slow sampleFn itself never actually finished running in the background")
	}
}

// TestDispatchWork_DoesNotStartSecondWorkerForSameGeneration covers the
// duplicate-prevention half of the sample-worker ledger: while a
// generation's own worker is still alive (whether or not loop has already
// given up waiting for it), dispatchWork must never start a second one for
// the same generation.
func TestDispatchWork_DoesNotStartSecondWorkerForSameGeneration(t *testing.T) {
	var started int32
	s := &Session{
		now: time.Now, cfg: Config{Interval: time.Hour},
		generations: map[string]*generationState{},
		dbJobCh:     make(chan dbJob, 8),
		sampleResCh: make(chan sampleEnvelope, 8),
		sampleFn: func(job sampleJob) sampleResult {
			atomic.AddInt32(&started, 1)
			time.Sleep(150 * time.Millisecond)
			return sampleResult{genKey: job.genKey}
		},
	}
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: os.Getpid()}, time.Now())
	g.idxState = indexReady
	s.generations[g.key()] = g

	now := time.Now()
	s.dispatchWork(now) // starts the one worker, marks g.sampleAlive
	s.dispatchWork(now) // must be a no-op: g.sampleAlive is already true
	s.dispatchWork(now)

	time.Sleep(300 * time.Millisecond) // let the one worker actually finish
	if got := atomic.LoadInt32(&started); got != 1 {
		t.Errorf("sampleFn was started %d times, want exactly 1 — dispatchWork must not start a second worker while one is still alive", got)
	}
}

// TestStartSampleWorker_StalledWorkerBlocksNeitherOthersNorHeartbeat_Deterministic
// covers the same property TestStartSampleWorker_StalledWorkerDoesNotBlockOthersOrHeartbeat
// does, but with the slow worker's own completion held at an explicit,
// test-controlled stop point (a gate channel) instead of a fixed
// time.Sleep duration this test could otherwise only assume the worker was
// still blocked for the whole time: every assertion below runs while the
// slow worker is provably still parked on <-gate — closing gate, letting it
// finally return, only happens afterward. A sleep-based proof is only ever
// probabilistic (a slow enough CI host could let the sleep elapse before
// the assertions run); holding an explicit stop point instead makes it
// certain.
//
// Every write this test checks is a real, synchronous, on-disk write
// (submitFinalSnapshot — the same machinery writeFinalSnapshotAndWait
// itself uses), never merely a local counter of how many times something
// was called: the fast generation's own check reads back its actual
// LastVerifiedAt and Executables content (not merely that generation's own
// presence, which predates any sample and would prove nothing), the slow
// generation's own check reads back its actual on-disk State (stalled), and
// the heartbeat check collects Sensor.HeartbeatAt from three separate such
// writes and requires them to be distinct — not just that a ticker fired
// three times.
//
// handleSampleEnvelope/writeSnapshotNow/buildSnapshot below are the same,
// real, unmodified functions (*Session).loop itself calls for exactly these
// same three envelope kinds and exactly the same heartbeat-triggered write;
// this test's own drain loop plays the role of loop's own select purely to
// avoid loop's own always-on internal container discovery (which runs
// against this test process's real /proc and cannot be made to recognize
// synthetic, non-Docker generations) — everything after a message is
// actually received is production code, not a reimplementation of it.
func TestStartSampleWorker_StalledWorkerBlocksNeitherOthersNorHeartbeat_Deterministic(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(dir+"/"+evidence.FileName, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	const (
		sampleTimeout = 40 * time.Millisecond
		heartbeatFast = 15 * time.Millisecond
	)

	gate := make(chan struct{})
	var slowStarted int32
	const fastExePath = "/usr/bin/fast-app"

	gSlow := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1}, time.Now())
	gFast := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('b')}, InitProcess{PID: 2}, time.Now())
	realSlowKey, realFastKey := gSlow.key(), gFast.key()

	s := &Session{
		// cfg.Interval only feeds Sensor.IntervalSeconds here (this test
		// drives sampling/heartbeat itself, never the real sampleTicker) —
		// kept within evidence's own valid schema range so the read-back
		// below succeeds.
		now: time.Now, cfg: Config{Interval: 30 * time.Second},
		evidenceFD: int(f.Fd()), heartbeatEvery: heartbeatFast, sampleTimeout: sampleTimeout,
		generations:    map[string]*generationState{realSlowKey: gSlow, realFastKey: gFast},
		dbJobCh:        make(chan dbJob, 8),
		dbResultCh:     make(chan dbResult, 8),
		sampleResCh:    make(chan sampleEnvelope, 8),
		writerCh:       make(chan writerJob, 1),
		writerReportCh: make(chan writeReport, 1),
		sampleFn: func(job sampleJob) sampleResult {
			if job.genKey == realSlowKey {
				atomic.AddInt32(&slowStarted, 1)
				<-gate // held here until the test explicitly releases it, below
				return sampleResult{genKey: job.genKey, attempted: 1, succeeded: 1}
			}
			return sampleResult{
				genKey: job.genKey, attempted: 1, succeeded: 1,
				executables: []executableObs{{path: fastExePath, kind: evidence.KindExe, obs: evidence.ProcessObservation{LastSeen: job.now}}},
			}
		},
	}
	go runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)
	defer close(s.writerCh)

	now := time.Now()
	s.startSampleWorker(gSlow, now)
	s.startSampleWorker(gFast, now)

	var sawFastResult, sawSlowTimeout bool
	heartbeatsSeen := map[time.Time]bool{}

drain:
	for {
		select {
		case env := <-s.sampleResCh:
			switch {
			case env.genKey == realFastKey && env.kind == sampleEnvResult:
				sawFastResult = true
			case env.genKey == realSlowKey && env.kind == sampleEnvTimeout:
				sawSlowTimeout = true
			case env.genKey == realSlowKey && env.kind == sampleEnvFinished:
				t.Fatalf("the slow worker's own sampleEnvFinished arrived before this test ever closed gate — it cannot have been genuinely blocked the whole time")
			}
			s.handleSampleEnvelope(env)
		case <-time.After(heartbeatFast):
			// Standing in for heartbeatTicker.C: a real, synchronous,
			// on-disk write of the current state (submitFinalSnapshot, the
			// same machinery writeFinalSnapshotAndWait itself uses), not
			// merely a local counter of how many times this fired.
			// buildSnapshot's own call to s.now() is what Sensor.HeartbeatAt
			// on disk will carry, captured here so this test can tell two
			// such writes apart without re-reading the file for each one.
			snap := s.buildSnapshot(evidence.SensorOK)
			if rep := submitFinalSnapshot(s.writerCh, snap); rep.err != nil {
				t.Fatalf("synchronous heartbeat write: %v", rep.err)
			}
			heartbeatsSeen[snap.Sensor.HeartbeatAt] = true
		}
		if sawFastResult && sawSlowTimeout && len(heartbeatsSeen) >= 3 {
			break drain
		}
	}

	// Every assertion below runs at this exact point: gate has not been
	// touched yet, so the slow worker's own goroutine is still parked on
	// <-gate inside sampleFn — not "probably still blocked", provably so,
	// since slowStarted was observed above and the Fatalf in the drain loop
	// would already have fired had sampleEnvFinished arrived early.
	if atomic.LoadInt32(&slowStarted) != 1 {
		t.Fatalf("the slow sampleFn was never actually started")
	}
	if !gSlow.sampleAlive {
		t.Errorf("gSlow.sampleAlive = false while its own worker is still genuinely blocked on gate, want true")
	}
	if len(heartbeatsSeen) < 3 {
		t.Errorf("saw only %d distinct Sensor.HeartbeatAt value(s) actually written to disk, want at least 3 — heartbeat_at must keep advancing on its own fixed schedule regardless of the stalled generation", len(heartbeatsSeen))
	}

	// One more synchronous write, then read the file back, for the content
	// checks below — proving the *content* on disk, not merely that some
	// write happened.
	if rep := submitFinalSnapshot(s.writerCh, s.buildSnapshot(evidence.SensorOK)); rep.err != nil {
		t.Fatalf("synchronous write before reading the file: %v", rep.err)
	}
	r := evidence.NewReader(dir)
	snap, err := r.Read(time.Now(), nil)
	if err != nil {
		t.Fatalf("read evidence while the slow worker is still blocked: %v", err)
	}
	var sawFast, sawSlow bool
	for _, g := range snap.Generations {
		switch g.Container.ID {
		case strings64('b'):
			sawFast = true
			if g.LastVerifiedAt.IsZero() {
				t.Errorf("fast generation's own LastVerifiedAt is still zero on disk, want it advanced by its own applied sample result")
			}
			if len(g.Executables) != 1 || g.Executables[0].Path != fastExePath {
				t.Errorf("fast generation's own Executables = %+v, want exactly one entry for %s — its own observed content, not merely its presence", g.Executables, fastExePath)
			}
		case strings64('a'):
			sawSlow = true
			if g.State != evidence.StateStalled {
				t.Errorf("slow generation's own State on disk = %q, want stalled", g.State)
			}
		}
	}
	if !sawFast {
		t.Fatalf("the fast generation is missing from disk entirely")
	}
	if !sawSlow {
		t.Fatalf("the slow generation is missing from disk entirely")
	}

	close(gate) // release the slow worker now that every assertion above is done

	// Drain its belated sampleEnvFinished so the goroutine can exit cleanly.
	for {
		env := <-s.sampleResCh
		s.handleSampleEnvelope(env)
		if env.genKey == realSlowKey && env.kind == sampleEnvFinished {
			break
		}
	}
}

// TestLoop_StalledGenerationDoesNotBlockAnothersResultsOrRepeatedHeartbeats
// covers the same property the two tests above do, but by actually running
// (*Session).loop itself: loop's own goroutine could be entirely broken —
// never calling handleSampleEnvelope, dispatchWork, or the heartbeat write
// at all — and a test that only drives its own copy of that logic in a
// hand-rolled select (as the two tests above do) would still pass.
//
// discoverFn is what makes this possible without Docker: loop's own
// always-on initial discovery pass would otherwise run a real
// scanProcs()+groupContainers() against this test process's own /proc,
// which can never be made to recognize a synthetic, non-Docker container —
// reconcileGenerations would end both generations below within loop's very
// first pass, before either one's sample worker ever got a chance to run.
// discoverFn (nil in production, resolving straight back to the real
// scanProcs()+groupContainers() pair — see defaultDiscover) lets this test
// hand loop a fixed, synthetic set of container groups instead, so every
// step after that — reconcileGenerations, dispatchWork, startSampleWorker,
// handleSampleEnvelope, the heartbeat-triggered write — is exercised by the
// genuine, unmodified (*Session).loop.
//
// Every property this test checks is read back from the evidence file
// loop's own writer goroutine actually wrote, never a local counter: the
// fast generation's own real LastVerifiedAt and Executables content, the
// slow generation's own real State (stalled), and at least three distinct
// Sensor.HeartbeatAt values — all while gate remains closed, so the slow
// generation's own sample worker is provably still blocked inside sampleFn
// the whole time.
func TestLoop_StalledGenerationDoesNotBlockAnothersResultsOrRepeatedHeartbeats(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(dir+"/"+evidence.FileName, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	const (
		sampleTimeout = 40 * time.Millisecond
		heartbeatFast = 15 * time.Millisecond
	)

	gate := make(chan struct{})
	var slowStarted int32
	const fastExePath = "/usr/bin/fast-app"

	slowInit := InitProcess{PID: 101, Starttime: 1}
	fastInit := InitProcess{PID: 102, Starttime: 1}
	slowContainerID := strings64('a')
	fastContainerID := strings64('b')
	realSlowKey := genKey(slowContainerID, slowInit)

	groups := map[string]containerGroup{
		slowContainerID: {ContainerID: slowContainerID, Processes: []InitProcess{slowInit}, Init: slowInit},
		fastContainerID: {ContainerID: fastContainerID, Processes: []InitProcess{fastInit}, Init: fastInit},
	}

	s := &Session{
		cfg:              Config{EvidenceDir: dir, Interval: 30 * time.Second},
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
		heartbeatEvery:   heartbeatFast,
		sampleTimeout:    sampleTimeout,
		discoverFn: func() (map[string]containerGroup, error) {
			return groups, nil
		},
		sampleFn: func(job sampleJob) sampleResult {
			if job.genKey == realSlowKey {
				atomic.AddInt32(&slowStarted, 1)
				<-gate // held here until the test explicitly releases it, below
				return sampleResult{genKey: job.genKey, attempted: 1, succeeded: 1}
			}
			return sampleResult{
				genKey: job.genKey, attempted: 1, succeeded: 1,
				executables: []executableObs{{path: fastExePath, kind: evidence.KindExe, obs: evidence.ProcessObservation{LastSeen: job.now}}},
			}
		},
	}

	go runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)
	go func() {
		for range s.writerReportCh {
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.loop(ctx, evidence.SensorOK) }()

	r := evidence.NewReader(dir)
	deadline := time.Now().Add(8 * time.Second)
	var sawFastContent, sawSlowStalled bool
	heartbeatsSeen := map[time.Time]bool{}
	for time.Now().Before(deadline) {
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			heartbeatsSeen[snap.Sensor.HeartbeatAt] = true
			for _, g := range snap.Generations {
				switch g.Container.ID {
				case fastContainerID:
					if !g.LastVerifiedAt.IsZero() && len(g.Executables) == 1 && g.Executables[0].Path == fastExePath {
						sawFastContent = true
					}
				case slowContainerID:
					if g.State == evidence.StateStalled {
						sawSlowStalled = true
					}
				}
			}
		}
		if sawFastContent && sawSlowStalled && len(heartbeatsSeen) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Every check below is the result of polling disk state without ever
	// touching gate: the slow generation's own sample worker is still
	// genuinely parked inside sampleFn this whole time.
	if !sawSlowStalled {
		t.Errorf("the slow generation's own State never reached stalled on disk within the deadline")
	}
	if !sawFastContent {
		t.Errorf("the fast generation's own LastVerifiedAt/Executables content never appeared on disk within the deadline, while the slow generation was stalled")
	}
	if len(heartbeatsSeen) < 3 {
		t.Errorf("saw only %d distinct Sensor.HeartbeatAt value(s) on disk within the deadline, want at least 3 — heartbeat_at must keep advancing on its own fixed schedule regardless of the stalled generation", len(heartbeatsSeen))
	}
	if atomic.LoadInt32(&slowStarted) != 1 {
		t.Errorf("the slow sampleFn was never actually started")
	}

	close(gate)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("loop: %v", err)
	}
}
