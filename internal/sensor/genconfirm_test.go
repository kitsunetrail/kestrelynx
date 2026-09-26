package sensor

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

func TestConfirmGenerationAliveMatchesRealProcess(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)
	if !confirmGenerationAlive(pid, starttime) {
		t.Error("confirmGenerationAlive(self, self's own real starttime) = false, want true")
	}
}

func TestConfirmGenerationAliveRejectsWrongStarttime(t *testing.T) {
	if confirmGenerationAlive(os.Getpid(), 1) {
		t.Error("confirmGenerationAlive(self, 1) = true, want false -- 1 is certainly not this process's real starttime")
	}
}

func TestConfirmGenerationAliveRejectsGoneProcess(t *testing.T) {
	if confirmGenerationAlive(1<<30, 1) {
		t.Error("confirmGenerationAlive(a PID that should not exist, ...) = true, want false")
	}
}

func TestConfirmGenerationAliveRejectsNonPositivePID(t *testing.T) {
	if confirmGenerationAlive(0, 1) || confirmGenerationAlive(-1, 1) {
		t.Error("confirmGenerationAlive with a non-positive PID = true, want false")
	}
}

// TestConfirmGenerationAliveRejectsZombie confirms the fix for a starttime
// match alone being treated as proof of life: per proc_pid_stat(5), a
// zombie task's own /proc/<pid>/stat still reports its original, unchanged
// starttime right up until its parent actually reaps it, so a starttime-only
// check would let an already-exited process that simply has not been
// reaped yet pass as "still alive". This forks a real child (/bin/true,
// which exits almost immediately), confirms via waitid(P_PID, pid,
// WEXITED|WNOWAIT) — reporting the exit without reaping it, so the zombie
// this test needs to still exist when confirmGenerationAlive reads it is
// not consumed by this confirmation itself — that it is genuinely a zombie
// ('Z') with its own starttime unchanged, and only then confirms
// confirmGenerationAlive itself refuses it.
func TestConfirmGenerationAliveRejectsZombie(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start(/bin/true): %v", err)
	}
	pid := cmd.Process.Pid
	defer cmd.Wait() // actually reap it once this test is done either way

	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
		t.Fatalf("Waitid(WNOWAIT): %v", err)
	}

	h, err := procfs.Open(pid)
	if err != nil {
		t.Fatalf("procfs.Open(zombie child): %v", err)
	}
	starttime := h.Starttime()
	state, stateErr := h.State()
	h.Close()
	if stateErr != nil {
		t.Fatalf("State: %v", stateErr)
	}
	if state != 'Z' {
		t.Fatalf("test's own precondition failed: state = %q, want 'Z' (zombie) -- Waitid(WNOWAIT) should have reported the exit without reaping it", string(rune(state)))
	}

	if confirmGenerationAlive(pid, starttime) {
		t.Error("confirmGenerationAlive(zombie pid, its own real starttime) = true, want false -- a zombie's own unchanged starttime must never be treated as proof of life")
	}
}

// TestApplyGenConfirmResult_ConfirmedDispatchesRoutedEvent confirms the
// success half of genconfirm.go's own wiring end to end, using this test
// process's own real PID/starttime so confirmGenerationAlive's own real
// (non-test-double) implementation genuinely confirms it: the routed event
// reaches dispatchRoutedEvent (here, a path-unknown exec_success event with
// no TGID, so it lands as an immediate, generation-attributed loss) exactly
// as if resolveEventGeneration had resolved it outright.
func TestApplyGenConfirmResult_ConfirmedDispatchesRoutedEvent(t *testing.T) {
	s := newTestSessionForEvents()
	cid := strings64('z')
	init := InitProcess{PID: os.Getpid(), Starttime: mustStarttime(t, os.Getpid())}
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, init, s.now(), evidence.CoverageSinceStart)
	// Registered on both tables: applyGenConfirmResult re-resolves fresh via
	// resolveEventGeneration once confirmed (never trusts res.g directly —
	// see that function's own doc comment on why), so this test's own event
	// must actually be resolvable the same way a real one would be.
	s.generations[g.key()] = g
	s.cgroupRoute.set(70, "/system.slice/docker-"+cid+".scope", cid)
	// Started a few ticks after init itself, well clear of g's own starttime
	// tick, so this item's own proof rests on lastAliveNs alone (TGID=0, so
	// it could never be proven to be g's own init itself were it inside
	// that tick instead).
	item := pendingRouteEvent{
		ev:   ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 70, StartBoottimeNs: uint64(init.Starttime+5) * nsPerClockTick},
		kind: evidence.KindExecEvent, isExec: true, receivedAt: s.now(),
	}
	waitUntilBootNsPast(t, item.ev.StartBoottimeNs)

	s.submitGenConfirmRequest(genConfirmRequest{g: g, item: item})
	if g.pendingConfirms != 1 {
		t.Fatalf("pendingConfirms = %d, want 1 while the confirmation is outstanding", g.pendingConfirms)
	}

	select {
	case res := <-s.genConfirmCh:
		if !res.confirmed {
			t.Fatal("confirmed = false, want true for this test's own real, live process")
		}
		s.applyGenConfirmResult(res)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for genconfirm.go's own answer")
	}

	if g.pendingConfirms != 0 {
		t.Errorf("pendingConfirms = %d, want 0 after the result was applied", g.pendingConfirms)
	}
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (dispatchRoutedEvent -> resolvePathAndDispatch -> TGID=0 loss)", g.eventsLost)
	}
}

// TestApplyGenConfirmResult_UnconfirmedRequeuesAndRequestsDiscovery confirms
// the failure half: a candidate whose own PID/starttime does not check out
// right now (a restart this session's own discovery has not yet noticed) is
// never dispatched. Its own event goes back through the ordinary
// pendingRouteEvent queue instead (routeUnresolved's own eventual TTL
// applies to it from here on), and an early discovery pass is requested so
// the restart is noticed as soon as possible.
func TestApplyGenConfirmResult_UnconfirmedRequeuesAndRequestsDiscovery(t *testing.T) {
	s := newTestSessionForEvents()
	s.discoveryCh = make(chan discoveryResult, 1) // startDiscovery's own goroutine sends here
	discovered := make(chan struct{}, 1)
	s.discoverFn = func() (map[string]containerGroup, error) {
		discovered <- struct{}{}
		return map[string]containerGroup{}, nil
	}
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('1')}, InitProcess{PID: 1 << 30, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	item := pendingRouteEvent{ev: ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 90}, kind: evidence.KindExecEvent, isExec: true, receivedAt: s.now()}

	s.submitGenConfirmRequest(genConfirmRequest{g: g, item: item})

	select {
	case res := <-s.genConfirmCh:
		if res.confirmed {
			t.Fatal("confirmed = true, want false -- PID 1<<30 should never exist")
		}
		s.applyGenConfirmResult(res)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for genconfirm.go's own answer")
	}

	if len(s.pendingRouteEvents) != 1 {
		t.Fatalf("len(pendingRouteEvents) = %d, want 1 (requeued, not dispatched)", len(s.pendingRouteEvents))
	}
	if g.eventsLost != 0 {
		t.Errorf("eventsLost = %d, want 0 -- an unconfirmed candidate must never be charged a loss directly", g.eventsLost)
	}
	select {
	case <-discovered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the early discovery pass requestEarlyDiscovery should have started")
	}
}

// TestSubmitGenConfirmRequest_ConcurrencyAndQueueBounded confirms this pool's
// own resource bound (maxConcurrentGenConfirms/maxQueuedGenConfirms): past
// both, a request is counted as an unattributable loss (recordUnattributableEventLoss)
// instead of growing the goroutine count or the queue without bound — a
// ticks-matched candidate for a real, already-classified container is a
// Sensor-side capacity failure to lose, not a "too short-lived to observe"
// case (see submitGenConfirmRequest's own doc comment). Each request here
// names its own distinct generation, so this pool's own concurrency/queue
// bound is what is actually being exercised, never genConfirmWaiters'
// own per-generation coalescing (see the sibling
// TestSubmitGenConfirmRequest_CoalescesSameGeneration for that).
func TestSubmitGenConfirmRequest_ConcurrencyAndQueueBounded(t *testing.T) {
	s := newTestSessionForEvents()
	s.genConfirmCh = make(chan genConfirmResult, maxConcurrentGenConfirms)

	// Each request below names its own freshly allocated generationState —
	// never registered on s.generations, and never needing to be, since this
	// test calls submitGenConfirmRequest directly rather than going through
	// resolveEventGeneration.
	total := maxConcurrentGenConfirms + maxQueuedGenConfirms
	gens := make([]*generationState, total)
	for i := 0; i < total; i++ {
		gens[i] = newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('g')}, InitProcess{PID: 1 << 30, Starttime: int64(i + 1)}, s.now(), evidence.CoverageSinceStart)
		s.submitGenConfirmRequest(genConfirmRequest{g: gens[i], item: pendingRouteEvent{ev: ebpf.Event{Kind: ebpf.EventExecSuccess}}})
	}
	if s.genConfirmInFlight != maxConcurrentGenConfirms {
		t.Errorf("genConfirmInFlight = %d, want %d", s.genConfirmInFlight, maxConcurrentGenConfirms)
	}
	if len(s.genConfirmQueue) != maxQueuedGenConfirms {
		t.Errorf("len(genConfirmQueue) = %d, want %d", len(s.genConfirmQueue), maxQueuedGenConfirms)
	}
	for i, g := range gens {
		if g.pendingConfirms != 1 {
			t.Errorf("gens[%d].pendingConfirms = %d, want 1 (every accepted request counted once)", i, g.pendingConfirms)
		}
	}
	if s.unattributedEventsLost != 0 {
		t.Errorf("unattributedEventsLost = %d, want 0 so far (nothing has overflowed the pool yet)", s.unattributedEventsLost)
	}

	// One more request, past both bounds, must be dropped and counted as an
	// unattributable loss rather than accepted.
	overflow := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('h')}, InitProcess{PID: 1 << 30, Starttime: 999}, s.now(), evidence.CoverageSinceStart)
	s.submitGenConfirmRequest(genConfirmRequest{g: overflow, item: pendingRouteEvent{ev: ebpf.Event{Kind: ebpf.EventExecSuccess}}})
	if s.genConfirmInFlight != maxConcurrentGenConfirms {
		t.Errorf("genConfirmInFlight = %d, want unchanged at %d", s.genConfirmInFlight, maxConcurrentGenConfirms)
	}
	if len(s.genConfirmQueue) != maxQueuedGenConfirms {
		t.Errorf("len(genConfirmQueue) = %d, want unchanged at %d", len(s.genConfirmQueue), maxQueuedGenConfirms)
	}
	if overflow.pendingConfirms != 0 {
		t.Errorf("overflow.pendingConfirms = %d, want 0 (the overflow request was never accepted)", overflow.pendingConfirms)
	}
	if s.unattributedEventsLost != 1 {
		t.Errorf("unattributedEventsLost = %d, want 1 (the request that overflowed both bounds)", s.unattributedEventsLost)
	}
}

// TestSubmitGenConfirmRequest_CoalescesSameGeneration confirms that many
// requests naming the exact same generation while one confirmation for it is
// already outstanding never dispatch their own separate procfs read, or
// consume their own pool slot each: they coalesce onto genConfirmWaiters
// instead, and all receive the exact same answer once the one outstanding
// confirmation actually completes. This is what keeps a burst of many
// distinct usage events for one still-unconfirmed container (the common case
// under heavy exec churn) from exhausting this pool on its own.
func TestSubmitGenConfirmRequest_CoalescesSameGeneration(t *testing.T) {
	s := newTestSessionForEvents()
	s.genConfirmCh = make(chan genConfirmResult, 1)
	cid := strings64('3')
	init := InitProcess{PID: os.Getpid(), Starttime: mustStarttime(t, os.Getpid())}
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: cid}, init, s.now(), evidence.CoverageSinceStart)
	// Registered on both tables: applyGenConfirmResult re-resolves every
	// coalesced item fresh via resolveEventGeneration once confirmed, never
	// trusting the confirmation's own target generation directly.
	s.generations[g.key()] = g
	s.cgroupRoute.set(71, "/system.slice/docker-"+cid+".scope", cid)

	// Each item's own process start tick is a few ticks after g's own real
	// starttime — clear of g's own starttime tick (TGID=0, so it could
	// never be proven to be g's own init itself were it inside that tick
	// instead) — guaranteed to satisfy s_ns <= lastAliveNs once the
	// confirmation below advances it to (approximately) the current real
	// boot nanosecond, so this test actually exercises
	// resolveEventGeneration's own step-1 proof on each coalesced item,
	// rather than the unrelated zero-StartBoottimeNs aggregate shortcut.
	newItem := func() pendingRouteEvent {
		return pendingRouteEvent{
			ev:         ebpf.Event{Kind: ebpf.EventExecSuccess, CgroupID: 71, StartBoottimeNs: uint64(init.Starttime+5) * nsPerClockTick},
			kind:       evidence.KindExecEvent,
			isExec:     true,
			receivedAt: s.now(),
		}
	}

	const waiterCount = 50
	waitUntilBootNsPast(t, newItem().ev.StartBoottimeNs)
	s.submitGenConfirmRequest(genConfirmRequest{g: g, item: newItem()})
	for i := 0; i < waiterCount; i++ {
		s.submitGenConfirmRequest(genConfirmRequest{g: g, item: newItem()})
	}
	if s.genConfirmInFlight != 1 {
		t.Errorf("genConfirmInFlight = %d, want 1 (every waiter coalesced, none dispatched its own)", s.genConfirmInFlight)
	}
	if len(s.genConfirmQueue) != 0 {
		t.Errorf("len(genConfirmQueue) = %d, want 0 (coalesced waiters never touch the pool's own queue)", len(s.genConfirmQueue))
	}
	if len(g.genConfirmWaiters) != waiterCount {
		t.Fatalf("len(genConfirmWaiters) = %d, want %d", len(g.genConfirmWaiters), waiterCount)
	}

	select {
	case res := <-s.genConfirmCh:
		if !res.confirmed {
			t.Fatal("confirmed = false, want true for this test's own real, live process")
		}
		s.applyGenConfirmResult(res)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for genconfirm.go's own answer")
	}

	if len(g.genConfirmWaiters) != 0 {
		t.Errorf("len(genConfirmWaiters) = %d, want 0 after the result was applied", len(g.genConfirmWaiters))
	}
	if g.pendingConfirms != 0 {
		t.Errorf("pendingConfirms = %d, want 0 after the result was applied", g.pendingConfirms)
	}
	// The primary item plus every coalesced waiter (all TGID=0 exec_success
	// events) each land as their own generation-attributed loss via
	// dispatchRoutedEvent -> resolvePathAndDispatch.
	if want := int64(1 + waiterCount); g.eventsLost != want {
		t.Errorf("eventsLost = %d, want %d (the primary item plus every coalesced waiter)", g.eventsLost, want)
	}
}

// waitUntilBootNsPast blocks until CLOCK_BOOTTIME has moved past target, so
// a synthetic event start time placed a few ticks after a real process's
// own start is guaranteed to be earlier than any liveness check taken
// afterwards (the "after the start tick, no later than the check" window
// these tests depend on).
func waitUntilBootNsPast(t *testing.T, target uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		now, err := bootNsNow()
		if err != nil {
			t.Fatalf("bootNsNow: %v", err)
		}
		if now > target {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("CLOCK_BOOTTIME did not pass %d within 5s", target)
		}
		time.Sleep(time.Millisecond)
	}
}
