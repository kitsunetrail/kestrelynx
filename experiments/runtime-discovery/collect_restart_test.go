package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- pure classification functions -----------------------------------

// TestClassifyRestartDetectsAStartedAtChangeUnderTheSameID reproduces the
// simplest restart: docker restart keeps the id, PIDs are new, and only
// StartedAt moves.
func TestClassifyRestartDetectsAStartedAtChangeUnderTheSameID(t *testing.T) {
	when := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	ev := classifyRestart("backend", "same-id", "sha256:old", "2026-09-20T00:00:00Z", "sha256:old", "2026-09-22T11:59:00Z", when)
	if ev == nil {
		t.Fatal("a StartedAt change under the same id was not reported as a restart")
	}
	if ev.Kind != "restart" {
		t.Errorf("kind = %q, want restart", ev.Kind)
	}
	if ev.OldContainerID != "same-id" || ev.NewContainerID != "same-id" {
		t.Errorf("a restart must keep the same id on both sides, got old=%q new=%q", ev.OldContainerID, ev.NewContainerID)
	}
	if ev.StartedAtBefore != "2026-09-20T00:00:00Z" || ev.StartedAtAfter != "2026-09-22T11:59:00Z" {
		t.Errorf("StartedAt before/after = %q/%q", ev.StartedAtBefore, ev.StartedAtAfter)
	}
	if !ev.DetectedAt.Equal(when) {
		t.Errorf("DetectedAt = %v, want %v", ev.DetectedAt, when)
	}
}

// TestClassifyRestartIgnoresAnUnchangedOrUnknownStartedAt checks the cases
// that must NOT be reported: nothing changed, or one side was never
// established (a fresh target, or an inspect that itself just failed) —
// neither is evidence of a restart having happened.
func TestClassifyRestartIgnoresAnUnchangedOrUnknownStartedAt(t *testing.T) {
	cases := []struct {
		name                   string
		oldStarted, newStarted string
	}{
		{"unchanged", "2026-09-20T00:00:00Z", "2026-09-20T00:00:00Z"},
		{"old side unknown", "", "2026-09-20T00:00:00Z"},
		{"new side unknown (failed inspect)", "2026-09-20T00:00:00Z", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ev := classifyRestart("backend", "id", "img", c.oldStarted, "img", c.newStarted, time.Now()); ev != nil {
				t.Errorf("got a restart event %+v, want none", ev)
			}
		})
	}
}

// TestMatchRecreatedContainer checks the three outcomes a fresh container
// listing can produce for a name that used to answer to oldID: a
// re-creation under a new id, the same container still there (a transient
// failure, not a re-creation), and no match at all.
func TestMatchRecreatedContainer(t *testing.T) {
	summaries := []dockerContainerSummary{
		{ID: "new-id", Names: []string{"/backend"}, Image: "app:2"},
		{ID: "unrelated-id", Names: []string{"/frontend"}, Image: "app:2"},
	}
	if got := matchRecreatedContainer(summaries, "backend", "old-id"); got == nil || got.ID != "new-id" {
		t.Fatalf("matchRecreatedContainer = %+v, want the /backend entry with the new id", got)
	}
	if got := matchRecreatedContainer(summaries, "frontend", "unrelated-id"); got != nil {
		t.Errorf("the same id under its name was reported as a re-creation: %+v", got)
	}
	if got := matchRecreatedContainer(summaries, "does-not-exist", "old-id"); got != nil {
		t.Errorf("an unmatched name produced a result: %+v", got)
	}
	if got := matchRecreatedContainer(nil, "backend", "old-id"); got != nil {
		t.Errorf("an empty listing produced a result: %+v", got)
	}
}

// --- a fake Docker Engine API for the client-calling paths -------------

// fakeDockerAPI serves a minimal, mutable stand-in for the three endpoints
// the collector's client uses, over a real UNIX socket, so detectRecreate
// and rolloverGeneration are exercised through the same *dockerClient the
// collector itself uses rather than through a hand-substituted interface.
type fakeDockerAPI struct {
	list       []dockerContainerSummary
	inspectFor map[string]dockerInspect
	topFor     map[string]dockerTop
}

func newFakeDockerAPI(t *testing.T) (*fakeDockerAPI, *dockerClient, string) {
	t.Helper()
	api := &fakeDockerAPI{inspectFor: map[string]dockerInspect{}, topFor: map[string]dockerTop{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.list)
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		// paths are /containers/{id}/json or /containers/{id}/top
		rest := r.URL.Path[len("/containers/"):]
		id, action := rest, ""
		for i := 0; i < len(rest); i++ {
			if rest[i] == '/' {
				id, action = rest[:i], rest[i+1:]
				break
			}
		}
		switch action {
		case "json":
			insp, ok := api.inspectFor[id]
			if !ok {
				http.Error(w, "no such container", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(insp)
		case "top":
			top, ok := api.topFor[id]
			if !ok {
				http.Error(w, "no such container", http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(top)
		default:
			http.NotFound(w, r)
		}
	})

	sockPath := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on fake docker socket: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return api, newDockerClient(sockPath), sockPath
}

// TestDetectRecreateFindsTheReplacementContainer checks the whole
// client-calling path: an old id that no longer answers, and a fresh
// listing showing the same name under a new id.
func TestDetectRecreateFindsTheReplacementContainer(t *testing.T) {
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "new-id", Names: []string{"/backend"}, Image: "app:2"}}
	api.inspectFor["new-id"] = dockerInspect{Id: "new-id", Image: "sha256:new"}
	api.inspectFor["new-id"] = mustSetStartedAt(api.inspectFor["new-id"], "2026-09-22T12:00:00Z")

	rec := &ContainerRecord{
		Subject: Subject{Docker: DockerSubject{ContainerID: "old-id", ContainerName: "backend", ImageID: "sha256:old"}},
		Docker:  DockerConfig{StartedAt: "2026-09-20T00:00:00Z"},
	}
	ev := detectRecreate(context.Background(), client, rec)
	if ev == nil {
		t.Fatal("a container found under a new id was not reported as a re-creation")
	}
	if ev.Kind != "recreate" {
		t.Errorf("kind = %q, want recreate", ev.Kind)
	}
	if ev.OldContainerID != "old-id" || ev.NewContainerID != "new-id" {
		t.Errorf("old/new id = %q/%q, want old-id/new-id", ev.OldContainerID, ev.NewContainerID)
	}
	if ev.ImageIDBefore != "sha256:old" || ev.ImageIDAfter != "sha256:new" {
		t.Errorf("image id before/after = %q/%q", ev.ImageIDBefore, ev.ImageIDAfter)
	}
	if ev.StartedAtAfter != "2026-09-22T12:00:00Z" {
		t.Errorf("StartedAtAfter = %q", ev.StartedAtAfter)
	}
}

// TestDetectRecreateFindsNothingWhenTheOldContainerIsStillListed guards
// against turning a transient top/inspect failure into a false
// re-creation: if the old id is still in the listing, nothing has actually
// been replaced yet.
func TestDetectRecreateFindsNothingWhenTheOldContainerIsStillListed(t *testing.T) {
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "old-id", Names: []string{"/backend"}, Image: "app:1"}}
	rec := &ContainerRecord{Subject: Subject{Docker: DockerSubject{ContainerID: "old-id", ContainerName: "backend"}}}
	if ev := detectRecreate(context.Background(), client, rec); ev != nil {
		t.Errorf("got a re-creation event %+v for a container still present under its old id", ev)
	}
}

func mustSetStartedAt(insp dockerInspect, startedAt string) dockerInspect {
	insp.State.StartedAt = startedAt
	return insp
}

// --- collectContainerSample's return value ------------------------------

// TestCollectContainerSampleReturnsARestartEventOnlyWhenAsked checks that
// enabling restart tracking neither changes the sample recorded against
// the record (the failure that already existed) nor fires when tracking is
// off, and that it does fire, with the right fields, when it is on.
func TestCollectContainerSampleReturnsARestartEventOnlyWhenAsked(t *testing.T) {
	api, client, _ := newFakeDockerAPI(t)
	api.topFor["case-id"] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"1", "0", "root"}}}
	api.inspectFor["case-id"] = mustSetStartedAt(dockerInspect{Id: "case-id", Image: "sha256:new"}, "2026-09-22T12:00:00Z")

	newRec := func() *ContainerRecord {
		return &ContainerRecord{
			Subject: Subject{Docker: DockerSubject{ContainerID: "case-id", ContainerName: "backend", ImageID: "sha256:old"}},
			Docker:  DockerConfig{StartedAt: "2026-09-20T00:00:00Z"},
		}
	}
	state := newContainerCollectState(false, defaultAuxLimits())

	rec := newRec()
	if ev := collectContainerSample(context.Background(), client, rec, "s0", defaultPSArgs, state, false); ev != nil {
		t.Errorf("trackRestarts=false returned an event %+v, want nil", ev)
	}
	if len(rec.CollectionResults) != 1 {
		t.Fatalf("collection results = %d, want 1 regardless of restart tracking", len(rec.CollectionResults))
	}

	rec2 := newRec()
	state2 := newContainerCollectState(false, defaultAuxLimits())
	ev := collectContainerSample(context.Background(), client, rec2, "s0", defaultPSArgs, state2, true)
	if ev == nil {
		t.Fatal("trackRestarts=true did not report the StartedAt change as a restart")
	}
	if ev.Kind != "restart" || ev.NewContainerID != "case-id" {
		t.Errorf("event = %+v, want a restart under the same id", ev)
	}
	if len(rec2.CollectionResults) != 1 {
		t.Errorf("collection results = %d, want 1: the sample is still recorded even though a rollover is coming", len(rec2.CollectionResults))
	}
	foundRestartFailure := false
	for _, f := range rec2.Failures {
		if f.Step == "top_failed" {
			foundRestartFailure = true
		}
	}
	if !foundRestartFailure {
		t.Error("the existing restart failure was not recorded on the sample; returning an event must not replace it")
	}
}

// --- rolloverGeneration --------------------------------------------------

// TestRolloverGenerationPartitionsEvidence is the core requirement: the
// finalized generation's evidence must stay exactly as it was, and the new
// generation must start with genuinely empty collection state so nothing
// observed under the old container can be attributed to the one that
// replaced it.
func TestRolloverGenerationPartitionsEvidence(t *testing.T) {
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "new-id", Names: []string{"/backend"}, Image: "app:2"}}
	// prepareTarget needs a process to read through; give it one whose
	// mount-view lookup will fail harmlessly (no such /proc entry), which
	// is recorded as a failure on the new record rather than aborting the
	// rollover — the point under test is partitioning, not a clean layout
	// read.
	api.topFor["new-id"] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"999999", "0", "root"}}}

	oldState := newContainerCollectState(true, defaultAuxLimits())
	oldState.initialDBRead = InitialDBReadLoad{Measured: true, DurationMS: 42}
	oldState.ledgerSeen["marker"] = true // proves this state is not the one the new generation gets

	windowStart := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(5 * time.Minute)
	boundary := windowStart.Add(2 * time.Minute) // strictly inside the window, not at an edge
	// The confirmation inspect reports the same StartedAt the detected
	// event already carries: this test is the ordinary case, where the
	// container has not moved on again by the time rolloverGeneration
	// confirms it, so the boundary rolloverGeneration commits to must be
	// exactly what both sides agree on, not a mismatch correction (that
	// case has its own test below).
	api.inspectFor["new-id"] = mustSetStartedAt(dockerInspect{Id: "new-id", Image: "sha256:new"}, boundary.Format(time.RFC3339Nano))

	oldRec := &ContainerRecord{
		Subject:           Subject{Docker: DockerSubject{ContainerID: "old-id", ContainerName: "backend", ImageID: "sha256:old"}},
		Docker:            DockerConfig{StartedAt: "2026-09-20T00:00:00Z"},
		CollectionResults: []CollectionResult{{SampleID: "s0", Valid: true}},
	}
	// Every target's record starts with its window set to the run's own
	// whole-run bounds (see runCollect's setup loop in collect.go) before
	// closeGenerationEnd ever narrows it - reproduced here so
	// closeGenerationEnd's own idempotency check (it only narrows a window
	// still at its unmodified ScheduledEnd) sees a realistic starting
	// state rather than a zero-value one it would mistake for "already
	// narrowed".
	oldRec.Window.ScheduledStart, oldRec.Window.ScheduledEnd = windowStart, windowEnd
	tgt := &target{id: "old-id", record: oldRec, state: oldState}
	ev := GenerationEvent{
		Kind: "recreate", ContainerName: "backend",
		OldContainerID: "old-id", NewContainerID: "new-id",
		ImageIDBefore: "sha256:old", ImageIDAfter: "sha256:new",
		StartedAtBefore: "2026-09-20T00:00:00Z", StartedAtAfter: boundary.Format(time.RFC3339Nano),
		DetectedAt: time.Now().UTC(),
	}
	// The production call site (collect.go's per-tick loop) always closes
	// the current generation's own window end before attempting a
	// rollover, unconditionally - this test reproduces that same sequence
	// rather than relying on rolloverGeneration to compute the boundary
	// itself.
	closeGenerationEnd(tgt.record, ev, windowStart, windowEnd)
	if _, err := rolloverGeneration(context.Background(), client, tgt, ev, RunKey{CaseVariant: "prod"}, "w-1", time.Now(), "collect_start", windowStart, windowEnd, nil, true, defaultAuxLimits(), defaultPSArgs); err != nil {
		t.Fatalf("rolloverGeneration: %v", err)
	}

	if len(tgt.prior) != 1 || tgt.prior[0] != oldRec {
		t.Fatalf("prior generations = %v, want the original record preserved by identity", tgt.prior)
	}
	if len(tgt.prior[0].CollectionResults) != 1 || tgt.prior[0].CollectionResults[0].SampleID != "s0" {
		t.Errorf("the finalized generation's own samples were altered: %+v", tgt.prior[0].CollectionResults)
	}
	if tgt.prior[0].Load.InitialDBRead.DurationMS != 42 {
		t.Errorf("the finalized generation's initial-database-read cost was not carried over from its state: %+v", tgt.prior[0].Load.InitialDBRead)
	}
	if tgt.record == oldRec {
		t.Fatal("the target's active record still points at the old generation")
	}
	if tgt.id != "new-id" {
		t.Errorf("target id = %q, want new-id", tgt.id)
	}
	if tgt.record.Subject.Docker.ContainerID != "new-id" || tgt.record.Subject.Docker.ImageID != "sha256:new" {
		t.Errorf("new record identity = %+v", tgt.record.Subject.Docker)
	}
	if len(tgt.record.CollectionResults) != 0 {
		t.Errorf("the new generation already has %d collection result(s), want none", len(tgt.record.CollectionResults))
	}
	if tgt.state == oldState {
		t.Fatal("the new generation was given the old generation's collection state")
	}
	if len(tgt.state.ledgerSeen) != 0 {
		t.Errorf("the new generation's state is not empty: ledgerSeen = %v", tgt.state.ledgerSeen)
	}
	if tgt.state.initialDBRead.Measured {
		t.Error("the new generation's state already reports an initial database read")
	}
	if !tgt.record.Window.ScheduledStart.Equal(boundary) {
		t.Errorf("new generation ScheduledStart = %v, want the generation-change boundary %v", tgt.record.Window.ScheduledStart, boundary)
	}
	if !tgt.record.Window.ScheduledEnd.Equal(windowEnd) {
		t.Errorf("new generation ScheduledEnd = %v, want the run's own end %v", tgt.record.Window.ScheduledEnd, windowEnd)
	}
	if !tgt.prior[0].Window.ScheduledEnd.Equal(boundary) {
		t.Errorf("finalized generation's ScheduledEnd = %v, want it narrowed to the boundary %v instead of spanning the whole run", tgt.prior[0].Window.ScheduledEnd, boundary)
	}
	for _, f := range append(append([]Failure{}, tgt.record.Failures...), tgt.prior[0].Failures...) {
		if f.Step == "generation_boundary_unknown" {
			t.Errorf("a known StartedAt boundary was reported as unknown: %+v", f)
		}
	}
}

// TestGenerationBoundaryPrefersStartedAtOverDetection checks the ordering
// rule directly: a parseable new StartedAt wins even when a detection time
// is also present, and detection time is the fallback used only when
// StartedAt cannot be parsed at all.
func TestGenerationBoundaryPrefersStartedAtOverDetection(t *testing.T) {
	started := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	detected := started.Add(3 * time.Second)
	ev := GenerationEvent{StartedAtAfter: started.Format(time.RFC3339Nano), DetectedAt: detected}
	got, source := generationBoundary(ev)
	if source != "started_at" || !got.Equal(started) {
		t.Errorf("generationBoundary = %v/%q, want %v/started_at", got, source, started)
	}

	ev2 := GenerationEvent{StartedAtAfter: "not a timestamp", DetectedAt: detected}
	got2, source2 := generationBoundary(ev2)
	if source2 != "detected_at" || !got2.Equal(detected) {
		t.Errorf("generationBoundary (fallback) = %v/%q, want %v/detected_at", got2, source2, detected)
	}

	ev3 := GenerationEvent{}
	got3, source3 := generationBoundary(ev3)
	if source3 != "" || !got3.IsZero() {
		t.Errorf("generationBoundary with nothing to go on = %v/%q, want zero time and an empty source", got3, source3)
	}
}

// TestClampToWindow checks the three cases directly: inside, before, after.
func TestClampToWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	if got := clampToWindow(start.Add(30*time.Minute), start, end); !got.Equal(start.Add(30 * time.Minute)) {
		t.Errorf("inside: got %v", got)
	}
	if got := clampToWindow(start.Add(-time.Minute), start, end); !got.Equal(start) {
		t.Errorf("before: got %v, want start %v", got, start)
	}
	if got := clampToWindow(end.Add(time.Minute), start, end); !got.Equal(end) {
		t.Errorf("after: got %v, want end %v", got, end)
	}
}

// TestRolloverGenerationLeavesTheBoundaryUnknownWhenNeitherSourceIsAvailable
// checks the defensive path generationBoundary's own doc comment describes
// as not happening in practice: a GenerationEvent with no StartedAtAfter
// and a zero DetectedAt must not produce a guessed boundary; the window is
// left spanning the whole run and a Failure records why on both sides.
func TestRolloverGenerationLeavesTheBoundaryUnknownWhenNeitherSourceIsAvailable(t *testing.T) {
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "new-id", Names: []string{"/backend"}}}
	api.inspectFor["new-id"] = dockerInspect{Id: "new-id", Image: "sha256:new"}
	api.topFor["new-id"] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"999999", "0", "root"}}}

	oldRec := &ContainerRecord{Subject: Subject{Docker: DockerSubject{ContainerID: "old-id", ContainerName: "backend"}}}
	tgt := &target{id: "old-id", record: oldRec, state: newContainerCollectState(true, defaultAuxLimits())}
	ev := GenerationEvent{Kind: "recreate", ContainerName: "backend", OldContainerID: "old-id", NewContainerID: "new-id"} // no StartedAtAfter, zero DetectedAt

	windowStart := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(5 * time.Minute)
	tgt.record.Window.ScheduledStart, tgt.record.Window.ScheduledEnd = windowStart, windowEnd
	closeGenerationEnd(tgt.record, ev, windowStart, windowEnd)
	if _, err := rolloverGeneration(context.Background(), client, tgt, ev, RunKey{}, "w-1", time.Now(), "collect_start", windowStart, windowEnd, nil, true, defaultAuxLimits(), defaultPSArgs); err != nil {
		t.Fatalf("rolloverGeneration: %v", err)
	}
	if !tgt.prior[0].Window.ScheduledEnd.Equal(windowEnd) {
		t.Errorf("old generation's end was narrowed despite no known boundary: %v", tgt.prior[0].Window.ScheduledEnd)
	}
	// The new generation's own start is seeded from the old generation's
	// (unnarrowed) end, per rolloverGeneration's doc comment - here that is
	// windowEnd itself, which gives the new generation a zero-width window
	// at the very end of the run rather than a guessed earlier start: safe
	// (it can be credited with essentially no event evidence) rather than
	// wrong in either direction.
	if !tgt.record.Window.ScheduledStart.Equal(windowEnd) {
		t.Errorf("new generation's start = %v, want it seeded from the old generation's own (unnarrowed) end %v", tgt.record.Window.ScheduledStart, windowEnd)
	}
	foundOld := false
	for _, f := range tgt.prior[0].Failures {
		if f.Step == "generation_boundary_unknown" {
			foundOld = true
		}
	}
	if !foundOld {
		t.Error("expected a generation_boundary_unknown Failure on the old (closed) generation's record")
	}
}

// TestRolloverGenerationFailsWithoutLosingTheOldGenerationWhenTheNewContainerIsGone
// checks the degraded path: if the container named by the event can no
// longer be found (a listing race, or it was removed again immediately),
// rolloverGeneration reports the problem and leaves the target's old
// generation exactly where it was, rather than losing it or panicking.
func TestRolloverGenerationFailsWithoutLosingTheOldGenerationWhenTheNewContainerIsGone(t *testing.T) {
	_, client, _ := newFakeDockerAPI(t) // empty listing: nothing answers to new-id
	oldRec := &ContainerRecord{Subject: Subject{Docker: DockerSubject{ContainerID: "old-id", ContainerName: "backend"}}}
	tgt := &target{id: "old-id", record: oldRec, state: newContainerCollectState(true, defaultAuxLimits())}
	ev := GenerationEvent{Kind: "recreate", ContainerName: "backend", OldContainerID: "old-id", NewContainerID: "new-id"}

	_, err := rolloverGeneration(context.Background(), client, tgt, ev, RunKey{}, "w-1", time.Now(), "collect_start", time.Now(), time.Now(), nil, true, defaultAuxLimits(), defaultPSArgs)
	if err == nil {
		t.Fatal("want an error when the new container cannot be found, got nil")
	}
	if tgt.record != oldRec {
		t.Error("the target's record changed even though the rollover failed")
	}
	if len(tgt.prior) != 0 {
		t.Errorf("prior = %v, want none: a failed rollover must not finalize the old generation either", tgt.prior)
	}
}

// TestRolloverGenerationRetriesRatherThanCommittingAFailedInspect covers a
// re-creation whose replacement container is listed (so matchRecreatedContainer
// / detectRecreate already found it) but whose inspect fails right when
// rolloverGeneration itself tries to build its record from it - a narrower
// race than "the container cannot be found at all", and the one a fixed
// listing snapshot racing a fast second restart can actually produce. The
// old generation must stay exactly as it was so the very next sample's
// re-inspect sees the same mismatch and retries, instead of the target
// being stuck on a generation that was never actually observed.
func TestRolloverGenerationRetriesRatherThanCommittingAFailedInspect(t *testing.T) {
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "new-id", Names: []string{"/backend"}, Image: "app:2"}}
	// Deliberately no api.inspectFor["new-id"] entry: the fake server's
	// /containers/new-id/json returns 404, so newContainerRecord's own
	// inspect fails, the same as a container that raced past "listed" and
	// into "gone again" before this inspect reached it.

	oldState := newContainerCollectState(true, defaultAuxLimits())
	oldState.ledgerSeen["still-active"] = true
	oldRec := &ContainerRecord{
		Subject:           Subject{Docker: DockerSubject{ContainerID: "old-id", ContainerName: "backend", ImageID: "sha256:old"}},
		Docker:            DockerConfig{StartedAt: "2026-09-20T00:00:00Z"},
		CollectionResults: []CollectionResult{{SampleID: "s0", Valid: true}},
	}
	tgt := &target{id: "old-id", record: oldRec, state: oldState}
	ev := GenerationEvent{Kind: "recreate", ContainerName: "backend", OldContainerID: "old-id", NewContainerID: "new-id", DetectedAt: time.Now().UTC()}

	_, err := rolloverGeneration(context.Background(), client, tgt, ev, RunKey{}, "w-1", time.Now(), "collect_start", time.Now(), time.Now().Add(time.Minute), nil, true, defaultAuxLimits(), defaultPSArgs)
	if err == nil {
		t.Fatal("want an error when the new generation's inspect fails, got nil")
	}
	if tgt.record != oldRec {
		t.Error("the target's active record changed even though the new generation's inspect failed")
	}
	if tgt.state != oldState {
		t.Error("the target's collection state was replaced even though the new generation's inspect failed")
	}
	if tgt.id != "old-id" {
		t.Errorf("target id = %q, want it to stay old-id until a generation actually gets observed", tgt.id)
	}
	if len(tgt.prior) != 0 {
		t.Errorf("prior = %v, want none: the old generation must not be finalized until its replacement is confirmed observable", tgt.prior)
	}
	if len(oldState.ledgerSeen) != 1 {
		t.Errorf("the old generation's own collection state was disturbed: %v", oldState.ledgerSeen)
	}
}

// TestRolloverGenerationCorrectsForARestartThatHappenedDuringConfirmation
// covers the gap between a change being detected and rolloverGeneration's
// own confirmation inspect actually running: the event says the container
// (still the same id - a restart, not a re-creation) now has StartedAt=t1,
// but by the time the confirmation inspect answers, a second restart has
// already happened and the container's real StartedAt is t2. Committing
// against t1 would credit the generation that starts here with everything
// from t1 onward, including activity that actually belongs to a
// generation the event never described at all. The inspect result must
// win: the committed generation starts at t2, and a correction event
// describing t1->t2 is handed back so the caller can record it as its own
// generation change rather than silently folding it into the original.
func TestRolloverGenerationCorrectsForARestartThatHappenedDuringConfirmation(t *testing.T) {
	const id = "steady-id"
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: id, Names: []string{"/backend"}, Image: "app:1"}}
	api.topFor[id] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"999999", "0", "root"}}}

	windowStart := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(5 * time.Minute)
	t1 := windowStart.Add(1 * time.Minute) // what the event detected
	t2 := windowStart.Add(2 * time.Minute) // what the confirmation inspect actually finds, later than t1

	// The confirmation inspect answers with the SAME id (this is a
	// restart, not a re-creation) but a StartedAt the detected event never
	// saw: a second restart happened in the gap between detection and
	// this confirmation.
	api.inspectFor[id] = mustSetStartedAt(dockerInspect{Id: id, Image: "sha256:app1"}, t2.Format(time.RFC3339Nano))

	oldRec := &ContainerRecord{
		Subject:           Subject{Docker: DockerSubject{ContainerID: id, ContainerName: "backend", ImageID: "sha256:app1"}},
		Docker:            DockerConfig{StartedAt: "2026-09-22T00:00:00Z"},
		CollectionResults: []CollectionResult{{SampleID: "s0", Valid: true}},
	}
	oldRec.Window.ScheduledStart, oldRec.Window.ScheduledEnd = windowStart, windowEnd
	tgt := &target{id: id, record: oldRec, state: newContainerCollectState(true, defaultAuxLimits())}
	ev := GenerationEvent{
		Kind: "restart", ContainerName: "backend",
		OldContainerID: id, NewContainerID: id,
		ImageIDBefore: "sha256:app1", ImageIDAfter: "sha256:app1",
		StartedAtBefore: "2026-09-22T00:00:00Z", StartedAtAfter: t1.Format(time.RFC3339Nano),
		DetectedAt: t1.Add(2 * time.Second),
	}
	closeGenerationEnd(tgt.record, ev, windowStart, windowEnd)
	correction, err := rolloverGeneration(context.Background(), client, tgt, ev, RunKey{}, "w-1", time.Now(), "collect_start", windowStart, windowEnd, nil, true, defaultAuxLimits(), defaultPSArgs)
	if err != nil {
		t.Fatalf("rolloverGeneration: %v", err)
	}

	if correction == nil {
		t.Fatal("want a correction event when the confirmation inspect disagrees with the detected event, got nil")
	}
	if correction.StartedAtBefore != t1.Format(time.RFC3339Nano) || correction.StartedAtAfter != t2.Format(time.RFC3339Nano) {
		t.Errorf("correction event = %+v, want StartedAtBefore=%s StartedAtAfter=%s", correction, t1.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
	}
	if correction.OldContainerID != id || correction.NewContainerID != id {
		t.Errorf("correction event ids = %q/%q, want both %q (a restart, same id)", correction.OldContainerID, correction.NewContainerID, id)
	}
	if correction.Kind != "restart" {
		t.Errorf("correction.Kind = %q, want restart (same id on both sides)", correction.Kind)
	}

	if !tgt.record.Window.ScheduledStart.Equal(t2) {
		t.Errorf("committed generation's start = %v, want the inspected StartedAt t2 = %v, not the event's stale t1 = %v", tgt.record.Window.ScheduledStart, t2, t1)
	}
	if len(tgt.prior) != 1 {
		t.Fatalf("prior generations = %d, want exactly 1", len(tgt.prior))
	}
	// The old generation's own end is unaffected by the correction: it was
	// already closed at t1 by closeGenerationEnd before rolloverGeneration
	// ever ran, and the gap between t1 and t2 is left attributed to
	// neither generation rather than guessed at.
	if !tgt.prior[0].Window.ScheduledEnd.Equal(t1) {
		t.Errorf("old generation's end = %v, want it to stay at the originally detected boundary t1 = %v", tgt.prior[0].Window.ScheduledEnd, t1)
	}
}

// TestRolloverGenerationUsesConfirmedStartedAtWhenDetectionInspectFailed covers
// the case where detectRecreate's own inspect of the newly found id failed
// (the common way a re-creation's own StartedAtAfter ends up empty), but by the
// time rolloverGeneration's own confirmation inspect runs, the same id answers
// successfully with a real StartedAt. That StartedAt must be used for the new
// generation's own boundary instead of falling back to DetectedAt (a coarser,
// later instant that would wrongly exclude activity between the real start and
// the moment this collector happened to notice the change).
func TestRolloverGenerationUsesConfirmedStartedAtWhenDetectionInspectFailed(t *testing.T) {
	const oldID, newID = "old-id", "new-id"
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: newID, Names: []string{"/backend"}, Image: "app:2"}}
	api.topFor[newID] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"999999", "0", "root"}}}

	windowStart := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(5 * time.Minute)
	realStart := windowStart.Add(90 * time.Second) // the new container's real StartedAt
	detectedAt := windowStart.Add(3 * time.Minute) // well after realStart - what DetectedAt fallback would wrongly use

	// The confirmation inspect succeeds this time, unlike the detection-time one
	// that produced ev below.
	api.inspectFor[newID] = mustSetStartedAt(dockerInspect{Id: newID, Image: "sha256:new"}, realStart.Format(time.RFC3339Nano))

	oldRec := &ContainerRecord{
		Subject:           Subject{Docker: DockerSubject{ContainerID: oldID, ContainerName: "backend", ImageID: "sha256:old"}},
		Docker:            DockerConfig{StartedAt: "2026-09-20T00:00:00Z"},
		CollectionResults: []CollectionResult{{SampleID: "s0", Valid: true}},
	}
	oldRec.Window.ScheduledStart, oldRec.Window.ScheduledEnd = windowStart, windowEnd
	tgt := &target{id: oldID, record: oldRec, state: newContainerCollectState(true, defaultAuxLimits())}
	// This is exactly what detectRecreate produces when matchRecreatedContainer
	// finds the new id but the immediately following inspectContainer call for it
	// fails: StartedAtAfter stays empty even though the new id is already known.
	ev := GenerationEvent{
		Kind: "recreate", ContainerName: "backend",
		OldContainerID: oldID, NewContainerID: newID,
		ImageIDBefore: "sha256:old", ImageIDAfter: "",
		StartedAtBefore: "2026-09-20T00:00:00Z", StartedAtAfter: "",
		DetectedAt: detectedAt,
	}
	closeGenerationEnd(tgt.record, ev, windowStart, windowEnd)
	correction, err := rolloverGeneration(context.Background(), client, tgt, ev, RunKey{}, "w-1", time.Now(), "collect_start", windowStart, windowEnd, nil, true, defaultAuxLimits(), defaultPSArgs)
	if err != nil {
		t.Fatalf("rolloverGeneration: %v", err)
	}

	if correction == nil {
		t.Fatal("want a correction event filling in the confirmed StartedAt, got nil")
	}
	if correction.Kind != "recreate" {
		t.Errorf("correction.Kind = %q, want recreate (ev's own kind - no further identity change happened, just a gap filled in)", correction.Kind)
	}
	if correction.OldContainerID != oldID || correction.NewContainerID != newID {
		t.Errorf("correction event ids = %q/%q, want %q/%q (ev's own identity, unchanged)", correction.OldContainerID, correction.NewContainerID, oldID, newID)
	}
	if correction.StartedAtAfter != realStart.Format(time.RFC3339Nano) {
		t.Errorf("correction.StartedAtAfter = %q, want the confirmed StartedAt %q", correction.StartedAtAfter, realStart.Format(time.RFC3339Nano))
	}

	if !tgt.record.Window.ScheduledStart.Equal(realStart) {
		t.Errorf("new generation's start = %v, want the confirmed StartedAt %v, not DetectedAt %v", tgt.record.Window.ScheduledStart, realStart, detectedAt)
	}
}

// TestRolloverGenerationCorrectionKindReflectsItsOwnIdsNotEvsKind covers a
// re-creation (A -> B) detected, but before rolloverGeneration ever confirms
// it, B itself restarts (same id, new StartedAt). The resulting
// correction describes B restarting - both its old and new id are B's own id -
// and must be reported as Kind "restart", never "recreate" copied from the
// original A->B event that detected an entirely different kind of change.
func TestRolloverGenerationCorrectionKindReflectsItsOwnIdsNotEvsKind(t *testing.T) {
	const oldID, bID = "a-id", "b-id"
	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: bID, Names: []string{"/backend"}, Image: "app:2"}}
	api.topFor[bID] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"999999", "0", "root"}}}

	windowStart := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(5 * time.Minute)
	t1 := windowStart.Add(1 * time.Minute) // B's StartedAt as detected by the A->B recreate event
	t2 := windowStart.Add(2 * time.Minute) // B's real StartedAt by the time confirmation runs (B restarted itself)

	// The confirmation inspect finds the SAME id (bID) but a later StartedAt: B
	// itself restarted between the A->B recreate detection and this confirmation.
	api.inspectFor[bID] = mustSetStartedAt(dockerInspect{Id: bID, Image: "sha256:b"}, t2.Format(time.RFC3339Nano))

	oldRec := &ContainerRecord{
		Subject:           Subject{Docker: DockerSubject{ContainerID: oldID, ContainerName: "backend", ImageID: "sha256:a"}},
		Docker:            DockerConfig{StartedAt: "2026-09-20T00:00:00Z"},
		CollectionResults: []CollectionResult{{SampleID: "s0", Valid: true}},
	}
	oldRec.Window.ScheduledStart, oldRec.Window.ScheduledEnd = windowStart, windowEnd
	tgt := &target{id: oldID, record: oldRec, state: newContainerCollectState(true, defaultAuxLimits())}
	// A re-creation, A -> B, exactly as detectRecreate would report it.
	ev := GenerationEvent{
		Kind: "recreate", ContainerName: "backend",
		OldContainerID: oldID, NewContainerID: bID,
		ImageIDBefore: "sha256:a", ImageIDAfter: "sha256:b",
		StartedAtBefore: "2026-09-20T00:00:00Z", StartedAtAfter: t1.Format(time.RFC3339Nano),
		DetectedAt: t1.Add(2 * time.Second),
	}
	closeGenerationEnd(tgt.record, ev, windowStart, windowEnd)
	correction, err := rolloverGeneration(context.Background(), client, tgt, ev, RunKey{}, "w-1", time.Now(), "collect_start", windowStart, windowEnd, nil, true, defaultAuxLimits(), defaultPSArgs)
	if err != nil {
		t.Fatalf("rolloverGeneration: %v", err)
	}

	if correction == nil {
		t.Fatal("want a correction event when B's own restart is discovered at confirmation, got nil")
	}
	if correction.Kind != "restart" {
		t.Errorf("correction.Kind = %q, want restart (same id on both sides), not ev's own Kind %q", correction.Kind, ev.Kind)
	}
	if correction.OldContainerID != bID || correction.NewContainerID != bID {
		t.Errorf("correction event ids = %q/%q, want both %q (B restarting, not A->B again)", correction.OldContainerID, correction.NewContainerID, bID)
	}
	if !tgt.record.Window.ScheduledStart.Equal(t2) {
		t.Errorf("committed generation's start = %v, want B's real StartedAt t2 = %v", tgt.record.Window.ScheduledStart, t2)
	}
}

// TestAppendGenerationEventWritesJSONLines checks the on-disk trail
// prod-observe.sh polls to know when to refresh the cgroup table: one JSON
// object per line, appended rather than replaced.
func TestAppendGenerationEventWritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "restarts.jsonl")
	ev1 := GenerationEvent{Kind: "restart", ContainerName: "backend", SampleID: "s0"}
	ev2 := GenerationEvent{Kind: "recreate", ContainerName: "frontend", SampleID: "s5"}
	if err := appendGenerationEvent(path, ev1); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if err := appendGenerationEvent(path, ev2); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got []GenerationEvent
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var ev GenerationEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal line %q: %v", line, err)
		}
		got = append(got, ev)
	}
	if len(got) != 2 || got[0].ContainerName != "backend" || got[1].ContainerName != "frontend" {
		t.Fatalf("got %+v, want both events in append order", got)
	}
}
