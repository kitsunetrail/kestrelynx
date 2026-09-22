package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// packageByName finds one package's verdict entry in a match result, or
// fails the test - every assertion below is about one specific package's
// s2_verdict, and a missing entry is itself a test failure, not a nil
// verdict to compare against.
func packageByName(t *testing.T, r MatchResult, name string) PackageVerdict {
	t.Helper()
	for _, pv := range r.Packages {
		if pv.Package == name {
			return pv
		}
	}
	t.Fatalf("no package %q in the match result", name)
	return PackageVerdict{}
}

// TestGenerationWindowNarrowingPreventsCrossGenerationEventAttribution is
// the direct proof for the restart-tracking fix: two generations sharing
// the same container id (a same-id restart, the case a differing id could
// not by itself protect against) and the same event log must each be
// credited only with the events that actually fall inside their own,
// narrowed Window.ScheduledStart/ScheduledEnd - never with an event that
// happened under the other generation.
//
// It runs the real match pipeline (runMatchPipeline, the same function the
// match subcommand and every other match test in this package call)
// against the hand-written testdata/synthetic_events_* fixtures, which
// already carry a container ("c0ffee...0001") with a real event log
// containing, among others: two "open" events for lodash at
// 2026-09-13T00:01:00.1-00:01:00.21Z, and one "exec" event for curl at
// 2026-09-13T00:01:40Z. Splitting the window at 00:01:20.5Z - a moment
// with no event on either side of it - puts lodash's events strictly
// before the split and curl's strictly after, exactly the way
// rolloverGeneration narrows a real restart's two generations.
func TestGenerationWindowNarrowingPreventsCrossGenerationEventAttribution(t *testing.T) {
	trivyData, err := os.ReadFile("testdata/synthetic_events_trivy.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(trivyData)
	if err != nil {
		t.Fatalf("parse scan report: %v", err)
	}
	idx, _, err := buildScanFileIndex(trivyData, false)
	if err != nil {
		t.Fatalf("index the scan report's paths: %v", err)
	}
	def, err := readCase("testdata/synthetic_events_case.json")
	if err != nil {
		t.Fatalf("read case: %v", err)
	}
	events, err := readEventLog("testdata/synthetic_events.jsonl")
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}

	loadRecord := func(t *testing.T) ContainerRecord {
		t.Helper()
		rec, err := readContainerRecord("testdata/synthetic_events_observation.json")
		if err != nil {
			t.Fatalf("read observation: %v", err)
		}
		return rec
	}

	boundary := mustParseRFC3339(t, "2026-09-13T00:01:20.500000000Z")

	// Generation 1: the fixture's own window, narrowed at its end to the
	// boundary - simulating the record rolloverGeneration leaves behind in
	// t.prior once a restart is detected at that instant.
	gen1 := loadRecord(t)
	gen1.Window.ScheduledEnd = boundary

	// Generation 2: same container id (a same-id restart, not a
	// re-creation - the case id-based attribution alone cannot separate),
	// narrowed at its start to the same boundary - simulating the new
	// record rolloverGeneration hands the target over to.
	gen2 := loadRecord(t)
	gen2.Window.ScheduledStart = boundary

	intel := syntheticIntel()
	result1, err := runMatchPipeline(context.Background(), gen1, scan, idx, nil, def, nil, events,
		intel, t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match (generation 1): %v", err)
	}
	result2, err := runMatchPipeline(context.Background(), gen2, scan, idx, nil, def, nil, events,
		intel, t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match (generation 2): %v", err)
	}

	lodash1 := packageByName(t, result1, "lodash")
	curl1 := packageByName(t, result1, "curl")
	lodash2 := packageByName(t, result2, "lodash")
	curl2 := packageByName(t, result2, "curl")

	if lodash1.S2Verdict != VerdictConfirmed {
		t.Errorf("generation 1: lodash s2_verdict = %q, want confirmed (its open events fall before the boundary)", lodash1.S2Verdict)
	}
	if curl1.S2Verdict == VerdictConfirmed {
		t.Errorf("generation 1: curl s2_verdict = confirmed, but its exec event is AFTER this generation's own window ended - it must not be credited here")
	}
	if curl2.S2Verdict != VerdictConfirmed {
		t.Errorf("generation 2: curl s2_verdict = %q, want confirmed (its exec event falls after the boundary)", curl2.S2Verdict)
	}
	if lodash2.S2Verdict == VerdictConfirmed {
		t.Errorf("generation 2: lodash s2_verdict = confirmed, but its open events are BEFORE this generation's own window started - it must not be credited here")
	}

	// Every confirmation actually kept must itself carry a timestamp inside
	// the generation's own window - not merely a verdict that happens to
	// agree, but the underlying evidence honoring the same boundary.
	for _, c := range lodash1.Confirmations {
		if c.ObservedAt.After(boundary) {
			t.Errorf("generation 1 kept a lodash confirmation observed at %v, after its own window ended at %v", c.ObservedAt, boundary)
		}
	}
	for _, c := range curl2.Confirmations {
		if c.ObservedAt.Before(boundary) {
			t.Errorf("generation 2 kept a curl confirmation observed at %v, before its own window started at %v", c.ObservedAt, boundary)
		}
	}
}

func mustParseRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

// TestRealRolloverOutputPreventsCrossGenerationEventAttribution is the
// regression test the window-narrowing fix itself needs: unlike
// TestGenerationWindowNarrowingPreventsCrossGenerationEventAttribution
// above, which sets each generation's Window by hand to check that match
// honors it, this test calls closeGenerationEnd and rolloverGeneration -
// the actual functions collect.go's per-tick loop calls on every detected
// restart - through a fake Docker Engine API, and only THEN runs the
// generation each one actually produced through the real match pipeline.
// Removing (or breaking) the window-narrowing inside either function makes
// this test fail; hand-setting the window elsewhere could not have caught
// that, since it never exercises the code path that computes it.
//
// The finalized old generation (t.prior[0], a full copy of the synthetic
// fixture with a genuinely computed, narrowed ScheduledEnd) is what proves
// the exclusion: it still carries every mapping input capable of
// confirming curl's event, so if the narrowing were ever removed nothing
// about its inputs would stop curl's post-boundary event from being
// confirmed there too. The newly rolled-over generation (t.record) has no
// real samples of its own - rolloverGeneration only just created it, and
// this test does not simulate any sampling ticks against it - so it is
// checked only for the window boundary rolloverGeneration actually gave
// it, which is the other half of the same computation.
func TestRealRolloverOutputPreventsCrossGenerationEventAttribution(t *testing.T) {
	trivyData, err := os.ReadFile("testdata/synthetic_events_trivy.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(trivyData)
	if err != nil {
		t.Fatalf("parse scan report: %v", err)
	}
	idx, _, err := buildScanFileIndex(trivyData, false)
	if err != nil {
		t.Fatalf("index the scan report's paths: %v", err)
	}
	def, err := readCase("testdata/synthetic_events_case.json")
	if err != nil {
		t.Fatalf("read case: %v", err)
	}
	events, err := readEventLog("testdata/synthetic_events.jsonl")
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}

	const containerID = "c0ffee0000000000000000000000000000000000000000000000000000000001"
	oldRec, err := readContainerRecord("testdata/synthetic_events_observation.json")
	if err != nil {
		t.Fatalf("read observation: %v", err)
	}
	windowStart, windowEnd := oldRec.Window.ScheduledStart, oldRec.Window.ScheduledEnd

	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: containerID, Names: []string{"/" + oldRec.Subject.Docker.ContainerName}, Image: oldRec.Subject.Docker.ImageRef}}
	newStartedAt := "2026-09-13T00:01:20.500000000Z" // the same boundary the hand-set test above uses
	api.inspectFor[containerID] = mustSetStartedAt(dockerInspect{Id: containerID, Image: oldRec.Subject.Docker.ImageID}, newStartedAt)
	// prepareTarget (called inside rolloverGeneration for the new
	// generation) needs a process to read through; this test's own PID is
	// used because it is a real, readable process on this host, unlike a
	// made-up one - what matters here is that prepareTarget completes
	// without crashing, not that it resolves this test binary's own
	// procfs entries to anything meaningful.
	api.topFor[containerID] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{strconv.Itoa(os.Getpid()), "0", "root"}}}

	tgt := &target{id: containerID, record: &oldRec, state: newContainerCollectState(false, defaultAuxLimits())}
	ev := GenerationEvent{
		Kind: "restart", ContainerName: oldRec.Subject.Docker.ContainerName,
		OldContainerID: containerID, NewContainerID: containerID,
		ImageIDBefore: oldRec.Subject.Docker.ImageID, ImageIDAfter: oldRec.Subject.Docker.ImageID,
		StartedAtBefore: oldRec.Subject.StartedAt, StartedAtAfter: newStartedAt,
		DetectedAt: mustParseRFC3339(t, "2026-09-13T00:01:25Z"),
	}

	// This is the exact call sequence collect.go's per-tick loop makes on
	// every detected generation change (see the comment at that call
	// site): close the current generation's own window end first,
	// unconditionally, then attempt the rollover.
	closeGenerationEnd(tgt.record, ev, windowStart, windowEnd)
	if _, err := rolloverGeneration(context.Background(), client, tgt, ev, oldRec.RunKey, oldRec.Window.ID, oldRec.Window.PhaseBase, oldRec.Window.PhaseBaseFrom, windowStart, windowEnd, nil, false, defaultAuxLimits(), defaultPSArgs); err != nil {
		t.Fatalf("rolloverGeneration: %v", err)
	}
	if len(tgt.prior) != 1 {
		t.Fatalf("prior generations = %d, want 1", len(tgt.prior))
	}
	gen1, gen2 := *tgt.prior[0], *tgt.record // copy: runMatchPipeline takes ContainerRecord by value

	boundary := mustParseRFC3339(t, newStartedAt)
	if !gen1.Window.ScheduledEnd.Equal(boundary) {
		t.Fatalf("rolloverGeneration gave the finalized generation ScheduledEnd = %v, want the real boundary %v - the assertions below would not be testing what they claim to", gen1.Window.ScheduledEnd, boundary)
	}
	if !gen2.Window.ScheduledStart.Equal(boundary) {
		t.Errorf("rolloverGeneration gave the new generation ScheduledStart = %v, want the same real boundary %v", gen2.Window.ScheduledStart, boundary)
	}

	intel := syntheticIntel()
	result1, err := runMatchPipeline(context.Background(), gen1, scan, idx, nil, def, nil, events,
		intel, t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match (finalized old generation): %v", err)
	}

	lodash1 := packageByName(t, result1, "lodash")
	curl1 := packageByName(t, result1, "curl")
	if lodash1.S2Verdict != VerdictConfirmed {
		t.Errorf("finalized generation: lodash s2_verdict = %q, want confirmed (its open events fall before the real, rollover-computed boundary)", lodash1.S2Verdict)
	}
	if curl1.S2Verdict == VerdictConfirmed {
		t.Error("finalized generation: curl s2_verdict = confirmed, but its exec event is after the real, rollover-computed boundary - this is exactly what deleting the window-narrowing inside rolloverGeneration/closeGenerationEnd would allow")
	}

	// The new generation itself, run through the same real match pipeline.
	// rolloverGeneration's own prepareTarget could not read a real package
	// database for it (there is no real container rootfs behind this
	// test's own PID), so it is given the same mapping inputs the
	// original fixture carries before match sees it - a restarted
	// container of the same image legitimately has the same package
	// database, and what is under test here is the WINDOW rolloverGeneration
	// computed, not prepareTarget's own read.
	copyMappingInputs(&gen2, oldRec)
	result2, err := runMatchPipeline(context.Background(), gen2, scan, idx, nil, def, nil, events,
		intel, t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match (new generation): %v", err)
	}
	lodash2 := packageByName(t, result2, "lodash")
	curl2 := packageByName(t, result2, "curl")
	if curl2.S2Verdict != VerdictConfirmed {
		t.Errorf("new generation: curl s2_verdict = %q, want confirmed (its exec event falls after the real, rollover-computed boundary)", curl2.S2Verdict)
	}
	if lodash2.S2Verdict == VerdictConfirmed {
		t.Error("new generation: lodash s2_verdict = confirmed, but its open events are before the real, rollover-computed boundary - they belong to the generation that was replaced")
	}
}

// copyMappingInputs copies the file-to-package mapping inputs (everything
// prepareTarget would have read through a real rootfs) from src onto dst,
// standing in for prepareTarget's own read in a test where the "new
// generation" has no real container behind it to read through - only the
// generation's own Window (what these tests are actually about) is left
// exactly as rolloverGeneration produced it.
func copyMappingInputs(dst *ContainerRecord, src ContainerRecord) {
	dst.AuxiliaryInputs = src.AuxiliaryInputs
	dst.PkgDBs = src.PkgDBs
	dst.PackageLedger = src.PackageLedger
	dst.InodeCalibration = src.InodeCalibration
}

// writeSyntheticEventLog writes a minimal event log JSONL file (the same
// wire shape testdata/synthetic_events.jsonl uses) with one header line,
// one line per given event, and a trailer, and reads it back through the
// real readEventLog - so tests that need events at specific instants this
// package's own fixtures do not happen to carry are still exercised
// through the real parser rather than an assembled-by-hand *EventLog that
// could skip an invariant only the parser itself sets up.
type syntheticEvent struct {
	ts, event, rawPath, source string
	pid                        int
}

func writeSyntheticEventLog(t *testing.T, containerID string, runKey RunKey, events []syntheticEvent) *EventLog {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create event log: %v", err)
	}
	fmt.Fprintf(f, `{"record":"events_header","config_id":%q,"sync":%q,"method":"bpftrace","version":"runtime-events.bt v1","started_at":"2026-09-13T00:00:00Z","boot_epoch":"2026-09-12T20:00:00Z","clock_note":"test","container_id":%q,"started":true,"attached":true,"clock_source":"CLOCK_MONOTONIC","clock_error_ns":0,"path_buffer_len":256}`+"\n",
		runKey.ConfigID, runKey.Sync, containerID)
	for i, e := range events {
		pid := e.pid
		if pid == 0 {
			pid = 4242
		}
		fmt.Fprintf(f, `{"record":"event","ts":%q,"event":%q,"pid":%d,"tid":%d,"starttime":"12345","raw_path":%q,"path":%q,"path_resolved":true,"ok":true,"cgroup_id":52161,"container_id":%q,"cgroup_depth":0,"attribution":"container","source":%q}`+"\n",
			e.ts, e.event, pid, pid, e.rawPath, e.rawPath, containerID, e.source)
		_ = i
	}
	fmt.Fprintf(f, `{"record":"events_trailer","ended_at":"2026-09-13T00:05:10Z","drops":{"lost_events":0,"lost_notifications":0,"enter_exit_unmatched":0,"map_overflow":0,"path_read_failures":0,"path_truncations":0,"convert_failures":0,"events_before_filter":%d,"events_after_filter":%d},"detach_confirmed":true,"detach_note":"test"}`+"\n",
		len(events), len(events))
	if err := f.Close(); err != nil {
		t.Fatalf("close event log: %v", err)
	}
	log, err := readEventLog(path)
	if err != nil {
		t.Fatalf("readEventLog: %v", err)
	}
	return log
}

// TestPendingRolloverFollowedByASecondRestartUsesTheSecondsOwnBoundary
// checks that a same-id restart (A -> B) whose replacement never becomes
// observable (B's inspect keeps failing) must
// not leave the target's next successful rollover (to C, once the
// container has actually moved on to a StartedAt of its own) starting
// from A's own, now-stale end boundary. It exercises the real
// closeGenerationEnd/rolloverGeneration call sequence collect.go's per-tick
// loop makes - twice, with the first rollover attempt failing exactly the
// way a still-pending replacement does - and then runs BOTH the finalized
// A and the newly committed C through the real match pipeline against a
// hand-built event log with one event in each of three positions: before
// A's own end, in the gap between A's end and C's start (which belongs to
// neither generation and must be confirmed by neither), and after C's own
// start.
func TestPendingRolloverFollowedByASecondRestartUsesTheSecondsOwnBoundary(t *testing.T) {
	trivyData, err := os.ReadFile("testdata/synthetic_events_trivy.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(trivyData)
	if err != nil {
		t.Fatalf("parse scan report: %v", err)
	}
	idx, _, err := buildScanFileIndex(trivyData, false)
	if err != nil {
		t.Fatalf("index the scan report's paths: %v", err)
	}
	def, err := readCase("testdata/synthetic_events_case.json")
	if err != nil {
		t.Fatalf("read case: %v", err)
	}

	const containerID = "c0ffee0000000000000000000000000000000000000000000000000000000001"
	windowStart := mustParseRFC3339(t, "2026-09-13T00:00:00Z")
	windowEnd := mustParseRFC3339(t, "2026-09-13T00:05:00Z")
	t1 := mustParseRFC3339(t, "2026-09-13T00:01:00Z") // A's own end (the first restart's boundary)
	t2 := mustParseRFC3339(t, "2026-09-13T00:03:00Z") // C's own start (the second restart's boundary) - later than t1

	oldRec, err := readContainerRecord("testdata/synthetic_events_observation.json")
	if err != nil {
		t.Fatalf("read observation: %v", err)
	}
	oldRec.Subject.Docker.ContainerID = containerID
	oldRec.Window.ScheduledStart, oldRec.Window.ScheduledEnd = windowStart, windowEnd

	api, client, _ := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: containerID, Names: []string{"/" + oldRec.Subject.Docker.ContainerName}, Image: oldRec.Subject.Docker.ImageRef}}
	// No api.inspectFor[containerID] entry yet: the first rollover attempt
	// (A -> B, boundary t1) must find the replacement uninspectable, the
	// same as a container that raced past "restarted" and back into
	// "not answering yet".
	api.topFor[containerID] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{strconv.Itoa(os.Getpid()), "0", "root"}}}

	tgt := &target{id: containerID, record: &oldRec, state: newContainerCollectState(false, defaultAuxLimits())}
	evAtoB := GenerationEvent{
		Kind: "restart", ContainerName: oldRec.Subject.Docker.ContainerName,
		OldContainerID: containerID, NewContainerID: containerID,
		StartedAtBefore: oldRec.Subject.StartedAt, StartedAtAfter: t1.Format(time.RFC3339Nano),
		DetectedAt: t1.Add(2 * time.Second),
	}
	closeGenerationEnd(tgt.record, evAtoB, windowStart, windowEnd)
	if _, err := rolloverGeneration(context.Background(), client, tgt, evAtoB, oldRec.RunKey, oldRec.Window.ID, oldRec.Window.PhaseBase, oldRec.Window.PhaseBaseFrom, windowStart, windowEnd, nil, false, defaultAuxLimits(), defaultPSArgs); err == nil {
		t.Fatal("want the first rollover attempt to fail (no inspect available yet), got success")
	}
	if len(tgt.prior) != 0 {
		t.Fatalf("prior = %v, want none yet: the first attempt must not have committed anything", tgt.prior)
	}
	if !tgt.record.Window.ScheduledEnd.Equal(t1) {
		t.Fatalf("after the first (failed) rollover attempt, the still-active record's own end = %v, want it already closed at t1 = %v", tgt.record.Window.ScheduledEnd, t1)
	}

	// Now the replacement becomes inspectable, but reports a StartedAt of
	// t2 - later than t1 - the same as a container that has, by now,
	// actually moved on to a second restart while the first was still
	// pending.
	api.inspectFor[containerID] = mustSetStartedAt(dockerInspect{Id: containerID, Image: oldRec.Subject.Docker.ImageID}, t2.Format(time.RFC3339Nano))
	evToC := GenerationEvent{
		Kind: "restart", ContainerName: oldRec.Subject.Docker.ContainerName,
		OldContainerID: containerID, NewContainerID: containerID,
		StartedAtBefore: oldRec.Subject.StartedAt, StartedAtAfter: t2.Format(time.RFC3339Nano),
		DetectedAt: t2.Add(2 * time.Second),
	}
	closeGenerationEnd(tgt.record, evToC, windowStart, windowEnd) // must be a no-op: already closed at t1
	if _, err := rolloverGeneration(context.Background(), client, tgt, evToC, oldRec.RunKey, oldRec.Window.ID, oldRec.Window.PhaseBase, oldRec.Window.PhaseBaseFrom, windowStart, windowEnd, nil, false, defaultAuxLimits(), defaultPSArgs); err != nil {
		t.Fatalf("second rollover attempt: %v", err)
	}
	if len(tgt.prior) != 1 {
		t.Fatalf("prior generations = %d, want exactly 1 (A, finalized once)", len(tgt.prior))
	}
	genA, genC := *tgt.prior[0], *tgt.record
	if !genA.Window.ScheduledEnd.Equal(t1) {
		t.Errorf("A's own end = %v, want it to stay at t1 = %v (never moved by the second, later change)", genA.Window.ScheduledEnd, t1)
	}
	if !genC.Window.ScheduledStart.Equal(t2) {
		t.Fatalf("C's own start = %v, want t2 = %v (its OWN boundary) - not t1, A's stale end", genC.Window.ScheduledStart, t2)
	}
	copyMappingInputs(&genC, oldRec)

	events := writeSyntheticEventLog(t, containerID, oldRec.RunKey, []syntheticEvent{
		{ts: "2026-09-13T00:00:30.000000000Z", event: "open", rawPath: "/app/node_modules/lodash/lodash.js", source: "sys_enter_openat"}, // before t1: A's own
		{ts: "2026-09-13T00:01:40.000000000Z", event: "exec", rawPath: "/usr/bin/curl", source: "sched_process_exec"},                    // between t1 and t2: nobody's
		{ts: "2026-09-13T00:04:00.000000000Z", event: "exec", rawPath: "/usr/bin/curl", source: "sched_process_exec"},                    // after t2: C's own
	})

	intel := syntheticIntel()
	resultA, err := runMatchPipeline(context.Background(), genA, scan, idx, nil, def, nil, events, intel, t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match (A): %v", err)
	}
	resultC, err := runMatchPipeline(context.Background(), genC, scan, idx, nil, def, nil, events, intel, t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match (C): %v", err)
	}

	lodashA := packageByName(t, resultA, "lodash")
	curlA := packageByName(t, resultA, "curl")
	curlC := packageByName(t, resultC, "curl")

	if lodashA.S2Verdict != VerdictConfirmed {
		t.Errorf("A: lodash s2_verdict = %q, want confirmed (its own event, before t1)", lodashA.S2Verdict)
	}
	if curlA.S2Verdict == VerdictConfirmed {
		t.Error("A: curl s2_verdict = confirmed, but every curl event happened after A's own end (t1) - one of them (00:01:40) is in the gap that belongs to no generation, and the other (00:04:00) is C's own")
	}
	// C SHOULD confirm curl - via the legitimate 00:04:00 event, after its
	// own start t2. What must not happen is that confirmation resting on
	// the 00:01:40 gap event instead, which is checked directly below
	// rather than by curlC's verdict alone (a confirmed verdict is the
	// correct outcome here, not itself a failure).
	if curlC.S2Verdict != VerdictConfirmed {
		t.Errorf("C: curl s2_verdict = %q, want confirmed (its own event, after t2)", curlC.S2Verdict)
	}
	for _, c := range curlC.Confirmations {
		if c.ObservedAt.Before(t2) {
			t.Errorf("C kept a curl confirmation observed at %v, before its own start %v - this is exactly the cross-generation attribution this fix prevents: seeding C's start from A's stale end would have let this happen", c.ObservedAt, t2)
		}
	}
}
