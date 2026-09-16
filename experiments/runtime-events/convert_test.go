package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// bootEpoch is a fixed monotonic-zero instant, so a fixture's monotonic
// stamps convert to known wall-clock times.
var bootEpoch = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)

func convertFixture(t *testing.T, opts ConvertOptions) ConvertResult {
	t.Helper()
	f, err := os.Open("testdata/trace-sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if opts.BootEpoch.IsZero() {
		opts.BootEpoch = bootEpoch
	}
	if opts.ClockTicksPerSecond == 0 {
		opts.ClockTicksPerSecond = 100
	}
	res, err := Convert(f, opts)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return res
}

func findEvent(t *testing.T, res ConvertResult, raw string) EventRecord {
	t.Helper()
	for _, ev := range res.Events {
		if ev.RawPath == raw {
			return ev
		}
	}
	t.Fatalf("no event for %q", raw)
	return EventRecord{}
}

// TestConvertPairsEntryWithOutcome checks the two halves of a system call
// meet: the entry carries the path, the exit carries the result, and only
// the pair says whether a file was actually opened.
func TestConvertPairsEntryWithOutcome(t *testing.T) {
	res := convertFixture(t, ConvertOptions{})

	ok := findEvent(t, res, "/usr/lib/x86_64-linux-gnu/libcurl.so.4")
	if !ok.OK || ok.Ret != 3 {
		t.Errorf("successful open: OK=%v Ret=%d, want true/3", ok.OK, ok.Ret)
	}
	failed := findEvent(t, res, "/usr/lib/x86_64-linux-gnu/libnghttp2.so.14")
	if failed.OK {
		t.Error("an open that returned an error is reported as successful; a failed open is not use")
	}
	if failed.Ret != -2 {
		t.Errorf("failed open Ret = %d, want -2", failed.Ret)
	}
	// The open's time is the entry's, not the exit's: that is when the
	// program asked for the file.
	wantTS := bootEpoch.Add(1000500000)
	if !ok.Timestamp.Equal(wantTS) {
		t.Errorf("open timestamp = %s, want the entry's time %s", ok.Timestamp, wantTS)
	}
}

// TestConvertReportsProcessGenerationInProcForm checks that the process
// generation's start time is converted into the clock ticks a workload's
// own log records, which is the identifier that reads the same on both
// sides of a container boundary.
//
// The generation is the leading thread's, not the running thread's: a
// workload reads its process's start time whichever thread does the
// reading, so recording anything else would make the two disagree for
// every threaded program. The fixture's threads all carry the leader's
// value, and this checks it survives the conversion unchanged.
func TestConvertReportsProcessGenerationInProcForm(t *testing.T) {
	res := convertFixture(t, ConvertOptions{ClockTicksPerSecond: 100})
	ev := findEvent(t, res, "/usr/bin/curl")
	// 400000000 ns at 100 ticks per second is 40 ticks.
	if ev.Starttime != "40" {
		t.Errorf("Starttime = %q, want 40 ticks", ev.Starttime)
	}
	if ev.Event != "exec" || !ev.OK {
		t.Errorf("execution event = %q OK=%v, want exec/true", ev.Event, ev.OK)
	}

	// A thread of the same process carries the same generation, and its
	// own thread number.
	thread := findEvent(t, res, "/app/node_modules/lodash/lodash.js")
	if thread.Starttime != ev.Starttime {
		t.Errorf("a thread of the same process reported generation %q, want the leader's %q", thread.Starttime, ev.Starttime)
	}
	if thread.TID == thread.PID {
		t.Error("the fixture's non-leading thread lost its own thread number")
	}
}

// TestConvertPairsHalvesArrivingOutOfOrder checks that an outcome
// delivered before its entry is still paired. The two halves cross
// per-processor buffers, so a thread moved between processors can have
// them arrive the wrong way round, and counting that as two separate
// losses would understate the collection twice over.
func TestConvertPairsHalvesArrivingOutOfOrder(t *testing.T) {
	res := convertFixture(t, ConvertOptions{})
	ev := findEvent(t, res, "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so")
	if !ev.OK || ev.Ret != 6 {
		t.Errorf("out-of-order pair: OK=%v Ret=%d, want true/6", ev.OK, ev.Ret)
	}
	// Only the deliberately unpaired outcome at the end of the fixture
	// should be counted.
	if res.Trailer.Drops.EnterExitUnmatched != 1 {
		t.Errorf("unmatched halves = %d, want 1", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestConvertRefusesToPairAcrossProcesses checks that an outcome whose
// process number disagrees with the entry held for that thread is not
// paired with it. A thread number reused between the two halves would
// otherwise attribute one process's open to another.
func TestConvertRefusesToPairAcrossProcesses(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|1000|10|10|1|400000000|-100|/lib/a.so",
		"X|2000|99|10|3",
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("emitted %d event(s); the two halves belong to different processes", len(res.Events))
	}
	if res.Trailer.Drops.EnterExitUnmatched != 2 {
		t.Errorf("unmatched halves = %d, want both counted", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestUnmatchedHalvesAreJudgedIndividually checks that when two halves
// fail to pair, only the one that actually lacks a PID or a TID adds to
// the identity-gap count. A record with a complete identity does not
// become a gap merely because the record it failed to pair with lacks
// one — in either arrival order.
func TestUnmatchedHalvesAreJudgedIndividually(t *testing.T) {
	// The entry arrives first and is missing its PID; the outcome that
	// follows has a complete identity.
	forward := strings.Join([]string{
		"V|1|256|64",
		"O|1000|0|10|1|400000000|-100|/a", // entry: PID missing
		"X|2000|10|10|3|1000",             // outcome: complete identity
	}, "\n")
	res, err := Convert(strings.NewReader(forward), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Trailer.Drops.EnterExitUnmatched; got != 2 {
		t.Errorf("forward order: unmatched halves = %d, want 2", got)
	}
	if got := res.Trailer.Drops.UnmatchedIdentityUnavailable; got != 1 {
		t.Errorf("forward order: identity-gap count = %d, want 1: only the entry lacked one", got)
	}

	// The same pair, but the outcome — complete identity — arrives first
	// and is held; the entry that later fails to join it is the one
	// missing its PID.
	reverse := strings.Join([]string{
		"V|1|256|64",
		"X|2000|10|10|3",                  // outcome: complete identity, held for lack of an entry
		"O|1000|0|10|1|400000000|-100|/a", // entry: PID missing, does not join it
	}, "\n")
	res, err = Convert(strings.NewReader(reverse), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	// Neither half reads as a boundary case here: no window was ever
	// given, so both the held outcome and the still-pending entry fall to
	// the mid-window default. Both land in EnterExitUnmatched, so only
	// their sum is checked.
	if got := res.Trailer.Drops.EnterExitUnmatched + res.Trailer.Drops.EnterExitUnmatchedBoundary; got != 2 {
		t.Errorf("reverse order: unmatched halves = %d, want 2", got)
	}
	if got := res.Trailer.Drops.UnmatchedIdentityUnavailable; got != 1 {
		t.Errorf("reverse order: identity-gap count = %d, want 1: only the entry lacked one", got)
	}
}

// TestConvertSeparatesTheThreeKindsOfPath checks the three cases a path
// can be in, before anything is resolved.
//
// An absolute path names a file. A path relative to the working directory
// names one only if that directory is known for that process generation.
// A path relative to a directory descriptor names one only to whoever
// holds the descriptor, which the tracer does not — and joining the
// working directory onto it would name a real file that was never opened,
// which is worse than naming no file at all.
func TestConvertSeparatesTheThreeKindsOfPath(t *testing.T) {
	cwd := []CWDEntry{{PID: 4242, Starttime: "40", Dir: "/srv/app"}}
	res := convertFixture(t, ConvertOptions{CWD: cwd})

	absolute := findEvent(t, res, "/usr/lib/x86_64-linux-gnu/libcurl.so.4")
	if !absolute.Resolved || absolute.Path != "/usr/lib/x86_64-linux-gnu/libcurl.so.4" {
		t.Errorf("an absolute path came back as %q (resolved=%v)", absolute.Path, absolute.Resolved)
	}

	// Relative to a directory descriptor: still unresolved even though a
	// working directory was supplied.
	viaDescriptor := findEvent(t, res, "relative/config.json")
	if viaDescriptor.Resolved || viaDescriptor.Path != "" {
		t.Errorf("a path relative to a directory descriptor resolved to %q; nothing here knows what that descriptor pointed at", viaDescriptor.Path)
	}

	viaCWD := findEvent(t, res, "cwd-relative/thing.js")
	if !viaCWD.Resolved || viaCWD.Path != "/srv/app/cwd-relative/thing.js" {
		t.Errorf("with the working directory supplied, path = %q resolved=%v", viaCWD.Path, viaCWD.Resolved)
	}

	// Without the entry, the same path names nothing.
	bare := convertFixture(t, ConvertOptions{})
	viaCWD = findEvent(t, bare, "cwd-relative/thing.js")
	if viaCWD.Resolved || viaCWD.Path != "" {
		t.Errorf("without a working directory, path resolved to %q", viaCWD.Path)
	}

	// An entry recorded for a different process generation is not an
	// answer about this one.
	wrongGeneration := convertFixture(t, ConvertOptions{CWD: []CWDEntry{{PID: 4242, Starttime: "999", Dir: "/srv/app"}}})
	viaCWD = findEvent(t, wrongGeneration, "cwd-relative/thing.js")
	if viaCWD.Resolved {
		t.Error("a working directory recorded for another process generation was used anyway")
	}
}

// TestConvertMarksTruncatedPaths checks that a path which filled the
// tracer's buffer is marked as cut off rather than compared against
// anything.
//
// The buffer holds the terminator as well as the text, so a string one
// short of the buffer filled it and where it really ended is unknown. The
// detection is on by default and the length comes from the trace's own
// version line, not from what the caller believed.
func TestConvertMarksTruncatedPaths(t *testing.T) {
	res := convertFixture(t, ConvertOptions{})
	var truncated *EventRecord
	for i := range res.Events {
		if res.Events[i].Truncated {
			truncated = &res.Events[i]
		}
	}
	if truncated == nil {
		t.Fatal("the fixture's buffer-filling path was not marked as cut off; detection must not need to be asked for")
	}
	if len(truncated.RawPath) != 255 {
		t.Errorf("the marked path is %d characters, want the one that filled the 256-byte buffer", len(truncated.RawPath))
	}
	if truncated.Resolved || truncated.Path != "" {
		t.Errorf("a cut-off path was resolved to %q; its real ending is unknown", truncated.Path)
	}
	if res.Trailer.Drops.PathTruncations != 1 {
		t.Errorf("PathTruncations = %d, want 1", res.Trailer.Drops.PathTruncations)
	}
}

// TestConvertCountsLosses checks every kind of loss is counted separately,
// and in particular that the number of overflow notifications is not
// reported as the number of events lost.
func TestConvertCountsLosses(t *testing.T) {
	res := convertFixture(t, ConvertOptions{})
	d := res.Trailer.Drops
	if d.LostEvents != 17 {
		t.Errorf("LostEvents = %d, want 17", d.LostEvents)
	}
	if d.LostNotifications != 1 {
		t.Errorf("LostNotifications = %d, want 1: one notification stood for seventeen events", d.LostNotifications)
	}
	// The tracer's own counting maps are read back: counting with a map is
	// what makes the numbers survive two processors counting at once.
	if d.EventsBeforeFilter != 4823 || d.EventsAfterFilter != 9 {
		t.Errorf("filter counts = %d before / %d after, want the tracer's own totals including its executions", d.EventsBeforeFilter, d.EventsAfterFilter)
	}
	if d.PathReadFailures != 3 {
		t.Errorf("path read failures = %d, want the tracer's own count of 3", d.PathReadFailures)
	}
	// A kind of loss this method cannot count at all is named, not
	// reported as zero: zero is a claim that nothing was lost.
	if len(d.Unmeasured) == 0 {
		t.Error("no loss kind was reported as unmeasurable, so a count of zero would read as a complete observation")
	}
}

// unmeasuredNamesMapOverflow reports whether the drop counts still list the
// pending map's insertion loss as unmeasurable.
func unmeasuredNamesMapOverflow(d EventDropCounts) bool {
	for _, u := range d.Unmeasured {
		if strings.HasPrefix(u, "map_overflow:") {
			return true
		}
	}
	return false
}

// TestMapInsertFailedCounterMeasuresThePendingMapLoss checks that a trace
// carrying the entry probe's own count of failed pending-map insertions —
// its has-the-key check right after the insert, since the insert itself
// has no return value to check — is read into MapOverflow and dropped
// from Unmeasured, whether the count is zero or not: a trace that can
// report the count at all has established it, and reporting zero on top
// of naming it unmeasurable would claim a gap that trace does not have.
func TestMapInsertFailedCounterMeasuresThePendingMapLoss(t *testing.T) {
	cases := []struct {
		name         string
		counterLine  string
		wantOverflow int
	}{
		{"zero", "@map_insert_failed: 0", 0},
		{"nonzero", "@map_insert_failed: 3", 3},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			trace := strings.Join([]string{
				"V|1|256|64",
				"E|1000000000|2|2|3|0|sh|/bin/sh",
				tt.counterLine,
			}, "\n")
			res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
			if err != nil {
				t.Fatal(err)
			}
			if got := res.Trailer.Drops.MapOverflow; got != tt.wantOverflow {
				t.Errorf("MapOverflow = %d, want %d", got, tt.wantOverflow)
			}
			if unmeasuredNamesMapOverflow(res.Trailer.Drops) {
				t.Error("map_overflow is still listed as unmeasured even though the trace carried its own count")
			}
		})
	}
}

// TestMapInsertFailedCounterAbsentLeavesItUnmeasured checks a trace with no
// map_insert_failed counter at all — the shape this collection method
// produced before the counter existed — still names the pending map's
// insertion loss as unmeasured rather than reporting it as a default zero.
func TestMapInsertFailedCounterAbsentLeavesItUnmeasured(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"E|1000000000|2|2|3|0|sh|/bin/sh",
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.MapOverflow != 0 {
		t.Errorf("MapOverflow = %d, want 0: nothing in the trace reported a count", res.Trailer.Drops.MapOverflow)
	}
	if !unmeasuredNamesMapOverflow(res.Trailer.Drops) {
		t.Error("a trace with no map_insert_failed counter did not name map_overflow as unmeasured")
	}
}

// TestMapInsertFailedCounterIsNotDoubleCounted checks that two occurrences
// of the line — the shape a script's explicit end-of-run printf and
// bpftrace's own automatic map dump would together produce if the map
// were ever left uncleared — are read as one count, the larger of the
// two, rather than summed as though two separate maps had each lost that
// many insertions.
func TestMapInsertFailedCounterIsNotDoubleCounted(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"E|1000000000|2|2|3|0|sh|/bin/sh",
		"@map_insert_failed: 2",
		"@map_insert_failed: 5",
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Trailer.Drops.MapOverflow; got != 5 {
		t.Errorf("MapOverflow = %d, want 5 (the larger of the two lines, not their sum of 7)", got)
	}
}

// TestConvertDoesNotGuessWhenTheCollectionStopped checks that the stop is
// what the wrapper observed rather than the last event's time. A
// collection that ran to the end of the window and saw nothing looks
// identical, from the inside, to one that died early.
func TestConvertDoesNotGuessWhenTheCollectionStopped(t *testing.T) {
	windowEnd := bootEpoch.Add(10 * time.Minute)
	unknown := convertFixture(t, ConvertOptions{WindowEnd: windowEnd})
	if unknown.Trailer.Drops.StoppedEarly {
		t.Error("the collection was declared to have stopped early from the last event's time alone")
	}
	named := false
	for _, u := range unknown.Trailer.Drops.Unmeasured {
		if strings.Contains(u, "stop time") {
			named = true
		}
	}
	if !named {
		t.Error("an unrecorded stop time was not reported as unknown")
	}

	stopped := convertFixture(t, ConvertOptions{WindowEnd: windowEnd, StoppedAt: bootEpoch.Add(4 * time.Minute), StopNote: "event rate threshold"})
	if !stopped.Trailer.Drops.StoppedEarly {
		t.Error("a collection the wrapper saw stop before the window ended was not reported as such")
	}
	if stopped.Trailer.Drops.GapSeconds != 360 {
		t.Errorf("gap = %v seconds, want 360", stopped.Trailer.Drops.GapSeconds)
	}
}

// TestConvertCarriesTheClockRelationsError checks that the conversion's
// own error and the clock it rests on travel with the log. A tolerance for
// pairing an event with an occurrence means nothing beside a conversion
// whose error is unknown, and two clocks that differ by however long the
// machine was suspended are not interchangeable.
func TestConvertCarriesTheClockRelationsError(t *testing.T) {
	res := convertFixture(t, ConvertOptions{ClockErrorNS: 4712, ClockSourceID: "CLOCK_MONOTONIC"})
	if res.Header.ClockErrorNS != 4712 {
		t.Errorf("clock error = %d, want it carried into the log", res.Header.ClockErrorNS)
	}
	if res.Header.ClockSource != "CLOCK_MONOTONIC" {
		t.Errorf("clock source = %q, want the clock named", res.Header.ClockSource)
	}
	if res.Header.PathBufferLen != 256 {
		t.Errorf("string length = %d, want the one the trace itself reports", res.Header.PathBufferLen)
	}
}

// TestConvertCountsUnmatchedEntries checks an entry whose outcome never
// arrived is counted rather than emitted as a successful open.
// testWindow is a window bound used by several tests below: entries and
// outcomes at monotonic offsets under 1000ns are before it, at 2000ns are
// inside it, and at or beyond 6000ns are after it.
func testWindow() (start, end time.Time) {
	return bootEpoch.Add(1000 * time.Nanosecond), bootEpoch.Add(5000 * time.Nanosecond)
}

// TestWithoutWindowEverythingIsAWindowLoss checks the fallback: with
// neither -window-start nor -window-end, no boundary can be measured at
// all, so both an entry with no outcome and an outcome with no entry are
// counted as mid-window losses rather than credited to a boundary this
// run never established.
func TestWithoutWindowEverythingIsAWindowLoss(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|1000|10|10|1|0|-100|/lib/a.so", // outcome never arrives
		"X|2000|11|11|3",                  // outcome with no entry
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("emitted %d event(s); neither half of a pair is an observation on its own", len(res.Events))
	}
	if res.Trailer.Drops.EnterExitUnmatched != 2 {
		t.Errorf("EnterExitUnmatched = %d, want 2: no window means no boundary can be measured", res.Trailer.Drops.EnterExitUnmatched)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 0", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestOrphanedExitBeforeWindowIsAStartBoundary checks that an outcome
// with no entry, timestamped before the observation window opens, is
// counted as a start-boundary residual: the collection is not answerable
// for anything before its own window, whatever caused the entry to be
// missing.
func TestOrphanedExitBeforeWindowIsAStartBoundary(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|500|10|10|3", // no entry ever arrives; before the window
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 1 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 1", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 {
		t.Errorf("EnterExitUnmatched = %d, want 0", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestOrphanedExitInsideWindowIsAWindowLoss is the contrasting case: the
// same shape of loss, timestamped inside the window, so it is a genuine
// mid-window loss the collection is answerable for.
func TestOrphanedExitInsideWindowIsAWindowLoss(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|2000|10|10|3", // no entry ever arrives; inside the window
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 1 {
		t.Errorf("EnterExitUnmatched = %d, want 1", res.Trailer.Drops.EnterExitUnmatched)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 0: this outcome is inside the window", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestOrphanedExitAfterWindowWithEntryInsideIsAWindowLoss reproduces the
// bug in judging an orphaned outcome by its own timestamp alone: the
// outcome here is after the window closed, but the entry time it carries
// back is inside the window. That entry was lost inside the window even
// though nothing else about it survived except an outcome that only
// shows up later, so this must not be credited to the end boundary.
func TestOrphanedExitAfterWindowWithEntryInsideIsAWindowLoss(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|6000|10|10|3|2000", // no entry ever arrives; the outcome is after the window, but entryAt (2000) is inside it
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 1 {
		t.Errorf("EnterExitUnmatched = %d, want 1: the entry time this outcome names is inside the window", res.Trailer.Drops.EnterExitUnmatched)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 0", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestOrphanedExitAfterWindowWithEntryOutsideIsAStartBoundary is the
// contrasting case: the outcome's own entry time is also outside the
// window (on either side of it), so nothing here was lost inside it.
func TestOrphanedExitAfterWindowWithEntryOutsideIsAStartBoundary(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|6000|10|10|3|5500", // both the outcome and the entry time it names are after the window
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 1 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 1", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 {
		t.Errorf("EnterExitUnmatched = %d, want 0", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestOrphanedExitInsideWindowWithEntryBeforeItIsAStartBoundary checks
// that the entry time an outcome names takes precedence over the
// outcome's own time: a call that began before the window and returned
// inside it lost its entry at the start boundary, not in the window.
func TestOrphanedExitInsideWindowWithEntryBeforeItIsAStartBoundary(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|3000|10|10|3|500", // the outcome is inside the window; the entry it names is before it
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 1 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 1", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 {
		t.Errorf("EnterExitUnmatched = %d, want 0", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestOldFormatOrphanedExitAfterWindowIsAWindowLoss checks the safe
// default for a trace old enough to carry no entry time on its outcomes
// at all: an outcome after the window proves nothing about when its
// missing entry happened, since a call that started inside the window
// and simply took a long time to return would look identical from the
// outcome alone. Without an entry time to rule that out, it is counted
// as a mid-window loss rather than assumed to be a boundary artifact.
func TestOldFormatOrphanedExitAfterWindowIsAWindowLoss(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|6000|10|10|3", // no entry ever arrives, and no entry time either; after the window
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 1 {
		t.Errorf("EnterExitUnmatched = %d, want 1: a mid-window entry cannot be ruled out without an entry time", res.Trailer.Drops.EnterExitUnmatched)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 0", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestPendingAtEndAfterWindowIsAnEndBoundary checks that an entry with no
// outcome, timestamped after the observation window has already closed,
// is counted as an end-boundary residual rather than a mid-window loss —
// whatever else was true of the collection at that point, the call is
// outside what this run measures.
func TestPendingAtEndAfterWindowIsAnEndBoundary(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|6000|10|10|1|400000000|-100|/lib/a.so", // never gets its outcome; after the window
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 1 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 1", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 {
		t.Errorf("EnterExitUnmatched = %d, want 0", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestPendingAtEndInsideWindowIsAWindowLoss checks that an entry still
// pending when the trace ends is not, by itself, evidence the call was
// still running past the window's own close: one timestamped inside the
// window is a mid-window loss regardless, since "still pending" says
// nothing on its own about whether the call had actually finished.
func TestPendingAtEndInsideWindowIsAWindowLoss(t *testing.T) {
	start, end := testWindow()
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|2000|10|10|1|400000000|-100|/lib/a.so", // never gets its outcome; inside the window
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 1 {
		t.Errorf("EnterExitUnmatched = %d, want 1", res.Trailer.Drops.EnterExitUnmatched)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 0: nothing here is outside the window", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestReorderedPairsAreMatchedByEntryTime checks that two of a thread's
// calls, arriving as both entries before either outcome, still pair
// correctly: pending is keyed by the entry's own time, not by thread
// alone, so the second entry does not evict the first while its outcome
// is still on the way, and each outcome's own entry time finds the right
// one regardless of the order all four records arrived in.
func TestReorderedPairsAreMatchedByEntryTime(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|100|10|10|1|400000000|-100|/lib/a.so",
		"O|300|10|10|1|400000000|-100|/lib/b.so",
		"X|200|10|10|3|100",
		"X|400|10|10|3|300",
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("got %d event(s), want both calls paired", len(res.Events))
	}
	a, b := findEvent(t, res, "/lib/a.so"), findEvent(t, res, "/lib/b.so")
	if !a.OK || !b.OK {
		t.Errorf("a.OK=%v b.OK=%v, want both true", a.OK, b.OK)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 || res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("unmatched = %d, boundary = %d, want 0/0: both calls found their own partner",
			res.Trailer.Drops.EnterExitUnmatched, res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestOldFormatMultipleOutcomesArriveBeforeEitherEntry checks that an
// older trace's outcomes — carrying no entry time — are matched by when
// the four records actually happened, not by which arrived first: both
// outcomes arrive before either entry, and the later call's own outcome
// (400, success) is listed first, ahead of the earlier call's (200,
// failure). A thread runs one call at a time, so sorted by time A must
// have returned (200) before B's own entry (300) could start, whatever
// order the file lists them in.
func TestOldFormatMultipleOutcomesArriveBeforeEitherEntry(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|400|10|10|3",                          // B's outcome (success), arrives first
		"X|200|10|10|-2",                         // A's outcome (failure), arrives second
		"O|100|10|10|1|400000000|-100|/lib/a.so", // A's entry
		"O|300|10|10|1|400000000|-100|/lib/b.so", // B's entry
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	a, b := findEvent(t, res, "/lib/a.so"), findEvent(t, res, "/lib/b.so")
	if a.OK {
		t.Error("A's own outcome was a failure; matching by arrival order gave it B's success instead")
	}
	if !b.OK {
		t.Error("B's own outcome was a success; matching by arrival order gave it A's failure instead")
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 || res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("unmatched = %d, boundary = %d, want 0/0: both calls resolved by their actual times",
			res.Trailer.Drops.EnterExitUnmatched, res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestOldFormatArrivalOrderDoesNotChangeThePairing checks the same
// four records as above, shuffled into yet another arrival order — both
// entries first this time, still scrambled relative to each other — and
// requires the identical result: an older trace's pairing depends only
// on what time each record carries, never on the order any of them
// arrived in.
func TestOldFormatArrivalOrderDoesNotChangeThePairing(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|300|10|10|1|400000000|-100|/lib/b.so", // B's entry, arrives first
		"O|100|10|10|1|400000000|-100|/lib/a.so", // A's entry, arrives second
		"X|400|10|10|3",                          // B's outcome (success)
		"X|200|10|10|-2",                         // A's outcome (failure)
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	a, b := findEvent(t, res, "/lib/a.so"), findEvent(t, res, "/lib/b.so")
	if a.OK {
		t.Error("A's own outcome was a failure")
	}
	if !b.OK {
		t.Error("B's own outcome was a success")
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 || res.Trailer.Drops.EnterExitUnmatchedBoundary != 0 {
		t.Errorf("unmatched = %d, boundary = %d, want 0/0", res.Trailer.Drops.EnterExitUnmatched, res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
}

// TestWindowStartAfterWindowEndIsRefused checks that an inverted window
// is refused outright rather than silently measuring nothing, or
// something backwards: a boundary judged against a window that ends
// before it starts is not a boundary this run actually established.
func TestWindowStartAfterWindowEndIsRefused(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|100|10|10|1|400000000|-100|/lib/a.so",
		"X|200|10|10|3",
	}, "\n")
	_, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100,
		WindowStart: bootEpoch.Add(5000 * time.Nanosecond),
		WindowEnd:   bootEpoch.Add(1000 * time.Nanosecond),
	})
	if err == nil {
		t.Fatal("expected an error from the inverted window, got none")
	}
}

// TestMalformedEntryTimeIsAConvertFailure checks that an entry-time
// column that is present but fails to parse is refused as a malformed
// record, not silently read as an older trace that never had the column
// at all: the latter would let this outcome settle into a pairing by
// guesswork instead of being kept out of one altogether.
func TestMalformedEntryTimeIsAConvertFailure(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|100|10|10|1|400000000|-100|/lib/a.so",
		"X|200|10|10|3|not-a-number", // the entry-time column is present but unparseable
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("emitted %d event(s); a malformed outcome must not be used for pairing", len(res.Events))
	}
	if res.Trailer.Drops.ConvertFailures != 1 {
		t.Errorf("ConvertFailures = %d, want 1", res.Trailer.Drops.ConvertFailures)
	}
	// The entry is left pending rather than consumed by the malformed
	// outcome, so it resolves as an ordinary unmatched entry (no window
	// given here).
	if res.Trailer.Drops.EnterExitUnmatched != 1 {
		t.Errorf("EnterExitUnmatched = %d, want 1: the entry was never claimed", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestAttachTimeIsRecordedButNotUsedForClassification checks that the
// trace's own reported attach time — read from a wall-clock-prefixed
// "Attached N probes" line — reaches the header for reference, but plays
// no part in judging an unmatched half: an outcome timestamped before the
// window, but after the reported attach time, still reads as a start
// boundary. If attach time were still doing the judging here, this same
// outcome would read as a mid-window loss instead, since every probe was
// already live by the time it happened.
func TestAttachTimeIsRecordedButNotUsedForClassification(t *testing.T) {
	start, end := testWindow()
	attachedAt := bootEpoch.Add(100 * time.Nanosecond) // before the outcome below (500), so an attach-based rule would call it a mid-window loss
	lostAt := bootEpoch.Add(20000 * time.Nanosecond)
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|500|10|10|3", // no entry ever arrives; before the window, after the attach time
		attachedAt.Format(time.RFC3339Nano) + " Attached 7 probes",
		lostAt.Format(time.RFC3339Nano) + " Lost 3 events (buffer full)",
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, WindowStart: start, WindowEnd: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.LostEvents != 3 {
		t.Errorf("LostEvents = %d, want 3: the prefix must not stop the notice from being read", res.Trailer.Drops.LostEvents)
	}
	if res.Trailer.Drops.LostNotifications != 1 {
		t.Errorf("LostNotifications = %d, want 1", res.Trailer.Drops.LostNotifications)
	}
	if !res.Header.AttachedAt.Equal(attachedAt) {
		t.Errorf("Header.AttachedAt = %s, want %s", res.Header.AttachedAt, attachedAt)
	}
	if res.Trailer.Drops.EnterExitUnmatchedBoundary != 1 {
		t.Errorf("EnterExitUnmatchedBoundary = %d, want 1: the window, not the attach time, decides this", res.Trailer.Drops.EnterExitUnmatchedBoundary)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 {
		t.Errorf("EnterExitUnmatched = %d, want 0", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestWallClockPrefixAcceptsZAndNumericOffset checks that a wrapper
// running under either offset form still has its stderr read correctly:
// bpftrace itself does not choose which one the host's clock uses.
func TestWallClockPrefixAcceptsZAndNumericOffset(t *testing.T) {
	traceZ := strings.Join([]string{
		"V|1|256|64",
		"2026-09-13T00:00:00.000000000Z Lost 4 events (buffer full)",
	}, "\n")
	res, err := Convert(strings.NewReader(traceZ), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.LostEvents != 4 {
		t.Errorf("Z offset: LostEvents = %d, want 4", res.Trailer.Drops.LostEvents)
	}

	traceOffset := strings.Join([]string{
		"V|1|256|64",
		"2026-09-13T09:00:00.000000000+09:00 Lost 5 events (buffer full)",
	}, "\n")
	res, err = Convert(strings.NewReader(traceOffset), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.LostEvents != 5 {
		t.Errorf("numeric offset: LostEvents = %d, want 5", res.Trailer.Drops.LostEvents)
	}
}

// TestAttachedAtAndStderrMustAgree checks that an explicit -attached-at
// and a wall-clock-prefixed "Attached N probes" line naming a different
// instant is refused rather than silently preferring one: a caller
// acting on one while the trace itself reports the other would be
// recording an instant that was never the true one, even though neither
// is used to judge a pairing.
func TestAttachedAtAndStderrMustAgree(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|100|10|10|1|400000000|-100|/lib/a.so",
		"X|200|10|10|3",
		bootEpoch.Add(650*time.Nanosecond).Format(time.RFC3339Nano) + " Attached 7 probes",
	}, "\n")
	_, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100,
		AttachedAt: bootEpoch.Add(999 * time.Nanosecond), // disagrees with the stderr line above
	})
	if err == nil {
		t.Fatal("expected an error from the disagreement, got none")
	}
}

// TestConvertRequiresAClockRelation checks a trace with no way to relate
// its monotonic stamps to a wall clock is refused rather than dated from
// an arbitrary zero.
func TestConvertRequiresAClockRelation(t *testing.T) {
	_, err := Convert(strings.NewReader("V|1|256|64\nE|1|2|2|3|0|sh|/bin/sh\n"), ConvertOptions{})
	if err == nil {
		t.Fatal("a trace with no clock relation was converted anyway")
	}
	if !strings.Contains(err.Error(), "clock") {
		t.Errorf("error = %v, want it to name the missing clock relation", err)
	}
}

// TestConvertPrefersTheTracersOwnClockReading checks that a paired reading
// taken by the tracer itself overrides a value supplied from outside,
// being the closer of the two.
func TestConvertPrefersTheTracersOwnClockReading(t *testing.T) {
	wall := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	trace := "V|1|256|64\nC|1000000000|" + strconv.FormatInt(wall.UnixNano(), 10) + "\nE|1000000000|2|2|3|0|sh|/bin/sh\n"
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(res.Events))
	}
	if !res.Events[0].Timestamp.Equal(wall) {
		t.Errorf("timestamp = %s, want %s from the tracer's own paired reading", res.Events[0].Timestamp, wall)
	}
}

// TestConvertAttributesThroughTheControlGroupTable checks an event is
// credited to a container only when the table knows its control group, and
// that an unknown one is reported as unattributed rather than as the
// host's.
func TestConvertAttributesThroughTheControlGroupTable(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	table := CgroupTable{Entries: []CgroupEntry{
		{CgroupID: 52161, Path: "/sys/fs/cgroup/system.slice/docker-abc.scope", ContainerID: "abc", Depth: 0, FirstSeen: now},
	}}
	res := convertFixture(t, ConvertOptions{Lookup: newCgroupLookup(table)})

	known := findEvent(t, res, "/usr/bin/curl")
	if known.ContainerID != "abc" || known.Attribution != attributionContainer {
		t.Errorf("known control group gave container %q attribution %q, want abc/container", known.ContainerID, known.Attribution)
	}
	unknown := findEvent(t, res, "/usr/bin/git")
	if unknown.ContainerID != "" {
		t.Errorf("unknown control group was credited to container %q", unknown.ContainerID)
	}
	if unknown.Attribution != attributionUnattributed {
		t.Errorf("unknown control group attribution = %q, want unattributed: a table with no entry does not mean the host", unknown.Attribution)
	}
}

// TestOutcomeIsNotJoinedToAnotherCallsEntry checks the pairing when an
// entry is lost.
//
// The thread number alone is not enough to pair the two halves: if one
// call's entry never arrives, the outcome that follows it would be joined
// to the next entry and report that call's success or failure as belonging
// to a different file. A failed open reported as a successful one becomes
// a confirmation of a package nothing used.
func TestOutcomeIsNotJoinedToAnotherCallsEntry(t *testing.T) {
	// A's entry is lost. Its outcome (success) arrives, then B's entry and
	// B's outcome (failure).
	trace := strings.Join([]string{
		"V|1|256|64",
		"X|1000|10|10|3|500", // A succeeded; its entry never arrived
		"O|2000|10|10|1|400000000|-100|/lib/b.so",
		"X|2100|10|10|-2|2000", // B failed
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d event(s), want only the call whose two halves both arrived", len(res.Events))
	}
	if res.Events[0].RawPath != "/lib/b.so" {
		t.Fatalf("the emitted event names %q", res.Events[0].RawPath)
	}
	if res.Events[0].OK {
		t.Error("a failed open was reported as successful: it took the other call's outcome")
	}
	// No window was given, so A's orphaned outcome falls to the
	// mid-window default rather than a boundary residual — but either way
	// it must be counted as a loss somewhere, not silently dropped.
	if res.Trailer.Drops.EnterExitUnmatched+res.Trailer.Drops.EnterExitUnmatchedBoundary < 1 {
		t.Error("the half whose partner never arrived was not counted as a loss")
	}
}

// TestOutcomeRunningBackwardsIsRefused checks the weaker pairing rule, for
// a trace whose outcomes do not carry the entry's own time. An outcome
// that precedes the entry held for it cannot be that entry's.
func TestOutcomeRunningBackwardsIsRefused(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|2000|10|10|1|400000000|-100|/lib/a.so",
		"X|1000|10|10|3", // earlier than the entry, and carrying no entry time
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Errorf("emitted %d event(s) from halves whose times run backwards", len(res.Events))
	}
	if res.Trailer.Drops.EnterExitUnmatched != 2 {
		t.Errorf("unmatched halves = %d, want both", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestSettingsDisagreementIsRefused checks that a conversion is refused
// when the trace and the caller disagree about the tracer's settings. The
// settings can be overridden from the environment, and the trace's own
// line is written by the script rather than read back from the running
// configuration — so a disagreement means one of the two is not what the
// run used.
func TestSettingsDisagreementIsRefused(t *testing.T) {
	trace := "V|1|256|64\nE|1000|2|2|3|400000000|sh|/bin/sh\n"
	_, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, PathBufferLen: 128,
	})
	if err == nil {
		t.Fatal("a string length the caller and the trace disagree on was accepted")
	}
	if !strings.Contains(err.Error(), "string length") {
		t.Errorf("error = %v, want it to name the disagreement", err)
	}

	res, err := Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100, PathBufferLen: 256,
		Header: EventHeader{BufferPages: 64},
	})
	if err != nil {
		t.Fatalf("agreeing settings were refused: %v", err)
	}
	if res.Header.PathBufferLen != 256 || res.Header.BufferPages != 64 {
		t.Errorf("settings = %d/%d, want the agreed 256/64", res.Header.PathBufferLen, res.Header.BufferPages)
	}
}

// TestUnspecifiedPathBufferYieldsToTheVersionLine checks that an unset
// -path-buffer flag (PathBufferLen left at its zero value, exactly as the
// CLI passes it through when the flag is not given) adopts whatever
// length the trace's own version line reports, rather than the compiled-in
// default colliding with it.
//
// Filling the unspecified case in with the default before the trace was
// even read made it indistinguishable from an explicit 256, and rejected
// every trace — such as filtered-b's, at 160 — whose script used a
// different length.
func TestUnspecifiedPathBufferYieldsToTheVersionLine(t *testing.T) {
	trace := "V|1|160|64|filtered-b\nE|1000|2|2|3|400000000|sh|/bin/sh\n"
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatalf("convert with -path-buffer unspecified: %v", err)
	}
	if res.Header.PathBufferLen != 160 {
		t.Errorf("path buffer length = %d, want the trace's own 160", res.Header.PathBufferLen)
	}
}

// TestPathReadFailuresAreNotCountedTwice checks that a failure the tracer
// already counted is not added again for the same event.
func TestPathReadFailuresAreNotCountedTwice(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"E|1000|2|2|3|400000000|sh|",
		"@path_read_failed: 1",
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.PathReadFailures != 1 {
		t.Errorf("path read failures = %d, want the tracer's own count of 1", res.Trailer.Drops.PathReadFailures)
	}

	// With no count from the tracer, the events themselves are what there
	// is to count.
	noCounter := "V|1|256|64\nE|1000|2|2|3|400000000|sh|\n"
	res, err = Convert(strings.NewReader(noCounter), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Trailer.Drops.PathReadFailures != 1 {
		t.Errorf("path read failures = %d, want 1 counted from the events", res.Trailer.Drops.PathReadFailures)
	}
}

// TestWorkingDirectoryEntriesAreBoundedInTimeAndGeneration checks the two
// things that make a recorded working directory an answer about a
// particular open, rather than a guess.
//
// A working directory can be changed while a process runs, and a process
// number is reused once the process using it exits. An entry that applies
// to neither a generation nor a stretch of time would resolve a relative
// path against whatever was recorded once — naming a real file that was
// never opened, which is worse than naming no file at all.
func TestWorkingDirectoryEntriesAreBoundedInTimeAndGeneration(t *testing.T) {
	entries, err := parseCWDMap("4242@40@2026-09-13T00:00:00Z-2026-09-13T00:10:00Z=/srv/app")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.PID != 4242 || e.Starttime != "40" || e.Dir != "/srv/app" {
		t.Errorf("entry = %+v", e)
	}
	if e.From.IsZero() || e.Until.IsZero() {
		t.Errorf("the period was not read: from %v until %v", e.From, e.Until)
	}

	opts := ConvertOptions{CWD: entries}
	inside := e.From.Add(time.Minute)
	if got := opts.workingDirectory(4242, "40", inside); got != "/srv/app" {
		t.Errorf("inside the period: %q, want /srv/app", got)
	}
	if got := opts.workingDirectory(4242, "40", e.Until.Add(time.Minute)); got != "" {
		t.Errorf("after the period: %q, want nothing", got)
	}
	if got := opts.workingDirectory(4242, "999", inside); got != "" {
		t.Errorf("a different generation: %q, want nothing", got)
	}
	// An event that does not say which generation produced it cannot be
	// answered at all.
	if got := opts.workingDirectory(4242, "", inside); got != "" {
		t.Errorf("an event with no generation: %q, want nothing", got)
	}

	if _, err := parseCWDMap("4242=/srv/app"); err == nil {
		t.Error("an entry naming no process generation was accepted")
	}
}

// TestNamespaceIdentifierIsReadUnsigned checks the namespace column: the
// identifier a task's PID namespace carries is an unsigned 32-bit number,
// and one written through a signed conversion must come back as the same
// namespace rather than be refused.
func TestNamespaceIdentifierIsReadUnsigned(t *testing.T) {
	for _, tc := range []struct {
		field string
		want  uint64
	}{{"4026532221", 4026532221}, {"-268435075", 4026532221}, {"7", 7}} {
		got, err := parseNamespaceID(tc.field)
		if err != nil || got != tc.want {
			t.Errorf("parseNamespaceID(%q) = %d, %v; want %d", tc.field, got, err, tc.want)
		}
	}
	if _, err := parseNamespaceID("x"); err == nil {
		t.Error("parseNamespaceID(\"x\") should fail")
	}
	trace := strings.Join([]string{
		"V|3|256|256|nofilter-256p",
		"E|1500|10|10|5|5|-268435075|21|1000|curl|/usr/bin/curl",
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || res.Events[0].PIDNamespace != 4026532221 {
		t.Fatalf("events = %+v, want one exec in namespace 4026532221", res.Events)
	}
}
