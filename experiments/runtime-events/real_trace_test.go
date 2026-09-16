package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// realTraceExcerpt is a verbatim excerpt of a trace taken on a real host.
// It is here because a hand-written fixture records what the output was
// believed to look like, and the things that went wrong on first contact
// with a real tracer were all things nobody had written down: a version
// line with fewer fields than expected, process numbers reported as zero
// for every process in a container, an empty path, source echoes on the
// error stream, and the tracer's own counting maps printed at exit.
const realTraceExcerpt = "testdata/trace-real-excerpt.txt"

func convertRealExcerpt(t *testing.T, opts ConvertOptions) ConvertResult {
	t.Helper()
	f, err := os.Open(realTraceExcerpt)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if opts.BootEpoch.IsZero() {
		opts.BootEpoch = time.Date(2026, 9, 10, 5, 34, 59, 154089325, time.UTC)
	}
	if opts.ClockTicksPerSecond == 0 {
		opts.ClockTicksPerSecond = 100
	}
	res, err := Convert(f, opts)
	if err != nil {
		t.Fatalf("convert a real trace: %v", err)
	}
	return res
}

// TestRealTraceConverts checks the excerpt end to end: the pairs pair, the
// outcomes are read, and nothing in the tracer's own chatter is mistaken
// for an event.
func TestRealTraceConverts(t *testing.T) {
	res := convertRealExcerpt(t, ConvertOptions{})

	byPath := map[string]EventRecord{}
	for _, ev := range res.Events {
		byPath[ev.RawPath] = ev
	}

	exec, ok := byPath["/bin/sh"]
	if !ok {
		t.Fatal("the execution in the excerpt produced no event")
	}
	if exec.Event != "exec" || !exec.OK || exec.PID != 2988932 {
		t.Errorf("execution = %+v", exec)
	}
	// 288964977576175 nanoseconds at a hundred ticks a second.
	if exec.Starttime != "28896497" {
		t.Errorf("generation = %q, want the leader's start in clock ticks", exec.Starttime)
	}

	success := byPath["/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat2/id"]
	if !success.OK || success.Ret != 32 {
		t.Errorf("the successful open came back OK=%v Ret=%d", success.OK, success.Ret)
	}
	failed := byPath["/proc/1/fd/"]
	if failed.OK {
		t.Error("an open that was refused came back as successful")
	}
	if failed.Ret != -13 {
		t.Errorf("the refused open's result = %d, want -13", failed.Ret)
	}

	// The tracer's counting maps, printed at exit, are read back rather
	// than counted as unconvertible lines.
	d := res.Trailer.Drops
	if d.EventsBeforeFilter != 10440 || d.EventsAfterFilter != 10440 {
		t.Errorf("filter counts = %d/%d, want the tracer's own totals including its executions", d.EventsBeforeFilter, d.EventsAfterFilter)
	}
	if d.LostEvents != 1714 || d.LostNotifications != 1 {
		t.Errorf("losses = %d event(s) over %d notification(s), want 1714/1", d.LostEvents, d.LostNotifications)
	}
	if d.PathReadFailures != 28 {
		t.Errorf("path read failures = %d, want the tracer's own count", d.PathReadFailures)
	}
	// The source echoes and warning banners on the error stream are not
	// records, and are not losses either.
	if d.ConvertFailures != 0 {
		t.Errorf("convert failures = %d; the tracer's own warnings are not records", d.ConvertFailures)
	}
}

// TestRealTraceIdentityGapsAreCounted is the failure this excerpt was
// taken to capture.
//
// The tracer reported zero for the process and thread numbers of every
// process inside a container, because its builtins answer from its own
// process namespace and those tasks have no number there. That is not
// merely missing information: every such call collides on the same
// pending-map key, so an entry and an outcome that happen to agree in time
// are not evidence they belong to the same call. The excerpt's
// container-side open is paired by time alone, and is counted as an
// identity gap rather than emitted as a confirmed success.
func TestRealTraceIdentityGapsAreCounted(t *testing.T) {
	res := convertRealExcerpt(t, ConvertOptions{})

	for _, ev := range res.Events {
		if ev.Path == "/proc/self/maps" {
			t.Errorf("an open with no identity to pair on was emitted as an event: %+v", ev)
		}
	}

	d := res.Trailer.Drops
	if d.UnmatchedIdentityUnavailable == 0 {
		t.Fatal("the excerpt's identity-less open halves were not counted at all")
	}
	// The per-event counter is for events the converter actually built; an
	// identity-less open is never built into one, so it never reaches it.
	if d.IdentityUnavailable != 0 {
		t.Errorf("IdentityUnavailable = %d, want 0: no event was built from an identity-less pair", d.IdentityUnavailable)
	}

	// An event with no path at all is counted as a read failure and
	// resolves to nothing.
	for _, ev := range res.Events {
		if ev.RawPath == "" && ev.Resolved {
			t.Error("an event with no path was resolved to something")
		}
	}
}

// TestIdentityLessEntryOverwriteDoesNotConfirmTheWrongCall reproduces the
// case that made identity alone unsafe to pair without: two identity-less
// entries are both held pending — under different keys, since pending is
// keyed by entry time, not by thread alone — and an outcome that carries
// the second entry's own time back is still refused: missing identity is
// checked before the times ever get compared, so it is not proof that the
// outcome belongs to the second call rather than to some other one this
// trace never named.
func TestIdentityLessEntryOverwriteDoesNotConfirmTheWrongCall(t *testing.T) {
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|1000|0|0|111|400000000|-100|/a", // A's entry, no identity
		"O|2000|0|0|222|400000000|-100|/b", // B's entry, overwrites A's key
		"X|3000|0|0|5|2000",                // carries B's entry time, ret 5 (success)
	}, "\n")
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range res.Events {
		if ev.OK {
			t.Errorf("an identity-less pair was emitted as a success: %+v", ev)
		}
	}
	if res.Trailer.Drops.EnterExitUnmatched == 0 {
		t.Error("the two entries and the unpaired outcome were not counted as losses")
	}
	if res.Trailer.Drops.UnmatchedIdentityUnavailable == 0 {
		t.Error("the collision was not attributed to the missing identity")
	}
}

// TestRealTraceOlderVersionLineStillConverts checks that a saved trace
// keeps converting after the scripts began naming their own variant. The
// excerpt's version line has four fields, not five.
func TestRealTraceOlderVersionLineStillConverts(t *testing.T) {
	res := convertRealExcerpt(t, ConvertOptions{Header: EventHeader{Variant: "nofilter"}})
	if res.Header.PathBufferLen != 256 {
		t.Errorf("string length = %d, want the one the trace reports", res.Header.PathBufferLen)
	}
	if res.Header.BufferPages != 64 {
		t.Errorf("buffer size = %d page(s), want the one the trace reports", res.Header.BufferPages)
	}
	// A trace that names no variant leaves the caller's value alone.
	if res.Header.Variant != "nofilter" {
		t.Errorf("variant = %q, want the caller's", res.Header.Variant)
	}
}

// TestVariantTagIsReadAndCrossChecked checks the field the scripts now
// write, which is what keeps two runs under different filters apart.
func TestVariantTagIsReadAndCrossChecked(t *testing.T) {
	trace := "V|1|256|64|filtered-a\nE|1000|2|2|3|400000000|sh|/bin/sh\n"
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Header.Variant != "filtered-a" {
		t.Errorf("variant = %q, want the one the trace names", res.Header.Variant)
	}
	if res.Header.Filter != "filtered-a" {
		t.Errorf("filter = %q, want the variant when none was given", res.Header.Filter)
	}

	_, err = Convert(strings.NewReader(trace), ConvertOptions{
		BootEpoch: bootEpoch, ClockTicksPerSecond: 100,
		Header: EventHeader{Variant: "filtered-b"},
	})
	if err == nil {
		t.Fatal("a variant the caller and the trace disagree on was accepted")
	}
	if !strings.Contains(err.Error(), "variant") {
		t.Errorf("error = %v, want it to name the disagreement", err)
	}
}

// v2TraceExcerpt is a hand-assembled fixture for script format version 2:
// see testdata/trace-v2-excerpt.txt for how its fields were assembled from
// a real run's own records, since no live capture in this format exists
// yet.
const v2TraceExcerpt = "testdata/trace-v2-excerpt.txt"

// TestVersion2TraceCarriesNamespaceNumbers checks that a version-2 trace's
// two extra columns are read into NSPID/NSTID, for both an execution and
// an open, without disturbing anything version 1 already reported —
// pairing, the outcome, the resolved generation.
func TestVersion2TraceCarriesNamespaceNumbers(t *testing.T) {
	f, err := os.Open(v2TraceExcerpt)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := Convert(f, ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatalf("convert a version-2 trace: %v", err)
	}
	if res.Header.Version != "2" {
		t.Errorf("header version = %q, want the trace's own 2", res.Header.Version)
	}

	byPath := map[string]EventRecord{}
	for _, ev := range res.Events {
		if _, seen := byPath[ev.RawPath]; !seen {
			byPath[ev.RawPath] = ev
		}
	}

	exec, ok := byPath["/usr/bin/curl"]
	if !ok || exec.Event != "exec" || !exec.OK {
		t.Fatalf("curl's execution did not convert: %+v", exec)
	}
	// The host and the container number this same process generation
	// differently; both are carried, and neither is guessed from the
	// other.
	if exec.PID != 3013915 || exec.TID != 3013915 {
		t.Errorf("host numbers = %d/%d, want 3013915/3013915", exec.PID, exec.TID)
	}
	if exec.NSPID != 3010380 || exec.NSTID != 3010380 {
		t.Errorf("namespace numbers = %d/%d, want 3010380/3010380", exec.NSPID, exec.NSTID)
	}
	// 292564211516946 nanoseconds at a hundred ticks a second.
	if exec.Starttime != "29256421" {
		t.Errorf("generation = %q, want 29256421 ticks", exec.Starttime)
	}

	open, ok := byPath["/etc/ld.so.cache"]
	if !ok || open.Event != "open" || !open.OK {
		t.Fatalf("curl's open of ld.so.cache did not convert: %+v", open)
	}
	if open.NSPID != 3010380 || open.NSTID != 3010380 {
		t.Errorf("open namespace numbers = %d/%d, want 3010380/3010380", open.NSPID, open.NSTID)
	}

	gitExec, ok := byPath["/usr/bin/git"]
	if !ok || gitExec.NSPID != 3010460 || gitExec.NSTID != 3010460 {
		t.Errorf("git's namespace numbers = %d/%d, want 3010460/3010460", gitExec.NSPID, gitExec.NSTID)
	}
	if res.Trailer.Drops.EnterExitUnmatched != 0 {
		t.Errorf("unmatched halves = %d, want none: every open in the fixture is complete", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestVersion1TraceReportsNoNamespaceNumbers checks that a trace in the
// format that predates ns_pid/ns_tid reports them as zero rather than
// misreading two of its own columns as though they were there.
func TestVersion1TraceReportsNoNamespaceNumbers(t *testing.T) {
	res := convertRealExcerpt(t, ConvertOptions{})
	for _, ev := range res.Events {
		if ev.NSPID != 0 || ev.NSTID != 0 {
			t.Errorf("event %q carries namespace numbers %d/%d from a version-1 trace, which has none", ev.RawPath, ev.NSPID, ev.NSTID)
		}
	}
}
