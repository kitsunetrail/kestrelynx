package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// These tests read the tracing scripts themselves and render the lines
// they would print, rather than checking a fixture whose fields were
// lined up by hand.
//
// The distinction matters. A hand-written fixture records what the output
// was believed to look like; the mistake it cannot catch is the script
// producing something else. That is exactly what happened here once: the
// entry's time and the identifier the outcome carried back were read from
// the clock separately, so the two never agreed and every open came out
// unpaired — while a fixture with the two fields set equal passed.

const scriptFiltered = "bpftrace/runtime-events.bt"
const scriptUnfiltered = "bpftrace/runtime-events-nofilter.bt"

// Every script that is shipped. The filtered variants exist because the
// first filtered script did not fit in the space a kernel program is
// given, and which of the two ways round that works is a property of the
// kernel and the version. All of them have to agree with the converter,
// whichever one a run ends up using.
var allScripts = []string{
	scriptFiltered,
	scriptUnfiltered,
	"bpftrace/runtime-events-filtered-a.bt",
	"bpftrace/runtime-events-filtered-b.bt",
	"bpftrace/runtime-events-nofilter-256p.bt",
	"bpftrace/runtime-events-nofilter-512p.bt",
}

// printfCall is one printf in a script: its format string and the
// arguments it passes.
type printfCall struct {
	format string
	args   []string
}

// printfCallRE matches a printf call spanning one or more lines, capturing
// the format string and, where there is one, the argument list. A call
// with no arguments — the version line — has to match too, or the check
// that every line's shape agrees with the converter would silently skip
// it.
var printfCallRE = regexp.MustCompile(`(?s)printf\("((?:[^"\\]|\\.)*)"\s*(?:,(.*?))?\);`)

func parsePrintfCalls(t *testing.T, path string) []printfCall {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	var out []printfCall
	for _, m := range printfCallRE.FindAllStringSubmatch(string(data), -1) {
		call := printfCall{format: m[1]}
		for _, a := range strings.Split(m[2], ",") {
			a = strings.TrimSpace(strings.ReplaceAll(a, "\n", " "))
			a = strings.Join(strings.Fields(a), " ")
			if a != "" {
				call.args = append(call.args, a)
			}
		}
		out = append(out, call)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no printf calls found; the parser and the script have diverged", path)
	}
	return out
}

func callsStartingWith(calls []printfCall, prefix string) []printfCall {
	var out []printfCall
	for _, c := range calls {
		if strings.HasPrefix(c.format, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// TestEntryAndOutcomeNameTheSameInstant is the check the hand-aligned
// fixture could not make.
//
// The outcome carries the entry's own time back so the two halves can be
// paired. That only works if the value the entry printed and the value it
// stored are the one reading: the clock moves between two readings, so
// taking it twice makes the outcome name an entry that never existed, and
// every open is then discarded as unpaired.
func TestEntryAndOutcomeNameTheSameInstant(t *testing.T) {
	for _, script := range allScripts {
		t.Run(script, func(t *testing.T) {
			data, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)

			// Every entry has to store and print one variable, not two
			// readings of the clock.
			if strings.Contains(text, "= nsecs(monotonic);\n\t@open_start") {
				t.Error("the entry stores a fresh reading of the clock; the value it prints will be a different one, and the outcome will name an entry that never existed")
			}
			stores := strings.Count(text, "@open_start[$htid] = $at;")
			if stores != 3 {
				t.Errorf("found %d entry probe(s) storing a held reading, want all three (open, openat, and openat2)", stores)
			}
			// The tracer's own process and thread builtins report a number
			// as its own namespace sees it, which is nothing at all for a
			// process in a container — every process this exists to watch.
			for _, builtin := range []string{", pid,", ", tid,", "@open_start[tid]"} {
				if strings.Contains(text, builtin) {
					t.Errorf("the script still uses %q, which reports nothing for a process in another namespace", strings.TrimSpace(builtin))
				}
			}
			// A length passed to str() draws a warning on every call site
			// when it equals the configured one, and the configured one
			// applies either way. The filtering variant passes a shorter
			// one on purpose, for the comparisons alone.
			if strings.Contains(text, "str(args->filename, 256)") {
				t.Error("str() is passed the same length the configuration already sets")
			}
			// The current form of the deletion takes the map and the key;
			// the one-argument form is deprecated and warns.
			if strings.Contains(text, "delete(@open_start[") {
				t.Error("the deprecated one-argument deletion is still used")
			}

			for _, c := range callsStartingWith(parsePrintfCalls(t, script), "O|") {
				if len(c.args) == 0 {
					t.Fatal("an entry printf passes no arguments")
				}
				if c.args[0] != "$at" {
					t.Errorf("the entry prints %q as its time, want the held reading it also stored", c.args[0])
				}
			}
		})
	}
}

// allSyscallProbes are the six syscall tracepoints every script has to
// attach in order to watch the whole open family. musl's open() on x86_64
// emits the legacy open syscall rather than calling openat(AT_FDCWD, ...)
// the way glibc's does, so watching only the openat and openat2 pairs
// misses every open() call a musl-linked process makes.
var allSyscallProbes = []string{
	"tracepoint:syscalls:sys_enter_open",
	"tracepoint:syscalls:sys_exit_open",
	"tracepoint:syscalls:sys_enter_openat",
	"tracepoint:syscalls:sys_exit_openat",
	"tracepoint:syscalls:sys_enter_openat2",
	"tracepoint:syscalls:sys_exit_openat2",
}

// TestScriptsAttachTheWholeOpenFamily checks that every script attaches
// all six open-family probes, each as its own attachment line rather than
// merely as a substring of another probe's name: "sys_enter_open" is a
// substring of "sys_enter_openat", so a naive substring search would pass
// even for a script that never attaches the plain open probe at all.
func TestScriptsAttachTheWholeOpenFamily(t *testing.T) {
	for _, script := range allScripts {
		t.Run(script, func(t *testing.T) {
			data, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			for _, probe := range allSyscallProbes {
				re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(probe) + `$`)
				if !re.MatchString(text) {
					t.Errorf("missing probe %q", probe)
				}
			}
		})
	}
}

// mapInsertCheckRE matches an insertion into the pending map immediately
// followed by the entry probe's own check that the key arrived — the only
// way to notice a failed insertion, since the assignment itself has no
// return value to test.
var mapInsertCheckRE = regexp.MustCompile(`(?s)@open_start\[\$htid\] = \$at;.*?if \(!has_key\(@open_start, \$htid\)\) \{\s*@map_insert_failed = count\(\);\s*\}`)

// TestMapInsertionFailureIsCounted checks that all three entry probes —
// open, openat, and openat2 — check their own insertion into the pending
// map right after making it and count a miss. Nothing else can catch this
// loss: bpftrace gives a map assignment no return value to test, so the
// only way to notice a failed one is to look for the key immediately
// afterward.
func TestMapInsertionFailureIsCounted(t *testing.T) {
	for _, script := range allScripts {
		t.Run(script, func(t *testing.T) {
			data, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			found := mapInsertCheckRE.FindAllString(text, -1)
			if len(found) != 3 {
				t.Errorf("found %d entry probe(s) checking their own insertion, want all three (open, openat, and openat2)", len(found))
			}
		})
	}
}

// endMapInsertFailedRE matches the END block's explicit report of the
// pending-map insertion failure count, right before clearing the map
// behind it.
var endMapInsertFailedRE = regexp.MustCompile(`printf\("@map_insert_failed: %llu\\n", \(uint64\)@map_insert_failed\);\s*\n\s*clear\(@map_insert_failed\);`)

// TestMapInsertFailedCounterIsExplicitlyReported checks that each script's
// END block prints the pending-map insertion failure count itself and
// clears the map right after, rather than leaving it to bpftrace's own
// automatic dump of a non-empty map. That dump never fires for this
// counter in the ordinary case where nothing failed, because bpftrace
// does not print an empty map at all — which is exactly what made a
// healthy run read as degraded before this was added.
func TestMapInsertFailedCounterIsExplicitlyReported(t *testing.T) {
	for _, script := range allScripts {
		t.Run(script, func(t *testing.T) {
			data, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			if !endMapInsertFailedRE.MatchString(string(data)) {
				t.Error("the script does not explicitly print @map_insert_failed and clear it right after, in its END block")
			}
		})
	}
}

// TestScriptOutputFieldsMatchTheConverter checks that the fields each line
// carries are the fields the converter reads out of it. A field added on
// one side and not the other is silently dropped or silently shifts every
// field after it.
func TestScriptOutputFieldsMatchTheConverter(t *testing.T) {
	for _, script := range allScripts {
		t.Run(script, func(t *testing.T) {
			calls := parsePrintfCalls(t, script)
			want := map[string]int{
				"V|": 5,  // version, string length, buffer pages, variant (the first field is the kind)
				"E|": 11, // time, pid, tid, nspid, nstid, pid namespace, control group, generation, command, path
				"O|": 11, // time, pid, tid, nspid, nstid, pid namespace, control group, generation, directory descriptor, path
				"X|": 9,  // time, pid, tid, nspid, nstid, pid namespace, result, the entry's time
			}
			for prefix, fields := range want {
				found := callsStartingWith(calls, prefix)
				if len(found) == 0 {
					t.Errorf("the script prints no %q line", prefix)
					continue
				}
				for _, c := range found {
					got := len(strings.Split(strings.TrimSuffix(c.format, `\n`), "|"))
					if got != fields {
						t.Errorf("a %q line carries %d field(s), want %d", prefix, got, fields)
					}
				}
			}
		})
	}
}

// verbRE matches one conversion in a format string.
var verbRE = regexp.MustCompile(`%[-+ #0]*[0-9]*(?:\.[0-9]+)?(?:ll|l|h)?[a-zA-Z]`)

// renderPrintf renders one of the script's printf calls by substituting
// each conversion with the value bound to the argument in that position.
//
// The line is built from the script's own format string and its own
// argument list, in the script's own order. A field moved from one place
// to another, or two arguments swapped, changes what this produces — which
// is the point: a line assembled here by hand would keep agreeing with the
// converter long after the script had stopped.
func renderPrintf(t *testing.T, c printfCall, bindings map[string]string) string {
	t.Helper()
	verbs := verbRE.FindAllStringIndex(c.format, -1)
	if len(verbs) != len(c.args) {
		t.Fatalf("the format %q has %d conversion(s) and %d argument(s)", c.format, len(verbs), len(c.args))
	}
	var b strings.Builder
	last := 0
	for i, v := range verbs {
		b.WriteString(c.format[last:v[0]])
		value, ok := bindings[c.args[i]]
		if !ok {
			t.Fatalf("no value bound for the argument %q of %q; the script prints something this test does not know about", c.args[i], c.format)
		}
		b.WriteString(value)
		last = v[1]
	}
	b.WriteString(c.format[last:])
	return strings.TrimSuffix(b.String(), `\n`)
}

// openBindings is what each of the script's arguments evaluates to for one
// open.
//
// The entry's held reading and the value the outcome sends back are
// deliberately the same binding: that the two are one reading is the
// property under test, and binding them separately here would hide a
// script that reads the clock twice.
func openBindings(entryAt, exitAt int64, pid, tid int, cgroup uint64, startNS int64, dirfd int, path string, ret int, pidns uint64) map[string]string {
	return map[string]string{
		"$at":                itoa64(entryAt),
		"@open_start[tid]":   itoa64(entryAt),
		"@open_start[$htid]": itoa64(entryAt),
		"nsecs(monotonic)":   itoa64(exitAt),
		// The process and thread numbers are read with pid(init) and
		// tid(init), which name the initial namespace's numbers. The bare
		// pid and tid builtins answer relative to the current pid
		// namespace, which is nothing at all for a process in a container.
		"pid(init)": itoa(pid),
		"tid(init)": itoa(tid),
		"$htid":     itoa(tid),
		"pid":       itoa(pid),
		"tid":       itoa(tid),
		// The namespace-scoped numbers, read from the task's own struct
		// pid rather than either builtin above. The fixture gives them
		// the same value as the initial-namespace ones: nothing here
		// models a container of its own, and what this test checks is
		// that the script prints the value it computed, not that the
		// value differs from pid(init)/tid(init).
		"$nspid": itoa(pid),
		"$nstid": itoa(tid),
		// The identifier of the PID namespace the two numbers above are
		// scoped to, read off the same struct pid entry $nstid comes from.
		"$nsinum":                               itoa64(int64(pidns)),
		"cgroup":                                itoa64(int64(cgroup)),
		"curtask->group_leader->start_boottime": itoa64(startNS),
		"args->dfd":                             itoa(dirfd),
		"args->ret":                             itoa(ret),
		"$p":                                    path,
		"$head":                                 path,
		"str(args->filename)":                   path,
		// The open probe has no directory-descriptor argument to read, so
		// it prints the literal -100 (AT_FDCWD) rather than a variable;
		// this is that literal's own rendering, not a stand-in for
		// args->dfd.
		"-100": itoa64(atFDCWD),
	}
}

// openProbePairs returns one entry-and-outcome pair per attachment point
// the script watches, each rendered from that probe's own format string
// and argument list.
//
// Every pair is returned, not the first. A script watches more than one
// attachment point — the three open calls — and they are separate code: a
// field added to one and not the other, or an argument order changed in
// one of them, is exactly the kind of divergence that survives a check
// which only ever looks at whichever came first in the file.
func openProbePairs(t *testing.T, script string, entryAt, exitAt int64, pid, tid int, cgroup uint64, startNS int64, dirfd int, path string, ret int, pidns uint64) [][2]string {
	t.Helper()
	calls := parsePrintfCalls(t, script)
	enter := callsStartingWith(calls, "O|")
	exit := callsStartingWith(calls, "X|")
	if len(enter) == 0 || len(exit) == 0 {
		t.Fatalf("%s: no entry or outcome line to render", script)
	}
	if len(enter) != len(exit) {
		t.Fatalf("%s: %d entry line(s) and %d outcome line(s); every attachment point that records an entry has to record its outcome",
			script, len(enter), len(exit))
	}
	bindings := openBindings(entryAt, exitAt, pid, tid, cgroup, startNS, dirfd, path, ret, pidns)
	out := make([][2]string, 0, len(enter))
	for i := range enter {
		out = append(out, [2]string{renderPrintf(t, enter[i], bindings), renderPrintf(t, exit[i], bindings)})
	}
	return out
}

func itoa(v int) string     { return itoa64(int64(v)) }
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

// TestOpenRoundTripFromTheScriptsOwnShape converts a successful and a
// failed open rendered from the scripts' own format strings, with the
// entry's time shared between the two halves the way the script shares it.
func TestOpenRoundTripFromTheScriptsOwnShape(t *testing.T) {
	for _, script := range allScripts {
		t.Run(script, func(t *testing.T) {
			// Each attachment point is converted on its own, so a
			// divergence in one of them cannot be covered by the other
			// working.
			okPairs := openProbePairs(t, script,
				1_000_000_000, 1_000_500_000, 4242, 4242, 52161, 400_000_000, atFDCWD, "/lib/a.so", 3, 4026531836)
			failPairs := openProbePairs(t, script,
				2_000_000_000, 2_000_500_000, 4242, 4242, 52161, 400_000_000, atFDCWD, "/lib/b.so", -2, 4026531836)
			if len(okPairs) != 3 {
				t.Fatalf("%s: rendered %d attachment point(s), want all three open calls", script, len(okPairs))
			}

			for probe := range okPairs {
				t.Run(fmt.Sprintf("probe %d", probe), func(t *testing.T) {
					okEntry, okExit := okPairs[probe][0], okPairs[probe][1]
					failEntry, failExit := failPairs[probe][0], failPairs[probe][1]
					for _, line := range []string{okEntry, okExit, failEntry, failExit} {
						if strings.Contains(line, "%") {
							t.Fatalf("a rendered line still holds a conversion: %q", line)
						}
					}

					// The scripts are on format version 3, which is what
					// their own rendered lines above are shaped like; an
					// earlier version's header here would make the converter
					// read them with the wrong field layout.
					trace := strings.Join([]string{
						"V|3|256|64", okEntry, okExit, failEntry, failExit,
					}, "\n") + "\n"

					res, err := Convert(strings.NewReader(trace), ConvertOptions{
						BootEpoch: bootEpoch, ClockTicksPerSecond: 100,
					})
					if err != nil {
						t.Fatalf("convert: %v", err)
					}
					if len(res.Events) != 2 {
						t.Fatalf("got %d event(s) from two complete opens, want 2 — the two halves did not pair", len(res.Events))
					}
					if res.Trailer.Drops.EnterExitUnmatched != 0 {
						t.Errorf("unmatched halves = %d, want none: both opens were complete", res.Trailer.Drops.EnterExitUnmatched)
					}

					byPath := map[string]EventRecord{}
					for _, ev := range res.Events {
						byPath[ev.Path] = ev
					}
					if got := byPath["/lib/a.so"]; !got.OK || got.Ret != 3 {
						t.Errorf("the successful open came back OK=%v Ret=%d", got.OK, got.Ret)
					}
					if got := byPath["/lib/b.so"]; got.OK {
						t.Error("the failed open came back as successful")
					}
					// The event's time is the entry's, which is when the
					// program asked for the file.
					if got := byPath["/lib/a.so"].MonotonicNS; got != 1_000_000_000 {
						t.Errorf("event time = %d, want the entry's %d", got, 1_000_000_000)
					}
					// The process generation is the leading thread's, in
					// the clock ticks the process table reports.
					if got := byPath["/lib/a.so"].Starttime; got != "40" {
						t.Errorf("generation = %q, want 40 ticks", got)
					}
				})
			}
		})
	}
}

// TestTwoClockReadingsWouldUnpairEveryOpen reproduces the failure the
// shared reading prevents, so a change that reintroduces it is caught by a
// test rather than by an empty result.
func TestTwoClockReadingsWouldUnpairEveryOpen(t *testing.T) {
	// The entry printed one instant and stored another, a nanosecond
	// apart: exactly what two readings of a moving clock produce.
	trace := strings.Join([]string{
		"V|1|256|64",
		"O|1000000000|4242|4242|52161|400000000|-100|/lib/a.so",
		"X|1000500000|4242|4242|3|1000000001",
	}, "\n") + "\n"
	res, err := Convert(strings.NewReader(trace), ConvertOptions{BootEpoch: bootEpoch, ClockTicksPerSecond: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		t.Error("an outcome naming an entry that never existed was paired anyway")
	}
	if res.Trailer.Drops.EnterExitUnmatched != 2 {
		t.Errorf("unmatched halves = %d, want both counted", res.Trailer.Drops.EnterExitUnmatched)
	}
}

// TestRenderingFollowsTheScriptsArgumentOrder checks that the renderer is
// sensitive to the order the script passes its arguments in.
//
// Without this the round-trip test would keep passing after two fields
// were swapped in the script: it would render the line the way it always
// had, and the converter would read the swapped fields into the wrong
// places with no test noticing.
func TestRenderingFollowsTheScriptsArgumentOrder(t *testing.T) {
	bindings := map[string]string{"pid": "11", "tid": "22"}
	asWritten := printfCall{format: `X|%d|%d\n`, args: []string{"pid", "tid"}}
	swapped := printfCall{format: `X|%d|%d\n`, args: []string{"tid", "pid"}}

	if got, want := renderPrintf(t, asWritten, bindings), "X|11|22"; got != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
	if got, want := renderPrintf(t, swapped, bindings), "X|22|11"; got != want {
		t.Errorf("with the arguments swapped, rendered %q, want %q", got, want)
	}
}

// TestEveryScriptArgumentIsAccountedFor checks that the renderer knows a
// value for every argument both scripts pass, on every line they print.
//
// Each enumerated call is rendered, not a stand-in for it: rendering fails
// the test on an argument nothing is bound for, so a probe that starts
// printing something new is caught here rather than quietly falling out of
// the round-trip check.
func TestEveryScriptArgumentIsAccountedFor(t *testing.T) {
	bindings := openBindings(1_000, 2_000, 1, 1, 1, 1, atFDCWD, "/lib/a.so", 0, 4026531836)
	// The lines that are not part of an open carry their own arguments.
	bindings["comm"] = "sh"
	bindings["@seen"] = "0"
	bindings["@kept"] = "0"
	bindings["(uint64)@map_insert_failed"] = "0"

	for _, script := range allScripts {
		t.Run(script, func(t *testing.T) {
			calls := parsePrintfCalls(t, script)
			for i, c := range calls {
				rendered := renderPrintf(t, c, bindings)
				if rendered == "" {
					t.Errorf("call %d (%q) rendered empty", i, c.format)
				}
				if strings.Contains(rendered, "%") {
					t.Errorf("call %d rendered %q, which still holds a conversion", i, rendered)
				}
			}
		})
	}
}

// TestNamespaceIdentifierIsPrintedUnsigned checks every record format in
// every script prints the namespace identifier with an unsigned
// conversion: the tracer renders %d through a signed 32-bit conversion,
// which would turn most identifiers negative.
func TestNamespaceIdentifierIsPrintedUnsigned(t *testing.T) {
	for _, script := range allScripts {
		src, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "printf(\"E|") && !strings.HasPrefix(trimmed, "printf(\"O|") && !strings.HasPrefix(trimmed, "printf(\"X|") {
				continue
			}
			cols := strings.Split(strings.TrimPrefix(strings.SplitN(trimmed, "\\n", 2)[0], "printf(\""), "|")
			if len(cols) < 7 || cols[6] != "%u" {
				t.Errorf("%s: %s: the namespace identifier column must be %%u, got %q", script, trimmed, cols[min(6, len(cols)-1)])
			}
		}
	}
}
