package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "convert":
		err = runConvert(os.Args[2:])
	case "cgroup-map":
		err = runCgroupMap(os.Args[2:])
	case "clock":
		err = runClock(os.Args[2:])
	case "-h", "-help", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s <subcommand> [flags]

subcommands:
  clock        print the wall-clock instant the monotonic clock reads zero at
  cgroup-map   build or refresh the control group to container correspondence table
  convert      turn a tracer's output into an event log

Run "%s <subcommand> -h" for subcommand flags.
`, os.Args[0], os.Args[0])
}

// runClock prints the wall-clock instant the monotonic clock reads zero
// at, which is what relates an event's monotonic stamp to anything else.
//
// It is computed from two readings taken as close together as the program
// can manage, and the gap between them is reported: a conversion whose
// error is unknown cannot be used to pair events with occurrences, so the
// error is part of the answer rather than left implicit.
func runClock(args []string) error {
	fs := flag.NewFlagSet("clock", flag.ExitOnError)
	out := fs.String("out", "", "write the reading to this file as JSON instead of standard output")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s clock [flags]\n\nPrints the wall-clock instant the monotonic clock reads zero at, with the error of the reading.\n\nflags:\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	epoch, errNS, err := monotonicEpoch()
	if err != nil {
		return err
	}
	reading := struct {
		BootEpoch   time.Time `json:"boot_epoch"`
		ErrorNS     int64     `json:"error_ns"`
		ClockSource string    `json:"clock_source"`
		Note        string    `json:"note"`
	}{
		BootEpoch: epoch, ErrorNS: errNS, ClockSource: "CLOCK_MONOTONIC",
		Note: "the wall-clock instant the monotonic clock reads zero at, computed from a wall reading and a monotonic reading taken in succession; error_ns is how far apart those two readings were. The tracing scripts stamp events with the same clock, named explicitly there: the boot clock differs from it by however long the machine was suspended",
	}
	data, err := json.MarshalIndent(reading, "", "  ")
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(string(data))
		return nil
	}
	return os.WriteFile(*out, append(data, '\n'), 0o644)
}

// monotonicEpoch reads the wall clock and the monotonic clock in
// succession and returns their difference, together with how long the two
// readings were apart — which bounds the error of the difference.
func monotonicEpoch() (time.Time, int64, error) {
	var ts syscall.Timespec
	before := time.Now()
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return time.Time{}, 0, fmt.Errorf("read the monotonic clock: %w", errno)
	}
	after := time.Now()
	mono := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
	mid := before.Add(after.Sub(before) / 2)
	return mid.Add(-mono).UTC(), after.Sub(before).Nanoseconds(), nil
}

// clockMonotonic is CLOCK_MONOTONIC, the clock a tracer's own timestamps
// are on.
const clockMonotonic = 1

func runCgroupMap(args []string) error {
	fs := flag.NewFlagSet("cgroup-map", flag.ExitOnError)
	root := fs.String("root", "/sys/fs/cgroup", "control group hierarchy root to walk")
	out := fs.String("out", "./out/cgroup-map.json", "output path for the correspondence table")
	merge := fs.String("merge", "", "an existing table to fold this snapshot into, so a container created during an observation window is added with the time it was found rather than replacing the table")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `usage: %s cgroup-map [flags]

Walks the control group hierarchy and records which container each group belongs to, the identifier the kernel reports for it, and how long the entry was valid. A group the walk does not find is not attributed to the host: it is simply not in the table, and an event in it is reported as unattributed.

Refresh the table during an observation window by running this again with -merge pointing at the previous output.

flags:
`, os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	table := buildCgroupTable(*root)
	if strings.TrimSpace(*merge) != "" {
		existing, err := readCgroupTable(*merge)
		if err != nil {
			return err
		}
		table = mergeCgroupTable(existing, table)
	}
	return writeJSON(*out, table)
}

func runConvert(args []string) error {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	in := fs.String("in", "", "the tracer's output to convert (required; \"-\" reads standard input)")
	out := fs.String("out", "./out/events.jsonl", "output path for the event log")
	cgroupMap := fs.String("cgroup-map", "", "the control group to container correspondence table; without it no event can be attributed to any container")
	configID := fs.String("config-id", "", "the event-collection configuration this log belongs to: collection method, script version, kernel-side filter and buffer size (required)")
	syncMode := fs.String("sync", "", "the ordering condition the collection ran under: startup | attach_running")
	method := fs.String("method", "bpftrace", "how the events were collected")
	version := fs.String("script-version", "3", "the tracing script's format version, checked against the second field of the trace's version line. Empty adopts the trace's own value; a saved trace in the pre-PID-namespace-identifier format needs -script-version 2, and one in the older, pre-namespace-number format needs -script-version 1")
	variant := fs.String("variant", "", "the tracing script's own variant name, checked against the fifth field of the trace's version line. Empty adopts the trace's own value")
	filter := fs.String("filter", "", "the kernel-side filter condition, empty when none was applied")
	bufferPages := fs.Int("buffer-pages", 0, "the collection buffer's size in pages")
	tracepoints := fs.String("tracepoints", "", "comma-separated list of the attachment points used")
	containerID := fs.String("container-id", "", "the container the collection was aimed at, when it was aimed at one")
	bootEpoch := fs.String("boot-epoch", "", "the wall-clock instant the monotonic clock reads zero at, as RFC3339 with nanoseconds (from the clock subcommand). A clock reading inside the trace overrides it")
	clockError := fs.Int64("clock-error-ns", 0, "how far apart the two readings the zero point was computed from were (the clock subcommand prints it). It bounds the conversion's own error, without which a pairing tolerance means nothing")
	clockSource := fs.String("clock-source", "CLOCK_MONOTONIC", "which clock the trace's stamps and the supplied zero point are both on. They must be the same clock: the boot clock differs from the monotonic one by however long the machine was suspended")
	clkTck := fs.Int64("clock-ticks", 100, "the kernel's clock ticks per second, used to convert a process generation's start time into the form the process table reports")
	pathBuffer := fs.Int("path-buffer", 0, "the tracer's string length. A path one short of it filled the buffer — the buffer holds the terminator too — so where it really ended is unknown and it is marked rather than compared. Left unset, the trace's own version line supplies it, falling back to 256 when the trace has none; an explicit value is instead checked against the version line")
	windowStart := fs.String("window-start", "", "when the observation window should have started, as RFC3339. Together with -window-end, this bounds what the collection guarantees complete: an entry or outcome timestamped outside it is credited to the window's own edge rather than counted as a loss inside it. Required together with -window-end for that boundary to be measured at all")
	windowEnd := fs.String("window-end", "", "when the observation window should have run to, as RFC3339")
	stoppedAt := fs.String("stopped-at", "", "when the collection actually stopped, as the wrapper observed it, in RFC3339. It is not guessed from the last event: a collection that ran to the end and saw nothing looks identical from the inside to one that died early")
	stopNote := fs.String("stop-reason", "", "why the collection stopped")
	started := fs.Bool("started", true, "whether the tracer came up at all")
	attached := fs.Bool("attached", false, "whether the attachment points were confirmed live by causing a known event and seeing it come out. Starting is not attaching, and an unconfirmed log is not evidence that nothing happened")
	attachedAt := fs.String("attached-at", "", "when every probe finished attaching, as RFC3339 with nanoseconds. bpftrace prints \"Attached N probes\" to stderr at that instant; where the wrapper has prefixed stderr with a wall-clock time per line, the trace supplies this itself and this flag is only needed when it has not. Given both, they must agree. Without either, an entry or outcome lost before every probe was live cannot be told apart from one lost after, and is counted as a loss inside the window rather than assumed to be a boundary artifact")
	cwdMap := fs.String("cwd-map", "", "comma-separated <pid>@<starttime>[@<from>-<to>]=<directory> entries giving a process generation's working directory over a stretch of time, which is what lets a path relative to it be resolved. The generation is required and the period is optional: a process number alone is reused, and a working directory can be changed, so resolving against the wrong one names a real file that was never opened. Times are RFC3339. Without a matching entry such a path stays unresolved")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `usage: %s convert [flags]

Turns a tracer's line-oriented output into an event log: pairs each system call's entry with its outcome, separates the path the program passed from the path that could be resolved from it, attributes each event to a container through its control group, and counts everything the collection missed.

Two things it will not do: guess at a path it could not resolve, and attribute an event whose control group the table does not know. Both would produce more usable-looking output and both would be inventions.

flags:
`, os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		fs.Usage()
		return fmt.Errorf("-in is required")
	}
	if strings.TrimSpace(*configID) == "" {
		return fmt.Errorf("-config-id is required: two runs collected under different filters or buffer sizes are different conditions, and a log that does not say which it belongs to cannot be kept apart from the other")
	}
	if strings.TrimSpace(*syncMode) == "" {
		return fmt.Errorf("-sync is required: a window whose workload began after the observation and one that joined a workload already running capture structurally different things, and a log that does not say which it is cannot be matched against an observation")
	}
	if *bufferPages <= 0 {
		return fmt.Errorf("-buffer-pages is required: the tracer's settings can be overridden from the environment, so the size that was actually used has to be stated and is checked against what the trace reports")
	}

	opts := ConvertOptions{
		Header: EventHeader{
			ConfigID: strings.TrimSpace(*configID), Sync: *syncMode, Method: *method,
			Version: *version, Variant: *variant, Filter: *filter, BufferPages: *bufferPages,
			ContainerID: *containerID, StartedAt: time.Now().UTC(),
		},
		ClockTicksPerSecond: *clkTck,
		PathBufferLen:       *pathBuffer,
		StopNote:            *stopNote,
		ClockErrorNS:        *clockError,
		ClockSourceID:       *clockSource,
		Started:             *started,
		Attached:            *attached,
	}
	for _, tp := range strings.Split(*tracepoints, ",") {
		if tp = strings.TrimSpace(tp); tp != "" {
			opts.Header.Tracepoints = append(opts.Header.Tracepoints, tp)
		}
	}
	if strings.TrimSpace(*bootEpoch) != "" {
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*bootEpoch))
		if err != nil {
			return fmt.Errorf("-boot-epoch: %w", err)
		}
		opts.BootEpoch = parsed
	}
	if strings.TrimSpace(*windowStart) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*windowStart))
		if err != nil {
			return fmt.Errorf("-window-start: %w", err)
		}
		opts.WindowStart = parsed
	}
	if strings.TrimSpace(*windowEnd) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*windowEnd))
		if err != nil {
			return fmt.Errorf("-window-end: %w", err)
		}
		opts.WindowEnd = parsed
	}
	if strings.TrimSpace(*stoppedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*stoppedAt))
		if err != nil {
			return fmt.Errorf("-stopped-at: %w", err)
		}
		opts.StoppedAt = parsed
	}
	if strings.TrimSpace(*attachedAt) != "" {
		parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(*attachedAt))
		if err != nil {
			return fmt.Errorf("-attached-at: %w", err)
		}
		opts.AttachedAt = parsed
	}
	entries, err := parseCWDMap(*cwdMap)
	if err != nil {
		return err
	}
	opts.CWD = entries
	if strings.TrimSpace(*cgroupMap) != "" {
		table, err := readCgroupTable(*cgroupMap)
		if err != nil {
			return err
		}
		opts.Lookup = newCgroupLookup(table)
	}

	src := os.Stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			return fmt.Errorf("read trace: %w", err)
		}
		defer f.Close()
		src = f
	}
	result, err := Convert(src, opts)
	if err != nil {
		return err
	}
	return writeEventLog(*out, result)
}

// parseCWDMap reads the working-directory entries. Each names a process
// generation, not merely a process number: a number is reused after a
// process exits, and resolving a relative path against the wrong
// directory names a real file that was never opened.
func parseCWDMap(spec string) ([]CWDEntry, error) {
	var out []CWDEntry
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		eq := strings.IndexByte(item, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("-cwd-map: %q is not a <pid>[@<starttime>]=<directory> entry", item)
		}
		key, dir := item[:eq], item[eq+1:]
		fields := strings.Split(key, "@")
		if len(fields) < 2 {
			return nil, fmt.Errorf("-cwd-map: %q names no process generation. A process number alone is reused after the process exits, and resolving a relative path against the wrong directory names a real file that was never opened; write <pid>@<starttime>[@<from>-<to>]=<directory>", item)
		}
		starttime := strings.TrimSpace(fields[1])
		if starttime == "" || starttime == "0" {
			return nil, fmt.Errorf("-cwd-map: %q has an empty process generation start time", item)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			return nil, fmt.Errorf("-cwd-map: %q does not start with a process number", item)
		}
		entry := CWDEntry{PID: pid, Starttime: starttime, Dir: dir}
		if len(fields) > 2 {
			// A working directory can be changed while a process runs, so
			// an entry may be bounded to the stretch over which it was
			// known to hold.
			period := strings.TrimSpace(fields[2])
			dash := strings.Index(period, "-")
			// The separator is the one between the two instants, not the
			// dashes inside a date.
			if i := strings.Index(period, "Z-"); i >= 0 {
				dash = i + 1
			}
			if dash <= 0 {
				return nil, fmt.Errorf("-cwd-map: %q has a period that is not <from>-<to>", item)
			}
			from, to := strings.TrimSpace(period[:dash]), strings.TrimSpace(period[dash+1:])
			if from != "" {
				parsed, perr := time.Parse(time.RFC3339, from)
				if perr != nil {
					return nil, fmt.Errorf("-cwd-map: %q: %w", item, perr)
				}
				entry.From = parsed
			}
			if to != "" {
				parsed, perr := time.Parse(time.RFC3339, to)
				if perr != nil {
					return nil, fmt.Errorf("-cwd-map: %q: %w", item, perr)
				}
				entry.Until = parsed
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// writeEventLog writes the header, every event, and the trailer, one JSON
// object per line.
func writeEventLog(path string, r ConvertResult) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(r.Header); err != nil {
		return err
	}
	for _, ev := range r.Events {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	return enc.Encode(r.Trailer)
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
