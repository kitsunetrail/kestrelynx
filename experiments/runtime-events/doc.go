// Command runtime-events converts kernel tracing output into an event log
// that says which container executed which program and read which file,
// and builds the control group correspondence table that attribution
// depends on.
//
// It is the companion to the sampling harness next to it. Sampling answers
// "what is loaded right now", which misses anything that starts and
// finishes between two samples; this answers "what happened", which is
// what short-lived programs and one-time module loads need.
//
// Three subcommands:
//
//	runtime-events clock
//	runtime-events cgroup-map -root /sys/fs/cgroup -out ./out/cgroup-map.json [-merge previous.json]
//	runtime-events convert -in trace.txt -cgroup-map ./out/cgroup-map.json -config-id bpftrace-v2-nofilter-64p -boot-epoch <instant> -out ./out/events.jsonl
//
// # Order of operations
//
// The observation has to be in place before the workload does anything, or
// a module loaded once at startup is missed by a collector that works
// perfectly. So: read the clock, build the correspondence table, start the
// tracer and confirm it is attached, start the sampling collector with the
// target registered, start the container, wait for the collector to accept
// it, and only then tell the workload to begin.
//
//	runtime-events clock -out ./out/clock.json
//	runtime-events cgroup-map -out ./out/cgroup-map.json
//	sudo bpftrace bpftrace/runtime-events-nofilter.bt > ./out/trace.txt 2> ./out/trace.err &
//	# ... start the container ...
//	runtime-events cgroup-map -merge ./out/cgroup-map.json -out ./out/cgroup-map.json
//	# ... confirm the attachment points are live by causing a known event ...
//	# ... wait for the collector's readiness file, fire the workload ...
//	# ... let the window run, stop the tracer, note when it stopped ...
//	runtime-events cgroup-map -merge ./out/cgroup-map.json -out ./out/cgroup-map.json
//	cat ./out/trace.txt ./out/trace.err |
//	  runtime-events convert -in - -cgroup-map ./out/cgroup-map.json \
//	    -config-id bpftrace-v2-nofilter-64p -sync startup -attached \
//	    -buffer-pages 64 -path-buffer 256 \
//	    -boot-epoch "$(jq -r .boot_epoch ./out/clock.json)" \
//	    -clock-error-ns "$(jq -r .error_ns ./out/clock.json)" \
//	    -stopped-at "$stop_instant" -window-end "$window_end" \
//	    -out ./out/events.jsonl
//
// The collection configuration, the ordering condition and the buffer size
// are all required, and the last two are checked against what the trace
// reports. The tracer's settings can be overridden from the environment,
// and the line it writes them on is written by the script rather than read
// back from the running configuration — so a disagreement means one of the
// two is not what the run used, and a measurement cannot be recorded
// against a configuration nobody can name.
//
// The tracer's standard error is fed in alongside its output because that
// is where it reports events it could not deliver, and those have to be
// counted.
//
// The correspondence table is refreshed twice, and the first refresh is
// not optional. A container created after the table was built is not in
// it, so every event it produces during the window resolves to nothing:
// the table has to be refreshed once the container exists and before the
// workload is told to begin. The second refresh, after the window, closes
// entries for containers that went away.
//
// Refreshing with -merge rather than rebuilding is what makes a container
// created or destroyed during the window resolvable: an entry closes at
// the moment a refresh found something else in its place, so an event from
// before that moment still resolves to the container that existed then,
// and one from after does not inherit it.
//
// Starting is not attaching. The tracer's first line of output says it
// began, not that every attachment point is live, so -attached is passed
// only after a known event has been caused and seen to come out. Without
// it the log is recorded as failed rather than as a window in which
// nothing happened, because those two cannot be told apart.
//
// # Clocks
//
// The tracer stamps events with the monotonic clock, named explicitly in
// the scripts rather than left to a default; the workload's own log is on
// a wall clock. The clock subcommand reads the same monotonic clock and a
// wall clock in succession and reports their difference together with how
// far apart the two readings were, which bounds the error.
//
// The two must be the one clock. The boot clock differs from the monotonic
// one by however long the machine was suspended, and a conversion built
// from one and applied to the other shifts every event by that much —
// silently, and by an amount nothing in the output would reveal.
//
// The bound travels with the log, and the matching side checks the pairing
// tolerance against it: a tolerance no wider than the conversion's own
// error would call a real pair a miss for a reason that has nothing to do
// with the collection.
//
// A trace that carries its own paired reading — a wrapper can prepend one —
// overrides the supplied value, being the closer reading.
//
// # What the converter will not do
//
// It will not guess at a path it could not resolve, and it will not
// attribute an event whose control group the table does not know. Both
// would produce more usable-looking output, and both would be inventions.
//
// Three kinds of path are separated before anything is resolved. An
// absolute path names a file. A path relative to the working directory
// names one only where that directory was recorded for that process
// generation. A path relative to a directory descriptor names one only to
// whoever holds the descriptor, which this does not — joining a working
// directory onto it would name a real file that was never opened, which is
// worse than naming no file.
//
// A path that filled the tracer's string buffer is marked as cut off
// rather than compared against anything. The buffer holds the terminator
// too, so a string one short of it filled it, and where it really ended is
// unknown; a shortened path that happens to match a real one is a false
// positive. The length comes from the trace's own version line rather than
// from what the caller believed.
//
// An event whose control group is unknown is reported as unattributed. It
// is not reported as the host's: the table has no entry for it, which is
// not the same as knowing it belongs to no container.
//
// # Losses
//
// Everything the collection missed is counted, by kind: events the buffer
// dropped, the notifications reporting those drops (which are a different
// number — one notification can stand for many events), system call halves
// whose partner never arrived, paths the kernel could not read, paths cut
// off at the buffer, lines that could not be converted, and a collection
// that stopped before the window ended, with the size of the hole it left.
//
// The counts come from the tracer's own counting maps, which survive two
// processors counting at once; adding to a scalar does not, and would
// quietly report fewer losses than there were.
//
// What cannot be counted is named rather than reported as zero. A failed
// insertion into the per-thread map is silent in this collection method;
// its consequence shows up as an unmatched half, but the count itself is
// unavailable, and a zero there would be a claim that nothing was lost. A
// window carrying any such kind is reported as degraded however clean the
// counted kinds are.
//
// The stop is what the wrapper observed, not the last event's time. A
// collection that ran to the end of the window and saw nothing looks
// identical, from the inside, to one that died early.
//
// # Scripts
//
// bpftrace/runtime-events-nofilter.bt is the collection script: it reports
// every successful execution and every openat/openat2 call it sees, and the
// converter and the mapping rules decide afterwards what is relevant.
//
// The three other scripts are the attempt to decide that in the kernel
// instead. runtime-events.bt compares a full-length copy of the path against
// a dozen markers; filtered-a compares a short head of the path and
// filtered-b shortens the configured string length. On Linux 6.6 with
// bpftrace 0.25 the verifier refused all three at load time — the string
// comparisons unroll into more conditional jumps than it will follow — so
// none of them has produced a measurement. They are kept so the attempt and
// its result stay reproducible; load one with --dry-run before assuming a
// different kernel accepts it. Each script names its own variant on its
// first line, and the converter records it, so two runs under different
// scripts cannot be added together.
//
// Every script takes the process and thread numbers as the initial PID
// namespace sees them, through pid(init) and tid(init). The plain pid and
// tid builtins answer from the tracer's own namespace and report zero for a
// task in another one — every process inside a container — and a zero used
// as the pending map's key collides across all of them, pairing outcomes
// with the wrong call.
//
// The filter matches on directory markers first and file endings second. A
// path cut off at the string length loses its ending but keeps its leading
// directories, so matching on the ending alone would drop exactly the long
// paths a module tree produces. A path cut off before any marker is still
// lost, and the unfiltered run is what measures how much that is.
//
// Both scripts set the string length and the output buffer size
// explicitly, and report them on their first line, so the size recorded
// beside a run is the size that was used rather than a default the caller
// assumed.
//
// This program is a standalone experiment: it is not part of the
// kestrelynx binary, imports no third-party dependencies, and its output
// (default ./out/) is never committed.
package main
