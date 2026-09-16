package main

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The tracing script writes one line per record, fields separated by "|",
// with the path last so a path containing the separator is still read
// whole.
//
//	V|<format version>|<string buffer length>|<buffer pages>|<script variant>
//	C|<monotonic ns>|<wall clock ns since the epoch>
//	E|<monotonic ns>|<pid>|<tid>|<nspid>|<nstid>|<cgroup id>|<leader start, ns>|<comm>|<path as passed>
//	O|<monotonic ns>|<pid>|<tid>|<nspid>|<nstid>|<cgroup id>|<leader start, ns>|<dirfd>|<path as passed>
//	X|<monotonic ns>|<pid>|<tid>|<nspid>|<nstid>|<return value>|<entry's monotonic ns>
//	M|<counter name>|<value>
//
// nspid and nstid are the process and thread numbers as the task's own PID
// namespace sees them, read from its struct pid rather than from either
// pid(init)/tid(init) or the bare pid/tid builtins; format version 1
// carries neither, and the converter reads such a trace as though both
// were zero. A version-1 trace's E, O and X lines are two fields shorter,
// at the same position.
//
// Entry and exit are separate records because the entry carries the path
// and the exit carries the outcome, and only a successful open is use.
//
// The tracer also prints its own counting maps on exit, one per line as
// "@<name>: <value>". Those are read too: counting with a map is what
// makes the numbers survive two processors counting at once, which adding
// to a scalar does not.
const (
	recVersion   = "V"
	recClockSync = "C"
	recExec      = "E"
	recOpenEnter = "O"
	recOpenExit  = "X"
	recCounter   = "M"
)

// lostEventsRE matches the tracer's own report of events it could not
// deliver. The number in it is events, not notifications, and the two are
// counted separately: one notification can stand for many lost events.
var lostEventsRE = regexp.MustCompile(`[Ll]ost\s+(\d+)\s+event`)

// counterMapRE matches one of the tracer's printed counting maps.
var counterMapRE = regexp.MustCompile(`^@([A-Za-z0-9_]+):\s*(\d+)\s*$`)

// wallClockPrefixRE matches a wall-clock time, as RFC3339 with
// nanoseconds, that a wrapper has prefixed onto a line of the tracer's
// stderr before saving it — the form the case runner writes so that a
// line reporting something at an instant (attach completing, a
// lost-event notice) can be judged against that instant rather than
// against when the line happened to reach the file. Both an offset of Z
// and a numeric one such as +09:00 are accepted, since the wrapper may
// run in either. A line from the trace's own stdout never carries this
// prefix.
var wallClockPrefixRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(.*)$`)

// attachedRE matches bpftrace's own report that every probe finished
// attaching.
var attachedRE = regexp.MustCompile(`^Attached\s+\d+\s+probes?\b`)

// atFDCWD is the "relative to the current directory" descriptor, as a
// trace records it.
const atFDCWD = -100

// defaultPathBufferLen is the string length the accompanying tracing
// scripts are configured with. Truncation detection is on by default
// because a path cut off at the buffer cannot be compared against
// anything, and treating one as complete produces a wrong match rather
// than a missing one.
const defaultPathBufferLen = 256

// CWDEntry is one process's working directory over a stretch of time.
//
// It is bounded in time for the same reason a control group entry is: a
// process can change its working directory, and a number is reused after a
// process exits. A relative path resolved against the wrong directory
// names a real file that was never opened, which is worse than naming no
// file at all.
type CWDEntry struct {
	PID       int       `json:"pid"`
	Starttime string    `json:"starttime,omitempty"`
	Dir       string    `json:"dir"`
	From      time.Time `json:"from,omitempty"`
	Until     time.Time `json:"until,omitempty"`
}

// ConvertOptions is everything the conversion needs that is not in the
// trace itself.
type ConvertOptions struct {
	Header EventHeader
	// BootEpoch is the wall-clock instant the monotonic clock reads zero
	// at, and ClockErrorNS how far apart the two readings it was computed
	// from were. The error is carried into the event log because a
	// tolerance for pairing events with occurrences means nothing beside a
	// conversion whose own error is unknown.
	BootEpoch     time.Time
	ClockErrorNS  int64
	ClockSourceID string
	// ClockTicksPerSecond converts a process generation's start time in
	// nanoseconds, as the kernel holds it, into the clock ticks the
	// process table reports — the form a workload's own log records, and
	// the only process identifier that reads the same inside a container
	// and outside it.
	ClockTicksPerSecond int64
	// PathBufferLen is the tracer's string length. A path that came back
	// one short of it filled the buffer, since the buffer also holds the
	// terminator, and where it really ended is unknown.
	PathBufferLen int
	// CWD is what a process's working directory was over a stretch of
	// time, where the case runner could record it. Without a matching
	// entry a path relative to the working directory stays unresolved.
	CWD    []CWDEntry
	Lookup *cgroupLookup

	// WindowStart and WindowEnd bound the observation window the
	// collection is answerable for. The wrapper starts the tracer before
	// this and stops it well after, so what the collection guarantees
	// complete is the window itself, not the whole time the tracer
	// happened to run — an entry/exit half timestamped outside
	// [WindowStart, WindowEnd] is judged accordingly (see the boundary
	// classification in Convert). Both are required together: with
	// either one missing, no boundary can be measured, and every
	// unmatched half is counted as a loss inside the window instead of
	// being credited to a boundary nothing here established.
	WindowStart time.Time
	WindowEnd   time.Time
	// StoppedAt is when the collection actually stopped, as the wrapper
	// observed it. It is not guessed from the last event: a collection
	// that ran to the end of the window and saw nothing looks identical
	// from the inside to one that died early.
	StoppedAt time.Time
	StopNote  string
	// Started and Attached say whether the tracer came up and whether its
	// attachment points were confirmed live by causing a known event.
	// Starting is not attaching, and neither is assumed.
	Started  bool
	Attached bool
	// AttachedAt is when every probe finished attaching, given explicitly
	// by the caller. bpftrace prints "Attached N probes" to stderr the
	// instant that happens; where the wrapper prefixes each stderr line
	// with a wall-clock time, the trace supplies this itself (see
	// wallClockPrefixRE) and AttachedAt is only a fallback for a trace
	// where it does not. Given both, they must agree — see Convert.
	AttachedAt time.Time
}

// ConvertResult is one conversion's output.
type ConvertResult struct {
	Header  EventHeader
	Events  []EventRecord
	Trailer EventsTrailer
}

// pendingKey identifies one open call by its thread and the monotonic
// time its entry was seen at. A thread only ever has one call outstanding
// in the kernel at a time, but records can still arrive in an order that
// makes it look otherwise — the entry's own time is what tells two of a
// thread's calls apart when that happens, rather than only ever letting
// one be tracked per thread at all.
type pendingKey struct {
	tid  int
	mono int64
}

// pendingOpen is one open whose entry has been seen and whose outcome has
// not, held under pendingKey.
type pendingOpen struct {
	monotonic int64
	pid       int
	tid       int
	// nspid and nstid are the process and thread as their own PID
	// namespace numbers them. A trace in the script format that predates
	// them carries zero here.
	nspid int
	nstid int
	// pidns is the identifier of the PID namespace nspid and nstid are
	// numbered in. A trace in the script format that predates it (format
	// version below 3) carries zero here.
	pidns   uint64
	cgroup  uint64
	startNS int64
	dirfd   int64
	rawPath string
	source  string
}

// pendingExit is an outcome that arrived before its entry. The two halves
// travel through per-processor buffers, so a thread moved between
// processors can have them delivered out of order; holding the outcome
// briefly is what keeps that from being counted as two separate losses.
//
// entryAt is the time the tracer recorded for the entry this outcome
// belongs to, sent back with the outcome. It is what makes the pairing
// safe: on the thread number alone, an outcome whose own entry was lost
// would be joined to the next entry and report that call's success or
// failure as belonging to a different file.
type pendingExit struct {
	monotonic int64
	pid       int
	ret       int64
	entryAt   int64
}

// Convert turns a tracer's output into an event log.
//
// Two things it deliberately does not do: it does not guess at a path it
// could not resolve, and it does not attribute an event whose control
// group the table does not know. Both would produce more usable-looking
// output and both would be inventions.
func Convert(r io.Reader, opts ConvertOptions) (ConvertResult, error) {
	out := ConvertResult{Header: opts.Header}
	out.Header.Record = eventsHeaderKind
	if out.Header.StartedAt.IsZero() {
		out.Header.StartedAt = time.Now().UTC()
	}
	ticks := opts.ClockTicksPerSecond
	if ticks <= 0 {
		ticks = 100
	}
	// A caller that named no length at all defers entirely to whatever the
	// trace's own version line reports. Folding an unspecified length
	// into the default before that comparison ran made it indistinguishable
	// from an explicit 256, and rejected every trace whose script was
	// configured with any other length. Only an explicit length is held
	// against the trace.
	pathBufferExplicit := opts.PathBufferLen > 0
	if opts.PathBufferLen <= 0 {
		opts.PathBufferLen = defaultPathBufferLen
	}
	bootEpoch := opts.BootEpoch

	// pending is keyed by the entry's own thread and monotonic time, not
	// by thread alone: a thread's two calls in flight at once — an
	// impossibility in the kernel, but not in the order records happen to
	// arrive in, once per-CPU buffers are in play — would otherwise have
	// the second overwrite the first's slot before its outcome ever
	// showed up. Keyed this way, an outcome that carries its entry's own
	// time (see pendingExit.entryAt) finds the exact entry it belongs to
	// regardless of what else is still outstanding for the same thread,
	// and regardless of the order the two arrived in.
	pending := map[pendingKey]pendingOpen{}
	// exitsByTid holds outcomes still waiting for their entry, per thread,
	// in the order they arrived. More than one can be held at once for
	// the same reason pending can hold more than one entry: reordering
	// across per-CPU buffers, not concurrent calls on one thread.
	exitsByTid := map[int][]pendingExit{}
	var drops EventDropCounts
	// attachedAtWall is when every probe finished attaching, read from a
	// wall-clock-prefixed "Attached N probes" line if the trace carries
	// one, or from ConvertOptions.AttachedAt. It is recorded in the
	// header for reference only: attach completion is not something the
	// collection measured against the observation window, and an entry
	// or outcome timestamped before it is not thereby known to predate
	// every probe being live. Only the window itself — see WindowStart
	// and WindowEnd — is what an unmatched half is judged against.
	var attachedAtWall time.Time
	// Events that arrived with no path at all. The tracer counts the same
	// failures itself, before its filter, so this is only used when the
	// trace carried no such count: adding both would report each failure
	// twice.
	emptyPaths := 0
	sawClockSync := false
	sawAnyRecord := false
	// sawMapInsertFailedCounter is whether the trace carried the tracer's
	// own count of failed pending-map insertions. Its absence, not its
	// value, is what decides whether the loss stays unmeasured: a trace
	// from before the counter existed carries neither the line nor a way
	// to tell a run that had no failures from one that could not see them.
	sawMapInsertFailedCounter := false
	// mapInsertFailedCount holds that count as it is read, kept apart from
	// drops.MapOverflow until the trace is fully read. -1 is "not seen",
	// not zero, so a script that explicitly reports zero is still told
	// apart from one that never reported at all. A second occurrence of
	// the line is not added to the first: the script's END block prints
	// this counter exactly once and clears the map behind it, so two
	// occurrences are a duplicate of the one count, not two counts to
	// combine, and the larger of the two is kept rather than their sum.
	mapInsertFailedCount := -1
	// scriptVersion is the trace's own format version, as a number rather
	// than a string, because it decides how many columns an E, O or X
	// line carries: format version 2 adds the namespace-scoped process
	// and thread numbers between the tid and the columns that follow it,
	// and reading a version-1 trace as though it had them would shift
	// every field after tid. It starts at the caller-supplied version,
	// where one was given, and is corrected to whatever the trace's own
	// V line reports once that line is read.
	scriptVersion := 1
	switch opts.Header.Version {
	case "2":
		scriptVersion = 2
	case "3":
		scriptVersion = 3
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\n")
		if line == "" {
			continue
		}
		// A wrapper that saves stderr with a wall-clock time prefixed onto
		// each line is reporting when that line was written, not part of
		// the tracer's own record. It is peeled off before anything else
		// reads the line, so every check below sees the same shape whether
		// or not the line came with one.
		var linePrefixWall time.Time
		if m := wallClockPrefixRE.FindStringSubmatch(line); m != nil {
			if t, terr := time.Parse(time.RFC3339Nano, m[1]); terr == nil {
				linePrefixWall = t
				line = m[2]
				if line == "" {
					continue
				}
			}
		}
		if attachedRE.MatchString(line) {
			// The first such line wins; the settings are what the run
			// actually used, and a second occurrence would be the same
			// fact reported again, not a different one.
			if !linePrefixWall.IsZero() && attachedAtWall.IsZero() {
				attachedAtWall = linePrefixWall
			}
			continue
		}
		if m := lostEventsRE.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			drops.LostEvents += n
			drops.LostNotifications++
			continue
		}
		if m := counterMapRE.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[2])
			if m[1] == "map_insert_failed" {
				sawMapInsertFailedCounter = true
				if n > mapInsertFailedCount {
					mapInsertFailedCount = n
				}
			} else {
				applyCounter(&drops, m[1], n)
			}
			sawAnyRecord = true
			continue
		}
		if !strings.Contains(line, "|") {
			// Anything the tracer writes that is not a record — its
			// startup banner, a warning — is not an event and not a loss.
			continue
		}
		kind := line[:strings.IndexByte(line, '|')]
		switch kind {
		case recVersion:
			sawAnyRecord = true
			// The tracer reports the format version, string length, and
			// buffer size it was actually configured with, which is what
			// belongs in the record beside the results — not whatever the
			// caller believed.
			f := strings.SplitN(line, "|", 5)
			if len(f) >= 2 {
				// The second column is the script's own format version;
				// the fifth, below, is its variant. The two name different
				// things, and checking one against the other left a run
				// under a named variant unable to state its own format
				// version at all.
				version := strings.TrimSpace(f[1])
				if out.Header.Version != "" && version != "" && out.Header.Version != version {
					return out, fmt.Errorf(
						"script version disagreement: the trace reports %q and the caller %q. One of them is not what this run used",
						version, out.Header.Version)
				}
				if version != "" {
					out.Header.Version = version
					// The trace's own line is what the E, O and X lines
					// that follow it are actually shaped like — not
					// whatever the caller believed the run used.
					switch version {
					case "2":
						scriptVersion = 2
					case "3":
						scriptVersion = 3
					default:
						scriptVersion = 1
					}
				}
			}
			if len(f) >= 3 {
				if n, err := strconv.Atoi(strings.TrimSpace(f[2])); err == nil && n > 0 {
					if pathBufferExplicit && opts.PathBufferLen != n {
						// The tracer's settings can be overridden from the
						// environment, and the line below is written by the
						// script rather than read back from the running
						// configuration. A disagreement means one of the two
						// is not what the run actually used, and a
						// measurement cannot be recorded against a
						// configuration nobody can name.
						return out, fmt.Errorf(
							"string length disagreement: the trace reports %d and the caller %d. One of them is not what this run used; settle it before recording a measurement against either",
							n, opts.PathBufferLen)
					}
					opts.PathBufferLen = n
				}
			}
			if len(f) >= 5 {
				// The script names its own variant. Two variants of the
				// filter are different conditions, and a log that does not
				// say which produced it cannot be kept apart from the
				// other.
				variant := strings.TrimSpace(f[4])
				if out.Header.Variant != "" && variant != "" && out.Header.Variant != variant {
					return out, fmt.Errorf(
						"script variant disagreement: the trace was produced by %q and the caller says %q. One of them is not what this run used",
						variant, out.Header.Variant)
				}
				if variant != "" {
					out.Header.Variant = variant
					if out.Header.Filter == "" {
						out.Header.Filter = variant
					}
				}
			}
			if len(f) >= 4 {
				if n, err := strconv.Atoi(strings.TrimSpace(f[3])); err == nil && n > 0 {
					if out.Header.BufferPages > 0 && out.Header.BufferPages != n {
						return out, fmt.Errorf(
							"buffer size disagreement: the trace reports %d page(s) and the caller %d. One of them is not what this run used, and the collection configuration identifier would name the wrong one",
							n, out.Header.BufferPages)
					}
					out.Header.BufferPages = n
				}
			}
			continue
		case recClockSync:
			sawAnyRecord = true
			f := strings.SplitN(line, "|", 3)
			if len(f) < 3 {
				drops.ConvertFailures++
				continue
			}
			mono, err1 := strconv.ParseInt(f[1], 10, 64)
			wall, err2 := strconv.ParseInt(f[2], 10, 64)
			if err1 != nil || err2 != nil {
				drops.ConvertFailures++
				continue
			}
			// The tracer's own paired reading of the two clocks beats any
			// value computed outside it.
			bootEpoch = time.Unix(0, wall-mono).UTC()
			sawClockSync = true
			continue
		case recCounter:
			sawAnyRecord = true
			f := strings.SplitN(line, "|", 3)
			if len(f) < 3 {
				drops.ConvertFailures++
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(f[2]))
			if err != nil {
				drops.ConvertFailures++
				continue
			}
			name := strings.TrimSpace(f[1])
			if name == "map_insert_failed" {
				sawMapInsertFailedCounter = true
				if n > mapInsertFailedCount {
					mapInsertFailedCount = n
				}
			} else {
				applyCounter(&drops, name, n)
			}
			continue
		case recExec:
			sawAnyRecord = true
			// Format version 2 inserts the namespace-scoped process and
			// thread numbers between tid and cgroup; version 3 adds the
			// identifier of the PID namespace they are numbered in right
			// after them. A version-1 trace carries none of this, and
			// reading it as though it did would shift every field after
			// tid.
			fieldCount := 8
			switch {
			case scriptVersion >= 3:
				fieldCount = 11
			case scriptVersion == 2:
				fieldCount = 10
			}
			f := strings.SplitN(line, "|", fieldCount)
			if len(f) < fieldCount {
				drops.ConvertFailures++
				continue
			}
			var nspid, nstid int
			var pidns uint64
			cgroupIdx, startIdx, commIdx, pathIdx := 4, 5, 6, 7
			if scriptVersion >= 2 {
				var nsErr error
				if nspid, nsErr = strconv.Atoi(strings.TrimSpace(f[4])); nsErr != nil {
					drops.ConvertFailures++
					continue
				}
				if nstid, nsErr = strconv.Atoi(strings.TrimSpace(f[5])); nsErr != nil {
					drops.ConvertFailures++
					continue
				}
				cgroupIdx, startIdx, commIdx, pathIdx = 6, 7, 8, 9
				if scriptVersion >= 3 {
					if pidns, nsErr = parseNamespaceID(f[6]); nsErr != nil {
						drops.ConvertFailures++
						continue
					}
					cgroupIdx, startIdx, commIdx, pathIdx = 7, 8, 9, 10
				}
			}
			mono, pid, tid, cgroup, startNS, ok := parseCommon(f[1], f[2], f[3], f[cgroupIdx], f[startIdx])
			if !ok {
				drops.ConvertFailures++
				continue
			}
			ev := EventRecord{
				Record: eventRecordKind, Event: "exec", MonotonicNS: mono,
				PID: pid, TID: tid, NSPID: nspid, NSTID: nstid, PIDNamespace: pidns, CgroupID: cgroup,
				Comm: f[commIdx], RawPath: f[pathIdx],
				OK: true, Source: "sched_process_exec",
			}
			finishEvent(&ev, startNS, ticks, bootEpoch, atFDCWD, opts, &drops, &emptyPaths)
			out.Events = append(out.Events, ev)
		case recOpenEnter:
			sawAnyRecord = true
			// Format version 2 inserts the namespace-scoped process and
			// thread numbers between tid and cgroup, the same as an exec
			// record; version 3 adds the identifier of the PID namespace
			// they are numbered in right after them.
			fieldCount := 8
			switch {
			case scriptVersion >= 3:
				fieldCount = 11
			case scriptVersion == 2:
				fieldCount = 10
			}
			f := strings.SplitN(line, "|", fieldCount)
			if len(f) < fieldCount {
				drops.ConvertFailures++
				continue
			}
			var nspid, nstid int
			var pidns uint64
			cgroupIdx, startIdx, dirfdIdx, pathIdx := 4, 5, 6, 7
			if scriptVersion >= 2 {
				var nsErr error
				if nspid, nsErr = strconv.Atoi(strings.TrimSpace(f[4])); nsErr != nil {
					drops.ConvertFailures++
					continue
				}
				if nstid, nsErr = strconv.Atoi(strings.TrimSpace(f[5])); nsErr != nil {
					drops.ConvertFailures++
					continue
				}
				cgroupIdx, startIdx, dirfdIdx, pathIdx = 6, 7, 8, 9
				if scriptVersion >= 3 {
					if pidns, nsErr = parseNamespaceID(f[6]); nsErr != nil {
						drops.ConvertFailures++
						continue
					}
					cgroupIdx, startIdx, dirfdIdx, pathIdx = 7, 8, 9, 10
				}
			}
			mono, pid, tid, cgroup, startNS, ok := parseCommon(f[1], f[2], f[3], f[cgroupIdx], f[startIdx])
			if !ok {
				drops.ConvertFailures++
				continue
			}
			dirfd, derr := strconv.ParseInt(strings.TrimSpace(f[dirfdIdx]), 10, 64)
			if derr != nil {
				drops.ConvertFailures++
				continue
			}
			p := pendingOpen{monotonic: mono, pid: pid, tid: tid, nspid: nspid, nstid: nstid, pidns: pidns, cgroup: cgroup,
				startNS: startNS, dirfd: dirfd, rawPath: f[pathIdx], source: "sys_enter_openat"}
			// An outcome that arrived first is held for exactly this: the
			// two halves cross per-processor buffers and a thread moved
			// between processors can have them delivered out of order. It
			// is only joined to this entry here when it names this exact
			// entry time — an outcome old enough to carry none is left
			// held rather than matched by a guess at arrival time: see
			// reconcileOldFormat, run once the whole trace has been read.
			// Any held outcome that does not name this entry is left
			// exactly where it is; it belongs to some other entry, still
			// to arrive or already lost, and nothing decides that here.
			held := exitsByTid[tid]
			matched := -1
			for i, x := range held {
				if x.entryAt != 0 && x.entryAt == mono && pairsWith(p, x) {
					matched = i
					break
				}
			}
			if matched >= 0 {
				x := held[matched]
				held = append(held[:matched], held[matched+1:]...)
				if len(held) == 0 {
					delete(exitsByTid, tid)
				} else {
					exitsByTid[tid] = held
				}
				out.Events = append(out.Events, buildOpenEvent(p, x.ret, ticks, bootEpoch, opts, &drops, &emptyPaths))
				continue
			}
			pending[pendingKey{tid: tid, mono: mono}] = p
		case recOpenExit:
			sawAnyRecord = true
			// Six fields: the outcome carries the entry's own time as a
			// sixth, and an older trace without it has five. Format
			// version 2 inserts the namespace-scoped process and thread
			// numbers between tid and the result, and version 3 adds the
			// identifier of the PID namespace they are numbered in right
			// after them, so the counts move up accordingly; they are read
			// here to keep the field count right, but discarded, since the
			// entry the outcome pairs with is where an open event's
			// namespace numbers come from.
			maxFields, minFields, retIdx := 6, 5, 4
			switch {
			case scriptVersion >= 3:
				maxFields, minFields, retIdx = 9, 8, 7
			case scriptVersion == 2:
				maxFields, minFields, retIdx = 8, 7, 6
			}
			f := strings.SplitN(line, "|", maxFields)
			if len(f) < minFields {
				drops.ConvertFailures++
				continue
			}
			mono, merr := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
			pid, perr := strconv.Atoi(strings.TrimSpace(f[2]))
			tid, terr := strconv.Atoi(strings.TrimSpace(f[3]))
			var nsperr, nsterr, nsierr error
			if scriptVersion >= 2 {
				_, nsperr = strconv.Atoi(strings.TrimSpace(f[4]))
				_, nsterr = strconv.Atoi(strings.TrimSpace(f[5]))
				if scriptVersion >= 3 {
					_, nsierr = parseNamespaceID(f[6])
				}
			}
			ret, rerr := strconv.ParseInt(strings.TrimSpace(f[retIdx]), 10, 64)
			if merr != nil || perr != nil || terr != nil || nsperr != nil || nsterr != nil || nsierr != nil || rerr != nil {
				drops.ConvertFailures++
				continue
			}
			x := pendingExit{monotonic: mono, pid: pid, ret: ret}
			if len(f) > retIdx+1 {
				// The column is present, so a value that fails to parse is
				// a malformed record, not an older trace that never had
				// the column at all: it is not read as "no entry time",
				// which would let this record settle into a pairing by
				// guesswork rather than being refused outright.
				entryAt, eerr := strconv.ParseInt(strings.TrimSpace(f[retIdx+1]), 10, 64)
				if eerr != nil {
					drops.ConvertFailures++
					continue
				}
				x.entryAt = entryAt
			}
			// The entry this outcome names, if it carries one, is looked
			// up exactly — by thread and entry time — regardless of what
			// else is pending for the same thread or what order the two
			// arrived in. Lacking an entry time, nothing is guessed at
			// here: see reconcileOldFormat, run once the whole trace has
			// been read, for how such an outcome is eventually resolved.
			if x.entryAt != 0 {
				if cand, ok := pending[pendingKey{tid: tid, mono: x.entryAt}]; ok && pairsWith(cand, x) {
					delete(pending, pendingKey{tid: tid, mono: x.entryAt})
					out.Events = append(out.Events, buildOpenEvent(cand, x.ret, ticks, bootEpoch, opts, &drops, &emptyPaths))
					continue
				}
			}
			// Nothing claims this outcome yet, or it names no entry at
			// all. It is held rather than discarded, in case its entry is
			// still on its way; if none ever comes, it is judged at end
			// of trace like every other unmatched half.
			exitsByTid[tid] = append(exitsByTid[tid], x)
		default:
			drops.ConvertFailures++
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("read trace: %w", err)
	}

	// The trace's own attach time and the caller's are reconciled once the
	// whole trace has been read — a wall-clock-prefixed "Attached N
	// probes" line can sit anywhere in the file relative to the record it
	// explains, and in the ordinary pipeline stderr is appended after all
	// of stdout, so it is read last. They are required to agree where
	// both are given: a caller acting on one while the trace itself
	// reports the other would be trusting an instant that was never the
	// true one. Neither one judges any half of a pairing — receiving the
	// report is not the same moment as every probe actually attaching —
	// so it is carried into the header for reference only; the boundary
	// below is judged against the observation window instead.
	if !opts.AttachedAt.IsZero() && !attachedAtWall.IsZero() && !opts.AttachedAt.Equal(attachedAtWall) {
		return out, fmt.Errorf(
			"attach time disagreement: -attached-at reports %s and the trace's own stderr reports %s. One of them is not what this run used",
			opts.AttachedAt.Format(time.RFC3339Nano), attachedAtWall.Format(time.RFC3339Nano))
	}
	if attachedAtWall.IsZero() {
		attachedAtWall = opts.AttachedAt
	}

	if bootEpoch.IsZero() {
		return out, fmt.Errorf("no clock relation: the trace carries no paired clock reading and none was supplied, so a monotonic event stamp cannot be related to any other record")
	}

	// The observation window is what the collection guarantees complete,
	// not the whole stretch the tracer happened to run: the wrapper
	// starts it before the window opens and stops it well after it
	// closes, so a call already running before the window or still
	// running after it is outside what this run measures at all. Both
	// ends are required together — with either missing, no boundary can
	// be measured, and every unmatched half below is counted as a
	// mid-window loss rather than credited to a boundary this run never
	// established.
	haveWindow := !opts.WindowStart.IsZero() && !opts.WindowEnd.IsZero()
	if haveWindow && opts.WindowStart.After(opts.WindowEnd) {
		return out, fmt.Errorf("window disagreement: -window-start %s is after -window-end %s",
			opts.WindowStart.Format(time.RFC3339Nano), opts.WindowEnd.Format(time.RFC3339Nano))
	}
	var windowStartMono, windowEndMono int64
	if haveWindow {
		windowStartMono = opts.WindowStart.Sub(bootEpoch).Nanoseconds()
		windowEndMono = opts.WindowEnd.Sub(bootEpoch).Nanoseconds()
	}
	insideWindow := func(mono int64) bool {
		return haveWindow && mono >= windowStartMono && mono <= windowEndMono
	}
	outsideWindow := func(mono int64) bool {
		return haveWindow && (mono < windowStartMono || mono > windowEndMono)
	}

	// Every record still held for a thread that never named an entry time
	// on its outcomes is resolved now, in the order the records actually
	// happened in rather than the order they arrived in or a map's own
	// iteration order: see reconcileOldFormat.
	pendingByTid := map[int][]pendingOpen{}
	for k, p := range pending {
		pendingByTid[k.tid] = append(pendingByTid[k.tid], p)
	}
	oldFormatByTid := map[int][]pendingExit{}
	namedOrphansByTid := map[int][]pendingExit{}
	for tid, xs := range exitsByTid {
		for _, x := range xs {
			if x.entryAt == 0 {
				oldFormatByTid[tid] = append(oldFormatByTid[tid], x)
			} else {
				// This outcome already named the one entry it belongs to,
				// and that entry never turned up: guessing it onto some
				// other entry of the same thread would override the one
				// identification this record actually carries.
				namedOrphansByTid[tid] = append(namedOrphansByTid[tid], x)
			}
		}
	}
	pending = map[pendingKey]pendingOpen{}
	exitsByTid = map[int][]pendingExit{}
	tids := map[int]bool{}
	for tid := range pendingByTid {
		tids[tid] = true
	}
	for tid := range oldFormatByTid {
		tids[tid] = true
	}
	for tid := range tids {
		paired, unmatchedEntries, unmatchedExits := reconcileOldFormat(pendingByTid[tid], oldFormatByTid[tid])
		for _, pc := range paired {
			out.Events = append(out.Events, buildOpenEvent(pc.entry, pc.exit.ret, ticks, bootEpoch, opts, &drops, &emptyPaths))
		}
		for _, e := range unmatchedEntries {
			pending[pendingKey{tid: tid, mono: e.monotonic}] = e
		}
		exitsByTid[tid] = append(exitsByTid[tid], unmatchedExits...)
	}
	for tid, xs := range namedOrphansByTid {
		exitsByTid[tid] = append(exitsByTid[tid], xs...)
	}

	// Every half still outstanding now is a half whose partner never
	// arrived — an entry with no outcome, or an outcome with no entry.
	//
	// An entry's own timestamp is exactly when it happened, so it is
	// judged against the window directly. An outcome carries no such
	// certainty about its missing entry: an entry can only ever be
	// earlier than or equal to its own outcome, so an outcome before the
	// window proves its entry was too, but an outcome after the window
	// proves nothing — the entry could still have landed inside the
	// window and simply taken a long time to return. Where the outcome
	// names its entry's own time (entryAt), that settles it directly;
	// otherwise the outcome is credited to the boundary only when its own
	// time is before the window, and counted as a mid-window loss
	// whenever that cannot be ruled out.
	for _, p := range pending {
		if outsideWindow(p.monotonic) {
			drops.EnterExitUnmatchedBoundary++
		} else {
			drops.EnterExitUnmatched++
		}
		if p.pid == 0 || p.tid == 0 {
			drops.UnmatchedIdentityUnavailable++
		}
	}
	for tid, xs := range exitsByTid {
		for _, x := range xs {
			boundary := false
			switch {
			case x.entryAt != 0:
				// The outcome names its own entry's time: that is where
				// the call began, and it alone decides whether the loss
				// sits inside the window.
				boundary = outsideWindow(x.entryAt)
			case insideWindow(x.monotonic):
				boundary = false
			case x.monotonic < windowStartMono:
				// The entry, if it ever existed, cannot be later than
				// this outcome, so it was before the window too.
				boundary = haveWindow
			default:
				// The outcome is after the window and carries no entry
				// time to check: a mid-window entry cannot be ruled out.
				boundary = false
			}
			if boundary {
				drops.EnterExitUnmatchedBoundary++
			} else {
				drops.EnterExitUnmatched++
			}
			if x.pid == 0 || tid == 0 {
				drops.UnmatchedIdentityUnavailable++
			}
		}
	}

	out.Header.BootEpoch = bootEpoch
	out.Header.AttachedAt = attachedAtWall
	out.Header.ClockSource = opts.ClockSourceID
	out.Header.ClockErrorNS = opts.ClockErrorNS
	if sawClockSync {
		out.Header.ClockNote = "paired monotonic and wall-clock reading taken by the tracer itself at start"
	} else if out.Header.ClockNote == "" {
		out.Header.ClockNote = "monotonic zero point supplied externally; its error is how far apart the two readings it was computed from were"
	}
	out.Header.PathBufferLen = opts.PathBufferLen
	out.Header.Started = opts.Started
	out.Header.Attached = opts.Attached

	if drops.EventsAfterFilter == 0 {
		drops.EventsAfterFilter = len(out.Events)
	}
	if drops.PathReadFailures == 0 {
		drops.PathReadFailures = emptyPaths
	}
	if mapInsertFailedCount >= 0 {
		drops.MapOverflow += mapInsertFailedCount
	}
	// A failed insertion into the per-thread map has no return value to
	// check either, but a trace that carries the tracer's own count of it
	// — the entry probe's own has-the-key check, folded into MapOverflow
	// above — has established the count, and reporting it as unmeasured
	// on top of a real zero would claim a gap that trace does not have.
	// Only a trace with no such count at all is left unable to say.
	if !sawMapInsertFailedCounter {
		drops.Unmeasured = append(drops.Unmeasured,
			"map_overflow: a failed insertion into the per-thread map is not reported by this collection method; its consequence appears as an unmatched entry or outcome")
	}
	if !sawAnyRecord {
		drops.Unmeasured = append(drops.Unmeasured,
			"the trace carries no records at all, so nothing about what the collection saw or missed can be established")
	}

	// The stop is what the wrapper observed, not the last event's time: a
	// collection that ran to the end of the window and saw nothing looks
	// exactly like one that died early, from the inside.
	stoppedAt := opts.StoppedAt
	if !stoppedAt.IsZero() {
		drops.StoppedAt = stoppedAt.UTC()
		drops.StopReason = opts.StopNote
		if !opts.WindowEnd.IsZero() && stoppedAt.Before(opts.WindowEnd) {
			drops.StoppedEarly = true
			drops.GapSeconds = opts.WindowEnd.Sub(stoppedAt).Seconds()
		}
	} else if !opts.WindowEnd.IsZero() {
		drops.Unmeasured = append(drops.Unmeasured,
			"the collection's actual stop time was not recorded, so whether it ran to the end of the window is unknown")
	}

	sort.SliceStable(out.Events, func(i, j int) bool { return out.Events[i].MonotonicNS < out.Events[j].MonotonicNS })
	out.Trailer = EventsTrailer{Record: eventsTrailerKind, EndedAt: time.Now().UTC(), Drops: drops}
	return out, nil
}

// applyCounter folds one of the tracer's counting maps into the loss
// accounting. map_insert_failed is read separately from this, before it
// ever reaches here, so its own count can be kept apart from a duplicate
// of the same line rather than summed with one; map_overflow is not
// printed by any current script but is read the ordinary way, in case a
// future collection method counts the same loss under that name.
func applyCounter(d *EventDropCounts, name string, n int) {
	switch name {
	case "map_overflow":
		d.MapOverflow += n
	case "path_read_failed":
		d.PathReadFailures += n
	case "events_before_filter":
		d.EventsBeforeFilter += n
	case "events_after_filter":
		d.EventsAfterFilter += n
	case "events_exec":
		d.EventsBeforeFilter += n
		d.EventsAfterFilter += n
	case "lost_events":
		d.LostEvents += n
	}
}

// buildOpenEvent turns one paired entry and outcome into an event.
func buildOpenEvent(p pendingOpen, ret int64, ticks int64, bootEpoch time.Time, opts ConvertOptions, drops *EventDropCounts, emptyPaths *int) EventRecord {
	source := p.source
	if source == "" {
		source = "sys_enter_openat"
	}
	ev := EventRecord{
		Record: eventRecordKind, Event: "open", MonotonicNS: p.monotonic,
		PID: p.pid, TID: p.tid, NSPID: p.nspid, NSTID: p.nstid, PIDNamespace: p.pidns, CgroupID: p.cgroup, RawPath: p.rawPath,
		OK: ret >= 0, Ret: int(ret), Source: source,
	}
	finishEvent(&ev, p.startNS, ticks, bootEpoch, p.dirfd, opts, drops, emptyPaths)
	return ev
}

// pairsWith decides whether an entry and an outcome are the two halves of
// one call.
//
// Where the tracer sent the entry's own time back with the outcome, that
// is the test and nothing else is needed. Where it did not — an older
// trace — the process has to be the same one and the outcome cannot
// precede the entry; neither is proof, so such a pairing is the weaker
// case and is only ever used when the stronger one is unavailable.
//
// An entry or an outcome with no identity is never paired, no matter how
// well the times line up. Every call the tracer could not read a number
// for collides on the same pending-map key, so a time that happens to
// agree is not evidence that the two belong together — it is what such a
// collision looks like from the outside.
func pairsWith(p pendingOpen, x pendingExit) bool {
	if p.pid == 0 || p.tid == 0 || x.pid == 0 {
		return false
	}
	if p.pid != x.pid {
		return false
	}
	if x.entryAt != 0 {
		return x.entryAt == p.monotonic
	}
	return x.monotonic >= p.monotonic
}

// pairedCall is one entry successfully joined to its outcome by
// reconcileOldFormat.
type pairedCall struct {
	entry pendingOpen
	exit  pendingExit
}

// reconcileOldFormat resolves, for the entries and entryAt-less outcomes
// still outstanding for one thread, which entry each outcome actually
// answers for — by the times they happened at, not by the order the
// records arrived in or by however a map happens to iterate them.
//
// A thread runs one call at a time, so sorted by time there is at most
// one entry "open" at once: an outcome closes whichever entry is
// currently open, and an entry arriving while one is already open means
// the open one's own outcome never showed up before the next call
// started — a genuine loss, not something a guess should paper over. An
// outcome that arrives with no entry open is equally left unmatched
// rather than attributed to some other entry it does not provably
// belong to (pairsWith still checks identity and, where it exists, an
// entry time — neither of which the sort by itself establishes).
func reconcileOldFormat(entries []pendingOpen, exits []pendingExit) (paired []pairedCall, unmatchedEntries []pendingOpen, unmatchedExits []pendingExit) {
	type item struct {
		mono   int64
		isExit bool
		entry  pendingOpen
		exit   pendingExit
	}
	items := make([]item, 0, len(entries)+len(exits))
	for _, e := range entries {
		items = append(items, item{mono: e.monotonic, entry: e})
	}
	for _, x := range exits {
		items = append(items, item{mono: x.monotonic, isExit: true, exit: x})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].mono < items[j].mono })

	var open *pendingOpen
	for _, it := range items {
		if !it.isExit {
			if open != nil {
				unmatchedEntries = append(unmatchedEntries, *open)
			}
			e := it.entry
			open = &e
			continue
		}
		if open != nil && pairsWith(*open, it.exit) {
			paired = append(paired, pairedCall{entry: *open, exit: it.exit})
			open = nil
			continue
		}
		unmatchedExits = append(unmatchedExits, it.exit)
	}
	if open != nil {
		unmatchedEntries = append(unmatchedEntries, *open)
	}
	return paired, unmatchedEntries, unmatchedExits
}

func parseCommon(monoS, pidS, tidS, cgroupS, startS string) (mono int64, pid, tid int, cgroup uint64, startNS int64, ok bool) {
	var err error
	if mono, err = strconv.ParseInt(strings.TrimSpace(monoS), 10, 64); err != nil {
		return 0, 0, 0, 0, 0, false
	}
	if pid, err = strconv.Atoi(strings.TrimSpace(pidS)); err != nil {
		return 0, 0, 0, 0, 0, false
	}
	if tid, err = strconv.Atoi(strings.TrimSpace(tidS)); err != nil {
		return 0, 0, 0, 0, 0, false
	}
	if cgroup, err = strconv.ParseUint(strings.TrimSpace(cgroupS), 10, 64); err != nil {
		return 0, 0, 0, 0, 0, false
	}
	// A kernel that does not expose the start time reports zero, which is
	// recorded as unknown rather than as a start at the epoch.
	startNS, _ = strconv.ParseInt(strings.TrimSpace(startS), 10, 64)
	return mono, pid, tid, cgroup, startNS, true
}

// finishEvent fills in everything derived: the wall-clock time, the
// process generation identifier in the form a workload's own log uses, the
// resolved path, and the container the event belongs to.
func finishEvent(ev *EventRecord, startNS, ticks int64, bootEpoch time.Time, dirfd int64, opts ConvertOptions, drops *EventDropCounts, emptyPaths *int) {
	ev.Timestamp = bootEpoch.Add(time.Duration(ev.MonotonicNS)).UTC()
	if startNS > 0 {
		ev.Starttime = strconv.FormatInt(startNS/(1_000_000_000/ticks), 10)
	}
	// The tracer's buffer holds the terminator as well as the text, so a
	// string one short of the buffer filled it and where it really ended
	// is unknown. It is marked rather than compared: a shortened path that
	// happens to match a real one is a false positive.
	if opts.PathBufferLen > 0 && len(ev.RawPath) >= opts.PathBufferLen-1 {
		ev.Truncated = true
		drops.PathTruncations++
	}
	if ev.RawPath == "" {
		*emptyPaths++
	}
	// A tracer that cannot read a process's numbers reports zero for them.
	// The event is still a real open of a real file in a real control
	// group; what it cannot do is say which process made it, so it is
	// counted here and left for the matching side to treat as unplaceable.
	if ev.PID == 0 || ev.TID == 0 {
		drops.IdentityUnavailable++
	}

	// The three cases are separated before anything is resolved, because
	// only the first two can be resolved at all and joining a working
	// directory onto the third names a real file that was never opened.
	switch {
	case ev.Truncated:
		ev.Resolved = false
	case strings.HasPrefix(ev.RawPath, "/"):
		ev.Path, ev.Resolved = path.Clean(ev.RawPath), true
	case ev.RawPath == "":
		ev.Resolved = false
	case dirfd == atFDCWD:
		if dir := opts.workingDirectory(ev.PID, ev.Starttime, ev.Timestamp); dir != "" {
			ev.Path, ev.Resolved = path.Clean(path.Join(dir, ev.RawPath)), true
		} else {
			ev.Resolved = false
		}
	default:
		// Relative to a directory descriptor the tracer does not hold.
		// Nothing here knows what that descriptor pointed at, so the file
		// has no name.
		ev.Resolved = false
	}

	if container, depth, ok := opts.Lookup.lookup(ev.CgroupID, ev.Timestamp); ok {
		ev.ContainerID, ev.CgroupDepth, ev.Attribution = container, depth, attributionContainer
	} else {
		ev.Attribution = attributionUnattributed
	}
}

// workingDirectory answers what a process's working directory was at one
// instant, from the entries the case runner recorded. An entry for a
// different process generation, or for another stretch of time, is not an
// answer about this one.
func (o ConvertOptions) workingDirectory(pid int, starttime string, at time.Time) string {
	if starttime == "" {
		// The event does not say which process generation produced it, so
		// nothing can say the recorded directory was that generation's.
		// Resolving anyway would name a real file that was never opened.
		return ""
	}
	for _, e := range o.CWD {
		if e.PID != pid {
			continue
		}
		if e.Starttime != starttime {
			continue
		}
		if !e.From.IsZero() && at.Before(e.From) {
			continue
		}
		if !e.Until.IsZero() && at.After(e.Until) {
			continue
		}
		return e.Dir
	}
	return ""
}

// parseNamespaceID reads a PID namespace identifier. The kernel keeps it
// as an unsigned 32-bit number; a tracer that printed it through a signed
// conversion wrote large identifiers as negative numbers, and those are
// read back as the unsigned value they stand for rather than refused.
func parseNamespaceID(field string) (uint64, error) {
	field = strings.TrimSpace(field)
	if v, err := strconv.ParseUint(field, 10, 64); err == nil {
		return v, nil
	}
	v, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return 0, err
	}
	if v < 0 && v >= -(1<<31) {
		return uint64(v + (1 << 32)), nil
	}
	return 0, fmt.Errorf("namespace identifier %q is out of range", field)
}
