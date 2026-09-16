package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Record discriminators for the event log. Every line carries one, and it
// is what keeps an event log from being read as a ground-truth log.
//
// The two formats are deliberately close — an event line and a usage-log
// line describe the same kind of fact — and that similarity is exactly the
// hazard: ground truth built from the observation it is supposed to judge
// makes every capture rate and every false-positive count meaningless.
// Each reader therefore refuses the other's format outright rather than
// making a best effort at it.
const (
	eventRecordKind   = "event"
	eventsHeaderKind  = "events_header"
	eventsTrailerKind = "events_trailer"
)

// Event collection states for one observation window.
const (
	eventStateObserved     = "observed"
	eventStateDegraded     = "degraded"
	eventStateFailed       = "failed"
	eventStateNotAttempted = "not_attempted"
)

// EventHeader is the first line of an event log: what produced it, under
// which configuration, and how its timestamps relate to a wall clock.
type EventHeader struct {
	Record   string `json:"record"`
	ConfigID string `json:"config_id"`
	// Sync is the ordering condition the events were collected under,
	// "startup" or "attach_running".
	Sync string `json:"sync,omitempty"`
	// Method is "bpftrace" or "core", Version the script or build
	// identifier, Filter the kernel-side filter condition (empty means
	// none was applied), and BufferPages the buffer size.
	Method      string    `json:"method"`
	Version     string    `json:"version,omitempty"`
	Filter      string    `json:"filter,omitempty"`
	BufferPages int       `json:"buffer_pages,omitempty"`
	Tracepoints []string  `json:"tracepoints,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	// BootEpoch is the wall-clock instant the kernel's monotonic clock
	// reads zero at, which is what converts a monotonic event stamp into a
	// comparable time. ClockNote records how it was obtained and with what
	// error, since a conversion whose error is unknown cannot be used to
	// pair events with occurrences at all.
	BootEpoch time.Time `json:"boot_epoch,omitempty"`
	ClockNote string    `json:"clock_note,omitempty"`
	// ClockSource names the clock the conversion rests on and ClockErrorNS
	// how far apart the two readings it was computed from were. The
	// pairing tolerance is checked against that error: a tolerance
	// narrower than the conversion's own error would call a real pair a
	// miss.
	ClockSource   string `json:"clock_source,omitempty"`
	ClockErrorNS  int64  `json:"clock_error_ns,omitempty"`
	PathBufferLen int    `json:"path_buffer_len,omitempty"`
	// Started and Attached say whether the collection came up and whether
	// its attachment points were confirmed live. Starting is not
	// attaching, and a log that cannot say the second is not evidence that
	// nothing happened.
	Started  bool `json:"started"`
	Attached bool `json:"attached"`
	// ContainerID is the container the collection was aimed at, when it
	// was aimed at one.
	ContainerID string `json:"container_id,omitempty"`
}

// EventRecord is one observed execution or file open.
//
// RawPath and Path are separate on purpose. The kernel hands the tracer
// the string the program passed, which can be relative, relative to a
// directory descriptor, or reached through a symbolic link; Path is the
// absolute path that was resolved from it, and is empty when nothing could
// be resolved. An unresolved path is never guessed at and never counted as
// evidence that the file was not used.
type EventRecord struct {
	Record      string    `json:"record"`
	Timestamp   time.Time `json:"ts"`
	MonotonicNS int64     `json:"monotonic_ns,omitempty"`
	Event       string    `json:"event"` // "exec" | "open"
	PID         int       `json:"pid"`
	TID         int       `json:"tid"`
	// NSPID and NSTID are the same process and thread as PID and TID name,
	// but numbered in the task's own PID namespace rather than the
	// namespace the collector's host-wide identifiers come from. They are
	// what the container_namespace_pid_and_thread matching rule uses when
	// no process-number correspondence table exists: a workload's own log
	// recorded inside a container reports its numbers in that same
	// namespace, so these are directly comparable to it, unlike PID/TID.
	// A collection in the format that predates them reports both as zero.
	NSPID int `json:"ns_pid"`
	NSTID int `json:"ns_tid"`
	// PIDNamespace is the identifier of the PID namespace NSPID and NSTID
	// are numbered in. A number by itself is not an identity: two tasks
	// in two different PID namespaces can carry the same NSPID, the same
	// NSTID, and even the same Starttime, so a comparison against an
	// independent log's own PIDNamespace is what NSPID/NSTID need before
	// they mean anything (see sameHostProcess in occurrence.go). A
	// collection in the format that predates it reports it as zero.
	PIDNamespace uint64 `json:"pid_ns,omitempty"`
	// Starttime is the process generation's start time in the same clock
	// ticks /proc reports, which is the one process identifier that reads
	// the same inside a container and outside it.
	Starttime string `json:"starttime,omitempty"`
	RawPath   string `json:"raw_path"`
	Path      string `json:"path,omitempty"`
	Resolved  bool   `json:"path_resolved"`
	Truncated bool   `json:"path_truncated,omitempty"`
	// OK is whether the operation succeeded. A failed open is not use, the
	// same way a failed execution is not.
	OK  bool `json:"ok"`
	Ret int  `json:"ret,omitempty"`

	CgroupID    uint64 `json:"cgroup_id,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	// CgroupDepth is how many levels above the event's own control group
	// the attributed container's group sits: a workload that creates
	// groups of its own produces events below the container's, and the
	// distance is recorded rather than flattened away.
	CgroupDepth int `json:"cgroup_depth,omitempty"`
	// Attribution is "container" (attributed to a known container) or
	// "unattributed" (no entry for this control group). There is no third
	// value for "the host": a control group the table does not know about
	// is unattributed, and calling it the host's would be a claim the
	// table cannot support.
	Attribution string `json:"attribution,omitempty"`
	Comm        string `json:"comm,omitempty"`
	Source      string `json:"source,omitempty"`
}

// EventDropCounts is the per-implementation accounting of what the
// collection missed. Buffer-overflow notifications and the events those
// notifications stand for are counted separately: one notification can
// represent many lost events, so the notification count is not a count of
// what was lost.
type EventDropCounts struct {
	LostEvents        int `json:"lost_events"`
	LostNotifications int `json:"lost_notifications"`
	// EnterExitUnmatched counts an entry with no outcome, or an outcome
	// with no entry, timestamped inside the collection's own observation
	// window. The converter discards such a half rather than guessing at
	// its missing partner, so the open it belongs to never becomes an
	// event at all — not an event with a degraded attribute, but a hole
	// in what the window observed. EnterExitUnmatchedBoundary is the same
	// shape of half timestamped outside that window instead — before it
	// opened or after it closed, a stretch the wrapper deliberately runs
	// the collection through without asking it to answer for — so it is
	// a boundary of what the run measures, not a loss inside it. Only the
	// first of the two says the window itself missed something; without
	// both ends of the window on record, nothing can be credited to the
	// boundary and it is counted as the first kind instead.
	EnterExitUnmatched         int `json:"enter_exit_unmatched"`
	EnterExitUnmatchedBoundary int `json:"enter_exit_unmatched_boundary"`
	MapOverflow                int `json:"map_overflow"`
	PathReadFailures           int `json:"path_read_failures"`
	PathTruncations            int `json:"path_truncations"`
	ConvertFailures            int `json:"convert_failures"`
	// IdentityUnavailable counts events the collection could not attach a
	// process or thread number to. The path and the control group are
	// there; what is missing is any way to say which process did it, so
	// such an event confirms nothing about an individual occurrence.
	IdentityUnavailable int `json:"identity_unavailable"`
	// UnmatchedIdentityUnavailable is the part of the unmatched halves
	// that had no readable identity, counted inside that total.
	UnmatchedIdentityUnavailable int `json:"unmatched_identity_unavailable"`

	// PartialEvents is how many of the counts above (PathReadFailures,
	// PathTruncations, EnterExitUnmatchedBoundary, IdentityUnavailable)
	// describe an event the collection did capture but could not fully
	// describe. It is filled in once the log has been read in full, and is
	// reported alongside the window's own EventState precisely because it
	// does not change that state: see windowIncomplete and
	// partialEventCount below.
	PartialEvents int `json:"partial_events"`

	// EventsBeforeFilter and EventsAfterFilter bracket what the
	// kernel-side filter removed, so a run with a filter can be compared
	// against one without.
	EventsBeforeFilter int `json:"events_before_filter"`
	EventsAfterFilter  int `json:"events_after_filter"`

	// StoppedEarly records a collection that did not last the whole
	// window, with the gap it left. A window with a hole in it is degraded
	// rather than complete, and the hole's extent is what says how much.
	StoppedEarly bool      `json:"stopped_early,omitempty"`
	StoppedAt    time.Time `json:"stopped_at,omitempty"`
	GapSeconds   float64   `json:"gap_seconds,omitempty"`
	StopReason   string    `json:"stop_reason,omitempty"`

	// Unmeasured names the kinds of loss the collection method cannot
	// count at all. A window carrying any of them has not established a
	// complete observation, whatever the counted kinds say.
	Unmeasured []string `json:"unmeasured,omitempty"`
}

// windowIncomplete reports whether some part of the window itself went
// unobserved: events lost to buffer overflow, notifications of such a
// loss, an early stop, a log line that could not be converted into an
// event, a loss kind this collection method cannot count at all, a
// map-overflow, or an entry/exit pair left unmatched for a reason inside
// the window. Map-overflow belongs here rather than in partialEventCount
// because it drops the open or execution the failed insertion would have
// produced, and an in-window enter_exit_unmatched belongs here for the
// same reason: the converter discards both halves of such a pair, so the
// open they describe never becomes an event at all. Both are a hole in
// what the window observed, not an attribute missing from an event that
// was captured — unlike EnterExitUnmatchedBoundary, which the converter
// counts separately for exactly that reason (see its own doc comment).
func (d EventDropCounts) windowIncomplete() bool {
	return d.LostEvents > 0 || d.LostNotifications > 0 || d.StoppedEarly ||
		d.ConvertFailures > 0 || len(d.Unmeasured) > 0 || d.MapOverflow > 0 ||
		d.EnterExitUnmatched > 0
}

// partialEventCount sums the counts that describe an event-level
// degradation rather than a hole in the window: a path that could not be
// read or had to be truncated, an entry/exit pair left unmatched by the
// observation window's own edges rather than by a loss inside it, and an
// event with no process/thread identity. Every event these counts
// describe was still captured — only some of its attributes could not be
// resolved — so none of them changes EventState; they are reported
// alongside it instead.
func (d EventDropCounts) partialEventCount() int {
	return d.PathReadFailures + d.PathTruncations + d.EnterExitUnmatchedBoundary + d.IdentityUnavailable
}

// EventsTrailer is the last line of an event log: when collection ended and
// what it lost.
type EventsTrailer struct {
	Record  string          `json:"record"`
	EndedAt time.Time       `json:"ended_at"`
	Drops   EventDropCounts `json:"drops"`
	// DetachConfirmed records that the probes were removed and nothing was
	// left loaded, checked rather than assumed.
	DetachConfirmed bool   `json:"detach_confirmed,omitempty"`
	DetachNote      string `json:"detach_note,omitempty"`
}

// EventLog is one parsed event log.
type EventLog struct {
	Header      EventHeader
	Events      []EventRecord
	Trailer     EventsTrailer
	ParseErrors []string
}

// readEventLog reads one event log. The first line must be the header: a
// file that does not start with one is not an event log, and reading it as
// one would let a ground-truth log be fed in as an observation.
func readEventLog(path string) (*EventLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read event log: %w", err)
	}
	defer f.Close()

	log := &EventLog{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	lineNo, sawHeader := 0, false
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var probe struct {
			Record string `json:"record"`
		}
		if uerr := json.Unmarshal([]byte(line), &probe); uerr != nil {
			log.ParseErrors = append(log.ParseErrors, fmt.Sprintf("line %d: %v", lineNo, uerr))
			continue
		}
		switch probe.Record {
		case eventsHeaderKind:
			if uerr := json.Unmarshal([]byte(line), &log.Header); uerr != nil {
				return nil, fmt.Errorf("event log %s line %d: %w", path, lineNo, uerr)
			}
			sawHeader = true
		case eventRecordKind:
			if !sawHeader {
				return nil, fmt.Errorf("event log %s: an event appears at line %d before any header, so the collection configuration these events belong to is unknown", path, lineNo)
			}
			var ev EventRecord
			if uerr := json.Unmarshal([]byte(line), &ev); uerr != nil {
				log.ParseErrors = append(log.ParseErrors, fmt.Sprintf("line %d: %v", lineNo, uerr))
				continue
			}
			log.Events = append(log.Events, ev)
		case eventsTrailerKind:
			if uerr := json.Unmarshal([]byte(line), &log.Trailer); uerr != nil {
				log.ParseErrors = append(log.ParseErrors, fmt.Sprintf("line %d: %v", lineNo, uerr))
			}
		case "":
			return nil, fmt.Errorf("event log %s line %d: no record kind. This reader takes event logs only; a ground-truth usage log must be passed as ground truth, not as an observation", path, lineNo)
		default:
			log.ParseErrors = append(log.ParseErrors, fmt.Sprintf("line %d: unknown record kind %q", lineNo, probe.Record))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("event log %s: %w", path, err)
	}
	if !sawHeader {
		return nil, fmt.Errorf("event log %s: no header record", path)
	}
	// A line the converter could not turn into an event is itself a loss,
	// and it is counted where every other loss is counted rather than
	// only appearing in a message.
	log.Trailer.Drops.ConvertFailures += len(log.ParseErrors)
	log.Trailer.Drops.PartialEvents = log.Trailer.Drops.partialEventCount()
	return log, nil
}

// deriveEventState reduces an event log to the window-level collection
// state. The state is a separate dimension from the sampling's own
// observation state: one failing says nothing about the other, and a
// window where the events were lost still has whatever the sampling saw.
func deriveEventState(log *EventLog) (string, []string) {
	if log == nil {
		return eventStateNotAttempted, nil
	}
	var notes []string
	// A collection that did not come up, or whose attachment points were
	// never confirmed live, has not observed anything — and an empty log
	// from it is not evidence that nothing happened. Starting is not
	// attaching, so both are required and neither is assumed from the
	// other.
	if !log.Header.Started {
		return eventStateFailed, []string{"the collection did not start"}
	}
	if !log.Header.Attached {
		return eventStateFailed, []string{
			"the collection started but its attachment points were never confirmed live, so an empty log cannot be told from a collection that saw nothing"}
	}
	d := log.Trailer.Drops
	if len(log.Events) == 0 && d.EventsAfterFilter == 0 && d.EventsBeforeFilter == 0 && !d.windowIncomplete() {
		// A collection that came up, attached, ran to the end of the
		// window and saw nothing is a window in which nothing happened —
		// not a failure. Calling it one would discard a real result, and
		// the three facts that distinguish the two are exactly what the
		// header and the stop record carry.
		if d.StoppedEarly {
			return eventStateDegraded, []string{"the collection stopped before the window ended and recorded no events"}
		}
		return eventStateObserved, []string{"the collection ran with its attachment points confirmed live and recorded no events"}
	}
	if d.StoppedEarly {
		notes = append(notes, fmt.Sprintf("collection stopped at %s, leaving a %.1fs gap in the window%s",
			d.StoppedAt.Format(time.RFC3339), d.GapSeconds, suffixIfSet(d.StopReason)))
	}
	if d.LostEvents > 0 {
		notes = append(notes, fmt.Sprintf("%d event(s) lost to buffer overflow across %d notification(s)", d.LostEvents, d.LostNotifications))
	}
	if d.EnterExitUnmatched > 0 {
		notes = append(notes, fmt.Sprintf("%d syscall entry/exit pair(s) could not be matched", d.EnterExitUnmatched))
	}
	if d.EnterExitUnmatchedBoundary > 0 {
		notes = append(notes, fmt.Sprintf("%d syscall entry/exit pair(s) were left unpaired by the observation window's own start or end", d.EnterExitUnmatchedBoundary))
	}
	if d.MapOverflow > 0 {
		notes = append(notes, fmt.Sprintf("%d intermediate-state map insertion(s) exceeded capacity", d.MapOverflow))
	}
	if d.PathReadFailures > 0 {
		notes = append(notes, fmt.Sprintf("%d path string(s) could not be read in the kernel", d.PathReadFailures))
	}
	if d.PathTruncations > 0 {
		notes = append(notes, fmt.Sprintf("%d path string(s) were truncated by the kernel-side buffer length", d.PathTruncations))
	}
	if d.ConvertFailures > 0 {
		notes = append(notes, fmt.Sprintf("%d line(s) could not be converted into events", d.ConvertFailures))
	}
	if d.IdentityUnavailable > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d event(s) carry no process or thread number, so nothing can say which process produced them (%d unmatched half-calls are a consequence of the same gap)",
			d.IdentityUnavailable, d.UnmatchedIdentityUnavailable))
	}
	for _, u := range d.Unmeasured {
		notes = append(notes, "not measurable by this collection method: "+u)
	}
	if d.windowIncomplete() {
		return eventStateDegraded, notes
	}
	return eventStateObserved, notes
}
