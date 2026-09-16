package main

import "time"

// Record discriminators. Every line of an event log carries one, and it is
// what keeps an event log from being read as ground truth by the tool that
// consumes it. The two formats describe the same kind of fact and look
// alike; ground truth built from the observation it is meant to judge
// makes every capture rate meaningless, so the mistake is made impossible
// rather than merely unlikely.
const (
	eventRecordKind   = "event"
	eventsHeaderKind  = "events_header"
	eventsTrailerKind = "events_trailer"
)

// The types below are the on-disk event log format. They are written here
// and read by the matching tool, which is a separate program, so the shape
// is deliberately duplicated rather than shared: the two are coupled by
// the file format, not by a Go type, and a change to either has to be a
// deliberate change to the format.

// EventHeader is the first line of an event log: what produced it, under
// which configuration, and how its timestamps relate to a wall clock.
type EventHeader struct {
	Record   string `json:"record"`
	ConfigID string `json:"config_id"`
	Sync     string `json:"sync,omitempty"`
	Method   string `json:"method"`
	// Version is the tracing script's own format version — the second
	// column of its V line — and Variant its filter variant, the fifth.
	// The two name different things: a run under a named variant still
	// has its own format version, and checking one against the other
	// left it unable to state either.
	Version     string    `json:"version,omitempty"`
	Variant     string    `json:"variant,omitempty"`
	Filter      string    `json:"filter,omitempty"`
	BufferPages int       `json:"buffer_pages,omitempty"`
	Tracepoints []string  `json:"tracepoints,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	// BootEpoch is the wall-clock instant the monotonic clock reads zero
	// at, which is what turns a monotonic event stamp into a comparable
	// time. ClockNote says how it was obtained and with what error: a
	// conversion whose error is unknown cannot pair events with
	// occurrences at all.
	BootEpoch time.Time `json:"boot_epoch,omitempty"`
	ClockNote string    `json:"clock_note,omitempty"`
	// ClockSource names the clock the conversion was computed from, and
	// ClockErrorNS how far apart the two readings it rests on were. Both
	// travel with the log: a tolerance for pairing an event with an
	// occurrence means nothing beside a conversion whose own error is
	// unknown, and two clocks that differ by however long the machine was
	// suspended are not interchangeable.
	ClockSource  string `json:"clock_source,omitempty"`
	ClockErrorNS int64  `json:"clock_error_ns,omitempty"`
	// PathBufferLen is the string length the tracer was configured with,
	// which is what decides whether a path came back whole.
	PathBufferLen int `json:"path_buffer_len,omitempty"`
	// Started and Attached say whether the tracer came up and whether its
	// attachment points were confirmed live by causing a known event and
	// seeing it come out. Starting is not attaching, and a log that cannot
	// say the second is not evidence that nothing happened.
	Started  bool `json:"started"`
	Attached bool `json:"attached"`
	// AttachedAt is when every probe finished attaching, where the trace
	// or the caller named an instant for it (bpftrace's own "Attached N
	// probes" report, read from a wall-clock-prefixed stderr line, or
	// -attached-at). It is carried for reference only: the collection's
	// own completeness is judged against the observation window, not
	// against this, since receiving the report is not the same moment as
	// whatever it reports on having happened.
	AttachedAt  time.Time `json:"attached_at,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
}

// EventRecord is one observed execution or file open.
//
// RawPath and Path are separate on purpose. The kernel hands the tracer
// the string the program passed, which can be relative, relative to a
// directory descriptor, or reached through a symbolic link; Path is what
// was resolved from it, and is empty when nothing could be. An unresolved
// path is never guessed at and never counted as evidence of non-use.
type EventRecord struct {
	Record      string    `json:"record"`
	Timestamp   time.Time `json:"ts"`
	MonotonicNS int64     `json:"monotonic_ns,omitempty"`
	Event       string    `json:"event"` // "exec" | "open"
	PID         int       `json:"pid"`
	TID         int       `json:"tid"`
	// NSPID and NSTID are the same process and thread as PID and TID name,
	// but numbered in the task's own PID namespace rather than the
	// namespace the tracer's pid(init)/tid(init) builtins read from. A
	// workload's own log recorded inside a container reports its numbers
	// in that same namespace, so these are what let such a log be
	// compared against an event with no process-number correspondence
	// table standing between them. A trace in the script format that
	// predates them reports both as zero.
	NSPID int `json:"ns_pid"`
	NSTID int `json:"ns_tid"`
	// PIDNamespace is the identifier of the PID namespace NSPID and NSTID
	// are numbered in. A number by itself is not an identity: two tasks
	// in two different PID namespaces can carry the same NSPID, the same
	// NSTID, and even the same Starttime, so NSPID/NSTID only mean
	// something once compared alongside the namespace they were read in
	// — this is what a comparison needs to require agreement on. A trace
	// in the script format that predates it (format version below 3)
	// reports it as zero.
	PIDNamespace uint64 `json:"pid_ns,omitempty"`
	// Starttime is the process generation's start time in the clock ticks
	// /proc reports, which is the one process identifier that reads the
	// same inside a container and outside it.
	Starttime string `json:"starttime,omitempty"`
	RawPath   string `json:"raw_path"`
	Path      string `json:"path,omitempty"`
	Resolved  bool   `json:"path_resolved"`
	Truncated bool   `json:"path_truncated,omitempty"`
	OK        bool   `json:"ok"`
	Ret       int    `json:"ret,omitempty"`

	CgroupID    uint64 `json:"cgroup_id,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	CgroupDepth int    `json:"cgroup_depth,omitempty"`
	Attribution string `json:"attribution,omitempty"`
	Comm        string `json:"comm,omitempty"`
	Source      string `json:"source,omitempty"`
}

// EventDropCounts is the accounting of what the collection missed.
// Overflow notifications and the events they stand for are counted
// separately: one notification can represent many lost events, so the
// notification count is not a count of what was lost.
type EventDropCounts struct {
	LostEvents        int `json:"lost_events"`
	LostNotifications int `json:"lost_notifications"`
	// EnterExitUnmatched counts an entry with no outcome, or an outcome
	// with no entry, timestamped inside the observation window: a call
	// the collection was answerable for and still lost track of.
	// EnterExitUnmatchedBoundary is the same shape of half — an entry
	// with no outcome, or an outcome with no entry — timestamped outside
	// [WindowStart, WindowEnd] instead: before the window opened or after
	// it closed, which the wrapper starts and stops well clear of on
	// purpose (see Convert.ConvertOptions.WindowStart), so such a half is
	// a boundary of what this run measures at all, not something it lost.
	// Judgment rests only on the half's own timestamp against the window;
	// arrival order plays no part, and neither does the collection's own
	// reported attach time (see EventHeader.AttachedAt), which is carried
	// for reference only. Without both WindowStart and WindowEnd, no
	// boundary can be measured and every such half is counted as the
	// first kind. Only the first kind says anything about the collection
	// missing something inside the window it was watching.
	EnterExitUnmatched         int `json:"enter_exit_unmatched"`
	EnterExitUnmatchedBoundary int `json:"enter_exit_unmatched_boundary"`
	// MapOverflow is how many insertions into the per-thread pending map
	// failed. The insertion itself has no return value to check, so the
	// entry probe checks for its own key immediately afterward and counts
	// a miss; a trace old enough to carry no such counter cannot report
	// this at zero and names it in Unmeasured instead.
	MapOverflow      int `json:"map_overflow"`
	PathReadFailures int `json:"path_read_failures"`
	PathTruncations  int `json:"path_truncations"`
	ConvertFailures  int `json:"convert_failures"`
	// IdentityUnavailable counts events the tracer could not attach a
	// process or thread number to. It is not a lost event — the path and
	// the control group are there — but nothing can say which process did
	// it, so it confirms nothing on its own.
	IdentityUnavailable int `json:"identity_unavailable"`
	// UnmatchedIdentityUnavailable is the part of the unmatched halves —
	// counted inside those two totals rather than beside them — that had
	// a missing PID or TID. It says nothing about why a given half went
	// unmatched, nor which of the two totals it fell into: a collision
	// with another identity-less record and an ordinary buffer loss both
	// leave the same gap, and this count does not tell them apart.
	UnmatchedIdentityUnavailable int `json:"unmatched_identity_unavailable"`

	EventsBeforeFilter int `json:"events_before_filter"`
	EventsAfterFilter  int `json:"events_after_filter"`

	StoppedEarly bool      `json:"stopped_early,omitempty"`
	StoppedAt    time.Time `json:"stopped_at,omitempty"`
	GapSeconds   float64   `json:"gap_seconds,omitempty"`
	StopReason   string    `json:"stop_reason,omitempty"`

	// Unmeasured names the kinds of loss this collection method cannot
	// count at all. They are listed rather than reported as zero: a count
	// of zero is a claim that nothing was lost, and a method that cannot
	// see a kind of loss has not established that.
	Unmeasured []string `json:"unmeasured,omitempty"`
}

// EventsTrailer is the last line of an event log.
type EventsTrailer struct {
	Record          string          `json:"record"`
	EndedAt         time.Time       `json:"ended_at"`
	Drops           EventDropCounts `json:"drops"`
	DetachConfirmed bool            `json:"detach_confirmed,omitempty"`
	DetachNote      string          `json:"detach_note,omitempty"`
}

// Attribution values a converted event can carry. There is no value for
// "the host": a control group the table does not know about is
// unattributed, and calling it the host's would be a claim the table
// cannot support.
const (
	attributionContainer    = "container"
	attributionUnattributed = "unattributed"
)

// CgroupEntry is one control group in the correspondence table: which
// container it belongs to, how far below that container's own group it
// sits, and when the entry was valid.
//
// A container that is recreated gets a new control group directory with a
// new identifier, so an entry is bounded in time rather than standing
// forever: Generation counts how many times the same path has been a
// different group, and ExpiredAt closes an entry the moment a later
// snapshot found something else there.
type CgroupEntry struct {
	CgroupID uint64 `json:"cgroup_id"`
	Path     string `json:"path"`
	// ContainerID is the container this group belongs to, empty when none
	// does. Depth is how many levels above this group that container's own
	// group sits: a workload that creates groups of its own produces
	// events below the container's, and the distance is recorded rather
	// than flattened away.
	ContainerID string `json:"container_id,omitempty"`
	Depth       int    `json:"depth"`
	Generation  int    `json:"generation"`

	// Inode is the directory's inode number and HandleID the identifier
	// the kernel reports for the same directory through its file handle.
	// Both are recorded because the table's whole premise is that they are
	// the same number, and a premise is checked rather than assumed.
	Inode       uint64 `json:"inode"`
	HandleID    uint64 `json:"handle_id,omitempty"`
	HandleErr   string `json:"handle_error,omitempty"`
	IDAgreement string `json:"id_agreement"` // "agree" | "disagree" | "unchecked"

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiredAt time.Time `json:"expired_at,omitempty"`
}

// CgroupTable is the saved correspondence between control groups and
// containers, accumulated over one or more snapshots.
type CgroupTable struct {
	GeneratedAt time.Time `json:"generated_at"`
	Root        string    `json:"root"`
	// Snapshots counts how many times the table has been refreshed, and
	// UpdatedAt when each refresh happened, because a container created
	// during an observation window is only in the table from the refresh
	// that found it.
	Snapshots int         `json:"snapshots"`
	UpdatedAt []time.Time `json:"updated_at,omitempty"`
	// Calibration is the check that a control group's identifier and its
	// directory's inode number are the same value. Where they are not, the
	// identifiers from the file-handle method are the ones to use, and the
	// table says so rather than silently mixing the two.
	Calibration string        `json:"calibration"` // "agree" | "disagree" | "unchecked"
	Entries     []CgroupEntry `json:"entries"`
	Errors      []string      `json:"errors,omitempty"`
}
