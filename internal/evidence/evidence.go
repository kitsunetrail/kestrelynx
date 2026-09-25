// Package evidence is the vocabulary and file format the Sensor and the main
// body share to describe runtime usage: which container generations exist,
// which OS packages and executables were observed running in them, and how
// confidently. The package also carries the reader-side contract for that
// file (a Sensor is an untrusted, separately-privileged process) and the
// pure judgement/projection functions that turn a validated snapshot plus a
// scanner Finding's identity into a usage verdict.
//
// Nothing in this package talks to a live Sensor process, a Docker socket or
// procfs: those are the Sensor's own job. This package only defines what a
// snapshot looks like on disk, how to read one safely, and how to interpret
// it once read.
package evidence

import "time"

// Schema is the evidence file's current format version. A snapshot carrying
// any other value is rejected outright rather than partially interpreted:
// a schema bump is expected to change field meanings, not just add fields,
// so guessing at compatibility would risk silently misreading old or new
// data.
const Schema = 1

// Snapshot is one Sensor evidence file's full decoded content: the Sensor's
// own self-report (Sensor) plus every container generation it currently
// knows about (Generations). It is the unit Write and Read exchange, and
// the unit the projection functions in project.go consume.
type Snapshot struct {
	Schema      int          `json:"schema"`
	Sensor      SensorInfo   `json:"sensor"`
	Generations []Generation `json:"generations"`
}

// SensorStatus is the Sensor's own self-report of whether it is observing
// normally. It is written by the Sensor and read verbatim; it is not the
// richer status the main body derives for display (that also accounts for a
// stale or missing evidence file, see notify/format for that projection).
type SensorStatus string

const (
	SensorOK                SensorStatus = "ok"
	SensorDegraded          SensorStatus = "degraded"
	SensorPermissionDenied  SensorStatus = "permission_denied"
	SensorIsolationFailed   SensorStatus = "isolation_failed"
	SensorIsolationDegraded SensorStatus = "isolation_degraded"
)

// Isolation is the Sensor's self-check of its own sandboxing, recorded so a
// reader can tell a fully-isolated Sensor from one running with a degraded
// sandbox without having to inspect the container it runs in.
type Isolation struct {
	NoNewPrivs  bool `json:"no_new_privs"`
	NonDumpable bool `json:"non_dumpable"`
	Seccomp     bool `json:"seccomp"`
	LandlockABI int  `json:"landlock_abi"`
}

// EventsStatus says whether the Sensor's eBPF event collection is attached
// and delivering events. Sampling continues regardless of this value: it is
// possible, and expected on some hosts, for Status to be SensorOK while
// EventsInfo.Status is EventsUnavailable.
type EventsStatus string

const (
	EventsOK          EventsStatus = "ok"
	EventsUnavailable EventsStatus = "unavailable"
)

// EventsReason explains why event collection did not attach. It is only
// meaningful when EventsInfo.Status is EventsUnavailable.
type EventsReason string

const (
	EventsReasonNone              EventsReason = ""
	EventsReasonKernelUnsupported EventsReason = "kernel_unsupported"
	EventsReasonBTFMissing        EventsReason = "btf_missing"
	EventsReasonPermission        EventsReason = "permission"
	EventsReasonAttachFailed      EventsReason = "attach_failed"
	EventsReasonCgroupV1          EventsReason = "cgroup_v1"
)

// EventsInfo is the Sensor-wide state of eBPF event collection: whether it
// is attached, when, and how many events have been dropped since.
type EventsInfo struct {
	Status     EventsStatus `json:"status"`
	Reason     EventsReason `json:"reason,omitempty"`
	AttachedAt time.Time    `json:"attached_at,omitempty"`
	Lost       int64        `json:"lost"`
}

// SensorInfo is the Sensor's self-report: who it is, how long it has been
// running, how often it samples, and its own isolation/event-collection
// state. HeartbeatAt is updated every sample (and at least every 60 seconds
// even without a content change), and is what the main body uses to decide
// whether the Sensor is still alive (StalenessThreshold).
type SensorInfo struct {
	Version          string       `json:"version"`
	SessionID        string       `json:"session_id"`
	SessionStartedAt time.Time    `json:"session_started_at"`
	HeartbeatAt      time.Time    `json:"heartbeat_at"`
	IntervalSeconds  int          `json:"interval_seconds"`
	Isolation        Isolation    `json:"isolation"`
	Status           SensorStatus `json:"status"`
	Events           EventsInfo   `json:"events"`
}
