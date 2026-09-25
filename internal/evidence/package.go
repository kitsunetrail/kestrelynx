package evidence

import "time"

// EvidenceKind is one concrete way a package or executable was seen in use.
// The OS kinds and the language kinds are different vocabularies that never
// mix on the same record: an OSPackageEvidence only ever carries the OS
// kinds, an ExecutableEvidence only ever carries the kinds relevant to
// whichever judgement (embedded-binary or runtime-loaded) produced it.
type EvidenceKind string

const (
	// OS package / executable kinds: a running process's own executable, an
	// executable mapping into another running process, a successful exec
	// event, and a successful library-load (mmap PROT_EXEC) event.
	KindExe              EvidenceKind = "exe"
	KindMappedLibrary    EvidenceKind = "mapped_library"
	KindExecEvent        EvidenceKind = "exec_event"
	KindLibraryLoadEvent EvidenceKind = "library_load_event"

	// Language package kinds: a binary embedding the package is a running
	// process's executable (Running) or was executed during the observation
	// window (Executed); a language runtime that loads the package is
	// running (Running) or was executed (Executed).
	KindBinaryRunning   EvidenceKind = "binary_running"
	KindBinaryExecuted  EvidenceKind = "binary_executed"
	KindRuntimeRunning  EvidenceKind = "runtime_running"
	KindRuntimeExecuted EvidenceKind = "runtime_executed"
)

// KindObservation is one evidence kind's aggregate for a package or
// executable within a generation. Samples counts how many samples observed
// a sampling-derived kind (exe, mapped_library, binary_running,
// runtime_running); Count counts how many times an event-derived kind fired
// (exec_event, library_load_event, binary_executed, runtime_executed). Only
// one of the two is meaningful for any given kind — which one is decided by
// which EvidenceKind this observation is filed under in a Kinds map, not by
// a field on this struct.
type KindObservation struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Samples   int       `json:"samples,omitempty"`
	Count     int       `json:"count,omitempty"`
}

// ProcessObservation is one same-sample, same-process combination of
// exposure and privilege facts: the process's own executable, effective
// UID, whether it runs in a user namespace, its effective capabilities, and
// any listening sockets it held at that sample. It is never assembled from
// facts read at different samples or from different processes — a root
// process's identity is never combined with a listening socket some other,
// unprivileged process opened.
type ProcessObservation struct {
	Exe          string    `json:"exe,omitempty"`
	EffectiveUID int       `json:"effective_uid"`
	Userns       bool      `json:"userns"`
	CapEff       string    `json:"cap_eff,omitempty"`
	Listeners    []string  `json:"listeners,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
}

// OSPackageEvidence is one OS package a generation has actually observed in
// use: its identity (matched against a Finding by exact name and version)
// and every kind of evidence and process combination seen for it.
type OSPackageEvidence struct {
	Name         string                           `json:"name"`
	Version      string                           `json:"version"`
	Kinds        map[EvidenceKind]KindObservation `json:"kinds,omitempty"`
	Observations []ProcessObservation             `json:"observations,omitempty"`
}

// UnavailableReason is why a package's usage could not be judged as in-use
// or not-observed.
type UnavailableReason string

const (
	ReasonSensorNotReporting   UnavailableReason = "sensor_not_reporting"   // no evidence file has ever appeared
	ReasonSensorStale          UnavailableReason = "sensor_stale"           // heartbeat older than the staleness threshold
	ReasonEvidenceInvalid      UnavailableReason = "evidence_invalid"       // the evidence file failed validation
	ReasonIsolationFailed      UnavailableReason = "isolation_failed"       // the Sensor never started observing
	ReasonPermissionDenied     UnavailableReason = "permission_denied"      // this generation's reads were refused
	ReasonInitializing         UnavailableReason = "initializing"           // this generation's package DB index isn't built yet
	ReasonStalled              UnavailableReason = "stalled"                // this generation's worker exceeded its time budget
	ReasonParseFailed          UnavailableReason = "parse_failed"           // the parser rejected this generation's package DB
	ReasonTruncated            UnavailableReason = "truncated"              // a read limit was hit while indexing this generation
	ReasonIncomplete           UnavailableReason = "incomplete"             // an observation was discarded this generation
	ReasonGenerationUnverified UnavailableReason = "generation_unverified"  // the evidence generation doesn't match the scanned entity
	ReasonContainerNotObserved UnavailableReason = "container_not_observed" // no evidence generation matches this container at all
	ReasonDBAbsent             UnavailableReason = "db_absent"              // no supported package database found
	ReasonDBError              UnavailableReason = "db_error"               // the package database failed to read/parse
	ReasonDBUnsupported        UnavailableReason = "db_unsupported"         // e.g. rpm: a format this Sensor does not parse
	ReasonNoFileList           UnavailableReason = "no_file_list"           // the database can't give this package's file list
	ReasonAttributionAmbiguous UnavailableReason = "attribution_ambiguous"  // more than one package owns the observed path
	ReasonFileReplaced         UnavailableReason = "file_replaced"          // the mapping was (deleted) or its dev/inode changed
	ReasonVersionMismatch      UnavailableReason = "version_mismatch"       // the owning package's name matched but not its version
	ReasonEcosystemUnmapped    UnavailableReason = "ecosystem_unmapped"     // this Result.Type has no runtime-executable mapping
	ReasonBinaryPathUnknown    UnavailableReason = "binary_path_unknown"    // an embedded-language Finding has no Result.Target
)

// UnavailablePackage is one OS package a generation could not judge, and
// why — kept apart from OSPackageEvidence so "we looked and couldn't tell"
// is never confused with "we haven't looked".
type UnavailablePackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Reason  UnavailableReason `json:"reason"`
}

// ExecutableEvidence is one executable file a generation has actually
// observed running or executed, regardless of whether it belongs to any
// known OS package. Every observed executable is recorded here (not just
// ones matched to a package), because language-package judgement matches
// against this list directly: a Go binary's Result.Target or a language
// runtime's resolved name, not an OS package identity.
type ExecutableEvidence struct {
	Path         string                           `json:"path"`
	Dev          string                           `json:"dev,omitempty"`
	Inode        uint64                           `json:"inode,omitempty"`
	Kinds        map[EvidenceKind]KindObservation `json:"kinds,omitempty"`
	Observations []ProcessObservation             `json:"observations,omitempty"`
}

// Usage is the three-way usage verdict shown for a package: seen in use,
// looked for and not seen, or impossible to judge. It never encodes
// priority or trust — a not-observed package is not "safer" than an
// unavailable one, and neither is ever used to lower a package's priority
// bucket.
type Usage string

const (
	UsageInUse       Usage = "in_use"
	UsageNotObserved Usage = "not_observed"
	UsageUnavailable Usage = "unavailable"
)

// Verdict is one usage judgement for a single observation unit: one
// PackageRef in one generation, one language Instance in one generation, or
// (after projection) a whole PackageGroup or diff element. Reason is only
// meaningful when Usage is UsageUnavailable; EvidenceKinds is only
// meaningful when Usage is UsageInUse; EventsCoverage is only carried when
// Usage is not UsageInUse, since it exists to qualify how much confidence a
// not-observed or unavailable verdict deserves, not an in-use one.
type Verdict struct {
	Usage          Usage
	Reason         UnavailableReason
	EvidenceKinds  []EvidenceKind
	EventsCoverage EventsCoverage
}
