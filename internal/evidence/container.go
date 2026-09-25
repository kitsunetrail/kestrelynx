package evidence

import "time"

// ContainerRef names one container. Runtime says which of the
// runtime-specific fields is populated; "docker" is the only runtime value
// this schema currently accepts (Namespace/Pod/Container exist so a future
// Kubernetes Sensor can share this shape without a breaking schema change,
// but nothing populates or accepts them yet).
type ContainerRef struct {
	Runtime   string `json:"runtime"`             // "docker" (only value written so far)
	ID        string `json:"id,omitempty"`        // Docker: 64-hex container ID
	Namespace string `json:"namespace,omitempty"` // Kubernetes only
	Pod       string `json:"pod,omitempty"`       // Kubernetes only
	Container string `json:"container,omitempty"` // Kubernetes only
}

// InitProcess identifies a container generation's init process: the
// process that belongs to the container's cgroup, whose parent does not, and
// whose starttime is the smallest among such processes. PID is a host PID
// (the Sensor observes host-wide, not from inside a container's PID
// namespace).
type InitProcess struct {
	PID       int   `json:"pid"`
	Starttime int64 `json:"starttime"`
}

// GenerationState is one container generation's own observation state,
// independent of any specific package's verdict.
type GenerationState string

const (
	StateInitializing GenerationState = "initializing" // package DB index not built yet
	StateObserving    GenerationState = "observing"    // normal steady state
	StateDenied       GenerationState = "denied"       // this container's procfs/DB reads are refused
	StateStalled      GenerationState = "stalled"      // this generation's worker exceeded its time budget
	StateParseFailed  GenerationState = "parse_failed" // the parser rejected this generation's package DB
	StateEnded        GenerationState = "ended"        // the generation is gone; kept only for its trailing 7 days
)

// EventsCoverage says how completely eBPF events cover one generation's
// lifetime. It never certifies that a short-lived process was caught: even
// CoverageSinceStart only means the collector was attached before this
// generation started and has not lost any events for it since.
type EventsCoverage string

const (
	CoverageSinceStart EventsCoverage = "since_start" // attached before the generation started, no losses since
	CoveragePartial    EventsCoverage = "partial"     // attached after start, or some events were lost
	CoverageNone       EventsCoverage = "none"        // eBPF is not attached at all
)

// PackageDBKind is which on-disk package database format a generation's
// container uses. The zero value ("") means no supported format was found.
type PackageDBKind string

const (
	DBKindDpkg       PackageDBKind = "dpkg"
	DBKindDistroless PackageDBKind = "distroless" // status.d directory
	DBKindApk        PackageDBKind = "apk"
)

// PackageDBStatus is whether a generation's package database could be read
// and indexed at all, independent of any individual package's file list.
type PackageDBStatus string

const (
	DBStatusOK          PackageDBStatus = "ok"
	DBStatusAbsent      PackageDBStatus = "absent"      // no supported database found in the container
	DBStatusError       PackageDBStatus = "error"       // a supported database was found but failed to read/parse
	DBStatusUnsupported PackageDBStatus = "unsupported" // e.g. rpm: a database format this Sensor does not parse
)

// PackageDBInfo describes one generation's package database as a whole.
// NoFileList names packages the database knows about but cannot give a file
// list for (dpkg/apk metapackages with no files, or a partially-readable
// database) — a path resolving to one of those is not evidence either way.
type PackageDBInfo struct {
	Kind       PackageDBKind   `json:"kind,omitempty"`
	Status     PackageDBStatus `json:"status"`
	NoFileList []string        `json:"no_file_list,omitempty"`
}

// ParseFailure records one input (a package database file) the parser
// rejected, plus the backoff schedule for retrying it. RetryAfter starts at
// FailedAt plus ten sampling intervals and doubles on every repeat failure
// of the same input (same dev/inode/size), capped at 24 hours; a change in
// dev, inode or size resets it, since that means a different file replaced
// the one that failed.
type ParseFailure struct {
	Input      string    `json:"input"`
	Path       string    `json:"path"`
	Dev        string    `json:"dev,omitempty"`
	Inode      uint64    `json:"inode,omitempty"`
	Size       int64     `json:"size,omitempty"`
	FailedAt   time.Time `json:"failed_at"`
	Count      int       `json:"count"`
	RetryAfter time.Time `json:"retry_after"`
}

// Generation is everything the Sensor knows about one container generation:
// its identity, its own observation state, its package database's health,
// and the OS packages/executables it has actually observed. Incomplete and
// Truncated are generation-wide flags — set when some observation had to be
// discarded or a limit was hit — because a discarded or truncated
// observation makes "not observed" un-claimable for every package in the
// generation, not just the one the discarded record was about.
type Generation struct {
	Container      ContainerRef    `json:"container"`
	Init           InitProcess     `json:"init"`
	StartedAt      time.Time       `json:"started_at"`
	EndedAt        *time.Time      `json:"ended_at"`
	LastVerifiedAt time.Time       `json:"last_verified_at"`
	State          GenerationState `json:"state"`
	PackageDB      PackageDBInfo   `json:"package_db"`
	// Incomplete is set when an observation had to be discarded because its
	// path could not be resolved to a file (the "candidate unknown" failure
	// mode), or because the main body's own read-time validation dropped a
	// record from this generation. It withdraws "not observed" from every
	// package and executable in the generation, since the discarded record
	// might have been the missing evidence.
	Incomplete bool `json:"incomplete"`
	// Truncated is set when a read limit was hit while indexing this
	// generation's container. It has the same effect as Incomplete: "not
	// observed" is not claimable, since the truncated part of the read could
	// have contained the missing evidence.
	Truncated      bool                 `json:"truncated"`
	EventsCoverage EventsCoverage       `json:"events_coverage"`
	EventsLost     int64                `json:"events_lost"`
	ParseFailed    []ParseFailure       `json:"parse_failed,omitempty"`
	OSPackages     []OSPackageEvidence  `json:"os_packages,omitempty"`
	Unavailable    []UnavailablePackage `json:"unavailable,omitempty"`
	Executables    []ExecutableEvidence `json:"executables,omitempty"`
}
