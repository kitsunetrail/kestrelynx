package main

import "time"

// DockerSubject identifies a Docker container. It is the only Subject.Runtime
// variant this harness ever populates.
type DockerSubject struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	ImageRef      string `json:"image_ref"`
	ImageID       string `json:"image_id"`
}

// KubernetesSubject identifies a Kubernetes-managed container. This harness
// never populates it; the field exists so a future collector for that
// runtime can share the same Subject shape without a breaking schema change.
type KubernetesSubject struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

// Subject is the common observation-subject structure: it can name either a
// Docker container or a Kubernetes container without the rest of the schema
// caring which. Runtime says which of Docker/Kubernetes is populated.
type Subject struct {
	Runtime    string            `json:"runtime"` // "docker" (only value this harness produces)
	Docker     DockerSubject     `json:"docker"`
	Kubernetes KubernetesSubject `json:"kubernetes"`
	StartedAt  string            `json:"started_at"` // Docker State.StartedAt, passed through verbatim
}

// RunKey uniquely identifies one execution: which case, under which
// permission condition, at which sampling interval/window/phase, and which
// replicate of that combination. Permission and Replicate are always
// supplied on the command line, never inferred from what the process
// actually achieved.
type RunKey struct {
	CaseVariant string `json:"case_variant"`
	Permission  string `json:"permission"` // "root" | "ptrace" | "ptrace_dac" | "none" | "bpf_perfmon" | "bpf_perfmon_dac" | "sysadmin"
	Interval    int    `json:"interval_seconds"`
	Window      int    `json:"window_seconds"`
	Phase       int    `json:"phase_seconds"`
	Replicate   int    `json:"replicate"`
	// Sync says how the observation and the workload were ordered:
	// "startup" starts the observation first and only then lets the
	// workload begin, "attach_running" joins a container that is already
	// working. The two capture structurally different things — a load that
	// happens once at startup exists only in the first — so results from
	// them are never merged, and the dimension belongs in the key that
	// keeps them apart.
	Sync string `json:"sync,omitempty"`
	// ConfigID encodes the event-collection configuration: the collection
	// method and its version, the kernel-side filter, and the buffer size.
	// A run that collected no events at all and one that collected them
	// under a different filter are not the same condition, and without
	// this they would write to the same place and be added up together.
	ConfigID string `json:"config_id,omitempty"`
}

// ProcessGeneration identifies one process instance: a PID is only unique
// together with its starttime (man 5 proc_pid_stat), since PIDs are reused.
// Every per-process fact (namespaces, paths, listeners, evidence) is keyed
// by generation, never by bare PID.
type ProcessGeneration struct {
	PID       int    `json:"pid"`
	Starttime string `json:"starttime,omitempty"`
}

// PortBinding is one entry of a Docker port mapping (host side may be empty
// for NetworkSettings.Ports entries that are exposed but not published).
type PortBinding struct {
	HostIP   string `json:"host_ip,omitempty"`
	HostPort string `json:"host_port,omitempty"`
}

// Window is the sampling window's schedule and the recorded schedule/actual
// timing of every sample taken in it.
type Window struct {
	ID string `json:"id"`
	// PhaseBase is the instant the phase offset is measured from: the
	// reference point of the workload's own cycle, supplied on the command
	// line (a case's recorded start time) or, failing that, collect's own
	// start. ScheduledStart is PhaseBase + the phase offset. Without it a
	// phase number says how long collect waited, but not what it waited
	// relative to, and the phase dimension cannot be interpreted after the
	// fact.
	PhaseBase      time.Time `json:"phase_base"`
	PhaseBaseFrom  string    `json:"phase_base_from"` // "flag" | "collect_start"
	ScheduledStart time.Time `json:"scheduled_start"`
	ScheduledEnd   time.Time `json:"scheduled_end"`
	// HostArch (runtime.GOARCH) is recorded because /proc/net/tcp{,6}'s
	// 32-bit words are stored in the host's native byte order.
	HostArch string         `json:"host_arch"`
	Samples  []SampleTiming `json:"samples"`
}

// SampleTiming is one sample's schedule vs. actual timing. Delay is always
// >= 0: a sample is never taken before its scheduled time, only later.
type SampleTiming struct {
	SampleID       string    `json:"sample_id"`
	Index          int       `json:"index"`
	ScheduledStart time.Time `json:"scheduled_start"`
	ActualStart    time.Time `json:"actual_start"`
	DelayMS        int64     `json:"delay_ms"`
	EndedAt        time.Time `json:"ended_at"`
}

// NamespaceRecord is one process generation's namespace identity, as
// observed in one sample: the readlink targets of ns/net, ns/mnt and
// ns/user, and its uid_map (recorded so a userns-remap environment is
// visible rather than silently assumed away). Invalid is set when this
// sample's identity disagrees with an earlier sample for the same PID
// (namespace id changed while the PID's starttime says it's still the same
// process record we last saw) — such a sample must not be used as evidence.
type NamespaceRecord struct {
	SampleID      string            `json:"sample_id"`
	Generation    ProcessGeneration `json:"process_generation"`
	Net           string            `json:"net,omitempty"`
	Mnt           string            `json:"mnt,omitempty"`
	User          string            `json:"user,omitempty"`
	UIDMap        string            `json:"uid_map,omitempty"`
	Error         string            `json:"error,omitempty"`
	Invalid       bool              `json:"invalid,omitempty"`
	InvalidReason string            `json:"invalid_reason,omitempty"`
}

// MapEntry is one file-backed, executable mapping line from /proc/<pid>/maps.
type MapEntry struct {
	Path    string `json:"path"`
	Dev     string `json:"dev"`
	Inode   string `json:"inode"`
	Perms   string `json:"perms"`
	Deleted bool   `json:"deleted"`
}

// ProcessRecord is everything read from procfs for one process generation in
// one sample. A field being empty/zero because a read failed is always
// accompanied by the corresponding *Error field.
type ProcessRecord struct {
	SampleID   string            `json:"sample_id"`
	Generation ProcessGeneration `json:"process_generation"`
	PPID       int               `json:"ppid"`
	User       string            `json:"user"`

	// Invalid is set when this PID's starttime, namespace identity or the
	// container's StartedAt disagreed between the checks taken before and
	// after this sample's reads: the record may then mix two process
	// generations and must not be used as evidence. A generation that
	// simply replaced an earlier one between samples is not invalid — it
	// is a different generation, recorded independently.
	Invalid       bool   `json:"invalid,omitempty"`
	InvalidReason string `json:"invalid_reason,omitempty"`

	Exe        string `json:"exe,omitempty"`
	ExeDeleted bool   `json:"exe_deleted"`
	ExeError   string `json:"exe_error,omitempty"`

	Maps      []MapEntry `json:"maps,omitempty"`
	MapsError string     `json:"maps_error,omitempty"`

	EffectiveUID string `json:"effective_uid,omitempty"`
	CapEff       string `json:"cap_eff,omitempty"`
	StatusError  string `json:"status_error,omitempty"`

	CgroupContainerID string `json:"cgroup_container_id,omitempty"`
	CgroupMatches     bool   `json:"cgroup_matches"`
	CgroupError       string `json:"cgroup_error,omitempty"`

	// FileDescriptors are the ordinary files this process had open, from
	// the readlink targets of its descriptor table. Sockets are not here:
	// they are resolved to inodes and reported as listeners. A file kept
	// open for the life of a process — a runtime holding its archives, for
	// instance — is visible here without any event collection.
	FileDescriptors []FDRecord `json:"file_descriptors,omitempty"`
	FDError         string     `json:"fd_error,omitempty"`
}

// Ownership is collect's own path-to-package resolution verdict, decided
// without reading any Trivy data.
type Ownership string

const (
	OwnershipOwned          Ownership = "owned"
	OwnershipMultipleOwners Ownership = "multiple_owners"
	OwnershipUnowned        Ownership = "unowned"
	OwnershipDeleted        Ownership = "deleted"
	OwnershipNoFileList     Ownership = "no_file_list"
	OwnershipDBAbsent       Ownership = "db_absent"
	OwnershipDBError        Ownership = "db_error"
	OwnershipUnresolvable   Ownership = "unresolvable"
)

// PathResolutionRecord is one observed path's ownership resolution at one
// sample, plus the two independent flags (MapsDeleted, PathInodeChanged)
// that feed into it without being collapsed into a single "replaced" state.
// trivy_match is never here: it requires Trivy data collect never reads.
type PathResolutionRecord struct {
	SampleID   string            `json:"sample_id"`
	Generation ProcessGeneration `json:"process_generation"`
	// MountViewID and DBGeneration name the exact package database
	// instance this resolution was made against, so the resolution can be
	// replayed against the matching package_ledger rows.
	MountViewID  string `json:"mount_view_id,omitempty"`
	DBGeneration string `json:"db_generation,omitempty"`
	// Source says which read produced this path: the process's executable
	// link, its memory mappings, or its open file descriptors. The three
	// support different claims — an executable was run, a mapping was
	// loaded, a descriptor is merely open — and collapsing them would let
	// a description say more than the observation does.
	Source   string `json:"source,omitempty"`   // "exe" | "maps" | "fd"
	Path     string `json:"path"`               // as observed (pre-resolution)
	Resolved string `json:"resolved,omitempty"` // resolveInRoot's output, "" if Ownership == unresolvable
	Dev      string `json:"dev,omitempty"`      // as recorded by /proc/<pid>/maps at observation time
	Inode    string `json:"inode,omitempty"`

	MapsDeleted bool `json:"maps_deleted"`
	// PathInodeChanged is a pointer so "not evaluated" (inode calibration
	// did not succeed for this container) is distinguishable from a
	// definite "false".
	PathInodeChanged *bool `json:"path_inode_changed,omitempty"`

	Ownership Ownership `json:"ownership"`
	DBKind    string    `json:"db_kind,omitempty"`
	Package   string    `json:"package,omitempty"`
	DBVersion string    `json:"db_version,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// LedgerEntry is one package_ledger row: everything the package database
// knew about one package at one (mount_view_id, db_generation), regardless
// of whether any observed path ever referenced it.
type LedgerEntry struct {
	MountViewID  string `json:"mount_view_id"`
	DBGeneration string `json:"db_generation"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Arch         string `json:"arch,omitempty"`
	// FileListPresent says whether the database could tell us this
	// package's file list at all. It is not "this package has files": a
	// package that installs nothing has a complete file list that happens
	// to be empty, and FileCount is what distinguishes the two.
	FileListPresent bool `json:"file_list_present"`
	// FileCount is how many paths that list contains. Zero with
	// FileListPresent means a package that provides no files — apk's
	// virtual packages (conventionally named with a leading ".", created
	// by `apk add --virtual` to bundle dependencies) and dpkg
	// metapackages, which exist only to depend on other packages.
	FileCount int `json:"file_count"`
}

// PkgDBGenerationInfo describes one (mount_view_id, db_generation) package
// database instance collect actually read.
type PkgDBGenerationInfo struct {
	MountViewID  string    `json:"mount_view_id"`
	DBGeneration string    `json:"db_generation"`
	DBKind       string    `json:"db_kind"` // "dpkg" | "dpkg-status.d" | "apk" | "none"
	Path         string    `json:"path,omitempty"`
	ReadAt       time.Time `json:"read_at"`
	SizeBytes    int64     `json:"size_bytes"`
	ModTime      time.Time `json:"mod_time"`
	ContentHash  string    `json:"content_hash,omitempty"`
	// FileListComplete is true when every package this database knows
	// about also has a recoverable file list. When it is false, a path the
	// index cannot resolve is "no_file_list" rather than "unowned": the
	// database cannot distinguish a file nothing owns from a file owned by
	// a package whose file list is missing.
	FileListComplete bool   `json:"file_list_complete"`
	Error            string `json:"error,omitempty"`
}

// InodeCalibration records whether dev/inode comparison could be trusted for
// this container, and what it was based on.
type InodeCalibration struct {
	Calibrated      bool   `json:"calibrated"`
	CalibrationPath string `json:"calibration_path,omitempty"`
	MapsDev         string `json:"maps_dev,omitempty"`
	MapsInode       string `json:"maps_inode,omitempty"`
	StatDev         string `json:"stat_dev,omitempty"`
	StatInode       string `json:"stat_inode,omitempty"`
	Error           string `json:"error,omitempty"`
}

// Listener is one LISTEN-state TCP socket found via /proc/<pid>/net/tcp{,6}
// and correlated to a process generation via that PID's open file
// descriptors.
type Listener struct {
	SampleID  string `json:"sample_id"`
	NetnsID   string `json:"netns_id,omitempty"`
	Protocol  string `json:"protocol"` // always "tcp": the transport protocol
	Family    string `json:"family"`   // "ipv4" | "ipv6": which procfs table it came from
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
	Inode     string `json:"inode"`
	// Generation is the first process generation found holding this
	// socket, kept for the common case of a single owner; Generations is
	// every generation whose file descriptor table referenced the inode. A
	// socket shared across a parent and its workers has several, and
	// keeping only one of them would attribute the listener to an
	// arbitrary process.
	Generation  ProcessGeneration   `json:"process_generation"`
	Generations []ProcessGeneration `json:"process_generations,omitempty"`
}

// DockerConfig is the container's Docker-reported configuration, fixed for
// the run.
type DockerConfig struct {
	NetworkMode string `json:"network_mode,omitempty"`
	// PortBindings and NetworkPorts preserve every declared port key even
	// when its value is a Docker-reported null (an exposed-but-unpublished
	// port): such a key maps to a nil slice here rather than being dropped.
	PortBindings map[string][]PortBinding `json:"port_bindings,omitempty"` // HostConfig.PortBindings
	NetworkPorts map[string][]PortBinding `json:"network_ports,omitempty"` // NetworkSettings.Ports
	Networks     map[string]string        `json:"networks,omitempty"`      // network name -> IP address
	ConfigUser   string                   `json:"config_user"`
	Privileged   bool                     `json:"privileged"`
	CapAdd       []string                 `json:"cap_add,omitempty"`
	CapDrop      []string                 `json:"cap_drop,omitempty"`
	StartedAt    string                   `json:"started_at,omitempty"`
}

// CollectionResult is one sample's proc_observe/pkgdb_read outcome and the
// derived validity used by the decision table.
type CollectionResult struct {
	SampleID    string `json:"sample_id"`
	ProcObserve string `json:"proc_observe"` // "ok" | "denied" | "gone" | "top_failed"
	PkgdbRead   string `json:"pkgdb_read"`   // "ok" | "absent" | "error"
	Valid       bool   `json:"valid"`
	// Views records which package database instance each mount view
	// present in this sample resolved to, re-verified for this sample
	// rather than assumed unchanged since the first one. It is what makes
	// a saved record replayable: a run whose database was updated
	// mid-window has more than one generation here, and each sample says
	// which one it actually read.
	Views []SampleDBView `json:"pkgdb_views,omitempty"`
}

// SampleDBView is one sample's outcome for one mount view's package
// database.
type SampleDBView struct {
	MountViewID  string `json:"mount_view_id"`
	DBGeneration string `json:"db_generation,omitempty"`
	DBKind       string `json:"db_kind,omitempty"`
	PkgdbRead    string `json:"pkgdb_read"` // "ok" | "absent" | "error"
	Error        string `json:"error,omitempty"`
}

// Failure is one recorded step failure.
type Failure struct {
	Step       string            `json:"step"`
	SampleID   string            `json:"sample_id,omitempty"`
	Generation ProcessGeneration `json:"process_generation,omitempty"`
	Message    string            `json:"message"`
}

// LoadMeasurement is the 3-tier load recording.
type LoadMeasurement struct {
	InitialDBRead InitialDBReadLoad `json:"initial_db_read"`
	SteadyState   CgroupLoad        `json:"steady_state"`
	DockerDaemon  CgroupLoad        `json:"docker_daemon"`
}

// InitialDBReadLoad is the one-time cost of building the package index:
// how long it took, and how much was actually read to do it (bytes and
// files opened, not packages found).
type InitialDBReadLoad struct {
	DurationMS int64 `json:"duration_ms"`
	BytesRead  int64 `json:"bytes_read"`
	FileCount  int   `json:"file_count"`
	Measured   bool  `json:"measured"`
}

// CgroupLoad is a cgroup v2 cpu.stat/memory.peak reading over the run. The
// CPU and memory measurements succeed or fail independently — memory.peak
// is absent on kernels before 5.19 even where cpu.stat is present — so each
// carries its own Measured flag and error. Neither is ever reported as a
// zero value standing in for an unread file.
//
// MemoryPeakBytes is the cgroup's own high-water mark, which covers the
// whole lifetime of that cgroup rather than just this run: it is only a
// measurement of this collector when the collector was started in a cgroup
// of its own (see the package documentation).
type CgroupLoad struct {
	CgroupPath         string `json:"cgroup_path,omitempty"`
	Measured           bool   `json:"measured"` // CPU delta measured
	CPUUsageDeltaUS    int64  `json:"cpu_usage_delta_us,omitempty"`
	Error              string `json:"error,omitempty"` // why the CPU delta is missing
	MemoryPeakMeasured bool   `json:"memory_peak_measured"`
	MemoryPeakBytes    int64  `json:"memory_peak_bytes,omitempty"`
	MemoryError        string `json:"memory_error,omitempty"`
}

// ContainerRecord is collect's output for exactly one run of one container:
// every sample's evidence, plus the container's fixed subject/config data.
// collect writes one such record per container (one file per container).
type ContainerRecord struct {
	Subject Subject `json:"subject"`
	RunKey  RunKey  `json:"run_key"`
	Window  Window  `json:"window"`

	// TargetRegistrations records the pre-registration state machine for a
	// target named before it existed: when it was registered, when it was
	// seen to start, when its auxiliary inputs were read, and when it
	// became an observation target.
	TargetRegistrations []TargetRegistration `json:"target_registrations,omitempty"`
	// AuxiliaryInputs holds, per package-database generation, the
	// file-to-package mapping information the sampling itself does not
	// produce. It is saved so a later match reads it instead of the
	// container's filesystem, which by then may be gone.
	AuxiliaryInputs []AuxiliaryInputs `json:"auxiliary_inputs,omitempty"`

	Namespaces        []NamespaceRecord      `json:"namespaces,omitempty"`
	Processes         []ProcessRecord        `json:"processes,omitempty"`
	PathResolution    []PathResolutionRecord `json:"path_resolution,omitempty"`
	PackageLedger     []LedgerEntry          `json:"package_ledger,omitempty"`
	PkgDBs            []PkgDBGenerationInfo  `json:"pkgdb,omitempty"`
	InodeCalibration  InodeCalibration       `json:"inode_calibration"`
	Listeners         []Listener             `json:"listeners,omitempty"`
	Docker            DockerConfig           `json:"docker"`
	CollectionResults []CollectionResult     `json:"collection_results,omitempty"`
	Failures          []Failure              `json:"failures,omitempty"`
	Load              LoadMeasurement        `json:"load"`

	// InspectError is set when /containers/{id}/json failed outright: the
	// container is excluded from measurement (observation_failed) and none
	// of the per-sample fields above are populated.
	InspectError string `json:"inspect_error,omitempty"`
}

// Manifest is collect's top-level output alongside the per-container record
// files.
type Manifest struct {
	GeneratedAt time.Time       `json:"generated_at"`
	SocketPath  string          `json:"socket_path"`
	Containers  []ManifestEntry `json:"containers"`
	Errors      []string        `json:"errors,omitempty"`
}

// ManifestEntry names one container's record file.
type ManifestEntry struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	File          string `json:"file"`
}
