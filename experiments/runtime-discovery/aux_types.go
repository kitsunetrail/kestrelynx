package main

import "time"

// Target registration states. A target named before it exists moves
// through these in order; a target that never starts ends in
// TargetNotStarted, which is a recorded failure rather than an absence of
// observation.
const (
	TargetRegistered = "registered_not_started"
	TargetPreparing  = "start_detected_preparing"
	TargetAccepted   = "accepted"
	TargetNotStarted = "not_started"
)

// TargetRegistration is one pre-registered target's state machine, with the
// instant of every transition. It exists because a collector that
// enumerates running containers once at startup cannot observe a container
// that starts afterwards: a case whose workload must not begin until the
// observation is in place has to name its target first, and then be able
// to tell from the outside that the target has been accepted.
type TargetRegistration struct {
	// Wanted is the container ID or name exactly as it was registered.
	Wanted string `json:"wanted"`
	State  string `json:"state"`
	// ContainerID is filled in once a container matching Wanted is seen.
	ContainerID string `json:"container_id,omitempty"`

	RegisteredAt time.Time `json:"registered_at"`
	// StartDetectedAt is when a container matching Wanted first appeared
	// in the runtime's container list, DetectedRunningAt when it was first
	// seen in the running state.
	StartDetectedAt time.Time `json:"start_detected_at,omitempty"`
	InspectedAt     time.Time `json:"inspected_at,omitempty"`
	// AuxCollectedAt is when the auxiliary mapping inputs for this target
	// finished being read; AcceptedAt is when it became an observation
	// target. The two are separate because acceptance waits on the
	// auxiliary read, and a case's readiness condition is the second
	// instant, not the first.
	AuxCollectedAt time.Time `json:"aux_collected_at,omitempty"`
	AcceptedAt     time.Time `json:"accepted_at,omitempty"`

	Error string `json:"error,omitempty"`
}

// ReadyReport is the file collect writes so a case runner can tell, from
// outside the collector, whether every pre-registered target has been
// accepted. It is rewritten on every state change, so a reader polling it
// sees the intermediate states too rather than only the final one.
type ReadyReport struct {
	// RunID identifies this execution of the collector. A case runner
	// waits on it as well as on the ready flag: a file left behind by an
	// earlier run of the same case would otherwise report ready
	// immediately, and the workload would begin with no observation in
	// place at all.
	RunID       string               `json:"run_id"`
	GeneratedAt time.Time            `json:"generated_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
	RunKey      RunKey               `json:"run_key"`
	Sync        string               `json:"sync"`
	Ready       bool                 `json:"ready"`
	Targets     []TargetRegistration `json:"targets"`
	// AttachRunning lists the containers picked up by the start-time
	// enumeration, which is the other way a target enters the run and is
	// kept alongside registration rather than replacing it.
	AttachRunning []string `json:"attach_running,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

// SymlinkEntry is one symbolic link and the string it points at, recorded
// verbatim. A directory listing alone cannot reproduce a layout that links
// arbitrary paths together (a package manager that stores every real
// package once and links each dependency into place), so the link text is
// saved as well as the fact that the link exists.
type SymlinkEntry struct {
	Path string `json:"path"`
	// Target is the raw readlink result, relative or absolute as recorded.
	Target string `json:"target"`
	// Resolved is the link's destination resolved inside the container
	// root, empty when resolution failed (Error then says why).
	Resolved string `json:"resolved,omitempty"`
	Error    string `json:"error,omitempty"`
}

// PythonSearchDir is one directory Python distributions are installed
// into, together with how it was found. The derivation is recorded because
// the list cannot be obtained by asking the container's own interpreter
// without adding a process to the very process set being measured.
type PythonSearchDir struct {
	Path string `json:"path"`
	// Derivation is "filesystem_scan" (a directory named site-packages or
	// dist-packages found under a scanned root) or "observed_path" (a
	// directory inferred from a path some process actually mapped).
	Derivation string `json:"derivation"`
}

// DistInfoRecord is one installed Python distribution's file manifest, as
// recorded by the installer. The first column of each line is the file
// path, which the specification allows to be either relative to the
// directory holding the .dist-info or absolute, so both forms are stored
// exactly as written and normalized later.
type DistInfoRecord struct {
	// DistInfoDir is the "<name>-<version>.dist-info" directory's path
	// inside the container, MetadataPath the METADATA file in it (the path
	// a scan report names), and RecordPath the RECORD file this content
	// came from.
	DistInfoDir  string `json:"dist_info_dir"`
	MetadataPath string `json:"metadata_path"`
	RecordPath   string `json:"record_path"`
	SearchDir    string `json:"search_dir"`
	// Files are the first-column entries of RECORD, verbatim.
	Files []string `json:"files,omitempty"`
	// Truncated is set when the file list was cut short by the entry
	// limit, so a later lookup miss is not mistaken for "this
	// distribution does not own that file".
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// EggInfoDistribution is one installed Python distribution recorded in the
// older egg-info form, which has no RECORD file. It is listed so that a
// file under it can be reported as unmappable for a stated reason rather
// than as simply unowned.
type EggInfoDistribution struct {
	Dir       string `json:"dir"`
	SearchDir string `json:"search_dir"`
}

// ModuleDirListing is one language-package directory tree's layout: the
// paths under it, without file contents. It covers both node_modules trees
// and Python search directories, since the mapping rules for both need to
// know which directories exist and where each package's boundary is.
type ModuleDirListing struct {
	// Kind is "node_modules" or "python_search_dir".
	Kind string `json:"kind"`
	Root string `json:"root"`
	// Entries are paths inside the container, each with a trailing "/" if
	// it is a directory.
	Entries   []string `json:"entries,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// OwnedPathEntry is one path an operating-system package database says a
// package owns. The whole index is saved, not only the paths some process
// happened to touch, because a file first seen in an event after the
// sampling finished has no other way to be resolved from saved data.
type OwnedPathEntry struct {
	Path    string `json:"path"`
	DBKind  string `json:"db_kind"`
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
}

// AuxTruncation records one place where a bounded read stopped early, so
// every later lookup miss can be told apart from a genuine absence.
type AuxTruncation struct {
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	Limit  int    `json:"limit"`
	Reason string `json:"reason"`
}

// AuxiliaryInputs is everything the file-to-package mapping needs that the
// sampling itself does not produce, saved once per (mount view, database
// generation) so a re-run of the matching reads it instead of the
// container's filesystem — which by then may not exist.
type AuxiliaryInputs struct {
	MountViewID string `json:"mount_view_id"`
	// DBGeneration is the operating-system package database generation
	// this reading happened alongside, recorded for correlation only.
	//
	// AuxGeneration is this reading's own generation, computed from the
	// files it describes rather than from that database. The two change
	// independently: a package manager for a language installs and removes
	// packages without touching the operating system's database, and an
	// image with no such database at all still has module trees to
	// describe. Keying this reading on the database's generation would
	// miss the first and skip the second entirely.
	DBGeneration  string `json:"db_generation,omitempty"`
	AuxGeneration string `json:"aux_generation"`
	// FirstSeen and LastSeen bound the stretch of the window over which
	// this reading was the one in force, and SampleIDs names the samples
	// taken during it. An observation is resolved against the reading that
	// covers it, never against one taken of a different layout.
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	SampleIDs   []string  `json:"sample_ids,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	// ReadThroughPID is the process whose mount view the filesystem was
	// read through, and ReadThroughStarttime and ReadThroughMountView its
	// identity at the moment the read began. Everything in this reading
	// came through that process's view, so a process replaced while it was
	// being read makes the reading describe whatever replaced it.
	ReadThroughPID       int    `json:"read_through_pid,omitempty"`
	ReadThroughStarttime string `json:"read_through_starttime,omitempty"`
	ReadThroughMountView string `json:"read_through_mount_view,omitempty"`
	// Invalid is set when that identity did not hold through the read.
	// Such a reading is kept — it is a record of what happened — but it is
	// not used to resolve anything: the ownership and the link targets in
	// it may belong to a different container's filesystem.
	Invalid       bool   `json:"invalid,omitempty"`
	InvalidReason string `json:"invalid_reason,omitempty"`

	PythonSearchDirs []PythonSearchDir     `json:"python_search_dirs,omitempty"`
	DistInfoRecords  []DistInfoRecord      `json:"dist_info_records,omitempty"`
	EggInfoDists     []EggInfoDistribution `json:"egg_info_distributions,omitempty"`
	ModuleDirs       []ModuleDirListing    `json:"module_dirs,omitempty"`
	Symlinks         []SymlinkEntry        `json:"symlinks,omitempty"`

	// OwnedPaths is the operating-system package database's full
	// path-to-package index at this generation.
	OwnedPaths          []OwnedPathEntry `json:"owned_paths,omitempty"`
	OwnedPathsTruncated bool             `json:"owned_paths_truncated,omitempty"`

	// UsrMerge holds the top-level directory symlinks that make two
	// spellings of the same path (/lib/... and /usr/lib/...) name one
	// file, and Mountinfo the raw per-process mount table, which is what
	// says whether a path is backed by the image or by something mounted
	// over it.
	UsrMerge  []SymlinkEntry `json:"usr_merge,omitempty"`
	Mountinfo string         `json:"mountinfo,omitempty"`

	Truncations []AuxTruncation `json:"truncations,omitempty"`
	Errors      []string        `json:"errors,omitempty"`
}

// FDRecord is one open file descriptor's readlink target. Sockets are
// resolved to their inode elsewhere; this records the ordinary files,
// which is how a runtime that keeps an archive open for the life of the
// process can be observed at all.
type FDRecord struct {
	FD int `json:"fd"`
	// Path is the readlink target with any deleted marker removed, and
	// Deleted says whether that marker was present.
	Path     string `json:"path"`
	Deleted  bool   `json:"deleted"`
	Resolved string `json:"resolved,omitempty"`
	Error    string `json:"error,omitempty"`
}
