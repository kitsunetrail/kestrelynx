// Command kestrelynx, `sensor --probe` mode: a deployment-and-permission
// verification tool for the Sensor's observer half. It assembles the same
// startup sequence a real observer follows — raise the transient
// capabilities from file capability, set NO_NEW_PRIVS and non-dumpable,
// load and attach the eBPF programs, drop CAP_BPF/CAP_PERFMON, spawn the
// parser over a socketpair, install the observer's own seccomp filter, run
// the self-check — and then, instead of starting the real sampling loop,
// runs a battery of read and (narrowly scoped) write/connect/signal/exec
// probes against whatever containers it is told about, and reports the
// results as one JSON document.
//
// # Safety constraints (do not weaken without re-reading this comment)
//
//   - Every probe that writes, connects, signals, or executes something is
//     attempted ONLY against a process ID passed on the command line with
//     --target-pid, and only after verifyTarget confirms, at the moment
//     this process runs (not from a possibly-stale --inspect-json alone):
//     the container carries the "kestrelynx.probe-target=true" label, its
//     "kestrelynx.probe-run" label matches --run-id, the PID's *current*
//     /proc/<pid>/cgroup names that same container ID, and its starttime
//     agrees with --inspect-json's StartedAt. A PID that fails any of these
//     is refused outright and recorded as a configuration error; no unsafe
//     probe is attempted against it. This is a hard requirement, not a
//     default: there is no flag to bypass it.
//   - Once verified, every filesystem-shaped operation against that PID
//     (mem write, a write under its container root, the ioctl probe) goes
//     through the /proc/<pid> directory descriptor verifyTarget opened
//     (OpenRelativeRaw, or FD() for a path-only syscall) — never a freshly
//     formatted "/proc/<pid>/…" string — so a PID reused by an unrelated
//     process after verification cannot redirect these specific operations.
//     That guarantee does NOT extend to the handful of syscalls that only
//     take a bare pid_t (ptrace, process_vm_readv/writev, pidfd_open,
//     kill): there is no *at()-style form of those that resolves through an
//     already-open descriptor, so a reused PID between verification and the
//     call could in principle redirect them. This tool sidesteps that
//     limitation instead of merely mitigating it: those four probes are
//     never run against a --target-pid's own PID at all. They run against a
//     disposable, same-UID child THIS PROCESS spawns for exactly this
//     purpose (spawnSameUIDChild) and deliberately never reaps — see that
//     function's doc comment for why an unreaped process's PID cannot be
//     recycled out from under it for as long as this tool runs.
//   - Every other container this tool learns about from --inspect-json
//     (i.e. every container without that label, standing in for a real
//     production container) is only ever read from: exe, maps, fd, status,
//     cgroup, net/tcp, and a root-directory listing. Nothing is ever
//     written to, connected to, signaled, or executed for such a
//     container.
//   - The probes that touch process memory (mem write, process_vm_writev)
//     never write to an arbitrary offset: they resolve the target's own
//     "[heap]" mapping first and only ever write inside that range — a
//     region the target process itself allocated, not Sensor-chosen or
//     caller-chosen memory.
//   - This tool never restarts, stops, or signals any container's own
//     entrypoint process outside of the scoped probes above.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/parser"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/rootfs"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/sandbox"
)

// probeTargetLabel, probeRunLabel, and probeKindLabel are the Docker labels
// a verification container must carry for this tool to attempt any
// write/connect/signal/exec probe against one of its processes. See the
// package doc comment's safety constraints.
const (
	probeTargetLabel = "kestrelynx.probe-target"
	probeRunLabel    = "kestrelynx.probe-run"
	probeKindLabel   = "kestrelynx.probe-kind"
)

// starttimeTolerance bounds how far a target's current starttime (derived
// from its /proc/<pid>/stat at verification time) may differ from
// --inspect-json's State.StartedAt before verifyTarget refuses it. Wider
// than the ~2-second figure observed for a freshly started container,
// specifically because this is a security gate (refuse anything that does
// not plausibly match), not a data-quality measurement — a target that
// misses even this generous a window is far more likely to be a stale
// --inspect-json or a reused PID than measurement jitter.
const starttimeTolerance = 5 * time.Second

// pidListFlag collects repeated -target-pid flags into a slice.
type pidListFlag []int

func (p *pidListFlag) String() string {
	if p == nil {
		return ""
	}
	parts := make([]string, len(*p))
	for i, v := range *p {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}

func (p *pidListFlag) Set(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("invalid --target-pid %q: %w", s, err)
	}
	*p = append(*p, n)
	return nil
}

// runSensorCommand handles `kestrelynx sensor <args...>`. Only --probe is
// implemented today; any other invocation prints usage and exits non-zero
// without touching anything, so this never changes the behavior of the
// pre-existing default command (which main.go never routes here).
func runSensorCommand(args []string) {
	fs := flag.NewFlagSet("kestrelynx sensor", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), sensorUsage)
		fs.PrintDefaults()
	}

	probe := fs.Bool("probe", false, "run the deployment/permission verification probe and exit")
	out := fs.String("out", "-", "write the probe report JSON here (\"-\" for stdout)")
	inspectJSONPath := fs.String("inspect-json", "", "path to a JSON file holding `docker inspect` output for the containers to read (required with --probe)")
	listenEvents := fs.Duration("listen-events", 3*time.Second, "how long to sample eBPF ring buffer events after attaching, once startup finishes")
	watchdog := fs.Duration("watchdog", 120*time.Second, "force-exit the whole probe if it has not finished within this long, so a hang against a real host cannot run unbounded")
	runID := fs.String("run-id", "", "expected value of the "+probeRunLabel+" label on any --target-pid's own container; required whenever --target-pid is used, or every target is refused")
	simulateAttachFailure := fs.Bool("simulate-ebpf-attach-failure", false, "force a partial eBPF attach failure (a corrupted attach point) to verify clean unwind and continued operation without eBPF; changes only the eBPF load path, nothing else")
	parserChild := fs.Bool("probe-parser-child", false, "internal: this process is the probe's re-exec'd parser child; do not pass this directly")
	execChildTarget := fs.String("probe-exec-child-target", "", "internal: this process is a disposable exec-denial probe child; do not pass this directly")
	sameUIDChildFlag := fs.Bool("probe-sameuid-target-child", false, "internal: this process is the probe's disposable same-UID ptrace/process_vm/pidfd/kill target; do not pass this directly")
	var targetPIDs pidListFlag
	fs.Var(&targetPIDs, "target-pid", "a host PID to run write/connect/signal/exec probes against (repeatable). Must pass verifyTarget's checks against --inspect-json and --run-id, or the probe against it is refused")
	fs.Parse(args)

	if *execChildTarget != "" {
		runProbeExecChild(*execChildTarget)
		return
	}
	if *parserChild {
		runProbeParserChild()
		return
	}
	if *sameUIDChildFlag {
		runProbeSameUIDTargetChild()
		return
	}
	if !*probe {
		fmt.Fprintln(os.Stderr, "kestrelynx sensor: only --probe is implemented; see --help")
		os.Exit(2)
	}
	if *inspectJSONPath == "" {
		fmt.Fprintln(os.Stderr, "kestrelynx sensor --probe: --inspect-json is required")
		os.Exit(2)
	}

	// The report destination is opened here, before any of runProbe's
	// sensitive startup sequence runs (in particular, before the observer's
	// own seccomp filter is installed): that filter denies every new
	// write-flagged open unconditionally, so the evidence-file discipline
	// this tool mirrors — open the fd early, write into the already-open fd
	// late — applies to the report file too, not only the real Sensor's
	// evidence file.
	outFile, err := openReportDestination(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kestrelynx sensor --probe: open --out destination: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	// A whole-probe watchdog, independent of any single step's own
	// timeouts (SetReadDeadline on the ring buffer reader, the parser's
	// RequestTimeout, …): this process reads from and probes a real host,
	// so nothing here can be allowed to hang it indefinitely. os.Exit does
	// not run this function's own deferred handle.Close()/target
	// Handle.Close() calls, but that is not a permanent resource leak —
	// process exit itself releases every fd, map, program, and link the
	// kernel was holding open on this process's behalf.
	watchdogTimer := time.AfterFunc(*watchdog, func() {
		fmt.Fprintf(os.Stderr, "kestrelynx sensor --probe: exceeded --watchdog (%s); exiting\n", *watchdog)
		os.Exit(124)
	})
	defer watchdogTimer.Stop()

	report := runProbe(probeConfig{
		InspectJSONPath:           *inspectJSONPath,
		TargetPIDs:                targetPIDs,
		ListenEvents:              *listenEvents,
		RunID:                     *runID,
		SimulateEBPFAttachFailure: *simulateAttachFailure,
	})
	if err := writeReport(outFile, report); err != nil {
		fmt.Fprintf(os.Stderr, "kestrelynx sensor --probe: write report: %v\n", err)
		os.Exit(1)
	}
}

// openReportDestination opens path for writing, or returns os.Stdout for
// "-"/"". Callers must call this before running any part of the probe that
// installs the observer's own seccomp filter — see runSensorCommand's
// comment at its call site.
func openReportDestination(path string) (*os.File, error) {
	if path == "-" || path == "" {
		return os.Stdout, nil
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
}

const sensorUsage = `Usage: kestrelynx sensor --probe --inspect-json <file> --run-id <id> [--target-pid PID ...] [--out FILE]

Verifies the Sensor observer's deployment and permission boundary: raises
its transient capabilities, loads and attaches eBPF, drops CAP_BPF/
CAP_PERFMON, spawns the parser, installs its own seccomp filter, self-checks,
then probes reads against every container named in --inspect-json and,
ONLY for PIDs also passed via --target-pid, a set of write/connect/signal/
exec probes that must be denied.

Safety: --target-pid is refused for any PID that verifyTarget cannot
confirm, at the moment this process runs, is a container labeled
"kestrelynx.probe-target=true" with a "kestrelynx.probe-run" label matching
--run-id, whose current cgroup and starttime still agree with
--inspect-json. Every other container is only ever read from, never written
to, connected to, signaled, or executed against. See this command's source
for the full safety constraints.

`

// probeConfig is runProbe's input, gathered from flags.
type probeConfig struct {
	InspectJSONPath           string
	TargetPIDs                []int
	ListenEvents              time.Duration
	RunID                     string
	SimulateEBPFAttachFailure bool
}

// probeResult is one pass/fail outcome this tool records: a syscall or
// operation it attempted, what it expected, and what actually happened.
// Expected is always "denied" for a syscall this tool tries specifically
// because containment should deny it. Outcome is one of:
//
//	"denied"    the attempt returned EPERM/EACCES — the expected outcome
//	"allowed"   the attempt succeeded — Unexpected is always true for this
//	"error"     the attempt failed for a reason other than EPERM/EACCES,
//	            meaning the check itself could not run to a real verdict
//	"skipped"   this tool deliberately did not attempt the operation (e.g.
//	            a target's generation changed between verification and the
//	            operation, or the object to test against does not exist)
//
// Unexpected flags a mismatch worth a human's attention without stopping
// the run; it is never set for "error" or "skipped", which is why a
// summary must report their counts separately rather than treating
// "unexpected == 0" as "every probe behaved".
type probeResult struct {
	Name       string `json:"name"`
	Expected   string `json:"expected"` // "denied" or "success"
	Outcome    string `json:"outcome"`  // "denied", "allowed", "error", "skipped"
	Detail     string `json:"detail,omitempty"`
	Unexpected bool   `json:"unexpected"`
}

func denyResult(name string, err error) probeResult {
	r := probeResult{Name: name, Expected: "denied"}
	switch {
	case err == nil:
		r.Outcome, r.Unexpected = "allowed", true
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		r.Outcome = "denied"
		r.Detail = err.Error()
	default:
		r.Outcome = "error"
		r.Detail = err.Error()
	}
	return r
}

func fromSandboxProbe(p sandbox.Probe) probeResult {
	r := probeResult{Name: p.Name, Expected: "denied"}
	switch {
	case p.Err == nil:
		r.Outcome, r.Unexpected = "allowed", true
	case p.Denied():
		r.Outcome = "denied"
		r.Detail = p.Err.Error()
	default:
		r.Outcome = "error"
		r.Detail = p.Err.Error()
	}
	return r
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// resultCounts summarizes a []probeResult by Outcome, so a report's summary
// can distinguish "every probe was denied as expected" from "some probes
// could not be run at all" without a reader having to scan every entry.
type resultCounts struct {
	Denied     int `json:"denied"`
	Allowed    int `json:"allowed"` // == unexpected, for a "denied"-expected probe
	Error      int `json:"error"`
	Skipped    int `json:"skipped"`
	Unexpected int `json:"unexpected"`
}

func countResults(results []probeResult) resultCounts {
	var c resultCounts
	for _, r := range results {
		switch r.Outcome {
		case "denied":
			c.Denied++
		case "allowed":
			c.Allowed++
		case "error":
			c.Error++
		case "skipped":
			c.Skipped++
		}
		if r.Unexpected {
			c.Unexpected++
		}
	}
	return c
}

// capState is one capability's story across the probe run: whether the
// file capability's permitted bits held it at process start, whether
// raising it effective succeeded, and (for CAP_BPF/CAP_PERFMON only)
// whether it was confirmed gone after DropAll.
type capState struct {
	PermittedAtStart       bool   `json:"permitted_at_start"`
	RaisedEffective        bool   `json:"raised_effective"`
	Error                  string `json:"error,omitempty"`
	ConfirmedGoneAfterDrop *bool  `json:"confirmed_gone_after_drop,omitempty"`
}

// parserFDCheck reports whether the parser's own /proc/<pid>/fd/* was
// enumerated at all (Status), and if so, exactly what was found —
// InheritedCount is always present (0 is a meaningful, checked result, not
// the absence of one), distinguishing "checked and found none" from
// "could not check" the way an omitted or nil field cannot.
type parserFDCheck struct {
	Status         string   `json:"status"` // "ok" or "failed"
	Reason         string   `json:"reason,omitempty"`
	InheritedCount int      `json:"inherited_count"`
	Inherited      []string `json:"inherited,omitempty"`
}

type startupReport struct {
	Capabilities            map[string]*capState `json:"capabilities"`
	NoNewPrivsSet           bool                 `json:"no_new_privs_set"`
	NoNewPrivsError         string               `json:"no_new_privs_error,omitempty"`
	NonDumpableSet          bool                 `json:"non_dumpable_set"`
	NonDumpableError        string               `json:"non_dumpable_error,omitempty"`
	ParserPID               int                  `json:"parser_pid,omitempty"`
	ParserReport            *parser.Report       `json:"parser_report,omitempty"`
	ParserError             string               `json:"parser_error,omitempty"`
	ParserBPFFDCheck        parserFDCheck        `json:"parser_bpf_fd_check"`
	ObserverFilterInstalled bool                 `json:"observer_filter_installed"`
	ObserverFilterError     string               `json:"observer_filter_error,omitempty"`
}

type cgroupReport struct {
	CgroupV2 bool   `json:"cgroup_v2"`
	Path     string `json:"path,omitempty"`
	KernfsID uint64 `json:"kernfs_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

type landlockReport struct {
	KernelABI     int    `json:"kernel_abi"`
	KernelError   string `json:"kernel_error,omitempty"`
	ParserApplied bool   `json:"parser_applied"`
	ParserABI     int    `json:"parser_abi"`
}

type mapOpsReport struct {
	Lookup  string `json:"lookup"`
	Update  string `json:"update"`
	NextKey string `json:"next_key"`
	Delete  string `json:"delete"`
}

type sampledEvent struct {
	Kind     string `json:"kind"`
	CgroupID uint64 `json:"cgroup_id"`
	// Container is the verification container's own name, resolved from
	// CgroupID against the map runProbe builds from --inspect-json before
	// raising any capability (see cgroupKernfsIDForPID) — empty when
	// CgroupID belongs to a process outside every container this run knows
	// about (the host itself, or an unrelated container). This is what
	// makes an exec/mmap event from, say, the short-lived-exec verification
	// container directly attributable in the report, rather than only
	// identifiable by a bare numeric cgroup ID.
	Container                  string `json:"container,omitempty"`
	Dev                        string `json:"dev,omitempty"`
	Ino                        uint64 `json:"ino,omitempty"`
	Path                       string `json:"path,omitempty"`
	PathTruncated              bool   `json:"path_truncated,omitempty"`
	PathLooksContainerRelative bool   `json:"path_looks_container_relative,omitempty"`
}

type ebpfReport struct {
	Attempted bool   `json:"attempted"`
	Loaded    bool   `json:"loaded"`
	Error     string `json:"error,omitempty"`
	// Status and Reason use the same vocabulary the real Sensor's evidence
	// file uses for its own sensor.events fields (evidence.EventsStatus/
	// EventsReason): "ok", or "unavailable" with one of
	// kernel_unsupported/btf_missing/permission/attach_failed/cgroup_v1.
	// Populated by classifyEBPFStatus: a --variant no-bpf-caps run ends up
	// with reason "permission", and --simulate-ebpf-attach-failure ends up
	// with reason "attach_failed".
	Status                 evidence.EventsStatus `json:"status"`
	Reason                 evidence.EventsReason `json:"reason,omitempty"`
	BTFReadable            bool                  `json:"btf_readable"`
	SimulatedAttachFailure bool                  `json:"simulated_attach_failure,omitempty"`

	ExcludedCgroupIDWritten uint64 `json:"excluded_cgroup_id_written,omitempty"`
	// ExcludedCgroupIDReadBack and ExcludedCgroupMatchesDirInode compare the
	// map's value against an independent, freshly taken stat of the cgroup
	// directory (statCgroupDirInode, called again after Load, not the
	// KernfsID cgroupReport already cached from before Load) — so this is a
	// check against reality, not merely a map-write round-trip.
	ExcludedCgroupIDReadBack      uint64 `json:"excluded_cgroup_id_read_back,omitempty"`
	ExcludedCgroupMatchesDirInode bool   `json:"excluded_cgroup_matches_dir_inode"`

	// AttachedAt/ClosedAt/ConnectedSeconds record how long this run actually
	// held eBPF programs attached to the host, independent of
	// --listen-events (which only bounds the ring-buffer read loop, not the
	// time between a successful Load and the Close call at the end of
	// runProbe).
	AttachedAt       *time.Time `json:"attached_at,omitempty"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
	ConnectedSeconds *float64   `json:"connected_seconds,omitempty"`

	MapOpsAfterDrop *mapOpsReport  `json:"map_ops_after_drop,omitempty"`
	SampledEvents   []sampledEvent `json:"sampled_events,omitempty"`
	LostEvents      uint64         `json:"lost_events,omitempty"`
	LostEventsError string         `json:"lost_events_error,omitempty"`
}

type readResult struct {
	Outcome string `json:"outcome"` // ok, denied, gone, error
	Detail  string `json:"detail,omitempty"`
}

func classifyRead(err error) readResult {
	if err == nil {
		return readResult{Outcome: "ok"}
	}
	return readResult{Outcome: string(procfs.Classify(err)), Detail: err.Error()}
}

type containerReport struct {
	ContainerID          string   `json:"container_id"`
	Name                 string   `json:"name,omitempty"`
	PID                  int      `json:"pid"`
	ProbeTarget          bool     `json:"probe_target"`
	Unconfined           bool     `json:"unconfined"`
	Privileged           bool     `json:"privileged"`
	CgroupContainerID    string   `json:"cgroup_container_id,omitempty"`
	CgroupIDMatch        *bool    `json:"cgroup_id_match,omitempty"`
	StarttimeDiffSeconds *float64 `json:"starttime_diff_seconds,omitempty"`
	// CgroupDirInode is this container's cgroup directory's inode number,
	// obtained independently via cgroupKernfsIDForPID/statCgroupDirInode —
	// not derived from any eBPF event. EventsCgroupIDConfirmed is set once
	// eBPF sampling has run: true only if at least one sampled event's own
	// CgroupID (the value bpf_get_current_cgroup_id() returned inside the
	// kernel for a real process in this container) equals CgroupDirInode
	// exactly — a direct comparison between what the kernel's BPF program
	// reported and an independently stat'd directory, not a map write
	// read back to itself.
	CgroupDirInode          uint64                `json:"cgroup_dir_inode,omitempty"`
	EventsCgroupIDConfirmed *bool                 `json:"events_cgroup_id_confirmed,omitempty"`
	Reads                   map[string]readResult `json:"reads"`
}

type probeReport struct {
	GeneratedAt      time.Time                `json:"generated_at"`
	Startup          startupReport            `json:"startup"`
	SelfCheck        *sandbox.SelfCheckReport `json:"self_check,omitempty"`
	SelfCheckError   string                   `json:"self_check_error,omitempty"`
	Landlock         landlockReport           `json:"landlock"`
	Cgroup           cgroupReport             `json:"cgroup"`
	EBPF             ebpfReport               `json:"ebpf"`
	DeniedOps        []probeResult            `json:"denied_ops"`
	DeniedOpsSummary resultCounts             `json:"denied_ops_summary"`
	Containers       []containerReport        `json:"containers"`
	UnsafeOps        []probeResult            `json:"unsafe_ops,omitempty"`
	UnsafeOpsSummary resultCounts             `json:"unsafe_ops_summary"`
	ConfigErrors     []string                 `json:"config_errors,omitempty"`
	Warnings         []string                 `json:"warnings,omitempty"`
}

// dockerInspectEntry is the subset of `docker inspect` output this tool
// reads. It is intentionally not internal/docker.InspectResult: this tool
// has no Docker socket (the Sensor never does; Docker API access stays with
// the main body) and instead reads `docker inspect`'s own JSON, captured
// ahead of time by run-probe.sh and handed in as a file.
type dockerInspectEntry struct {
	Id    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		SecurityOpt []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (e dockerInspectEntry) isProbeTarget() bool {
	return e.Config.Labels[probeTargetLabel] == "true"
}

// runID returns the container's kestrelynx.probe-run label, empty if unset.
func (e dockerInspectEntry) runID() string { return e.Config.Labels[probeRunLabel] }

// kind returns the container's kestrelynx.probe-kind label (e.g. "sameuid",
// "sockets", "setuid", "ext4vol"), which decides which unsafe probes, if
// any, apply to it — see runUnsafeOpsForTarget.
func (e dockerInspectEntry) kind() string { return e.Config.Labels[probeKindLabel] }

func (e dockerInspectEntry) isUnconfined() bool {
	if e.HostConfig.Privileged {
		return true
	}
	for _, opt := range e.HostConfig.SecurityOpt {
		if strings.TrimSpace(opt) == "apparmor=unconfined" {
			return true
		}
	}
	return false
}

func loadInspectEntries(path string) ([]dockerInspectEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var entries []dockerInspectEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return entries, nil
}

// writeReport marshals report and writes it into f, which the caller must
// already have open (see openReportDestination and runSensorCommand's call
// site): this function never opens, creates, or truncates anything itself,
// since a write-flagged open attempted this late would be denied by the
// observer's own seccomp filter once installed.
func writeReport(f *os.File, report probeReport) error {
	report.DeniedOpsSummary = countResults(report.DeniedOps)
	report.UnsafeOpsSummary = countResults(report.UnsafeOps)

	enc, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	enc = append(enc, '\n')
	if _, err := f.Write(enc); err != nil {
		return err
	}
	if f == os.Stdout {
		return nil
	}
	if err := f.Truncate(int64(len(enc))); err != nil {
		return err
	}
	return f.Sync()
}

// verifiedTarget is one --target-pid that verifyTarget has confirmed, at
// the moment this process is running, belongs to a genuine verification
// container matching --run-id — see the package doc comment's safety
// constraints. Handle is the /proc/<pid> directory descriptor verifyTarget
// opened to perform that check; every further operation against this
// target should resolve through Handle (via OpenRelativeRaw, or FD() for a
// path-only syscall like connect(2)) rather than a freshly formatted
// "/proc/<pid>/…" string, so a PID reused by an unrelated process after
// verification cannot redirect it. Callers must close Handle when done.
type verifiedTarget struct {
	Kind        string
	PID         int
	ContainerID string
	Handle      *procfs.Handle
}

// verifyTarget re-derives, right now, everything that must be true before
// any write/connect/signal/exec probe may run against pid: the container's
// labels, its current cgroup membership, and its starttime — never trusting
// --inspect-json's snapshot alone. See the package doc comment's safety
// constraints for why each check exists.
func verifyTarget(pid int, e dockerInspectEntry, wantRunID string) (verifiedTarget, error) {
	if !e.isProbeTarget() {
		return verifiedTarget{}, fmt.Errorf("container not labeled %s=true", probeTargetLabel)
	}
	if wantRunID == "" {
		return verifiedTarget{}, fmt.Errorf("--run-id not provided; refusing to trust any target")
	}
	if e.runID() != wantRunID {
		return verifiedTarget{}, fmt.Errorf("container's %s label (%q) does not match --run-id (%q)", probeRunLabel, e.runID(), wantRunID)
	}

	h, err := procfs.Open(pid)
	if err != nil {
		return verifiedTarget{}, fmt.Errorf("open /proc/%d: %w", pid, err)
	}

	cid, ok, err := h.ContainerID()
	if err != nil {
		h.Close()
		return verifiedTarget{}, fmt.Errorf("read current cgroup: %w", err)
	}
	if !ok || cid != e.Id {
		h.Close()
		return verifiedTarget{}, fmt.Errorf("current cgroup names container %q (found=%v), --inspect-json says %q", cid, ok, e.Id)
	}

	// StartedAt is never optional for this check: an empty value is refused
	// outright rather than treated as "nothing to compare", since skipping
	// the starttime cross-check for a container missing that field would
	// weaken the same PID-reuse/wrong-generation protection this check
	// exists for, silently, for exactly the inputs that most need it.
	if e.State.StartedAt == "" {
		h.Close()
		return verifiedTarget{}, fmt.Errorf("--inspect-json has no State.StartedAt for this container; refusing to skip the starttime check")
	}
	startedAt, perr := time.Parse(time.RFC3339Nano, e.State.StartedAt)
	if perr != nil {
		h.Close()
		return verifiedTarget{}, fmt.Errorf("parse --inspect-json StartedAt: %w", perr)
	}
	wall, werr := starttimeToWall(h.Starttime())
	if werr != nil {
		h.Close()
		return verifiedTarget{}, fmt.Errorf("resolve current starttime: %w", werr)
	}
	if diff := wall.Sub(startedAt); diff < -starttimeTolerance || diff > starttimeTolerance {
		h.Close()
		return verifiedTarget{}, fmt.Errorf("current starttime differs from --inspect-json StartedAt by %s (tolerance %s)", diff, starttimeTolerance)
	}

	return verifiedTarget{Kind: e.kind(), PID: pid, ContainerID: e.Id, Handle: h}, nil
}

// runProbe assembles the observer's startup sequence (raise capabilities,
// NNP + non-dumpable, load eBPF, drop CAP_BPF/CAP_PERFMON, spawn the
// parser, install the observer's own filter, self-check) using the same
// internal/sensor/{sandbox,ebpf,parser} building blocks a real observer
// uses, then runs the read/denied-op/unsafe-op probes and returns the
// assembled report. It never calls os.Exit or log.Fatal: every unexpected
// failure is recorded in the report and the run continues, per this
// command's job of reporting reality rather than asserting it. (The
// whole-probe watchdog that does call os.Exit lives one level up, in
// runSensorCommand, precisely so it is independent of anything in here.)
func runProbe(cfg probeConfig) probeReport {
	report := probeReport{GeneratedAt: time.Now().UTC()}

	entries, err := loadInspectEntries(cfg.InspectJSONPath)
	if err != nil {
		report.ConfigErrors = append(report.ConfigErrors, err.Error())
	}
	byPID := map[int]dockerInspectEntry{}
	for _, e := range entries {
		if e.State.Pid > 0 {
			byPID[e.State.Pid] = e
		}
	}

	// Verified once, up front, before any capability is raised (verifyTarget
	// needs none: reading /proc/<pid>/cgroup and /proc/<pid>/stat requires
	// no privilege). Every unsafe probe below is gated on this list, never
	// on cfg.TargetPIDs directly, and only ever resolves the target through
	// the retained Handle each entry carries.
	var verifiedTargets []verifiedTarget
	seenTarget := map[int]bool{}
	for _, pid := range cfg.TargetPIDs {
		if seenTarget[pid] {
			continue
		}
		seenTarget[pid] = true
		e, ok := byPID[pid]
		if !ok {
			report.ConfigErrors = append(report.ConfigErrors, fmt.Sprintf(
				"--target-pid %d refused: not present in --inspect-json", pid))
			continue
		}
		vt, verr := verifyTarget(pid, e, cfg.RunID)
		if verr != nil {
			report.ConfigErrors = append(report.ConfigErrors, fmt.Sprintf(
				"--target-pid %d refused: %v; no unsafe probe attempted", pid, verr))
			continue
		}
		verifiedTargets = append(verifiedTargets, vt)
	}
	defer func() {
		for _, vt := range verifiedTargets {
			vt.Handle.Close()
		}
	}()

	// Built before any capability is raised, same as verifyTarget above:
	// reading /proc/<pid>/cgroup needs none (see cgroupKernfsIDForPID), so
	// this map is available for tagging sampled eBPF events with a
	// container name however early in startup an event happens to be
	// captured. Best-effort: a container whose cgroup ID could not be
	// resolved is simply absent from the map, and its events show no
	// Container in the report rather than failing the run.
	cgroupIDToName := map[uint64]string{}
	nameToInode := map[string]uint64{}
	for _, e := range entries {
		if e.State.Pid <= 0 {
			continue
		}
		if id, err := cgroupKernfsIDForPID(e.State.Pid); err == nil && id != 0 {
			name := strings.TrimPrefix(e.Name, "/")
			cgroupIDToName[id] = name
			nameToInode[name] = id
		}
	}

	// --- 1. Raise the observer's transient capabilities from the file
	// capability's permitted set, one at a time (so one missing capability
	// does not block the others from being reported individually).
	capNames := []struct {
		name string
		num  uintptr
	}{
		{"CAP_SYS_PTRACE", unix.CAP_SYS_PTRACE},
		{"CAP_DAC_READ_SEARCH", unix.CAP_DAC_READ_SEARCH},
		{"CAP_BPF", unix.CAP_BPF},
		{"CAP_PERFMON", unix.CAP_PERFMON},
	}
	report.Startup.Capabilities = map[string]*capState{}
	startStatuses, statErr := sandbox.ReadTaskStatuses(os.Getpid())
	var permittedAtStart uint64
	if statErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("read own task status at start: %v", statErr))
	} else if len(startStatuses) > 0 {
		permittedAtStart = startStatuses[0].CapPermitted
	}
	for _, c := range capNames {
		cs := &capState{PermittedAtStart: permittedAtStart&(1<<c.num) != 0}
		if err := sandbox.RaiseEffective(c.num); err != nil {
			cs.Error = err.Error()
		} else {
			cs.RaisedEffective = true
		}
		report.Startup.Capabilities[c.name] = cs
	}

	// --- 2. NO_NEW_PRIVS + non-dumpable, on every thread, before anything
	// touches untrusted input.
	if err := sandbox.SetNoNewPrivsAll(); err != nil {
		report.Startup.NoNewPrivsError = err.Error()
	} else {
		report.Startup.NoNewPrivsSet = true
	}
	if err := sandbox.SetNonDumpable(); err != nil {
		report.Startup.NonDumpableError = err.Error()
	} else {
		report.Startup.NonDumpableSet = true
	}

	// --- 3. Determine this process's own cgroup ID (needed both for the
	// eBPF self-exclusion map and for the cgroup-ID/inode cross-check).
	cgRep, cgID, cgErr := ownCgroupInfo()
	report.Cgroup = cgRep

	// --- 4. Load and attach eBPF, before dropping CAP_BPF/CAP_PERFMON.
	report.EBPF.Attempted = true
	report.EBPF.SimulatedAttachFailure = cfg.SimulateEBPFAttachFailure
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		report.EBPF.BTFReadable = true
	} else {
		report.Warnings = append(report.Warnings, fmt.Sprintf("BTF not readable: %v", err))
	}
	var handle *ebpf.Handle
	var loadErr error
	if cgErr != nil {
		loadErr = cgErr
		report.EBPF.Error = fmt.Sprintf("cgroup id unavailable: %v", cgErr)
	} else {
		var h *ebpf.Handle
		var err error
		if cfg.SimulateEBPFAttachFailure {
			h, err = ebpf.LoadForFaultInjectionTest(cgID)
		} else {
			h, err = ebpf.Load(cgID)
		}
		loadErr = err
		if err != nil {
			report.EBPF.Error = err.Error()
		} else {
			handle = h
			attachedAt := time.Now()
			report.EBPF.AttachedAt = &attachedAt
			report.EBPF.Loaded = true
			report.EBPF.ExcludedCgroupIDWritten = cgID
			if got, err := h.ExcludedCgroupID(); err != nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("read back excluded cgroup id: %v", err))
			} else {
				report.EBPF.ExcludedCgroupIDReadBack = got
				// Independent of the value just written/read back: a fresh
				// stat of the cgroup directory, not the KernfsID cgRep
				// already cached from before Load — see ebpfReport's doc
				// comment on these two fields for why that distinction
				// matters.
				if freshIno, ferr := statCgroupDirInode(cgRep.Path); ferr != nil {
					report.Warnings = append(report.Warnings, fmt.Sprintf("independent cgroup inode re-stat: %v", ferr))
				} else {
					report.EBPF.ExcludedCgroupMatchesDirInode = got == freshIno
				}
			}
		}
	}
	report.EBPF.Status, report.EBPF.Reason = classifyEBPFStatus(
		cgErr, report.EBPF.BTFReadable,
		report.Startup.Capabilities["CAP_BPF"].RaisedEffective,
		report.Startup.Capabilities["CAP_PERFMON"].RaisedEffective,
		loadErr)

	// --- 5. Drop CAP_BPF/CAP_PERFMON unconditionally, whether or not eBPF
	// actually loaded.
	if err := sandbox.DropAll(unix.CAP_BPF, unix.CAP_PERFMON); err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("drop CAP_BPF/CAP_PERFMON: %v", err))
	}
	if hasAny, err := sandbox.EffectiveHasAny(unix.CAP_BPF, unix.CAP_PERFMON); err == nil {
		gone := !hasAny
		report.Startup.Capabilities["CAP_BPF"].ConfirmedGoneAfterDrop = &gone
		report.Startup.Capabilities["CAP_PERFMON"].ConfirmedGoneAfterDrop = &gone
	}

	// --- 6. Spawn the parser over a socketpair, and run the two unsafe
	// self-check probes in a disposable child — both are execve from this
	// process's point of view, so both must happen before the observer's
	// own filter (which denies execve unconditionally) is installed.
	parserPID, parserReport, parserErr := spawnProbeParser()
	if parserErr != nil {
		report.Startup.ParserError = parserErr.Error()
	} else {
		report.Startup.ParserPID = parserPID
		report.Startup.ParserReport = &parserReport
	}
	report.Startup.ParserBPFFDCheck = checkParserBPFFDs(parserPID)

	unsafeSelfProbes, unsafeErr := sandbox.RunUnsafeProbesInSubprocess()
	if unsafeErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("RunUnsafeProbesInSubprocess: %v", unsafeErr))
	}

	// Spawning this is also an execve, so it must happen here too — see
	// spawnSameUIDChild's own doc comment for what it is and why the
	// bare-pid_t probes (ptrace/process_vm_*/pidfd/kill) target it rather
	// than any --target-pid's own container process.
	sameUID, sameUIDErr := spawnSameUIDChild()
	if sameUIDErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("spawnSameUIDChild: %v", sameUIDErr))
	}

	// Every exec-based probe (both the generic "own image" ones and the
	// setuid-file one, run only against a target actually labeled
	// kestrelynx.probe-kind=setuid) must also run here, before the filter:
	// once installed, ObserverFilter denies execve unconditionally, which
	// means this process itself can no longer fork/exec the disposable
	// child a probe like this needs (see runProbeExecChild's doc comment).
	report.DeniedOps = append(report.DeniedOps, tryExecOwnImageBinary("/usr/local/bin/trivy"))
	report.DeniedOps = append(report.DeniedOps, tryExecOwnImageBinary("/bin/sh"))
	report.DeniedOps = append(report.DeniedOps, probeOpenByHandleAtWrite())
	for _, vt := range verifiedTargets {
		if vt.Kind == "setuid" {
			report.UnsafeOps = append(report.UnsafeOps, tryExecSetuidInTarget(vt))
		}
	}

	// --- 7. Install the observer's own seccomp filter.
	selfPID := int32(os.Getpid())
	filter, err := sandbox.ObserverFilter(selfPID)
	if err != nil {
		report.Startup.ObserverFilterError = err.Error()
	} else if err := sandbox.InstallFilter(filter); err != nil {
		report.Startup.ObserverFilterError = err.Error()
	} else {
		report.Startup.ObserverFilterInstalled = true
	}

	// --- 8. Self-check.
	report.Landlock.KernelABI, err = sandbox.DetectLandlockABI()
	if err != nil {
		report.Landlock.KernelError = err.Error()
	}
	if parserErr == nil {
		report.Landlock.ParserApplied = parserReport.LandlockApplied
		report.Landlock.ParserABI = parserReport.LandlockABI
	}

	scReport, scErr := sandbox.RunObserverSelfCheck(sandbox.ObserverSelfCheckInput{
		ParserPID:    parserPID,
		GuardedCaps:  []uintptr{unix.CAP_BPF, unix.CAP_PERFMON},
		UnsafeProbes: unsafeSelfProbes,
	})
	if scErr != nil {
		report.SelfCheckError = scErr.Error()
	} else {
		report.SelfCheck = &scReport
	}

	// --- 9. Denied-op probes: generic operations that must fail no matter
	// which container (if any) is involved. Self-contained: only ever
	// touches this process and this container's own filesystem/image.
	for _, p := range sandbox.RunProbes() {
		report.DeniedOps = append(report.DeniedOps, fromSandboxProbe(p))
	}
	for _, p := range sandbox.RunBPFCmdProbes() {
		report.DeniedOps = append(report.DeniedOps, fromSandboxProbe(p))
	}
	report.DeniedOps = append(report.DeniedOps, tryWriteOwnFilesystem())
	if sameUIDErr == nil {
		report.DeniedOps = append(report.DeniedOps,
			trySignal(sameUID),
			tryPtraceAttach(sameUID),
			tryProcessVMReadv(sameUID),
			tryProcessVMWritev(sameUID),
			tryPidfdGetfd(sameUID),
		)
	}

	// --- eBPF map ops and event sampling, after the drop and the final
	// filter are both in place.
	if handle != nil {
		ops := handle.ProbeMapOps()
		report.EBPF.MapOpsAfterDrop = &mapOpsReport{
			Lookup:  errString(ops.Lookup),
			Update:  errString(ops.Update),
			NextKey: errString(ops.NextKey),
			Delete:  errString(ops.Delete),
		}
		if cfg.ListenEvents > 0 {
			sampleEvents(handle, cfg.ListenEvents, &report.EBPF, cgroupIDToName)
		}
		if lost, err := handle.LostEvents(); err != nil {
			report.EBPF.LostEventsError = err.Error()
		} else {
			report.EBPF.LostEvents = lost
		}
	}

	// --- 10. Container reads (every entry) and, only for verified targets,
	// the remaining (non-exec) unsafe ops appropriate to that target's kind.
	for _, e := range entries {
		report.Containers = append(report.Containers, readContainer(e))
	}

	// Direct cgroup-ID cross-check: for each container whose cgroup
	// directory inode is known (nameToInode, resolved independently of
	// eBPF), record whether any sampled event's own CgroupID — the value
	// bpf_get_current_cgroup_id() returned inside the kernel for a real
	// process in that container — equals it exactly. This runs after
	// sampleEvents (above) so report.EBPF.SampledEvents is already final.
	cgroupIDSeenInEvents := map[uint64]bool{}
	for _, ev := range report.EBPF.SampledEvents {
		if ev.Container != "" {
			cgroupIDSeenInEvents[ev.CgroupID] = true
		}
	}
	for i := range report.Containers {
		cr := &report.Containers[i]
		inode, ok := nameToInode[cr.Name]
		if !ok {
			continue
		}
		cr.CgroupDirInode = inode
		confirmed := cgroupIDSeenInEvents[inode]
		cr.EventsCgroupIDConfirmed = &confirmed
	}

	for _, vt := range verifiedTargets {
		ops, cerr := runUnsafeOpsForTarget(vt)
		report.UnsafeOps = append(report.UnsafeOps, ops...)
		if cerr != "" {
			report.ConfigErrors = append(report.ConfigErrors, cerr)
		}
	}

	if handle != nil {
		if err := handle.Close(); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("close ebpf handle: %v", err))
		}
		closedAt := time.Now()
		report.EBPF.ClosedAt = &closedAt
		if report.EBPF.AttachedAt != nil {
			d := closedAt.Sub(*report.EBPF.AttachedAt).Seconds()
			report.EBPF.ConnectedSeconds = &d
		}
	}

	return report
}

// runUnsafeOpsForTarget dispatches the write/connect/signal probes
// appropriate to vt's kind (its kestrelynx.probe-kind label, captured at
// verification time): each of the four verification-container kinds
// deploy/docker/probe-targets.sh creates is equipped for a different probe,
// and this only ever runs the probe(s) that target is actually equipped
// for — e.g. the exec-a-setuid-file probe only ever runs against the one
// container that actually has a setuid file (handled separately, in
// runProbe's pre-filter phase, by tryExecSetuidInTarget). A kind this
// function does not recognize runs no unsafe probe at all and is reported
// as a configuration error instead of silently doing nothing.
func runUnsafeOpsForTarget(vt verifiedTarget) (ops []probeResult, configError string) {
	switch vt.Kind {
	case "sameuid":
		// The bare-pid_t probes (ptrace/process_vm_*/pidfd/kill) do not run
		// here at all: they target a disposable same-UID child this tool
		// spawns itself (spawnSameUIDChild), not this container's own
		// process — see that function's doc comment and the package doc
		// comment's safety constraints for why. Only the fd-based mem-write
		// probe, which stays bound to this exact verified process via its
		// retained directory descriptor, runs against the container itself.
		return []probeResult{tryMemWrite(vt)}, ""
	case "sockets":
		return []probeResult{
			tryRootWrite(vt),
			tryUnixConnect(vt, "stream"),
			tryUnixConnect(vt, "dgram"),
			trySocketDgramSendto(vt),
		}, ""
	case "ext4vol":
		return []probeResult{tryIoctlSetFlags(vt)}, ""
	case "setuid":
		// The exec probe for this kind already ran in runProbe's
		// pre-filter phase (see tryExecSetuidInTarget's own doc comment
		// for why it cannot run here, after the filter is installed).
		return nil, ""
	default:
		return nil, fmt.Sprintf(
			"--target-pid %d refused: unrecognized or missing %s label %q; no unsafe probe attempted", vt.PID, probeKindLabel, vt.Kind)
	}
}

// ownCgroupInfo determines this process's own cgroup v2 path and the
// kernfs (directory inode) ID that identifies it — the same ID
// bpf_get_current_cgroup_id() returns for a process in that cgroup — by
// reading /proc/self/cgroup and stat'ing the corresponding directory under
// /sys/fs/cgroup (host-visible when the Sensor container runs with
// `cgroup: host`, and simply the host's own tree otherwise).
func ownCgroupInfo() (cgroupReport, uint64, error) {
	var stfs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &stfs); err != nil {
		err = fmt.Errorf("statfs /sys/fs/cgroup: %w", err)
		return cgroupReport{Error: err.Error()}, 0, err
	}
	if int64(stfs.Type) != int64(unix.CGROUP2_SUPER_MAGIC) {
		err := fmt.Errorf("cgroup_v1: /sys/fs/cgroup is not cgroup2 (statfs type %#x)", stfs.Type)
		return cgroupReport{CgroupV2: false, Error: err.Error()}, 0, err
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		err = fmt.Errorf("read /proc/self/cgroup: %w", err)
		return cgroupReport{CgroupV2: true, Error: err.Error()}, 0, err
	}
	line := strings.TrimSpace(string(data))
	rel, ok := strings.CutPrefix(line, "0::")
	if !ok {
		err := fmt.Errorf("unexpected /proc/self/cgroup content (not a single cgroup-v2 line): %q", line)
		return cgroupReport{CgroupV2: true, Error: err.Error()}, 0, err
	}
	ino, err := statCgroupDirInode(rel)
	if err != nil {
		return cgroupReport{CgroupV2: true, Path: rel, Error: err.Error()}, 0, err
	}
	return cgroupReport{CgroupV2: true, Path: rel, KernfsID: ino}, ino, nil
}

// statCgroupDirInode stats /sys/fs/cgroup/<relPath> and returns its inode
// number, freshly, every time it is called — used both by ownCgroupInfo at
// startup and, called a second time later with the same relPath, as the
// independent check ebpfReport's ExcludedCgroupMatchesDirInode field
// documents: a second, later stat is what makes that check a comparison
// against reality rather than only a map read-back of a value this process
// wrote to the map itself.
func statCgroupDirInode(relPath string) (uint64, error) {
	full := filepath.Join("/sys/fs/cgroup", relPath)
	var st unix.Stat_t
	if err := unix.Stat(full, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", full, err)
	}
	return st.Ino, nil
}

// classifyEBPFStatus turns the individual failure points of the eBPF
// load/attach attempt into the same (status, reason) vocabulary the real
// Sensor's evidence file uses for sensor.events, so a probe run without
// CAP_BPF/CAP_PERFMON in the container's bounding set (a --variant
// no-bpf-caps run) reports the same thing a real, permission-limited
// deployment would: EventsUnavailable with reason "permission", not a bare
// error string. Checked in this order because an earlier failure explains
// a later one (no cgroup ID means Load was never even attempted with a
// real value; missing BTF means Load could not have succeeded regardless
// of capabilities; missing capabilities explain a Load failure that would
// otherwise look like an unexplained attach failure; --simulate-ebpf
// -attach-failure, with capabilities and BTF both fine, falls through to
// the final attach_failed case).
func classifyEBPFStatus(cgErr error, btfReadable, capBPFRaised, capPERFMONRaised bool, loadErr error) (evidence.EventsStatus, evidence.EventsReason) {
	switch {
	case cgErr != nil && strings.HasPrefix(cgErr.Error(), "cgroup_v1:"):
		return evidence.EventsUnavailable, evidence.EventsReasonCgroupV1
	case cgErr != nil:
		return evidence.EventsUnavailable, evidence.EventsReasonAttachFailed
	case !btfReadable:
		return evidence.EventsUnavailable, evidence.EventsReasonBTFMissing
	case !capBPFRaised || !capPERFMONRaised:
		return evidence.EventsUnavailable, evidence.EventsReasonPermission
	case loadErr != nil:
		return evidence.EventsUnavailable, evidence.EventsReasonAttachFailed
	default:
		return evidence.EventsOK, evidence.EventsReasonNone
	}
}

// cgroupKernfsIDForPID resolves an arbitrary process's cgroup v2 kernfs ID
// the same way ownCgroupInfo resolves this process's own — reading
// /proc/<pid>/cgroup (world-readable, no ptrace check: see the read
// contract's own table for exactly which procfs entries have none) and
// stat'ing the corresponding directory under /sys/fs/cgroup. Used to build
// the cgroup-ID-to-container-name map runProbe uses to attribute a sampled
// eBPF event to one of the containers named in --inspect-json.
func cgroupKernfsIDForPID(pid int) (uint64, error) {
	h, err := procfs.Open(pid)
	if err != nil {
		return 0, err
	}
	defer h.Close()
	data, err := h.Cgroup()
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(data))
	rel, ok := strings.CutPrefix(line, "0::")
	if !ok {
		return 0, fmt.Errorf("pid %d: unexpected /proc/%d/cgroup content (not a single cgroup-v2 line): %q", pid, pid, line)
	}
	return statCgroupDirInode(rel)
}

// plainParserBinary returns the path to the parser's own executable: the
// same source and build as this process, but never a file that carries the
// observer's file capability. In the deployed image, this process runs as
// /usr/local/bin/kestrelynx-sensor (the setcap copy) and the parser must
// instead exec /usr/local/bin/kestrelynx (the plain copy in the same
// directory, with no security.capability xattr at all) — spawning the
// parser from the setcap'd binary would give it CAP_SYS_PTRACE/
// CAP_DAC_READ_SEARCH/CAP_BPF/CAP_PERFMON in its own permitted set purely
// from the file it exec'd, defeating the goal of a parser with no
// capability at all, even though those bits would stay out of its
// effective set until something raised them. Outside that image (e.g. a
// local, non-setcap build under test), this process's own executable has
// no capability either way, so it is used as-is.
func plainParserBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir, base := filepath.Split(exe)
	if base == "kestrelynx-sensor" {
		return filepath.Join(dir, "kestrelynx"), nil
	}
	return exe, nil
}

// spawnProbeParser starts a fresh copy of this same binary as
// `kestrelynx sensor --probe-parser-child` over a SOCK_SEQPACKET
// socketpair, exactly the way a real observer spawns its parser, and waits
// for its self-check Report.
func spawnProbeParser() (pid int, report parser.Report, err error) {
	exe, err := plainParserBinary()
	if err != nil {
		return 0, parser.Report{}, fmt.Errorf("locate plain (capability-less) executable: %w", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, parser.Report{}, fmt.Errorf("socketpair: %w", err)
	}
	parentFD := fds[0]
	childFile := os.NewFile(uintptr(fds[1]), "sensor-probe-parser-sock")

	cmd := exec.Command(exe, "sensor", "--probe-parser-child")
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		unix.Close(parentFD)
		childFile.Close()
		return 0, parser.Report{}, fmt.Errorf("start parser child: %w", err)
	}
	childFile.Close()

	report, rerr := parser.ReadReport(parentFD)
	if rerr != nil {
		return cmd.Process.Pid, parser.Report{}, fmt.Errorf("read parser report: %w", rerr)
	}
	return cmd.Process.Pid, report, nil
}

// runProbeParserChild is the entry point for a re-exec'd
// `kestrelynx sensor --probe-parser-child` process: it applies the real
// parser's lockdown (via parser.Run -> parser.LockDown) and then idles,
// serving no real requests (the deployment/permission verification this
// tool performs does not require a real package-database round trip; it
// only needs a genuine, separately-locked-down parser process to check the
// observer's self-check and fd-inheritance behavior against).
func runProbeParserChild() {
	cfg := parser.Config{
		SocketFD:    3,
		Handler:     probeNoopHandler{},
		MaxLifetime: 60 * time.Second,
	}
	if err := parser.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "kestrelynx sensor --probe-parser-child: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

type probeNoopHandler struct{}

func (probeNoopHandler) Handle(kind string, fd int) (json.RawMessage, error) {
	return json.RawMessage(`{"ok":true}`), nil
}

// sameUIDChild is a disposable, same-UID process this tool spawns for the
// ptrace/process_vm_readv/process_vm_writev/pidfd_getfd/kill probes to run
// against — see spawnSameUIDChild's doc comment for why these five probes
// target this instead of a --target-pid's own container process.
type sameUIDChild struct {
	PID  int
	Addr uintptr
	Len  int
}

// sameUIDChildLifeline holds the write end of spawnSameUIDChild's lifeline
// pipe open for the rest of this process's own lifetime. Deliberately never
// closed anywhere in this file — see spawnSameUIDChild's doc comment for
// what that closes automatically, and when.
var sameUIDChildLifeline *os.File

// spawnSameUIDChild starts a fresh copy of this same binary as
// `kestrelynx sensor --probe-sameuid-target-child`, over a pipe it reports
// its own PID and the address/length of a buffer it allocated for exactly
// this purpose back on, and then never reaps (never calls cmd.Wait()).
//
// The five bare-pid_t probes (ptrace, process_vm_readv, process_vm_writev,
// pidfd_open+pidfd_getfd, kill) have no *at()-style form that resolves
// through an already-open descriptor the way OpenRelativeRaw does for
// filesystem operations — a PID reused by an unrelated process between
// verification and the syscall could redirect them. Rather than merely
// narrowing that window (a Recheck() immediately before the syscall was
// tried and found insufficient: the window between Recheck and the syscall
// itself is still a real race), this tool removes the target from anyone
// else's control entirely: a process whose exit this tool deliberately
// never waits for remains a zombie, still holding its PID, for as long as
// this tool's own process is alive to not-wait for it — the kernel does
// not recycle a PID out from under an unreaped zombie. That is what makes
// it safe to run these five probes against this child's PID without a
// verifyTarget-style check immediately beforehand: nothing on the system,
// short of this tool's own process exiting first, can make that PID number
// refer to something else during this run.
//
// Called from the pre-filter phase (spawning it is an execve from this
// process's point of view, same as the parser and the exec-based probes),
// unconditionally: these five probes need a same-UID target process, not
// specifically a --target-pid, so this never depends on --target-pid being
// used at all.
func spawnSameUIDChild() (sameUIDChild, error) {
	exe, err := os.Executable()
	if err != nil {
		return sameUIDChild{}, fmt.Errorf("locate own executable: %w", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return sameUIDChild{}, fmt.Errorf("pipe: %w", err)
	}
	defer r.Close()

	// lifelineR/lifelineW: a second, dedicated pipe the child reads from
	// and this process holds the write end of for as long as this process
	// itself is alive. This process's copy of lifelineW is never closed —
	// the kernel closes it, along with every other fd this process holds,
	// the instant this process exits for any reason (normal completion, a
	// crash, an unhandled signal), and the child's blocking read on its own
	// end observes that as EOF and exits itself. This is what keeps a
	// bare-host run of this tool from leaving the child running forever;
	// inside Docker, container teardown would eventually do the same thing,
	// but this does not depend on that.
	lifelineR, lifelineW, err := os.Pipe()
	if err != nil {
		return sameUIDChild{}, fmt.Errorf("lifeline pipe: %w", err)
	}
	defer lifelineR.Close()

	cmd := exec.Command(exe, "sensor", "--probe-sameuid-target-child")
	cmd.ExtraFiles = []*os.File{w, lifelineR}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		w.Close()
		lifelineW.Close()
		return sameUIDChild{}, fmt.Errorf("start same-UID target child: %w", err)
	}
	w.Close()
	sameUIDChildLifeline = lifelineW

	var pid int
	var addr uintptr
	var length int
	if _, err := fmt.Fscanf(r, "%d %d %d\n", &pid, &addr, &length); err != nil {
		return sameUIDChild{}, fmt.Errorf("read same-UID target child's report: %w", err)
	}
	if pid != cmd.Process.Pid {
		return sameUIDChild{}, fmt.Errorf("same-UID target child reported pid %d, exec reported %d", pid, cmd.Process.Pid)
	}
	// Deliberately no cmd.Wait() call, ever — see this function's own doc
	// comment for why that is exactly what keeps this PID from being
	// reused for the rest of this run. The child exits on its own once the
	// lifeline above closes, rather than needing to be reaped to stop
	// running.
	return sameUIDChild{PID: pid, Addr: addr, Len: length}, nil
}

// runProbeSameUIDTargetChild is the entry point for a re-exec'd
// `kestrelynx sensor --probe-sameuid-target-child` process: it allocates a
// dedicated buffer, reports its own PID and that buffer's address/length on
// fd 3, and then blocks on fd 4 (the read end of spawnSameUIDChild's
// lifeline pipe) until that read returns EOF, which happens the instant the
// parent process exits for any reason — at that point it exits itself
// rather than lingering. It applies none of the observer's own sandboxing
// (NO_NEW_PRIVS, the seccomp filter, capability drops) — it is not itself
// under test; it exists only to be a stable, known, same-UID process the
// parent's ptrace/process_vm_*/pidfd/kill probes can target for exactly as
// long as the parent itself runs.
func runProbeSameUIDTargetChild() {
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = 0
	}
	addr := uintptr(unsafe.Pointer(&buf[0]))
	fmt.Fprintf(os.NewFile(3, "sameuid-child-report"), "%d %d %d\n", os.Getpid(), addr, len(buf))

	lifeline := os.NewFile(4, "sameuid-child-lifeline")
	var b [1]byte
	for {
		n, err := lifeline.Read(b[:])
		if n == 0 && err != nil {
			break
		}
	}
	// Keep buf reachable for as long as the parent may write into it.
	runtime.KeepAlive(buf)
}

// checkParserBPFFDs lists parserPID's own fds and reports whether any of
// them names a BPF kernel object (anon_inode:bpf-map, anon_inode:bpf-prog,
// or anon_inode:bpf-link — the kernel's own naming for these anonymous
// inodes), so a caller can confirm a BPF fd was not inherited across the
// exec that started the parser (cilium/ebpf opens all of its fds
// O_CLOEXEC, which this exists to check empirically rather than assume).
// Status is always "ok", "incomplete" (some fds could not be read) or
// "failed", and InheritedCount is always present
// (0 is a checked, meaningful result), so a reader of the report can never
// confuse "checked and found none" with "the check itself did not run".
func checkParserBPFFDs(parserPID int) parserFDCheck {
	if parserPID <= 0 {
		return parserFDCheck{Status: "failed", Reason: "parser was not started"}
	}
	h, err := procfs.Open(parserPID)
	if err != nil {
		return parserFDCheck{Status: "failed", Reason: fmt.Sprintf("open parser /proc entry: %v", err)}
	}
	defer h.Close()
	names, err := h.FDNames()
	if err != nil {
		return parserFDCheck{Status: "failed", Reason: fmt.Sprintf("list parser fds: %v", err)}
	}
	if len(names) == 0 {
		return parserFDCheck{Status: "failed", Reason: "parser reported zero open fds (expected at least its socketpair end and stderr)"}
	}
	var inherited []string
	var readErrs int
	for _, n := range names {
		target, terr := h.FDTarget(n)
		if terr != nil {
			readErrs++
			continue
		}
		if strings.HasPrefix(target, "anon_inode:bpf-") {
			inherited = append(inherited, fmt.Sprintf("fd %s -> %s", n, target))
		}
	}
	// A count of 0 must only ever mean "checked every fd and found none",
	// never "some fds could not be checked" — so any unread fd downgrades
	// the status instead of being folded into a still-"ok" result: failed
	// when nothing could be confirmed either way, incomplete when only
	// some of them could.
	switch {
	case readErrs == len(names):
		return parserFDCheck{Status: "failed",
			Reason: fmt.Sprintf("all %d fd targets could not be read; inheritance could not be confirmed either way", readErrs)}
	case readErrs > 0:
		return parserFDCheck{Status: "incomplete",
			Reason:         fmt.Sprintf("%d of %d fd targets could not be read; the %d found among the rest may not be the complete picture", readErrs, len(names), len(inherited)),
			InheritedCount: len(inherited), Inherited: inherited}
	default:
		return parserFDCheck{Status: "ok", InheritedCount: len(inherited), Inherited: inherited}
	}
}

// maxUnattributedSampledEvents and maxAttributedSampledEvents bound the two
// separate categories sampleEvents keeps: events whose cgroup does not
// match any container named in --inspect-json (host noise, or an unrelated
// container — pid:host observes the whole host, not just the verification
// containers this run created), and events that do. A single combined cap
// of 50 was found, on a busy interactive host, to fill up entirely with
// unrelated host activity within the first fraction of a second of the
// listen window, before the short-lived-exec verification container's own
// once-a-second exec ever had a chance to be captured — sampleEvents keeps
// discarding already-capped unattributed events (without storing them) for
// as long as attributed room remains, specifically so that noise cannot
// crowd out the handful of events this run actually cares about.
const (
	maxUnattributedSampledEvents = 50
	maxAttributedSampledEvents   = 200
)

// sampleEvents reads ring buffer events for at most d, tagging each with
// the container it belongs to (if any) and bounding how many of each
// category it keeps (see the constants above). It checks the wall clock
// explicitly on every iteration, in addition to setting the reader's own
// deadline: (*ringbuf.Reader).Read is documented to keep returning
// already-buffered records after its deadline elapses rather than stopping
// dead, so a deadline alone does not bound how long this loop can keep
// draining a backlog — the explicit check is what actually bounds it.
func sampleEvents(h *ebpf.Handle, d time.Duration, rep *ebpfReport, cgroupIDToName map[uint64]string) {
	deadline := time.Now().Add(d)
	h.SetReadDeadline(deadline)
	var unattributed, attributed int
	for unattributed < maxUnattributedSampledEvents || attributed < maxAttributedSampledEvents {
		if time.Now().After(deadline) {
			break
		}
		ev, err := h.Read()
		if err != nil {
			break // deadline exceeded, or the handle was closed
		}
		container := cgroupIDToName[ev.CgroupID]
		if container == "" {
			if unattributed >= maxUnattributedSampledEvents {
				continue
			}
			unattributed++
		} else {
			if attributed >= maxAttributedSampledEvents {
				continue
			}
			attributed++
		}
		rep.SampledEvents = append(rep.SampledEvents, sampledEvent{
			Kind:          ev.Kind.String(),
			CgroupID:      ev.CgroupID,
			Container:     container,
			Dev:           fmt.Sprintf("%x", ev.Dev),
			Ino:           ev.Ino,
			Path:          ev.Path,
			PathTruncated: ev.PathTruncated,
			// bpf_d_path resolves relative to the opening process's own
			// mount namespace: a container-relative path starts with "/"
			// and is never rooted under this Sensor's own "/proc" view of
			// the host (which is what a host-rooted path picked up by
			// mistake would look like).
			PathLooksContainerRelative: strings.HasPrefix(ev.Path, "/") && !strings.HasPrefix(ev.Path, "/proc/"),
		})
	}
}

// tryWriteOwnFilesystem attempts to open a plain file inside the Sensor's
// own container for writing: writes into the Sensor's own reachable
// filesystem must fail the same way writes into another container's do.
// Denied by the observer's own filter unconditionally (any write-flagged
// open), independent of DAC permissions on the target path.
func tryWriteOwnFilesystem() probeResult {
	_, err := unix.Open("/etc/hostname", unix.O_WRONLY, 0)
	return denyResult("write /etc/hostname (own container filesystem)", err)
}

// probeOpenByHandleAtWrite attempts to obtain a real file handle for a file
// this process can read (via name_to_handle_at) and then attempts
// open_by_handle_at with O_WRONLY on it — the write-capable form of the
// open_by_handle_at bypass CAP_DAC_READ_SEARCH is granted for, which a
// read-only or invalid-handle attempt alone does not exercise.
//
// In practice this probe can never get past its first step:
// name_to_handle_at is excluded from the container-wide seccomp profile
// unconditionally (see scripts/gen_sensor_seccomp_profile.py), for every
// process in this container regardless of when in this process's own
// lifecycle it is called — there is no pre-filter/post-filter distinction
// that changes this, since that profile is enforced by the container
// runtime from the moment this container's init process starts, not
// installed by this tool itself. Reaching the write-attempt this probe
// exists to check would require constructing the handle in a process
// outside this container's seccomp confinement (e.g. inside one of the
// read-only verification containers) and passing its bytes in — not
// implemented here. This is recorded as "skipped" with that reason, not as
// a denial this process never actually attempted: the fact that
// name_to_handle_at itself is denied is still meaningful (it is what makes
// the write-capable form unreachable at all), and is recorded in Detail.
func probeOpenByHandleAtWrite() probeResult {
	name := "open_by_handle_at(O_WRONLY) via name_to_handle_at"
	const target = "/etc/hostname"

	// A fd on the target file itself, not on "/": open_by_handle_at's
	// mount_fd only has to identify the right mount, and Docker
	// individually bind-mounts /etc/hostname (and /etc/hosts,
	// /etc/resolv.conf) from the host, so it is not reliably on the same
	// mount as "/" — a fd on the target itself is correct regardless of
	// whether that happens to be true.
	mountFD, err := unix.Open(target, unix.O_RDONLY, 0)
	if err != nil {
		return probeResult{Name: name, Expected: "denied", Outcome: "error", Detail: "open mount context: " + err.Error()}
	}
	defer unix.Close(mountFD)

	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, target, 0)
	if err != nil {
		return probeResult{Name: name, Expected: "denied", Outcome: "skipped",
			Detail: "name_to_handle_at is excluded from the container-wide seccomp profile for every process in this container; the write attempt this probe exists to check cannot be constructed from inside it: " + err.Error()}
	}
	fd, err := unix.OpenByHandleAt(mountFD, handle, unix.O_WRONLY)
	if err == nil {
		unix.Close(fd)
	}
	return denyResult(name, err)
}

// execChildExitBase anchors runProbeExecChild's exit codes: any code at or
// above this value decodes to execChildExitBase+errno (see
// decodeExecChildExitCode), and any code below it means the target actually
// executed and ran to completion, exiting with that code itself. Chosen
// high enough (128) that no real errno this tool expects to see
// (EPERM=1, ENOENT=2, EACCES=13, …) collides with an ordinary 0-127 process
// exit code space.
const execChildExitBase = 128

// runProbeExecChild is the entry point for a re-exec'd
// `kestrelynx sensor --probe-exec-child-target=<path>` process: a
// disposable child (mirroring sandbox.RunUnsafeProbesInSubprocess's own
// pattern) that applies the observer's NO_NEW_PRIVS and seccomp filter to
// itself and then attempts to exec exactly one path, reporting the exact
// errno via its own exit code (execChildExitBase+errno) rather than
// collapsing every non-EPERM failure into one bucket. Any exit code below
// execChildExitBase, or death by signal, means the exec actually replaced
// this process's image and whatever it execed into ran to completion —
// which is why every caller of this must only ever point it at a binary
// known to be harmless when run with no arguments (see
// tryExecOwnImageBinary and the probe-target setuid binary
// probe-targets.sh creates). target may be a plain path or
// "/proc/self/fd/<n>" naming an inherited fd (see tryExecFD).
func runProbeExecChild(target string) {
	_ = sandbox.SetNoNewPrivsAll()
	if filter, err := sandbox.ObserverFilter(int32(os.Getpid())); err == nil {
		_ = sandbox.InstallFilter(filter)
	}
	err := unix.Exec(target, []string{target}, nil)
	errno, ok := err.(syscall.Errno)
	if !ok {
		syscall.Exit(255)
	}
	code := execChildExitBase + int(errno)
	if code > 255 {
		code = 255
	}
	syscall.Exit(code)
}

// decodeExecChildExitCode reverses runProbeExecChild's exit-code encoding.
// ranToCompletion is true when code is below execChildExitBase, meaning
// execve actually succeeded and this is the target's own exit code, not an
// errno at all.
func decodeExecChildExitCode(code int) (errno syscall.Errno, ranToCompletion bool) {
	if code < execChildExitBase {
		return 0, true
	}
	return syscall.Errno(code - execChildExitBase), false
}

// classifyExecResult turns the disposable exec-probe child's wait result
// into a probeResult: EPERM is "denied" (the expected outcome), ENOENT is
// "skipped" (the target does not exist, so nothing about containment was
// actually exercised), any other errno is "error", and a below-threshold
// exit code or a signal death means the target actually ran — always
// "allowed" and Unexpected, the sandbox-failure case every caller of this
// must already have made harmless (see runProbeExecChild's doc comment).
func classifyExecResult(name string, runErr error) probeResult {
	code := 0
	if runErr != nil {
		exitErr, ok := runErr.(*exec.ExitError)
		if !ok {
			return probeResult{Name: name, Expected: "denied", Outcome: "error", Detail: runErr.Error()}
		}
		code = exitErr.ExitCode()
		if code == -1 {
			return probeResult{Name: name, Expected: "denied", Outcome: "allowed", Unexpected: true,
				Detail: fmt.Sprintf("exec child was terminated by a signal instead of exiting: %v", exitErr)}
		}
	}
	errno, ranToCompletion := decodeExecChildExitCode(code)
	if ranToCompletion {
		return probeResult{Name: name, Expected: "denied", Outcome: "allowed", Unexpected: true,
			Detail: fmt.Sprintf("exec child exited %d: the target binary actually ran to completion", code)}
	}
	switch errno {
	case syscall.EPERM:
		return probeResult{Name: name, Expected: "denied", Outcome: "denied"}
	case syscall.ENOENT:
		return probeResult{Name: name, Expected: "denied", Outcome: "skipped", Detail: "target does not exist (ENOENT)"}
	default:
		return probeResult{Name: name, Expected: "denied", Outcome: "error",
			Detail: fmt.Sprintf("exec failed with errno %d (%s), not EPERM", int(errno), errno)}
	}
}

// tryExecPath runs runProbeExecChild against a plain path target in a
// disposable child. See runProbeExecChild's doc comment for the exit-code
// contract and the safety requirement on target.
func tryExecPath(name, target string) probeResult {
	exe, err := os.Executable()
	if err != nil {
		return probeResult{Name: name, Expected: "denied", Outcome: "error", Detail: err.Error()}
	}
	cmd := exec.Command(exe, "sensor", "--probe-exec-child-target="+target)
	// Stdout/Stderr must both be existing, already-open fds, not left nil:
	// os/exec opens /dev/null O_WRONLY itself, from this parent process, for
	// either one left unset. Once this call runs after the observer's own
	// filter is installed, that open would be denied the same as any other
	// write-flagged open this process attempts. Both are pointed at this
	// process's own stderr, not stdout: if the target binary actually runs
	// (the sandbox-failure case this probe exists to catch) and prints
	// anything, it must not land in the probe report itself when --out is
	// "-".
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()
	return classifyExecResult(name, runErr)
}

// tryExecFD runs runProbeExecChild against an already-open fd (targeting it
// via "/proc/self/fd/3" inside the child, where ExtraFiles places it),
// taking ownership of fd and closing it before returning. Used when the
// target must be reached through a retained procfs.Handle rather than a
// freshly formatted path string — see tryExecSetuidInTarget.
func tryExecFD(name string, fd int) probeResult {
	targetFile := os.NewFile(uintptr(fd), "exec-target")
	defer targetFile.Close()

	exe, err := os.Executable()
	if err != nil {
		return probeResult{Name: name, Expected: "denied", Outcome: "error", Detail: err.Error()}
	}
	cmd := exec.Command(exe, "sensor", "--probe-exec-child-target=/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{targetFile}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()
	return classifyExecResult(name, runErr)
}

func tryExecOwnImageBinary(path string) probeResult {
	return tryExecPath(fmt.Sprintf("execve %s (own image)", path), path)
}

// readContainer performs every read-only probe for one container: exe,
// maps, fd listing and one fd target, net/tcp, status, cgroup (including
// the container-ID cross-check and the starttime/StartedAt cross-check),
// and a root-directory listing. It never writes, connects, signals, or
// executes anything.
func readContainer(e dockerInspectEntry) containerReport {
	cr := containerReport{
		ContainerID: e.Id,
		Name:        strings.TrimPrefix(e.Name, "/"),
		PID:         e.State.Pid,
		ProbeTarget: e.isProbeTarget(),
		Unconfined:  e.isUnconfined(),
		Privileged:  e.HostConfig.Privileged,
		Reads:       map[string]readResult{},
	}
	if e.State.Pid <= 0 {
		cr.Reads["open"] = readResult{Outcome: "error", Detail: "no State.Pid in inspect entry"}
		return cr
	}

	h, err := procfs.Open(e.State.Pid)
	if err != nil {
		cr.Reads["open"] = classifyRead(err)
		return cr
	}
	defer h.Close()

	cid, ok, err := h.ContainerID()
	cr.Reads["cgroup"] = classifyRead(err)
	if err == nil {
		cr.CgroupContainerID = cid
		match := ok && cid == e.Id
		cr.CgroupIDMatch = &match
	}

	if e.State.StartedAt != "" {
		startedAt, perr := time.Parse(time.RFC3339Nano, e.State.StartedAt)
		if perr != nil {
			cr.Reads["starttime"] = readResult{Outcome: "error", Detail: perr.Error()}
		} else if wall, werr := starttimeToWall(h.Starttime()); werr != nil {
			cr.Reads["starttime"] = readResult{Outcome: "error", Detail: werr.Error()}
		} else {
			diff := wall.Sub(startedAt).Seconds()
			cr.StarttimeDiffSeconds = &diff
		}
	}

	_, _, err = h.Exe()
	cr.Reads["exe"] = classifyRead(err)

	_, _, err = h.Maps()
	cr.Reads["maps"] = classifyRead(err)

	_, _, err = h.Status()
	cr.Reads["status"] = classifyRead(err)

	_, err = h.NetTCPListens("tcp")
	cr.Reads["net_tcp"] = classifyRead(err)

	names, err := h.FDNames()
	cr.Reads["fd_list"] = classifyRead(err)
	if err == nil && len(names) > 0 {
		_, terr := h.FDTarget(names[0])
		cr.Reads["fd_target"] = classifyRead(terr)
	}

	root, err := h.OpenRoot()
	if err != nil {
		cr.Reads["root"] = classifyRead(err)
	} else {
		rr := rootfs.Open(root)
		_, _, rerr := rr.ReadDir("/")
		cr.Reads["root"] = classifyRead(rerr)
		rr.Close()
	}

	return cr
}

// userHZ is USER_HZ, the fixed clock-tick rate /proc/<pid>/stat's starttime
// field is expressed in (proc(5): "divide by sysconf(_SC_CLK_TCK)"). Unlike
// the kernel's own internal timer frequency (CONFIG_HZ), USER_HZ is a
// stable part of the Linux ABI and has been 100 on every architecture this
// Sensor targets (x86_64, aarch64) for as long as those architectures have
// existed; it is not read from the running kernel because there is no
// syscall to do so cheaply (glibc's sysconf(_SC_CLK_TCK) is itself just a
// compiled-in constant for these architectures, not a kernel query).
const userHZ = 100

func bootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			secs, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("parse btime %q: %w", rest, err)
			}
			return time.Unix(secs, 0).UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("no btime line in /proc/stat")
}

func starttimeToWall(ticks int64) (time.Time, error) {
	bt, err := bootTime()
	if err != nil {
		return time.Time{}, err
	}
	return bt.Add(time.Duration(float64(ticks) / userHZ * float64(time.Second))), nil
}

// heapRange resolves h's own "[heap]" mapping from its /proc/<pid>/maps,
// read through h's own retained directory descriptor (OpenRelativeRaw)
// rather than a freshly formatted "/proc/<pid>/maps" path — the one range
// the mem-write and process_vm_writev probes will ever write into, because
// it is memory the target process allocated for itself, not memory Sensor
// or a caller chose.
func heapRange(h *procfs.Handle) (addr, size uint64, err error) {
	fd, err := h.OpenRelativeRaw("maps", unix.O_RDONLY, 0)
	if err != nil {
		return 0, 0, err
	}
	f := os.NewFile(uintptr(fd), "maps")
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasSuffix(strings.TrimSpace(line), "[heap]") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		lo, hi, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		loN, e1 := strconv.ParseUint(lo, 16, 64)
		hiN, e2 := strconv.ParseUint(hi, 16, 64)
		if e1 != nil || e2 != nil || hiN <= loN {
			continue
		}
		return loN, hiN - loN, nil
	}
	return 0, 0, fmt.Errorf("no [heap] mapping found")
}

// tryMemWrite attempts to open the target's own /proc/<pid>/mem for writing
// through its retained directory descriptor (expected to be denied
// unconditionally by the observer's own filter, since it is a
// write-flagged open). If that open were ever to unexpectedly succeed, the
// only write this function will still perform is a single byte inside the
// target's own "[heap]" mapping (see heapRange's doc comment) — never an
// offset supplied by anything else, and never at all if the heap mapping
// cannot be resolved.
func tryMemWrite(vt verifiedTarget) probeResult {
	name := fmt.Sprintf("write /proc/%d/mem (own-allocated [heap] region only)", vt.PID)
	fd, err := vt.Handle.OpenRelativeRaw("mem", unix.O_WRONLY, 0)
	if err != nil {
		return denyResult(name, err)
	}
	defer unix.Close(fd)

	addr, size, herr := heapRange(vt.Handle)
	if herr != nil || size == 0 {
		return probeResult{Name: name, Expected: "denied", Outcome: "allowed", Unexpected: true,
			Detail: "open succeeded unexpectedly, and no dedicated (heap) region could be resolved, so no write was attempted: " + errString(herr)}
	}
	_, werr := unix.Pwrite(fd, []byte{0}, int64(addr))
	if werr != nil {
		return probeResult{Name: name, Expected: "denied", Outcome: "denied",
			Detail: "open succeeded but the write into the target's own heap was denied: " + werr.Error()}
	}
	return probeResult{Name: name, Expected: "denied", Outcome: "allowed", Unexpected: true,
		Detail: fmt.Sprintf("wrote 1 byte at heap offset %#x (heap size %d)", addr, size)}
}

// trySignal, tryPtraceAttach, tryProcessVMReadv, tryProcessVMWritev, and
// tryPidfdGetfd all target a sameUIDChild (see spawnSameUIDChild's doc
// comment for why), never a --target-pid's own container process: none of
// these five syscalls has an *at()-style form resolving through an
// already-open descriptor, and an unreaped child's PID cannot be recycled
// out from under it for the lifetime of this run, which is what makes
// targeting it safe without a same-moment recheck.

func trySignal(c sameUIDChild) probeResult {
	name := fmt.Sprintf("kill(%d, 0) (same-UID signal)", c.PID)
	return denyResult(name, unix.Kill(c.PID, 0))
}

func tryPtraceAttach(c sameUIDChild) probeResult {
	const name = "ptrace(PTRACE_ATTACH)"
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_ATTACH, uintptr(c.PID), 0, 0, 0, 0)
	if errno == 0 {
		// Detach immediately: an attached-but-untraced tracee is left
		// group-stopped by PTRACE_ATTACH until detached.
		unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(c.PID), 0, 0, 0, 0)
		return probeResult{Name: name, Expected: "denied", Outcome: "allowed", Unexpected: true}
	}
	return denyResult(name, errno)
}

func tryProcessVMReadv(c sameUIDChild) probeResult {
	const name = "process_vm_readv (own-allocated region only)"
	buf := make([]byte, 1)
	local := []unix.Iovec{{Base: &buf[0], Len: 1}}
	remote := []unix.RemoteIovec{{Base: c.Addr, Len: 1}}
	_, err := unix.ProcessVMReadv(c.PID, local, remote, 0)
	return denyResult(name, err)
}

// tryProcessVMWritev, like tryMemWrite, never writes anywhere but the
// dedicated region the target allocated for exactly this purpose.
func tryProcessVMWritev(c sameUIDChild) probeResult {
	const name = "process_vm_writev (own-allocated region only)"
	buf := []byte{0}
	local := []unix.Iovec{{Base: &buf[0], Len: 1}}
	remote := []unix.RemoteIovec{{Base: c.Addr, Len: 1}}
	_, err := unix.ProcessVMWritev(c.PID, local, remote, 0)
	return denyResult(name, err)
}

func tryPidfdGetfd(c sameUIDChild) probeResult {
	const name = "pidfd_getfd"
	pidfd, err := unix.PidfdOpen(c.PID, 0)
	if err != nil {
		// pidfd_open itself is not meant to be denied (only pidfd_getfd
		// is); a failure here just means this probe cannot run, recorded as
		// an error rather than a denial either way.
		return probeResult{Name: name, Expected: "denied", Outcome: "error",
			Detail: "pidfd_open: " + err.Error()}
	}
	defer unix.Close(pidfd)
	fd, err := unix.PidfdGetfd(pidfd, 0, 0)
	if err == nil {
		unix.Close(fd)
	}
	return denyResult(name, err)
}

// procSelfFDPath forms a path rooted at h's own retained directory
// descriptor via /proc/self/fd/<FD()> rather than a freshly formatted
// "/proc/<pid>/…" string — for the handful of operations (connect(2),
// sendto(2)) that take a pathname and have no *at()-style form resolving
// through an already-open descriptor directly. Resolution still stays
// bound to the exact process verifyTarget checked: /proc/self/fd/<FD()> is
// this process's own magic-symlink view of its own descriptor, not a fresh
// lookup of the PID number.
func procSelfFDPath(h *procfs.Handle, rel string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", h.FD(), rel)
}

func tryRootWrite(vt verifiedTarget) probeResult {
	const relPath = "root/tmp/kestrelynx-probe-write-test"
	name := fmt.Sprintf("write into /proc/%d/root (other container's rootfs)", vt.PID)
	fd, err := vt.Handle.OpenRelativeRaw(relPath, unix.O_WRONLY|unix.O_CREAT, 0o600)
	if err == nil {
		unix.Close(fd)
		// Best-effort cleanup of the file this would have unexpectedly
		// created; failure here does not change the probe's own result.
		unix.Unlinkat(vt.Handle.FD(), relPath, 0)
	}
	return denyResult(name, err)
}

func tryUnixConnect(vt verifiedTarget, kind string) probeResult {
	suffix := ""
	sockType := unix.SOCK_STREAM
	if kind == "dgram" {
		suffix = ".dgram"
		sockType = unix.SOCK_DGRAM
	}
	path := procSelfFDPath(vt.Handle, "root/tmp/kestrelynx-probe.sock"+suffix)
	name := fmt.Sprintf("connect to other container's %s unix socket", kind)
	fd, err := unix.Socket(unix.AF_UNIX, sockType, 0)
	if err != nil {
		// The container-wide profile excludes socket(2) entirely (see
		// scripts/gen_sensor_seccomp_profile.py), so on a real deployment
		// this is where the denial actually happens — before connect(2) is
		// ever reached, not a failure to run the intended check.
		return denyResult(name, err)
	}
	defer unix.Close(fd)
	cerr := unix.Connect(fd, &unix.SockaddrUnix{Name: path})
	return denyResult(name, cerr)
}

func trySocketDgramSendto(vt verifiedTarget) probeResult {
	path := procSelfFDPath(vt.Handle, "root/tmp/kestrelynx-probe.sock.dgram")
	const name = "sendto other container's dgram unix socket"
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		// Same reasoning as tryUnixConnect: the container-wide profile
		// excludes socket(2) entirely, so this is the real deployment's
		// actual point of denial.
		return denyResult(name, err)
	}
	defer unix.Close(fd)
	serr := unix.Sendto(fd, []byte("kestrelynx-probe"), 0, &unix.SockaddrUnix{Name: path})
	return denyResult(name, serr)
}

// fsImmutableFL is FS_IMMUTABLE_FL from linux/fs.h (the "immutable" inode
// attribute bit), a stable UAPI value not exported by golang.org/x/sys/unix.
const fsImmutableFL = 0x00000010

func tryIoctlSetFlags(vt verifiedTarget) probeResult {
	const relPath = "root/data/kestrelynx-probe-ioctl-test"
	const name = "ioctl(FS_IOC_SETFLAGS) on other container's file"
	fd, err := vt.Handle.OpenRelativeRaw(relPath, unix.O_RDONLY, 0)
	if err != nil {
		return denyResult(name+" (open)", err)
	}
	defer unix.Close(fd)
	flags := uint32(fsImmutableFL)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.FS_IOC_SETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno == 0 {
		return probeResult{Name: name, Expected: "denied", Outcome: "allowed", Unexpected: true}
	}
	return denyResult(name, errno)
}

// tryExecSetuidInTarget attempts to exec the setuid binary
// deploy/docker/probe-targets.sh creates inside vt's own container
// (/usr/local/bin/probe-setuid-true, a copy of /bin/true — harmless if the
// exec were to actually succeed; see classifyExecResult's doc comment for
// why that matters), reached through vt's retained directory descriptor
// (OpenRelativeRaw, then execed via the inherited fd's own
// "/proc/self/fd/3" — see tryExecFD) rather than a freshly formatted
// "/proc/<pid>/root/…" string. Callers must run this before the observer's
// own filter is installed, alongside the other exec-based probes — see
// runProbe's pre-filter phase.
func tryExecSetuidInTarget(vt verifiedTarget) probeResult {
	name := fmt.Sprintf("execve setuid file in pid %d's container", vt.PID)
	fd, err := vt.Handle.OpenRelativeRaw("root/usr/local/bin/probe-setuid-true", unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return probeResult{Name: name, Expected: "denied", Outcome: "skipped", Detail: "open target: " + err.Error()}
	}
	return tryExecFD(name, fd)
}
