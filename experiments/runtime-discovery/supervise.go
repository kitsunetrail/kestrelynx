package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// oPathFlag is O_PATH, which syscall does not define for amd64/386 (present on other
// architectures) despite the value being the same everywhere; needed to open the cgroup
// directory as a bare file descriptor for SysProcAttr.CgroupFD without requiring any
// particular permission on the directory's own contents.
const oPathFlag = 0x200000

// cgroupV2Root is the cgroup v2 mount point every cgroup path this program touches must
// live under. It is a variable, not a constant, only so a test can point the controller-
// enablement logic at a synthetic directory tree and exercise it without root.
var cgroupV2Root = "/sys/fs/cgroup"

// SuperviseRecord is supervise's own JSON output (see -record), written once right after
// startup verification (so a caller killed before the child exits still has it) and again,
// complete, once the child has actually exited or been stopped. Every reading that can fail
// independently of every other is its own MeasuredInt64/MeasuredBool, never a bare zero
// standing in for "not read".
type SuperviseRecord struct {
	Cgroup             string   `json:"cgroup"`
	CgroupMethod       string   `json:"cgroup_method"` // "clone3_cgroup_fd" | "post_start_write_fallback" | "none"
	ControllersEnabled []string `json:"controllers_enabled,omitempty"`
	ControllerWarnings []string `json:"controller_warnings,omitempty"`

	// PlacementAtomic reports whether the child was in its cgroup from its very first
	// instruction. false means the fallback path placed it only after exec, so the
	// startup CPU and the initial memory footprint of the child are NOT in this cgroup's
	// counters: a reader must treat this run's load figures as incomplete rather than
	// comparable with an atomically-placed run's.
	PlacementAtomic MeasuredBool `json:"placement_atomic"`

	User string `json:"user,omitempty"`
	UID  int    `json:"uid,omitempty"`
	GID  int    `json:"gid,omitempty"`

	Command      []string `json:"command"`
	EnvUnset     []string `json:"env_unset,omitempty"`
	ExpectExe    string   `json:"expect_exe,omitempty"`
	ExpectCapEff string   `json:"expect_capeff,omitempty"`

	BaselineCPUUsageUsec    MeasuredInt64 `json:"baseline_cpu_usage_usec"`
	BaselineMemoryPeakBytes MeasuredInt64 `json:"baseline_memory_peak_bytes"`

	StartedAtWall      string  `json:"started_at_wall"`
	StartedAtMonotonic float64 `json:"started_at_monotonic_s"`
	PID                int     `json:"pid"`

	ExeVerified       MeasuredBool `json:"exe_verified"`
	ActualExe         string       `json:"actual_exe,omitempty"`
	RealUID           int          `json:"real_uid"`
	EffectiveUID      int          `json:"effective_uid"`
	SavedUID          int          `json:"saved_uid"`
	FilesystemUID     int          `json:"filesystem_uid"`
	UIDVerified       MeasuredBool `json:"uid_verified"`
	CapEff            string       `json:"cap_eff,omitempty"`
	CapEffVerified    MeasuredBool `json:"capeff_verified,omitempty"`
	AttrCurrent       string       `json:"attr_current,omitempty"`
	Limits            string       `json:"limits,omitempty"`
	VerificationError string       `json:"verification_error,omitempty"`

	// Status is one of:
	//   "setup_failed"          - the child was never started at all
	//   "running"               - the first, partial write, right after verification
	//   "exited"                - the child was reaped and its cgroup holds no task
	//   "exited_residual_tasks" - the child was reaped but a descendant is still present
	//   "stop_unconfirmed"      - the child did NOT exit within the bounded wait after
	//                             SIGKILL: no exit time and no exit status are recorded,
	//                             because none was observed. Never reported as "exited".
	Status string `json:"status"`

	StopRequested    bool   `json:"stop_requested,omitempty"`
	StopReason       string `json:"stop_reason,omitempty"`
	DeadlineExceeded bool   `json:"deadline_exceeded,omitempty"`

	// TerminationConfirmed is the single yes/no a caller should gate "this run stopped
	// cleanly" on: true only when the child itself was reaped AND (where a cgroup exists
	// to check) no task is left in it.
	TerminationConfirmed MeasuredBool `json:"termination_confirmed"`
	// ResidualTasks is cgroup.events' own populated flag read after the child was reaped.
	ResidualTasks MeasuredBool `json:"residual_tasks"`

	ExitedAtWall      string  `json:"exited_at_wall,omitempty"`
	ExitedAtMonotonic float64 `json:"exited_at_monotonic_s,omitempty"`
	// ExitCode is a pointer so a real exit code of 0 is emitted as 0 and an exit that was
	// never observed is emitted as null - the two must never collapse into the same JSON.
	ExitCode   *int   `json:"exit_code"`
	ExitSignal string `json:"exit_signal,omitempty"`
	WaitError  string `json:"wait_error,omitempty"`

	FinalCPUUsageUsec    MeasuredInt64 `json:"final_cpu_usage_usec"`
	FinalMemoryPeakBytes MeasuredInt64 `json:"final_memory_peak_bytes"`

	CgroupRemoved MeasuredBool `json:"cgroup_removed"`
}

func writeRecord(path string, rec *SuperviseRecord) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", " ")
	if err := enc.Encode(rec); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// controllerSet splits a cgroup.controllers / cgroup.subtree_control file's own contents
// into the set of controller names it lists. These files are whitespace-separated and end
// in a newline, so a substring search for " memory " against their raw contents misses the
// last name on the line ("cpu memory\n") - the exact reason this goes through
// strings.Fields instead.
func controllerSet(data []byte) map[string]bool {
	set := map[string]bool{}
	for _, f := range strings.Fields(string(data)) {
		set[f] = true
	}
	return set
}

// enableControllersUpChain enables the cpu and memory controllers, wherever this cgroup v2
// mount's own hierarchy actually offers them, in every ancestor directory's own
// cgroup.subtree_control from the mount's root down to (not including) target - a
// controller only applies to a cgroup once every ancestor, not merely the immediate parent,
// has delegated it. target itself must already exist. Returns an error only when target's
// own cgroup.controllers still does not list "memory" once this returns: cpu.stat's own
// usage_usec is populated by the cgroup core regardless of controller delegation, so only
// memory availability is worth failing the whole run over by default (see -allow-unmeasured
// in runSupervise for the caller-facing override).
func enableControllersUpChain(target string) (enabled, warnings []string, err error) {
	root := cgroupV2Root
	rel, relErr := filepath.Rel(root, target)
	if relErr != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, nil, fmt.Errorf("cgroup path %s is not under %s", target, root)
	}
	dirs := []string{root}
	if dir := filepath.Dir(rel); dir != "." {
		cur := root
		for _, p := range strings.Split(dir, string(filepath.Separator)) {
			cur = filepath.Join(cur, p)
			dirs = append(dirs, cur)
		}
	}
	for _, dir := range dirs {
		avail, aerr := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
		if aerr != nil {
			warnings = append(warnings, fmt.Sprintf("%s: cannot read cgroup.controllers: %v", dir, aerr))
			continue
		}
		have, herr := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
		if herr != nil {
			warnings = append(warnings, fmt.Sprintf("%s: cannot read cgroup.subtree_control: %v", dir, herr))
			continue
		}
		availSet, haveSet := controllerSet(avail), controllerSet(have)
		var want []string
		for _, c := range []string{"cpu", "memory"} {
			if availSet[c] && !haveSet[c] {
				want = append(want, "+"+c)
			}
		}
		if len(want) == 0 {
			continue
		}
		spec := strings.Join(want, " ")
		if werr := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(spec), 0644); werr != nil {
			warnings = append(warnings, fmt.Sprintf("%s/cgroup.subtree_control %s: %v", dir, spec, werr))
		} else {
			enabled = append(enabled, fmt.Sprintf("%s: %s", dir, spec))
		}
	}
	targetAvail, taErr := os.ReadFile(filepath.Join(target, "cgroup.controllers"))
	if taErr != nil {
		return enabled, warnings, fmt.Errorf("cannot read %s/cgroup.controllers: %w", target, taErr)
	}
	if !controllerSet(targetAvail)["memory"] {
		return enabled, warnings, fmt.Errorf("memory controller not available on %s after enabling the ancestor chain (warnings: %v)", target, warnings)
	}
	return enabled, warnings, nil
}

// childEnv is the environment the child is given: this process's own, minus every name in
// unset. Removing the variables here, rather than by wrapping the command in `env -u ...`,
// is what makes the process this program starts, verifies and supervises the TARGET binary
// itself: with a wrapper, exec.Cmd's own Start() only guarantees the wrapper's exec, so the
// exe/CapEff read right afterwards can be the wrapper's rather than the target's.
func childEnv(unset []string) []string {
	if len(unset) == 0 {
		return nil // nil Cmd.Env means "inherit this process's environment unchanged"
	}
	drop := map[string]bool{}
	for _, n := range unset {
		drop[n] = true
	}
	out := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if drop[name] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// startInCgroup starts cmdArgs[0] with cmdArgs[1:], placing it in cgroupPath from its very
// first instruction via clone3's CLONE_INTO_CGROUP (SysProcAttr.UseCgroupFD), so no startup
// work - script compilation, probe attachment, calibration - ever runs outside the cgroup
// whose accounting this run reports. Falls back to starting normally and writing the child's
// pid to cgroup.procs immediately after Start() returns (no shell, no extra fork in between)
// when clone3/CLONE_INTO_CGROUP is not available (old kernel, seccomp, lack of
// CAP_SYS_ADMIN) - a real, if much smaller, residual race than the atomic path, recorded as
// such in CgroupMethod/PlacementAtomic rather than presented as equivalent to it.
// cgroupPath == "" starts the child with no cgroup of its own at all (-no-cgroup).
func startInCgroup(cgroupPath string, uid, gid int, hasUser bool, env []string, cmdArgs []string) (*exec.Cmd, string, error) {
	newCmd := func() *exec.Cmd {
		c := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
		c.Env = env
		return c
	}
	if cgroupPath == "" {
		cmd := newCmd()
		if hasUser {
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		}
		if err := cmd.Start(); err != nil {
			return nil, "", err
		}
		return cmd, "none", nil
	}
	fd, oerr := syscall.Open(cgroupPath, oPathFlag|syscall.O_DIRECTORY, 0)
	if oerr == nil {
		cmd := newCmd()
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
		if hasUser {
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		}
		err := cmd.Start()
		syscall.Close(fd)
		if err == nil {
			return cmd, "clone3_cgroup_fd", nil
		}
		// Falls through to the fallback below on any Start failure from this path (not
		// only ones classifiable as "clone3 unsupported"): a genuine, unrelated failure
		// (binary not found, say) will fail identically there too and produce one clear
		// final error instead of two different ones for the same underlying problem.
	}
	cmd := newCmd()
	if hasUser {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	}
	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("start (cgroup-fd attempt error: %v): %w", oerr, err)
	}
	if err := os.WriteFile(cgroupPath+"/cgroup.procs", []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, "", fmt.Errorf("fallback cgroup.procs write: %w", err)
	}
	return cmd, "post_start_write_fallback", nil
}

// childSnapshot is one coherent reading of a child's own /proc entries. Every field comes
// from the same pid at (as close as the kernel allows) the same moment, so the uid fields,
// CapEff and the exe they are reported alongside always belong to one and the same exec
// stage of that process - never a mixture of a pre-exec and a post-exec reading.
type childSnapshot struct {
	Exe         string
	ExeErr      error
	Status      []byte
	AttrCurrent string
	Limits      string
}

func readChildSnapshot(procRoot string, pid int) (childSnapshot, error) {
	var snap childSnapshot
	status, err := os.ReadFile(fmt.Sprintf("%s/%d/status", procRoot, pid))
	if err != nil {
		return snap, err
	}
	snap.Status = status
	snap.Exe, snap.ExeErr = os.Readlink(fmt.Sprintf("%s/%d/exe", procRoot, pid))
	if attr, aerr := os.ReadFile(fmt.Sprintf("%s/%d/attr/current", procRoot, pid)); aerr == nil {
		snap.AttrCurrent = strings.TrimSpace(string(attr))
	}
	if limits, lerr := os.ReadFile(fmt.Sprintf("%s/%d/limits", procRoot, pid)); lerr == nil {
		snap.Limits = string(limits)
	}
	return snap, nil
}

// stableChildSnapshot polls procRoot/<pid> until it can take a snapshot whose exe is still
// the same immediately afterwards (and, when expectExe is given, until the exe actually IS
// expectExe). exec.Cmd's own Start() already returns only once the child's execve has
// succeeded - the child reports an exec failure back through its own CLOEXEC pipe - so with
// the target binary started directly this is confirmation rather than a wait; it is what
// keeps every attribute in one snapshot belonging to the same exec of the same process.
func stableChildSnapshot(procRoot string, pid int, expectExe string) (childSnapshot, error) {
	var last error
	deadline := time.Now().Add(2 * time.Second)
	for attempt := 0; ; attempt++ {
		snap, err := readChildSnapshot(procRoot, pid)
		if err != nil {
			last = err
		} else if expectExe != "" && snap.Exe != expectExe {
			last = fmt.Errorf("exe is %q, not the expected %q", snap.Exe, expectExe)
		} else if again, aerr := os.Readlink(fmt.Sprintf("%s/%d/exe", procRoot, pid)); aerr != nil {
			last = fmt.Errorf("exe could not be re-read for consistency: %w", aerr)
		} else if again != snap.Exe {
			last = fmt.Errorf("exe changed while the process was being read (%q -> %q)", snap.Exe, again)
		} else {
			return snap, nil
		}
		if attempt > 0 && time.Now().After(deadline) {
			return snap, last
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// applySnapshot records the actually exec'd binary's own path, its real/effective/saved/
// filesystem UIDs (the four whitespace-separated fields of /proc/<pid>/status's own "Uid:"
// line, in that order), CapEff, LSM attr/current and rlimits into rec - the process's own
// ground truth, never inferred from what this program merely asked the kernel for. Takes an
// already-read snapshot specifically so this part - the actual field extraction and
// verification logic - can be unit-tested against a synthetic directory standing in for
// /proc, without a real process or root at all.
func applySnapshot(rec *SuperviseRecord, snap childSnapshot, expectExe, expectCapEff string, hasUser bool, wantUID int) {
	if snap.ExeErr != nil {
		rec.ExeVerified = MeasuredBool{Measured: false, Reason: snap.ExeErr.Error()}
	} else {
		rec.ActualExe = snap.Exe
		if expectExe != "" {
			rec.ExeVerified = MeasuredBool{Measured: true, Value: snap.Exe == expectExe}
		} else {
			rec.ExeVerified = MeasuredBool{Measured: false, Reason: "-expect-exe not given"}
		}
	}

	for _, line := range strings.Split(string(snap.Status), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "Uid:" {
			rec.RealUID, _ = strconv.Atoi(fields[1])
			rec.EffectiveUID, _ = strconv.Atoi(fields[2])
			rec.SavedUID, _ = strconv.Atoi(fields[3])
			rec.FilesystemUID, _ = strconv.Atoi(fields[4])
		}
		if len(fields) >= 2 && fields[0] == "CapEff:" {
			rec.CapEff = fields[1]
		}
	}
	if hasUser {
		rec.UIDVerified = MeasuredBool{Measured: true, Value: rec.RealUID == wantUID && rec.EffectiveUID == wantUID}
	} else {
		rec.UIDVerified = MeasuredBool{Measured: false, Reason: "-user not given; nothing to verify against"}
	}
	if expectCapEff != "" {
		if rec.CapEff == "" {
			rec.CapEffVerified = MeasuredBool{Measured: false, Reason: "CapEff line not found in /proc/<pid>/status"}
		} else {
			rec.CapEffVerified = MeasuredBool{Measured: true, Value: strings.EqualFold(rec.CapEff, expectCapEff)}
		}
	}

	rec.AttrCurrent = snap.AttrCurrent
	rec.Limits = snap.Limits
}

// verifyChild is applySnapshot for a real, running child: it takes a stable snapshot of the
// real /proc for the given pid and fills in a not_measured VerificationError (rather than
// applying a snapshot at all) when no consistent reading could be taken - a process that
// exited first, or one whose exe never became the expected binary.
func verifyChild(rec *SuperviseRecord, pid int, expectExe, expectCapEff string, hasUser bool, wantUID int) {
	snap, err := stableChildSnapshot("/proc", pid, expectExe)
	if err != nil {
		rec.VerificationError = fmt.Sprintf("no consistent /proc reading for process %d: %v", pid, err)
		rec.ExeVerified = MeasuredBool{Measured: false, Reason: rec.VerificationError}
		rec.UIDVerified = MeasuredBool{Measured: false, Reason: rec.VerificationError}
		if expectCapEff != "" {
			rec.CapEffVerified = MeasuredBool{Measured: false, Reason: rec.VerificationError}
		}
		if snap.Status != nil {
			// Whatever WAS read is still recorded (as unverified facts) rather than
			// discarded: it is evidence about what this process actually was.
			rec.ActualExe = snap.Exe
		}
		return
	}
	applySnapshot(rec, snap, expectExe, expectCapEff, hasUser, wantUID)
}

// forwardStopSequence sends SIGINT, waits up to grace seconds for the child to exit,
// escalates to SIGTERM with the same bounded wait, and SIGKILL as the last resort (5s) -
// every stop this program performs on a process it started goes through this bounded,
// escalating sequence, never a single signal with no confirmation the process actually left.
// The second return value is whether the child was actually reaped: false means even SIGKILL
// did not produce an exit within the final wait, which is an error state the caller must
// report as such - never as a normal exit with a made-up exit time.
func forwardStopSequence(pid int, waitCh <-chan error, grace int) (error, bool) {
	return forwardStopSequenceWith(func(sig syscall.Signal) { syscall.Kill(pid, sig) },
		waitCh, time.Duration(grace)*time.Second, 5*time.Second)
}

// forwardStopSequenceWith is forwardStopSequence with the signal delivery and both wait
// bounds injected, so the "even SIGKILL produced no exit" branch - the one case a test
// cannot provoke with a real process, since nothing survives SIGKILL on purpose - is still
// covered by a test rather than only by reading the code.
func forwardStopSequenceWith(kill func(syscall.Signal), waitCh <-chan error, grace, kickWait time.Duration) (error, bool) {
	try := func(sig syscall.Signal, timeout time.Duration) (error, bool) {
		kill(sig)
		select {
		case err := <-waitCh:
			return err, true
		case <-time.After(timeout):
			return nil, false
		}
	}
	if err, done := try(syscall.SIGINT, grace); done {
		return err, true
	}
	if err, done := try(syscall.SIGTERM, grace); done {
		return err, true
	}
	return try(syscall.SIGKILL, kickWait)
}

// applyExitOutcome records the child's own exit facts, and only those actually observed:
// with reaped false (even SIGKILL did not produce an exit within its own bounded wait) no
// exit time and no exit status are written at all, and the status says the termination was
// never confirmed rather than claiming the process exited.
func applyExitOutcome(rec *SuperviseRecord, reaped bool, waitErr error, exitedAtWall string, elapsed time.Duration) {
	rec.StartedAtMonotonic = 0 // this process's own monotonic clock counts from Start(), not from an external epoch
	if !reaped {
		rec.Status = "stop_unconfirmed"
		return
	}
	rec.ExitedAtWall = exitedAtWall
	rec.ExitedAtMonotonic = elapsed.Seconds()
	code := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				rec.ExitSignal = ws.Signal().String()
			}
		} else {
			rec.WaitError = waitErr.Error()
			code = -1
		}
	}
	rec.ExitCode = &code
	rec.Status = "exited"
}

// applyTerminationConfirmation folds the two independent halves of "this run actually
// stopped" into one recorded answer: the supervised child itself was reaped, AND no task is
// left in its cgroup (cgroup.events populated=1 after the child is gone means a descendant
// it started is still running, which is not a stopped run however cleanly the child exited).
func applyTerminationConfirmation(rec *SuperviseRecord, reaped bool, residual MeasuredBool) {
	rec.ResidualTasks = residual
	switch {
	case !reaped:
		rec.TerminationConfirmed = MeasuredBool{Measured: true, Value: false,
			Reason: "the child did not exit within the bounded wait after SIGKILL"}
	case !residual.Measured:
		rec.TerminationConfirmed = MeasuredBool{Measured: false,
			Reason: "the child was reaped but residual tasks could not be ruled out: " + residual.Reason}
	case residual.Value:
		rec.TerminationConfirmed = MeasuredBool{Measured: true, Value: false,
			Reason: "the child was reaped but cgroup.events still reports populated=1: a descendant task is still running"}
		rec.Status = "exited_residual_tasks"
	default:
		rec.TerminationConfirmed = MeasuredBool{Measured: true, Value: true}
	}
}

// commaList splits a comma-separated flag value into its non-empty, trimmed items.
func commaList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runSupervise(args []string) error {
	fs := flag.NewFlagSet("supervise", flag.ExitOnError)
	cgroupPath := fs.String("cgroup", "", "cgroup v2 directory to create and run the child inside (must not already exist; required unless -no-cgroup)")
	noCgroup := fs.Bool("no-cgroup", false, "run the child with no cgroup of its own: every cgroup-derived reading is recorded as not_measured. For paths where no cgroup can be created (no root) and the process supervision itself is what matters")
	keepCgroup := fs.Bool("keep-cgroup", false, "do not remove the cgroup when the child exits: leave it, and its counters, in place for the caller to read at its own final checkpoint and then remove with the cgroup-remove subcommand")
	userName := fs.String("user", "", "switch to this user's uid/gid before exec (refuses a name that resolves to uid 0)")
	unsetEnv := fs.String("unset-env", "", "comma-separated environment variable names to remove from the child's environment (applied to the child's own env directly, never by wrapping the command in another binary)")
	expectExe := fs.String("expect-exe", "", "verify /proc/<pid>/exe resolves to exactly this path after start")
	expectCapEff := fs.String("expect-capeff", "", "verify /proc/<pid>/status CapEff equals this hex value (case-insensitive) after start")
	recordPath := fs.String("record", "", "path to write the JSON supervision record (required)")
	stopRequestPath := fs.String("stop-request", "", "path polled once per second; non-empty contents are read as the stop reason")
	grace := fs.Int("grace", 10, "seconds to wait after SIGINT before SIGTERM, and after SIGTERM before SIGKILL")
	deadline := fs.Int("deadline", 0, "hard wall-clock seconds after start before forcing a stop with reason deadline_exceeded (0 = none)")
	allowUnmeasured := fs.Bool("allow-unmeasured", false, "proceed even if the memory controller could not be confirmed on the cgroup's ancestor chain, recording memory as not_measured, instead of failing")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: runtime-discovery supervise -cgroup DIR -record FILE [flags] -- cmd [args...]\n\nCreates a fresh cgroup v2 directory, starts cmd inside it from its very first\ninstruction (clone3 CLONE_INTO_CGROUP, falling back to an immediate post-start\ncgroup.procs write), verifies its actual exe/uid/CapEff, and supervises it until it\nexits or a stop is requested (stop-request file, SIGINT/SIGTERM to this process, or\n-deadline), escalating SIGINT -> SIGTERM -> SIGKILL with bounded waits. A stop that\nSIGKILL itself did not confirm is recorded as status=stop_unconfirmed with no exit\ntime. Removes the cgroup only once cgroup.events reports populated=0, and not at all\nunder -keep-cgroup (use the cgroup-remove subcommand after your own final readings).\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmdArgs := fs.Args()
	if *recordPath == "" {
		fs.Usage()
		return fmt.Errorf("supervise: -record is required")
	}
	if *noCgroup {
		if *cgroupPath != "" {
			return fmt.Errorf("supervise: -no-cgroup and -cgroup are mutually exclusive")
		}
	} else if *cgroupPath == "" {
		fs.Usage()
		return fmt.Errorf("supervise: -cgroup is required (or -no-cgroup to run without one)")
	}
	if len(cmdArgs) == 0 {
		fs.Usage()
		return fmt.Errorf("supervise: no command given after --")
	}

	envUnset := commaList(*unsetEnv)
	rec := &SuperviseRecord{Cgroup: *cgroupPath, Command: cmdArgs, EnvUnset: envUnset,
		ExpectExe: *expectExe, ExpectCapEff: *expectCapEff, Status: "setup_failed"}

	hasUser := *userName != ""
	uid, gid := 0, 0
	if hasUser {
		u, err := user.Lookup(*userName)
		if err != nil {
			return fmt.Errorf("supervise: -user %s: %w", *userName, err)
		}
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
		if uid == 0 {
			return fmt.Errorf("supervise: -user %s resolves to uid 0; refusing to run a non-root condition as root", *userName)
		}
		rec.User, rec.UID, rec.GID = *userName, uid, gid
	}

	noCgroupReason := "-no-cgroup: this run was supervised without a cgroup of its own"
	cgroupOK := true
	var cerr error
	if *noCgroup {
		rec.BaselineCPUUsageUsec = MeasuredInt64{Measured: false, Reason: noCgroupReason}
		rec.BaselineMemoryPeakBytes = MeasuredInt64{Measured: false, Reason: noCgroupReason}
	} else {
		if err := os.Mkdir(*cgroupPath, 0755); err != nil {
			return fmt.Errorf("supervise: cgroup: %w (it must not already exist)", err)
		}
		defer func() {
			if cgroupOK {
				return
			}
			os.Remove(*cgroupPath)
		}()

		var enabled, warnings []string
		enabled, warnings, cerr = enableControllersUpChain(*cgroupPath)
		rec.ControllersEnabled, rec.ControllerWarnings = enabled, warnings
		if cerr != nil && !*allowUnmeasured {
			cgroupOK = false
			writeRecord(*recordPath, rec)
			return fmt.Errorf("supervise: %w (pass -allow-unmeasured to proceed anyway with memory recorded as not_measured)", cerr)
		}

		baseUsec, buErr := readCPUStatUsageUsec(*cgroupPath + "/cpu.stat")
		rec.BaselineCPUUsageUsec = measuredInt(baseUsec, buErr)
		basePeak, bpErr := readSingleInt(*cgroupPath + "/memory.peak")
		if cerr != nil {
			bpErr = fmt.Errorf("memory controller not available: %v", cerr)
		}
		rec.BaselineMemoryPeakBytes = measuredInt(basePeak, bpErr)
	}

	// Signal delivery is taken over BEFORE any child exists. A SIGTERM that arrives while
	// the child is being started or verified must reach the child too, and it can only do
	// that if this process is still here to forward it: with the default disposition still
	// in place, that same signal ends this process alone and leaves the child running with
	// nothing supervising it. The channel is buffered, so a signal that arrives during
	// startup is still waiting on it when the stop loop below takes its first turn, and is
	// acted on there through exactly the same bounded termination path as any other stop.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	startWall := time.Now().UTC()
	startMono := time.Now()
	cmd, method, serr := startInCgroup(*cgroupPath, uid, gid, hasUser, childEnv(envUnset), cmdArgs)
	if serr != nil {
		cgroupOK = false
		writeRecord(*recordPath, rec)
		return fmt.Errorf("supervise: %w", serr)
	}
	rec.CgroupMethod = method
	switch method {
	case "clone3_cgroup_fd":
		rec.PlacementAtomic = MeasuredBool{Measured: true, Value: true}
	case "post_start_write_fallback":
		rec.PlacementAtomic = MeasuredBool{Measured: true, Value: false,
			Reason: "clone3 CLONE_INTO_CGROUP was unavailable; the child was placed in its cgroup only after exec, so its own startup CPU and initial memory are not in these counters"}
	default:
		rec.PlacementAtomic = MeasuredBool{Measured: false, Reason: noCgroupReason}
	}
	rec.StartedAtWall = startWall.Format("2006-01-02T15:04:05.000000000Z")
	rec.PID = cmd.Process.Pid
	rec.Status = "running"

	verifyChild(rec, rec.PID, *expectExe, *expectCapEff, hasUser, uid)
	writeRecord(*recordPath, rec) // partial record, available even if this process is killed before the child exits

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	var deadlineAt time.Time
	if *deadline > 0 {
		deadlineAt = startMono.Add(time.Duration(*deadline) * time.Second)
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// A stop request written while this process was starting and verifying the child is
	// read now rather than a tick later: the runner may already be waiting on it.
	if *stopRequestPath != "" {
		if data, rerr := os.ReadFile(*stopRequestPath); rerr == nil {
			if reason := strings.TrimSpace(string(data)); reason != "" {
				rec.StopRequested, rec.StopReason = true, reason+" (requested during startup)"
			}
		}
	}

	var waitErr error
	reaped := true // a child that exits on its own has, by definition, been reaped
	first := true  // the first turn of the loop is where a signal buffered during startup lands
	if rec.StopRequested {
		waitErr, reaped = forwardStopSequence(rec.PID, waitCh, *grace)
		goto stopped
	}
stopLoop:
	for {
		select {
		case waitErr = <-waitCh:
			break stopLoop
		case sig := <-sigCh:
			reason := fmt.Sprintf("received signal %s", sig)
			if first {
				// Buffered from before the stop loop began: the signal arrived while the
				// child was still being started or verified.
				reason += " during startup"
			}
			rec.StopRequested, rec.StopReason = true, reason
			waitErr, reaped = forwardStopSequence(rec.PID, waitCh, *grace)
			break stopLoop
		case <-ticker.C:
			if *stopRequestPath != "" {
				if data, rerr := os.ReadFile(*stopRequestPath); rerr == nil {
					if reason := strings.TrimSpace(string(data)); reason != "" {
						rec.StopRequested, rec.StopReason = true, reason
						waitErr, reaped = forwardStopSequence(rec.PID, waitCh, *grace)
						break stopLoop
					}
				}
			}
			if !deadlineAt.IsZero() && time.Now().After(deadlineAt) {
				rec.StopRequested, rec.DeadlineExceeded, rec.StopReason = true, true, "deadline_exceeded"
				waitErr, reaped = forwardStopSequence(rec.PID, waitCh, *grace)
				break stopLoop
			}
		}
		first = false
	}

stopped:
	applyExitOutcome(rec, reaped, waitErr,
		time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"), time.Since(startMono))

	if *noCgroup {
		rec.FinalCPUUsageUsec = MeasuredInt64{Measured: false, Reason: noCgroupReason}
		rec.FinalMemoryPeakBytes = MeasuredInt64{Measured: false, Reason: noCgroupReason}
		rec.CgroupRemoved = MeasuredBool{Measured: false, Reason: noCgroupReason}
		// With no cgroup there is nothing to read residual descendants from; that half of
		// the confirmation is not_measured rather than assumed clean, and the reason says
		// so wherever it is read.
		applyTerminationConfirmation(rec, reaped, MeasuredBool{Measured: false, Reason: noCgroupReason})
	} else {
		finalUsec, fuErr := readCPUStatUsageUsec(*cgroupPath + "/cpu.stat")
		rec.FinalCPUUsageUsec = measuredInt(finalUsec, fuErr)
		finalPeak, fpErr := readSingleInt(*cgroupPath + "/memory.peak")
		if cerr != nil {
			fpErr = fmt.Errorf("memory controller not available: %v", cerr)
		}
		rec.FinalMemoryPeakBytes = measuredInt(finalPeak, fpErr)

		populated, poErr := readCgroupEventsPopulated(*cgroupPath + "/cgroup.events")
		applyTerminationConfirmation(rec, reaped, measuredBool(populated, poErr))

		switch {
		case *keepCgroup:
			rec.CgroupRemoved = MeasuredBool{Measured: true, Value: false,
				Reason: "-keep-cgroup: removal is the caller's own step (cgroup-remove), after its final readings"}
			cgroupOK = true // deliberately left in place; the deferred cleanup must not take it
		case poErr != nil:
			rec.CgroupRemoved = MeasuredBool{Measured: false, Reason: fmt.Sprintf("cannot read cgroup.events: %v", poErr)}
		case populated:
			rec.CgroupRemoved = MeasuredBool{Measured: true, Value: false, Reason: "cgroup.events reports populated=1 (a task is still present); not removed"}
		default:
			if rerr := os.Remove(*cgroupPath); rerr != nil {
				rec.CgroupRemoved = MeasuredBool{Measured: true, Value: false, Reason: rerr.Error()}
			} else {
				rec.CgroupRemoved = MeasuredBool{Measured: true, Value: true}
				cgroupOK = true // already removed; the deferred cleanup above must not try again
			}
		}
	}

	if err := writeRecord(*recordPath, rec); err != nil {
		return fmt.Errorf("supervise: writing final record: %w", err)
	}
	if rec.Status == "stop_unconfirmed" {
		return fmt.Errorf("supervise: process %d did not exit within the bounded wait after SIGKILL; termination is unconfirmed", rec.PID)
	}
	return nil
}
