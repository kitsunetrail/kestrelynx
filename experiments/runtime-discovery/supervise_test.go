package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMeasuredIntAndBool(t *testing.T) {
	v := measuredInt(42, nil)
	if !v.Measured || v.Value != 42 {
		t.Fatalf("measuredInt(42, nil) = %+v", v)
	}
	v2 := measuredInt(0, errors.New("boom"))
	if v2.Measured || v2.Reason != "boom" {
		t.Fatalf("measuredInt(0, err) = %+v", v2)
	}
	b := measuredBool(true, nil)
	if !b.Measured || !b.Value {
		t.Fatalf("measuredBool(true, nil) = %+v", b)
	}
}

// A measured zero and a measured false must survive the trip through JSON as "value": 0 and
// "value": false. Omitting them would make a brand new cgroup's own CPU baseline (always
// exactly 0) indistinguishable, on the reading side, from a counter that was never read.
func TestMeasuredZeroAndFalseAreEmittedNotOmitted(t *testing.T) {
	b, err := json.Marshal(MeasuredInt64{Measured: true, Value: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"value":0`) {
		t.Fatalf("a measured zero must appear in the JSON, got %s", b)
	}
	b, err = json.Marshal(MeasuredBool{Measured: true, Value: false})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"value":false`) {
		t.Fatalf("a measured false must appear in the JSON, got %s", b)
	}
}

func TestReadCgroupEventsPopulated(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(dir, "cgroup.events"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("populated 0\nfrozen 0\n")
	if v, err := readCgroupEventsPopulated(filepath.Join(dir, "cgroup.events")); err != nil || v {
		t.Fatalf("expected populated=false, got %v err=%v", v, err)
	}
	write("populated 1\nfrozen 0\n")
	if v, err := readCgroupEventsPopulated(filepath.Join(dir, "cgroup.events")); err != nil || !v {
		t.Fatalf("expected populated=true, got %v err=%v", v, err)
	}
	write("frozen 0\n")
	if _, err := readCgroupEventsPopulated(filepath.Join(dir, "cgroup.events")); err == nil {
		t.Fatal("expected an error when no populated line is present, got nil")
	}
	if _, err := readCgroupEventsPopulated(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
}

func TestEnableControllersUpChainRejectsPathOutsideCgroupRoot(t *testing.T) {
	_, _, err := enableControllersUpChain("/tmp/not-under-cgroup-root")
	if err == nil {
		t.Fatal("expected an error for a path outside /sys/fs/cgroup, got nil")
	}
	if !strings.Contains(err.Error(), "not under") {
		t.Fatalf("expected a \"not under\" error, got: %v", err)
	}
}

func TestControllerSetHandlesTheTrailingNewline(t *testing.T) {
	// cgroup.controllers and cgroup.subtree_control are newline-terminated, so the LAST
	// controller named on the line has no trailing space after it. A reader that searched
	// for " memory " in the raw contents of "cpu memory\n" would miss it entirely.
	set := controllerSet([]byte("cpu memory\n"))
	if !set["cpu"] || !set["memory"] {
		t.Fatalf("expected both cpu and memory in %v", set)
	}
	if len(controllerSet([]byte("\n"))) != 0 {
		t.Fatal("an empty controller file must produce an empty set")
	}
}

// buildFakeCgroupTree makes a synthetic cgroup v2 hierarchy (root -> mid -> target) whose
// controller files are written exactly as the kernel writes them - names separated by
// spaces and terminated by a newline - so the ancestor-chain enablement can be exercised
// without root and without a real cgroup mount.
func buildFakeCgroupTree(t *testing.T, availLine, rootSubtree string) (root, target string) {
	t.Helper()
	root = t.TempDir()
	mid := filepath.Join(root, "mid")
	target = filepath.Join(mid, "leaf")
	for _, d := range []string{mid, target} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{root, mid, target} {
		if err := os.WriteFile(filepath.Join(d, "cgroup.controllers"), []byte(availLine), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{root, mid} {
		if err := os.WriteFile(filepath.Join(d, "cgroup.subtree_control"), []byte(rootSubtree), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root, target
}

func TestEnableControllersUpChainEnablesBothOnEveryAncestor(t *testing.T) {
	root, target := buildFakeCgroupTree(t, "cpuset cpu io memory pids\n", "\n")
	saved := cgroupV2Root
	cgroupV2Root = root
	defer func() { cgroupV2Root = saved }()

	enabled, warnings, err := enableControllersUpChain(target)
	if err != nil {
		t.Fatalf("unexpected error: %v (warnings %v)", err, warnings)
	}
	if len(enabled) != 2 {
		t.Fatalf("expected both ancestors (root and mid) to be enabled, got %v", enabled)
	}
	for _, dir := range []string{root, filepath.Join(root, "mid")} {
		got, rerr := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(got) != "+cpu +memory" {
			t.Fatalf("%s/cgroup.subtree_control = %q", dir, got)
		}
	}
}

func TestEnableControllersUpChainAcceptsAnAlreadyEnabledNewlineTerminatedSet(t *testing.T) {
	// The exact shape a normal, already-delegated host presents: "cpu memory\n" both
	// available and already enabled. Nothing must be written, and memory must be found.
	root, target := buildFakeCgroupTree(t, "cpu memory\n", "cpu memory\n")
	saved := cgroupV2Root
	cgroupV2Root = root
	defer func() { cgroupV2Root = saved }()

	enabled, warnings, err := enableControllersUpChain(target)
	if err != nil {
		t.Fatalf("memory must be found in an already-enabled, newline-terminated set: %v (warnings %v)", err, warnings)
	}
	if len(enabled) != 0 {
		t.Fatalf("nothing needed enabling, got %v", enabled)
	}
}

func TestEnableControllersUpChainReportsAMissingMemoryController(t *testing.T) {
	root, target := buildFakeCgroupTree(t, "cpuset cpu io pids\n", "\n")
	saved := cgroupV2Root
	cgroupV2Root = root
	defer func() { cgroupV2Root = saved }()

	if _, _, err := enableControllersUpChain(target); err == nil {
		t.Fatal("expected an error when memory is not available anywhere on the chain")
	}
}

// buildFakeProc constructs a synthetic directory standing in for /proc/<pid>/... so
// applySnapshot's own field-extraction and verification logic can be tested without a real
// process, a real /proc, or root - exactly the "cgroup-less paths with a fake proc tree"
// case supervise's own design calls for.
func buildFakeProc(t *testing.T, pid int, exeTarget string, status string, attrCurrent string, limits string) string {
	t.Helper()
	root := t.TempDir()
	pidDir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(pidDir, "attr"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0644); err != nil {
		t.Fatal(err)
	}
	if exeTarget != "" {
		// The symlink target does not need to exist on disk; os.Readlink only reads the
		// link's own text, which is all the verification compares against expectExe.
		if err := os.Symlink(exeTarget, filepath.Join(pidDir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pidDir, "attr", "current"), []byte(attrCurrent), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "limits"), []byte(limits), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

const fakeStatus = "Name:\tbpftrace\nState:\tS (sleeping)\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\nCapEff:\t0000000000003000\n"

func TestVerifyChildAtMatchingExeAndUID(t *testing.T) {
	const exe = "/var/tmp/kl-privilege/bin/bpftrace"
	root := buildFakeProc(t, 4242, exe, fakeStatus, "unconfined\n", "Max open files 1024\n")
	snap, err := stableChildSnapshot(root, 4242, exe)
	if err != nil {
		t.Fatalf("expected a stable snapshot, got %v", err)
	}
	rec := &SuperviseRecord{}
	applySnapshot(rec, snap, exe, "0000000000003000", true, 1001)

	if !rec.ExeVerified.Measured || !rec.ExeVerified.Value {
		t.Fatalf("expected exe verified true, got %+v (actual_exe=%q)", rec.ExeVerified, rec.ActualExe)
	}
	if rec.RealUID != 1001 || rec.EffectiveUID != 1001 || rec.SavedUID != 1001 || rec.FilesystemUID != 1001 {
		t.Fatalf("expected all four uid fields to be 1001, got real=%d eff=%d saved=%d fs=%d",
			rec.RealUID, rec.EffectiveUID, rec.SavedUID, rec.FilesystemUID)
	}
	if !rec.UIDVerified.Measured || !rec.UIDVerified.Value {
		t.Fatalf("expected uid verified true, got %+v", rec.UIDVerified)
	}
	if !rec.CapEffVerified.Measured || !rec.CapEffVerified.Value {
		t.Fatalf("expected capeff verified true, got %+v (cap_eff=%q)", rec.CapEffVerified, rec.CapEff)
	}
	if rec.AttrCurrent != "unconfined" {
		t.Fatalf("expected attr_current 'unconfined', got %q", rec.AttrCurrent)
	}
	if !strings.HasPrefix(rec.Limits, "Max open files") {
		t.Fatalf("expected the limits text to be carried through, got %q", rec.Limits)
	}
}

func TestVerifyChildAtMismatchedExeIsNotSilentlyTrue(t *testing.T) {
	root := buildFakeProc(t, 100, "/usr/bin/bpftrace", fakeStatus, "", "")
	snap, err := readChildSnapshot(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	rec := &SuperviseRecord{}
	applySnapshot(rec, snap, "/var/tmp/kl-privilege/bin/bpftrace", "", false, 0)
	if !rec.ExeVerified.Measured || rec.ExeVerified.Value {
		t.Fatalf("expected exe verified (measured) false for a mismatched exe, got %+v", rec.ExeVerified)
	}
}

// A snapshot is only taken once the exe actually is the expected binary: this is what keeps
// the recorded uid/CapEff from belonging to some other binary than the one verified.
func TestStableChildSnapshotRefusesAnExeThatNeverBecomesTheExpectedOne(t *testing.T) {
	root := buildFakeProc(t, 55, "/usr/bin/env", fakeStatus, "", "")
	start := time.Now()
	if _, err := stableChildSnapshot(root, 55, "/usr/bin/bpftrace"); err == nil {
		t.Fatal("expected an error when the exe never becomes the expected binary")
	} else if !strings.Contains(err.Error(), "not the expected") {
		t.Fatalf("expected an exe-mismatch error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the bounded poll took %s; it must give up quickly", elapsed)
	}
}

func TestVerifyChildAtStillRootIsNotVerifiedAsNonRoot(t *testing.T) {
	// A process that is still running as uid 0 despite -user being given (a privilege-drop
	// that silently failed) must never be reported as a verified non-root condition.
	rootStatus := "Name:\tbpftrace\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0000003fffffffff\n"
	dir := buildFakeProc(t, 7, "/usr/bin/bpftrace", rootStatus, "", "")
	snap, err := readChildSnapshot(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	rec := &SuperviseRecord{}
	applySnapshot(rec, snap, "", "", true, 1001)
	if !rec.UIDVerified.Measured || rec.UIDVerified.Value {
		t.Fatalf("expected uid verified (measured) false when the process is still uid 0, got %+v", rec.UIDVerified)
	}
}

func TestVerifyChildNoStatusRecordsNotMeasuredNotFabricated(t *testing.T) {
	rec := &SuperviseRecord{}
	verifyChild(rec, 999999999, "/usr/bin/bpftrace", "deadbeef", true, 1001)
	if rec.VerificationError == "" {
		t.Fatal("expected a verification error for a nonexistent pid")
	}
	if rec.ExeVerified.Measured || rec.UIDVerified.Measured || rec.CapEffVerified.Measured {
		t.Fatalf("expected every verification to be reported not_measured, got exe=%+v uid=%+v capeff=%+v",
			rec.ExeVerified, rec.UIDVerified, rec.CapEffVerified)
	}
}

func TestChildEnvRemovesOnlyTheNamedVariables(t *testing.T) {
	t.Setenv("KL_TEST_KEEP", "keep")
	t.Setenv("BPFTRACE_MAX_STRLEN", "200")
	if childEnv(nil) != nil {
		t.Fatal("an empty unset list must leave the child's environment inherited unchanged (nil Cmd.Env)")
	}
	env := childEnv([]string{"BPFTRACE_MAX_STRLEN"})
	for _, kv := range env {
		if strings.HasPrefix(kv, "BPFTRACE_MAX_STRLEN=") {
			t.Fatalf("BPFTRACE_MAX_STRLEN survived in %v", kv)
		}
	}
	found := false
	for _, kv := range env {
		if kv == "KL_TEST_KEEP=keep" {
			found = true
		}
	}
	if !found {
		t.Fatal("an unrelated variable must be left in place")
	}
}

func TestCommaList(t *testing.T) {
	got := commaList(" A, B ,,C ")
	if len(got) != 3 || got[0] != "A" || got[1] != "B" || got[2] != "C" {
		t.Fatalf("commaList = %v", got)
	}
	if commaList("") != nil {
		t.Fatal("an empty value must produce no names")
	}
}

func TestForwardStopSequenceEscalatesOnNonResponsiveProcess(t *testing.T) {
	// A process that ignores SIGINT and SIGTERM must still be brought down by the final
	// SIGKILL. The marker file - written only once the trap is actually installed - closes
	// the race between this test sending its first signal and bash getting there first:
	// without it, a SIGINT delivered before "trap" runs would hit bash's own default
	// (terminate) disposition instead, exiting quickly for the wrong reason and never
	// exercising the SIGKILL escalation this test exists to check.
	marker := filepath.Join(t.TempDir(), "trapped")
	cmd := exec.Command("bash", "-c", "trap '' INT TERM; touch "+marker+"; sleep 30")
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start a test process: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("trap marker never appeared; the helper process did not start as expected")
		}
		time.Sleep(20 * time.Millisecond)
	}

	start := time.Now()
	_, confirmed := forwardStopSequence(cmd.Process.Pid, waitCh, 1) // 1s grace at each stage keeps this test fast
	elapsed := time.Since(start)

	if !confirmed {
		t.Fatal("SIGKILL must have produced a confirmed exit for a plain sleep")
	}
	// With the trap confirmed installed, SIGINT and SIGTERM are both no-ops: this must
	// have gone all the way through both 1s graces to the final SIGKILL stage (whose own
	// wait is capped at 5s), so it should take at least ~2s and comfortably under 10s.
	if elapsed < 2*time.Second {
		t.Fatalf("forwardStopSequence took only %s; expected it to exhaust both 1s graces before SIGKILL", elapsed)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("forwardStopSequence took %s; expected it to reach SIGKILL well under 10s with a 1s grace", elapsed)
	}
}

func TestForwardStopSequenceRespondsToSIGINT(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start a test process: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	start := time.Now()
	_, confirmed := forwardStopSequence(cmd.Process.Pid, waitCh, 5)
	elapsed := time.Since(start)
	if !confirmed {
		t.Fatal("a process that exits on SIGINT must be reported as confirmed")
	}
	// sleep exits promptly on SIGINT (no trap), so this must not have needed to escalate
	// all the way to the 5s SIGTERM/SIGKILL stages.
	if elapsed > 2*time.Second {
		t.Fatalf("forwardStopSequence took %s to stop a process that responds to SIGINT; expected well under the 5s grace", elapsed)
	}
}

func TestForwardStopSequenceReportsAnUnconfirmedStop(t *testing.T) {
	signals := []syscall.Signal{}
	never := make(chan error) // nothing ever reports an exit
	err, confirmed := forwardStopSequenceWith(func(s syscall.Signal) { signals = append(signals, s) },
		never, 10*time.Millisecond, 10*time.Millisecond)
	if confirmed {
		t.Fatal("a stop no exit was ever observed for must never be reported as confirmed")
	}
	if err != nil {
		t.Fatalf("no wait error can be known for an unconfirmed stop, got %v", err)
	}
	if len(signals) != 3 || signals[0] != syscall.SIGINT || signals[1] != syscall.SIGTERM || signals[2] != syscall.SIGKILL {
		t.Fatalf("expected the full INT -> TERM -> KILL escalation, got %v", signals)
	}
}

func TestApplyExitOutcomeRecordsNoExitForAnUnconfirmedStop(t *testing.T) {
	rec := &SuperviseRecord{Status: "running"}
	applyExitOutcome(rec, false, nil, "2026-09-22T00:00:00.000000000Z", 42*time.Second)
	if rec.Status != "stop_unconfirmed" {
		t.Fatalf("status = %q; an unconfirmed termination is never an exit", rec.Status)
	}
	if rec.ExitedAtWall != "" || rec.ExitedAtMonotonic != 0 || rec.ExitCode != nil {
		t.Fatalf("no exit time or status may be recorded for a stop that was never observed: %+v", rec)
	}
}

func TestApplyExitOutcomeRecordsAZeroExitCodeAsZero(t *testing.T) {
	rec := &SuperviseRecord{Status: "running"}
	applyExitOutcome(rec, true, nil, "2026-09-22T00:00:00.000000000Z", time.Second)
	if rec.Status != "exited" || rec.ExitCode == nil || *rec.ExitCode != 0 {
		t.Fatalf("a clean exit must be recorded as exit code 0, got status=%q code=%v", rec.Status, rec.ExitCode)
	}
}

func TestApplyTerminationConfirmationCoversResidualTasks(t *testing.T) {
	cases := []struct {
		name     string
		reaped   bool
		residual MeasuredBool
		wantOK   bool
		wantMeas bool
		wantStat string
	}{
		{"reaped and empty", true, MeasuredBool{Measured: true, Value: false}, true, true, "exited"},
		{"reaped but populated", true, MeasuredBool{Measured: true, Value: true}, false, true, "exited_residual_tasks"},
		{"reaped, residual unknown", true, MeasuredBool{Measured: false, Reason: "no cgroup"}, false, false, "exited"},
		{"never reaped", false, MeasuredBool{Measured: true, Value: false}, false, true, "exited"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &SuperviseRecord{Status: "exited"}
			applyTerminationConfirmation(rec, c.reaped, c.residual)
			if rec.TerminationConfirmed.Measured != c.wantMeas || rec.TerminationConfirmed.Value != c.wantOK {
				t.Fatalf("termination_confirmed = %+v, want measured=%v value=%v",
					rec.TerminationConfirmed, c.wantMeas, c.wantOK)
			}
			if rec.Status != c.wantStat {
				t.Fatalf("status = %q, want %q", rec.Status, c.wantStat)
			}
			if !rec.TerminationConfirmed.Value && rec.TerminationConfirmed.Reason == "" {
				t.Fatal("a termination that is not confirmed must say why")
			}
		})
	}
}

// writeFakeCgroupDir makes one directory with the three files cgroup-stat and
// cgroup-remove actually read, so both can be exercised without root.
func writeFakeCgroupDir(t *testing.T, usageUsec, peak string, populated bool) string {
	t.Helper()
	dir := t.TempDir()
	pop := "0"
	if populated {
		pop = "1"
	}
	for name, content := range map[string]string{
		"cpu.stat":      "usage_usec " + usageUsec + "\nuser_usec 0\nsystem_usec 0\n",
		"memory.peak":   peak + "\n",
		"cgroup.events": "populated " + pop + "\nfrozen 0\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRemoveCgroupWaitsForAnEmptyCgroupAndReportsWhyNot(t *testing.T) {
	populated := writeFakeCgroupDir(t, "1000", "4096", true)
	res := removeCgroup(populated, 0)
	if !res.Removed.Measured || res.Removed.Value {
		t.Fatalf("a populated cgroup must not be removed, got %+v", res.Removed)
	}
	if !strings.Contains(res.Removed.Reason, "populated=1") {
		t.Fatalf("the reason must name the populated flag, got %q", res.Removed.Reason)
	}
	if _, err := os.Stat(populated); err != nil {
		t.Fatal("the directory must still be there")
	}

	empty := writeFakeCgroupDir(t, "1000", "4096", false)
	// A real cgroup directory holds only kernel files, which vanish with it; this stand-in
	// holds regular files, so they are removed first to let os.Remove behave the same way.
	for _, n := range []string{"cpu.stat", "memory.peak", "cgroup.events"} {
		content, _ := os.ReadFile(filepath.Join(empty, n))
		_ = content
	}
	res = removeCgroup(empty, 0)
	if !res.Removed.Measured || res.Removed.Value {
		t.Fatalf("a directory that still holds regular files reports the real failure: %+v", res.Removed)
	}

	missing := filepath.Join(t.TempDir(), "never-created")
	res = removeCgroup(missing, 0)
	if !res.Removed.Measured || !res.Removed.Value {
		t.Fatalf("an already-absent cgroup is not a failure, got %+v", res.Removed)
	}
}

// runSuperviseCapturing runs the supervise subcommand for real (this process is not root,
// so -no-cgroup is what makes the process-supervision half of it exercisable at all) and
// returns the record it wrote.
func runSuperviseCapturing(t *testing.T, args ...string) (*SuperviseRecord, error) {
	t.Helper()
	recordPath := filepath.Join(t.TempDir(), "supervise.json")
	full := append([]string{"-no-cgroup", "-record", recordPath}, args...)
	err := runSupervise(full)
	data, rerr := os.ReadFile(recordPath)
	if rerr != nil {
		t.Fatalf("no record was written (%v); supervise returned %v", rerr, err)
	}
	var rec SuperviseRecord
	if jerr := json.Unmarshal(data, &rec); jerr != nil {
		t.Fatalf("record is not valid JSON: %v\n%s", jerr, data)
	}
	return &rec, err
}

func TestSuperviseRunsACommandToCompletion(t *testing.T) {
	rec, err := runSuperviseCapturing(t, "--", "/bin/sh", "-c", "exit 7")
	if err != nil {
		t.Fatalf("supervise returned %v", err)
	}
	if rec.Status != "exited" || rec.ExitCode == nil || *rec.ExitCode != 7 {
		t.Fatalf("expected a clean exit with code 7, got status=%q code=%v", rec.Status, rec.ExitCode)
	}
	// Without a cgroup there is no way to rule out a descendant the child left behind, so
	// the confirmation is honestly not_measured rather than claimed clean - and the reason
	// says exactly which half is missing.
	if rec.TerminationConfirmed.Measured || !strings.Contains(rec.TerminationConfirmed.Reason, "no-cgroup") {
		t.Fatalf("expected a not_measured confirmation naming the missing cgroup, got %+v", rec.TerminationConfirmed)
	}
	if rec.ExitedAtWall == "" {
		t.Fatal("an observed exit must carry its own time")
	}
	if rec.CgroupMethod != "none" || rec.PlacementAtomic.Measured {
		t.Fatalf("-no-cgroup must report no placement at all, got method=%q atomic=%+v", rec.CgroupMethod, rec.PlacementAtomic)
	}
	if rec.BaselineCPUUsageUsec.Measured || rec.FinalCPUUsageUsec.Measured {
		t.Fatal("-no-cgroup must report every cgroup counter as not_measured, never as zero")
	}
}

func TestSuperviseStopsOnAStopRequestFile(t *testing.T) {
	dir := t.TempDir()
	stop := filepath.Join(dir, "stop_request.txt")
	go func() {
		time.Sleep(1500 * time.Millisecond)
		os.WriteFile(stop, []byte("test stop\n"), 0644)
	}()
	start := time.Now()
	rec, err := runSuperviseCapturing(t, "-stop-request", stop, "-grace", "2", "--", "sleep", "60")
	if err != nil {
		t.Fatalf("supervise returned %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("the stop took %s; the bounded sequence should be far quicker", elapsed)
	}
	if !rec.StopRequested || rec.StopReason != "test stop" {
		t.Fatalf("the stop request must be recorded verbatim, got requested=%v reason=%q", rec.StopRequested, rec.StopReason)
	}
	if rec.Status != "exited" || rec.ExitSignal == "" {
		t.Fatalf("expected an exit by signal, got status=%q signal=%q", rec.Status, rec.ExitSignal)
	}
}

func TestSuperviseEnforcesItsOwnDeadline(t *testing.T) {
	rec, err := runSuperviseCapturing(t, "-deadline", "1", "-grace", "2", "--", "sleep", "60")
	if err != nil {
		t.Fatalf("supervise returned %v", err)
	}
	if !rec.DeadlineExceeded || rec.StopReason != "deadline_exceeded" {
		t.Fatalf("expected the deadline to be recorded, got %+v", rec)
	}
	if rec.Status != "exited" {
		t.Fatalf("status = %q", rec.Status)
	}
}

func TestSuperviseRefusesAUserResolvingToRoot(t *testing.T) {
	err := runSupervise([]string{"-no-cgroup", "-record", filepath.Join(t.TempDir(), "r.json"), "-user", "root", "--", "/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "uid 0") {
		t.Fatalf("expected a refusal naming uid 0, got %v", err)
	}
}

// TestGoToPythonMeasuredJSONBoundary is the boundary test between the two halves of this
// harness: the Go side writes a real cgroup-stat result and a real supervise record, and
// the Python side (load.py, which builds load.json out of exactly these files) reads them
// back. A measured zero - the CPU baseline of a cgroup nothing has run in yet, and the exit
// code of a command that succeeded - must arrive on the Python side as 0, not as a missing
// or unmeasured value.
func TestGoToPythonMeasuredJSONBoundary(t *testing.T) {
	python, perr := exec.LookPath("python3")
	if perr != nil {
		t.Skipf("python3 is not available: %v", perr)
	}
	dir := t.TempDir()

	cgDir := writeFakeCgroupDir(t, "0", "0", false)
	statPath := filepath.Join(dir, "cgroup-stat.json")
	statFile, err := os.Create(statPath)
	if err != nil {
		t.Fatal(err)
	}
	savedStdout := os.Stdout
	os.Stdout = statFile
	statErr := runCgroupStat([]string{cgDir})
	os.Stdout = savedStdout
	statFile.Close()
	if statErr != nil {
		t.Fatalf("cgroup-stat: %v", statErr)
	}

	recordPath := filepath.Join(dir, "supervise.json")
	if err := runSupervise([]string{"-no-cgroup", "-record", recordPath, "--", "/bin/true"}); err != nil {
		t.Fatalf("supervise: %v", err)
	}

	script := `
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), 'tools'))
import load
stat = json.load(open(sys.argv[1]))
rec = json.load(open(sys.argv[2]))
cpu = load.from_measured_json(stat['cpu_usage_usec'], 'missing')
if load.is_not_measured(cpu) or cpu != 0:
    raise SystemExit('measured zero cpu_usage_usec arrived as %r' % (cpu,))
peak = load.from_measured_json(stat['memory_peak_bytes'], 'missing')
if load.is_not_measured(peak) or peak != 0:
    raise SystemExit('measured zero memory.peak arrived as %r' % (peak,))
pop = load.from_measured_json(stat['populated'], 'missing')
if load.is_not_measured(pop) or pop is not False:
    raise SystemExit('measured false populated arrived as %r' % (pop,))
if rec.get('exit_code') != 0:
    raise SystemExit('a zero exit code arrived as %r' % (rec.get('exit_code'),))
base = load.from_measured_json(rec['baseline_cpu_usage_usec'], 'missing')
if not load.is_not_measured(base):
    raise SystemExit('an unread counter must stay not_measured, got %r' % (base,))
print('ok')
`
	out, err := exec.Command(python, "-c", script, statPath, recordPath).CombinedOutput()
	if err != nil {
		t.Fatalf("the Python side could not read the Go side's own JSON: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ok") {
		t.Fatalf("unexpected python output: %s", out)
	}
}

// TestSuperviseHelperProcess is not a test of its own: it is how another test in this file
// runs the supervise subcommand as a REAL separate process (this test binary re-executed
// with KL_SUPERVISE_HELPER_ARGS set), which is the only way to send it a real signal
// without signalling the test process itself.
func TestSuperviseHelperProcess(t *testing.T) {
	args := os.Getenv("KL_SUPERVISE_HELPER_ARGS")
	if args == "" {
		t.Skip("not a helper invocation")
	}
	if err := runSupervise(strings.Split(args, "\x1f")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestSuperviseForwardsASignalThatArrivesDuringStartup(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "supervise.json")
	// -expect-exe names a path the child can never have, which holds the verification poll
	// open for its full two seconds: that is the window in which this stop has to arrive
	// for the test to be testing what it claims to.
	args := []string{"-no-cgroup", "-record", record, "-expect-exe", "/nonexistent-on-purpose",
		"-grace", "1", "--", "sleep", "60"}
	helper := exec.Command(os.Args[0], "-test.run=^TestSuperviseHelperProcess$")
	helper.Env = append(os.Environ(), "KL_SUPERVISE_HELPER_ARGS="+strings.Join(args, "\x1f"))
	helper.Stdout, helper.Stderr = nil, nil
	if err := helper.Start(); err != nil {
		t.Skipf("could not start the helper process: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // inside the verification poll, before the stop loop
	if err := helper.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling the helper: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- helper.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		helper.Process.Kill()
		t.Fatal("the helper did not exit within 30s of SIGTERM")
	}

	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("a stop during startup must still leave a record: %v", err)
	}
	var rec SuperviseRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v\n%s", err, data)
	}
	if !rec.StopRequested || !strings.Contains(rec.StopReason, "during startup") {
		t.Fatalf("the record must say a stop arrived during startup, got requested=%v reason=%q",
			rec.StopRequested, rec.StopReason)
	}
	if rec.Status != "exited" || rec.ExitCode == nil {
		t.Fatalf("the child must have been stopped and reaped, got status=%q code=%v", rec.Status, rec.ExitCode)
	}
	if rec.PID == 0 {
		t.Fatal("the record carries no child pid to check")
	}
	// The whole point: the child must be gone too, not left running by a signal that only
	// ended its supervisor.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscall.Kill(rec.PID, 0); err != nil {
			break // no such process: the child really is gone
		}
		if time.Now().After(deadline) {
			syscall.Kill(rec.PID, syscall.SIGKILL)
			t.Fatalf("child pid %d is still running after its supervisor was signalled during startup", rec.PID)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
