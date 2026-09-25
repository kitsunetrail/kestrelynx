package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

// parseResultLines turns the helper's "name=OUTCOME" stdout lines into a
// map, so each test can look up the outcome it cares about by name.
func parseResultLines(t *testing.T, out string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		name, val, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unparseable helper output line: %q (full output:\n%s)", line, out)
		}
		m[name] = val
	}
	return m
}

func wantDenied(t *testing.T, results map[string]string, name string) {
	t.Helper()
	got, ok := results[name]
	if !ok {
		t.Fatalf("helper did not report a result for %q (results: %+v)", name, results)
	}
	if !strings.HasPrefix(got, "DENIED:") {
		t.Errorf("%s = %q, want denied", name, got)
	}
}

func wantAllowed(t *testing.T, results map[string]string, name string) {
	t.Helper()
	got, ok := results[name]
	if !ok {
		t.Fatalf("helper did not report a result for %q (results: %+v)", name, results)
	}
	if got != "ALLOWED" {
		t.Errorf("%s = %q, want ALLOWED", name, got)
	}
}

// TestObserverFilter_DeniesWriteExecSignalSocketpair covers the observer
// filter's deny list: write-oriented open/openat, openat2 (always denied,
// since its flags live inside a struct the BPF program cannot read),
// execve, signalling another process, and socketpair (already used up by
// the time this filter installs). A same-pid tgkill and a read-only openat
// must both still succeed, or the filter would be useless to an observer
// that still needs to read procfs and write its evidence file.
//
// On amd64, this also confirms the raw open(2)/creat(2) syscalls are
// denied by number (not just by way of unix.Open's own openat-based
// implementation, which the "open_via_openat_wronly_creat" result already
// covers and which would pass even if the SYS_OPEN/SYS_CREAT checks were
// silently missing). There is nothing to check for this on arm64: those
// two syscalls do not exist there under any number — see
// arch_arm64.go's legacySyscallsToDeny and
// TestLegacyOpenCreatChecks_EmptyContributesNothing, which together cover
// that architecture's shape of this same guarantee without needing arm64
// hardware to run on.
func TestObserverFilter_DeniesWriteExecSignalSocketpair(t *testing.T) {
	out, code := reexecSelf(t, "observer-filter")
	if code != 0 {
		t.Fatalf("helper exited %d, output:\n%s", code, out)
	}
	r := parseResultLines(t, out)

	wantDenied(t, r, "open_via_openat_wronly_creat")
	wantDenied(t, r, "openat_wronly_creat")
	wantDenied(t, r, "openat2")
	wantDenied(t, r, "execve")
	wantDenied(t, r, "kill_self_sig0")
	wantDenied(t, r, "tgkill_other")
	wantDenied(t, r, "socketpair")

	wantAllowed(t, r, "openat_rdonly")
	wantAllowed(t, r, "tgkill_self")

	if len(legacySyscallsToDeny()) > 0 {
		wantDenied(t, r, "raw_open_syscall")
		wantDenied(t, r, "raw_creat_syscall")
	} else {
		if _, ok := r["raw_open_syscall"]; ok {
			t.Errorf("raw_open_syscall was reported on an architecture with no legacy open/creat syscalls")
		}
	}

	// Threads locked and parked before NO_NEW_PRIVS/the seccomp filter
	// existed, released only after both are installed: checked both
	// behaviorally and via /proc/self/task/<tid>/status, by TID, so this
	// actually exercises TSYNC/AllThreadsSyscall6 reaching pre-existing
	// threads rather than only threads created after setup (see
	// observerFilter's own comment on this in testdata/helpermain).
	sawPreThread, sawPreStatus := false, false
	for name, val := range r {
		switch {
		case strings.HasPrefix(name, "pre_existing_thread_"):
			sawPreThread = true
			if !strings.HasPrefix(val, "DENIED:") {
				t.Errorf("%s = %q, want denied", name, val)
			}
		case strings.HasPrefix(name, "proc_status_pre_tid_"):
			sawPreStatus = true
			if val != "NoNewPrivs:1,Seccomp:2" {
				t.Errorf("%s = %q, want NoNewPrivs:1,Seccomp:2", name, val)
			}
		}
	}
	if !sawPreThread || !sawPreStatus {
		t.Errorf("expected both pre_existing_thread_* and proc_status_pre_tid_* results, got: %+v", r)
	}
}

// TestParserFilter_DeniesFileOpen checks the parser filter's core property:
// with Landlock and the parser's allow-list filter both installed, opening
// any file — even one that plainly exists and is world-readable — is
// denied. open(2)/openat(2) are not in the allow-list at all, so seccomp
// itself is what rejects this before Landlock's own denial would apply.
func TestParserFilter_DeniesFileOpen(t *testing.T) {
	stdout, lines, code := reexecSelfWithSocket(t, "parser-filter")
	if code != 0 {
		t.Fatalf("helper exited %d, stdout:\n%s\nsocket lines: %v", code, stdout, lines)
	}
	r := parseResultLines(t, stdout+"\n"+strings.Join(lines, "\n"))

	if abi, ok := r["landlock_abi"]; !ok || abi == "" {
		t.Errorf("helper did not report landlock_abi (results: %+v)", r)
	}
	wantDenied(t, r, "openat_rdonly")
	wantDenied(t, r, "open_rdonly")
}

// TestLandlock_AppliesToAllThreads checks the property that actually
// matters for the parser (launched, and applying Landlock to itself,
// before the observer's own filter exists — nothing about *when* new
// threads appear later can be assumed to matter): RestrictAllFiles must
// reach OS threads that already existed at the moment it is called, not
// only ones a caller creates afterward. The helper locks n goroutines onto
// n real OS threads and parks them *before* calling RestrictAllFiles,
// recording each parked thread's TID, then only releases them once the
// restriction is applied — so this checks specific, pre-existing TIDs by
// number, both behaviorally (file open denied) and via
// /proc/self/task/<tid>/status (NoNewPrivs reads back 1 for that same
// TID), not just "goroutines spawned after setup pass".
func TestLandlock_AppliesToAllThreads(t *testing.T) {
	out, code := reexecSelf(t, "landlock-all-threads")
	if code != 0 {
		t.Fatalf("helper exited %d, output:\n%s", code, out)
	}
	r := parseResultLines(t, out)
	if len(r) == 0 {
		t.Fatalf("no per-thread results reported, output:\n%s", out)
	}
	sawThread, sawProcStatus := false, false
	for name, val := range r {
		switch {
		case strings.HasPrefix(name, "thread_"):
			sawThread = true
			if !strings.HasPrefix(val, "DENIED:") {
				t.Errorf("%s = %q, want denied", name, val)
			}
		case strings.HasPrefix(name, "proc_status_tid_"):
			sawProcStatus = true
			if val != "NoNewPrivs:1" {
				t.Errorf("%s = %q, want NoNewPrivs:1 (this TID existed before RestrictAllFiles/SetNoNewPrivsAll ran)", name, val)
			}
		default:
			t.Errorf("unexpected result key %q = %q", name, val)
		}
	}
	if !sawThread || !sawProcStatus {
		t.Fatalf("expected both thread_* and proc_status_tid_* results, got: %+v", r)
	}
}

// TestAsyncPreemption_SurvivesObserverFilter and
// TestAsyncPreemption_SurvivesParserFilter check the same property from two
// angles: after either filter is installed, the Go runtime's
// async-preemption signal (tgkill(getpid(), tid, SIGURG) followed by
// rt_sigreturn from the handler) must still work, or a goroutine running a
// function-call-free loop could never be stopped for GC. The busy-loop
// goroutines are locked onto OS threads and parked *before* the filter is
// installed, so a passing test means an async-preemption signal reached a
// thread that predated TSYNC — not just a thread the runtime happened to
// create afterward, which would inherit the filter from its creator
// regardless of whether TSYNC itself worked.
func TestAsyncPreemption_SurvivesObserverFilter(t *testing.T) {
	out, code := reexecSelf(t, "async-preempt")
	if code != 0 {
		t.Fatalf("helper exited %d (GC likely hung), output:\n%s", code, out)
	}
	if !strings.Contains(out, "pre_existing_threads=") {
		t.Errorf("expected a pre_existing_threads=N line, got:\n%s", out)
	}
	if !strings.Contains(out, "gc=COMPLETED") {
		t.Errorf("expected gc=COMPLETED, got:\n%s", out)
	}
}

func TestAsyncPreemption_SurvivesParserFilter(t *testing.T) {
	stdout, lines, code := reexecSelfWithSocket(t, "async-preempt-parser")
	if code != 0 {
		t.Fatalf("helper exited %d (GC likely hung), stdout:\n%s\nsocket lines: %v", code, stdout, lines)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "pre_existing_threads=") {
		t.Errorf("expected a pre_existing_threads=N line, got stdout:\n%s\nsocket lines:\n%s", stdout, joined)
	}
	if !strings.Contains(joined, "gc=COMPLETED") {
		t.Errorf("expected gc=COMPLETED, got stdout:\n%s\nsocket lines:\n%s", stdout, joined)
	}
}

// TestSelfCheckProbes_WithoutContainerProfile_ReportsPossibleGaps runs the
// self-check probe list with only the observer's own filter active (no
// container-wide seccomp profile (a), which only a real Docker deployment
// applies — see scripts/gen_sensor_seccomp_profile.py, which real container
// deployment tests separately). socketpair(AF_UNIX, SOCK_DGRAM) and openat(O_WRONLY) and
// execve and bpf(BPF_PROG_LOAD) are denied by the observer's own filter
// regardless; socket(AF_UNIX), open_by_handle_at and
// ptrace(PTRACE_TRACEME) are not restricted by (b) at all, so this
// specific unprivileged test process is expected to succeed at some of
// them — demonstrating exactly the gap the self-check's "probe not denied"
// path exists to catch when profile (a) is missing from a deployment.
func TestSelfCheckProbes_WithoutContainerProfile_ReportsPossibleGaps(t *testing.T) {
	out, code := reexecSelf(t, "self-check-probes", "KL_SANDBOX_APPLY_FILTER=observer")
	if code != 0 {
		t.Fatalf("helper exited %d, output:\n%s", code, out)
	}
	r := parseResultLines(t, out)

	wantDenied(t, r, "socketpair(AF_UNIX, SOCK_DGRAM)")
	wantDenied(t, r, "openat(O_WRONLY)")
	wantDenied(t, r, "execve")
	wantDenied(t, r, "bpf(BPF_PROG_LOAD)")

	// Not restricted without the container-wide profile (a): recorded here
	// as ASSUMED-environment-dependent, not asserted, since an unprivileged
	// CI sandbox could plausibly deny ptrace/socket for reasons unrelated
	// to this package (e.g. a Yama ptrace_scope or a pre-existing seccomp
	// applied by the test runner itself). What matters for this test is
	// only that RunProbes() ran to completion and reported every probe.
	for _, name := range []string{"open_by_handle_at", "socket(AF_UNIX)", "ptrace(PTRACE_TRACEME)"} {
		if _, ok := r[name]; !ok {
			t.Errorf("missing probe result for %q (results: %+v)", name, r)
		}
	}
}

// TestRunObserverSelfCheck_EndToEnd exercises the self-check aggregator end
// to end: a process applies the observer's own restrictions to itself,
// spawns a genuinely separate parser-longlived child (Landlock + seccomp
// applied, not a mock) and a genuinely separate RunUnsafeProbesInSubprocess
// child (execve/ptrace probes, run before this process's own ObserverFilter
// goes live), passes both plus a GuardedCaps list into
// sandbox.RunObserverSelfCheck, and checks the aggregate. With no
// container-wide profile (a) present (this is a raw process, not a Docker
// deployment — see scripts/gen_sensor_seccomp_profile.py), every hard check
// must pass (Failed empty, including the GuardedCaps check finding no
// CAP_BPF/CAP_PERFMON on either process) and exactly the probes only
// profile (a) would have caught — socket(AF_UNIX), and
// ptrace(PTRACE_TRACEME), which ObserverFilter itself never restricts —
// must show up as Degraded, proving the aggregator correctly tells "fully
// isolated" apart from "missing the distributed profile" instead of
// conflating the two, for probes run inline and probes run in the
// unsafe-probe subprocess alike.
func TestRunObserverSelfCheck_EndToEnd(t *testing.T) {
	out, code := reexecSelf(t, "self-check-full")
	if code != 0 {
		t.Fatalf("helper exited %d, output:\n%s", code, out)
	}
	var report struct {
		Failed   []string
		Degraded []string
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &report); err != nil {
		t.Fatalf("unmarshal report %q: %v", out, err)
	}
	if len(report.Failed) != 0 {
		t.Errorf("Failed = %v, want empty (NoNewPrivs/Seccomp/dumpable/CapEff/GuardedCaps all checked out on both processes)", report.Failed)
	}
	for _, want := range []string{`"socket(AF_UNIX)"`, `"ptrace(PTRACE_TRACEME)"`} {
		found := false
		for _, d := range report.Degraded {
			if strings.Contains(d, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("Degraded = %v, want it to include a probe containing %s (only profile (a), absent here, denies it)", report.Degraded, want)
		}
	}
	// execve is denied by ObserverFilter itself (unlike socket/ptrace,
	// which only profile (a) restricts), so it must NOT show up as
	// degraded even without profile (a) present.
	for _, d := range report.Degraded {
		if strings.Contains(d, `"execve"`) {
			t.Errorf("Degraded = %v, execve should be denied by ObserverFilter alone, not reported as a gap", report.Degraded)
		}
	}
}
