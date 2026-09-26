package ebpf

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// unprivilegedTestUID is a non-root UID used to exec the same file at low
// privilege before re-execing it as root — nobody's conventional UID on
// every Linux distribution this Sensor targets.
const unprivilegedTestUID = 65534

// TestUsageKeyPrivilegeClassLetsOneTimeHighPrivilegeThrough is a real-kernel
// confirmation of kl_usage_key's own privilege-class fields
// (bpf/kestrelynx.c): a coarse privilege class was added to the "usage"
// dedup key specifically so that a file
// already suppressed at low privilege still produces a fresh
// EventExecSuccess the first time it is used at a different (here, higher)
// privilege — without ever including tgid/start time, which would defeat
// the same key's own point of surviving a hot loop of short-lived,
// equally-privileged execs (see that struct's own doc comment).
//
// This execs the exact same file twice — once as an unprivileged UID, once
// as root — and confirms both produce their own EventExecSuccess for the
// same (dev, inode), never suppressing the second as a mere repeat of the
// first. Needs real privilege (CAP_BPF/CAP_PERFMON) to load the programs,
// and additionally the ability to exec as a different UID (ordinarily only
// available to root, or a process with CAP_SETUID) for the low-privilege
// half; skipped if either is unavailable.
func TestUsageKeyPrivilegeClassLetsOneTimeHighPrivilegeThrough(t *testing.T) {
	h, err := Load(1)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	defer h.Close()

	var st unix.Stat_t
	if err := unix.Stat("/bin/true", &st); err != nil {
		t.Fatalf("stat /bin/true: %v", err)
	}
	wantIno := st.Ino

	events := make(chan Event, 64)
	errs := make(chan error, 1)
	go func() {
		for {
			ev, err := h.Read()
			if err != nil {
				errs <- err
				return
			}
			events <- ev
		}
	}()

	lowPriv := exec.Command("/bin/true")
	lowPriv.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: unprivilegedTestUID, Gid: unprivilegedTestUID}}
	if err := lowPriv.Run(); err != nil {
		t.Skipf("skipping: cannot exec as UID %d (needs CAP_SETUID or root beyond what CAP_BPF/CAP_PERFMON alone provide): %v", unprivilegedTestUID, err)
	}

	lowEv, ok := waitForExecSuccess(t, events, errs, wantIno, 5*time.Second)
	if !ok {
		t.Fatal("timed out waiting for the low-privilege exec's own EventExecSuccess")
	}
	if lowEv.EUID == 0 {
		t.Fatalf("low-privilege exec reported EUID 0, want %d — this test's own privilege-class distinction requires this to actually be non-root", unprivilegedTestUID)
	}

	if os.Getuid() != 0 {
		t.Skip("skipping the high-privilege half: this test process is not root, so a root-EUID exec cannot be produced to compare against")
	}
	highPriv := exec.Command("/bin/true") // no Credential override: runs as this (root) process's own EUID
	if err := highPriv.Run(); err != nil {
		t.Fatalf("exec /bin/true as root: %v", err)
	}

	highEv, ok := waitForExecSuccess(t, events, errs, wantIno, 5*time.Second)
	if !ok {
		t.Fatal("the same file's own second EventExecSuccess (now at root) never appeared — " +
			"a one-time higher-privilege use of an already-reported file must never be permanently suppressed")
	}
	if highEv.EUID != 0 {
		t.Errorf("high-privilege exec's own EventExecSuccess reported EUID %d, want 0", highEv.EUID)
	}
}

// waitForExecSuccess drains events until an EventExecSuccess matching
// wantIno arrives (or deadline elapses), reporting ok=false on timeout.
func waitForExecSuccess(t *testing.T, events <-chan Event, errs <-chan error, wantIno uint64, deadline time.Duration) (Event, bool) {
	t.Helper()
	timeout := time.After(deadline)
	for {
		select {
		case ev := <-events:
			if ev.Kind == EventExecSuccess && ev.Ino == wantIno {
				return ev, true
			}
		case err := <-errs:
			t.Fatalf("Read: %v", err)
		case <-timeout:
			return Event{}, false
		}
	}
}
