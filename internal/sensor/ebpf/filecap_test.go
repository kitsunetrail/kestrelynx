package ebpf

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestFileCapabilityExecReportsElevatedCapEffective confirms cap_effective
// is read from the exec'd process's own post-exec credentials (BPF_CORE_READ
// on cred->cap_effective, bpf/kestrelynx.c's kl_exec_success), so a file
// capability alone — with no setuid bit, and run entirely as an unprivileged
// UID — is enough to produce a nonzero EventExecSuccess.CapEffective, not
// only a setuid-root exec's own all-bits-set one.
//
// Needs real privilege beyond CAP_BPF/CAP_PERFMON: CAP_SETFCAP (or root) to
// set a file capability at all, filesystem/kernel support for the
// security.capability xattr (not guaranteed on every temp filesystem), and
// the ability to exec as a different UID (ordinarily only available to root
// or a process with CAP_SETUID). Skipped, not failed, if any of these is
// unavailable — this is an environment capability check, not this test's
// own claim about the Sensor.
func TestFileCapabilityExecReportsElevatedCapEffective(t *testing.T) {
	h, err := Load(1)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	defer h.Close()

	setcapPath, err := exec.LookPath("setcap")
	if err != nil {
		t.Skip("setcap not found in PATH; cannot grant a file capability without it")
	}

	// The unprivileged UID this test execs as (unprivilegedTestUID, defined
	// in privilege_test.go) must be able to traverse every directory down to
	// the file itself, not just the leaf directory holding it: t.TempDir()
	// creates its own directory 0700, under a per-test-binary parent Go's
	// own testing package also creates 0700 (t.TempDir()'s own doc comment:
	// each call gets a unique directory, but says nothing about the parent's
	// own mode) — chmod'ing only the leaf, as an earlier version of this
	// test did, still leaves that parent blocking UID 65534's own traversal,
	// so cmd.Run() below fails with a permission error indistinguishable
	// from a genuinely missing CAP_SETUID, and this test always skips
	// without ever actually exercising the exec it exists to check. A
	// dedicated 0755 directory created directly under os.TempDir() (world-
	// searchable, e.g. /tmp) avoids the whole chain-of-custody problem: only
	// this one new directory's own mode matters.
	dir, err := os.MkdirTemp("", "kl-filecap-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}

	src, err := os.Open("/bin/true")
	if err != nil {
		t.Fatalf("open /bin/true: %v", err)
	}
	srcBytes, err := io.ReadAll(src)
	src.Close()
	if err != nil {
		t.Fatalf("read /bin/true: %v", err)
	}
	path := filepath.Join(dir, "filecap-exec")
	if err := os.WriteFile(path, srcBytes, 0o755); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}

	// cap_net_bind_service is a harmless, ordinarily-available capability to
	// grant via a file capability, chosen only to produce a nonzero
	// cap_effective distinct from an unprivileged exec's own all-zero one —
	// this test does not exercise what the capability itself is used for.
	if out, err := exec.Command(setcapPath, "cap_net_bind_service=+ep", path).CombinedOutput(); err != nil {
		t.Skipf("setcap failed (%v: %s) -- this filesystem/kernel may not support file capabilities here", err, out)
	}

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

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

	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: unprivilegedTestUID, Gid: unprivilegedTestUID}}
	if err := cmd.Run(); err != nil {
		t.Skipf("skipping: cannot exec as UID %d (needs CAP_SETUID or root beyond what CAP_BPF/CAP_PERFMON alone provide): %v", unprivilegedTestUID, err)
	}

	ev, ok := waitForExecSuccess(t, events, errs, st.Ino, 5*time.Second)
	if !ok {
		t.Fatal("timed out waiting for the file-capability exec's own EventExecSuccess")
	}
	if ev.EUID == 0 {
		t.Fatalf("file-capability exec reported EUID 0, want %d — this test's own claim (a file capability alone, "+
			"no setuid) requires this to actually be non-root", unprivilegedTestUID)
	}
	if ev.CapEffective == 0 {
		t.Error("EventExecSuccess.CapEffective = 0 for a file-capability exec, want the granted capability reflected")
	}
}
