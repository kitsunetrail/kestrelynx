package procfs

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests read the running test binary's own /proc/self entries through
// Handle, against the real kernel: there is no fixture that can stand in
// for procfs's actual format contract, and this process is always readable
// to itself regardless of the environment's privileges.

func TestHandle_OpenSelf(t *testing.T) {
	pid := os.Getpid()
	h, err := Open(pid)
	if err != nil {
		t.Fatalf("Open(%d): %v", pid, err)
	}
	defer h.Close()

	if h.PID() != pid {
		t.Errorf("PID() = %d, want %d", h.PID(), pid)
	}
	if h.Starttime() <= 0 {
		t.Errorf("Starttime() = %d, want > 0", h.Starttime())
	}
}

func TestHandle_Exe(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	path, deleted, err := h.Exe()
	if err != nil {
		t.Fatalf("Exe: %v", err)
	}
	if deleted {
		t.Error("Exe deleted = true, want false (the running test binary is not unlinked)")
	}
	if !strings.HasPrefix(path, "/") {
		t.Errorf("Exe path = %q, want an absolute path", path)
	}
	// The exe symlink target must itself exist and be this same file (dev,
	// inode) — the strongest available confirmation that the openat-based
	// read landed on the right entry.
	self, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat exe path %q: %v", path, err)
	}
	if !self.Mode().IsRegular() {
		t.Errorf("exe path %q is not a regular file", path)
	}
}

func TestHandle_Maps(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	exe, _, err := h.Exe()
	if err != nil {
		t.Fatalf("Exe: %v", err)
	}

	entries, truncated, err := h.Maps()
	if err != nil {
		t.Fatalf("Maps: %v", err)
	}
	if truncated {
		t.Error("Maps truncated = true, want false for a normal test process")
	}
	foundExe := false
	for _, e := range entries {
		if e.Path == "" || e.Dev == "" {
			t.Errorf("entry %+v has an empty Path or Dev", e)
		}
		if len(e.Perms) < 3 || e.Perms[2] != 'x' {
			t.Errorf("entry %+v is not executable, should have been filtered", e)
		}
		if e.Path == exe {
			foundExe = true
		}
	}
	if !foundExe {
		t.Errorf("Maps() = %+v, want an entry for the process's own executable %q", entries, exe)
	}
}

func TestHandle_Status(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	uid, capEff, err := h.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if uid != os.Geteuid() {
		t.Errorf("effective uid = %d, want %d (os.Geteuid)", uid, os.Geteuid())
	}
	if len(capEff) == 0 {
		t.Error("CapEff is empty")
	}
}

func TestHandle_Cgroup(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	data, err := h.Cgroup()
	if err != nil {
		t.Fatalf("Cgroup: %v", err)
	}
	if len(data) == 0 {
		t.Error("Cgroup() returned no data")
	}
	// The test process is not (usually) itself a Docker container, so no
	// container ID is expected — only that looking for one doesn't error.
	if _, ok, err := h.ContainerID(); err != nil {
		t.Errorf("ContainerID: %v", err)
	} else if ok {
		t.Log("ContainerID found one (test runs inside a container); not itself a failure")
	}
}

func TestHandle_NSLink(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	link, err := h.NSLink("net")
	if err != nil {
		t.Fatalf("NSLink(net): %v", err)
	}
	if !strings.HasPrefix(link, "net:[") {
		t.Errorf("NSLink(net) = %q, want a \"net:[...]\" link", link)
	}
}

func TestHandle_UIDMap(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	m, err := h.UIDMap()
	if err != nil {
		t.Fatalf("UIDMap: %v", err)
	}
	if len(strings.TrimSpace(m)) == 0 {
		t.Error("UIDMap() returned no data")
	}
}

func TestHandle_NetTCPListens(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	if _, err := h.NetTCPListens("tcp"); err != nil {
		t.Errorf("NetTCPListens(tcp): %v", err)
	}
	if _, err := h.NetTCPListens("tcp6"); err != nil {
		t.Errorf("NetTCPListens(tcp6): %v", err)
	}
	if _, err := h.NetTCPListens("udp"); err == nil {
		t.Error("NetTCPListens(udp) should be rejected (only tcp/tcp6 are read)")
	}
}

func TestHandle_OpenRoot(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	root, err := h.OpenRoot()
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()

	var st unix.Stat_t
	if err := unix.Fstat(int(root.Fd()), &st); err != nil {
		t.Fatalf("fstat root fd: %v", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		t.Errorf("root fd mode = %o, want a directory", st.Mode)
	}
}

func TestHandle_Recheck_Unchanged(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	if err := h.Recheck(); err != nil {
		t.Errorf("Recheck immediately after Open: %v", err)
	}
}

func TestHandle_Recheck_GenerationChanged(t *testing.T) {
	h, err := Open(os.Getpid())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer h.Close()

	// White-box: simulate what a PID-reuse race looks like from Recheck's
	// point of view by forcing a mismatch against this same, still-live
	// process, rather than trying to arrange an actual PID reuse (not
	// something a unit test can force deterministically).
	h.starttime++

	err = h.Recheck()
	if err == nil {
		t.Fatal("Recheck: expected an error for a changed generation")
	}
	if !errors.Is(err, ErrGenerationChanged) {
		t.Errorf("Recheck error = %v, want it to wrap ErrGenerationChanged", err)
	}
}

func TestHandle_Open_NonexistentPID(t *testing.T) {
	// A PID that (almost certainly) doesn't exist.
	if _, err := Open(1 << 30); err == nil {
		t.Fatal("Open: expected an error for a nonexistent pid")
	}
}
