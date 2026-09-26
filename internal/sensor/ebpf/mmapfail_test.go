package ebpf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestFailedMmapNeverBecomesUsageEvidence confirms kl_mmap_success's own
// KL_IS_ERR_VALUE(ret) check (bpf/kestrelynx.c): do_mmap's return value must
// be checked before ever treating a mapping as usage evidence, so a mapping
// attempt that never actually reaches the kernel's own success path must
// never produce an EventMmapSuccess for the file it named.
//
// The failure here is forced at the real kernel level, not merely by a
// Go-side precheck: golang.org/x/sys/unix.Mmap only ever short-circuits in
// Go itself for a non-positive length (mmapper.Mmap: "if length <= 0, return
// EINVAL" before ever reaching the raw syscall) — a zero-length request
// would never actually exercise do_mmap/kl_mmap_success at all, silently
// passing even if this Sensor's own success/failure check were broken. This
// test instead opens a real file O_WRONLY (no read access at all) and
// requests a MAP_PRIVATE mapping of it: Linux's own do_mmap unconditionally
// requires FMODE_READ on the file for MAP_PRIVATE, regardless of the
// requested prot, so this call is guaranteed to reach do_mmap and fail
// inside it with EACCES — exactly the KL_IS_ERR_VALUE(ret) case
// kl_mmap_success exists to check for. The failing Mmap call itself is a
// required, verified precondition of this test, not merely assumed: if it
// somehow succeeded on some kernel/build, the rest of the test would not
// actually be exercising what it claims to.
// Needs real privilege (CAP_BPF/CAP_PERFMON); skipped without it.
func TestFailedMmapNeverBecomesUsageEvidence(t *testing.T) {
	h, err := Load(1)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	defer h.Close()

	const fileSize = 4096

	path := filepath.Join(t.TempDir(), "mmapfail-target")
	if err := os.WriteFile(path, make([]byte, fileSize), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	// O_WRONLY: no FMODE_READ at all, so do_mmap's own MAP_PRIVATE check
	// must reject this regardless of the PROT_EXEC requested here.
	fd, err := unix.Open(path, unix.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s (O_WRONLY): %v", path, err)
	}
	defer unix.Close(fd)

	if _, err := unix.Mmap(fd, 0, fileSize, unix.PROT_EXEC, unix.MAP_PRIVATE); err == nil {
		t.Fatal("Mmap(O_WRONLY fd, PROT_EXEC, MAP_PRIVATE) succeeded, want an error (EACCES) — " +
			"this test's own required precondition (the mapping attempt must actually fail inside the kernel) was not met")
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

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Kind == EventMmapSuccess && ev.Ino == st.Ino {
				t.Fatalf("EventMmapSuccess fired for %s after its own mapping attempt failed — "+
					"a failed mmap must never become usage evidence", path)
			}
		case err := <-errs:
			t.Fatalf("Read: %v", err)
		case <-deadline:
			return // no EventMmapSuccess for this file ever arrived, as required
		}
	}
}
