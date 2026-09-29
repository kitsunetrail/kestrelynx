package ebpf

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestLoadRejectsZeroExcludedCgroupID(t *testing.T) {
	if _, err := Load(0, 0); err == nil {
		t.Fatal("Load(0) = nil error, want an error (0 means \"no exclusion\" to the BPF side)")
	}
}

// skipIfUnprivileged reports whether err is the kind of permission failure
// expected when this process lacks CAP_BPF/CAP_PERFMON (or root), and skips
// the test if so. Any other error is a real failure the test should report.
func skipIfUnprivileged(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("skipping: process lacks the privilege to load BPF programs: %v", err)
	}
}

// TestLoadAttachAndReceiveEvent is the one test in this package that needs
// real privilege: loading five CO-RE programs, attaching them, and (if that
// succeeds) running a throwaway process to generate real exec events and
// reading them back off the ring buffer. Everything from event decoding
// down is covered without privilege elsewhere in this package; this test
// exists to catch the parts that can only fail at load/attach time
// (program verification, missing BTF, wrong attach type per program) and,
// for EventExecOpen's Path, what only a real bpf_d_path call can show:
// whether the decoded path is exactly the opened file's path with no
// trailing NUL byte left over from bpf_d_path's own return-length
// convention (see events.go's DecodeEvent).
//
// A single exec of a dynamically linked binary produces more than one
// EventExecOpen: loading /bin/true also opens its ELF interpreter
// (ld-linux*.so) with the same FMODE_EXEC flag, so this test does not
// assume the first EventExecOpen it sees is the executable itself. It
// matches by (Dev, Ino) against EventExecSuccess instead, exactly the
// correlation bpf/kestrelynx.c's own comments describe a consumer using.
func TestLoadAttachAndReceiveEvent(t *testing.T) {
	// The excluded cgroup ID only has to be nonzero and not match this
	// test's own cgroup; the test process's own exec events are exactly
	// what it wants to observe.
	h, err := Load(1, 0)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	defer h.Close()

	if lost, err := h.LostEvents(); err != nil {
		t.Fatalf("LostEvents: %v", err)
	} else if lost != 0 {
		t.Errorf("LostEvents = %d immediately after attach, want 0", lost)
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

	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Fatalf("exec /bin/true: %v", err)
	}

	var execSuccess *Event
	var execOpens []Event
	matchingOpen := func() *Event {
		if execSuccess == nil {
			return nil
		}
		for i := range execOpens {
			if execOpens[i].Dev == execSuccess.Dev && execOpens[i].Ino == execSuccess.Ino {
				return &execOpens[i]
			}
		}
		return nil
	}

	deadline := time.After(5 * time.Second)
	var execOpen *Event
	for execOpen == nil {
		select {
		case ev := <-events:
			switch ev.Kind {
			case EventExecSuccess:
				e := ev
				execSuccess = &e
			case EventExecOpen:
				execOpens = append(execOpens, ev)
			}
			execOpen = matchingOpen()
		case err := <-errs:
			t.Fatalf("Read: %v", err)
		case <-deadline:
			h.Close() // unblock the reader goroutine per ringbuf.Reader.Close's documented behavior
			t.Fatalf("timed out waiting for a matching EventExecSuccess/EventExecOpen pair from /bin/true "+
				"(success seen=%v, %d exec-open candidates)", execSuccess != nil, len(execOpens))
		}
	}

	if execSuccess.CgroupID == 0 {
		t.Error("EventExecSuccess.CgroupID = 0, want nonzero")
	}
	if execSuccess.Dev == 0 && execSuccess.Ino == 0 {
		t.Error("EventExecSuccess.Dev and Ino are both 0, want the executed file's identity")
	}

	if strings.IndexByte(execOpen.Path, 0) >= 0 {
		t.Errorf("EventExecOpen.Path = %q contains an embedded NUL byte", execOpen.Path)
	}
	if !strings.HasSuffix(execOpen.Path, "true") {
		t.Errorf("EventExecOpen.Path = %q, want it to end in %q", execOpen.Path, "true")
	}
}

// TestDeletePathSeen_RemovesRealKernelEntry confirms Handle.DeletePathSeen
// actually deletes the matching kl_dedup_path entry from a real kernel map —
// the one part of sensor.pathIndex's own onEvict wiring (see events.go's
// pathIndex and session.go's deletePathSeenKey) that no unprivileged,
// no-kernel unit test elsewhere in this repository can exercise. It never
// attaches any program (a bare Load is enough to create the map), so it
// needs no target process or event to actually observe — just the same
// CAP_BPF/CAP_PERFMON privilege every other test in this file already
// requires and self-skips without (skipIfUnprivileged).
func TestDeletePathSeen_RemovesRealKernelEntry(t *testing.T) {
	h, err := Load(1, 0)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	defer h.Close()

	key := kestrelynxebpfKlPathKey{MntNsId: 1, RootDev: 2, RootIno: 3, Dev: 4, Ino: 5}
	if err := h.objs.KlDedupPath.Update(key, uint64(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seed kl_dedup_path entry: %v", err)
	}
	var got uint64
	if err := h.objs.KlDedupPath.Lookup(key, &got); err != nil {
		t.Fatalf("lookup seeded entry: %v", err)
	}

	if err := h.DeletePathSeen(1, 2, 3, 4, 5); err != nil {
		t.Fatalf("DeletePathSeen: %v", err)
	}
	if err := h.objs.KlDedupPath.Lookup(key, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("lookup after DeletePathSeen = %v, want ebpf.ErrKeyNotExist", err)
	}

	// A second delete of the same, now-absent key must not be treated as an
	// error — see DeletePathSeen's own doc comment on why ErrKeyNotExist
	// specifically is expected, not a failure (the kernel's own LRU_HASH
	// eviction, or a caller racing its own earlier delete, can produce
	// exactly this).
	if err := h.DeletePathSeen(1, 2, 3, 4, 5); err != nil {
		t.Errorf("second DeletePathSeen on an already-absent key = %v, want nil", err)
	}
}
