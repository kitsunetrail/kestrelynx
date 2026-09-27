package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCgroupMkdirTruncatesLongPath confirms kl_cgroup_mkdir's own
// bpf_probe_read_kernel_str truncation check (bpf/kestrelynx.c): a cgroup
// path long enough to fill KL_PATH_MAX (256 bytes) exactly must be reported
// PathTruncated, not handed to Go as an ordinary, seemingly-complete path —
// bpf_probe_read_kernel_str returns that same positive byte count (its
// buffer's own capacity) both when the source fits with room to spare for
// its own NUL and when it had to cut the source off, so a naive "n < 0"
// check (an earlier version of this file's own bug) cannot tell truncation
// from an exact fit, and would let a long cgroup path silently pass through
// with a path that stops mid-name — which cgroupmap.go's own ancestor walk
// could then mismatch against a completely different, shorter host cgroup.
//
// Needs real privilege beyond CAP_BPF/CAP_PERFMON: creating a nested cgroup
// directory this deep, directly under the real /sys/fs/cgroup, needs
// CAP_SYS_ADMIN (or cgroup delegation not ordinarily available to a test
// process); skipped, not failed, if that is unavailable.
func TestCgroupMkdirTruncatesLongPath(t *testing.T) {
	h, err := Load(1, 0)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	defer h.Close()

	// marker is unique to this test run and placed first, so it survives
	// intact even once the kernel truncates the rest of the path (a fixed
	// 256-byte buffer is filled from the start of the string).
	marker := fmt.Sprintf("kl-trunc-test-%d", time.Now().UnixNano())
	segment := strings.Repeat("a", 60)
	topDir := filepath.Join("/sys/fs/cgroup", marker+"-"+segment)
	// Four more nested levels of the same long segment comfortably push the
	// full path (from the cgroup2 root) past 256 bytes.
	deepDir := filepath.Join(topDir, segment, segment, segment, segment)
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Skipf("cannot create a nested cgroup directory (needs CAP_SYS_ADMIN/cgroup delegation): %v", err)
	}
	defer os.RemoveAll(topDir)

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

	deadline := time.After(5 * time.Second)
	sawMarker := false
	for !sawMarker {
		select {
		case ev := <-events:
			if ev.Kind != EventCgroupMkdir || !strings.Contains(ev.Path, marker) {
				continue
			}
			// The deepest mkdir is the one whose own full path actually
			// exceeds the buffer; an intermediate, shorter one along the
			// way may legitimately fit and report PathTruncated=false —
			// only the longest one this test creates is required to be
			// truncated.
			if len(ev.Path) < 200 {
				continue
			}
			sawMarker = true
			if !ev.PathTruncated {
				t.Errorf("EventCgroupMkdir for a path this long (%d chars observed) reported PathTruncated=false, want true", len(ev.Path))
			}
		case err := <-errs:
			t.Fatalf("Read: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for the deeply-nested cgroup's own EventCgroupMkdir")
		}
	}
}
