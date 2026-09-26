package ebpf

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// floodTargetCount is chosen to comfortably exceed the ring buffer's own
// capacity for distinct records: kl_events is 2 MiB (1<<21 bytes,
// bpf/kestrelynx.c), and each kl_event record is 340 bytes
// (9 __u64 fields + 2 __u32 fields + kind/path_truncated/path_len + a
// 256-byte path buffer), which a BPF ring buffer stores behind its own
// 8-byte-aligned header — roughly 348-352 bytes on the wire per record —
// giving a capacity on the order of 2097152/352 ≈ 5957 records. Flooding
// with more than that many *distinct* dedup keys, without ever draining the
// buffer, is what actually forces bpf_ringbuf_reserve to fail: a single
// repeated target would not, since kl_usage_seen suppresses every repeat of
// an already-successfully-sent key before reservation is even attempted
// (see bpf/kestrelynx.c's own kl_usage_seen/kl_usage_mark doc comment) —
// exactly the gap a flood of the same 2-3 binaries left in an earlier
// version of this test. ASSUMED: comfortably above the estimate to tolerate
// the record-size estimate being slightly off and to guarantee overflow
// rather than merely approach it.
const floodTargetCount = 8000

// totalLost sums LostEvents (the fallback counter) and every value
// LostEventsByCgroup reports into the one Sensor-wide count this test
// actually needs to know changed, without caring which of the two kernel-
// side counters happened to record it.
func totalLost(t *testing.T, h *Handle) uint64 {
	t.Helper()
	lost, err := h.LostEvents()
	if err != nil {
		t.Fatalf("LostEvents: %v", err)
	}
	byCgroup, err := h.LostEventsByCgroup()
	if err != nil {
		t.Fatalf("LostEventsByCgroup: %v", err)
	}
	for _, c := range byCgroup {
		lost += c
	}
	return lost
}

// TestReservationFailureResendsTheSpecificFailedTarget uses distinct keys to
// *reliably* cause bpf_ringbuf_reserve to fail (not relying on incidental
// timing), and identifies that the *specific* target whose reservation
// failed is the one that gets resent — not merely that *some* exec_success
// event turns up afterward, which could just as easily be a leftover,
// unrelated event.
//
// It floods the ring buffer with floodTargetCount distinct, freshly-copied
// executable files (each its own inode, hence its own kl_dedup_usage key)
// without ever draining it, confirms via LostEvents/LostEventsByCgroup that
// this genuinely caused reservation failures, then execs one specific,
// separately identifiable marker file and *requires* — by comparing the
// same two loss counters immediately before and immediately after that
// exact exec, still with nothing draining the buffer — that this marker's
// own first attempt is itself among the ones that failed to reserve space,
// rather than merely assuming it from openat/exec.Command's own success
// (exec succeeding as a process says nothing about whether this Sensor's
// own BPF program managed to reserve ring buffer space for it) or from a
// timeout with nothing found. Only once that failure is directly confirmed,
// and only once draining has actually caught the buffer back up to idle
// (see the drain loop below), does the test exec the marker a second time
// and require its own EventExecSuccess (matched by its own real (dev,
// inode), not merely by kind) to actually appear.
// Needs real privilege (CAP_BPF/CAP_PERFMON); skipped without it.
func TestReservationFailureResendsTheSpecificFailedTarget(t *testing.T) {
	h, err := Load(1)
	if err != nil {
		skipIfUnprivileged(t, err)
		t.Fatalf("Load: %v", err)
	}
	defer h.Close()

	dir := t.TempDir()
	src, err := os.Open("/bin/true")
	if err != nil {
		t.Fatalf("open /bin/true: %v", err)
	}
	srcBytes, err := io.ReadAll(src)
	src.Close()
	if err != nil {
		t.Fatalf("read /bin/true: %v", err)
	}

	copyExecutable := func(name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, srcBytes, 0o755); err != nil {
			t.Fatalf("WriteFile(%s): %v", path, err)
		}
		return path
	}

	// Flood with floodTargetCount distinct copies, entirely before this
	// test ever calls h.Read() — nothing else drains a BPF ring buffer, so
	// every one of these execs is a genuine, undrained reservation attempt.
	for i := 0; i < floodTargetCount; i++ {
		path := copyExecutable("flood-" + strconv.Itoa(i))
		exec.Command(path).Run()
	}

	if lost := totalLost(t, h); lost == 0 {
		t.Fatalf("no losses recorded after flooding %d distinct targets without draining — "+
			"the ring buffer capacity estimate (see floodTargetCount's own doc comment) may be wrong for this kernel/build", floodTargetCount)
	}

	// The marker: its own real (dev, inode), obtained the same way this
	// Sensor's own event does (a plain stat), is what this test actually
	// looks for — never just "some EventExecSuccess arrived".
	markerPath := copyExecutable("marker")
	var st unix.Stat_t
	if err := unix.Stat(markerPath, &st); err != nil {
		t.Fatalf("stat marker: %v", err)
	}
	wantDev, wantIno := st.Dev, st.Ino

	// The marker's own first attempt must be a verified, required
	// precondition of this test — not an assumption, and not merely inferred
	// from a later timeout finding nothing. Nothing has drained the buffer
	// since the flood above, so comparing the same two loss counters
	// immediately before and immediately after this exact exec isolates
	// whatever they report to this one attempt.
	lostBeforeMarker := totalLost(t, h)
	if err := exec.Command(markerPath).Run(); err != nil {
		t.Fatalf("exec marker (first attempt): %v", err)
	}
	if lostAfterMarker := totalLost(t, h); lostAfterMarker <= lostBeforeMarker {
		t.Fatalf("marker's own first exec did not increase the loss counters (before=%d after=%d) -- "+
			"this test requires that attempt's own reservation to have actually failed, not merely "+
			"assumed; floodTargetCount (see its own doc comment) may need to be larger for this "+
			"kernel/build, or the buffer may have already started draining", lostBeforeMarker, lostAfterMarker)
	}

	events := make(chan Event, 256)
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

	// Drain down from the flood's own backlog before the marker's second
	// attempt: without this, that second exec races against a still-full
	// buffer and can fail to reserve space too, for the same reason the
	// first attempt already did, making this test's own final assertion
	// flaky rather than a reliable confirmation of the resend it exists to
	// check. "Drained" here means idle: no new event has arrived for
	// drainIdleWindow, which only happens once the reader has actually
	// caught up with whatever the BPF side is still producing.
	const (
		drainIdleWindow = 500 * time.Millisecond
		drainMaxWait    = 30 * time.Second
	)
	drainDeadline := time.After(drainMaxWait)
	idleTimer := time.NewTimer(drainIdleWindow)
	defer idleTimer.Stop()
drain:
	for {
		select {
		case <-events:
			if !idleTimer.Stop() {
				<-idleTimer.C
			}
			idleTimer.Reset(drainIdleWindow)
		case err := <-errs:
			t.Fatalf("Read: %v", err)
		case <-idleTimer.C:
			break drain
		case <-drainDeadline:
			t.Fatal("timed out waiting for the ring buffer to drain down from the flood")
		}
	}

	findMarker := func(deadline time.Duration) bool {
		timeout := time.After(deadline)
		for {
			select {
			case ev := <-events:
				if ev.Kind == EventExecSuccess {
					// dev/ino from a real fstat (unix.Stat_t.Dev) use the
					// userspace/glibc encoding; ev.Dev/ev.Ino are the raw
					// kernel-internal encoding this package's own
					// DecodeEvent never converts (that conversion is the
					// Sensor's own job — see kerneldev.go in package
					// sensor). Comparing the raw kernel-side inode alone
					// (stable across either encoding) is enough to identify
					// this specific file.
					if ev.Ino == wantIno {
						return true
					}
				}
			case <-timeout:
				return false
			case err := <-errs:
				t.Fatalf("Read: %v", err)
			}
		}
	}

	// The marker's own first attempt is now confirmed (above) to have failed
	// to reserve space; per kl_usage_mark only ever being called after a
	// successful bpf_ringbuf_submit, its own dedup key was never registered
	// as "already sent", so this second exec must produce a fresh,
	// undeduplicated attempt — the resend this test exists to confirm.
	if err := exec.Command(markerPath).Run(); err != nil {
		t.Fatalf("exec marker (second attempt): %v", err)
	}
	if !findMarker(5 * time.Second) {
		t.Fatalf("marker's own EventExecSuccess (dev=%d ino=%d) never appeared after two attempts — "+
			"a target whose reservation failed must still be resent on its next occurrence", wantDev, wantIno)
	}
}
