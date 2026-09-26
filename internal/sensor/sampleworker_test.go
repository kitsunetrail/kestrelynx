package sensor

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// TestRunSampleWorker_UnresolvableBasisWithdrawsProcessEntirely covers the
// same observable consequence a chrooted process has on this Sensor's own
// attribution: when init's own mount-namespace/root identity cannot be
// resolved at all, every process in the job — including one that itself
// reads back successfully — contributes nothing: not even its own exe
// path, and the generation is marked Incomplete rather than guessing.
// resolveMountBasis now runs inside runSampleWorker itself, computed from
// job.init (never injected by loop — see mountBasis's own doc comment), so
// this test forces that resolution to fail the same way a real identity
// change would: job.init carries a Starttime that no longer matches the
// real process behind that PID, which is exactly the guard
// resolveMountBasis applies to every process, including init. This test
// does not call chroot(2) itself (that needs a privilege this test process
// may not have); withdrawing on an unresolved basis is the same withdrawal
// path a genuinely chrooted process's own root/basis mismatch would reach
// once resolved.
func TestRunSampleWorker_UnresolvableBasisWithdrawsProcessEntirely(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	job := sampleJob{
		genKey: "g",
		init:   InitProcess{PID: pid, Starttime: starttime + 1}, // deliberately wrong: resolveMountBasis(job.init) then reports not ok
		processes: []InitProcess{
			{PID: pid, Starttime: starttime}, // the process itself still reads back fine
		},
		indexReady: true,
		now:        time.Now(),
	}

	res := runSampleWorker(job)

	if res.basis.ok {
		t.Errorf("basis.ok = true, want false — job.init's own starttime was deliberately wrong")
	}
	if !res.incomplete {
		t.Errorf("incomplete = false, want true — an unresolvable basis must withdraw every process")
	}
	if len(res.executables) != 0 {
		t.Errorf("executables = %+v, want none — nothing is attributable without a resolved basis", res.executables)
	}
	if len(res.candidates) != 0 {
		t.Errorf("candidates = %+v, want none", res.candidates)
	}
	if res.succeeded == 0 {
		t.Errorf("succeeded = 0, want at least 1 — the process itself was read successfully, just withdrawn for the unresolved basis, not for a read failure")
	}
}

// TestRunSampleWorker_MatchingBasisAttributesNormally is
// UnresolvableBasisWithdrawsProcessEntirely's own control case: a job whose
// init resolves cleanly must let a matching process's exe through
// normally, confirming the withdrawal test above is actually exercising
// the basis resolution, not merely always withdrawing everything
// regardless of the job given.
func TestRunSampleWorker_MatchingBasisAttributesNormally(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	job := sampleJob{
		genKey:     "g",
		init:       InitProcess{PID: pid, Starttime: starttime},
		processes:  []InitProcess{{PID: pid, Starttime: starttime}},
		indexReady: false, // no package-db lookup needed for this test
		now:        time.Now(),
	}
	res := runSampleWorker(job)
	if !res.basis.ok {
		t.Errorf("basis.ok = false, want true — job.init is this real process, whose own basis should resolve cleanly")
	}
	if res.incomplete {
		t.Errorf("incomplete = true, want false — this process's own root does match the basis")
	}
	if len(res.executables) == 0 {
		t.Errorf("executables = none, want this process's own exe to be recorded")
	}
}

// TestOpenRootWithBasis_ReaderMatchesItsOwnReportedBasis covers the whole
// point of merging basis resolution and the actual root fd into one open
// (see openRootWithBasis's own doc comment): the *rootfs.Reader it returns
// must read through the exact same object basis itself describes, since
// both come from the exact same open call, never a separate later reopen
// that a chroot/unshare happening in between could have silently pointed
// somewhere else.
func TestOpenRootWithBasis_ReaderMatchesItsOwnReportedBasis(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	r, basis := openRootWithBasis(InitProcess{PID: pid, Starttime: starttime})
	if r == nil {
		t.Fatalf("openRootWithBasis(self) returned a nil reader")
	}
	defer r.Close()
	if !basis.ok {
		t.Fatalf("basis.ok = false, want true")
	}

	dev, ino, err := r.Stat(".")
	if err != nil {
		t.Fatalf("r.Stat(\".\"): %v", err)
	}
	if dev != basis.rootDev || ino != basis.rootIno {
		t.Errorf("r.Stat(\".\") = %s/%d, want it to match basis's own %s/%d — both must come from the same open, never a separate reopen", dev, ino, basis.rootDev, basis.rootIno)
	}
}

// TestOpenRootWithBasis_RejectsZombie confirms openRootWithBasis's own
// starttime-match check is not enough on its own — see
// confirmGenerationAlive's own doc comment in genconfirm.go for why a
// zombie's own /proc/<pid>/stat still reports its original, unchanged
// starttime right up until its parent actually reaps it. Same reproduction
// as TestConfirmGenerationAliveRejectsZombie: a real child that has already
// exited but is confirmed, via waitid(P_PID, pid, WEXITED|WNOWAIT), not yet
// reaped.
func TestOpenRootWithBasis_RejectsZombie(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start(/bin/true): %v", err)
	}
	pid := cmd.Process.Pid
	defer cmd.Wait()

	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
		t.Fatalf("Waitid(WNOWAIT): %v", err)
	}

	h, err := procfs.Open(pid)
	if err != nil {
		t.Fatalf("procfs.Open(zombie child): %v", err)
	}
	starttime := h.Starttime()
	state, stateErr := h.State()
	h.Close()
	if stateErr != nil {
		t.Fatalf("State: %v", stateErr)
	}
	if state != 'Z' {
		t.Fatalf("test's own precondition failed: state = %q, want 'Z' (zombie)", string(rune(state)))
	}

	r, basis := openRootWithBasis(InitProcess{PID: pid, Starttime: starttime})
	if r != nil {
		r.Close()
	}
	if basis.ok {
		t.Error("openRootWithBasis(zombie init) basis.ok = true, want false -- a zombie's own unchanged starttime must never be treated as proof of life")
	}
}

func mustStarttime(t *testing.T, pid int) int64 {
	t.Helper()
	h, err := procfs.Open(pid)
	if err != nil {
		t.Fatalf("procfs.Open: %v", err)
	}
	defer h.Close()
	return h.Starttime()
}
