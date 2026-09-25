package parser

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/sandbox"
	"golang.org/x/sys/unix"
)

// ErrPreCheckFailed means the parser process did not start in the state it
// must: either it already has an effective capability, or PR_SET_DUMPABLE
// did not take. Either is a sign this binary was not launched the way the
// parser requires (a capability-less exec, condition 1), and the caller
// must exit without ever entering the request loop — the observer,
// noticing the parser exit before ever reporting a Report, is what turns
// this into an isolation_failed status in the evidence file.
var ErrPreCheckFailed = errors.New("parser: pre-restriction self-check failed (capability or dumpable state wrong at birth)")

// ErrPostCheckFailed means that after installing both Landlock (if
// available) and the seccomp allow-list, an ordinary file open was not
// denied. This is the same "exit without a Report, let the observer call
// it isolation_failed" situation as ErrPreCheckFailed.
var ErrPostCheckFailed = errors.New("parser: post-restriction self-check failed (open was not denied)")

// Report is the parser's self-check result once it has finished locking
// itself down and is about to enter the request loop. Run sends this as
// the first message on the socket (see protocol.go) so the observer knows
// whether to treat this session as fully isolated or degraded before it
// ever hands over a single fd.
//
// There is no field for the pre/post-restriction checks: those two are
// binary "did the process even come up correctly" gates that, on failure,
// mean the process exits via ErrPreCheckFailed/ErrPostCheckFailed *before*
// a Report is ever built or sent, not something a Report value could
// express as false.
type Report struct {
	// LandlockApplied is true only if RestrictAllFiles succeeded (a
	// supported kernel and a successful landlock_restrict_self on every
	// thread). false means Landlock is unavailable or failed on this
	// kernel; the process continues anyway, running degraded rather than
	// failing outright, relying on the seccomp allow-list alone for
	// containment.
	LandlockApplied bool
	// LandlockABI is the kernel's reported Landlock ABI version. It is 0
	// when LandlockApplied is false.
	LandlockABI int
}

// LockDown applies every restriction the parser must have in place before
// it can safely read anything an untrusted input hands it: PR_SET_DUMPABLE(0)
// first, then a self-check that the process already has no capability and
// is now non-dumpable, then Landlock (best-effort), then
// the seccomp allow-list (mandatory), then a self-check that filesystem
// access is actually denied. It also pins GOMAXPROCS to 1 — see
// sandbox.ParserFilter's doc comment for why a parser process must never
// let the Go scheduler need a second OS thread once the seccomp filter
// (which has no clone/clone3) is active.
//
// Callers must treat ErrPreCheckFailed and ErrPostCheckFailed as "exit
// immediately, do not send a Report, do not enter the request loop": the
// observer is the one that turns a parser exiting before ever reporting
// into an isolation-failure signal, not this package reporting the failure
// itself.
func LockDown() (Report, error) {
	runtime.GOMAXPROCS(1)

	if err := sandbox.SetNonDumpable(); err != nil {
		return Report{}, fmt.Errorf("parser: SetNonDumpable: %w", err)
	}

	capEmpty, err := sandbox.EffectiveEmpty()
	if err != nil {
		return Report{}, fmt.Errorf("parser: read effective capabilities: %w", err)
	}
	dumpable, err := sandbox.Dumpable()
	if err != nil {
		return Report{}, fmt.Errorf("parser: read dumpable: %w", err)
	}
	if !capEmpty || dumpable {
		return Report{}, ErrPreCheckFailed
	}

	// landlock_restrict_self (like seccomp) requires NO_NEW_PRIVS already
	// set on the calling thread, or CAP_SYS_ADMIN (which this process never
	// has). This must happen before RestrictAllFiles, on every thread.
	if err := sandbox.SetNoNewPrivsAll(); err != nil {
		return Report{}, fmt.Errorf("parser: SetNoNewPrivsAll: %w", err)
	}

	var report Report
	if abi, err := sandbox.RestrictAllFiles(); err == nil {
		report.LandlockApplied = true
		report.LandlockABI = abi
	}
	// A Landlock failure is not fatal here (degraded, not failed): the
	// seccomp allow-list installed next has no path to open a file at all,
	// so it alone is still a real (if singular) line of containment.

	filter, err := sandbox.ParserFilter(int32(os.Getpid()))
	if err != nil {
		return report, fmt.Errorf("parser: build seccomp filter: %w", err)
	}
	if err := sandbox.InstallFilter(filter); err != nil {
		return report, fmt.Errorf("parser: install seccomp filter: %w", err)
	}

	_, errOpen := unix.Openat(unix.AT_FDCWD, "/", unix.O_RDONLY, 0)
	if errOpen != unix.EPERM {
		return report, ErrPostCheckFailed
	}
	return report, nil
}
