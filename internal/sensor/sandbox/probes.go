package sandbox

import "golang.org/x/sys/unix"

// Probe is one denied-syscall check from the observer's self-check: a
// syscall that should be unreachable once the container-wide profile and
// the observer's own filter are both active. Err is the error the attempt
// actually returned (nil on unexpected success).
type Probe struct {
	Name string
	Err  error
}

// Denied reports whether the probe's attempt was rejected specifically by a
// permission check — errno EPERM, the action both ObserverFilter and the
// distributed container profile use for every denial in this package. It
// deliberately does not treat any other error as "denied": an invalid
// argument (EINVAL), a target that does not exist (ENOENT), or a bad file
// descriptor (EBADF) all mean the attempt failed for some reason other than
// being blocked, and folding those into "denied" would let a probe that
// was never actually reaching the permission check at all (a typo in a
// path, a malformed handle) masquerade as isolation working correctly.
// Unexpected reports that case instead.
func (p Probe) Denied() bool { return p.Err == unix.EPERM }

// Unexpected reports whether the probe failed for a reason other than
// EPERM — success (Err == nil, the "not denied" gap this package's callers
// care about) is not "unexpected" in that sense, so this is false for it
// too; Unexpected is specifically "something about this attempt itself was
// wrong, independent of whatever isolation is or isn't in place".
func (p Probe) Unexpected() bool { return p.Err != nil && p.Err != unix.EPERM }

// RunProbes attempts every syscall in the observer's self-check probe list
// that is safe to attempt from a process that must keep running afterward
// — meaning an unexpected *success* leaves the calling process's own state
// unchanged, not just that the attempt itself doesn't panic. It reports
// what happened to each, without interpreting the results: a probe that
// unexpectedly succeeds does not, on its own, distinguish
// "isolation_degraded" from "isolation_failed" — that judgement belongs to
// whatever holds the Sensor's full self-check state (see package doc).
//
// This is 5 of the design's 7 self-check probes. The other two —
// execve and ptrace(PTRACE_TRACEME) — are in RunUnsafeProbes instead: see
// its doc comment for why they must never be called from here.
func RunProbes() []Probe {
	return []Probe{
		probeOpenByHandleAt(),
		probeSocketUnix(),
		probeSocketpairDgram(),
		probeOpenatWronly(),
		probeBPFProgLoad(),
	}
}

// RunUnsafeProbes attempts the two self-check probes whose unexpected
// *success* changes the calling process's own state in a way nothing can
// undo:
//
//   - execve replaces the calling process's entire image on success. If
//     this is not denied (isolation degraded to the point that (a) and (b)
//     both failed to catch it), the process that called RunUnsafeProbes
//     stops existing as itself the moment this returns — there is no
//     "continue running the observer afterward".
//   - ptrace(PTRACE_TRACEME) on success makes the calling process traced by
//     its own parent. The very next signal or trace-stop event then
//     suspends it waiting for a tracer that was never expecting to act as
//     one (an init process, a shell, systemd, Docker's own supervisor) —
//     found the hard way, by this package's own self-check test hanging a
//     process that needed to keep running after the probe.
//
// Both facts are discovered empirically in this package's own tests, not
// merely reasoned about: an earlier version of this package ran both
// probes as part of RunObserverSelfCheck and left the calling test process
// permanently stopped. execve is attempted first, ptrace(PTRACE_TRACEME)
// second, for the same reason RunUnsafeProbesInSubprocess's own child runs
// them in that order — see its doc comment.
//
// Callers must only invoke this from a disposable process that is about to
// exit regardless of the outcome (a throwaway child spawned solely to run
// these two probes and report back before being reaped) — never from the
// observer's own long-lived process. RunUnsafeProbesInSubprocess is that
// disposable-process wrapper, for a caller that wants the result folded
// into RunObserverSelfCheck; a caller that already knows it is disposable
// itself (this package's own tests, for instance) can call this directly
// instead.
func RunUnsafeProbes() []Probe {
	return []Probe{
		probeExecve(),
		probePtraceTraceme(),
	}
}

func probeOpenByHandleAt() Probe {
	// A zeroed file_handle of a plausible size; open_by_handle_at must
	// reject this long before the handle's content would matter if it is
	// reachable at all (CAP_DAC_READ_SEARCH check happens first).
	h := unix.NewFileHandle(0, make([]byte, 8))
	_, err := unix.OpenByHandleAt(unix.AT_FDCWD, h, unix.O_RDONLY)
	return Probe{Name: "open_by_handle_at", Err: err}
}

func probeSocketUnix() Probe {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.Close(fd)
	}
	return Probe{Name: "socket(AF_UNIX)", Err: err}
}

func probeSocketpairDgram() Probe {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err == nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
	}
	return Probe{Name: "socketpair(AF_UNIX, SOCK_DGRAM)", Err: err}
}

func probeOpenatWronly() Probe {
	fd, err := unix.Openat(unix.AT_FDCWD, "/dev/null", unix.O_WRONLY, 0)
	if err == nil {
		unix.Close(fd)
	}
	return Probe{Name: "openat(O_WRONLY)", Err: err}
}

// probePtraceTraceme must only ever be called from RunUnsafeProbes, by a
// disposable process — see that function's doc comment.
func probePtraceTraceme() Probe {
	// golang.org/x/sys/unix has no PtraceTraceme wrapper on Linux (its
	// exported Ptrace* helpers all target an already-known pid); PTRACE_TRACEME
	// ignores its pid/addr/data arguments, so they are passed as 0.
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0, 0, 0, 0)
	if errno == 0 {
		return Probe{Name: "ptrace(PTRACE_TRACEME)"}
	}
	return Probe{Name: "ptrace(PTRACE_TRACEME)", Err: errno}
}

// probeExecve must only ever be called from RunUnsafeProbes, by a
// disposable process — see that function's doc comment.
func probeExecve() Probe {
	argv := []string{"/bin/true"}
	err := unix.Exec("/bin/true", argv, nil)
	// A successful exec never returns, so reaching this line already means
	// it was denied; Exec's own error (nil is impossible here) is returned
	// for completeness.
	return Probe{Name: "execve", Err: err}
}

func probeBPFProgLoad() Probe {
	// bpf(BPF_PROG_LOAD, NULL, 0): the attr pointer is never dereferenced
	// before the cmd itself is checked (by the seccomp filter, or by the
	// kernel's own capability check when CAP_BPF is absent).
	_, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(bpfProgLoad), 0, 0)
	if errno == 0 {
		return Probe{Name: "bpf(BPF_PROG_LOAD)"}
	}
	return Probe{Name: "bpf(BPF_PROG_LOAD)", Err: errno}
}
