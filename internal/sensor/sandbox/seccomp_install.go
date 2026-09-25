package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// InstallFilter loads filter as the process's seccomp-BPF program via the
// seccomp(2) syscall (not prctl(PR_SET_SECCOMP)): only the syscall form
// accepts flags, and SECCOMP_FILTER_FLAG_TSYNC is what synchronizes the new
// filter onto every other OS thread the Go runtime is currently running, in
// the same call. Without TSYNC, only the calling thread would be filtered,
// leaving every other OS thread — and therefore any goroutine scheduled
// onto one — unrestricted.
//
// The caller must have already set NO_NEW_PRIVS on every thread this call
// needs to reach (via SetNoNewPrivsAll): the kernel requires NNP (or
// CAP_SYS_ADMIN, which the Sensor never holds) per thread before that
// thread will accept a filter, TSYNC included.
func InstallFilter(filter []unix.SockFilter) error {
	if len(filter) == 0 {
		return fmt.Errorf("sandbox: install filter: empty program")
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	r1, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return fmt.Errorf("sandbox: install filter: %w", errno)
	}
	// With SECCOMP_FILTER_FLAG_TSYNC, a thread that could not be
	// synchronized to the new filter is reported by returning its TID as
	// the syscall's own return value — not as a negative errno (kernel
	// v6.6 kernel/seccomp.c: seccomp_set_mode_filter returns ret, and ret
	// is set to the offending TID, not -errno, when
	// seccomp_can_sync_threads fails). r1 == 0 is the only success case;
	// a non-zero r1 here means at least one existing thread is still
	// running under the old filter (or no filter at all), which is
	// exactly the gap self-checking NoNewPrivs/Seccomp per thread exists
	// to catch, but that self-check only runs after this returns, so this
	// return value must be checked directly rather than assumed benign.
	if r1 != 0 {
		return fmt.Errorf("sandbox: install filter: TSYNC failed to synchronize thread %d", r1)
	}
	return nil
}
