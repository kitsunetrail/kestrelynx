package sandbox

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetNoNewPrivsAll sets PR_SET_NO_NEW_PRIVS on every OS thread the Go
// runtime currently has running, using syscall.AllThreadsSyscall6. NNP is a
// per-thread task_struct flag (not shared like a process's dumpable bit or
// its mm), and future threads the runtime spawns after this call inherit it
// from whichever existing thread clones them — but a thread that already
// exists when this call is made only gets it if we reach that thread
// directly, which is exactly what AllThreadsSyscall6 does.
//
// cgo is not supported here: AllThreadsSyscall6 returns ENOTSUP when cgo is
// active, because it cannot enumerate non-Go-runtime OS threads.
func SetNoNewPrivsAll() error {
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("sandbox: set no_new_privs on all threads: %w", errno)
	}
	return nil
}

// SetNonDumpable clears the process's dumpable bit (PR_SET_DUMPABLE 0). This
// is a single, process-wide call (not AllThreadsSyscall6): dumpable lives on
// the shared mm_struct, not on the per-thread task_struct, so any one thread
// setting it changes it for the whole process, including threads spawned
// later.
func SetNonDumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("sandbox: set non-dumpable: %w", err)
	}
	return nil
}

// Dumpable reads the process's current dumpable bit via PR_GET_DUMPABLE.
func Dumpable() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return false, fmt.Errorf("sandbox: get dumpable: %w", err)
	}
	return v != 0, nil
}
