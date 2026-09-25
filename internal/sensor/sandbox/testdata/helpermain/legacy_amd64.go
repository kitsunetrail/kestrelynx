//go:build amd64

package main

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeLegacyOpenCreat exercises the raw open(2)/creat(2) syscalls
// directly — via unix.Syscall with the numeric SYS_OPEN/SYS_CREAT
// constants, not unix.Open/unix.Creat, both of which are implemented on
// top of openat(2) on every architecture (golang.org/x/sys/unix,
// syscall_linux.go) and so would never actually exercise these two
// syscall numbers even on amd64. Without this, ObserverFilter's
// unconditional deny of SYS_OPEN/SYS_CREAT had no test ever actually
// issuing either syscall by number.
func probeLegacyOpenCreat() {
	devNull, err := unix.BytePtrFromString("/dev/null")
	if err != nil {
		die("BytePtrFromString(/dev/null)", err)
	}
	_, _, errno := unix.Syscall(unix.SYS_OPEN, uintptr(unsafe.Pointer(devNull)), uintptr(unix.O_RDONLY), 0)
	result("raw_open_syscall", errnoAsError(errno))

	target, err := unix.BytePtrFromString("/tmp/kl-sandbox-test-should-not-be-created-by-creat")
	if err != nil {
		die("BytePtrFromString(creat target)", err)
	}
	_, _, errno = unix.Syscall(unix.SYS_CREAT, uintptr(unsafe.Pointer(target)), 0o600, 0)
	result("raw_creat_syscall", errnoAsError(errno))
}

// errnoAsError returns errno as a plain error, preserving == comparability
// against unix.EPERM (resultLine compares by value, not via errors.Is) —
// wrapping it (e.g. fmt.Errorf("%w", errno)) would defeat that.
func errnoAsError(errno unix.Errno) error {
	if errno == 0 {
		return nil
	}
	return errno
}
