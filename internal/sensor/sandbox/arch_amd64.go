//go:build amd64

package sandbox

import "golang.org/x/sys/unix"

// currentAuditArch is AUDIT_ARCH_X86_64 (linux/audit.h: EM_X86_64 |
// __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE = 62 | 0x80000000 | 0x40000000).
// Checking this word first in every filter this package builds is what
// rejects the classic 32-bit-syscall-table seccomp bypass on amd64 (a
// process compiled for amd64 invoking the compat int 0x80 / 32-bit syscall
// entry point, which seccomp_data.arch would report as AUDIT_ARCH_I386
// instead).
const currentAuditArch uint32 = 0xC000003E

// legacySyscallsToDeny lists the numbered syscalls ObserverFilter denies
// unconditionally in addition to openat2/execve/execveat/etc.: open(2) and
// creat(2). Both exist as their own syscall numbers on amd64's syscall
// table (golang.org/x/sys/unix.SYS_OPEN = 2, SYS_CREAT = 85) — legacy
// entries amd64 has carried since it predates the openat(2) family. See
// arch_arm64.go for why this list is empty there instead of using the same
// two numbers: they are not the same syscalls on that architecture, or
// anything at all.
func legacySyscallsToDeny() []uint32 {
	return []uint32{uint32(unix.SYS_OPEN), uint32(unix.SYS_CREAT)}
}
