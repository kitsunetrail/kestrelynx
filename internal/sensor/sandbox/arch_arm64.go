//go:build arm64

package sandbox

// currentAuditArch is AUDIT_ARCH_AARCH64 (linux/audit.h: EM_AARCH64 |
// __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE = 183 | 0x80000000 | 0x40000000).
// See arch_amd64.go for why this check exists.
const currentAuditArch uint32 = 0xC00000B7

// legacySyscallsToDeny is empty on arm64: open(2) and creat(2) do not exist
// as syscalls here at all, under any number. arm64 syscalls are numbered
// from the kernel's generic table (include/uapi/asm-generic/unistd.h),
// which — unlike amd64's own table — was written after openat(2) already
// existed and never assigned open/creat a number of their own; every
// arm64 C library implements open(3) by calling openat(AT_FDCWD, ...),
// exactly like golang.org/x/sys/unix.Open does on every architecture (see
// its openat-based implementation in syscall_linux.go). Concretely, on
// arm64, syscall number 2 (amd64's SYS_OPEN) is __NR_io_submit, and number
// 85 (amd64's SYS_CREAT) is __NR_timerfd_create — checking for those
// numbers here would not "also deny open/creat by another number", it
// would deny two unrelated, legitimate syscalls (kernel v6.6
// include/uapi/asm-generic/unistd.h, VERIFIED). golang.org/x/sys/unix
// confirms this from the library side too: it defines no SYS_OPEN or
// SYS_CREAT constant at all for linux/arm64 (zsysnum_linux_arm64.go has no
// such entries), which is what makes referencing them a compile error
// instead of a silently wrong value.
//
// Every way arm64 actually has to open a file — openat and openat2 — is
// still covered by ObserverFilter's own checks regardless of this list
// being empty: the write-flags mask and the O_TMPFILE check apply to
// openat's arguments directly, and openat2 is denied unconditionally by
// syscall number, none of which this function has any say over.
func legacySyscallsToDeny() []uint32 {
	return nil
}
