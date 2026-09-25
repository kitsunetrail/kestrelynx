//go:build arm64

package main

// probeLegacyOpenCreat is a no-op on arm64: open(2)/creat(2) do not exist
// as syscalls at all on this architecture (see
// internal/sensor/sandbox/arch_arm64.go's legacySyscallsToDeny for the
// kernel-level detail), so there is no raw syscall number left to probe.
// ObserverFilter's coverage of arm64's actual file-opening paths
// (openat/openat2) is exercised the same way on every architecture by
// TestObserverFilter_DeniesWriteExecSignalSocketpair; this file exists so
// observerFilter() can call probeLegacyOpenCreat() unconditionally without
// a build tag of its own.
func probeLegacyOpenCreat() {}
