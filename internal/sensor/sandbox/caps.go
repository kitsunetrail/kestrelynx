package sandbox

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// capWord/capBit split a capability number (0..63) into which of the two
// 32-bit words of CapUserData it lives in, and its bit within that word
// (CAP_TO_INDEX / CAP_TO_MASK in <linux/capability.h>).
func capWord(cap uintptr) int              { return int(cap / 32) }
func capBit(cap uintptr) uint32            { return uint32(1) << (cap % 32) }
func hasCap(word uint32, cap uintptr) bool { return word&capBit(cap) != 0 }

// currentCaps reads the calling thread's capability sets via Capget. All
// callers in this file rely on every OS thread having identical capability
// sets at the moment they call it — true after exec (before any thread has
// called capset) and true again right after RaiseEffective or DropAll have
// applied the same change everywhere — so a single-thread read accurately
// describes the whole process.
func currentCaps() (unix.CapUserHeader, [2]unix.CapUserData, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return hdr, data, fmt.Errorf("sandbox: capget: %w", err)
	}
	return hdr, data, nil
}

// setCapsAllThreads applies data via capset on every OS thread the Go
// runtime currently has, using AllThreadsSyscall6. capset's target is always
// "the calling thread" (CapUserHeader.Pid == 0), so running the identical
// syscall on every thread applies the identical new capability sets to each
// of them individually — this is what makes the change effective regardless
// of which OS thread a given goroutine happens to be scheduled on.
//
// Capabilities are thread-specific state in Linux (a deliberate, if
// POSIX-violating, choice predating this codebase), which is exactly why a
// plain single-threaded os/x/sys call would only affect one of the many OS
// threads the Go runtime schedules goroutines onto.
func setCapsAllThreads(hdr unix.CapUserHeader, data [2]unix.CapUserData) error {
	hdr.Pid = 0
	// The uintptr(unsafe.Pointer(...)) conversions must stay inline in this
	// call expression: that is the pattern the compiler recognizes to keep
	// hdr/data alive and pinned for the duration of the syscall, the same
	// rule that applies to syscall.Syscall/RawSyscall (unsafe package doc,
	// "Pattern (4)"); AllThreadsSyscall6 is handled the same way.
	if _, _, errno := syscall.AllThreadsSyscall6(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0, 0, 0, 0,
	); errno != 0 {
		return fmt.Errorf("sandbox: capset on all threads: %w", errno)
	}
	return nil
}

// RaiseEffective sets the given capabilities effective on every OS thread,
// leaving Permitted and Inheritable untouched. Each requested capability
// must already be present in the process's Permitted set (put there by the
// file capability's permitted bits surviving exec); RaiseEffective never
// grants a capability that was not already permitted, and returns an error
// naming the first one that was not.
func RaiseEffective(caps ...uintptr) error {
	hdr, data, err := currentCaps()
	if err != nil {
		return err
	}
	for _, c := range caps {
		w := capWord(c)
		if !hasCap(data[w].Permitted, c) {
			return fmt.Errorf("sandbox: capability %d is not in the permitted set", c)
		}
		data[w].Effective |= capBit(c)
	}
	return setCapsAllThreads(hdr, data)
}

// DropAll removes the given capabilities from both the Effective and
// Permitted sets on every OS thread. Once dropped this way (rather than
// just lowered out of Effective), the capability cannot be raised again
// without a new exec that re-derives Permitted from a file capability —
// which is the point: this is how the observer permanently gives up
// CAP_BPF/CAP_PERFMON after it has finished loading eBPF programs.
func DropAll(caps ...uintptr) error {
	hdr, data, err := currentCaps()
	if err != nil {
		return err
	}
	for _, c := range caps {
		w := capWord(c)
		data[w].Effective &^= capBit(c)
		data[w].Permitted &^= capBit(c)
	}
	return setCapsAllThreads(hdr, data)
}

// EffectiveEmpty reports whether the calling thread's effective capability
// set is entirely zero. It is used by the self-check that confirms the
// observer actually shed CAP_BPF/CAP_PERFMON, and by the parser confirming
// it never had any capability to begin with.
func EffectiveEmpty() (bool, error) {
	_, data, err := currentCaps()
	if err != nil {
		return false, err
	}
	return data[0].Effective == 0 && data[1].Effective == 0, nil
}

// EffectiveHasAny reports whether any of the given capabilities is set in
// the calling thread's effective set. It is used by the self-check that
// confirms CAP_BPF/CAP_PERFMON are gone after DropAll.
func EffectiveHasAny(caps ...uintptr) (bool, error) {
	_, data, err := currentCaps()
	if err != nil {
		return false, err
	}
	for _, c := range caps {
		if hasCap(data[capWord(c)].Effective, c) {
			return true, nil
		}
	}
	return false, nil
}
