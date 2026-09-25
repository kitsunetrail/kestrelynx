package sandbox

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fsAccessMaskForABI returns every filesystem access-right bit this
// function knows about that the given Landlock ABI version defines, so a
// ruleset that handles all of them with no allow rules denies every one of
// them. ABI 1 (Linux 5.13) introduced the base set; ABI 2 (5.19) added
// REFER; ABI 3 (6.2) added TRUNCATE; ABI 5 (6.10) added IOCTL_DEV — this
// function knows about exactly those four ABI versions' filesystem bits
// (ABI 4, 6.7, added network rules in a separate ruleset field this
// function does not touch at all: the parser has no network access to
// begin with, seccomp already denies socket/connect). Any ABI version this
// function does not otherwise recognize (0, meaning Landlock is
// unsupported, or anything above 5) falls back to whichever of these four
// known masks applies at or below it — abi==6 gets the same mask as
// abi==5, not "every right that ABI 6 itself might define" — which is a
// stricter ruleset than the running kernel is capable of, never a looser
// one, so it is always safe, just not necessarily complete for a kernel
// newer than this function has been checked against.
func fsAccessMaskForABI(abi int) uint64 {
	const base = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM

	mask := uint64(base)
	if abi >= 2 {
		mask |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		mask |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		mask |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return mask
}

// DetectLandlockABI returns the running kernel's Landlock ABI version, as
// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
// defines: the call takes no ruleset attributes and instead returns the
// version number directly. A kernel with no Landlock support at all
// returns ENOSYS; that is reported as (0, err) rather than papered over,
// since the caller needs to distinguish "no Landlock" (continue in a
// degraded, non-isolating mode) from a real ruleset failure.
func DetectLandlockABI() (int, error) {
	r1, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0,
		uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION),
	)
	if errno != 0 {
		return 0, fmt.Errorf("sandbox: landlock_create_ruleset(version probe): %w", errno)
	}
	return int(r1), nil
}

// RestrictAllFiles creates a Landlock ruleset that handles every
// filesystem access right fsAccessMaskForABI knows about for the detected
// ABI (see its doc comment for exactly which ABI versions and bits that
// is), adds no rules to it (so every handled access is denied everywhere),
// and applies it to every OS thread the Go runtime currently has via
// AllThreadsSyscall6.
//
// landlock_restrict_self applies only to the calling thread (there is no
// TSYNC-equivalent flag for it in the ABI versions this package targets),
// which is why this — like NO_NEW_PRIVS — has to go through
// AllThreadsSyscall6 rather than a single call: a thread this call does not
// reach would keep unrestricted filesystem access, and any goroutine the Go
// scheduler put on it would inherit that gap.
//
// It returns the detected ABI version on success. The ruleset fd is closed
// before returning (landlock_restrict_self only needs it open at the moment
// each thread applies it, and a leaked ruleset fd across the seccomp
// install that follows would just be one more descriptor an already fully
// self-contained parser has no use for).
func RestrictAllFiles() (abi int, err error) {
	abi, err = DetectLandlockABI()
	if err != nil {
		return 0, err
	}
	if abi < 1 {
		return 0, fmt.Errorf("sandbox: landlock not supported by this kernel")
	}

	attr := unix.LandlockRulesetAttr{Access_fs: fsAccessMaskForABI(abi)}
	// Only Access_fs is populated; the syscall is told the struct is just
	// that one 8-byte field, so kernels of any ABI version (older ones that
	// don't know about Access_net/Scoped, and newer ones that do) treat the
	// fields beyond it as zero rather than reading uninitialized memory.
	const attrSize = unsafe.Sizeof(attr.Access_fs)

	rulesetFD, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		attrSize,
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("sandbox: landlock_create_ruleset: %w", errno)
	}
	fd := int(rulesetFD)
	defer unix.Close(fd)

	if _, _, errno := syscall.AllThreadsSyscall6(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(fd), 0, 0, 0, 0, 0,
	); errno != 0 {
		return 0, fmt.Errorf("sandbox: landlock_restrict_self on all threads: %w", errno)
	}
	return abi, nil
}
