package sandbox

import "golang.org/x/sys/unix"

// openWriteFlagsMask is every simple open/openat flag that means "I intend
// to write, create, truncate, or append" — O_WRONLY, O_RDWR, O_CREAT,
// O_TRUNC, O_APPEND. It deliberately excludes O_TMPFILE, which is checked
// separately (see the "any bit set" vs. "every bit set" comment on
// ObserverFilter's check_openat block): O_TMPFILE's own bit pattern
// (linux/fcntl.h: __O_TMPFILE | O_DIRECTORY) *is* O_DIRECTORY plus one more
// bit, by the kernel's own definition, so an "any of these bits" test that
// included it would also fire on any ordinary, read-only
// openat(..., O_DIRECTORY) — such as opening /proc/<pid>/task itself,
// which this package's own self-check does. Confirmed by that self-check
// failing outright before this was split out.
const openWriteFlagsMask = uint32(unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC | unix.O_APPEND)

// ObserverFilter builds the observer's own seccomp-BPF program: the (b)
// layer of the Sensor's containment, installed with TSYNC after the
// process has already opened its evidence file, created its eBPF objects,
// dropped CAP_BPF/CAP_PERFMON, and spawned the parser over a socketpair.
// From that point on this filter denies every remaining way the observer
// could write, execute, signal another process, or open a new
// communication channel — leaving it able to read (procfs, package DBs it
// hands off to the parser as fds), pwrite/ftruncate/fsync its one evidence
// fd, and operate the BPF maps it already holds open.
//
// selfPID is the observer's own PID (tgid): the filter allows tgkill only
// when its first argument equals selfPID, which is what lets the Go
// runtime's async-preemption signal (tgkill(getpid(), tid, sig)) keep
// working after this filter is installed, while still denying the process
// any way to signal a different process or container.
//
// The filter denies with SCMP_ACT_ERRNO(EPERM) rather than killing the
// process: a denied syscall is expected during normal operation (this is a
// deny-list of things the observer's own code should simply never do once
// past startup), not a sign of compromise severe enough to warrant losing
// the observer's own evidence-writing ability mid-request.
func ObserverFilter(selfPID int32) ([]unix.SockFilter, error) {
	prog := []insn{
		loadArch(),
		jeq(currentAuditArch, "check_nr", "deny"),

		labeled("check_nr", loadNr()),
	}
	// Denies open(2)/creat(2) on architectures that have them as their own
	// numbered syscall (amd64); contributes nothing on architectures that
	// don't (arm64), where every file open already goes through
	// openat/openat2 instead — see legacySyscallsToDeny in the per-arch
	// files for exactly why this can't just be "the same two syscalls,
	// different numbers".
	prog = append(prog, legacyOpenCreatChecks(legacySyscallsToDeny(), "l1")...)
	prog = append(prog,
		labeled("l1", jeq(uint32(unix.SYS_OPENAT2), "deny", "l2")),
		labeled("l2", jeq(uint32(unix.SYS_EXECVE), "deny", "l3")),
		labeled("l3", jeq(uint32(unix.SYS_EXECVEAT), "deny", "l4")),
		labeled("l4", jeq(uint32(unix.SYS_KILL), "deny", "l5")),
		labeled("l5", jeq(uint32(unix.SYS_TKILL), "deny", "l6")),
		labeled("l6", jeq(uint32(unix.SYS_RT_SIGQUEUEINFO), "deny", "l7")),
		labeled("l7", jeq(uint32(unix.SYS_RT_TGSIGQUEUEINFO), "deny", "l8")),
		labeled("l8", jeq(uint32(unix.SYS_PIDFD_SEND_SIGNAL), "deny", "l9")),
		labeled("l9", jeq(uint32(unix.SYS_SOCKETPAIR), "deny", "l10")),
		labeled("l10", jeq(uint32(unix.SYS_OPENAT), "check_openat", "l11")),
		labeled("l11", jeq(uint32(unix.SYS_TGKILL), "check_tgkill", "l12")),
		labeled("l12", jeq(uint32(unix.SYS_BPF), "check_bpf", "allow")),

		// check_openat: deny if the flags argument (arg 2) has any of the
		// simple write-ish bits set (any-of test, jset), OR if it is an
		// O_TMPFILE request specifically (every-of test: AND with
		// O_TMPFILE's own bits, then compare equal to O_TMPFILE — jset
		// alone cannot express "every one of these bits", only "at least
		// one"). A plain read-only openat, including one that passes
		// O_DIRECTORY on its own (no O_TMPFILE), falls through to allow.
		labeled("check_openat", loadArgLow(2)),
		jset(openWriteFlagsMask, "deny", "check_openat_tmpfile"),
		labeled("check_openat_tmpfile", loadArgLow(2)),
		andK(uint32(unix.O_TMPFILE)),
		jeq(uint32(unix.O_TMPFILE), "deny", "allow"),

		// check_tgkill: allow only tgkill(selfPID, *, *). High word of a
		// valid pid_t argument is always zero.
		labeled("check_tgkill", loadArgHigh(0)),
		jeq(0, "check_tgkill_low", "deny"),
		labeled("check_tgkill_low", loadArgLow(0)),
		jeq(uint32(selfPID), "allow", "deny"),

		// check_bpf: allow only the four map-operation commands; deny
		// BPF_MAP_CREATE, BPF_PROG_LOAD, and everything else now that the
		// observer has already loaded and linked its programs and no
		// longer holds CAP_BPF/CAP_PERFMON.
		labeled("check_bpf", loadArgHigh(0)),
		jeq(0, "check_bpf_low", "deny"),
		labeled("check_bpf_low", loadArgLow(0)),
		jeq(bpfMapLookupElem, "allow", "bpf2"),
		labeled("bpf2", jeq(bpfMapUpdateElem, "allow", "bpf3")),
		labeled("bpf3", jeq(bpfMapDeleteElem, "allow", "bpf4")),
		labeled("bpf4", jeq(bpfMapGetNextKey, "allow", "deny")),

		labeled("allow", ret(unix.SECCOMP_RET_ALLOW)),
		labeled("deny", ret(unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM))),
	)
	return assemble(prog)
}

// legacyOpenCreatChecks returns the instructions that deny each syscall
// number in nrs (chained together with jeq, falling through to
// fallthroughLabel once none matches), or nil if nrs is empty — in which
// case it contributes no instructions at all, and execution simply
// continues on to whatever follows it in the caller's slice. nrs is a
// parameter (rather than this function calling legacySyscallsToDeny()
// itself) so a test can exercise both the empty and non-empty shapes
// without needing to cross-compile or emulate another architecture.
func legacyOpenCreatChecks(nrs []uint32, fallthroughLabel string) []insn {
	switch len(nrs) {
	case 0:
		return nil
	case 1:
		return []insn{jeq(nrs[0], "deny", fallthroughLabel)}
	case 2:
		return []insn{
			jeq(nrs[0], "deny", "legacy_creat"),
			labeled("legacy_creat", jeq(nrs[1], "deny", fallthroughLabel)),
		}
	default:
		// Not reached by any architecture this package supports today; if
		// a third legacy syscall number is ever added to some future
		// architecture's list, extend this instead of guessing at a
		// three-element chain here.
		panic("legacyOpenCreatChecks: unsupported number of legacy syscalls")
	}
}
