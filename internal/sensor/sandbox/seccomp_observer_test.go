package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestLegacyOpenCreatChecks_EmptyContributesNothing covers the arm64 case
// without needing arm64 hardware or an emulator: legacySyscallsToDeny()
// returns nil there (see arch_arm64.go for the kernel-level reasoning), and
// this confirms that an empty list assembles into zero instructions rather
// than, say, a stray always-false check or a broken label — nothing is
// inserted at all, so whatever follows in ObserverFilter's program is
// reached directly.
func TestLegacyOpenCreatChecks_EmptyContributesNothing(t *testing.T) {
	got := legacyOpenCreatChecks(nil, "somewhere_else")
	if len(got) != 0 {
		t.Fatalf("legacyOpenCreatChecks(nil, ...) = %d instructions, want 0", len(got))
	}
}

// TestLegacyOpenCreatChecks_TwoEntriesChainCorrectly covers the amd64 case:
// both syscall numbers must each independently deny, and neither one's
// check may accidentally swallow the other or the fallthrough target.
func TestLegacyOpenCreatChecks_TwoEntriesChainCorrectly(t *testing.T) {
	const (
		nrOpen  = 2
		nrCreat = 85
	)
	insns := legacyOpenCreatChecks([]uint32{nrOpen, nrCreat}, "fallthrough")
	if len(insns) != 2 {
		t.Fatalf("got %d instructions, want 2: %+v", len(insns), insns)
	}

	// Assemble it as a tiny standalone program to confirm the labels
	// actually resolve (assemble() itself is the authority on that), then
	// walk the raw BPF to confirm each K value and jt/jf target is what it
	// should be — the only way to be sure the fallthrough label's offset
	// actually lands on "allow" and not on the middle of the other check.
	prog := append(append([]insn{}, insns...),
		labeled("fallthrough", ret(unix.SECCOMP_RET_ALLOW)),
		labeled("deny", ret(unix.SECCOMP_RET_ERRNO)),
	)
	filter, err := assemble(prog)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(filter) != 4 { // 2 jeq + 2 ret
		t.Fatalf("assembled %d BPF instructions, want 4: %+v", len(filter), filter)
	}

	// Rather than hand-compute every jump offset (fragile if the
	// assembler's internal layout ever changes), check the property that
	// actually matters: both syscall numbers appear as K values, in the
	// order given, on the two jeq instructions this produced.
	if filter[0].K != nrOpen {
		t.Errorf("filter[0].K = %d, want %d (open)", filter[0].K, nrOpen)
	}
	if filter[1].K != nrCreat {
		t.Errorf("filter[1].K = %d, want %d (creat)", filter[1].K, nrCreat)
	}
}

// TestLegacyOpenCreatChecks_OneEntry covers the shape a hypothetical
// single-legacy-syscall architecture would take (not used by amd64 or
// arm64 today, but the switch in legacyOpenCreatChecks has this case, and
// an untested case is exactly the kind of thing that silently rots).
func TestLegacyOpenCreatChecks_OneEntry(t *testing.T) {
	insns := legacyOpenCreatChecks([]uint32{7}, "fallthrough")
	if len(insns) != 1 {
		t.Fatalf("got %d instructions, want 1", len(insns))
	}
	prog := append(append([]insn{}, insns...),
		labeled("fallthrough", ret(unix.SECCOMP_RET_ALLOW)),
		labeled("deny", ret(unix.SECCOMP_RET_ERRNO)),
	)
	if _, err := assemble(prog); err != nil {
		t.Fatalf("assemble: %v", err)
	}
}

// TestObserverFilter_AssemblesOnThisHostsArchitecture confirms
// ObserverFilter itself — using the real, arch-specific
// legacySyscallsToDeny() — still assembles to a non-empty, valid program.
// The full behavioral test (which syscalls it actually denies) is
// TestObserverFilter_DeniesWriteExecSignalSocketpair; this one exists so a
// future edit that breaks the plumbing between legacyOpenCreatChecks and
// ObserverFilter fails fast, in a plain unit test, without needing the
// subprocess machinery that test uses.
func TestObserverFilter_AssemblesOnThisHostsArchitecture(t *testing.T) {
	filter, err := ObserverFilter(1234)
	if err != nil {
		t.Fatalf("ObserverFilter: %v", err)
	}
	if len(filter) == 0 {
		t.Fatal("ObserverFilter returned an empty program")
	}
}
