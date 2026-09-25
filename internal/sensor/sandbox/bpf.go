package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// This file is a tiny, label-based classic-BPF (cBPF) assembler for
// building seccomp programs by hand. Both filters this package installs
// (ObserverFilter, ParserFilter) are small enough (well under BPF_MAXINSNS)
// that computing raw relative jump offsets by hand would be error-prone and
// unreviewable; a label lets each instruction be written next to the
// condition it tests instead of next to an offset arithmetic comment.
//
// seccomp_data (the struct BPF_ABS loads read from) is a stable kernel UAPI
// (linux/seccomp.h): nr at offset 0, arch at offset 4, instruction_pointer
// at offset 8, args[0..5] (64-bit each) starting at offset 16.
const (
	seccompDataOffNr      = 0
	seccompDataOffArch    = 4
	seccompDataOffArgBase = 16 // offset of args[0]'s low 32 bits
)

// argOffset returns the byte offset of the low 32 bits of syscall argument
// index i (0-based) within seccomp_data, on a little-endian architecture
// (amd64, arm64 — the only two GOARCH values this package supports; see
// currentAuditArch). Each arg slot is 8 bytes wide regardless of the
// syscall's actual argument width, per the struct's own definition.
func argOffsetLow(i int) uint32 { return uint32(seccompDataOffArgBase + i*8) }
func argOffsetHigh(i int) uint32 {
	return uint32(seccompDataOffArgBase + i*8 + 4)
}

// insn is one not-yet-assembled instruction. Exactly one of the "kind"
// groups below applies:
//   - a plain statement (ld/st/alu/ret): filter is used as-is, Jt/Jf ignored
//   - a two-way conditional jump (jeq/jset/...): jt/jf name the labels to
//     jump to on true/false
//   - an unconditional jump (ja): ja names the label to jump to
//
// label, if non-empty, marks this instruction's own position as a jump
// target other instructions may refer to.
type insn struct {
	label string
	sf    unix.SockFilter

	isCond bool
	jt, jf string

	isJA bool
	ja   string
}

func stmt(code uint16, k uint32) insn {
	return insn{sf: unix.SockFilter{Code: code, K: k}}
}

func labeled(label string, i insn) insn {
	i.label = label
	return i
}

func condJump(code uint16, k uint32, jt, jf string) insn {
	return insn{sf: unix.SockFilter{Code: code, K: k}, isCond: true, jt: jt, jf: jf}
}

func jumpAlways(target string) insn {
	return insn{sf: unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JA}, isJA: true, ja: target}
}

// assemble resolves labels into relative jump offsets and returns the final
// program. It returns an error if a label is referenced but never defined,
// or if a computed offset does not fit the 8-bit field cBPF jumps use
// (unsigned for jt/jf, K itself for ja — but classic BPF's ja offset is a
// 32-bit K field, so only jt/jf are actually range-limited).
func assemble(prog []insn) ([]unix.SockFilter, error) {
	pos := make(map[string]int, len(prog))
	for i, in := range prog {
		if in.label == "" {
			continue
		}
		if _, dup := pos[in.label]; dup {
			return nil, fmt.Errorf("sandbox: bpf: duplicate label %q", in.label)
		}
		pos[in.label] = i
	}

	resolve := func(from int, label string) (uint32, error) {
		target, ok := pos[label]
		if !ok {
			return 0, fmt.Errorf("sandbox: bpf: undefined label %q", label)
		}
		off := target - (from + 1)
		if off < 0 {
			return 0, fmt.Errorf("sandbox: bpf: label %q resolves backwards (from %d to %d); this assembler only supports forward jumps", label, from, target)
		}
		return uint32(off), nil
	}

	out := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		switch {
		case in.isJA:
			off, err := resolve(i, in.ja)
			if err != nil {
				return nil, err
			}
			out[i] = unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JA, K: off}
		case in.isCond:
			jt, err := resolve(i, in.jt)
			if err != nil {
				return nil, err
			}
			jf, err := resolve(i, in.jf)
			if err != nil {
				return nil, err
			}
			if jt > 0xff || jf > 0xff {
				return nil, fmt.Errorf("sandbox: bpf: jump offset out of range at instruction %d (jt=%d jf=%d)", i, jt, jf)
			}
			out[i] = unix.SockFilter{Code: in.sf.Code, Jt: uint8(jt), Jf: uint8(jf), K: in.sf.K}
		default:
			out[i] = in.sf
		}
	}
	if len(out) > unix.BPF_MAXINSNS {
		return nil, fmt.Errorf("sandbox: bpf: program has %d instructions, exceeds BPF_MAXINSNS (%d)", len(out), unix.BPF_MAXINSNS)
	}
	return out, nil
}

// loadNr/loadArch load the syscall number / audit arch word into the BPF
// accumulator.
func loadNr() insn   { return stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataOffNr) }
func loadArch() insn { return stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataOffArch) }

// loadArgLow/loadArgHigh load the low/high 32 bits of syscall argument i.
func loadArgLow(i int) insn  { return stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, argOffsetLow(i)) }
func loadArgHigh(i int) insn { return stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, argOffsetHigh(i)) }

// jeq/jset are the two comparisons these filters need against the
// accumulator: equality, and "any of these bits set" (via AND then JNE 0,
// expressed here directly as BPF_JSET so callers don't have to spell out
// the AND step themselves).
func jeq(k uint32, jt, jf string) insn {
	return condJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, k, jt, jf)
}
func jset(k uint32, jt, jf string) insn {
	return condJump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, k, jt, jf)
}

func ret(action uint32) insn { return stmt(unix.BPF_RET|unix.BPF_K, action) }

// andK computes A &= k. Unlike jeq/jset (pure tests that never touch A),
// this modifies the accumulator, so any later instruction that needs the
// original loaded value again must reload it first.
func andK(k uint32) insn { return stmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, k) }
