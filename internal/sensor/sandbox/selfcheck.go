package sandbox

import (
	"fmt"
	"os"
)

// SelfCheckReport is the result of running every item in the observer's
// self-check: which checks came back exactly as expected, and which did
// not. It intentionally does not carry an evidence.SensorStatus
// value — mapping Failed/Degraded onto the Sensor's reported status is the
// job of whatever assembles the evidence file (the observer's main loop),
// which knows the full context (e.g. whether eBPF was ever attempted) that
// this package does not.
type SelfCheckReport struct {
	// Failed lists every check whose result means containment did not take
	// effect at all: the process should not start observing.
	Failed []string
	// Degraded lists every check whose result means containment is
	// incomplete but not absent (e.g. the distributed container-wide
	// seccomp profile was not applied): observing can continue, reported
	// as degraded.
	Degraded []string
}

// OK reports whether every check passed.
func (r SelfCheckReport) OK() bool { return len(r.Failed) == 0 && len(r.Degraded) == 0 }

// ObserverSelfCheckInput is everything RunObserverSelfCheck needs that it
// cannot discover on its own: the parser's pid (to read its /proc/<pid>/task
// entries) and the capabilities that must be gone from the observer's own
// effective/permitted sets by the time this check runs (CAP_BPF,
// CAP_PERFMON — passed in rather than hardcoded so a test can check the
// function's logic against a smaller, unprivileged set of "must be absent"
// capabilities).
type ObserverSelfCheckInput struct {
	ParserPID int
	// GuardedCaps must be non-empty in production (the real observer always
	// passes CAP_BPF and CAP_PERFMON here): RunObserverSelfCheck reports an
	// empty slice as a Failed entry rather than silently skipping that
	// check, so a caller that forgets to wire it up gets a hard failure
	// instead of a self-check that quietly verified less than it claims to.
	// A test exercising only the other checks in isolation should call the
	// smaller functions this one is built from (AllCapsExclude, RunProbes,
	// ...) directly instead of passing an empty slice here.
	GuardedCaps []uintptr
	// UnsafeProbes is the result of RunUnsafeProbesInSubprocess, computed
	// by the caller *before* installing ObserverFilter on itself (once
	// that filter is active, this process can no longer exec the
	// subprocess RunUnsafeProbesInSubprocess needs — see its doc comment).
	// Like GuardedCaps, this must be non-nil in production; RunObserverSelfCheck
	// reports a nil value as a Failed entry for the same reason.
	UnsafeProbes []Probe
}

// RunObserverSelfCheck runs every item in the observer's self-check table
// against the current process (as "the observer") and against
// in.ParserPID (as "the parser"), plus the denied-syscall probes. It
// returns an error only when a check could not be performed at all (e.g.
// the parser's /proc entry disappeared); a check that ran and came back
// wrong is recorded in the returned report instead, never as an error.
func RunObserverSelfCheck(in ObserverSelfCheckInput) (SelfCheckReport, error) {
	var report SelfCheckReport

	// Missing required input is itself a self-check failure, not a
	// skipped check: a caller that forgot to compute GuardedCaps or
	// UnsafeProbes should see that as loudly as a check that actually ran
	// and came back wrong, not as a quietly narrower self-check.
	if len(in.GuardedCaps) == 0 {
		report.Failed = append(report.Failed, "GuardedCaps not provided: cannot confirm CAP_BPF/CAP_PERFMON have been dropped")
	}
	if in.UnsafeProbes == nil {
		report.Failed = append(report.Failed, "UnsafeProbes not provided: execve/ptrace(PTRACE_TRACEME) probe results are missing")
	} else {
		for _, want := range []string{"execve", "ptrace(PTRACE_TRACEME)"} {
			if !hasProbe(in.UnsafeProbes, want) {
				report.Failed = append(report.Failed, "UnsafeProbes missing result for "+want)
			}
		}
	}

	selfStatuses, err := ReadTaskStatuses(os.Getpid())
	if err != nil {
		return report, fmt.Errorf("sandbox: self-check: read observer task statuses: %w", err)
	}
	if ok, bad := AllNoNewPrivsAndSeccomp(selfStatuses); !ok {
		report.Failed = append(report.Failed, fmt.Sprintf(
			"observer thread %d: NoNewPrivs=%d Seccomp=%d (want 1, 2)", bad.TID, bad.NoNewPrivs, bad.Seccomp))
	}

	dumpable, err := Dumpable()
	if err != nil {
		return report, fmt.Errorf("sandbox: self-check: read observer dumpable: %w", err)
	}
	if dumpable {
		report.Failed = append(report.Failed, "observer is dumpable")
	}

	if len(in.GuardedCaps) > 0 {
		if ok, bad := AllCapsExclude(selfStatuses, maskFor(in.GuardedCaps)); !ok {
			report.Failed = append(report.Failed, fmt.Sprintf(
				"observer thread %d still holds a guarded capability (CapEff=%016x CapPrm=%016x)", bad.TID, bad.CapEffective, bad.CapPermitted))
		}
	}

	if in.ParserPID > 0 {
		parserStatuses, err := ReadTaskStatuses(in.ParserPID)
		if err != nil {
			return report, fmt.Errorf("sandbox: self-check: read parser task statuses: %w", err)
		}
		if ok, bad := AllNoNewPrivsAndSeccomp(parserStatuses); !ok {
			report.Failed = append(report.Failed, fmt.Sprintf(
				"parser thread %d: NoNewPrivs=%d Seccomp=%d (want 1, 2)", bad.TID, bad.NoNewPrivs, bad.Seccomp))
		}
		if ok, bad := AllCapEffEmpty(parserStatuses); !ok {
			report.Failed = append(report.Failed, fmt.Sprintf(
				"parser thread %d has non-empty CapEff=%016x", bad.TID, bad.CapEffective))
		}
	}

	for _, p := range RunProbes() {
		if !p.Denied() {
			report.Degraded = append(report.Degraded, fmt.Sprintf("probe %q was not denied", p.Name))
		}
	}
	// RunUnsafeProbes (execve, ptrace(PTRACE_TRACEME)) is never called
	// directly here: this function runs inside the observer's own
	// long-lived process, and those two probes' whole failure mode is
	// changing the calling process's own state irrecoverably on unexpected
	// success (replacing its image, or leaving it trace-stopped forever).
	// in.UnsafeProbes carries their result instead, computed by the caller
	// beforehand via RunUnsafeProbesInSubprocess.
	for _, p := range in.UnsafeProbes {
		if !p.Denied() {
			report.Degraded = append(report.Degraded, fmt.Sprintf("probe %q was not denied", p.Name))
		}
	}

	return report, nil
}

// maskFor ORs the given capability numbers into a single bitmask. /proc's
// CapEff/CapPrm fields are a single 64-bit hex value covering capabilities
// 0..63 (unlike CapUserData's two 32-bit words), so this — not capBit,
// which addresses one of those two words — is the right shift to compare
// against a status file's parsed value.
func maskFor(caps []uintptr) uint64 {
	var m uint64
	for _, c := range caps {
		m |= uint64(1) << c
	}
	return m
}

// hasProbe reports whether probes carries a result named name.
func hasProbe(probes []Probe, name string) bool {
	for _, p := range probes {
		if p.Name == name {
			return true
		}
	}
	return false
}
