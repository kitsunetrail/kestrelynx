package sandbox

import (
	"strings"
	"testing"
)

// TestRunObserverSelfCheck_RequiresGuardedCapsAndUnsafeProbes covers the
// production self-check entry point's own input validation: an empty
// GuardedCaps or a nil UnsafeProbes must show up as a Failed entry, not as
// a silently narrower self-check. Without this, a caller that forgot to
// wire either one up would get a SelfCheckReport.OK() == true report that
// never actually checked what it claims to.
func TestRunObserverSelfCheck_RequiresGuardedCapsAndUnsafeProbes(t *testing.T) {
	contains := func(list []string, substr string) bool {
		for _, s := range list {
			if strings.Contains(s, substr) {
				return true
			}
		}
		return false
	}

	t.Run("empty GuardedCaps", func(t *testing.T) {
		report, err := RunObserverSelfCheck(ObserverSelfCheckInput{
			UnsafeProbes: []Probe{{Name: "execve", Err: nil}}, // present but GuardedCaps is not
		})
		if err != nil {
			t.Fatalf("RunObserverSelfCheck: %v", err)
		}
		if !contains(report.Failed, "GuardedCaps not provided") {
			t.Errorf("Failed = %v, want an entry about GuardedCaps not provided", report.Failed)
		}
	})

	t.Run("nil UnsafeProbes", func(t *testing.T) {
		report, err := RunObserverSelfCheck(ObserverSelfCheckInput{
			GuardedCaps: []uintptr{39, 38}, // present but UnsafeProbes is not
		})
		if err != nil {
			t.Fatalf("RunObserverSelfCheck: %v", err)
		}
		if !contains(report.Failed, "UnsafeProbes not provided") {
			t.Errorf("Failed = %v, want an entry about UnsafeProbes not provided", report.Failed)
		}
	})

	t.Run("empty or partial UnsafeProbes", func(t *testing.T) {
		for _, probes := range [][]Probe{{}, {{Name: "execve"}}} {
			report, err := RunObserverSelfCheck(ObserverSelfCheckInput{
				GuardedCaps:  []uintptr{39, 38},
				UnsafeProbes: probes,
			})
			if err != nil {
				t.Fatalf("RunObserverSelfCheck: %v", err)
			}
			if !contains(report.Failed, "UnsafeProbes missing result for ptrace(PTRACE_TRACEME)") {
				t.Errorf("probes %v: Failed = %v, want an entry about the missing ptrace result", probes, report.Failed)
			}
		}
	})

	t.Run("both missing", func(t *testing.T) {
		report, err := RunObserverSelfCheck(ObserverSelfCheckInput{})
		if err != nil {
			t.Fatalf("RunObserverSelfCheck: %v", err)
		}
		if !contains(report.Failed, "GuardedCaps not provided") || !contains(report.Failed, "UnsafeProbes not provided") {
			t.Errorf("Failed = %v, want entries about both GuardedCaps and UnsafeProbes not provided", report.Failed)
		}
		if report.OK() {
			t.Errorf("OK() = true for a self-check missing both required inputs, want false")
		}
	})
}
