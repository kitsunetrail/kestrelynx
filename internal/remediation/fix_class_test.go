package remediation

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// TestClassOf covers every rule in order, plus the boundary conditions the
// rules deliberately don't special-case: an inconsistent "fixed" status with
// no fixed version (on both OS and language packages), a language package
// whose ecosystem didn't parse, and every raw Trivy status ClassOf doesn't
// name explicitly.
func TestClassOf(t *testing.T) {
	cases := []struct {
		name     string
		status   scanner.Status
		class    inventory.PkgClass
		eco      inventory.Ecosystem
		fixedVer string
		want     FixClass
	}{
		// Rule 1: will_not_fix always wins, regardless of class/eco/fixedVer.
		{"wont_fix os", scanner.StatusWontFix, inventory.ClassOS, inventory.EcosystemDebian, "1.2.3", FixNotFixable},
		{"wont_fix lang unknown eco", scanner.StatusWontFix, inventory.ClassLang, inventory.EcosystemUnknown, "", FixNotFixable},

		// Rule 2: affected always means not_yet_fixed, regardless of the rest.
		{"affected os", scanner.StatusAffected, inventory.ClassOS, inventory.EcosystemAlpine, "", FixNotYetFixed},
		{"affected lang with a fixedVer set anyway", scanner.StatusAffected, inventory.ClassLang, inventory.EcosystemNpm, "2.0.0", FixNotYetFixed},

		// Rule 3: fixed + non-empty fixedVer + OS -> os_package. Ecosystem is
		// irrelevant for OS packages (distro Type, or none at all, decides
		// nothing here).
		{"fixed os with known ecosystem", scanner.StatusFixed, inventory.ClassOS, inventory.EcosystemDebian, "1.2.3", FixOSPackage},
		{"fixed os with unknown ecosystem", scanner.StatusFixed, inventory.ClassOS, inventory.EcosystemUnknown, "1.2.3", FixOSPackage},

		// Rule 4: fixed + non-empty fixedVer + lang + known ecosystem ->
		// app_dependency.
		{"fixed lang with known ecosystem", scanner.StatusFixed, inventory.ClassLang, inventory.EcosystemNpm, "2.0.0", FixAppDep},

		// Rule 5 (unknown), each condition in isolation:
		{"fixed os but empty fixedVer (inconsistent report)", scanner.StatusFixed, inventory.ClassOS, inventory.EcosystemDebian, "", FixUnknown},
		{"fixed lang but empty fixedVer (inconsistent report)", scanner.StatusFixed, inventory.ClassLang, inventory.EcosystemNpm, "", FixUnknown},
		{"fixed lang with unknown ecosystem", scanner.StatusFixed, inventory.ClassLang, inventory.EcosystemUnknown, "2.0.0", FixUnknown},
		{"fix_deferred", scanner.StatusFixDeferred, inventory.ClassOS, inventory.EcosystemDebian, "", FixUnknown},
		{"under_investigation", scanner.StatusUnderInvestigation, inventory.ClassLang, inventory.EcosystemNpm, "", FixUnknown},
		{"end_of_life", scanner.StatusEndOfLife, inventory.ClassOS, inventory.EcosystemDebian, "", FixUnknown},
		{"not_affected", scanner.StatusNotAffected, inventory.ClassOS, inventory.EcosystemDebian, "", FixUnknown},
		{"unknown status", scanner.StatusUnknown, inventory.ClassLang, inventory.EcosystemNpm, "", FixUnknown},
		{"a status Trivy might add later", scanner.Status("future_status"), inventory.ClassOS, inventory.EcosystemDebian, "1.2.3", FixUnknown},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassOf(c.status, c.class, c.eco, c.fixedVer)
			if got != c.want {
				t.Errorf("ClassOf(%q, %q, %q, %q) = %q, want %q", c.status, c.class, c.eco, c.fixedVer, got, c.want)
			}
		})
	}
}
