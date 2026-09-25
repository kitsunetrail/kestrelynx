package remediation

import (
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// FixClass is where a Finding's fix belongs: a distro update, an
// application-level manifest/lockfile bump, or neither. It is a judgement
// derived from a Finding's own Status/Class/Ecosystem/FixedVer, not an
// identity — the same package can carry a different FixClass per CVE, since
// one CVE on a package can be will_not_fix while another is fixed.
type FixClass string

const (
	FixUnknown     FixClass = "unknown"        // the inputs don't determine a class
	FixOSPackage   FixClass = "os_package"     // fix a distro/base-image update
	FixAppDep      FixClass = "app_dependency" // fix a manifest/lockfile bump
	FixNotFixable  FixClass = "not_fixable"    // upstream has declared it will not fix
	FixNotYetFixed FixClass = "not_yet_fixed"  // upstream has not shipped a fix yet
)

// ClassOf derives a Finding's FixClass, deterministically and without
// guessing: the rules are evaluated in order, and the first match wins.
//
//  1. will_not_fix always means not_fixable, regardless of class or fixedVer.
//  2. affected (upstream hasn't fixed it yet) always means not_yet_fixed.
//  3. fixed + a non-empty fixedVer + an OS package means a distro update.
//  4. fixed + a non-empty fixedVer + a language package with a known
//     ecosystem means an app-level dependency bump.
//  5. everything else — an inconsistent fixed/empty-fixedVer report, a
//     language package whose ecosystem didn't parse, or any other status
//     (fix_deferred, under_investigation, end_of_life, not_affected,
//     unknown) — is unknown rather than a guess: "fixed" alone does not
//     imply a fixable target, and a status this function wasn't told how to
//     read is not silently folded into one that it was.
func ClassOf(status scanner.Status, class inventory.PkgClass, eco inventory.Ecosystem, fixedVer string) FixClass {
	switch {
	case status == scanner.StatusWontFix:
		return FixNotFixable
	case status == scanner.StatusAffected:
		return FixNotYetFixed
	case status == scanner.StatusFixed && fixedVer != "" && class == inventory.ClassOS:
		return FixOSPackage
	case status == scanner.StatusFixed && fixedVer != "" && class == inventory.ClassLang && eco != inventory.EcosystemUnknown:
		return FixAppDep
	default:
		return FixUnknown
	}
}
