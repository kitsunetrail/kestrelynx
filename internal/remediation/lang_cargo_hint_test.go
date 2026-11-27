package remediation

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// A crate whose fixes are all of another series is left to a person with the
// lowest such fix named, so that a notification can say which version it is.
func TestLanguagePlan_CargoNamesTheFixOfAnotherSeries(t *testing.T) {
	const pkgToml = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1\"\n"
	lock := func(version string) string {
		return cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), cratesBlock("tokio", version, cksumA))
	}
	finding := func(id, installed, fixed string) scanner.Finding {
		return rustFinding(id, typeCargo, "app/Cargo.lock", "tokio", installed, fixed)
	}
	for name, c := range map[string]struct {
		lock     string
		findings []scanner.Finding
		reason   Reason
		fix      string // "" for no hint
	}{
		"the fix is of the next major version": {lock("1.18.0"), []scanner.Finding{finding("CVE-1", "1.18.0", "2.0.1")}, ReasonCargoFixInOtherSeries, "2.0.1"},
		"a 0.x fix of another minor version":   {lock("0.3.1"), []scanner.Finding{finding("CVE-1", "0.3.1", "0.4.0")}, ReasonCargoFixInOtherSeries, "0.4.0"},
		"the lowest fix that fixes every advisory": {lock("1.18.0"),
			[]scanner.Finding{finding("CVE-1", "1.18.0", "1.18.4"), finding("CVE-2", "1.18.0", "2.1.0"), finding("CVE-3", "1.18.0", "2.0.3")}, ReasonCargoFixInOtherSeries, "2.1.0"},
		// An advisory with an older fix of another series, and one fixed in the
		// series in use: the hint is of an incompatible version only.
		"a fix of the series in use is never the hint": {lock("1.5.0"),
			[]scanner.Finding{finding("CVE-1", "1.5.0", "1.0.1, 2.0.1"), finding("CVE-2", "1.5.0", "1.5.1")}, ReasonCargoFixInOtherSeries, "2.0.1"},
		"a fix in the series is a target, not a hint": {lock("1.18.0"), []scanner.Finding{finding("CVE-1", "1.18.0", "1.18.4")}, "", ""},
		"no fix above has no hint":                    {lock("1.18.0"), []scanner.Finding{finding("CVE-1", "1.18.0", "1.17.0")}, ReasonNoFixedVersion, ""},
	} {
		gh := newFakeGitHub()
		cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": pkgToml, "Cargo.lock": c.lock})
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", c.findings...)))
		if len(it.Packages) != 1 {
			t.Errorf("%s: packages = %+v", name, it.Packages)
			continue
		}
		p := it.Packages[0]
		if c.reason != "" && p.Reason != c.reason {
			t.Errorf("%s: reason = %s (%s)", name, p.Reason, p.Detail)
		}
		switch h := p.Hint(); {
		case c.fix == "" && p.FixHint != nil:
			t.Errorf("%s: hint = %+v", name, p.FixHint)
		case c.fix != "" && (h == nil || h.Fix == nil || h.Fix.Version != c.fix || h.Direct || len(h.HeldBy) != 0):
			t.Errorf("%s: hint = %+v", name, h)
		}
	}
}

// Fixes named only as pre-releases of another series: no one release is known
// to fix every advisory, so each advisory's fix is given.
func TestLanguagePlan_CargoNamesEachAdvisoryFix(t *testing.T) {
	const pkgToml = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nml-dsa = \"0.0.4\"\n"
	lock := cargoLockText(4, ownBlock("app", "0.1.0", "ml-dsa"), cratesBlock("ml-dsa", "0.0.4", cksumA))
	f := func(id, fixed string) scanner.Finding {
		return rustFinding(id, typeCargo, "app/Cargo.lock", "ml-dsa", "0.0.4", fixed)
	}
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": pkgToml, "Cargo.lock": lock})
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api",
		f("CVE-2026-22705", "0.1.0-rc.3"), f("CVE-2026-24850", "0.1.0-rc.4"), f("GHSA-h37v-hp6w-2pp8", "0.1.0-rc.5"))))
	if len(it.Packages) != 1 {
		t.Fatalf("packages = %+v", it.Packages)
	}
	p := it.Packages[0]
	if p.Reason != ReasonCargoFixInOtherSeries {
		t.Fatalf("reason = %s (%s)", p.Reason, p.Detail)
	}
	h := p.Hint()
	want := []AdvisoryFix{{"CVE-2026-22705", "0.1.0-rc.3"}, {"CVE-2026-24850", "0.1.0-rc.4"}, {"GHSA-h37v-hp6w-2pp8", "0.1.0-rc.5"}}
	if h == nil || h.Fix != nil || len(h.Advisories) != len(want) {
		t.Fatalf("hint = %+v", h)
	}
	got := map[string]string{}
	for _, a := range h.Advisories {
		got[a.VulnID] = a.Version
	}
	for _, w := range want {
		if got[w.VulnID] != w.Version {
			t.Errorf("advisories = %+v", h.Advisories)
		}
	}
}
