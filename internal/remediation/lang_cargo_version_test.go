package remediation

import (
	"strings"
	"testing"
)

func TestCargoSeries(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"1.18.0", "1.38.2", true},
		{"1.0.0", "2.0.0", false},
		{"0.2.18", "0.2.19", true},
		{"0.2.18", "0.3.0", false},
		{"0.0.3", "0.0.3", true},
		{"0.0.3", "0.0.4", false},
		{"0.0.3", "0.1.0", false},
		{"1.0.0-rc.1", "1.0.0", true},
		{"1.2.3+build.5", "1.9.9", true},
		{"0.1.0", "1.0.0", false},
	} {
		a, ok1 := parseSemver(c.a)
		b, ok2 := parseSemver(c.b)
		if !ok1 || !ok2 {
			t.Fatalf("%s or %s does not parse", c.a, c.b)
		}
		if got := cargoCompatible(a, b); got != c.same {
			t.Errorf("compatible(%s, %s) = %v, want %v", c.a, c.b, got, c.same)
		}
		if got := cargoCompatible(b, a); got != c.same {
			t.Errorf("compatible(%s, %s) = %v, want %v", c.b, c.a, got, c.same)
		}
	}
}

func TestCargoVersionScheme(t *testing.T) {
	if got := ManagerCargo.scheme(); got != schemeSemver {
		t.Errorf("scheme = %v", got)
	}
	if ManagerCargo.LockfileName() != "Cargo.lock" {
		t.Errorf("lockfile = %q", ManagerCargo.LockfileName())
	}
	// Build metadata takes no part in the order.
	if c, ok := compareVersions(ManagerCargo.scheme(), "1.2.3+a", "1.2.3+b"); !ok || c != 0 {
		t.Errorf("build metadata: %d %v", c, ok)
	}
	if c, ok := compareVersions(ManagerCargo.scheme(), "1.0.0-rc.1", "1.0.0"); !ok || c >= 0 {
		t.Errorf("pre-release: %d %v", c, ok)
	}
}

func cargoCVE(id string, fixed ...string) CVERef { return CVERef{VulnID: id, FixedVers: fixed} }

func TestCargoTarget(t *testing.T) {
	for name, c := range map[string]struct {
		installed string
		cves      []CVERef
		want      string
		reason    Reason
		detail    string
	}{
		"several series of fixes: the lowest above the installed": {
			installed: "1.18.0", cves: []CVERef{cargoCVE("A", "1.18.4, 1.20.3, 1.23.1")}, want: "1.18.4",
		},
		"the highest over the vulnerabilities": {
			installed: "1.18.0",
			cves: []CVERef{
				cargoCVE("A", "1.18.4, 1.20.3, 1.23.1"),
				cargoCVE("B", "1.24.2, 1.20.4, 1.18.5"),
				cargoCVE("C", "1.44.2, 1.38.2, 1.43.1"),
			},
			want: "1.38.2",
		},
		"fixes at or below the installed version are not targets": {
			installed: "1.20.3", cves: []CVERef{cargoCVE("A", "1.18.4, 1.20.3, 1.23.1")}, want: "1.23.1",
		},
		"0.x: the minor version is the series": {
			installed: "0.2.18", cves: []CVERef{cargoCVE("A", "0.3.1, 0.2.20")}, want: "0.2.20",
		},
		"0.x: a fix of the next minor version is of another series": {
			installed: "0.2.18", cves: []CVERef{cargoCVE("A", "0.3.1")},
			reason: ReasonFixInOtherMajor, detail: "A is fixed in 0.3.1 only",
		},
		"0.0.x: the version is the series": {
			installed: "0.0.3", cves: []CVERef{cargoCVE("A", "0.0.4, 0.1.0")},
			reason: ReasonFixInOtherMajor, detail: "0.0.4, 0.1.0",
		},
		"0.0.x: a later fix of the same version never is": {
			installed: "0.0.3", cves: []CVERef{cargoCVE("A", "0.0.3")},
			reason: ReasonNoFixedVersion,
		},
		"only another major version fixes it": {
			installed: "1.5.0", cves: []CVERef{cargoCVE("A", "2.0.1")},
			reason: ReasonFixInOtherMajor, detail: "2.0.1",
		},
		"one vulnerability is fixed only in another series": {
			installed: "1.5.0", cves: []CVERef{cargoCVE("A", "1.6.0"), cargoCVE("B", "2.0.1")},
			reason: ReasonFixInOtherMajor, detail: "B is fixed in 2.0.1",
		},
		"no fix above the installed version": {
			installed: "1.5.0", cves: []CVERef{cargoCVE("A", "1.4.0")}, reason: ReasonNoFixedVersion,
		},
		"a fix that is not a version": {
			installed: "1.5.0", cves: []CVERef{cargoCVE("A", "next")}, reason: ReasonUnparsableVersion,
		},
		"an installed version that is not a version": {
			installed: "x", cves: []CVERef{cargoCVE("A", "1.5.0")}, reason: ReasonUnparsableVersion,
		},
		"nothing to fix": {installed: "1.5.0", reason: ReasonNoFixedVersion},
	} {
		got, reason, detail := cargoTarget(c.installed, c.cves)
		if got != c.want || reason != c.reason || (c.detail != "" && !strings.Contains(detail, c.detail)) {
			t.Errorf("%s: got %q %q %q, want %q %q (%q)", name, got, reason, detail, c.want, c.reason, c.detail)
		}
	}
}

func TestCargoReqAllows(t *testing.T) {
	for _, c := range []struct {
		req, v    string
		ok, evalu bool
	}{
		// The default operator is the caret.
		{"1", "1.38.2", true, true},
		{"1", "2.0.0", false, true},
		{"1.2.3", "1.2.2", false, true},
		{"1.2.3", "1.9.0", true, true},
		{"0.2.3", "0.2.9", true, true},
		{"0.2.3", "0.3.0", false, true},
		{"0.0.3", "0.0.4", false, true},
		{"0.0.3", "0.0.3", true, true},
		{"0.0", "0.0.9", true, true},
		{"0.0", "0.1.0", false, true},
		{"0", "0.9.0", true, true},
		{"0", "1.0.0", false, true},
		{"^1.2", "1.9.0", true, true},
		// Tilde.
		{"~1.2.3", "1.2.9", true, true},
		{"~1.2.3", "1.3.0", false, true},
		{"~1.2", "1.2.0", true, true},
		{"~1.2", "1.3.0", false, true},
		{"~1", "1.9.0", true, true},
		{"~1", "2.0.0", false, true},
		// Exact and the comparison operators, with partial versions.
		{"=1.20.0", "1.23.1", false, true},
		{"=1.23.1", "1.23.1", true, true},
		{"=1.2", "1.2.7", true, true},
		{"=1.2", "1.3.0", false, true},
		{">1.2", "1.2.9", false, true},
		{">1.2", "1.3.0", true, true},
		{">1", "1.9.9", false, true},
		{">1", "2.0.0", true, true},
		{">=1.2", "1.2.0", true, true},
		{"<1.2", "1.1.9", true, true},
		{"<1.2", "1.2.0", false, true},
		{"<=1.2", "1.2.9", true, true},
		{"<=1.2", "1.3.0", false, true},
		{"<=1.2.3", "1.2.3", true, true},
		{">= 1.2.3", "1.2.3", true, true},
		// Wildcards.
		{"*", "9.9.9", true, true},
		{"1.*", "1.9.0", true, true},
		{"1.*", "2.0.0", false, true},
		{"1.2.*", "1.2.9", true, true},
		{"1.2.*", "1.3.0", false, true},
		{"1.x", "1.4.0", true, true},
		// Several comparators must all hold.
		{">=1.2, <1.5", "1.4.0", true, true},
		{">=1.2, <1.5", "1.5.0", false, true},
		{">=1.2,<1.5", "1.1.0", false, true},
		{" ^1.0 , <1.9 ", "1.8.0", true, true},
		// What is not evaluated.
		{"1.0.0-beta", "1.0.0", false, false},
		{">=1.0.0-rc.1", "1.0.0", false, false},
		{"1.0.0+build", "1.0.0", false, false},
		{"", "1.0.0", false, false},
		{"v1.0", "1.0.0", false, false},
		{"1.2.3.4", "1.2.3", false, false},
		{">=*", "1.0.0", false, false},
		{"^1.*", "1.0.0", false, false},
		{"1.2.3 || 2.0.0", "1.2.3", false, false},
		{"~>1.2", "1.2.3", false, false},
		{"01.2", "1.2.3", false, false},
		{"1, ", "1.2.3", false, false},
		{"1", "1.0.0-rc.1", false, false},
	} {
		v, ok := parseSemver(c.v)
		if !ok {
			t.Fatalf("%q does not parse", c.v)
		}
		gotOK, gotEval := cargoReqAllows(c.req, v)
		if gotEval != c.evalu || (c.evalu && gotOK != c.ok) {
			t.Errorf("cargoReqAllows(%q, %s) = %v, %v; want %v, %v", c.req, c.v, gotOK, gotEval, c.ok, c.evalu)
		}
	}
}
