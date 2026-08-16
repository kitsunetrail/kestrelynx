package analyze

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var fixedTime = time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)

// f builds a Finding with the common fields used across tests.
func f(image string, class scanner.PkgClass, pkg, installed, fixed string, status scanner.Status, sev scanner.Severity, vuln string) scanner.Finding {
	return scanner.Finding{
		Image: image, Class: class, Package: pkg,
		InstalledVer: installed, FixedVer: fixed,
		Status: status, Severity: sev, VulnID: vuln,
	}
}

func pkgGroup(t *testing.T, section []ImageFindings, image, pkg string) PackageGroup {
	t.Helper()
	for _, img := range section {
		if img.Image != image {
			continue
		}
		for _, g := range img.Packages {
			if g.Package == pkg {
				return g
			}
		}
	}
	t.Fatalf("package %q not found for image %q", pkg, image)
	return PackageGroup{}
}

func TestBuild_RoutesByStatus(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-1"),
			f("demo:1.0", scanner.ClassOS, "e2fsprogs", "1.44", "", scanner.StatusAffected, scanner.SeverityHigh, "CVE-2"),
			f("demo:1.0", scanner.ClassOS, "gcc-8-base", "8.3", "", scanner.StatusWontFix, scanner.SeverityHigh, "CVE-3"),
		},
	}}
	r := Build(scans, Triage{}, fixedTime)

	if len(r.Actionable) != 1 || len(r.Watch) != 1 || len(r.WontFix) != 1 {
		t.Fatalf("section sizes: actionable=%d watch=%d wontfix=%d", len(r.Actionable), len(r.Watch), len(r.WontFix))
	}
	if !r.GeneratedAt.Equal(fixedTime) {
		t.Errorf("GeneratedAt = %v", r.GeneratedAt)
	}
}

func TestBuild_GroupsByPackageAndCounts(t *testing.T) {
	// libc-bin has 4 CRITICAL CVEs sharing one fix → one group, Critical=4.
	var finds []scanner.Finding
	for _, id := range []string{"CVE-A", "CVE-B", "CVE-C", "CVE-D"} {
		finds = append(finds, f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityCritical, id))
	}
	finds = append(finds, f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityHigh, "CVE-E"))

	r := Build([]scanner.ImageScan{{Image: "demo:1.0", Findings: finds}}, Triage{}, fixedTime)
	g := pkgGroup(t, r.Actionable, "demo:1.0", "libc-bin")

	if g.Critical != 4 || g.High != 1 {
		t.Errorf("counts: critical=%d high=%d, want 4/1", g.Critical, g.High)
	}
	if g.Total() != 5 {
		t.Errorf("Total = %d, want 5", g.Total())
	}
	ids := g.VulnIDs()
	if len(ids) != 5 {
		t.Errorf("VulnIDs = %v, want 5 unique", ids)
	}
	// deterministic ordering
	if ids[0] != "CVE-A" {
		t.Errorf("VulnIDs not sorted: %v", ids)
	}
}

func TestBuild_RiskLabels(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			// OS fixed → distro update (semver not applied)
			f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-OS"),
			// lang minor bump → safe
			f("demo:1.0", scanner.ClassLang, "pip", "21.0.1", "21.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-PIP"),
			// lang major bump → caution
			f("demo:1.0", scanner.ClassLang, "setuptools", "53.0.0", "78.1.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-ST"),
			// lang unparseable → unknown
			f("demo:1.0", scanner.ClassLang, "weird", "abc", "xyz", scanner.StatusFixed, scanner.SeverityHigh, "CVE-W"),
		},
	}}
	r := Build(scans, Triage{}, fixedTime)

	cases := map[string]Risk{
		"libc-bin":   RiskDistroUpdate,
		"pip":        RiskSafe,
		"setuptools": RiskCaution,
		"weird":      RiskUnknown,
	}
	for pkg, want := range cases {
		if got := pkgGroup(t, r.Actionable, "demo:1.0", pkg).Risk; got != want {
			t.Errorf("%s Risk = %q, want %q", pkg, got, want)
		}
	}
}

func TestBuild_NonFixedHasNoRisk(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "e2fsprogs", "1.44", "", scanner.StatusAffected, scanner.SeverityHigh, "CVE-2"),
		},
	}}
	r := Build(scans, Triage{}, fixedTime)
	if got := pkgGroup(t, r.Watch, "demo:1.0", "e2fsprogs").Risk; got != RiskNone {
		t.Errorf("affected Risk = %q, want empty", got)
	}
}

func TestBuild_EOSLAndErrors(t *testing.T) {
	scans := []scanner.ImageScan{
		{Image: "old:1", OSEOSL: true, Findings: nil},
		{Image: "broken:1", Err: errString("pull failed")},
	}
	r := Build(scans, Triage{}, fixedTime)

	if len(r.EOSLImages) != 1 || r.EOSLImages[0] != "old:1" {
		t.Errorf("EOSLImages = %v", r.EOSLImages)
	}
	if len(r.ScanErrors) != 1 || r.ScanErrors[0].Image != "broken:1" {
		t.Errorf("ScanErrors = %+v", r.ScanErrors)
	}
	if !r.HasFindings() {
		t.Errorf("HasFindings = false, but an EOSL image should count")
	}
	if !r.HasIssues() {
		t.Errorf("HasIssues = false, want true (EOSL present)")
	}
}

func TestBuild_SortsCriticalFirst(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "aaa-high", "1", "2", scanner.StatusFixed, scanner.SeverityHigh, "CVE-H"),
			f("demo:1.0", scanner.ClassOS, "zzz-crit", "1", "2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-C"),
		},
	}}
	r := Build(scans, Triage{}, fixedTime)
	pkgs := r.Actionable[0].Packages
	// zzz-crit (CRITICAL) must sort before aaa-high despite alphabetical order.
	if pkgs[0].Package != "zzz-crit" {
		t.Errorf("first package = %q, want zzz-crit (critical first)", pkgs[0].Package)
	}
}

func TestBuild_VulnRefCarriesTitle(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: "glibc: example title"},
		},
	}}
	r := Build(scans, Triage{}, fixedTime)
	g := pkgGroup(t, r.Actionable, "demo:1.0", "libc-bin")
	if got := g.TopVuln().Title; got != "glibc: example title" {
		t.Errorf("TopVuln().Title = %q, want %q", got, "glibc: example title")
	}
}

// The same CVE ID can appear on more than one Trivy result line (e.g. an OS
// package matched by more than one data source); a title-less line must not
// blank out a title already captured for that ID, regardless of arrival order.
func TestBuild_DuplicateVulnIDPrefersNonEmptyTitle(t *testing.T) {
	titledFirst := []scanner.Finding{
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: "glibc: example title"},
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: ""},
	}
	titledSecond := []scanner.Finding{
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: ""},
		{Image: "demo:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-T", Title: "glibc: example title"},
	}
	for name, finds := range map[string][]scanner.Finding{"titled_first": titledFirst, "titled_second": titledSecond} {
		t.Run(name, func(t *testing.T) {
			r := Build([]scanner.ImageScan{{Image: "demo:1.0", Findings: finds}}, Triage{}, fixedTime)
			g := pkgGroup(t, r.Actionable, "demo:1.0", "libc-bin")
			if got := g.TopVuln().Title; got != "glibc: example title" {
				t.Errorf("TopVuln().Title = %q, want the non-empty title regardless of arrival order", got)
			}
		})
	}
}

func TestBuild_FromRealSample(t *testing.T) {
	data, err := readSample()
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	scan, err := scanner.ParseReport(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := Build([]scanner.ImageScan{scan}, Triage{}, fixedTime)
	if !r.HasIssues() {
		t.Fatal("expected issues from sample")
	}
	if len(r.EOSLImages) != 1 {
		t.Errorf("EOSLImages = %v", r.EOSLImages)
	}
	// setuptools major bump should be flagged caution.
	g := pkgGroup(t, r.Actionable, "demo:1.0", "setuptools")
	if g.Risk != RiskCaution {
		t.Errorf("setuptools Risk = %q, want caution", g.Risk)
	}
}
