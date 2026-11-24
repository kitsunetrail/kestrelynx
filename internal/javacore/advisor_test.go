package javacore

import (
	"context"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var allSeverities = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"}

func javaScan(javaVersion string, extra ...string) scanner.ImageScan {
	env := []string{"PATH=/opt/java/openjdk/bin:/usr/bin", "JAVA_VERSION=" + javaVersion}
	return scanner.ImageScan{
		Image:     "app:1",
		ConfigEnv: append(env, extra...),
		Platform:  inventory.Platform{OS: "linux", Architecture: "amd64"},
	}
}

func advisorWithFixture(t *testing.T) *Advisor {
	t.Helper()
	a := &Advisor{}
	a.Set(fixtureSnapshot(t))
	return a
}

func TestAugment_FindingShape(t *testing.T) {
	aug := advisorWithFixture(t).Augment(javaScan("jdk-21.0.13+9", "JAVA_HOME=/opt/java/openjdk"), allSeverities)
	if len(aug.Unchecked) != 0 {
		t.Fatalf("Unchecked = %v", aug.Unchecked)
	}
	// The nine CVEs of 2026-11-17 for line 21 and CVE-2026-91403.
	if len(aug.Findings) != 10 {
		t.Fatalf("findings = %d, want 10", len(aug.Findings))
	}
	var f scanner.Finding
	for _, x := range aug.Findings {
		if x.VulnID == "CVE-2026-91403" {
			f = x
		}
	}
	want := scanner.Finding{
		Image: "app:1", Class: scanner.ClassLang, Package: "Java runtime", InstalledVer: "21.0.13",
		FixedVer: "21.0.13.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical,
		VulnID: "CVE-2026-91403", Title: "OpenJDK: security-libs/java.security",
		URL:  "https://openjdk.org/groups/vulnerability/advisories/2026-10-21",
		Type: "java-runtime", Target: "opt/java/openjdk/bin/java", PkgPath: "opt/java/openjdk/bin/java",
	}
	if f != want {
		t.Errorf("finding =\n%+v\nwant\n%+v", f, want)
	}
	for i := 1; i < len(aug.Findings); i++ {
		if aug.Findings[i-1].VulnID >= aug.Findings[i].VulnID {
			t.Errorf("findings are not sorted by CVE: %s, %s", aug.Findings[i-1].VulnID, aug.Findings[i].VulnID)
		}
	}
	for _, f := range aug.Findings {
		if f.LayerDiffID != "" || f.LayerDigest != "" {
			t.Errorf("%s has a layer: %q %q", f.VulnID, f.LayerDiffID, f.LayerDigest)
		}
	}
	if len(aug.Packages) != 1 {
		t.Fatalf("packages = %+v", aug.Packages)
	}
	pk := aug.Packages[0]
	if pk.Target != "opt/java/openjdk/bin/java" || pk.Class != scanner.ClassLang || pk.Type != "java-runtime" ||
		len(pk.Packages) != 1 || pk.Packages[0].Name != "Java runtime" || pk.Packages[0].Version != "21.0.13" ||
		pk.Packages[0].PkgPath != "opt/java/openjdk/bin/java" {
		t.Errorf("package list = %+v", pk)
	}
}

func TestAugment_FixedVersionIsAlignedAndPerCVEFixSurvivesUntilThen(t *testing.T) {
	// 27 is fixed by 27.0.1.0.2 for CVE-2026-114820 but the 2026-11-17 CVEs
	// need 27.0.1.1: every fixed finding says the version that fixes them all.
	aug := advisorWithFixture(t).Augment(javaScan("jdk-27+35", "JAVA_HOME=/opt/java/openjdk"), allSeverities)
	seen := false
	for _, f := range aug.Findings {
		if f.Status != scanner.StatusFixed {
			continue
		}
		if f.FixedVer != "27.0.1.1" {
			t.Errorf("%s fixed version = %s, want 27.0.1.1", f.VulnID, f.FixedVer)
		}
		if f.VulnID == "CVE-2026-114820" {
			seen = true
		}
	}
	if !seen {
		t.Error("27 did not have CVE-2026-114820")
	}

	aug = advisorWithFixture(t).Augment(javaScan("jdk-21.0.12.1+1", "JAVA_HOME=/opt/java/openjdk"), allSeverities)
	for _, f := range aug.Findings {
		if f.FixedVer != "21.0.13.1" {
			t.Errorf("%s fixed version = %q, want 21.0.13.1", f.VulnID, f.FixedVer)
		}
	}
	aug = advisorWithFixture(t).Augment(javaScan("jdk8u512-b09", "JAVA_HOME=/opt/java/openjdk"), allSeverities)
	if len(aug.Findings) != 5 || aug.Findings[0].InstalledVer != "8u512" || aug.Findings[0].FixedVer != "8u514" {
		t.Errorf("8u512 findings = %+v", aug.Findings)
	}
}

func TestAugment_MixedStatusesKeepTheirOwnFixedVersion(t *testing.T) {
	// 26.0.2.1 has inferred end-of-life findings, which keep no fixed version.
	aug := advisorWithFixture(t).Augment(javaScan("jdk-26.0.2.1+1", "JAVA_HOME=/opt/java/openjdk"), allSeverities)
	n := 0
	for _, f := range aug.Findings {
		if f.Status == scanner.StatusEndOfLife {
			n++
			if f.FixedVer != "" {
				t.Errorf("%s: end-of-life with fixed version %q", f.VulnID, f.FixedVer)
			}
		}
	}
	if n == 0 {
		t.Error("no end-of-life findings")
	}
}

func TestAugment_JavaHomeVariants(t *testing.T) {
	adv := advisorWithFixture(t)
	cases := []struct {
		name string
		env  []string
		path string
	}{
		{"absolute", []string{"JAVA_HOME=/opt/java/openjdk"}, "opt/java/openjdk/bin/java"},
		{"unset", nil, ""},
		{"empty", []string{"JAVA_HOME="}, ""},
		{"relative", []string{"JAVA_HOME=jdk"}, ""},
	}
	for _, c := range cases {
		aug := adv.Augment(javaScan("jdk-21.0.13+9", c.env...), allSeverities)
		if len(aug.Findings) != 10 || len(aug.Unchecked) != 0 {
			t.Errorf("%s: %d findings, unchecked %v: the runtime is still matched", c.name, len(aug.Findings), aug.Unchecked)
			continue
		}
		for _, f := range aug.Findings {
			if f.Target != c.path || f.PkgPath != c.path {
				t.Errorf("%s: %s target %q path %q, want %q", c.name, f.VulnID, f.Target, f.PkgPath, c.path)
			}
		}
		pk := aug.Packages[0]
		if pk.Target != c.path || pk.Packages[0].PkgPath != c.path {
			t.Errorf("%s: package list = %+v, want path %q", c.name, pk, c.path)
		}
	}
}

func TestAugment_SeverityFilter(t *testing.T) {
	adv := advisorWithFixture(t)
	aug := adv.Augment(javaScan("jdk-21.0.13+9"), []string{"CRITICAL"})
	if len(aug.Findings) != 1 || aug.Findings[0].VulnID != "CVE-2026-91403" {
		t.Errorf("CRITICAL findings = %+v", aug.Findings)
	}
	// The package is listed even when no finding passes the filter.
	aug = adv.Augment(javaScan("jdk-21.0.13+9"), []string{"LOW"})
	if len(aug.Findings) != 0 || len(aug.Packages) != 1 {
		t.Errorf("LOW: %d findings, %d packages", len(aug.Findings), len(aug.Packages))
	}
	aug = adv.Augment(javaScan("jdk-21.0.13+9"), []string{" high ", "medium"})
	for _, f := range aug.Findings {
		if f.Severity != scanner.SeverityHigh && f.Severity != scanner.SeverityMedium {
			t.Errorf("%s severity %s", f.VulnID, f.Severity)
		}
	}
	if len(aug.Findings) != 9 {
		t.Errorf("HIGH and MEDIUM findings = %d, want 9", len(aug.Findings))
	}
}

func TestAugment_NothingDetected(t *testing.T) {
	adv := advisorWithFixture(t)
	for _, v := range []string{"21.0.10", "21.0.13.0", "22", "jdk-28-ea+3", "jdk-11.0.11+9_openj9-0.26.0", "1.8.0_512"} {
		aug := adv.Augment(javaScan(v, "JAVA_HOME=/opt/java/openjdk"), allSeverities)
		if len(aug.Findings) != 0 || len(aug.Packages) != 0 || len(aug.Unchecked) != 0 {
			t.Errorf("JAVA_VERSION=%s: %+v", v, aug)
		}
	}
	aug := adv.Augment(scanner.ImageScan{Image: "x", ConfigEnv: []string{"JAVA_HOME=/opt/java/openjdk"}}, allSeverities)
	if len(aug.Findings)+len(aug.Packages)+len(aug.Unchecked) != 0 {
		t.Errorf("no JAVA_VERSION: %+v", aug)
	}
}

func TestAugment_NoSnapshotIsUnchecked(t *testing.T) {
	var adv Advisor
	aug := adv.Augment(javaScan("jdk-21.0.13+9"), allSeverities)
	if len(aug.Unchecked) != 1 || aug.Unchecked[0] != inventory.JavaRuntimePackage || len(aug.Findings) != 0 || len(aug.Packages) != 0 {
		t.Errorf("aug = %+v", aug)
	}
	// An image with no detectable JDK is not reported as unchecked.
	if aug := adv.Augment(javaScan("21.0.10"), allSeverities); len(aug.Unchecked) != 0 {
		t.Errorf("aug = %+v", aug)
	}
}

func TestAugment_UncheckedLine(t *testing.T) {
	sn := fixtureSnapshot(t)
	sn.unchecked[21] = true
	adv := &Advisor{}
	adv.Set(sn)
	aug := adv.Augment(javaScan("jdk-21.0.13+9"), allSeverities)
	if len(aug.Unchecked) != 1 || len(aug.Findings) != 0 {
		t.Errorf("line 21: %+v", aug)
	}
	aug = adv.Augment(javaScan("jdk-25.0.5+9"), allSeverities)
	if len(aug.Unchecked) != 0 {
		t.Errorf("line 25 was unchecked: %+v", aug)
	}
}

func TestEcosystemRegistration(t *testing.T) {
	if got := inventory.RuntimeVersionEnv(inventory.EcosystemJavaRuntime); got != "JAVA_VERSION" {
		t.Errorf("RuntimeVersionEnv = %q", got)
	}
	if got := inventory.RuntimeLocationEnv(inventory.EcosystemJavaRuntime); got != "JAVA_HOME" {
		t.Errorf("RuntimeLocationEnv = %q", got)
	}
	if inventory.ParseEcosystem(string(inventory.EcosystemJavaRuntime)) != inventory.EcosystemJavaRuntime {
		t.Error("java-runtime is not a known ecosystem")
	}
	if inventory.JavaRuntimePackage != "Java runtime" || inventory.EcosystemJavaRuntime != "java-runtime" {
		t.Error("constants changed")
	}
}

func TestRefresher_FailureLeavesNoSnapshot(t *testing.T) {
	site := newSite(t)
	adv := &Advisor{}
	r := Refresher{Source: site.source(t), Advisor: adv}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if adv.snap.Load() == nil {
		t.Fatal("no snapshot after a successful refresh")
	}
	site.fail("/avail", 500)
	r.Source = site.source(t) // a new cache dir: nothing to fall back on
	if err := r.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "java advisories unavailable") {
		t.Fatalf("Refresh = %v", err)
	}
	if adv.snap.Load() != nil {
		t.Error("the snapshot was kept after a failed refresh")
	}
	if aug := adv.Augment(javaScan("jdk-21.0.13+9"), allSeverities); len(aug.Unchecked) != 1 {
		t.Errorf("aug = %+v", aug)
	}
}
