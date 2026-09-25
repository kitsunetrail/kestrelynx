package analyze

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// packagesNamed returns every PackageGroup named pkg for image, in whatever
// order Build/sortPackages produced them — unlike pkgGroup (analyze_test.go),
// which assumes the name alone identifies a single group and returns only
// the first match, these tests are specifically about a name no longer being
// enough.
func packagesNamed(t *testing.T, section []ImageFindings, image, pkg string) []PackageGroup {
	t.Helper()
	var out []PackageGroup
	for _, img := range section {
		if img.Image != image {
			continue
		}
		for _, g := range img.Packages {
			if g.Package == pkg {
				out = append(out, g)
			}
		}
	}
	return out
}

// TestBuild_EcosystemCollisionNotMerged is the motivating case from the
// rule: an OS package and a language package that happen to share a name
// (the distro's openssl and a Rust openssl crate) must never be merged into
// one row, because they are different things with different fixes.
func TestBuild_EcosystemCollisionNotMerged(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{
				Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
				InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-OS-1", Type: "debian",
			},
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "openssl",
				InstalledVer: "0.10.55", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-RUST-1", Type: "cargo",
			},
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	groups := packagesNamed(t, r.Watch, "demo:1.0", "openssl")
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2 (OS debian openssl and cargo openssl must stay separate)", len(groups))
	}
	byEco := map[inventory.Ecosystem]PackageGroup{}
	for _, g := range groups {
		byEco[g.Ecosystem] = g
	}
	os, ok := byEco[inventory.EcosystemDebian]
	if !ok {
		t.Fatalf("no group with Ecosystem debian; got %+v", groups)
	}
	if os.Class != inventory.ClassOS || os.InstalledVer != "3.0.7" || os.VulnIDs()[0] != "CVE-OS-1" {
		t.Errorf("debian openssl group = %+v, want the OS finding's own data", os)
	}
	cargo, ok := byEco[inventory.EcosystemCargo]
	if !ok {
		t.Fatalf("no group with Ecosystem cargo; got %+v", groups)
	}
	if cargo.Class != inventory.ClassLang || cargo.InstalledVer != "0.10.55" || cargo.VulnIDs()[0] != "CVE-RUST-1" {
		t.Errorf("cargo openssl group = %+v, want the Rust finding's own data", cargo)
	}
}

// TestBuild_MultipleInstalledVersionsNotMerged: two different installed
// versions of the same named package in the same ecosystem, in the same
// status section, must produce two groups (Version is part of PackageRef,
// the aggregation key) rather than one group silently keeping whichever
// version's Finding line Build happened to see first.
func TestBuild_MultipleInstalledVersionsNotMerged(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "lodash",
				InstalledVer: "4.17.19", Status: scanner.StatusFixed, FixedVer: "4.17.21",
				Severity: scanner.SeverityHigh, VulnID: "CVE-OLD", Type: "node-pkg",
				Target: "app/service-a/node_modules/lodash/package.json",
			},
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "lodash",
				InstalledVer: "4.17.15", Status: scanner.StatusFixed, FixedVer: "4.17.21",
				Severity: scanner.SeverityCritical, VulnID: "CVE-OLDER", Type: "node-pkg",
				Target: "app/service-b/node_modules/lodash/package.json",
			},
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	groups := packagesNamed(t, r.Actionable, "demo:1.0", "lodash")
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2 (two installed versions must not merge)", len(groups))
	}
	versions := map[string]PackageGroup{}
	for _, g := range groups {
		versions[g.InstalledVer] = g
	}
	if _, ok := versions["4.17.19"]; !ok {
		t.Errorf("missing version 4.17.19 group; got %+v", groups)
	}
	if _, ok := versions["4.17.15"]; !ok {
		t.Errorf("missing version 4.17.15 group; got %+v", groups)
	}
	// Each group keeps only its own CVE and Instance — the two versions
	// never merged their vulnerabilities or Instances either.
	for v, g := range versions {
		if len(g.Instances) != 1 {
			t.Errorf("version %s: len(Instances) = %d, want 1", v, len(g.Instances))
		}
	}
}

// TestBuild_SameVersionAcrossBinariesKeepsBothInstances pins the
// worked example: the same vendored Go module, same installed version,
// embedded in two separately built binaries (/app/api and /app/tool). They
// share one PackageRef (name/version/ecosystem/class are identical) so they
// aggregate into a single PackageGroup, but Instances must retain both
// Targets — a later phase decides runtime usage per Target, and losing one
// here would make that phase blind to the other binary entirely.
func TestBuild_SameVersionAcrossBinariesKeepsBothInstances(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
				InstalledVer: "v0.17.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-GO-NET", Type: "gobinary", Target: "app/api",
			},
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
				InstalledVer: "v0.17.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-GO-NET", Type: "gobinary", Target: "app/tool",
			},
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	groups := packagesNamed(t, r.Watch, "demo:1.0", "golang.org/x/net")
	if len(groups) != 1 {
		t.Fatalf("len(groups) = %d, want 1 (same name/version/ecosystem/class must merge)", len(groups))
	}
	g := groups[0]
	if len(g.Instances) != 2 {
		t.Fatalf("len(Instances) = %d, want 2 (both /app/api and /app/tool must survive)", len(g.Instances))
	}
	targets := map[string]bool{}
	for _, inst := range g.Instances {
		targets[inst.Target] = true
		if inst.PackageRef != g.PackageRef() {
			t.Errorf("Instance.PackageRef = %+v, want the group's own %+v", inst.PackageRef, g.PackageRef())
		}
	}
	if !targets["app/api"] || !targets["app/tool"] {
		t.Errorf("targets = %v, want both app/api and app/tool", targets)
	}
	// The single CVE line reported against both targets deduplicates to one
	// vulnerability on the merged group, same as any other duplicate CVE ID.
	if len(g.VulnIDs()) != 1 {
		t.Errorf("VulnIDs = %v, want exactly [CVE-GO-NET]", g.VulnIDs())
	}
}

// sortedRefs runs sortPackages on every rotation of groups and requires the
// same PackageRef order every time (shuffle-proof: the tie-break must not
// depend on the order groups arrived in, e.g. incidental map iteration
// order upstream in Build).
func sortedRefs(t *testing.T, groups []PackageGroup) []inventory.PackageRef {
	t.Helper()
	var lastOrder []inventory.PackageRef
	for start := 0; start < len(groups); start++ {
		rotated := append(append([]PackageGroup{}, groups[start:]...), groups[:start]...)
		sortPackages(rotated)
		order := make([]inventory.PackageRef, len(rotated))
		for i, g := range rotated {
			order[i] = g.PackageRef()
		}
		if lastOrder != nil {
			for i := range order {
				if order[i] != lastOrder[i] {
					t.Fatalf("rotation %d produced a different order: %+v, want %+v", start, order, lastOrder)
				}
			}
		}
		lastOrder = order
	}
	return lastOrder
}

// TestSortPackages_EcosystemAndVersionBreakNameTies pins sortPackages'
// tie-break: once PackageRef (not just name) is the aggregation key, several
// groups can share a Package name, and the order among them must be a
// deterministic function of Ecosystem then Version — not incidental map
// iteration order.
func TestSortPackages_EcosystemAndVersionBreakNameTies(t *testing.T) {
	groups := []PackageGroup{
		{Package: "openssl", Class: inventory.ClassLang, InstalledVer: "0.10.55", Ecosystem: inventory.EcosystemCargo, Critical: 0, High: 1},
		{Package: "openssl", Class: inventory.ClassOS, InstalledVer: "3.0.7", Ecosystem: inventory.EcosystemDebian, Critical: 0, High: 1},
		{Package: "openssl", Class: inventory.ClassLang, InstalledVer: "0.9.90", Ecosystem: inventory.EcosystemCargo, Critical: 0, High: 1},
	}
	lastOrder := sortedRefs(t, groups)
	// Same total (Critical+High) for all three, so the tie-break is entirely
	// name -> ecosystem -> version: Ecosystem and Version are compared as
	// plain strings (not semver), so "cargo" < "debian" lexically, and
	// within cargo "0.10.55" < "0.9.90" lexically (the '1' in "0.10.55"'s
	// second component is less than the '9' in "0.9.90"'s, even though
	// 0.10.55 is numerically the newer release).
	want := []inventory.Ecosystem{inventory.EcosystemCargo, inventory.EcosystemCargo, inventory.EcosystemDebian}
	for i, eco := range want {
		if lastOrder[i].Ecosystem != eco {
			t.Errorf("order[%d].Ecosystem = %q, want %q", i, lastOrder[i].Ecosystem, eco)
		}
	}
	if lastOrder[0].Version != "0.10.55" || lastOrder[1].Version != "0.9.90" {
		t.Errorf("cargo versions out of order: %+v", lastOrder[:2])
	}
}

// TestBuild_SameCVEInDifferentGroupsNotDeduped: the same CVE ID reported
// against two different packages (a coincidence — an advisory can be filed
// under one CVE for both a distro package and a bundled copy of the same
// code, or Trivy's own data sources can disagree) must not be deduplicated
// across the two PackageGroups it belongs to. CVE-ID dedup (pkgAcc.vulns) is
// scoped per package identity, not global to the image or the report.
func TestBuild_SameCVEInDifferentGroupsNotDeduped(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{
				Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
				InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-SHARED", Type: "debian",
			},
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "openssl",
				InstalledVer: "0.10.55", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical,
				VulnID: "CVE-SHARED", Type: "cargo",
			},
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	groups := packagesNamed(t, r.Watch, "demo:1.0", "openssl")
	if len(groups) != 2 {
		t.Fatalf("len(groups) = %d, want 2", len(groups))
	}
	for _, g := range groups {
		if len(g.VulnIDs()) != 1 || g.VulnIDs()[0] != "CVE-SHARED" {
			t.Errorf("group %+v: VulnIDs = %v, want exactly [CVE-SHARED] (each group keeps its own copy)", g.PackageRef(), g.VulnIDs())
		}
		if g.Total() != 1 {
			t.Errorf("group %+v: Total() = %d, want 1 (no cross-group dedup collapsing counts)", g.PackageRef(), g.Total())
		}
	}
}

// TestByPriority_CollisionSplitsAcrossBuckets: with triage on, a colliding
// OS/language pair whose CVEs earn different verdicts (one KEV act_now, one
// merely watch-band EPSS) must land in different priority buckets — the
// same package name never forces the two identities' CVEs into the same
// bucket.
func TestByPriority_CollisionSplitsAcrossBuckets(t *testing.T) {
	enrich := map[string]Enrichment{
		"CVE-OS-1":   {EPSS: 0.02, EPSSKnown: true}, // >= WatchEPSS, < ActNowEPSS -> watch
		"CVE-RUST-1": {KEV: true},                   // -> act_now
	}
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{
				Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
				InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-OS-1", Type: "debian",
			},
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "openssl",
				InstalledVer: "0.10.55", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-RUST-1", Type: "cargo",
			},
		},
	}}
	r := Build(scans, nil, tr(enrich), fixedTime)
	pv := r.ByPriority()

	actNow := packagesNamed(t, pv.ActNow, "demo:1.0", "openssl")
	if len(actNow) != 1 || actNow[0].PackageRef().Ecosystem != inventory.EcosystemCargo {
		t.Fatalf("ActNow openssl groups = %+v, want exactly the cargo group", actNow)
	}
	watch := packagesNamed(t, pv.Watch, "demo:1.0", "openssl")
	if len(watch) != 1 || watch[0].PackageRef().Ecosystem != inventory.EcosystemDebian {
		t.Fatalf("Watch openssl groups = %+v, want exactly the debian group", watch)
	}
}

// TestBuild_EOLCollisionKeepsGroupsSeparateAndProjectsActNow: the
// end_of_life section applies the same PackageRef aggregation as every other
// section (a collision there stays split too), and ByPriority's "only
// act_now EOL groups join ActNow" rule is evaluated per group, not per
// package name — an act_now EOL group joins ActNow even though its
// same-named sibling doesn't.
func TestBuild_EOLCollisionKeepsGroupsSeparateAndProjectsActNow(t *testing.T) {
	enrich := map[string]Enrichment{
		"CVE-OS-1":   {}, // no signal -> low
		"CVE-RUST-1": {KEV: true},
	}
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{
				Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
				InstalledVer: "3.0.7", Status: scanner.StatusEndOfLife, Severity: scanner.SeverityHigh,
				VulnID: "CVE-OS-1", Type: "debian",
			},
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "openssl",
				InstalledVer: "0.10.55", Status: scanner.StatusEndOfLife, Severity: scanner.SeverityHigh,
				VulnID: "CVE-RUST-1", Type: "cargo",
			},
		},
	}}
	r := Build(scans, nil, tr(enrich), fixedTime)

	eol := packagesNamed(t, r.EOLPackages, "demo:1.0", "openssl")
	if len(eol) != 2 {
		t.Fatalf("EOLPackages openssl groups = %d, want 2 (collision must stay split in end_of_life too)", len(eol))
	}

	pv := r.ByPriority()
	actNow := packagesNamed(t, pv.ActNow, "demo:1.0", "openssl")
	if len(actNow) != 1 || actNow[0].PackageRef().Ecosystem != inventory.EcosystemCargo {
		t.Fatalf("ActNow openssl groups = %+v, want exactly the act_now cargo EOL group", actNow)
	}
	// The low-priority debian EOL group must not also appear in ActNow just
	// because its same-named sibling does.
	watchOrLow := packagesNamed(t, pv.Watch, "demo:1.0", "openssl")
	watchOrLow = append(watchOrLow, packagesNamed(t, pv.Low, "demo:1.0", "openssl")...)
	for _, g := range watchOrLow {
		if g.PackageRef().Ecosystem == inventory.EcosystemCargo {
			t.Errorf("the act_now cargo EOL group must not also appear in Watch/Low: %+v", g)
		}
	}
}

// TestSortPackages_ClassBreaksEcosystemAndVersionTie covers the case
// Ecosystem and Version alone still can't separate: a same-named,
// same-version OS package and language package whose Trivy Type was never
// recorded (both Ecosystem == EcosystemUnknown, same as an OS package whose
// Type Build never saw). Same Critical/High counts too, so without Class as
// a final tie-break the order would fall back to incidental map iteration
// order — exactly the same problem PackageRef existing was meant to fix.
func TestSortPackages_ClassBreaksEcosystemAndVersionTie(t *testing.T) {
	groups := []PackageGroup{
		{Package: "curl", Class: inventory.ClassOS, InstalledVer: "7.81.0", Ecosystem: inventory.EcosystemUnknown, Critical: 0, High: 1},
		{Package: "curl", Class: inventory.ClassLang, InstalledVer: "7.81.0", Ecosystem: inventory.EcosystemUnknown, Critical: 0, High: 1},
	}
	lastOrder := sortedRefs(t, groups)
	// "lang" < "os" lexically, so the language group sorts first.
	if lastOrder[0].Class != inventory.ClassLang || lastOrder[1].Class != inventory.ClassOS {
		t.Errorf("order = %+v, want lang before os", lastOrder)
	}
}
