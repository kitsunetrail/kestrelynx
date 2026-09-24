package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestSectionOf(t *testing.T) {
	cases := []struct {
		in     scanner.Status
		want   scanner.Status
		wantOK bool
	}{
		{scanner.StatusFixed, scanner.StatusFixed, true},
		{scanner.StatusAffected, scanner.StatusAffected, true},
		{scanner.StatusWontFix, scanner.StatusWontFix, true},
		{scanner.StatusFixDeferred, scanner.StatusAffected, true},
		{scanner.StatusUnknown, scanner.StatusAffected, true},
		{"", scanner.StatusAffected, true},
		{scanner.StatusUnderInvestigation, scanner.StatusAffected, true},
		{"future_status", scanner.StatusAffected, true},
		{scanner.StatusEndOfLife, scanner.StatusEndOfLife, true},
		{scanner.StatusNotAffected, "", false},
	}
	for _, c := range cases {
		got, ok := sectionOf(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("sectionOf(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// vulnStatus returns the raw status of id inside g, failing if absent.
func vulnStatus(t *testing.T, g PackageGroup, id string) scanner.Status {
	t.Helper()
	for _, v := range g.Vulns {
		if v.ID == id {
			return v.Status
		}
	}
	t.Fatalf("vuln %s not in group %s", id, g.Package)
	return ""
}

// A package whose CVEs carry affected and the statuses folded into it must
// render as one Watch group, not one group per raw status, while every CVE
// keeps its own raw status.
func TestBuild_FoldedStatusesShareOneWatchGroup(t *testing.T) {
	scans := []scanner.ImageScan{{Image: "img:1", Findings: []scanner.Finding{
		f("img:1", scanner.ClassOS, "curl", "7.88", "", scanner.StatusAffected, scanner.SeverityHigh, "CVE-A"),
		f("img:1", scanner.ClassOS, "curl", "7.88", "", scanner.StatusFixDeferred, scanner.SeverityHigh, "CVE-B"),
		f("img:1", scanner.ClassOS, "curl", "7.88", "", scanner.StatusUnknown, scanner.SeverityCritical, "CVE-C"),
		f("img:1", scanner.ClassOS, "curl", "7.88", "", scanner.StatusUnderInvestigation, scanner.SeverityHigh, "CVE-D"),
		f("img:1", scanner.ClassOS, "curl", "7.88", "", "future_status", scanner.SeverityHigh, "CVE-E"),
	}}}
	r := Build(scans, nil, Triage{}, fixedTime)
	if len(r.Watch) != 1 || len(r.Watch[0].Packages) != 1 {
		t.Fatalf("Watch = %+v, want exactly one group", r.Watch)
	}
	g := r.Watch[0].Packages[0]
	if g.Status != scanner.StatusAffected || g.Critical != 1 || g.High != 4 {
		t.Errorf("group = status %q CRITICAL %d HIGH %d, want affected 1/4", g.Status, g.Critical, g.High)
	}
	want := map[string]scanner.Status{
		"CVE-A": scanner.StatusAffected, "CVE-B": scanner.StatusFixDeferred, "CVE-C": scanner.StatusUnknown,
		"CVE-D": scanner.StatusUnderInvestigation, "CVE-E": "future_status",
	}
	for id, st := range want {
		if got := vulnStatus(t, g, id); got != st {
			t.Errorf("%s raw status = %q, want %q", id, got, st)
		}
	}
	if len(r.Actionable) != 0 || len(r.WontFix) != 0 || len(r.EOLPackages) != 0 {
		t.Errorf("no other section expected: %+v", r)
	}
}

// When one CVE ID shows up more than once in the same group with different
// raw statuses, the recorded status must not depend on the input order.
func TestBuild_RawStatusConflictIsOrderIndependent(t *testing.T) {
	cases := []struct {
		name string
		a, b scanner.Status
		want scanner.Status
	}{
		{"section status wins", scanner.StatusFixDeferred, scanner.StatusAffected, scanner.StatusAffected},
		{"otherwise the lexically smallest", scanner.StatusUnderInvestigation, scanner.StatusFixDeferred, scanner.StatusFixDeferred},
		{"unknown against a future value", scanner.StatusUnknown, "future_status", "future_status"},
	}
	for _, c := range cases {
		for _, order := range [][2]scanner.Status{{c.a, c.b}, {c.b, c.a}} {
			scans := []scanner.ImageScan{{Image: "img:1", Findings: []scanner.Finding{
				f("img:1", scanner.ClassOS, "curl", "7.88", "", order[0], scanner.SeverityHigh, "CVE-A"),
				f("img:1", scanner.ClassOS, "curl", "7.88", "", order[1], scanner.SeverityHigh, "CVE-A"),
			}}}
			r := Build(scans, nil, Triage{}, fixedTime)
			g := pkgGroup(t, r.Watch, "img:1", "curl")
			if len(g.Vulns) != 1 {
				t.Fatalf("%s: vulns = %+v, want the duplicate collapsed", c.name, g.Vulns)
			}
			if got := g.Vulns[0].Status; got != c.want {
				t.Errorf("%s: order %v raw status = %q, want %q", c.name, order, got, c.want)
			}
		}
	}
}

// The same CVE in two different sections stays in both: that is how a CVE
// fixed by one data source and end-of-life for another has always been
// reported.
func TestBuild_SameCVEInTwoSectionsStaysInBoth(t *testing.T) {
	scans := []scanner.ImageScan{{Image: "img:1", Findings: []scanner.Finding{
		f("img:1", scanner.ClassOS, "libx", "1.0", "1.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-A"),
		f("img:1", scanner.ClassOS, "libx", "1.0", "", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-A"),
	}}}
	r := Build(scans, nil, Triage{}, fixedTime)
	if pkgGroup(t, r.Actionable, "img:1", "libx").Total() != 1 || pkgGroup(t, r.EOLPackages, "img:1", "libx").Total() != 1 {
		t.Errorf("CVE-A must appear once in Actionable and once in EOLPackages: %+v", r)
	}
}

func TestBuild_NotAffectedDropped(t *testing.T) {
	scans := []scanner.ImageScan{{Image: "img:1", Findings: []scanner.Finding{
		f("img:1", scanner.ClassOS, "glibc", "2.28", "", scanner.StatusNotAffected, scanner.SeverityCritical, "CVE-N"),
	}}}
	r := Build(scans, nil, Triage{}, fixedTime)
	if r.HasFindings() || r.AffectedImageCount() != 0 {
		t.Errorf("not_affected must not surface anywhere: %+v", r)
	}
}

// An end_of_life group is triaged on the same KEV/EPSS/severity rules, with
// no status-based demotion: an unfixable CRITICAL stays watch, and with no
// usable intel it becomes act_now like any CRITICAL.
func TestBuild_EndOfLifePriority(t *testing.T) {
	eol := func(pkg string, sev scanner.Severity, id string) scanner.Finding {
		return f("img:1", scanner.ClassOS, pkg, "1.0", "", scanner.StatusEndOfLife, sev, id)
	}
	scans := []scanner.ImageScan{{Image: "img:1", Findings: []scanner.Finding{
		eol("kev", scanner.SeverityHigh, "CVE-KEV"),
		eol("crit", scanner.SeverityCritical, "CVE-CRIT"),
		eol("quiet", scanner.SeverityHigh, "CVE-QUIET"),
	}}}
	r := Build(scans, nil, tr(map[string]Enrichment{"CVE-KEV": {KEV: true}}), fixedTime)
	for pkg, want := range map[string]Priority{"kev": PriorityActNow, "crit": PriorityWatch, "quiet": PriorityLow} {
		if got := pkgGroup(t, r.EOLPackages, "img:1", pkg).Priority; got != want {
			t.Errorf("%s priority = %q, want %q", pkg, got, want)
		}
	}

	degraded := tr(nil)
	degraded.Intel = IntelStatus{}
	r = Build(scans, nil, degraded, fixedTime)
	if got := pkgGroup(t, r.EOLPackages, "img:1", "crit").Priority; got != PriorityActNow {
		t.Errorf("degraded CRITICAL end_of_life priority = %q, want act_now", got)
	}
	if got := pkgGroup(t, r.EOLPackages, "img:1", "quiet").Priority; got != PriorityWatch {
		t.Errorf("degraded HIGH end_of_life priority = %q, want watch", got)
	}
}

func TestBuild_EOLOnlyImageCountsAsAffected(t *testing.T) {
	scans := []scanner.ImageScan{{Image: "img:1", Findings: []scanner.Finding{
		f("img:1", scanner.ClassOS, "qt", "5.15", "", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-1"),
	}}}
	r := Build(scans, nil, Triage{}, fixedTime)
	if !r.HasFindings() || r.AffectedImageCount() != 1 {
		t.Errorf("HasFindings = %v, AffectedImageCount = %d, want true/1", r.HasFindings(), r.AffectedImageCount())
	}
}

// eolReport has an ambiguous reference (two entities under app:1, with
// observed containers), an act_now end-of-life group, and an image whose
// base OS is itself end-of-life.
func eolReport(t *testing.T) Report {
	t.Helper()
	eol := func(image, pkg, id string) scanner.Finding {
		return f(image, scanner.ClassOS, pkg, "1.0", "", scanner.StatusEndOfLife, scanner.SeverityHigh, id)
	}
	scans := []scanner.ImageScan{
		resolvedScan("app:1", contentA, nil, eol("app:1", "libxml2", "CVE-KEV"), eol("app:1", "qt", "CVE-Q")),
		resolvedScan("app:1", contentB, nil, eol("app:1", "qt", "CVE-Q")),
		{Image: "legacy:1", OSEOSL: true, Findings: []scanner.Finding{
			eol("legacy:1", "zlib", "CVE-KEV2"), eol("legacy:1", "bzip2", "CVE-B"),
		}},
	}
	containers := []inventory.Container{
		{Name: "app-a", Image: inventory.RunningImage{Ref: "app:1", Config: configDigest(t, contentA)}},
		{Name: "app-b", Image: inventory.RunningImage{Ref: "app:1", Config: configDigest(t, contentB)}},
	}
	return Build(scans, containers, tr(map[string]Enrichment{"CVE-KEV": {KEV: true}, "CVE-KEV2": {KEV: true}}), fixedTime)
}

func TestEOLPackageAlerts(t *testing.T) {
	r := eolReport(t)
	alerts := r.EOLPackageAlerts()
	if len(alerts) != 2 {
		t.Fatalf("alerts = %+v, want the two app:1 entities kept apart and legacy:1 folded away", alerts)
	}
	seen := map[string]bool{}
	for _, img := range alerts {
		if img.Image != "app:1" || !img.Pinned || !img.Subject.Resolved {
			t.Errorf("alert entry = %+v, want a pinned app:1 entity", img)
		}
		if len(img.Containers) != 1 {
			t.Errorf("alert entry containers = %+v, want the entity's own container", img.Containers)
		}
		seen[img.Subject.Key.Digest.String()] = true
	}
	if !seen[contentA] || !seen[contentB] {
		t.Errorf("both entities must be present separately, got %v", seen)
	}
	var sawActNow bool
	for _, img := range alerts {
		for _, g := range img.Packages {
			if g.Package == "libxml2" && g.Priority == PriorityActNow {
				sawActNow = true
			}
		}
	}
	if !sawActNow {
		t.Errorf("act_now groups must stay in the alerts: %+v", alerts)
	}
	if got := r.FoldedEOLCount("legacy:1"); got != 2 {
		t.Errorf("FoldedEOLCount(legacy:1) = %d, want 2 (act_now included)", got)
	}
	if got := r.FoldedEOLCount("app:1"); got != 0 {
		t.Errorf("FoldedEOLCount(app:1) = %d, want 0 (base OS supported)", got)
	}
}

func TestByPriority_EOLActNowOnly(t *testing.T) {
	pv := eolReport(t).ByPriority()
	got := map[string]bool{}
	for _, img := range pv.ActNow {
		for _, g := range img.Packages {
			got[img.Image+" "+g.Package] = true
		}
	}
	if !got["app:1 libxml2"] || !got["legacy:1 zlib"] || len(got) != 2 {
		t.Errorf("ActNow = %v, want the two act_now end-of-life groups, folded image included", got)
	}
	if len(pv.Watch) != 0 || len(pv.Low) != 0 {
		t.Errorf("end-of-life groups must not join watch/low: watch %+v low %+v", pv.Watch, pv.Low)
	}
}

// For scans carrying only the three original statuses, every CVE's raw
// status equals its group's: nothing about those groups changes.
func TestBuild_RawStatusMatchesSectionForThreeStatusFixtures(t *testing.T) {
	for _, name := range []string{"sample.json", "real_python_3.9.1-slim.json"} {
		data, err := os.ReadFile(filepath.Join("..", "scanner", "testdata", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scan, err := scanner.ParseReport(data)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		r := Build([]scanner.ImageScan{scan}, nil, Triage{}, fixedTime)
		if len(r.EOLPackages) != 0 {
			t.Errorf("%s: unexpected EOLPackages %+v", name, r.EOLPackages)
		}
		n := 0
		for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix} {
			for _, img := range section {
				for _, g := range img.Packages {
					for _, v := range g.Vulns {
						n++
						if v.Status != g.Status {
							t.Errorf("%s: %s in %s raw status %q != group status %q", name, v.ID, g.Package, v.Status, g.Status)
						}
					}
				}
			}
		}
		if n == 0 {
			t.Errorf("%s: no vulnerabilities checked", name)
		}
	}
}

// The real Debian scan: curl's fix_deferred and affected CVEs share one
// Watch group, its fixed CVE stays in Actionable.
func TestBuild_RealDebianStatusMix(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "scanner", "testdata", "real_debian12_status_mix.json"))
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	r := Build([]scanner.ImageScan{scan}, nil, Triage{}, fixedTime)
	img := scan.Image
	watch := pkgGroup(t, r.Watch, img, "curl")
	if watch.Total() != 3 || vulnStatus(t, watch, "CVE-2026-12064") != scanner.StatusFixDeferred || vulnStatus(t, watch, "CVE-2026-6276") != scanner.StatusAffected {
		t.Errorf("curl watch group = %+v, want 3 CVEs with raw statuses kept", watch)
	}
	if pkgGroup(t, r.Actionable, img, "curl").Total() != 1 || pkgGroup(t, r.WontFix, img, "zlib1g").Total() != 1 {
		t.Errorf("fixed and will_not_fix findings must keep their sections: %+v", r)
	}
}

// The synthetic all-status fixture: end_of_life gets its own section,
// not_affected disappears, everything else unfixed lands in Watch.
func TestBuild_EveryTrivyStatus(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "scanner", "testdata", "status_all.json"))
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	r := Build([]scanner.ImageScan{scan}, nil, Triage{}, fixedTime)
	img := scan.Image
	if got := pkgGroup(t, r.Watch, img, "libxml2").Total(); got != 6 {
		t.Errorf("libxml2 watch CVEs = %d, want 6 (affected, fix_deferred, under_investigation, missing, unknown, future_status)", got)
	}
	if got := pkgGroup(t, r.EOLPackages, img, "qt5-qtbase"); got.Total() != 2 || got.Status != scanner.StatusEndOfLife {
		t.Errorf("qt5-qtbase EOL group = %+v, want 2 end_of_life CVEs", got)
	}
	for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, i := range section {
			for _, g := range i.Packages {
				if g.Package == "glibc" {
					t.Errorf("not_affected glibc must be dropped, found in %q", g.Status)
				}
			}
		}
	}
}
