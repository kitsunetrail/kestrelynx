package analyze

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// tr is a triage config with the default thresholds and healthy intel.
func tr(enrich map[string]Enrichment) Triage {
	return Triage{
		Enabled:    true,
		ActNowEPSS: 0.10,
		WatchEPSS:  0.01,
		Enrich:     enrich,
		Intel:      IntelStatus{KEVOK: true, EPSSOK: true},
	}
}

func TestPriorityOf_RuleTable(t *testing.T) {
	cases := []struct {
		name   string
		sev    scanner.Severity
		e      Enrichment
		status scanner.Status
		want   Priority
	}{
		{"KEV is act_now regardless of severity", scanner.SeverityHigh, Enrichment{KEV: true}, scanner.StatusFixed, PriorityActNow},
		{"KEV without a fix is still act_now", scanner.SeverityHigh, Enrichment{KEV: true}, scanner.StatusAffected, PriorityActNow},
		{"KEV is never demoted by will_not_fix", scanner.SeverityHigh, Enrichment{KEV: true}, scanner.StatusWontFix, PriorityActNow},
		{"EPSS at act_now threshold", scanner.SeverityHigh, Enrichment{EPSS: 0.10, EPSSKnown: true}, scanner.StatusFixed, PriorityActNow},
		{"EPSS at watch threshold", scanner.SeverityHigh, Enrichment{EPSS: 0.01, EPSSKnown: true}, scanner.StatusFixed, PriorityWatch},
		{"CRITICAL with low EPSS stays watch (fallback net)", scanner.SeverityCritical, Enrichment{EPSS: 0.002, EPSSKnown: true}, scanner.StatusFixed, PriorityWatch},
		{"CRITICAL with no EPSS data is watch", scanner.SeverityCritical, Enrichment{}, scanner.StatusFixed, PriorityWatch},
		{"HIGH with low EPSS is low", scanner.SeverityHigh, Enrichment{EPSS: 0.002, EPSSKnown: true}, scanner.StatusFixed, PriorityLow},
		{"HIGH with no EPSS data is low", scanner.SeverityHigh, Enrichment{}, scanner.StatusFixed, PriorityLow},
		{"will_not_fix demotes watch to low", scanner.SeverityCritical, Enrichment{}, scanner.StatusWontFix, PriorityLow},
		{"will_not_fix keeps EPSS act_now", scanner.SeverityHigh, Enrichment{EPSS: 0.5, EPSSKnown: true}, scanner.StatusWontFix, PriorityActNow},
	}
	rules := tr(nil)
	for _, c := range cases {
		if got := rules.priorityOf(c.sev, c.e, c.status); got != c.want {
			t.Errorf("%s: priorityOf = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPriorityOf_Degraded(t *testing.T) {
	rules := tr(nil)
	rules.Intel = IntelStatus{} // neither dataset usable
	if !rules.Intel.Degraded() {
		t.Fatal("want degraded intel")
	}
	if got := rules.priorityOf(scanner.SeverityCritical, Enrichment{}, scanner.StatusFixed); got != PriorityActNow {
		t.Errorf("degraded CRITICAL = %q, want act_now", got)
	}
	// No low bucket while flying blind — even will_not_fix HIGH stays visible.
	if got := rules.priorityOf(scanner.SeverityHigh, Enrichment{}, scanner.StatusWontFix); got != PriorityWatch {
		t.Errorf("degraded HIGH = %q, want watch", got)
	}
}

func TestPriorityOf_Disabled(t *testing.T) {
	var rules Triage
	if got := rules.priorityOf(scanner.SeverityCritical, Enrichment{KEV: true}, scanner.StatusFixed); got != PriorityNone {
		t.Errorf("disabled = %q, want none", got)
	}
}

func TestBuild_AssignsGroupPriorityAndEvidence(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "nginx:1.25.3",
		Findings: []scanner.Finding{
			f("nginx:1.25.3", scanner.ClassOS, "openssl", "3.0.7", "3.0.11", scanner.StatusFixed, scanner.SeverityCritical, "CVE-KEV"),
			f("nginx:1.25.3", scanner.ClassOS, "openssl", "3.0.7", "3.0.11", scanner.StatusFixed, scanner.SeverityHigh, "CVE-QUIET"),
		},
	}}
	enrich := map[string]Enrichment{
		"CVE-KEV":   {KEV: true, Ransomware: true, EPSS: 0.94, EPSSKnown: true},
		"CVE-QUIET": {EPSS: 0.003, EPSSKnown: true},
	}
	r := Build(scans, nil, tr(enrich), fixedTime)
	if !r.Triage {
		t.Fatal("Report.Triage = false, want true")
	}
	g := pkgGroup(t, r.Actionable, "nginx:1.25.3", "openssl")
	if g.Priority != PriorityActNow {
		t.Errorf("group priority = %q, want act_now (max of members)", g.Priority)
	}
	top := g.TopVuln()
	if top.ID != "CVE-KEV" || !top.KEV || !top.Ransomware || top.EPSS != 0.94 {
		t.Errorf("TopVuln = %+v, want the KEV CVE with its evidence", top)
	}
	if g.Vulns[1].Priority != PriorityLow {
		t.Errorf("second vuln priority = %q, want low", g.Vulns[1].Priority)
	}
}

func TestByPriority_RegroupsAcrossStatusSections(t *testing.T) {
	scans := []scanner.ImageScan{
		{
			Image: "app:1",
			Findings: []scanner.Finding{
				// fixed + KEV → act_now
				f("app:1", scanner.ClassOS, "openssl", "3.0.7", "3.0.11", scanner.StatusFixed, scanner.SeverityCritical, "CVE-KEV"),
				// affected CRITICAL, no signal → watch
				f("app:1", scanner.ClassOS, "e2fsprogs", "1.44.5", "", scanner.StatusAffected, scanner.SeverityCritical, "CVE-WAIT"),
				// fixed HIGH, no signal → low
				f("app:1", scanner.ClassOS, "dpkg", "1.19.7", "1.19.8", scanner.StatusFixed, scanner.SeverityHigh, "CVE-MEH"),
			},
		},
		{
			Image: "db:2",
			Findings: []scanner.Finding{
				// will_not_fix CRITICAL → demoted to low
				f("db:2", scanner.ClassOS, "gcc-8-base", "8.3.0", "", scanner.StatusWontFix, scanner.SeverityCritical, "CVE-WNF"),
			},
		},
	}
	enrich := map[string]Enrichment{"CVE-KEV": {KEV: true}}
	r := Build(scans, nil, tr(enrich), fixedTime)
	pv := r.ByPriority()

	if GroupCount(pv.ActNow) != 1 || pv.ActNow[0].Image != "app:1" || pv.ActNow[0].Packages[0].Package != "openssl" {
		t.Errorf("ActNow = %+v, want app:1/openssl only", pv.ActNow)
	}
	if GroupCount(pv.Watch) != 1 || pv.Watch[0].Packages[0].Package != "e2fsprogs" {
		t.Errorf("Watch = %+v, want app:1/e2fsprogs only", pv.Watch)
	}
	if GroupCount(pv.Low) != 2 {
		t.Errorf("Low group count = %d, want 2 (dpkg + gcc-8-base)", GroupCount(pv.Low))
	}
	// app:1 appears in three buckets; its packages must not leak across them.
	for _, img := range pv.Low {
		for _, g := range img.Packages {
			if g.Package == "openssl" || g.Package == "e2fsprogs" {
				t.Errorf("package %s leaked into Low bucket", g.Package)
			}
		}
	}
}

// TestByPriority_PreservesContentIDForSingleEntity guards against regrouping
// by Ref alone: the ordinary single-resolved-entity case must keep its
// ContentID through ByPriority, not just through the status sections.
func TestByPriority_PreservesContentIDForSingleEntity(t *testing.T) {
	scans := []scanner.ImageScan{
		resolvedScan("app:1", contentA, nil,
			f("app:1", scanner.ClassOS, "openssl", "3.0.7", "3.0.11", scanner.StatusFixed, scanner.SeverityCritical, "CVE-KEV")),
	}
	enrich := map[string]Enrichment{"CVE-KEV": {KEV: true}}
	r := Build(scans, nil, tr(enrich), fixedTime)
	pv := r.ByPriority()

	if len(pv.ActNow) != 1 || pv.ActNow[0].ContentID != contentA {
		t.Fatalf("ActNow = %+v, want one entry with ContentID %s", pv.ActNow, contentA)
	}
}

// TestByPriority_AmbiguousReferenceStaysSplit is the regression case: keying
// the priority regrouping on Ref alone would silently merge an Ambiguous
// reference's two distinct entities back into one section, undoing the
// (Ref, ContentID) aggregation the status sections already enforce.
func TestByPriority_AmbiguousReferenceStaysSplit(t *testing.T) {
	scans := []scanner.ImageScan{
		resolvedScan("app:1", contentA, nil,
			f("app:1", scanner.ClassOS, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityCritical, "CVE-A")),
		resolvedScan("app:1", contentB, nil,
			f("app:1", scanner.ClassOS, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityCritical, "CVE-B")),
	}
	enrich := map[string]Enrichment{"CVE-A": {KEV: true}, "CVE-B": {KEV: true}}
	r := Build(scans, nil, tr(enrich), fixedTime)
	pv := r.ByPriority()

	if len(pv.ActNow) != 2 {
		t.Fatalf("ActNow = %+v, want two separate entries (one per ContentID), not merged", pv.ActNow)
	}
	seen := map[string]bool{}
	for _, img := range pv.ActNow {
		if img.Image != "app:1" {
			t.Errorf("unexpected Image %q", img.Image)
		}
		seen[img.ContentID] = true
	}
	if !seen[contentA] || !seen[contentB] {
		t.Errorf("ContentIDs seen = %v, want both %s and %s", seen, contentA, contentB)
	}
}

// TestByPriority_AmbiguousReferencePreservesOwnContainers guards the same
// regrouping join ByPriority does for ContentID (see
// TestByPriority_AmbiguousReferenceStaysSplit) but for Containers: each of
// the two entities under the Ambiguous ref must keep only the containers
// running its own ContentID, not the sibling entity's.
func TestByPriority_AmbiguousReferencePreservesOwnContainers(t *testing.T) {
	scans := []scanner.ImageScan{
		resolvedScan("app:1", contentA, nil,
			f("app:1", scanner.ClassOS, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityCritical, "CVE-A")),
		resolvedScan("app:1", contentB, nil,
			f("app:1", scanner.ClassOS, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityCritical, "CVE-B")),
	}
	containers := []inventory.Container{
		{Name: "app-a", Image: inventory.RunningImage{Ref: "app:1", ContentID: contentA}},
		{Name: "app-b", Image: inventory.RunningImage{Ref: "app:1", ContentID: contentB}},
	}
	enrich := map[string]Enrichment{"CVE-A": {KEV: true}, "CVE-B": {KEV: true}}
	r := Build(scans, containers, tr(enrich), fixedTime)
	pv := r.ByPriority()

	if len(pv.ActNow) != 2 {
		t.Fatalf("ActNow = %+v, want two separate entries (one per ContentID)", pv.ActNow)
	}
	byContentID := map[string]ImageFindings{}
	for _, img := range pv.ActNow {
		byContentID[img.ContentID] = img
	}
	entA, ok := byContentID[contentA]
	if !ok || len(entA.Containers) != 1 || entA.Containers[0].Name != "app-a" {
		t.Errorf("contentA entry Containers = %+v, want exactly [app-a]", entA.Containers)
	}
	entB, ok := byContentID[contentB]
	if !ok || len(entB.Containers) != 1 || entB.Containers[0].Name != "app-b" {
		t.Errorf("contentB entry Containers = %+v, want exactly [app-b]", entB.Containers)
	}
}

func TestBuild_TriageDisabledLeavesNoPriorities(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			f("app:1", scanner.ClassOS, "openssl", "3.0.7", "3.0.11", scanner.StatusFixed, scanner.SeverityCritical, "CVE-X"),
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)
	if r.Triage {
		t.Error("Report.Triage = true, want false")
	}
	g := pkgGroup(t, r.Actionable, "app:1", "openssl")
	if g.Priority != PriorityNone {
		t.Errorf("priority = %q, want none", g.Priority)
	}
}

func TestBuild_AttachesRefs(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "nginx:1",
		Findings: []scanner.Finding{
			{Image: "nginx:1", Class: scanner.ClassOS, Package: "libh2", InstalledVer: "1.0", FixedVer: "1.1",
				Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-KEV",
				URL: "https://avd.aquasec.com/nvd/cve-kev"},
		},
	}}
	rules := tr(map[string]Enrichment{
		"CVE-KEV": {KEV: true, KEVNoteURL: "https://vendor.test/advisory"},
	})
	rules.Refs = map[string][]Ref{
		"CVE-KEV": {{Kind: "discussion", Label: "HN (166 pts)", URL: "https://news.ycombinator.com/item?id=1"}},
	}
	r := Build(scans, nil, rules, fixedTime)
	top := pkgGroup(t, r.Actionable, "nginx:1", "libh2").TopVuln()

	if top.URL != "https://avd.aquasec.com/nvd/cve-kev" {
		t.Errorf("URL = %q, want the scanner's advisory link", top.URL)
	}
	if len(top.Refs) != 2 {
		t.Fatalf("Refs = %+v, want vendor + discussion", top.Refs)
	}
	if top.Refs[0].Kind != "vendor" || top.Refs[0].URL != "https://vendor.test/advisory" {
		t.Errorf("Refs[0] = %+v, want the KEV vendor advisory first", top.Refs[0])
	}
	if top.Refs[1].Kind != "discussion" {
		t.Errorf("Refs[1] = %+v, want the discussion", top.Refs[1])
	}
}
