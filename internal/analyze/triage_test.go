package analyze

import (
	"testing"

	"github.com/kitsunetrail/stackwatch/internal/scanner"
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
	r := Build(scans, tr(enrich), fixedTime)
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
	r := Build(scans, tr(enrich), fixedTime)
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

func TestBuild_TriageDisabledLeavesNoPriorities(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			f("app:1", scanner.ClassOS, "openssl", "3.0.7", "3.0.11", scanner.StatusFixed, scanner.SeverityCritical, "CVE-X"),
		},
	}}
	r := Build(scans, Triage{}, fixedTime)
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
	r := Build(scans, rules, fixedTime)
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
