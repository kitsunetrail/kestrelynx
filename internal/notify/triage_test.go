package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// triageRules is the default-threshold triage config with healthy intel.
func triageRules(enrich map[string]analyze.Enrichment) analyze.Triage {
	return analyze.Triage{
		Enabled: true, ActNowEPSS: 0.10, WatchEPSS: 0.01,
		Enrich: enrich, Intel: analyze.IntelStatus{KEVOK: true, EPSSOK: true},
	}
}

// triageScans covers all three buckets plus EOSL and a scan error.
func triageScans() []scanner.ImageScan {
	return []scanner.ImageScan{
		{
			Image:  "web:1.0",
			OSEOSL: true,
			Findings: []scanner.Finding{
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", FixedVer: "3.0.11", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-KEV"},
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "e2fsprogs", InstalledVer: "1.44", FixedVer: "", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-WAIT"},
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "dpkg", InstalledVer: "1.19.7", FixedVer: "1.19.8", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-MEH"},
			},
		},
		{Image: "broken:1", Err: errString("pull failed")},
	}
}

func triageEnrich() map[string]analyze.Enrichment {
	return map[string]analyze.Enrichment{
		"CVE-KEV":  {KEV: true, Ransomware: true, EPSS: 0.94321, EPSSKnown: true},
		"CVE-WAIT": {EPSS: 0.031, EPSSKnown: true},
		"CVE-MEH":  {EPSS: 0.0004, EPSSKnown: true},
	}
}

func triageReport() analyze.Report {
	return analyze.Build(triageScans(), nil, triageRules(triageEnrich()), genTime)
}

func TestFormatSlackText_TriageLayout(t *testing.T) {
	out := FormatSlackText(triageReport())

	mustContain := []string{
		"*Priority:* ⛔ 1 EOL base · 🚨 1 act now · 👀 1 watch · 🔕 1 low",
		"*🚨 Act now (1) — exploited or likely to be*",
		"• web:1.0", // image lines are plain bullets in triage mode
		"openssl 3.0.7 → 3.0.11",
		"CVE-KEV CRITICAL · CISA KEV (exploited in the wild) · EPSS 94% · 🧨 ransomware campaign",
		"*👀 Watch (1) — not urgent, keep an eye on*",
		"e2fsprogs 1.44 (no fix available)",
		"CVE-WAIT · EPSS 3%",
		"*🔕 Low priority (1)*",
		"end-of-life", // EOSL warning stays top-priority
		"broken:1",    // scan errors always shown
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n---\n%s", s, out)
		}
	}
	// The low bucket is a count, not a listing.
	if strings.Contains(out, "dpkg 1.19.7") {
		t.Errorf("low-priority package should be collapsed to a count:\n%s", out)
	}
	// Triage mode drops the per-image severity emoji: the bucket header
	// already carries the urgency signal.
	if strings.Contains(out, "🔴") {
		t.Errorf("triage mode must not show a severity emoji on image lines:\n%s", out)
	}
	// Order: act now before watch before low.
	if !(strings.Index(out, "Act now") < strings.Index(out, "Watch (") &&
		strings.Index(out, "Watch (") < strings.Index(out, "Low priority")) {
		t.Errorf("bucket order wrong:\n%s", out)
	}
}

func TestFormatSlackText_TriageNoFixActNow(t *testing.T) {
	// KEV-listed but no fix available: still act now, with the mitigation hint.
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-K"},
		},
	}}
	out := FormatSlackText(analyze.Build(scans, nil, triageRules(map[string]analyze.Enrichment{"CVE-K": {KEV: true}}), genTime))
	if !strings.Contains(out, "*🚨 Act now (1) — exploited or likely to be*") {
		t.Errorf("KEV without fix must stay act now:\n%s", out)
	}
	if !strings.Contains(out, "no fix yet, consider mitigation") {
		t.Errorf("expected the mitigation hint:\n%s", out)
	}
	if !strings.Contains(out, "EPSS n/a") {
		t.Errorf("missing EPSS should read n/a, not 0:\n%s", out)
	}
}

func TestFormatSlackText_TriageDegraded(t *testing.T) {
	tr := triageRules(nil)
	tr.Intel = analyze.IntelStatus{} // no usable intel
	out := FormatSlackText(analyze.Build(triageScans(), nil, tr, genTime))

	if !strings.Contains(out, "⚠️ Vulnerability intel (KEV/EPSS) unavailable") {
		t.Errorf("degraded mode must be announced:\n%s", out)
	}
	if strings.Contains(out, "Low priority") {
		t.Errorf("degraded mode must not produce a low bucket:\n%s", out)
	}
	if !strings.Contains(out, "severity only (intel unavailable)") {
		t.Errorf("degraded evidence should state the fallback:\n%s", out)
	}
}

func TestFormatSlackText_TriageStaleNote(t *testing.T) {
	tr := triageRules(triageEnrich())
	tr.Intel.StaleDays = 3
	out := FormatSlackText(analyze.Build(triageScans(), nil, tr, genTime))
	if !strings.Contains(out, "Intel data is 3 day(s) old") {
		t.Errorf("stale intel should be annotated:\n%s", out)
	}
}

func TestFormatSlackDiffText_TriageEscalation(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-1"},
	}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(nil), genTime))
	r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(map[string]analyze.Enrichment{"CVE-1": {KEV: true}}), genTime.AddDate(0, 0, 1))
	d, _ := state.Compute(st, r)

	out := FormatSlackDiffText(r, d, false)
	if !strings.Contains(out, "⬆️ escalated to ACT NOW") {
		t.Errorf("escalation must be called out:\n%s", out)
	}
	if !strings.Contains(out, "CISA KEV (exploited in the wild)") {
		t.Errorf("escalated act-now change needs its evidence line:\n%s", out)
	}
	if !strings.Contains(out, "🚨 1 act-now") {
		t.Errorf("heartbeat should break down by priority:\n%s", out)
	}
}

func TestFormatSlackDiffText_TriageHeartbeatAgesUrgentOnly(t *testing.T) {
	lowScan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-L"},
	}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{lowScan}, nil, triageRules(nil), genTime))
	// 30 days later, still open, still low: no red aging in the heartbeat.
	r := analyze.Build([]scanner.ImageScan{lowScan}, nil, triageRules(nil), genTime.AddDate(0, 0, 30))
	d, _ := state.Compute(st, r)

	out := FormatSlackDiffText(r, d, false)
	if !strings.Contains(out, "🔕 1 low") {
		t.Errorf("heartbeat should show the open low count:\n%s", out)
	}
	if strings.Contains(out, "oldest act-now/watch") {
		t.Errorf("an old low finding must not age the heartbeat:\n%s", out)
	}
}

// The heartbeat age names its subject ("act-now/watch"): an aged watch-only
// backlog was misread as urgent act-now debt under the old "oldest urgent"
// wording.
func TestFormatSlackDiffText_TriageHeartbeatAgeWording(t *testing.T) {
	watchScan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-W"},
	}}
	enrich := map[string]analyze.Enrichment{"CVE-W": {EPSS: 0.03, EPSSKnown: true}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{watchScan}, nil, triageRules(enrich), genTime))
	// 20 days later, still open, still watch: aged past staleDays, red.
	r := analyze.Build([]scanner.ImageScan{watchScan}, nil, triageRules(enrich), genTime.AddDate(0, 0, 20))
	d, _ := state.Compute(st, r)

	out := FormatSlackDiffText(r, d, false)
	if !strings.Contains(out, "⏰ oldest act-now/watch unresolved 20 day(s)") {
		t.Errorf("aged watch finding must age the heartbeat under its own name:\n%s", out)
	}
}

func TestBuildWebhookPayload_TriageFields(t *testing.T) {
	r := triageReport()
	d, _ := state.Compute(state.State{}, r)
	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}

	sum := p["summary"].(map[string]any)
	counts := sum["priority_counts"].(map[string]any)
	if counts["act_now"].(float64) != 1 || counts["watch"].(float64) != 1 || counts["low"].(float64) != 1 {
		t.Errorf("priority_counts = %v, want 1/1/1", counts)
	}
	intel := sum["intel"].(map[string]any)
	if intel["degraded"].(bool) || !intel["kev_ok"].(bool) {
		t.Errorf("intel = %v", intel)
	}

	// The act-now finding carries per-CVE evidence.
	actionable := p["actionable"].([]any)
	finding := actionable[0].(map[string]any)["findings"].([]any)[0].(map[string]any)
	if finding["priority"] != "act_now" {
		t.Errorf("finding priority = %v, want act_now", finding["priority"])
	}
	vuln := finding["vulns"].([]any)[0].(map[string]any)
	if vuln["id"] != "CVE-KEV" || vuln["kev"] != true || vuln["epss"].(float64) != 0.94321 {
		t.Errorf("vuln payload = %v", vuln)
	}

	// Compatibility: the status sections and vuln_ids are untouched.
	for _, key := range []string{"actionable", "watch", "wont_fix", "eosl_images"} {
		if _, ok := p[key]; !ok {
			t.Errorf("payload missing legacy key %q", key)
		}
	}
	if _, ok := finding["vuln_ids"]; !ok {
		t.Error("payload missing legacy vuln_ids")
	}
}

func TestBuildWebhookPayload_NoTriageOmitsTriageFields(t *testing.T) {
	r := sampleReport() // built with Triage{} disabled
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	sum := p["summary"].(map[string]any)
	if _, ok := sum["priority_counts"]; ok {
		t.Error("priority_counts must be omitted when triage is off")
	}
	if _, ok := sum["intel"]; ok {
		t.Error("intel must be omitted when triage is off")
	}
}

func TestFormatSlackText_TriageRefsLine(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "nginx:1",
		Findings: []scanner.Finding{
			{Image: "nginx:1", Class: scanner.ClassOS, Package: "libh2", InstalledVer: "1.0", FixedVer: "1.1",
				Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-KEV",
				URL: "https://avd.aquasec.com/nvd/cve-kev"},
		},
	}}
	rules := triageRules(map[string]analyze.Enrichment{
		"CVE-KEV": {KEV: true, KEVNoteURL: "https://vendor.test/advisory"},
	})
	rules.Refs = map[string][]analyze.Ref{
		"CVE-KEV": {{Kind: "discussion", Label: "HN (166 pts)", URL: "https://news.ycombinator.com/item?id=1"}},
	}
	out := FormatSlackText(analyze.Build(scans, nil, rules, genTime))

	if !strings.Contains(out, "📎 <https://avd.aquasec.com/nvd/cve-kev|advisory> · <https://vendor.test/advisory|vendor advisory> · <https://news.ycombinator.com/item?id=1|💬 HN (166 pts)>") {
		t.Errorf("expected the refs line with Slack link syntax:\n%s", out)
	}
}

func TestBuildWebhookPayload_Refs(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "nginx:1",
		Findings: []scanner.Finding{
			{Image: "nginx:1", Class: scanner.ClassOS, Package: "libh2", InstalledVer: "1.0", FixedVer: "1.1",
				Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-KEV",
				URL: "https://avd.aquasec.com/nvd/cve-kev"},
		},
	}}
	rules := triageRules(map[string]analyze.Enrichment{"CVE-KEV": {KEV: true, KEVNoteURL: "https://vendor.test/advisory"}})
	r := analyze.Build(scans, nil, rules, genTime)
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	finding := p["actionable"].([]any)[0].(map[string]any)["findings"].([]any)[0].(map[string]any)
	vuln := finding["vulns"].([]any)[0].(map[string]any)
	if vuln["url"] != "https://avd.aquasec.com/nvd/cve-kev" {
		t.Errorf("vuln url = %v", vuln["url"])
	}
	refs := vuln["refs"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["kind"] != "vendor" {
		t.Errorf("refs = %v, want the vendor advisory", refs)
	}
}
