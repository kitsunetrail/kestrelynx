package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
	"github.com/kitsunetrail/stackwatch/internal/state"
)

var genTime = time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)

// sampleReport builds a report exercising every section.
func sampleReport() analyze.Report {
	scans := []scanner.ImageScan{
		{
			Image:  "web:1.0",
			OSEOSL: true,
			Findings: []scanner.Finding{
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
				{Image: "web:1.0", Class: scanner.ClassLang, Package: "setuptools", InstalledVer: "53.0.0", FixedVer: "78.1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2"},
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "e2fsprogs", InstalledVer: "1.44", FixedVer: "", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-3"},
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "gcc-8-base", InstalledVer: "8.3", FixedVer: "", Status: scanner.StatusWontFix, Severity: scanner.SeverityHigh, VulnID: "CVE-4"},
			},
		},
		{Image: "broken:1", Err: errString("pull failed")},
	}
	return analyze.Build(scans, analyze.Triage{}, genTime)
}

type errString string

func (e errString) Error() string { return string(e) }

func TestFormatSlackText_Sections(t *testing.T) {
	out := FormatSlackText(sampleReport())

	mustContain := []string{
		"StackWatch",
		"2026-06-24",
		"web:1.0",
		"libc-bin",
		"2.28-10 → 2.28-10+deb10u2",
		"setuptools",
		"Distro security update", // OS distro_update label
		"Needs care",             // lang caution label
		"end-of-life",            // EOSL
		"e2fsprogs",              // affected
		"gcc-8-base",             // wont_fix
		"broken:1",               // scan error
		"pull failed",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n---\n%s", s, out)
		}
	}
}

func TestFormatSlackText_Ordering(t *testing.T) {
	out := FormatSlackText(sampleReport())
	eosl := strings.Index(out, "end-of-life")
	actionable := strings.Index(out, "libc-bin")
	affected := strings.Index(out, "e2fsprogs")
	wontfix := strings.Index(out, "gcc-8-base")

	if !(eosl < actionable && actionable < affected && affected < wontfix) {
		t.Errorf("section order wrong: eosl=%d actionable=%d affected=%d wontfix=%d", eosl, actionable, affected, wontfix)
	}
}

// collapseReport builds an image with one CRITICAL package plus several
// low-risk (safe minor-bump) fixes, to exercise the collapsing behavior.
func collapseReport() analyze.Report {
	finds := []scanner.Finding{
		{Image: "big:1", Class: scanner.ClassLang, Package: "crit-pkg", InstalledVer: "2.0.0", FixedVer: "2.1.0", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "C-1"},
	}
	for _, n := range []string{"safe-a", "safe-b", "safe-c", "safe-d", "safe-e", "safe-f", "safe-g"} {
		finds = append(finds, scanner.Finding{Image: "big:1", Class: scanner.ClassLang, Package: n, InstalledVer: "1.0.0", FixedVer: "1.2.0", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "H-" + n})
	}
	return analyze.Build([]scanner.ImageScan{{Image: "big:1", Findings: finds}}, analyze.Triage{}, genTime)
}

func TestFormatSlackText_CollapsesLowRisk(t *testing.T) {
	out := FormatSlackText(collapseReport())

	if !strings.Contains(out, "*Priority:*") {
		t.Errorf("expected a priority headline:\n%s", out)
	}
	if !strings.Contains(out, "crit-pkg") {
		t.Errorf("critical package must be shown in full:\n%s", out)
	}
	if !strings.Contains(out, "+7 lower-risk fixes") {
		t.Errorf("expected the 7 safe fixes collapsed into one summary line:\n%s", out)
	}
	// Only collapsePreview names are listed; the rest are elided, not enumerated.
	if strings.Contains(out, "safe-g") {
		t.Errorf("low-risk package beyond the preview should be collapsed, not listed:\n%s", out)
	}
	if !strings.Contains(out, "summarized") {
		t.Errorf("expected the footer pointing to the webhook for full detail:\n%s", out)
	}
}

func TestFormatSlackText_Clean(t *testing.T) {
	clean := analyze.Build([]scanner.ImageScan{{Image: "ok:1"}}, analyze.Triage{}, genTime)
	out := FormatSlackText(clean)
	if !strings.Contains(out, "All clear") {
		t.Errorf("clean report should say All clear, got:\n%s", out)
	}
}

// diffFixture runs sampleReport through state.Compute against empty state, so
// every finding comes back as a KindNew change with realistic groups.
func diffFixture() (analyze.Report, state.Diff) {
	r := sampleReport()
	d, _ := state.Compute(state.State{}, r)
	return r, d
}

func TestFormatSlackDiffText_NewFindings(t *testing.T) {
	r, d := diffFixture()
	out := FormatSlackDiffText(r, d, false)

	mustContain := []string{
		"New since last scan",
		"New: base OS end-of-life", // EOSL first seen goes through the diff too
		"web:1.0",
		"libc-bin",
		"setuptools",
		"Open now: CRITICAL 1 / HIGH 3",
		"broken:1", // scan errors always shown
		"pull failed",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n---\n%s", s, out)
		}
	}
	if strings.Contains(out, "Resolved since last scan") {
		t.Errorf("no resolved section expected on first run:\n%s", out)
	}
}

func TestFormatSlackDiffText_Heartbeat(t *testing.T) {
	r := sampleReport()
	_, st := state.Compute(state.State{}, r)
	// Second scan, same findings: no changes.
	d, _ := state.Compute(st, r)
	out := FormatSlackDiffText(r, d, false)

	if !strings.Contains(out, "No changes since last scan") {
		t.Errorf("expected heartbeat line:\n%s", out)
	}
	if !strings.Contains(out, "Open now: CRITICAL 1 / HIGH 3") {
		t.Errorf("heartbeat must keep the open summary:\n%s", out)
	}
	if strings.Contains(out, "libc-bin") {
		t.Errorf("heartbeat must not repeat finding details:\n%s", out)
	}
}

func TestFormatSlackDiffText_AgeAndEscalation(t *testing.T) {
	r := sampleReport()
	old := genTime.AddDate(0, 0, -20)
	st := state.State{Version: 1, Findings: map[string]state.Entry{
		"web:1.0\tlibc-bin": {FirstSeen: old, Fixable: true, VulnIDs: []string{"CVE-1"}},
	}, EOSL: map[string]time.Time{}}
	d, _ := state.Compute(st, r)
	out := FormatSlackDiffText(r, d, false)

	if !strings.Contains(out, "🔴 oldest unresolved 20 day(s)") {
		t.Errorf("expected escalated age marker for a 20-day-old finding:\n%s", out)
	}
}

func TestFormatSlackDiffText_Resolved(t *testing.T) {
	r := sampleReport()
	st := state.State{Version: 1, Findings: map[string]state.Entry{
		"web:1.0\tlibc-bin": {FirstSeen: genTime, Fixable: true, VulnIDs: []string{"CVE-1"}},
		"gone:1\told-pkg":   {FirstSeen: genTime, Fixable: true, VulnIDs: []string{"CVE-9"}},
	}, EOSL: map[string]time.Time{}}
	d, _ := state.Compute(st, r)
	out := FormatSlackDiffText(r, d, false)

	if !strings.Contains(out, "Resolved since last scan") || !strings.Contains(out, "gone:1: old-pkg") {
		t.Errorf("expected resolved section for gone:1 old-pkg:\n%s", out)
	}
}

func TestFormatSlackDiffText_WeeklyFullReport(t *testing.T) {
	r := sampleReport()
	_, st := state.Compute(state.State{}, r)
	d, _ := state.Compute(st, r) // unchanged day
	out := FormatSlackDiffText(r, d, true)

	if !strings.Contains(out, "Weekly full report") {
		t.Errorf("expected weekly full report heading:\n%s", out)
	}
	// Full body repeats every open finding even though nothing changed.
	for _, s := range []string{"libc-bin", "e2fsprogs", "gcc-8-base", "end-of-life"} {
		if !strings.Contains(out, s) {
			t.Errorf("full report missing %q:\n%s", s, out)
		}
	}
}

func TestFormatSlackDiffText_AllResolvedCelebrates(t *testing.T) {
	clean := analyze.Build([]scanner.ImageScan{{Image: "ok:1"}}, analyze.Triage{}, genTime)
	st := state.State{Version: 1, Findings: map[string]state.Entry{
		"ok:1\topenssl": {FirstSeen: genTime, Fixable: true, VulnIDs: []string{"CVE-1"}},
	}, EOSL: map[string]time.Time{}}
	d, _ := state.Compute(st, clean)
	out := FormatSlackDiffText(clean, d, false)

	if !strings.Contains(out, "Resolved since last scan") {
		t.Errorf("expected resolved section:\n%s", out)
	}
	if !strings.Contains(out, "Open now: none") {
		t.Errorf("expected all-clear open line:\n%s", out)
	}
}

func TestBuildWebhookPayload_Diff(t *testing.T) {
	r, d := diffFixture()
	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	diff, ok := p["diff"].(map[string]any)
	if !ok {
		t.Fatalf("diff missing/wrong type: %T", p["diff"])
	}
	if n := len(diff["new"].([]any)); n != 4 {
		t.Errorf("diff.new = %d entries, want 4", n)
	}
	first := diff["new"].([]any)[0].(map[string]any)
	for _, key := range []string{"image", "package", "kind", "critical", "high"} {
		if _, ok := first[key]; !ok {
			t.Errorf("diff entry missing %q: %v", key, first)
		}
	}
	// Full sections must still be present alongside the diff.
	if _, ok := p["actionable"]; !ok {
		t.Error("payload must keep full sections in diff mode")
	}
}

func TestBuildWebhookPayload_NoDiffOmitted(t *testing.T) {
	data, err := json.Marshal(BuildWebhookPayload(sampleReport(), nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), `"diff"`) {
		t.Error("diff key should be omitted in full mode")
	}
}

func TestBuildWebhookPayload(t *testing.T) {
	data, err := json.Marshal(BuildWebhookPayload(sampleReport(), nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := p["generated_at"]; !ok {
		t.Error("missing generated_at")
	}
	summary, ok := p["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing/wrong type: %T", p["summary"])
	}
	if summary["images_total"].(float64) != 2 {
		t.Errorf("images_total = %v, want 2", summary["images_total"])
	}
	for _, key := range []string{"actionable", "watch", "wont_fix", "eosl_images", "scan_errors"} {
		if _, ok := p[key]; !ok {
			t.Errorf("payload missing %q", key)
		}
	}

	// drill into one actionable finding for field shape
	act := p["actionable"].([]any)
	if len(act) == 0 {
		t.Fatal("actionable empty")
	}
	img := act[0].(map[string]any)
	finds := img["findings"].([]any)
	fnd := finds[0].(map[string]any)
	for _, key := range []string{"package", "installed", "fixed", "severity_counts", "upgrade_risk", "vuln_ids"} {
		if _, ok := fnd[key]; !ok {
			t.Errorf("finding missing %q: %v", key, fnd)
		}
	}
}
