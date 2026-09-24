package notify

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// updateGolden rewrites the files under testdata/golden from the current
// output instead of comparing against them. Only ever run it deliberately,
// then review the resulting diff line by line: these files pin the exact
// text existing users receive.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/golden from current output")

// checkGolden compares got with testdata/golden/<name>.golden byte for byte.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".golden")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update-golden to create it)", path, err)
	}
	if got != string(want) {
		t.Errorf("%s: output differs from golden\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// threadSeparator joins the messages of one thread report in a golden file
// so the split points are pinned along with the text.
const threadSeparator = "\n===== next thread message =====\n"

// goldenThread renders the thread report for a golden comparison, with the
// first-seen lookups a diff-mode cycle passes (the state after the cycle).
// It is the single call site the golden tests use.
func goldenThread(r analyze.Report, st state.State, limit int) string {
	return strings.Join(BuildThreadMessages(r, Ages{Finding: st.FirstSeen, EOL: st.EOLFirstSeen}, limit), threadSeparator)
}

// goldenWebhook marshals the webhook payload, removes the top-level and diff
// keys that later additions are allowed to introduce, and re-marshals the
// remainder with sorted keys, so the comparison covers every field that
// existed before those additions.
func goldenWebhook(t *testing.T, r analyze.Report, d *state.Diff) string {
	t.Helper()
	data, err := json.Marshal(BuildWebhookPayload(r, d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(m, "eol_packages")
	if diff, ok := m["diff"].(map[string]any); ok {
		delete(diff, "new_eol_packages")
		delete(diff, "resolved_eol_packages")
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return string(out) + "\n"
}

const (
	goldenContentWeb = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	goldenContentAPI = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// goldenTodayScans is the current cycle of the protective fixture: only the
// fixed, affected and will_not_fix statuses, spread over two pinned images
// so every triage bucket, both upgrade-risk kinds, a package split across
// two status groups, and a scan failure all appear. eosl marks web:1.0's
// base OS as end-of-life.
func goldenTodayScans(eosl bool) []scanner.ImageScan {
	web := pinned(scanner.ImageScan{
		Image:  "web:1.0",
		OSEOSL: eosl,
		Findings: []scanner.Finding{
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", FixedVer: "3.0.11", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-2031-0001", URL: "https://avd.example/CVE-2031-0001", Title: "openssl: buffer overread"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0002"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "e2fsprogs", InstalledVer: "1.47.0-2", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-2031-0003", Title: "e2fsprogs: out-of-bounds write"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "dpkg", InstalledVer: "1.21.22", FixedVer: "1.21.23", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0004"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "gcc-12-base", InstalledVer: "12.2.0-14", Status: scanner.StatusWontFix, Severity: scanner.SeverityCritical, VulnID: "CVE-2031-0005"},
		},
	}, goldenContentWeb)
	api := pinned(scanner.ImageScan{
		Image: "api:2.0",
		Findings: []scanner.Finding{
			{Image: "api:2.0", Class: scanner.ClassOS, Package: "libxml2", InstalledVer: "2.9.14", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0006", URL: "https://avd.example/CVE-2031-0006", Title: "libxml2: use-after-free"},
			{Image: "api:2.0", Class: scanner.ClassOS, Package: "libxml2", InstalledVer: "2.9.14", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0007"},
			{Image: "api:2.0", Class: scanner.ClassLang, Package: "setuptools", InstalledVer: "53.0.0", FixedVer: "78.1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0008"},
			{Image: "api:2.0", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1.2.13", Status: scanner.StatusWontFix, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0009"},
		},
	}, goldenContentAPI)
	return []scanner.ImageScan{web, api, {Image: "broken:1", Err: errString("pull failed")}}
}

// goldenPrevScans is the previous cycle the diff fixtures start from, twenty
// days earlier: openssl had only its fixed CVE, dpkg had no fix yet, libxml2
// had one CVE fewer, zlib did not exist, and old-pkg has since disappeared.
func goldenPrevScans(eosl bool) []scanner.ImageScan {
	web := pinned(scanner.ImageScan{
		Image:  "web:1.0",
		OSEOSL: eosl,
		Findings: []scanner.Finding{
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", FixedVer: "3.0.11", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-2031-0001"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "e2fsprogs", InstalledVer: "1.47.0-2", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-2031-0003"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "dpkg", InstalledVer: "1.21.22", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0004"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "gcc-12-base", InstalledVer: "12.2.0-14", Status: scanner.StatusWontFix, Severity: scanner.SeverityCritical, VulnID: "CVE-2031-0005"},
			{Image: "web:1.0", Class: scanner.ClassOS, Package: "old-pkg", InstalledVer: "0.9", FixedVer: "1.0", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0010"},
		},
	}, goldenContentWeb)
	api := pinned(scanner.ImageScan{
		Image: "api:2.0",
		Findings: []scanner.Finding{
			{Image: "api:2.0", Class: scanner.ClassOS, Package: "libxml2", InstalledVer: "2.9.14", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0006"},
			{Image: "api:2.0", Class: scanner.ClassLang, Package: "setuptools", InstalledVer: "53.0.0", FixedVer: "78.1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2031-0008"},
		},
	}, goldenContentAPI)
	return []scanner.ImageScan{web, api}
}

// goldenTodayEnrich drives every priority rule: KEV with ransomware
// (act_now), EPSS above the act-now threshold on an unfixed CVE (act_now),
// KEV on a will_not_fix CVE (act_now), EPSS in the watch band, CRITICAL
// without a signal (watch), a will_not_fix CRITICAL demoted to low, and an
// unknown EPSS.
func goldenTodayEnrich() map[string]analyze.Enrichment {
	return map[string]analyze.Enrichment{
		"CVE-2031-0001": {KEV: true, Ransomware: true, EPSS: 0.94321, EPSSKnown: true, KEVNoteURL: "https://vendor.example/advisory/1"},
		"CVE-2031-0002": {EPSS: 0.0004, EPSSKnown: true},
		"CVE-2031-0003": {EPSS: 0.031, EPSSKnown: true},
		"CVE-2031-0004": {EPSS: 0.0004, EPSSKnown: true},
		"CVE-2031-0005": {EPSS: 0.02, EPSSKnown: true},
		"CVE-2031-0006": {EPSS: 0.2, EPSSKnown: true},
		"CVE-2031-0007": {EPSS: 0.05, EPSSKnown: true},
		"CVE-2031-0009": {KEV: true, EPSS: 0.5, EPSSKnown: true},
	}
}

// goldenPrevEnrich is the previous cycle's intel: CVE-2031-0001 was not yet
// in KEV, so today's cycle escalates it.
func goldenPrevEnrich() map[string]analyze.Enrichment {
	e := goldenTodayEnrich()
	e["CVE-2031-0001"] = analyze.Enrichment{EPSS: 0.0004, EPSSKnown: true}
	return e
}

// goldenPrevTime is when the previous cycle ran.
var goldenPrevTime = genTime.AddDate(0, 0, -20)

type goldenMode struct {
	name   string
	triage func(map[string]analyze.Enrichment) analyze.Triage
}

func goldenModes() []goldenMode {
	return []goldenMode{
		{name: "triage", triage: triageRules},
		{name: "notriage", triage: func(map[string]analyze.Enrichment) analyze.Triage { return analyze.Triage{} }},
		{name: "degraded", triage: func(e map[string]analyze.Enrichment) analyze.Triage {
			tr := triageRules(e)
			tr.Intel = analyze.IntelStatus{}
			return tr
		}},
	}
}

// goldenCycle builds today's report and the diffs of the three diff-mode
// situations: changes since the previous cycle, and an unchanged follow-up
// cycle. It returns the state after today's cycle for first-seen lookups.
func goldenCycle(m goldenMode, eosl bool) (r analyze.Report, changed, unchanged state.Diff, next state.State) {
	prev := analyze.Build(goldenPrevScans(eosl), nil, m.triage(goldenPrevEnrich()), goldenPrevTime)
	_, prevState := state.Compute(state.State{}, prev)
	r = analyze.Build(goldenTodayScans(eosl), nil, m.triage(goldenTodayEnrich()), genTime)
	changed, next = state.Compute(prevState, r)
	unchanged, _ = state.Compute(next, r)
	return r, changed, unchanged, next
}

// TestGolden_ThreeStatusOutputs pins the complete text of every Slack
// rendering, every thread message, and the pre-existing webhook fields for
// a scan carrying only the fixed, affected and will_not_fix statuses and no
// end-of-life base image. None of these outputs may change when support for
// further statuses is added.
func TestGolden_ThreeStatusOutputs(t *testing.T) {
	for _, m := range goldenModes() {
		t.Run(m.name, func(t *testing.T) {
			r, changed, unchanged, next := goldenCycle(m, false)
			p := "status3_" + m.name + "_"
			checkGolden(t, p+"slack_full", FormatSlackText(r))
			checkGolden(t, p+"slack_diff_changes", FormatSlackDiffText(r, changed, false, false))
			checkGolden(t, p+"slack_diff_nochanges", FormatSlackDiffText(r, unchanged, false, false))
			checkGolden(t, p+"slack_diff_weekly", FormatSlackDiffText(r, changed, true, false))
			checkGolden(t, p+"slack_diff_weekly_nochanges", FormatSlackDiffText(r, unchanged, true, false))
			checkGolden(t, p+"thread", goldenThread(r, next, 0))
			checkGolden(t, p+"thread_split", goldenThread(r, next, 700))
			checkGolden(t, p+"webhook_full", goldenWebhook(t, r, nil))
			checkGolden(t, p+"webhook_diff", goldenWebhook(t, r, &changed))
		})
	}
}

// TestGolden_EOSLOutputs is the same fixture with web:1.0's base OS marked
// end-of-life. It is kept apart from TestGolden_ThreeStatusOutputs because
// the "Open now" heartbeat of this fixture is allowed to change: the base
// image count moves to the state-held set and appears with triage off too.
func TestGolden_EOSLOutputs(t *testing.T) {
	for _, m := range goldenModes() {
		t.Run(m.name, func(t *testing.T) {
			r, changed, unchanged, next := goldenCycle(m, true)
			p := "eosl_" + m.name + "_"
			checkGolden(t, p+"slack_full", FormatSlackText(r))
			checkGolden(t, p+"slack_diff_changes", FormatSlackDiffText(r, changed, false, false))
			checkGolden(t, p+"slack_diff_nochanges", FormatSlackDiffText(r, unchanged, false, false))
			checkGolden(t, p+"thread", goldenThread(r, next, 0))
			checkGolden(t, p+"webhook_diff", goldenWebhook(t, r, &changed))
		})
	}
}

// TestGolden_FailureHoldingOutputs pins the heartbeat of cycles where state
// is holding findings because a scan failed:
//   - eosl_failed: the end-of-life image's scan fails while another image
//     still has findings, so its base-OS record is held.
//   - all_failed_clean: the only image with history fails while a second
//     image scans clean, so the current report has no findings at all.
//
// These are the outputs that later changes are allowed to alter (the held
// base image is counted, and a report that is empty only because of a
// failure no longer claims "all clear").
func TestGolden_FailureHoldingOutputs(t *testing.T) {
	for _, m := range goldenModes() {
		t.Run(m.name, func(t *testing.T) {
			_, _, _, st := goldenCycle(m, true)

			webFailed := pinned(scanner.ImageScan{Image: "web:1.0", Err: errString("pull failed")}, goldenContentWeb)
			today := goldenTodayScans(true)
			failedCycle := analyze.Build([]scanner.ImageScan{webFailed, today[1]}, nil, m.triage(goldenTodayEnrich()), genTime.AddDate(0, 0, 1))
			d, _ := state.Compute(st, failedCycle)
			checkGolden(t, "failure_"+m.name+"_eosl_failed", FormatSlackDiffText(failedCycle, d, false, false))

			apiClean := pinned(scanner.ImageScan{Image: "api:2.0"}, goldenContentAPI)
			_, webOnly := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{goldenTodayScans(false)[0]}, nil, m.triage(goldenTodayEnrich()), genTime))
			cleanCycle := analyze.Build([]scanner.ImageScan{webFailed, apiClean}, nil, m.triage(goldenTodayEnrich()), genTime.AddDate(0, 0, 1))
			d2, _ := state.Compute(webOnly, cleanCycle)
			checkGolden(t, "failure_"+m.name+"_all_failed_clean", FormatSlackDiffText(cleanCycle, d2, false, false))
		})
	}
}
