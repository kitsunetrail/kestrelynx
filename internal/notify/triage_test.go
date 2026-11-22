package notify

import (
	"encoding/json"
	"fmt"
	"slices"
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

func TestChannel_TriageLayout(t *testing.T) {
	out := renderFull(triageReport())

	mustContain := []string{
		"*Priority:* ⛔ 1 EOL base · 🚨 1 act now · 👀 1 watch · 🔕 1 low",
		"*🚨 Act now (1) — exploited or likely to be*",
		"*Image: web:1.0", // image lines carry no severity emoji in triage mode
		"*◆ openssl*\nInstalled: 3.0.7\nFixed in: 3.0.11",
		"CVEs:\n• <https://nvd.nist.gov/vuln/detail/CVE-KEV|CVE-KEV> · CRITICAL · EPSS 94% · CISA KEV (exploited in the wild) · 🧨 ransomware campaign",
		"*👀 Watch (1) — not urgent, keep an eye on*",
		"*◆ e2fsprogs*\nInstalled: 1.44 · Fixed in: none",
		"CVEs: <https://nvd.nist.gov/vuln/detail/CVE-WAIT|CVE-WAIT> (EPSS 3%)",
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
	if strings.Contains(out, "*◆ dpkg*") {
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

func TestChannel_TriageNoFixActNow(t *testing.T) {
	// KEV-listed but no fix available: still act now, with the mitigation hint.
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-K"},
		},
	}}
	out := renderFull(analyze.Build(scans, nil, triageRules(map[string]analyze.Enrichment{"CVE-K": {KEV: true}}), genTime))
	if !strings.Contains(out, "*🚨 Act now (1) — exploited or likely to be*") {
		t.Errorf("KEV without fix must stay act now:\n%s", out)
	}
	if !strings.Contains(out, "Fixed in: none — consider mitigation") {
		t.Errorf("expected the mitigation hint:\n%s", out)
	}
	if !strings.Contains(out, "EPSS n/a") {
		t.Errorf("missing EPSS should read n/a, not 0:\n%s", out)
	}
}

func TestChannel_TriageDegraded(t *testing.T) {
	tr := triageRules(nil)
	tr.Intel = analyze.IntelStatus{} // no usable intel
	out := renderFull(analyze.Build(triageScans(), nil, tr, genTime))

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

func TestChannel_TriageStaleNote(t *testing.T) {
	tr := triageRules(triageEnrich())
	tr.Intel.StaleDays = 3
	out := renderFull(analyze.Build(triageScans(), nil, tr, genTime))
	if !strings.Contains(out, "Intel data is 3 day(s) old") {
		t.Errorf("stale intel should be annotated:\n%s", out)
	}
}

func TestChannelDiff_TriageEscalation(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-1"},
	}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(nil), genTime))
	r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(map[string]analyze.Enrichment{"CVE-1": {KEV: true}}), genTime.AddDate(0, 0, 1))
	d, _ := state.Compute(st, r)

	out := renderDiff(r, d, false, false)
	if !strings.Contains(out, "⬆️ escalated to ACT NOW") {
		t.Errorf("escalation must be called out:\n%s", out)
	}
	if !strings.Contains(out, "CISA KEV (exploited in the wild)") {
		t.Errorf("escalated act-now change needs the KEV fact on its CVE line:\n%s", out)
	}
	if !strings.Contains(out, "🚨 1 act-now") {
		t.Errorf("heartbeat should break down by priority:\n%s", out)
	}
}

// A triage-mode change item other than act-now carries a line naming its
// CVEs, so "New since last scan" says which CVEs are behind the card instead
// of leaving the reader to open the webhook payload.
// An act-now change shows its evidence in the card's own evidence section, so
// its head must not repeat it.
func TestChannelDiff_TriageChangeCompactEvidence(t *testing.T) {
	r := triageReport()
	d, _ := state.Compute(state.State{}, r)
	out := renderDiff(r, d, false, false)

	if !strings.Contains(out, "*◆ e2fsprogs*\nInstalled: 1.44 · Fixed in: none\nFindings: CRITICAL 1 / HIGH 0\nCVEs: <https://nvd.nist.gov/vuln/detail/CVE-WAIT|CVE-WAIT> (EPSS 3%)") {
		t.Errorf("expected the CVE line on the watch change card:\n%s", out)
	}
	if strings.Contains(out, "Fixed in: 3.0.11 (🟢 distro security patch)") {
		t.Errorf("an act-now change must be a detail card, not a compact one repeating the evidence:\n%s", out)
	}
}

// A known package escalated to WATCH shows the escalation on its change line
// and the CVE the verdict rests on with its EPSS.
func TestChannelDiff_TriageEscalationToWatch(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-1"},
	}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(nil), genTime))
	r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(map[string]analyze.Enrichment{"CVE-1": {EPSS: 0.03, EPSSKnown: true}}), genTime.AddDate(0, 0, 1))
	d, _ := state.Compute(st, r)

	out := renderDiff(r, d, false, false)
	want := "*◆ openssl*\nChange: ⬆️ escalated to WATCH\nInstalled: 1.0 · Fixed in: 1.1 (🟢 distro security patch)\nFindings: CRITICAL 0 / HIGH 1\nCVEs: <https://nvd.nist.gov/vuln/detail/CVE-1|CVE-1> (EPSS 3%)"
	if !strings.Contains(out, want) {
		t.Errorf("expected the escalation and the evidence:\n%s\nin:\n%s", want, out)
	}
}

// With intel degraded the CVE line must not cite KEV/EPSS (there is none to
// cite); each CVE shows its severity instead.
func TestChannelDiff_TriageDegradedCompactEvidence(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-1"},
	}}
	rules := triageRules(nil)
	rules.Intel = analyze.IntelStatus{}
	r := analyze.Build([]scanner.ImageScan{scan}, nil, rules, genTime)
	d, _ := state.Compute(state.State{}, r)

	out := renderDiff(r, d, false, false)
	want := "*◆ openssl*\nInstalled: 1.0 · Fixed in: 1.1 (🟢 distro security patch)\nFindings: CRITICAL 0 / HIGH 1\nCVEs: <https://nvd.nist.gov/vuln/detail/CVE-1|CVE-1> (HIGH)"
	if !strings.Contains(out, want) {
		t.Errorf("expected id and severity under degraded intel:\n%s\nin:\n%s", want, out)
	}
}

// nginxFinding is one HIGH finding of a fixed nginx package.
func nginxFinding(id string) scanner.Finding {
	return scanner.Finding{Image: "nginx:1.30-alpine", Class: scanner.ClassOS, Package: "nginx", InstalledVer: "1.30.6-r1", FixedVer: "1.30.7-r0", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: id}
}

func nvdLink(id string) string { return "<https://nvd.nist.gov/vuln/detail/" + id + "|" + id + ">" }

// A newly detected package that is not act now names every one of its CVEs on
// one line, strongest first, so a CVE can be found by its number on the day
// it is detected. No CVE is set apart from the others, and one without a
// score is named without "EPSS n/a".
func TestChannelDiff_NewPackageListsItsCVEs(t *testing.T) {
	ids := []string{"CVE-2026-113425", "CVE-2026-121810", "CVE-2026-123007", "CVE-2026-123633", "CVE-2026-123634"}
	var findings []scanner.Finding
	for _, id := range ids {
		findings = append(findings, nginxFinding(id))
	}
	scan := scanner.ImageScan{Image: "nginx:1.30-alpine", Findings: findings}

	t.Run("no scores", func(t *testing.T) {
		r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(nil), genTime)
		d, _ := state.Compute(state.State{}, r)
		out := renderDiff(r, d, false, false)
		var links []string
		for _, id := range ids {
			links = append(links, nvdLink(id))
		}
		want := "Findings: CRITICAL 0 / HIGH 5\nCVEs: " + strings.Join(links, ", ") + "\n"
		if !strings.Contains(out+"\n", want) {
			t.Errorf("want the line\n%s\nin:\n%s", want, out)
		}
		for _, not := range []string{"Top CVE", "Other CVEs", "EPSS n/a", "more CVE"} {
			if strings.Contains(out, not) {
				t.Errorf("%q must not appear:\n%s", not, out)
			}
		}
	})

	t.Run("scores put the strongest first", func(t *testing.T) {
		// 123633 has the higher EPSS of the two scored ones; neither reaches
		// the watch threshold, so the package stays low.
		r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(map[string]analyze.Enrichment{
			"CVE-2026-123007": {EPSS: 0.002, EPSSKnown: true},
			"CVE-2026-123633": {EPSS: 0.004, EPSSKnown: true},
		}), genTime)
		d, _ := state.Compute(state.State{}, r)
		out := renderDiff(r, d, false, false)
		want := "CVEs: " + nvdLink("CVE-2026-123633") + " (EPSS 0.4%), " + nvdLink("CVE-2026-123007") + " (EPSS 0.2%), " +
			nvdLink("CVE-2026-113425") + ", " + nvdLink("CVE-2026-121810") + ", " + nvdLink("CVE-2026-123634")
		if !strings.Contains(out, want) {
			t.Errorf("want the line\n%s\nin:\n%s", want, out)
		}
	})

	t.Run("japanese label", func(t *testing.T) {
		r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(nil), genTime)
		d, _ := state.Compute(state.State{}, r)
		out := renderDiff(r, d, false, false, LanguageJA)
		if !strings.Contains(out, "\nCVE: "+nvdLink("CVE-2026-113425")+", ") || strings.Contains(out, "代表CVE") {
			t.Errorf("want a CVE: line and no 代表CVE line:\n%s", out)
		}
	})
}

// The order of the line puts priority before EPSS. A CRITICAL CVE without a score is watch, a HIGH
// one with a score under the watch threshold is low, so the unscored one
// leads although only the other has an EPSS.
func TestChannelDiff_CVEListOrdersByPriorityBeforeEPSS(t *testing.T) {
	crit := nginxFinding("CVE-2026-20002")
	crit.Severity = scanner.SeverityCritical
	scan := scanner.ImageScan{Image: "nginx:1.30-alpine", Findings: []scanner.Finding{nginxFinding("CVE-2026-20001"), crit}}
	r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(map[string]analyze.Enrichment{
		"CVE-2026-20001": {EPSS: 0.004, EPSSKnown: true},
	}), genTime)
	d, _ := state.Compute(state.State{}, r)
	out := renderDiff(r, d, false, false)
	want := "Findings: CRITICAL 1 / HIGH 1\nCVEs: " + nvdLink("CVE-2026-20002") + ", " + nvdLink("CVE-2026-20001") + " (EPSS 0.4%)"
	if !strings.Contains(out, want) {
		t.Errorf("want the line\n%s\nin:\n%s", want, out)
	}
}

// The line itself, for each kind of entry: a score, none, and the severity
// that stands in when the triage intel cannot be used.
func TestCVELine(t *testing.T) {
	en := renderer{msg: messagesFor(LanguageEN)}
	ja := renderer{msg: messagesFor(LanguageJA)}
	scored := cardCVE{ID: "CVE-2026-1", Severity: "HIGH", EPSS: "3%", EPSSKnown: true, Intel: true}
	unscored := cardCVE{ID: "CVE-2026-2", Severity: "HIGH", EPSS: "n/a", Intel: true}
	// In CISA KEV: such a package is act now and never has this line, and
	// the line does not depend on that.
	kev := cardCVE{ID: "CVE-2026-3", Severity: "CRITICAL", EPSS: "83%", EPSSKnown: true, KEV: true, Intel: true}
	noIntel := cardCVE{ID: "CVE-2026-4", Severity: "CRITICAL", EPSS: "n/a", IntelDegraded: true}
	other := cardCVE{ID: "GHSA-aaaa-bbbb-cccc", Severity: "HIGH", EPSS: "n/a", Intel: true}

	cases := []struct {
		name string
		rd   renderer
		card pkgCard
		want string
	}{
		{"scores and none", en, pkgCard{CVEs: []cardCVE{kev, scored, unscored, other}},
			"CVEs: " + nvdLink("CVE-2026-3") + " (EPSS 83%), " + nvdLink("CVE-2026-1") + " (EPSS 3%), " + nvdLink("CVE-2026-2") + ", GHSA-aaaa-bbbb-cccc"},
		{"severity without intel", en, pkgCard{CVEs: []cardCVE{noIntel}},
			"CVEs: " + nvdLink("CVE-2026-4") + " (CRITICAL)"},
		{"overflow", en, pkgCard{CVEs: []cardCVE{unscored}, CVEExtra: 5},
			"CVEs: " + nvdLink("CVE-2026-2") + " (+5 more)"},
		{"japanese", ja, pkgCard{CVEs: []cardCVE{scored, unscored}, CVEExtra: 2},
			"CVE: " + nvdLink("CVE-2026-1") + " (EPSS 3%), " + nvdLink("CVE-2026-2") + " (ほか +2件)"},
		{"nothing to list", en, pkgCard{}, ""},
	}
	for _, tc := range cases {
		if got := tc.rd.cveLine(tc.card); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// Past cveListMax the rest of a package's CVEs are a count.
func TestChannelDiff_NewPackageCVEListOverflows(t *testing.T) {
	var findings []scanner.Finding
	const total = cveListMax + 5
	for i := 1; i <= total; i++ {
		findings = append(findings, nginxFinding(fmt.Sprintf("CVE-2026-%05d", 10000+i)))
	}
	r := analyze.Build([]scanner.ImageScan{{Image: "nginx:1.30-alpine", Findings: findings}}, nil, triageRules(nil), genTime)
	d, _ := state.Compute(state.State{}, r)
	out := renderDiff(r, d, false, false)
	var links []string
	for i := 1; i <= cveListMax; i++ {
		links = append(links, nvdLink(fmt.Sprintf("CVE-2026-%05d", 10000+i)))
	}
	want := fmt.Sprintf("Findings: CRITICAL 0 / HIGH %d\nCVEs: ", total) + strings.Join(links, ", ") + " (+5 more)"
	if !strings.Contains(out, want) {
		t.Errorf("want the line\n%s\nin:\n%s", want, out)
	}
	if strings.Contains(out, fmt.Sprintf("CVE-2026-%05d", 10000+cveListMax+1)) {
		t.Errorf("an id past the limit is named:\n%s", out)
	}
}

// Without an advisory from the scanner, vulnerability ids in Slack output
// link to their NVD record; ids from other schemes (GHSA-, DLA-, ...) have no
// NVD page and stay plain (escaped) text.
func TestCardIDLink(t *testing.T) {
	if got, want := cardIDLink("CVE-2026-1234"), "<https://nvd.nist.gov/vuln/detail/CVE-2026-1234|CVE-2026-1234>"; got != want {
		t.Errorf("cardIDLink(CVE) = %q, want %q", got, want)
	}
	if got := cardIDLink("GHSA-xxxx-yyyy-zzzz"); got != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("non-CVE id must stay plain, got %q", got)
	}
}

// An id links to the scanner's advisory for it, whatever its scheme; a URL
// that cannot be a link target is not used.
func TestCVELink(t *testing.T) {
	cases := []struct{ id, advisory, want string }{
		{"CVE-2026-1", "https://avd.aquasec.com/nvd/cve-2026-1", "<https://avd.aquasec.com/nvd/cve-2026-1|CVE-2026-1>"},
		{"GHSA-aaaa-bbbb-cccc", "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "<https://github.com/advisories/GHSA-aaaa-bbbb-cccc|GHSA-aaaa-bbbb-cccc>"},
		{"CVE-2026-1", "", nvdLink("CVE-2026-1")},
		{"CVE-2026-1", "javascript:alert(1)", nvdLink("CVE-2026-1")},
		{"CVE-2026-1", "https://example.com/a|b", nvdLink("CVE-2026-1")},
		{"GHSA-aaaa-bbbb-cccc", "", "GHSA-aaaa-bbbb-cccc"},
		{"GHSA-<x>", "https://example.com/x", "<https://example.com/x|GHSA-&lt;x&gt;>"},
	}
	for _, tc := range cases {
		if got := cveLink(tc.id, tc.advisory); got != tc.want {
			t.Errorf("cveLink(%q, %q) = %q, want %q", tc.id, tc.advisory, got, tc.want)
		}
	}
}

// The lines of a detail card, for each kind of entry: the facts the intel
// gives, the severity alone without it, and the count past the limit.
func TestCVELines(t *testing.T) {
	en := renderer{msg: messagesFor(LanguageEN)}
	ja := renderer{msg: messagesFor(LanguageJA)}
	kev := cardCVE{ID: "CVE-2026-3", Severity: "CRITICAL", EPSS: "83%", EPSSKnown: true, KEV: true, Ransomware: true, Intel: true,
		URL: "https://avd.example/CVE-2026-3", Title: "pkg: <title> & more",
		Refs: []cardRef{{Kind: "vendor", Label: "vendor advisory", URL: "https://vendor.example/a"}}}
	unscored := cardCVE{ID: "CVE-2026-2", Severity: "HIGH", EPSS: "n/a", Intel: true}
	degraded := cardCVE{ID: "CVE-2026-4", Severity: "CRITICAL", EPSS: "n/a", KEV: true, IntelDegraded: true, Title: "pkg: title"}
	triageOff := cardCVE{ID: "CVE-2026-5", Severity: "HIGH", EPSS: "n/a", Title: "pkg: title"}

	cases := []struct {
		name string
		rd   renderer
		card pkgCard
		want []string
	}{
		{"facts, title and vendor advisory", en, pkgCard{CVEs: []cardCVE{kev, unscored}}, []string{
			"CVEs:",
			"• <https://avd.example/CVE-2026-3|CVE-2026-3> · CRITICAL · EPSS 83% · CISA KEV (exploited in the wild) · 🧨 ransomware campaign · pkg: &lt;title&gt; &amp; more · <https://vendor.example/a|vendor advisory>",
			"• " + nvdLink("CVE-2026-2") + " · HIGH · EPSS n/a",
		}},
		{"intel unusable", en, pkgCard{CVEs: []cardCVE{degraded}}, []string{
			"CVEs: severity only (intel unavailable)",
			"• " + nvdLink("CVE-2026-4") + " · CRITICAL · pkg: title",
		}},
		{"triage off", en, pkgCard{CVEs: []cardCVE{triageOff}}, []string{
			"CVEs:",
			"• " + nvdLink("CVE-2026-5") + " · HIGH · pkg: title",
		}},
		{"overflow", en, pkgCard{CVEs: []cardCVE{unscored}, CVEExtra: 5}, []string{
			"CVEs:",
			"• " + nvdLink("CVE-2026-2") + " · HIGH · EPSS n/a",
			"• +5 more",
		}},
		{"japanese", ja, pkgCard{CVEs: []cardCVE{kev}, CVEExtra: 2}, []string{
			"CVE:",
			"• <https://avd.example/CVE-2026-3|CVE-2026-3> · CRITICAL · EPSS 83% · CISA KEV (実際の攻撃で悪用あり) · 🧨 ランサムウェア攻撃 · pkg: &lt;title&gt; &amp; more · <https://vendor.example/a|ベンダーのアドバイザリ>",
			"• ほか +2件",
		}},
		// A summary cannot start a line of its own or format the text
		// around it.
		{"summary with a newline and formatting", en, pkgCard{CVEs: []cardCVE{{ID: "CVE-2026-6", Severity: "HIGH", Title: "pkg: flaw\n*◆ fake*\r\nFixed in: `none`"}}}, []string{
			"CVEs:",
			"• " + nvdLink("CVE-2026-6") + " · HIGH · `pkg: flaw *◆ fake*  Fixed in: 'none'`",
		}},
		{"nothing to list", en, pkgCard{}, nil},
	}
	for _, tc := range cases {
		if got := tc.rd.cveLines(tc.card); !slices.Equal(got, tc.want) {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// A card that only points at Act now names no CVE, and every other card of a
// package names all of them, up to the limit, whichever view it is in.
func TestCardsListCVEsUpToTheLimit(t *testing.T) {
	// 23 CVEs and one finding without an id, which takes none of the 20
	// places and is not counted among the rest.
	findings := []scanner.Finding{nginxFinding("")}
	for i := 1; i <= 23; i++ {
		findings = append(findings, nginxFinding(fmt.Sprintf("CVE-2026-%05d", 30000+i)))
	}
	r := analyze.Build([]scanner.ImageScan{{Image: "nginx:1.30-alpine", Findings: findings}}, nil,
		triageRules(map[string]analyze.Enrichment{"CVE-2026-30001": {KEV: true}}), genTime)
	last, past := "CVE-2026-30020", "CVE-2026-30021"
	for name, out := range map[string]string{"channel": renderFull(r), "thread": renderThread(r, Ages{})} {
		if !strings.Contains(out, "CVEs:\n• "+nvdLink("CVE-2026-30001")+" · HIGH · EPSS n/a · CISA KEV (exploited in the wild)\n") {
			t.Errorf("%s: the KEV CVE must lead the lines:\n%s", name, out)
		}
		if !strings.Contains(out, "• "+nvdLink(last)+" · HIGH · EPSS n/a\n• +3 more") {
			t.Errorf("%s: the lines must end at the limit with a count:\n%s", name, out)
		}
		if strings.Contains(out, past) {
			t.Errorf("%s: an id past the limit is named:\n%s", name, out)
		}
	}
}

// The webhook "reason" is consumed outside Slack, so the CVE id must appear
// without mrkdwn link markup.
func TestBuildWebhookPayload_EscalationReasonIsPlain(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-1"},
	}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(nil), genTime))
	r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(map[string]analyze.Enrichment{"CVE-1": {KEV: true}}), genTime.AddDate(0, 0, 1))
	d, _ := state.Compute(st, r)

	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"reason":"CVE-1 HIGH · CISA KEV (exploited in the wild) · EPSS n/a"`) {
		t.Errorf("escalation reason must carry the plain CVE id:\n%s", data)
	}
	if strings.Contains(string(data), "nvd.nist.gov") {
		t.Errorf("webhook payload must not carry Slack link markup:\n%s", data)
	}
}

func TestChannelDiff_TriageHeartbeatAgesUrgentOnly(t *testing.T) {
	lowScan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-L"},
	}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{lowScan}, nil, triageRules(nil), genTime))
	// 30 days later, still open, still low: no red aging in the heartbeat.
	r := analyze.Build([]scanner.ImageScan{lowScan}, nil, triageRules(nil), genTime.AddDate(0, 0, 30))
	d, _ := state.Compute(st, r)

	out := renderDiff(r, d, false, false)
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
func TestChannelDiff_TriageHeartbeatAgeWording(t *testing.T) {
	watchScan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		{Image: "web:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-W"},
	}}
	enrich := map[string]analyze.Enrichment{"CVE-W": {EPSS: 0.03, EPSSKnown: true}}
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{watchScan}, nil, triageRules(enrich), genTime))
	// 20 days later, still open, still watch: aged past staleDays, red.
	r := analyze.Build([]scanner.ImageScan{watchScan}, nil, triageRules(enrich), genTime.AddDate(0, 0, 20))
	d, _ := state.Compute(st, r)

	out := renderDiff(r, d, false, false)
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

// The id links to the scanner's advisory, and the vendor advisory from the
// KEV notes ends the line of the CVE it belongs to.
func TestChannel_TriageCVELinks(t *testing.T) {
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
	out := renderFull(analyze.Build(scans, nil, rules, genTime))

	want := "• <https://avd.aquasec.com/nvd/cve-kev|CVE-KEV> · HIGH · EPSS n/a · CISA KEV (exploited in the wild) · <https://vendor.test/advisory|vendor advisory>"
	if !slices.Contains(strings.Split(out, "\n"), want) {
		t.Errorf("expected the CVE line with Slack link syntax:\n%s", out)
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
