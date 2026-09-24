package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// Tests for end-of-life package rendering.

const (
	eolContentApp    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	eolContentLegacy = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	eolContentOld    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
)

func eolF(image, pkg, ver string, status scanner.Status, sev scanner.Severity, id string) scanner.Finding {
	fixed := ""
	if status == scanner.StatusFixed {
		fixed = ver + "+fix"
	}
	return scanner.Finding{Image: image, Class: scanner.ClassOS, Package: pkg, InstalledVer: ver, FixedVer: fixed, Status: status, Severity: sev, VulnID: id, URL: "https://avd.example/" + id}
}

// eolTodayScans: app:2.1 has end-of-life packages of every priority, a
// package mixing ordinary and end-of-life CVEs (curl), and one that left
// end-of-life (sqlite); legacy:1's base OS is end-of-life, with an act_now
// and a low end-of-life package; old:3's base OS became end-of-life today.
func eolTodayScans() []scanner.ImageScan {
	const app, legacy, old = "app:2.1", "legacy:1", "old:3"
	return []scanner.ImageScan{
		pinned(scanner.ImageScan{Image: app, Findings: []scanner.Finding{
			eolF(app, "libwebkit2gtk", "2.38.5-1", scanner.StatusEndOfLife, scanner.SeverityCritical, "CVE-2033-0001"),
			eolF(app, "qt5-qtbase", "5.15.3-1", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0002"),
			eolF(app, "libxml2", "2.9.7-16", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0003"),
			eolF(app, "curl", "7.61.1-34", scanner.StatusAffected, scanner.SeverityHigh, "CVE-2033-0011"),
			eolF(app, "curl", "7.61.1-34", scanner.StatusFixDeferred, scanner.SeverityHigh, "CVE-2033-0012"),
			eolF(app, "curl", "7.61.1-34", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0004"),
			eolF(app, "sqlite-libs", "3.26.0-19", scanner.StatusAffected, scanner.SeverityHigh, "CVE-2033-0008"),
		}}, eolContentApp),
		pinned(scanner.ImageScan{Image: legacy, OSEOSL: true, Findings: []scanner.Finding{
			eolF(legacy, "zlib", "1.2.11", scanner.StatusEndOfLife, scanner.SeverityCritical, "CVE-2033-0005"),
			eolF(legacy, "zlib", "1.2.11", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0007"),
			eolF(legacy, "bzip2", "1.0.6", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0006"),
		}}, eolContentLegacy),
		pinned(scanner.ImageScan{Image: old, OSEOSL: true, Findings: []scanner.Finding{
			eolF(old, "perl", "5.26.3", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0009"),
		}}, eolContentOld),
	}
}

// eolPrevScans is twenty days earlier: libwebkit2gtk and libxml2 were
// already end-of-life (libxml2 not yet in KEV), curl had only its affected
// CVE, sqlite-libs was end-of-life, tar had ordinary and end-of-life CVEs
// and old-eol was end-of-life (both gone today); legacy:1 had only zlib's
// first CVE, and old:3 was a supported, clean image.
func eolPrevScans() []scanner.ImageScan {
	const app, legacy, old = "app:2.1", "legacy:1", "old:3"
	return []scanner.ImageScan{
		pinned(scanner.ImageScan{Image: app, Findings: []scanner.Finding{
			eolF(app, "libwebkit2gtk", "2.38.5-1", scanner.StatusEndOfLife, scanner.SeverityCritical, "CVE-2033-0001"),
			eolF(app, "libxml2", "2.9.7-16", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0003"),
			eolF(app, "curl", "7.61.1-34", scanner.StatusAffected, scanner.SeverityHigh, "CVE-2033-0011"),
			eolF(app, "sqlite-libs", "3.26.0-19", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0008"),
			eolF(app, "tar", "1.30", scanner.StatusFixed, scanner.SeverityHigh, "CVE-2033-0013"),
			eolF(app, "tar", "1.30", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0014"),
			eolF(app, "old-eol", "0.1", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-2033-0015"),
		}}, eolContentApp),
		pinned(scanner.ImageScan{Image: legacy, OSEOSL: true, Findings: []scanner.Finding{
			eolF(legacy, "zlib", "1.2.11", scanner.StatusEndOfLife, scanner.SeverityCritical, "CVE-2033-0005"),
		}}, eolContentLegacy),
		pinned(scanner.ImageScan{Image: old}, eolContentOld),
	}
}

func eolTodayEnrich() map[string]analyze.Enrichment {
	return map[string]analyze.Enrichment{
		"CVE-2033-0001": {EPSS: 0.004, EPSSKnown: true},
		"CVE-2033-0002": {EPSS: 0.0001, EPSSKnown: true},
		"CVE-2033-0003": {KEV: true, EPSS: 0.12, EPSSKnown: true},
		"CVE-2033-0004": {EPSS: 0.0002, EPSSKnown: true},
		"CVE-2033-0005": {KEV: true, EPSS: 0.3, EPSSKnown: true},
		"CVE-2033-0006": {EPSS: 0.0003, EPSSKnown: true},
		"CVE-2033-0007": {EPSS: 0.0005, EPSSKnown: true},
		"CVE-2033-0009": {EPSS: 0.0006, EPSSKnown: true},
		"CVE-2033-0011": {EPSS: 0.02, EPSSKnown: true},
	}
}

func eolPrevEnrich() map[string]analyze.Enrichment {
	e := eolTodayEnrich()
	e["CVE-2033-0003"] = analyze.Enrichment{EPSS: 0.0004, EPSSKnown: true}
	return e
}

// eolCycle mirrors goldenCycle for the end-of-life fixture.
func eolCycle(m goldenMode) (r analyze.Report, changed, unchanged state.Diff, next state.State) {
	prev := analyze.Build(eolPrevScans(), nil, m.triage(eolPrevEnrich()), goldenPrevTime)
	_, prevState := state.Compute(state.State{}, prev)
	r = analyze.Build(eolTodayScans(), nil, m.triage(eolTodayEnrich()), genTime)
	changed, next = state.Compute(prevState, r)
	unchanged, _ = state.Compute(next, r)
	return r, changed, unchanged, next
}

func goldenWebhookFull(t *testing.T, r analyze.Report, d *state.Diff) string {
	t.Helper()
	data, err := json.MarshalIndent(BuildWebhookPayload(r, d), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data) + "\n"
}

// TestGolden_EOLOutputs pins the complete text of every rendering of the
// end-of-life fixture in each triage mode.
func TestGolden_EOLOutputs(t *testing.T) {
	for _, m := range goldenModes() {
		t.Run(m.name, func(t *testing.T) {
			r, changed, unchanged, next := eolCycle(m)
			p := "eolpkg_" + m.name + "_"
			checkGolden(t, p+"slack_full", FormatSlackText(r))
			checkGolden(t, p+"slack_diff_changes", FormatSlackDiffText(r, changed, false, false))
			checkGolden(t, p+"slack_diff_nochanges", FormatSlackDiffText(r, unchanged, false, false))
			checkGolden(t, p+"slack_diff_weekly_nochanges", FormatSlackDiffText(r, unchanged, true, false))
			checkGolden(t, p+"thread", goldenThread(r, next, 0))
			checkGolden(t, p+"thread_split", goldenThread(r, next, 650))
			checkGolden(t, p+"webhook_diff", goldenWebhookFull(t, r, &changed))
		})
	}
}

func mustContainAll(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n---\n%s", s, out)
		}
	}
}

// An act_now end-of-life group appears in both the end-of-life section (as a
// pointer) and Act now (in full, with the end-of-life mark); a folded one
// appears in Act now only, and the base-OS line counts it.
func TestFormatSlackText_EOLActNowInBothSections(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[0])
	out := FormatSlackText(r)
	mustContainAll(t, out,
		"*Priority:* ⛔ 2 EOL base · ⛔ 4 EOL package · 🚨 2 act now",
		"• legacy:1 — base OS is EOL (no more security updates coming) · includes 2 end-of-life package(s)",
		"*⛔ Package end-of-life (4) — vendor reports these CVEs as out of support for this release*",
		"   • libxml2 2.9.7-16 (end-of-life: no fix planned for this release) (CRITICAL 0 / HIGH 1) — 🚨 see Act now",
		"   • qt5-qtbase 5.15.3-1 (end-of-life: no fix planned for this release) (CRITICAL 0 / HIGH 1) — <https://nvd.nist.gov/vuln/detail/CVE-2033-0002|CVE-2033-0002> · EPSS <0.1%",
		"*🚨 Act now (2) — exploited or likely to be*",
		"• legacy:1\n   • zlib 1.2.11 (end-of-life: no fix planned for this release) (CRITICAL 1 / HIGH 1)\n     ↳ <https://nvd.nist.gov/vuln/detail/CVE-2033-0005|CVE-2033-0005> CRITICAL · CISA KEV (exploited in the wild) · EPSS 30% (+1 more CVE(s) in this package) — end-of-life: no fix planned for this release, consider a supported version",
	)
	eolSec := strings.Index(out, "*⛔ Package end-of-life")
	actNow := strings.Index(out, "*🚨 Act now")
	eosl := strings.Index(out, "*⛔ Base OS end-of-life")
	if !(eosl < eolSec && eolSec < actNow) {
		t.Errorf("order must be EOL base, package EOL, Act now: %d %d %d", eosl, eolSec, actNow)
	}
	if strings.Contains(out[eolSec:actNow], "zlib") || strings.Contains(out[eolSec:actNow], "bzip2") {
		t.Errorf("packages of an end-of-life base OS must be folded out of the package section:\n%s", out[eolSec:actNow])
	}
}

// Triage off: the end-of-life section and the headline segment still
// appear, laid out like the status sections, before Actionable.
func TestFormatSlackText_EOLWithoutTriage(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[1])
	out := FormatSlackText(r)
	mustContainAll(t, out,
		"*Priority:* ⛔ 2 EOL base · ⛔ 4 EOL package · 🔴 2 CRITICAL",
		"*⛔ Package end-of-life (4) — vendor reports these CVEs as out of support for this release*\n🔴 app:2.1  CRITICAL 1 / HIGH 3\n",
	)
	if strings.Contains(out, "see Act now") {
		t.Errorf("triage off has no Act now section to point at:\n%s", out)
	}
	if strings.Index(out, "*⛔ Package end-of-life") > strings.Index(out, "*ℹ️ No fix yet") {
		t.Errorf("the end-of-life section must precede the status sections:\n%s", out)
	}
}

// The diff: end-of-life changes get their own section after the new base-OS
// block; 🆕 carries only ordinary changes; act_now rows carry their evidence
// and the end-of-life mark but never "see Act now"; a folded image's
// non-act_now changes collapse into one line; a base OS that became
// end-of-life notes its newly end-of-life packages.
func TestFormatSlackDiffText_EOLChanges(t *testing.T) {
	r, changed, _, _ := eolCycle(goldenModes()[0])
	out := FormatSlackDiffText(r, changed, false, false)
	mustContainAll(t, out,
		"• old:3 — base OS is EOL (no more security updates coming) · includes 1 newly end-of-life package(s)",
		"*⛔ New: package end-of-life (5) — vendor reports these CVEs as out of support for this release*",
		"   • libxml2 2.9.7-16 (end-of-life: no fix planned for this release) (CRITICAL 0 / HIGH 1) — ⬆️ escalated to ACT NOW\n     ↳ <https://nvd.nist.gov/vuln/detail/CVE-2033-0003|CVE-2033-0003> HIGH · CISA KEV (exploited in the wild) · EPSS 12% — end-of-life: no fix planned for this release, consider a supported version",
		"   • zlib 1.2.11 (end-of-life: no fix planned for this release) (CRITICAL 1 / HIGH 1) — new: <https://nvd.nist.gov/vuln/detail/CVE-2033-0007|CVE-2033-0007>\n     ↳ <https://nvd.nist.gov/vuln/detail/CVE-2033-0005|CVE-2033-0005> CRITICAL",
		"• legacy:1 — 1 package(s) newly end-of-life (base OS already EOL)",
		"*🆕 New since last scan (1)*",
		"   • curl 7.61.1-34 (no fix available) (CRITICAL 0 / HIGH 2) — new: <https://nvd.nist.gov/vuln/detail/CVE-2033-0012|CVE-2033-0012>",
		"• app:2.1: old-eol, tar",
		"• app:2.1: sqlite-libs — no longer end-of-life",
		"*✅ Resolved since last scan (3)*",
		"📌 Open now: ⛔ 2 EOL base / ⛔ 4 EOL package / 🚨 2 act-now / 👀 1 watch",
	)
	if strings.Contains(out, "see Act now") {
		t.Errorf("the diff has no Act now section to point at:\n%s", out)
	}
	newEOL := strings.Index(out, "*⛔ New: package end-of-life")
	newEOSL := strings.Index(out, "*⛔ New: base OS end-of-life")
	fresh := strings.Index(out, "*🆕 New since last scan")
	if !(newEOSL < newEOL && newEOL < fresh) {
		t.Errorf("order must be new base OS, new package EOL, 🆕: %d %d %d", newEOSL, newEOL, fresh)
	}
	if strings.Contains(out[fresh:], "libxml2") || strings.Contains(out[fresh:], "zlib") {
		t.Errorf("end-of-life changes must not be repeated in 🆕:\n%s", out[fresh:])
	}
}

// The three fold-line wordings for an image whose base OS was already
// end-of-life, and the new-base-OS note.
func TestWriteEOLChanges_FoldWordings(t *testing.T) {
	group := analyze.PackageGroup{Package: "p", Status: scanner.StatusEndOfLife, High: 1, Priority: analyze.PriorityLow}
	change := func(image, pkg string, kind state.EOLChangeKind) state.EOLChange {
		g := group
		g.Package = pkg
		return state.EOLChange{Image: image, Package: pkg, Kind: kind, Groups: []analyze.PackageGroup{g}}
	}
	d := state.Diff{
		OpenEOSL: []string{"a:1", "b:1", "c:1", "d:1"},
		NewEOSL:  []string{"d:1"},
		NewEOLPackages: []state.EOLChange{
			change("a:1", "x", state.EOLKindNew),
			change("a:1", "y", state.EOLKindNew),
			change("b:1", "x", state.EOLKindNewCVEs),
			change("c:1", "x", state.EOLKindNew),
			change("c:1", "y", state.EOLKindNewCVEs),
			change("d:1", "x", state.EOLKindNew),
			change("d:1", "y", state.EOLKindNewCVEs),
		},
	}
	r := analyze.Report{Triage: true, Intel: analyze.IntelStatus{KEVOK: true, EPSSOK: true}}
	var b strings.Builder
	v := splitEOLChanges(d)
	writeEOLChanges(&b, r, v, nil)
	out := b.String()
	mustContainAll(t, out,
		"*⛔ New: package end-of-life (6) —", // d:1's newly end-of-life package is noted on its new base-OS line instead
		"• a:1 — 2 package(s) newly end-of-life (base OS already EOL)\n",
		"• b:1 — 1 end-of-life package(s) with new CVEs (base OS already EOL)\n",
		"• c:1 — 1 package(s) newly end-of-life, 1 end-of-life package(s) with new CVEs (base OS already EOL)\n",
		"• d:1 — 1 end-of-life package(s) with new CVEs (base OS already EOL)\n",
	)
	if v.newEOSLNote["d:1"] != 1 {
		t.Errorf("new base-OS note = %v, want d:1 → 1", v.newEOSLNote)
	}
}

// An act_now end-of-life package gaining a CVE in the diff: evidence line
// with the end-of-life mark, no pointer to Act now.
func TestFormatSlackDiffText_EOLActNowNewCVEs(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-K": {KEV: true}}
	scan1 := pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
		eolF("app:1", "qt", "5.15", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-K"),
	}}, eolContentApp)
	scan2 := scan1
	scan2.Findings = append(append([]scanner.Finding(nil), scan1.Findings...), eolF("app:1", "qt", "5.15", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-L"))
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{scan1}, nil, triageRules(enrich), goldenPrevTime))
	r := analyze.Build([]scanner.ImageScan{scan2}, nil, triageRules(enrich), genTime)
	d, _ := state.Compute(st, r)
	out := FormatSlackDiffText(r, d, false, false)
	want := "*⛔ New: package end-of-life (1) — vendor reports these CVEs as out of support for this release*\n" +
		"🚨 app:1\n" +
		"   • qt 5.15 (end-of-life: no fix planned for this release) (CRITICAL 0 / HIGH 2) — new: <https://nvd.nist.gov/vuln/detail/CVE-L|CVE-L>\n" +
		"     ↳ <https://nvd.nist.gov/vuln/detail/CVE-K|CVE-K> HIGH · CISA KEV (exploited in the wild) · EPSS n/a (+1 more CVE(s) in this package) — end-of-life: no fix planned for this release, consider a supported version\n"
	mustContainAll(t, out, want)
	if strings.Contains(out, "see Act now") || strings.Contains(out, "🆕") {
		t.Errorf("unexpected pointer or 🆕 section:\n%s", out)
	}
}

// A package with an end-of-life group and an ordinary group that gets a
// fix: now_fixable stays in 🆕, the end-of-life side is quiet.
func TestFormatSlackDiffText_MixedPackageNowFixable(t *testing.T) {
	for _, m := range goldenModes()[:2] {
		scan := func(status scanner.Status) scanner.ImageScan {
			return pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
				eolF("app:1", "qt", "5.15", status, scanner.SeverityHigh, "CVE-A"),
				eolF("app:1", "qt", "5.15", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-B"),
			}}, eolContentApp)
		}
		_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{scan(scanner.StatusAffected)}, nil, m.triage(nil), goldenPrevTime))
		r := analyze.Build([]scanner.ImageScan{scan(scanner.StatusFixed)}, nil, m.triage(nil), genTime)
		d, _ := state.Compute(st, r)
		out := FormatSlackDiffText(r, d, false, false)
		mustContainAll(t, out, "*🆕 New since last scan (1)*", "qt 5.15 → 5.15+fix", "fix now available")
		if strings.Contains(out, "New: package end-of-life") {
			t.Errorf("%s: no end-of-life change expected:\n%s", m.name, out)
		}
	}
}

// The heartbeat counts each package once across priority buckets: an
// ordinary watch or low package whose end-of-life CVE is act_now counts as
// act-now only.
func TestFormatSlackDiffText_OpenNowCountsEachPackageOnce(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-KEV": {KEV: true}, "CVE-W": {EPSS: 0.05, EPSSKnown: true}}
	r := analyze.Build([]scanner.ImageScan{pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
		eolF("app:1", "a", "1", scanner.StatusAffected, scanner.SeverityHigh, "CVE-W"),
		eolF("app:1", "a", "1", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-KEV"),
		eolF("app:1", "b", "1", scanner.StatusAffected, scanner.SeverityHigh, "CVE-LOW"),
		eolF("app:1", "b", "1", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-KEV"),
	}}, eolContentApp)}, nil, triageRules(enrich), genTime)
	d, _ := state.Compute(state.State{}, r)
	out := FormatSlackDiffText(r, d, false, false)
	mustContainAll(t, out, "📌 Open now: ⛔ 2 EOL package / 🚨 2 act-now\n")
}

// "All clear" only when nothing is held: an image with nothing but
// end-of-life packages, then a failed scan of it (held), then a clean scan.
// The same for ordinary findings, and for a failed image next to a clean
// one, in both triage modes.
func TestFormatSlackDiffText_AllClearOnlyWhenNothingHeld(t *testing.T) {
	const holdLine = "📌 Open now: not re-scanned — holding previous findings until the next successful scan\n"
	const clearLine = "🎉 Open now: none — all clear\n"
	for _, m := range goldenModes()[:2] {
		for _, status := range []scanner.Status{scanner.StatusEndOfLife, scanner.StatusFixed} {
			name := fmt.Sprintf("%s/%s", m.name, status)
			withFinding := pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
				eolF("app:1", "qt", "5.15", status, scanner.SeverityHigh, "CVE-A"),
			}}, eolContentApp)
			failed := pinned(scanner.ImageScan{Image: "app:1", Err: errString("pull failed")}, eolContentApp)
			clean := pinned(scanner.ImageScan{Image: "app:1"}, eolContentApp)

			_, st1 := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{withFinding}, nil, m.triage(nil), genTime))
			r2 := analyze.Build([]scanner.ImageScan{failed}, nil, m.triage(nil), genTime.AddDate(0, 0, 1))
			d2, st2 := state.Compute(st1, r2)
			if out := FormatSlackDiffText(r2, d2, false, false); !strings.Contains(out, holdLine) || strings.Contains(out, clearLine) {
				t.Errorf("%s cycle 2 (failed, held):\n%s", name, out)
			}
			r3 := analyze.Build([]scanner.ImageScan{clean}, nil, m.triage(nil), genTime.AddDate(0, 0, 2))
			d3, _ := state.Compute(st2, r3)
			if out := FormatSlackDiffText(r3, d3, false, false); !strings.Contains(out, clearLine) {
				t.Errorf("%s cycle 3 (clean, nothing held):\n%s", name, out)
			}

			// A failed image with history next to a clean image.
			other := pinned(scanner.ImageScan{Image: "web:1"}, goldenContentWeb)
			r4 := analyze.Build([]scanner.ImageScan{failed, other}, nil, m.triage(nil), genTime.AddDate(0, 0, 1))
			d4, _ := state.Compute(st1, r4)
			if out := FormatSlackDiffText(r4, d4, false, false); !strings.Contains(out, holdLine) {
				t.Errorf("%s failed + clean:\n%s", name, out)
			}
		}
	}
}

// The thread: an end-of-life section after the base-OS images, act_now
// groups as pointers there and in full under ACT NOW, end-of-life ages
// taken from the end-of-life lookup, and the section header repeated when a
// small limit splits it.
func TestBuildThreadMessages_EOLSection(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[0])
	ages := Ages{
		Finding: seenDaysAgo(30),
		EOL: func(image, pkg string) (t0 time.Time, ok bool) {
			return genTime.AddDate(0, 0, -5), true
		},
	}
	out := strings.Join(BuildThreadMessages(r, ages, 0), "\n")
	mustContainAll(t, out,
		"*⛔ EOL base images (2)*\n• legacy:1 — base OS is EOL (no more security updates coming) · includes 2 end-of-life package(s)",
		"*⛔ EOL packages (4) — vendor reports these CVEs as out of support for this release*",
		"   • libxml2 2.9.7-16 (end-of-life: no fix planned for this release) (CRITICAL 0 / HIGH 1) — 🚨 see Act now\n",
		"*🚨 ACT NOW (2) — exploited or likely to be*",
		"— end-of-life: no fix planned for this release, consider a supported version",
		"     ⏱ open 5 day(s) — first seen 2026-06-19",
	)
	eolSec := strings.Index(out, "*⛔ EOL packages")
	actNow := strings.Index(out, "*🚨 ACT NOW")
	if !(strings.Index(out, "*⛔ EOL base images") < eolSec && eolSec < actNow) {
		t.Errorf("thread order wrong:\n%s", out)
	}
	// Every package in this fixture that is ordinary (curl, sqlite-libs)
	// is dated by the ordinary lookup.
	if !strings.Contains(out[actNow:], "⏱ open 5 day(s)") {
		t.Errorf("act_now end-of-life groups must use the end-of-life age:\n%s", out[actNow:])
	}

	msgs := BuildThreadMessages(r, ages, 500)
	var cont bool
	for _, m := range msgs {
		if len(m) > 500 {
			t.Errorf("message exceeds limit: %d", len(m))
		}
		if strings.Contains(m, "*⛔ EOL packages (4) — vendor reports these CVEs as out of support for this release* _(cont.)_") {
			cont = true
		}
	}
	if !cont {
		t.Errorf("a split end-of-life section must repeat its header:\n%s", strings.Join(msgs, "\n=====\n"))
	}
}

// A report with nothing but end-of-life packages still posts a thread.
func TestBuildThreadMessages_EOLOnly(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
		eolF("app:1", "qt", "5.15", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-A"),
	}}, eolContentApp)}, nil, analyze.Triage{}, genTime)
	if msgs := BuildThreadMessages(r, Ages{}, 0); len(msgs) != 1 || !strings.Contains(msgs[0], "*⛔ EOL packages (1)") {
		t.Errorf("thread = %q", msgs)
	}
}

// The webhook: eol_packages always present, vulns[].status only where it
// differs from the finding's status, and the two diff arrays.
func TestBuildWebhookPayload_EOL(t *testing.T) {
	r, changed, _, _ := eolCycle(goldenModes()[0])
	data, err := json.Marshal(BuildWebhookPayload(r, &changed))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Summary struct {
			PriorityCounts map[string]int `json:"priority_counts"`
		} `json:"summary"`
		Watch []struct {
			Findings []struct {
				Package string `json:"package"`
				Status  string `json:"status"`
				Vulns   []map[string]any
			} `json:"findings"`
		} `json:"watch"`
		EOLPackages []struct {
			Image    string `json:"image"`
			Findings []struct {
				Package  string `json:"package"`
				Status   string `json:"status"`
				Priority string `json:"priority"`
				Vulns    []map[string]any
			} `json:"findings"`
		} `json:"eol_packages"`
		Diff struct {
			New                 []map[string]any `json:"new"`
			NewEOLPackages      []map[string]any `json:"new_eol_packages"`
			ResolvedEOLPackages []map[string]any `json:"resolved_eol_packages"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.EOLPackages) != 3 {
		t.Errorf("eol_packages = %d entries, want every image incl. folded ones (3)", len(p.EOLPackages))
	}
	for _, img := range p.EOLPackages {
		for _, f := range img.Findings {
			if f.Status != "end_of_life" {
				t.Errorf("%s %s status = %q", img.Image, f.Package, f.Status)
			}
			for _, v := range f.Vulns {
				if _, ok := v["status"]; ok {
					t.Errorf("vulns[].status must be omitted when equal to the finding's: %v", v)
				}
			}
		}
	}
	var sawDeferred bool
	for _, img := range p.Watch {
		for _, f := range img.Findings {
			for _, v := range f.Vulns {
				switch v["id"] {
				case "CVE-2033-0012":
					sawDeferred = v["status"] == "fix_deferred"
				case "CVE-2033-0011":
					if _, ok := v["status"]; ok {
						t.Errorf("affected CVE in watch must not carry status: %v", v)
					}
				}
			}
		}
	}
	if !sawDeferred {
		t.Error("the fix_deferred CVE in watch must carry vulns[].status")
	}
	if got := p.Summary.PriorityCounts["act_now"]; got != 2 {
		t.Errorf("priority_counts.act_now = %d, want 2 (end-of-life act_now groups included)", got)
	}
	kinds := map[string]map[string]any{}
	for _, c := range p.Diff.NewEOLPackages {
		kinds[c["image"].(string)+" "+c["package"].(string)] = c
	}
	if c := kinds["app:2.1 libxml2"]; c["kind"] != "eol_escalated" || c["reason"] == nil || c["new_cve_ids"] != nil {
		t.Errorf("libxml2 change = %v", c)
	}
	if c := kinds["legacy:1 zlib"]; c["kind"] != "eol_new_cves" || fmt.Sprint(c["new_cve_ids"]) != "[CVE-2033-0007]" || c["reason"] != nil {
		t.Errorf("zlib change = %v", c)
	}
	if c := kinds["app:2.1 qt5-qtbase"]; c["kind"] != "eol_new" {
		t.Errorf("qt5-qtbase change = %v", c)
	}
	for _, c := range p.Diff.New {
		switch c["kind"] {
		case "new", "escalated", "new_cves", "now_fixable":
		default:
			t.Errorf("diff.new kind must stay within the four published values: %v", c)
		}
	}
	resolved := map[string]bool{}
	for _, res := range p.Diff.ResolvedEOLPackages {
		resolved[res["package"].(string)] = res["still_open"].(bool)
	}
	if len(resolved) != 3 || !resolved["sqlite-libs"] || resolved["tar"] || resolved["old-eol"] {
		t.Errorf("resolved_eol_packages = %v", p.Diff.ResolvedEOLPackages)
	}
}

// The diff arrays are always present (empty, not absent) in diff mode.
func TestBuildWebhookPayload_EOLArraysAlwaysPresent(t *testing.T) {
	r := sampleReport()
	d := state.Diff{}
	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"eol_packages":[]`, `"new_eol_packages":[]`, `"resolved_eol_packages":[]`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("payload missing %s:\n%s", key, data)
		}
	}
}
