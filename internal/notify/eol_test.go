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

// TestGolden_EOLOutputs pins the webhook payload of the end-of-life fixture in
// each triage mode.
func TestGolden_EOLOutputs(t *testing.T) {
	for _, m := range goldenModes() {
		t.Run(m.name, func(t *testing.T) {
			r, changed, _, _ := eolCycle(m)
			checkGolden(t, "eolpkg_"+m.name+"_webhook_diff", goldenWebhookFull(t, r, &changed))
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
func TestChannel_EOLActNowInBothSections(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[0])
	out := renderFull(r)
	mustContainAll(t, out,
		"*Priority:* ⛔ 2 EOL base · ⛔ 4 EOL package · 🚨 2 act now",
		"*Image: legacy:1*\nStatus: base OS is EOL (no more security updates coming)\nincludes 2 end-of-life package(s)",
		"*⛔ Package end-of-life (4) — vendor reports these CVEs as out of support for this release*",
		"*◆ libxml2*\nInstalled: 2.9.7-16 · Fixed in: none — end-of-life: no fix planned for this release\nFindings: CRITICAL 0 / HIGH 1\nDetails: 🚨 see Act now",
		"*◆ qt5-qtbase*\nInstalled: 5.15.3-1 · Fixed in: none — end-of-life: no fix planned for this release\nFindings: CRITICAL 0 / HIGH 1\nTop CVE: <https://nvd.nist.gov/vuln/detail/CVE-2033-0002|CVE-2033-0002> · EPSS &lt;0.1%",
		"*🚨 Act now (2) — exploited or likely to be*",
		"*◆ zlib*\nInstalled: 1.2.11\nFixed in: none — end-of-life: no fix planned for this release, consider a supported version\nFindings: CRITICAL 1 / HIGH 1",
		"Top CVE: <https://nvd.nist.gov/vuln/detail/CVE-2033-0005|CVE-2033-0005> · CRITICAL · EPSS 30% (+1 more CVE(s) in this package)\nExploitation: CISA KEV (exploited in the wild)",
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
func TestChannel_EOLWithoutTriage(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[1])
	out := renderFull(r)
	mustContainAll(t, out,
		"*Priority:* ⛔ 2 EOL base · ⛔ 4 EOL package · 🔴 2 CRITICAL",
		"*⛔ Package end-of-life (4) — vendor reports these CVEs as out of support for this release*\n*Image: app:2.1*\n🔴 CRITICAL 1 / HIGH 3\n*◆ libwebkit2gtk*",
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
func TestChannel_EOLChanges(t *testing.T) {
	r, changed, _, _ := eolCycle(goldenModes()[0])
	out := renderDiff(r, changed, false, false)
	mustContainAll(t, out,
		"*Image: old:3*\nStatus: base OS is EOL (no more security updates coming)\nincludes 1 newly end-of-life package(s)",
		"*⛔ New: package end-of-life (5) — vendor reports these CVEs as out of support for this release*",
		"*◆ libxml2*\nChange: ⬆️ escalated to ACT NOW\nInstalled: 2.9.7-16\nFixed in: none — end-of-life: no fix planned for this release, consider a supported version\nFindings: CRITICAL 0 / HIGH 1",
		"Top CVE: <https://nvd.nist.gov/vuln/detail/CVE-2033-0003|CVE-2033-0003> · HIGH · EPSS 12%\nExploitation: CISA KEV (exploited in the wild)",
		"*◆ zlib*\nChange: new CVEs: <https://nvd.nist.gov/vuln/detail/CVE-2033-0007|CVE-2033-0007>\nInstalled: 1.2.11",
		"Top CVE: <https://nvd.nist.gov/vuln/detail/CVE-2033-0005|CVE-2033-0005> · CRITICAL",
		"*Image: legacy:1*\n1 package(s) newly end-of-life (base OS already EOL)",
		"*🆕 New since last scan (1)*",
		"*◆ curl*\nChange: new CVEs: <https://nvd.nist.gov/vuln/detail/CVE-2033-0012|CVE-2033-0012>\nInstalled: 7.61.1-34 · Fixed in: none\nFindings: CRITICAL 0 / HIGH 2",
		"• app:2.1: old-eol, tar",
		"• app:2.1: sqlite-libs — no longer end-of-life",
		"*✅ Resolved since last scan (3)*",
		"📌 *Open now:* ⛔ 2 EOL base / ⛔ 4 EOL package / 🚨 2 act-now / 👀 1 watch",
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

// The fold-line wordings for an image whose base OS was already end-of-life,
// and the new-base-OS note.
func TestChannel_EOLFoldWordings(t *testing.T) {
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
	v := &chView{r: r, msg: enMessages, rd: renderer{msg: enMessages, lim: defaultRenderLimits}}
	ev := splitEOLChanges(d)
	v.eolChangesCategory(ev)
	var texts []string
	for _, u := range v.l.units {
		for _, b := range u.blocks {
			texts = append(texts, b.Text)
		}
	}
	out := strings.Join(texts, "\n")
	mustContainAll(t, out,
		"*⛔ New: package end-of-life (6) —", // d:1's newly end-of-life package is noted on its new base-OS line instead
		"*Image: a:1*\n2 package(s) newly end-of-life (base OS already EOL)",
		"*Image: b:1*\n1 end-of-life package(s) with new CVEs (base OS already EOL)",
		"*Image: c:1*\n1 package(s) newly end-of-life, 1 end-of-life package(s) with new CVEs (base OS already EOL)",
		"*Image: d:1*\n1 end-of-life package(s) with new CVEs (base OS already EOL)",
	)
	if ev.newEOSLNote["d:1"] != 1 {
		t.Errorf("new base-OS note = %v, want d:1 → 1", ev.newEOSLNote)
	}
}

// An act_now end-of-life package gaining a CVE in the diff: evidence line
// with the end-of-life mark, no pointer to Act now.
func TestChannel_EOLActNowNewCVEs(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-K": {KEV: true}}
	scan1 := pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
		eolF("app:1", "qt", "5.15", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-K"),
	}}, eolContentApp)
	scan2 := scan1
	scan2.Findings = append(append([]scanner.Finding(nil), scan1.Findings...), eolF("app:1", "qt", "5.15", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-L"))
	_, st := state.Compute(state.State{}, analyze.Build([]scanner.ImageScan{scan1}, nil, triageRules(enrich), goldenPrevTime))
	r := analyze.Build([]scanner.ImageScan{scan2}, nil, triageRules(enrich), genTime)
	d, _ := state.Compute(st, r)
	out := renderDiff(r, d, false, false)
	mustContainAll(t, out,
		"*⛔ New: package end-of-life (1) — vendor reports these CVEs as out of support for this release*\n*Image: app:1*",
		"*◆ qt*\nChange: new CVEs: <https://nvd.nist.gov/vuln/detail/CVE-L|CVE-L>\nInstalled: 5.15\nFixed in: none — end-of-life: no fix planned for this release, consider a supported version\nFindings: CRITICAL 0 / HIGH 2",
		"Top CVE: <https://nvd.nist.gov/vuln/detail/CVE-K|CVE-K> · HIGH · EPSS n/a (+1 more CVE(s) in this package)\nExploitation: CISA KEV (exploited in the wild)",
	)
	if strings.Contains(out, "see Act now") || strings.Contains(out, "🆕") {
		t.Errorf("unexpected pointer or 🆕 section:\n%s", out)
	}
}

// A package with an end-of-life group and an ordinary group that gets a
// fix: now_fixable stays in 🆕, the end-of-life side is quiet.
func TestChannel_MixedPackageNowFixable(t *testing.T) {
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
		out := renderDiff(r, d, false, false)
		mustContainAll(t, out, "*🆕 New since last scan (1)*", "*◆ qt*", "Fixed in: 5.15+fix", "Change: fix now available")
		if strings.Contains(out, "New: package end-of-life") {
			t.Errorf("%s: no end-of-life change expected:\n%s", m.name, out)
		}
	}
}

// The heartbeat counts each package once across priority buckets: an
// ordinary watch or low package whose end-of-life CVE is act_now counts as
// act-now only.
func TestChannel_OpenNowCountsEachPackageOnce(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-KEV": {KEV: true}, "CVE-W": {EPSS: 0.05, EPSSKnown: true}}
	r := analyze.Build([]scanner.ImageScan{pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
		eolF("app:1", "a", "1", scanner.StatusAffected, scanner.SeverityHigh, "CVE-W"),
		eolF("app:1", "a", "1", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-KEV"),
		eolF("app:1", "b", "1", scanner.StatusAffected, scanner.SeverityHigh, "CVE-LOW"),
		eolF("app:1", "b", "1", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-KEV"),
	}}, eolContentApp)}, nil, triageRules(enrich), genTime)
	d, _ := state.Compute(state.State{}, r)
	out := renderDiff(r, d, false, false)
	mustContainAll(t, out, "📌 *Open now:* ⛔ 2 EOL package / 🚨 2 act-now")
}

// "All clear" only when nothing is held: an image with nothing but
// end-of-life packages, then a failed scan of it (held), then a clean scan.
// The same for ordinary findings, and for a failed image next to a clean
// one, in both triage modes.
func TestChannel_AllClearOnlyWhenNothingHeld(t *testing.T) {
	const holdLine = "📌 *Open now:* not re-scanned — holding previous findings until the next successful scan"
	const clearLine = "🎉 *Open now:* none — all clear"
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
			if out := renderDiff(r2, d2, false, false); !strings.Contains(out, holdLine) || strings.Contains(out, clearLine) {
				t.Errorf("%s cycle 2 (failed, held):\n%s", name, out)
			}
			r3 := analyze.Build([]scanner.ImageScan{clean}, nil, m.triage(nil), genTime.AddDate(0, 0, 2))
			d3, _ := state.Compute(st2, r3)
			if out := renderDiff(r3, d3, false, false); !strings.Contains(out, clearLine) {
				t.Errorf("%s cycle 3 (clean, nothing held):\n%s", name, out)
			}

			// A failed image with history next to a clean image.
			other := pinned(scanner.ImageScan{Image: "web:1"}, goldenContentWeb)
			r4 := analyze.Build([]scanner.ImageScan{failed, other}, nil, m.triage(nil), genTime.AddDate(0, 0, 1))
			d4, _ := state.Compute(st1, r4)
			if out := renderDiff(r4, d4, false, false); !strings.Contains(out, holdLine) {
				t.Errorf("%s failed + clean:\n%s", name, out)
			}
		}
	}
}

// The thread: an end-of-life section after the base-OS images, act_now
// groups as pointers there and in full under ACT NOW, end-of-life ages
// taken from the end-of-life lookup, and the section header repeated when a
// small limit splits it.
func TestThread_EOLSection(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[0])
	ages := Ages{
		Finding: seenDaysAgo(30),
		EOL: func(image, pkg string) (t0 time.Time, ok bool) {
			return genTime.AddDate(0, 0, -5), true
		},
	}
	out := renderThread(r, ages)
	mustContainAll(t, out,
		"*⛔ EOL base images (2)*\n*Image: legacy:1*\nStatus: base OS is EOL (no more security updates coming)\nincludes 2 end-of-life package(s)",
		"*⛔ EOL packages (4) — vendor reports these CVEs as out of support for this release*",
		"*◆ libxml2*\nInstalled: 2.9.7-16 · Fixed in: none — end-of-life: no fix planned for this release\nFindings: CRITICAL 0 / HIGH 1\nDetails: 🚨 see Act now",
		"*🚨 ACT NOW (2) — exploited or likely to be*",
		"Fixed in: none — end-of-life: no fix planned for this release, consider a supported version",
		"⏱ open 5 day(s) · first seen 2026-06-19",
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

	msgs := buildThreadBlockMessages(r, ages, enMessages, testSplitLimits)
	checkMessageConstraints(t, "eol thread split", msgs, testSplitLimits)
	cont := false
	for _, m := range msgs {
		if strings.Contains(allBlocksText([]SlackMessage{m}), "*⛔ EOL packages (4) — vendor reports these CVEs as out of support for this release* _(cont.)_") {
			cont = true
		}
	}
	if !cont {
		t.Errorf("a split end-of-life section must repeat its header:\n%s", dumpMessages(msgs))
	}
}

// A report with nothing but end-of-life packages still posts a thread.
func TestThread_EOLOnly(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{pinned(scanner.ImageScan{Image: "app:1", Findings: []scanner.Finding{
		eolF("app:1", "qt", "5.15", scanner.StatusEndOfLife, scanner.SeverityHigh, "CVE-A"),
	}}, eolContentApp)}, nil, analyze.Triage{}, genTime)
	if msgs := BuildThreadBlockMessages(r, Ages{}, LanguageEN); len(msgs) != 1 || !strings.Contains(allBlocksText(msgs), "*⛔ EOL packages (1)") {
		t.Errorf("thread = %v", msgs)
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
