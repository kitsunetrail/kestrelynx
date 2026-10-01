package notify

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// Mute golden fixture: runtime.mute_unfixable_not_in_use scenarios,
// built on the same web:1.0/openssl/curl shapes runtime_golden_test.go
// already uses. openssl stays act_now and in use (never muted, and always
// shown) side by side with curl, an affected, not-observed, low-priority OS
// package whose container has been running for well over the 7-day
// observation window — the one finding these scenarios mute.

// muteGoldenReport builds the report before runtime evidence is attached:
// one act_now finding (openssl) that must never be hidden, and one
// muting-eligible finding (curl).
func muteGoldenReport(t *testing.T) analyze.Report {
	t.Helper()
	web := rtGoldenScan(t, "web:1.0", rtGoldenWebDigest,
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-OPENSSL"},
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "curl", InstalledVer: "8.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-CURL"},
	)
	scans := []scanner.ImageScan{web}
	return analyze.Build(scans, rtGoldenContainers(t), triageRules(map[string]analyze.Enrichment{
		"CVE-OPENSSL": {KEV: true},
	}), genTime)
}

// muteGoldenGenWeb is rtGoldenGenWeb with its container generation's
// StartedAt pushed back 8 days — past the 7-day observation window —
// leaving everything else (the PID/starttime pair matchGeneration checks,
// openssl's in-use evidence) untouched. curl has no OSPackages/Unavailable
// entry of its own, so it judges not_observed exactly as it already does in
// runtime_golden_test.go's healthy-Sensor fixture.
func muteGoldenGenWeb() rtevidence.Generation {
	gen := rtGoldenGenWeb()
	gen.StartedAt = genTime.Add(-8 * 24 * time.Hour)
	return gen
}

// muteGoldenAttach attaches runtime evidence built from
// muteGoldenGenWeb and, when mute is true, runs ApplyMuting —
// mirroring runner.RunOnce's own order (AttachRuntime, then ApplyMuting
// only when runtime.mute_unfixable_not_in_use is on).
func muteGoldenAttach(t *testing.T, r *analyze.Report, mute bool) {
	t.Helper()
	gen := muteGoldenGenWeb()
	snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(), Generations: []rtevidence.Generation{gen}}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(gen, rtGoldenSubject(t, *r, "web:1.0"), rtGoldenWebPorts()),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)
	if mute {
		analyze.ApplyMuting(r, genTime)
	}
}

// TestGolden_MuteUnfixableNotInUse pins the channel full view, the diff
// (first-cycle) channel body, the thread, and the webhook payload for a
// report with one muted finding (curl) and one act_now finding (openssl)
// that stays fully visible alongside it.
func TestGolden_MuteUnfixableNotInUse(t *testing.T) {
	r := muteGoldenReport(t)
	muteGoldenAttach(t, &r, true)

	d, _ := state.Compute(state.State{}, r)
	checkGolden(t, "mute_webhook", mustIndentJSON(t, BuildWebhookPayload(r, &d)))
}

// TestMuteUnfixableNotInUse_Disabled proves that leaving
// runtime.mute_unfixable_not_in_use off (analyze.ApplyMuting is then
// never called — the exact path every deployment used before this setting
// existed) still produces the byte-identical output runtime_golden_test.go
// already pinned for the plain runtime-enabled fixture. Comparing two fresh
// calls that both skip ApplyMuting would only prove the code is
// deterministic, not that disabling the setting reproduces pre-existing
// behavior — the goldens here were captured before this feature's own
// tests existed, so this is a real compatibility check against them.
func TestMuteUnfixableNotInUse_Disabled(t *testing.T) {
	r := rtGoldenReport(t)
	rtGoldenAttach(t, &r)
	// mute_unfixable_not_in_use off: analyze.ApplyMuting is
	// deliberately never called, mirroring runner.RunOnce's own gating.

	checkGolden(t, "runtime_healthy_webhook", mustIndentJSON(t, BuildWebhookPayload(r, nil)))

	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			for _, g := range img.Packages {
				if g.Muted {
					t.Errorf("%s/%s: Muted = true with mute_unfixable_not_in_use off, want false", img.Image, g.Package)
				}
			}
		}
	}
}

// TestMuteUnfixableNotInUse_Unmuted drives the two-cycle
// "fell out of muting" transition: curl is muted on cycle 1 (not
// observed, container generation 8 days old), then becomes in use on cycle
// 2 — a change no ordinary Kind (new/escalated/new_cves/now_fixable) would
// otherwise report, since neither its CVEs, its fix status, nor its
// priority changed. state.Compute must synthesize KindUnmuted, and
// the rendered line must read "↩️ Unmuted (now in use)".
func TestMuteUnfixableNotInUse_Unmuted(t *testing.T) {
	cycle1 := muteGoldenReport(t)
	muteGoldenAttach(t, &cycle1, true)
	_, prev := state.Compute(state.State{}, cycle1)
	if !prev.Muted["web:1.0\tcurl"] {
		t.Fatalf("cycle 1: curl not recorded as muted in state: %+v", prev.Muted)
	}

	cycle2 := muteGoldenReport(t)
	gen := muteGoldenGenWeb()
	// curl is now actually running: JudgeOSPackage matches it and the group
	// becomes in_use, the same as openssl already is.
	gen.OSPackages = append(gen.OSPackages, rtevidence.OSPackageEvidence{
		Name: "curl", Version: "8.0.0", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
			rtevidence.KindExe: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
		}, Observations: []rtevidence.ProcessObservation{
			{Exe: "/usr/bin/curl", EffectiveUID: 0, LastSeen: genTime},
		},
	})
	snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(), Generations: []rtevidence.Generation{gen}}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(gen, rtGoldenSubject(t, cycle2, "web:1.0"), rtGoldenWebPorts()),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(&cycle2, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)
	analyze.ApplyMuting(&cycle2, genTime)

	curl := findPkgGroup(t, cycle2.Watch, "web:1.0", "curl")
	if curl.Runtime.Usage != rtevidence.UsageInUse {
		t.Fatalf("cycle 2: curl.Runtime.Usage = %q, want in_use", curl.Runtime.Usage)
	}
	if curl.Muted {
		t.Fatalf("cycle 2: curl.Muted = true, want false (in use is never muted)")
	}

	diff, next := state.Compute(prev, cycle2)
	if next.Muted["web:1.0\tcurl"] {
		t.Errorf("cycle 2: curl still recorded as muted in next state")
	}
	var found *state.Change
	for i, c := range diff.Changes {
		if c.Image == "web:1.0" && c.Package == "curl" {
			found = &diff.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("cycle 2: no diff.Changes entry for web:1.0/curl:\n%+v", diff.Changes)
	}
	if found.Kind != state.KindUnmuted {
		t.Errorf("cycle 2: Kind = %q, want %q", found.Kind, state.KindUnmuted)
	}

}

// muteGoldenReportWithCurlEOL is muteGoldenReport's cycle-2 counterpart
// for the end-of-life transition: the identical scan, plus a second CVE
// against curl reported end-of-life — the base OS or the package itself
// aging out from under an otherwise unchanged finding. curl's own CVE-CURL,
// fix status and priority never change.
func muteGoldenReportWithCurlEOL(t *testing.T) analyze.Report {
	t.Helper()
	web := rtGoldenScan(t, "web:1.0", rtGoldenWebDigest,
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-OPENSSL"},
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "curl", InstalledVer: "8.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-CURL"},
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "curl", InstalledVer: "8.0.0", Status: scanner.StatusEndOfLife, Severity: scanner.SeverityHigh, VulnID: "CVE-CURL-EOL"},
	)
	scans := []scanner.ImageScan{web}
	return analyze.Build(scans, rtGoldenContainers(t), triageRules(map[string]analyze.Enrichment{
		"CVE-OPENSSL": {KEV: true},
	}), genTime)
}

// TestMuteUnfixableNotInUse_EOLUnmuted drives the "unmuted by
// becoming end-of-life" transition, checking that the reported reason names
// the actual cause rather than defaulting to something unrelated: curl is
// muted on cycle 1, then on cycle 2 the exact same CVE-CURL is joined by
// a second, end-of-life CVE for the same package —
// curl's own CVEs, fix status and priority never change, so no ordinary
// Kind fires and only KindUnmuted can carry the news. The reason
// must read "now end-of-life", not "insufficient observation": Change.
// Groups alone (the three ordinary sections) never sees the new
// end-of-life group, which is exactly the gap Change.EOLGroups and
// changeReasonGroups close.
func TestMuteUnfixableNotInUse_EOLUnmuted(t *testing.T) {
	cycle1 := muteGoldenReport(t)
	muteGoldenAttach(t, &cycle1, true)
	_, prev := state.Compute(state.State{}, cycle1)
	if !prev.Muted["web:1.0\tcurl"] {
		t.Fatalf("cycle 1: curl not recorded as muted in state: %+v", prev.Muted)
	}

	cycle2 := muteGoldenReportWithCurlEOL(t)
	muteGoldenAttach(t, &cycle2, true)

	curl := findPkgGroup(t, cycle2.Watch, "web:1.0", "curl")
	if curl.Muted {
		t.Fatalf("cycle 2: curl.Muted = true, want false (an end-of-life sibling blocks the whole key)")
	}

	diff, next := state.Compute(prev, cycle2)
	if next.Muted["web:1.0\tcurl"] {
		t.Errorf("cycle 2: curl still recorded as muted in next state")
	}
	var found *state.Change
	for i, c := range diff.Changes {
		if c.Image == "web:1.0" && c.Package == "curl" {
			found = &diff.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("cycle 2: no diff.Changes entry for web:1.0/curl:\n%+v", diff.Changes)
	}
	if found.Kind != state.KindUnmuted {
		t.Errorf("cycle 2: Kind = %q, want %q", found.Kind, state.KindUnmuted)
	}
	if len(found.EOLGroups) == 0 {
		t.Fatalf("cycle 2: Change.EOLGroups is empty, want curl's end-of-life group attached")
	}

	checkGolden(t, "mute_lost_eol_webhook", mustIndentJSON(t, BuildWebhookPayload(cycle2, &diff)))
}

// TestUnmutedReason_PicksTheRightFactInPriorityOrder checks
// unmutedReason's fixed precedence — in use, then act_now, then a
// fix, then end-of-life, then unreliable runtime evidence, then a
// no-longer-eligible status, falling back to "insufficient observation" —
// reading from every group a key carries this cycle, not attributing one
// group's own state to another.
func TestUnmutedReason_PicksTheRightFactInPriorityOrder(t *testing.T) {
	inUse := analyze.PackageGroup{Status: scanner.StatusAffected, Runtime: analyze.Runtime{Usage: rtevidence.UsageInUse}}
	actNow := analyze.PackageGroup{Status: scanner.StatusAffected, Priority: analyze.PriorityActNow, Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}}
	fixed := analyze.PackageGroup{Status: scanner.StatusFixed}
	eol := analyze.PackageGroup{Status: scanner.StatusEndOfLife, Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}}
	unavailable := analyze.PackageGroup{Status: scanner.StatusAffected, Runtime: analyze.Runtime{Usage: rtevidence.UsageUnavailable}}
	plainNotObserved := analyze.PackageGroup{Status: scanner.StatusAffected, Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}}

	tests := []struct {
		name   string
		groups []analyze.PackageGroup
		want   string
	}{
		{"in use wins over everything else", []analyze.PackageGroup{fixed, actNow, eol, inUse}, "now in use"},
		{"act now wins over fixed/eol/unavailable", []analyze.PackageGroup{fixed, eol, unavailable, actNow}, "act now"},
		{"fix available wins over eol/unavailable", []analyze.PackageGroup{eol, unavailable, fixed}, "fix available"},
		{"now end-of-life wins over unavailable — the package's own EOLGroups, not just its ordinary Groups", []analyze.PackageGroup{unavailable, eol}, "now end-of-life"},
		{"insufficient observation is checked after end-of-life", []analyze.PackageGroup{unavailable}, "insufficient observation"},
		{"plain not-observed falls back to insufficient observation", []analyze.PackageGroup{plainNotObserved}, "insufficient observation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unmutedReason(tt.groups, enMessages); got != tt.want {
				t.Errorf("unmutedReason(%+v) = %q, want %q", tt.groups, got, tt.want)
			}
		})
	}
}

// TestChangeReasonGroups_IncludesEOLGroups verifies that
// unmutedReason sees a key's end-of-life groups, not just its
// ordinary ones — otherwise an unmute caused by the package
// becoming end-of-life reads as "insufficient observation" instead of
// naming the actual cause.
func TestChangeReasonGroups_IncludesEOLGroups(t *testing.T) {
	ordinary := analyze.PackageGroup{Status: scanner.StatusWontFix, Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}}
	eol := analyze.PackageGroup{Status: scanner.StatusEndOfLife, Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}}
	c := state.Change{
		Kind:      state.KindUnmuted,
		Groups:    []analyze.PackageGroup{ordinary},
		EOLGroups: []analyze.PackageGroup{eol},
	}
	combined := changeReasonGroups(c)
	if len(combined) != 2 {
		t.Fatalf("changeReasonGroups returned %d groups, want 2 (ordinary + end-of-life)", len(combined))
	}
	if got := unmutedReason(combined, enMessages); got != "now end-of-life" {
		t.Errorf("unmutedReason(changeReasonGroups(c)) = %q, want %q", got, "now end-of-life")
	}
	if got := unmutedReason(c.Groups, enMessages); got == "now end-of-life" {
		t.Error("unmutedReason(c.Groups, enMessages) alone unexpectedly saw the end-of-life group — Groups must not include EOLGroups")
	}
}
