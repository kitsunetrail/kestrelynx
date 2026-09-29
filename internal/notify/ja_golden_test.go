package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// Japanese-language golden tests: language: ja renderings of a representative
// slice of the scenarios already pinned in English elsewhere in this
// package. Every fixture here reuses an existing top-level builder (golden_
// test.go/eol_test.go/runtime_golden_test.go/mute_golden_test.go) rather
// than inventing new report shapes, so these files are only ever exercising
// jaMessages against report data this package's English goldens already
// cover. File names start with ja_ to keep them apart from the English set,
// which TestGolden_* elsewhere in this package pin byte-for-byte and this
// file never touches.

// goldenThreadJA is goldenThread's Japanese counterpart.
func goldenThreadJA(r analyze.Report, st state.State, limit int) string {
	return strings.Join(BuildThreadMessages(r, Ages{Finding: st.FirstSeen, EOL: st.EOLFirstSeen}, limit, LanguageJA), threadSeparator)
}

// TestGoldenJA_StatusFullView covers the full-view scenario (triage on and
// off) that TestGolden_ThreeStatusOutputs pins in English.
func TestGoldenJA_StatusFullView(t *testing.T) {
	for _, m := range goldenModes()[:2] { // triage, notriage — degraded is covered by TestGoldenJA_IntelDegraded
		t.Run(m.name, func(t *testing.T) {
			r, _, _, _ := goldenCycle(m, false)
			checkGolden(t, "ja_status3_"+m.name+"_slack_full", FormatSlackText(r, LanguageJA))
		})
	}
}

// TestGoldenJA_StatusDiff covers the three diff-mode framings (changes,
// no changes, weekly full report) in triage mode.
func TestGoldenJA_StatusDiff(t *testing.T) {
	r, changed, unchanged, _ := goldenCycle(goldenModes()[0], false)
	checkGolden(t, "ja_status3_triage_slack_diff_changes", FormatSlackDiffText(r, changed, false, false, LanguageJA))
	checkGolden(t, "ja_status3_triage_slack_diff_nochanges", FormatSlackDiffText(r, unchanged, false, false, LanguageJA))
	checkGolden(t, "ja_status3_triage_slack_diff_weekly", FormatSlackDiffText(r, changed, true, false, LanguageJA))
}

// TestGoldenJA_Thread covers the thread report.
func TestGoldenJA_Thread(t *testing.T) {
	r, _, _, next := goldenCycle(goldenModes()[0], false)
	checkGolden(t, "ja_status3_triage_thread", goldenThreadJA(r, next, 0))
}

// TestGoldenJA_EOSL covers the base-OS end-of-life scenario
// (TestGolden_EOSLOutputs's English counterpart).
func TestGoldenJA_EOSL(t *testing.T) {
	r, _, _, _ := goldenCycle(goldenModes()[0], true)
	checkGolden(t, "ja_eosl_triage_slack_full", FormatSlackText(r, LanguageJA))
}

// TestGoldenJA_EOLPackages covers the package-level end-of-life scenario
// (TestGolden_EOLOutputs's English counterpart), which exercises the
// EOLSectionReason/EOLPackageText/EOLEvidenceMark/EOLSeeActNow wording
// TestGoldenJA_EOSL's base-OS-only fixture never reaches.
func TestGoldenJA_EOLPackages(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[0])
	checkGolden(t, "ja_eolpkg_triage_slack_full", FormatSlackText(r, LanguageJA))
}

// TestGoldenJA_RuntimeHealthy covers the runtime-usage overlay in its normal
// (Sensor healthy) state.
func TestGoldenJA_RuntimeHealthy(t *testing.T) {
	r := rtGoldenReport(t)
	genWeb, genAPI := rtGoldenGenWeb(), rtGoldenGenAPI()
	snap := rtevidence.Snapshot{
		Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(),
		Generations: []rtevidence.Generation{genWeb, genAPI},
	}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, r, "web:1.0"), rtGoldenWebPorts()),
			rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, r, "api:2.0"), nil),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)

	checkGolden(t, "ja_runtime_healthy_slack_full", FormatSlackText(r, LanguageJA))
}

// TestGoldenJA_RuntimeNotReporting covers the Sensor-never-reported warning
// banner.
func TestGoldenJA_RuntimeNotReporting(t *testing.T) {
	r := rtGoldenReport(t)
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{NotReporting: true, LoadFailed: true}, rtevidence.Snapshot{}, analyze.GenerationInspect{}, genTime)

	checkGolden(t, "ja_runtime_not_reporting_slack_full", FormatSlackText(r, LanguageJA))
}

// TestGoldenJA_RuntimeEBPFUnavailable covers the narrower eBPF-unavailable
// warning (Sensor otherwise healthy).
func TestGoldenJA_RuntimeEBPFUnavailable(t *testing.T) {
	r := rtGoldenReport(t)
	genWeb, genAPI := rtGoldenGenWeb(), rtGoldenGenAPI()
	sensor := rtGoldenSensorInfo()
	sensor.Events = rtevidence.EventsInfo{Status: rtevidence.EventsUnavailable, Reason: rtevidence.EventsReasonBTFMissing}
	genWeb.EventsCoverage, genAPI.EventsCoverage = rtevidence.CoverageNone, rtevidence.CoverageNone
	snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: sensor, Generations: []rtevidence.Generation{genWeb, genAPI}}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, r, "web:1.0"), rtGoldenWebPorts()),
			rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, r, "api:2.0"), nil),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)

	checkGolden(t, "ja_runtime_ebpf_unavailable_slack_full", FormatSlackText(r, LanguageJA))
}

// TestGoldenJA_Mute covers the muted-findings count line
// (runtime.mute_unfixable_not_in_use on).
func TestGoldenJA_Mute(t *testing.T) {
	r := muteGoldenReport(t)
	muteGoldenAttach(t, &r, true)

	checkGolden(t, "ja_mute_slack_full", FormatSlackText(r, LanguageJA))
}

// TestGoldenJA_Unmuted covers the "fell out of muting" diff change
// (Unmuted/unmutedReason), mirroring
// TestMuteUnfixableNotInUse_Unmuted's English fixture.
func TestGoldenJA_Unmuted(t *testing.T) {
	cycle1 := muteGoldenReport(t)
	muteGoldenAttach(t, &cycle1, true)
	_, prev := state.Compute(state.State{}, cycle1)

	cycle2 := muteGoldenReport(t)
	gen := muteGoldenGenWeb()
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

	diff, _ := state.Compute(prev, cycle2)
	checkGolden(t, "ja_mute_lost_slack_diff", FormatSlackDiffText(cycle2, diff, false, false, LanguageJA))
}

// TestGoldenJA_IntelDegraded covers the degraded-intel warning
// (writeIntelWarning's IntelDegradedWarning branch).
func TestGoldenJA_IntelDegraded(t *testing.T) {
	r, _, _, _ := goldenCycle(goldenModes()[2], false) // degraded
	checkGolden(t, "ja_status3_degraded_slack_full", FormatSlackText(r, LanguageJA))
}
