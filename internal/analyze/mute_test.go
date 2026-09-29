package analyze

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// muteTestNow is the fixed "now" every ApplyMuting test here judges
// against; muteTestOldGen is a container generation well past the 7-day
// observation window.
var (
	muteTestNow    = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	muteTestOldGen = muteTestNow.Add(-8 * 24 * time.Hour)
)

// eligibleRuntime is a not-observed verdict whose one container generation
// is old enough to qualify for runtime.mute_unfixable_not_in_use on its
// own — the baseline every "individually eligible" group in these tests
// starts from.
func eligibleRuntime() Runtime {
	return Runtime{
		Usage: evidence.UsageNotObserved,
		Containers: []ContainerRuntime{
			{ContainerID: testContainerID, GenerationStartedAt: muteTestOldGen, Usage: evidence.UsageNotObserved},
		},
	}
}

// countMuted tallies every Muted PackageGroup across every section of
// r, for a single "how many groups did ApplyMuting actually mute"
// assertion.
func countMuted(r Report) int {
	n := 0
	for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			for _, g := range img.Packages {
				if g.Muted {
					n++
				}
			}
		}
	}
	return n
}

// TestApplyMuting_MixedKeyNeverMuted covers the all-or-nothing rule:
// a (image, package) key is muted only when every group the Report
// carries for it this cycle — across every section, end-of-life included —
// is individually eligible. Each case pairs one otherwise-eligible group
// with a disqualifying sibling under the very same key, and neither group
// may end up Muted.
func TestApplyMuting_MixedKeyNeverMuted(t *testing.T) {
	tests := []struct {
		name   string
		report Report
	}{
		{
			// A package with both fixed and unfixed CVEs: the fixed side is
			// never itself eligible, and already puts its own row in front
			// of the reader, so the unfixed side must not be hidden either.
			name: "fixed sibling blocks an eligible-looking affected sibling",
			report: Report{
				Runtime: &RuntimeInfo{},
				Actionable: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
					{Package: "curl", Status: scanner.StatusFixed},
				}}},
				Watch: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
					{Package: "curl", Status: scanner.StatusAffected, Runtime: eligibleRuntime()},
				}}},
			},
		},
		{
			// A package whose base OS makes it end-of-life alongside an
			// ordinary affected finding for the same name: end-of-life is
			// always reported, so the whole key stays visible.
			name: "end-of-life sibling blocks an eligible-looking watch sibling",
			report: Report{
				Runtime: &RuntimeInfo{},
				Watch: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
					{Package: "curl", Status: scanner.StatusAffected, Runtime: eligibleRuntime()},
				}}},
				EOLPackages: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
					{Package: "curl", Status: scanner.StatusEndOfLife},
				}}},
			},
		},
		{
			// An OS package and a same-named language package collide under
			// state's coarser (image, package-name) key even though analyze
			// keeps them as distinct groups: one is in use, the other looks
			// eligible on its own — the key must still not be muted.
			name: "in-use sibling of a different ecosystem blocks an eligible-looking one",
			report: Report{
				Runtime: &RuntimeInfo{},
				Watch: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
					{Package: "curl", Class: scanner.ClassOS, Status: scanner.StatusAffected, Runtime: eligibleRuntime()},
					{Package: "curl", Class: scanner.ClassLang, Ecosystem: inventory.EcosystemNodePkg, Status: scanner.StatusAffected, Runtime: Runtime{Usage: evidence.UsageInUse}},
				}}},
			},
		},
		{
			// A group whose container generation is too new (a recent
			// redeploy) blocks a same-key sibling that has otherwise been
			// observed long enough.
			name: "too-recent sibling blocks an eligible-looking one",
			report: Report{
				Runtime: &RuntimeInfo{},
				Watch: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
					{Package: "curl", Class: scanner.ClassOS, Status: scanner.StatusAffected, Runtime: eligibleRuntime()},
					{
						Package: "curl", Class: scanner.ClassLang, Ecosystem: inventory.EcosystemNodePkg, Status: scanner.StatusAffected,
						Runtime: Runtime{Usage: evidence.UsageNotObserved, Containers: []ContainerRuntime{
							{ContainerID: testContainerID, GenerationStartedAt: muteTestNow.Add(-time.Hour), Usage: evidence.UsageNotObserved},
						}},
					},
				}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.report
			ApplyMuting(&r, muteTestNow)
			if n := countMuted(r); n != 0 {
				t.Errorf("countMuted = %d, want 0 (a mixed key must never be partially muted)", n)
			}
		})
	}
}

// TestApplyMuting_AllEligibleGroupsMuted is
// TestApplyMuting_MixedKeyNeverMuted's positive counterpart: when
// every group under a key is individually eligible — including more than
// one of them, e.g. an affected group and a will_not_fix group for the same
// package — every one of them is Muted.
func TestApplyMuting_AllEligibleGroupsMuted(t *testing.T) {
	r := Report{
		Runtime: &RuntimeInfo{},
		Watch: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
			{Package: "curl", Status: scanner.StatusAffected, Runtime: eligibleRuntime()},
		}}},
		WontFix: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
			{Package: "curl", Status: scanner.StatusWontFix, Runtime: eligibleRuntime()},
		}}},
	}
	ApplyMuting(&r, muteTestNow)
	if n := countMuted(r); n != 2 {
		t.Fatalf("countMuted = %d, want 2 (both groups of a fully-eligible key)", n)
	}
	for _, img := range r.Watch {
		for _, g := range img.Packages {
			if g.MutedReason != MutedNoFixNotInUse7d {
				t.Errorf("Watch group MutedReason = %q, want %q", g.MutedReason, MutedNoFixNotInUse7d)
			}
		}
	}
}

// TestApplyMuting_HeldReferenceNeverMuted covers the same holding
// condition state.Compute itself keys off (ScanFailed, PartialFailure,
// Unconfirmed on the matching ImageObservation): a group that looks
// individually eligible on its own must still never be muted while its
// own reference is in one of these states this cycle. Report.Images for a
// reference that failed to scan at all would normally carry no groups under
// it either, but the check must not depend on that — it must hold even when
// a sibling entity's success still puts an eligible-looking group in front
// of ApplyMuting, since state itself has no fresh, complete picture of
// the reference to judge muting from this cycle.
func TestApplyMuting_HeldReferenceNeverMuted(t *testing.T) {
	tests := []struct {
		name string
		obs  ImageObservation
	}{
		{"scan failed", ImageObservation{Ref: "web:1", ScanFailed: true}},
		{"partial failure", ImageObservation{Ref: "web:1", PartialFailure: true}},
		{"unconfirmed", ImageObservation{Ref: "web:1", Unconfirmed: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Report{
				Runtime: &RuntimeInfo{},
				Images:  []ImageObservation{tt.obs},
				Watch: []ImageFindings{{Image: "web:1", Packages: []PackageGroup{
					{Package: "curl", Status: scanner.StatusAffected, Runtime: eligibleRuntime()},
				}}},
			}
			ApplyMuting(&r, muteTestNow)
			if n := countMuted(r); n != 0 {
				t.Errorf("countMuted = %d, want 0 (a held reference must never be muted, however eligible its groups look)", n)
			}
		})
	}
}
