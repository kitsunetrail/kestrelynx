package remediation

import "testing"

func TestFingerprintFollowsNewerSeries(t *testing.T) {
	a := Target{VulnID: "CVE-A", Package: PackageCoord{Name: "libc"}}
	b := Target{VulnID: "CVE-B", Package: PackageCoord{Name: "openssl"}}
	other := Target{VulnID: "CVE-X", Package: PackageCoord{Name: "zlib"}}
	cand := func(outA, outB Outcome) NewerSeriesCandidate {
		return NewerSeriesCandidate{
			Tag: "2.0.1", Change: SeriesChangeMajor, Status: NewerSeriesResolvesPartially, BaselineScan: "s1", CandidateScan: "s2", Detail: "d",
			Candidate: &ImageState{Ref: "nginx:2.0.1", Tag: "2.0.1", TopDigest: "sha256:t", ManifestDigest: "sha256:m"},
			Comparison: &VerificationResult{Comparable: true, Verdicts: []VulnVerdict{
				{VulnID: a.VulnID, Package: a.Package, Outcome: outA}, {VulnID: b.VulnID, Package: b.Package, Outcome: outB},
				{VulnID: other.VulnID, Package: other.Package, Outcome: OutcomeResolved},
			}},
			Counts: &NewerSeriesCounts{Targets: 2, Resolved: 1, Remaining: 1},
		}
	}
	plan := func(edit func(*NewerSeries, *DockerfileEntity)) Plan {
		ns := &NewerSeries{Status: NewerSeriesResolvesPartially, Shown: "2.0.1", Candidates: []NewerSeriesCandidate{cand(OutcomeResolved, OutcomeRemaining)}}
		ent := DockerfileEntity{Running: ImageState{Ref: "app:1", Entity: "e"}, Category: CategoryNoCandidate, Reason: ReasonNoNewerTag, Targets: []Target{a, b},
			NewerSeries: &NewerSeries{Status: NewerSeriesResolves, Shown: "2.0.1", Candidates: []NewerSeriesCandidate{cand(OutcomeResolved, OutcomeResolved)}}}
		edit(ns, &ent)
		return Plan{
			Items:           []Item{{Key: "nginx:1.24.1|x", Kind: TagPinned, Category: CategoryNoCandidate, Reason: ReasonNoNewerTag, Targets: []Target{a, b}, NewerSeries: ns}},
			DockerfileItems: []DockerfileItem{{Key: "df", Category: CategoryNoCandidate, Reason: ReasonNoNewerTag, Entities: []DockerfileEntity{ent}}},
		}
	}
	base := Fingerprint(plan(func(*NewerSeries, *DockerfileEntity) {}))
	for name, edit := range map[string]func(*NewerSeries, *DockerfileEntity){
		"status":           func(ns *NewerSeries, _ *DockerfileEntity) { ns.Status = NewerSeriesNotChecked },
		"shown":            func(ns *NewerSeries, _ *DockerfileEntity) { ns.Shown = "" },
		"reason":           func(ns *NewerSeries, _ *DockerfileEntity) { ns.Reason = ReasonCandidateScanLimit },
		"candidate reason": func(ns *NewerSeries, _ *DockerfileEntity) { ns.Candidates[0].Reason = ReasonRegistryError },
		"content":          func(ns *NewerSeries, _ *DockerfileEntity) { ns.Candidates[0].Candidate.TopDigest = "sha256:u" },
		"manifest":         func(ns *NewerSeries, _ *DockerfileEntity) { ns.Candidates[0].Candidate.ManifestDigest = "sha256:n" },
		"resolved swaps": func(ns *NewerSeries, _ *DockerfileEntity) {
			ns.Candidates[0] = cand(OutcomeRemaining, OutcomeResolved)
		},
		"entity result": func(_ *NewerSeries, e *DockerfileEntity) { e.NewerSeries.Status = NewerSeriesNotResolving },
		"none":          func(ns *NewerSeries, _ *DockerfileEntity) { *ns = NewerSeries{Status: NewerSeriesNone} },
	} {
		if Fingerprint(plan(edit)) == base {
			t.Errorf("%s: the fingerprint did not change", name)
		}
	}
	for name, edit := range map[string]func(*NewerSeries, *DockerfileEntity){
		"scan IDs": func(ns *NewerSeries, _ *DockerfileEntity) {
			ns.Candidates[0].BaselineScan, ns.Candidates[0].CandidateScan = "s8", "s9"
		},
		"detail": func(ns *NewerSeries, _ *DockerfileEntity) { ns.Candidates[0].Detail, ns.Detail = "other", "other" },
		"a finding that is no target": func(ns *NewerSeries, _ *DockerfileEntity) {
			ns.Candidates[0].Comparison.Verdicts[2].Outcome = OutcomeRemaining
		},
	} {
		if Fingerprint(plan(edit)) != base {
			t.Errorf("%s: the fingerprint changed", name)
		}
	}
}
