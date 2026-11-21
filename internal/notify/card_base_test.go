package notify

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	baseItemKey = "dockerfile:ex/es@main:Dockerfile#stages[0]"
	baseUnitKey = "dockerfile|ex/es|main|Dockerfile|stages[0]"
)

// basePlan is baseWaitPlan with the kind of the base's tag, the item's
// outcome and the running image's own.
func basePlan(t *testing.T, kind remediation.TagKind, itemCat remediation.Category, itemReason remediation.Reason, entCat remediation.Category, entReason remediation.Reason) *PlanInfo {
	p := baseWaitPlan(t, itemCat, itemReason)
	it := &p.Plan.DockerfileItems[0]
	it.BaseKind = kind
	it.Entities[0].Category, it.Entities[0].Reason = entCat, entReason
	return p
}

// withBaseCandidate gives the running image of the plan's Dockerfile item
// the candidate base 8.19.24 and a comparison with the outcome of each jsoup
// target in outs, in order.
func withBaseCandidate(p *PlanInfo, outs ...remediation.Outcome) *PlanInfo {
	it := &p.Plan.DockerfileItems[0]
	e := &it.Entities[0]
	cand := remediation.ImageState{Ref: "docker.elastic.co/elasticsearch/elasticsearch:8.19.24", Tag: "8.19.24"}
	it.Candidate, e.CandidateBase = &cand, &cand
	vr := &remediation.VerificationResult{Comparable: true}
	for i, o := range outs {
		vr.Verdicts = append(vr.Verdicts, remediation.VulnVerdict{VulnID: e.Targets[i].VulnID, Package: e.Targets[i].Package, Outcome: o})
	}
	e.Comparison = vr
	return p
}

// adoptedBase is a pinned base whose candidate every running image adopts.
func adoptedBase(t *testing.T, outs ...remediation.Outcome) *PlanInfo {
	return withBaseCandidate(basePlan(t, remediation.TagPinned, remediation.CategoryPRCandidate, remediation.ReasonAdopted,
		remediation.CategoryPRCandidate, remediation.ReasonAdopted), outs...)
}

func baseAssigned() []remediation.PRItemResult {
	return []remediation.PRItemResult{{Kind: remediation.PRItemKindDockerfile, ItemKey: baseItemKey, UnitKeys: []string{baseUnitKey}, Status: remediation.PRItemAssigned}}
}

func baseUnit(status remediation.PRUnitStatus, number int) remediation.PRUnit {
	u := remediation.PRUnit{Kind: "dockerfile", Key: baseUnitKey, Repo: "ex/es", Path: "Dockerfile", Status: status, Number: number}
	if number > 0 {
		u.URL = "https://github.com/ex/es/pull/12"
	}
	return u
}

type baseCase struct {
	name   string
	plan   *PlanInfo
	ja, en string
}

func runBaseCases(t *testing.T, r analyze.Report, cases []baseCase) {
	t.Helper()
	for _, c := range cases {
		for _, l := range []struct {
			lang Language
			want string
		}{{LanguageJA, c.ja}, {LanguageEN, c.en}} {
			if got := actionLineOf(t, r, c.plan, l.lang); got != l.want {
				t.Errorf("%s (%s):\n got %q\nwant %q", c.name, l.lang, got, l.want)
			}
		}
	}
}

func TestCardBase_CandidateOfTheBase(t *testing.T) {
	link := "<https://github.com/ex/es/pull/12|#12>"
	manual := func(reason remediation.Reason, entCat remediation.Category, entReason remediation.Reason) *PlanInfo {
		return basePlan(t, remediation.TagPinned, remediation.CategoryManual, reason, entCat, entReason)
	}
	runBaseCases(t, baseWaitReport(t), []baseCase{
		{"resolves", adoptedBase(t, resolved(), resolved()),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves it (base images compared)"},
		{"resolves part", adoptedBase(t, resolved(), remaining()),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で一部解消（2件中1件、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves part of it (1 of 2, base images compared)"},
		{"remains", adoptedBase(t, remaining(), remaining()),
			"元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列の 8.19.24 では未解消、ベースの比較）",
			"waiting for a newer base image of elasticsearch 8.19.23 (not resolved in 8.19.24 of the same series, base images compared)"},
		{"not judged", adoptedBase(t, resolved(), remediation.OutcomeUnknown),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消するか確認できない（ベースの比較）",
			"whether base image elasticsearch 8.19.23 → 8.19.24 resolves it could not be confirmed (base images compared)"},
		{"a verdict missing", adoptedBase(t, resolved()),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消するか確認できない（ベースの比較）",
			"whether base image elasticsearch 8.19.23 → 8.19.24 resolves it could not be confirmed (base images compared)"},

		{"with a pull request", withPR(adoptedBase(t, resolved(), resolved()), baseAssigned(), baseUnit(remediation.PRStatusCreated, 12)),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（Pull Request " + link + "、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves it (Pull Request " + link + ", base images compared)"},
		{"part with a pull request", withPR(adoptedBase(t, resolved(), remaining()), baseAssigned(), baseUnit(remediation.PRStatusOpen, 12)),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で一部解消（2件中1件、Pull Request " + link + "、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves part of it (1 of 2, Pull Request " + link + ", base images compared)"},
		{"a merged pull request", withPR(adoptedBase(t, resolved(), resolved()), baseAssigned(), baseUnit(remediation.PRStatusMerged, 12)),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（Pull Request " + link + " はマージ済み、イメージの再ビルド待ち、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves it (Pull Request " + link + " is merged; waiting for the image to be rebuilt, base images compared)"},
		{"the stage did not run", withPR(adoptedBase(t, resolved(), resolved()), []remediation.PRItemResult{
			{Kind: remediation.PRItemKindDockerfile, ItemKey: baseItemKey, Status: remediation.PRItemNotProcessed, Reason: remediation.ReasonStorageFailed}}),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（Pull Request は未作成: " + planReasonText(LanguageJA, "storage_failed") + "、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves it (Pull Request not created: " + planReasonText(LanguageEN, "storage_failed") + ", base images compared)"},
		{"remaining findings name no pull request", withPR(adoptedBase(t, remaining(), remaining()), baseAssigned(), baseUnit(remediation.PRStatusCreated, 12)),
			"元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列の 8.19.24 では未解消、ベースの比較）",
			"waiting for a newer base image of elasticsearch 8.19.23 (not resolved in 8.19.24 of the same series, base images compared)"},
		{"the result of an image item is not the Dockerfile's", withPR(adoptedBase(t, resolved(), resolved()), []remediation.PRItemResult{
			{Kind: remediation.PRItemKindImage, ItemKey: baseItemKey, Status: remediation.PRItemNotApplicable, Reason: remediation.ReasonSourceMappingMissing}}),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves it (base images compared)"},

		{"decision, resolves", withBaseCandidate(manual(remediation.ReasonIntroducedFindings, remediation.CategoryManual, remediation.ReasonIntroducedFindings), resolved(), resolved()),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（要判断: 候補で新たな所見が入る、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves it (decision needed: the candidate brings new findings, base images compared)"},
		{"decision, resolves part", withBaseCandidate(manual(remediation.ReasonIntroducedFindings, remediation.CategoryManual, remediation.ReasonIntroducedFindings), resolved(), remaining()),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で一部解消（2件中1件、要判断: 候補で新たな所見が入る、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves part of it (1 of 2, decision needed: the candidate brings new findings, base images compared)"},
		{"decision, remains", withBaseCandidate(manual(remediation.ReasonIntroducedFindings, remediation.CategoryManual, remediation.ReasonIntroducedFindings), remaining(), remaining()),
			"元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列の 8.19.24 では未解消、要判断: 候補で新たな所見が入る、ベースの比較）",
			"waiting for a newer base image of elasticsearch 8.19.23 (not resolved in 8.19.24 of the same series, decision needed: the candidate brings new findings, base images compared)"},
		// The images of the Dockerfile do not agree: the one that adopts the
		// candidate still shows what it does, as a person's to decide.
		{"decision of the item, the image adopts", withBaseCandidate(manual(remediation.ReasonDockerfileSetNotAdopted, remediation.CategoryPRCandidate, remediation.ReasonAdopted), resolved(), resolved()),
			"元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（要判断: " + planReasonText(LanguageJA, "dockerfile_set_not_adopted") + "、ベースの比較）",
			"base image elasticsearch 8.19.23 → 8.19.24 resolves it (decision needed: " + planReasonText(LanguageEN, "dockerfile_set_not_adopted") + ", base images compared)"},
		{"decision without a comparison", manual(remediation.ReasonDockerfileSetNotAdopted, remediation.CategoryFailed, remediation.ReasonScanFailed),
			"元イメージの更新は要判断（" + planReasonText(LanguageJA, "dockerfile_set_not_adopted") + "）",
			"updating the base image needs a decision (" + planReasonText(LanguageEN, "dockerfile_set_not_adopted") + ")"},
		{"decision, not judged", withBaseCandidate(manual(remediation.ReasonIntroducedKEV, remediation.CategoryManual, remediation.ReasonIntroducedKEV), resolved(), remediation.OutcomeUnknown),
			"元イメージの更新は要判断（" + planReasonText(LanguageJA, "introduced_kev") + "）",
			"updating the base image needs a decision (" + planReasonText(LanguageEN, "introduced_kev") + ")"},
		{"decision without a reason", manual("", remediation.CategoryManual, ""), "", ""},
	})
}

func TestCardBase_NoCandidateAndUnchecked(t *testing.T) {
	plan := func(kind remediation.TagKind, cat remediation.Category, reason remediation.Reason) *PlanInfo {
		return basePlan(t, kind, cat, reason, cat, reason)
	}
	withNewer := func(p *PlanInfo, s remediation.NewerSeriesStatus) *PlanInfo {
		it := &p.Plan.DockerfileItems[0]
		it.NewerSeries, it.Entities[0].NewerSeries = newerOf(s, ""), newerOf(s, "")
		return p
	}
	pinned, floating := remediation.TagPinned, remediation.TagFloating
	notFixing := func() *PlanInfo {
		return withBaseCandidate(plan(pinned, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing), remaining(), remaining())
	}
	sameContentJA := "元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列の新しいタグも内容は同じ）"
	sameContentEN := "waiting for a newer base image of elasticsearch 8.19.23 (the newer tag of the same series has the same content)"
	notFixedJA := "元イメージ elasticsearch の新しい版待ち（同じ系列の新しい版では未解消、ベースの比較）"
	notFixedEN := "waiting for a newer base image of elasticsearch (not resolved by the newer tag of the same series, base images compared)"
	runBaseCases(t, baseWaitReport(t), []baseCase{
		{"floating base unchanged", plan(floating, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged),
			"元イメージ elasticsearch 8.19.23 の新しい内容待ち（タグの内容は作成時から変わっていない）",
			"waiting for new content of base image elasticsearch 8.19.23 (the tag's content has not changed since the image was built)"},
		{"unchanged needs a floating tag", plan(pinned, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged), "", ""},

		{"same content", plan(pinned, remediation.CategoryNoCandidate, remediation.ReasonSameContent), sameContentJA, sameContentEN},
		{"same content, no newer series", withNewer(plan(pinned, remediation.CategoryNoCandidate, remediation.ReasonSameContent), remediation.NewerSeriesNone), sameContentJA, sameContentEN},
		{"same content, newer series not checked", withNewer(plan(pinned, remediation.CategoryNoCandidate, remediation.ReasonSameContent), remediation.NewerSeriesNotChecked), "", ""},
		{"same content of a floating tag", plan(floating, remediation.CategoryNoCandidate, remediation.ReasonSameContent), "", ""},

		{"not fixing", notFixing(), notFixedJA, notFixedEN},
		{"not fixing, no newer series", withNewer(notFixing(), remediation.NewerSeriesNone), notFixedJA, notFixedEN},
		{"not fixing, newer series not checked", withNewer(notFixing(), remediation.NewerSeriesNotChecked), "", ""},
		{"not fixing, a finding not judged", withBaseCandidate(plan(pinned, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing), remaining(), remediation.OutcomeUnknown), "", ""},
		{"not fixing without a comparison", plan(pinned, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing), "", ""},

		{"excluded", plan(pinned, remediation.CategoryExcluded, remediation.Reason(remediation.ExcludePrerelease)),
			"元イメージの新しい版は確認していない（" + planReasonText(LanguageJA, "prerelease") + "）",
			"a newer base image has not been checked (" + planReasonText(LanguageEN, "prerelease") + ")"},
		{"not comparable", plan(pinned, remediation.CategoryNotComparable, remediation.ReasonAnalysisIncomplete),
			"元イメージの新しい版を確認できなかった（" + planReasonText(LanguageJA, "analysis_incomplete") + "）",
			"a newer base image could not be checked (" + planReasonText(LanguageEN, "analysis_incomplete") + ")"},
		{"failed", plan(pinned, remediation.CategoryFailed, remediation.ReasonScanFailed),
			"元イメージの新しい版を確認できなかった（" + planReasonText(LanguageJA, "scan_failed") + "）",
			"a newer base image could not be checked (" + planReasonText(LanguageEN, "scan_failed") + ")"},
		{"deferred", plan(pinned, remediation.CategoryDeferred, remediation.ReasonCandidateScanLimit),
			"元イメージの新しい版は次回以降に確認（" + planReasonText(LanguageJA, "candidate_scan_limit") + "）",
			"a newer base image will be checked in a later run (" + planReasonText(LanguageEN, "candidate_scan_limit") + ")"},
		{"failed without a reason", plan(pinned, remediation.CategoryFailed, ""), "", ""},
	})
}

// A finding is the base's only when every layer the card's findings were
// attributed to is a base layer the targets were reported in, and when the
// dependency files do not hold it.
func TestCardBase_NeedsTheBaseLayersAndNoOtherSource(t *testing.T) {
	plan := func() *PlanInfo { return adoptedBase(t, resolved(), resolved()) }
	// A copy of the package in a later layer.
	fs := baseWaitFindings()
	upper := append(fs, jsoupFinding("1.21.2", "CVE-2031-1111", "sha256:app-layer", "app/lib/jsoup.jar"), jsoupFinding("1.21.2", "CVE-2031-2222", "sha256:app-layer", "app/lib/jsoup.jar"))
	if got := actionLineOf(t, baseWaitReportOf(t, baseWaitScan(t, "a", upper)), plan(), LanguageEN); got != "" {
		t.Errorf("a package also in a later layer has the line %q", got)
	}
	// A finding without a layer.
	unlayered := []scanner.Finding{jsoupFinding("1.21.2", "CVE-2031-1111", "", "usr/lib/a/jsoup.jar"), jsoupFinding("1.21.2", "CVE-2031-2222", "", "usr/lib/a/jsoup.jar")}
	if got := actionLineOf(t, baseWaitReportOf(t, baseWaitScan(t, "a", unlayered)), plan(), LanguageEN); got != "" {
		t.Errorf("a package without a layer has the line %q", got)
	}
	// One of the card's findings is not a target of the base.
	p := plan()
	e := &p.Plan.DockerfileItems[0].Entities[0]
	e.Targets = e.Targets[:1]
	if got := actionLineOf(t, baseWaitReport(t), p, LanguageEN); got != "" {
		t.Errorf("a partly targeted package has the line %q", got)
	}
	// The dependency files hold one of the card's findings.
	f := fs[0]
	ref := f.PackageRef()
	p = plan()
	p.Plan.LanguageItems = []remediation.LanguageItem{{Key: "deps:ex/es@main:.#maven", Packages: []remediation.LanguagePackage{{
		Name: f.Package, Installed: f.InstalledVer, Action: remediation.ActionUpdate,
		Origins: []remediation.FindingOrigin{{Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a")), Ecosystem: string(ref.Ecosystem),
			Class: string(ref.Class), Name: f.Package, Version: f.InstalledVer, VulnID: f.VulnID, PkgPath: f.PkgPath}},
	}}}}
	if got := actionLineOf(t, baseWaitReport(t), p, LanguageEN); got != "" {
		t.Errorf("a card of a dependency file's finding has the line %q", got)
	}
	// Another running entity of the same reference is not the one judged.
	if got := actionLineOf(t, baseWaitReportOf(t, baseWaitScan(t, "b", fs)), plan(), LanguageEN); got != "" {
		t.Errorf("another entity has the line %q", got)
	}
	// The image's own tag does not answer for a finding the base holds.
	p = basePlan(t, remediation.TagPinned, remediation.CategoryNoCandidate, remediation.ReasonNoBaseFindings, remediation.CategoryNoCandidate, remediation.ReasonNoBaseFindings)
	p.Plan.Items = itemPlan(t, remediation.TagFloating, remediation.CategoryPullAgain, remediation.ReasonAdopted, true, resolved(), resolved()).Plan.Items
	if got := actionLineOf(t, baseWaitReport(t), p, LanguageEN); got != "" {
		t.Errorf("a card of the base's findings has the image's line %q", got)
	}
}

// nodeRuntimeFindings are two findings of the Node.js runtime, which no layer
// holds.
func nodeRuntimeFindings() []scanner.Finding {
	f := func(id string) scanner.Finding {
		return scanner.Finding{Image: baseWaitImage, Class: scanner.ClassLang, Package: inventory.NodeRuntimePackage, InstalledVer: "24.1.0", FixedVer: "24.2.0",
			Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: id, Type: string(inventory.EcosystemNodeRuntime),
			Target: "usr/local/bin/node", PkgPath: "usr/local/bin/node"}
	}
	return []scanner.Finding{f("CVE-2031-1111"), f("CVE-2031-2222")}
}

// The plan takes a language runtime for the base's by the version both
// declare; its findings have no layer.
func TestCardBase_RuntimeWithoutLayer(t *testing.T) {
	fs := nodeRuntimeFindings()
	r := baseWaitReportOf(t, baseWaitScan(t, "a", fs))
	p := basePlan(t, remediation.TagFloating, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged)
	e := &p.Plan.DockerfileItems[0].Entities[0]
	e.Targets = nil
	for _, f := range fs {
		tg := baseWaitTarget(f)
		tg.Layers = nil
		e.Targets = append(e.Targets, tg)
	}
	want := "waiting for new content of base image elasticsearch 8.19.23 (the tag's content has not changed since the image was built)"
	if got := actionLineOf(t, r, p, LanguageEN); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// A target with a layer is not one taken by the version.
	e.Targets[0].Layers = []string{baseLayer}
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a runtime target with a layer: got %q", got)
	}
}

// movedBase is a floating base whose tag moved after the image was built,
// with the comparison of the running image and the tag's current content.
func movedBase(t *testing.T, c *remediation.RebuildCheck, runtimes ...remediation.RuntimeRebuild) *PlanInfo {
	p := basePlan(t, remediation.TagFloating, remediation.CategoryNotComparable, remediation.ReasonFloatingBaseUnconfirmed,
		remediation.CategoryNotComparable, remediation.ReasonFloatingBaseUnconfirmed)
	e := &p.Plan.DockerfileItems[0].Entities[0]
	e.Targets, e.RebuildCheck, e.RebuildRuntimes = nil, c, runtimes
	return p
}

func jsoupRebuild(path string, vulns ...string) remediation.RebuildPackage {
	return remediation.RebuildPackage{Name: "org.jsoup:jsoup", Version: "1.21.2", Class: inventory.ClassLang, Ecosystem: "jar", Type: "jar", Path: path, VulnIDs: vulns}
}

func TestCardBase_RebuildOnTheCurrentBase(t *testing.T) {
	const a, b, path = "CVE-2031-1111", "CVE-2031-2222", "usr/lib/a/jsoup.jar"
	checked := func(c remediation.RebuildCheck) *PlanInfo {
		c.Status = remediation.RebuildChecked
		return movedBase(t, &c)
	}
	otherEcosystem, otherVersion := jsoupRebuild(path, a, b), jsoupRebuild(path, a, b)
	otherEcosystem.Ecosystem = "gobinary"
	otherVersion.Version = "1.20.0"
	old := jsoupRebuild(path, a, b)
	old.Ecosystem, old.Type = "", ""
	runBaseCases(t, baseWaitReport(t), []baseCase{
		{"gone", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}}),
			"再ビルドで解消する見込み（現在の元イメージ elasticsearch 8.19.23 では修正済み）",
			"a rebuild is expected to resolve it (fixed in the current base image elasticsearch 8.19.23)"},
		{"partly gone", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a)}, Remaining: []remediation.RebuildPackage{jsoupRebuild(path, b)}}),
			"再ビルドで一部解消する見込み（2件中1件、現在の元イメージ elasticsearch 8.19.23 との比較）",
			"a rebuild is expected to resolve part of it (1 of 2, compared with the current base image elasticsearch 8.19.23)"},
		{"remains", checked(remediation.RebuildCheck{Remaining: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}}),
			"元イメージ elasticsearch 8.19.23 の新しい内容待ち（現在の内容にも残る）",
			"waiting for new content of base image elasticsearch 8.19.23 (still present in its current content)"},
		{"not in the base", checked(remediation.RebuildCheck{NotInBase: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}}),
			"再ビルドで解消するか確認できない（現在の元イメージに同じ場所のパッケージがない）",
			"whether a rebuild resolves it could not be confirmed (the current base image has no package at the same location)"},
		{"a partial check still names the card's findings", func() *PlanInfo {
			p := checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}, Undetermined: 3})
			p.Plan.DockerfileItems[0].Entities[0].RebuildCheck.Status = remediation.RebuildPartial
			return p
		}(),
			"再ビルドで解消する見込み（現在の元イメージ elasticsearch 8.19.23 では修正済み）",
			"a rebuild is expected to resolve it (fixed in the current base image elasticsearch 8.19.23)"},

		{"one finding not judged", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a)}}), "", ""},
		{"gone and not in the base", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a)}, NotInBase: []remediation.RebuildPackage{jsoupRebuild(path, b)}}), "", ""},
		{"another place", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild("app/lib/jsoup.jar", a, b)}}), "", ""},
		{"another ecosystem", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{otherEcosystem}}), "", ""},
		{"another version", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{otherVersion}}), "", ""},
		{"a record without the ecosystem", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{old}}), "", ""},
		{"only in the base", checked(remediation.RebuildCheck{OnlyInBase: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}}), "", ""},
		{"not compared", movedBase(t, &remediation.RebuildCheck{Status: remediation.RebuildNotChecked, Reason: remediation.ReasonBaselineRescanLimit,
			Gone: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}}), "", ""},
		{"no check", movedBase(t, nil), "", ""},
	})

	// The same package in two places: every place needs the same verdict.
	two := append(baseWaitFindings(), jsoupFinding("1.21.2", a, baseLayer, "usr/lib/b/jsoup.jar"), jsoupFinding("1.21.2", b, baseLayer, "usr/lib/b/jsoup.jar"))
	r := baseWaitReportOf(t, baseWaitScan(t, "a", two))
	const other = "usr/lib/b/jsoup.jar"
	runBaseCases(t, r, []baseCase{
		{"both places gone", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a, b), jsoupRebuild(other, a, b)}}),
			"再ビルドで解消する見込み（現在の元イメージ elasticsearch 8.19.23 では修正済み）",
			"a rebuild is expected to resolve it (fixed in the current base image elasticsearch 8.19.23)"},
		{"one place gone, the other remains", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}, Remaining: []remediation.RebuildPackage{jsoupRebuild(other, a, b)}}), "", ""},
		{"one place not judged", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}}), "", ""},
	})

	// An OS package has its place by its name.
	osf := func(id string) scanner.Finding {
		return scanner.Finding{Image: baseWaitImage, Class: scanner.ClassOS, Package: "libcurl", InstalledVer: "8.20.0-r1", FixedVer: "8.21.0-r0",
			Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: id, Type: "alpine", Target: "shop-es:1 (alpine 3.22)", LayerDiffID: baseLayer}
	}
	r = baseWaitReportOf(t, baseWaitScan(t, "a", []scanner.Finding{osf(a), osf(b)}))
	libcurl := remediation.RebuildPackage{Name: "libcurl", Version: "8.20.0-r1", Class: inventory.ClassOS, Ecosystem: "alpine", Type: "alpine", BaseVersion: "8.21.0-r0", VulnIDs: []string{a, b}}
	runBaseCases(t, r, []baseCase{
		{"an OS package gone", checked(remediation.RebuildCheck{Gone: []remediation.RebuildPackage{libcurl}}),
			"再ビルドで解消する見込み（現在の元イメージ elasticsearch 8.19.23 では修正済み）",
			"a rebuild is expected to resolve it (fixed in the current base image elasticsearch 8.19.23)"},
	})

	// A language runtime is compared by the version the base declares.
	r = baseWaitReportOf(t, baseWaitScan(t, "a", nodeRuntimeFindings()))
	rr := func(dis, rem []string) remediation.RuntimeRebuild {
		return remediation.RuntimeRebuild{Package: inventory.NodeRuntimePackage, Installed: "24.1.0", BaseVersion: "24.2.0", Disappearing: dis, Remaining: rem}
	}
	otherInstalled := rr([]string{a, b}, nil)
	otherInstalled.Installed = "22.0.0"
	runBaseCases(t, r, []baseCase{
		{"runtime gone", movedBase(t, nil, rr([]string{a, b}, nil)),
			"再ビルドで解消する見込み（現在の元イメージ elasticsearch 8.19.23 では修正済み）",
			"a rebuild is expected to resolve it (fixed in the current base image elasticsearch 8.19.23)"},
		{"runtime partly gone", movedBase(t, nil, rr([]string{a}, []string{b})),
			"再ビルドで一部解消する見込み（2件中1件、現在の元イメージ elasticsearch 8.19.23 との比較）",
			"a rebuild is expected to resolve part of it (1 of 2, compared with the current base image elasticsearch 8.19.23)"},
		{"runtime remains", movedBase(t, nil, rr(nil, []string{a, b})),
			"元イメージ elasticsearch 8.19.23 の新しい内容待ち（現在の内容にも残る）",
			"waiting for new content of base image elasticsearch 8.19.23 (still present in its current content)"},
		{"runtime, a finding not named", movedBase(t, nil, rr([]string{a}, nil)), "", ""},
		{"runtime of another version", movedBase(t, nil, otherInstalled), "", ""},
	})
}

// A rebuild line does not stand in for the dependency files, and a finding
// the comparison says nothing of is left to the image's own tag.
func TestCardBase_RebuildYieldsAndFallsThrough(t *testing.T) {
	const a, b, path = "CVE-2031-1111", "CVE-2031-2222", "usr/lib/a/jsoup.jar"
	gone := func() *PlanInfo {
		return movedBase(t, &remediation.RebuildCheck{Status: remediation.RebuildChecked, Gone: []remediation.RebuildPackage{jsoupRebuild(path, a, b)}})
	}
	f := baseWaitFindings()[0]
	ref := f.PackageRef()
	p := gone()
	p.Plan.LanguageItems = []remediation.LanguageItem{{Key: "deps:ex/es@main:.#maven", Packages: []remediation.LanguagePackage{{
		Name: f.Package, Installed: f.InstalledVer, Action: remediation.ActionUpdate,
		Origins: []remediation.FindingOrigin{{Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a")), Ecosystem: string(ref.Ecosystem),
			Class: string(ref.Class), Name: f.Package, Version: f.InstalledVer, VulnID: f.VulnID, PkgPath: f.PkgPath}},
	}}}}
	if got := actionLineOf(t, baseWaitReport(t), p, LanguageEN); got != "" {
		t.Errorf("a card of a dependency file's finding has the line %q", got)
	}
	// Nothing of the card in the comparison: the image's own tag answers.
	p = movedBase(t, &remediation.RebuildCheck{Status: remediation.RebuildChecked})
	p.Plan.Items = itemPlan(t, remediation.TagFloating, remediation.CategoryPullAgain, remediation.ReasonAdopted, true, resolved(), resolved()).Plan.Items
	if got, want := actionLineOf(t, baseWaitReport(t), p, LanguageEN), "pulling image shop-es 1 again resolves it"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCardBase_MergedUpdateNotRebuilt(t *testing.T) {
	link := "<https://github.com/ex/es/pull/13|#13>"
	entity := remediation.EntityKeyString(baseWaitKeyOf(t, "a"))
	merged := func(change func(*remediation.BaseUpdateMerged)) *PlanInfo {
		p := basePlan(t, remediation.TagPinned, remediation.CategoryNotComparable, remediation.ReasonBaseUpdateNotDeployed,
			remediation.CategoryNotComparable, remediation.ReasonBaseLayersMismatch)
		it := &p.Plan.DockerfileItems[0]
		it.Entities[0].Targets = nil
		m := &remediation.BaseUpdateMerged{Number: 13, URL: "https://github.com/ex/es/pull/13", From: "elasticsearch:8.19.23", To: "8.19.24"}
		for _, tg := range jsoupTargets() {
			m.FixTargets = append(m.FixTargets, remediation.FixTarget{Location: "stages[0]", VulnID: tg.VulnID, Package: tg.Package,
				Layers: []string{baseLayer}, Entities: []string{baseWaitImage + "|" + entity}})
		}
		if change != nil {
			change(m)
		}
		it.AwaitingDeploy = m
		return p
	}
	runBaseCases(t, baseWaitReport(t), []baseCase{
		{"the pull request resolves the card's findings", merged(nil),
			"Pull Request " + link + " はマージ済み、イメージの再ビルド待ち",
			"Pull Request " + link + " is merged; waiting for the image to be rebuilt"},
		{"one finding is not its target", merged(func(m *remediation.BaseUpdateMerged) { m.FixTargets = m.FixTargets[:1] }), "", ""},
		{"resolved for another image", merged(func(m *remediation.BaseUpdateMerged) {
			for i := range m.FixTargets {
				m.FixTargets[i].Entities = []string{"other:1|" + entity}
			}
		}), "", ""},
		{"in other layers", merged(func(m *remediation.BaseUpdateMerged) {
			for i := range m.FixTargets {
				m.FixTargets[i].Layers = []string{"sha256:other"}
			}
		}), "", ""},
		{"layers not recorded", merged(func(m *remediation.BaseUpdateMerged) {
			for i := range m.FixTargets {
				m.FixTargets[i].Layers, m.FixTargets[i].LayersDigest = nil, "sha256:digest"
			}
		}), "", ""},
		{"no targets recorded", merged(func(m *remediation.BaseUpdateMerged) { m.FixTargets = nil }), "", ""},
	})
}

func TestCardBase_LineInThreadAndEmail(t *testing.T) {
	r := baseWaitReport(t)
	p := adoptedBase(t, resolved(), resolved())
	want := "対応: 元イメージ elasticsearch 8.19.23 → 8.19.24 で解消（ベースの比較）"
	thread := allBlocksText(buildThreadBlockMessagesWithPlan(r, Ages{}, p, jaMessages, defaultRenderLimits))
	if n := countLines(thread, want); n != 1 {
		t.Errorf("thread: the line appears %d times:\n%s", n, thread)
	}
}

func countLines(text, line string) int {
	n := 0
	for _, l := range splitLines(text) {
		if l == line {
			n++
		}
	}
	return n
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// A card the base has no line for keeps the line of the image's own tag it
// had before: the candidate of the image's own series, and the wait a check
// of newer series gives.
func TestCardBase_NoLineLeavesTheImageItsOwn(t *testing.T) {
	// The package is in a base layer and in a later one, so it is not the
	// base's alone, whatever the Dockerfile part found for its targets.
	fs := baseWaitFindings()
	upper := append(fs, jsoupFinding("1.21.2", "CVE-2031-1111", "sha256:app-layer", "app/lib/jsoup.jar"), jsoupFinding("1.21.2", "CVE-2031-2222", "sha256:app-layer", "app/lib/jsoup.jar"))
	r := baseWaitReportOf(t, baseWaitScan(t, "a", upper))
	bases := map[string]func() *PlanInfo{
		"no newer tag": func() *PlanInfo { return baseWaitNoNewer(t) },
		"adopted":      func() *PlanInfo { return adoptedBase(t, resolved(), resolved()) },
		"base unchanged": func() *PlanInfo {
			return basePlan(t, remediation.TagFloating, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged)
		},
	}
	for name, base := range bases {
		p := candidatePlan(t, resolved(), resolved())
		p.Plan.DockerfileItems = base().Plan.DockerfileItems
		if got, want := actionLineOf(t, r, p, LanguageEN), "image shop-es 1 → 1.0.1 resolves it"; got != want {
			t.Errorf("%s, candidate of the image: got %q, want %q", name, got, want)
		}
		p = imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesNone, ""))
		p.Plan.DockerfileItems = base().Plan.DockerfileItems
		want := "waiting for a newer image of shop-es 1 (no newer tag in the same series or in a newer series of the same form)"
		if got := actionLineOf(t, r, p, LanguageEN); got != want {
			t.Errorf("%s, newer series of the image: got %q, want %q", name, got, want)
		}
	}
	// The same holds for a card only part of whose findings are the base's
	// targets.
	p := candidatePlan(t, resolved(), resolved())
	p.Plan.DockerfileItems = adoptedBase(t, resolved(), resolved()).Plan.DockerfileItems
	e := &p.Plan.DockerfileItems[0].Entities[0]
	e.Targets = e.Targets[:1]
	if got, want := actionLineOf(t, baseWaitReport(t), p, LanguageEN), "image shop-es 1 → 1.0.1 resolves it"; got != want {
		t.Errorf("partly targeted by the base: got %q, want %q", got, want)
	}
}
