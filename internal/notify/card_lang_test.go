package notify

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	langItemKey = "deps:ex/api@main:.#pnpm"
	langUnitKey = "language|ex/api|main|pnpm-lock.yaml"
)

// multerFindings are two findings of multer 2.0.0 as the application's
// dependency files install it.
func multerFindings() []scanner.Finding {
	const path = "app/node_modules/multer/package.json"
	return []scanner.Finding{nodeFinding("multer", "2.0.0", "CVE-2031-0011", path), nodeFinding("multer", "2.0.0", "CVE-2031-0012", path)}
}

func multerReport(t *testing.T) analyze.Report { return globalReport(t, multerFindings()...) }

// multerPlan is a plan whose pnpm item holds multer with the action and
// reason given, and the item's own outcome.
func multerPlan(t *testing.T, cat remediation.Category, itemReason remediation.Reason, action remediation.PackageAction, reason remediation.Reason) *PlanInfo {
	p := langPackage(t, reason, multerFindings()...)
	p.Action, p.SelectionLowerBound = action, "2.0.3"
	li := remediation.LanguageItem{Key: langItemKey, Manager: remediation.ManagerPnpm, Category: cat, Reason: itemReason, Packages: []remediation.LanguagePackage{p}}
	return &PlanInfo{Plan: &remediation.Plan{LanguageItems: []remediation.LanguageItem{li}}}
}

// updatedPlan is a plan whose update of multer to 2.0.4 was run and checked.
func updatedPlan(t *testing.T) *PlanInfo {
	p := multerPlan(t, remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified, remediation.ActionUpdate, remediation.ReasonUpdateVerified)
	p.Plan.LanguageItems[0].Packages[0].AdoptedVersion = "2.0.4"
	return p
}

// langUnit is the unit of the item's update: with a number it is a pull
// request that moves multer to 2.0.4.
func langUnit(status remediation.PRUnitStatus, number int) remediation.PRUnit {
	u := remediation.PRUnit{Kind: "language", Key: langUnitKey, ItemKey: langItemKey, Repo: "ex/api", Path: "pnpm-lock.yaml", Status: status, Number: number,
		Language: &remediation.PRLanguage{Manager: "pnpm", Root: ".", Packages: []remediation.PRLanguagePackage{{Name: "multer", Ecosystem: "node-pkg", From: "2.0.0", To: "2.0.4"}}}}
	if number > 0 {
		u.URL = "https://github.com/ex/api/pull/12"
	}
	return u
}

func langAssigned() []remediation.PRItemResult {
	return []remediation.PRItemResult{{Kind: remediation.PRItemKindLanguage, ItemKey: langItemKey, UnitKeys: []string{langUnitKey}, Status: remediation.PRItemAssigned}}
}

func TestCardLang_PullRequestOfTheUpdate(t *testing.T) {
	link := "<https://github.com/ex/api/pull/12|#12>"
	withUnit := func(p *PlanInfo, u remediation.PRUnit) *PlanInfo { return withPR(p, langAssigned(), u) }
	replaced := langUnit(remediation.PRStatusSuppressed, 12)
	replaced.ReplacedBy = 13
	modified := langUnit(remediation.PRStatusOpen, 12)
	modified.UserModified = true
	noView := langUnit(remediation.PRStatusOpen, 12)
	noView.Language = nil
	leaves := langUnit(remediation.PRStatusOpen, 12)
	leaves.Language.Packages = []remediation.PRLanguagePackage{{Name: "express", Ecosystem: "node-pkg", From: "4.0.0", To: "4.1.0"}}
	leaves.Language.Remaining = []remediation.PRLanguageRemaining{{Name: "multer", Ecosystem: "node-pkg", From: "2.0.0", Target: "2.0.3", Reason: remediation.ReasonTargetNotUpdated}}
	leavesTied := langUnit(remediation.PRStatusOpen, 12)
	leavesTied.Language.Packages = leaves.Language.Packages
	leavesTied.Language.Remaining = []remediation.PRLanguageRemaining{{Name: "multer", Ecosystem: "node-pkg", From: "2.0.0", Target: "2.0.3", Reason: remediation.ReasonPostUpdateCheckFailed}}
	otherVersion := langUnit(remediation.PRStatusOpen, 12)
	otherVersion.Language.Packages[0].From = "1.9.0"
	// A tied item was not updated again: the pull request made from the same
	// inputs stands for it, and names the version.
	tied := func() *PlanInfo {
		p := updatedPlan(t)
		li := &p.Plan.LanguageItems[0]
		li.Reason, li.Packages[0].AdoptedVersion, li.Packages[0].Reason = remediation.ReasonUpdateAlreadyProposed, "", ""
		return p
	}
	left := func() *PlanInfo {
		p := updatedPlan(t)
		pkg := &p.Plan.LanguageItems[0].Packages[0]
		pkg.Action, pkg.Reason, pkg.LeftOut, pkg.AdoptedVersion = remediation.ActionManual, remediation.ReasonTargetNotUpdated, true, ""
		return p
	}
	runBaseCases(t, multerReport(t), []baseCase{
		{"created", withUnit(updatedPlan(t), langUnit(remediation.PRStatusCreated, 12)),
			"Pull Request " + link + " で 2.0.4 に更新",
			"updated to 2.0.4 in Pull Request " + link},
		{"open, tied", withUnit(tied(), langUnit(remediation.PRStatusOpen, 12)),
			"Pull Request " + link + " で 2.0.4 に更新",
			"updated to 2.0.4 in Pull Request " + link},
		{"merged", withUnit(tied(), langUnit(remediation.PRStatusMerged, 12)),
			"Pull Request " + link + " で 2.0.4 に更新、マージ済み、稼働中のイメージには未反映",
			"updated to 2.0.4 in Pull Request " + link + "; merged, but not yet in the running image"},
		{"closed", withUnit(tied(), langUnit(remediation.PRStatusSuppressed, 12)),
			"Pull Request " + link + " で 2.0.4 に更新する変更は未マージでクローズ",
			"the update to 2.0.4 in Pull Request " + link + " was closed without merging"},
		{"replaced", withUnit(tied(), replaced),
			"Pull Request " + link + " で 2.0.4 に更新する変更は未マージでクローズ、#13 に置き換え",
			"the update to 2.0.4 in Pull Request " + link + " was closed without merging and replaced by #13"},
		{"the pull request leaves the package out", withUnit(left(), leaves),
			"pnpm-lock.yaml では自動修正できない（" + planReasonText(LanguageJA, "target_not_updated") + "）",
			"it could not be fixed automatically through pnpm-lock.yaml (" + planReasonText(LanguageEN, "target_not_updated") + ")"},
		// The record of the pull request leaves the package out although the
		// item still plans its update: the record's reason is stated.
		{"left out by the record of the pull request", withUnit(tied(), leavesTied),
			"pnpm-lock.yaml では自動修正できない（" + planReasonText(LanguageJA, "post_update_check_failed") + "）",
			"it could not be fixed automatically through pnpm-lock.yaml (" + planReasonText(LanguageEN, "post_update_check_failed") + ")"},
		{"changed by a person", withUnit(tied(), modified),
			"pnpm-lock.yaml の更新内容を確認できない（" + planReasonText(LanguageJA, "pull_request_not_as_created") + "）",
			"the update to pnpm-lock.yaml could not be confirmed (" + planReasonText(LanguageEN, "pull_request_not_as_created") + ")"},
		{"no record of its packages", withUnit(tied(), noView),
			"pnpm-lock.yaml の更新内容を確認できない",
			"the update to pnpm-lock.yaml could not be confirmed"},
		// The pull request names another version of the package: it says
		// nothing of this one, and a tied package has no version of its own.
		{"another version in the pull request", withUnit(tied(), otherVersion), "", ""},
		// The unit of another item is not this item's.
		{"the unit of another item", func() *PlanInfo {
			u := langUnit(remediation.PRStatusOpen, 12)
			u.ItemKey = "deps:ex/other@main:.#pnpm"
			return withUnit(tied(), u)
		}(), "", ""},
	})
}

func TestCardLang_CandidatesAndRebuild(t *testing.T) {
	manualUnit := langUnit(remediation.PRUnitStatus("manual"), 0)
	manualUnit.Reason = remediation.ReasonArtifactsUnusable
	candidate := func() *PlanInfo {
		return multerPlan(t, remediation.CategoryDependencyUpdateCandidate, remediation.ReasonUpdateCandidateInSource, remediation.ActionUpdate, "")
	}
	noBound := candidate()
	noBound.Plan.LanguageItems[0].Packages[0].SelectionLowerBound = ""
	rebuild := multerPlan(t, remediation.CategoryRebuildExpected, remediation.ReasonRangeAllowsFix, remediation.ActionRebuildExpected, remediation.ReasonRangeAllowsFix)
	rebuild.Plan.LanguageItems[0].Packages[0].Action = remediation.ActionRebuildExpected
	noVersion := updatedPlan(t)
	noVersion.Plan.LanguageItems[0].Packages[0].AdoptedVersion = ""
	noManager := updatedPlan(t)
	noManager.Plan.LanguageItems[0].Manager = ""
	on := true
	candidateOn := candidate()
	candidateOn.Plan.PullRequestsEnabled = &on
	// With pull requests off, a unit that has a number is not this cycle's
	// to state.
	off := updatedPlan(t)
	off.Plan.PullRequests = []remediation.PRUnit{langUnit(remediation.PRStatusOpen, 12)}
	runBaseCases(t, multerReport(t), []baseCase{
		{"updated, pull requests off", updatedPlan(t),
			"pnpm-lock.yaml の更新で 2.0.4 に上げる候補",
			"candidate to update to 2.0.4 through pnpm-lock.yaml"},
		{"updated, the unit has no pull request", withPR(updatedPlan(t), langAssigned(), manualUnit),
			"pnpm-lock.yaml の更新で 2.0.4 に上げる候補（Pull Request は未作成: " + planReasonText(LanguageJA, "artifacts_unusable") + "）",
			"candidate to update to 2.0.4 through pnpm-lock.yaml (Pull Request not created: " + planReasonText(LanguageEN, "artifacts_unusable") + ")"},
		{"updated, the stage did not run", withPR(updatedPlan(t), []remediation.PRItemResult{
			{Kind: remediation.PRItemKindLanguage, ItemKey: langItemKey, Status: remediation.PRItemNotProcessed, Reason: remediation.ReasonStorageFailed}}),
			"pnpm-lock.yaml の更新で 2.0.4 に上げる候補（Pull Request は未作成: " + planReasonText(LanguageJA, "storage_failed") + "）",
			"candidate to update to 2.0.4 through pnpm-lock.yaml (Pull Request not created: " + planReasonText(LanguageEN, "storage_failed") + ")"},
		{"updated, a unit with a number and pull requests off", off,
			"pnpm-lock.yaml の更新で 2.0.4 に上げる候補",
			"candidate to update to 2.0.4 through pnpm-lock.yaml"},
		{"updated, no version recorded", noVersion, "", ""},
		{"updated, no file name", noManager,
			"依存ファイル の更新で 2.0.4 に上げる候補",
			"candidate to update to 2.0.4 through the dependency files"},

		{"not updated yet, pull requests off", candidate(),
			"pnpm-lock.yaml の更新で 2.0.3 以上に上げる候補",
			"candidate to update to 2.0.3 or later through pnpm-lock.yaml"},
		{"not updated yet, pull requests on", candidateOn,
			"pnpm-lock.yaml の更新で 2.0.3 以上に上げる候補（Pull Request は未作成: 依存ファイルの更新結果は未確認）",
			"candidate to update to 2.0.3 or later through pnpm-lock.yaml (Pull Request not created: the dependency-file update has not been verified)"},
		{"not updated yet, no version chosen", noBound, "", ""},

		{"a rebuild is expected to take it", rebuild,
			"再ビルドで 2.0.3 以上が入る見込み",
			"a rebuild is expected to install 2.0.3 or later"},
	})
}

func TestCardLang_NotUpdated(t *testing.T) {
	manual := remediation.ActionManual
	leftOut := multerPlan(t, remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified, manual, remediation.ReasonTargetNotUpdated)
	leftOut.Plan.LanguageItems[0].Packages[0].LeftOut = true
	// A package left out of an update that then failed keeps its own reason
	// beside the item's.
	leftOutSame := multerPlan(t, remediation.CategoryManual, remediation.ReasonTargetNotUpdated, manual, remediation.ReasonTargetNotUpdated)
	leftOutSame.Plan.LanguageItems[0].Packages[0].LeftOut = true
	jaOf := func(code string) string { return planReasonText(LanguageJA, code) }
	enOf := func(code string) string { return planReasonText(LanguageEN, code) }
	runBaseCases(t, multerReport(t), []baseCase{
		{"the package's own reason", multerPlan(t, remediation.CategoryDependencyUpdateCandidate, remediation.ReasonUpdateCandidateInSource, manual, remediation.ReasonRangeExcludesFix),
			"pnpm-lock.yaml では自動修正できない（" + jaOf("constraint_excludes_fix") + "）",
			"it could not be fixed automatically through pnpm-lock.yaml (" + enOf("constraint_excludes_fix") + ")"},
		{"its own reason in an item of another", multerPlan(t, remediation.CategoryManual, remediation.ReasonPackagesManual, manual, remediation.ReasonRangeExcludesFix),
			"pnpm-lock.yaml では自動修正できない（" + jaOf("constraint_excludes_fix") + "）",
			"it could not be fixed automatically through pnpm-lock.yaml (" + enOf("constraint_excludes_fix") + ")"},
		{"left out of the update", leftOut,
			"pnpm-lock.yaml では自動修正できない（" + jaOf("target_not_updated") + "）",
			"it could not be fixed automatically through pnpm-lock.yaml (" + enOf("target_not_updated") + ")"},
		{"left out, the item has the same reason", leftOutSame,
			"pnpm-lock.yaml では自動修正できない（" + jaOf("target_not_updated") + "）",
			"it could not be fixed automatically through pnpm-lock.yaml (" + enOf("target_not_updated") + ")"},

		{"the update of the item failed", multerPlan(t, remediation.CategoryFailed, remediation.ReasonUpdateJobFailed, manual, remediation.ReasonUpdateJobFailed),
			"pnpm-lock.yaml を更新できない（" + jaOf("update_job_failed") + "）",
			"pnpm-lock.yaml could not be updated (" + enOf("update_job_failed") + ")"},
		{"the files cannot be used", multerPlan(t, remediation.CategoryManual, remediation.ReasonAmbiguousDependencyFile, manual, remediation.ReasonAmbiguousDependencyFile),
			"pnpm-lock.yaml を更新できない（" + jaOf("ambiguous_dependency_files") + "）",
			"pnpm-lock.yaml could not be updated (" + enOf("ambiguous_dependency_files") + ")"},
		// The binary could not be compared with go.mod: that is the item's
		// outcome, not a package the file cannot reach.
		{"the files could not be compared with the image", multerPlan(t, remediation.CategoryManual, remediation.ReasonGoBinaryNotFromSource, manual, remediation.ReasonGoBinaryNotFromSource),
			"pnpm-lock.yaml を更新できない（" + jaOf("go_binary_not_from_source") + "）",
			"pnpm-lock.yaml could not be updated (" + enOf("go_binary_not_from_source") + ")"},
		{"the item failed, the package was not matched", multerPlan(t, remediation.CategoryFailed, remediation.ReasonSourceError, "", ""),
			"pnpm-lock.yaml を更新できない（" + jaOf("source_error") + "）",
			"pnpm-lock.yaml could not be updated (" + enOf("source_error") + ")"},

		{"the update was left to a later run", multerPlan(t, remediation.CategoryDeferred, remediation.ReasonCycleDeadline, remediation.ActionUpdate, ""),
			"pnpm-lock.yaml の更新は次回以降（" + jaOf("cycle_deadline") + "）",
			"updating pnpm-lock.yaml is deferred to a later run (" + enOf("cycle_deadline") + ")"},
		{"left to a later run, the package was not matched", multerPlan(t, remediation.CategoryDeferred, remediation.ReasonCycleDeadline, "", ""),
			"pnpm-lock.yaml の更新は次回以降（" + jaOf("cycle_deadline") + "）",
			"updating pnpm-lock.yaml is deferred to a later run (" + enOf("cycle_deadline") + ")"},

		{"the files do not hold the package", multerPlan(t, remediation.CategoryManual, remediation.ReasonNotFoundInSource, manual, remediation.ReasonNotFoundInSource),
			"pnpm-lock.yaml の更新では直せない（" + jaOf("not_found_in_source") + "）",
			"updating pnpm-lock.yaml cannot fix it (" + enOf("not_found_in_source") + ")"},

		{"no reason", multerPlan(t, remediation.CategoryManual, "", manual, ""), "", ""},
		{"an item with no reason, the package not matched", multerPlan(t, remediation.CategoryDeferred, "", "", ""), "", ""},
		{"a planned update in an item that proposes a rebuild", multerPlan(t, remediation.CategoryRebuildExpected, remediation.ReasonRangeAllowsFix, remediation.ActionUpdate, ""), "", ""},
	})
}

// Every fixed finding of the card has to come from the same package of the
// same item.
func TestCardLang_NeedsOnePackageOfOneItem(t *testing.T) {
	r := multerReport(t)
	// One of the card's findings is not in the plan.
	p := updatedPlan(t)
	pkg := &p.Plan.LanguageItems[0].Packages[0]
	pkg.Origins = pkg.Origins[:1]
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a partly covered package has the line %q", got)
	}
	// Two items hold the package.
	p = updatedPlan(t)
	other := updatedPlan(t).Plan.LanguageItems[0]
	other.Key = "deps:ex/other@main:.#pnpm"
	p.Plan.LanguageItems = append(p.Plan.LanguageItems, other)
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a package of two items has the line %q", got)
	}
	// Another running entity is not the one the plan matched.
	key := baseWaitKeyOf(t, "d")
	otherEntity := analyze.Build([]scanner.ImageScan{{Image: globalImage, Subject: inventory.ImageSubject{Ref: globalImage, Key: key, Resolved: true}, ScannedKey: key, Pinned: true,
		Source: scanner.SourceLocal, Findings: multerFindings()}}, nil, analyze.Triage{}, genTime)
	if got := actionLineOf(t, otherEntity, updatedPlan(t), LanguageEN); got != "" {
		t.Errorf("another entity has the line %q", got)
	}
	// Another version of the package is another card.
	older := globalReport(t, nodeFinding("multer", "1.9.0", "CVE-2031-0011", "app/node_modules/multer/package.json"))
	if got := actionLineOf(t, older, updatedPlan(t), LanguageEN); got != "" {
		t.Errorf("another version has the line %q", got)
	}
}

// jsoupLangPlan is p with a Maven item that holds jsoup (the card of
// baseWaitReport) with the reason given.
func jsoupLangPlan(t *testing.T, p *PlanInfo, reason remediation.Reason) *PlanInfo {
	fs := baseWaitFindings()[:2]
	pkg := remediation.LanguagePackage{Name: fs[0].Package, Ecosystem: fs[0].Type, Installed: fs[0].InstalledVer, Action: remediation.ActionManual, Reason: reason}
	for _, f := range fs {
		ref := f.PackageRef()
		pkg.Origins = append(pkg.Origins, remediation.FindingOrigin{Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a")), Ecosystem: string(ref.Ecosystem),
			Class: string(ref.Class), Name: f.Package, Version: f.InstalledVer, VulnID: f.VulnID, PkgPath: f.PkgPath})
	}
	p.Plan.LanguageItems = []remediation.LanguageItem{{Key: "deps:ex/es@main:.#maven", Manager: remediation.ManagerMaven,
		Category: remediation.CategoryManual, Reason: remediation.ReasonPackagesManual, Packages: []remediation.LanguagePackage{pkg}}}
	return p
}

// The dependency files come first for a package they can reach; one they
// cannot reach is left to the images, and what the files say of it comes
// only when the images say nothing.
func TestCardLang_OrderAmongTheSources(t *testing.T) {
	r := baseWaitReport(t)
	reach, noReach := remediation.ReasonRangeExcludesFix, remediation.ReasonJarBundled
	filesLine := "it could not be fixed automatically through pom.xml (" + planReasonText(LanguageEN, "constraint_excludes_fix") + ")"
	noReachLine := "updating pom.xml cannot fix it (" + planReasonText(LanguageEN, "jar_bundled_copy") + ")"
	baseLine := "base image elasticsearch 8.19.23 → 8.19.24 resolves it (base images compared)"
	waitLine := "waiting for a newer base image of elasticsearch 8.19.23 (no newer tag in the same series)"
	imageLine := "image shop-es 1 → 1.0.1 resolves it"
	noPlace := func(p *PlanInfo) *PlanInfo {
		os := p.Plan.LanguageItems[0].Packages[0].Origins
		os[0].PkgPath = ""
		return p
	}
	cases := []struct {
		name string
		plan *PlanInfo
		want string
	}{
		{"reachable, beside a line of the base", jsoupLangPlan(t, adoptedBase(t, resolved(), resolved()), reach), filesLine},
		{"reachable, beside a wait of the base", jsoupLangPlan(t, baseWaitNoNewer(t), reach), filesLine},
		{"reachable, beside a candidate of the image", jsoupLangPlan(t, candidatePlan(t, resolved(), resolved()), reach), filesLine},
		{"not compared, beside a line of the base", jsoupLangPlan(t, adoptedBase(t, resolved(), resolved()), remediation.ReasonGoBinaryNotFromSource),
			"it could not be fixed automatically through pom.xml (" + planReasonText(LanguageEN, "go_binary_not_from_source") + ")"},
		// A finding that names no archive is not shown to be a bundled copy:
		// nothing is said of it, and the images do not answer in its place.
		{"bundled without a place, beside a line of the base", noPlace(jsoupLangPlan(t, adoptedBase(t, resolved(), resolved()), noReach)), ""},
		{"bundled without a place, nothing else", noPlace(jsoupLangPlan(t, &PlanInfo{Plan: &remediation.Plan{}}, noReach)), ""},
		{"out of reach, beside a line of the base", jsoupLangPlan(t, adoptedBase(t, resolved(), resolved()), noReach), baseLine},
		{"out of reach, beside a wait of the base", jsoupLangPlan(t, baseWaitNoNewer(t), noReach), waitLine},
		{"out of reach, beside a candidate of the image", jsoupLangPlan(t, candidatePlan(t, resolved(), resolved()), noReach), imageLine},
		{"out of reach, nothing else", jsoupLangPlan(t, &PlanInfo{Plan: &remediation.Plan{}}, noReach), noReachLine},
		// The image's own tag says nothing of an image a mapped Dockerfile
		// builds: the files' line is all there is.
		{"out of reach, the images have no line", jsoupLangPlan(t, itemPlan(t, remediation.TagFloating, remediation.CategoryNoCandidate, remediation.ReasonSameContent, false), noReach),
			"waiting for new content of image shop-es 1 (the tag has the same content as the running image)"},
	}
	for _, c := range cases {
		if got := actionLineOf(t, r, c.plan, LanguageEN); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
	// A package the files can reach and have no line for keeps the images
	// from stating what they would of it, as before.
	p := jsoupLangPlan(t, adoptedBase(t, resolved(), resolved()), reach)
	p.Plan.LanguageItems[0].Packages[0].Reason = ""
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a reachable package without a line: got %q", got)
	}
}

func TestCardLang_LineInThread(t *testing.T) {
	p := withPR(updatedPlan(t), langAssigned(), langUnit(remediation.PRStatusOpen, 12))
	want := "対応: Pull Request <https://github.com/ex/api/pull/12|#12> で 2.0.4 に更新"
	thread := allBlocksText(buildThreadBlockMessagesWithPlan(multerReport(t), Ages{}, p, jaMessages, defaultRenderLimits))
	if n := countLines(thread, want); n != 1 {
		t.Errorf("thread: the line appears %d times:\n%s", n, thread)
	}
}
