package notify

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	candItemKey  = baseWaitImage + "|a"
	candUnitKey  = "compose|ex/shop|main|compose.yml|shop-es:1"
	candWorkload = "compose/shop/es"
)

// candidatePlan is a plan whose pinned running image baseWaitImage (entity
// "a") has the candidate tag 1.0.1 in its own series, with the outcome of
// each jsoup target in outs, in order. A target without an outcome has no
// verdict.
func candidatePlan(t *testing.T, outs ...remediation.Outcome) *PlanInfo {
	ts := jsoupTargets()
	vr := &remediation.VerificationResult{Comparable: true}
	for i, o := range outs {
		vr.Verdicts = append(vr.Verdicts, remediation.VulnVerdict{VulnID: ts[i].VulnID, Package: ts[i].Package, Outcome: o})
	}
	it := remediation.Item{
		Key: candItemKey, Kind: remediation.TagPinned, Category: remediation.CategoryPRCandidate, Reason: remediation.ReasonAdopted,
		Services:   []remediation.ServiceRef{{Project: "shop", Service: "es"}},
		Current:    remediation.ImageState{Ref: baseWaitImage, Tag: "1", Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a"))},
		Candidate:  &remediation.ImageState{Ref: "shop-es:1.0.1", Tag: "1.0.1"},
		Targets:    ts,
		Comparison: vr,
	}
	return &PlanInfo{Plan: &remediation.Plan{Items: []remediation.Item{it}}}
}

// withPR turns pull requests on in the plan and records what the stage did
// with the candidate item.
func withPR(p *PlanInfo, items []remediation.PRItemResult, units ...remediation.PRUnit) *PlanInfo {
	on := true
	p.Plan.PullRequestsEnabled = &on
	p.Plan.PRItems = items
	p.Plan.PullRequests = units
	return p
}

func assigned(unitKeys ...string) []remediation.PRItemResult {
	return []remediation.PRItemResult{{Kind: remediation.PRItemKindImage, ItemKey: candItemKey, Workload: candWorkload, UnitKeys: unitKeys, Status: remediation.PRItemAssigned}}
}

func notAssigned(workload string, status remediation.PRItemStatus, reason remediation.Reason) remediation.PRItemResult {
	return remediation.PRItemResult{Kind: remediation.PRItemKindImage, ItemKey: candItemKey, Workload: workload, Status: status, Reason: reason}
}

func candUnit(status remediation.PRUnitStatus, number int) remediation.PRUnit {
	u := remediation.PRUnit{Key: candUnitKey, Repo: "ex/shop", Path: "compose.yml", Current: baseWaitImage, CandidateTag: "1.0.1", Status: status, Number: number}
	if number > 0 {
		u.URL = "https://github.com/ex/shop/pull/12"
	}
	return u
}

// actionLineOf is the action line of the jsoup card, "" when it has none.
func actionLineOf(t *testing.T, r analyze.Report, p *PlanInfo, lang Language) string {
	t.Helper()
	label := "Action: "
	if lang == LanguageJA {
		label = "対応: "
	}
	var lines []string
	for _, l := range strings.Split(renderChannelWithPlan(r, p, lang), "\n") {
		if strings.HasPrefix(l, label) {
			lines = append(lines, strings.TrimPrefix(l, label))
		}
	}
	if len(lines) > 1 {
		t.Fatalf("%d action lines: %q", len(lines), lines)
	}
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func TestCardAction_CandidateOfTheSameSeries(t *testing.T) {
	r := baseWaitReport(t)
	cases := []struct {
		name string
		outs []remediation.Outcome
		ja   string
		en   string
	}{
		{"resolved", []remediation.Outcome{resolved(), resolved()},
			"イメージ shop-es 1 → 1.0.1 で解消",
			"image shop-es 1 → 1.0.1 resolves it"},
		{"partial", []remediation.Outcome{resolved(), remaining()},
			"イメージ shop-es 1 → 1.0.1 で一部解消（2件中1件）",
			"image shop-es 1 → 1.0.1 resolves part of it (1 of 2)"},
		{"remains", []remediation.Outcome{remaining(), remaining()},
			"イメージ shop-es 1 の新しい版待ち（同じ系列の 1.0.1 では未解消）",
			"waiting for a newer image of shop-es 1 (not resolved in 1.0.1 of the same series)"},
		{"unknown", []remediation.Outcome{resolved(), remediation.OutcomeUnknown},
			"イメージ shop-es 1 → 1.0.1 で解消するか確認できない",
			"whether image shop-es 1 → 1.0.1 resolves it could not be confirmed"},
		{"no verdict", []remediation.Outcome{resolved()},
			"イメージ shop-es 1 → 1.0.1 で解消するか確認できない",
			"whether image shop-es 1 → 1.0.1 resolves it could not be confirmed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := actionLineOf(t, r, candidatePlan(t, c.outs...), LanguageJA); got != c.ja {
				t.Errorf("ja: got %q, want %q", got, c.ja)
			}
			if got := actionLineOf(t, r, candidatePlan(t, c.outs...), LanguageEN); got != c.en {
				t.Errorf("en: got %q, want %q", got, c.en)
			}
		})
	}
}

func TestCardAction_PullRequestClause(t *testing.T) {
	r := baseWaitReport(t)
	both := func(t *testing.T) *PlanInfo { return candidatePlan(t, resolved(), resolved()) }
	link := "<https://github.com/ex/shop/pull/12|#12>"
	modified := candUnit(remediation.PRStatusOpen, 12)
	modified.UserModified = true
	replaced := candUnit(remediation.PRStatusSuppressed, 12)
	replaced.ReplacedBy = 13
	other := candUnit(remediation.PRStatusOpen, 14)
	other.Key, other.URL = "kubernetes|ex/k8s|main|es.yaml|shop-es:1", "https://github.com/ex/k8s/pull/14"
	cases := []struct {
		name string
		plan func(t *testing.T) *PlanInfo
		ja   string
		en   string
	}{
		{"created", func(t *testing.T) *PlanInfo {
			return withPR(both(t), assigned(candUnitKey), candUnit(remediation.PRStatusCreated, 12))
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + "）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + ")"},
		{"merged", func(t *testing.T) *PlanInfo {
			return withPR(both(t), assigned(candUnitKey), candUnit(remediation.PRStatusMerged, 12))
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + " はマージ済み、稼働中のイメージは未更新）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + " is merged; the running image has not been updated)"},
		{"closed", func(t *testing.T) *PlanInfo {
			return withPR(both(t), assigned(candUnitKey), candUnit(remediation.PRStatusSuppressed, 12))
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + " は未マージでクローズ）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + " was closed without merging)"},
		{"replaced", func(t *testing.T) *PlanInfo { return withPR(both(t), assigned(candUnitKey), replaced) },
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + " は未マージでクローズ、#13 に置き換え）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + " was closed without merging and replaced by #13)"},
		{"modified", func(t *testing.T) *PlanInfo { return withPR(both(t), assigned(candUnitKey), modified) },
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + " の内容は作成時と異なる）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + " differs from its original content)"},
		{"merged after a person changed it", func(t *testing.T) *PlanInfo {
			u := candUnit(remediation.PRStatusMerged, 12)
			u.UserModified = true
			return withPR(both(t), assigned(candUnitKey), u)
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + " の内容は作成時と異なる）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + " differs from its original content)"},
		{"unit without a pull request", func(t *testing.T) *PlanInfo {
			u := candUnit(remediation.PRStatusManual, 0)
			u.Reason = remediation.Reason("compose_variable")
			return withPR(both(t), assigned(candUnitKey), u)
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request は未作成: image の値に変数が含まれる）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request not created: the image value contains a variable)"},
		{"write outcome unknown", func(t *testing.T) *PlanInfo {
			u := candUnit(remediation.PRStatusDeferred, 0)
			u.Reason = remediation.ReasonWriteOutcomeUnknown
			return withPR(both(t), assigned(candUnitKey), u)
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request の作成結果は未確認: " + planReasonText(LanguageJA, "write_outcome_unknown") + "）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request creation is unconfirmed: " + planReasonText(LanguageEN, "write_outcome_unknown") + ")"},
		{"no source mapping", func(t *testing.T) *PlanInfo {
			return withPR(both(t), []remediation.PRItemResult{notAssigned(candWorkload, remediation.PRItemNotApplicable, remediation.ReasonSourceMappingMissing)})
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request は作成しない: " + planReasonText(LanguageJA, "source_mapping_missing") + "）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request will not be created: " + planReasonText(LanguageEN, "source_mapping_missing") + ")"},
		{"stage not run", func(t *testing.T) *PlanInfo {
			return withPR(both(t), []remediation.PRItemResult{notAssigned(candWorkload, remediation.PRItemNotProcessed, remediation.ReasonStorageFailed)})
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request は未作成: " + planReasonText(LanguageJA, "storage_failed") + "）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request not created: " + planReasonText(LanguageEN, "storage_failed") + ")"},
		{"a mapped and an unmapped workload", func(t *testing.T) *PlanInfo {
			items := append(assigned(candUnitKey), notAssigned("compose/shop/es2", remediation.PRItemNotApplicable, remediation.ReasonSourceMappingMissing))
			return withPR(both(t), items, candUnit(remediation.PRStatusOpen, 12))
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + "）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + ")"},
		{"two open pull requests", func(t *testing.T) *PlanInfo {
			return withPR(both(t), assigned(candUnitKey, other.Key), candUnit(remediation.PRStatusOpen, 12), other)
		},
			"イメージ shop-es 1 → 1.0.1 で解消（Pull Request " + link + "、<https://github.com/ex/k8s/pull/14|#14>）",
			"image shop-es 1 → 1.0.1 resolves it (Pull Request " + link + ", <https://github.com/ex/k8s/pull/14|#14>)"},
		{"enabled without a record of the item", func(t *testing.T) *PlanInfo { return withPR(both(t), nil) },
			"イメージ shop-es 1 → 1.0.1 で解消",
			"image shop-es 1 → 1.0.1 resolves it"},
		// What disagrees gives no line at all.
		{"units that disagree", func(t *testing.T) *PlanInfo {
			return withPR(both(t), assigned(candUnitKey, other.Key), candUnit(remediation.PRStatusMerged, 12), other)
		}, "", ""},
		{"workloads without a unit that disagree", func(t *testing.T) *PlanInfo {
			return withPR(both(t), []remediation.PRItemResult{
				notAssigned(candWorkload, remediation.PRItemNotApplicable, remediation.ReasonSourceMappingMissing),
				notAssigned("container/es", remediation.PRItemNotApplicable, remediation.ReasonContainerImageTagUnsupported)})
		}, "", ""},
		{"a unit the plan does not have", func(t *testing.T) *PlanInfo { return withPR(both(t), assigned(candUnitKey)) }, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := actionLineOf(t, r, c.plan(t), LanguageJA); got != c.ja {
				t.Errorf("ja: got %q, want %q", got, c.ja)
			}
			if got := actionLineOf(t, r, c.plan(t), LanguageEN); got != c.en {
				t.Errorf("en: got %q, want %q", got, c.en)
			}
		})
	}
}

// The clause is about the pull request that resolves the card's findings, so
// a card whose findings remain does not name it.
func TestCardAction_RemainingFindingsNameNoPullRequest(t *testing.T) {
	r := baseWaitReport(t)
	p := withPR(candidatePlan(t, remaining(), remaining()), assigned(candUnitKey), candUnit(remediation.PRStatusOpen, 12))
	if got, want := actionLineOf(t, r, p, LanguageEN), "waiting for a newer image of shop-es 1 (not resolved in 1.0.1 of the same series)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCardAction_CandidateNeedsEveryFixedFindingAndTheSameEntity(t *testing.T) {
	r := baseWaitReport(t)
	// One of the card's findings is not a target of the item.
	p := candidatePlan(t, resolved())
	p.Plan.Items[0].Targets = p.Plan.Items[0].Targets[:1]
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a card with a finding the item does not target has the line %q", got)
	}
	// The item is of another entity of the same reference.
	p = candidatePlan(t, resolved(), resolved())
	p.Plan.Items[0].Current.Entity = remediation.EntityKeyString(baseWaitKeyOf(t, "b"))
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("an item of another entity gives the line %q", got)
	}
}

// itemPlan is candidatePlan with the item's kind, category and reason set;
// an item without a candidate has no comparison either.
func itemPlan(t *testing.T, kind remediation.TagKind, cat remediation.Category, reason remediation.Reason, candidate bool, outs ...remediation.Outcome) *PlanInfo {
	p := candidatePlan(t, outs...)
	it := &p.Plan.Items[0]
	it.Kind, it.Category, it.Reason = kind, cat, reason
	if !candidate {
		it.Candidate, it.Comparison = nil, nil
	}
	return p
}

func TestCardAction_OtherStatesOfTheImage(t *testing.T) {
	r := baseWaitReport(t)
	pinned, floating := remediation.TagPinned, remediation.TagFloating
	both := []remediation.Outcome{resolved(), resolved()}
	part := []remediation.Outcome{resolved(), remaining()}
	none := []remediation.Outcome{remaining(), remaining()}
	unknown := []remediation.Outcome{resolved(), remediation.OutcomeUnknown}
	cases := []struct {
		name      string
		kind      remediation.TagKind
		cat       remediation.Category
		reason    remediation.Reason
		candidate bool
		outs      []remediation.Outcome
		ja, en    string
	}{
		{"pull again resolves", floating, remediation.CategoryPullAgain, remediation.ReasonAdopted, true, both,
			"イメージ shop-es 1 の再pullで解消",
			"pulling image shop-es 1 again resolves it"},
		{"pull again resolves part", floating, remediation.CategoryPullAgain, remediation.ReasonAdopted, true, part,
			"イメージ shop-es 1 の再pullで一部解消（2件中1件）",
			"pulling image shop-es 1 again resolves part of it (1 of 2)"},
		{"pull again leaves the card's findings", floating, remediation.CategoryPullAgain, remediation.ReasonAdopted, true, none,
			"イメージ shop-es 1 の新しい内容待ち（再pullでも未解消）",
			"waiting for new content of image shop-es 1 (pulling again does not resolve it)"},
		{"pull again not judged", floating, remediation.CategoryPullAgain, remediation.ReasonAdopted, true, unknown,
			"イメージ shop-es 1 の再pullで解消するか確認できない",
			"whether pulling image shop-es 1 again resolves it could not be confirmed"},

		{"pinned decision resolves", pinned, remediation.CategoryManual, remediation.ReasonIntroducedFindings, true, both,
			"イメージ shop-es 1 → 1.0.1 で解消（要判断: 候補で新たな所見が入る）",
			"image shop-es 1 → 1.0.1 resolves it (decision needed: the candidate brings new findings)"},
		{"pinned decision resolves part", pinned, remediation.CategoryManual, remediation.ReasonIntroducedFindings, true, part,
			"イメージ shop-es 1 → 1.0.1 で一部解消（2件中1件、要判断: 候補で新たな所見が入る）",
			"image shop-es 1 → 1.0.1 resolves part of it (1 of 2, decision needed: the candidate brings new findings)"},
		{"pinned decision remains", pinned, remediation.CategoryManual, remediation.ReasonIntroducedKEV, true, none,
			"イメージ shop-es 1 の新しい版待ち（同じ系列の 1.0.1 では未解消、要判断: 候補でKEV掲載の脆弱性が新たに入る）",
			"waiting for a newer image of shop-es 1 (not resolved in 1.0.1 of the same series, decision needed: the candidate brings a vulnerability on the KEV list)"},
		{"pinned decision not judged", pinned, remediation.CategoryManual, remediation.ReasonIntroducedFindings, true, unknown,
			"イメージ shop-es の更新は要判断（候補で新たな所見が入る）",
			"updating image shop-es needs a decision (the candidate brings new findings)"},
		{"pinned decision without a comparison", pinned, remediation.CategoryManual, remediation.ReasonComposeBuildUndetermined, false, nil,
			"イメージ shop-es の更新は要判断（サービスのビルド方法を判断できない）",
			"updating image shop-es needs a decision (how the service is built cannot be determined)"},

		{"floating decision resolves", floating, remediation.CategoryManual, remediation.ReasonIntroducedFindings, true, both,
			"イメージ shop-es 1 の再pullで解消（要判断: 候補で新たな所見が入る）",
			"pulling image shop-es 1 again resolves it (decision needed: the candidate brings new findings)"},
		{"floating decision resolves part", floating, remediation.CategoryManual, remediation.ReasonIntroducedFindings, true, part,
			"イメージ shop-es 1 の再pullで一部解消（2件中1件、要判断: 候補で新たな所見が入る）",
			"pulling image shop-es 1 again resolves part of it (1 of 2, decision needed: the candidate brings new findings)"},
		{"floating decision remains", floating, remediation.CategoryManual, remediation.ReasonIntroducedFindings, true, none,
			"イメージ shop-es 1 の新しい内容待ち（再pullでも未解消、要判断: 候補で新たな所見が入る）",
			"waiting for new content of image shop-es 1 (pulling again does not resolve it, decision needed: the candidate brings new findings)"},
		{"floating decision without a comparison", floating, remediation.CategoryManual, remediation.ReasonComposeBuildUndetermined, false, nil,
			"イメージ shop-es 1 の再pullは要判断（サービスのビルド方法を判断できない）",
			"pulling image shop-es 1 again needs a decision (how the service is built cannot be determined)"},

		{"floating tag unchanged", floating, remediation.CategoryNoCandidate, remediation.ReasonSameContent, false, nil,
			"イメージ shop-es 1 の新しい内容待ち（タグの内容は稼働中と同じ）",
			"waiting for new content of image shop-es 1 (the tag has the same content as the running image)"},
		{"floating tag does not resolve", floating, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing, true, none,
			"イメージ shop-es 1 の新しい内容待ち（再pullでも未解消）",
			"waiting for new content of image shop-es 1 (pulling again does not resolve it)"},
		{"pinned series has no newer tag", pinned, remediation.CategoryNoCandidate, remediation.ReasonNoNewerTag, false, nil,
			"イメージ shop-es 1 の新しい版待ち（同じ系列に新しい版なし）",
			"waiting for a newer image of shop-es 1 (no newer tag in the same series)"},
		{"pinned newer tag is the same content", pinned, remediation.CategoryNoCandidate, remediation.ReasonSameContent, false, nil,
			"イメージ shop-es 1 の新しい版待ち（同じ系列の新しいタグも内容は同じ）",
			"waiting for a newer image of shop-es 1 (the newer tag of the same series has the same content)"},
		{"pinned newer tag does not resolve", pinned, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing, true, none,
			"イメージ shop-es の新しい版待ち（同じ系列の新しい版では未解消）",
			"waiting for a newer image of shop-es (not resolved by the newer tag of the same series)"},

		{"excluded", remediation.TagExcluded, remediation.CategoryExcluded, remediation.Reason(remediation.ExcludePrerelease), false, nil,
			"イメージの新しい版は確認していない（タグがプレリリース版に見える）",
			"a newer image has not been checked (the tag looks like a prerelease)"},
		{"built on the host", floating, remediation.CategoryExcluded, remediation.ReasonLocallyBuilt, false, nil,
			"イメージの新しい版は確認していない（ホストでビルドしたイメージで、レジストリに実体がない）",
			"a newer image has not been checked (the image was built on its host and has no copy in a registry)"},
		{"not comparable", pinned, remediation.CategoryNotComparable, remediation.ReasonAuthRequired, false, nil,
			"イメージの新しい版を確認できなかった（レジストリへのログインが必要である）",
			"a newer image could not be checked (the registry requires a login)"},
		{"failed", pinned, remediation.CategoryFailed, remediation.ReasonScanFailed, true, nil,
			"イメージの新しい版を確認できなかった（スキャンに失敗した）",
			"a newer image could not be checked (a scan failed)"},
		{"deferred", pinned, remediation.CategoryDeferred, remediation.ReasonCycleDeadline, false, nil,
			"イメージの新しい版は次回以降に確認（実行時間の上限に達した）",
			"a newer image will be checked in a later run (the time limit of the run was reached)"},

		{"floating tag with a finding not judged", floating, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing, true, []remediation.Outcome{remaining()}, "", ""},
		{"pinned newer tag with a finding not judged", pinned, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing, true, []remediation.Outcome{remaining()}, "", ""},
		{"pinned newer tag without a comparison", pinned, remediation.CategoryNoCandidate, remediation.ReasonCandidateNotFixing, false, nil, "", ""},
		{"a decision without a reason", pinned, remediation.CategoryManual, "", true, both, "", ""},
		{"a failure without a reason", pinned, remediation.CategoryFailed, "", false, nil, "", ""},
		{"no candidate for another reason", pinned, remediation.CategoryNoCandidate, remediation.ReasonRegistryError, false, nil, "", ""},
		{"a floating series", floating, remediation.CategoryNoCandidate, remediation.ReasonNoNewerTag, false, nil, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := actionLineOf(t, r, itemPlan(t, c.kind, c.cat, c.reason, c.candidate, c.outs...), LanguageJA); got != c.ja {
				t.Errorf("ja: got %q, want %q", got, c.ja)
			}
			if got := actionLineOf(t, r, itemPlan(t, c.kind, c.cat, c.reason, c.candidate, c.outs...), LanguageEN); got != c.en {
				t.Errorf("en: got %q, want %q", got, c.en)
			}
		})
	}
}

// A pinned image whose newer series were checked keeps the line of that
// check, and stays without a line where the check gives none.
func TestCardAction_NewerSeriesResultComesFirst(t *testing.T) {
	r := baseWaitReport(t)
	p := imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesNone, ""))
	want := "waiting for a newer image of shop-es 1 (no newer tag in the same series or in a newer series of the same form)"
	if got := actionLineOf(t, r, p, LanguageEN); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// The line of the check does not depend on what the dependency files
	// hold, as before.
	f := baseWaitFindings()[0]
	ref := f.PackageRef()
	p.Plan.LanguageItems = []remediation.LanguageItem{{Key: "deps:ex/es@main:.#maven", Packages: []remediation.LanguagePackage{{
		Name: f.Package, Installed: f.InstalledVer, Action: remediation.ActionUpdate,
		Origins: []remediation.FindingOrigin{{Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a")), Ecosystem: string(ref.Ecosystem),
			Class: string(ref.Class), Name: f.Package, Version: f.InstalledVer, VulnID: f.VulnID, PkgPath: f.PkgPath}},
	}}}}
	if got := actionLineOf(t, r, p, LanguageEN); got != want {
		t.Errorf("with a dependency file's finding: got %q, want %q", got, want)
	}
}

// No newer series after the own series had a newer tag: the check adds
// nothing to say, and the card states what the newer tag of the own series
// showed.
func TestCardAction_NoNewerSeriesAfterANewerTagOfTheOwnSeries(t *testing.T) {
	r := baseWaitReport(t)
	plan := func(reason remediation.Reason, candidate bool, outs ...remediation.Outcome) *PlanInfo {
		p := itemPlan(t, remediation.TagPinned, remediation.CategoryNoCandidate, reason, candidate, outs...)
		p.Plan.Items[0].NewerSeries = newerOf(remediation.NewerSeriesNone, "")
		return p
	}
	cases := []struct {
		name   string
		p      *PlanInfo
		ja, en string
	}{
		{"the newer tag resolves none", plan(remediation.ReasonCandidateNotFixing, true, remaining(), remaining()),
			"イメージ shop-es の新しい版待ち（同じ系列の新しい版では未解消）",
			"waiting for a newer image of shop-es (not resolved by the newer tag of the same series)"},
		{"the newer tag has the same content", plan(remediation.ReasonSameContent, false),
			"イメージ shop-es 1 の新しい版待ち（同じ系列の新しいタグも内容は同じ）",
			"waiting for a newer image of shop-es 1 (the newer tag of the same series has the same content)"},
		{"a finding not judged", plan(remediation.ReasonCandidateNotFixing, true, remaining(), remediation.OutcomeUnknown), "", ""},
		{"no comparison", plan(remediation.ReasonCandidateNotFixing, false), "", ""},
		{"no reason", plan("", false), "", ""},
		{"a reason with no line", plan(remediation.ReasonAdopted, false), "", ""},
	}
	for _, c := range cases {
		for _, l := range []struct {
			lang Language
			want string
		}{{LanguageJA, c.ja}, {LanguageEN, c.en}} {
			if got := actionLineOf(t, r, c.p, l.lang); got != l.want {
				t.Errorf("%s (%s): got %q, want %q", c.name, l.lang, got, l.want)
			}
		}
	}
	// A check that found a newer series, or one not finished, stays the
	// waits' to state.
	for _, s := range []remediation.NewerSeriesStatus{remediation.NewerSeriesNotChecked, remediation.NewerSeriesNotResolving} {
		p := plan(remediation.ReasonCandidateNotFixing, true, remaining(), remaining())
		p.Plan.Items[0].NewerSeries = newerOf(s, "")
		if got := actionLineOf(t, r, p, LanguageEN); got != "" {
			t.Errorf("status %s: the card has the line %q", s, got)
		}
	}
}

// A finding the dependency files or the Dockerfile's base hold is theirs to
// answer: the image's tag says nothing of a card with one, a candidate of
// its own series aside.
func TestCardAction_ImageStatesYieldToMoreSpecificSources(t *testing.T) {
	r := baseWaitReport(t)
	same := func() *PlanInfo {
		return itemPlan(t, remediation.TagFloating, remediation.CategoryNoCandidate, remediation.ReasonSameContent, false)
	}
	// The base of the Dockerfile targets the card's findings and has no line
	// for them: the item is adopted, yet this image has no candidate base.
	p := same()
	p.Plan.DockerfileItems = baseWaitPlan(t, remediation.CategoryPRCandidate, remediation.ReasonAdopted).Plan.DockerfileItems
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a card of the base's findings has the image's line %q", got)
	}
	// The dependency files hold one of the card's findings.
	f := baseWaitFindings()[0]
	ref := f.PackageRef()
	p = same()
	p.Plan.LanguageItems = []remediation.LanguageItem{{Key: "deps:ex/es@main:.#maven", Packages: []remediation.LanguagePackage{{
		Name: f.Package, Installed: f.InstalledVer, Action: remediation.ActionUpdate,
		Origins: []remediation.FindingOrigin{{Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a")), Ecosystem: string(ref.Ecosystem),
			Class: string(ref.Class), Name: f.Package, Version: f.InstalledVer, VulnID: f.VulnID, PkgPath: f.PkgPath}},
	}}}}
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a card of a dependency file's finding has the image's line %q", got)
	}
	// One of the card's findings is not a target of the item.
	p = same()
	p.Plan.Items[0].Targets = p.Plan.Items[0].Targets[:1]
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a card with a finding the item does not target has the line %q", got)
	}
	// A mapped Dockerfile builds the image: nobody else publishes a newer
	// version of it to wait for or to look up, though a comparison made
	// with what its tag holds now is still told.
	built := baseWaitPlan(t, remediation.CategoryNoCandidate, remediation.ReasonBaseUnchanged).Plan.DockerfileItems
	built[0].Entities[0].Targets = nil
	for _, c := range []struct {
		cat    remediation.Category
		reason remediation.Reason
	}{
		{remediation.CategoryNoCandidate, remediation.ReasonSameContent},
		{remediation.CategoryExcluded, remediation.ReasonLocallyBuilt},
	} {
		p = itemPlan(t, remediation.TagFloating, c.cat, c.reason, false)
		p.Plan.DockerfileItems = built
		if got := actionLineOf(t, r, p, LanguageEN); got != "" {
			t.Errorf("%s of an image built from a mapped Dockerfile has the line %q", c.cat, got)
		}
	}
	p = itemPlan(t, remediation.TagFloating, remediation.CategoryPullAgain, remediation.ReasonAdopted, true, resolved(), resolved())
	p.Plan.DockerfileItems = built
	if got, want := actionLineOf(t, r, p, LanguageEN), "pulling image shop-es 1 again resolves it"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// Without any of them the image answers.
	want := "waiting for new content of image shop-es 1 (the tag has the same content as the running image)"
	if got := actionLineOf(t, r, same(), LanguageEN); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The base of the Dockerfile answers before the image's own tag.
func TestCardAction_BaseComesBeforeTheCandidateOfTheImage(t *testing.T) {
	r := baseWaitReport(t)
	p := baseWaitNoNewer(t)
	p.Plan.Items = candidatePlan(t, resolved(), resolved()).Plan.Items
	want := "waiting for a newer base image of elasticsearch 8.19.23 (no newer tag in the same series)"
	if got := actionLineOf(t, r, p, LanguageEN); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

const (
	globalImage = "shop-api:latest"
	globalDir   = "usr/local/lib/node_modules"
)

func nodeFinding(name, ver, id, path string) scanner.Finding {
	return scanner.Finding{Image: globalImage, Class: scanner.ClassLang, Package: name, InstalledVer: ver, FixedVer: "99.0.0",
		Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: id, Type: "node-pkg", PkgPath: path, LayerDiffID: upperLayer}
}

func globalReport(t *testing.T, fs ...scanner.Finding) analyze.Report {
	key := baseWaitKeyOf(t, "c")
	return analyze.Build([]scanner.ImageScan{{Image: globalImage, Subject: inventory.ImageSubject{Ref: globalImage, Key: key, Resolved: true},
		ScannedKey: key, Pinned: true, Source: scanner.SourceLocal, Findings: fs}}, nil, analyze.Triage{}, genTime)
}

// langPackage is the plan's entry of the findings fs of one package version,
// all of which have the reason given.
func langPackage(t *testing.T, reason remediation.Reason, fs ...scanner.Finding) remediation.LanguagePackage {
	p := remediation.LanguagePackage{Name: fs[0].Package, Ecosystem: fs[0].Type, Installed: fs[0].InstalledVer, Action: remediation.ActionManual, Reason: reason}
	if reason == "" {
		p.Action = remediation.ActionUpdate
	}
	for _, f := range fs {
		ref := f.PackageRef()
		p.Origins = append(p.Origins, remediation.FindingOrigin{Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "c")),
			Ecosystem: string(ref.Ecosystem), Class: string(ref.Class), Name: f.Package, Version: f.InstalledVer, VulnID: f.VulnID,
			PkgPath: f.PkgPath, Workload: "compose/shop/api"})
	}
	return p
}

func langPlan(manager remediation.DependencyManager, pkgs ...remediation.LanguagePackage) *PlanInfo {
	li := remediation.LanguageItem{Key: "deps:ex/api@main:.#" + string(manager), Manager: manager, Category: remediation.CategoryManual,
		Reason: remediation.ReasonGlobalNodeModules, Packages: pkgs}
	return &PlanInfo{Plan: &remediation.Plan{LanguageItems: []remediation.LanguageItem{li}}}
}

func TestCardAction_GlobalNodeModules(t *testing.T) {
	global := remediation.ReasonGlobalNodeModules
	tar1 := nodeFinding("tar", "7.5.16", "CVE-2031-0001", globalDir+"/pnpm/dist/node_modules/tar/package.json")
	tar2 := nodeFinding("tar", "7.5.16", "CVE-2031-0002", globalDir+"/pnpm/dist/node_modules/tar/package.json")
	pnpm := nodeFinding("pnpm", "10.34.4", "CVE-2031-0003", globalDir+"/pnpm/package.json")
	undici := nodeFinding("undici", "6.28.0", "CVE-2031-0004", globalDir+"/npm/node_modules/undici/package.json")
	scoped := nodeFinding("semver", "7.0.0", "CVE-2031-0005", "opt/lib/node_modules/@acme/cli/node_modules/semver/package.json")

	t.Run("bundled with a package whose version the plan knows", func(t *testing.T) {
		r := globalReport(t, tar1, tar2)
		p := langPlan(remediation.ManagerPnpm, langPackage(t, global, tar1, tar2), langPackage(t, global, pnpm))
		if got, want := actionLineOf(t, r, p, LanguageJA), "pnpm 10.34.4 の同梱物（/usr/local/lib/node_modules）で、pnpm-lock.yaml の更新では直らない"; got != want {
			t.Errorf("ja: got %q, want %q", got, want)
		}
		if got, want := actionLineOf(t, r, p, LanguageEN), "bundled with pnpm 10.34.4 (/usr/local/lib/node_modules); updating pnpm-lock.yaml will not fix it"; got != want {
			t.Errorf("en: got %q, want %q", got, want)
		}
	})
	t.Run("the package installed there itself", func(t *testing.T) {
		r := globalReport(t, pnpm)
		p := langPlan(remediation.ManagerPnpm, langPackage(t, global, pnpm))
		if got, want := actionLineOf(t, r, p, LanguageJA), "/usr/local/lib/node_modules に入っている pnpm 本体で、pnpm-lock.yaml の更新では直らない"; got != want {
			t.Errorf("ja: got %q, want %q", got, want)
		}
		if got, want := actionLineOf(t, r, p, LanguageEN), "pnpm itself in /usr/local/lib/node_modules; updating pnpm-lock.yaml will not fix it"; got != want {
			t.Errorf("en: got %q, want %q", got, want)
		}
	})
	t.Run("bundled with a package whose version the plan does not know", func(t *testing.T) {
		r := globalReport(t, undici)
		p := langPlan(remediation.ManagerNpm, langPackage(t, global, undici))
		if got, want := actionLineOf(t, r, p, LanguageJA), "npm の同梱物（/usr/local/lib/node_modules）で、package-lock.json の更新では直らない"; got != want {
			t.Errorf("ja: got %q, want %q", got, want)
		}
		if got, want := actionLineOf(t, r, p, LanguageEN), "bundled with npm (/usr/local/lib/node_modules); updating package-lock.json will not fix it"; got != want {
			t.Errorf("en: got %q, want %q", got, want)
		}
	})
	t.Run("a scoped owner in another prefix, and an item without a dependency file", func(t *testing.T) {
		r := globalReport(t, scoped)
		p := langPlan("", langPackage(t, global, scoped))
		if got, want := actionLineOf(t, r, p, LanguageEN), "bundled with @acme/cli (/opt/lib/node_modules); updating the dependency files will not fix it"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("the same version in the dependency files too", func(t *testing.T) {
		app := nodeFinding("tar", "7.5.16", "CVE-2031-0001", "app/node_modules/tar/package.json")
		r := globalReport(t, tar1, app)
		p := langPlan(remediation.ManagerPnpm, langPackage(t, global, tar1), langPackage(t, "", app))
		if got := actionLineOf(t, r, p, LanguageEN); got != "" {
			t.Errorf("a package the dependency files hold as well has the line %q", got)
		}
	})
	t.Run("bundled with two packages", func(t *testing.T) {
		inNpm := nodeFinding("tar", "7.5.16", "CVE-2031-0001", globalDir+"/npm/node_modules/tar/package.json")
		r := globalReport(t, tar1, inNpm)
		p := langPlan(remediation.ManagerPnpm, langPackage(t, global, tar1, inNpm))
		if got := actionLineOf(t, r, p, LanguageEN); got != "" {
			t.Errorf("a package bundled with two packages has the line %q", got)
		}
	})
	t.Run("a finding the plan does not have", func(t *testing.T) {
		r := globalReport(t, tar1, tar2)
		p := langPlan(remediation.ManagerPnpm, langPackage(t, global, tar1))
		if got := actionLineOf(t, r, p, LanguageEN); got != "" {
			t.Errorf("a card with a finding outside the plan has the line %q", got)
		}
	})
	t.Run("another entity", func(t *testing.T) {
		r := globalReport(t, tar1)
		p := langPlan(remediation.ManagerPnpm, langPackage(t, global, tar1))
		p.Plan.LanguageItems[0].Packages[0].Origins[0].Entity = remediation.EntityKeyString(baseWaitKeyOf(t, "d"))
		if got := actionLineOf(t, r, p, LanguageEN); got != "" {
			t.Errorf("a package of another entity has the line %q", got)
		}
	})
}

// A global package keeps its own line although the image's tag has a
// candidate: the dependency files are asked first.
func TestCardAction_GlobalComesBeforeTheImage(t *testing.T) {
	tar1 := nodeFinding("tar", "7.5.16", "CVE-2031-0001", globalDir+"/pnpm/dist/node_modules/tar/package.json")
	r := globalReport(t, tar1)
	p := langPlan(remediation.ManagerPnpm, langPackage(t, remediation.ReasonGlobalNodeModules, tar1))
	ref := tar1.PackageRef()
	target := remediation.Target{VulnID: tar1.VulnID, Package: remediation.PackageCoord{Ecosystem: ref.Ecosystem, Class: ref.Class, Name: ref.Name}}
	p.Plan.Items = []remediation.Item{{
		Key: globalImage + "|c", Kind: remediation.TagPinned, Category: remediation.CategoryPRCandidate,
		Current:    remediation.ImageState{Ref: globalImage, Tag: "latest", Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "c"))},
		Candidate:  &remediation.ImageState{Ref: "shop-api:2", Tag: "2"},
		Targets:    []remediation.Target{target},
		Comparison: &remediation.VerificationResult{Comparable: true, Verdicts: []remediation.VulnVerdict{{VulnID: target.VulnID, Package: target.Package, Outcome: resolved()}}},
	}}
	if got, want := actionLineOf(t, r, p, LanguageEN), "bundled with pnpm (/usr/local/lib/node_modules); updating pnpm-lock.yaml will not fix it"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGlobalPlace(t *testing.T) {
	cases := []struct {
		path, owner, dir string
		self, ok         bool
	}{
		{"usr/local/lib/node_modules/pnpm/dist/node_modules/tar/package.json", "pnpm", "/usr/local/lib/node_modules", false, true},
		{"/usr/local/lib/node_modules/pnpm/package.json", "pnpm", "/usr/local/lib/node_modules", true, true},
		{"usr/lib/node_modules/@acme/cli/package.json", "@acme/cli", "/usr/lib/node_modules", true, true},
		{"usr/lib/node_modules/@acme/cli/node_modules/x/package.json", "@acme/cli", "/usr/lib/node_modules", false, true},
		{"app/node_modules/tar/package.json", "", "", false, false},
	}
	for _, c := range cases {
		owner, dir, self, ok := globalPlace(c.path)
		if owner != c.owner || dir != c.dir || self != c.self || ok != c.ok {
			t.Errorf("%s: got (%q, %q, %v, %v), want (%q, %q, %v, %v)", c.path, owner, dir, self, ok, c.owner, c.dir, c.self, c.ok)
		}
	}
}

// The thread and the email body build their cards the way the channel does.
func TestCardAction_LineInThreadAndEmail(t *testing.T) {
	r := baseWaitReport(t)
	want := "対応: イメージ shop-es 1 → 1.0.1 で解消"
	thread := allBlocksText(buildThreadBlockMessagesWithPlan(r, Ages{}, candidatePlan(t, resolved(), resolved()), jaMessages, defaultRenderLimits))
	if !strings.Contains(thread, want) {
		t.Errorf("thread card lacks the line:\n%s", thread)
	}
	email := allBlocksText(buildEmailMessages(Message{Report: r, Plan: candidatePlan(t, resolved(), resolved()), Thread: true}, LanguageJA))
	if strings.Count(email, want) < 2 {
		t.Errorf("the email lacks the line in the channel part or the thread part:\n%s", email)
	}
}
