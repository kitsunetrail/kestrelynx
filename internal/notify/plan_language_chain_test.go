package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// chainItem is a dependency item whose express was held back by a package that
// depends on it and was taken to its fixed version by updating mkdirp.
func chainItem(p *remediation.Plan) *remediation.LanguageItem {
	li := &p.LanguageItems[0]
	li.Packages = li.Packages[:1]
	li.Packages[0].SelectionLowerBound = "4.19.2"
	li.Update = &remediation.LanguageUpdate{Chain: &remediation.ChainUpdate{
		Outcome: remediation.ChainAdopted, Source: "chain_job",
		Blocked: []remediation.ChainBlock{{Package: "express", Version: "4.18.2", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "4.18.2", Proof: "exact"}},
		Tops:    []remediation.ChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.6", Kind: "top"}},
	}}
	return li
}

func TestPlanSlack_ChainUpdateNamesTheDirectDependency(t *testing.T) {
	r, _, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified
	li.Packages[0].AdoptedVersion = "4.19.2"
	li.Packages[0].Through = []string{"mkdirp"}
	info := &PlanInfo{Plan: &p, Changed: true}
	if got := slackPlanText(r, info, LanguageEN); !strings.Contains(got, "express 4.18.2 → 4.19.2 (with mkdirp 0.5.1 → 0.5.6)") {
		t.Errorf("en:\n%s", got)
	}
	if got := slackPlanText(r, info, LanguageJA); !strings.Contains(got, "express 4.18.2 → 4.19.2（mkdirp 0.5.1 → 0.5.6 も更新）") {
		t.Errorf("ja:\n%s", got)
	}
	// The pull request's own view says the same.
	p2 := languageFixture()
	chainItem(&p2)
	units := []remediation.PRUnit{{
		Kind: "language", ItemKey: p2.LanguageItems[0].Key, Number: 3, Status: remediation.PRStatusOpen, Repo: "ex/app", Path: "backend/package-lock.json",
		Language: &remediation.PRLanguage{
			Packages: []remediation.PRLanguagePackage{{Name: "express", From: "4.18.2", To: "4.19.2", Through: []string{"mkdirp"}}},
			Chain:    []remediation.LangChainMove{{Name: "mkdirp", From: "0.5.1", To: "0.5.6"}},
		},
	}}
	p2.PullRequests = units
	if got := slackPlanText(r, &PlanInfo{Plan: &p2, Changed: true}, LanguageEN); !strings.Contains(got, "express 4.18.2 → 4.19.2 (with mkdirp 0.5.1 → 0.5.6)") {
		t.Errorf("unit:\n%s", got)
	}
}

func TestPlanSlack_PackagesTheChainUpdateDidNotTake(t *testing.T) {
	r, _, _ := planCycleFixture()
	cases := []struct {
		name   string
		reason remediation.Reason
		chain  remediation.ChainUpdate
		en, ja string
	}{
		{"not fixed", remediation.ReasonDependentsNotFixed, remediation.ChainUpdate{Outcome: remediation.ChainNotFixed},
			"express 4.18.2 → 4.19.2: not raised, as the dependent mkdirp 0.5.1 requires express 4.18.2",
			"express 4.18.2 → 4.19.2: 依存元の mkdirp 0.5.1 が express を 4.18.2 と指定しているため上げられない"},
		{"rejected", remediation.ReasonDependentsRejected, remediation.ChainUpdate{Outcome: remediation.ChainRejected, Reason: remediation.ReasonSourceIntroduced},
			"express 4.18.2 → 4.19.2 needs mkdirp 0.5.1 updated as well, and that update was not adopted because the update brings new findings into the dependency files",
			"express 4.18.2 → 4.19.2 には mkdirp 0.5.1 の更新も必要だが、更新で依存関係ファイルに新たな所見が入るため採用しない"},
		{"limit", remediation.ReasonDependentsLimit, remediation.ChainUpdate{Outcome: remediation.ChainNotTried, Reason: remediation.ReasonChainItemBudget},
			"express 4.18.2 → 4.19.2 is held back by mkdirp 0.5.1, and updating mkdirp 0.5.1 was not tried because the update needs more work than one item may use",
			"express 4.18.2 → 4.19.2 は mkdirp 0.5.1 に止められていて、更新に必要な作業が1項目の上限を超えるため mkdirp 0.5.1 の更新を試していない"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := languageFixture()
			li := chainItem(&p)
			chain := c.chain
			chain.Blocked = li.Update.Chain.Blocked
			li.Update.Chain = &chain
			li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonTargetNotUpdated
			li.Packages[0].Action, li.Packages[0].Reason = remediation.ActionManual, c.reason
			info := &PlanInfo{Plan: &p, Changed: true}
			if got := slackPlanText(r, info, LanguageEN); !strings.Contains(got, c.en) {
				t.Errorf("en:\n%s", got)
			}
			if got := slackPlanText(r, info, LanguageJA); !strings.Contains(got, c.ja) {
				t.Errorf("ja:\n%s", got)
			}
		})
	}
	t.Run("without tops the line is the package's reason", func(t *testing.T) {
		p := languageFixture()
		li := chainItem(&p)
		li.Update.Chain = &remediation.ChainUpdate{Outcome: remediation.ChainNotTried, Reason: remediation.ReasonDependentsUnsupported}
		li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonTargetNotUpdated
		li.Packages[0].Action, li.Packages[0].Reason = remediation.ActionManual, remediation.ReasonDependentsUnsupported
		got := slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, LanguageEN)
		if !strings.Contains(got, "express 4.18.2 → 4.19.2: the packages that depend on it cannot be updated by this tool") {
			t.Errorf("text:\n%s", got)
		}
	})
}

func TestPlanSlack_ChainUpdateThatWaitsForAVersionToAge(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	retry := time.Date(2026, 10, 20, 3, 4, 5, 0, time.UTC)
	li.Category, li.Reason, li.RetryAfter = remediation.CategoryDeferred, remediation.ReasonReleaseTooNew, &retry
	li.Update.Chain = &remediation.ChainUpdate{Outcome: remediation.ChainDeferred, Reason: remediation.ReasonReleaseTooNew, Blocked: li.Update.Chain.Blocked}
	info := &PlanInfo{Plan: &p, Changed: true}
	if got := slackPlanText(r, info, LanguageEN); !strings.Contains(got, "express 4.18.2 → 4.19.2 needs mkdirp 0.5.1 updated as well; a version it brings in is less than 72 hours old, so it is tried again after 2026-10-20T03:04:05Z") {
		t.Errorf("en:\n%s", got)
	}
	if got := slackPlanText(r, info, LanguageJA); !strings.Contains(got, "express 4.18.2 → 4.19.2 には mkdirp 0.5.1 の更新も必要だが、入る版の公開から72時間経っていないため 2026-10-20T03:04:05Z 以降に再試行する") {
		t.Errorf("ja:\n%s", got)
	}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, info))["remediation"].(map[string]any)
	item := rem["language_items"].([]any)[0].(map[string]any)
	if item["retry_after"] != "2026-10-20T03:04:05Z" || item["reason"] != "release_too_new" {
		t.Errorf("item = %v", item)
	}
}

func TestWebhook_ChainFields(t *testing.T) {
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateVerified
	li.Packages[0].AdoptedVersion = "4.19.2"
	li.Packages[0].Through = []string{"mkdirp"}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	item := rem["language_items"].([]any)[0].(map[string]any)
	pkg := item["packages"].([]any)[0].(map[string]any)
	if th, _ := pkg["through"].([]any); len(th) != 1 || th[0] != "mkdirp" {
		t.Errorf("package = %v", pkg)
	}
	chain := item["update"].(map[string]any)["chain"].(map[string]any)
	if chain["outcome"] != "adopted" || chain["source"] != "chain_job" || len(chain["blocked"].([]any)) != 1 || len(chain["tops"].([]any)) != 1 {
		t.Errorf("chain = %v", chain)
	}
	if _, has := item["retry_after"]; has {
		t.Error("retry_after on an item that does not wait")
	}
	// An item without a chain has none of the fields.
	plain := languageFixture()
	rem = webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &plain, Changed: true}))["remediation"].(map[string]any)
	first := rem["language_items"].([]any)[0].(map[string]any)
	if _, has := first["update"]; has {
		t.Errorf("update on an item that has none: %v", first["update"])
	}
	if pk := first["packages"].([]any)[0].(map[string]any); pk["through"] != nil {
		t.Errorf("through = %v", pk["through"])
	}
}

func TestWebhook_ThroughIsKeptWhenThePlanTiesTheItemToItsPullRequest(t *testing.T) {
	// The next cycle does not update the item again: its packages carry no
	// Through, and the pull request's view does.
	r, changed, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	li.Category, li.Reason = remediation.CategoryPRCandidate, remediation.ReasonUpdateAlreadyProposed
	li.Update = nil
	p.PullRequests = []remediation.PRUnit{{
		Kind: "language", ItemKey: li.Key, Number: 3, Status: remediation.PRStatusOpen, Repo: "ex/app", Path: "backend/package-lock.json",
		Language: &remediation.PRLanguage{Packages: []remediation.PRLanguagePackage{
			{Name: "express", Ecosystem: "node-pkg", From: "4.18.2", To: "4.19.2", Through: []string{"mkdirp"}},
			{Name: "express", Ecosystem: "python-pkg", From: "1", To: "2", Through: []string{"other"}},
		}},
	}}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	pkg := rem["language_items"].([]any)[0].(map[string]any)["packages"].([]any)[0].(map[string]any)
	if th, _ := pkg["through"].([]any); len(th) != 1 || th[0] != "mkdirp" {
		t.Errorf("package = %v", pkg)
	}
}

// A chain update that recorded no requirement for the package itself still
// names the direct dependencies it re-resolved.
func TestPlanSlack_ChainNotFixedWithoutHolder(t *testing.T) {
	r, _, _ := planCycleFixture()
	p := languageFixture()
	li := chainItem(&p)
	li.Update.Chain = &remediation.ChainUpdate{Outcome: remediation.ChainNotFixed,
		Blocked: []remediation.ChainBlock{{Package: "other", Version: "1.0.0", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "1.0.0", Proof: "exact"}},
		Tops:    []remediation.ChainMove{{Name: "mkdirp", From: "0.5.1", Kind: "top"}}}
	li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonTargetNotUpdated
	li.Packages[0].Action, li.Packages[0].Reason = remediation.ActionManual, remediation.ReasonDependentsNotFixed
	if got := slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, LanguageJA); !strings.Contains(got, "express 4.18.2 → 4.19.2: mkdirp 0.5.1 をプロジェクトの範囲内で解決し直したが、今回の再解決では修正版に届かなかった") {
		t.Errorf("ja:\n%s", got)
	}
}

// The hints are listed under the package's chain line: what the newest
// release within the project's range and the newest release of all declare.
func TestPlanSlack_ChainHints(t *testing.T) {
	r, _, _ := planCycleFixture()
	held := remediation.ChainBlock{Package: "express", Version: "4.18.2", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "4.18.2", Proof: "exact", Via: []string{"mkdirp"}}
	cases := []struct {
		name    string
		outcome string
		reason  remediation.Reason
		blocked []remediation.ChainBlock
		hints   []remediation.ChainHint
		ja, en  []string
	}{
		{"in spec and latest", remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Spec: "^0.5.1",
				InSpec: &remediation.ChainHintRelease{Version: "0.5.6", Range: "4.18.2"},
				Latest: &remediation.ChainHintRelease{Version: "1.0.4", Range: "^4.19.2", Fixes: true}}},
			[]string{
				"express 4.18.2 → 4.19.2: 依存元の mkdirp 0.5.1 が express を 4.18.2 と指定しているため上げられない\n  • package.json の指定（^0.5.1）の範囲で最新の 0.5.6 も、express を 4.18.2 と指定（修正版を含まない）\n  • 1 系の最新の 1.0.4 は、express を ^4.19.2 と指定（修正版を含む）",
			},
			[]string{
				"  • the newest 0.5.6 within the package.json range (^0.5.1) also requires express 4.18.2 (no fixed version included)\n  • the newest 1.0.4 of the 1 series requires express ^4.19.2 (a fixed version included)",
			}},
		{"current is the newest in range, and a 0.x series", remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Spec: "^0.5.1",
				InSpec: &remediation.ChainHintRelease{Version: "0.5.1", Range: "4.18.2"},
				Latest: &remediation.ChainHintRelease{Version: "0.6.2", Range: "4.18.2"}}},
			[]string{"  • package.json の指定（^0.5.1）の範囲では、今の 0.5.1 が最新\n  • 0.6 系の最新の 0.6.2 も、express を 4.18.2 と指定（修正版を含まない）"},
			[]string{"  • within the package.json range (^0.5.1), the current 0.5.1 is the newest\n  • the newest 0.6.2 of the 0.6 series also requires express 4.18.2 (no fixed version included)"}},
		{"a dependent below a direct dependency", remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed,
			[]remediation.ChainBlock{{Package: "express", Version: "4.18.2", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "4.18.2", Proof: "exact", Via: []string{"app-kit"}}},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Via: []string{"app-kit"},
				Latest: &remediation.ChainHintRelease{Version: "0.5.6", Range: "^4.19.2", Fixes: true}}},
			[]string{"  • mkdirp 0.5 系の最新の 0.5.6 は、express を ^4.19.2 と指定（修正版を含む）\n  • app-kit のどの版でこの mkdirp が入るかは未確認"},
			[]string{"  • the newest mkdirp 0.5.6 of the 0.5 series requires express ^4.19.2 (a fixed version included)\n  • which release of app-kit brings in this mkdirp is not checked"}},
		{"a dependent below, already at its newest", remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed,
			[]remediation.ChainBlock{{Package: "express", Version: "4.18.2", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "4.18.2", Proof: "exact", Via: []string{"app-kit"}}},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Via: []string{"app-kit"},
				Latest: &remediation.ChainHintRelease{Version: "0.5.1", Range: "4.18.2"}}},
			[]string{"  • mkdirp は今の 0.5.1 が最新の版"},
			[]string{"  • mkdirp 0.5.1 is the newest release"}},
		{"dropped", remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Spec: "^0.5.1",
				Latest: &remediation.ChainHintRelease{Version: "1.0.4", Dropped: true}}},
			[]string{"  • 1 系の最新の 1.0.4 は、express を直接は使っていない"},
			[]string{"  • the newest 1.0.4 of the 1 series does not depend on express directly"}},
		{"two dependents are named", remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed,
			[]remediation.ChainBlock{held, {Package: "express", Version: "4.18.2", Parent: "optimist", ParentVersion: "0.6.1", Range: "~4.18.0", Proof: "upper_bound", Via: []string{"optimist"}}},
			[]remediation.ChainHint{
				{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Spec: "^0.5.1", InSpec: &remediation.ChainHintRelease{Version: "0.5.6", Range: "^4.19.2", Fixes: true}},
				{Package: "express", Parent: "optimist", ParentVersion: "0.6.1", Spec: "^0.6.1", InSpec: &remediation.ChainHintRelease{Version: "0.6.1", Range: "~4.18.0"}},
			},
			[]string{
				"依存元の mkdirp 0.5.1 が express を 4.18.2、optimist 0.6.1 が express を `~4.18.0` と指定しているため上げられない",
				"  • package.json の mkdirp の指定（^0.5.1）の範囲で最新の 0.5.6 は、express を ^4.19.2 と指定（修正版を含む）\n  • package.json の optimist の指定（^0.6.1）の範囲では、今の 0.6.1 が最新",
			},
			[]string{"  • the newest mkdirp 0.5.6 within the package.json range (^0.5.1) requires express ^4.19.2 (a fixed version included)\n  • within the package.json range of optimist (^0.6.1), the current 0.6.1 is the newest"}},
		{"two dependents, one hint: still named", remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed,
			[]remediation.ChainBlock{held, {Package: "express", Version: "4.18.2", Parent: "optimist", ParentVersion: "0.6.1", Range: "~4.18.0", Proof: "upper_bound", Via: []string{"optimist"}}},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Spec: "^0.5.1", Latest: &remediation.ChainHintRelease{Version: "1.0.4", Range: "^4.19.2", Fixes: true}}},
			[]string{"  • mkdirp 1 系の最新の 1.0.4 は、express を ^4.19.2 と指定（修正版を含む）"},
			[]string{"  • the newest mkdirp 1.0.4 of the 1 series requires express ^4.19.2 (a fixed version included)"}},
		{"rejected keeps its line and gets the hints", remediation.ChainRejected, remediation.ReasonDependentsRejected, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Spec: "^0.5.1",
				Latest: &remediation.ChainHintRelease{Version: "1.0.4", Range: "^4.19.2", Fixes: true}}},
			[]string{"express 4.18.2 → 4.19.2 には mkdirp 0.5.1 の更新も必要だが、", "\n  • 1 系の最新の 1.0.4 は、express を ^4.19.2 と指定（修正版を含む）"},
			[]string{"\n  • the newest 1.0.4 of the 1 series requires express ^4.19.2 (a fixed version included)"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := languageFixture()
			li := chainItem(&p)
			li.Update.Chain = &remediation.ChainUpdate{Outcome: c.outcome, Reason: remediation.ReasonSourceIntroduced, Blocked: c.blocked,
				Tops: []remediation.ChainMove{{Name: "mkdirp", From: "0.5.1", Kind: "top"}}, Hints: c.hints}
			li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonTargetNotUpdated
			li.Packages[0].Action, li.Packages[0].Reason = remediation.ActionManual, c.reason
			info := &PlanInfo{Plan: &p, Changed: true}
			ja := slackPlanText(r, info, LanguageJA)
			for _, want := range c.ja {
				if !strings.Contains(ja, want) {
					t.Errorf("ja lacks %q:\n%s", want, ja)
				}
			}
			en := slackPlanText(r, info, LanguageEN)
			for _, want := range c.en {
				if !strings.Contains(en, want) {
					t.Errorf("en lacks %q:\n%s", want, en)
				}
			}
		})
	}
}
