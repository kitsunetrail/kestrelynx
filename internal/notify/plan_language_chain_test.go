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
			"express 4.18.2 cannot be raised to the fixed 4.19.2 (the dependent mkdirp 0.5.1 limits the version of express)",
			"express 4.18.2 を修正版の 4.19.2 に上げられない（依存元の mkdirp 0.5.1 が express の版を制限）"},
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

// The hints are listed under the package's chain line, one release of a
// dependent a line, saying whether it lets the project use a fixed version.
func TestPlanSlack_ChainHints(t *testing.T) {
	r, _, _ := planCycleFixture()
	held := remediation.ChainBlock{Package: "express", Version: "4.18.2", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "4.18.2", Proof: "exact", Via: []string{"mkdirp"}}
	below := remediation.ChainBlock{Package: "express", Version: "4.18.2", Parent: "mkdirp", ParentVersion: "0.5.1", Range: "4.18.2", Proof: "exact", Via: []string{"app-kit"}}
	optimist := remediation.ChainBlock{Package: "express", Version: "4.18.2", Parent: "optimist", ParentVersion: "0.6.1", Range: "~4.18.0", Proof: "upper_bound", Via: []string{"optimist"}}
	rel := func(v, rng string, fixes bool) *remediation.ChainHintRelease {
		return &remediation.ChainHintRelease{Version: v, Range: rng, Fixes: fixes}
	}
	cases := []struct {
		name    string
		manager remediation.DependencyManager
		outcome string
		reason  remediation.Reason
		blocked []remediation.ChainBlock
		hints   []remediation.ChainHint
		ja, en  []string
	}{
		{"in range and newest", remediation.ManagerNpm, remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Direct: true, Spec: "^0.5.1", InSpec: rel("0.5.6", "4.18.2", false), Latest: rel("1.0.4", "^4.19.2", true)}},
			[]string{"express 4.18.2 を修正版の 4.19.2 に上げられない（依存元の mkdirp 0.5.1 が express の版を制限）\n  • mkdirp 0.5.6（package.json で指定している範囲の最新）: 修正版の express を使えない\n  • mkdirp 1.0.4（最新）: 修正版の express を使える"},
			[]string{"express 4.18.2 cannot be raised to the fixed 4.19.2 (the dependent mkdirp 0.5.1 limits the version of express)\n  • mkdirp 0.5.6 (newest within the range package.json specifies): cannot use a fixed express\n  • mkdirp 1.0.4 (newest): can use a fixed express"}},
		{"the release it has is the newest in range", remediation.ManagerNpm, remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Direct: true, Spec: "^0.5.1", InSpec: rel("0.5.1", "4.18.2", false)}},
			[]string{"  • mkdirp 0.5.1（package.json で指定している範囲の最新）: 修正版の express を使えない"},
			[]string{"  • mkdirp 0.5.1 (newest within the range package.json specifies): cannot use a fixed express"}},
		{"a dependent below a direct dependency", remediation.ManagerNpm, remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{below},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Via: []string{"app-kit"}, Latest: rel("0.5.6", "^4.19.2", true)}},
			[]string{"  • mkdirp 0.5.6（最新）: 修正版の express を使える\n  • app-kit のどの版でこの mkdirp が入るかは未確認"},
			[]string{"  • mkdirp 0.5.6 (newest): can use a fixed express\n  • which release of app-kit brings in this mkdirp is not checked"}},
		{"dropped", remediation.ManagerNpm, remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Direct: true, Spec: "^0.5.1", Latest: &remediation.ChainHintRelease{Version: "1.0.4", Dropped: true}}},
			[]string{"  • mkdirp 1.0.4（最新）: express を直接は使っていない"},
			[]string{"  • mkdirp 1.0.4 (newest): does not use express directly"}},
		{"two dependents", remediation.ManagerNpm, remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held, optimist},
			[]remediation.ChainHint{
				{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Direct: true, Spec: "^0.5.1", InSpec: rel("0.5.6", "^4.19.2", true)},
				{Package: "express", Parent: "optimist", ParentVersion: "0.6.1", Direct: true, Spec: "^0.6.1", InSpec: rel("0.6.1", "~4.18.0", false)},
			},
			[]string{"（依存元の mkdirp 0.5.1、optimist 0.6.1 が express の版を制限）\n  • mkdirp 0.5.6（package.json で指定している範囲の最新）: 修正版の express を使えるが、今回の更新では上げられなかった\n  • optimist 0.6.1（package.json で指定している範囲の最新）: 修正版の express を使えない"},
			[]string{"(the dependent mkdirp 0.5.1, optimist 0.6.1 limits the version of express)"}},
		{"rejected: the newest in range allowing the fix reads plainly", remediation.ManagerNpm, remediation.ChainRejected, remediation.ReasonDependentsRejected, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Direct: true, Spec: "^0.5.1", InSpec: rel("0.5.6", "^4.19.2", true)}},
			[]string{"  • mkdirp 0.5.6（package.json で指定している範囲の最新）: 修正版の express を使える\n"},
			[]string{"  • mkdirp 0.5.6 (newest within the range package.json specifies): can use a fixed express\n"}},
		{"rejected keeps its line and gets the hints", remediation.ManagerNpm, remediation.ChainRejected, remediation.ReasonDependentsRejected, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Direct: true, Spec: "^0.5.1", Latest: rel("1.0.4", "^4.19.2", true)}},
			[]string{"express 4.18.2 → 4.19.2 には mkdirp 0.5.1 の更新も必要だが、", "\n  • mkdirp 1.0.4（最新）: 修正版の express を使える"},
			[]string{"\n  • mkdirp 1.0.4 (newest): can use a fixed express"}},
		{"uv speaks of pyproject.toml, and no resolution reads the same", remediation.ManagerUv, remediation.ChainNotFixed, remediation.ReasonDependentsNotFixed, []remediation.ChainBlock{held},
			[]remediation.ChainHint{{Package: "express", Parent: "mkdirp", ParentVersion: "0.5.1", Direct: true, InSpec: rel("0.5.6", "", true)}},
			[]string{"express 4.18.2 を修正版の 4.19.2 に上げられない（依存元の mkdirp 0.5.1 が express の版を制限）\n  • mkdirp 0.5.6（pyproject.toml で指定している範囲の最新）: 修正版の express を使えるが、今回の更新では上げられなかった"},
			[]string{"  • mkdirp 0.5.6 (newest within the range pyproject.toml specifies): can use a fixed express, but this update did not raise it"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := languageFixture()
			li := chainItem(&p)
			li.Manager = c.manager
			chainReason := remediation.ReasonSourceIntroduced
			if c.manager == remediation.ManagerUv {
				chainReason = remediation.ReasonNoResolution
			}
			li.Update.Chain = &remediation.ChainUpdate{Outcome: c.outcome, Reason: chainReason, Blocked: c.blocked,
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

// A uv item's hints are found under the package's name however the image
// writes it, and are listed for a package left out of the update too.
func TestPlanSlack_ChainHintsUvNames(t *testing.T) {
	r, _, _ := planCycleFixture()
	chain := &remediation.ChainUpdate{Outcome: remediation.ChainNotFixed,
		Blocked: []remediation.ChainBlock{{Package: "pyyaml", Version: "5.3", Parent: "awscli", ParentVersion: "1.18.0", Range: "<5.4,>=3.10", Proof: "upper_bound", Via: []string{"awscli"}}},
		Hints: []remediation.ChainHint{{Package: "pyyaml", Parent: "awscli", ParentVersion: "1.18.0", Direct: true,
			InSpec: &remediation.ChainHintRelease{Version: "1.40.0", Fixes: true}}}}
	want := []string{
		"PyYAML 5.3 を修正版の 5.4 に上げられない（依存元の awscli 1.18.0 が PyYAML の版を制限）",
		"  • awscli 1.40.0（pyproject.toml で指定している範囲の最新）: 修正版の PyYAML を使えるが、今回の更新では上げられなかった",
	}
	t.Run("manual", func(t *testing.T) {
		p := languageFixture()
		li := chainItem(&p)
		li.Manager = remediation.ManagerUv
		li.Update.Chain = chain
		li.Packages[0].Name, li.Packages[0].Installed, li.Packages[0].SelectionLowerBound = "PyYAML", "5.3", "5.4"
		li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonTargetNotUpdated
		li.Packages[0].Action, li.Packages[0].Reason = remediation.ActionManual, remediation.ReasonDependentsNotFixed
		ja := slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, LanguageJA)
		for _, w := range want {
			if !strings.Contains(ja, w) {
				t.Errorf("ja lacks %q:\n%s", w, ja)
			}
		}
	})
	t.Run("left out", func(t *testing.T) {
		p := leftOutFixture()
		li := &p.LanguageItems[0]
		li.Manager = remediation.ManagerUv
		li.Update = &remediation.LanguageUpdate{Chain: chain}
		li.Packages[1].Name, li.Packages[1].Installed, li.Packages[1].SelectionLowerBound, li.Packages[1].Reason = "PyYAML", "5.3", "5.4", remediation.ReasonDependentsNotFixed
		ja := slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, LanguageJA)
		if !strings.Contains(ja, want[1]) {
			t.Errorf("ja lacks %q:\n%s", want[1], ja)
		}
	})
}
