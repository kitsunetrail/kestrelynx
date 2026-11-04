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

// A pip package that the packages depending on it hold back is shown with
// them and with what their newest releases declare, whether the item is
// manual for it or a pull request leaves it out.
func TestPlanSlack_PipHeldBack(t *testing.T) {
	r, _, _ := planCycleFixture()
	hint := &remediation.FixHint{
		HeldBy: []remediation.FixHolder{{Parent: "botocore", ParentVersion: "1.34.0", Range: "<2.1,>=1.25.4"}},
		Releases: []remediation.ChainHint{{Package: "urllib3", Parent: "botocore", ParentVersion: "1.34.0",
			Latest: &remediation.ChainHintRelease{Version: "1.35.10", Range: "<3,>=1.25.4", Fixes: true}}},
	}
	ja := []string{
		"urllib3 1.26.18 を修正版の 2.2.2 に上げられない（依存元の botocore 1.34.0 が urllib3 の版を制限）",
		"  • botocore 1.35.10（最新）: 修正版の urllib3 を使える",
	}
	en := []string{
		"urllib3 1.26.18 cannot be raised to the fixed 2.2.2 (the dependent botocore 1.34.0 limits the version of urllib3)",
		"  • botocore 1.35.10 (newest): can use a fixed urllib3",
	}
	check := func(t *testing.T, p *remediation.Plan) {
		t.Helper()
		info := &PlanInfo{Plan: p, Changed: true}
		got := slackPlanText(r, info, LanguageJA)
		for _, w := range ja {
			if !strings.Contains(got, w) {
				t.Errorf("ja lacks %q:\n%s", w, got)
			}
		}
		got = slackPlanText(r, info, LanguageEN)
		for _, w := range en {
			if !strings.Contains(got, w) {
				t.Errorf("en lacks %q:\n%s", w, got)
			}
		}
	}
	t.Run("manual", func(t *testing.T) {
		p := languageFixture()
		li := &p.LanguageItems[0]
		li.Manager = remediation.ManagerPip
		li.Packages = li.Packages[:1]
		pk := &li.Packages[0]
		pk.Name, pk.Installed, pk.SelectionLowerBound = "urllib3", "1.26.18", "2.2.2"
		li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonDependentsHoldBack
		pk.Action, pk.Reason, pk.FixHint = remediation.ActionManual, remediation.ReasonDependentsHoldBack, hint
		check(t, &p)
	})
	t.Run("left out", func(t *testing.T) {
		p := leftOutFixture()
		li := &p.LanguageItems[0]
		li.Manager = remediation.ManagerPip
		pk := &li.Packages[1]
		pk.Name, pk.Installed, pk.SelectionLowerBound, pk.Reason, pk.FixHint = "urllib3", "1.26.18", "2.2.2", remediation.ReasonDependentsHoldBack, hint
		check(t, &p)
	})
	t.Run("a hint without its reason is not shown", func(t *testing.T) {
		p := languageFixture()
		li := &p.LanguageItems[0]
		li.Manager = remediation.ManagerPip
		li.Packages = li.Packages[:1]
		pk := &li.Packages[0]
		pk.Name, pk.Installed, pk.SelectionLowerBound = "urllib3", "1.26.18", "2.2.2"
		li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonPostUpdateCheckFailed
		pk.Action, pk.Reason, pk.FixHint = remediation.ActionManual, remediation.ReasonPostUpdateCheckFailed, hint
		if got := slackPlanText(r, &PlanInfo{Plan: &p, Changed: true}, LanguageJA); strings.Contains(got, "botocore") {
			t.Errorf("hint shown:\n%s", got)
		}
	})
}

// Go packages are shown with what decides them: the lowest fix of another
// major version and what brings the old one in, or the module whose go.mod
// asks for the Go an update needs.
func TestPlanSlack_GoHints(t *testing.T) {
	r, _, _ := planCycleFixture()
	cases := []struct {
		name           string
		reason         remediation.Reason
		target         string
		hint           *remediation.FixHint
		ja, en, absent string
	}{
		{"another major, through a dependent", remediation.ReasonFixInOtherMajor, "", &remediation.FixHint{
			Fix:      &remediation.FixRelease{Version: "v2.1.0"},
			HeldBy:   []remediation.FixHolder{{Parent: "example.com/mid", ParentVersion: "v1.0.0", Range: "v1.4.0"}},
			Releases: []remediation.ChainHint{{Package: "example.com/old", Parent: "example.com/mid", ParentVersion: "v1.0.0", Latest: &remediation.ChainHintRelease{Version: "v1.3.0", Dropped: true}}},
		},
			"example.com/old v1.4.0 の修正版は別のメジャー版（v2.1.0）にしかない（依存元の example.com/mid v1.0.0 が使っている）\n  • example.com/mid v1.3.0（最新）: example.com/old を直接は使っていない",
			"example.com/old v1.4.0 has its fixes only in another major version (v2.1.0) (the dependent example.com/mid v1.0.0 uses it)\n  • example.com/mid v1.3.0 (newest): does not use example.com/old directly", ""},
		{"another major, required directly", remediation.ReasonFixInOtherMajor, "", &remediation.FixHint{Fix: &remediation.FixRelease{Version: "v2.1.0"}, Direct: true},
			"example.com/old v1.4.0 の修正版は別のメジャー版（v2.1.0）にしかない（go.mod で直接指定・import の書き換えが必要）",
			"example.com/old v1.4.0 has its fixes only in another major version (v2.1.0) (go.mod requires it directly, so the imports need rewriting)", ""},
		{"go line", remediation.ReasonGoLineRaised, "v1.4.5", &remediation.FixHint{GoLine: &remediation.GoLineHint{Module: "example.com/old", Version: "v1.4.5", Go: "1.24", BuiltWith: "1.23.4"}},
			"example.com/old v1.4.0 を修正版の v1.4.5 に上げると、go.mod の go の行が 1.24 に上がる（example.com/old v1.4.5 の go.mod が go 1.24 を指定・稼働中のバイナリは Go 1.23.4 でビルド）",
			"example.com/old v1.4.0 cannot be raised to the fixed v1.4.5 without raising the go line of go.mod to 1.24 (the go.mod of example.com/old v1.4.5 declares go 1.24; the running binaries were built with Go 1.23.4)", ""},
		{"go line, build Go not known", remediation.ReasonGoLineRaised, "v1.4.5", &remediation.FixHint{GoLine: &remediation.GoLineHint{Module: "example.com/old", Version: "v1.4.5", Go: "1.24"}},
			"稼働中のバイナリをビルドした Go は不明）", "the Go the running binaries were built with is not known)", ""},
		{"go line, the version the update took", remediation.ReasonGoLineRaised, "v1.4.5", &remediation.FixHint{GoLine: &remediation.GoLineHint{Module: "example.com/old", Version: "v1.4.6", Go: "1.24", BuiltWith: "1.23.4", To: "v1.4.6"}},
			"example.com/old v1.4.0 を修正版の v1.4.6 に上げると", "cannot be raised to the fixed v1.4.6 without", ""},
		{"no supported Go", remediation.ReasonGoRuntimeUnavailable, "v1.4.5", &remediation.FixHint{GoLine: &remediation.GoLineHint{Module: "example.com/old", Version: "v1.4.5", Go: "1.99"}},
			"example.com/old v1.4.0 を修正版の v1.4.5 に上げるには Go 1.99 が必要（example.com/old v1.4.5 の go.mod が指定・サポート中の Go にない）",
			"example.com/old v1.4.0 needs Go 1.99 to be raised to the fixed v1.4.5 (the go.mod of example.com/old v1.4.5 declares it, and no supported Go is that new)", ""},
		{"a hint without its reason", remediation.ReasonGoReplace, "", &remediation.FixHint{Fix: &remediation.FixRelease{Version: "v2.1.0"}}, "", "", "v2.1.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := languageFixture()
			li := &p.LanguageItems[0]
			li.Manager = remediation.ManagerGo
			li.Packages = li.Packages[:1]
			pk := &li.Packages[0]
			pk.Name, pk.Installed, pk.SelectionLowerBound = "example.com/old", "v1.4.0", c.target
			li.Category, li.Reason = remediation.CategoryManual, c.reason
			pk.Action, pk.Reason, pk.FixHint = remediation.ActionManual, c.reason, c.hint
			info := &PlanInfo{Plan: &p, Changed: true}
			ja, en := slackPlanText(r, info, LanguageJA), slackPlanText(r, info, LanguageEN)
			if c.absent != "" {
				if strings.Contains(ja, c.absent) {
					t.Errorf("shown:\n%s", ja)
				}
				return
			}
			if !strings.Contains(ja, c.ja) {
				t.Errorf("ja lacks %q:\n%s", c.ja, ja)
			}
			if !strings.Contains(en, c.en) {
				t.Errorf("en lacks %q:\n%s", c.en, en)
			}
		})
	}
}

// Maven and Gradle packages are shown with the pom outside the project that
// decides their version and what two of its releases set them to, or with the
// lowest fix of another major version.
func TestPlanSlack_MavenHints(t *testing.T) {
	r, _, _ := planCycleFixture()
	const name = "com.fasterxml.jackson.core:jackson-databind"
	rel := func(v, set string, fixes, dropped bool) *remediation.ChainHintRelease {
		return &remediation.ChainHintRelease{Version: v, Range: set, Fixes: fixes, Dropped: dropped}
	}
	cases := []struct {
		name    string
		manager remediation.DependencyManager
		reason  remediation.Reason
		hint    *remediation.FixHint
		ja, en  string
	}{
		{"parent pom", remediation.ManagerMaven, remediation.ReasonMavenVersionSourceUnsupported, &remediation.FixHint{
			DecidedBy: &remediation.FixDecider{Kind: remediation.DeciderParentPOM, Name: "com.example:parent", Version: "1.0.0"},
			Releases:  []remediation.ChainHint{{Package: name, Parent: "com.example:parent", ParentVersion: "1.0.0", Direct: true, InSpec: rel("1.0.3", "2.13.4", true, false), Latest: rel("2.0.0", "", false, true)}},
		},
			name + " 2.13.0 を修正版の 2.13.4 に上げられない（版は親 pom の com.example:parent 1.0.0 が決めている）\n  • com.example:parent 1.0.3（同じマイナー版の最新）: 修正版を指定している\n  • com.example:parent 2.0.0（最新）: " + name + " を指定していない",
			name + " 2.13.0 cannot be raised to the fixed 2.13.4 (the version is decided by the parent pom com.example:parent 1.0.0)\n  • com.example:parent 1.0.3 (newest in the same minor version): specifies a fixed version\n  • com.example:parent 2.0.0 (newest): does not specify " + name},
		{"BOM", remediation.ManagerMaven, remediation.ReasonMavenVersionSourceUnsupported, &remediation.FixHint{
			DecidedBy: &remediation.FixDecider{Kind: remediation.DeciderBOM, Name: "org.example:platform-bom", Version: "1.2.0"},
			Releases:  []remediation.ChainHint{{Package: name, Parent: "org.example:platform-bom", ParentVersion: "1.2.0", Direct: true, InSpec: rel("1.2.7", "2.13.3", false, false)}},
		},
			"（版は BOM の org.example:platform-bom 1.2.0 が決めている）\n  • org.example:platform-bom 1.2.7（同じマイナー版の最新）: 修正版を指定していない",
			"(the version is decided by the BOM org.example:platform-bom 1.2.0)\n  • org.example:platform-bom 1.2.7 (newest in the same minor version): does not specify a fixed version"},
		{"Spring Boot", remediation.ManagerGradle, remediation.ReasonGradleVersionSourceUnsupported, &remediation.FixHint{
			DecidedBy: &remediation.FixDecider{Kind: remediation.DeciderSpringBoot, Name: "org.springframework.boot:spring-boot-dependencies", Version: "3.2.1"},
			Releases:  []remediation.ChainHint{{Package: name, Parent: "org.springframework.boot:spring-boot-dependencies", ParentVersion: "3.2.1", Direct: true, InSpec: rel("3.2.12", "2.15.4", true, false), Latest: rel("3.5.7", "2.19.2", true, false)}},
		},
			"（版は Spring Boot 3.2.1 の BOM が決めている）\n  • Spring Boot 3.2.12（同じマイナー版の最新）: 修正版を指定している\n  • Spring Boot 3.5.7（最新）: 修正版を指定している",
			"(the version is decided by the BOM of Spring Boot 3.2.1)\n  • Spring Boot 3.2.12 (newest in the same minor version): specifies a fixed version\n  • Spring Boot 3.5.7 (newest): specifies a fixed version"},
		{"another major", remediation.ManagerMaven, remediation.ReasonMavenReleaseNotFound, &remediation.FixHint{Fix: &remediation.FixRelease{Version: "3.0.1"}},
			name + " 2.13.0 の修正版は別のメジャー版（3.0.1）にしかない",
			name + " 2.13.0 has its fixes only in another major version (3.0.1)"},
		{"another major, planned so", remediation.ManagerGradle, remediation.ReasonMavenFixInOtherMajor, &remediation.FixHint{Fix: &remediation.FixRelease{Version: "3.0.1"}},
			name + " 2.13.0 の修正版は別のメジャー版（3.0.1）にしかない",
			name + " 2.13.0 has its fixes only in another major version (3.0.1)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := languageFixture()
			li := &p.LanguageItems[0]
			li.Manager = c.manager
			li.Packages = li.Packages[:1]
			pk := &li.Packages[0]
			pk.Name, pk.Ecosystem, pk.Installed, pk.SelectionLowerBound = name, "jar", "2.13.0", "2.13.4"
			li.Category, li.Reason = remediation.CategoryManual, c.reason
			pk.Action, pk.Reason, pk.FixHint = remediation.ActionManual, c.reason, c.hint
			info := &PlanInfo{Plan: &p, Changed: true}
			if ja := slackPlanText(r, info, LanguageJA); !strings.Contains(ja, c.ja) {
				t.Errorf("ja lacks %q:\n%s", c.ja, ja)
			}
			if en := slackPlanText(r, info, LanguageEN); !strings.Contains(en, c.en) {
				t.Errorf("en lacks %q:\n%s", c.en, en)
			}
		})
	}
}
