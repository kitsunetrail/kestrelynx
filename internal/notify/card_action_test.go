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
	// An item that is not a candidate says nothing here.
	p = candidatePlan(t, resolved(), resolved())
	p.Plan.Items[0].Category = remediation.CategoryManual
	if got := actionLineOf(t, r, p, LanguageEN); got != "" {
		t.Errorf("a manual item gives the line %q", got)
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
