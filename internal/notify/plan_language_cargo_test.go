package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// cargoUpdated is a Cargo item the update stage has handled, with the pull
// request unit made of it.
func cargoUpdated() (remediation.LanguageItem, remediation.PRUnit) {
	li := languageUpdated("deps:ex/app@main:.#cargo")
	li.Manager = remediation.ManagerCargo
	li.Source.Files = []remediation.SourceFile{{Path: "Cargo.lock", BlobSHA: strings.Repeat("b", 40)}, {Path: "Cargo.toml", BlobSHA: strings.Repeat("d", 40)}}
	li.Source.Trees = []remediation.SourceTree{{Path: "crates", SHA: strings.Repeat("e", 40)}}
	li.Packages = []remediation.LanguagePackage{{Name: "tokio", Ecosystem: "cargo", Installed: "1.18.0", AdoptedVersion: "1.18.4", Action: remediation.ActionUpdate,
		Relation: remediation.RelationDirect, CVEs: []remediation.CVERef{{VulnID: "CVE-2023-22466"}}}}
	li.Update = &remediation.LanguageUpdate{
		Steps: []remediation.UpdateStep{{ID: "update", Op: "cargo.update"}},
		Cargo: &remediation.CargoLockChange{
			Targets: []remediation.CargoCrateChange{{Name: "tokio", From: "1.18.0", To: "1.18.4"}}, LockVersionFrom: 4, LockVersionTo: 4,
			Moved: []remediation.CargoCrateRef{{Name: "tokio", Version: "1.18.4"}}, MaxRustVersion: "1.63.0",
		},
	}
	li.Artifacts = []remediation.ArtifactFile{{Path: "Cargo.lock", SHA256: strings.Repeat("c", 64), Size: 3, Mode: "100644", Content: []byte("new")}}
	u := languageUnit(remediation.PRStatusCreated, 4, "")
	u.Key, u.ItemKey, u.Path = "language|ex/app|main|Cargo.lock", li.Key, "Cargo.lock"
	u.Language = &remediation.PRLanguage{Manager: "cargo", Root: ".", Packages: []remediation.PRLanguagePackage{
		{Name: "tokio", Ecosystem: "cargo", Relation: "direct", From: "1.18.0", To: "1.18.4"},
	}}
	return li, u
}

// A Cargo item is shown as the other dependency items are, with the lockfile
// named Cargo.lock.
func TestPlanSlack_CargoItem(t *testing.T) {
	r := planReport()
	li, u := cargoUpdated()
	for lang, wants := range map[Language][]string{
		LanguageJA: {"Cargo.lock", "tokio", "1.18.4"},
		LanguageEN: {"Cargo.lock", "tokio", "1.18.4"},
	} {
		got := slackPlanText(r, languagePlanOf(li, u), lang)
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %q in\n%s", lang, w, got)
			}
		}
		if strings.Contains(got, "package-lock.json") || strings.Contains(got, "go.mod") {
			t.Errorf("%s: another manager's file is named:\n%s", lang, got)
		}
	}

	// An item that is not yet updated names the lockfile too.
	li.Category, li.Reason = remediation.CategoryDependencyUpdateCandidate, remediation.ReasonUpdateCandidateInSource
	li.Update, li.SourceCheck, li.Artifacts = nil, nil, nil
	li.Packages[0].SelectionLowerBound, li.Packages[0].AdoptedVersion = "1.18.4", ""
	if got := slackPlanText(r, languagePlanOf(li), LanguageEN); !strings.Contains(got, "Cargo.lock") || !strings.Contains(got, "tokio") {
		t.Errorf("a candidate does not name Cargo.lock:\n%s", got)
	}
}

// A crate whose fixes are all of another series is shown with the lowest such
// fix.
func TestPlanSlack_CargoFixInAnotherSeries(t *testing.T) {
	r := planReport()
	li, _ := cargoUpdated()
	li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonCargoFixInOtherSeries
	li.Update, li.SourceCheck, li.Artifacts = nil, nil, nil
	li.Packages = []remediation.LanguagePackage{{Name: "tokio", Ecosystem: "cargo", Installed: "1.18.0", Action: remediation.ActionManual, Reason: remediation.ReasonCargoFixInOtherSeries,
		FixHint: &remediation.FixHint{Fix: &remediation.FixRelease{Version: "2.0.1"}}}}
	for lang, want := range map[Language]string{
		LanguageJA: "tokio 1.18.0 の修正版は互換でない系列（2.0.1）にしかない",
		LanguageEN: "tokio 1.18.0 has its fixes only in a series not compatible with it (2.0.1)",
	} {
		if got := slackPlanText(r, languagePlanOf(li), lang); !strings.Contains(got, want) {
			t.Errorf("%s: missing %q in\n%s", lang, want, got)
		}
	}
}

// A crate of which no one release is known to fix every advisory is shown with
// the fix each advisory names.
func TestPlanSlack_CargoFixOfEachAdvisory(t *testing.T) {
	r := planReport()
	li, _ := cargoUpdated()
	li.Category, li.Reason = remediation.CategoryManual, remediation.ReasonCargoFixInOtherSeries
	li.Update, li.SourceCheck, li.Artifacts = nil, nil, nil
	li.Packages = []remediation.LanguagePackage{{Name: "ml-dsa", Ecosystem: "cargo", Installed: "0.0.4", Action: remediation.ActionManual, Reason: remediation.ReasonCargoFixInOtherSeries,
		FixHint: &remediation.FixHint{Advisories: []remediation.AdvisoryFix{{VulnID: "CVE-2026-22705", Version: "0.1.0-rc.3"}, {VulnID: "CVE-2026-24850", Version: "0.1.0-rc.4"}, {VulnID: "GHSA-h37v-hp6w-2pp8", Version: "0.1.0-rc.5"}}}}}
	for lang, want := range map[Language]string{
		LanguageJA: "ml-dsa 0.0.4 の修正版は互換でない系列にしかなく、すべての勧告を直す版は分からない（CVE-2026-22705 0.1.0-rc.3",
		LanguageEN: "ml-dsa 0.0.4 has its fixes only in series not compatible with it, and no one release is known to fix every advisory (CVE-2026-22705 0.1.0-rc.3",
	} {
		if got := slackPlanText(r, languagePlanOf(li), lang); !strings.Contains(got, want) || !strings.Contains(got, "CVE-2026-24850 0.1.0-rc.4") || !strings.Contains(got, "GHSA-h37v-hp6w-2pp8 0.1.0-rc.5") {
			t.Errorf("%s: missing %q in\n%s", lang, want, got)
		}
	}
}

// The webhook carries what a Cargo update changed in Cargo.lock and the
// directories the plan listed, and never the content of the file.
func TestWebhook_CargoItem(t *testing.T) {
	r, changed, _ := planCycleFixture()
	li, u := cargoUpdated()
	raw, err := json.Marshal(BuildWebhookPayloadWithPlan(r, &changed, languagePlanOf(li, u)))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	item := payload["remediation"].(map[string]any)["language_items"].([]any)[0].(map[string]any)
	cargo := item["update"].(map[string]any)["cargo"].(map[string]any)
	if cargo["lock_version_to"] != float64(4) || cargo["max_rust_version"] != "1.63.0" || len(cargo["targets"].([]any)) != 1 {
		t.Errorf("cargo = %v", cargo)
	}
	trees := item["source"].(map[string]any)["trees"].([]any)
	if len(trees) != 1 || trees[0].(map[string]any)["path"] != "crates" {
		t.Errorf("trees = %v", trees)
	}
	if item["manager"] != "cargo" || strings.Contains(string(raw), "bmV3") {
		t.Errorf("item = %v", item)
	}

	// An item of another manager has no trees key.
	other := languageUpdated("deps:ex/app@main:.#npm")
	raw, err = json.Marshal(BuildWebhookPayloadWithPlan(r, &changed, languagePlanOf(other)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\"trees\"") {
		t.Error("a trees key appears for an item that listed no directory")
	}
}
