package remediation

import (
	"strings"
	"testing"
	"time"
)

// itCargoUpdate runs the update of tokio 1.18.0, the single crate of
// testdata/cargo/exp1.Cargo.toml and check_tokio_1_18_0.Cargo.lock, in the work
// container of the Rust image, against the real crates.io index and a real
// Trivy, and requires it to be a pull request candidate that takes tokio to
// 1.18.4 or above. The vulnerability the crate has there (CVE-2023-22466) is of
// medium severity, so the scans of this case include that severity.
func itCargoUpdate(t *testing.T, e *itEnv) LanguageItem {
	t.Helper()
	files := map[string]string{
		"Cargo.toml": cargoFixture(t, "exp1.Cargo.toml"),
		"Cargo.lock": cargoFixture(t, "check_tokio_1_18_0.Cargo.lock"),
		"src/lib.rs": "pub fn f() {}\n",
	}
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", files)
	in := langInput("shop", "api", rustFinding("CVE-2023-22466", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", "1.18.4, 1.20.3, 1.23.1"))
	it := cargoItem(t, cargoPlan(t, gh, in))
	if it.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the fixture is not an update candidate: %s %s %s", it.Category, it.Reason, it.Detail)
	}

	tr := e.trivy
	tr.Severity = []string{"MEDIUM", "HIGH", "CRITICAL"}
	prepared, err := tr.CurrentConditions(e.ctx)
	if err != nil {
		t.Fatalf("trivy conditions: %v", err)
	}
	cfg := e.config(LangUpdateConfig{GitHub: gh, MaxJobs: 4, JobIDPrefix: "it"})
	cfg.Scanner, cfg.Prepared = tr, prepared
	up, err := NewLangUpdater(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{it}}
	start := time.Now()
	up.Run(e.ctx, plan)
	got := plan.LanguageItems[0]
	t.Logf("category=%s reason=%s detail=%q took=%s", got.Category, got.Reason, got.Detail, time.Since(start).Round(time.Millisecond))
	if got.Update != nil {
		t.Logf("steps=%+v notes=%v cargo=%+v", got.Update.Steps, got.Update.Notes, got.Update.Cargo)
	}
	if got.Category != CategoryPRCandidate {
		t.Fatalf("category = %s (%s: %s), want pr_candidate", got.Category, got.Reason, got.Detail)
	}
	if !got.UpdateExecuted || !got.PostUpdateCheckExecuted {
		t.Errorf("executed flags = %v %v", got.UpdateExecuted, got.PostUpdateCheckExecuted)
	}
	p := got.Packages[0]
	if c, ok := compareVersions(schemeSemver, p.AdoptedVersion, "1.18.4"); !ok || c < 0 || !strings.HasPrefix(p.AdoptedVersion, "1.") {
		t.Errorf("adopted = %q, want 1.18.4 or above", p.AdoptedVersion)
	}
	if rt := got.Update.Runtime; rt == nil || rt.Digest == "" || !strings.HasPrefix(rt.ID, "rust") {
		t.Errorf("runtime = %+v", got.Update.Runtime)
	}
	if sc := got.SourceCheck; sc == nil || !sc.Passed || len(sc.Resolved) == 0 || sc.Resolved[0].VulnID != "CVE-2023-22466" {
		t.Fatalf("source check = %+v", sc)
	}
	if len(got.Artifacts) != 1 || got.Artifacts[0].Path != "svc/Cargo.lock" || len(got.Artifacts[0].Content) == 0 {
		t.Errorf("artifacts = %+v", got.Artifacts)
	}
	if got.Update.Cargo == nil || len(got.Update.Cargo.Targets) != 1 {
		t.Errorf("cargo change = %+v", got.Update.Cargo)
	}
	return got
}
