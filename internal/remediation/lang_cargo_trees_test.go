package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// globWorkspace is a workspace whose one member is found by a "crates/*"
// entry.
func globWorkspace(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"Cargo.toml":          "[workspace]\nmembers = [\"crates/*\"]\n",
		"crates/a/Cargo.toml": cargoFixture(t, "exp1.Cargo.toml"),
		"crates/a/src/lib.rs": cargoLibRS,
		"Cargo.lock":          cargoFixture(t, "check_tokio_1_18_0.Cargo.lock"),
	}
}

// withoutRootTree hides the part of a reader that gives the tree of the root.
type withoutRootTree struct{ GitHubReader }

// The plan records the tree of a directory whose listing decided which members
// the workspace has, and only of those.
func TestCargoTrees_RecordedForTheDirectoryAGlobExpands(t *testing.T) {
	f := newCargoFlow(t, globWorkspace(t), realTokioIndex(t), tokioInput(), nil)
	want := []SourceTree{{Path: "svc/crates", SHA: fakeTreeSHA("ex/app", "svc/crates")}}
	if got := f.item.Source.Trees; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("trees = %+v, want %+v", got, want)
	}
	if got := strings.Join(f.item.Cargo.GlobDirs, ","); got != "svc/crates" {
		t.Errorf("glob dirs = %q", got)
	}

	// A workspace whose members are all named by path expands nothing.
	f = newTokioFlow(t)
	if len(f.item.Source.Trees) != 0 {
		t.Errorf("trees = %+v for a package without a glob", f.item.Source.Trees)
	}

	// Two entries that expand the same directory record it once.
	files := globWorkspace(t)
	files["Cargo.toml"] = "[workspace]\nmembers = [\"crates/*\", \"crates/*\"]\n"
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", files)
	it := cargoItem(t, cargoPlan(t, gh, tokioInput()))
	if len(it.Source.Trees) > 1 {
		t.Errorf("trees = %+v", it.Source.Trees)
	}
}

// The listing of the directory's parent has to give its tree SHA; a listing
// that does not stops the unit.
func TestCargoTrees_ListingWithoutATreeSHAIsNotUsed(t *testing.T) {
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", globWorkspace(t))
	for i, e := range gh.dirs["ex/app/svc"] {
		if e.Name == "crates" {
			gh.dirs["ex/app/svc"][i].SHA = ""
		}
	}
	it := cargoItem(t, cargoPlan(t, gh, tokioInput()))
	if it.Category != CategoryFailed || it.Reason != ReasonSourceError || !strings.Contains(it.Detail, "no tree SHA for crates") {
		t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
}

// A glob in the repository root needs the tree of the root commit, which a
// reader that cannot give it leaves to a person.
func TestCargoTrees_RootGlob(t *testing.T) {
	setup := func() *fakeGitHub {
		gh := newFakeGitHub()
		cargoRepo(gh, "ex/app", ".", map[string]string{
			"Cargo.toml":   "[workspace]\nmembers = [\"*\"]\n",
			"a/Cargo.toml": cargoFixture(t, "exp1.Cargo.toml"),
			"a/src/lib.rs": cargoLibRS,
			"Cargo.lock":   cargoFixture(t, "check_tokio_1_18_0.Cargo.lock"),
			"README.md":    "a file the pattern skips\n",
		})
		return gh
	}
	deps := []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}
	in := langInput("shop", "api", rustFinding("CVE-TOKIO", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", "1.18.4"))

	gh := setup()
	it := cargoItem(t, langPlan(t, gh, deps, nil, in).LanguageItems)
	if want := []SourceTree{{Path: ".", SHA: fakeTreeSHA("ex/app", ".")}}; len(it.Source.Trees) != 1 || it.Source.Trees[0] != want[0] {
		t.Errorf("trees = %+v, want %+v (%s %s %s)", it.Source.Trees, want, it.Category, it.Reason, it.Detail)
	}

	it = cargoItem(t, langPlan(t, withoutRootTree{setup()}, deps, nil, in).LanguageItems)
	if it.Category != CategoryManual || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, "repository root") || len(it.Source.Trees) != 0 {
		t.Errorf("item = %s %s (%s) trees %+v", it.Category, it.Reason, it.Detail, it.Source.Trees)
	}
}

// The update stage reads the workspace again with the same code and requires
// the directories it expands to be the ones the plan recorded, tree included.
func TestCargoTrees_UpdateStageChecksTheTrees(t *testing.T) {
	f := newCargoFlow(t, globWorkspace(t), realTokioIndex(t), tokioInput(), nil)
	if it := f.run(); it.Category != CategoryPRCandidate {
		t.Fatalf("an unchanged workspace gave %s %s (%s)", it.Category, it.Reason, it.Detail)
	}

	f = newCargoFlow(t, globWorkspace(t), realTokioIndex(t), tokioInput(), nil)
	f.item.Source.Trees[0].SHA = strings.Repeat("0", 40)
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonSourceChanged, "svc/crates")
	if len(f.work.jobs) != 0 {
		t.Error("a job was run")
	}

	// The same commit read again gives another tree.
	f = newCargoFlow(t, globWorkspace(t), realTokioIndex(t), tokioInput(), nil)
	for i, e := range f.gh.dirs["ex/app/svc"] {
		if e.Name == "crates" {
			f.gh.dirs["ex/app/svc"][i].SHA = strings.Repeat("1", 40)
		}
	}
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonSourceChanged, "svc/crates")

	// A plan that recorded no directory for a workspace that expands one.
	f = newCargoFlow(t, globWorkspace(t), realTokioIndex(t), tokioInput(), nil)
	f.item.Source.Trees = nil
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonSourceChanged, "svc/crates")
}

func TestDirTreeSHA(t *testing.T) {
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", globWorkspace(t))
	gh.putEntry("ex/app", "svc", github.Entry{Name: "link", Type: github.EntrySymlink, SHA: strings.Repeat("2", 40)})
	ctx := context.Background()
	if got, err := dirTreeSHA(ctx, gh, "ex/app", testCommit, "svc/crates"); err != nil || got != fakeTreeSHA("ex/app", "svc/crates") {
		t.Errorf("svc/crates = %q, %v", got, err)
	}
	if got, err := dirTreeSHA(ctx, gh, "ex/app", testCommit, "."); err != nil || got != fakeTreeSHA("ex/app", ".") {
		t.Errorf("root = %q, %v", got, err)
	}
	if _, err := dirTreeSHA(ctx, withoutRootTree{gh}, "ex/app", testCommit, "."); err != errNoRootTree {
		t.Errorf("root without a reader that gives it: %v", err)
	}
	if _, err := dirTreeSHA(ctx, gh, "ex/app", testCommit, "svc/gone"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("a missing directory: %v", err)
	}
	if _, err := dirTreeSHA(ctx, gh, "ex/app", testCommit, "svc/link"); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a link: %v", err)
	}
}

// The directories a plan listed are part of what the update is made from, and
// a plan with none has the fingerprint it had before the field existed.
func TestLanguageInputFingerprint_Trees(t *testing.T) {
	pkg := LanguagePackage{Ecosystem: "gomod", Name: "golang.org/x/net", Installed: "v0.1.0", SelectionLowerBound: "v0.2.0", Action: ActionUpdate}
	files := []SourceFile{{Path: "svc/go.mod", BlobSHA: "aaaa"}, {Path: "svc/go.sum", BlobSHA: "bbbb"}}
	goItem := LanguageItem{Key: "deps:example/app@main:svc#go", Manager: ManagerGo, GoBuiltWith: "1.26.10",
		Source: SourceRecord{Files: files, Absent: []string{"svc/go.work"}}, Packages: []LanguagePackage{pkg}}
	// The fingerprints of items without the field, as they were computed
	// before it was added.
	if got, want := LanguageInputFingerprint(goItem), "d39c7f26c913e9960ec9dc26398ca8e6c0dbf110e8ff69191be141e07b99beed"; got != want {
		t.Errorf("go fingerprint = %s, want %s", got, want)
	}
	cargoItem := goItem
	cargoItem.Manager, cargoItem.Key, cargoItem.Source.Absent = ManagerCargo, "deps:example/app@main:svc#cargo", nil
	if got, want := LanguageInputFingerprint(cargoItem), "39b1bb03e1d94a148048b882116a0724965b2bc6df0df6ce930ae66c8ef6bae6"; got != want {
		t.Errorf("cargo fingerprint = %s, want %s", got, want)
	}
	cargoItem.Source.Trees = []SourceTree{}
	if got := LanguageInputFingerprint(cargoItem); got != "39b1bb03e1d94a148048b882116a0724965b2bc6df0df6ce930ae66c8ef6bae6" {
		t.Errorf("an empty list changed the fingerprint: %s", got)
	}

	a, b := SourceTree{Path: "svc/crates", SHA: strings.Repeat("a", 40)}, SourceTree{Path: "svc/tools", SHA: strings.Repeat("b", 40)}
	cargoItem.Source.Trees = []SourceTree{a, b}
	fp := LanguageInputFingerprint(cargoItem)
	if fp == "39b1bb03e1d94a148048b882116a0724965b2bc6df0df6ce930ae66c8ef6bae6" {
		t.Error("the trees are not in the fingerprint")
	}
	cargoItem.Source.Trees = []SourceTree{b, a}
	if got := LanguageInputFingerprint(cargoItem); got != fp {
		t.Error("the order of the trees changes the fingerprint")
	}
	cargoItem.Source.Trees = []SourceTree{a, {Path: b.Path, SHA: strings.Repeat("c", 40)}}
	if got := LanguageInputFingerprint(cargoItem); got == fp {
		t.Error("another tree SHA gives the same fingerprint")
	}
}
