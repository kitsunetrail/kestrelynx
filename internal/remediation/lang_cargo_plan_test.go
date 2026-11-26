package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// --- helpers ---

// rustFinding is a fixed finding of a crate, of the scanner result type typ
// (typeRustBinary or typeCargo) in the result target.
func rustFinding(vuln, typ, target, crate, installed, fixed string) scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: typ, Target: target, Package: crate,
		InstalledVer: installed, FixedVer: fixed, Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

// rustBinaryPackages is the package list of a cargo-auditable binary: the
// root crate (none when rootName is empty) and the crates built into it, as
// name and version pairs.
func rustBinaryPackages(target, rootName, rootVersion string, deps ...string) scanner.ResultPackages {
	rp := scanner.ResultPackages{Target: target, Class: inventory.ClassLang, Type: typeRustBinary}
	if rootName != "" {
		rp.Packages = append(rp.Packages, scanner.Package{Name: rootName, Version: rootVersion, Relationship: "root"})
	}
	for i := 0; i+1 < len(deps); i += 2 {
		rp.Packages = append(rp.Packages, scanner.Package{Name: deps[i], Version: deps[i+1]})
	}
	return rp
}

// cargoPut adds a file at a repository path, and the directories above it to
// the listings of their parents.
func cargoPut(gh *fakeGitHub, repo, p, content string) {
	dir := path.Dir(p)
	gh.put(repo, dir, path.Base(p), content)
	for dir != "." {
		parent := path.Dir(dir)
		if _, ok := byName(gh.dirs[repo+"/"+parent], path.Base(dir)); !ok {
			gh.putEntry(repo, parent, github.Entry{Name: path.Base(dir), Type: github.EntryDir})
		}
		dir = parent
	}
}

// cargoRepo puts the files, by path relative to dir, into the repository.
func cargoRepo(gh *fakeGitHub, repo, dir string, files map[string]string) {
	for p, c := range files {
		cargoPut(gh, repo, pathIn(dir, p), c)
	}
}

// exp2Repo is a single package that depends on tokio, as cargo wrote it.
func exp2Repo(t *testing.T, gh *fakeGitHub) {
	t.Helper()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml": cargoFixture(t, "exp2.Cargo.toml"),
		"Cargo.lock": cargoFixture(t, "exp2.Cargo.lock"),
	})
}

// rustScan reads a Trivy report of testdata/cargo.
func rustScan(t *testing.T, name string) scanner.ImageScan {
	t.Helper()
	data, err := os.ReadFile("testdata/cargo/" + name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := scanner.ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// rustInput is a scanned image of a Compose service with the findings and
// packages of the given scans' Rust results.
func rustInput(scans ...scanner.ImageScan) ImageInput {
	in := langInput("shop", "api")
	for _, s := range scans {
		in.Scan.Findings = append(in.Scan.Findings, s.Findings...)
		in.Scan.Packages = append(in.Scan.Packages, s.Packages...)
	}
	return in
}

// exp2Input is an image with the application binary built from the exp2
// package, and a tool of another crate that has tokio at the same version.
func exp2Input(fs ...scanner.Finding) ImageInput {
	in := langInput("shop", "api", fs...)
	in.Scan.Packages = []scanner.ResultPackages{
		rustBinaryPackages("usr/local/bin/app", "exp2", "0.1.0", "once_cell", "1.21.4", "pin-project-lite", "0.2.18", "tokio", "1.18.0"),
		rustBinaryPackages("usr/local/bin/tool", "tool", "1.0.0", "tokio", "1.18.0"),
	}
	return in
}

const tokioFixes = "1.18.4, 1.20.3, 1.23.1"

func tokioApp(vuln string) scanner.Finding {
	return rustFinding(vuln, typeRustBinary, "usr/local/bin/app", "tokio", "1.18.0", tokioFixes)
}

func cargoPlan(t *testing.T, gh *fakeGitHub, ins ...ImageInput) []LanguageItem {
	t.Helper()
	return langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}, nil, ins...).LanguageItems
}

func cargoItem(t *testing.T, items []LanguageItem) LanguageItem {
	t.Helper()
	var found []LanguageItem
	for _, it := range items {
		if it.Manager == ManagerCargo {
			found = append(found, it)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d Cargo items in %+v", len(found), items)
	}
	return found[0]
}

func cargoPackages(it LanguageItem) map[string]LanguagePackage {
	out := map[string]LanguagePackage{}
	for _, p := range it.Packages {
		out[p.Name+"@"+p.Installed] = p
	}
	return out
}

// --- planning from real data ---

// The cargo-auditable binary of a real image is matched against the Cargo.lock
// of its package: tokio is a direct dependency, and the target is the highest
// of the lowest fixes of each vulnerability in tokio 1's series.
func TestLanguagePlan_CargoRealRustBinary(t *testing.T) {
	gh := newFakeGitHub()
	exp2Repo(t, gh)
	items := cargoPlan(t, gh, rustInput(rustScan(t, "real_rustbinary_exp2.json")))
	if len(items) != 1 {
		t.Fatalf("items = %+v", items)
	}
	it := cargoItem(t, items)
	if it.Key != "deps:ex/app@main:svc#cargo" || it.Category != CategoryDependencyUpdateCandidate || it.Reason != ReasonUpdateCandidateInSource {
		t.Fatalf("item = %s %s %s (%s)", it.Key, it.Category, it.Reason, it.Detail)
	}
	if len(it.Packages) != 1 {
		t.Fatalf("packages = %+v", it.Packages)
	}
	p := it.Packages[0]
	if p.Name != "tokio" || p.Installed != "1.18.0" || p.Ecosystem != typeCargo || p.Action != ActionUpdate || p.SelectionLowerBound != "1.38.2" || p.Relation != RelationDirect || len(p.CVEs) != 3 {
		t.Errorf("tokio = %+v", p)
	}
	if len(p.Origins) != 3 || p.Origins[0].Ecosystem != "rustbinary" || p.Origins[0].Target != "usr/local/bin/exp2-auditable" {
		t.Errorf("origins = %+v", p.Origins)
	}
	if len(p.Occurrences) != 1 || !p.Occurrences[0].Matched || !p.Occurrences[0].Direct || p.Occurrences[0].Path != "svc/Cargo.lock" {
		t.Errorf("occurrences = %+v", p.Occurrences)
	}
	if got := it.Source.Files; len(got) != 2 || got[0].Path != "svc/Cargo.toml" || got[1].Path != "svc/Cargo.lock" {
		t.Errorf("files = %+v", got)
	}
	rec := it.Cargo
	if rec == nil || rec.LockVersion != 4 || len(rec.Members) != 1 || rec.Members[0] != (CargoMember{Path: "svc", Name: "exp2", Version: "0.1.0"}) || rec.RustVersion != "" || len(rec.Toolchains) != 0 {
		t.Errorf("record = %+v", rec)
	}
	// Nothing was executed.
	if it.UpdateExecuted || it.PostUpdateCheckExecuted || it.Source.Origin != OriginConfig || it.Source.Confidence != ConfidenceAsserted {
		t.Errorf("item = %+v", it)
	}
	// The files looked for and not found are recorded: those of the
	// directory, and of the one above it, up to the root of the repository.
	wantAbsent := []string{
		"svc/.cargo/config.toml", "svc/.cargo/config", "svc/rust-toolchain", "svc/rust-toolchain.toml",
		"Cargo.toml", ".cargo/config.toml", ".cargo/config", "rust-toolchain", "rust-toolchain.toml",
	}
	if strings.Join(it.Source.Absent, ",") != strings.Join(wantAbsent, ",") {
		t.Errorf("absent = %v", it.Source.Absent)
	}
	// It survives the plan's JSON.
	b, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}
	var back LanguageItem
	if err := json.Unmarshal(b, &back); err != nil || back.Cargo == nil || back.Cargo.LockVersion != 4 || back.Manager != ManagerCargo {
		t.Errorf("round trip: %v %+v", err, back)
	}
}

// A Cargo.lock in the image is matched by name and version, whichever crate
// the lock is of.
func TestLanguagePlan_CargoRealLockfile(t *testing.T) {
	gh := newFakeGitHub()
	exp2Repo(t, gh)
	it := cargoItem(t, cargoPlan(t, gh, rustInput(rustScan(t, "real_cargo_lock_exp2.json"))))
	if it.Category != CategoryDependencyUpdateCandidate || len(it.Packages) != 1 {
		t.Fatalf("item = %+v", it)
	}
	p := it.Packages[0]
	if p.Name != "tokio" || p.SelectionLowerBound != "1.38.2" || p.Origins[0].Ecosystem != "cargo" || p.Origins[0].Target != "app/Cargo.lock" {
		t.Errorf("tokio = %+v", p)
	}

	// The lock of a tool of the image is matched too: no root is asked of it.
	gh = newFakeGitHub()
	exp2Repo(t, gh)
	in := rustInput(rustScan(t, "real_cargo_lock_exp2.json"))
	for i := range in.Scan.Packages {
		for j := range in.Scan.Packages[i].Packages {
			in.Scan.Packages[i].Packages[j].Relationship = ""
		}
	}
	if it := cargoItem(t, cargoPlan(t, gh, in)); it.Category != CategoryDependencyUpdateCandidate {
		t.Errorf("item = %+v", it)
	}
}

// The binary and the lockfile of an image name the same crate: one package
// that keeps where each was seen.
func TestLanguagePlan_CargoBinaryAndLockfileAreOnePackage(t *testing.T) {
	gh := newFakeGitHub()
	exp2Repo(t, gh)
	it := cargoItem(t, cargoPlan(t, gh, rustInput(rustScan(t, "real_rustbinary_exp2.json"), rustScan(t, "real_cargo_lock_exp2.json"))))
	if len(it.Packages) != 1 {
		t.Fatalf("packages = %+v", it.Packages)
	}
	eco := map[string]int{}
	targets := map[string]bool{}
	for _, o := range it.Packages[0].Origins {
		eco[o.Ecosystem]++
		targets[o.Target] = true
	}
	if eco["rustbinary"] != 3 || eco["cargo"] != 3 || !targets["usr/local/bin/exp2-auditable"] || !targets["app/Cargo.lock"] {
		t.Errorf("origins = %+v", it.Packages[0].Origins)
	}
	if len(it.Packages[0].CVEs) != 3 {
		t.Errorf("cves = %+v", it.Packages[0].CVEs)
	}
}

// --- workspaces ---

const cargoWorkspaceRoot = "[workspace]\nmembers = [\"a\", \"b\"]\nresolver = \"2\"\n"

func exp3Repo(t *testing.T, gh *fakeGitHub) {
	t.Helper()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml":   cargoFixture(t, "exp3.Cargo.toml"),
		"a/Cargo.toml": cargoFixture(t, "exp3.a.Cargo.toml"),
		"b/Cargo.toml": cargoFixture(t, "exp3.b.Cargo.toml"),
		"Cargo.lock":   cargoFixture(t, "exp3.Cargo.lock"),
	})
}

func TestLanguagePlan_CargoWorkspace(t *testing.T) {
	gh := newFakeGitHub()
	exp3Repo(t, gh)
	in := langInput("shop", "api",
		rustFinding("CVE-SV", typeRustBinary, "usr/local/bin/a", "smallvec", "1.6.0", "1.6.1"),
		rustFinding("CVE-TK", typeRustBinary, "usr/local/bin/a", "tokio", "1.54.1", "1.54.2"),
		rustFinding("CVE-PL", typeRustBinary, "usr/local/bin/a", "pin-project-lite", "0.2.18", "0.2.19"),
		// The workspace's own library has no fix to take, being its own.
		rustFinding("CVE-B", typeRustBinary, "usr/local/bin/a", "b", "0.1.0", "0.1.1"),
	)
	in.Scan.Packages = []scanner.ResultPackages{
		rustBinaryPackages("usr/local/bin/a", "a", "0.1.0", "b", "0.1.0", "smallvec", "1.6.0", "tokio", "1.54.1", "pin-project-lite", "0.2.18"),
	}
	it := cargoItem(t, cargoPlan(t, gh, in))
	if it.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
	got := cargoPackages(it)
	if sv := got["smallvec@1.6.0"]; sv.Action != ActionUpdate || sv.Relation != RelationDirect || sv.SelectionLowerBound != "1.6.1" {
		t.Errorf("smallvec = %+v", sv)
	}
	if tk := got["tokio@1.54.1"]; tk.Action != ActionUpdate || tk.Relation != RelationDirect {
		t.Errorf("tokio = %+v", tk)
	}
	if pl := got["pin-project-lite@0.2.18"]; pl.Action != ActionUpdate || pl.Relation != RelationTransitive {
		t.Errorf("pin-project-lite = %+v", pl)
	}
	if b := got["b@0.1.0"]; b.Action != ActionManual || b.Reason != ReasonNonRegistrySource {
		t.Errorf("b = %+v", b)
	}
	if rec := it.Cargo; rec == nil || len(rec.Members) != 2 || rec.Members[0] != (CargoMember{Path: "svc/a", Name: "a", Version: "0.1.0"}) || rec.Members[1].Path != "svc/b" || len(rec.GlobDirs) != 0 {
		t.Errorf("record = %+v", rec)
	}
	var files []string
	for _, f := range it.Source.Files {
		files = append(files, f.Path)
	}
	if strings.Join(files, ",") != "svc/Cargo.toml,svc/a/Cargo.toml,svc/b/Cargo.toml,svc/Cargo.lock" {
		t.Errorf("files = %v", files)
	}

	// A binary of the library crate leads from it: tokio is not one of its
	// crates, though the lock has it for the workspace.
	in = langInput("shop", "api", rustFinding("CVE-TK", typeRustBinary, "usr/local/bin/b", "tokio", "1.54.1", "1.54.2"))
	in.Scan.Packages = []scanner.ResultPackages{rustBinaryPackages("usr/local/bin/b", "b", "0.1.0", "tokio", "1.54.1")}
	it = cargoItem(t, cargoPlan(t, gh, in))
	if it.Category != CategoryManual || it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "tokio@1.54.1 is built in but Cargo.lock does not lead to it from b@0.1.0") {
		t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
}

func TestLanguagePlan_CargoMembersByGlob(t *testing.T) {
	gh := newFakeGitHub()
	lock := cargoLockText(4,
		ownBlock("app", "0.1.0", "tokio"),
		ownBlock("lib", "0.1.0"),
		cratesBlock("tokio", "1.18.0", cksumA),
	)
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml":            "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/old\"]\n",
		"crates/app/Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1\"\n",
		"crates/lib/Cargo.toml": "[package]\nname = \"lib\"\nversion = \"0.1.0\"\n",
		"crates/old/Cargo.toml": "[package]\nname = \"old\"\nversion = \"9.9.9\"\n",
		"crates/README.md":      "a file, not a directory\n",
		"Cargo.lock":            lock,
	})
	in := langInput("shop", "api", rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", "1.18.4"))
	it := cargoItem(t, cargoPlan(t, gh, in))
	if it.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
	rec := it.Cargo
	if rec == nil || len(rec.Members) != 2 || rec.Members[0].Name != "app" || rec.Members[1].Name != "lib" || strings.Join(rec.GlobDirs, ",") != "svc/crates" {
		t.Errorf("record = %+v", rec)
	}
	if gh.count("read:ex/app/svc/crates/old") != 0 {
		t.Errorf("an excluded directory was read: %v", gh.calls)
	}
	if p := it.Packages[0]; p.Relation != RelationDirect || p.SelectionLowerBound != "1.18.4" {
		t.Errorf("tokio = %+v", p)
	}

	// A directory the pattern matches that has no Cargo.toml stops Cargo, so
	// the unit is left to a person.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml":            "[workspace]\nmembers = [\"crates/*\"]\n",
		"crates/app/Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1\"\n",
		"crates/docs/README.md": "not a crate\n",
		"Cargo.lock":            cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), cratesBlock("tokio", "1.18.0", cksumA)),
	})
	it = cargoItem(t, cargoPlan(t, gh, in))
	if it.Category != CategoryManual || it.Reason != ReasonDependencyFilesNotFound || !strings.Contains(it.Detail, "svc/crates/docs") {
		t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
	}

	// A member listed by its path stays a member when the exclude list also
	// names it, as Cargo does.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml":            "[workspace]\nmembers = [\"crates/app\", \"crates/lib\"]\nexclude = [\"crates/lib\"]\n",
		"crates/app/Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1\"\n",
		"crates/lib/Cargo.toml": "[package]\nname = \"lib\"\nversion = \"0.1.0\"\n",
		"Cargo.lock":            cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), ownBlock("lib", "0.1.0"), cratesBlock("tokio", "1.18.0", cksumA)),
	})
	it = cargoItem(t, cargoPlan(t, gh, in))
	if it.Category != CategoryDependencyUpdateCandidate || len(it.Cargo.Members) != 2 {
		t.Errorf("item = %s %s (%s) %+v", it.Category, it.Reason, it.Detail, it.Cargo)
	}
}

func TestLanguagePlan_CargoImplicitMembers(t *testing.T) {
	lock := cargoLockText(4,
		ownBlock("app", "0.1.0", "helper", "tokio"),
		ownBlock("helper", "0.2.0", "smallvec"),
		cratesBlock("smallvec", "1.6.0", cksumB),
		cratesBlock("tokio", "1.18.0", cksumA),
	)
	smallvec := rustFinding("CVE-SV", typeCargo, "app/Cargo.lock", "smallvec", "1.6.0", "1.6.1")
	app := "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nhelper = { path = \"helper\" }\ntokio = \"1\"\n"
	helper := "[package]\nname = \"helper\"\nversion = \"0.2.0\"\n[dependencies]\nsmallvec = \"1\"\n"
	appWS := app + "[workspace]\n"

	// Without a [workspace] the package is a member of nothing but itself, and
	// a path dependency is not handled: helper's own dependency is not the
	// workspace's.
	gh0 := newFakeGitHub()
	cargoRepo(gh0, "ex/app", "svc", map[string]string{"Cargo.toml": app, "helper/Cargo.toml": helper, "Cargo.lock": lock})
	it0 := cargoItem(t, cargoPlan(t, gh0, langInput("shop", "api", smallvec)))
	if it0.Category != CategoryManual || it0.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it0.Detail, "without a [workspace]") || it0.Cargo != nil {
		t.Errorf("single package: %s %s (%s)", it0.Category, it0.Reason, it0.Detail)
	}

	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": appWS, "helper/Cargo.toml": helper, "Cargo.lock": lock})
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", smallvec)))
	if it.Category != CategoryDependencyUpdateCandidate || len(it.Cargo.Members) != 2 {
		t.Fatalf("item = %s %s (%s) %+v", it.Category, it.Reason, it.Detail, it.Cargo)
	}
	// The dependency of the implicit member is direct.
	if p := it.Packages[0]; p.Relation != RelationDirect || p.SelectionLowerBound != "1.6.1" {
		t.Errorf("smallvec = %+v", p)
	}

	// An implicit member's own path dependency is followed.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml": appWS, "helper/Cargo.toml": strings.Replace(helper, "[dependencies]\n", "[dependencies]\ndeep = { path = \"../deep\" }\n", 1),
		"deep/Cargo.toml": "[package]\nname = \"deep\"\nversion = \"0.0.1\"\n",
		"Cargo.lock":      strings.Replace(lock, "[[package]]\nname = \"helper\"", "[[package]]\nname = \"deep\"\nversion = \"0.0.1\"\n\n[[package]]\nname = \"helper\"", 1),
	})
	it = cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", smallvec)))
	if len(it.Cargo.Members) != 3 {
		t.Errorf("record = %+v", it.Cargo)
	}

	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"a path dependency outside the root": {
			map[string]string{"Cargo.toml": strings.Replace(appWS, "path = \"helper\"", "path = \"../outside\"", 1), "Cargo.lock": lock}, "outside the workspace",
		},
		"a path dependency in an excluded directory": {
			map[string]string{"Cargo.toml": app + "[workspace]\nexclude = [\"helper\"]\n", "helper/Cargo.toml": helper, "Cargo.lock": lock}, "excluded directory",
		},
		"a path dependency without a Cargo.toml": {
			map[string]string{"Cargo.toml": appWS, "Cargo.lock": lock}, "svc/helper has no Cargo.toml",
		},
		"a path dependency that is a workspace of its own": {
			map[string]string{"Cargo.toml": appWS, "helper/Cargo.toml": helper + "[workspace]\n", "Cargo.lock": lock}, "[workspace] of its own",
		},
		"a path dependency in the workspace table, outside": {
			map[string]string{"Cargo.toml": app + "[workspace.dependencies]\nx = { path = \"../x\" }\n", "helper/Cargo.toml": helper, "Cargo.lock": lock}, "outside the workspace",
		},
	} {
		gh := newFakeGitHub()
		cargoRepo(gh, "ex/app", "svc", c.files)
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", smallvec)))
		if it.Category != CategoryManual || (it.Reason != ReasonWorkspaceUnsupported && it.Reason != ReasonDependencyFilesNotFound) || !strings.Contains(it.Detail, c.want) {
			t.Errorf("%s: %s %s (%s)", name, it.Category, it.Reason, it.Detail)
		}
		if len(it.Packages) != 1 || it.Packages[0].Action != ActionManual || it.Packages[0].Reason != it.Reason {
			t.Errorf("%s: packages = %+v", name, it.Packages)
		}
	}
}

func TestLanguagePlan_CargoInheritance(t *testing.T) {
	root := `[workspace]
members = ["app"]
[workspace.package]
version = "3.1.0"
rust-version = "1.75"
[workspace.dependencies]
tokio = "=1.20.0"
alias-log = { package = "log", version = "0.4" }
`
	app := `[package]
name = "app"
version.workspace = true
rust-version.workspace = true
[dependencies]
tokio = { workspace = true, features = ["rt"] }
`
	lock := cargoLockText(4, ownBlock("app", "3.1.0", "tokio"), cratesBlock("tokio", "1.18.0", cksumA))
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": root, "app/Cargo.toml": app, "Cargo.lock": lock})
	in := langInput("shop", "api", rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes))
	it := cargoItem(t, cargoPlan(t, gh, in))
	// The version and rust-version come from the workspace, and the
	// requirement the member inherits rules out the fix; the message says
	// which file requires it.
	if rec := it.Cargo; rec == nil || rec.Members[0].Version != "3.1.0" || rec.RustVersion != "1.75" {
		t.Errorf("record = %+v", rec)
	}
	p := it.Packages[0]
	if p.Action != ActionManual || p.Reason != ReasonRangeExcludesFix || p.SelectionLowerBound != "1.18.4" ||
		p.Detail != `svc/app/Cargo.toml (package app) requires tokio "=1.20.0", which does not allow 1.18.4` {
		t.Errorf("tokio = %+v", p)
	}

	// Without an entry in the workspace table, there is nothing to inherit.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml": strings.Replace(root, "tokio = \"=1.20.0\"\n", "", 1), "app/Cargo.toml": app, "Cargo.lock": lock,
	})
	it = cargoItem(t, cargoPlan(t, gh, in))
	if it.Reason != ReasonCargoManifestUnsupported || !strings.Contains(it.Detail, "has no tokio") {
		t.Errorf("item = %s (%s)", it.Reason, it.Detail)
	}
	// Nor is there a version to take when the workspace sets none.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml": strings.Replace(root, "version = \"3.1.0\"\n", "", 1), "app/Cargo.toml": app, "Cargo.lock": lock,
	})
	it = cargoItem(t, cargoPlan(t, gh, in))
	if it.Reason != ReasonCargoManifestUnsupported || !strings.Contains(it.Detail, "inherits its version") {
		t.Errorf("item = %s (%s)", it.Reason, it.Detail)
	}
	// The lowest rust-version of the members that declare one is recorded.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml":   "[workspace]\nmembers = [\"x\", \"y\", \"z\"]\n",
		"x/Cargo.toml": "[package]\nname = \"x\"\nrust-version = \"1.80\"\n[dependencies]\ntokio = \"1\"\n",
		"y/Cargo.toml": "[package]\nname = \"y\"\nrust-version = \"1.70.1\"\n",
		"z/Cargo.toml": "[package]\nname = \"z\"\n",
		"Cargo.lock":   cargoLockText(4, ownBlock("x", "0.0.0", "tokio"), ownBlock("y", "0.0.0"), ownBlock("z", "0.0.0"), cratesBlock("tokio", "1.18.0", cksumA)),
	})
	it = cargoItem(t, cargoPlan(t, gh, in))
	if it.Category != CategoryDependencyUpdateCandidate || it.Cargo.RustVersion != "1.70.1" || it.Cargo.Members[0].Version != "0.0.0" {
		t.Errorf("item = %s (%s) %+v", it.Category, it.Detail, it.Cargo)
	}
}

// --- the files of the unit ---

func TestLanguagePlan_CargoRefusals(t *testing.T) {
	const pkg = "[package]\nname = \"exp2\"\nversion = \"0.1.0\"\n"
	dep := "[dependencies]\ntokio = \"1\"\n"
	for name, c := range map[string]struct {
		manifest string
		extra    map[string]string
		reason   Reason
	}{
		"patch":                         {pkg + dep + "[patch.crates-io]\ntokio = { path = \"../t\" }\n", nil, ReasonUnsupportedSource},
		"replace":                       {pkg + dep + "[replace]\n\"tokio:1.18.0\" = { path = \"../t\" }\n", nil, ReasonUnsupportedSource},
		"cargo-features":                {"cargo-features = [\"x\"]\n" + pkg + dep, nil, ReasonUnsupportedSource},
		"git":                           {pkg + dep + "g = { git = \"https://github.com/x/g\" }\n", nil, ReasonUnsupportedSource},
		"registry":                      {pkg + dep + "g = { version = \"1\", registry = \"corp\" }\n", nil, ReasonUnsupportedSource},
		"git in dev":                    {pkg + dep + "[dev-dependencies]\ng = { git = \"https://github.com/x/g\" }\n", nil, ReasonUnsupportedSource},
		"underscore":                    {pkg + dep + "[dev_dependencies]\ng = \"1\"\n", nil, ReasonCargoManifestUnsupported},
		"unknown table":                 {pkg + dep + "[frobnicate]\nx = 1\n", nil, ReasonCargoManifestUnsupported},
		"package.workspace":             {"[package]\nname = \"exp2\"\nversion = \"0.1.0\"\nworkspace = \"..\"\n" + dep, nil, ReasonWorkspaceUnsupported},
		"member pattern":                {"[workspace]\nmembers = [\"crates/a*\"]\n", nil, ReasonWorkspaceUnsupported},
		"member outside":                {"[workspace]\nmembers = [\"../x\"]\n", nil, ReasonWorkspaceUnsupported},
		"member missing":                {"[workspace]\nmembers = [\"a\"]\n", nil, ReasonDependencyFilesNotFound},
		"member with workspace":         {"[workspace]\nmembers = [\"a\"]\n", map[string]string{"a/Cargo.toml": "[package]\nname = \"a\"\n[workspace]\n"}, ReasonWorkspaceUnsupported},
		"member of a package.workspace": {"[workspace]\nmembers = [\"a\"]\n", map[string]string{"a/Cargo.toml": "[package]\nname = \"a\"\nworkspace = \".\"\n"}, ReasonWorkspaceUnsupported},
		"member without package":        {"[workspace]\nmembers = [\"a\"]\n", map[string]string{"a/Cargo.toml": "[workspace]\n"}, ReasonWorkspaceUnsupported},
		"not TOML":                      {"[package\n", nil, ReasonUnparsableSource},
		"two packages the same":         {"[workspace]\nmembers = [\"a\", \"b\"]\n", map[string]string{"a/Cargo.toml": "[package]\nname = \"p\"\n", "b/Cargo.toml": "[package]\nname = \"p\"\n"}, ReasonWorkspaceUnsupported},
	} {
		gh := newFakeGitHub()
		files := map[string]string{"Cargo.toml": c.manifest, "Cargo.lock": cargoFixture(t, "exp2.Cargo.lock")}
		for k, v := range c.extra {
			files[k] = v
		}
		cargoRepo(gh, "ex/app", "svc", files)
		it := cargoItem(t, cargoPlan(t, gh, exp2Input(tokioApp("CVE-1"))))
		if it.Category != CategoryManual || it.Reason != c.reason {
			t.Errorf("%s: %s %s (%s), want %s", name, it.Category, it.Reason, it.Detail, c.reason)
			continue
		}
		// Every finding of the unit is carried, as the workspace was not read.
		if len(it.Packages) != 1 || it.Packages[0].Action != ActionManual || it.Packages[0].Reason != c.reason {
			t.Errorf("%s: packages = %+v", name, it.Packages)
		}
	}
}

func TestLanguagePlan_CargoFiles(t *testing.T) {
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes)

	t.Run("no Cargo.lock", func(t *testing.T) {
		gh := newFakeGitHub()
		cargoPut(gh, "ex/app", "svc/Cargo.toml", cargoFixture(t, "exp2.Cargo.toml"))
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Category != CategoryManual || it.Reason != ReasonDependencyFilesNotFound || !strings.Contains(it.Detail, "no Cargo.lock") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("no Cargo.toml: the findings are not this source's", func(t *testing.T) {
		gh := newFakeGitHub()
		cargoPut(gh, "ex/app", "svc/Cargo.lock", cargoFixture(t, "exp2.Cargo.lock"))
		if items := cargoPlan(t, gh, langInput("shop", "api", tok)); len(items) != 0 {
			t.Errorf("items = %+v", items)
		}
	})
	t.Run("Cargo.toml is a directory", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.putEntry("ex/app", "svc", github.Entry{Name: "Cargo.toml", Type: github.EntryDir})
		cargoPut(gh, "ex/app", "svc/Cargo.lock", cargoFixture(t, "exp2.Cargo.lock"))
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Reason != ReasonDependencyFileUnusable || !strings.Contains(it.Detail, "svc/Cargo.toml is a dir") {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("Cargo.lock is a symlink", func(t *testing.T) {
		gh := newFakeGitHub()
		cargoPut(gh, "ex/app", "svc/Cargo.toml", cargoFixture(t, "exp2.Cargo.toml"))
		gh.putEntry("ex/app", "svc", github.Entry{Name: "Cargo.lock", Type: github.EntrySymlink})
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Reason != ReasonDependencyFileUnusable {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("unreadable Cargo.lock", func(t *testing.T) {
		for name, c := range map[string]struct {
			text   string
			reason Reason
		}{
			"old format": {"version = 2\n", ReasonUnsupportedLockfile},
			"git source": {cargoLockText(4, "name = \"g\"\nversion = \"1.0.0\"\nsource = \"git+https://github.com/x/g#abc\"\n"), ReasonUnsupportedSource},
			"garbage":    {"[[package\n", ReasonUnparsableSource},
			"duplicate":  {cargoLockText(4, cratesBlock("t", "1.0.0", cksumA), cratesBlock("t", "1.0.0", cksumA)), ReasonUnparsableSource},
		} {
			gh := newFakeGitHub()
			cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": cargoFixture(t, "exp2.Cargo.toml"), "Cargo.lock": c.text})
			it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
			if it.Category != CategoryManual || it.Reason != c.reason {
				t.Errorf("%s: %s %s (%s)", name, it.Category, it.Reason, it.Detail)
			}
		}
	})
	t.Run("GitHub refuses the read", func(t *testing.T) {
		gh := newFakeGitHub()
		exp2Repo(t, gh)
		gh.readErr["ex/app/svc/Cargo.toml"] = github.ErrForbidden
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Category != CategoryFailed || it.Reason != ReasonSourceAccessDenied {
			t.Errorf("item = %s %s", it.Category, it.Reason)
		}
	})
}

func TestLanguagePlan_CargoSurroundings(t *testing.T) {
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes)
	plan := func(t *testing.T, extra map[string]string) LanguageItem {
		t.Helper()
		gh := newFakeGitHub()
		exp2Repo(t, gh)
		for p, c := range extra {
			cargoPut(gh, "ex/app", p, c)
		}
		return cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
	}

	t.Run("a Cargo.toml above without a workspace is recorded as read", func(t *testing.T) {
		it := plan(t, map[string]string{"Cargo.toml": "[package]\nname = \"top\"\nversion = \"1.0.0\"\n"})
		if it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
		var files []string
		for _, f := range it.Source.Files {
			files = append(files, f.Path)
		}
		if strings.Join(files, ",") != "svc/Cargo.toml,Cargo.toml,svc/Cargo.lock" || containsString(it.Source.Absent, "Cargo.toml") {
			t.Errorf("files = %v, absent = %v", files, it.Source.Absent)
		}
	})
	t.Run("a Cargo.toml above with a workspace", func(t *testing.T) {
		it := plan(t, map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"svc\"]\n"})
		if it.Category != CategoryManual || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, "Cargo.toml has a [workspace]") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a Cargo.toml above that does not parse", func(t *testing.T) {
		it := plan(t, map[string]string{"Cargo.toml": "[workspace\n"})
		if it.Reason != ReasonUnparsableSource {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	for _, p := range []string{"svc/.cargo/config.toml", "svc/.cargo/config", ".cargo/config.toml", ".cargo/config"} {
		t.Run("configuration at "+p, func(t *testing.T) {
			it := plan(t, map[string]string{p: "[source.crates-io]\nreplace-with = \"mirror\"\n"})
			if it.Category != CategoryManual || it.Reason != ReasonUnsupportedSource || !strings.Contains(it.Detail, p+" exists") {
				t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
			}
		})
	}
	t.Run("a .cargo directory without a configuration", func(t *testing.T) {
		it := plan(t, map[string]string{"svc/.cargo/notes.txt": "x\n"})
		if it.Category != CategoryDependencyUpdateCandidate || !containsString(it.Source.Absent, "svc/.cargo/config.toml") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("toolchain files are read and recorded", func(t *testing.T) {
		it := plan(t, map[string]string{
			"svc/rust-toolchain.toml": "[toolchain]\nchannel = \"1.75.0\"\n",
			"rust-toolchain":          "stable\n",
		})
		if it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
		want := []CargoToolchain{
			{Path: "svc/rust-toolchain.toml", Channel: "1.75.0", Version: "1.75.0"},
			{Path: "rust-toolchain", Channel: "stable"},
		}
		if got := it.Cargo.Toolchains; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("toolchains = %+v", got)
		}
		var files []string
		for _, f := range it.Source.Files {
			files = append(files, f.Path)
		}
		if strings.Join(files, ",") != "svc/Cargo.toml,svc/rust-toolchain.toml,rust-toolchain,svc/Cargo.lock" ||
			containsString(it.Source.Absent, "svc/rust-toolchain.toml") || !containsString(it.Source.Absent, "svc/rust-toolchain") || !containsString(it.Source.Absent, "rust-toolchain.toml") {
			t.Errorf("files = %v, absent = %v", files, it.Source.Absent)
		}
	})
	t.Run("a toolchain file that does not parse", func(t *testing.T) {
		it := plan(t, map[string]string{"svc/rust-toolchain.toml": "[toolchain\n"})
		if it.Reason != ReasonUnparsableSource {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("a unit in the root of the repository has no directory above", func(t *testing.T) {
		gh := newFakeGitHub()
		cargoRepo(gh, "ex/app", ".", map[string]string{"Cargo.toml": cargoFixture(t, "exp2.Cargo.toml"), "Cargo.lock": cargoFixture(t, "exp2.Cargo.lock")})
		items := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", ".")}, nil, langInput("shop", "api", tok)).LanguageItems
		it := cargoItem(t, items)
		if it.Category != CategoryDependencyUpdateCandidate || it.Cargo.Members[0].Path != "." || it.Packages[0].Occurrences[0].Path != "Cargo.lock" {
			t.Errorf("item = %s %s (%s) %+v", it.Category, it.Reason, it.Detail, it.Cargo)
		}
		if got := strings.Join(it.Source.Absent, ","); got != ".cargo/config.toml,.cargo/config,rust-toolchain,rust-toolchain.toml" {
			t.Errorf("absent = %s", got)
		}
	})
}

func TestLanguagePlan_CargoLimits(t *testing.T) {
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes)
	t.Run("more packages than the limit", func(t *testing.T) {
		gh := newFakeGitHub()
		files := map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"m/*\"]\n", "Cargo.lock": cargoLockText(4)}
		for i := 0; i <= maxCargoMembers; i++ {
			files[fmt.Sprintf("m/p%03d/Cargo.toml", i)] = fmt.Sprintf("[package]\nname = \"p%03d\"\n", i)
		}
		cargoRepo(gh, "ex/app", "svc", files)
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Category != CategoryManual || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, "more than 64 packages") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("more files than the limit", func(t *testing.T) {
		defer func(n int) { maxCargoFiles = n }(maxCargoFiles)
		maxCargoFiles = 4
		gh := newFakeGitHub()
		files := map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"m/*\"]\n", "Cargo.lock": cargoLockText(4)}
		for i := 0; i < 4; i++ {
			files[fmt.Sprintf("m/p%03d/Cargo.toml", i)] = fmt.Sprintf("[package]\nname = \"p%03d\"\n", i)
		}
		cargoRepo(gh, "ex/app", "svc", files)
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Category != CategoryManual || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, "more than 4 files") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
}

// --- the binaries of the image ---

func TestLanguagePlan_CargoBinarySelection(t *testing.T) {
	app := tokioApp("CVE-APP")
	tool := rustFinding("CVE-TOOL", typeRustBinary, "usr/local/bin/tool", "tokio", "1.18.0", "1.18.4")
	setup := func(t *testing.T) *fakeGitHub {
		gh := newFakeGitHub()
		exp2Repo(t, gh)
		return gh
	}

	t.Run("a finding of a binary of another crate is dropped without a trace", func(t *testing.T) {
		it := cargoItem(t, cargoPlan(t, setup(t), exp2Input(app, tool)))
		if it.Category != CategoryDependencyUpdateCandidate || len(it.Packages) != 1 || len(it.Packages[0].CVEs) != 1 || it.Packages[0].CVEs[0].VulnID != "CVE-APP" {
			t.Fatalf("item = %+v", it)
		}
		for _, o := range it.Packages[0].Origins {
			if o.Target != "usr/local/bin/app" {
				t.Errorf("origin of another binary: %+v", o)
			}
		}
	})
	t.Run("only other binaries: no item", func(t *testing.T) {
		if items := cargoPlan(t, setup(t), exp2Input(tool)); len(items) != 0 {
			t.Errorf("items = %+v", items)
		}
	})
	t.Run("the same crate in two binaries of the workspace is one package", func(t *testing.T) {
		in := exp2Input(app, rustFinding("CVE-APP", typeRustBinary, "usr/local/bin/app2", "tokio", "1.18.0", tokioFixes))
		in.Scan.Packages = append(in.Scan.Packages, rustBinaryPackages("usr/local/bin/app2", "exp2", "0.1.0", "once_cell", "1.21.4", "pin-project-lite", "0.2.18", "tokio", "1.18.0"))
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if len(it.Packages) != 1 || len(it.Packages[0].Origins) != 2 {
			t.Errorf("packages = %+v", it.Packages)
		}
	})
	t.Run("a binary with no root crate", func(t *testing.T) {
		in := exp2Input(app)
		in.Scan.Packages[0] = rustBinaryPackages("usr/local/bin/app", "", "", "tokio", "1.18.0")
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if it.Category != CategoryManual || it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "names 0 root crates") || len(it.Packages) != 1 {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a binary with two roots", func(t *testing.T) {
		in := exp2Input(app)
		in.Scan.Packages[0].Packages = append(in.Scan.Packages[0].Packages, scanner.Package{Name: "other", Version: "1.0.0", Relationship: "root"})
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "names 2 root crates (exp2@0.1.0, other@1.0.0)") {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("a package list cut short", func(t *testing.T) {
		in := exp2Input(app)
		in.Scan.PackagesTruncated = true
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "cut short") {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("a finding with no package list for its binary", func(t *testing.T) {
		in := exp2Input(app)
		in.Scan.Packages = nil
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "not available") {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("the same root name at another version is another crate", func(t *testing.T) {
		in := exp2Input(app)
		in.Scan.Packages[0].Packages[0].Version = "0.2.0"
		if items := cargoPlan(t, setup(t), in); len(items) != 0 {
			t.Errorf("items = %+v", items)
		}
	})
	t.Run("a crate built in that Cargo.lock does not list", func(t *testing.T) {
		in := exp2Input(app)
		in.Scan.Packages[0].Packages = append(in.Scan.Packages[0].Packages, scanner.Package{Name: "extra", Version: "2.0.0"})
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if it.Category != CategoryManual || it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "extra@2.0.0 is built in but Cargo.lock does not list it") ||
			!strings.Contains(it.Detail, "usr/local/bin/app, built from exp2@0.1.0") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
		if len(it.Packages) != 1 || it.Packages[0].Action != ActionManual || it.Packages[0].Reason != ReasonRustBinaryNotFromSource {
			t.Errorf("packages = %+v", it.Packages)
		}
	})
	t.Run("a crate at another version than the lock's", func(t *testing.T) {
		in := exp2Input(app)
		in.Scan.Packages[0].Packages[1].Version = "1.21.5"
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "once_cell@1.21.5 is built in but Cargo.lock does not list it") {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("a finding of a crate that is not in the binary's list", func(t *testing.T) {
		in := exp2Input(app, rustFinding("CVE-X", typeRustBinary, "usr/local/bin/app", "once_cell", "1.17.0", "1.17.1"))
		it := cargoItem(t, cargoPlan(t, setup(t), in))
		if it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "once_cell 1.17.0, which is not in the binary's crate list") {
			t.Errorf("item = %s (%s)", it.Reason, it.Detail)
		}
	})
	t.Run("a binary of the workspace's own root crate in the real kanidm image does not match", func(t *testing.T) {
		in := rustInput(rustScan(t, "real_rustbinary_kanidm_trimmed.json"))
		if len(in.Scan.Packages) != 1 || len(in.Scan.Packages[0].Packages) != 9 {
			t.Fatalf("packages = %+v", in.Scan.Packages)
		}
		in.Scan.Findings = []scanner.Finding{rustFinding("CVE-D", typeRustBinary, "sbin/kanidmd", "aes", "0.9.4", "0.9.5")}
		if items := cargoPlan(t, setup(t), in); len(items) != 0 {
			t.Errorf("items = %+v", items)
		}
		// Its root is a crate named daemon at 1.12.1: a workspace with such a
		// package takes the binary, and the crates it lists must then be in the
		// lock.
		gh := newFakeGitHub()
		cargoRepo(gh, "ex/app", "svc", map[string]string{
			"Cargo.toml": "[package]\nname = \"daemon\"\nversion = \"1.12.1\"\n[dependencies]\naes = \"0.9\"\n",
			"Cargo.lock": cargoLockText(4, ownBlock("daemon", "1.12.1", "aes"), cratesBlock("aes", "0.9.4", cksumA)),
		})
		it := cargoItem(t, cargoPlan(t, gh, in))
		if it.Category != CategoryManual || it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "sbin/kanidmd, built from daemon@1.12.1") ||
			!strings.Contains(it.Detail, "and ") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
}

func TestLanguagePlan_CargoUnverified(t *testing.T) {
	unverified := func(fs ...scanner.Finding) ImageInput {
		in := exp2Input(fs...)
		in.Scan.Pinned = false
		return in
	}
	app := tokioApp("CVE-APP")
	tool := rustFinding("CVE-TOOL", typeRustBinary, "usr/local/bin/tool", "tokio", "1.18.0", "1.18.4")

	gh := newFakeGitHub()
	exp2Repo(t, gh)
	got := cargoPlan(t, gh, unverified(app, tool))
	if len(got) != 1 || !strings.HasSuffix(got[0].Key, "#unverified") || got[0].Reason != ReasonScanNotPinned || len(got[0].Packages) != 1 ||
		got[0].Packages[0].CVEs[0].VulnID != "CVE-APP" || got[0].Packages[0].Ecosystem != typeCargo {
		t.Errorf("items = %+v; only the application's finding is listed", got)
	}

	// A directory without a Cargo.toml lists nothing.
	gh = newFakeGitHub()
	npmRepo(gh, "ex/app", "svc")
	if got := cargoPlan(t, gh, unverified(app)); len(got) != 0 {
		t.Errorf("items without a Cargo.toml = %+v", got)
	}

	// A verified scan and an unverified one of the same unit: the item and
	// the list.
	gh = newFakeGitHub()
	exp2Repo(t, gh)
	got = cargoPlan(t, gh, exp2Input(app), unverified(rustFinding("CVE-OLD", typeRustBinary, "usr/local/bin/app", "tokio", "1.18.0", "1.18.5")))
	if len(got) != 2 || got[0].Manager != ManagerCargo || !strings.HasSuffix(got[1].Key, "#unverified") {
		t.Fatalf("items = %+v", got)
	}
}

// --- matching against Cargo.lock ---

func TestLanguagePlan_CargoMatching(t *testing.T) {
	const pkgToml = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n"
	dep := func(req string) string { return pkgToml + "[dependencies]\ntokio = " + req + "\n" }
	tokioLock := func(version string, extra ...string) string {
		ref := "tokio"
		if len(extra) > 0 {
			ref = "tokio " + version
		}
		return cargoLockText(4, append([]string{ownBlock("app", "0.1.0", ref), cratesBlock("tokio", version, cksumA)}, extra...)...)
	}
	tokio := func(installed, fixed string) scanner.Finding {
		return rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", installed, fixed)
	}
	for name, c := range map[string]struct {
		manifest, lock string
		finding        scanner.Finding
		action         PackageAction
		reason         Reason
		target         string
		relation       Relation
		detail         string
	}{
		"candidate": {dep(`"1"`), tokioLock("1.18.0"), tokio("1.18.0", tokioFixes), ActionUpdate, ReasonUpdateCandidateInSource, "1.18.4", RelationDirect, ""},
		"transitive": {pkgToml + "[dependencies]\nx = \"1\"\n", cargoLockText(4, ownBlock("app", "0.1.0", "x"), cratesBlock("x", "1.0.0", cksumB, "tokio"), cratesBlock("tokio", "1.18.0", cksumA)),
			tokio("1.18.0", "1.18.4"), ActionUpdate, ReasonUpdateCandidateInSource, "1.18.4", RelationTransitive, ""},
		"crate not in the lock":                              {dep(`"1"`), cargoLockText(4, ownBlock("app", "0.1.0")), tokio("1.18.0", "1.18.4"), ActionManual, ReasonNotFoundInSource, "", "", "does not list"},
		"other version in the lock":                          {dep(`"1"`), tokioLock("1.20.0"), tokio("1.18.0", "1.18.4"), ActionManual, ReasonNotFoundInSource, "", "", "locks tokio at 1.20.0, not 1.18.0"},
		"a package of the lock that is not of the workspace": {dep(`"1"`), cargoLockText(4, ownBlock("tokio", "1.18.0"), ownBlock("app", "0.1.0")), tokio("1.18.0", "1.18.4"), ActionManual, ReasonDependencyFileUnusable, "", "", "no package of the workspace is that"},
		"a package and a crate of the same name and version": {
			dep(`"1"`), cargoLockText(4, ownBlock("app", "0.1.0", "tokio 1.18.0 ("+cratesIOSource+")"), ownBlock("tokio", "1.18.0"), cratesBlock("tokio", "1.18.0", cksumA)),
			tokio("1.18.0", "1.18.4"), ActionManual, ReasonDependencyFileUnusable, "", "", "no package of the workspace is that",
		},
		"two versions of the crate": {
			dep(`"1"`), tokioLock("1.18.0", cratesBlock("tokio", "0.2.25", cksumB)), tokio("1.18.0", "1.18.4"), ActionManual, ReasonMultipleVersions, "", "", "0.2.25, 1.18.0",
		},
		"the fix is in another major version": {dep(`"1"`), tokioLock("1.18.0"), tokio("1.18.0", "2.0.1"), ActionManual, ReasonFixInOtherMajor, "", RelationDirect, "2.0.1"},
		"a 0.x fix of another minor version":  {dep(`"0.3"`), tokioLock("0.3.1"), tokio("0.3.1", "0.4.0"), ActionManual, ReasonFixInOtherMajor, "", RelationDirect, "0.4.0"},
		"no fix above":                        {dep(`"1"`), tokioLock("1.18.0"), tokio("1.18.0", "1.17.0"), ActionManual, ReasonNoFixedVersion, "", RelationDirect, ""},
		"requirement excludes the fix": {dep(`"=1.18.0"`), tokioLock("1.18.0"), tokio("1.18.0", "1.18.4"), ActionManual, ReasonRangeExcludesFix, "1.18.4", RelationDirect,
			`svc/Cargo.toml (package app) requires tokio "=1.18.0", which does not allow 1.18.4`},
		"requirement with a tilde":          {dep(`"~1.18.0"`), tokioLock("1.18.0"), tokio("1.18.0", "1.20.3"), ActionManual, ReasonRangeExcludesFix, "1.20.3", RelationDirect, `"~1.18.0"`},
		"requirement allows the fix":        {dep(`"~1.18"`), tokioLock("1.18.0"), tokio("1.18.0", "1.18.4"), ActionUpdate, ReasonUpdateCandidateInSource, "1.18.4", RelationDirect, ""},
		"requirement in a table":            {dep(`{ version = ">=1.0, <1.18.2", features = ["rt"] }`), tokioLock("1.18.0"), tokio("1.18.0", "1.18.4"), ActionManual, ReasonRangeExcludesFix, "1.18.4", RelationDirect, `">=1.0, <1.18.2"`},
		"requirement that cannot be judged": {dep(`"1.0.0-beta.1"`), tokioLock("1.18.0"), tokio("1.18.0", "1.18.4"), ActionManual, ReasonRangeNotEvaluable, "1.18.4", RelationDirect, "cannot be judged against 1.18.4"},
		"requirement of a renamed dependency": {pkgToml + "[dependencies]\nrt = { package = \"tokio\", version = \"=1.18.0\" }\n", tokioLock("1.18.0"),
			tokio("1.18.0", "1.18.4"), ActionManual, ReasonRangeExcludesFix, "1.18.4", RelationDirect, `requires tokio "=1.18.0"`},
		"requirement of a dev dependency": {pkgToml + "[dependencies]\ntokio = \"1\"\n[dev-dependencies]\ntokio = { version = \"=1.18.0\" }\n", tokioLock("1.18.0"),
			tokio("1.18.0", "1.18.4"), ActionManual, ReasonRangeExcludesFix, "1.18.4", RelationDirect, `"=1.18.0"`},
		"requirement of a dependency by platform": {pkgToml + "[target.'cfg(unix)'.dependencies]\ntokio = \"=1.18.0\"\n", tokioLock("1.18.0"),
			tokio("1.18.0", "1.18.4"), ActionManual, ReasonRangeExcludesFix, "1.18.4", RelationDirect, `"=1.18.0"`},
		"a local crate of the name the lock has on crates.io": {pkgToml + "[workspace]\n[dependencies]\ntokio = { path = \"t\", version = \"=1.18.0\" }\n", tokioLock("1.18.0"),
			tokio("1.18.0", "1.18.4"), ActionManual, ReasonDependencyFileUnusable, "", "", "does not list the package tokio 9.0.0"},
	} {
		gh := newFakeGitHub()
		files := map[string]string{"Cargo.toml": c.manifest, "Cargo.lock": c.lock}
		if strings.Contains(c.manifest, "path = \"t\"") {
			files["t/Cargo.toml"] = "[package]\nname = \"tokio\"\nversion = \"9.0.0\"\n"
		}
		cargoRepo(gh, "ex/app", "svc", files)
		items := cargoPlan(t, gh, langInput("shop", "api", c.finding))
		if len(items) != 1 {
			t.Errorf("%s: items = %+v", name, items)
			continue
		}
		it := items[0]
		if len(it.Packages) != 1 {
			t.Errorf("%s: item = %s %s (%s) packages = %+v", name, it.Category, it.Reason, it.Detail, it.Packages)
			continue
		}
		p := it.Packages[0]
		if p.Action != c.action || p.Reason != c.reason || p.SelectionLowerBound != c.target || p.Relation != c.relation || !strings.Contains(p.Detail, c.detail) {
			t.Errorf("%s: package = %+v", name, p)
		}
		want := CategoryManual
		if c.action == ActionUpdate {
			want = CategoryDependencyUpdateCandidate
		}
		if it.Category != want {
			t.Errorf("%s: category = %s %s (%s)", name, it.Category, it.Reason, it.Detail)
		}
	}
	// The detail of an excluded fix names the file, the crate, the requirement
	// as written and the version.
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": dep(`"=1.18.0"`), "Cargo.lock": tokioLock("1.18.0")})
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tokio("1.18.0", "1.18.4"))))
	if d := it.Packages[0].Detail; d != `svc/Cargo.toml (package app) requires tokio "=1.18.0", which does not allow 1.18.4` {
		t.Errorf("detail = %s", d)
	}
}

// A crate that is in the lock under two versions cannot be updated by name;
// another that is in it once can, in the same file.
func TestLanguagePlan_CargoRealMultipleVersions(t *testing.T) {
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml": cargoFixture(t, "exp4.Cargo.toml"),
		"Cargo.lock": cargoFixture(t, "exp4.Cargo.lock"),
	})
	in := langInput("shop", "api",
		rustFinding("CVE-SYN", typeCargo, "app/Cargo.lock", "syn", "1.0.109", "1.0.110"),
		rustFinding("CVE-TK", typeCargo, "app/Cargo.lock", "tokio", "1.40.0", "1.40.1"),
	)
	it := cargoItem(t, cargoPlan(t, gh, in))
	got := cargoPackages(it)
	if syn := got["syn@1.0.109"]; syn.Action != ActionManual || syn.Reason != ReasonMultipleVersions || !strings.Contains(syn.Detail, "1.0.109, 2.0.50") {
		t.Errorf("syn = %+v", syn)
	}
	// tokio's requirement is "1", which allows the fix; the file is version 3
	// and the project declares rust-version 1.60.
	if tk := got["tokio@1.40.0"]; tk.Action != ActionUpdate || tk.SelectionLowerBound != "1.40.1" || tk.Relation != RelationDirect {
		t.Errorf("tokio = %+v", tk)
	}
	if it.Category != CategoryDependencyUpdateCandidate || it.Cargo.LockVersion != 3 || it.Cargo.RustVersion != "1.60" {
		t.Errorf("item = %s (%s) %+v", it.Category, it.Detail, it.Cargo)
	}
}

// The files of a project with a platform-specific dependency tree: the real
// lock of a direct dependency that brings in crates per platform.
func TestLanguagePlan_CargoRealPlatformDependencies(t *testing.T) {
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml": cargoFixture(t, "exp1.Cargo.toml"),
		"Cargo.lock": cargoFixture(t, "exp1.Cargo.lock"),
	})
	in := langInput("shop", "api",
		rustFinding("CVE-TK", typeCargo, "app/Cargo.lock", "tokio", "1.23.1", "1.23.2, 1.24.2"),
		rustFinding("CVE-WS", typeCargo, "app/Cargo.lock", "windows-sys", "0.42.0", "0.42.1"),
		rustFinding("CVE-MSVC", typeCargo, "app/Cargo.lock", "windows_x86_64_msvc", "0.42.2", "0.48.5"),
	)
	got := cargoPackages(cargoItem(t, cargoPlan(t, gh, in)))
	if tk := got["tokio@1.23.1"]; tk.Action != ActionUpdate || tk.SelectionLowerBound != "1.23.2" || tk.Relation != RelationDirect {
		t.Errorf("tokio = %+v", tk)
	}
	if ws := got["windows-sys@0.42.0"]; ws.Action != ActionUpdate || ws.SelectionLowerBound != "0.42.1" || ws.Relation != RelationTransitive {
		t.Errorf("windows-sys = %+v", ws)
	}
	// 0.48.5 is of another series than 0.42.2.
	if m := got["windows_x86_64_msvc@0.42.2"]; m.Action != ActionManual || m.Reason != ReasonFixInOtherMajor {
		t.Errorf("windows_x86_64_msvc = %+v", m)
	}
}

// --- what the planner does not change, and the update stage ---

// A directory of another ecosystem, or with no Cargo.toml, has the plan it
// had before Rust findings were read.
func TestLanguagePlan_CargoFindingsLeaveOtherPlansAlone(t *testing.T) {
	npmFinding := finding("CVE-N", "ignored", "1", "2", scanner.SeverityHigh)
	npmFinding.Class, npmFinding.Type, npmFinding.Target = inventory.ClassLang, typeNodePkg, "app/package.json"
	npmFinding.Package, npmFinding.InstalledVer, npmFinding.FixedVer = "minimist", "1.2.5", "1.2.6"
	rust := rustFinding("CVE-R", typeRustBinary, "usr/local/bin/app", "tokio", "1.18.0", tokioFixes)

	mk := func(withRust bool) []LanguageItem {
		gh := newFakeGitHub()
		npmRepo(gh, "ex/app", "svc")
		in := langInput("shop", "api", npmFinding)
		if withRust {
			in.Scan.Findings = append(in.Scan.Findings, rust, rustFinding("CVE-C", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes))
			in.Scan.Packages = []scanner.ResultPackages{rustBinaryPackages("usr/local/bin/app", "exp2", "0.1.0", "tokio", "1.18.0")}
		}
		return cargoPlan(t, gh, in)
	}
	before, after := mk(false), mk(true)
	if len(before) == 0 {
		t.Fatal("no items without Rust findings")
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Errorf("the plan changed:\n%s\n%s", a, b)
	}
}

func TestLangUpdater_CargoUnitsAreNotUpdated(t *testing.T) {
	cargo := LanguageItem{Key: "k#cargo", Manager: ManagerCargo, Category: CategoryDependencyUpdateCandidate, Reason: ReasonUpdateCandidateInSource,
		Packages: []LanguagePackage{{Name: "tokio", Installed: "1.18.0", Action: ActionUpdate, SelectionLowerBound: "1.18.4"}}}
	maven := LanguageItem{Key: "k#maven", Manager: ManagerMaven, Category: CategoryDependencyUpdateCandidate, Reason: ReasonUpdateCandidateInSource}
	plan := Plan{LanguageItems: []LanguageItem{cargo, maven}}
	// An updater that may run no job defers what it would update; a Cargo
	// unit is not one of those, and stays a candidate that nothing was run for.
	use := (&LangUpdater{}).Run(context.Background(), &plan)
	if use.Jobs != 0 {
		t.Errorf("jobs = %d", use.Jobs)
	}
	if got := plan.LanguageItems[0]; got.Category != CategoryDependencyUpdateCandidate || got.Reason != ReasonUpdateCandidateInSource || got.UpdateExecuted {
		t.Errorf("cargo item = %s %s executed=%v", got.Category, got.Reason, got.UpdateExecuted)
	}
	if got := plan.LanguageItems[1]; got.Category != CategoryDeferred || got.Reason != ReasonUpdateJobLimit {
		t.Errorf("maven item = %s %s", got.Category, got.Reason)
	}
}
