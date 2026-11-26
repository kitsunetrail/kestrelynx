package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The Cargo update is run against fakes: a GitHub with the tree of a
// repository, a work container that returns the Cargo.lock of a real cargo
// (testdata/cargo/check_*, made as lang_cargo_check_test.go says), a crates.io
// index made of real lines, and a scanner that reports the crates of the
// Cargo.lock it is given.

const cargoLibRS = "pub fn f() {}\n"

// cargoFlow is one Cargo item and what runs it.
type cargoFlow struct {
	t     *testing.T
	gh    *fakeGitHub
	item  LanguageItem
	work  *fakeWork
	fs    *fakeFS
	idx   *fakeCargoIndex
	cfg   LangUpdateConfig
	vulns map[string][]string // by name@version
	// lock is the Cargo.lock the work container returns for the files it was
	// given, and outcome changes what it does besides.
	lock    func(src map[string][]byte) []byte
	outcome func(o *fakeOutcome)
	// scan changes the report of a scan (0 before, 1 after) of the lockfile.
	scan func(n int, packages [][2]string, vulns [][3]string) ([][2]string, [][3]string)
}

// singleCargoFiles is the package the real locks were made for.
func singleCargoFiles(t *testing.T) map[string]string {
	return map[string]string{
		"Cargo.toml":  cargoFixture(t, "exp1.Cargo.toml"),
		"Cargo.lock":  cargoFixture(t, "check_tokio_1_18_0.Cargo.lock"),
		"src/lib.rs":  cargoLibRS,
		"src/main.rs": cargoLibRS,
	}
}

// newCargoFlow plans the Cargo item of a repository made of files (relative to
// the directory of the unit) for the findings, and prepares the fakes. setup,
// when given, changes the repository before it is planned.
func newCargoFlow(t *testing.T, files map[string]string, idx *fakeCargoIndex, in ImageInput, setup func(gh *fakeGitHub)) *cargoFlow {
	t.Helper()
	f := &cargoFlow{t: t, gh: newFakeGitHub(), idx: idx, vulns: map[string][]string{"tokio@1.18.0": {"CVE-TOKIO"}}}
	cargoRepo(f.gh, "ex/app", "svc", files)
	if setup != nil {
		setup(f.gh)
	}
	f.item = cargoItem(t, cargoPlan(t, f.gh, in))
	if f.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the plan gave %s %s (%s)", f.item.Category, f.item.Reason, f.item.Detail)
	}
	f.lock = func(map[string][]byte) []byte { return []byte(cargoFixture(t, "check_tokio_1_18_4.Cargo.lock")) }
	f.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		o := fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"Cargo.lock": f.lock(src)}}}
		if f.outcome != nil {
			f.outcome(&o)
		}
		return o
	}}
	f.fs = &fakeFS{fn: f.scanLock}
	f.cfg = LangUpdateConfig{Scanner: f.fs, Work: f.work, PyPI: &fakePyPI{}, Npm: &fakeNpm{}, Cargo: idx, GitHub: f.gh,
		Prepared: fsConds, MaxJobs: 5, Now: func() time.Time { return time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC) }}
	f.cfg = withTestTools(t, f.cfg)
	return f
}

// scanLock reports every crate of the Cargo.lock it is given, and the
// vulnerabilities in f.vulns.
func (f *cargoFlow) scanLock(n int, files map[string][]byte) (scanner.FSScan, error) {
	l, err := parseCargoLock(files["Cargo.lock"])
	if err != nil {
		return scanner.FSScan{}, err
	}
	var pkgs [][2]string
	var vulns [][3]string
	for _, c := range l.crates {
		pkgs = append(pkgs, [2]string{c.name, c.version})
		for _, id := range f.vulns[c.name+"@"+c.version] {
			vulns = append(vulns, [3]string{c.name, c.version, id})
		}
	}
	if f.scan != nil {
		pkgs, vulns = f.scan(n, pkgs, vulns)
	}
	return fsReport(typeCargo, pkgs, vulns), nil
}

// run runs the update stage over the item and returns the item after it.
func (f *cargoFlow) run() LanguageItem {
	f.t.Helper()
	up, err := NewLangUpdater(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{f.item}}
	up.Run(context.Background(), plan)
	return plan.LanguageItems[0]
}

func wantCargoOutcome(t *testing.T, it LanguageItem, cat Category, reason Reason, detail string) {
	t.Helper()
	if it.Category != cat || it.Reason != reason || !strings.Contains(it.Detail, detail) {
		t.Fatalf("got %s %s (%s), want %s %s containing %q", it.Category, it.Reason, it.Detail, cat, reason, detail)
	}
}

func tokioInput() ImageInput {
	return langInput("shop", "api", rustFinding("CVE-TOKIO", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", "1.18.4"))
}

func realTokioIndex(t *testing.T) *fakeCargoIndex { return realCargoIndex(t, "check_index.jsonl") }

func newTokioFlow(t *testing.T) *cargoFlow {
	t.Helper()
	return newCargoFlow(t, singleCargoFiles(t), realTokioIndex(t), tokioInput(), nil)
}

// A package whose files are the ones a real cargo made: the update runs one
// cargo update of the crate to the release of the index, with the files of the
// package as the job's inputs, and the Cargo.lock it returns is the one a
// pull request is made of.
func TestCargoUpdate_RealPackagePassesToPRCandidate(t *testing.T) {
	f := newTokioFlow(t)
	it := f.run()
	if it.Category != CategoryPRCandidate || it.Reason != ReasonUpdateVerified {
		t.Fatalf("got %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
	if !it.UpdateExecuted || !it.PostUpdateCheckExecuted {
		t.Errorf("executed flags = %v %v", it.UpdateExecuted, it.PostUpdateCheckExecuted)
	}
	if len(f.work.jobs) != 1 {
		t.Fatalf("jobs = %d", len(f.work.jobs))
	}
	job := f.work.jobs[0]
	if job.Manager != worker.ManagerCargo || job.Runtime.ID != "rust1.100" || job.Tool != nil {
		t.Errorf("job = %+v", job)
	}
	if len(job.Steps) != 1 || job.Steps[0].ID != stepUpdate || job.Steps[0].Op != worker.OpCargoUpdate ||
		len(job.Steps[0].Packages) != 1 || job.Steps[0].Packages[0] != (worker.Package{Name: "tokio", From: "1.18.0", Version: "1.18.4"}) {
		t.Errorf("steps = %+v", job.Steps)
	}
	roles := map[string]string{}
	for _, in := range job.Inputs {
		roles[in.Path] = in.Role
	}
	want := map[string]string{"Cargo.lock": worker.RoleLockfile, "Cargo.toml": worker.RoleManifest, "src/lib.rs": worker.RoleEmpty, "src/main.rs": worker.RoleEmpty}
	if fmt.Sprint(roles) != fmt.Sprint(want) {
		t.Errorf("inputs = %v, want %v", roles, want)
	}
	if got := f.work.srcs[0]["src/lib.rs"]; len(got) != 0 {
		t.Errorf("src/lib.rs was sent with %d bytes", len(got))
	}
	if fmt.Sprint(job.Outputs) != "[Cargo.lock Cargo.toml src/lib.rs src/main.rs]" {
		t.Errorf("outputs = %v", job.Outputs)
	}
	p := it.Packages[0]
	if p.AdoptedVersion != "1.18.4" || p.Reason != ReasonUpdateVerified {
		t.Errorf("package = %+v", p)
	}
	if c := it.Update.Cargo; c == nil || len(c.Targets) != 1 || c.Targets[0] != (CargoCrateChange{"tokio", "1.18.0", "1.18.4"}) {
		t.Errorf("cargo change = %+v", it.Update.Cargo)
	}
	if rt := it.Update.Runtime; rt == nil || rt.ID != "rust1.100" || rt.Digest == "" {
		t.Errorf("runtime = %+v", rt)
	}
	if len(it.Artifacts) != 1 || it.Artifacts[0].Path != "svc/Cargo.lock" || string(it.Artifacts[0].Content) != cargoFixture(t, "check_tokio_1_18_4.Cargo.lock") {
		t.Errorf("artifacts = %+v", it.Artifacts)
	}
	sc := it.SourceCheck
	if sc == nil || !sc.Passed || len(sc.Resolved) != 1 || sc.Resolved[0].VulnID != "CVE-TOKIO" {
		t.Fatalf("source check = %+v", sc)
	}
	// Only the lockfile is scanned, before and after.
	if f.fs.calls != 2 {
		t.Errorf("scans = %d", f.fs.calls)
	}
}

// The files of every package of a workspace and the build targets named in a
// Cargo.toml and found in the tree are given to the job, the ones that are
// only files as empty ones.
func TestCargoUpdate_WorkspaceInputs(t *testing.T) {
	files := map[string]string{
		"Cargo.toml":          cargoFixture(t, "exp3.Cargo.toml"),
		"a/Cargo.toml":        cargoFixture(t, "exp3.a.Cargo.toml"),
		"b/Cargo.toml":        cargoFixture(t, "exp3.b.Cargo.toml"),
		"Cargo.lock":          cargoFixture(t, "exp3.Cargo.lock"),
		"a/src/main.rs":       cargoLibRS,
		"a/src/bin/x.rs":      cargoLibRS,
		"a/src/bin/y/main.rs": cargoLibRS,
		"a/tests/t.rs":        cargoLibRS,
		"a/build.rs":          cargoLibRS,
		"b/src/lib.rs":        cargoLibRS,
		"b/examples/e.rs":     cargoLibRS,
		"b/README.md":         "x",
	}
	idx := &fakeCargoIndex{rels: map[string][]CargoRelease{
		"tokio":    {{Name: "tokio", Version: "1.54.1"}, {Name: "tokio", Version: "1.54.2"}},
		"smallvec": {{Name: "smallvec", Version: "1.6.0"}, {Name: "smallvec", Version: "1.6.1"}},
	}}
	in := langInput("shop", "api",
		rustFinding("CVE-SV", typeRustBinary, "usr/local/bin/a", "smallvec", "1.6.0", "1.6.1"),
		rustFinding("CVE-TK", typeRustBinary, "usr/local/bin/a", "tokio", "1.54.1", "1.54.2"))
	in.Scan.Packages = []scanner.ResultPackages{
		rustBinaryPackages("usr/local/bin/a", "a", "0.1.0", "b", "0.1.0", "smallvec", "1.6.0", "tokio", "1.54.1"),
	}
	f := newCargoFlow(t, files, idx, in, nil)
	f.outcome = func(o *fakeOutcome) { o.failStep = stepUpdate }
	it := f.run()
	wantCargoOutcome(t, it, CategoryManual, ReasonUpdateStepFailed, "")
	if len(f.work.jobs) != 1 {
		t.Fatalf("jobs = %d", len(f.work.jobs))
	}
	job := f.work.jobs[0]
	roles := map[string]string{}
	var paths []string
	for _, in := range job.Inputs {
		roles[in.Path] = in.Role
		paths = append(paths, in.Path)
	}
	sort.Strings(paths)
	wantPaths := "Cargo.lock,Cargo.toml,a/Cargo.toml,a/build.rs,a/src/bin/x.rs,a/src/bin/y/main.rs,a/src/main.rs,a/tests/t.rs,b/Cargo.toml,b/examples/e.rs,b/src/lib.rs"
	if strings.Join(paths, ",") != wantPaths {
		t.Fatalf("inputs = %v", paths)
	}
	for _, m := range []string{"Cargo.toml", "a/Cargo.toml", "b/Cargo.toml"} {
		if roles[m] != worker.RoleManifest {
			t.Errorf("%s has the role %q", m, roles[m])
		}
	}
	if roles["Cargo.lock"] != worker.RoleLockfile || roles["a/src/main.rs"] != worker.RoleEmpty || roles["b/src/lib.rs"] != worker.RoleEmpty {
		t.Errorf("roles = %v", roles)
	}
	// One cargo update for each crate, by name, each from the version of the
	// lock to the release of the index.
	if len(job.Steps) != 2 || job.Steps[0].ID != "update" || job.Steps[1].ID != "update-2" ||
		job.Steps[0].Packages[0] != (worker.Package{Name: "smallvec", From: "1.6.0", Version: "1.6.1"}) ||
		job.Steps[1].Packages[0] != (worker.Package{Name: "tokio", From: "1.54.1", Version: "1.54.2"}) {
		t.Errorf("steps = %+v", job.Steps)
	}
	if string(f.work.srcs[0]["a/Cargo.toml"]) != files["a/Cargo.toml"] || len(f.work.srcs[0]["a/src/main.rs"]) != 0 {
		t.Error("the members' files are not as the repository has them")
	}
}

// What the job returns of the files it was given has to be what it was given.
func TestCargoUpdate_FilesReturnedChanged(t *testing.T) {
	f := newTokioFlow(t)
	f.outcome = func(o *fakeOutcome) {
		o.edit[stepUpdate]["Cargo.toml"] = []byte(strings.Replace(cargoFixture(t, "exp1.Cargo.toml"), `"1"`, `"1.18"`, 1))
	}
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonManifestChanged, "Cargo.toml")

	f = newTokioFlow(t)
	f.outcome = func(o *fakeOutcome) { o.edit[stepUpdate]["src/lib.rs"] = []byte("fn main() {}") }
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonOutputFilesInvalid, "src/lib.rs")

	f = newTokioFlow(t)
	f.lock = func(src map[string][]byte) []byte { return src["Cargo.lock"] }
	it := f.run()
	wantCargoOutcome(t, it, CategoryManual, ReasonTargetNotUpdated, "unchanged")
	if len(it.Artifacts) != 0 {
		t.Errorf("artifacts = %+v", it.Artifacts)
	}

	f = newTokioFlow(t)
	f.outcome = func(o *fakeOutcome) { o.failStep = stepUpdate }
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonUpdateStepFailed, "")

	// The copy a step collected is checked too, though the final tree has
	// the file as it was sent.
	stepCopy := func(name string, content []byte) func(o *fakeOutcome) {
		return func(o *fakeOutcome) {
			key := worker.StepsDir + "/" + stepUpdate + "/" + name
			o.mangleResult = func(r *worker.Result) {
				for i, out := range r.Steps[0].Outputs {
					if out.Path == name {
						r.Steps[0].Outputs[i].Size, r.Steps[0].Outputs[i].SHA256 = int64(len(content)), sha256Hex(content)
					}
				}
			}
			o.mangle = func(files map[string][]byte) { files[key] = content }
		}
	}
	f = newTokioFlow(t)
	f.outcome = stepCopy("Cargo.toml", []byte("[package]\nname = \"other\"\n"))
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonManifestChanged, "Cargo.toml (in step update)")

	f = newTokioFlow(t)
	f.outcome = stepCopy("src/main.rs", []byte("fn main() {}"))
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonOutputFilesInvalid, "src/main.rs, a file it was given with no content (in step update)")
}

func TestCargoUpdate_OutputTotal(t *testing.T) {
	// Each copy is within the bound of one file; the three come to more
	// than the copies of a job.
	big := make([]byte, worker.MaxOutTotalBytes/3+1)
	files := map[string][]byte{worker.StepsDir + "/update/Cargo.lock": big, worker.StepsDir + "/update-2/Cargo.lock": big, worker.FinalDir + "/Cargo.lock": big}
	job := worker.Job{Manager: worker.ManagerCargo}
	inputs := map[string][]byte{"Cargo.lock": big}
	f := outputSizeFailure(job, inputs, files)
	if f == nil || f.reason != ReasonOutputFilesInvalid || !strings.Contains(f.detail, "copies a job collects") {
		t.Fatalf("got %+v", f)
	}
	delete(files, worker.FinalDir+"/Cargo.lock")
	if f := outputSizeFailure(job, inputs, files); f != nil {
		t.Fatalf("got %+v", f)
	}
}

// A Cargo.lock the check does not accept is not proposed.
func TestCargoUpdate_LockRefused(t *testing.T) {
	f := newTokioFlow(t)
	f.lock = func(map[string][]byte) []byte {
		return []byte(strings.Replace(cargoFixture(t, "check_tokio_1_18_4.Cargo.lock"), `name = "pin-project-lite"
version = "0.2.18"`, `name = "pin-project-lite"
version = "0.2.17"`, 1))
	}
	it := f.run()
	if it.Category != CategoryManual {
		t.Fatalf("got %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
	if len(it.Artifacts) != 0 {
		t.Errorf("artifacts = %+v", it.Artifacts)
	}
}

// Where the build targets are is read from the tree of the commit, and what
// cannot be told stops the update before a container is run.
func TestCargoUpdate_BuildTargets(t *testing.T) {
	type tc struct {
		name   string
		files  func(m map[string]string)
		setup  func(gh *fakeGitHub)
		reason Reason
		detail string
	}
	cases := []tc{
		{name: "a target the manifest names is not in the tree",
			files:  func(m map[string]string) { m["Cargo.toml"] += "\n[lib]\npath = \"src/missing.rs\"\n" },
			reason: ReasonDependencyFilesNotFound, detail: "svc/src/missing.rs"},
		{name: "a target the manifest names is a directory",
			files: func(m map[string]string) {
				m["Cargo.toml"] += "\n[[bin]]\nname = \"x\"\npath = \"src/dir\"\n"
				m["src/dir/main.rs"] = cargoLibRS
			},
			reason: ReasonDependencyFileUnusable, detail: "svc/src/dir is a dir"},
		{name: "a target path reaches outside the workspace",
			files:  func(m map[string]string) { m["Cargo.toml"] += "\n[lib]\npath = \"../x.rs\"\n" },
			reason: ReasonWorkspaceUnsupported, detail: "../x.rs"},
		{name: "a target table is not one cargo reads",
			files:  func(m map[string]string) { m["Cargo.toml"] += "\n[lib]\npath = 3\n" },
			reason: ReasonCargoManifestUnsupported, detail: "[lib] with a path"},
		{name: "lib.rs is a symlink",
			files: func(m map[string]string) { delete(m, "src/lib.rs") },
			setup: func(gh *fakeGitHub) {
				gh.putEntry("ex/app", "svc/src", github.Entry{Name: "lib.rs", Type: github.EntrySymlink})
			},
			reason: ReasonDependencyFileUnusable, detail: "svc/src/lib.rs is a symlink"},
		{name: "a file of the build is a submodule",
			files: func(m map[string]string) {},
			setup: func(gh *fakeGitHub) {
				gh.putEntry("ex/app", "svc", github.Entry{Name: "build.rs", Type: github.EntrySubmodule})
			},
			reason: ReasonDependencyFileUnusable, detail: "svc/build.rs is a submodule"},
		{name: "a directory of targets is a symlink",
			files: func(m map[string]string) {},
			setup: func(gh *fakeGitHub) {
				gh.putEntry("ex/app", "svc", github.Entry{Name: "tests", Type: github.EntrySymlink})
			},
			reason: ReasonDependencyFileUnusable, detail: "svc/tests is a symlink"},
		{name: "more files than a job takes",
			files: func(m map[string]string) {
				for i := 0; i < worker.MaxCargoInputs; i++ {
					m[fmt.Sprintf("src/bin/b%d.rs", i)] = cargoLibRS
				}
			},
			reason: ReasonUpdateInputLimit, detail: fmt.Sprintf("more than the %d one job takes", worker.MaxCargoInputs)},
		{name: "a path the job cannot name",
			files:  func(m map[string]string) { m["src/bin/a b.rs"] = cargoLibRS },
			reason: ReasonWorkspaceUnsupported, detail: "a b.rs"},
		{name: "a path with an element that starts with a dash",
			files:  func(m map[string]string) { m["src/bin/-x.rs"] = cargoLibRS },
			reason: ReasonWorkspaceUnsupported, detail: "-x.rs"},
		{name: "a target path passes through a link",
			files: func(m map[string]string) {
				m["Cargo.toml"] += "\n[lib]\npath = \"link/../src/lib.rs\"\n"
			},
			setup: func(gh *fakeGitHub) {
				gh.putEntry("ex/app", "svc", github.Entry{Name: "link", Type: github.EntrySymlink})
			},
			reason: ReasonWorkspaceUnsupported, detail: "link/../src/lib.rs"},
		{name: "a directory on the way to a target path is a link",
			files: func(m map[string]string) {
				m["Cargo.toml"] += "\n[lib]\npath = \"link/lib.rs\"\n"
			},
			setup: func(gh *fakeGitHub) {
				gh.putEntry("ex/app", "svc", github.Entry{Name: "link", Type: github.EntrySymlink})
				gh.putEntry("ex/app", "svc/link", github.Entry{Name: "lib.rs", Type: github.EntryFile})
			},
			reason: ReasonDependencyFileUnusable, detail: "svc/link is a symlink"},
		{name: "finding targets by their place is turned off",
			files: func(m map[string]string) {
				m["Cargo.toml"] = strings.Replace(m["Cargo.toml"], "[package]\n", "[package]\nautobins = false\n", 1)
			},
			reason: ReasonCargoManifestUnsupported, detail: "package.autobins = false"},
		{name: "an auto key that is not a boolean",
			files: func(m map[string]string) {
				m["Cargo.toml"] = strings.Replace(m["Cargo.toml"], "[package]\n", "[package]\nautotests = \"no\"\n", 1)
			},
			reason: ReasonCargoManifestUnsupported, detail: "package.autotests"},
		{name: "a path of more elements than a job takes",
			files: func(m map[string]string) {
				m["src/bin/a/main.rs"] = cargoLibRS
				m["Cargo.toml"] += "\n[[bin]]\nname = \"deep\"\npath = \"a/b/c/d/e/f/g/i/h.rs\"\n"
				m["a/b/c/d/e/f/g/i/h.rs"] = cargoLibRS
			},
			reason: ReasonWorkspaceUnsupported, detail: "elements"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := singleCargoFiles(t)
			c.files(files)
			f := newCargoFlow(t, files, realTokioIndex(t), tokioInput(), c.setup)
			it := f.run()
			wantCargoOutcome(t, it, CategoryManual, c.reason, c.detail)
			if len(f.work.jobs) != 0 {
				t.Errorf("a job was run")
			}
		})
	}
}

// The files are read again from the commit the plan was made from and must be
// what the plan recorded.
func TestCargoUpdate_SourcesChanged(t *testing.T) {
	f := newTokioFlow(t)
	f.item.Source.Files[0].BlobSHA = "0000000000000000000000000000000000000000"
	wantCargoOutcome(t, f.run(), CategoryFailed, ReasonSourceChanged, "svc/Cargo.toml")

	// A file the plan did not find is there now.
	f = newTokioFlow(t)
	f.gh.put("ex/app", "svc", "rust-toolchain.toml", "[toolchain]\nchannel = \"1.80\"\n")
	wantCargoOutcome(t, f.run(), CategoryFailed, ReasonSourceChanged, "svc/rust-toolchain.toml")

	// The packages of the workspace are not the ones the plan recorded.
	f = newTokioFlow(t)
	f.item.Cargo.Members[0].Version = "9.9.9"
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonSourceChanged, "9.9.9")
	if len(f.work.jobs) != 0 {
		t.Error("a job was run")
	}

	// A member the glob of the workspace now has that the plan did not read.
	files := map[string]string{
		"Cargo.toml":          "[workspace]\nmembers = [\"crates/*\"]\n",
		"crates/a/Cargo.toml": cargoFixture(t, "exp1.Cargo.toml"),
		"crates/a/src/lib.rs": cargoLibRS,
		"Cargo.lock":          cargoFixture(t, "check_tokio_1_18_0.Cargo.lock"),
	}
	f = newCargoFlow(t, files, realTokioIndex(t), tokioInput(), nil)
	f.gh.put("ex/app", "svc/crates/b", "Cargo.toml", strings.Replace(cargoFixture(t, "exp1.Cargo.toml"), "exp1", "exp9", 1))
	f.gh.putEntry("ex/app", "svc/crates", github.Entry{Name: "b", Type: github.EntryDir})
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonDependencyFilesNotFound, "svc/crates/b")
}

// Without a crates.io index client, or a Rust runtime that has been run on the
// platform, nothing runs.
func TestCargoUpdate_Environment(t *testing.T) {
	f := newTokioFlow(t)
	f.cfg.Cargo = nil
	wantCargoOutcome(t, f.run(), CategoryFailed, ReasonUpdateInputInvalid, "crates.io index")

	f = newTokioFlow(t)
	f.cfg.Platform = "linux/arm64"
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonCargoRuntimeUnavailable, "linux/arm64")
	if len(f.work.jobs) != 0 {
		t.Error("a job was run")
	}

	// A runtime past the end of its support is not used.
	f = newTokioFlow(t)
	f.cfg.Now = func() time.Time { return time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC) }
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonRuntimeEndOfLife, "")
}

// The releases are looked up in the index within the budget of lookups an
// update may make.
func TestCargoUpdate_IndexLookups(t *testing.T) {
	f := newTokioFlow(t)
	f.idx.err = map[string]error{"tokio": ErrReleaseNotFound}
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonDistributionMismatch, "tokio")

	f = newTokioFlow(t)
	f.idx.err = map[string]error{"tokio": fmt.Errorf("boom")}
	wantCargoOutcome(t, f.run(), CategoryFailed, ReasonDistributionLookup, "tokio")

	// A target the index has no release for.
	f = newTokioFlow(t)
	f.item.Packages[0].SelectionLowerBound = "1.99.0"
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonCargoReleaseNotFound, "1.99.0")

	// A release with build metadata cannot be named exactly.
	idx := &fakeCargoIndex{rels: map[string][]CargoRelease{"tokio": {{Name: "tokio", Version: "1.18.0"}, {Name: "tokio", Version: "1.18.4+meta"}}}}
	f = newCargoFlow(t, singleCargoFiles(t), idx, tokioInput(), nil)
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonCargoReleaseNotFound, "build metadata")

	// The lookups of one update are bounded.
	f = newTokioFlow(t)
	up, err := NewLangUpdater(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	set, fail := newUpdateSet(&f.item)
	if fail != nil {
		t.Fatal(fail.detail)
	}
	r := &updateRun{u: up, it: &f.item, set: set, lookups: maxRegistryChecks}
	l, err := parseCargoLock([]byte(cargoFixture(t, "check_tokio_1_18_0.Cargo.lock")))
	if err != nil {
		t.Fatal(err)
	}
	_, _, fail = r.cargoTargets(context.Background(), l)
	if fail == nil || fail.category != CategoryDeferred || fail.reason != ReasonRegistryCheckLimit || f.idx.total() != 0 {
		t.Fatalf("got %+v (%d lookups)", fail, f.idx.total())
	}
	// The check of the Cargo.lock that comes back shares the budget.
	r = &updateRun{u: up, it: &f.item, set: set, lookups: maxRegistryChecks - 1}
	_, targets, fail := r.cargoTargets(context.Background(), l)
	if fail != nil || len(targets) != 1 || r.lookups != maxRegistryChecks {
		t.Fatalf("got %+v %+v lookups=%d", fail, targets, r.lookups)
	}
	if err := r.spendCargoLookup(); err == nil {
		t.Error("a lookup over the budget was allowed")
	}
}

// What the lookups of one update read of the index is bounded, for the
// choosing of the releases and the check of the Cargo.lock together.
func TestCargoUpdate_IndexBytes(t *testing.T) {
	ctx := context.Background()
	idx := &fakeCargoIndex{rels: map[string][]CargoRelease{"a": {{Name: "a", Version: "1.0.0"}}}, size: map[string]int64{"a": 20}}

	// A file that does not fit in what is left is not read to its end.
	b := &cargoIndexBudget{used: maxCargoIndexTotalBytes - 10}
	if _, err := b.versions(ctx, idx, "a"); !errors.Is(err, errCargoIndexBudget) || b.used != maxCargoIndexTotalBytes+1 {
		t.Fatalf("got %v, used %d", err, b.used)
	}
	// Nothing is asked once the budget is spent.
	if _, err := b.versions(ctx, idx, "a"); !errors.Is(err, errCargoIndexBudget) || idx.total() != 1 {
		t.Fatalf("got %v after %d requests", err, idx.total())
	}
	// Within the budget the bytes are counted.
	b = &cargoIndexBudget{}
	if rels, err := b.versions(ctx, idx, "a"); err != nil || len(rels) != 1 || b.used != 20 {
		t.Fatalf("got %v %+v, used %d", err, rels, b.used)
	}
	// A file over the bound of one file, with the budget not the reason, is
	// the error of the index.
	idx.size["a"] = maxCargoIndexBytes + 1
	if _, err := b.versions(ctx, idx, "a"); !errors.Is(err, errCargoIndexOverLimit) {
		t.Fatalf("got %v", err)
	}

	// The update and the check of what comes back share the budget.
	f := newTokioFlow(t)
	f.idx.size = map[string]int64{"tokio": 30 << 20}
	if it := f.run(); it.Category != CategoryPRCandidate {
		t.Fatalf("got %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
	up, err := NewLangUpdater(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	set, fail := newUpdateSet(&f.item)
	if fail != nil {
		t.Fatal(fail.detail)
	}
	r := &updateRun{u: up, it: &f.item, set: set, cargoIndex: cargoIndexBudget{used: maxCargoIndexTotalBytes - 1}}
	l, err := parseCargoLock([]byte(cargoFixture(t, "check_tokio_1_18_0.Cargo.lock")))
	if err != nil {
		t.Fatal(err)
	}
	_, _, fail = r.cargoTargets(ctx, l)
	if fail == nil || fail.category != CategoryManual || fail.reason != ReasonRegistryCheckLimit || !strings.Contains(fail.detail, "67108864 bytes") {
		t.Fatalf("got %+v", fail)
	}

	f = newTokioFlow(t)
	f.idx.size = map[string]int64{"tokio": maxCargoIndexBytes + 1}
	wantCargoOutcome(t, f.run(), CategoryFailed, ReasonDistributionLookup, "tokio")
}

// The scans of the Cargo.lock before and after are compared by crate, version
// and vulnerability.
func TestCargoUpdate_Scans(t *testing.T) {
	// A crate of the file the scan does not list.
	f := newTokioFlow(t)
	f.scan = func(n int, pkgs [][2]string, vulns [][3]string) ([][2]string, [][3]string) {
		if n == 1 {
			pkgs = pkgs[:len(pkgs)-1]
		}
		return pkgs, vulns
	}
	it := f.run()
	wantCargoOutcome(t, it, CategoryNotComparable, ReasonSourceScanIncomplete, "updated files does not list")

	f = newTokioFlow(t)
	f.scan = func(n int, pkgs [][2]string, vulns [][3]string) ([][2]string, [][3]string) {
		if n == 0 {
			pkgs = pkgs[:len(pkgs)-1]
		}
		return pkgs, vulns
	}
	wantCargoOutcome(t, f.run(), CategoryNotComparable, ReasonSourceScanIncomplete, "original files does not list")

	// A vulnerability the update was for is still reported.
	f = newTokioFlow(t)
	f.vulns["tokio@1.18.4"] = []string{"CVE-TOKIO"}
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonSourceTargetStillDetected, "CVE-TOKIO")

	// A finding of a crate and a version the file did not have is new, though
	// the crate has the same vulnerability at another version before.
	f = newTokioFlow(t)
	f.vulns["pin-project-lite@0.2.18"] = []string{"CVE-PL"}
	f.scan = func(n int, pkgs [][2]string, vulns [][3]string) ([][2]string, [][3]string) {
		if n == 1 {
			pkgs = append(pkgs, [2]string{"pin-project-lite", "0.2.99"})
			vulns = append(vulns, [3]string{"pin-project-lite", "0.2.99", "CVE-PL"})
		}
		return pkgs, vulns
	}
	it = f.run()
	wantCargoOutcome(t, it, CategoryManual, ReasonSourceIntroduced, "pin-project-lite 0.2.99")
	if sc := it.SourceCheck; sc == nil || len(sc.Introduced) != 1 || len(sc.Remaining) != 1 {
		t.Errorf("source check = %+v", sc)
	}

	// A new finding of another crate.
	f = newTokioFlow(t)
	f.vulns["tokio@1.18.4"] = nil
	f.scan = func(n int, pkgs [][2]string, vulns [][3]string) ([][2]string, [][3]string) {
		if n == 1 {
			vulns = append(vulns, [3]string{"pin-project-lite", "0.2.18", "CVE-NEW"})
		}
		return pkgs, vulns
	}
	wantCargoOutcome(t, f.run(), CategoryManual, ReasonSourceIntroduced, "CVE-NEW")
}

// The record of the workspace the plan made stays on the item.
func TestCargoUpdate_RecordIsKept(t *testing.T) {
	f := newTokioFlow(t)
	it := f.run()
	if it.Cargo == nil || it.Cargo.LockVersion != 4 || len(it.Cargo.Members) != 1 {
		t.Fatalf("record = %+v", it.Cargo)
	}
}
