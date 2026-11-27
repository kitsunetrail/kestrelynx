package remediation

import (
	"context"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// prTreeSource lets the pull request stage list the directories of the fake
// GitHub and read the tree of its root, as the real client does: the tree SHA
// of a directory changes when anything under it does.
type prTreeSource struct{ *fakePRGitHub }

func (s prTreeSource) files(repo, sha string) (map[string]fakeEntry, error) {
	rs, err := s.repo(repo)
	if err != nil {
		return nil, err
	}
	c, ok := rs.commits[sha]
	if !ok {
		return nil, github.ErrNotFound
	}
	return rs.trees[c.tree], nil
}

// dirSHA is the stand-in tree SHA of dir: a hash of what is under it.
func dirSHA(files map[string]fakeEntry, dir string) string {
	var parts []string
	for p, e := range files {
		if dir == "." || strings.HasPrefix(p, dir+"/") {
			parts = append(parts, p+"="+e.blob+"="+e.mode)
		}
	}
	sort.Strings(parts)
	return fakeSHA(append([]string{"tree", dir}, parts...)...)
}

func (s prTreeSource) ListDirectory(_ context.Context, repo, sha, dir string) ([]github.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := readErr(s.begin("ListDirectory", repo, false)); err != nil {
		return nil, err
	}
	files, err := s.files(repo, sha)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []github.Entry
	for p, e := range files {
		rest := p
		if dir != "." {
			if !strings.HasPrefix(p, dir+"/") {
				continue
			}
			rest = strings.TrimPrefix(p, dir+"/")
		}
		name, _, nested := strings.Cut(rest, "/")
		if seen[name] {
			continue
		}
		seen[name] = true
		if nested {
			out = append(out, github.Entry{Name: name, Path: path.Join(dir, name), Type: github.EntryDir, SHA: dirSHA(files, path.Join(dir, name))})
		} else {
			out = append(out, github.Entry{Name: name, Path: path.Join(dir, name), Type: github.EntryFile, SHA: e.blob})
		}
	}
	if len(out) == 0 {
		return nil, github.ErrNotFound
	}
	return out, nil
}

func (s prTreeSource) RootTree(_ context.Context, repo, sha string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.files(repo, sha)
	if err != nil {
		return "", err
	}
	return dirSHA(files, "."), nil
}

// cargoGlobFixture is a Cargo update of a workspace whose member is found by a
// "crates/*" entry; only Cargo.lock changes.
func cargoGlobFixture() langFixture {
	fx := langFixtures()["cargo"]
	fx.files = map[string]string{
		"svc/Cargo.toml":          "[workspace]\nmembers = [\"crates/*\"]\n",
		"svc/crates/a/Cargo.toml": "[package]\nname = \"a\"\nversion = \"0.1.0\"\n",
		"svc/Cargo.lock":          "version = 4\n# a\n",
	}
	return fx
}

// cargoGlobItem is the item of the fixture as the update stage leaves it, with
// the tree of the directory the plan listed as it is at the plan's commit.
func cargoGlobItem(h *prHarness, fx langFixture, src prTreeSource) LanguageItem {
	it := h.langItem(fx)
	files, err := src.files(testRepo, it.Source.CommitSHA)
	if err != nil {
		h.t.Fatal(err)
	}
	it.Source.Trees = []SourceTree{{Path: "svc/crates", SHA: dirSHA(files, "svc/crates")}}
	it.Update.Cargo = &CargoLockChange{
		Targets:         []CargoCrateChange{{Name: "tokio", From: "1.18.0", To: "1.18.4"}},
		Others:          []CargoCrateChange{{Name: "bytes", From: "1.5.0", To: "1.6.1"}},
		LockVersionFrom: 4, LockVersionTo: 4,
		Moved:          []CargoCrateRef{{Name: "bytes", Version: "1.6.1"}, {Name: "tokio", Version: "1.18.4"}},
		MaxRustVersion: "1.63.0",
	}
	return it
}

// A pr_candidate Cargo item becomes one pull request whose commit changes
// Cargo.lock and nothing else, and whose description is the Cargo one.
func TestPRStageCargoMakesAPullRequestOfCargoLockOnly(t *testing.T) {
	fx := cargoGlobFixture()
	h := langHarness(t, fx)
	h.source = prTreeSource{h.gh}
	it := cargoGlobItem(h, fx, prTreeSource{h.gh})
	base := h.gh.branch(testRepo, "main")
	u := onlyUnit(t, h.run(prLangPlan(it)))
	wantStatus(t, u, PRStatusCreated, "")
	if u.Language == nil || u.Language.Manager != "cargo" || u.Path != "svc/Cargo.lock" {
		t.Errorf("unit = %+v", u)
	}
	pr := h.gh.pulls(testRepo)[0]
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Lang == nil || m.Lang.Manager != "cargo" || m.verify(testRepoID) != nil {
		t.Fatalf("marker %+v err %v", m, err)
	}
	if len(m.Changes) != 1 || m.Changes[0].Path != "svc/Cargo.lock" {
		t.Errorf("marker changes = %+v", m.Changes)
	}

	// Every file but Cargo.lock is the one the base has.
	h.gh.mu.Lock()
	rs := h.gh.repos[strings.ToLower(testRepo)]
	before, after := rs.trees[rs.commits[base].tree], rs.trees[rs.commits[pr.HeadSHA].tree]
	h.gh.mu.Unlock()
	if len(before) != len(after) {
		t.Errorf("%d files before, %d after", len(before), len(after))
	}
	for p, e := range after {
		if p != "svc/Cargo.lock" && before[p] != e {
			t.Errorf("%s changed", p)
		}
	}
	if string(h.readHead(pr, "svc/Cargo.lock")) != "version = 4\n# b\n" {
		t.Error("Cargo.lock is not the updated one")
	}
	for _, want := range []string{"`cargo build --locked && cargo test --locked`", "**Cargo update**", "`tokio`: `1.18.0` to `1.18.4`", "`bytes`: `1.5.0` to `1.6.1`", "`1.63.0`", "crates.io"} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the description lacks %q:\n%s", want, pr.Body)
		}
	}
}

func (h *prHarness) readHead(pr github.PullRequest, p string) []byte {
	h.t.Helper()
	f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, p)
	if err != nil {
		h.t.Fatal(err)
	}
	return f.Content
}

// When the base branch has moved since the plan, the directories the plan
// listed are read again: the same trees let the update through, a tree that
// differs or a directory that is gone or is no longer one defers it.
func TestPRStageCargoChecksTheListedDirectoriesWhenTheBaseMoved(t *testing.T) {
	type moved struct {
		name   string
		move   func(h *prHarness)
		edit   func(it *LanguageItem)
		status PRUnitStatus
		reason Reason
	}
	for _, c := range []moved{
		{name: "an unrelated file is pushed", move: func(h *prHarness) { h.addFiles(map[string]string{"README.md": "hi\n"}) },
			status: PRStatusCreated},
		{name: "a member is added", move: func(h *prHarness) {
			h.addFiles(map[string]string{"svc/crates/b/Cargo.toml": "[package]\nname = \"b\"\nversion = \"0.1.0\"\n"})
		}, status: PRStatusDeferred, reason: ReasonSourceChanged},
		{name: "a file of a member is pushed", move: func(h *prHarness) {
			h.addFiles(map[string]string{"svc/crates/a/src/lib.rs": "pub fn f() {}\n"})
		}, status: PRStatusDeferred, reason: ReasonSourceChanged},
		{name: "the recorded directory is not there", move: func(h *prHarness) { h.addFiles(map[string]string{"README.md": "hi\n"}) },
			edit:   func(it *LanguageItem) { it.Source.Trees[0].Path = "svc/gone" },
			status: PRStatusDeferred, reason: ReasonSourceChanged},
		{name: "the recorded directory is a file now", move: func(h *prHarness) { h.addFiles(map[string]string{"README.md": "hi\n"}) },
			edit:   func(it *LanguageItem) { it.Source.Trees[0].Path = "svc/Cargo.toml" },
			status: PRStatusDeferred, reason: ReasonSourceChanged},
	} {
		t.Run(c.name, func(t *testing.T) {
			fx := cargoGlobFixture()
			h := langHarness(t, fx)
			h.source = prTreeSource{h.gh}
			it := cargoGlobItem(h, fx, prTreeSource{h.gh})
			c.move(h)
			if c.edit != nil {
				c.edit(&it)
			}
			u := onlyUnit(t, h.run(prLangPlan(it)))
			wantStatus(t, u, c.status, c.reason)
			if want := c.status == PRStatusCreated; (len(h.gh.pulls(testRepo)) == 1) != want {
				t.Errorf("pulls = %d", len(h.gh.pulls(testRepo)))
			}
		})
	}
}

// The directories are not read when the base branch is where the plan left it.
func TestPRStageCargoDoesNotListWhenTheBaseDidNotMove(t *testing.T) {
	fx := cargoGlobFixture()
	h := langHarness(t, fx)
	h.source = prTreeSource{h.gh}
	it := cargoGlobItem(h, fx, prTreeSource{h.gh})
	it.Source.Trees[0].SHA = strings.Repeat("0", 40)
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(it))), PRStatusCreated, "")
	if n := countCalls(h.gh, "ListDirectory"); n != 0 {
		t.Errorf("%d listings", n)
	}
}

// A source that cannot list a directory, or fails to, does not let the
// update through once the base has moved.
func TestPRStageCargoNeedsTheListingWhenTheBaseMoved(t *testing.T) {
	fx := cargoGlobFixture()
	h := langHarness(t, fx)
	it := cargoGlobItem(h, fx, prTreeSource{h.gh})
	h.addFiles(map[string]string{"README.md": "hi\n"})
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(it))), PRStatusFailed, ReasonGitHubError)

	h = langHarness(t, fx)
	h.source = prTreeSource{h.gh}
	it = cargoGlobItem(h, fx, prTreeSource{h.gh})
	h.addFiles(map[string]string{"README.md": "hi\n"})
	h.gh.failNext("ListDirectory", failError)
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(it))), PRStatusFailed, ReasonGitHubError)

	// A root directory needs a source that gives the tree of the root.
	h = langHarness(t, fx)
	h.source = prTreeSource{h.gh}
	it = cargoGlobItem(h, fx, prTreeSource{h.gh})
	h.addFiles(map[string]string{"README.md": "hi\n"})
	it.Source.Trees = []SourceTree{{Path: ".", SHA: strings.Repeat("0", 40)}}
	h.source = listOnly{prTreeSource{h.gh}}
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(it))), PRStatusFailed, ReasonGitHubError)
}

// listOnly lists directories but cannot give the tree of the root.
type listOnly struct{ s prTreeSource }

func (l listOnly) ResolveBranch(ctx context.Context, repo, branch string) (string, error) {
	return l.s.ResolveBranch(ctx, repo, branch)
}
func (l listOnly) ReadFile(ctx context.Context, repo, sha, p string) (github.File, error) {
	return l.s.ReadFile(ctx, repo, sha, p)
}
func (l listOnly) ListDirectory(ctx context.Context, repo, sha, dir string) ([]github.Entry, error) {
	return l.s.ListDirectory(ctx, repo, sha, dir)
}

// An item whose files other than Cargo.lock changed is not written: a Cargo
// update changes Cargo.lock only.
func TestPRStageCargoRefusesOtherChangedFiles(t *testing.T) {
	fx := cargoGlobFixture()
	h := langHarness(t, fx)
	h.source = prTreeSource{h.gh}
	it := cargoGlobItem(h, fx, prTreeSource{h.gh})
	extra := []byte("[package]\nname = \"a\"\nversion = \"0.2.0\"\n")
	it.Artifacts = append(it.Artifacts, ArtifactFile{Path: "svc/Cargo.toml", SHA256: sha256Hex(extra), Size: int64(len(extra)), Mode: "100644", Content: extra})
	wantStatus(t, onlyUnit(t, h.run(prLangPlan(it))), PRStatusManual, ReasonArtifactsUnusable)
	if len(h.gh.pulls(testRepo)) != 0 {
		t.Error("a pull request was made")
	}
}

// A pull request is for the manager the marker names, and a manager the stage
// does not know is refused.
func TestCargoMarkerRecord(t *testing.T) {
	rec := LangRecord{Manager: "cargo", Packages: []LangKeyEntry{{Ecosystem: "cargo", Name: "tokio", Adopted: "1.18.4"}}}
	if err := rec.wellFormed(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"cargoo", "Cargo", "rust", ""} {
		rec.Manager = m
		if rec.wellFormed() == nil {
			t.Errorf("manager %q is well formed", m)
		}
	}
}

func TestLanguagePRBody_Cargo(t *testing.T) {
	base := func(lang BodyLanguage) languageBodyInput {
		in := languageBodyFixture(lang, "<!-- marker -->", true)
		in.Item.Manager = ManagerCargo
		in.LockPath = "svc/Cargo.lock"
		in.Files = []FileChange{{Path: "svc/Cargo.lock"}}
		in.Record.Manager = "cargo"
		in.Record.Chain, in.Record.ManifestEdits, in.Record.Tool = nil, nil, nil
		in.Record.Runtime = &RuntimeRecord{ID: "rust1.91", Version: "1.91.1", Image: "rust@sha256:" + strings.Repeat("c", 64)}
		in.Item.Update.Diff, in.Item.Update.Notes = nil, nil
		in.Record.DeprecatedNotes, in.Record.DeprecatedChanged, in.Record.Followed = nil, 0, nil
		in.Item.Update.Steps = []UpdateStep{{ID: "update", Op: "cargo.update"}}
		in.Item.Update.Cargo = &CargoLockChange{
			Targets:         []CargoCrateChange{{Name: "tokio", From: "1.18.0", To: "1.18.4"}},
			LockVersionFrom: 4, LockVersionTo: 4,
			Moved: []CargoCrateRef{{Name: "tokio", Version: "1.18.4"}}, MaxRustVersion: "1.63.0",
		}
		return in
	}
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		// Targets only: no other crate, no change of the format, every crate
		// declares a Rust version.
		in := base(lang)
		body, err := buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"`tokio`: `1.18.0`", "`1.18.4`", "`1.63.0`", "`cargo build --locked && cargo test --locked`", "crates.io", "cargo update", "--locked", "`rust1.91`"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the body lacks %q:\n%s", lang, want, body)
			}
		}
		for _, not := range []string{"installs from the lockfile", "Maven", "Gradle", "%!", "製品", "added at", "removed", "Cargo.lock の形式", "format goes"} {
			if strings.Contains(body, not) {
				t.Errorf("%s: the body says %q:\n%s", lang, not, body)
			}
		}
		if strings.Count(body, "tokio") != 1 {
			t.Errorf("%s: the target is not listed once:\n%s", lang, body)
		}

		// Other crates that moved, were added or were removed, one to a line.
		in = base(lang)
		in.Item.Update.Cargo.Others = []CargoCrateChange{{Name: "bytes", From: "1.5.0", To: "1.6.1"}, {Name: "mio", To: "0.8.11"}, {Name: "old", From: "0.3.2"}}
		body, err = buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"- `bytes`: `1.5.0`", "`1.6.1`", "- `mio`: ", "`0.8.11`", "- `old`: ", "`0.3.2`"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the body lacks %q:\n%s", lang, want, body)
			}
		}
		for _, l := range strings.Split(body, "\n") {
			if strings.Contains(l, "`bytes`") && (strings.Contains(l, "`mio`") || strings.Contains(l, "`old`")) {
				t.Errorf("%s: two crates on a line: %s", lang, l)
			}
		}

		// The format of Cargo.lock changed.
		in = base(lang)
		in.Item.Update.Cargo.LockVersionFrom, in.Item.Update.Cargo.LockVersionTo = 3, 4
		body, err = buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "`3`") || !strings.Contains(body, "`4`") {
			t.Errorf("%s: the body does not say the format went from 3 to 4:\n%s", lang, body)
		}

		// No crate declares a Rust version: the highest is not claimed.
		in = base(lang)
		in.Item.Update.Cargo.MaxRustVersion, in.Item.Update.Cargo.NoRustVersion = "", 1
		body, err = buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body, "1.63.0") || strings.Contains(body, "highest") || strings.Contains(body, "最も高い") {
			t.Errorf("%s: a highest Rust version is claimed:\n%s", lang, body)
		}
		if !strings.Contains(body, "Of the 1 crates at a version Cargo.lock did not have before, 1 have") && !strings.Contains(body, "crate 1 個のうち、crates.io の索引に読み取れる rust-version がないのは 1 個") {
			t.Errorf("%s: the crates without a declaration are not counted:\n%s", lang, body)
		}

		// Some declare one and some do not.
		in = base(lang)
		in.Item.Update.Cargo.Moved = append(in.Item.Update.Cargo.Moved, CargoCrateRef{Name: "bytes", Version: "1.6.1"}, CargoCrateRef{Name: "mio", Version: "0.8.11"})
		in.Item.Update.Cargo.NoRustVersion = 2
		body, err = buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "`1.63.0`") || (!strings.Contains(body, "Of the 3 crates at a version Cargo.lock did not have before, 2 have") && !strings.Contains(body, "crate 3 個のうち、crates.io の索引に読み取れる rust-version がないのは 2 個")) {
			t.Errorf("%s: the highest Rust version and the count are not both given:\n%s", lang, body)
		}

		// Every crate declares one: the count of 0 is given too.
		in = base(lang)
		in.Item.Update.Cargo.NoRustVersion = 0
		body, err = buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, ", 0 have no rust-version") && !strings.Contains(body, "rust-version がないのは 0 個") {
			t.Errorf("%s: the count of 0 is not given:\n%s", lang, body)
		}

		// Every crate the update moved does not fit in the list.
		in = base(lang)
		for i := 0; i < maxListedEntries+3; i++ {
			in.Item.Update.Cargo.Others = append(in.Item.Update.Cargo.Others, CargoCrateChange{Name: "crate" + string(rune('a'+i%26)) + string(rune('a'+i/26)), From: "1.0.0", To: "1.0.1"})
		}
		body, err = buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(body, "`1.0.1`"); n != maxListedEntries {
			t.Errorf("%s: %d crates listed, want %d:\n%s", lang, n, maxListedEntries, body)
		}

		// A manager the body has no wording for is an error, not another
		// manager's CI step.
		in = base(lang)
		in.Item.Manager = "nuget"
		if _, err := buildLanguagePRBody(in); err == nil {
			t.Errorf("%s: a manager without wording got a body", lang)
		}
	}
}
