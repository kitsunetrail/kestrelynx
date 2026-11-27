package remediation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// ReasonCargoRuntimeUnavailable: no Rust runtime of the runtime table has been
// run by an integration test on the platform the update jobs run on.
const ReasonCargoRuntimeUnavailable Reason = "cargo_runtime_unavailable"

// spendCargoLookup counts one request to the crates.io index against the
// registry lookups an update may make.
func (r *updateRun) spendCargoLookup() error {
	if r.lookups >= maxRegistryChecks {
		return errRegistryBudget
	}
	r.lookups++
	return nil
}

// cargoReplay serves the files of a unit that were read again and checked
// against the blobs the plan recorded, so that the workspace is read from
// exactly those bytes; a directory is listed on GitHub.
type cargoReplay struct {
	gh    GitHubReader
	files map[string][]byte
	blobs map[string]string
	modes map[string]string
}

func (c cargoReplay) ResolveBranch(ctx context.Context, repo, branch string) (string, error) {
	return c.gh.ResolveBranch(ctx, repo, branch)
}

func (c cargoReplay) ListDirectory(ctx context.Context, repo, sha, dir string) ([]github.Entry, error) {
	return c.gh.ListDirectory(ctx, repo, sha, dir)
}

// RootTree gives the tree of a commit's root when the reader under it can.
func (c cargoReplay) RootTree(ctx context.Context, repo, sha string) (string, error) {
	if rt, ok := c.gh.(rootTreeReader); ok {
		return rt.RootTree(ctx, repo, sha)
	}
	return "", errNoRootTree
}

func (c cargoReplay) ReadFile(_ context.Context, _, _, p string) (github.File, error) {
	content, ok := c.files[p]
	if !ok {
		return github.File{}, github.ErrNotFound
	}
	return github.File{Path: p, SHA: c.blobs[p], Content: content, Mode: c.modes[p]}, nil
}

// cargoWorkspace reads the workspace of the unit again, with the same code the
// plan used, from the files that were read again, and requires its packages to
// be the ones the plan recorded.
func (r *updateRun) cargoWorkspace(ctx context.Context, content map[string][]byte, mode map[string]string) (*cargoWorkspaceInfo, *updateFailure) {
	src := r.it.Source
	root := pathIn(src.Directory, "Cargo.toml")
	data, ok := content[root]
	if !ok {
		return nil, failedFailure(ReasonUpdateInputInvalid, "the plan does not record %s", root)
	}
	blobs := map[string]string{}
	for _, f := range src.Files {
		blobs[f.Path] = f.BlobSHA
	}
	replay := cargoReplay{gh: r.u.cfg.GitHub, files: content, blobs: blobs, modes: mode}
	// The unit reads into an item of its own, whose outcome, when it stops, is
	// the failure of this update.
	scratch := &LanguageItem{Source: SourceRecord{Repository: src.Repository, CommitSHA: src.CommitSHA, Directory: src.Directory}}
	rr := &run{p: &Planner{cfg: Config{GitHub: replay}}, ctx: ctx}
	cu := &cargoUnit{r: rr, it: scratch, u: &depUnit{repo: src.Repository, dir: src.Directory}, sha: src.CommitSHA}
	ws, ok := cu.loadWorkspace(data)
	if !ok {
		if scratch.Category == "" {
			return nil, failedFailure(ReasonUpdateInputInvalid, "the workspace of %s cannot be read", root)
		}
		return nil, &updateFailure{category: scratch.Category, reason: scratch.Reason, detail: scratch.Detail}
	}
	// The directories the members were found in are the ones the plan listed,
	// with the trees it saw.
	if !sameTrees(scratch.Source.Trees, src.Trees) {
		return nil, manualFailure(ReasonSourceChanged, "the directories the workspace members were found in are not the ones the plan was made from (%s, now %s)", cargoTreeList(src.Trees), cargoTreeList(scratch.Source.Trees))
	}
	rec := r.it.Cargo
	var now []CargoMember
	for _, m := range ws.members {
		now = append(now, CargoMember{Path: m.dir, Name: m.name, Version: m.version})
	}
	sort.Slice(now, func(i, j int) bool { return now[i].Path < now[j].Path })
	if !sameCargoMembers(now, rec.Members) {
		return nil, manualFailure(ReasonSourceChanged, "the packages of the workspace are not the ones the plan was made from (%s, now %s)", cargoMemberList(rec.Members), cargoMemberList(now))
	}
	return ws, nil
}

func cargoTreeList(ts []SourceTree) string {
	var s []string
	for _, t := range ts {
		s = append(s, t.Path+" "+t.SHA)
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}

func sameCargoMembers(a, b []CargoMember) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cargoMemberList(ms []CargoMember) string {
	var s []string
	for _, m := range ms {
		s = append(s, m.Name+" "+m.Version+" in "+m.Path)
	}
	return strings.Join(s, ", ")
}

// cargoTree lists the directories of the commit the build targets are found
// in, each once.
type cargoTree struct {
	r       *updateRun
	ctx     context.Context
	listed  map[string][]github.Entry
	listing int
}

// ls lists a directory of the commit; one that is not there is empty.
func (t *cargoTree) ls(dir string) ([]github.Entry, *updateFailure) {
	if es, ok := t.listed[dir]; ok {
		return es, nil
	}
	if t.listing >= maxCargoFiles {
		return nil, manualFailure(ReasonWorkspaceUnsupported, "finding the build targets of the workspace needs more than %d directories to be listed", maxCargoFiles)
	}
	t.listing++
	src := t.r.it.Source
	es, err := t.r.u.cfg.GitHub.ListDirectory(t.ctx, src.Repository, src.CommitSHA, dir)
	switch {
	case errors.Is(err, github.ErrNotFound):
		es = nil
	case err != nil:
		return nil, readFailure(err, dir)
	}
	t.listed[dir] = es
	return es, nil
}

// cargoRegular reports whether the directory has a plain file of the name. An
// entry of that name that is not a plain file fails the update; one that is not
// there is not a failure.
func cargoRegular(dir string, es []github.Entry, name string) (bool, *updateFailure) {
	e, ok := byName(es, name)
	switch {
	case !ok:
		return false, nil
	case e.Type != github.EntryFile:
		return false, manualFailure(ReasonDependencyFileUnusable, "%s is a %s, and a file of the build is expected there", pathIn(dir, name), e.Type)
	}
	return true, nil
}

// discover adds the files of dir that Cargo takes for build targets: a *.rs
// file and the main.rs of a directory.
func (t *cargoTree) discover(dir string, into map[string]bool) *updateFailure {
	es, fail := t.ls(dir)
	if fail != nil {
		return fail
	}
	for _, e := range es {
		switch {
		case strings.HasSuffix(e.Name, ".rs"):
			if e.Type != github.EntryFile {
				return manualFailure(ReasonDependencyFileUnusable, "%s is a %s, and a file of the build is expected there", pathIn(dir, e.Name), e.Type)
			}
			into[pathIn(dir, e.Name)] = true
		case e.Type == github.EntryDir:
			sub := pathIn(dir, e.Name)
			ses, fail := t.ls(sub)
			if fail != nil {
				return fail
			}
			ok, fail := cargoRegular(sub, ses, "main.rs")
			if fail != nil {
				return fail
			}
			if ok {
				into[pathIn(sub, "main.rs")] = true
			}
		case e.Type == github.EntrySymlink || e.Type == github.EntrySubmodule:
			// What a link or a submodule holds is not known, so whether it is a
			// target is not either.
			return manualFailure(ReasonDependencyFileUnusable, "%s is a %s, and what is in it is not read", pathIn(dir, e.Name), e.Type)
		}
	}
	return nil
}

// packageTargets collects the paths in the tree of one package of the workspace
// that Cargo may build: the ones it finds by their place, and the ones the
// Cargo.toml names.
func (t *cargoTree) packageTargets(m *cargoManifest, data []byte, rootDir string, into map[string]bool) *updateFailure {
	es, fail := t.ls(m.dir)
	if fail != nil {
		return fail
	}
	if ok, fail := cargoRegular(m.dir, es, "build.rs"); fail != nil {
		return fail
	} else if ok {
		into[pathIn(m.dir, "build.rs")] = true
	}
	for _, sub := range []string{"src", "examples", "tests", "benches"} {
		e, present := byName(es, sub)
		if !present {
			continue
		}
		if e.Type != github.EntryDir {
			return manualFailure(ReasonDependencyFileUnusable, "%s is a %s, and a directory of the build is expected there", pathIn(m.dir, sub), e.Type)
		}
		dir := pathIn(m.dir, sub)
		if sub != "src" {
			if fail := t.discover(dir, into); fail != nil {
				return fail
			}
			continue
		}
		ses, fail := t.ls(dir)
		if fail != nil {
			return fail
		}
		for _, name := range []string{"lib.rs", "main.rs"} {
			if ok, fail := cargoRegular(dir, ses, name); fail != nil {
				return fail
			} else if ok {
				into[pathIn(dir, name)] = true
			}
		}
		be, present := byName(ses, "bin")
		if !present {
			continue
		}
		if be.Type != github.EntryDir {
			return manualFailure(ReasonDependencyFileUnusable, "%s is a %s, and a directory of the build is expected there", pathIn(dir, "bin"), be.Type)
		}
		if fail := t.discover(pathIn(dir, "bin"), into); fail != nil {
			return fail
		}
	}

	paths, err := cargoNamedPaths(m.file, data)
	if err != nil {
		var ue *UnsupportedError
		if errors.As(err, &ue) {
			return manualFailure(ue.Reason, "%s", ue.Detail)
		}
		return manualFailure(ReasonCargoManifestUnsupported, "%v", err)
	}
	for _, p := range paths {
		base, rest, ok := cargoTargetPath(m.dir, p)
		full := path.Join(base, rest)
		if !ok || !cargoPathInside(rootDir, base) || !cargoPathInside(rootDir, full) {
			return manualFailure(ReasonWorkspaceUnsupported, "%s names the build target %q, which is not a path inside the workspace in a form this version reads", m.file, p)
		}
		// Each directory on the way is listed and must be a directory, so
		// that no link or submodule stands between the package and the file.
		dir := base
		elems := strings.Split(rest, "/")
		for _, e := range elems[:len(elems)-1] {
			des, fail := t.ls(dir)
			if fail != nil {
				return fail
			}
			de, present := byName(des, e)
			switch {
			case !present:
				return manualFailure(ReasonDependencyFilesNotFound, "%s names the build target %s, and the commit has no such file", m.file, full)
			case de.Type != github.EntryDir:
				return manualFailure(ReasonDependencyFileUnusable, "%s is a %s, and a directory of the build is expected there", pathIn(dir, e), de.Type)
			}
			dir = pathIn(dir, e)
		}
		pes, fail := t.ls(path.Dir(full))
		if fail != nil {
			return fail
		}
		if _, present := byName(pes, path.Base(full)); !present {
			return manualFailure(ReasonDependencyFilesNotFound, "%s names the build target %s, and the commit has no such file", m.file, full)
		}
		if _, fail := cargoRegular(path.Dir(full), pes, path.Base(full)); fail != nil {
			return fail
		}
		into[full] = true
	}
	return nil
}

// cargoTargetPath splits the path a Cargo.toml in the directory dir gives a
// build target into the directory it starts from and the rest: a leading
// "./" is dropped and leading ".." elements climb from dir, and the rest must
// be plain names (no "", "." or ".."). ok is false for an absolute path, one
// with a backslash, one that climbs above the repository, or one of another
// form.
func cargoTargetPath(dir, p string) (base, rest string, ok bool) {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return "", "", false
	}
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	base = dir
	elems := strings.Split(p, "/")
	for len(elems) > 0 && elems[0] == ".." {
		if base == "." || base == "" {
			return "", "", false
		}
		base = path.Dir(base)
		elems = elems[1:]
	}
	if len(elems) == 0 {
		return "", "", false
	}
	for _, e := range elems {
		if e == "" || e == "." || e == ".." {
			return "", "", false
		}
	}
	return base, strings.Join(elems, "/"), true
}

// cargoAutoKeys are the keys of [package] that turn Cargo's finding of build
// targets by their place off.
var cargoAutoKeys = []string{"autolib", "autobins", "autoexamples", "autotests", "autobenches"}

// cargoNamedPaths reads the paths a Cargo.toml gives its build targets: the
// path of [lib] and of each [[bin]], [[example]], [[test]] and [[bench]], and
// package.build when it is a path. A table that is not in a form Cargo reads
// is an error, and so is a package that turns finding targets by their place
// off (see cargoAutoKeys).
func cargoNamedPaths(file string, data []byte) ([]string, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	bad := func(what string) error {
		return unsupported(ReasonCargoManifestUnsupported, "%s has %s in a form that is not read by this version", file, what)
	}
	var out []string
	one := func(v any, what string) error {
		t, ok := v.(map[string]any)
		if !ok {
			return bad(what)
		}
		p, has := t["path"]
		if !has {
			return nil
		}
		s, ok := p.(string)
		if !ok || s == "" {
			return bad(what + " with a path")
		}
		out = append(out, s)
		return nil
	}
	if v, ok := doc["lib"]; ok {
		if err := one(v, "[lib]"); err != nil {
			return nil, err
		}
	}
	for _, k := range []string{"bin", "example", "test", "bench"} {
		v, ok := doc[k]
		if !ok {
			continue
		}
		list, ok := v.([]any)
		if !ok {
			return nil, bad("[[" + k + "]]")
		}
		for _, e := range list {
			if err := one(e, "[["+k+"]]"); err != nil {
				return nil, err
			}
		}
	}
	if v, ok := doc["package"].(map[string]any); ok {
		// With finding by place turned off, the files Cargo builds are not
		// the ones collected by their place here; such a package is not
		// handled.
		for _, k := range cargoAutoKeys {
			switch a := v[k].(type) {
			case nil:
			case bool:
				if !a {
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s sets package.%s = false, and this version does not handle a package whose build targets Cargo does not find by their place", file, k)
				}
			default:
				return nil, bad("package." + k)
			}
		}
		switch b := v["build"].(type) {
		case nil, bool:
			// No build script, or the one build.rs names.
		case string:
			if b == "" {
				return nil, bad("package.build")
			}
			out = append(out, b)
		default:
			return nil, bad("package.build")
		}
	}
	return out, nil
}

// cargoBuildFiles collects the repository paths of the build targets of every
// package of the workspace, which the job is given as empty files.
func (r *updateRun) cargoBuildFiles(ctx context.Context, ws *cargoWorkspaceInfo, content map[string][]byte) (map[string]bool, *updateFailure) {
	t := &cargoTree{r: r, ctx: ctx, listed: map[string][]github.Entry{}}
	into := map[string]bool{}
	for _, m := range ws.members {
		data, ok := content[m.file]
		if !ok {
			return nil, failedFailure(ReasonUpdateInputInvalid, "the plan does not record %s", m.file)
		}
		if fail := t.packageTargets(m, data, r.it.Source.Directory, into); fail != nil {
			return nil, fail
		}
	}
	return into, nil
}

// cargoRel is a repository path relative to the directory of the unit.
func cargoRel(dir, p string) string {
	if dir == "." || dir == "" {
		return p
	}
	return strings.TrimPrefix(p, dir+"/")
}

// cargoTargets settles what each target is updated from and to: the one
// version Cargo.lock holds of it, and the release the crates.io index lists
// for it (see selectCargoRelease).
func (r *updateRun) cargoTargets(ctx context.Context, lock *cargoLock) ([]worker.Package, []cargoCheckTarget, *updateFailure) {
	var pkgs []worker.Package
	var targets []cargoCheckTarget
	for _, n := range r.set.names {
		installed := r.it.Packages[r.set.byName[n][0]].Installed
		idx := lock.byName[n]
		switch {
		case len(idx) > 1:
			return nil, nil, pkgFailure(n, ReasonMultipleVersions, "Cargo.lock locks %s at %s", n, strings.Join(lock.versionsOf(n), ", "))
		case len(idx) == 0 || !lock.crates[idx[0]].registry() || lock.crates[idx[0]].version != installed:
			return nil, nil, failedFailure(ReasonUpdateInputInvalid, "Cargo.lock does not hold %s %s from crates.io, which the plan updates", n, installed)
		}
		if err := r.spendCargoLookup(); err != nil {
			return nil, nil, lookupFailure(ctx, err, "the crates.io index entry of "+n)
		}
		rels, err := r.cargoIndex.versions(ctx, r.u.cfg.Cargo, n)
		if err != nil {
			return nil, nil, lookupFailure(ctx, err, "the crates.io index entry of "+n)
		}
		rel, reason, detail := selectCargoRelease(rels, installed, r.set.target[n])
		if reason != "" {
			return nil, nil, pkgFailure(n, reason, "%s", detail)
		}
		if strings.Contains(rel.Version, "+") {
			return nil, nil, pkgFailure(n, ReasonCargoReleaseNotFound, "the release %s of %s has build metadata, which an update to an exact version does not name", rel.Version, n)
		}
		if rel.Version == installed {
			return nil, nil, pkgFailure(n, ReasonCargoReleaseNotFound, "the release chosen for %s is the version it is at", n)
		}
		pkgs = append(pkgs, worker.Package{Name: n, From: installed, Version: rel.Version})
		targets = append(targets, cargoCheckTarget{name: n, from: installed, to: rel.Version})
	}
	return pkgs, targets, nil
}

// cargoKeptInputs requires a tree the job returned to hold every file it was
// given, with each Cargo.toml as it was sent and each empty file still empty.
func cargoKeptInputs(files []cargoFile, where string, get func(string) ([]byte, bool)) *updateFailure {
	for _, f := range files {
		got, ok := get(f.path)
		switch {
		case !ok:
			return manualFailure(ReasonOutputFilesInvalid, "%s lacks %s", where, f.path)
		case f.role == worker.RoleManifest && !bytes.Equal(got, f.content):
			return manualFailure(ReasonManifestChanged, "the update changed %s (in %s)", f.path, where)
		case f.role == worker.RoleEmpty && len(got) != 0:
			return manualFailure(ReasonOutputFilesInvalid, "the update wrote to %s, a file it was given with no content (in %s)", f.path, where)
		}
	}
	return nil
}

// runCargo is the update of a Cargo workspace: the files the plan read are read
// again, a work container runs one cargo update of each target to an exact
// release the crates.io index lists, and the Cargo.lock it returns is checked
// here and scanned before and after. Only Cargo.lock may change.
func (r *updateRun) runCargo(ctx context.Context) *updateFailure {
	if r.u.cfg.Cargo == nil {
		return failedFailure(ReasonUpdateInputInvalid, "no crates.io index client is configured")
	}
	if r.it.Cargo == nil {
		return failedFailure(ReasonUpdateInputInvalid, "the plan has no record of the Cargo workspace")
	}
	r.noPartial = true
	if len(r.set.names) > worker.MaxPackages {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdatePackageLimit,
			detail: fmt.Sprintf("the update names %d packages, more than the %d one job takes", len(r.set.names), worker.MaxPackages)}
	}
	content, mode, fail := r.readRecordedSources(ctx)
	if fail != nil {
		return fail
	}
	dir := r.it.Source.Directory
	lockPath := pathIn(dir, "Cargo.lock")
	origLock, ok := content[lockPath]
	if !ok {
		return failedFailure(ReasonUpdateInputInvalid, "the plan does not record %s", lockPath)
	}
	ws, fail := r.cargoWorkspace(ctx, content, mode)
	if fail != nil {
		return fail
	}
	lock, err := parseCargoLock(origLock)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "%v", err)
	}
	if why := cargoLockMismatch(lock, ws); why != "" {
		return manualFailure(ReasonDependencyFileUnusable, "%s", why)
	}
	pkgs, targets, fail := r.cargoTargets(ctx, lock)
	if fail != nil {
		return fail
	}

	spec, ok := r.u.cargoRuntime()
	if !ok {
		return manualFailure(ReasonCargoRuntimeUnavailable, "no Rust runtime of the runtime table has been run on %s", r.u.cfg.Platform)
	}
	r.toolSpec = ToolSpec{Manager: ManagerCargo, Runtime: spec.ID}

	empties, fail := r.cargoBuildFiles(ctx, ws, content)
	if fail != nil {
		return fail
	}
	files := []cargoFile{{path: "Cargo.lock", role: worker.RoleLockfile, content: origLock}}
	seen := map[string]bool{}
	for _, m := range ws.members {
		rel := cargoRel(dir, m.file)
		seen[rel] = true
		files = append(files, cargoFile{path: rel, role: worker.RoleManifest, content: content[m.file]})
	}
	if rootRel := "Cargo.toml"; !seen[rootRel] {
		files = append(files, cargoFile{path: rootRel, role: worker.RoleManifest, content: content[pathIn(dir, "Cargo.toml")]})
	}
	for p := range empties {
		files = append(files, cargoFile{path: cargoRel(dir, p), role: worker.RoleEmpty})
	}
	inputs, fail := cargoInputs(files)
	if fail != nil {
		return fail
	}
	r.cargoRoles = map[string]string{}
	for _, f := range files {
		r.cargoRoles[f.path] = f.role
	}

	steps := make([]worker.Step, len(pkgs))
	for i, p := range pkgs {
		id := stepUpdate
		if i > 0 {
			id = fmt.Sprintf("%s-%d", stepUpdate, i+1)
		}
		steps[i] = worker.Step{ID: id, Op: worker.OpCargoUpdate, Packages: []worker.Package{p}}
	}
	out, fail := r.exec(ctx, worker.ManagerCargo, inputs, steps, "update")
	if fail != nil {
		return fail
	}
	r.it.PostUpdateCheckExecuted = true

	// The copies each step collected are checked as well as the final tree:
	// what the container says of a step is not trusted, and a Cargo.toml it
	// changed and then put back is still a change the update made.
	for _, st := range steps {
		if fail := cargoKeptInputs(files, "step "+st.ID, func(p string) ([]byte, bool) { return out.stepFile(st.ID, p) }); fail != nil {
			return fail
		}
	}
	if fail := cargoKeptInputs(files, "the final tree", out.finalFile); fail != nil {
		return fail
	}
	newLock, _ := out.finalFile("Cargo.lock")
	if bytes.Equal(newLock, origLock) {
		f := manualFailure(ReasonTargetNotUpdated, "the update left Cargo.lock unchanged")
		f.lockUnchanged = true
		return f
	}
	chk := &cargoChecker{index: r.u.cfg.Cargo, bytes: &r.cargoIndex, spend: func() *updateFailure {
		if err := r.spendCargoLookup(); err != nil {
			return lookupFailure(ctx, err, "the crates.io index")
		}
		return nil
	}}
	ch, fail := chk.check(ctx, cargoCheckInput{before: origLock, after: newLock, members: ws.members, targets: targets, record: *r.it.Cargo})
	if fail != nil {
		return fail
	}
	after, err := parseCargoLock(newLock)
	if err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "the updated Cargo.lock cannot be read: %v", err)
	}
	r.upd.Cargo = ch
	r.cargoLocks = [2]*cargoLock{lock, after}
	r.adopted, r.afterVersions = map[string]string{}, map[string][]string{}
	for _, n := range r.set.names {
		var vs []string
		for _, i := range after.byName[n] {
			if c := after.crates[i]; c.registry() {
				vs = append(vs, c.version)
			}
		}
		sort.Slice(vs, func(i, j int) bool {
			c, _ := compareVersions(schemeSemver, vs[i], vs[j])
			return c < 0
		})
		if len(vs) == 0 {
			return manualFailure(ReasonTargetRemoved, "the updated Cargo.lock does not hold %s", n)
		}
		r.adopted[n], r.afterVersions[n] = vs[0], vs
	}
	if fail := r.sourceCheck(ctx, map[string][]byte{"Cargo.lock": origLock}, map[string][]byte{"Cargo.lock": newLock}); fail != nil {
		return fail
	}
	m := mode[lockPath]
	if m == "" {
		m = "100644"
	}
	r.cargoArtifacts = []ArtifactFile{{Path: lockPath, SHA256: sha256Hex(newLock), Size: int64(len(newLock)), Mode: m, Content: newLock}}
	return nil
}
