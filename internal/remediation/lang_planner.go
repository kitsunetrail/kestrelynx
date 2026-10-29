package remediation

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// depUnit is one shared dependency root: the same repository, base branch and
// directory, however many workloads are mapped to it.
type depUnit struct {
	key       string
	repo      string
	branch    string
	dir       string
	workloads map[string]bool
	order     []string        // workload keys in mapping order
	groups    []*findingGroup // findings of verified scans
	unpinned  []*findingGroup // findings of scans that did not confirm the running image
	priority  Priority
	rank      int // the best position among the planner's inputs of an image that maps to the unit
	// The Go findings are kept per running image and binary until go.mod
	// names the module they must come from (see goSelect): goPinned and
	// goUnpinned are those of verified and other scans, goBins and
	// goBinsUnpinned the binaries of those scans by entity and target.
	goPinned, goUnpinned   []srcFinding
	goBins, goBinsUnpinned map[string]*goBinary
}

// dependencyPair is a manager's manifest and lockfile; lock is the file the
// packages are matched against.
type dependencyPair struct {
	manager  DependencyManager
	manifest string // package.json or pyproject.toml; empty for pip
	lock     string
	pkgType  string // the scanner result type the pair's packages are reported as
}

var dependencyPairs = []dependencyPair{
	{ManagerNpm, "package.json", "package-lock.json", typeNodePkg},
	{ManagerPnpm, "package.json", "pnpm-lock.yaml", typeNodePkg},
	{ManagerUv, "pyproject.toml", "uv.lock", typePythonPkg},
	{ManagerPip, "", "requirements.txt", typePythonPkg},
	// go.mod is what the packages are matched against; go.sum is read with
	// it as the second file, since an update changes both.
	{ManagerGo, "go.sum", "go.mod", typeGoBinary},
}

// unitsOf groups the mappings into units, in the order they first appear.
func unitsOf(ms []DependencyMapping) []*depUnit {
	var out []*depUnit
	idx := map[string]*depUnit{}
	for _, m := range ms {
		k := strings.ToLower(m.Repository) + "\x00" + m.BaseBranch + "\x00" + m.Directory
		u := idx[k]
		if u == nil {
			u = &depUnit{
				key:       "deps:" + strings.ToLower(m.Repository) + "@" + m.BaseBranch + ":" + m.Directory,
				repo:      m.Repository,
				branch:    m.BaseBranch,
				dir:       m.Directory,
				workloads: map[string]bool{},
				goBins:    map[string]*goBinary{},

				goBinsUnpinned: map[string]*goBinary{},
			}
			idx[k] = u
			out = append(out, u)
		}
		if !u.workloads[m.Workload] {
			u.workloads[m.Workload] = true
			u.order = append(u.order, m.Workload)
		}
	}
	return out
}

// workloadKey is the workload key of a service reference.
func workloadKey(s ServiceRef) string { return s.WorkloadKey() }

// languagePart builds the plan items of the dependency units: it reads each
// unit's dependency files at one commit and matches the findings of the
// workloads mapped to it. It runs after the distributed-image part and
// shares its deadline; nothing is executed and nothing is written.
func (r *run) languagePart(inputs []ImageInput) {
	cfg := r.p.cfg
	if cfg.GitHub == nil || len(cfg.Dependencies) == 0 {
		return
	}
	units := unitsOf(cfg.Dependencies)
	var active []*depUnit
	for _, u := range units {
		var pinned, unpinned []srcFinding
		for rank, in := range inputs {
			if in.Scan.Err != nil {
				continue
			}
			var ws []string
			for _, s := range in.Services {
				if k := workloadKey(s); u.workloads[k] && !containsString(ws, k) {
					ws = append(ws, k)
				}
			}
			if len(ws) == 0 {
				continue
			}
			entity := entityString(in.Scan.Subject.Key)
			// Only a scan that confirmed which image content it saw says
			// anything about the running image.
			verified := in.Scan.Pinned && in.Scan.Subject.Resolved
			if verified {
				goBinariesOf(rank, in.Scan, u.goBins)
			} else {
				goBinariesOf(rank, in.Scan, u.goBinsUnpinned)
			}
			for _, f := range in.Scan.Findings {
				lf := srcFinding{f: f, entity: entity, workloads: ws, rank: rank}
				switch {
				case f.Type == typeGoBinary && verified:
					u.goPinned = append(u.goPinned, lf)
				case f.Type == typeGoBinary:
					u.goUnpinned = append(u.goUnpinned, lf)
				case verified:
					pinned = append(pinned, lf)
				default:
					unpinned = append(unpinned, lf)
				}
			}
		}
		u.groups = groupLanguageFindings(pinned, cfg.Intel)
		u.unpinned = groupLanguageFindings(unpinned, cfg.Intel)
		// The Go findings are grouped as they are only to place the unit
		// among the others.
		goAll := groupLanguageFindings(append(append([]srcFinding(nil), u.goPinned...), u.goUnpinned...), cfg.Intel)
		if len(u.groups) == 0 && len(u.unpinned) == 0 && len(goAll) == 0 {
			continue
		}
		u.rank = int(^uint(0) >> 1)
		for _, g := range append(append(append([]*findingGroup(nil), u.groups...), u.unpinned...), goAll...) {
			if g.priority.Rank() > u.priority.Rank() {
				u.priority = g.priority
			}
			if g.rank < u.rank {
				u.rank = g.rank
			}
		}
		active = append(active, u)
	}
	// Strongest priority first; within one priority the planner's input order
	// (which callers set by their own preference) is kept.
	sort.SliceStable(active, func(i, j int) bool {
		a, b := active[i], active[j]
		if a.priority.Rank() != b.priority.Rank() {
			return a.priority.Rank() > b.priority.Rank()
		}
		return a.rank < b.rank
	})

	for _, u := range active {
		r.plan.LanguageItems = append(r.plan.LanguageItems, r.languageUnits(u)...)
	}
}

// stopReason says why no further GitHub work may start: the cycle's deadline
// has passed, or an earlier read ended the pass (rate limit, exhausted
// budgets). It is checked before each ecosystem's work and each file read.
func (r *run) stopReason() *halt {
	if err := r.ctx.Err(); err != nil {
		return &halt{ReasonCycleDeadline, err.Error()}
	}
	return r.srcHalt
}

// languageUnits plans one unit. The unit's findings are split by ecosystem
// and each part gets its own item, keyed by the manager once the files tell
// it (by the ecosystem before that): node packages are matched against an npm
// or pnpm pair, Python packages against a uv or pip pair, Go binaries against
// a go.mod, so a directory holding files of several ecosystems is several
// items, not an ambiguity. The branch is resolved and the directory listed
// once for all of them.
func (r *run) languageUnits(u *depUnit) []LanguageItem {
	var node, python []*findingGroup
	for _, g := range u.groups {
		switch g.Type {
		case typeNodePkg:
			node = append(node, g)
		case typePythonPkg:
			python = append(python, g)
		}
	}
	var subs [][]*findingGroup
	for _, gs := range [][]*findingGroup{node, python} {
		if len(gs) > 0 {
			subs = append(subs, gs)
		}
	}
	hasGo := len(u.goPinned) > 0 || len(u.goUnpinned) > 0

	var sha string
	var entries []github.Entry
	var srcErr error
	if (len(subs) > 0 || hasGo) && r.stopReason() == nil {
		gh := r.p.cfg.GitHub
		if sha, srcErr = gh.ResolveBranch(r.ctx, u.repo, u.branch); srcErr == nil {
			entries, srcErr = gh.ListDirectory(r.ctx, u.repo, sha, u.dir)
		}
	}

	newItem := func(kind string) LanguageItem {
		it := LanguageItem{
			Key:       u.key + "#" + kind,
			Workloads: append([]string(nil), u.order...),
			Source: SourceRecord{
				Repository: u.repo, BaseBranch: u.branch, Directory: u.dir, CommitSHA: sha,
				Origin: OriginConfig, Confidence: ConfidenceAsserted,
			},
		}
		sort.Strings(it.Workloads)
		return it
	}

	var out []LanguageItem
	// A Go binary's findings belong to this source only if the directory is a
	// Go module, and then only those of the binaries built from that module:
	// an image may carry Go programs of its base image, and a directory of
	// another ecosystem says nothing about them. Go comes first, so that the
	// reads of the other ecosystems do not use up what it needs to learn the
	// module.
	var goModule string
	if _, isGo := byName(entries, "go.mod"); hasGo && srcErr == nil && isGo && r.stopReason() == nil {
		it := newItem(typeGoBinary)
		var keep bool
		var std *LanguageItem
		if goModule, keep, std = r.analyseGoUnit(&it, u, entries); keep {
			out = append(out, it)
		}
		if std != nil {
			out = append(out, *std)
		}
	}

	for _, gs := range subs {
		it := newItem(gs[0].Type)
		for _, g := range gs {
			if g.priority.Rank() > it.Priority.Rank() {
				it.Priority = g.priority
			}
		}
		switch h := r.stopReason(); {
		case h != nil:
			r.deferUnit(&it, gs, h.reason, h.detail)
		case srcErr != nil:
			r.sourceFailure(&it, gs, srcErr, false)
		default:
			r.analyseUnit(&it, u, gs, entries)
		}
		out = append(out, it)
	}

	unpinned := u.unpinned
	if goModule != "" && len(u.goUnpinned) > 0 {
		// The unverified scans' Go findings are those of binaries built from
		// the module; they are listed, not matched against go.mod.
		kept, _ := goSelect(u.goUnpinned, u.goBinsUnpinned, &goMod{module: goModule}, false)
		unpinned = append(append([]*findingGroup(nil), unpinned...), groupLanguageFindings(kept, r.p.cfg.Intel)...)
	}
	if len(unpinned) > 0 {
		it := newItem("unverified")
		it.Source.CommitSHA = ""
		for _, g := range unpinned {
			if g.priority.Rank() > it.Priority.Rank() {
				it.Priority = g.priority
			}
		}
		it.Category, it.Reason = CategoryNotComparable, ReasonScanNotPinned
		it.Detail = "the scan did not confirm which image content it saw, so its findings are not matched against the source"
		it.Packages = unitPackages(unpinned, "", "", "")
		out = append(out, it)
	}
	return out
}

// analyseUnit reads and matches the dependency files for one ecosystem's
// findings of a unit (Go has its own, analyseGoUnit).
func (r *run) analyseUnit(it *LanguageItem, u *depUnit, groups []*findingGroup, entries []github.Entry) {
	gh := r.p.cfg.GitHub
	sha := it.Source.CommitSHA
	pair, reason, detail := detectPair(entries, groups[0].Type)
	if reason != "" {
		unitManual(it, groups, reason, detail)
		return
	}
	it.Manager = pair.manager
	it.Key = u.key + "#" + string(pair.manager)

	read := func(name string) ([]byte, bool) {
		if h := r.stopReason(); h != nil {
			r.deferUnit(it, groups, h.reason, h.detail)
			return nil, false
		}
		f, err := gh.ReadFile(r.ctx, u.repo, sha, pathIn(u.dir, name))
		if err != nil {
			r.sourceFailure(it, groups, err, true)
			return nil, false
		}
		it.Source.Files = append(it.Source.Files, SourceFile{Path: f.Path, BlobSHA: f.SHA})
		return f.Content, true
	}
	var manifest []byte
	if pair.manifest != "" {
		var ok bool
		if manifest, ok = read(pair.manifest); !ok {
			return
		}
	}
	lockData, ok := read(pair.lock)
	if !ok {
		return
	}
	if pair.pkgType == typeNodePkg {
		// Where packages come from is also set outside the lockfile.
		if pair.manager == ManagerPnpm {
			// pnpm looks for pnpm-workspace.yaml in the directory and in each one
			// above it, up to the root of the repository: a file there may make
			// the directory a member of a workspace, or apply its settings. One
			// in a directory above is left to a person.
			if why, ok := r.ancestorWorkspace(it, groups, u, sha); !ok {
				return
			} else if why != "" {
				unitManual(it, groups, ReasonWorkspaceUnsupported, why)
				return
			}
			e, present := byName(entries, "pnpm-workspace.yaml")
			if !present {
				// That there is no settings file is part of what the update
				// is made from: one added later must be seen.
				it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, pnpmWorkspaceName))
			}
			if present {
				if e.Type != github.EntryFile {
					unitManual(it, groups, ReasonDependencyFileUnusable, "pnpm-workspace.yaml is a "+string(e.Type))
					return
				}
				ws, ok := read("pnpm-workspace.yaml")
				if !ok {
					return
				}
				// A file of settings only makes the directory one project; a
				// workspace, or a setting that changes what is resolved, does not.
				if reason, why := pnpmWorkspaceProblem(ws); reason != "" {
					unitManual(it, groups, reason, why)
					return
				}
			}
		}
		if e, ok := byName(entries, ".npmrc"); ok {
			if e.Type != github.EntryFile {
				unitManual(it, groups, ReasonDependencyFileUnusable, ".npmrc is a "+string(e.Type))
				return
			}
			rc, ok := read(".npmrc")
			if !ok {
				return
			}
			if why := npmrcProblem(rc); why != "" {
				unitManual(it, groups, ReasonUnsupportedSource, why)
				return
			}
		}
	}

	var lock *lockfile
	var err error
	switch pair.manager {
	case ManagerNpm:
		lock, err = parseNpm(manifest, lockData)
	case ManagerPnpm:
		lock, err = parsePnpm(manifest, lockData)
	case ManagerUv:
		lock, err = parseUv(manifest, lockData)
	case ManagerPip:
		lock, err = parseRequirements(lockData)
	default:
		err = fmt.Errorf("no parser for %s", pair.manager)
	}
	if err != nil {
		var ue *UnsupportedError
		if errors.As(err, &ue) {
			unitManual(it, groups, ue.Reason, ue.Detail)
			return
		}
		unitManual(it, groups, ReasonUnparsableSource, err.Error())
		return
	}

	// The runtime and tool versions the project declares, and the settings
	// that fetch tools, are settled before anything is matched or run.
	if !r.planToolSpec(it, u, groups, entries, pair, manifest, lockData, sha, read) {
		return
	}

	pkgs := make([]LanguagePackage, 0, len(groups))
	for _, g := range groups {
		pkgs = append(pkgs, matchPackage(lock, g))
	}
	reconcileVersions(lock, pkgs)
	it.Packages = pkgs
	classify(it)
	return
}

// analyseGoUnit plans the Go item of a unit whose directory has a go.mod:
// it reads go.mod for the module, keeps the findings of the binaries built
// from it (goSelect), and matches the module's own dependencies against
// go.mod, the standard library apart. Until go.mod has been read the module
// is not known, so an outcome reached before that (a failed read, a go.mod
// that does not parse) carries every Go finding of the unit. A workspace
// (go.work here or above) or a vendor directory sends the unit to a person;
// their absence is recorded, since one added later changes what an update is
// made from. The Go release an update runs with is chosen when it runs.
//
// The standard library's findings are an item of their own when the module's
// dependencies have findings too: they are fixed by building with a newer
// Go, which no pull request of go.mod does, and stay to be read when the
// module's item becomes one.
//
// It returns the module go.mod declares ("" when it was not read), whether
// the unit has an item (none when no finding comes from a binary built from
// the module) and the standard library's own item.
func (r *run) analyseGoUnit(it *LanguageItem, u *depUnit, entries []github.Entry) (string, bool, *LanguageItem) {
	gh := r.p.cfg.GitHub
	sha := it.Source.CommitSHA
	intel := r.p.cfg.Intel
	all := groupLanguageFindings(u.goPinned, intel)
	setPriority := func(gs []*findingGroup) { setPriorityOf(it, gs) }
	setPriority(all)
	it.Manager = ManagerGo
	it.Key = u.key + "#" + string(ManagerGo)
	read := func(groups []*findingGroup, name string) ([]byte, bool) {
		if e, _ := byName(entries, name); e.Type != github.EntryFile {
			unitManual(it, groups, ReasonDependencyFileUnusable, name+" is a "+string(e.Type))
			return nil, false
		}
		if h := r.stopReason(); h != nil {
			r.deferUnit(it, groups, h.reason, h.detail)
			return nil, false
		}
		f, err := gh.ReadFile(r.ctx, u.repo, sha, pathIn(u.dir, name))
		if err != nil {
			r.sourceFailure(it, groups, err, true)
			return nil, false
		}
		it.Source.Files = append(it.Source.Files, SourceFile{Path: f.Path, BlobSHA: f.SHA})
		return f.Content, true
	}
	refuse := func(groups []*findingGroup, err error) {
		var ue *UnsupportedError
		if errors.As(err, &ue) {
			unitManual(it, groups, ue.Reason, ue.Detail)
			return
		}
		unitManual(it, groups, ReasonUnparsableSource, err.Error())
	}
	keepAll := len(all) > 0

	modData, ok := read(all, "go.mod")
	if !ok {
		return "", keepAll, nil
	}
	gm, err := parseGoMod(modData)
	if err != nil {
		refuse(all, err)
		return "", keepAll, nil
	}

	kept, why := goSelect(u.goPinned, u.goBins, gm, true)
	groups := groupLanguageFindings(kept, intel)
	if len(groups) == 0 {
		return gm.module, false, nil
	}
	setPriority(groups)
	it.GoBuiltWith = goBuiltWith(u.goBins, gm.module)
	if why != "" {
		unitManual(it, groups, ReasonGoBinaryNotFromSource, why)
		return gm.module, true, nil
	}

	if _, present := byName(entries, "go.sum"); !present {
		unitManual(it, groups, ReasonDependencyFilesNotFound, "the directory has go.mod but no go.sum")
		return gm.module, true, nil
	}
	sumData, ok := read(groups, "go.sum")
	if !ok {
		return gm.module, true, nil
	}
	if err := checkGoSum(sumData); err != nil {
		refuse(groups, err)
		return gm.module, true, nil
	}
	if err := goModRefusal(gm); err != nil {
		refuse(groups, err)
		return gm.module, true, nil
	}
	lock, err := goLockfile(gm)
	if err != nil {
		refuse(groups, err)
		return gm.module, true, nil
	}

	for _, name := range []string{"go.work", "vendor"} {
		if _, found := byName(entries, name); found {
			unitManual(it, groups, ReasonWorkspaceUnsupported, pathIn(u.dir, name)+" exists; a Go workspace or a vendor directory is not handled")
			return gm.module, true, nil
		}
		it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, name))
	}
	if found, ok := r.ancestorFile(it, groups, u, sha, "go.work"); !ok {
		return gm.module, true, nil
	} else if found != "" {
		unitManual(it, groups, ReasonWorkspaceUnsupported, found+" exists; a Go workspace applies to the modules below it and is not handled")
		return gm.module, true, nil
	}

	mods, stdlib := goSplit(groups)
	var std *LanguageItem
	if len(mods) > 0 && len(stdlib) > 0 {
		s := *it
		s.Key = it.Key + "-" + goStdlib
		s.Source.Files = append([]SourceFile(nil), it.Source.Files...)
		s.Source.Absent = append([]string(nil), it.Source.Absent...)
		s.Packages = nil
		for _, g := range stdlib {
			s.Packages = append(s.Packages, goStdlibPackage(g))
		}
		setPriorityOf(&s, stdlib)
		classify(&s)
		std = &s
		setPriority(mods)
		stdlib = nil
	}
	pkgs := make([]LanguagePackage, 0, len(groups))
	for _, g := range mods {
		p := matchPackage(lock, g)
		if p.Action == ActionUpdate {
			if why := goMajorProblem(g.Name, p.Installed, p.SelectionLowerBound); why != "" {
				p.SelectionLowerBound = ""
				manualPackage(&p, ReasonFixInOtherMajor, why)
			}
		}
		pkgs = append(pkgs, p)
	}
	reconcileVersions(lock, pkgs)
	for _, g := range stdlib {
		pkgs = append(pkgs, goStdlibPackage(g))
	}
	it.Packages = pkgs
	classify(it)
	return gm.module, true, std
}

// setPriorityOf sets an item's priority to the strongest of its groups'.
func setPriorityOf(it *LanguageItem, gs []*findingGroup) {
	it.Priority = ""
	for _, g := range gs {
		if g.priority.Rank() > it.Priority.Rank() {
			it.Priority = g.priority
		}
	}
}

// ancestorWorkspace looks for a pnpm-workspace.yaml in each directory above
// the unit's, up to the repository root. It returns a description when one
// exists. The directories without one are recorded on the item as places the
// file was looked for and not found. ok is false when a listing failed and the
// item has been given its outcome.
func (r *run) ancestorWorkspace(it *LanguageItem, groups []*findingGroup, u *depUnit, sha string) (why string, ok bool) {
	found, ok := r.ancestorFile(it, groups, u, sha, pnpmWorkspaceName)
	if found != "" {
		why = fmt.Sprintf("%s has a pnpm-workspace.yaml, which pnpm applies to this directory (it may be a member of a workspace)", found)
	}
	return why, ok
}

// ancestorFile looks for a file of the given name in each directory above
// the unit's, up to the repository root, and returns the path of the first
// one found. The directories without one are recorded on the item as places
// the file was looked for and not found. ok is false when a listing failed
// and the item has been given its outcome.
func (r *run) ancestorFile(it *LanguageItem, groups []*findingGroup, u *depUnit, sha, name string) (found string, ok bool) {
	for dir := u.dir; dir != "." && dir != ""; {
		parent := path.Dir(dir)
		if parent == "" || parent == "/" {
			parent = "."
		}
		dir = parent
		if h := r.stopReason(); h != nil {
			r.deferUnit(it, groups, h.reason, h.detail)
			return "", false
		}
		entries, err := r.p.cfg.GitHub.ListDirectory(r.ctx, u.repo, sha, dir)
		switch {
		case errors.Is(err, github.ErrNotFound):
			entries = nil
		case err != nil:
			r.sourceFailure(it, groups, err, false)
			return "", false
		}
		if _, found := byName(entries, name); found {
			return pathIn(dir, name), true
		}
		it.Source.Absent = append(it.Source.Absent, pathIn(dir, name))
	}
	return "", true
}

// classify sets the category of an analysed unit from its packages: a unit
// with any package that has a target is a candidate, one with only range
// requirements expects a rebuild, and the rest is manual. Packages that need
// a person stay listed in the unit with their reasons.
func classify(it *LanguageItem) {
	total := len(it.Packages)
	upd, reb := it.Count(ActionUpdate), it.Count(ActionRebuildExpected)
	switch {
	case upd > 0:
		it.Category, it.Reason = CategoryDependencyUpdateCandidate, ReasonUpdateCandidateInSource
		it.Detail = fmt.Sprintf("%d of %d packages have a target version in the dependency files; the update and its post-update check were not run", upd, total)
	case reb > 0:
		it.Category, it.Reason = CategoryRebuildExpected, ReasonRangeAllowsFix
		it.Detail = fmt.Sprintf("%d of %d packages are given as version ranges that allow the fix; rebuilding the image is expected to take it", reb, total)
	default:
		it.Category, it.Reason = CategoryManual, ReasonPackagesManual
		it.Detail = fmt.Sprintf("none of the %d packages can be proposed", total)
		if first := it.Packages[0].Reason; first != "" {
			same := true
			for _, p := range it.Packages {
				same = same && p.Reason == first
			}
			if same {
				it.Reason = first
			}
		}
	}
}

// ReasonPackagesManual is the reason of an analysed unit none of whose
// packages can be proposed, when they differ in why.
const ReasonPackagesManual Reason = "packages_need_manual_update"

// unitManual records a unit whose files cannot be used, listing its packages
// as manual with the same reason.
func unitManual(it *LanguageItem, gs []*findingGroup, reason Reason, detail string) {
	it.Category, it.Reason, it.Detail = CategoryManual, reason, detail
	it.Packages = unitPackages(gs, ActionManual, reason, detail)
}

// deferUnit records a unit left undone.
func (r *run) deferUnit(it *LanguageItem, gs []*findingGroup, reason Reason, detail string) {
	it.Category, it.Reason, it.Detail = CategoryDeferred, reason, detail
	it.Packages = unitPackages(gs, "", "", "")
}

// unitPackages lists the running packages of a unit that could not be
// matched, with the action and reason shared by all of them.
func unitPackages(gs []*findingGroup, action PackageAction, reason Reason, detail string) []LanguagePackage {
	out := make([]LanguagePackage, 0, len(gs))
	for _, g := range gs {
		p := LanguagePackage{Name: g.Name, Ecosystem: g.Type, Installed: g.Installed, CVEs: g.cves, Origins: g.origins, Action: action, Reason: reason, Detail: detail}
		if g.Type == typePythonPkg {
			p.Normalized = normalizePyName(g.Name)
		}
		out = append(out, p)
	}
	return out
}

// detectPair finds the one manager whose files are in the directory. Only the
// directory itself is looked at: no other location is searched, and several
// pairs are never ranked. A file that is not a regular file (a symlink, a
// submodule, a directory) is not read.
func detectPair(entries []github.Entry, pkgType string) (dependencyPair, Reason, string) {
	byName := map[string]github.Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	var pairs []dependencyPair
	for _, p := range dependencyPairs {
		if p.pkgType == pkgType {
			pairs = append(pairs, p)
		}
	}
	var bad []string
	for _, p := range pairs {
		for _, n := range []string{p.manifest, p.lock} {
			if e, ok := byName[n]; ok && n != "" && e.Type != github.EntryFile {
				bad = append(bad, fmt.Sprintf("%s is a %s", n, e.Type))
			}
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return dependencyPair{}, ReasonDependencyFileUnusable, strings.Join(bad, "; ")
	}
	var found []dependencyPair
	for _, p := range pairs {
		_, hasLock := byName[p.lock]
		_, hasManifest := byName[p.manifest]
		if hasLock && (p.manifest == "" || hasManifest) {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 0:
		return dependencyPair{}, ReasonDependencyFilesNotFound, "the directory has none of: " + noPairText[pkgType]
	case 1:
		return found[0], "", ""
	}
	var names []string
	for _, p := range found {
		names = append(names, p.lock)
	}
	return dependencyPair{}, ReasonAmbiguousDependencyFile, "the directory holds more than one set of dependency files for the same ecosystem: " + strings.Join(names, ", ")
}

var noPairText = map[string]string{
	typeNodePkg:   "package.json with package-lock.json, package.json with pnpm-lock.yaml",
	typePythonPkg: "pyproject.toml with uv.lock, requirements.txt",
	typeGoBinary:  "go.mod with go.sum",
}

// byName finds a directory entry.
func byName(entries []github.Entry, name string) (github.Entry, bool) {
	for _, e := range entries {
		if e.Name == name {
			return e, true
		}
	}
	return github.Entry{}, false
}

// npmrcProblem returns why an .npmrc cannot be accepted: it points package
// downloads somewhere other than the public npm registry, or it has a line
// the plan cannot interpret (a section, a malformed quote, an escape). It
// reads the ini syntax npm does for the keys and values it looks at: keys and
// values may be quoted, ";" and "#" start comments, also after a value.
// Only the registry settings (registry= and @scope:registry=) are checked;
// credentials and other settings do not change where a package comes from.
func npmrcProblem(content []byte) string {
	// npm's ini parser breaks lines at CRLF, LF and a lone CR alike.
	for i, raw := range iniLines(string(content)) {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			return fmt.Sprintf(".npmrc line %d starts a section, which is not interpreted", i+1)
		}
		k, v, hasValue, ok := iniLine(line)
		if !ok {
			return fmt.Sprintf(".npmrc line %d cannot be interpreted", i+1)
		}
		if k != "registry" && !(strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry")) {
			continue
		}
		if !hasValue || strings.TrimRight(v, "/") != "https://"+publicNpmHost {
			return ".npmrc sets " + k + " to a registry other than the public npm registry"
		}
	}
	return ""
}

// iniLines splits ini text at "\r\n", "\n" and a lone "\r".
func iniLines(s string) []string {
	return strings.FieldsFunc(strings.ReplaceAll(s, "\r\n", "\n"), func(r rune) bool { return r == '\n' || r == '\r' })
}

// iniLine splits one non-blank, non-comment line of an ini file into a key
// and a value. ok is false for a line that is malformed or uses a feature
// (backslash escapes outside quotes) the plan does not interpret.
func iniLine(line string) (key, val string, hasValue, ok bool) {
	i := 0
	switch line[0] {
	case '"', '\'':
		k, n, ok := iniQuoted(line)
		if !ok {
			return "", "", false, false
		}
		// npm unquotes a quoted key further when it still looks quoted; a key
		// that holds quotes or escapes after one unquoting is not interpreted.
		if strings.ContainsAny(k, "\\\"'") {
			return "", "", false, false
		}
		key, i = k, n
	default:
		j := strings.IndexAny(line, "=;#")
		if j < 0 {
			j = len(line)
		}
		key = strings.TrimSpace(line[:j])
		if key == "" || strings.ContainsAny(key, "\\\"'") {
			return "", "", false, false
		}
		i = j
	}
	rest := strings.TrimSpace(line[i:])
	if rest == "" || rest[0] == ';' || rest[0] == '#' {
		return key, "", false, true
	}
	if rest[0] != '=' {
		return "", "", false, false
	}
	rest = strings.TrimSpace(rest[1:])
	if rest == "" {
		return key, "", true, true
	}
	if rest[0] == '"' || rest[0] == '\'' {
		v, n, ok := iniQuoted(rest)
		if !ok {
			return "", "", false, false
		}
		if tail := strings.TrimSpace(rest[n:]); tail != "" && tail[0] != ';' && tail[0] != '#' {
			return "", "", false, false
		}
		return key, v, true, true
	}
	if j := strings.IndexAny(rest, ";#"); j >= 0 {
		rest = rest[:j]
	}
	if strings.Contains(rest, "\\") {
		return "", "", false, false
	}
	return key, strings.TrimSpace(rest), true, true
}

// iniQuoted reads a quoted string at the start of s: double quotes take
// JSON-style escapes, single quotes are literal. n is the length consumed.
func iniQuoted(s string) (val string, n int, ok bool) {
	q := s[0]
	for j := 1; j < len(s); j++ {
		switch {
		case s[j] == '\\' && q == '"':
			j++
		case s[j] == q:
			if q == '\'' {
				return s[1:j], j + 1, true
			}
			v, err := strconv.Unquote(s[:j+1])
			return v, j + 1, err == nil
		}
	}
	return "", 0, false
}

func pathIn(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

// sourceFailure maps a GitHub error to the unit's outcome. Rate limiting, an
// exhausted budget and a dead context stop all further reads in the pass and
// defer the rest; a missing or forbidden source is a failure of that unit.
//
// A file over its own size cap is a failure of that file (file is true when a
// file was being read); running out of the cycle's file bytes is a deferral,
// as the file itself is fine.
func (r *run) sourceFailure(it *LanguageItem, gs []*findingGroup, err error, file bool) {
	var limited *github.RateLimitedError
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		r.srcHalt = &halt{ReasonCycleDeadline, err.Error()}
		r.deferUnit(it, gs, r.srcHalt.reason, r.srcHalt.detail)
	case errors.Is(err, github.ErrBudgetExhausted):
		r.srcHalt = &halt{ReasonGitHubBudget, "GitHub request budget exhausted"}
		r.deferUnit(it, gs, r.srcHalt.reason, r.srcHalt.detail)
	case errors.As(err, &limited):
		r.srcHalt = &halt{ReasonRateLimited, err.Error()}
		r.deferUnit(it, gs, r.srcHalt.reason, r.srcHalt.detail)
	case errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrNotRegularFile):
		unitManual(it, gs, ReasonDependencyFileUnusable, err.Error())
	case errors.Is(err, github.ErrNotFound):
		it.Category, it.Reason, it.Detail = CategoryFailed, ReasonSourceNotFound, err.Error()
		it.Packages = unitPackages(gs, "", "", "")
	case errors.Is(err, github.ErrAuthRequired), errors.Is(err, github.ErrForbidden):
		it.Category, it.Reason, it.Detail = CategoryFailed, ReasonSourceAccessDenied, err.Error()
		it.Packages = unitPackages(gs, "", "", "")
	case errors.Is(err, github.ErrByteBudgetExhausted):
		r.srcHalt = &halt{ReasonByteBudget, err.Error()}
		r.deferUnit(it, gs, r.srcHalt.reason, r.srcHalt.detail)
	case errors.Is(err, github.ErrTooLarge):
		reason := ReasonSourceTooLarge
		if file {
			reason = ReasonFileTooLarge
		}
		it.Category, it.Reason, it.Detail = CategoryFailed, reason, err.Error()
		it.Packages = unitPackages(gs, "", "", "")
	default:
		it.Category, it.Reason, it.Detail = CategoryFailed, ReasonSourceError, err.Error()
		it.Packages = unitPackages(gs, "", "", "")
	}
}
