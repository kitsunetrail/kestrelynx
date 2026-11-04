package remediation

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Reasons of the Maven update.
const (
	// ReasonMavenVersionSourceUnsupported: the version of a target is decided
	// in a way no edit of the project's pom files changes (a version written
	// in a parent outside the project, an expression, a property also used
	// by plugins).
	ReasonMavenVersionSourceUnsupported Reason = "maven_version_source_unsupported"
	// ReasonMavenReleaseNotFound: Maven Central lists no release of a target
	// (or of a package that moves with it) that the update can take.
	ReasonMavenReleaseNotFound Reason = "maven_release_not_found"
	// ReasonMavenDependencyHeldBack: after the update, a dependency the
	// target's new release declares resolves below the version it declares
	// (management of the project or its parents holds it back), so the
	// release would run with older libraries than it was built for.
	ReasonMavenDependencyHeldBack Reason = "maven_dependency_held_back"
	// ReasonMavenBOMSeriesUnreached: a target's version is decided by a BOM,
	// and no release of the BOM in the minor version the project imports
	// manages it at its target. The BOM is not moved to another minor
	// version, and a package of a BOM is not pinned apart from its set.
	ReasonMavenBOMSeriesUnreached Reason = "maven_bom_series_unreached"
)

// Bounds of the Maven update.
const (
	maxMavenParentDepth   = 10
	maxMavenBOMCandidates = 20
	// maxMavenBOMRaiseLookups bounds the poms read to find the release of a
	// later minor version that a person can raise a BOM to.
	maxMavenBOMRaiseLookups = 8
	maxMavenRelayRequests   = 2000
)

// MavenUpdate records what a Maven update changed in the pom files and what
// moved with it.
type MavenUpdate struct {
	Edits []MavenEditRecord `json:"edits,omitempty"`
	// Moves are the packages besides the targets whose resolved versions
	// changed, as the scans of the files before and after resolve them.
	Moves []MavenMove `json:"moves,omitempty"`
}

// Kinds of MavenEditRecord.
const (
	MavenEditVersion          = "version"           // a version written in a declaration
	MavenEditProperty         = "property"          // a property the project defines
	MavenEditPropertyOverride = "property_override" // a property of a parent, set in the project
	MavenEditManagedPin       = "managed_pin"       // a pin added to dependencyManagement
)

// MavenEditRecord is one change of a pom file.
type MavenEditRecord struct {
	File     string `json:"file"`
	Kind     string `json:"kind"`
	Package  string `json:"package,omitempty"`
	Property string `json:"property,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to"`
}

// MavenMove is a package whose resolved versions changed: From is empty for
// one that came in, To for one that went away.
type MavenMove struct {
	Name string   `json:"name"`
	From []string `json:"from,omitempty"`
	To   []string `json:"to,omitempty"`
}

// mavenChainPOM is one pom of a module's chain of parents: a module of the
// reactor or a pom fetched from Maven Central.
type mavenChainPOM struct {
	pom    *mavenPOM
	module *mavenModule // nil for a fetched pom
	coord  string       // g:a:v of a fetched pom
}

// mavenFiles are the reactor's pom files as the plan recorded them, read
// again, by repository path.
type mavenFiles struct {
	rx      *mavenReactor
	content map[string][]byte
	mode    map[string]string
}

// spendMavenLookup counts one request of the update to Maven Central against
// the registry lookups an update may make.
func (r *updateRun) spendMavenLookup() error {
	if r.lookups >= maxRegistryChecks {
		return errRegistryBudget
	}
	r.lookups++
	return nil
}

// readMavenSources reads every file the plan recorded again, requires the
// blobs it recorded and the places it found empty to be empty still, and
// rebuilds the reactor from them.
func (r *updateRun) readMavenSources(ctx context.Context) (*mavenFiles, *updateFailure) {
	src := r.it.Source
	if src.CommitSHA == "" {
		return nil, failedFailure(ReasonUpdateInputInvalid, "the plan recorded no commit")
	}
	gh := r.u.cfg.GitHub
	mf := &mavenFiles{content: map[string][]byte{}, mode: map[string]string{}}
	for _, f := range src.Files {
		if f.Repository != "" {
			return nil, failedFailure(ReasonUpdateInputInvalid, "the plan records %s from another repository", f.Path)
		}
		got, err := gh.ReadFile(ctx, src.Repository, src.CommitSHA, f.Path)
		if err != nil {
			return nil, readFailure(err, f.Path)
		}
		if got.SHA != f.BlobSHA || got.Path != f.Path {
			return nil, failedFailure(ReasonSourceChanged, "%s is not the blob the plan was made from (%s, now %s)", f.Path, f.BlobSHA, got.SHA)
		}
		mf.content[f.Path], mf.mode[f.Path] = got.Content, got.Mode
	}
	for _, p := range src.Absent {
		_, err := gh.ReadFile(ctx, src.Repository, src.CommitSHA, p)
		var nr *github.NotRegularFileError
		switch {
		case errors.Is(err, github.ErrNotFound):
		case err == nil, errors.As(err, &nr), errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrTooLarge):
			return nil, failedFailure(ReasonSourceChanged, "%s did not exist when the plan was made and does now", p)
		default:
			return nil, readFailure(err, p)
		}
	}
	rootPath := pathIn(src.Directory, "pom.xml")
	rx := &mavenReactor{byCoord: map[string]*mavenModule{}, byPath: map[string]*mavenModule{}}
	queue := []string{rootPath}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if rx.byPath[p] != nil {
			continue
		}
		data, ok := mf.content[p]
		if !ok {
			return nil, failedFailure(ReasonUpdateInputInvalid, "the plan does not record %s, a module of the reactor", p)
		}
		pom, err := parseMavenPOM(data)
		if err != nil {
			return nil, manualFailure(ReasonUnparsableSource, "%s: %v", p, err)
		}
		m := &mavenModule{path: p, dir: path.Dir(p), pom: pom}
		m.coord = pom.EffectiveGroupID() + ":" + pom.ArtifactID
		if rx.byCoord[m.coord] != nil {
			return nil, manualFailure(ReasonMavenReactorUnsupported, "two modules declare %s", m.coord)
		}
		rx.modules = append(rx.modules, m)
		rx.byCoord[m.coord], rx.byPath[p] = m, m
		for _, name := range pom.Modules {
			dir, why := mavenModuleDir(src.Directory, m.dir, name)
			if why != "" {
				return nil, manualFailure(ReasonMavenReactorUnsupported, "%s lists the module %q: %s", p, name, why)
			}
			queue = append(queue, pathIn(dir, "pom.xml"))
		}
	}
	if reason, why := mavenModelProblem(rx); reason != "" {
		return nil, manualFailure(reason, "%s", why)
	}
	mf.rx = rx
	return mf, nil
}

// fetchPOM reads a pom from Maven Central, once per update.
func (r *updateRun) fetchPOM(ctx context.Context, g, a, v string) (*mavenPOM, *updateFailure) {
	key := g + ":" + a + ":" + v
	if p, ok := r.mavenPOMs[key]; ok {
		return p, nil
	}
	if err := r.spendMavenLookup(); err != nil {
		return nil, lookupFailure(ctx, err, key+" on Maven Central")
	}
	data, err := r.u.cfg.Maven.POM(ctx, g, a, v)
	if err != nil {
		return nil, lookupFailure(ctx, err, key+" on Maven Central")
	}
	pom, err := parseMavenPOM(data)
	if err != nil {
		return nil, manualFailure(ReasonDistributionMismatch, "the pom of %s cannot be read: %v", key, err)
	}
	if pom.EffectiveGroupID() != g || pom.ArtifactID != a || pom.EffectiveVersion() != v {
		return nil, manualFailure(ReasonDistributionMismatch, "Maven Central serves %s:%s:%s for %s", pom.EffectiveGroupID(), pom.ArtifactID, pom.EffectiveVersion(), key)
	}
	r.mavenPOMs[key] = pom
	return pom, nil
}

// versions lists the releases of g:a on Maven Central, once per update.
func (r *updateRun) versions(ctx context.Context, g, a string) ([]string, *updateFailure) {
	key := g + ":" + a
	if vs, ok := r.mavenVersions[key]; ok {
		return vs, nil
	}
	if err := r.spendMavenLookup(); err != nil {
		return nil, lookupFailure(ctx, err, key+" on Maven Central")
	}
	vs, err := r.u.cfg.Maven.Versions(ctx, g, a)
	if err != nil {
		return nil, lookupFailure(ctx, err, "the versions of "+key+" on Maven Central")
	}
	r.mavenVersions[key] = vs
	return vs, nil
}

// chainOf is a module's chain of parents, the module first: the reactor
// modules it inherits from, then the poms fetched from Maven Central above
// the last of them.
func (r *updateRun) chainOf(ctx context.Context, rx *mavenReactor, m *mavenModule) ([]mavenChainPOM, *updateFailure) {
	var out []mavenChainPOM
	cur := m
	for {
		out = append(out, mavenChainPOM{pom: cur.pom, module: cur})
		next := rx.parent(cur)
		if next == nil {
			break
		}
		cur = next
	}
	pa := cur.pom.Parent
	for depth := 0; pa != nil; depth++ {
		if depth >= maxMavenParentDepth {
			return nil, manualFailure(ReasonMavenVersionSourceUnsupported, "the parents of %s go deeper than %d levels", m.path, maxMavenParentDepth)
		}
		if strings.Contains(pa.GroupID+pa.ArtifactID+pa.Version, "${") {
			return nil, manualFailure(ReasonMavenVersionSourceUnsupported, "a parent of %s is named with an expression", m.path)
		}
		pom, fail := r.fetchPOM(ctx, pa.GroupID, pa.ArtifactID, pa.Version)
		if fail != nil {
			return nil, fail
		}
		out = append(out, mavenChainPOM{pom: pom, coord: pa.GroupID + ":" + pa.ArtifactID + ":" + pa.Version})
		pa = pom.Parent
	}
	return out, nil
}

// chainResolve gives the value of a text in the effective model of the
// first pom of chain: a ${name} is looked up nearest first, the project's
// coordinates are the first pom's. ok is false for an expression that is not
// one reference, or a property no pom of the chain defines.
func chainResolve(chain []mavenChainPOM, s string) (string, bool) {
	for depth := 0; depth < 8; depth++ {
		if !strings.Contains(s, "${") {
			return s, s != ""
		}
		name, ok := mavenPropertyRef(s)
		if !ok {
			return "", false
		}
		switch name {
		case "project.groupId", "pom.groupId":
			return chain[0].pom.EffectiveGroupID(), true
		case "project.version", "pom.version":
			return chain[0].pom.EffectiveVersion(), true
		case "project.artifactId", "pom.artifactId":
			return chain[0].pom.ArtifactID, true
		}
		if pa := chain[0].pom.Parent; pa != nil {
			switch name {
			case "project.parent.groupId", "parent.groupId":
				return pa.GroupID, pa.GroupID != ""
			case "project.parent.artifactId", "parent.artifactId":
				return pa.ArtifactID, pa.ArtifactID != ""
			case "project.parent.version", "parent.version":
				return pa.Version, pa.Version != ""
			}
		}
		found := false
		for _, c := range chain {
			if v, ok := c.pom.Properties[name]; ok {
				s, found = v, true
				break
			}
		}
		if !found {
			return "", false
		}
	}
	return "", false
}

// propertyOwner is the pom of chain nearest the module that defines name,
// and its index; -1 when none does.
func propertyOwner(chain []mavenChainPOM, name string) int {
	for i, c := range chain {
		if _, ok := c.pom.Properties[name]; ok {
			return i
		}
	}
	return -1
}

// mavenPlace is where a target's version is decided, and the edit that
// changes it.
type mavenPlace struct {
	kind  string    // a MavenEdit* kind
	file  string    // the repository path of the pom to edit
	edit  mavenEdit // with Value filled in once the version is chosen
	prop  string    // the property, for the property kinds
	from  string    // the version or value it had
	bom   string    // g:a of the BOM whose import version the property is, for a BOM override
	chain []mavenChainPOM
	// managed is set when the version is decided by management only, so a
	// pin in the root's management can decide it instead.
	managed bool
}

// placesOf finds, for each module, the declaration that decides the version
// of name there, as Maven's precedence goes: the dependency declaration
// nearest the module (a module's own overrides what it inherits) when it
// writes a version; else the explicit management nearest the module; else
// the one BOM it imports that manages the package; else nothing (an
// unmanaged transitive package), which a pin in the reactor's root decides.
// When some modules declare the package, only those are looked at; else the
// package comes in through other dependencies and every module is.
func (r *updateRun) placesOf(ctx context.Context, mf *mavenFiles, chains map[*mavenModule][]mavenChainPOM, name string) ([]mavenPlace, *updateFailure) {
	rx := mf.rx
	root := rx.modules[0]
	unknown := func(m *mavenModule) *updateFailure {
		return manualFailure(ReasonMavenVersionSourceUnsupported, "a dependency or management entry %s reads has a name that cannot be read, so where the version of %s is decided is not known", m.path, name)
	}
	var mods []*mavenModule
	for _, m := range rx.modules {
		ci, _ := nearestDeclaration(chains[m], name)
		if ci == mavenUnknown {
			return nil, unknown(m)
		}
		if ci >= 0 {
			mods = append(mods, m)
		}
	}
	if len(mods) == 0 {
		mods = rx.modules
	}
	var out []mavenPlace
	for _, m := range mods {
		chain := chains[m]
		if ci, i := nearestDeclaration(chain, name); ci >= 0 && chain[ci].pom.Dependencies[i].Version != "" {
			pl, fail := placeOfText(chain, ci, chain[ci].pom.Dependencies[i].Version, i, false, root, name)
			if fail != nil {
				return nil, fail
			}
			out = append(out, pl)
			continue
		}
		ci, i := nearestManagement(chain, name)
		if ci == mavenUnknown {
			return nil, unknown(m)
		}
		if ci >= 0 {
			pl, fail := placeOfText(chain, ci, chain[ci].pom.DependencyManagement[i].Version, i, true, root, name)
			if fail != nil {
				return nil, fail
			}
			pl.managed = true
			out = append(out, pl)
			continue
		}
		pl, fail := r.bomPlace(ctx, chain, root, name)
		if fail != nil {
			return nil, fail
		}
		out = append(out, pl)
	}
	return dedupePlaces(out), nil
}

// mavenUnknown is what the nearest-entry lookups return when an entry
// before any match has a name that cannot be read, so whether it is the
// package is not known.
const mavenUnknown = -2

// entryNameIn reads the groupId:artifactId of an entry in the module's
// context; ok is false when either cannot be read.
func entryNameIn(chain []mavenChainPOM, d mavenDep) (string, bool) {
	g, ok1 := chainResolve(chain, d.GroupID)
	a, ok2 := chainResolve(chain, d.ArtifactID)
	return g + ":" + a, ok1 && ok2
}

// nearestDeclaration finds the dependency declaration of name nearest the
// module, at compile or runtime scope: the index of the pom in chain and of
// the entry, -1 when there is none, or mavenUnknown. What a parent declares
// is interpolated in the module.
func nearestDeclaration(chain []mavenChainPOM, name string) (int, int) {
	for ci, c := range chain {
		for i, d := range c.pom.Dependencies {
			if !mavenRuntimeScope(d) {
				continue
			}
			n, ok := entryNameIn(chain, d)
			if !ok {
				return mavenUnknown, mavenUnknown
			}
			if n == name {
				return ci, i
			}
		}
	}
	return -1, -1
}

// bomPlace is the place of a package the module's chain manages through an
// imported BOM: the property its import version is, when exactly one BOM
// manages it itself (in the BOM or the BOM's parents) and that version is a
// property; a pin in the root when no BOM manages it. A BOM moves its
// packages together, so a package one manages otherwise (through a BOM it
// imports, or several BOMs) is not pinned apart from the rest: it is left
// alone.
func (r *updateRun) bomPlace(ctx context.Context, chain []mavenChainPOM, root *mavenModule, name string) (mavenPlace, *updateFailure) {
	var managers []mavenPlace
	for _, c := range chain {
		for _, d := range c.pom.DependencyManagement {
			if !d.IsImport() {
				continue
			}
			g, ok1 := chainResolve(chain, d.GroupID)
			a, ok2 := chainResolve(chain, d.ArtifactID)
			v, ok3 := chainResolve(chain, d.Version)
			if !ok1 || !ok2 || !ok3 {
				return mavenPlace{}, manualFailure(ReasonMavenVersionSourceUnsupported, "an imported BOM is named with an expression that cannot be resolved")
			}
			direct, nested, fail := r.bomManagesDeep(ctx, g, a, v, name, 0)
			if fail != nil {
				return mavenPlace{}, fail
			}
			if !direct && !nested {
				continue
			}
			p, isRef := mavenPropertyRef(d.Version)
			if !direct || !isRef || propertyOwner(chain, p) < 0 {
				f := manualFailure(ReasonMavenVersionSourceUnsupported, "%s is managed by the BOM %s:%s, whose version is not a property the project can set to move the set, and a package of a BOM is not pinned apart from the rest", name, g, a)
				f.decider = &FixDecider{Kind: DeciderBOM, Name: g + ":" + a, Version: v}
				return mavenPlace{}, f
			}
			managers = append(managers, mavenPlace{kind: MavenEditPropertyOverride, file: root.path, prop: p, from: v, bom: g + ":" + a, chain: chain,
				edit: mavenEdit{Kind: mavenSetProperty, Name: p}})
		}
	}
	managers = dedupePlaces(managers)
	switch len(managers) {
	case 0:
		// Nothing manages it: a pin of the project's own decides.
		pl := pinPlace(root, chain, name)
		pl.managed = true
		return pl, nil
	case 1:
		return managers[0], nil
	}
	return mavenPlace{}, manualFailure(ReasonMavenVersionSourceUnsupported, "%s is managed by more than one imported BOM", name)
}

// bomManagesDeep reports whether the BOM g:a:v manages name itself (in its
// own management or its parents'), or only through a BOM it imports,
// followed to a bounded depth. A BOM that cannot be followed is a failure:
// what it manages is not known, so the package is not pinned.
func (r *updateRun) bomManagesDeep(ctx context.Context, g, a, v, name string, depth int) (direct, nested bool, fail *updateFailure) {
	if depth > 3 {
		return false, false, manualFailure(ReasonMavenVersionSourceUnsupported, "the BOMs %s:%s:%s imports go deeper than this update follows", g, a, v)
	}
	bom, fail := r.fetchPOM(ctx, g, a, v)
	if fail != nil {
		return false, false, fail
	}
	bchain := []mavenChainPOM{{pom: bom, coord: g + ":" + a + ":" + v}}
	for pa, up := bom.Parent, 0; pa != nil && up < maxMavenParentDepth; up++ {
		pp, fail := r.fetchPOM(ctx, pa.GroupID, pa.ArtifactID, pa.Version)
		if fail != nil {
			return false, false, fail
		}
		bchain = append(bchain, mavenChainPOM{pom: pp, coord: pa.GroupID + ":" + pa.ArtifactID + ":" + pa.Version})
		pa = pp.Parent
	}
	switch ci, _ := nearestManagement(bchain, name); {
	case ci == mavenUnknown:
		return false, false, manualFailure(ReasonMavenVersionSourceUnsupported, "%s:%s:%s manages a package whose name cannot be read, so whether it manages %s is not known", g, a, v, name)
	case ci >= 0:
		return true, false, nil
	}
	for _, c := range bchain {
		for _, d := range c.pom.DependencyManagement {
			if !d.IsImport() {
				continue
			}
			ig, ok1 := chainResolve(bchain, d.GroupID)
			ia, ok2 := chainResolve(bchain, d.ArtifactID)
			iv, ok3 := chainResolve(bchain, d.Version)
			if !ok1 || !ok2 || !ok3 {
				return false, false, manualFailure(ReasonMavenVersionSourceUnsupported, "%s:%s:%s imports a BOM named with an expression that cannot be resolved", g, a, v)
			}
			dd, nn, fail := r.bomManagesDeep(ctx, ig, ia, iv, name, depth+1)
			if fail != nil {
				return false, false, fail
			}
			if dd || nn {
				return false, true, nil
			}
		}
	}
	return false, false, nil
}

// pinPlace pins name in the root's management: its explicit entry's version
// when it has one, a new entry otherwise.
func pinPlace(root *mavenModule, chain []mavenChainPOM, name string) mavenPlace {
	g, a := strings.SplitN(name, ":", 2)[0], strings.SplitN(name, ":", 2)[1]
	if i := rootManagementIndex(root.pom, name); i >= 0 {
		return mavenPlace{kind: MavenEditVersion, file: root.path, from: root.pom.DependencyManagement[i].Version, chain: chain, edit: mavenEdit{Kind: mavenEditManagedVersion, Index: i}}
	}
	return mavenPlace{kind: MavenEditManagedPin, file: root.path, chain: chain, edit: mavenEdit{Kind: mavenAddManaged, GroupID: g, ArtifactID: a}}
}

// nearestManagement finds the explicit management of name nearest the
// module: the index of the pom in chain and of the entry, -1 when there is
// none, or mavenUnknown.
func nearestManagement(chain []mavenChainPOM, name string) (int, int) {
	for ci, c := range chain {
		for i, d := range c.pom.DependencyManagement {
			if d.IsImport() || d.Classifier != "" || mavenTypeOf(d) != "jar" {
				continue
			}
			n, ok := entryNameIn(chain, d)
			if !ok {
				return mavenUnknown, mavenUnknown
			}
			if n == name {
				return ci, i
			}
		}
	}
	return -1, -1
}

// rootManagementIndex is the index of the root's explicit management of
// name, or -1.
func rootManagementIndex(root *mavenPOM, name string) int {
	for i, d := range root.DependencyManagement {
		if !d.IsImport() && d.GroupID+":"+d.ArtifactID == name && d.Classifier == "" && mavenTypeOf(d) == "jar" {
			return i
		}
	}
	return -1
}

// placeOfText is the edit for a version text written in the ci-th pom of
// chain: the text itself when it is written in a reactor pom (A), the
// property it names when a reactor pom defines it (B), an override in the
// reactor's root when a fetched pom defines it (C). A version written in a
// fetched pom is not changed by any edit of the project unless it is
// managed (managed is set for a management entry, which a pin in the root
// overrides: D).
func placeOfText(chain []mavenChainPOM, ci int, text string, index int, managed bool, root *mavenModule, name string) (mavenPlace, *updateFailure) {
	g, a := strings.SplitN(name, ":", 2)[0], strings.SplitN(name, ":", 2)[1]
	at := chain[ci]
	p, isRef := mavenPropertyRef(text)
	switch {
	case !strings.Contains(text, "${") && at.module != nil:
		kind := mavenEditDependencyVersion
		if managed {
			kind = mavenEditManagedVersion
		}
		return mavenPlace{kind: MavenEditVersion, file: at.module.path, from: text, chain: chain, edit: mavenEdit{Kind: kind, Index: index}}, nil
	case !strings.Contains(text, "${") && managed:
		return mavenPlace{kind: MavenEditManagedPin, file: root.path, from: text, chain: chain, edit: mavenEdit{Kind: mavenAddManaged, GroupID: g, ArtifactID: a}}, nil
	case !strings.Contains(text, "${"):
		f := manualFailure(ReasonMavenVersionSourceUnsupported, "%s is declared at %s in %s, a parent outside the project, which management does not override", name, text, at.coord)
		f.decider = deciderOf(DeciderParentPOM, at.coord)
		return mavenPlace{}, f
	case !isRef:
		return mavenPlace{}, manualFailure(ReasonMavenVersionSourceUnsupported, "the version of %s is the expression %s", name, text)
	}
	owner := propertyOwner(chain, p)
	switch {
	case owner < 0:
		return mavenPlace{}, manualFailure(ReasonMavenVersionSourceUnsupported, "the version of %s is ${%s}, which no pom defines", name, p)
	case chain[owner].module != nil:
		return mavenPlace{kind: MavenEditProperty, file: chain[owner].module.path, prop: p, from: chain[owner].pom.Properties[p], chain: chain,
			edit: mavenEdit{Kind: mavenSetProperty, Name: p}}, nil
	}
	return mavenPlace{kind: MavenEditPropertyOverride, file: root.path, prop: p, from: chain[owner].pom.Properties[p], chain: chain,
		edit: mavenEdit{Kind: mavenSetProperty, Name: p}}, nil
}

// dedupePlaces keeps one place per file and edit.
func dedupePlaces(ps []mavenPlace) []mavenPlace {
	seen := map[string]bool{}
	var out []mavenPlace
	for _, p := range ps {
		k := fmt.Sprintf("%s|%d|%d|%s|%s:%s", p.file, p.edit.Kind, p.edit.Index, p.edit.Name, p.edit.GroupID, p.edit.ArtifactID)
		if !seen[k] {
			seen[k] = true
			out = append(out, p)
		}
	}
	return out
}

// chooseRelease is the lowest release Maven Central lists that is at least
// the target and can replace installed: of the same major version, not a
// pre-release unless installed is one, and of the same variant.
func chooseRelease(versions []string, installed, target string) (string, bool) {
	major, ok := mavenMajor(installed)
	if !ok {
		return "", false
	}
	pre, flavor := mavenIsPrerelease(installed), mavenFlavor(installed)
	var best version
	bestStr := ""
	for _, v := range versions {
		pv, ok := parseVersion(schemeMaven, v)
		if !ok {
			continue
		}
		if c, ok := compareVersions(schemeMaven, v, target); !ok || c < 0 {
			continue
		}
		if m, ok := mavenMajor(v); !ok || m != major || (!pre && mavenIsPrerelease(v)) || mavenFlavor(v) != flavor {
			continue
		}
		if best == nil || pv.compare(best) < 0 {
			best, bestStr = pv, v
		}
	}
	return bestStr, best != nil
}

// mavenMajorMinor is the first two numeric parts of a version ("2.13" of
// "2.13.4.20221013").
func mavenMajorMinor(v string) string {
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' })
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// bomRelease finds the lowest release of a BOM, of the same major and minor
// version as the one imported and above it, that manages name at the
// target or above, and the version it manages.
func (r *updateRun) bomRelease(ctx context.Context, bom, current, name, target string) (string, string, *updateFailure) {
	g, a := strings.SplitN(bom, ":", 2)[0], strings.SplitN(bom, ":", 2)[1]
	vs, fail := r.versions(ctx, g, a)
	if fail != nil {
		return "", "", fail
	}
	var cands []string
	for _, v := range vs {
		if c, ok := compareVersions(schemeMaven, v, current); ok && c > 0 && mavenMajorMinor(v) == mavenMajorMinor(current) && !mavenIsPrerelease(v) {
			cands = append(cands, v)
		}
	}
	sort.Slice(cands, func(i, j int) bool { c, _ := compareVersions(schemeMaven, cands[i], cands[j]); return c < 0 })
	if len(cands) > maxMavenBOMCandidates {
		cands = cands[:maxMavenBOMCandidates]
	}
	for _, v := range cands {
		pom, fail := r.fetchPOM(ctx, g, a, v)
		if fail != nil {
			return "", "", fail
		}
		if mv, ok := bomManagesAt(pom, name, target); ok {
			return v, mv, nil
		}
	}
	return "", "", nil
}

// bomManagesAt returns the version a BOM's own management gives name, when it
// is the target or above.
func bomManagesAt(pom *mavenPOM, name, target string) (string, bool) {
	for _, d := range pom.DependencyManagement {
		dg := d.GroupID
		if dg == "${project.groupId}" {
			dg = pom.EffectiveGroupID()
		}
		if d.IsImport() || dg+":"+d.ArtifactID != name || d.Classifier != "" || mavenTypeOf(d) != "jar" {
			continue
		}
		mv, ok := chainResolve([]mavenChainPOM{{pom: pom}}, d.Version)
		if !ok {
			return "", false
		}
		if c, ok := compareVersions(schemeMaven, mv, target); ok && c >= 0 {
			return mv, true
		}
		return "", false
	}
	return "", false
}

// bomRaise looks for the lowest release of a BOM, of the same major version
// as the one imported and a later minor version, that manages name at the
// target or above: what a person can raise the BOM to when no release of the
// imported minor version does. Releases of a BOM manage higher versions as
// they go up, so the releases are searched by halves, a few poms at most. It
// only informs: it returns nil when none is found within its reads or a read
// fails, and the update goes on the same either way.
func (r *updateRun) bomRaise(ctx context.Context, place mavenPlace, name, target string) *MavenBOMRaise {
	g, a := strings.SplitN(place.bom, ":", 2)[0], strings.SplitN(place.bom, ":", 2)[1]
	vs, fail := r.versions(ctx, g, a)
	if fail != nil {
		return nil
	}
	cur := place.from
	major, ok := mavenMajor(cur)
	if !ok {
		return nil
	}
	var cands []string
	for _, v := range vs {
		if m, ok := mavenMajor(v); !ok || m != major {
			continue
		}
		if c, ok := compareVersions(schemeMaven, v, cur); ok && c > 0 && mavenMajorMinor(v) != mavenMajorMinor(cur) && !mavenIsPrerelease(v) {
			cands = append(cands, v)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	sort.Slice(cands, func(i, j int) bool { c, _ := compareVersions(schemeMaven, cands[i], cands[j]); return c < 0 })
	reads := 0
	reaches := func(v string) (string, bool, bool) {
		if reads >= maxMavenBOMRaiseLookups {
			return "", false, false
		}
		reads++
		pom, fail := r.fetchPOM(ctx, g, a, v)
		if fail != nil {
			return "", false, false
		}
		mv, ok := bomManagesAt(pom, name, target)
		return mv, ok, true
	}
	// The highest release first: when it does not reach, none does.
	lo, hi := 0, len(cands)-1
	best := cands[hi]
	managed, ok, read := reaches(best)
	if !read || !ok {
		return nil
	}
	for lo < hi {
		mid := (lo + hi) / 2
		mv, ok, read := reaches(cands[mid])
		if !read {
			break
		}
		if ok {
			best, managed, hi = cands[mid], mv, mid
		} else {
			lo = mid + 1
		}
	}
	return &MavenBOMRaise{BOM: place.bom, Property: place.prop, From: cur, To: best, Manages: managed}
}

// pluginRefs reports whether any pom of the reactor or of the modules'
// chains uses the property outside dependencies and management.
func pluginRefs(chains map[*mavenModule][]mavenChainPOM, prop string) bool {
	for _, chain := range chains {
		for _, c := range chain {
			if containsString(c.pom.PluginVersionRefs, prop) {
				return true
			}
		}
	}
	return false
}

// propertyInExpression returns a dependency or management version of the
// chains that reads prop inside a longer text ("${v}-tests"), or "".
func propertyInExpression(chains map[*mavenModule][]mavenChainPOM, prop string) string {
	for _, chain := range chains {
		for _, c := range chain {
			for _, d := range append(append([]mavenDep(nil), c.pom.Dependencies...), c.pom.DependencyManagement...) {
				if p, exact := mavenPropertyRef(d.Version); exact && p == prop {
					continue
				}
				if containsString(mavenPropertyRefs(d.Version), prop) {
					return d.Version
				}
			}
		}
	}
	return ""
}

// propertyUsers lists the packages whose version a pom of the chains
// writes as exactly ${prop}, in dependencies or management (imports apart).
func propertyUsers(chains map[*mavenModule][]mavenChainPOM, prop string) []string {
	var out []string
	for _, chain := range chains {
		for _, c := range chain {
			for _, d := range append(append([]mavenDep(nil), c.pom.Dependencies...), c.pom.DependencyManagement...) {
				if d.IsImport() {
					continue
				}
				if p, ok := mavenPropertyRef(d.Version); ok && p == prop {
					g, ok := chainResolve(chain, d.GroupID)
					if ok && !containsString(out, g+":"+d.ArtifactID) {
						out = append(out, g+":"+d.ArtifactID)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// runMaven is the update of a Maven reactor: this program finds where each
// target's version is decided and changes it there (a declared version, a
// property, an override of a parent's property, a pin in the root's
// management), and the pom files before and after are scanned through the
// Maven Central relay to see the targets fixed and nothing new.
func (r *updateRun) runMaven(ctx context.Context) *updateFailure {
	if r.u.cfg.Maven == nil {
		return failedFailure(ReasonUpdateInputInvalid, "no Maven Central client is configured")
	}
	r.noPartial = true
	r.mavenPOMs, r.mavenVersions = map[string]*mavenPOM{}, map[string][]string{}
	mf, fail := r.readMavenSources(ctx)
	if fail != nil {
		return fail
	}
	rx := mf.rx
	root := rx.modules[0]
	// An override or a pin is written in the root, so every module must
	// inherit from it.
	for _, m := range rx.modules[1:] {
		reaches := false
		for cur, seen := m, map[*mavenModule]bool{}; cur != nil && !seen[cur]; cur = rx.parent(cur) {
			seen[cur] = true
			if cur == root {
				reaches = true
				break
			}
		}
		if !reaches {
			return manualFailure(ReasonMavenReactorUnsupported, "%s does not inherit from the root pom, where an override would be written", m.path)
		}
	}
	chains := map[*mavenModule][]mavenChainPOM{}
	for _, m := range rx.modules {
		c, fail := r.chainOf(ctx, rx, m)
		if fail != nil {
			return fail
		}
		chains[m] = c
	}

	// Where each target's version is decided, and the release it moves to. A
	// target that cannot be placed or has no release to move to is left out,
	// and the update is made again without it when others remain.
	var plans []mavenPlanned
	leftOut := map[string]updateFailureDetail{}
	var firstOut *updateFailure
	for _, n := range r.set.names {
		pl, fail := r.planTarget(ctx, mf, chains, n)
		if fail != nil {
			if fail.category != CategoryManual {
				return fail
			}
			leftOut[n] = updateFailureDetail{fail.reason, fail.detail}
			if firstOut == nil {
				firstOut = fail
			}
			continue
		}
		plans = append(plans, pl)
	}
	if len(leftOut) > 0 {
		if len(plans) == 0 {
			return &updateFailure{category: CategoryManual, reason: firstOut.reason, detail: firstOut.detail, pkgs: leftOut}
		}
		// Nothing has been edited yet, so the targets that cannot be placed are
		// left out of this run itself; the run made again without packages, if
		// one is needed, is kept for what only the scans can tell.
		merged := map[string]updateFailureDetail{}
		for k, v := range r.leftOut {
			merged[k] = v
		}
		for k, v := range leftOut {
			merged[k] = v
		}
		r.leftOut = merged
		r.set = r.set.without(leftOut)
		for n := range leftOut {
			r.upd.Notes = append(r.upd.Notes, fmt.Sprintf("%s was left out of the update: %s", n, leftOut[n].detail))
		}
	}

	// The values of the properties and the versions written; a property
	// shared by several targets takes the highest.
	type key struct{ file, prop string }
	propValue := map[key]string{}
	bomOf := map[key]string{}
	for _, pl := range plans {
		for pi, place := range pl.places {
			if place.prop == "" {
				continue
			}
			k := key{place.file, place.prop}
			want := pl.release
			if place.bom != "" {
				want = pl.bomValues[pi]
				bomOf[k] = place.bom
			}
			if old, ok := propValue[k]; ok {
				if c, ok := compareVersions(schemeMaven, want, old); !ok || c <= 0 {
					continue
				}
			}
			propValue[k] = want
		}
	}
	// A property that plugins also use, or whose other packages Maven Central
	// does not publish at the new value, is not changed.
	for k, v := range propValue {
		if bomOf[k] != "" {
			continue
		}
		for _, user := range propertyUsers(chains, k.prop) {
			g, a := strings.SplitN(user, ":", 2)[0], strings.SplitN(user, ":", 2)[1]
			vs, fail := r.versions(ctx, g, a)
			if fail != nil {
				return fail
			}
			if !containsString(vs, v) {
				return manualFailure(ReasonMavenReleaseNotFound, "the property %s also sets the version of %s, which Maven Central does not publish at %s", k.prop, user, v)
			}
		}
	}

	// The edits of each file.
	edits := map[string][]mavenEdit{}
	rec := &MavenUpdate{}
	added := map[string]bool{}
	for _, pl := range plans {
		for _, place := range pl.places {
			e := place.edit
			to := pl.release
			if place.prop != "" {
				to = propValue[key{place.file, place.prop}]
			}
			e.Value = to
			id := fmt.Sprintf("%s|%d|%d|%s|%s:%s", place.file, e.Kind, e.Index, e.Name, e.GroupID, e.ArtifactID)
			if added[id] {
				continue
			}
			added[id] = true
			edits[place.file] = append(edits[place.file], e)
			rec.Edits = append(rec.Edits, MavenEditRecord{File: place.file, Kind: place.kind, Package: pl.name, Property: place.prop, From: place.from, To: to})
		}
	}
	after := map[string][]byte{}
	for p, c := range mf.content {
		if rx.byPath[p] != nil {
			after[p] = c
		}
	}
	var changed []string
	for file, es := range edits {
		out, err := applyMavenEdits(mf.content[file], es)
		if err != nil {
			return manualFailure(ReasonOutputFilesInvalid, "%s cannot be edited: %v", file, err)
		}
		after[file] = out
		changed = append(changed, file)
	}
	sort.Strings(changed)
	if len(changed) == 0 {
		return manualFailure(ReasonTargetNotUpdated, "no pom file needs a change")
	}
	r.it.UpdateExecuted = true
	r.it.PostUpdateCheckExecuted = true
	r.upd.Maven = rec

	releases := map[string]string{}
	for _, pl := range plans {
		releases[pl.name] = pl.release
	}
	fail = r.mavenSourceCheck(ctx, mf, after, releases)
	if fail != nil {
		return fail
	}
	for _, f := range changed {
		r.mavenArtifacts = append(r.mavenArtifacts, ArtifactFile{Path: f, SHA256: sha256Hex(after[f]), Size: int64(len(after[f])), Mode: mf.mode[f], Content: after[f]})
	}
	return nil
}

// mavenPlanned is a target, the release chosen for it and the places its
// version is decided; bomValues holds, for a place that is a BOM's import
// version, the BOM release that manages the target at the release.
type mavenPlanned struct {
	name, installed, release string
	places                   []mavenPlace
	bomValues                map[int]string
}

// planTarget finds where a target's version is decided and the release it
// moves to. A manual failure belongs to the target alone.
func (r *updateRun) planTarget(ctx context.Context, mf *mavenFiles, chains map[*mavenModule][]mavenChainPOM, n string) (mavenPlanned, *updateFailure) {
	p := r.it.Packages[r.set.byName[n][0]]
	r.clearHints(n)
	places, fail := r.placesOf(ctx, mf, chains, n)
	if fail != nil {
		r.setDecider(n, fail.decider)
		return mavenPlanned{}, fail
	}
	g, a := strings.SplitN(n, ":", 2)[0], strings.SplitN(n, ":", 2)[1]
	vs, fail := r.versions(ctx, g, a)
	if fail != nil {
		return mavenPlanned{}, fail
	}
	rel, ok := chooseRelease(vs, p.Installed, r.set.target[n])
	if !ok {
		r.otherMajorRelease(n, p.Installed, vs)
		return mavenPlanned{}, manualFailure(ReasonMavenReleaseNotFound, "Maven Central lists no release of %s at %s or above that can replace %s", n, r.set.target[n], p.Installed)
	}
	pl := mavenPlanned{name: n, installed: p.Installed, release: rel, places: places, bomValues: map[int]string{}}
	root := mf.rx.modules[0]
	for i, place := range places {
		if place.prop == "" {
			continue
		}
		// A property that something besides dependency versions reads, or
		// whose other packages Maven Central does not publish at the release,
		// is not changed: management decides the package instead when it can.
		why := ""
		if pluginRefs(chains, place.prop) {
			why = fmt.Sprintf("the property %s is also read outside dependency versions (by a plugin, another property or a profile, say)", place.prop)
		} else if e := propertyInExpression(chains, place.prop); e != "" {
			why = fmt.Sprintf("the property %s is also part of the version %s, which changing it would make another version", place.prop, e)
		} else if place.bom == "" {
			for _, user := range propertyUsers(chains, place.prop) {
				ug, ua := strings.SplitN(user, ":", 2)[0], strings.SplitN(user, ":", 2)[1]
				uvs, fail := r.versions(ctx, ug, ua)
				if fail != nil {
					return mavenPlanned{}, fail
				}
				if !containsString(uvs, rel) {
					why = fmt.Sprintf("the property %s also sets the version of %s, which Maven Central does not publish at %s", place.prop, user, rel)
					break
				}
			}
		} else {
			bv, managed, fail := r.bomRelease(ctx, place.bom, place.from, n, rel)
			if fail != nil {
				return mavenPlanned{}, fail
			}
			if bv == "" {
				why = fmt.Sprintf("no release of the BOM %s of the same minor version as %s manages %s at %s or above", place.bom, place.from, n, rel)
				// A package of a BOM moves with its set or not at all; a later
				// minor version of the BOM is named for a person to judge.
				raise := r.bomRaise(ctx, place, n, rel)
				if raise != nil {
					why += fmt.Sprintf("; its release %s, of a later minor version, manages it at %s", raise.To, raise.Manages)
				}
				for _, k := range r.full.byName[n] {
					r.it.Packages[k].MavenBOM = raise
				}
				return mavenPlanned{}, manualFailure(ReasonMavenBOMSeriesUnreached, "%s", why)
			} else {
				r.upd.Notes = append(r.upd.Notes, fmt.Sprintf("%s is managed by %s, whose version %s takes it to %s", n, place.bom, bv, managed))
				pl.bomValues[i] = bv
			}
		}
		if why == "" {
			continue
		}
		if !place.managed || place.bom != "" {
			// A package of a BOM moves with its set or not at all.
			return mavenPlanned{}, manualFailure(ReasonMavenVersionSourceUnsupported, "%s", why)
		}
		r.upd.Notes = append(r.upd.Notes, why+"; "+n+" is pinned in the root's dependencyManagement instead")
		pin := pinPlace(root, place.chain, n)
		pin.from, pin.managed = place.from, true
		pl.places[i] = pin
		delete(pl.bomValues, i)
	}
	return pl, nil
}

// mavenSourceCheck scans the reactor's pom files before and after through a
// Maven Central relay each, refuses a scan the relay or the files make
// incomplete, and judges the two as every update is judged, with new
// findings also compared per module.
func (r *updateRun) mavenSourceCheck(ctx context.Context, mf *mavenFiles, after map[string][]byte, releases map[string]string) *updateFailure {
	cfg := r.u.cfg
	dir := r.it.Source.Directory
	rel := func(files map[string][]byte) map[string][]byte {
		out := map[string][]byte{}
		for p, c := range files {
			if mf.rx.byPath[p] == nil {
				continue
			}
			k := p
			if dir != "." {
				k = strings.TrimPrefix(p, dir+"/")
			}
			out[k] = c
		}
		return out
	}
	before := map[string][]byte{}
	for p := range after {
		before[p] = mf.content[p]
	}
	reactor := map[string]string{}
	for _, m := range mf.rx.modules {
		reactor[m.coord] = m.pom.EffectiveVersion()
	}
	sc := &SourceCheck{CommitSHA: r.it.Source.CommitSHA, Before: hashedFiles(rel(before)), After: hashedFiles(rel(after))}
	r.check = sc
	scan := func(files map[string][]byte) (scanner.FSScan, *updateFailure) {
		relay, err := startMavenRelay(cfg.Maven, r.u.mavenCache, reactor, maxMavenRelayRequests)
		if err != nil {
			return scanner.FSScan{}, failedFailure(ReasonSourceScanFailed, "start the Maven Central relay: %v", err)
		}
		defer relay.Close()
		res, err := cfg.Scanner.ScanFSWith(ctx, rel(files), cfg.Prepared, scanner.FSOptions{MavenMirror: relay.URL()})
		switch {
		case err == nil:
		case errors.Is(err, scanner.ErrConditionsUnknown):
			return res, &updateFailure{category: CategoryNotComparable, reason: ReasonConditionsUnknown, detail: "the scan conditions of the cycle are not known"}
		case errors.Is(err, scanner.ErrConditionsDiffer):
			return res, &updateFailure{category: CategoryNotComparable, reason: ReasonConditionsDiffer, detail: clip(err.Error(), 300)}
		case ctx.Err() != nil:
			return res, &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		default:
			return res, failedFailure(ReasonSourceScanFailed, "%v", clip(err.Error(), 300))
		}
		var own []*mavenPOM
		for p, c := range files {
			if mf.rx.byPath[p] == nil {
				continue
			}
			pom, err := parseMavenPOM(c)
			if err != nil {
				return res, manualFailure(ReasonOutputFilesInvalid, "%s: %v", p, err)
			}
			own = append(own, pom)
		}
		problems := append(relay.Problems(), mavenAggregateProblems(append(relay.Fetched(), own...))...)
		for _, rp := range res.Report.Packages {
			if rp.Type != sourceScanTypes[ManagerMaven] {
				continue
			}
			for _, p := range rp.Packages {
				if p.Version == "" {
					problems = append(problems, fmt.Sprintf("the scan could not decide the version of %s in %s", p.Name, rp.Target))
				}
			}
		}
		if len(problems) > 0 {
			sort.Strings(problems)
			return res, &updateFailure{category: CategoryNotComparable, reason: ReasonSourceScanIncomplete,
				detail: clip(fmt.Sprintf("the scan through Maven Central cannot be relied on: %s", strings.Join(problems, "; ")), 600)}
		}
		return res, nil
	}
	b, fail := scan(before)
	if fail != nil {
		return fail
	}
	a, fail := scan(mergeFiles(mf, after))
	if fail != nil {
		return fail
	}
	sc.Conditions = a.Conditions
	if !b.Conditions.Equal(a.Conditions) {
		return &updateFailure{category: CategoryNotComparable, reason: ReasonConditionsDiffer, detail: "the scan conditions changed between the scan before the update and the scan after it"}
	}
	// The versions each target resolves to after the update, every one of
	// them at least the release chosen.
	typ := sourceScanTypes[ManagerMaven]
	r.afterVersions, r.adopted = map[string][]string{}, map[string]string{}
	resolved := func(s scanner.ImageScan) map[string][]string {
		out := map[string][]string{}
		for _, rp := range s.Packages {
			if rp.Type != typ {
				continue
			}
			for _, p := range rp.Packages {
				if !containsString(out[p.Name], p.Version) {
					out[p.Name] = append(out[p.Name], p.Version)
				}
			}
		}
		return out
	}
	vb, va := resolved(b.Report), resolved(a.Report)
	for n, want := range releases {
		for _, v := range va[n] {
			if c, ok := compareVersions(schemeMaven, v, want); !ok || c < 0 {
				holders, direct := mavenHolders(a.Report, n, v)
				r.setHolders(n, holders, direct, "")
				return pkgFailure(n, ReasonTargetNotUpdated, "the updated files resolve %s to %s, below %s", n, v, want)
			}
			if lo := r.adopted[n]; lo == "" {
				r.adopted[n] = v
			} else if c, _ := compareVersions(schemeMaven, v, lo); c < 0 {
				r.adopted[n] = v
			}
		}
		r.afterVersions[n] = va[n]
	}
	if fail := r.evaluateSourceCheck(sc, b.Report, a.Report); fail != nil {
		return fail
	}
	if fail := r.heldBack(ctx, releases, va); fail != nil {
		return fail
	}
	if intro := introducedPerTarget(typ, b.Report, a.Report); len(intro) > 0 {
		sc.Passed = false
		return manualFailure(ReasonSourceIntroduced, "the update brings findings into a module that did not have them: %s", strings.Join(intro, "; "))
	}
	// What moved besides the targets.
	var names []string
	for n := range vb {
		names = append(names, n)
	}
	for n := range va {
		if _, ok := vb[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if _, target := releases[n]; target {
			continue
		}
		from, to := append([]string(nil), vb[n]...), append([]string(nil), va[n]...)
		sort.Strings(from)
		sort.Strings(to)
		if strings.Join(from, ",") != strings.Join(to, ",") {
			r.upd.Maven.Moves = append(r.upd.Maven.Moves, MavenMove{Name: n, From: from, To: to})
		}
	}
	return nil
}

// heldBack requires every dependency a target's release declares (at
// compile or runtime scope, not optional, with a version its pom, parents or
// imported BOMs give), its own or inherited, to resolve after the update at
// that version or above, for every version the update resolves the target
// to. A target whose dependencies stay lower is left out, and the update is
// made again without it when others remain.
func (r *updateRun) heldBack(ctx context.Context, releases map[string]string, after map[string][]string) *updateFailure {
	out := map[string]updateFailureDetail{}
	var first *updateFailure
	for _, n := range stringKeys(releases) {
		g, a := strings.SplitN(n, ":", 2)[0], strings.SplitN(n, ":", 2)[1]
		var low []string
		for _, rel := range after[n] {
			needs, fail := r.declaredNeeds(ctx, g, a, rel)
			if fail != nil {
				return fail
			}
			for _, need := range needs {
				for _, got := range after[need[0]] {
					if c, ok := compareVersions(schemeMaven, got, need[1]); ok && c < 0 {
						low = append(low, fmt.Sprintf("%s %s (%s %s declares %s)", need[0], got, n, rel, need[1]))
					}
				}
			}
		}
		if len(low) == 0 {
			continue
		}
		sort.Strings(low)
		f := manualFailure(ReasonMavenDependencyHeldBack, "%s declares dependencies that the updated files resolve lower: %s", n, strings.Join(uniqueSorted(low), ", "))
		out[n] = updateFailureDetail{f.reason, f.detail}
		if first == nil {
			first = f
		}
	}
	if first == nil {
		return nil
	}
	first.pkgs = out
	if len(out) < len(releases) && r.attempt == 0 {
		first.retryWithout = out
	}
	return first
}

// declaredNeeds lists the dependencies g:a:v declares at compile or runtime
// scope (its own and those its parents declare, a child's over a parent's),
// with the version each is declared or managed at: written, managed by the
// pom or a parent, or managed by a BOM they import. A version range is not
// judged; a name or version that cannot be read fails the target.
func (r *updateRun) declaredNeeds(ctx context.Context, g, a, v string) ([][2]string, *updateFailure) {
	pom, fail := r.fetchPOM(ctx, g, a, v)
	if fail != nil {
		return nil, fail
	}
	chain := []mavenChainPOM{{pom: pom, coord: g + ":" + a + ":" + v}}
	for pa, depth := pom.Parent, 0; pa != nil && depth < maxMavenParentDepth; depth++ {
		pp, fail := r.fetchPOM(ctx, pa.GroupID, pa.ArtifactID, pa.Version)
		if fail != nil {
			return nil, fail
		}
		chain = append(chain, mavenChainPOM{pom: pp, coord: pa.GroupID + ":" + pa.ArtifactID + ":" + pa.Version})
		pa = pp.Parent
	}
	var out [][2]string
	seen := map[string]bool{}
	for _, c := range chain {
		for _, d := range c.pom.Dependencies {
			if d.IsImport() {
				continue
			}
			dg, ok1 := chainResolve(chain, d.GroupID)
			da, ok2 := chainResolve(chain, d.ArtifactID)
			if !ok1 || !ok2 {
				return nil, manualFailure(ReasonMavenDependencyHeldBack, "%s:%s:%s declares a dependency whose name cannot be read (%s:%s)", g, a, v, d.GroupID, d.ArtifactID)
			}
			name := dg + ":" + da
			if seen[name] {
				continue
			}
			seen[name] = true
			// The scope and optional are read with the properties first.
			if sc, ok := chainResolve(chain, d.Scope); ok || d.Scope == "" {
				d.Scope = sc
			}
			if op, ok := chainResolve(chain, d.Optional); ok || d.Optional == "" {
				d.Optional = op
			}
			if !mavenRuntimeScope(d) || d.Optional == "true" {
				continue
			}
			ver := d.Version
			if ver == "" {
				if ci, i := nearestManagement(chain, name); ci == mavenUnknown {
					return nil, manualFailure(ReasonMavenDependencyHeldBack, "%s:%s:%s manages a package whose name cannot be read, so the version it needs of %s is not known", g, a, v, name)
				} else if ci >= 0 {
					ver = chain[ci].pom.DependencyManagement[i].Version
				} else {
					bv, fail := r.bomManagedVersion(ctx, chain, name, 0)
					if fail != nil {
						return nil, fail
					}
					ver = bv
				}
			}
			want, ok := chainResolve(chain, ver)
			if !ok || want == "" {
				return nil, manualFailure(ReasonMavenDependencyHeldBack, "the version %s:%s:%s needs of %s cannot be read", g, a, v, name)
			}
			if isMavenVersionRange(want) {
				continue
			}
			out = append(out, [2]string{name, want})
		}
	}
	return out, nil
}

// bomManagedVersion is the version the first BOM the chain imports that
// manages name gives it, read in the BOM with its parents and its own
// imports (to a bounded depth); "" when none does.
func (r *updateRun) bomManagedVersion(ctx context.Context, chain []mavenChainPOM, name string, depth int) (string, *updateFailure) {
	if depth > 4 {
		return "", nil
	}
	for _, c := range chain {
		for _, d := range c.pom.DependencyManagement {
			if !d.IsImport() {
				continue
			}
			g, ok1 := chainResolve(chain, d.GroupID)
			a, ok2 := chainResolve(chain, d.ArtifactID)
			v, ok3 := chainResolve(chain, d.Version)
			if !ok1 || !ok2 || !ok3 {
				continue
			}
			bom, fail := r.fetchPOM(ctx, g, a, v)
			if fail != nil {
				return "", fail
			}
			bchain := []mavenChainPOM{{pom: bom, coord: g + ":" + a + ":" + v}}
			for pa, up := bom.Parent, 0; pa != nil && up < maxMavenParentDepth; up++ {
				pp, fail := r.fetchPOM(ctx, pa.GroupID, pa.ArtifactID, pa.Version)
				if fail != nil {
					return "", fail
				}
				bchain = append(bchain, mavenChainPOM{pom: pp, coord: pa.GroupID + ":" + pa.ArtifactID + ":" + pa.Version})
				pa = pp.Parent
			}
			ci, i := nearestManagement(bchain, name)
			if ci == mavenUnknown {
				return "", manualFailure(ReasonMavenDependencyHeldBack, "%s manages a package whose name cannot be read", g+":"+a+":"+v)
			}
			if ci >= 0 {
				// A BOM that manages the package decides its version; one whose
				// version cannot be read leaves it unknown, not to a BOM below.
				mv, ok := chainResolve(bchain, bchain[ci].pom.DependencyManagement[i].Version)
				if !ok {
					return "", manualFailure(ReasonMavenDependencyHeldBack, "%s manages %s at %s, which cannot be read", g+":"+a+":"+v, name, bchain[ci].pom.DependencyManagement[i].Version)
				}
				return mv, nil
			}
			mv, fail := r.bomManagedVersion(ctx, bchain, name, depth+1)
			if fail != nil || mv != "" {
				return mv, fail
			}
		}
	}
	return "", nil
}

// stringKeys lists the keys of a map of strings in order.
func stringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mergeFiles is every reactor pom, edited or not, with the edited content.
func mergeFiles(mf *mavenFiles, after map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for p, c := range mf.content {
		if mf.rx.byPath[p] != nil {
			out[p] = c
		}
	}
	for p, c := range after {
		out[p] = c
	}
	return out
}

// introducedPerTarget lists the (package, vulnerability) pairs that each
// scan target (a module's pom) reports after and not before: a finding
// another module already had is still new to the module it comes into.
func introducedPerTarget(typ string, before, after scanner.ImageScan) []string {
	pairs := func(s scanner.ImageScan) map[string]bool {
		out := map[string]bool{}
		for _, f := range s.Findings {
			if f.Type == typ {
				out[f.Target+"\x00"+f.Package+"\x00"+f.VulnID] = true
			}
		}
		return out
	}
	b, a := pairs(before), pairs(after)
	var out []string
	for k := range a {
		if !b[k] {
			parts := strings.SplitN(k, "\x00", 3)
			out = append(out, fmt.Sprintf("%s for %s in %s", parts[2], parts[1], parts[0]))
		}
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = append(out[:5], fmt.Sprintf("and %d more", len(out)-5))
	}
	return out
}
