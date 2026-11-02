package remediation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Reasons of the Gradle update.
const (
	// ReasonGradleVersionSourceUnsupported: the version of a target is decided
	// in a way no edit of the project's files changes (a Spring Boot BOM that
	// writes it as a literal, a catalog version a plugin shares, a package
	// declared in a configuration the standard inheritance does not cover).
	ReasonGradleVersionSourceUnsupported Reason = "gradle_version_source_unsupported"
	// ReasonGradleLockEntryRemoved: the update took an entry out of
	// gradle.lockfile. An entry that is gone cannot be told from a dependency
	// the build still needs, so the update is not proposed.
	ReasonGradleLockEntryRemoved Reason = "gradle_lock_entry_removed"
	// ReasonGradleLockConfigurationsChanged: the update changed which
	// configurations gradle.lockfile locks, or which of them it lists as
	// empty.
	ReasonGradleLockConfigurationsChanged Reason = "gradle_lock_configurations_changed"
	// ReasonGradleLockVersionUnsupported: the updated gradle.lockfile locks a
	// snapshot version.
	ReasonGradleLockVersionUnsupported Reason = "gradle_lock_version_unsupported"
)

// Kinds of GradleEditRecord.
const (
	GradleEditCatalogVersion   = "catalog_version"   // an entry of [versions] in the version catalog
	GradleEditCatalogLibrary   = "catalog_library"   // the version a library of the catalog writes itself
	GradleEditDeclaration      = "declaration"       // the version in a "group:artifact:version" of the build script
	GradleEditProperty         = "property"          // a property the project already sets, in gradle.properties or the build script
	GradleEditPropertyOverride = "property_override" // a property of the Spring Boot BOM, newly set in gradle.properties
	GradleEditConstraint       = "constraint"        // a dependency constraint added at the end of the build script
)

// GradleUpdate records the edits of a Gradle update and what moved with them.
type GradleUpdate struct {
	Edits []GradleEditRecord `json:"edits,omitempty"`
	// Moves are the packages besides the targets whose locked versions
	// changed or that the update added to gradle.lockfile.
	Moves []GradleMove `json:"moves,omitempty"`
	// Companions are the packages a property or a catalog version moves
	// besides the target, with the value they were checked to exist at on
	// Maven Central.
	Companions []GradleCompanion `json:"companions,omitempty"`
	// BOM is the Spring Boot BOM (group:artifact:version) the properties
	// written belong to.
	BOM string `json:"bom,omitempty"`
}

// GradleEditRecord is one change of a file of the project.
type GradleEditRecord struct {
	File     string `json:"file"`
	Kind     string `json:"kind"`
	Package  string `json:"package,omitempty"`
	Property string `json:"property,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to"`
}

// GradleMove is a package whose locked versions changed: From is empty for one
// the update added.
type GradleMove struct {
	Name string   `json:"name"`
	From []string `json:"from,omitempty"`
	To   []string `json:"to"`
}

// GradleCompanion lists the packages whose version a property or a catalog
// version sets together with a target.
type GradleCompanion struct {
	Key      string   `json:"key"`
	Value    string   `json:"value"`
	Packages []string `json:"packages"`
}

// The BOM of the Spring Boot plugin: the version of the plugin names the release.
const (
	springBootBOMGroup    = "org.springframework.boot"
	springBootBOMArtifact = "spring-boot-dependencies"
)

// gradleProject is the files of a Gradle unit as the update reads them, and
// what the recognizers of the plan make of them.
type gradleProject struct {
	dir     string
	content map[string][]byte // by repository path

	version   string // the Gradle version of the wrapper
	toolchain int

	buildPath, settingsPath, catalogPath, propsPath, lockPath, wrapperPath string
	hasCatalog, hasProps                                                   bool
	kotlin                                                                 bool

	cat    *gradleCatalog
	script *gradleScript
	props  []GradleProperty // the version properties of gradle.properties
	lock   *gradleLock

	bootVersion string
	depMgmt     bool
}

// gradleRefusal maps a refusal of a recognizer to a manual failure.
func gradleRefusal(err error) *updateFailure {
	var ue *UnsupportedError
	if errors.As(err, &ue) {
		return manualFailure(ue.Reason, "%s", ue.Detail)
	}
	return manualFailure(ReasonUnparsableSource, "%v", err)
}

// parseGradleProject reads the files of the unit with the recognizers the
// plan used. The same refusals as in the plan apply, so a project edited by
// the update is accepted only if it is still one the plan accepts.
func parseGradleProject(dir string, content map[string][]byte) (*gradleProject, *updateFailure) {
	p := &gradleProject{dir: dir, content: content}
	has := func(name string) bool { _, ok := content[pathIn(dir, name)]; return ok }
	pick := func(names []string) (string, *updateFailure) {
		var found []string
		for _, n := range names {
			if has(n) {
				found = append(found, n)
			}
		}
		if len(found) != 1 {
			return "", failedFailure(ReasonUpdateInputInvalid, "the project has %d of %s", len(found), strings.Join(names, " and "))
		}
		return found[0], nil
	}
	build, fail := pick(gradleBuildFiles)
	if fail != nil {
		return nil, fail
	}
	settings, fail := pick(gradleSettingsFiles)
	if fail != nil {
		return nil, fail
	}
	p.buildPath, p.settingsPath = pathIn(dir, build), pathIn(dir, settings)
	p.kotlin = strings.HasSuffix(build, ".kts")
	p.lockPath = pathIn(dir, "gradle.lockfile")
	p.wrapperPath = pathIn(dir, "gradle/wrapper/gradle-wrapper.properties")
	p.catalogPath = pathIn(dir, "gradle/libs.versions.toml")
	p.propsPath = pathIn(dir, "gradle.properties")
	p.hasCatalog, p.hasProps = has("gradle/libs.versions.toml"), has("gradle.properties")
	for _, f := range []string{p.lockPath, p.wrapperPath} {
		if _, ok := content[f]; !ok {
			return nil, failedFailure(ReasonUpdateInputInvalid, "the plan does not record %s", f)
		}
	}

	var err error
	if p.version, err = parseGradleWrapper(p.wrapperPath, content[p.wrapperPath]); err != nil {
		return nil, gradleRefusal(err)
	}
	if major, _, _ := strings.Cut(p.version, "."); !gradleMajors[major] {
		return nil, manualFailure(ReasonGradleVersionUnsupported, "the wrapper uses Gradle %s; only Gradle 8 and 9 are handled", p.version)
	}
	if p.hasCatalog {
		if p.cat, err = parseGradleCatalog(p.catalogPath, content[p.catalogPath]); err != nil {
			return nil, gradleRefusal(err)
		}
	}
	if p.hasProps {
		if p.props, err = parseGradleProperties(p.propsPath, content[p.propsPath]); err != nil {
			return nil, gradleRefusal(err)
		}
	}
	if _, err = recognizeGradleScript(p.settingsPath, content[p.settingsPath], true, nil, p.version); err != nil {
		return nil, gradleRefusal(err)
	}
	if p.script, err = recognizeGradleScript(p.buildPath, content[p.buildPath], false, p.cat, p.version); err != nil {
		return nil, gradleRefusal(err)
	}
	p.toolchain = gradleDefaultToolchain
	if p.script.toolchain != 0 {
		p.toolchain = p.script.toolchain
	}
	for _, pl := range p.script.plugins {
		switch pl.id {
		case gradleBootPlugin:
			p.bootVersion = pl.version
		case gradleDependencyMgmtPlugin:
			p.depMgmt = true
		}
	}
	if !gradleToolchains[p.toolchain] {
		return nil, manualFailure(ReasonGradleToolchainUnsupported, "the build asks for a Java %d toolchain; only 17, 21 and 25 are handled", p.toolchain)
	}
	if p.lock, err = parseGradleLockfile(p.lockPath, content[p.lockPath]); err != nil {
		return nil, gradleRefusal(err)
	}
	for _, c := range gradleRuntimeNeeded {
		if !p.lock.configs[c] {
			return nil, manualFailure(ReasonGradleLockingUnenforced, "%s lists no %s, so it does not cover the application", p.lockPath, c)
		}
	}
	return p, nil
}

// rel is the path of a file of the unit inside the unit's directory, the
// name the work container is given it under.
func (p *gradleProject) rel(repoPath string) string {
	if p.dir == "." || p.dir == "" {
		return repoPath
	}
	return strings.TrimPrefix(repoPath, p.dir+"/")
}

// readGradleSources reads again every file the plan recorded, requires the
// blobs it recorded and the places it found empty to be empty still.
func (r *updateRun) readGradleSources(ctx context.Context) (map[string][]byte, map[string]string, *updateFailure) {
	src := r.it.Source
	if src.CommitSHA == "" {
		return nil, nil, failedFailure(ReasonUpdateInputInvalid, "the plan recorded no commit")
	}
	gh := r.u.cfg.GitHub
	content, mode := map[string][]byte{}, map[string]string{}
	for _, f := range src.Files {
		if f.Repository != "" {
			return nil, nil, failedFailure(ReasonUpdateInputInvalid, "the plan records %s from another repository", f.Path)
		}
		got, err := gh.ReadFile(ctx, src.Repository, src.CommitSHA, f.Path)
		if err != nil {
			return nil, nil, readFailure(err, f.Path)
		}
		if got.SHA != f.BlobSHA || got.Path != f.Path {
			return nil, nil, failedFailure(ReasonSourceChanged, "%s is not the blob the plan was made from (%s, now %s)", f.Path, f.BlobSHA, got.SHA)
		}
		content[f.Path], mode[f.Path] = got.Content, got.Mode
	}
	for _, p := range src.Absent {
		_, err := gh.ReadFile(ctx, src.Repository, src.CommitSHA, p)
		var nr *github.NotRegularFileError
		switch {
		case errors.Is(err, github.ErrNotFound):
		case err == nil, errors.As(err, &nr), errors.Is(err, github.ErrLFSPointer), errors.Is(err, github.ErrTooLarge):
			return nil, nil, failedFailure(ReasonSourceChanged, "%s did not exist when the plan was made and does now", p)
		default:
			return nil, nil, readFailure(err, p)
		}
	}
	return content, mode, nil
}

// gradlePlace is where a target's version is decided and the edit that
// changes it.
type gradlePlace struct {
	kind string // a GradleEdit* kind
	file string // the repository path of the file to edit
	// name is the group:artifact of a declaration, a library or a constraint;
	// alias the library of the catalog; key the entry of [versions] or the
	// property.
	name, alias, key string
	from, to         string
	// inScript: the property is set by extra or ext in the build script.
	inScript bool
	// users are the packages the value is also the version of.
	users []string
	// bom is the group:artifact of the BOM a property sets the import version
	// of, "" for a property that sets the packages' versions.
	bom string
}

func (p gradlePlace) id() string {
	return strings.Join([]string{p.kind, p.file, p.name, p.alias, p.key}, "|")
}

// gradlePlanned is a target, the release chosen for it and the places its
// version is decided.
type gradlePlanned struct {
	name, installed, release string
	places                   []gradlePlace
}

// gradleImplementationConfs are the configurations of the lockfile that
// implementation feeds by the standard inheritance: a constraint on
// implementation reaches a package locked only in these.
var gradleImplementationConfs = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range gradleFeeds["implementation"] {
		m[c] = true
	}
	return m
}()

// runGradle is the update of a Gradle project: this program finds where each
// target's version is decided and changes it there, a work container makes
// gradle.lockfile again from the edited files, and the lockfile is checked
// here and scanned before and after.
func (r *updateRun) runGradle(ctx context.Context) *updateFailure {
	if r.u.cfg.Maven == nil {
		return failedFailure(ReasonUpdateInputInvalid, "no Maven Central client is configured")
	}
	r.noPartial = true
	r.mavenPOMs, r.mavenVersions = map[string]*mavenPOM{}, map[string][]string{}
	content, mode, fail := r.readGradleSources(ctx)
	if fail != nil {
		return fail
	}
	proj, fail := parseGradleProject(r.it.Source.Directory, content)
	if fail != nil {
		return fail
	}
	if len(r.set.names) > worker.MaxPackages {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdatePackageLimit,
			detail: fmt.Sprintf("the update names %d packages, more than the %d one job takes", len(r.set.names), worker.MaxPackages)}
	}

	// The work container runs the Gradle the wrapper names, on the JDK of the
	// toolchain the build asks for.
	spec, err := worker.FindGradleRuntime(proj.version, proj.toolchain, r.u.cfg.Platform)
	switch {
	case errors.Is(err, worker.ErrGradleVersionUnsupported):
		return manualFailure(ReasonGradleVersionUnsupported, "no work image runs Gradle %s", proj.version)
	case errors.Is(err, worker.ErrGradleToolchainUnsupported):
		return manualFailure(ReasonGradleToolchainUnsupported, "no work image runs Gradle %s on JDK %d", proj.version, proj.toolchain)
	case err != nil:
		return failedFailure(ReasonUpdateInputInvalid, "choose the runtime: %v", err)
	}
	r.toolSpec = ToolSpec{Manager: ManagerGradle, Runtime: spec.ID}

	// The Spring Boot BOM decides the versions of what the dependency
	// management plugin manages, and the names the project may set as
	// properties are the ones it defines.
	var bom []mavenChainPOM
	if proj.bootVersion == "" {
		// Without the Spring Boot plugin there is no BOM to say which names are
		// properties of it, so none is accepted.
		if all := append(append([]GradleProperty(nil), proj.props...), proj.script.props...); len(all) > 0 {
			return manualFailure(ReasonGradleBuildUnsupported, "%s sets the property %q, and the build applies no Spring Boot plugin whose BOM could define it", all[0].File, all[0].Name)
		}
	}
	if proj.bootVersion != "" {
		if bom, fail = r.gradleBOMChain(ctx, proj.bootVersion); fail != nil {
			return fail
		}
		for _, prop := range append(append([]GradleProperty(nil), proj.props...), proj.script.props...) {
			if propertyOwner(bom, prop.Name) < 0 {
				return manualFailure(ReasonGradleBuildUnsupported, "%s sets the property %q, which the Spring Boot BOM %s does not define", prop.File, prop.Name, proj.bootVersion)
			}
		}
	}

	var plans []gradlePlanned
	leftOut := map[string]updateFailureDetail{}
	var firstOut *updateFailure
	for _, n := range r.set.names {
		pl, fail := r.planGradleTarget(ctx, proj, bom, n)
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
		// left out of this run itself.
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

	places, fail := r.mergeGradlePlaces(ctx, plans)
	if fail != nil {
		return fail
	}
	after, rec, fail := r.applyGradleEdits(proj, plans, places)
	if fail != nil {
		return fail
	}
	if bom != nil {
		rec.BOM = springBootBOMGroup + ":" + springBootBOMArtifact + ":" + proj.bootVersion
	}
	rec.Companions = placesCompanions(places)
	r.upd.Gradle = rec

	// The edited project must still be one the plan accepts, and differ from
	// the original in the edits and nothing else.
	edited, fail := parseGradleProject(proj.dir, after)
	if fail != nil {
		return manualFailure(ReasonOutputFilesInvalid, "the edited files are not accepted when read again: %s", fail.detail)
	}
	if why := gradleEditMismatch(proj, edited, places); why != "" {
		return manualFailure(ReasonOutputFilesInvalid, "the edited files differ from what the edits were meant to make: %s", why)
	}

	// The job carries the unit's files as edited, at the paths they have in
	// the repository relative to its directory.
	inputs := map[string][]byte{}
	for p, c := range after {
		inputs[proj.rel(p)] = c
	}
	var pkgs []worker.Package
	for _, pl := range plans {
		if _, gone := r.leftOut[pl.name]; !gone {
			pkgs = append(pkgs, worker.Package{Name: pl.name})
		}
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	steps := []worker.Step{{ID: stepUpdate, Op: worker.OpGradleUpdateLocks, Packages: pkgs}}
	out, fail := r.exec(ctx, worker.ManagerGradle, inputs, steps, "update")
	if fail != nil {
		return fail
	}
	r.it.PostUpdateCheckExecuted = true

	releases := map[string]string{}
	for _, pl := range plans {
		if _, gone := r.leftOut[pl.name]; !gone {
			releases[pl.name] = pl.release
		}
	}
	newLock, fail := r.checkGradleOutput(ctx, proj, out, inputs, releases)
	if fail != nil {
		return fail
	}

	nl, err := parseGradleLockfile("gradle.lockfile", newLock)
	if err != nil {
		return gradleRefusal(err)
	}
	r.gradleLocks = [2]*gradleLock{proj.lock, nl}
	fail = r.sourceCheck(ctx,
		map[string][]byte{"gradle.lockfile": content[proj.lockPath]},
		map[string][]byte{"gradle.lockfile": newLock})
	if fail != nil {
		return fail
	}
	var changed []string
	for p, c := range after {
		if p == proj.lockPath {
			continue
		}
		if orig, ok := content[p]; !ok || string(orig) != string(c) {
			changed = append(changed, p)
		}
	}
	changed = append(changed, proj.lockPath)
	sort.Strings(changed)
	for _, p := range changed {
		c := after[p]
		if p == proj.lockPath {
			c = newLock
		}
		m := mode[p]
		if m == "" {
			m = "100644"
		}
		r.gradleArtifacts = append(r.gradleArtifacts, ArtifactFile{Path: p, SHA256: sha256Hex(c), Size: int64(len(c)), Mode: m, Content: c})
	}
	return nil
}

// gradleBOMChain is the BOM of the Spring Boot plugin of the given version
// with its parents, the BOM first.
func (r *updateRun) gradleBOMChain(ctx context.Context, version string) ([]mavenChainPOM, *updateFailure) {
	pom, fail := r.fetchPOM(ctx, springBootBOMGroup, springBootBOMArtifact, version)
	if fail != nil {
		return nil, fail
	}
	chain := []mavenChainPOM{{pom: pom, coord: springBootBOMGroup + ":" + springBootBOMArtifact + ":" + version}}
	for pa, depth := pom.Parent, 0; pa != nil; depth++ {
		if depth >= maxMavenParentDepth {
			return nil, manualFailure(ReasonGradleVersionSourceUnsupported, "the parents of the Spring Boot BOM go deeper than %d levels", maxMavenParentDepth)
		}
		pp, fail := r.fetchPOM(ctx, pa.GroupID, pa.ArtifactID, pa.Version)
		if fail != nil {
			return nil, fail
		}
		chain = append(chain, mavenChainPOM{pom: pp, coord: pa.GroupID + ":" + pa.ArtifactID + ":" + pa.Version})
		pa = pp.Parent
	}
	return chain, nil
}

// bomProperty is the property of the Spring Boot BOM that decides a package's
// version: the property the package's management reads, or the one that sets
// the version of the BOM it imports (bom is then that BOM).
type bomProperty struct {
	prop, from, bom string
}

// gradleBOMProperty finds the property of the BOM that decides the version
// of name. managed is false when the BOM does not manage it.
func (r *updateRun) gradleBOMProperty(ctx context.Context, chain []mavenChainPOM, name string) (bp bomProperty, managed bool, fail *updateFailure) {
	unreadable := func() *updateFailure {
		return manualFailure(ReasonGradleVersionSourceUnsupported, "a management entry of the Spring Boot BOM has a name that cannot be read, so where the version of %s is decided is not known", name)
	}
	switch ci, i := nearestManagement(chain, name); {
	case ci == mavenUnknown:
		return bp, false, unreadable()
	case ci >= 0:
		text := chain[ci].pom.DependencyManagement[i].Version
		p, ok := mavenPropertyRef(text)
		if !ok || propertyOwner(chain, p) < 0 {
			return bp, false, manualFailure(ReasonGradleVersionSourceUnsupported, "%s is managed by the Spring Boot BOM at %q, which is not one property the project can set", name, text)
		}
		from, _ := chainResolve(chain, text)
		return bomProperty{prop: p, from: from}, true, nil
	}
	var found []bomProperty
	for _, c := range chain {
		for _, d := range c.pom.DependencyManagement {
			if !d.IsImport() {
				continue
			}
			g, ok1 := chainResolve(chain, d.GroupID)
			a, ok2 := chainResolve(chain, d.ArtifactID)
			v, ok3 := chainResolve(chain, d.Version)
			if !ok1 || !ok2 || !ok3 {
				return bp, false, manualFailure(ReasonGradleVersionSourceUnsupported, "a BOM the Spring Boot BOM imports is named with an expression that cannot be resolved")
			}
			direct, nested, fail := r.bomManagesDeep(ctx, g, a, v, name, 0)
			if fail != nil {
				return bp, false, fail
			}
			if !direct && !nested {
				continue
			}
			p, isRef := mavenPropertyRef(d.Version)
			if !direct || !isRef || propertyOwner(chain, p) < 0 {
				return bp, false, manualFailure(ReasonGradleVersionSourceUnsupported, "%s is managed by the BOM %s:%s, whose version is not a property the project can set to move the set, and a package of a BOM is not pinned apart from its set", name, g, a)
			}
			cand := bomProperty{prop: p, from: v, bom: g + ":" + a}
			dup := false
			for _, f := range found {
				dup = dup || f == cand
			}
			if !dup {
				found = append(found, cand)
			}
		}
	}
	switch len(found) {
	case 0:
		return bp, false, nil
	case 1:
		return found[0], true, nil
	}
	return bp, false, manualFailure(ReasonGradleVersionSourceUnsupported, "%s is managed by more than one BOM the Spring Boot BOM imports", name)
}

// planGradleTarget finds where a target's version is decided and the release
// it moves to. A manual failure belongs to the target alone.
func (r *updateRun) planGradleTarget(ctx context.Context, proj *gradleProject, bom []mavenChainPOM, n string) (gradlePlanned, *updateFailure) {
	p := r.it.Packages[r.set.byName[n][0]]
	installed := p.Installed
	g, a := strings.SplitN(n, ":", 2)[0], strings.SplitN(n, ":", 2)[1]
	vs, fail := r.versions(ctx, g, a)
	if fail != nil {
		return gradlePlanned{}, fail
	}
	rel, ok := chooseRelease(vs, installed, r.set.target[n])
	if !ok {
		return gradlePlanned{}, manualFailure(ReasonMavenReleaseNotFound, "Maven Central lists no release of %s at %s or above that can replace %s", n, r.set.target[n], installed)
	}
	pl := gradlePlanned{name: n, installed: installed, release: rel}

	// The configurations the package is locked in at all.
	var confs []string
	for _, i := range proj.lock.byName[n] {
		for _, c := range proj.lock.entries[i].confs {
			if !containsString(confs, c) {
				confs = append(confs, c)
			}
		}
	}

	// A declaration of the package in the project: its version is the one to
	// change, when it is the version that resolves.
	unversioned := false
	for _, d := range proj.script.decls {
		if d.constraint || d.name != n {
			continue
		}
		switch {
		case d.version == "":
			unversioned = true
			continue
		case !versionsEqual(schemeMaven, d.version, installed):
			return pl, manualFailure(ReasonGradleVersionSourceUnsupported, "%s is declared at %s while the lockfile resolves it to %s, so the declaration is not what decides the version", n, d.version, installed)
		case d.catalog == "":
			pl.places = append(pl.places, gradlePlace{kind: GradleEditDeclaration, file: proj.buildPath, name: n, from: d.version, to: rel})
			continue
		}
		lib := proj.cat.libs[accessorForm.Replace(d.catalog)]
		if lib.versionRef == "" {
			pl.places = append(pl.places, gradlePlace{kind: GradleEditCatalogLibrary, file: proj.catalogPath, name: n, alias: lib.alias, from: lib.version, to: rel})
			continue
		}
		if proj.cat.pluginVersionRefs[lib.versionRef] {
			return pl, manualFailure(ReasonGradleVersionSourceUnsupported, "the catalog version %q of %s is also the version of a plugin, which the update does not change", lib.versionRef, n)
		}
		place := gradlePlace{kind: GradleEditCatalogVersion, file: proj.catalogPath, key: lib.versionRef, from: lib.version, to: rel}
		for _, other := range proj.cat.libs {
			if other.versionRef == lib.versionRef && other.group+":"+other.artifact != n {
				place.users = append(place.users, other.group+":"+other.artifact)
			}
		}
		pl.places = append(pl.places, place)
	}
	if unversioned && len(pl.places) > 0 {
		return pl, manualFailure(ReasonGradleVersionSourceUnsupported, "%s is declared both with a version and without one", n)
	}
	if len(pl.places) > 0 {
		pl.places = dedupeGradlePlaces(pl.places)
		return pl, tryGradlePlaces(proj, n, pl.places)
	}

	// The version is decided by the Spring Boot BOM, or by nothing the
	// project writes: a property of the BOM, or a constraint.
	if proj.depMgmt && bom != nil {
		bp, managed, fail := r.gradleBOMProperty(ctx, bom, n)
		if fail != nil {
			return pl, fail
		}
		if managed {
			place, fail := r.gradlePropertyPlace(ctx, proj, bom, bp, n, rel)
			if fail != nil {
				return pl, fail
			}
			pl.places = []gradlePlace{place}
			return pl, tryGradlePlaces(proj, n, pl.places)
		}
	}
	if unversioned {
		return pl, manualFailure(ReasonGradleVersionSourceUnsupported, "%s is declared without a version, and no BOM of the project manages it", n)
	}
	for _, c := range confs {
		if !gradleImplementationConfs[c] {
			return pl, manualFailure(ReasonGradleVersionSourceUnsupported, "%s is locked in %s, which a constraint on implementation does not reach", n, c)
		}
	}
	pl.places = []gradlePlace{{kind: GradleEditConstraint, file: proj.buildPath, name: n, to: rel}}
	return pl, nil
}

// gradlePropertyPlace is the place of a property of the Spring Boot BOM that
// decides the version of n: the project's own setting of it when there is
// exactly one, else a new line in gradle.properties.
func (r *updateRun) gradlePropertyPlace(ctx context.Context, proj *gradleProject, bom []mavenChainPOM, bp bomProperty, n, rel string) (gradlePlace, *updateFailure) {
	chains := map[*mavenModule][]mavenChainPOM{{}: bom}
	if e := propertyInExpression(chains, bp.prop); e != "" {
		return gradlePlace{}, manualFailure(ReasonGradleVersionSourceUnsupported, "the property %s is also part of the version %s, which changing it would make another version", bp.prop, e)
	}
	place := gradlePlace{kind: GradleEditPropertyOverride, file: proj.propsPath, key: bp.prop, bom: bp.bom}
	// Where the project sets the property now.
	var inProps, inScript []GradleProperty
	for _, p := range proj.props {
		if p.Name == bp.prop {
			inProps = append(inProps, p)
		}
	}
	for _, p := range proj.script.props {
		if p.Name == bp.prop {
			inScript = append(inScript, p)
		}
	}
	switch {
	case len(inProps)+len(inScript) > 1:
		return gradlePlace{}, manualFailure(ReasonGradleVersionSourceUnsupported, "the property %s is set more than once in the project", bp.prop)
	case len(inProps) == 1:
		place.kind, place.from = GradleEditProperty, inProps[0].Value
	case len(inScript) == 1:
		place.kind, place.from, place.file, place.inScript = GradleEditProperty, inScript[0].Value, proj.buildPath, true
	default:
		place.from = bp.from
	}
	if bp.bom == "" {
		// The property sets the version of packages: each of them must exist
		// at the new value.
		place.to = rel
		for _, u := range propertyUsers(chains, bp.prop) {
			if u != n {
				place.users = append(place.users, u)
			}
		}
		return place, nil
	}
	// The property sets the version of a BOM that manages the package: the
	// lowest release of it in the same minor version that reaches the target.
	current := place.from
	bv, managed, fail := r.bomRelease(ctx, bp.bom, current, n, rel)
	if fail != nil {
		return gradlePlace{}, fail
	}
	if bv == "" {
		why := fmt.Sprintf("no release of the BOM %s of the same minor version as %s manages %s at %s or above", bp.bom, current, n, rel)
		raise := r.bomRaise(ctx, mavenPlace{prop: bp.prop, from: current, bom: bp.bom}, n, rel)
		if raise != nil {
			why += fmt.Sprintf("; its release %s, of a later minor version, manages it at %s", raise.To, raise.Manages)
		}
		for _, k := range r.full.byName[n] {
			r.it.Packages[k].MavenBOM = raise
		}
		return gradlePlace{}, manualFailure(ReasonMavenBOMSeriesUnreached, "%s", why)
	}
	r.upd.Notes = append(r.upd.Notes, fmt.Sprintf("%s is managed by %s, whose version %s takes it to %s", n, bp.bom, bv, managed))
	place.to = bv
	return place, nil
}

func dedupeGradlePlaces(ps []gradlePlace) []gradlePlace {
	seen := map[string]bool{}
	var out []gradlePlace
	for _, p := range ps {
		if !seen[p.id()] {
			seen[p.id()] = true
			out = append(out, p)
		}
	}
	return out
}

// mergeGradlePlaces gives every place its final value (a place several
// targets share takes the highest) and checks that the packages a value is
// also the version of exist at it on Maven Central. The places are returned
// by id.
func (r *updateRun) mergeGradlePlaces(ctx context.Context, plans []gradlePlanned) (map[string]gradlePlace, *updateFailure) {
	places := map[string]gradlePlace{}
	for _, pl := range plans {
		for _, p := range pl.places {
			old, ok := places[p.id()]
			if ok {
				if c, ok := compareVersions(schemeMaven, p.to, old.to); !ok || c <= 0 {
					p = old
				}
				p.users = uniqueSorted(append(append([]string(nil), old.users...), p.users...))
			}
			places[p.id()] = p
		}
	}
	for _, id := range sortedMapKeys(places) {
		p := places[id]
		for _, u := range p.users {
			g, a := strings.SplitN(u, ":", 2)[0], strings.SplitN(u, ":", 2)[1]
			vs, fail := r.versions(ctx, g, a)
			if fail != nil {
				return nil, fail
			}
			if !containsString(vs, p.to) {
				what := "the property " + p.key
				if p.kind == GradleEditCatalogVersion {
					what = "the catalog version " + p.key
				}
				return nil, manualFailure(ReasonMavenReleaseNotFound, "%s also sets the version of %s, which Maven Central does not publish at %s", what, u, p.to)
			}
		}
	}
	return places, nil
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// placesCompanions lists, for the places that set the version of more than
// one package, the packages and the value.
func placesCompanions(places map[string]gradlePlace) []GradleCompanion {
	var out []GradleCompanion
	for _, id := range sortedMapKeys(places) {
		p := places[id]
		if len(p.users) > 0 {
			out = append(out, GradleCompanion{Key: p.key, Value: p.to, Packages: p.users})
		}
	}
	return out
}

// applyGradleEdits makes the edited files from the original ones. The edits
// are made on the text of each file (see lang_gradle_edit.go); a file that
// does not exist yet is made from nothing.
func (r *updateRun) applyGradleEdits(proj *gradleProject, plans []gradlePlanned, places map[string]gradlePlace) (map[string][]byte, *GradleUpdate, *updateFailure) {
	after := map[string][]byte{}
	for p, c := range proj.content {
		after[p] = c
	}
	rec := &GradleUpdate{}
	// owner is the first target that placed each place, for the record.
	owner := map[string]string{}
	for _, pl := range plans {
		if _, gone := r.leftOut[pl.name]; gone {
			continue
		}
		for _, p := range pl.places {
			if _, ok := owner[p.id()]; !ok {
				owner[p.id()] = pl.name
			}
		}
	}
	fail := func(p gradlePlace, err error) *updateFailure {
		return manualFailure(ReasonOutputFilesInvalid, "%s cannot be edited: %v", p.file, err)
	}
	var constraints []gradleConstraint
	for _, id := range sortedMapKeys(places) {
		p := places[id]
		if _, ok := owner[id]; !ok {
			continue // a place of a target that was left out
		}
		if p.kind == GradleEditConstraint {
			constraints = append(constraints, gradleConstraint{name: p.name, version: p.to})
		} else if err := applyGradlePlace(proj, after, p); err != nil {
			return nil, nil, fail(p, err)
		}
		er := GradleEditRecord{File: p.file, Kind: p.kind, Package: owner[id], From: p.from, To: p.to}
		if p.kind == GradleEditProperty || p.kind == GradleEditPropertyOverride || p.kind == GradleEditCatalogVersion {
			er.Property = p.key
		}
		rec.Edits = append(rec.Edits, er)
	}
	if len(constraints) > 0 {
		after[proj.buildPath] = appendGradleConstraints(after[proj.buildPath], proj.kotlin, constraints)
	}
	changed := false
	for p, c := range after {
		if orig, ok := proj.content[p]; !ok || string(orig) != string(c) {
			changed = true
		}
	}
	if !changed {
		return nil, nil, manualFailure(ReasonTargetNotUpdated, "no file of the project needs a change")
	}
	sort.SliceStable(rec.Edits, func(i, j int) bool {
		a, b := rec.Edits[i], rec.Edits[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Package < b.Package
	})
	return after, rec, nil
}

// applyGradlePlace makes the edit of one place in after, the files by
// repository path. A constraint is not made here: they are added together.
func applyGradlePlace(proj *gradleProject, after map[string][]byte, p gradlePlace) error {
	var err error
	switch p.kind {
	case GradleEditCatalogVersion:
		after[p.file], err = setCatalogVersion(after[p.file], p.key, p.from, p.to)
	case GradleEditCatalogLibrary:
		after[p.file], err = setCatalogLibrary(after[p.file], p.alias, p.name, p.from, p.to)
	case GradleEditDeclaration:
		after[p.file], err = replaceGradleCoordinate(after[p.file], proj.kotlin, p.name, p.from, p.to)
	case GradleEditProperty:
		if p.inScript {
			after[p.file], err = setGradleExtra(after[p.file], proj.kotlin, p.key, p.from, p.to)
		} else {
			after[p.file], err = setPropertiesValue(after[p.file], p.key, p.from, p.to)
		}
	case GradleEditPropertyOverride:
		after[p.file] = appendProperty(after[p.file], p.key, p.to)
	case GradleEditConstraint:
	default:
		err = fmt.Errorf("unknown edit %q", p.kind)
	}
	return err
}

// tryGradlePlaces makes the edits of a target's places on the original files
// to see whether each finds the one place it is for: a version written
// twice, or in a form the edit does not follow, belongs to the target alone.
func tryGradlePlaces(proj *gradleProject, n string, ps []gradlePlace) *updateFailure {
	scratch := map[string][]byte{}
	for p, c := range proj.content {
		scratch[p] = c
	}
	for _, p := range ps {
		if err := applyGradlePlace(proj, scratch, p); err != nil {
			return manualFailure(ReasonGradleVersionSourceUnsupported, "the version of %s cannot be changed where it is decided (%s): %v", n, p.file, err)
		}
	}
	return nil
}

// gradleEditMismatch compares the project read again after the edits with
// the original: the version catalog, the declarations and the properties
// must have changed exactly as the edits say, and the plugins, the toolchain
// and the rest of what the recognizers read must be the same.
func gradleEditMismatch(old, edited *gradleProject, places map[string]gradlePlace) string {
	if old.version != edited.version || old.toolchain != edited.toolchain || old.bootVersion != edited.bootVersion || old.depMgmt != edited.depMgmt ||
		old.script.compileOnlyExtendsAP != edited.script.compileOnlyExtendsAP || old.script.rootName != edited.script.rootName {
		return "the Gradle version, the toolchain or the plugins changed"
	}
	if !reflect.DeepEqual(old.script.plugins, edited.script.plugins) {
		return "the plugins changed"
	}
	// The catalog.
	if (old.cat == nil) != (edited.cat == nil) {
		return "the version catalog appeared or went"
	}
	versions := map[string]string{}
	libs := map[string]gradleCatLib{}
	if old.cat != nil {
		for k, v := range old.cat.versions {
			versions[k] = v
		}
		for k, v := range old.cat.libs {
			libs[k] = v
		}
		for _, p := range places {
			switch p.kind {
			case GradleEditCatalogVersion:
				versions[p.key] = p.to
				for k, l := range libs {
					if l.versionRef == p.key {
						l.version = p.to
						libs[k] = l
					}
				}
			case GradleEditCatalogLibrary:
				k := accessorForm.Replace(p.alias)
				l := libs[k]
				l.version = p.to
				libs[k] = l
			}
		}
		if !reflect.DeepEqual(versions, edited.cat.versions) || !reflect.DeepEqual(libs, edited.cat.libs) ||
			!reflect.DeepEqual(old.cat.bundles, edited.cat.bundles) || !reflect.DeepEqual(old.cat.pluginVersionRefs, edited.cat.pluginVersionRefs) {
			return "the version catalog differs"
		}
	}
	// The declarations.
	norm := func(ds []gradleDecl) []gradleDecl {
		out := append([]gradleDecl(nil), ds...)
		for i := range out {
			out[i].line = 0
		}
		return out
	}
	want := norm(old.script.decls)
	for i, d := range want {
		switch {
		case d.catalog != "" && old.cat != nil:
			want[i].version = libs[accessorForm.Replace(d.catalog)].version
		case d.catalog == "" && !d.constraint:
			for _, p := range places {
				if p.kind == GradleEditDeclaration && p.name == d.name && p.from == d.version {
					want[i].version = p.to
				}
			}
		}
	}
	for _, p := range places {
		if p.kind == GradleEditConstraint {
			want = append(want, gradleDecl{conf: "implementation", name: p.name, version: p.to, constraint: true})
		}
	}
	got := norm(edited.script.decls)
	sortDecls := func(ds []gradleDecl) {
		sort.SliceStable(ds, func(i, j int) bool {
			a, b := ds[i], ds[j]
			if a.constraint != b.constraint {
				return !a.constraint
			}
			return a.name+"|"+a.conf+"|"+a.version < b.name+"|"+b.conf+"|"+b.version
		})
	}
	sortDecls(want)
	sortDecls(got)
	if !reflect.DeepEqual(want, got) {
		return "the dependency declarations differ"
	}
	// The properties.
	propSet := func(ps ...[]GradleProperty) []string {
		var out []string
		for _, l := range ps {
			for _, p := range l {
				out = append(out, p.File+"|"+p.Name+"|"+p.Value)
			}
		}
		sort.Strings(out)
		return out
	}
	wantProps := map[string]GradleProperty{}
	for _, l := range [][]GradleProperty{old.props, old.script.props} {
		for _, p := range l {
			wantProps[p.File+"|"+p.Name] = p
		}
	}
	for _, p := range places {
		switch p.kind {
		case GradleEditProperty, GradleEditPropertyOverride:
			wantProps[p.file+"|"+p.key] = GradleProperty{Name: p.key, Value: p.to, File: p.file}
		}
	}
	var wantList []GradleProperty
	for _, p := range wantProps {
		wantList = append(wantList, p)
	}
	if !reflect.DeepEqual(propSet(wantList), propSet(edited.props, edited.script.props)) {
		return "the properties differ"
	}
	return ""
}
