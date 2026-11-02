package remediation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// gradleDefaultToolchain is the Java version used when the build declares no
// toolchain.
const gradleDefaultToolchain = 21

// gradleToolchains are the Java versions a build of the update is available
// for.
var gradleToolchains = map[int]bool{17: true, 21: true, 25: true}

// gradleMajors are the Gradle major versions a build of the update is
// available for.
var gradleMajors = map[string]bool{"8": true, "9": true}

// gradleBuildFiles and gradleSettingsFiles are the names of the scripts, one
// of each kind at most.
var (
	gradleBuildFiles    = []string{"build.gradle", "build.gradle.kts"}
	gradleSettingsFiles = []string{"settings.gradle", "settings.gradle.kts"}
)

// gradleRuntimeNeeded are the configurations a lockfile must list, as entries
// or among those it lists as empty: without them it does not cover the
// application.
var gradleRuntimeNeeded = []string{"compileClasspath", "runtimeClasspath"}

// analyseGradleUnit plans the Gradle item of a unit whose directory has a
// gradle.lockfile or a build script (and no pom.xml). Gradle's coordinates of the application
// itself cannot be read from the files, so every jar finding of the images is
// matched by name and version against the lockfile. The build scripts are
// only read, never run: the unit goes on only when they are written in the
// forms the recognizer accepts and set the build to build exactly what the
// lockfile lists. Nothing is resolved or updated here. It returns whether the
// unit has an item.
func (r *run) analyseGradleUnit(it *LanguageItem, u *depUnit, entries []github.Entry) bool {
	gh := r.p.cfg.GitHub
	sha := it.Source.CommitSHA
	all := groupLanguageFindings(u.jarPinned, r.p.cfg.Intel)
	if len(all) == 0 {
		return false
	}
	setPriorityOf(it, all)
	it.Manager = ManagerGradle
	it.Key = u.key + "#" + string(ManagerGradle)
	manual := func(reason Reason, format string, args ...any) bool {
		unitManual(it, all, reason, fmt.Sprintf(format, args...))
		return true
	}

	present := map[string]bool{}
	for _, name := range append(append([]string{"gradle.lockfile", "gradle.properties", "settings-gradle.lockfile", "buildscript-gradle.lockfile"}, gradleBuildFiles...), gradleSettingsFiles...) {
		e, ok := byName(entries, name)
		if ok && e.Type != github.EntryFile {
			return manual(ReasonDependencyFileUnusable, "%s is a %s", pathIn(u.dir, name), e.Type)
		}
		if present[name] = ok; !ok {
			it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, name))
		}
	}
	if !present["gradle.lockfile"] {
		return manual(ReasonDependencyFilesNotFound, "the directory has a Gradle build script but no gradle.lockfile; a gradle.lockfile with dependency locking is required for Gradle updates")
	}
	if _, ok := byName(entries, "buildSrc"); ok {
		return manual(ReasonGradleBuildUnsupported, "%s exists; code in buildSrc runs in every build and is not handled", pathIn(u.dir, "buildSrc"))
	}
	it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, "buildSrc"))
	// pick names the one script of a kind; stop is set when the item has its
	// outcome.
	pick := func(names []string, what string, required bool) (name string, stop bool) {
		var found []string
		for _, n := range names {
			if present[n] {
				found = append(found, n)
			}
		}
		switch {
		case len(found) > 1:
			return "", manual(ReasonAmbiguousDependencyFile, "the directory has %s", strings.Join(found, " and "))
		case len(found) == 0 && required:
			return "", manual(ReasonDependencyFilesNotFound, "the directory has gradle.lockfile but no %s", what)
		case len(found) == 0:
			return "", false
		}
		return found[0], false
	}
	buildName, stop := pick(gradleBuildFiles, "build.gradle or build.gradle.kts", true)
	if stop {
		return true
	}
	// Gradle looks for a settings file in the directories above when there is
	// none here, and such a file could include this project and change its
	// locking, so one in the directory itself is required.
	settingsName, stop := pick(gradleSettingsFiles, "settings.gradle or settings.gradle.kts; a settings file in the directory is required", true)
	if stop {
		return true
	}

	// The gradle directory: the wrapper (required), the version catalog, and
	// the per-configuration lockfiles, which are not handled.
	listSub := func(dir string) ([]github.Entry, bool) {
		if h := r.stopReason(); h != nil {
			r.deferUnit(it, all, h.reason, h.detail)
			return nil, false
		}
		es, err := gh.ListDirectory(r.ctx, u.repo, sha, dir)
		switch {
		case errors.Is(err, github.ErrNotFound):
			return nil, true
		case err != nil:
			r.sourceFailure(it, all, err, false)
			return nil, false
		}
		return es, true
	}
	var gradleDir, wrapperDir []github.Entry
	var ok bool
	if e, found := byName(entries, "gradle"); found {
		if e.Type != github.EntryDir {
			return manual(ReasonDependencyFileUnusable, "%s is a %s", pathIn(u.dir, "gradle"), e.Type)
		}
		if gradleDir, ok = listSub(pathIn(u.dir, "gradle")); !ok {
			return true
		}
	}
	if _, found := byName(gradleDir, "dependency-locks"); found {
		return manual(ReasonGradleBuildUnsupported, "%s exists; per-configuration lockfiles are not handled", pathIn(u.dir, "gradle/dependency-locks"))
	}
	it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, "gradle/dependency-locks"))
	if e, found := byName(gradleDir, "wrapper"); found {
		if e.Type != github.EntryDir {
			return manual(ReasonDependencyFileUnusable, "%s is a %s", pathIn(u.dir, "gradle/wrapper"), e.Type)
		}
		if wrapperDir, ok = listSub(pathIn(u.dir, "gradle/wrapper")); !ok {
			return true
		}
	}
	const wrapperName = "gradle/wrapper/gradle-wrapper.properties"
	if e, found := byName(wrapperDir, "gradle-wrapper.properties"); !found {
		return manual(ReasonDependencyFilesNotFound, "the directory has gradle.lockfile but no %s", wrapperName)
	} else if e.Type != github.EntryFile {
		return manual(ReasonDependencyFileUnusable, "%s is a %s", pathIn(u.dir, wrapperName), e.Type)
	}
	const catalogName = "gradle/libs.versions.toml"
	hasCatalog := false
	if e, found := byName(gradleDir, "libs.versions.toml"); found {
		if e.Type != github.EntryFile {
			return manual(ReasonDependencyFileUnusable, "%s is a %s", pathIn(u.dir, catalogName), e.Type)
		}
		hasCatalog = true
	} else {
		it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, catalogName))
	}

	read := func(name string) ([]byte, bool) {
		if h := r.stopReason(); h != nil {
			r.deferUnit(it, all, h.reason, h.detail)
			return nil, false
		}
		f, err := gh.ReadFile(r.ctx, u.repo, sha, pathIn(u.dir, name))
		if err != nil {
			r.sourceFailure(it, all, err, true)
			return nil, false
		}
		it.Source.Files = append(it.Source.Files, SourceFile{Path: f.Path, BlobSHA: f.SHA})
		return f.Content, true
	}
	names := []string{"gradle.lockfile", wrapperName, buildName, settingsName}
	if hasCatalog {
		names = append(names, catalogName)
	}
	for _, n := range []string{"gradle.properties", "settings-gradle.lockfile", "buildscript-gradle.lockfile"} {
		if present[n] {
			names = append(names, n)
		}
	}
	content := map[string][]byte{}
	for _, n := range names {
		b, ok := read(n)
		if !ok {
			return true
		}
		content[n] = b
	}

	refuse := func(err error) bool {
		var ue *UnsupportedError
		if errors.As(err, &ue) {
			return manual(ue.Reason, "%s", ue.Detail)
		}
		return manual(ReasonUnparsableSource, "%v", err)
	}

	// The Gradle version of the wrapper decides which plugins are accepted.
	gradle, err := parseGradleWrapper(pathIn(u.dir, wrapperName), content[wrapperName])
	if err != nil {
		return refuse(err)
	}
	rec := &GradleRecord{Version: gradle, Toolchain: gradleDefaultToolchain}
	it.Gradle = rec
	if major, _, _ := strings.Cut(gradle, "."); !gradleMajors[major] {
		return manual(ReasonGradleVersionUnsupported, "the wrapper uses Gradle %s; only Gradle 8 and 9 are handled", gradle)
	}
	var cat *gradleCatalog
	if hasCatalog {
		if cat, err = parseGradleCatalog(pathIn(u.dir, catalogName), content[catalogName]); err != nil {
			return refuse(err)
		}
	}
	if present["gradle.properties"] {
		if rec.Properties, err = parseGradleProperties(pathIn(u.dir, "gradle.properties"), content["gradle.properties"]); err != nil {
			return refuse(err)
		}
	}
	{
		if _, err = recognizeGradleScript(pathIn(u.dir, settingsName), content[settingsName], true, nil, gradle); err != nil {
			return refuse(err)
		}
	}
	script, err := recognizeGradleScript(pathIn(u.dir, buildName), content[buildName], false, cat, gradle)
	if err != nil {
		return refuse(err)
	}
	rec.Properties = append(rec.Properties, script.props...)
	for _, p := range script.plugins {
		switch p.id {
		case gradleBootPlugin:
			rec.BootVersion = p.version
		case gradleDependencyMgmtPlugin:
			rec.DependencyManagement = true
		}
	}
	if script.toolchain != 0 {
		rec.Toolchain = script.toolchain
	}
	if !gradleToolchains[rec.Toolchain] {
		return manual(ReasonGradleToolchainUnsupported, "the build asks for a Java %d toolchain; only 17, 21 and 25 are handled", rec.Toolchain)
	}

	lockPath := pathIn(u.dir, "gradle.lockfile")
	lock, err := parseGradleLockfile(lockPath, content["gradle.lockfile"])
	if err != nil {
		return refuse(err)
	}
	for _, c := range gradleRuntimeNeeded {
		if !lock.configs[c] {
			return manual(ReasonGradleLockingUnenforced, "%s lists no %s, so it does not cover the application", lockPath, c)
		}
	}
	// With a version catalog, Gradle locks the configuration the settings
	// resolve the catalog through and writes settings-gradle.lockfile with
	// --write-locks (an "empty=incomingCatalogFor..." line). A project that
	// does not keep the file gets it from the update as a file nobody asked
	// for, so the lock state the build was given is not the whole of it.
	if hasCatalog && !present["settings-gradle.lockfile"] {
		return manual(ReasonGradleLockingUnenforced, "%s is missing: with a version catalog, Gradle writes it with --write-locks", pathIn(u.dir, "settings-gradle.lockfile"))
	}

	direct := map[string][]string{}
	for _, d := range script.decls {
		if !d.constraint {
			direct[d.name] = append(direct[d.name], d.conf)
		}
	}
	pkgs := make([]LanguagePackage, 0, len(all))
	for _, g := range all {
		pkgs = append(pkgs, gradleMatch(lock, direct, script.compileOnlyExtendsAP, lockPath, g))
	}
	mavenOneVersionEach(pkgs)
	it.Packages = pkgs
	classify(it)
	return true
}

// gradleDependencyMgmtPlugin is the id of the dependency-management plugin.
const gradleDependencyMgmtPlugin = "io.spring.dependency-management"

// gradleMatch matches one running package against the lockfile: it is a
// candidate when the lockfile holds the installed version in a configuration
// the application is made of. It is direct when a build file or the version
// catalog declares it in a configuration that the locked configuration of
// that version inherits from (see gradleFeeds), transitive otherwise. A copy bundled in another archive is reached by no
// change of the build files.
func gradleMatch(lock *gradleLock, declared map[string][]string, apInCompileOnly bool, lockPath string, g *findingGroup) LanguagePackage {
	p := LanguagePackage{Name: g.Name, Ecosystem: g.Type, Installed: g.Installed, CVEs: g.cves, Origins: g.origins}
	for _, o := range g.origins {
		if !jarOwnFile(g.Name, g.Installed, o.PkgPath) {
			manualPackage(&p, ReasonJarBundled, fmt.Sprintf("%s is reported inside %s, an archive that bundles a copy of it", g.Name, o.PkgPath))
			return p
		}
	}
	idx := lock.byName[g.Name]
	if len(idx) == 0 {
		manualPackage(&p, ReasonNotFoundInSource, "gradle.lockfile does not list the package")
		return p
	}
	var occs, matched []SourceOccurrence
	var versions []string
	for _, i := range idx {
		e := lock.entries[i]
		o := SourceOccurrence{Path: lockPath, Version: e.version}
		versions = append(versions, fmt.Sprintf("%s (%s)", e.version, strings.Join(e.confs, ", ")))
		if versionsEqual(schemeMaven, e.version, g.Installed) && e.inRuntime() {
			o.Matched = true
			direct, ok := gradleDirect(declared[g.Name], e, apInCompileOnly)
			if !ok {
				manualPackage(&p, ReasonGradleBuildUnsupported, fmt.Sprintf("%s is declared in a configuration (%s) whose part in the resolution of %s is not decided by the standard java plugins", g.Name, strings.Join(declared[g.Name], ", "), strings.Join(e.confs, ", ")))
				p.Occurrences = append(occs, o)
				return p
			}
			o.Direct = direct
			matched = append(matched, o)
		}
		occs = append(occs, o)
	}
	p.Occurrences = occs
	if len(matched) == 0 {
		manualPackage(&p, ReasonNotFoundInSource, fmt.Sprintf("gradle.lockfile locks %s at %s, not %s in a configuration the application is made of", g.Name, strings.Join(versions, "; "), g.Installed))
		return p
	}
	p.Relation = relationOf(matched)
	target, reason, detail := chooseMavenTarget(g.Installed, g.cves)
	if reason != "" {
		manualPackage(&p, reason, detail)
		return p
	}
	p.SelectionLowerBound = target
	p.Action, p.Reason = ActionUpdate, ReasonUpdateCandidateInSource
	return p
}

// gradleFeeds are, for each configuration a dependency is declared in, the
// configurations of the lockfile that resolve it, by the inheritance of the
// standard java plugins. A configuration that is not here has no standard
// inheritance to judge by.
var gradleFeeds = map[string][]string{
	"implementation":          {"compileClasspath", "runtimeClasspath", "productionRuntimeClasspath", "testCompileClasspath", "testRuntimeClasspath"},
	"api":                     {"compileClasspath", "runtimeClasspath", "productionRuntimeClasspath", "testCompileClasspath", "testRuntimeClasspath"},
	"runtimeOnly":             {"runtimeClasspath", "productionRuntimeClasspath", "testRuntimeClasspath"},
	"compileOnly":             {"compileClasspath"},
	"testImplementation":      {"testCompileClasspath", "testRuntimeClasspath"},
	"testCompileOnly":         {"testCompileClasspath"},
	"testRuntimeOnly":         {"testRuntimeClasspath"},
	"annotationProcessor":     {"annotationProcessor"},
	"testAnnotationProcessor": {"testAnnotationProcessor"},
}

// gradleDirect reports whether a lockfile entry of the application is there
// because the project declares the package in one of confs: some declaration
// feeds a production configuration the entry is locked in. ok is false when
// apInCompileOnly says the project makes compileOnly extend annotationProcessor.
// ok is false when a declaration is in a configuration with no standard inheritance
// (developmentOnly), so the relation cannot be decided.
func gradleDirect(confs []string, e gradleLockEntry, apInCompileOnly bool) (direct, ok bool) {
	for _, c := range confs {
		feeds, known := gradleFeeds[c]
		if !known {
			return false, false
		}
		if c == "annotationProcessor" && apInCompileOnly {
			// compileOnly extends annotationProcessor in this project.
			feeds = append(append([]string(nil), feeds...), gradleFeeds["compileOnly"]...)
		}
		for _, f := range feeds {
			for _, l := range gradleRuntimeConfs {
				if f == l && containsString(e.confs, l) {
					direct = true
				}
			}
		}
	}
	return direct, true
}
