package remediation

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// typeJar is the scanner result type of the Java archives of an image.
const typeJar = "jar"

// Reasons of the Maven part.
const (
	// ReasonJarBundled: a copy of the package sits inside another archive
	// (a shaded or bundled copy), which no change of the pom files reaches.
	ReasonJarBundled Reason = "jar_bundled_copy"
	// ReasonMavenAppJarAmbiguous: an image holds more than one archive of
	// the project's own modules, or its package list was cut short, so the
	// findings of the project cannot be told apart.
	ReasonMavenAppJarAmbiguous Reason = "maven_app_jar_ambiguous"
	// ReasonMavenModelUnsupported: the pom files use a form whose
	// resolution the check of the result does not reproduce (a profile that
	// changes dependencies, an optional direct dependency, a classifier or
	// another type on the package, a version range, a relocation, a
	// duplicated declaration).
	ReasonMavenModelUnsupported Reason = "maven_model_unsupported"
	// ReasonMavenParentMismatch: a pom file found where a parent is looked
	// for has the parent's artifactId but not its coordinates, or is a
	// parent outside the modules read.
	ReasonMavenParentMismatch Reason = "maven_parent_mismatch"
	// ReasonMavenReactorUnsupported: the modules cannot be read as one
	// reactor (a module without a pom.xml, a module path outside the
	// directory, too many modules).
	ReasonMavenReactorUnsupported Reason = "maven_reactor_unsupported"
	// ReasonMavenFixInOtherMajor: every reported fix is of another major
	// version than the one the image runs.
	ReasonMavenFixInOtherMajor Reason = "maven_fix_in_other_major"
)

// Bounds of the modules read for one unit.
const (
	maxMavenModules     = 100
	maxMavenModuleDepth = 8
)

// jarPackage is one Java archive a scan lists.
type jarPackage struct {
	name, version, path string
}

// jarScan is the archives of one scan, by the scan's place among the
// planner's inputs.
type jarScan struct {
	pkgs      []jarPackage
	truncated bool
}

// jarPackagesOf records the archives of the scan of input.
func jarPackagesOf(input int, s scanner.ImageScan, into map[int]*jarScan) {
	js := &jarScan{truncated: s.PackagesTruncated}
	for _, rp := range s.Packages {
		if rp.Type != typeJar {
			continue
		}
		for _, p := range rp.Packages {
			js.pkgs = append(js.pkgs, jarPackage{name: p.Name, version: p.Version, path: strings.TrimPrefix(p.PkgPath, "/")})
		}
	}
	into[input] = js
}

// mavenModule is one pom file of a reactor.
type mavenModule struct {
	path  string // repository path of the pom.xml
	dir   string // its directory
	pom   *mavenPOM
	coord string // effective groupId:artifactId
}

// mavenReactor is the root pom of a unit and every module its <modules>
// reach, the root first.
type mavenReactor struct {
	modules []*mavenModule
	byCoord map[string]*mavenModule
	byPath  map[string]*mavenModule
}

// parent returns the module's parent when the parent is a module of the
// reactor with the same coordinates.
func (rx *mavenReactor) parent(m *mavenModule) *mavenModule {
	pa := m.pom.Parent
	if pa == nil {
		return nil
	}
	p := rx.byCoord[pa.GroupID+":"+pa.ArtifactID]
	if p == nil || p.pom.EffectiveVersion() != pa.Version {
		return nil
	}
	return p
}

// resolve gives the value of a version or groupId text in module m: the text
// itself without references, or the value of one ${name} reference defined
// by the module or a reactor parent, or a project coordinate. ok is false for
// anything else (a property only a parent outside the reactor defines, an
// expression).
func (rx *mavenReactor) resolve(m *mavenModule, s string) (string, bool) {
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
			return m.pom.EffectiveGroupID(), true
		case "project.version", "pom.version":
			return m.pom.EffectiveVersion(), true
		case "project.artifactId", "pom.artifactId":
			return m.pom.ArtifactID, true
		}
		found := false
		seen := map[*mavenModule]bool{}
		for cur := m; cur != nil && !seen[cur]; cur = rx.parent(cur) {
			seen[cur] = true
			if v, ok := cur.pom.Properties[name]; ok {
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

// readReactor reads the modules below the root pom of a unit. ok is false
// when the item has been given its outcome.
func (r *run) readReactor(it *LanguageItem, groups []*findingGroup, u *depUnit, sha string, root *mavenPOM, rootPath string) (*mavenReactor, bool) {
	gh := r.p.cfg.GitHub
	rx := &mavenReactor{byCoord: map[string]*mavenModule{}, byPath: map[string]*mavenModule{}}
	add := func(m *mavenModule) bool {
		m.coord = m.pom.EffectiveGroupID() + ":" + m.pom.ArtifactID
		if other := rx.byCoord[m.coord]; other != nil {
			unitManual(it, groups, ReasonMavenReactorUnsupported, fmt.Sprintf("%s and %s both declare %s", other.path, m.path, m.coord))
			return false
		}
		rx.modules = append(rx.modules, m)
		rx.byCoord[m.coord] = m
		rx.byPath[m.path] = m
		return true
	}
	if !add(&mavenModule{path: rootPath, dir: path.Dir(rootPath), pom: root}) {
		return nil, false
	}
	type pending struct {
		m     *mavenModule
		depth int
	}
	queue := []pending{{rx.modules[0], 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, name := range cur.m.pom.Modules {
			dir, why := mavenModuleDir(u.dir, cur.m.dir, name)
			if why != "" {
				unitManual(it, groups, ReasonMavenReactorUnsupported, fmt.Sprintf("%s lists the module %q: %s", cur.m.path, name, why))
				return nil, false
			}
			p := pathIn(dir, "pom.xml")
			if rx.byPath[p] != nil {
				continue
			}
			if cur.depth+1 > maxMavenModuleDepth || len(rx.modules) >= maxMavenModules {
				unitManual(it, groups, ReasonMavenReactorUnsupported, fmt.Sprintf("the modules go deeper than %d levels or number more than %d", maxMavenModuleDepth, maxMavenModules))
				return nil, false
			}
			if h := r.stopReason(); h != nil {
				r.deferUnit(it, groups, h.reason, h.detail)
				return nil, false
			}
			f, err := gh.ReadFile(r.ctx, u.repo, sha, p)
			if errors.Is(err, github.ErrNotFound) {
				unitManual(it, groups, ReasonMavenReactorUnsupported, fmt.Sprintf("the module %s has no pom.xml", dir))
				return nil, false
			}
			if err != nil {
				r.sourceFailure(it, groups, err, true)
				return nil, false
			}
			it.Source.Files = append(it.Source.Files, SourceFile{Path: f.Path, BlobSHA: f.SHA})
			pom, err := parseMavenPOM(f.Content)
			if err != nil {
				unitManual(it, groups, ReasonUnparsableSource, fmt.Sprintf("%s: %v", p, err))
				return nil, false
			}
			m := &mavenModule{path: p, dir: dir, pom: pom}
			if !add(m) {
				return nil, false
			}
			queue = append(queue, pending{m, cur.depth + 1})
		}
	}
	for _, m := range rx.modules {
		seen := map[*mavenModule]bool{}
		for cur := m; cur != nil; cur = rx.parent(cur) {
			if seen[cur] {
				unitManual(it, groups, ReasonMavenReactorUnsupported, fmt.Sprintf("the parents of %s form a cycle", m.path))
				return nil, false
			}
			seen[cur] = true
		}
	}
	return rx, true
}

// mavenModuleDir is the directory a <module> entry names, relative to the
// directory of the pom that lists it, or why it is not one this plan reads.
func mavenModuleDir(unitDir, from, name string) (string, string) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", "an empty module path"
	case strings.HasPrefix(name, "/") || strings.Contains(name, "\\"):
		return "", "not a relative path"
	case strings.HasSuffix(name, ".xml"):
		return "", "a module named by its pom file is not handled"
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." || strings.HasPrefix(seg, ".") {
			return "", "a path that leaves the directory or names a hidden one"
		}
	}
	var dir string
	if from == "." {
		dir = path.Clean(name)
	} else {
		dir = path.Clean(from + "/" + name)
	}
	if unitDir != "." && dir != unitDir && !strings.HasPrefix(dir, unitDir+"/") {
		return "", "outside the mapped directory"
	}
	return dir, ""
}

// mavenModelProblem says why the reactor's pom files use a form the check of
// an update does not reproduce, with the reason, or "".
func mavenModelProblem(rx *mavenReactor) (Reason, string) {
	for _, m := range rx.modules {
		p := m.pom
		for _, pr := range p.Profiles {
			if pr.Dependencies || pr.DependencyManagement || pr.Properties || pr.Parent || pr.Modules || pr.Repositories {
				return ReasonMavenModelUnsupported, fmt.Sprintf("%s has the profile %q, which changes what is resolved", m.path, pr.ID)
			}
		}
		if len(p.Repositories) > 0 || len(p.PluginRepositories) > 0 {
			return ReasonUnsupportedSource, fmt.Sprintf("%s declares repositories; only Maven Central is handled", m.path)
		}
		if p.Relocation {
			return ReasonMavenModelUnsupported, fmt.Sprintf("%s declares a relocation", m.path)
		}
		seen := map[string]bool{}
		for _, d := range p.Dependencies {
			k := d.GroupID + ":" + d.ArtifactID
			if seen[k] {
				return ReasonMavenModelUnsupported, fmt.Sprintf("%s declares %s more than once among its dependencies", m.path, k)
			}
			seen[k] = true
			if strings.EqualFold(d.Optional, "true") {
				return ReasonMavenModelUnsupported, fmt.Sprintf("%s declares %s as optional", m.path, k)
			}
			if isMavenVersionRange(d.Version) {
				return ReasonMavenModelUnsupported, fmt.Sprintf("%s gives %s the version range %s", m.path, k, d.Version)
			}
		}
		managed := map[string]bool{}
		for _, d := range p.DependencyManagement {
			k := strings.Join([]string{d.GroupID, d.ArtifactID, mavenTypeOf(d), d.Classifier}, ":")
			if managed[k] {
				return ReasonMavenModelUnsupported, fmt.Sprintf("%s manages %s:%s more than once", m.path, d.GroupID, d.ArtifactID)
			}
			managed[k] = true
			if d.Optional != "" || d.HasExclusions {
				return ReasonMavenModelUnsupported, fmt.Sprintf("%s manages %s:%s with optional or exclusions", m.path, d.GroupID, d.ArtifactID)
			}
			if isMavenVersionRange(d.Version) {
				return ReasonMavenModelUnsupported, fmt.Sprintf("%s manages %s:%s with the version range %s", m.path, d.GroupID, d.ArtifactID, d.Version)
			}
		}
	}
	return "", ""
}

// mavenTypeOf is a dependency's type, jar when it names none.
func mavenTypeOf(d mavenDep) string {
	if d.Type == "" {
		return "jar"
	}
	return d.Type
}

// checkMavenParents looks at every place the parent of a reactor pom is
// looked for in the repository: its relativePath when it names one, and
// ../pom.xml in any case (a resolver may fall back to it). A pom file there
// with the parent's artifactId must be the parent itself, with the same
// coordinates, and be a module of the reactor; one of another artifactId is
// not taken as the parent by either Maven or the scanner, and is recorded so
// that a change of it is seen. A relativePath that leaves the repository is
// refused. The places with no file are recorded as absent. ok is false when
// the item has been given its outcome.
func (r *run) checkMavenParents(it *LanguageItem, groups []*findingGroup, u *depUnit, sha string, rx *mavenReactor) bool {
	gh := r.p.cfg.GitHub
	listings := map[string][]github.Entry{}
	checked := map[string]bool{}
	// entry finds what the repository has at p. ok is false when the item has
	// been given its outcome.
	entry := func(p string) (github.Entry, bool, bool) {
		dir := path.Dir(p)
		entries, listed := listings[dir]
		if !listed {
			if h := r.stopReason(); h != nil {
				r.deferUnit(it, groups, h.reason, h.detail)
				return github.Entry{}, false, false
			}
			var err error
			entries, err = gh.ListDirectory(r.ctx, u.repo, sha, dir)
			switch {
			case errors.Is(err, github.ErrNotFound):
				entries = nil
			case err != nil:
				r.sourceFailure(it, groups, err, false)
				return github.Entry{}, false, false
			}
			listings[dir] = entries
		}
		e, found := byName(entries, path.Base(p))
		return e, found, true
	}
	for _, m := range rx.modules {
		pa := m.pom.Parent
		if pa == nil {
			continue
		}
		type place struct {
			p        string
			explicit bool // a relativePath, which may name a directory
		}
		places := []place{{path.Join(m.dir, "..", "pom.xml"), false}}
		if rel := strings.TrimSpace(pa.RelativePath); rel != "" {
			c := path.Clean(path.Join(m.dir, rel))
			if strings.HasPrefix(rel, "/") || c == ".." || strings.HasPrefix(c, "../") {
				// A parent named outside the repository is read from wherever the
				// build runs, which nothing here can see.
				unitManual(it, groups, ReasonMavenParentMismatch, fmt.Sprintf("%s names its parent at %s, outside the repository", m.path, pa.RelativePath))
				return false
			}
			places = append(places, place{c, true})
		}
		for _, pl := range places {
			c := path.Clean(pl.p)
			if c == ".." || strings.HasPrefix(c, "../") {
				continue // the default place, above the repository root
			}
			if pl.explicit && rx.byPath[c] == nil && rx.byPath[pathIn(c, "pom.xml")] != nil {
				c = pathIn(c, "pom.xml")
			}
			if mod := rx.byPath[c]; mod != nil {
				if mod.pom.ArtifactID == pa.ArtifactID && (mod.pom.EffectiveGroupID() != pa.GroupID || mod.pom.EffectiveVersion() != pa.Version) {
					unitManual(it, groups, ReasonMavenParentMismatch, fmt.Sprintf("%s names the parent %s:%s:%s, and %s has its artifactId with other coordinates", m.path, pa.GroupID, pa.ArtifactID, pa.Version, c))
					return false
				}
				continue
			}
			if checked[m.path+"\x00"+c] {
				continue
			}
			checked[m.path+"\x00"+c] = true
			var e github.Entry
			found, ok := true, true
			if c == "." {
				// The repository root is a directory that no listing names.
				e.Type = github.EntryDir
			} else if e, found, ok = entry(c); !ok {
				return false
			}
			if found && e.Type == github.EntryDir && pl.explicit {
				// A relativePath may name the directory of the parent's pom.xml.
				c = pathIn(c, "pom.xml")
				if e, found, ok = entry(c); !ok {
					return false
				}
			}
			switch {
			case !found:
				if !containsString(it.Source.Absent, c) {
					it.Source.Absent = append(it.Source.Absent, c)
				}
				continue
			case e.Type != github.EntryFile:
				unitManual(it, groups, ReasonMavenParentMismatch, fmt.Sprintf("%s, where the parent of %s is looked for, is a %s", c, m.path, e.Type))
				return false
			}
			if h := r.stopReason(); h != nil {
				r.deferUnit(it, groups, h.reason, h.detail)
				return false
			}
			f, err := gh.ReadFile(r.ctx, u.repo, sha, c)
			if err != nil {
				r.sourceFailure(it, groups, err, true)
				return false
			}
			other, err := parseMavenPOM(f.Content)
			if err != nil {
				unitManual(it, groups, ReasonMavenParentMismatch, fmt.Sprintf("%s, where the parent of %s is looked for, cannot be read: %v", c, m.path, err))
				return false
			}
			if other.ArtifactID == pa.ArtifactID {
				unitManual(it, groups, ReasonMavenParentMismatch, fmt.Sprintf("%s, where the parent of %s is looked for, is a pom with the parent's artifactId outside the modules read", c, m.path))
				return false
			}
			// A pom of another artifact is not taken as the parent; it is recorded
			// so that a change of it is seen.
			it.Source.Files = append(it.Source.Files, SourceFile{Path: f.Path, BlobSHA: f.SHA})
		}
	}
	return true
}

// mavenSelect keeps, of the jar findings of a unit, those of the project's
// own archives. The application archive of an image is an archive with the
// coordinates of a module of the reactor that holds other archives (a
// Spring Boot jar, say); an archive of a module that holds none is a library
// of the application like any other (a module's jar beside the dependencies
// of an image laid out without an application archive, or one nested in the
// application archive). Per scan: when the image has an application archive,
// only the findings inside it are kept and its module is the image's
// application; when it has none, every jar finding of the image is kept and
// matched by name and version. why is set when an image has more than one
// application archive, or its package list was cut short.
func mavenSelect(fs []srcFinding, scans map[int]*jarScan, rx *mavenReactor) (kept []srcFinding, apps map[*mavenModule]bool, all bool, why string) {
	apps = map[*mavenModule]bool{}
	type sel struct {
		app  string
		mod  *mavenModule
		none bool
	}
	decided := map[int]*sel{}
	for _, lf := range fs {
		s := decided[lf.rank]
		if s == nil {
			s = &sel{}
			js := scans[lf.rank]
			var paths []string
			switch {
			case js != nil && js.truncated:
				// The archives listed are not all there are: the findings are kept
				// whole, and the unit goes to a person.
				if why == "" {
					why = fmt.Sprintf("the package list of %s was cut short, so the project's own archive cannot be found", lf.entity)
				}
			case js != nil:
				for _, p := range js.pkgs {
					mod := rx.byCoord[p.name]
					if mod == nil || p.path == "" || containsString(paths, p.path) || !holdsArchives(js.pkgs, p.path) {
						continue
					}
					paths = append(paths, p.path)
					s.mod = mod
				}
			}
			switch len(paths) {
			case 0:
				s.none = true
				all = true
			case 1:
				s.app = paths[0]
				apps[s.mod] = true
			default:
				sort.Strings(paths)
				if why == "" {
					why = fmt.Sprintf("%s holds more than one archive of the project's modules (%s)", lf.entity, strings.Join(paths, ", "))
				}
				s.none = true
			}
			decided[lf.rank] = s
		}
		if s.none || strings.HasPrefix(strings.TrimPrefix(lf.f.PkgPath, "/"), s.app+"/") {
			kept = append(kept, lf)
		}
	}
	return kept, apps, all, why
}

// holdsArchives reports whether any archive of the list sits inside the
// archive at p.
func holdsArchives(pkgs []jarPackage, p string) bool {
	for _, q := range pkgs {
		if strings.HasPrefix(q.path, p+"/") {
			return true
		}
	}
	return false
}

// jarOwnFile reports whether a finding of a package at version was reported
// at the package's own archive (artifactId-version.jar) rather than at an
// archive that bundles a copy of it.
func jarOwnFile(name, version, pkgPath string) bool {
	i := strings.LastIndex(name, ":")
	if i < 0 || pkgPath == "" {
		return false
	}
	return path.Base(pkgPath) == name[i+1:]+"-"+version+".jar"
}

// mavenRuntimeScope reports a dependency the running application gets:
// compile (the default) or runtime scope.
func mavenRuntimeScope(d mavenDep) bool {
	return d.Scope == "" || d.Scope == "compile" || d.Scope == "runtime"
}

// mavenSearchModules is the modules a finding of the given applications can
// come from: the applications, the reactor modules they depend on at compile
// or runtime scope, followed through, and the reactor parents of all of them. With all set, every
// module.
func mavenSearchModules(rx *mavenReactor, apps map[*mavenModule]bool, all bool) []*mavenModule {
	if all {
		return rx.modules
	}
	in := map[*mavenModule]bool{}
	var queue []*mavenModule
	push := func(m *mavenModule) {
		if m != nil && !in[m] {
			in[m] = true
			queue = append(queue, m)
		}
	}
	for m := range apps {
		push(m)
	}
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		push(rx.parent(m))
		for _, d := range m.pom.Dependencies {
			if !mavenRuntimeScope(d) {
				continue
			}
			g, ok := rx.resolve(m, d.GroupID)
			if !ok {
				continue
			}
			push(rx.byCoord[g+":"+d.ArtifactID])
		}
	}
	var out []*mavenModule
	for _, m := range rx.modules {
		if in[m] {
			out = append(out, m)
		}
	}
	return out
}

// mavenMatch matches one running package against the reactor: the
// dependencies the searched modules declare for it, or none when it comes
// in through other dependencies (which the update confirms when it resolves
// the original files). It chooses the version selection starts from.
func mavenMatch(rx *mavenReactor, mods []*mavenModule, g *findingGroup) LanguagePackage {
	p := LanguagePackage{Name: g.Name, Ecosystem: g.Type, Installed: g.Installed, CVEs: g.cves, Origins: g.origins}
	if strings.HasSuffix(g.Installed, "-SNAPSHOT") {
		manualPackage(&p, ReasonMavenModelUnsupported, fmt.Sprintf("the image runs a SNAPSHOT of %s, which Maven Central does not publish", g.Name))
		return p
	}
	for _, o := range g.origins {
		if !jarOwnFile(g.Name, g.Installed, o.PkgPath) {
			manualPackage(&p, ReasonJarBundled, fmt.Sprintf("%s is reported inside %s, an archive that bundles a copy of it", g.Name, o.PkgPath))
			return p
		}
	}
	var occs []SourceOccurrence
	for _, m := range mods {
		for _, d := range m.pom.Dependencies {
			if !mavenRuntimeScope(d) {
				continue
			}
			gid, ok := rx.resolve(m, d.GroupID)
			if !ok || gid+":"+d.ArtifactID != g.Name {
				continue
			}
			o := SourceOccurrence{Path: m.path, Direct: true}
			switch v, known := rx.resolve(m, d.Version); {
			case d.Classifier != "" || mavenTypeOf(d) != "jar":
				o.ManualReason, o.Detail = ReasonMavenModelUnsupported, fmt.Sprintf("%s declares %s with a classifier or a type other than jar", m.path, g.Name)
			case isMavenVersionRange(d.Version):
				o.ManualReason, o.Detail = ReasonMavenModelUnsupported, fmt.Sprintf("%s gives %s a version range", m.path, g.Name)
			case known:
				o.Version = v
				if strings.HasSuffix(v, "-SNAPSHOT") {
					o.ManualReason, o.Detail = ReasonMavenModelUnsupported, fmt.Sprintf("%s requires a SNAPSHOT of %s", m.path, g.Name)
				} else if !versionsEqual(schemeMaven, v, g.Installed) {
					o.ManualReason, o.Detail = ReasonNotFoundInSource, fmt.Sprintf("%s requires %s %s, and the image runs %s", m.path, g.Name, v, g.Installed)
				}
			}
			if o.ManualReason == "" {
				o.Matched = true
			}
			occs = append(occs, o)
		}
	}
	if len(occs) == 0 {
		occs = []SourceOccurrence{{Path: rx.modules[0].path, Detail: "required through other dependencies; the update confirms the version when it resolves the files"}}
	}
	p.Occurrences = occs
	p.Relation = relationOf(occs)
	for _, o := range occs {
		if o.ManualReason != "" {
			manualPackage(&p, o.ManualReason, o.Detail)
			return p
		}
	}
	target, reason, detail := chooseMavenTarget(g.Installed, g.cves)
	if reason != "" {
		manualPackage(&p, reason, detail)
		return p
	}
	p.SelectionLowerBound = target
	p.Action, p.Reason = ActionUpdate, ReasonUpdateCandidateInSource
	return p
}

// chooseMavenTarget picks the version selection starts from, as
// chooseTarget does, among the reported fixes that can replace the
// installed version: of the same major version, not a pre-release unless the
// installed version is one, and of the same variant (a "-jre" build is not
// replaced by an "-android" one). Which release Maven Central has is settled
// when the update runs.
func chooseMavenTarget(installed string, cves []CVERef) (string, Reason, string) {
	inst, ok := parseVersion(schemeMaven, installed)
	if !ok {
		return "", ReasonUnparsableVersion, fmt.Sprintf("the installed version %q is not a version", installed)
	}
	major, ok := mavenMajor(installed)
	if !ok {
		return "", ReasonUnparsableVersion, fmt.Sprintf("the installed version %q does not start with a number", installed)
	}
	pre, flavor := mavenIsPrerelease(installed), mavenFlavor(installed)
	var best version
	bestStr := ""
	for _, c := range cves {
		var low version
		lowStr := ""
		otherMajor := false
		for _, alt := range c.FixedVers {
			for _, one := range splitFixed(alt) {
				v, ok := parseVersion(schemeMaven, one)
				if !ok {
					return "", ReasonUnparsableVersion, fmt.Sprintf("%s reports the fixed version %q, which is not a version", c.VulnID, one)
				}
				if v.compare(inst) <= 0 {
					continue
				}
				if m, ok := mavenMajor(one); !ok || m != major {
					otherMajor = true
					continue
				}
				if !pre && mavenIsPrerelease(one) {
					continue
				}
				if f := mavenFlavor(one); f != "" && f != flavor {
					continue
				}
				if low == nil || v.compare(low) < 0 {
					low, lowStr = v, one
				}
			}
		}
		if low == nil {
			if otherMajor {
				return "", ReasonMavenFixInOtherMajor, fmt.Sprintf("%s is fixed only in another major version than %s", c.VulnID, installed)
			}
			return "", ReasonNoFixedVersion, fmt.Sprintf("%s reports no fixed version above %s that can replace it", c.VulnID, installed)
		}
		if best == nil || low.compare(best) > 0 {
			best, bestStr = low, lowStr
		}
	}
	if best == nil {
		return "", ReasonNoFixedVersion, "no vulnerability to fix"
	}
	return bestStr, "", ""
}

// mavenOneVersionEach sends to a person every package that runs at more than
// one version: one update of the pom files gives a package one version.
func mavenOneVersionEach(pkgs []LanguagePackage) {
	versions := map[string][]string{}
	for _, p := range pkgs {
		if !containsString(versions[p.Name], p.Installed) {
			versions[p.Name] = append(versions[p.Name], p.Installed)
		}
	}
	for i := range pkgs {
		vs := versions[pkgs[i].Name]
		if len(vs) < 2 || pkgs[i].Action != ActionUpdate {
			continue
		}
		sort.Strings(vs)
		pkgs[i].SelectionLowerBound = ""
		manualPackage(&pkgs[i], ReasonMultipleVersions, fmt.Sprintf("the images run %s at %s", pkgs[i].Name, strings.Join(vs, ", ")))
	}
}

// analyseMavenUnit plans the Maven item of a unit whose directory has a
// pom.xml: it reads the reactor (the pom and the modules it lists), refuses
// the forms the check of an update does not reproduce, keeps the findings of
// the project's own archives (mavenSelect) and matches them against the
// dependencies the modules declare. Nothing is resolved here: a package the
// modules do not declare is a candidate that comes in through other
// dependencies, and the update confirms that the original files resolve it
// at the version the image runs. It returns the reactor (nil when it was not
// read) and whether the unit has an item.
func (r *run) analyseMavenUnit(it *LanguageItem, u *depUnit, entries []github.Entry) (*mavenReactor, bool) {
	gh := r.p.cfg.GitHub
	sha := it.Source.CommitSHA
	intel := r.p.cfg.Intel
	all := groupLanguageFindings(u.jarPinned, intel)
	setPriorityOf(it, all)
	it.Manager = ManagerMaven
	it.Key = u.key + "#" + string(ManagerMaven)
	keepAll := len(all) > 0

	if e, _ := byName(entries, "pom.xml"); e.Type != github.EntryFile {
		unitManual(it, all, ReasonDependencyFileUnusable, "pom.xml is a "+string(e.Type))
		return nil, keepAll
	}
	if h := r.stopReason(); h != nil {
		r.deferUnit(it, all, h.reason, h.detail)
		return nil, keepAll
	}
	rootPath := pathIn(u.dir, "pom.xml")
	f, err := gh.ReadFile(r.ctx, u.repo, sha, rootPath)
	if err != nil {
		r.sourceFailure(it, all, err, true)
		return nil, keepAll
	}
	it.Source.Files = append(it.Source.Files, SourceFile{Path: f.Path, BlobSHA: f.SHA})
	root, err := parseMavenPOM(f.Content)
	if err != nil {
		unitManual(it, all, ReasonUnparsableSource, fmt.Sprintf("%s: %v", rootPath, err))
		return nil, keepAll
	}
	rx, ok := r.readReactor(it, all, u, sha, root, rootPath)
	if !ok {
		return nil, keepAll
	}

	kept, apps, allMods, why := mavenSelect(u.jarPinned, u.jarScans, rx)
	groups := groupLanguageFindings(kept, intel)
	if len(groups) == 0 {
		return rx, false
	}
	setPriorityOf(it, groups)
	if why != "" {
		unitManual(it, groups, ReasonMavenAppJarAmbiguous, why)
		return rx, true
	}
	if reason, why := mavenModelProblem(rx); reason != "" {
		unitManual(it, groups, reason, why)
		return rx, true
	}
	// Settings that change what Maven resolves sit in .mvn of the root.
	if e, found := byName(entries, ".mvn"); found {
		if e.Type != github.EntryDir {
			unitManual(it, groups, ReasonDependencyFileUnusable, ".mvn is a "+string(e.Type))
			return rx, true
		}
		if h := r.stopReason(); h != nil {
			r.deferUnit(it, groups, h.reason, h.detail)
			return rx, true
		}
		mvn, err := gh.ListDirectory(r.ctx, u.repo, sha, pathIn(u.dir, ".mvn"))
		if err != nil && !errors.Is(err, github.ErrNotFound) {
			r.sourceFailure(it, groups, err, false)
			return rx, true
		}
		for _, name := range []string{"maven.config", "extensions.xml"} {
			if _, found := byName(mvn, name); found {
				unitManual(it, groups, ReasonUnsupportedSource, pathIn(u.dir, ".mvn/"+name)+" exists; settings that change what Maven resolves are not handled")
				return rx, true
			}
		}
	}
	for _, name := range []string{".mvn/maven.config", ".mvn/extensions.xml"} {
		it.Source.Absent = append(it.Source.Absent, pathIn(u.dir, name))
	}
	if !r.checkMavenParents(it, groups, u, sha, rx) {
		return rx, true
	}

	mods := mavenSearchModules(rx, apps, allMods)
	pkgs := make([]LanguagePackage, 0, len(groups))
	for _, g := range groups {
		pkgs = append(pkgs, mavenMatch(rx, mods, g))
	}
	mavenOneVersionEach(pkgs)
	it.Packages = pkgs
	classify(it)
	return rx, true
}
