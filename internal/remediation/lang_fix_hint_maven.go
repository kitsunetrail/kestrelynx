package remediation

import (
	"context"
	"sort"
	"strings"
)

// The kinds of pom outside the project that decide a package's version.
const (
	DeciderParentPOM  = "parent_pom"
	DeciderBOM        = "bom"
	DeciderSpringBoot = "spring_boot"
)

// dependentPOM is how the pom of a package that depends on another is read
// for the version it brings of that one: its dependency declaration, with the
// version its management gives when the declaration writes none, and nothing
// when it does not declare it.
const dependentPOM = "dependent"

// FixDecider is the pom outside the project whose release decides a
// package's version: a parent pom that declares it, a BOM the project
// imports, or the BOM of the Spring Boot plugin. Name is its
// groupId:artifactId and Version the release the project has.
type FixDecider struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// maxDeciderReads bounds what the hint of one package reads from Maven
// Central once the item is settled: the list of releases of the deciding pom,
// and the poms of the two releases judged with their parents and the BOMs
// they import. What the hints of the item read already is not read again.
var maxDeciderReads = 12

// setDecider records on the packages of name the pom that decides its
// version; what its releases set the package to is looked up once the item is
// settled (mavenHints).
func (r *updateRun) setDecider(name string, d *FixDecider) {
	if d == nil {
		return
	}
	for _, k := range r.full.byName[name] {
		r.it.Packages[k].FixHint = &FixHint{DecidedBy: d}
	}
}

// mavenHints finds the hints of a Maven or Gradle item's packages that need
// no update run: the lowest fix of another major version of a package whose
// fixes are all of one, and, for a package whose version a pom outside the
// project decides or that packages it depends on bring in below its target,
// what the newest release of that pom (or of each of those packages) in its
// minor version (InSpec) and its newest release (Latest) set the package to.
func (u *LangUpdater) mavenHints(ctx context.Context, it *LanguageItem) {
	for i := range it.Packages {
		p := &it.Packages[i]
		if p.Reason == ReasonMavenFixInOtherMajor && p.FixHint == nil {
			if v := mavenOtherMajorFix(p.Installed, p.CVEs); v != "" {
				p.FixHint = &FixHint{Fix: &FixRelease{Version: v}}
			}
		}
	}
	if u.cfg.Maven == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, hintTimeout)
	defer cancel()
	poms := map[string]*mavenPOM{}
	versions := map[string][]string{}
	pairs := 0
	for i := range it.Packages {
		p := &it.Packages[i]
		h := p.Hint()
		if h == nil || h.Releases != nil || ctx.Err() != nil {
			continue
		}
		type pom struct{ kind, name, version string }
		var whose []pom
		switch {
		case h.DecidedBy != nil:
			whose = []pom{{h.DecidedBy.Kind, h.DecidedBy.Name, h.DecidedBy.Version}}
		case len(h.HeldBy) > 0:
			for _, x := range h.HeldBy {
				if pairs >= maxHintPairs {
					break
				}
				pairs++
				whose = append(whose, pom{dependentPOM, x.Parent, x.ParentVersion})
			}
		}
		reads := 0 // what the hint of the package reads, over all its poms
		for _, w := range whose {
			if ch := u.pomReleases(ctx, w.kind, w.name, w.version, p, poms, versions, &reads); ch != nil {
				h.Releases = append(h.Releases, *ch)
			}
		}
	}
}

// pomReleases judges what the newest release of the pom name in the minor
// version of cur (InSpec) and its newest release (Latest) set package p to,
// counting in reads the poms and lists it reads apart from what the item's
// hints read already, up to maxDeciderReads for the package; nil when
// neither can be told.
func (u *LangUpdater) pomReleases(ctx context.Context, kind, name, cur string, p *LanguagePackage, poms map[string]*mavenPOM, versions map[string][]string, reads *int) *ChainHint {
	spend := func() bool {
		if *reads >= maxDeciderReads || ctx.Err() != nil {
			return false
		}
		*reads++
		return true
	}
	fetch := func(g, a, v string) *mavenPOM {
		key := g + ":" + a + ":" + v
		if pom, ok := poms[key]; ok {
			return pom
		}
		if !spend() {
			return nil
		}
		data, err := u.cfg.Maven.POM(ctx, g, a, v)
		if err != nil {
			return nil
		}
		pom, err := parseMavenPOM(data)
		if err != nil || pom.EffectiveGroupID() != g || pom.ArtifactID != a || pom.EffectiveVersion() != v {
			return nil
		}
		poms[key] = pom
		return pom
	}
	g, a, ok := strings.Cut(name, ":")
	if !ok {
		return nil
	}
	vs, ok := versions[name]
	if !ok {
		if !spend() {
			return nil
		}
		var err error
		if vs, err = u.cfg.Maven.Versions(ctx, g, a); err != nil {
			return nil
		}
		versions[name] = vs
	}
	sameMinor, latest := deciderReleases(vs, cur)
	ch := &ChainHint{Package: p.Name, Parent: name, ParentVersion: cur, Direct: true}
	if sameMinor != "" {
		ch.InSpec = deciderRelease(kind, g, a, sameMinor, p.Name, p.SelectionLowerBound, p.CVEs, fetch)
	}
	if latest != "" && latest != sameMinor {
		ch.Latest = deciderRelease(kind, g, a, latest, p.Name, p.SelectionLowerBound, p.CVEs, fetch)
	}
	if ch.InSpec == nil && ch.Latest == nil {
		return nil
	}
	return ch
}

// deciderReleases picks, of the releases of the deciding pom (pre-releases
// left out), the newest in the minor version of cur, cur included, and the
// newest of all at cur or above.
func deciderReleases(vs []string, cur string) (sameMinor, latest string) {
	newer := func(v, than string) bool {
		if than == "" {
			return true
		}
		c, ok := compareVersions(schemeMaven, v, than)
		return ok && c > 0
	}
	for _, v := range vs {
		if mavenIsPrerelease(v) {
			continue
		}
		c, ok := compareVersions(schemeMaven, v, cur)
		if !ok || c < 0 {
			continue
		}
		if newer(v, latest) {
			latest = v
		}
		if mavenMajorMinor(v) == mavenMajorMinor(cur) && newer(v, sameMinor) {
			sameMinor = v
		}
	}
	return sameMinor, latest
}

// deciderRelease judges what release v of the deciding pom g:a sets name to:
// for a parent pom, the version its dependency declaration gives, or without
// one its management; for a BOM, the version its management gives, through
// the BOMs it imports. Dropped says it sets no version of name; nil when that
// cannot be told within the reads, a pom with a profile that may set another
// version included.
func deciderRelease(kind, g, a, v, name, target string, cves []CVERef, fetch func(g, a, v string) *mavenPOM) *ChainHintRelease {
	chain := deciderChain(g, a, v, fetch)
	if chain == nil {
		return nil
	}
	set, found, ok := "", false, false
	ci, i := -1, -1
	if kind == DeciderParentPOM || kind == dependentPOM {
		ci, i = nearestDeclaration(chain, name)
	}
	switch {
	case ci == mavenUnknown:
		return nil
	case ci < 0 && kind == dependentPOM:
		return &ChainHintRelease{Version: v, Dropped: true}
	case ci >= 0 && chain[ci].pom.Dependencies[i].Version != "":
		set, ok = chainResolve(chain, chain[ci].pom.Dependencies[i].Version)
		found = true
	default:
		set, found, ok = bomVersion(chain, name, fetch, 0)
	}
	switch {
	case !ok:
		return nil
	case !found:
		return &ChainHintRelease{Version: v, Dropped: true}
	}
	fixes := false
	if c, ok := compareVersions(schemeMaven, set, target); ok && c >= 0 {
		fixes = mavenFixedAt(set, cves)
	}
	return &ChainHintRelease{Version: v, Range: set, Fixes: fixes}
}

// deciderChain is the pom g:a:v with its parents, nil when one cannot be read
// or has a profile that may change the versions it sets.
func deciderChain(g, a, v string, fetch func(g, a, v string) *mavenPOM) []mavenChainPOM {
	pom := fetch(g, a, v)
	if pom == nil || profileMaySetVersions(pom) {
		return nil
	}
	chain := []mavenChainPOM{{pom: pom, coord: g + ":" + a + ":" + v}}
	for pa, depth := pom.Parent, 0; pa != nil; depth++ {
		if depth >= maxMavenParentDepth {
			return nil
		}
		pp := fetch(pa.GroupID, pa.ArtifactID, pa.Version)
		if pp == nil || profileMaySetVersions(pp) {
			return nil
		}
		chain = append(chain, mavenChainPOM{pom: pp, coord: pa.GroupID + ":" + pa.ArtifactID + ":" + pa.Version})
		pa = pp.Parent
	}
	return chain
}

// profileMaySetVersions reports whether a pom has a profile that may be on
// without a build asking for it by name (one with a condition it turns on by,
// activeByDefault included) and changes dependencies, management, properties
// or the parent.
func profileMaySetVersions(p *mavenPOM) bool {
	for _, pr := range p.Profiles {
		if pr.Activation && (pr.Dependencies || pr.DependencyManagement || pr.Properties || pr.Parent) {
			return true
		}
	}
	return false
}

// bomVersion is the version the management of chain gives name: its own
// nearest entry, else the first BOM it imports that manages it, followed to
// a bounded depth. found is false when none manages it; ok is false when that
// cannot be told.
func bomVersion(chain []mavenChainPOM, name string, fetch func(g, a, v string) *mavenPOM, depth int) (string, bool, bool) {
	switch ci, i := nearestManagement(chain, name); {
	case ci == mavenUnknown:
		return "", false, false
	case ci >= 0:
		v, ok := chainResolve(chain, chain[ci].pom.DependencyManagement[i].Version)
		return v, true, ok
	}
	if depth > 3 {
		return "", false, false
	}
	for _, c := range chain {
		for _, d := range c.pom.DependencyManagement {
			if !d.IsImport() {
				continue
			}
			ig, ok1 := chainResolve(chain, d.GroupID)
			ia, ok2 := chainResolve(chain, d.ArtifactID)
			iv, ok3 := chainResolve(chain, d.Version)
			if !ok1 || !ok2 || !ok3 {
				return "", false, false
			}
			sub := deciderChain(ig, ia, iv, fetch)
			if sub == nil {
				return "", false, false
			}
			v, found, ok := bomVersion(sub, name, fetch, depth+1)
			if !ok || found {
				return v, found, ok
			}
		}
	}
	return "", false, true
}

// mavenFixedAt reports whether version v fixes every vulnerability, the
// fixes of another flavour than v's left out (a fix written with none counts
// for every flavour, as the plan reads it): at or above every fix a
// vulnerability reports in the series (major and minor version) of v, or,
// without one there, every fix in the major version of v, or, without one
// there either, every fix it reports. A vulnerability with no fix of the
// flavour is not fixed.
func mavenFixedAt(v string, cves []CVERef) bool {
	major, ok := mavenMajor(v)
	if !ok || len(cves) == 0 {
		return false
	}
	series, flavor := mavenMajorMinor(v), mavenFlavor(v)
	for _, c := range cves {
		var inSeries, inMajor, all []string
		for _, alt := range c.FixedVers {
			for _, one := range splitFixed(alt) {
				if _, ok := parseVersion(schemeMaven, one); !ok {
					return false
				}
				if f := mavenFlavor(one); f != "" && f != flavor {
					continue
				}
				all = append(all, one)
				if m, ok := mavenMajor(one); ok && m == major {
					inMajor = append(inMajor, one)
					if mavenMajorMinor(one) == series {
						inSeries = append(inSeries, one)
					}
				}
			}
		}
		bounds := inSeries
		if len(bounds) == 0 {
			bounds = inMajor
		}
		if len(bounds) == 0 {
			bounds = all
		}
		if len(bounds) == 0 {
			return false
		}
		for _, f := range bounds {
			if cmp, ok := compareVersions(schemeMaven, v, f); !ok || cmp < 0 {
				return false
			}
		}
	}
	return true
}

// mavenOtherMajorFix is the lowest version the advisories of a package report
// as a fix, of another major version than installed, not a pre-release and of
// the same flavour (or written with none), that fixes every one of them; ""
// when none does.
func mavenOtherMajorFix(installed string, cves []CVERef) string {
	major, ok := mavenMajor(installed)
	if !ok {
		return ""
	}
	var cands []string
	for _, c := range cves {
		for _, alt := range c.FixedVers {
			for _, one := range splitFixed(alt) {
				if f := mavenFlavor(one); f != "" && f != mavenFlavor(installed) {
					continue
				}
				if m, ok := mavenMajor(one); !ok || m == major || mavenIsPrerelease(one) {
					continue
				}
				cands = append(cands, one)
			}
		}
	}
	sort.Slice(cands, func(i, j int) bool { c, _ := compareVersions(schemeMaven, cands[i], cands[j]); return c < 0 })
	for _, v := range cands {
		if c, ok := compareVersions(schemeMaven, v, installed); ok && c > 0 && mavenFixedAt(v, cves) {
			return v
		}
	}
	return ""
}

// otherMajorRelease records on the packages of name, which no release of its
// installed major version reaches, the lowest release Maven Central lists at
// the target or above, of another major version, that is not a pre-release,
// has the same flavour and fixes every target vulnerability.
func (r *updateRun) otherMajorRelease(name, installed string, vs []string) {
	major, ok := mavenMajor(installed)
	if !ok {
		return
	}
	var cves []CVERef
	for _, k := range r.full.byName[name] {
		cves = append(cves, r.it.Packages[k].CVEs...)
	}
	best := ""
	for _, v := range vs {
		if m, ok := mavenMajor(v); !ok || m == major || mavenIsPrerelease(v) || mavenFlavor(v) != mavenFlavor(installed) {
			continue
		}
		if c, ok := compareVersions(schemeMaven, v, r.full.target[name]); !ok || c < 0 || !mavenFixedAt(v, cves) {
			continue
		}
		if best == "" {
			best = v
		} else if c, ok := compareVersions(schemeMaven, v, best); ok && c < 0 {
			best = v
		}
	}
	if best == "" {
		return
	}
	for _, k := range r.full.byName[name] {
		r.it.Packages[k].FixHint = &FixHint{Fix: &FixRelease{Version: best}}
	}
}

// clearHints takes the hints of an earlier run off the packages of name.
func (r *updateRun) clearHints(name string) {
	for _, k := range r.full.byName[name] {
		r.it.Packages[k].FixHint = nil
	}
}

// deciderOf names the pom at coord ("g:a:v") as the decider of kind.
func deciderOf(kind, coord string) *FixDecider {
	i := strings.LastIndex(coord, ":")
	if i < 0 {
		return nil
	}
	return &FixDecider{Kind: kind, Name: coord[:i], Version: coord[i+1:]}
}
