package remediation

import (
	"context"
	"sort"
	"strings"
	"time"
)

// ChainHint tells, for a package a dependent holds back, what releases of the
// dependent declare for it: the newest release the project's own range for
// the dependent allows (when the dependent is a direct dependency) and the
// newest release of all. Each is a fact about that one release; nothing is
// claimed of the releases between, nor that the release would resolve or work.
type ChainHint struct {
	Package       string   `json:"package"`
	Parent        string   `json:"parent"`
	ParentVersion string   `json:"parent_version"`
	Via           []string `json:"via,omitempty"`
	// Direct says Parent is one of the project's direct dependencies, and Spec
	// is the range the project declares for it ("" for none, which allows
	// every version).
	Direct bool              `json:"direct,omitempty"`
	Spec   string            `json:"spec,omitempty"`
	InSpec *ChainHintRelease `json:"in_spec,omitempty"`
	Latest *ChainHintRelease `json:"latest,omitempty"`
}

// ChainHintRelease is what one release of the dependent declares for the
// package: the range, and whether the range allows a released version of the
// package that fixes every vulnerability of it. Dropped says the release
// declares no requirement for the package at all, which does not mean the
// package leaves the project (another package may still bring it in).
type ChainHintRelease struct {
	Version string `json:"version"`
	Range   string `json:"range,omitempty"`
	Fixes   bool   `json:"fixes"`
	Dropped bool   `json:"dropped,omitempty"`
}

// FixHint is, for a package an update could not take to its fixed version,
// what holds it back: the packages whose requirements leave the fixed version
// out, and for each of them what its newest release declares for the package
// (Releases, empty when that could not be told).
type FixHint struct {
	HeldBy   []FixHolder `json:"held_by,omitempty"`
	Releases []ChainHint `json:"releases,omitempty"`
	// GoLine is, for a Go update held back by the Go it needs, the module
	// version whose go.mod asks for that Go.
	GoLine *GoLineHint `json:"go_line,omitempty"`
	// Fix is, for a package whose fixes are all of another major version, the
	// lowest of them that fixes every target vulnerability; Direct says the
	// project requires the package itself (go.mod lists it without
	// "// indirect"), so its own imports name the major version. HeldBy are
	// then the modules the project requires whose go.mod requires the
	// package, Range the version each asks for.
	Fix    *FixRelease `json:"fix,omitempty"`
	Direct bool        `json:"direct,omitempty"`
	// DecidedBy is, for a Maven or Gradle package whose version a pom
	// outside the project decides, that pom; Releases then say what two of
	// its releases set the package to (InSpec the newest in its minor
	// version, Latest the newest).
	DecidedBy *FixDecider `json:"decided_by,omitempty"`
}

// FixRelease is a release of a package that fixes it.
type FixRelease struct {
	Version string `json:"version"`
}

// GoLineHint is a module version whose go.mod declares the go line Go, which
// an update of the package to To (the version it was asked for, "" when it
// was not reached) needs; BuiltWith is the Go the running binaries were built
// with, when the update was held back by it.
type GoLineHint struct {
	Module    string `json:"module"`
	Version   string `json:"version"`
	Go        string `json:"go"`
	BuiltWith string `json:"built_with,omitempty"`
	To        string `json:"to,omitempty"`
}

// FixHolder is a package of the project, at the version the project has, that
// asks for the package at Range, which leaves out its fixed version.
type FixHolder struct {
	Parent        string `json:"parent"`
	ParentVersion string `json:"parent_version"`
	Range         string `json:"range"`
}

// fixHintReasons are the package reasons a FixHint is read with.
var fixHintReasons = map[Reason]bool{
	ReasonDependentsHoldBack: true, ReasonGoLineRaised: true, ReasonGoRuntimeUnavailable: true, ReasonFixInOtherMajor: true,
	ReasonMavenVersionSourceUnsupported: true, ReasonGradleVersionSourceUnsupported: true, ReasonMavenReleaseNotFound: true,
	ReasonMavenFixInOtherMajor: true,
}

// The hints are looked up after the item is settled, within limits of their
// own, so that they never take what the update needs: at most this many
// (package, dependent) pairs per item, and this long in all.
const (
	maxHintPairs = 3
	hintTimeout  = 30 * time.Second
)

// hintOutcomes are the outcomes of a chain update that a hint is looked up
// for: the dependents were found holding the package back, and the package
// was not taken to its fixed version.
var hintOutcomes = map[string]bool{ChainNotFixed: true, ChainRejected: true, ChainNotTried: true}

// fixHints looks up the hints of a chain update that did not take its packages
// to their fixed versions and records them on the chain. A lookup that fails
// or cannot be judged leaves its part of the hint out; nothing about the item
// changes.
func (u *LangUpdater) fixHints(ctx context.Context, it *LanguageItem, set updateSet, scope *chainScope, sh *itemShared, chain *ChainUpdate) {
	if chain == nil || scope == nil || !hintOutcomes[chain.Outcome] || len(chain.Blocked) == 0 {
		return
	}
	src := u.hintSourceFor(it.Manager, sh)
	if src == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, hintTimeout)
	defer cancel()
	l := &hintLookup{ctx: ctx, sc: it.Manager.scheme(), src: src, rels: map[string][]string{}}

	specs := map[string]string{}
	for _, t := range scope.Tops {
		specs[t.Name] = t.Spec
	}
	type pair struct{ pkg, parent, version string }
	seen := map[pair]bool{}
	var hints []ChainHint
	for _, b := range chain.Blocked {
		p := pair{b.Package, b.Parent, b.ParentVersion}
		if seen[p] {
			continue
		}
		seen[p] = true
		if len(seen) > maxHintPairs || ctx.Err() != nil {
			break
		}
		var cves []CVERef
		for _, i := range set.byName[b.Package] {
			cves = append(cves, it.Packages[i].CVEs...)
		}
		if len(cves) == 0 {
			continue
		}
		h := ChainHint{Package: b.Package, Parent: b.Parent, ParentVersion: b.ParentVersion, Via: append([]string(nil), b.Via...)}
		// The project's range is the dependent's own only where the project
		// requires that entry itself, not another entry of the same name
		// further down.
		if spec, top := specs[b.Parent]; top && scope.directParents[b.Parent+"@"+b.ParentVersion] {
			h.Direct, h.Spec = true, spec
		}
		l.hint(&h, b.Range, cves)
		if h.InSpec != nil || h.Latest != nil {
			hints = append(hints, h)
		}
	}
	chain.Hints = hints
}

// packageHints settles the hints of an item's packages once the item is
// settled: a hint is dropped from a package whose reason it is not read with,
// and what each manager looks up for the hints left is looked up, within the
// limits of the hints: for pip, what the newest release of each package
// holding a package back declares for it; for Go, what brings in a package
// whose fixes are all of another major version; for Maven and Gradle, what
// the releases of the pom that decides a package's version set it to. A lookup
// that fails or cannot be judged leaves its part out.
func (u *LangUpdater) packageHints(ctx context.Context, it *LanguageItem) {
	for i := range it.Packages {
		if p := &it.Packages[i]; p.FixHint != nil && p.Hint() == nil {
			p.FixHint = nil
		}
	}
	switch it.Manager {
	case ManagerGo:
		u.goMajorHints(ctx, it)
	case ManagerMaven, ManagerGradle:
		u.mavenHints(ctx, it)
	case ManagerPip:
		u.holderHints(ctx, it)
	}
}

// holderHints looks up, for each package held back by the packages that
// depend on it, what the newest release of each of them declares for it.
func (u *LangUpdater) holderHints(ctx context.Context, it *LanguageItem) {
	var todo []int
	cves := map[string][]CVERef{}
	for i := range it.Packages {
		p := &it.Packages[i]
		if p.FixHint == nil {
			continue
		}
		p.FixHint.Releases = nil
		if len(p.FixHint.HeldBy) > 0 {
			todo = append(todo, i)
			cves[p.matchName()] = append(cves[p.matchName()], p.CVEs...)
		}
	}
	if len(todo) == 0 {
		return
	}
	src := u.hintSourceFor(it.Manager, nil)
	if src == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, hintTimeout)
	defer cancel()
	l := &hintLookup{ctx: ctx, sc: it.Manager.scheme(), src: src, rels: map[string][]string{}, judgeHeld: true}
	type pair struct{ pkg, parent, version string }
	looked := map[pair]*ChainHint{}
	for _, i := range todo {
		p := &it.Packages[i]
		for _, h := range p.FixHint.HeldBy {
			k := pair{p.matchName(), h.Parent, h.ParentVersion}
			c, seen := looked[k]
			if !seen {
				if len(looked) >= maxHintPairs || ctx.Err() != nil {
					continue
				}
				c = &ChainHint{Package: p.Name, Parent: h.Parent, ParentVersion: h.ParentVersion}
				l.hint(c, h.Range, cves[p.matchName()])
				if c.InSpec == nil && c.Latest == nil {
					c = nil
				}
				looked[k] = c
			}
			if c != nil {
				p.FixHint.Releases = append(p.FixHint.Releases, *c)
			}
		}
	}
}

// hintSource reads, for the hints of one manager, what the index publishes.
type hintSource interface {
	// versions returns the versions of name the index offers; ok is false
	// when they cannot be told.
	versions(ctx context.Context, name string) (vs []string, ok bool)
	// requirement returns what parent at version declares for pkg: its range,
	// or dropped when it declares no requirement for pkg at all; ok is false
	// when that cannot be told.
	requirement(ctx context.Context, parent, version, pkg string) (rng string, dropped, ok bool)
	// allows reports whether rng allows version; evaluable is false when that
	// cannot be told.
	allows(rng, version string) (allowed, evaluable bool)
}

// hintSourceFor is the source of the hints of a manager, nil for a manager
// without one or when the index client cannot list the versions of a package.
func (u *LangUpdater) hintSourceFor(m DependencyManager, sh *itemShared) hintSource {
	switch m {
	case ManagerNpm, ManagerPnpm:
		if u.cfg.Npm == nil {
			return nil
		}
		if t, ok := u.cfg.Npm.(NpmPublishTimes); ok {
			return &npmHints{m: m, npm: u.cfg.Npm, times: t, sh: sh}
		}
	case ManagerUv, ManagerPip:
		if u.cfg.PyPI == nil {
			return nil
		}
		if v, ok := u.cfg.PyPI.(PyPIVersions); ok {
			return &pyHints{py: u.cfg.PyPI, vers: v, sh: sh}
		}
	}
	return nil
}

// hintLookup judges the releases of the dependents of one item.
type hintLookup struct {
	ctx  context.Context
	sc   scheme
	src  hintSource
	rels map[string][]string
	// judgeHeld says the range the dependent's current release declares is
	// judged against the released versions too: it is known to leave out the
	// version the update asked for, not every fixed version.
	judgeHeld bool
}

// releases returns the released versions of a package (pre-releases left
// out), newest first.
func (l *hintLookup) releases(name string) ([]string, bool) {
	if rs, ok := l.rels[name]; ok {
		return rs, len(rs) > 0
	}
	vs, ok := l.src.versions(l.ctx, name)
	if !ok {
		return nil, false
	}
	type rel struct {
		s string
		v version
	}
	var rs []rel
	for _, s := range vs {
		if v, ok := parseVersion(l.sc, s); ok && !isPre(v) {
			rs = append(rs, rel{s, v})
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].v.compare(rs[j].v) > 0 })
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.s
	}
	l.rels[name] = out
	return out, len(out) > 0
}

// hint fills the releases of h: the newest release the project's range
// allows, when the dependent is a direct dependency, and the newest release of
// all when it is another. Either may be the release the project has, whose
// requirement (held, the range given) is known without a lookup; a release
// older than that is not shown.
func (l *hintLookup) hint(h *ChainHint, held string, cves []CVERef) {
	parents, ok := l.releases(h.Parent)
	if !ok {
		return
	}
	children, ok := l.releases(h.Package)
	if !ok {
		return
	}
	cur, ok := parseVersion(l.sc, h.ParentVersion)
	if !ok {
		return
	}
	at := func(s string) *ChainHintRelease {
		v, _ := parseVersion(l.sc, s)
		switch c := v.compare(cur); {
		case c == 0 && l.judgeHeld:
			return l.judged(s, held, children, cves)
		case c == 0:
			return &ChainHintRelease{Version: s, Range: held}
		case c > 0:
			return l.release(h.Parent, s, h.Package, children, cves)
		}
		return nil
	}
	inSpec := ""
	if h.Direct {
		for _, s := range parents {
			allowed, evaluable := l.src.allows(h.Spec, s)
			if !evaluable {
				break
			}
			if allowed {
				inSpec = s
				break
			}
		}
	}
	if inSpec != "" {
		h.InSpec = at(inSpec)
	}
	if latest := parents[0]; latest != inSpec {
		h.Latest = at(latest)
	}
}

// release judges what one release of the dependent declares for the package,
// or nil when that cannot be told.
func (l *hintLookup) release(parent, version, pkg string, children []string, cves []CVERef) *ChainHintRelease {
	rng, dropped, ok := l.src.requirement(l.ctx, parent, version, pkg)
	switch {
	case !ok:
		return nil
	case dropped:
		return &ChainHintRelease{Version: version, Dropped: true}
	}
	return l.judged(version, rng, children, cves)
}

// judged is a release of the dependent that declares rng for the package:
// whether rng allows a released version that fixes it, or nil when that
// cannot be told.
func (l *hintLookup) judged(version, rng string, children []string, cves []CVERef) *ChainHintRelease {
	fixes := false
	for _, s := range children {
		allowed, evaluable := l.src.allows(rng, s)
		if !evaluable {
			return nil
		}
		if allowed && fixedAt(l.sc, s, cves) {
			fixes = true
			break
		}
	}
	return &ChainHintRelease{Version: version, Range: rng, Fixes: fixes}
}

// npmHints reads the npm registry, reusing what the item's runs have read.
type npmHints struct {
	m     DependencyManager
	npm   NpmRegistry
	times NpmPublishTimes
	sh    *itemShared
}

func (n *npmHints) versions(ctx context.Context, name string) ([]string, bool) {
	t, ok := map[string]time.Time(nil), false
	if n.sh != nil {
		t, ok = n.sh.cache.times[name]
	}
	if !ok {
		var err error
		if t, _, err = n.times.PublishTimes(ctx, name); err != nil {
			return nil, false
		}
	}
	out := make([]string, 0, len(t))
	for v := range t {
		out = append(out, v)
	}
	return out, true
}

// requirement reads the registry's declaration of the release, reduced as the
// chain update reduces it. A peer dependency, an alias of the package, ranges
// that differ, or a shrinkwrap the release carries cannot be told as one
// requirement.
func (n *npmHints) requirement(ctx context.Context, parent, version, pkg string) (string, bool, bool) {
	d, ok := NpmDist{}, false
	if n.sh != nil {
		d, ok = n.sh.cache.npm[parent+"@"+version]
	}
	if !ok {
		var err error
		if d, err = n.npm.VersionDist(ctx, parent, version); err != nil {
			return "", false, false
		}
	}
	if d.HasShrinkwrap || aliases(d, pkg) {
		return "", false, false
	}
	edges, unsupported := normalizeParentEdges(n.m, nil, d)
	for _, u := range unsupported {
		if u == pkg {
			return "", false, false
		}
	}
	e, found := edges[pkg]
	switch {
	case !found:
		return "", true, true
	case e.peerOnly:
		return "", false, false
	}
	return e.spec, false, true
}

func (n *npmHints) allows(rng, v string) (bool, bool) {
	sv, ok := parseSemver(v)
	if !ok {
		return false, false
	}
	return npmRangeAllows(rng, sv)
}

// pyHints reads PyPI, reusing what the item's runs have read.
type pyHints struct {
	py   PyPIFiles
	vers PyPIVersions
	sh   *itemShared
}

func (p *pyHints) versions(ctx context.Context, name string) ([]string, bool) {
	vs, _, err := p.vers.Versions(ctx, name)
	return vs, err == nil
}

// requirement reads the release's requires_dist as the chain update does: a
// requirement counts whatever its marker says, as a uv.lock holds every
// environment at once (for pip, which resolves for one environment, that is
// the stricter reading), and a package required with different specifiers, or
// a requirement that cannot be read, cannot be told as one requirement.
func (p *pyHints) requirement(ctx context.Context, parent, version, pkg string) (string, bool, bool) {
	key := normalizePyName(parent) + "==" + version
	rel, ok := PyPIRelease{}, false
	if p.sh != nil {
		rel, ok = p.sh.cache.py[key]
	}
	if !ok {
		var err error
		if rel, err = p.py.Release(ctx, parent, version); err != nil {
			return "", false, false
		}
	}
	want := normalizePyName(pkg)
	found, spec := false, ""
	for _, rd := range rel.RequiresDist {
		name, constraint, _, ok := requirementOf(rd)
		if !ok {
			return "", false, false
		}
		if normalizePyName(name) != want {
			continue
		}
		if found && constraint != spec {
			return "", false, false
		}
		found, spec = true, constraint
	}
	if !found {
		return "", true, true
	}
	return spec, false, true
}

func (p *pyHints) allows(rng, v string) (bool, bool) {
	pv, ok := parsePEP440(v)
	if !ok {
		return false, false
	}
	return pySatisfies(pv, rng)
}

// aliases reports whether a release declares the package under another name:
// "other": "npm:pkg@range", or "npm:pkg" with no range, a scoped name
// included.
func aliases(d NpmDist, pkg string) bool {
	for _, deps := range []map[string]string{d.Dependencies, d.OptionalDependencies, d.PeerDependencies} {
		for _, spec := range deps {
			if aliasTarget(spec) == pkg {
				return true
			}
		}
	}
	return false
}

// aliasTarget is the name an "npm:" alias stands for, "" for a spec that is
// not one.
func aliasTarget(spec string) string {
	s, ok := strings.CutPrefix(strings.TrimSpace(spec), "npm:")
	if !ok {
		return ""
	}
	from := 0
	if strings.HasPrefix(s, "@") {
		from = 1 // the "@" of a scope is not the one before the range
	}
	if i := strings.IndexByte(s[from:], '@'); i >= 0 {
		return s[:from+i]
	}
	return s
}
