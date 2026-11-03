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
	// Spec is the range the project declares for Parent when Parent is one of
	// its direct dependencies, "" otherwise.
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
	if it.Manager != ManagerNpm && it.Manager != ManagerPnpm {
		return
	}
	if u.cfg.Npm == nil {
		return
	}
	reg, ok := u.cfg.Npm.(NpmPublishTimes)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, hintTimeout)
	defer cancel()
	l := &hintLookup{ctx: ctx, m: it.Manager, npm: u.cfg.Npm, times: reg, sh: sh, timesOf: map[string]map[string]time.Time{}}

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
			h.Spec = spec
		}
		l.hint(&h, b.Range, cves)
		if h.InSpec != nil || h.Latest != nil {
			hints = append(hints, h)
		}
	}
	chain.Hints = hints
}

// hintLookup reads the registry for the hints of one item, reusing what the
// item's runs have read.
type hintLookup struct {
	ctx     context.Context
	m       DependencyManager
	npm     NpmRegistry
	times   NpmPublishTimes
	sh      *itemShared
	timesOf map[string]map[string]time.Time
}

// releases returns the released versions of a package, newest first.
func (l *hintLookup) releases(name string) ([]string, bool) {
	t, ok := l.timesOf[name]
	if !ok && l.sh != nil {
		t, ok = l.sh.cache.times[name]
	}
	if !ok {
		var err error
		if t, _, err = l.times.PublishTimes(l.ctx, name); err != nil {
			return nil, false
		}
	}
	l.timesOf[name] = t
	type rel struct {
		s string
		v semver
	}
	var rs []rel
	for s := range t {
		if v, ok := parseSemver(s); ok && !v.isPrerelease() {
			rs = append(rs, rel{s, v})
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].v.compare(rs[j].v) > 0 })
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.s
	}
	return out, len(out) > 0
}

// dist returns what the registry declares for name at version.
func (l *hintLookup) dist(name, version string) (NpmDist, bool) {
	if l.sh != nil {
		if d, ok := l.sh.cache.npm[name+"@"+version]; ok {
			return d, true
		}
	}
	d, err := l.npm.VersionDist(l.ctx, name, version)
	return d, err == nil
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
	sc := l.m.scheme()
	cur, ok := parseSemver(h.ParentVersion)
	if !ok {
		return
	}
	at := func(s string) *ChainHintRelease {
		v, _ := parseSemver(s)
		switch c := v.compare(cur); {
		case c == 0:
			return &ChainHintRelease{Version: s, Range: held}
		case c > 0:
			return l.release(h.Parent, s, h.Package, children, sc, cves)
		}
		return nil
	}
	inSpec := ""
	if h.Spec != "" {
		for _, s := range parents {
			v, _ := parseSemver(s)
			allowed, evaluable := npmRangeAllows(h.Spec, v)
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

// release judges what one release of the dependent declares for the
// package, or nil when that cannot be told: the declaration is not one
// requirement (a peer dependency, an alias of the package, ranges that
// differ), the range cannot be evaluated, or the release carries its own
// shrinkwrap.
func (l *hintLookup) release(parent, version, pkg string, children []string, sc scheme, cves []CVERef) *ChainHintRelease {
	d, ok := l.dist(parent, version)
	if !ok || d.HasShrinkwrap {
		return nil
	}
	if aliases(d, pkg) {
		return nil
	}
	edges, unsupported := normalizeParentEdges(l.m, nil, d)
	for _, n := range unsupported {
		if n == pkg {
			return nil
		}
	}
	e, found := edges[pkg]
	if !found {
		return &ChainHintRelease{Version: version, Dropped: true}
	}
	if e.peerOnly {
		return nil
	}
	fixes := false
	for _, s := range children {
		v, _ := parseSemver(s)
		allowed, evaluable := npmRangeAllows(e.spec, v)
		if !evaluable {
			return nil
		}
		if allowed && fixedAt(sc, s, cves) {
			fixes = true
			break
		}
	}
	return &ChainHintRelease{Version: version, Range: e.spec, Fixes: fixes}
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
