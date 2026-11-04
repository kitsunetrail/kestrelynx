package remediation

import (
	"context"
	"sort"
	"strings"
)

// maxGoHintReads bounds the go.mod files the hints of one Go item read: of
// the modules the project requires, to find those that require a package,
// and of their latest versions.
var maxGoHintReads = 200

// goMajorHints records, for each Go package of the item whose fixes are all of
// another major version, the lowest such fix and what brings the old major
// version in: the project itself, or the modules its go.mod requires whose
// go.mod requires the package, with what the latest version of each requires
// of it. A file or lookup that fails leaves its part out.
func (u *LangUpdater) goMajorHints(ctx context.Context, it *LanguageItem) {
	var idx []int
	for i, p := range it.Packages {
		if p.Reason == ReasonFixInOtherMajor && p.FixHint == nil {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	for _, i := range idx {
		if v := goOtherMajorFix(it.Packages[i]); v != "" {
			it.Packages[i].FixHint = &FixHint{Fix: &FixRelease{Version: v}}
		}
	}
	reg := u.cfg.Go
	if reg == nil || u.cfg.GitHub == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, hintTimeout)
	defer cancel()
	sf, fail := u.readUnitSources(ctx, it)
	if fail != nil {
		return
	}
	gm, err := parseGoMod(sf.lock)
	if err != nil {
		return
	}
	graph, err := newGoModGraph(ctx, reg, u.goCache, sf.manifest)
	if err != nil {
		return
	}
	reqs := append([]goRequire(nil), gm.requires...)
	sort.Slice(reqs, func(a, b int) bool { return reqs[a].path < reqs[b].path })
	// What each requirement of the project requires, read once for every
	// package, within the bound.
	reads := 0
	of := map[string]*goModEntry{}
	read := func(path, version string) (*goModEntry, bool) {
		k := path + "@" + version
		if e, ok := of[k]; ok {
			return e, e != nil
		}
		if reads >= maxGoHintReads || ctx.Err() != nil {
			return nil, false
		}
		reads++
		e, err := graph.entry(path, version)
		if err != nil {
			e = nil
		}
		of[k] = e
		return e, e != nil
	}
	pairs := 0
	for _, i := range idx {
		p := &it.Packages[i]
		if p.FixHint == nil {
			p.FixHint = &FixHint{}
		}
		h := p.FixHint
		for _, r := range reqs {
			if r.path == p.Name && !r.indirect {
				h.Direct = true
			}
		}
		if h.Direct {
			continue
		}
		for _, r := range reqs {
			if r.path == p.Name {
				continue
			}
			e, ok := read(r.path, r.version)
			if !ok {
				continue
			}
			for _, x := range e.reqs {
				if x.path == p.Name {
					h.HeldBy = append(h.HeldBy, FixHolder{Parent: r.path, ParentVersion: r.version, Range: x.version})
					break
				}
			}
		}
		for _, holder := range h.HeldBy {
			if pairs >= maxHintPairs || ctx.Err() != nil {
				break
			}
			pairs++
			if rel := goLatestRequirement(ctx, reg, read, holder, p.Name); rel != nil {
				h.Releases = append(h.Releases, ChainHint{Package: p.Name, Parent: holder.Parent, ParentVersion: holder.ParentVersion, Latest: rel})
			}
		}
		if h.Fix == nil && !h.Direct && len(h.HeldBy) == 0 {
			p.FixHint = nil
		}
	}
}

// goLatestRequirement is what the latest version of a module that requires
// path declares for it: the version it requires (which is of the old major
// version, so no fix), or that it does not require it; nil when that cannot
// be told, a go.mod the proxy made up for a module without one included.
func goLatestRequirement(ctx context.Context, reg GoModuleRegistry, read func(path, version string) (*goModEntry, bool), holder FixHolder, path string) *ChainHintRelease {
	latest, err := reg.Latest(ctx, holder.Parent)
	if err != nil {
		return nil
	}
	if c, ok := compareVersions(schemeGo, latest.Version, holder.ParentVersion); !ok || c < 0 {
		return nil
	} else if c == 0 {
		return &ChainHintRelease{Version: holder.ParentVersion, Range: holder.Range}
	}
	e, ok := read(holder.Parent, latest.Version)
	if !ok || e.synth {
		return nil
	}
	for _, x := range e.reqs {
		if x.path == path {
			return &ChainHintRelease{Version: latest.Version, Range: x.version}
		}
	}
	return &ChainHintRelease{Version: latest.Version, Dropped: true}
}

// goOtherMajorFix is the lowest version the advisories of a package name as a
// fix that fixes every one of them, "" when none does; for a package whose
// fixes are all of another major version, it is of that one.
func goOtherMajorFix(p LanguagePackage) string {
	best, bestV := "", version(nil)
	for _, c := range p.CVEs {
		for _, f := range c.FixedVers {
			s := strings.TrimSpace(f)
			if !strings.HasPrefix(s, "v") {
				s = "v" + s
			}
			v, ok := parseVersion(schemeGo, s)
			if !ok || (bestV != nil && v.compare(bestV) >= 0) || !fixedAt(schemeGo, s, p.CVEs) {
				continue
			}
			best, bestV = s, v
		}
	}
	return best
}
