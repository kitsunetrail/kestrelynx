package remediation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// hintNpm is a registry of package versions and what each declares; a lookup
// it has no answer for fails and is counted.
type hintNpm struct {
	versions map[string][]string // name -> versions published
	dists    map[string]NpmDist  // name@version -> declaration
	lookups  map[string]int      // name or name@version -> lookups
	failing  map[string]bool     // names whose version list fails
}

func (f *hintNpm) PublishTimes(ctx context.Context, name string) (map[string]time.Time, int64, error) {
	f.count(name)
	if f.failing[name] {
		return nil, 0, errors.New("registry answered 500")
	}
	vs, ok := f.versions[name]
	if !ok {
		return nil, 0, ErrReleaseNotFound
	}
	out := map[string]time.Time{}
	for i, v := range vs {
		out[v] = time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)
	}
	return out, 100, nil
}

func (f *hintNpm) VersionDist(ctx context.Context, name, version string) (NpmDist, error) {
	f.count(name + "@" + version)
	d, ok := f.dists[name+"@"+version]
	if !ok {
		return NpmDist{}, fmt.Errorf("%s@%s: %w", name, version, ErrReleaseNotFound)
	}
	return d, nil
}

func (f *hintNpm) count(k string) {
	if f.lookups == nil {
		f.lookups = map[string]int{}
	}
	f.lookups[k]++
}

// multerRegistry is the registry of the case the hints are for: every
// @nestjs/platform-express of the 11 series and 12.2.0 require multer 2.4.0
// exactly, 12.3.x require 2.5.0, the fixed version.
func multerRegistry() *hintNpm {
	return &hintNpm{
		versions: map[string][]string{
			"@nestjs/platform-express": {"11.2.6", "11.2.7", "11.2.8", "12.2.0", "12.3.0", "12.3.2", "13.0.0-beta.1"},
			"multer":                   {"2.3.0", "2.4.0", "2.5.0", "3.0.0-rc.1"},
		},
		dists: map[string]NpmDist{
			"@nestjs/platform-express@11.2.8": {Dependencies: map[string]string{"multer": "2.4.0", "express": "5.2.1"}},
			"@nestjs/platform-express@12.3.2": {Dependencies: map[string]string{"multer": "2.5.0", "express": "5.2.1"}},
		},
	}
}

// hintItem is an npm item with multer held back by the dependent at the
// version given, which the project declares with spec ("" for a dependent the
// project does not declare).
func hintItem(parent, parentVersion, spec string, fixed ...string) (*LanguageItem, updateSet, *chainScope, *ChainUpdate) {
	if len(fixed) == 0 {
		fixed = []string{"2.5.0"}
	}
	it := &LanguageItem{Manager: ManagerNpm, Packages: []LanguagePackage{{CVEs: []CVERef{{VulnID: "CVE-2026-0001", FixedVers: fixed}}}}}
	set := updateSet{byName: map[string][]int{"multer": {0}}}
	scope := &chainScope{directParents: map[string]bool{}}
	via := []string{"express"}
	if spec != "" {
		scope.Tops = []chainTop{{Name: parent, Group: "dependencies", Spec: spec}}
		scope.directParents[parent+"@"+parentVersion] = true
		via = []string{parent}
	}
	chain := &ChainUpdate{Outcome: ChainNotFixed, Blocked: []ChainBlock{{Package: "multer", Version: "2.4.0", Parent: parent, ParentVersion: parentVersion, Range: "2.4.0", Proof: proofExact, Via: via}}}
	return it, set, scope, chain
}

func TestFixHints_InSpecAndLatest(t *testing.T) {
	reg := multerRegistry()
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
	it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	want := []ChainHint{{
		Package: "multer", Parent: "@nestjs/platform-express", ParentVersion: "11.2.7", Via: []string{"@nestjs/platform-express"}, Direct: true, Spec: "^11.2.0",
		InSpec: &ChainHintRelease{Version: "11.2.8", Range: "2.4.0"},
		Latest: &ChainHintRelease{Version: "12.3.2", Range: "2.5.0", Fixes: true},
	}}
	if !reflect.DeepEqual(chain.Hints, want) {
		t.Errorf("hints = %+v, want %+v", chain.Hints, want)
	}
	// The pre-release is never the newest release, and only the two releases
	// shown are read.
	if reg.lookups["@nestjs/platform-express@13.0.0-beta.1"] != 0 || reg.lookups["@nestjs/platform-express@12.3.0"] != 0 {
		t.Errorf("unexpected lookups: %v", reg.lookups)
	}
}

// The project's range allows nothing newer than the release it has: that is
// told from the requirement already known, without a lookup.
func TestFixHints_CurrentIsNewestInSpec(t *testing.T) {
	reg := multerRegistry()
	reg.versions["@nestjs/platform-express"] = []string{"11.2.7", "12.3.2"}
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
	it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 1 {
		t.Fatalf("hints = %+v", chain.Hints)
	}
	if got, want := chain.Hints[0].InSpec, (&ChainHintRelease{Version: "11.2.7", Range: "2.4.0"}); !reflect.DeepEqual(got, want) {
		t.Errorf("in spec = %+v, want %+v", got, want)
	}
	if reg.lookups["@nestjs/platform-express@11.2.7"] != 0 {
		t.Errorf("the release the project has was looked up")
	}
}

// A dependent the project does not declare gets the newest release only, and
// a release that no longer declares the package says so without claiming a fix.
func TestFixHints_IndirectDependentAndDropped(t *testing.T) {
	reg := multerRegistry()
	reg.dists["@nestjs/platform-express@12.3.2"] = NpmDist{Dependencies: map[string]string{"express": "5.2.1"}}
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
	it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "")
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 1 {
		t.Fatalf("hints = %+v", chain.Hints)
	}
	h := chain.Hints[0]
	if h.Spec != "" || h.InSpec != nil || !reflect.DeepEqual(h.Via, []string{"express"}) {
		t.Errorf("hint = %+v", h)
	}
	if want := (&ChainHintRelease{Version: "12.3.2", Dropped: true}); !reflect.DeepEqual(h.Latest, want) {
		t.Errorf("latest = %+v, want %+v", h.Latest, want)
	}
}

// A release whose declaration cannot be read as one requirement for the package
// is not judged.
func TestFixHints_UnjudgedReleases(t *testing.T) {
	cases := map[string]NpmDist{
		"peer only":    {PeerDependencies: map[string]string{"multer": "^2.5.0"}},
		"alias":        {Dependencies: map[string]string{"upload": "npm:multer@^2.5.0"}},
		"tag":          {Dependencies: map[string]string{"multer": "latest"}},
		"differ":       {Dependencies: map[string]string{"multer": "^2.4.0"}, OptionalDependencies: map[string]string{"multer": "^2.5.0"}},
		"shrinkwrap":   {Dependencies: map[string]string{"multer": "2.5.0"}, HasShrinkwrap: true},
		"peer and dep": {Dependencies: map[string]string{"multer": "2.5.0"}, PeerDependencies: map[string]string{"multer": "2.5.0"}},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			reg := multerRegistry()
			reg.dists["@nestjs/platform-express@12.3.2"] = d
			u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
			it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "")
			u.fixHints(context.Background(), it, set, scope, nil, chain)
			if len(chain.Hints) != 0 {
				t.Errorf("hints = %+v, want none", chain.Hints)
			}
		})
	}
}

// A range fixes only when it allows one released version that meets the fix of
// every vulnerability; with fixes in two series, either series counts.
func TestFixHints_RangeAgainstFixedVersions(t *testing.T) {
	cases := []struct {
		rng   string
		fixed []string
		want  bool
	}{
		{"^2.4.0", []string{"2.5.0"}, true},
		{"~2.4.0", []string{"2.5.0"}, false},
		{"2.5.0", []string{"2.5.0"}, true},
		{">=2.3.0 <2.5.0", []string{"2.5.0"}, false},
		{"~2.3.0", []string{"2.3.0", "2.5.0"}, true},
		{"^2.5.0", []string{"3.0.0-rc.1"}, false},
	}
	for _, tc := range cases {
		reg := multerRegistry()
		reg.dists["@nestjs/platform-express@12.3.2"] = NpmDist{Dependencies: map[string]string{"multer": tc.rng}}
		u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
		it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "", tc.fixed...)
		u.fixHints(context.Background(), it, set, scope, nil, chain)
		if len(chain.Hints) != 1 || chain.Hints[0].Latest == nil {
			t.Errorf("%s %v: hints = %+v", tc.rng, tc.fixed, chain.Hints)
			continue
		}
		if got := chain.Hints[0].Latest.Fixes; got != tc.want {
			t.Errorf("%s %v: fixes = %v, want %v", tc.rng, tc.fixed, got, tc.want)
		}
	}
}

// Hints are looked up only for npm and pnpm items whose dependents were found
// holding the package back and which did not take it to its fixed version, at
// most for maxHintPairs pairs, and a failed lookup leaves the hint out.
func TestFixHints_WhenLookedUp(t *testing.T) {
	t.Run("outcomes", func(t *testing.T) {
		for outcome, want := range map[string]bool{ChainNotFixed: true, ChainRejected: true, ChainNotTried: true, ChainAdopted: false, ChainFailed: false, ChainDeferred: false} {
			u := &LangUpdater{cfg: LangUpdateConfig{Npm: multerRegistry()}}
			it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
			chain.Outcome = outcome
			u.fixHints(context.Background(), it, set, scope, nil, chain)
			if got := len(chain.Hints) > 0; got != want {
				t.Errorf("%s: hints %v, want %v", outcome, got, want)
			}
		}
	})
	t.Run("manager", func(t *testing.T) {
		u := &LangUpdater{cfg: LangUpdateConfig{Npm: multerRegistry()}}
		it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
		it.Manager = ManagerUv
		u.fixHints(context.Background(), it, set, scope, nil, chain)
		if len(chain.Hints) != 0 {
			t.Errorf("uv got hints: %+v", chain.Hints)
		}
	})
	t.Run("pairs", func(t *testing.T) {
		reg := multerRegistry()
		u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
		it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
		b := chain.Blocked[0]
		for _, v := range []string{"11.2.6", "11.2.7", "11.2.8", "12.2.0"} {
			b.ParentVersion = v
			chain.Blocked = append(chain.Blocked, b)
		}
		reg.dists["@nestjs/platform-express@12.2.0"] = NpmDist{Dependencies: map[string]string{"multer": "2.4.0"}}
		u.fixHints(context.Background(), it, set, scope, nil, chain)
		if len(chain.Hints) != maxHintPairs {
			t.Errorf("hints = %d, want %d", len(chain.Hints), maxHintPairs)
		}
	})
	t.Run("failed lookup", func(t *testing.T) {
		reg := multerRegistry()
		reg.failing = map[string]bool{"multer": true}
		u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
		it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
		u.fixHints(context.Background(), it, set, scope, nil, chain)
		if len(chain.Hints) != 0 {
			t.Errorf("hints = %+v, want none", chain.Hints)
		}
	})
	t.Run("shared cache", func(t *testing.T) {
		reg := multerRegistry()
		sh := newItemShared()
		sh.cache.times["multer"] = map[string]time.Time{"2.4.0": {}, "2.5.0": {}}
		sh.cache.npm["@nestjs/platform-express@12.3.2"] = NpmDist{Dependencies: map[string]string{"multer": "2.5.0"}}
		u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
		it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
		u.fixHints(context.Background(), it, set, scope, sh, chain)
		if len(chain.Hints) != 1 || reg.lookups["multer"] != 0 || reg.lookups["@nestjs/platform-express@12.3.2"] != 0 {
			t.Errorf("hints = %+v, lookups = %v", chain.Hints, reg.lookups)
		}
	})
}

// At most maxHintPairs pairs are looked up, counting those whose lookups fail.
func TestFixHints_PairsLookedUpAreCapped(t *testing.T) {
	reg := multerRegistry()
	reg.failing = map[string]bool{"a": true, "b": true, "c": true}
	reg.versions["d"] = []string{"1.0.0", "2.0.0"}
	reg.dists["d@2.0.0"] = NpmDist{Dependencies: map[string]string{"multer": "2.5.0"}}
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
	it, set, scope, chain := hintItem("a", "1.0.0", "")
	b := chain.Blocked[0]
	for _, p := range []string{"b", "c", "d"} {
		b.Parent = p
		chain.Blocked = append(chain.Blocked, b)
	}
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 0 || reg.lookups["d"] != 0 {
		t.Errorf("hints = %+v, lookups = %v", chain.Hints, reg.lookups)
	}
}

// An alias of the package, with or without a range, beside the package's own
// name or not, leaves the release unjudged rather than read as dropped.
func TestFixHints_Aliases(t *testing.T) {
	for name, deps := range map[string]map[string]string{
		"without a range":     {"upload": "npm:multer"},
		"beside its own name": {"multer": "2.5.0", "upload": "npm:multer@^2.4.0"},
	} {
		t.Run(name, func(t *testing.T) {
			reg := multerRegistry()
			reg.dists["@nestjs/platform-express@12.3.2"] = NpmDist{Dependencies: deps}
			u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
			it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "")
			u.fixHints(context.Background(), it, set, scope, nil, chain)
			if len(chain.Hints) != 0 {
				t.Errorf("hints = %+v, want none", chain.Hints)
			}
		})
	}
	for spec, want := range map[string]string{
		"npm:multer": "multer", "npm:multer@^2": "multer", "npm:@scope/multer": "@scope/multer",
		"npm:@scope/multer@2.5.0": "@scope/multer", "^2.5.0": "", "npm:": "",
	} {
		if got := aliasTarget(spec); got != want {
			t.Errorf("aliasTarget(%q) = %q, want %q", spec, got, want)
		}
	}
}

// A dependent of the same name as a direct dependency but further down does
// not get the project's range for it, even when the direct dependency of that
// name is the one it hangs below (Via names it).
func TestFixHints_SameNameBelowADirectDependency(t *testing.T) {
	reg := multerRegistry()
	reg.dists["@nestjs/platform-express@11.2.6"] = NpmDist{Dependencies: map[string]string{"multer": "2.4.0"}}
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
	it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
	below := chain.Blocked[0]
	below.ParentVersion = "11.2.6"
	chain.Blocked = append(chain.Blocked, below)
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 2 {
		t.Fatalf("hints = %+v", chain.Hints)
	}
	if h := chain.Hints[0]; h.Spec != "^11.2.0" || h.InSpec == nil {
		t.Errorf("direct dependency: %+v", h)
	}
	if h := chain.Hints[1]; h.Spec != "" || h.InSpec != nil || h.Latest == nil {
		t.Errorf("same name below app-kit: %+v", h)
	}
}

// A range fixes only when one version of the package meets every
// vulnerability's fix.
func TestFixHints_EveryVulnerability(t *testing.T) {
	reg := multerRegistry()
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
	it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "")
	it.Packages[0].CVEs = append(it.Packages[0].CVEs, CVERef{VulnID: "CVE-2026-0002", FixedVers: []string{"3.0.0"}})
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 1 || chain.Hints[0].Latest == nil || chain.Hints[0].Latest.Fixes {
		t.Errorf("hints = %+v", chain.Hints)
	}
}

// The hints of a chain the item did not settle with are not looked up.
func TestSettledHints_OnlyForTheRecordedChain(t *testing.T) {
	reg := multerRegistry()
	u := &LangUpdater{cfg: LangUpdateConfig{Npm: reg}}
	it, set, scope, chain := hintItem("@nestjs/platform-express", "11.2.7", "^11.2.0")
	it.Update = &LanguageUpdate{Chain: &ChainUpdate{Outcome: ChainDeferred}}
	u.settledHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 0 || len(reg.lookups) != 0 {
		t.Errorf("hints = %+v, lookups = %v", chain.Hints, reg.lookups)
	}
	it.Update.Chain = chain
	u.settledHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 1 {
		t.Errorf("hints of the recorded chain = %+v", chain.Hints)
	}
}
