package main

import (
	"reflect"
	"testing"
)

// osSymlinkReport carries every operating-system package these tests need
// an owner for, and a Node application package with no node_modules tree
// at all — the two categories the saved symlink table and the ancestor
// package.json fallback exist to reach.
const osSymlinkReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-os-symlink-test:1",
  "Metadata": { "OS": { "Family": "debian" } },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "debian",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-3000", "PkgName": "mawk", "InstalledVersion": "1.3.4.20200120-3", "Severity": "LOW", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-3001", "PkgName": "tzdata", "InstalledVersion": "2024a-1", "Severity": "LOW", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-3002", "PkgName": "app-tool", "InstalledVersion": "2.0", "Severity": "LOW", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-3003", "PkgName": "libc-bin", "InstalledVersion": "2.36-9", "Severity": "LOW", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-3004", "PkgName": "libc6", "InstalledVersion": "2.36-9", "Severity": "LOW", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "node-pkg", "Target": "Node.js",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-4000", "PkgName": "app", "PkgPath": "app/package.json", "InstalledVersion": "1.0.0", "Severity": "LOW", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-4001", "PkgName": "left-pad", "PkgPath": "app/node_modules/left-pad/package.json", "InstalledVersion": "1.3.0", "Severity": "LOW", "Status": "fixed" }
      ]
    }
  ]
}`

func osSymlinkIndex(t *testing.T) *scanFileIndex {
	t.Helper()
	idx, _, err := buildScanFileIndex([]byte(osSymlinkReport), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	return idx
}

// osSymlinkAux is the layout information a collection would save for an
// image where awk is switched by update-alternatives, the timezone is a
// distribution-wide link, a deployment link points at a release directory
// by a relative name, and one package's own symlink names a file a
// different package ships — none of these owned at both hops by the same
// package, or (the last case) owned at either hop by the same one.
func osSymlinkAux() []AuxiliaryInputs {
	return []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-os-symlink",
		Symlinks: []SymlinkEntry{
			// update-alternatives: neither hop is owned by any package.
			{Path: "/usr/bin/awk", Target: "/etc/alternatives/awk"},
			{Path: "/etc/alternatives/awk", Target: "/usr/bin/mawk"},
			// A distribution-wide link: neither hop is owned either.
			{Path: "/etc/localtime", Target: "/usr/share/zoneinfo/Etc/UTC"},
			// A relative target, resolved against the link's own directory.
			{Path: "/opt/app/current", Target: "releases/v2"},
			// A symlink one package ships naming a file a different
			// package ships.
			{Path: "/usr/bin/ld.so", Target: "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"},
			// A two-entry loop.
			{Path: "/a", Target: "/b"},
			{Path: "/b", Target: "/a"},
			// A link to its own containing directory: crossed twice by a
			// path that repeats its own name, and still well-defined each
			// time, not a cycle.
			{Path: "/self", Target: "."},
		},
		OwnedPaths: []OwnedPathEntry{
			{Path: "/usr/bin/mawk", DBKind: "dpkg", Package: "mawk", Version: "1.3.4.20200120-3"},
			{Path: "/usr/share/zoneinfo/Etc/UTC", DBKind: "dpkg", Package: "tzdata", Version: "2024a-1"},
			{Path: "/opt/app/releases/v2/bin/tool", DBKind: "dpkg", Package: "app-tool", Version: "2.0"},
			{Path: "/usr/bin/ld.so", DBKind: "dpkg", Package: "libc-bin", Version: "2.36-9"},
			{Path: "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", DBKind: "dpkg", Package: "libc6", Version: "2.36-9"},
		},
	}}
}

func osSymlinkResolver(t *testing.T) *fileResolver {
	t.Helper()
	return newFileResolver(osSymlinkIndex(t), osSymlinkAux())
}

// TestUpdateAlternativesChainResolvesToTheSelectedTool checks (a): a tool
// switched by update-alternatives is owned by neither /usr/bin/awk nor
// /etc/alternatives/awk, only by the two-hop chain's own end.
func TestUpdateAlternativesChainResolvesToTheSelectedTool(t *testing.T) {
	r := osSymlinkResolver(t)
	out := r.resolve("/usr/bin/awk")
	if out.Unresolved || out.Conflict {
		t.Fatalf("the alternatives chain did not resolve: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "mawk" {
		t.Errorf("resolved to %v, want mawk", got)
	}
	if got := out.Matches[0].Via; got != "symlink:/usr/bin/mawk" {
		t.Errorf("via = %q, want the resolved path recorded", got)
	}
}

// TestLocaltimeLinkResolvesToTzdata checks (b): /etc/localtime itself is
// owned by no package, only the zoneinfo file it names is.
func TestLocaltimeLinkResolvesToTzdata(t *testing.T) {
	r := osSymlinkResolver(t)
	out := r.resolve("/etc/localtime")
	if out.Unresolved || out.Conflict {
		t.Fatalf("the localtime link did not resolve: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "tzdata" {
		t.Errorf("resolved to %v, want tzdata", got)
	}
}

// TestLoopingSymlinkChainIsUnresolved checks (c): a chain that loops is
// left unresolved rather than followed forever or guessed at.
func TestLoopingSymlinkChainIsUnresolved(t *testing.T) {
	r := osSymlinkResolver(t)
	if _, _, ok := r.resolveSymlinkChain("/a"); ok {
		t.Fatalf("a looping symlink chain resolved anyway")
	}
	if got := r.normalize("/a"); got != "/a" {
		t.Errorf("normalize of a looping path = %q, want the path left as it was", got)
	}
}

// TestResolveSymlinkChainFollowsARelativeTarget checks (d): a relative
// link target is resolved against the link's own containing directory, not
// against the container's root.
func TestResolveSymlinkChainFollowsARelativeTarget(t *testing.T) {
	r := osSymlinkResolver(t)
	out := r.resolve("/opt/app/current/bin/tool")
	if out.Unresolved || out.Conflict {
		t.Fatalf("a relative link target did not resolve: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "app-tool" {
		t.Errorf("resolved to %v, want app-tool", got)
	}
}

// TestSymlinkOwnedDifferentlyOnEachHopConfirmsBoth checks (e), revised
// after ground truth's own semantics were confirmed against a real run
// (Ubuntu 26.04's /usr/bin/cat, a uutils-coreutils symlink naming
// rust-coreutils's own binary underneath): a symlink one package ships
// naming a file a different package ships is not an ambiguity — truth.py
// itself counts using either hop as using both packages the chain names —
// so both are confirmed, with the resolved side's own Via recording the
// chain it was reached through. This is different from
// TestOriginalOwnerAloneDoesNotHideAmbiguityOnTheResolvedSide's own case:
// that one is a single file two packages both claim, which stays a
// conflict.
func TestSymlinkOwnedDifferentlyOnEachHopConfirmsBoth(t *testing.T) {
	r := osSymlinkResolver(t)
	out := r.resolve("/usr/bin/ld.so")
	if out.Unresolved || out.Conflict {
		t.Fatalf("a symlink owned by one package naming a file owned by another did not resolve cleanly: %+v", out)
	}
	got := packagesOf(out)
	if len(got) != 2 {
		t.Fatalf("resolved to %v, want both libc-bin and libc6", got)
	}
	want := map[string]bool{"libc-bin": true, "libc6": true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("resolved to unexpected package %q", p)
		}
	}
	var sawVia bool
	for _, m := range out.Matches {
		if m.File == "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" {
			if m.Via != "symlink:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" {
				t.Errorf("resolved side's via = %q, want the chain recorded", m.Via)
			}
			sawVia = true
		}
	}
	if !sawVia {
		t.Errorf("the resolved side's own file was not among the matches: %+v", out.Matches)
	}
}

// TestResolveSymlinkChainCrossesTheSameLinkTwiceWithoutLooping checks that
// a link to its own containing directory ("/self" ->
// ".") is crossed once for each repeated path component that names it, and
// each crossing is well-defined — this is not a cycle, and only the hop
// count (mirrored from resolveInRoot and truth.py's own resolver), never
// whether a particular link's own path was seen before, is what decides
// whether a chain is given up on.
func TestResolveSymlinkChainCrossesTheSameLinkTwiceWithoutLooping(t *testing.T) {
	r := osSymlinkResolver(t)
	resolved, changed, ok := r.resolveSymlinkChain("/self/self/file")
	if !ok {
		t.Fatalf("a link crossed twice by its own repeated name was treated as a loop")
	}
	if !changed {
		t.Errorf("resolveSymlinkChain reported no change for a path that crossed a link twice")
	}
	if resolved != "/file" {
		t.Errorf("resolved = %q, want /file", resolved)
	}
}

// TestOriginalOwnerAloneDoesNotHideAmbiguityOnTheResolvedSide checks that
// when the observed path has one clean owner but what
// it resolves to has two disagreeing ones, the ambiguity on the resolved
// side is not silently discarded in favor of the clean answer on the
// other.
func TestOriginalOwnerAloneDoesNotHideAmbiguityOnTheResolvedSide(t *testing.T) {
	const report = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-ambiguous-test:1",
  "Metadata": { "OS": { "Family": "debian" } },
  "Results": [
    { "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [
      { "VulnerabilityID": "CVE-2030-5000", "PkgName": "single-owner", "InstalledVersion": "1.0", "Severity": "LOW", "Status": "fixed" },
      { "VulnerabilityID": "CVE-2030-5001", "PkgName": "multi-a", "InstalledVersion": "1.0", "Severity": "LOW", "Status": "fixed" },
      { "VulnerabilityID": "CVE-2030-5002", "PkgName": "multi-b", "InstalledVersion": "1.0", "Severity": "LOW", "Status": "fixed" }
    ]}
  ]
}`
	idx, _, err := buildScanFileIndex([]byte(report), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	aux := []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-ambiguous",
		Symlinks: []SymlinkEntry{
			{Path: "/opt/link", Target: "/opt/target"},
		},
		OwnedPaths: []OwnedPathEntry{
			{Path: "/opt/link", DBKind: "dpkg", Package: "single-owner", Version: "1.0"},
			{Path: "/opt/target", DBKind: "dpkg", Package: "multi-a", Version: "1.0"},
			{Path: "/opt/target", DBKind: "dpkg", Package: "multi-b", Version: "1.0"},
		},
	}}
	r := newFileResolver(idx, aux)
	out := r.resolve("/opt/link")
	if !out.Conflict {
		t.Fatalf("a clean owner on the observed side hid an ambiguity on the resolved side: %+v", out)
	}
	if len(out.Matches) != 0 {
		t.Errorf("a conflicting path still produced %d match(es)", len(out.Matches))
	}
}

// TestUsrMergeAppliesAgainToASymlinkTarget checks that
// UsrMerge's own rewrite is not only applied once to the path as observed,
// but again to a symlink's own raw target when that target still uses a
// merged directory's pre-merge spelling.
func TestUsrMergeAppliesAgainToASymlinkTarget(t *testing.T) {
	const report = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-usrmerge-chain-test:1",
  "Metadata": { "OS": { "Family": "debian" } },
  "Results": [
    { "Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [
      { "VulnerabilityID": "CVE-2030-6000", "PkgName": "real-tool", "InstalledVersion": "1.0", "Severity": "LOW", "Status": "fixed" }
    ]}
  ]
}`
	idx, _, err := buildScanFileIndex([]byte(report), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	aux := []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-usrmerge-chain",
		UsrMerge: []SymlinkEntry{
			{Path: "/bin", Target: "usr/bin", Resolved: "/usr/bin"},
		},
		Symlinks: []SymlinkEntry{
			// A package's own symlink still spelled the pre-merge way.
			{Path: "/usr/bin/tool", Target: "/bin/real"},
		},
		OwnedPaths: []OwnedPathEntry{
			{Path: "/usr/bin/real", DBKind: "dpkg", Package: "real-tool", Version: "1.0"},
		},
	}}
	r := newFileResolver(idx, aux)
	out := r.resolve("/usr/bin/tool")
	if out.Unresolved || out.Conflict {
		t.Fatalf("a symlink target using the pre-merge spelling did not resolve: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "real-tool" {
		t.Errorf("resolved to %v, want real-tool", got)
	}
}

// TestNodeModulesFileResolvingOutsideIsNotAttributedToTheProject checks
// the a dependency's own file that a symlink chain
// leads outside node_modules entirely (a store kept next to, not inside,
// the project, say) is left unresolved rather than credited to the
// application's own manifest merely because the dependency's own manifest
// could not be found afterward.
func TestNodeModulesFileResolvingOutsideIsNotAttributedToTheProject(t *testing.T) {
	idx := osSymlinkIndex(t)
	aux := []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-node-escape",
		Symlinks: []SymlinkEntry{
			// A dependency stored outside node_modules and linked in.
			{Path: "/app/node_modules/dep", Target: "../vendor/dep"},
		},
	}}
	r := newFileResolver(idx, aux)
	out := r.resolve("/app/node_modules/dep/index.js")
	for _, m := range out.Matches {
		if m.File == "app/package.json" {
			t.Fatalf("a dependency's own file was attributed to the application's own manifest: %+v", out)
		}
	}
}

// TestNodeApplicationManifestIsFoundWithoutABoundary checks (f): a path
// outside any node_modules tree at all still reaches the report's own
// package.json, through the nearest ancestor directory that carries one,
// when nodePackageBoundary itself has no /node_modules/ to find.
func TestNodeApplicationManifestIsFoundWithoutABoundary(t *testing.T) {
	r := newFileResolver(osSymlinkIndex(t), nil)
	out := r.resolve("/app/app.js")
	if out.Unresolved || out.Conflict {
		t.Fatalf("the application's own manifest was not reached: %+v", out)
	}
	if got := out.Matches[0].File; got != "app/package.json" {
		t.Errorf("resolved to %q, want the application's own manifest", got)
	}
	if got := out.Matches[0].Rule; got != "node_project_manifest" {
		t.Errorf("rule = %q, want node_project_manifest", got)
	}
}

// TestNodeModulesBoundaryTakesPriorityOverTheProjectManifest checks (g):
// when a real node_modules boundary exists, it is used, never the
// ancestor-manifest fallback.
func TestNodeModulesBoundaryTakesPriorityOverTheProjectManifest(t *testing.T) {
	r := newFileResolver(osSymlinkIndex(t), nil)
	out := r.resolve("/app/node_modules/left-pad/index.js")
	if out.Unresolved || out.Conflict {
		t.Fatalf("the dependency's own manifest was not reached: %+v", out)
	}
	if got := out.Matches[0].File; got != "app/node_modules/left-pad/package.json" {
		t.Errorf("resolved to %q, want the dependency's own manifest, not the application's", got)
	}
	if got := out.Matches[0].Rule; got != "node_package_boundary" {
		t.Errorf("rule = %q, want node_package_boundary", got)
	}
}

// TestOldInputsWithNoSymlinkTableStillResolve checks (h): a reading saved
// before this symlink table existed carries no Symlinks at all, and every
// existing rule — the compiled binary, the module tree, and the saved
// operating-system path index — resolves exactly as it always did rather
// than treating the table's absence as one that somehow changes anything.
func TestOldInputsWithNoSymlinkTableStillResolve(t *testing.T) {
	aux := mappingAux()
	aux[0].Symlinks = nil
	r := newFileResolver(mappingIndex(t), aux)
	// UsrMerge's own entry is folded into the same table (see
	// addSymlinkTarget), so clearing Symlinks alone does not empty it —
	// only Symlinks itself is what this input predates.
	if want := map[string]string{"/lib": "usr/lib"}; !reflect.DeepEqual(r.symlinkTargets, want) {
		t.Fatalf("symlinkTargets = %v, want only the UsrMerge entry %v", r.symlinkTargets, want)
	}

	if out := r.resolve("/server"); out.Unresolved || out.Conflict {
		t.Errorf("the compiled binary rule stopped resolving: %+v", out)
	}
	if out := r.resolve("/usr/lib/x86_64-linux-gnu/libssl.so.3"); out.Unresolved || out.Conflict {
		t.Errorf("the saved operating-system path index stopped resolving: %+v", out)
	}
	// The module tree's own link (lodash stored once and linked into
	// place) is gone along with the rest of Symlinks, so the link
	// spelling alone is now unreachable — only the real directory's own
	// spelling, which the report names directly, still resolves.
	if out := r.resolve("/app/node_modules/.pnpm/lodash@4.17.15/node_modules/lodash/lodash.js"); out.Unresolved || out.Conflict {
		t.Errorf("the module tree's own path stopped resolving: %+v", out)
	}
}
