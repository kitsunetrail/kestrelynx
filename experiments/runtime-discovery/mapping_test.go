package main

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// mappingReport is a scan report carrying one package of each ecosystem
// whose mapping rule differs, written in the shape a real report takes:
// a compiled binary's path on the result, every other language package's
// path on the package itself, and operating-system packages with no path
// at all.
const mappingReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-mapping-test:1",
  "Metadata": { "OS": { "Family": "debian" }, "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "debian",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-1000", "PkgName": "libssl3", "InstalledVersion": "3.0.13-1", "Severity": "HIGH", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "gobinary", "Target": "server",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2020-14040", "PkgName": "golang.org/x/text", "InstalledVersion": "v0.3.0", "Severity": "HIGH", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-1002", "PkgName": "stdlib", "InstalledVersion": "1.22.0", "Severity": "HIGH", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "jar", "Target": "Java",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-core", "PkgPath": "app/log4j-core-2.14.1.jar", "InstalledVersion": "2.14.1", "Severity": "CRITICAL", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-nested", "PkgPath": "app/fat.jar/BOOT-INF/lib/log4j-core-2.14.1.jar", "InstalledVersion": "2.14.1", "Severity": "CRITICAL", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "node-pkg", "Target": "Node.js",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash", "PkgPath": "app/node_modules/.pnpm/lodash@4.17.15/node_modules/lodash/package.json", "InstalledVersion": "4.17.15", "Severity": "HIGH", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-1004", "PkgName": "nested-dep", "PkgPath": "app/node_modules/outer/node_modules/nested-dep/package.json", "InstalledVersion": "1.0.0", "Severity": "HIGH", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-1005", "PkgName": "nested-dep", "PkgPath": "app/node_modules/nested-dep/package.json", "InstalledVersion": "2.0.0", "Severity": "HIGH", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "python-pkg", "Target": "Python",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2023-38325", "PkgName": "cryptography", "PkgPath": "usr/local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info/METADATA", "InstalledVersion": "41.0.0", "Severity": "HIGH", "Status": "fixed" },
        { "VulnerabilityID": "CVE-2030-1006", "PkgName": "oldstyle", "PkgPath": "usr/lib/python3/dist-packages/oldstyle-1.0.egg-info/PKG-INFO", "InstalledVersion": "1.0", "Severity": "HIGH", "Status": "fixed" }
      ]
    }
  ]
}`

func mappingIndex(t *testing.T) *scanFileIndex {
	t.Helper()
	idx, _, err := buildScanFileIndex([]byte(mappingReport), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	return idx
}

// mappingAux is the layout information a collection would have saved at
// observation time: a merged top-level directory, the link a
// content-addressed package manager leaves behind, the installed-file
// manifest for one distribution, and a distribution recorded in the older
// form that has no manifest at all.
func mappingAux() []AuxiliaryInputs {
	return []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux1",
		UsrMerge: []SymlinkEntry{{Path: "/lib", Target: "usr/lib", Resolved: "/usr/lib"}},
		Symlinks: []SymlinkEntry{
			{Path: "/app/node_modules/lodash", Target: ".pnpm/lodash@4.17.15/node_modules/lodash",
				Resolved: "/app/node_modules/.pnpm/lodash@4.17.15/node_modules/lodash"},
		},
		PythonSearchDirs: []PythonSearchDir{
			{Path: "/usr/local/lib/python3.12/site-packages", Derivation: "filesystem_scan"},
			{Path: "/usr/lib/python3/dist-packages", Derivation: "filesystem_scan"},
		},
		DistInfoRecords: []DistInfoRecord{{
			DistInfoDir:  "/usr/local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info",
			MetadataPath: "/usr/local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info/METADATA",
			RecordPath:   "/usr/local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info/RECORD",
			SearchDir:    "/usr/local/lib/python3.12/site-packages",
			// The first column may be written either relative to the
			// directory holding the metadata or absolute; the
			// specification permits both, so both appear here.
			Files: []string{
				"cryptography/hazmat/bindings/_rust.abi3.so",
				"cryptography/fernet.py",
				"/usr/local/lib/python3.12/site-packages/cryptography/__init__.py",
			},
		}},
		EggInfoDists: []EggInfoDistribution{{
			Dir: "/usr/lib/python3/dist-packages/oldstyle-1.0.egg-info", SearchDir: "/usr/lib/python3/dist-packages",
		}},
		ModuleDirs: []ModuleDirListing{{Kind: "node_modules", Root: "/app/node_modules"}},
		OwnedPaths: []OwnedPathEntry{
			{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", DBKind: "dpkg", Package: "libssl3", Version: "3.0.13-1"},
			{Path: "/usr/bin/curl", DBKind: "dpkg", Package: "curl", Version: "7.88.1-1"},
			{Path: "/usr/share/shared-by-two", DBKind: "dpkg", Package: "libssl3", Version: "3.0.13-1"},
			{Path: "/usr/share/shared-by-two", DBKind: "dpkg", Package: "curl", Version: "7.88.1-1"},
		},
	}}
}

func mappingResolver(t *testing.T) *fileResolver {
	t.Helper()
	return newFileResolver(mappingIndex(t), mappingAux())
}

func packagesOf(out mappingOutcome) []string {
	var names []string
	for _, m := range out.Matches {
		for _, k := range m.Keys {
			names = append(names, k.Package)
		}
	}
	return names
}

// TestMapCompiledBinaryToEveryModuleInIt checks the compiled-binary rule.
// The report names the binary, not the modules, and every module built
// into it hangs off that one path — so identifying the file has to spread
// the evidence over all of them. That is a one-file-to-many-packages
// relation, not an ambiguity.
func TestMapCompiledBinaryToEveryModuleInIt(t *testing.T) {
	out := mappingResolver(t).resolve("/server")
	if out.Unresolved || out.Conflict {
		t.Fatalf("the binary's own path did not resolve: %+v", out)
	}
	got := packagesOf(out)
	if len(got) != 2 {
		t.Fatalf("resolved to %v, want both modules built into the binary", got)
	}
	if out.Matches[0].Rule != "go_target_path" {
		t.Errorf("rule = %q, want the compiled-binary path rule", out.Matches[0].Rule)
	}
}

// TestMapArchiveByItsOwnPath checks the archive rule, and that an archive
// packed inside another one is not reachable by any path of its own: the
// only file the system opens is the outer one.
func TestMapArchiveByItsOwnPath(t *testing.T) {
	r := mappingResolver(t)
	out := r.resolve("/app/log4j-core-2.14.1.jar")
	if out.Unresolved {
		t.Fatalf("an archive named directly by the report did not resolve: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "org.apache.logging.log4j:log4j-core" {
		t.Errorf("resolved to %v, want the archive's own package", got)
	}

	idx := mappingIndex(t)
	nested := pkgGroupKey{Class: scanner.ClassLang, Package: "org.apache.logging.log4j:log4j-nested", InstalledVer: "2.14.1"}
	present, why := r.mappingInputsPresent(nested, idx.mappingInput[nested], ecoJar)
	if !present {
		t.Error("an archive inside an archive was reported as having no mapping input; the report does name its path")
	}
	if why == "" {
		t.Error("an archive inside an archive carries no qualification; an observation of the outer file does not show the inner one was loaded")
	}
}

// TestMapModuleTreeUsesTheDeepestBoundary checks that a file inside a
// module tree is attributed to the package it is actually in. A tree that
// holds two versions of one package nests the second inside the first, and
// the shallower boundary would credit the inner package's files to the
// outer one.
func TestMapModuleTreeUsesTheDeepestBoundary(t *testing.T) {
	r := mappingResolver(t)
	out := r.resolve("/app/node_modules/outer/node_modules/nested-dep/index.js")
	if out.Unresolved || out.Conflict {
		t.Fatalf("a nested module-tree file did not resolve: %+v", out)
	}
	if got := out.Matches[0].File; got != "app/node_modules/outer/node_modules/nested-dep/package.json" {
		t.Errorf("resolved to %q, want the inner package's own manifest", got)
	}
	if got := out.Matches[0].Keys[0].InstalledVer; got != "1.0.0" {
		t.Errorf("resolved to version %q, want the inner copy's 1.0.0", got)
	}
}

// TestMapModuleTreeThroughALink checks that both spellings of a package
// stored once and linked into place reach the same package: the link's
// path as an application resolves it, and the real directory's path as the
// report names it.
func TestMapModuleTreeThroughALink(t *testing.T) {
	r := mappingResolver(t)
	const want = "app/node_modules/.pnpm/lodash@4.17.15/node_modules/lodash/package.json"
	for _, observed := range []string{
		"/app/node_modules/lodash/lodash.js",
		"/app/node_modules/.pnpm/lodash@4.17.15/node_modules/lodash/lodash.js",
	} {
		out := r.resolve(observed)
		if out.Unresolved || out.Conflict {
			t.Fatalf("%s did not resolve: %+v", observed, out)
		}
		if got := out.Matches[0].File; got != want {
			t.Errorf("%s resolved to %q, want %q", observed, got, want)
		}
	}
}

// TestMapInstalledDistributionThroughItsManifest checks the installed
// Python distribution rule: the manifest says which distribution owns the
// file, and the distribution's metadata file is what the report names.
// Both spellings the manifest may use are handled, and a compiled module —
// which the manifest usually does not list at all — is reduced to the
// source it was compiled from.
func TestMapInstalledDistributionThroughItsManifest(t *testing.T) {
	r := mappingResolver(t)
	const want = "usr/local/lib/python3.12/site-packages/cryptography-41.0.0.dist-info/METADATA"
	cases := []struct{ name, observed string }{
		{"manifest entry written relative to the search directory", "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"},
		{"manifest entry written as an absolute path", "/usr/local/lib/python3.12/site-packages/cryptography/__init__.py"},
		{"a compiled module reduced to its source", "/usr/local/lib/python3.12/site-packages/cryptography/__pycache__/fernet.cpython-312.pyc"},
		{"an optimised compiled module reduced to its source", "/usr/local/lib/python3.12/site-packages/cryptography/__pycache__/fernet.cpython-312.opt-1.pyc"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			out := r.resolve(tt.observed)
			if out.Unresolved || out.Conflict {
				t.Fatalf("did not resolve: %+v", out)
			}
			if got := out.Matches[0].File; got != want {
				t.Errorf("resolved to %q, want %q", got, want)
			}
		})
	}
}

// TestDistributionWithoutAManifestIsUnmappable checks that a distribution
// recorded in the older form, which has no installed-file manifest, is
// reported as unreachable for that stated reason rather than as a file
// nothing owns.
func TestDistributionWithoutAManifestIsUnmappable(t *testing.T) {
	r := mappingResolver(t)
	out := r.resolve("/usr/lib/python3/dist-packages/oldstyle/core.py")
	if !out.Unresolved {
		t.Fatalf("a file under a manifest-less distribution resolved anyway: %+v", out)
	}
	if out.UnresolvedWh == "" {
		t.Error("no reason was recorded for why it could not be reached")
	}

	idx := mappingIndex(t)
	key := pkgGroupKey{Class: scanner.ClassLang, Package: "oldstyle", InstalledVer: "1.0"}
	present, why := r.mappingInputsPresent(key, idx.mappingInput[key], ecoPythonPkg)
	if present {
		t.Error("a distribution with no installed-file manifest was reported as mappable")
	}
	if why == "" {
		t.Error("no reason was recorded for the missing mapping input")
	}
}

// TestMergedDirectorySpellingsMeet checks that the two names one file has
// on an image where a top-level directory is a link into another arrive at
// the same place.
func TestMergedDirectorySpellingsMeet(t *testing.T) {
	r := mappingResolver(t)
	if got := r.normalize("/lib/x86_64-linux-gnu/libc.so.6"); got != "/usr/lib/x86_64-linux-gnu/libc.so.6" {
		t.Errorf("normalize = %q, want the merged spelling", got)
	}
}

// TestOperatingSystemPackagesCarryNoPath checks that an operating-system
// package is recorded as having no mapping input from the report. That is
// not a gap: its files come from the container's own package database, and
// the report is not where they would be found.
func TestOperatingSystemPackagesCarryNoPath(t *testing.T) {
	idx := mappingIndex(t)
	key := pkgGroupKey{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.13-1"}
	if got := idx.mappingInput[key]; got != mappingInputNone {
		t.Errorf("mapping input = %q, want none", got)
	}
	if got := idx.ecosystem[key]; got != ecoOS {
		t.Errorf("ecosystem = %q, want the operating-system one", got)
	}
}

// TestUnresolvedPathIsNeverGuessedAt checks that a path no rule reaches is
// reported as unresolved with a reason, rather than being attached to the
// nearest thing that looks similar.
func TestUnresolvedPathIsNeverGuessedAt(t *testing.T) {
	r := mappingResolver(t)
	for _, observed := range []string{"/usr/bin/unrelated", "relative/path.js", ""} {
		out := r.resolve(observed)
		if !out.Unresolved {
			t.Errorf("%q resolved to %v; nothing in the report corresponds to it", observed, packagesOf(out))
		}
		if out.UnresolvedWh == "" {
			t.Errorf("%q was left unresolved with no reason recorded", observed)
		}
	}
}

// TestMapOperatingSystemPackageThroughTheSavedPathIndex checks the route
// an operating-system package is reached by.
//
// The scan report carries no path for one: its files come from the
// container's own package database. Without the index that database
// produced, saved at observation time, an execution of a program such a
// package installed could never be related back to it — which is most of
// what an execution record is for on a distribution image.
func TestMapOperatingSystemPackageThroughTheSavedPathIndex(t *testing.T) {
	r := mappingResolver(t)
	out := r.resolve("/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if out.Unresolved || out.Conflict {
		t.Fatalf("a file the package database owns did not resolve: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "libssl3" {
		t.Errorf("resolved to %v, want the owning operating-system package", got)
	}
	if out.Matches[0].Ecosystem != ecoOS {
		t.Errorf("ecosystem = %q, want the operating-system one", out.Matches[0].Ecosystem)
	}
}

// TestOperatingSystemPackageVersionMustAgree checks that a path whose
// owner carries a different version than the scan reports is not a
// confirmation. The same package at another version is a different state
// of the container, and confirming it would credit a version that is not
// the one installed.
func TestOperatingSystemPackageVersionMustAgree(t *testing.T) {
	aux := mappingAux()
	aux[0].OwnedPaths = []OwnedPathEntry{
		{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", DBKind: "dpkg", Package: "libssl3", Version: "3.0.99-1"},
	}
	r := newFileResolver(mappingIndex(t), aux)
	out := r.resolve("/usr/lib/x86_64-linux-gnu/libssl.so.3")
	if !out.Unresolved {
		t.Errorf("a path owned at a different version was matched anyway: %v", packagesOf(out))
	}
}

// TestTwoPackagesClaimingOneFileIsAConflict checks that a file two
// packages both claim confirms neither. Attributing it to one of them
// would be a guess, and the guess would be recorded as an observation.
func TestTwoPackagesClaimingOneFileIsAConflict(t *testing.T) {
	r := mappingResolver(t)
	out := r.resolve("/usr/share/shared-by-two")
	if !out.Conflict {
		t.Fatalf("a file two packages claim did not come back as a conflict: %+v", out)
	}
	if len(out.Matches) != 0 {
		t.Errorf("a conflicting path still produced %d match(es)", len(out.Matches))
	}
}

// TestMissKindsAreSeparated checks the three reasons a path reaches no
// package are told apart. Only the first is a shortfall in the
// observation; a path that resolved perfectly well and names nothing the
// scan reports is what most of a workload's activity looks like, and
// counting it as a failure would report a broken collection every time.
func TestMissKindsAreSeparated(t *testing.T) {
	r := mappingResolver(t)

	if got := r.resolve("relative/path.js"); got.MissKind != missPathUnresolved {
		t.Errorf("a path that is not absolute: miss kind = %q, want %q", got.MissKind, missPathUnresolved)
	}
	if got := r.resolve("/usr/lib/python3/dist-packages/oldstyle/core.py"); got.MissKind != missUnmappable {
		t.Errorf("a file under a manifest-less distribution: miss kind = %q, want %q", got.MissKind, missUnmappable)
	}
	if got := r.resolve("/etc/ssl/certs/ca-certificates.crt"); got.MissKind != missOutsideScan {
		t.Errorf("an ordinary file nothing reports: miss kind = %q, want %q", got.MissKind, missOutsideScan)
	}
}

// TestTheReadingThatCoveredAnObservationIsTheOneUsed checks that an
// observation is resolved against the layout reading that covered it,
// rather than against every reading merged together. A package installed
// after a sample was taken was not there when that sample looked, and
// answering from the later reading would relate the sample to a layout it
// never saw.
func TestTheReadingThatCoveredAnObservationIsTheOneUsed(t *testing.T) {
	early := mappingAux()[0]
	early.AuxGeneration, early.SampleIDs = "gen-early", []string{"s0"}
	early.FirstSeen = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	early.LastSeen = early.FirstSeen
	early.DistInfoRecords = nil // the distribution is not installed yet

	late := mappingAux()[0]
	late.AuxGeneration, late.SampleIDs = "gen-late", []string{"s1"}
	late.FirstSeen = early.FirstSeen.Add(time.Minute)
	late.LastSeen = late.FirstSeen

	set := newResolverSet(mappingIndex(t), []AuxiliaryInputs{early, late})
	const observed = "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"

	before := set.forObservation("mnt:[1]", "s0", early.FirstSeen).resolve(observed)
	if !before.Unresolved {
		t.Errorf("the earlier sample resolved a distribution that was not installed when it looked: %v", packagesOf(before))
	}
	after := set.forObservation("mnt:[1]", "s1", late.FirstSeen).resolve(observed)
	if after.Unresolved {
		t.Fatalf("the later sample did not resolve a distribution that was installed by then: %+v", after)
	}
	if got := packagesOf(after); len(got) != 1 || got[0] != "cryptography" {
		t.Errorf("resolved to %v, want cryptography", got)
	}
}

// An instant between two readings of the same mount view is answered by
// both neighbours, so an observation made while the layout was changing
// (bytecode caches appearing under a distribution, say) still resolves
// when the readings agree about the file, while an instant before the first
// reading stays unresolved.
func TestReadingsAnswerForTheGapBetweenThemAndBeforeTheFirst(t *testing.T) {
	early := mappingAux()[0]
	early.AuxGeneration, early.SampleIDs = "gen-early", []string{"s0"}
	early.FirstSeen = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	early.LastSeen = early.FirstSeen

	late := mappingAux()[0]
	late.AuxGeneration, late.SampleIDs = "gen-late", []string{"s1"}
	late.FirstSeen = early.FirstSeen.Add(time.Minute)
	late.LastSeen = late.FirstSeen

	set := newResolverSet(mappingIndex(t), []AuxiliaryInputs{early, late})
	const observed = "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"

	if out := set.resolveEvent(observed, early.FirstSeen.Add(-10*time.Second)); !out.Unresolved {
		t.Errorf("an event before the first reading was resolved by a layout nobody had read yet: %v", packagesOf(out))
	}
	for name, at := range map[string]time.Time{
		"between the readings": early.FirstSeen.Add(30 * time.Second),
		"after the last":       late.FirstSeen.Add(time.Hour),
	} {
		out := set.resolveEvent(observed, at)
		if out.Unresolved || out.Conflict {
			t.Errorf("%s: an event was not resolved by the readings around it: %+v", name, out)
			continue
		}
		if got := packagesOf(out); len(got) != 1 || got[0] != "cryptography" {
			t.Errorf("%s: resolved to %v, want cryptography", name, got)
		}
	}
}

// A generation that returns after another one was found in between is two
// stretches, and the reading in between still answers for its own instant.
func TestAReturningGenerationDoesNotSwallowTheReadingBetween(t *testing.T) {
	base := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	a1 := mappingAux()[0]
	a1.AuxGeneration, a1.SampleIDs, a1.FirstSeen, a1.LastSeen = "gen-a", []string{"s0"}, base, base
	b := mappingAux()[0]
	b.AuxGeneration, b.SampleIDs, b.FirstSeen, b.LastSeen = "gen-b", []string{"s1"}, base.Add(time.Minute), base.Add(time.Minute)
	b.DistInfoRecords = nil // the distribution is absent in this reading
	a2 := mappingAux()[0]
	a2.AuxGeneration, a2.SampleIDs, a2.FirstSeen, a2.LastSeen = "gen-a", []string{"s2"}, base.Add(2*time.Minute), base.Add(2*time.Minute)

	set := newResolverSet(mappingIndex(t), []AuxiliaryInputs{a1, b, a2})
	if len(set.resolvers) != 3 {
		t.Fatalf("got %d stretches, want 3 (a, b, a again)", len(set.resolvers))
	}
	const observed = "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"
	between := set.resolvers[1]
	if between.generation != "gen-b" || !between.covers("mnt:[1]", "", b.FirstSeen) {
		t.Fatalf("the reading in between is not its own stretch answering for its own instant: generation %q", between.generation)
	}
	if out := set.forObservation("mnt:[1]", "s1", b.FirstSeen).resolve(observed); !out.Unresolved {
		t.Errorf("the sample taken in between resolved a distribution absent in its own reading: %v", packagesOf(out))
	}
	if set.resolvers[2].coversFrom.Before(b.LastSeen) {
		t.Errorf("the returning generation's stretch starts at %v, before the reading in between ended at %v", set.resolvers[2].coversFrom, b.LastSeen)
	}
}

// Two readings that both know a file but attribute it to different
// packages disagree, and an instant they both answer for is a conflict.
func TestReadingsAttributingAFileDifferentlyConflict(t *testing.T) {
	early := mappingAux()[0]
	early.AuxGeneration, early.SampleIDs = "gen-early", []string{"s0"}
	early.FirstSeen = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	early.LastSeen = early.FirstSeen
	late := mappingAux()[0]
	late.AuxGeneration, late.SampleIDs = "gen-late", []string{"s1"}
	late.FirstSeen = early.FirstSeen.Add(time.Minute)
	late.LastSeen = late.FirstSeen

	set := newResolverSet(mappingIndex(t), []AuxiliaryInputs{early, late})
	const observed = "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"
	a := set.resolvers[0].resolve(observed)
	b := a
	b.Matches = append([]fileMatch(nil), a.Matches...)
	b.Matches[0].Keys = []pkgGroupKey{{Class: "lang", Package: "somethingelse", InstalledVer: "1"}}
	if sameFiles(a, b) {
		t.Errorf("the same file attributed to different packages was treated as agreement")
	}
	if !sameFiles(a, set.resolvers[1].resolve(observed)) {
		t.Errorf("two identical readings were treated as disagreeing")
	}
}

// Two neighbouring readings, one attributing a file and one unable to,
// disagree about the stretch they both answer for: the event is a
// conflict, not the attributing reading's answer.
func TestAReadingThatResolvesAndANeighbourThatCannotConflict(t *testing.T) {
	early := mappingAux()[0]
	early.AuxGeneration, early.SampleIDs = "gen-early", []string{"s0"}
	early.FirstSeen = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	early.LastSeen = early.FirstSeen
	late := mappingAux()[0]
	late.AuxGeneration, late.SampleIDs = "gen-late", []string{"s1"}
	late.FirstSeen = early.FirstSeen.Add(time.Minute)
	late.LastSeen = late.FirstSeen
	late.DistInfoRecords = nil // the distribution is gone in the later reading

	set := newResolverSet(mappingIndex(t), []AuxiliaryInputs{early, late})
	const observed = "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so"
	out := set.resolveEvent(observed, early.FirstSeen.Add(30*time.Second))
	if !out.Conflict {
		t.Errorf("an event in the stretch between a reading that owns the file and one that does not was not a conflict: %+v", out)
	}
	if out := set.resolveEvent(observed, late.FirstSeen.Add(time.Hour)); !out.Unresolved || out.Conflict {
		t.Errorf("an event only the later reading answers for was not simply unresolved: %+v", out)
	}
}
