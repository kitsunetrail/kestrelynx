package main

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// allPackagesReport mirrors the shape a --list-all-pkgs scan actually
// takes (as sampled from a real trivy invocation against a coverage
// case's image): each Result carries both its Finding-bearing
// Vulnerabilities and a fuller Packages list that also names packages
// with no Finding at all. One OS package (base-files), one jar
// (commons-io) and one Go module (golang.org/x/mod) appear only in
// Packages, never in Vulnerabilities.
const allPackagesReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-all-packages-test:1",
  "Metadata": { "OS": { "Family": "ubuntu" }, "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "ubuntu",
      "Packages": [
        { "Name": "libssl3t64", "Version": "3.5.7-1~deb13u2" },
        { "Name": "base-files", "Version": "13.8+deb13u6" },
        { "Name": "curl", "Version": "8.14.1-2+deb13u5" }
      ],
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-1000", "PkgName": "libssl3t64", "InstalledVersion": "3.5.7-1~deb13u2", "Severity": "HIGH", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "jar", "Target": "app.jar",
      "Packages": [
        { "Name": "org.apache.logging.log4j:log4j-core", "Version": "2.14.1", "FilePath": "app/log4j-core-2.14.1.jar" },
        { "Name": "commons-io:commons-io", "Version": "2.15.1", "FilePath": "app/lazy/commons-io-2.15.1.jar" }
      ],
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-core", "PkgPath": "app/log4j-core-2.14.1.jar", "InstalledVersion": "2.14.1", "Severity": "CRITICAL", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "gobinary", "Target": "server",
      "Packages": [
        { "Name": "golang.org/x/text", "Version": "v0.3.0" },
        { "Name": "golang.org/x/mod", "Version": "v0.14.0" }
      ],
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2020-14040", "PkgName": "golang.org/x/text", "InstalledVersion": "v0.3.0", "Severity": "HIGH", "Status": "fixed" }
      ]
    }
  ]
}`

// noPackagesReport is an ordinary scan (no --list-all-pkgs): every result
// carries Vulnerabilities but no Packages at all.
const noPackagesReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-no-packages-test:1",
  "Metadata": { "OS": { "Family": "ubuntu" }, "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "ubuntu",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-1000", "PkgName": "libssl3t64", "InstalledVersion": "3.5.7-1~deb13u2", "Severity": "HIGH", "Status": "fixed" }
      ]
    }
  ]
}`

func TestBuildScanFileIndexWithoutAllPackagesFlagIgnoresPackagesList(t *testing.T) {
	idx, extra, err := buildScanFileIndex([]byte(allPackagesReport), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	if extra != nil {
		t.Errorf("extra = %v, want nil when the flag is off", extra)
	}
	// The Packages-only entries must not have leaked into the index either:
	// base-files never appeared in Vulnerabilities, so it must not be a
	// known OS name.
	if _, ok := idx.osByName["base-files"]; ok {
		t.Errorf("base-files is registered in the index even though -all-packages was not requested")
	}
}

func TestAllPackagesFlagAddsOnlyZeroFindingGroups(t *testing.T) {
	idx, extra, err := buildScanFileIndex([]byte(allPackagesReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	got := map[pkgGroupKey]bool{}
	for _, g := range extra {
		if len(g.vulns) != 0 {
			t.Errorf("extra group %+v carries %d Finding(s), want zero", g.key, len(g.vulns))
		}
		got[g.key] = true
	}
	want := []pkgGroupKey{
		{Class: scanner.ClassOS, Package: "base-files", InstalledVer: "13.8+deb13u6"},
		{Class: scanner.ClassOS, Package: "curl", InstalledVer: "8.14.1-2+deb13u5"},
		{Class: scanner.ClassLang, Package: "commons-io:commons-io", InstalledVer: "2.15.1"},
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("extra groups missing %+v", k)
		}
	}
	// The Finding-bearing packages must not be duplicated into extra.
	dup := pkgGroupKey{Class: scanner.ClassOS, Package: "libssl3t64", InstalledVer: "3.5.7-1~deb13u2"}
	if got[dup] {
		t.Errorf("a Finding-bearing package (%+v) was also added as a zero-Finding group", dup)
	}
	// Go binaries are excluded from -all-packages by design.
	for k := range got {
		if k.Package == "golang.org/x/mod" {
			t.Errorf("a Go-binary-only package (%+v) was added; -all-packages must exclude gobinary", k)
		}
	}
	if len(extra) != len(want) {
		t.Errorf("len(extra) = %d, want %d (%v)", len(extra), len(want), extra)
	}

	// The widened index must carry these packages' ecosystem and mapping
	// input too, the same as a Finding-bearing one, or their S1/S2
	// evaluation would have nothing to resolve against.
	wide := idx.widened
	if wide == nil {
		t.Fatal("the flag produced no widened index for the zero-Finding groups to resolve against")
	}
	commonsIOKey := pkgGroupKey{Class: scanner.ClassLang, Package: "commons-io:commons-io", InstalledVer: "2.15.1"}
	if wide.ecosystem[commonsIOKey] != ecoJar {
		t.Errorf("ecosystem[commons-io] = %q, want %q", wide.ecosystem[commonsIOKey], ecoJar)
	}
	if wide.mappingInput[commonsIOKey] != mappingInputPkgPath {
		t.Errorf("mappingInput[commons-io] = %q, want %q", wide.mappingInput[commonsIOKey], mappingInputPkgPath)
	}
	if paths := wide.pathsOf[commonsIOKey]; len(paths) != 1 || paths[0] != "app/lazy/commons-io-2.15.1.jar" {
		t.Errorf("pathsOf[commons-io] = %v, want [app/lazy/commons-io-2.15.1.jar]", paths)
	}
	baseFilesKey := pkgGroupKey{Class: scanner.ClassOS, Package: "base-files", InstalledVer: "13.8+deb13u6"}
	if _, ok := wide.osByName["base-files"]; !ok {
		t.Errorf("base-files was not registered in osByName")
	}
	if wide.ecosystem[baseFilesKey] != ecoOS {
		t.Errorf("ecosystem[base-files] = %q, want %q", wide.ecosystem[baseFilesKey], ecoOS)
	}
	// None of it may reach the index the Finding-bearing packages are
	// resolved against, or the flag would move their own verdicts.
	if _, ok := idx.osByName["base-files"]; ok {
		t.Error("a zero-Finding operating-system package reached the Vulnerabilities-only index")
	}
	if _, ok := idx.ecosystem[commonsIOKey]; ok {
		t.Error("a zero-Finding jar reached the Vulnerabilities-only index")
	}
	if _, ok := idx.files["app/lazy/commons-io-2.15.1.jar"]; ok {
		t.Error("a zero-Finding jar's file reached the Vulnerabilities-only index")
	}
}

func TestAllPackagesFlagWithoutAnyPackagesFieldIsRefused(t *testing.T) {
	_, _, err := buildScanFileIndex([]byte(noPackagesReport), true)
	if err == nil {
		t.Fatal("-all-packages against a scan with no Packages entries at all was not refused")
	}
	if !strings.Contains(err.Error(), "--list-all-pkgs") {
		t.Errorf("error = %v, want it to name --list-all-pkgs as the fix", err)
	}
}

// TestAllPackagesDoesNotChangeFindingAggregates runs the synthetic events
// pipeline twice — once exactly as every existing test does (extraGroups
// nil) and once with a hand-built zero-Finding extra group added — and
// checks that every Finding-unit aggregate (Overall, the three series'
// overall Metrics, and G4's total Finding counts) comes out identical,
// while the zero-Finding package still gets its own S0/S1/S2 verdict in
// result.Packages.
func TestAllPackagesDoesNotChangeFindingAggregates(t *testing.T) {
	rec, scan, idx, def, gtb, events := loadSyntheticEventRun(t)

	baseline, err := runMatchPipeline(context.Background(), rec, scan, idx, nil, def, gtb, events,
		syntheticIntel(), t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("baseline runMatchPipeline: %v", err)
	}

	extra := []pkgGroup{{key: pkgGroupKey{Class: scanner.ClassOS, Package: "zero-finding-pkg", InstalledVer: "1.0"}}}
	// This package needs an ecosystem/mapping-input registration the same
	// way -all-packages would have given it, or its verdict computation
	// has nothing to resolve against; registering it directly here keeps
	// this test from also depending on buildScanFileIndex's own parsing,
	// which the tests above already cover on their own.
	idx.ecosystem[extra[0].key] = ecoOS
	idx.mappingInput[extra[0].key] = mappingInputNone

	withExtra, err := runMatchPipeline(context.Background(), rec, scan, idx, extra, def, gtb, events,
		syntheticIntel(), t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("runMatchPipeline with extraGroups: %v", err)
	}

	if len(withExtra.Packages) != len(baseline.Packages)+1 {
		t.Errorf("len(Packages) = %d, want %d (baseline + the one zero-Finding group)", len(withExtra.Packages), len(baseline.Packages)+1)
	}
	found := false
	for _, pv := range withExtra.Packages {
		if pv.Package == "zero-finding-pkg" {
			found = true
			if pv.FindingCount != 0 {
				t.Errorf("zero-finding-pkg FindingCount = %d, want 0", pv.FindingCount)
			}
			if pv.S1Verdict == "" || pv.S2Verdict == "" {
				t.Errorf("zero-finding-pkg has no S1/S2 verdict at all: %+v", pv)
			}
		}
	}
	if !found {
		t.Fatal("zero-finding-pkg is missing from result.Packages entirely")
	}

	if withExtra.Overall != baseline.Overall {
		t.Errorf("Overall changed:\n baseline=%+v\n withExtra=%+v", baseline.Overall, withExtra.Overall)
	}
	if len(withExtra.Series) != len(baseline.Series) {
		t.Fatalf("len(Series) changed: %d vs %d", len(withExtra.Series), len(baseline.Series))
	}
	for i := range baseline.Series {
		if withExtra.Series[i].Overall != baseline.Series[i].Overall {
			t.Errorf("Series[%d] (%s) Overall changed:\n baseline=%+v\n withExtra=%+v",
				i, baseline.Series[i].Series, baseline.Series[i].Overall, withExtra.Series[i].Overall)
		}
	}
	if len(withExtra.G4) != len(baseline.G4) {
		t.Fatalf("len(G4) changed: %d vs %d", len(withExtra.G4), len(baseline.G4))
	}
	for i := range baseline.G4 {
		if withExtra.G4[i].TotalFindings != baseline.G4[i].TotalFindings {
			t.Errorf("G4[%d] (%s/%s) TotalFindings changed: %d vs %d",
				i, baseline.G4[i].Series, baseline.G4[i].Priority, baseline.G4[i].TotalFindings, withExtra.G4[i].TotalFindings)
		}
	}
	if withExtra.GTB != baseline.GTB {
		t.Errorf("GTB changed:\n baseline=%+v\n withExtra=%+v", baseline.GTB, withExtra.GTB)
	}
	// The mapping report (mapping.csv's own population) is Finding-shaped
	// too: it must stay exactly the Finding-bearing rows it always was,
	// with no trace of the zero-Finding addition, since Metrics and
	// Mapping* structs hold maps and cannot be compared with ==.
	if !reflect.DeepEqual(withExtra.Mapping, baseline.Mapping) {
		t.Errorf("Mapping report changed:\n baseline=%+v\n withExtra=%+v", baseline.Mapping, withExtra.Mapping)
	}
}

// --- A1: OS version reconstruction (Epoch:Version-Release) ---------------

const epochReleaseReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-epoch-test:1",
  "Metadata": { "OS": { "Family": "ubuntu" }, "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "ubuntu",
      "Packages": [
        { "Name": "git", "Version": "2.53.0", "Epoch": 1, "Release": "1ubuntu1" },
        { "Name": "curl", "Version": "8.18.0", "Release": "1ubuntu2.5" },
        { "Name": "base-files", "Version": "14ubuntu6.2" }
      ],
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-9000", "PkgName": "git", "InstalledVersion": "1:2.53.0-1ubuntu1", "Severity": "HIGH", "Status": "fixed" }
      ]
    }
  ]
}`

func TestAllPackagesReconstructsDpkgVersionForZeroFindingPackages(t *testing.T) {
	_, extra, err := buildScanFileIndex([]byte(epochReleaseReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	got := map[string]bool{}
	for _, g := range extra {
		got[g.key.Package+"@"+g.key.InstalledVer] = true
	}
	// curl: Release only, no epoch prefix. base-files: neither.
	if !got["curl@8.18.0-1ubuntu2.5"] {
		t.Errorf("curl's reconstructed version is wrong; extra=%v", extra)
	}
	if !got["base-files@14ubuntu6.2"] {
		t.Errorf("base-files's reconstructed version is wrong; extra=%v", extra)
	}
	// git carries a Finding at "1:2.53.0-1ubuntu1" already, so it must
	// NOT also appear as its own zero-Finding group below.
	if got["git@1:2.53.0-1ubuntu1"] || got["git@2.53.0-1ubuntu1"] || got["git@2.53.0"] {
		t.Errorf("git should not be re-registered as a zero-Finding group at all; extra=%v", extra)
	}
}

func TestAllPackagesOSVersionMatchesFindingInstalledVersionExactly(t *testing.T) {
	// git appears both as a Finding (dpkg-combined InstalledVersion) and
	// in Packages (split Version/Epoch/Release): the reconstructed key
	// must be identical to the Finding's own key, or dedup silently fails
	// and git is double-counted as its own extra population entry.
	idx, extra, err := buildScanFileIndex([]byte(epochReleaseReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	gitFindingKey := pkgGroupKey{Class: scanner.ClassOS, Package: "git", InstalledVer: "1:2.53.0-1ubuntu1"}
	if _, ok := idx.mappingInput[gitFindingKey]; !ok {
		t.Fatalf("git's Finding-derived key is missing from the index: %+v", idx.mappingInput)
	}
	for _, g := range extra {
		if g.key.Package == "git" {
			t.Errorf("git produced an extra (zero-Finding) group %+v; it should have matched the Finding's own key and added nothing", g.key)
		}
	}
	if len(extra) != 2 {
		t.Errorf("len(extra) = %d, want 2 (curl, base-files); got %v", len(extra), extra)
	}
}

// --- A2: multiple placements of one zero-Finding package are all kept ----

const multiPlacementReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-multi-placement-test:1",
  "Metadata": { "OS": { "Family": "ubuntu" }, "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" },
  "Results": [
    {
      "Class": "lang-pkgs", "Type": "jar", "Target": "app.jar",
      "Packages": [
        { "Name": "commons-io:commons-io", "Version": "2.15.1", "FilePath": "app/lib/commons-io-2.15.1.jar" },
        { "Name": "commons-io:commons-io", "Version": "2.15.1", "FilePath": "app/lazy/commons-io-2.15.1.jar" }
      ],
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2021-99999", "PkgName": "org.apache.logging.log4j:log4j-core", "PkgPath": "app/log4j-core-2.14.1.jar", "InstalledVersion": "2.14.1", "Severity": "CRITICAL", "Status": "fixed" }
      ]
    }
  ]
}`

func TestAllPackagesRegistersEveryPlacementOfOneZeroFindingGroup(t *testing.T) {
	idx, extra, err := buildScanFileIndex([]byte(multiPlacementReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	key := pkgGroupKey{Class: scanner.ClassLang, Package: "commons-io:commons-io", InstalledVer: "2.15.1"}
	count := 0
	for _, g := range extra {
		if g.key == key {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("commons-io produced %d extra groups, want exactly 1 (one evaluated group, several placements)", count)
	}
	wide := idx.widened
	if wide == nil {
		t.Fatal("the flag produced no widened index")
	}
	paths := wide.pathsOf[key]
	if len(paths) != 2 {
		t.Fatalf("pathsOf[commons-io] = %v, want both placements", paths)
	}
	for _, want := range []string{"app/lib/commons-io-2.15.1.jar", "app/lazy/commons-io-2.15.1.jar"} {
		found := false
		for _, p := range paths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("pathsOf[commons-io] is missing placement %q: %v", want, paths)
		}
		if !containsKey(wide.files[want].Keys, key) {
			t.Errorf("the widened index's files[%q].Keys does not include commons-io", want)
		}
	}
}

// TestAllPackagesAddsExtraPlacementToAFindingBearingPackageToo checks that
// a Finding-bearing package's own additional placement (one Packages
// names but no Vulnerabilities entry ever pointed at) is still registered,
// even though no new zero-Finding group is created for it.
const findingWithExtraPlacementReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-finding-extra-placement-test:1",
  "Metadata": { "OS": { "Family": "ubuntu" }, "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" },
  "Results": [
    {
      "Class": "lang-pkgs", "Type": "jar", "Target": "app.jar",
      "Packages": [
        { "Name": "org.apache.logging.log4j:log4j-core", "Version": "2.14.1", "FilePath": "app/log4j-core-2.14.1.jar" },
        { "Name": "org.apache.logging.log4j:log4j-core", "Version": "2.14.1", "FilePath": "app/backup/log4j-core-2.14.1.jar" }
      ],
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2021-44228", "PkgName": "org.apache.logging.log4j:log4j-core", "PkgPath": "app/log4j-core-2.14.1.jar", "InstalledVersion": "2.14.1", "Severity": "CRITICAL", "Status": "fixed" }
      ]
    }
  ]
}`

func TestAllPackagesAddsExtraPlacementToAFindingBearingPackageToo(t *testing.T) {
	idx, extra, err := buildScanFileIndex([]byte(findingWithExtraPlacementReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	key := pkgGroupKey{Class: scanner.ClassLang, Package: "org.apache.logging.log4j:log4j-core", InstalledVer: "2.14.1"}
	for _, g := range extra {
		if g.key == key {
			t.Errorf("a Finding-bearing package must not also get its own zero-Finding group: %+v", g.key)
		}
	}
	if idx.widened == nil {
		t.Fatal("the flag produced no widened index")
	}
	paths := idx.widened.pathsOf[key]
	if len(paths) != 2 {
		t.Fatalf("pathsOf[log4j-core] = %v, want both the Finding's own placement and the Packages-only one", paths)
	}
	// The extra placement is exactly the kind of addition that must not
	// reach a Finding-bearing package's own resolution: an archive this
	// package is reachable at is what decides whether its mapping inputs
	// are present at all.
	if own := idx.pathsOf[key]; len(own) != 1 || own[0] != "app/log4j-core-2.14.1.jar" {
		t.Errorf("the Vulnerabilities-only index's pathsOf[log4j-core] = %v, want only the Finding's own placement", own)
	}
}

// --- The two populations are resolved against two indexes ----------------

// bundledArchivePath is an archive a module tree carries inside one of its
// packages. Two mapping rules can speak for it: the archive rule, which
// answers with the archive itself when the report names it, and the
// module-boundary rule, which answers with the package manifest the file
// sits under. While only the manifest is named, the path resolves to one
// file and the package that manifest belongs to is confirmed. Once the
// archive is named as well, two different files answer to one path, which
// is the one ambiguity stage one treats as a failure to resolve.
const bundledArchivePath = "/app/node_modules/bridge/vendor/native.jar"

// bundledArchiveReport names the module package in Vulnerabilities and the
// archive bundled inside it only in Packages, which is what a
// --list-all-pkgs scan of an image with a native bridge module looks like:
// the archive ships with the module and carries no Finding of its own.
const bundledArchiveReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-bundled-archive-test:1",
  "Metadata": { "OS": { "Family": "debian" }, "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" },
  "Results": [
    {
      "Class": "lang-pkgs", "Type": "node-pkg", "Target": "Node.js",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-2000", "PkgName": "bridge", "PkgPath": "app/node_modules/bridge/package.json", "InstalledVersion": "1.0.0", "Severity": "HIGH", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "jar", "Target": "Java",
      "Packages": [
        { "Name": "com.example:native-bridge", "Version": "3.1.0", "FilePath": "app/node_modules/bridge/vendor/native.jar" }
      ],
      "Vulnerabilities": []
    }
  ]
}`

// TestAllPackagesNeverWidensWhatAFindingBearingPackageResolvesAgainst
// checks stage one directly: the same observed path must resolve to the
// same file, with the same conflict answer, whether or not -all-packages
// was asked for. The widened index does see the second file and does
// report the ambiguity — that is what it is for — but a package that
// carries a Finding must not be judged through it.
func TestAllPackagesNeverWidensWhatAFindingBearingPackageResolvesAgainst(t *testing.T) {
	withoutFlag, extraOff, err := buildScanFileIndex([]byte(bundledArchiveReport), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex without the flag: %v", err)
	}
	if extraOff != nil {
		t.Errorf("extra = %v, want nil when the flag is off", extraOff)
	}
	withFlag, extraOn, err := buildScanFileIndex([]byte(bundledArchiveReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex with the flag: %v", err)
	}
	if len(extraOn) != 1 {
		t.Fatalf("extra = %v, want the one bundled archive", extraOn)
	}
	if withFlag.widened == nil {
		t.Fatal("the flag produced no widened index")
	}

	// The fixture is only worth anything if the flag actually adds a file:
	// a report whose Packages name nothing new could not tell a shared
	// index from a separated one.
	if len(withFlag.widened.files) <= len(withoutFlag.files) {
		t.Fatalf("the widened index holds %d file(s) and the Vulnerabilities-only one %d; this fixture adds nothing and proves nothing",
			len(withFlag.widened.files), len(withoutFlag.files))
	}
	if len(withFlag.files) != len(withoutFlag.files) {
		t.Errorf("the returned index holds %d file(s) with the flag and %d without; the flag widened what Finding-bearing packages resolve against",
			len(withFlag.files), len(withoutFlag.files))
	}

	off := newFileResolver(withoutFlag, nil).resolve(bundledArchivePath)
	on := newFileResolver(withFlag, nil).resolve(bundledArchivePath)
	if !reflect.DeepEqual(off, on) {
		t.Errorf("the same path resolves differently once -all-packages is passed:\n without=%+v\n with=%+v", off, on)
	}
	if off.Conflict || off.Unresolved || len(off.Matches) != 1 {
		t.Fatalf("the module manifest did not answer for the bundled archive on its own: %+v", off)
	}
	if got := off.Matches[0].File; got != "app/node_modules/bridge/package.json" {
		t.Errorf("resolved to %q, want the module package's own manifest", got)
	}

	// The widened index is where the second file belongs, and where the
	// ambiguity it creates is reported. This is the state the
	// Finding-bearing resolution above would have been computed in had the
	// two shared one index.
	wide := newFileResolver(withFlag.widened, nil).resolve(bundledArchivePath)
	if !wide.Conflict {
		t.Errorf("the widened index did not see the archive the flag added: %+v", wide)
	}
}

// TestMappingReportCountsOnlyTheFindingBearingScansFiles checks the
// reported file count. ScanReportFiles says how many files the scan report
// attributes a package to; counting the packages that carry no Finding at
// all among them would make the same report look like it named more files
// whenever the flag happened to be passed, next to rates computed over a
// population that did not change.
func TestMappingReportCountsOnlyTheFindingBearingScansFiles(t *testing.T) {
	withoutFlag, _, err := buildScanFileIndex([]byte(bundledArchiveReport), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex without the flag: %v", err)
	}
	withFlag, _, err := buildScanFileIndex([]byte(bundledArchiveReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex with the flag: %v", err)
	}
	off := buildMappingReport(withoutFlag, nil, newEvidenceSet())
	on := buildMappingReport(withFlag, nil, newEvidenceSet())
	if !reflect.DeepEqual(off, on) {
		t.Errorf("the mapping report changed with -all-packages:\n without=%+v\n with=%+v", off, on)
	}
	found := false
	for _, r := range off.Rows {
		if r.Ecosystem == ecoNodePkg {
			found = true
			if r.ScanReportFiles != 1 {
				t.Errorf("node-pkg ScanReportFiles = %d, want the one manifest the report attributes a Finding to", r.ScanReportFiles)
			}
		}
	}
	if !found {
		t.Error("no node-pkg row at all, so the count this test is about was never produced")
	}
}

// bundledArchiveRun takes the hand-written end-to-end window and adds the
// one thing it lacks: a descriptor held open on an archive bundled inside
// the module tree, and a scan report that names the module package as a
// Finding and the archive only in its --list-all-pkgs Packages list.
//
// The scan report is amended rather than written afresh so that everything
// else about the window — the image identity, the case, the ground truth
// and the events — stays exactly what the saved inputs say it is.
func bundledArchiveRun(t *testing.T) (ContainerRecord, scanner.ImageScan, []byte, Case, *GroundTruthB, *EventLog) {
	t.Helper()
	rec, _, _, def, gtb, events := loadSyntheticEventRun(t)
	for _, sampleID := range []string{"s0", "s1"} {
		rec.PathResolution = append(rec.PathResolution, PathResolutionRecord{
			SampleID:     sampleID,
			Generation:   ProcessGeneration{PID: 1001, Starttime: "12345"},
			MountViewID:  "mnt:[4026531841]",
			DBGeneration: "gen1",
			Source:       "fd",
			Path:         bundledArchivePath,
			Resolved:     bundledArchivePath,
			Ownership:    OwnershipUnowned,
		})
	}

	data, err := os.ReadFile("testdata/synthetic_events_trivy.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("read the saved scan report: %v", err)
	}
	results, ok := doc["Results"].([]any)
	if !ok || len(results) == 0 {
		t.Fatal("the saved scan report has no results to amend")
	}
	amended := 0
	for _, r := range results {
		res, ok := r.(map[string]any)
		if !ok {
			continue
		}
		switch res["Type"] {
		case "node-pkg":
			vulns, ok := res["Vulnerabilities"].([]any)
			if !ok {
				t.Fatal("the node-pkg result carries no vulnerabilities to add to")
			}
			res["Vulnerabilities"] = append(vulns, map[string]any{
				"VulnerabilityID":  "CVE-2030-2000",
				"PkgName":          "bridge",
				"PkgPath":          "app/node_modules/bridge/package.json",
				"InstalledVersion": "1.0.0",
				"FixedVersion":     "1.0.1",
				"Status":           "fixed",
				"Severity":         "HIGH",
				"Title":            "a module package whose own manifest is what the bundled archive's path resolves to",
			})
			amended++
		case "jar":
			res["Packages"] = []any{map[string]any{
				"Name":     "com.example:native-bridge",
				"Version":  "3.1.0",
				"FilePath": strings.TrimPrefix(bundledArchivePath, "/"),
			}}
			amended++
		}
	}
	if amended != 2 {
		t.Fatalf("amended %d result(s), want the node-pkg and jar ones", amended)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(out)
	if err != nil {
		t.Fatalf("parse the amended scan report: %v", err)
	}
	return rec, scan, out, def, gtb, events
}

// TestAllPackagesLeavesEveryFindingBearingVerdictUnchanged runs the whole
// pipeline twice over identical saved inputs, once with -all-packages and
// once without, and requires every Finding-bearing package's verdict and
// the mapping report to come out identical.
//
// The window is built so that they would not: the archive the flag adds
// sits at a path the module-boundary rule already answered for, so a
// shared index would turn the module package's own confirmation into an
// unresolvable ambiguity — a package judged differently on the strength of
// a flag that added nothing about it.
func TestAllPackagesLeavesEveryFindingBearingVerdictUnchanged(t *testing.T) {
	rec, scan, trivyData, def, gtb, events := bundledArchiveRun(t)

	withoutFlag, extraOff, err := buildScanFileIndex(trivyData, false)
	if err != nil {
		t.Fatalf("buildScanFileIndex without the flag: %v", err)
	}
	withFlag, extraOn, err := buildScanFileIndex(trivyData, true)
	if err != nil {
		t.Fatalf("buildScanFileIndex with the flag: %v", err)
	}
	if withFlag.widened == nil {
		t.Fatal("the flag produced no widened index")
	}
	// Without a file index that actually grows, this window could not tell
	// a shared index from a separated one.
	if len(withFlag.widened.files) <= len(withoutFlag.files) {
		t.Fatalf("the widened index holds %d file(s) and the Vulnerabilities-only one %d; this window adds nothing and proves nothing",
			len(withFlag.widened.files), len(withoutFlag.files))
	}
	if wide := newFileResolver(withFlag.widened, nil).resolve(bundledArchivePath); !wide.Conflict {
		t.Fatalf("the widened index does not make this path ambiguous, so the window does not exercise the sharing at all: %+v", wide)
	}

	baseline, err := runMatchPipeline(context.Background(), rec, scan, withoutFlag, extraOff, def, gtb, events,
		syntheticIntel(), t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("baseline runMatchPipeline: %v", err)
	}
	all, err := runMatchPipeline(context.Background(), rec, scan, withFlag, extraOn, def, gtb, events,
		syntheticIntel(), t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("runMatchPipeline with -all-packages: %v", err)
	}

	// The module package is confirmed through the archive it holds open;
	// if it were not, the comparison below would pass over a window where
	// nothing was ever at stake.
	var bridge PackageVerdict
	for _, pv := range baseline.Packages {
		if pv.Package == "bridge" {
			bridge = pv
		}
	}
	if bridge.S1Verdict != VerdictConfirmed {
		t.Fatalf("the module package was not confirmed without the flag (%q/%q), so this window shows nothing",
			bridge.S1Verdict, bridge.S1Factor)
	}

	if len(all.Packages) != len(baseline.Packages)+len(extraOn) {
		t.Fatalf("len(Packages) = %d, want %d (the Finding-bearing population plus the zero-Finding groups)",
			len(all.Packages), len(baseline.Packages)+len(extraOn))
	}
	for i := range baseline.Packages {
		if !reflect.DeepEqual(baseline.Packages[i], all.Packages[i]) {
			t.Errorf("%s is judged differently with -all-packages:\n without=%+v\n with=%+v",
				baseline.Packages[i].Package, baseline.Packages[i], all.Packages[i])
		}
	}
	if !reflect.DeepEqual(baseline.Mapping, all.Mapping) {
		t.Errorf("the mapping report changed with -all-packages:\n without=%+v\n with=%+v", baseline.Mapping, all.Mapping)
	}
	if !reflect.DeepEqual(baseline.SourceInputStates, all.SourceInputStates) {
		t.Errorf("the evidence sources' input states changed with -all-packages:\n without=%+v\n with=%+v",
			baseline.SourceInputStates, all.SourceInputStates)
	}

	// The flag still does its own job: the bundled archive is carried
	// through the same per-package computation and reaches the result.
	found := false
	for _, pv := range all.Packages[len(baseline.Packages):] {
		if pv.Package == "com.example:native-bridge" {
			found = true
			if pv.FindingCount != 0 {
				t.Errorf("the bundled archive reports %d Finding(s), want none", pv.FindingCount)
			}
			if pv.S1Verdict == "" || pv.S2Verdict == "" {
				t.Errorf("the bundled archive has no S1/S2 verdict at all: %+v", pv)
			}
		}
	}
	if !found {
		t.Error("the bundled archive is missing from result.Packages entirely")
	}
}
