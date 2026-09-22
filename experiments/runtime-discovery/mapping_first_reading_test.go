package main

import (
	"testing"
	"time"
)

// firstReadingReport carries one operating-system package (tzdata), both
// as a Finding and (when read with -all-packages) in the scan's own
// Packages list.
const firstReadingReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-first-reading-test:1",
  "Metadata": { "OS": { "Family": "debian" } },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "debian",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-7000", "PkgName": "tzdata", "InstalledVersion": "2024a-1", "Severity": "LOW", "Status": "fixed" }
      ],
      "Packages": [
        { "Name": "tzdata", "Version": "2024a-1" }
      ]
    }
  ]
}`

// firstReadingAux is the layout information a single mount view's first
// reading would have saved: /etc/localtime linking to the zoneinfo file
// tzdata owns, and the operating-system package set the caller supplies.
func firstReadingAux(firstSeen time.Time, ownedPaths []OwnedPathEntry) []AuxiliaryInputs {
	return []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-first-reading",
		FirstSeen: firstSeen, LastSeen: firstSeen,
		Symlinks: []SymlinkEntry{
			{Path: "/etc/localtime", Target: "/usr/share/zoneinfo/Etc/UTC"},
		},
		OwnedPaths: ownedPaths,
	}}
}

// TestOSOwnershipBeforeTheFirstReadingIsUnresolved documents the accepted
// limitation this project's own real measurement runs hit: an open of
// /etc/localtime at or moments after container startup, before the first
// reading of its mount view completed, is not attributed to the
// operating-system package owning what it names. A reading's own
// operating-system package (name, version) set matching the scan's
// population was tried as a basis for widening that reading's own
// coverage backward (see the removed first_reading_layout_invariant), but
// that match does not prove the layout itself is unchanged back to
// container start — /etc/localtime can be re-pointed, and a file can be
// replaced by another of the same version, without either ever showing up
// in that set — so the widening was retracted rather than kept.
func TestOSOwnershipBeforeTheFirstReadingIsUnresolved(t *testing.T) {
	idx, _, err := buildScanFileIndex([]byte(firstReadingReport), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	firstSeen := time.Date(2026, 9, 19, 14, 7, 40, 0, time.UTC)
	aux := firstReadingAux(firstSeen, []OwnedPathEntry{
		{Path: "/usr/share/zoneinfo/Etc/UTC", DBKind: "dpkg", Package: "tzdata", Version: "2024a-1"},
	})
	set := newResolverSet(idx, aux)

	before := firstSeen.Add(-3 * time.Second)
	out := set.resolveEvent("/etc/localtime", before)
	if !out.Unresolved {
		t.Errorf("an operating-system path before the first reading resolved: %v", packagesOf(out))
	}
}

// TestGenericFallbackResolvesNodeAndJarBeforeTheFirstReading checks that a
// require or a jar open from before the first reading of its mount view
// still resolves from the observed path and the scan report alone (a
// module tree's own /node_modules/ boundary, a jar's own suffix), needing
// no saved layout at all — the dataless fallback resolver
// (resolveEventVerb's own s.fallback) always answers this, independent of
// whatever operating-system package data a reading happens to carry.
func TestGenericFallbackResolvesNodeAndJarBeforeTheFirstReading(t *testing.T) {
	const report = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-fallback-test:1",
  "Metadata": { "OS": { "Family": "debian" } },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "debian",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-9000", "PkgName": "tzdata", "InstalledVersion": "2024a-1", "Severity": "LOW", "Status": "fixed" }
      ],
      "Packages": [ { "Name": "tzdata", "Version": "2024a-1" } ]
    },
    {
      "Class": "lang-pkgs", "Type": "node-pkg", "Target": "Node.js",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-9001", "PkgName": "express", "PkgPath": "app/node_modules/express/package.json", "InstalledVersion": "4.18.0", "Severity": "LOW", "Status": "fixed" }
      ]
    },
    {
      "Class": "lang-pkgs", "Type": "jar", "Target": "Java",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-9002", "PkgName": "org.example:lib", "PkgPath": "app/lib.jar", "InstalledVersion": "1.0", "Severity": "LOW", "Status": "fixed" }
      ]
    }
  ]
}`
	idx, _, err := buildScanFileIndex([]byte(report), true)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	firstSeen := time.Date(2026, 9, 19, 14, 7, 40, 0, time.UTC)
	aux := firstReadingAux(firstSeen, []OwnedPathEntry{
		{Path: "/usr/share/zoneinfo/Etc/UTC", DBKind: "dpkg", Package: "tzdata", Version: "2024a-1"},
	})
	set := newResolverSet(idx, aux)

	before := firstSeen.Add(-3 * time.Second)
	nodeOut := set.resolveEvent("/app/node_modules/express/index.js", before)
	if nodeOut.Unresolved || nodeOut.Conflict {
		t.Fatalf("a require before the first reading did not resolve: %+v", nodeOut)
	}
	if got := packagesOf(nodeOut); len(got) != 1 || got[0] != "express" {
		t.Errorf("resolved to %v, want express", got)
	}

	jarOut := set.resolveEvent("/app/lib.jar", before)
	if jarOut.Unresolved || jarOut.Conflict {
		t.Fatalf("a jar open before the first reading did not resolve: %+v", jarOut)
	}
	if got := packagesOf(jarOut); len(got) != 1 || got[0] != "org.example:lib" {
		t.Errorf("resolved to %v, want org.example:lib", got)
	}
}
