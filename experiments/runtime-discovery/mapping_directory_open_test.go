package main

import "testing"

// directoryOpenReport carries one operating-system package (base-files)
// whose own file list includes both a directory (/proc) and an ordinary
// file (/usr/bin/base-tool), the shape a real package's own file list
// takes.
const directoryOpenReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-directory-open-test:1",
  "Metadata": { "OS": { "Family": "debian" } },
  "Results": [
    {
      "Class": "os-pkgs", "Type": "debian",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-8000", "PkgName": "base-files", "InstalledVersion": "14ubuntu6.2", "Severity": "LOW", "Status": "fixed" }
      ]
    }
  ]
}`

func directoryOpenIndex(t *testing.T) *scanFileIndex {
	t.Helper()
	idx, _, err := buildScanFileIndex([]byte(directoryOpenReport), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	return idx
}

// directoryOpenAux marks /proc as a directory (IsDir) and
// /usr/bin/base-tool as an ordinary file, both owned by base-files —
// exactly the layout information a collection saves once it lstats each
// package-database path.
func directoryOpenAux() []AuxiliaryInputs {
	return []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-directory-open",
		OwnedPaths: []OwnedPathEntry{
			{Path: "/proc", DBKind: "dpkg", Package: "base-files", Version: "14ubuntu6.2", IsDir: true},
			{Path: "/usr/bin/base-tool", DBKind: "dpkg", Package: "base-files", Version: "14ubuntu6.2"},
		},
	}}
}

func directoryOpenResolver(t *testing.T) *fileResolver {
	t.Helper()
	return newFileResolver(directoryOpenIndex(t), directoryOpenAux())
}

// TestDirectoryOpenEventIsNotConfirmed checks that an open event naming a
// path saved layout information records as a directory is left
// unresolved with the dedicated reason, rather than confirming the
// package that ships the directory.
func TestDirectoryOpenEventIsNotConfirmed(t *testing.T) {
	r := directoryOpenResolver(t)
	out := r.resolveForEvent("/proc", true)
	if !out.Unresolved {
		t.Fatalf("a directory open resolved anyway: %+v", out)
	}
	if out.MissKind != missDirectoryOpen {
		t.Errorf("miss kind = %q, want %q", out.MissKind, missDirectoryOpen)
	}
	if out.UnresolvedWh == "" {
		t.Error("no reason was recorded for the directory-open refusal")
	}
	if len(out.Matches) != 0 {
		t.Errorf("a directory open still produced %d match(es)", len(out.Matches))
	}
}

// TestDirectoryPathStillConfirmsOutsideAnOpenEvent checks that the
// exclusion is specific to a genuine open event: an exec of the very same
// path (not a real scenario a directory produces, but the rule must never
// depend on that), and the plain resolve() the sampling pass and every
// non-event caller uses, both still confirm the owning package exactly as
// they always did.
func TestDirectoryPathStillConfirmsOutsideAnOpenEvent(t *testing.T) {
	r := directoryOpenResolver(t)

	if out := r.resolve("/proc"); out.Unresolved || out.Conflict {
		t.Errorf("resolve() (sampling/exec) refused a directory path: %+v", out)
	} else if got := packagesOf(out); len(got) != 1 || got[0] != "base-files" {
		t.Errorf("resolve() resolved to %v, want base-files", got)
	}

	if out := r.resolveForEvent("/proc", false); out.Unresolved || out.Conflict {
		t.Errorf("resolveForEvent(..., isOpenEvent=false) (exec) refused a directory path: %+v", out)
	} else if got := packagesOf(out); len(got) != 1 || got[0] != "base-files" {
		t.Errorf("resolveForEvent(..., false) resolved to %v, want base-files", got)
	}
}

// TestDirectoryOpenExclusionDoesNotTouchOrdinaryFiles checks that the new
// rule is scoped to paths actually recorded as directories: an ordinary
// file's open event confirms exactly as before.
func TestDirectoryOpenExclusionDoesNotTouchOrdinaryFiles(t *testing.T) {
	r := directoryOpenResolver(t)
	out := r.resolveForEvent("/usr/bin/base-tool", true)
	if out.Unresolved || out.Conflict {
		t.Fatalf("an ordinary file's open event was refused: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "base-files" {
		t.Errorf("resolved to %v, want base-files", got)
	}
}

// TestOldInputWithoutIsDirStillConfirmsDirectoryOpen checks that a reading
// saved before IsDir existed (every entry false, indistinguishable from an
// ordinary file) behaves exactly as it always did: an open event on it
// still confirms the owning package, since nothing recorded that it was
// ever a directory in the first place.
func TestOldInputWithoutIsDirStillConfirmsDirectoryOpen(t *testing.T) {
	aux := []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-no-isdir",
		OwnedPaths: []OwnedPathEntry{
			// The same path as directoryOpenAux's own /proc entry, but
			// from a reading that predates IsDir: it is simply absent
			// (false), the same as every field an older input never
			// wrote.
			{Path: "/proc", DBKind: "dpkg", Package: "base-files", Version: "14ubuntu6.2"},
		},
	}}
	r := newFileResolver(directoryOpenIndex(t), aux)
	out := r.resolveForEvent("/proc", true)
	if out.Unresolved || out.Conflict {
		t.Fatalf("an input with no IsDir information stopped confirming a directory open: %+v", out)
	}
	if got := packagesOf(out); len(got) != 1 || got[0] != "base-files" {
		t.Errorf("resolved to %v, want base-files", got)
	}
}

// TestResolveEventVerbRefusesADirectoryOpenThroughTheResolverSet checks
// the same exclusion through resolverSet.resolveEventVerb, the path a
// real event actually takes (series.go's own call site), including the
// plain two-argument resolveEvent staying exec-shaped (never refusing).
func TestResolveEventVerbRefusesADirectoryOpenThroughTheResolverSet(t *testing.T) {
	set := newResolverSet(directoryOpenIndex(t), directoryOpenAux())

	openOut := set.resolveEventVerb("/proc", set.anyResolver().firstSeen, true)
	if !openOut.Unresolved || openOut.MissKind != missDirectoryOpen {
		t.Fatalf("resolveEventVerb(isOpenEvent=true) did not refuse the directory open: %+v", openOut)
	}

	execOut := set.resolveEventVerb("/proc", set.anyResolver().firstSeen, false)
	if execOut.Unresolved || execOut.Conflict {
		t.Fatalf("resolveEventVerb(isOpenEvent=false) refused a directory path: %+v", execOut)
	}

	plainOut := set.resolveEvent("/proc", set.anyResolver().firstSeen)
	if plainOut.Unresolved || plainOut.Conflict {
		t.Fatalf("resolveEvent (isOpenEvent=false by default) refused a directory path: %+v", plainOut)
	}
}

// TestDirectoryOpenPrecedesNodeModuleBoundaryMatch checks that the
// directory check runs ahead of every package rule, not only the
// operating-system one: a path that both saved layout information records
// as a directory and structurally satisfies the node_package_boundary
// rule (it sits under a real node_modules/<name>/ prefix the scan report
// also names a manifest for) is refused as a directory open before
// node_package_boundary's own add() ever runs, the same way it already is
// for the operating-system rule.
func TestDirectoryOpenPrecedesNodeModuleBoundaryMatch(t *testing.T) {
	const report = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-directory-node-test:1",
  "Metadata": { "OS": { "Family": "debian" } },
  "Results": [
    {
      "Class": "lang-pkgs", "Type": "node-pkg", "Target": "Node.js",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2030-8100", "PkgName": "dep", "PkgPath": "app/node_modules/dep/package.json", "InstalledVersion": "1.0.0", "Severity": "LOW", "Status": "fixed" }
      ]
    }
  ]
}`
	idx, _, err := buildScanFileIndex([]byte(report), false)
	if err != nil {
		t.Fatalf("buildScanFileIndex: %v", err)
	}
	aux := []AuxiliaryInputs{{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", AuxGeneration: "aux-directory-node",
		OwnedPaths: []OwnedPathEntry{
			// Layout information saying this exact path is a directory —
			// which package (if any) happens to have listed it in its own
			// file list is beside the point being tested.
			{Path: "/app/node_modules/dep/lib", DBKind: "dpkg", Package: "some-os-pkg", Version: "1.0", IsDir: true},
		},
	}}
	r := newFileResolver(idx, aux)

	out := r.resolveForEvent("/app/node_modules/dep/lib", true)
	if !out.Unresolved || out.MissKind != missDirectoryOpen {
		t.Fatalf("a directory under node_modules was not refused ahead of the node_package_boundary rule: %+v", out)
	}
	for _, p := range packagesOf(out) {
		if p == "dep" {
			t.Fatalf("the directory open was attributed to dep despite being a directory: %+v", out)
		}
	}

	// The plain, non-open-event resolve() must never depend on this
	// check: a directory is not a real scenario an exec or a sampled path
	// produces, but the rule must never assume that rather than checking
	// isOpenEvent.
	if out := r.resolve("/app/node_modules/dep/lib"); out.Unresolved || out.Conflict {
		t.Fatalf("resolve() unexpectedly refused a directory path: %+v", out)
	}
	if got := packagesOf(r.resolve("/app/node_modules/dep/lib")); len(got) != 1 || got[0] != "dep" {
		t.Errorf("resolve() resolved to %v, want dep", got)
	}
}
