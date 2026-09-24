package main

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestGroupFindingsDedup(t *testing.T) {
	findings := []scanner.Finding{
		{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.13-1", VulnID: "CVE-1"},
		{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.13-1", VulnID: "CVE-1"}, // exact duplicate
		{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.13-1", VulnID: "CVE-2"},
		{Class: scanner.ClassOS, Package: "gzip", InstalledVer: "1.12-1", VulnID: "CVE-3"},
	}
	groups := groupFindings(findings)
	if len(groups) != 2 {
		t.Fatalf("groupFindings returned %d groups, want 2", len(groups))
	}
	if groups[0].key.Package != "gzip" || len(groups[0].vulns) != 1 {
		t.Errorf("groups[0] = %+v, want gzip with 1 vuln", groups[0])
	}
	if groups[1].key.Package != "libssl3" || len(groups[1].vulns) != 2 {
		t.Errorf("groups[1] = %+v, want libssl3 with 2 distinct vulns (duplicate CVE-1 removed)", groups[1])
	}
}

// syntheticRecord is a fully-valid, two-sample, single-package-owning
// container: two collection_results both valid, libssl3 confirmed via
// s1's maps, package_ledger says both libssl3 and gzip have file lists.
func syntheticRecord() *ContainerRecord {
	return &ContainerRecord{
		Window: Window{Samples: []SampleTiming{{SampleID: "s0"}, {SampleID: "s1"}}},
		CollectionResults: []CollectionResult{
			{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "ok", Valid: true},
			{SampleID: "s1", ProcObserve: "ok", PkgdbRead: "ok", Valid: true},
		},
		Processes: []ProcessRecord{
			{SampleID: "s0", Generation: ProcessGeneration{PID: 1}, Exe: "/usr/sbin/nginx"},
			{SampleID: "s1", Generation: ProcessGeneration{PID: 1}, Exe: "/usr/sbin/nginx"},
		},
		PathResolution: []PathResolutionRecord{
			{SampleID: "s0", Generation: ProcessGeneration{PID: 1}, Path: "/usr/sbin/nginx", Resolved: "/usr/sbin/nginx", Ownership: OwnershipOwned, DBKind: dpkgKind, Package: "nginx", DBVersion: "1.27.0-1"},
			{SampleID: "s1", Generation: ProcessGeneration{PID: 1}, Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Resolved: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Ownership: OwnershipOwned, DBKind: dpkgKind, Package: "libssl3", DBVersion: "3.0.13-1"},
		},
		PackageLedger: []LedgerEntry{
			{Name: "nginx", Version: "1.27.0-1", FileListPresent: true},
			{Name: "libssl3", Version: "3.0.13-1", FileListPresent: true},
			{Name: "gzip", Version: "1.12-1", FileListPresent: true},
		},
		PkgDBs: []PkgDBGenerationInfo{{DBKind: dpkgKind}},
	}
}

func syntheticWindowValidity(rec *ContainerRecord) windowValidity {
	return computeWindowValidity(rec)
}

func TestObservationStateObserved(t *testing.T) {
	rec := syntheticRecord()
	wv := syntheticWindowValidity(rec)
	if state := observationState(rec, wv); state != "observed" {
		t.Errorf("observationState = %q, want observed", state)
	}
}

// TestObservationFailedMixedFailureModes is the required decision-table
// edge case: a sample with proc_observe=ok/pkgdb_read=error, and a sample
// with proc_observe=denied/pkgdb_read=ok. Neither sample is individually
// valid (valid requires BOTH proc_observe=ok AND pkgdb_read in {ok,absent}
// on the SAME sample), so the window has zero valid samples even though
// each operation "succeeded" at least once.
func TestObservationFailedMixedFailureModes(t *testing.T) {
	rec := &ContainerRecord{
		CollectionResults: []CollectionResult{
			{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "error", Valid: false},
			{SampleID: "s1", ProcObserve: "denied", PkgdbRead: "ok", Valid: false},
		},
	}
	wv := computeWindowValidity(rec)
	if wv.Valid != 0 {
		t.Fatalf("valid samples = %d, want 0", wv.Valid)
	}
	if state := observationState(rec, wv); state != "observation_failed" {
		t.Errorf("observationState = %q, want observation_failed", state)
	}
}

func TestObservationStatePartial(t *testing.T) {
	rec := syntheticRecord()
	rec.CollectionResults[0] = CollectionResult{SampleID: "s0", ProcObserve: "top_failed", PkgdbRead: "error", Valid: false}
	wv := computeWindowValidity(rec)
	if state := observationState(rec, wv); state != "partially_observed" {
		t.Errorf("observationState = %q, want partially_observed", state)
	}
}

// TestDecisionTable exercises each of the 5 decision-table rows in order.
func TestDecisionTable(t *testing.T) {
	rec := syntheticRecord()
	wv := computeWindowValidity(rec)

	t.Run("rule1 observation_failed beats everything", func(t *testing.T) {
		g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.13-1"}, vulns: []findingVuln{{VulnID: "CVE-1"}}}
		pv := assignVerdict(g, rec, Case{}, "observation_failed", wv)
		if pv.Verdict != VerdictNotDetermined {
			t.Errorf("Verdict = %q, want not_determined even though a confirming path exists", pv.Verdict)
		}
	})

	t.Run("rule2 lang class is always unobserved/lang_pkg_unmappable", func(t *testing.T) {
		g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassLang, Package: "cryptography", InstalledVer: "3.3.2"}, vulns: []findingVuln{{VulnID: "CVE-7"}}}
		pv := assignVerdict(g, rec, Case{}, "observed", wv)
		if pv.Verdict != VerdictUnobserved || pv.Factor != factorLangPkg {
			t.Errorf("got (%q, %q), want (unobserved, lang_pkg_unmappable)", pv.Verdict, pv.Factor)
		}
	})

	t.Run("rule3 confirmed by an owned, version-matching valid-sample path", func(t *testing.T) {
		g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.13-1"}, vulns: []findingVuln{{VulnID: "CVE-1"}}}
		pv := assignVerdict(g, rec, Case{}, "observed", wv)
		if pv.Verdict != VerdictConfirmed {
			t.Fatalf("Verdict = %q, want confirmed", pv.Verdict)
		}
		if pv.CaptureSamples != 1 || len(pv.ObservedPaths) != 1 {
			t.Errorf("CaptureSamples/ObservedPaths = %d/%v", pv.CaptureSamples, pv.ObservedPaths)
		}
	})

	t.Run("rule4 file_list present but never observed -> unobserved", func(t *testing.T) {
		g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassOS, Package: "gzip", InstalledVer: "1.12-1"}, vulns: []findingVuln{{VulnID: "CVE-3"}}}
		pv := assignVerdict(g, rec, Case{}, "observed", wv)
		if pv.Verdict != VerdictUnobserved || pv.Factor != factorNoObserved {
			t.Errorf("got (%q, %q), want (unobserved, no_observation)", pv.Verdict, pv.Factor)
		}
	})

	t.Run("rule5a file_list absent -> unresolved/no_file_list", func(t *testing.T) {
		g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassOS, Package: "base-files", InstalledVer: "12"}, vulns: []findingVuln{{VulnID: "CVE-9"}}}
		pv := assignVerdict(g, rec, Case{}, "observed", wv) // base-files not in ledger at all
		if pv.Verdict != VerdictUnresolved || pv.Factor != factorNoFileList {
			t.Errorf("got (%q, %q), want (unresolved, no_file_list)", pv.Verdict, pv.Factor)
		}
	})

	t.Run("rule5b no usable database at all -> unresolved/db_absent", func(t *testing.T) {
		noDB := &ContainerRecord{
			Window:            Window{Samples: []SampleTiming{{SampleID: "s0"}}},
			CollectionResults: []CollectionResult{{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "absent", Valid: true}},
		}
		wvNoDB := computeWindowValidity(noDB)
		g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassOS, Package: "libc6", InstalledVer: "2.36-9"}, vulns: []findingVuln{{VulnID: "CVE-9"}}}
		pv := assignVerdict(g, noDB, Case{}, "observed", wvNoDB)
		if pv.Verdict != VerdictUnresolved || pv.Factor != factorDBAbsent {
			t.Errorf("got (%q, %q), want (unresolved, db_absent)", pv.Verdict, pv.Factor)
		}
	})
}

func TestAssignVerdictVersionMismatchNotConfirmed(t *testing.T) {
	rec := syntheticRecord()
	wv := computeWindowValidity(rec)
	g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.15-2"}, vulns: []findingVuln{{VulnID: "CVE-1"}}}
	pv := assignVerdict(g, rec, Case{}, "observed", wv)
	if pv.Verdict == VerdictConfirmed {
		t.Fatalf("Verdict = confirmed, want not confirmed (version mismatch)")
	}
	if len(pv.VersionMismatchPaths) != 1 {
		t.Errorf("VersionMismatchPaths = %v, want one entry", pv.VersionMismatchPaths)
	}
}

func TestAssignVerdictCaseHintShortLived(t *testing.T) {
	rec := syntheticRecord()
	rec.PackageLedger = append(rec.PackageLedger, LedgerEntry{Name: "git", Version: "1:2.39.2-1", FileListPresent: true})
	wv := computeWindowValidity(rec)
	def := Case{Expected: []ExpectedUsage{{Package: "git", Class: "os", ExpectedVerdict: "confirmed", FactorHint: factorShortLived}}}
	g := pkgGroup{key: pkgGroupKey{Class: scanner.ClassOS, Package: "git", InstalledVer: "1:2.39.2-1"}, vulns: []findingVuln{{VulnID: "CVE-11"}}}
	pv := assignVerdict(g, rec, def, "observed", wv)
	if pv.Verdict != VerdictUnobserved || pv.Factor != factorShortLived {
		t.Fatalf("got (%q, %q), want (unobserved, short_lived)", pv.Verdict, pv.Factor)
	}
}

func TestClassifyGap(t *testing.T) {
	staticLink := gapEvidence{StaticallyLinked: true}
	tests := []struct {
		name               string
		pv                 PackageVerdict
		e4                 bool
		evidence           gapEvidence
		wantClass          string
		wantRecoverability string
	}{
		{"confirmed is not a gap", PackageVerdict{Verdict: VerdictConfirmed}, false, gapEvidence{}, "", ""},
		{"not_determined is not a gap", PackageVerdict{Verdict: VerdictNotDetermined}, false, gapEvidence{}, "", ""},
		{"E3 before E1: GT-B not_used wins even if factor looks like a sampling gap", PackageVerdict{Verdict: VerdictUnobserved, Factor: factorShortLived, GTBTruth: "not_used"}, false, gapEvidence{}, "E3", ""},
		{"E1: unobserved + GT-B used, with ownership resolvable", PackageVerdict{Verdict: VerdictUnobserved, Factor: factorShortLived, GTBTruth: "used"}, false, gapEvidence{}, "E1", "candidate"},
		{"lang unmappable is E2, not E1, even when GT-B says used", PackageVerdict{Verdict: VerdictUnobserved, Factor: factorLangPkg, GTBTruth: "used"}, false, gapEvidence{}, "E2", "candidate"},
		{"E2: unresolved for a missing file list", PackageVerdict{Verdict: VerdictUnresolved, Factor: factorNoFileList, GTBTruth: "used"}, false, gapEvidence{}, "E2", "candidate"},
		{"a database that could not be read at all is not an E2 mapping gap", PackageVerdict{Verdict: VerdictUnresolved, Factor: factorDBError, GTBTruth: "used"}, false, gapEvidence{}, "unclassified", "unknown"},
		{"E4: declared and borne out by the observation", PackageVerdict{Verdict: VerdictUnobserved, Factor: factorNoObserved}, true, staticLink, "E4", ""},
		{"a declared E4 the observation does not support is not E4", PackageVerdict{Verdict: VerdictUnobserved, Factor: factorNoObserved}, true, gapEvidence{}, "unclassified", "unknown"},
		{"unclassified: no GT-B, no E4 declaration", PackageVerdict{Verdict: VerdictUnobserved, Factor: factorNoObserved}, false, gapEvidence{}, "unclassified", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			class, recoverability := classifyGap(tt.pv, tt.e4, tt.evidence)
			if class != tt.wantClass {
				t.Errorf("classifyGap class = %q, want %q", class, tt.wantClass)
			}
			if recoverability != tt.wantRecoverability {
				t.Errorf("classifyGap recoverability = %q, want %q", recoverability, tt.wantRecoverability)
			}
		})
	}
}

// TestComputeGapEvidence checks that the two observable grounds for an
// unrecoverable gap come from the observation rather than from the case
// definition: a container that maps shared libraries is not statically
// linked no matter what its case declares.
func TestComputeGapEvidence(t *testing.T) {
	rec := syntheticRecord()
	rec.Processes[1].Maps = []MapEntry{{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3"}}
	wv := computeWindowValidity(rec)
	if ev := computeGapEvidence(rec, wv); ev.StaticallyLinked {
		t.Error("StaticallyLinked = true for a process that maps a shared library")
	}

	static := syntheticRecord()
	for i := range static.Processes {
		static.Processes[i].Maps = nil
	}
	wvStatic := computeWindowValidity(static)
	if ev := computeGapEvidence(static, wvStatic); !ev.StaticallyLinked {
		t.Error("StaticallyLinked = false where no process mapped anything but its own executable")
	}
}

func TestRateOrNA(t *testing.T) {
	if got := rateOrNA(0, 0); got != -1 {
		t.Errorf("rateOrNA(0,0) = %v, want -1 (N/A)", got)
	}
	if got := rateOrNA(2, 4); got != 0.5 {
		t.Errorf("rateOrNA(2,4) = %v, want 0.5", got)
	}
}

// TestGTBBoundsFourFormulas checks all four FPR/FNR bound formulas against a
// hand-computed scenario: 1 TP, 1 FN, 1 FP, 1 TN confirmed, plus 2
// undetermined pairs (one predicted-positive, one predicted-negative).
func TestGTBBoundsFourFormulas(t *testing.T) {
	packages := []PackageVerdict{
		{Package: "a", Verdict: VerdictConfirmed, FindingCount: 1, GTBTruth: "used"},          // TP
		{Package: "b", Verdict: VerdictUnobserved, FindingCount: 1, GTBTruth: "used"},         // FN
		{Package: "c", Verdict: VerdictConfirmed, FindingCount: 1, GTBTruth: "not_used"},      // FP
		{Package: "d", Verdict: VerdictUnobserved, FindingCount: 1, GTBTruth: "not_used"},     // TN
		{Package: "e", Verdict: VerdictConfirmed, FindingCount: 1, GTBTruth: "undetermined"},  // undetermined, predicted positive
		{Package: "f", Verdict: VerdictUnobserved, FindingCount: 1, GTBTruth: "undetermined"}, // undetermined, predicted negative
	}
	c, _ := computeGTBCounts(packages)
	if c.TP != 1 || c.FN != 1 || c.FP != 1 || c.TN != 1 || c.Undetermined != 2 {
		t.Fatalf("counts = %+v", c)
	}
	// Point estimates ignore undetermined entirely.
	if c.FPR != 0.5 || c.FNR != 0.5 {
		t.Errorf("FPR/FNR = %v/%v, want 0.5/0.5", c.FPR, c.FNR)
	}
	// FPR upper: undetermined-positive(1) -> FP; undetermined-negative excluded (-> FN).
	// FPR_upper = (FP+1)/((FP+1)+TN) = 2/3
	if got, want := c.FPRUpperBound, 2.0/3.0; !floatsClose(got, want) {
		t.Errorf("FPRUpperBound = %v, want %v", got, want)
	}
	// FPR lower: undetermined-negative(1) -> TN; undetermined-positive excluded (-> TP).
	// FPR_lower = FP/(FP+(TN+1)) = 1/3
	if got, want := c.FPRLowerBound, 1.0/3.0; !floatsClose(got, want) {
		t.Errorf("FPRLowerBound = %v, want %v", got, want)
	}
	// FNR upper: undetermined-negative(1) -> FN; undetermined-positive excluded (-> FP).
	// FNR_upper = (FN+1)/((FN+1)+TP) = 2/3
	if got, want := c.FNRUpperBound, 2.0/3.0; !floatsClose(got, want) {
		t.Errorf("FNRUpperBound = %v, want %v", got, want)
	}
	// FNR lower: undetermined-positive(1) -> TP; undetermined-negative excluded (-> TN).
	// FNR_lower = FN/(FN+(TP+1)) = 1/3
	if got, want := c.FNRLowerBound, 1.0/3.0; !floatsClose(got, want) {
		t.Errorf("FNRLowerBound = %v, want %v", got, want)
	}
}

func floatsClose(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

func TestBuildGTBTruthOpenOnlyStaysUsed(t *testing.T) {
	// required test: a dependency library recorded only via "open" (no
	// exec->exit or dlopen->dlclose interval of its own) must be "used",
	// and must never be demoted to "not used".
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind:         "usage_log",
		PathPackages: []PathPackage{{Path: "/usr/lib/x86_64-linux-gnu/libcurl.so.4", Package: "libcurl4"}},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(10 * time.Second), PID: 100, Path: "/usr/lib/x86_64-linux-gnu/libcurl.so.4", Event: "open", OK: true},
		},
	}
	scope := scopeSet([]string{"libcurl4"})
	truth := buildGTBTruth(gtb, scope, windowStart, windowEnd)
	if !truth.Covered["libcurl4"] || !truth.Used["libcurl4"] {
		t.Fatalf("libcurl4: covered=%v used=%v, want covered=true used=true", truth.Covered["libcurl4"], truth.Used["libcurl4"])
	}
}

// TestBuildGTBTruthOutOfWindowOpenAttachedToInterval covers the interval
// attachment rule: a library loaded before the window opened is still in
// use inside it, as long as the process that loaded it is recorded as
// still running then.
func TestBuildGTBTruthOutOfWindowOpenAttachedToInterval(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PathPackages: []PathPackage{
			{Path: "/server", Package: "server-pkg"},
			{Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Package: "libsqlite3-0"},
		},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 7, Starttime: 42, Path: "/server", Event: "exec", OK: true},
			{Timestamp: windowStart.Add(-59 * time.Second), PID: 7, Starttime: 42, Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Event: "open", OK: true},
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"libsqlite3-0"}), windowStart, windowEnd)
	if !truth.Covered["libsqlite3-0"] || !truth.Used["libsqlite3-0"] {
		t.Fatalf("libsqlite3-0: covered=%v used=%v, want both true (loaded before the window by a process still running in it)",
			truth.Covered["libsqlite3-0"], truth.Used["libsqlite3-0"])
	}
}

// TestBuildGTBTruthOrphanOpenStaysUndetermined covers the completeness
// condition: an out-of-window open belonging to no recorded interval
// neither proves use nor allows non-use to be concluded.
func TestBuildGTBTruthOrphanOpenStaysUndetermined(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind:         "usage_log",
		PathPackages: []PathPackage{{Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Package: "libsqlite3-0"}},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 7, Starttime: 42, Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Event: "open", OK: true},
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"libsqlite3-0"}), windowStart, windowEnd)
	if truth.Covered["libsqlite3-0"] {
		t.Errorf("libsqlite3-0: covered=true, want false: an orphan open cannot certify non-use")
	}
	if truth.UndeterminedWhy["libsqlite3-0"] == "" {
		t.Error("an undetermined package must record why it could not be decided")
	}
}

// TestBuildGTBTruthExitStatusDoesNotDiscardEndpoint covers the split
// between "an exit was observed" and "the process succeeded": a non-zero
// exit still closes the interval, so a command that ran and failed before
// the window is not reported as in use throughout it.
func TestBuildGTBTruthExitStatusDoesNotDiscardEndpoint(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	status := 1
	gtb := &GroundTruthB{
		Kind:         "usage_log",
		PathPackages: []PathPackage{{Path: "/usr/bin/git", Package: "git"}},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 9, Starttime: 7, Path: "/usr/bin/git", Event: "exec", OK: true},
			{Timestamp: windowStart.Add(-59 * time.Second), PID: 9, Starttime: 7, Path: "/usr/bin/git", Event: "exit", OK: true, Status: &status},
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"git"}), windowStart, windowEnd)
	if truth.Used["git"] {
		t.Error("git: used=true, want false: the run ended before the window, non-zero exit included")
	}
	if !truth.Covered["git"] {
		t.Error("git: covered=false, want true: the log is complete for it, so non-use is decidable")
	}
}

// TestBuildGTBTruthUnownedPathDoesNotBlockCompleteness covers the
// distinction between a path the independent resolution could not map and
// one it confirmed belongs to no package at all (the workload's own
// binary, say): only the first should withdraw the completeness guarantee
// from every package in the case's scope.
func TestBuildGTBTruthUnownedPathDoesNotBlockCompleteness(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PathPackages: []PathPackage{
			{Path: "/dlopen_loop", Unowned: true},
			{Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Package: "libsqlite3-0"},
		},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 1, Starttime: 5, Path: "/dlopen_loop", Event: "exec", OK: true},
			// libsqlite3-0 is never opened anywhere in this log.
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"libsqlite3-0"}), windowStart, windowEnd)
	if !truth.Covered["libsqlite3-0"] || truth.Used["libsqlite3-0"] {
		t.Fatalf("libsqlite3-0: covered=%v used=%v, want covered=true used=false: the unowned exec path must not make this undetermined",
			truth.Covered["libsqlite3-0"], truth.Used["libsqlite3-0"])
	}
	if why := truth.UndeterminedWhy["libsqlite3-0"]; why != "" {
		t.Errorf("libsqlite3-0: undetermined why=%q, want none", why)
	}
}

// TestBuildGTBTruthEmptyPathPackageRecordDoesNotResolve covers a
// PathPackages entry that names neither a package nor Unowned — an empty
// {"path": "/x"} a bug elsewhere could produce. It must answer nothing,
// not be mistaken for a confirmed absence of an owner.
func TestBuildGTBTruthEmptyPathPackageRecordDoesNotResolve(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PathPackages: []PathPackage{
			{Path: "/x"}, // neither Package/Packages nor Unowned set
			{Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Package: "libsqlite3-0"},
		},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 1, Starttime: 5, Path: "/x", Event: "exec", OK: true},
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"libsqlite3-0"}), windowStart, windowEnd)
	if truth.Covered["libsqlite3-0"] {
		t.Error("libsqlite3-0: covered=true, want false: an empty PathPackages record must not certify completeness")
	}
	if truth.UndeterminedWhy["libsqlite3-0"] == "" {
		t.Error("an undetermined package must record why it could not be decided")
	}
}

// TestBuildGTBTruthEmptyPackagesListDoesNotResolve covers the same gap as
// above, reached through an explicit but empty "packages" list instead of
// an entirely empty record.
func TestBuildGTBTruthEmptyPackagesListDoesNotResolve(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PathPackages: []PathPackage{
			{Path: "/x", Packages: []PackageRef{}},
			{Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Package: "libsqlite3-0"},
		},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 1, Starttime: 5, Path: "/x", Event: "exec", OK: true},
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"libsqlite3-0"}), windowStart, windowEnd)
	if truth.Covered["libsqlite3-0"] {
		t.Error("libsqlite3-0: covered=true, want false: an empty packages list must not certify completeness")
	}
}

// TestBuildGTBTruthPackageAndUnownedTogetherIsUnsupported covers a record
// that contradicts itself: a path cannot both belong to a named package
// and be confirmed to belong to none. Neither claim is believed.
func TestBuildGTBTruthPackageAndUnownedTogetherIsUnsupported(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PathPackages: []PathPackage{
			{Path: "/x", Package: "some-pkg", Unowned: true},
			{Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Package: "libsqlite3-0"},
		},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 1, Starttime: 5, Path: "/x", Event: "exec", OK: true},
			{Timestamp: windowStart.Add(10 * time.Second), PID: 2, Path: "/x", Event: "open", OK: true},
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"libsqlite3-0", "some-pkg"}), windowStart, windowEnd)
	if truth.Covered["libsqlite3-0"] {
		t.Error("libsqlite3-0: covered=true, want false: the contradictory record must not certify completeness")
	}
	if truth.Used["some-pkg"] {
		t.Error("some-pkg: used=true, want false: a contradictory record must not credit the package it names either")
	}
}

// TestBuildGTBTruthMultiplePackagesOnOnePathBothCredited covers a fat
// archive that packs more than one package's files into a single file: the
// package the case's scope actually cares about is not necessarily the
// one a plain single-package record would have named, so every package
// listed on the path must be credited, not only the first.
func TestBuildGTBTruthMultiplePackagesOnOnePathBothCredited(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PathPackages: []PathPackage{
			{Path: "/app/fat.jar", Packages: []PackageRef{
				{Package: "org.apache.logging.log4j:log4j-api"},
				{Package: "org.apache.logging.log4j:log4j-core"},
			}},
		},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(10 * time.Second), PID: 1, Path: "/app/fat.jar", Event: "open", OK: true},
		},
	}
	scope := scopeSet([]string{"org.apache.logging.log4j:log4j-core"})
	truth := buildGTBTruth(gtb, scope, windowStart, windowEnd)
	if !truth.Used["org.apache.logging.log4j:log4j-core"] {
		t.Error("log4j-core: used=false, want true: it is one of the packages this path lists, not only the first")
	}
}

func TestBuildGTBTruthOutOfScopeIsUndetermined(t *testing.T) {
	// required test: a package outside gt_b_scope is always undetermined,
	// even if the usage log happens to mention its path.
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind:         "usage_log",
		PathPackages: []PathPackage{{Path: "/usr/bin/curl", Package: "curl"}},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(1 * time.Second), PID: 1, Path: "/usr/bin/curl", Event: "exec", OK: true},
			{Timestamp: windowStart.Add(2 * time.Second), PID: 1, Path: "/usr/bin/curl", Event: "exit", OK: true},
		},
	}
	scope := scopeSet(nil) // curl declared nowhere in gt_b_scope
	truth := buildGTBTruth(gtb, scope, windowStart, windowEnd)
	if truth.Covered["curl"] {
		t.Errorf("curl: covered=%v, want false (outside gt_b_scope)", truth.Covered["curl"])
	}
	if truth.Used["curl"] {
		t.Error("curl must not be marked used when out of scope")
	}
}

func TestInodeCalibrationNotEvaluated(t *testing.T) {
	// required test: when calibration did not succeed, path_inode_changed
	// must never be evaluated (left nil), regardless of what dev/inode
	// values are observed.
	rec := &PathResolutionRecord{}
	cache := &containerPkgCache{calibration: InodeCalibration{Calibrated: false}}
	got := resolvePathRecord("s0", ProcessGeneration{PID: 1}, t.TempDir(), "maps", "/usr/sbin/nginx", "08:01", "12345", false, cache)
	if got.PathInodeChanged != nil {
		t.Errorf("PathInodeChanged = %v, want nil (uncalibrated container must never evaluate it)", *got.PathInodeChanged)
	}
	_ = rec
}

func TestComputeExposureHostNetworkIsUnknown(t *testing.T) {
	rec := &ContainerRecord{Docker: DockerConfig{NetworkMode: "host"}, Listeners: []Listener{{Generation: ProcessGeneration{PID: 1}}}}
	if got := computeExposure(rec, nil).Verdict; got != "unknown" {
		t.Errorf("Exposure = %q, want unknown for host network", got)
	}
}

func TestComputeExposureNoneNetworkIsContainerListening(t *testing.T) {
	rec := &ContainerRecord{Docker: DockerConfig{NetworkMode: "none"}}
	if got := computeExposure(rec, nil).Verdict; got != "container_listening" {
		t.Errorf("Exposure = %q, want container_listening for network_mode=none", got)
	}
}

func TestComputeExposureNoAttribution(t *testing.T) {
	rec := &ContainerRecord{Listeners: []Listener{{Generation: ProcessGeneration{PID: 0}}}}
	if got := computeExposure(rec, nil).Verdict; got != "unknown" {
		t.Errorf("Exposure = %q, want unknown when no listener is pid-attributed", got)
	}
}

func TestComputeExposurePublishedAll(t *testing.T) {
	rec := &ContainerRecord{
		Listeners: []Listener{{Generation: ProcessGeneration{PID: 42}, Protocol: "tcp", Family: "ipv4", LocalPort: 80}},
		Docker:    DockerConfig{NetworkPorts: map[string][]PortBinding{"80/tcp": {{HostIP: "0.0.0.0", HostPort: "18080"}}}},
	}
	if got := computeExposure(rec, nil).Verdict; got != "host_published_all" {
		t.Errorf("Exposure = %q, want host_published_all", got)
	}
}

// TestComputeExposureIPv6ListenerUsesTCPKey covers the protocol/family
// split: a socket in /proc/<pid>/net/tcp6 is still a TCP port, and Docker
// keys its published ports "<port>/tcp" regardless of address family.
// Keying it "<port>/tcp6" would find no declaration and report unknown.
func TestComputeExposureIPv6ListenerUsesTCPKey(t *testing.T) {
	rec := &ContainerRecord{
		Listeners: []Listener{{Generation: ProcessGeneration{PID: 42}, Protocol: "tcp", Family: "ipv6", LocalAddr: "::", LocalPort: 8080}},
		Docker:    DockerConfig{NetworkPorts: map[string][]PortBinding{"8080/tcp": {{HostIP: "0.0.0.0", HostPort: "18080"}}}},
	}
	if got := computeExposure(rec, nil).Verdict; got != "host_published_all" {
		t.Errorf("Exposure = %q, want host_published_all", got)
	}
}

// TestComputeExposureStrongestCandidateWins covers the priority rule: with
// several attributed listeners, the strongest stage decides, whatever order
// procfs happened to list them in.
func TestComputeExposureStrongestCandidateWins(t *testing.T) {
	rec := &ContainerRecord{
		Listeners: []Listener{
			{Generation: ProcessGeneration{PID: 42}, Protocol: "tcp", Family: "ipv4", LocalAddr: "127.0.0.1", LocalPort: 9000},
			{Generation: ProcessGeneration{PID: 42}, Protocol: "tcp", Family: "ipv4", LocalAddr: "0.0.0.0", LocalPort: 80},
		},
		Docker: DockerConfig{NetworkPorts: map[string][]PortBinding{
			"9000/tcp": {{HostIP: "127.0.0.1", HostPort: "19000"}},
			"80/tcp":   {{HostIP: "0.0.0.0", HostPort: "18080"}},
		}},
	}
	if got := computeExposure(rec, nil).Verdict; got != "host_published_all" {
		t.Errorf("Exposure = %q, want host_published_all (the loopback listener must not decide it)", got)
	}
}

func TestComputeExposureLoopback(t *testing.T) {
	rec := &ContainerRecord{
		Listeners: []Listener{{Generation: ProcessGeneration{PID: 42}, Protocol: "tcp", Family: "ipv4", LocalPort: 6379}},
		Docker:    DockerConfig{NetworkPorts: map[string][]PortBinding{"6379/tcp": {{HostIP: "127.0.0.1", HostPort: "16379"}}}},
	}
	if got := computeExposure(rec, nil).Verdict; got != "host_published_loopback" {
		t.Errorf("Exposure = %q, want host_published_loopback", got)
	}
}

func TestComputeExposureContainerListening(t *testing.T) {
	rec := &ContainerRecord{
		Listeners: []Listener{{Generation: ProcessGeneration{PID: 42}, Protocol: "tcp", Family: "ipv4", LocalPort: 5432}},
		Docker:    DockerConfig{NetworkPorts: map[string][]PortBinding{"5432/tcp": nil}}, // declared, not published
	}
	if got := computeExposure(rec, nil).Verdict; got != "container_listening" {
		t.Errorf("Exposure = %q, want container_listening", got)
	}
}

// TestDeclaresE4RequiresARationale covers the one classification that ends
// an investigation: a case may not label its shortfall unrecoverable
// without writing down what makes it so.
func TestDeclaresE4RequiresARationale(t *testing.T) {
	withReason := Case{GapClassHint: "E4", GapClassRationale: "statically linked; no shared library is mapped at all"}
	if !declaresE4(withReason, "anything") {
		t.Error("a case-level E4 declaration with a rationale must be accepted")
	}
	withoutReason := Case{GapClassHint: "E4"}
	if declaresE4(withoutReason, "anything") {
		t.Error("a case-level E4 declaration with no rationale must not be accepted")
	}
	perPackage := Case{
		GapClassHint:      "E4",
		GapClassRationale: "case-level reason",
		Expected:          []ExpectedUsage{{Package: "libc6", GapClassHint: "E4"}},
	}
	if declaresE4(perPackage, "libc6") {
		t.Error("a per-package E4 declaration with no rationale of its own must not fall back to the case-level one")
	}
	if !declaresE4(perPackage, "zlib1g") {
		t.Error("a package with no declaration of its own must still take the case-level declaration")
	}
}

// TestJoinPackageEvidenceDoesNotSynthesizeAcrossProcesses covers the
// combination rule at its sharpest: one process confirms the package while
// holding a published socket, another confirms it while running as root.
// Neither is both. Maximizing the axes separately would label the package
// "published and privileged", which is a state no observed process was
// ever in.
func TestJoinPackageEvidenceDoesNotSynthesizeAcrossProcesses(t *testing.T) {
	key := pkgGroupKey{Class: scanner.ClassOS, Package: "libssl3", InstalledVer: "3.0.13-1"}
	exposed := ProcessGeneration{PID: 10, Starttime: "100"}
	privileged := ProcessGeneration{PID: 11, Starttime: "110"}
	rec := &ContainerRecord{
		Docker:            DockerConfig{NetworkMode: "bridge", NetworkPorts: map[string][]PortBinding{"443/tcp": {{HostIP: "0.0.0.0", HostPort: "8443"}}}},
		CollectionResults: []CollectionResult{{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "ok", Valid: true}},
		Processes: []ProcessRecord{
			{SampleID: "s0", Generation: exposed, EffectiveUID: "101", CapEff: "0000000000000000"},
			{SampleID: "s0", Generation: privileged, EffectiveUID: "0", CapEff: "0000000000000000"},
		},
		Listeners: []Listener{
			{SampleID: "s0", Protocol: "tcp", Family: "ipv4", LocalAddr: "0.0.0.0", LocalPort: 443, Inode: "1", Generation: exposed, Generations: []ProcessGeneration{exposed}},
		},
		PathResolution: []PathResolutionRecord{
			{SampleID: "s0", Generation: exposed, Resolved: "/usr/lib/libssl.so.3", Ownership: OwnershipOwned, Package: "libssl3", DBVersion: "3.0.13-1"},
			{SampleID: "s0", Generation: privileged, Resolved: "/usr/lib/libssl.so.3", Ownership: OwnershipOwned, Package: "libssl3", DBVersion: "3.0.13-1"},
		},
	}
	wv := computeWindowValidity(rec)
	ev := joinPackageEvidence(rec, []pkgGroup{{key: key}}, wv)[key]

	if !ev.Confirmed {
		t.Fatal("Confirmed = false, want true: two processes mapped an owned, version-matching path")
	}
	if ev.Exposure == "host_published_all" && ev.HighPrivilege {
		t.Error("evidence was synthesized across processes: no single process generation was both published and privileged")
	}
	if exposureRank[ev.Exposure] < exposureRank["host_published_all"] && !ev.HighPrivilege {
		t.Errorf("evidence = %+v, want the strongest single confirming observation, not the weakest", ev)
	}
}

// TestBuildGTBTruthDlcloseBeforeWindowEndsUse covers which interval an
// out-of-window open attaches to. The library was explicitly unloaded
// before the window opened; the process that loaded it runs on through the
// window. Attaching the open to that long exec interval instead of to its
// own dlopen/dlclose pair would report a library that is demonstrably not
// loaded as in use.
func TestBuildGTBTruthDlcloseBeforeWindowEndsUse(t *testing.T) {
	windowStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(300 * time.Second)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PathPackages: []PathPackage{
			{Path: "/dlopen-loop", Package: "loop-pkg"},
			{Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Package: "libsqlite3-0"},
		},
		UsageLog: []UsageEvent{
			{Timestamp: windowStart.Add(-90 * time.Second), PID: 5, Starttime: 9, Path: "/dlopen-loop", Event: "exec", OK: true},
			{Timestamp: windowStart.Add(-60 * time.Second), PID: 5, Starttime: 9, Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Event: "dlopen", OK: true},
			{Timestamp: windowStart.Add(-59 * time.Second), PID: 5, Starttime: 9, Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Event: "open", OK: true},
			{Timestamp: windowStart.Add(-30 * time.Second), PID: 5, Starttime: 9, Path: "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0", Event: "dlclose", OK: true},
		},
	}
	truth := buildGTBTruth(gtb, scopeSet([]string{"libsqlite3-0"}), windowStart, windowEnd)
	if truth.Used["libsqlite3-0"] {
		t.Error("libsqlite3-0: used=true, want false: it was dlclosed before the window opened")
	}
	if !truth.Covered["libsqlite3-0"] {
		t.Error("libsqlite3-0: covered=false, want true: the log pairs its dlopen with a dlclose, so non-use is decidable")
	}
}

// TestPackageFileListStatusNoUsableGeneration separates "this window read
// no database" from "this record predates per-sample view recording". In
// the first case the ledger must not answer at all: every valid sample
// established that no database was present.
func TestPackageFileListStatusNoUsableGeneration(t *testing.T) {
	key := pkgGroupKey{Class: scanner.ClassOS, Package: "libc6", InstalledVer: "2.36-9"}
	ledger := []LedgerEntry{{MountViewID: "mv1", DBGeneration: "gen1", Name: "libc6", Version: "2.36-9", FileListPresent: true}}

	absent := &ContainerRecord{
		CollectionResults: []CollectionResult{{
			SampleID: "s0", ProcObserve: "ok", PkgdbRead: "absent", Valid: true,
			Views: []SampleDBView{{MountViewID: "mv1", DBKind: noDBKind, PkgdbRead: "absent"}},
		}},
		PackageLedger: ledger,
	}
	if _, found := packageFileListStatus(absent, computeWindowValidity(absent), key); found {
		t.Error("a window whose every sample found no database must not be answered from a stale ledger entry")
	}

	legacy := &ContainerRecord{
		CollectionResults: []CollectionResult{{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "ok", Valid: true}},
		PackageLedger:     ledger,
	}
	present, found := packageFileListStatus(legacy, computeWindowValidity(legacy), key)
	if !found || !present {
		t.Error("a record with no per-sample view information must still fall back to the whole ledger")
	}
}

// TestClassifyGapVersionMismatchIsNotASamplingGap keeps E1 to shortfalls
// more sampling could actually close. A package whose paths were observed
// but whose version disagreed would fail identically at any sampling rate.
func TestClassifyGapVersionMismatchIsNotASamplingGap(t *testing.T) {
	pv := PackageVerdict{
		Verdict: VerdictUnobserved, Factor: factorNoObserved, GTBTruth: "used",
		VersionMismatchPaths: []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"},
	}
	if class, _ := classifyGap(pv, false, gapEvidence{}); class == "E1" {
		t.Error("a version-mismatched package must not be classified as a sampling gap")
	}
	pv.VersionMismatchPaths = nil
	if class, _ := classifyGap(pv, false, gapEvidence{}); class != "E1" {
		t.Errorf("classifyGap = %q, want E1 for a genuine sampling gap", class)
	}
}

// TestAggregatePathTallyDistinguishesInodes covers the path-count key: the
// same name backed by two different files across the window is two paths,
// which is exactly what a replaced library looks like.
func TestAggregatePathTallyDistinguishesInodes(t *testing.T) {
	matches := []PathMatchRecord{
		{PathResolutionRecord: PathResolutionRecord{SampleID: "s0", Resolved: "/opt/lib2/libsqlite3.so.0", Dev: "08:01", Inode: "111", Ownership: OwnershipUnowned}, TrivyMatch: TrivyMatchNotApplicable},
		{PathResolutionRecord: PathResolutionRecord{SampleID: "s1", Resolved: "/opt/lib2/libsqlite3.so.0", Dev: "08:01", Inode: "222", Ownership: OwnershipUnowned}, TrivyMatch: TrivyMatchNotApplicable},
		{PathResolutionRecord: PathResolutionRecord{SampleID: "s2", Resolved: "/opt/lib2/libsqlite3.so.0", Dev: "08:01", Inode: "222", Ownership: OwnershipUnowned}, TrivyMatch: TrivyMatchNotApplicable},
	}
	var unowned int
	for _, row := range aggregatePathTally(matches) {
		if row.Ownership == string(OwnershipUnowned) {
			unowned = row.Paths
		}
	}
	if unowned != 2 {
		t.Errorf("unowned paths = %d, want 2: one name, two distinct inodes, the third a repeat of the second", unowned)
	}
}

// statusMixTrivyReport mirrors what a real Debian scan contains: Trivy
// reports a vulnerability status per finding. curl in a real case 9 scan
// carried four fix_deferred findings and one affected one; the four came
// back with no priority at all while the product's triage only sorted
// fixed, affected and will_not_fix into sections. The product now sorts
// every status into a section except not_affected, which it drops, so the
// not_affected finding below is what keeps the unclassified path covered.
const statusMixTrivyReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-status-mix:1",
  "Metadata": {
    "OS": { "Family": "debian", "Name": "12.5", "EOSL": false },
    "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732"
  },
  "Results": [
    {
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2030-1001",
          "PkgName": "curl",
          "InstalledVersion": "7.88.1-10+deb12u12",
          "Status": "fix_deferred",
          "Severity": "LOW",
          "Title": "deferred fix, no section in the product's own triage"
        },
        {
          "VulnerabilityID": "CVE-2030-1002",
          "PkgName": "curl",
          "InstalledVersion": "7.88.1-10+deb12u12",
          "Status": "fix_deferred",
          "Severity": "MEDIUM",
          "Title": "second deferred finding on the same package"
        },
        {
          "VulnerabilityID": "CVE-2030-1003",
          "PkgName": "curl",
          "InstalledVersion": "7.88.1-10+deb12u12",
          "Status": "affected",
          "Severity": "HIGH",
          "Title": "upstream affected, no fix yet"
        },
        {
          "VulnerabilityID": "CVE-2030-1004",
          "PkgName": "git",
          "InstalledVersion": "1:2.39.5-0+deb12u2",
          "FixedVersion": "1:2.39.5-0+deb12u3",
          "Status": "fixed",
          "Severity": "CRITICAL",
          "Title": "ordinary fixed finding"
        },
        {
          "VulnerabilityID": "CVE-2030-1005",
          "PkgName": "git",
          "InstalledVersion": "1:2.39.5-0+deb12u2",
          "Status": "will_not_fix",
          "Severity": "HIGH",
          "Title": "will not be fixed"
        },
        {
          "VulnerabilityID": "CVE-2030-1006",
          "PkgName": "libssl3",
          "InstalledVersion": "3.0.16-1~deb12u1",
          "Status": "end_of_life",
          "Severity": "HIGH",
          "Title": "end of life, triaged in its own section"
        },
        {
          "VulnerabilityID": "CVE-2030-1007",
          "PkgName": "libc6",
          "InstalledVersion": "2.36-9+deb12u10",
          "Status": "not_affected",
          "Severity": "HIGH",
          "Title": "not affected, the one status the product drops"
        }
      ]
    }
  ]
}`

// TestPrioritiesCoverEveryStatus is the case 9 defect: findings whose status the
// product does not sort into a section produced an empty priority key, so
// they fell out of the per-priority tables while staying in the overall
// denominator, and the two stopped adding up. Every finding must now carry
// a named priority, and the per-priority denominators must reconcile with
// the overall one. fix_deferred and end_of_life now get real priorities;
// not_affected is the status left unclassified.
func TestPrioritiesCoverEveryStatus(t *testing.T) {
	scan, err := scanner.ParseReport([]byte(statusMixTrivyReport))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if len(scan.Findings) != 7 {
		t.Fatalf("ParseReport returned %d findings, want 7: no status may be dropped before matching", len(scan.Findings))
	}

	tr := analyze.Triage{
		Enabled: true, ActNowEPSS: defaultActNowEPSS, WatchEPSS: defaultWatchEPSS,
		Intel: analyze.IntelStatus{KEVOK: true, EPSSOK: true},
	}
	priorityByIndex := computePriorities(scan.Findings, scan.Image, scan.OSFamily, tr, time.Now())
	for i, p := range priorityByIndex {
		if p == "" {
			t.Errorf("finding %d (%s, status %q) has an empty priority", i, scan.Findings[i].VulnID, scan.Findings[i].Status)
		}
	}

	// The statuses the product does triage keep their real priority; the
	// ones it does not are named rather than blank.
	byVuln := map[string]string{}
	for i, f := range scan.Findings {
		byVuln[f.VulnID] = priorityByIndex[i]
	}
	if byVuln["CVE-2030-1007"] != priorityUnclassified {
		t.Errorf("CVE-2030-1007: priority = %q, want %q", byVuln["CVE-2030-1007"], priorityUnclassified)
	}
	for _, vuln := range []string{"CVE-2030-1001", "CVE-2030-1002", "CVE-2030-1003", "CVE-2030-1004", "CVE-2030-1005", "CVE-2030-1006"} {
		if byVuln[vuln] == priorityUnclassified || byVuln[vuln] == "" {
			t.Errorf("%s: priority = %q, want a real priority (its status has a section)", vuln, byVuln[vuln])
		}
	}

	if got := unclassifiedByStatus(scan.Findings, priorityByIndex); got["not_affected"] != 1 || len(got) != 1 {
		t.Errorf("unclassifiedByStatus = %v, want not_affected=1 only", got)
	}

	// The denominators have to reconcile: every Finding is in exactly one
	// priority bucket, so the buckets sum to the overall count.
	rec := syntheticRecord()
	wv := computeWindowValidity(rec)
	groups := groupFindings(scan.Findings)
	var packages []PackageVerdict
	for _, g := range groups {
		pv := assignVerdict(g, rec, Case{}, "observed", wv)
		applyPriorities(&pv, g, priorityByIndex)
		if _, blank := pv.Priorities[""]; blank {
			t.Errorf("%s: priorities carry an empty key: %v", pv.Package, pv.Priorities)
		}
		packages = append(packages, pv)
	}

	overall, _, byPrio, _, _, _, _ := aggregate(packages)
	if overall.FindingDenominator != 7 {
		t.Fatalf("overall denominator = %d, want 7", overall.FindingDenominator)
	}
	sum, pkgSum := 0, 0
	for prio, m := range byPrio {
		if prio == "" {
			t.Error("by_priority carries an empty-string row")
		}
		sum += m.FindingDenominator
		pkgSum += m.PkgDenominator
	}
	if sum != overall.FindingDenominator {
		t.Errorf("per-priority Finding denominators sum to %d, want %d (the overall denominator)", sum, overall.FindingDenominator)
	}
	if pkgSum != overall.PkgDenominator {
		t.Errorf("per-priority package denominators sum to %d, want %d", pkgSum, overall.PkgDenominator)
	}
	if _, ok := byPrio[priorityUnclassified]; !ok {
		t.Errorf("by_priority = %v, want an %q row", byPrio, priorityUnclassified)
	}
}

// TestApplyPrioritiesUnclassifiedRanksBelowLow checks the max-priority rule
// for a package whose findings are a mix: the package is classified by what
// the product did triage, not dragged down to unclassified by what it did
// not.
func TestApplyPrioritiesUnclassifiedRanksBelowLow(t *testing.T) {
	g := pkgGroup{
		key: pkgGroupKey{Class: scanner.ClassOS, Package: "curl", InstalledVer: "7.88.1"},
		vulns: []findingVuln{
			{VulnID: "CVE-1", OriginalIndex: 0},
			{VulnID: "CVE-2", OriginalIndex: 1},
		},
	}
	var pv PackageVerdict
	applyPriorities(&pv, g, []string{priorityUnclassified, "low"})
	if pv.MaxPriority != "low" {
		t.Errorf("MaxPriority = %q, want low", pv.MaxPriority)
	}

	var allUnclassified PackageVerdict
	applyPriorities(&allUnclassified, g, []string{priorityUnclassified, priorityUnclassified})
	if allUnclassified.MaxPriority != priorityUnclassified {
		t.Errorf("MaxPriority = %q, want %q when nothing was triaged", allUnclassified.MaxPriority, priorityUnclassified)
	}
}
