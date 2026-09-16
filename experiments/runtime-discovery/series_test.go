package main

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var seriesWindowStart = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
var seriesWindowEnd = seriesWindowStart.Add(5 * time.Minute)

// seriesRecord is one window's observation: two samples, both usable, with
// the binary executed, an archive held open, a compiled extension mapped,
// and one operating-system package resolved the way the first stage
// resolves them.
func seriesRecord() ContainerRecord {
	gen := ProcessGeneration{PID: 1, Starttime: "555"}
	return ContainerRecord{
		Subject: Subject{Runtime: "docker", Docker: DockerSubject{ContainerID: "c1", ImageID: "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732"}},
		RunKey:  RunKey{CaseVariant: "SERIES", Permission: "root", Interval: 150, Window: 300, Replicate: 1, Sync: "startup", ConfigID: "bpftrace-test"},
		Window: Window{
			ID: "w1", ScheduledStart: seriesWindowStart, ScheduledEnd: seriesWindowEnd,
			Samples: []SampleTiming{
				{SampleID: "s0", ActualStart: seriesWindowStart},
				{SampleID: "s1", ActualStart: seriesWindowStart.Add(150 * time.Second)},
			},
		},
		CollectionResults: []CollectionResult{
			{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "ok", Valid: true, Views: []SampleDBView{{MountViewID: "mnt:[1]", DBGeneration: "gen1", PkgdbRead: "ok"}}},
			{SampleID: "s1", ProcObserve: "ok", PkgdbRead: "ok", Valid: true, Views: []SampleDBView{{MountViewID: "mnt:[1]", DBGeneration: "gen1", PkgdbRead: "ok"}}},
		},
		Processes: []ProcessRecord{{
			SampleID: "s0", Generation: gen, Exe: "/server",
			Maps:            []MapEntry{{Path: "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so", Dev: "08:01", Inode: "10", Perms: "r-xp"}},
			FileDescriptors: []FDRecord{{FD: 5, Path: "/app/log4j-core-2.14.1.jar", Resolved: "/app/log4j-core-2.14.1.jar"}},
		}},
		PathResolution: []PathResolutionRecord{
			{SampleID: "s0", Generation: gen, Source: "exe", Path: "/server", Resolved: "/server", Ownership: OwnershipUnowned, MountViewID: "mnt:[1]", DBGeneration: "gen1"},
			{SampleID: "s0", Generation: gen, Source: "maps", Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Resolved: "/usr/lib/x86_64-linux-gnu/libssl.so.3",
				Ownership: OwnershipOwned, DBKind: dpkgKind, Package: "libssl3", DBVersion: "3.0.13-1", MountViewID: "mnt:[1]", DBGeneration: "gen1"},
			{SampleID: "s0", Generation: gen, Source: "maps", Path: "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so",
				Resolved: "/usr/local/lib/python3.12/site-packages/cryptography/hazmat/bindings/_rust.abi3.so", Ownership: OwnershipUnowned, MountViewID: "mnt:[1]", DBGeneration: "gen1"},
			{SampleID: "s0", Generation: gen, Source: "fd", Path: "/app/log4j-core-2.14.1.jar", Resolved: "/app/log4j-core-2.14.1.jar",
				Ownership: OwnershipUnowned, MountViewID: "mnt:[1]", DBGeneration: "gen1"},
		},
		PackageLedger: []LedgerEntry{
			{MountViewID: "mnt:[1]", DBGeneration: "gen1", Name: "libssl3", Version: "3.0.13-1", FileListPresent: true, FileCount: 3},
		},
		PkgDBs:          []PkgDBGenerationInfo{{MountViewID: "mnt:[1]", DBGeneration: "gen1", DBKind: dpkgKind, FileListComplete: true}},
		AuxiliaryInputs: mappingAux(),
	}
}

// seriesEventLog is an event log for the same window: the module-tree file
// is only ever read and closed, so nothing but an event can reach it.
func seriesEventLog(drops EventDropCounts) *EventLog {
	at := seriesWindowStart.Add(time.Minute)
	return &EventLog{
		Header: EventHeader{Record: eventsHeaderKind, ConfigID: "bpftrace-test", Method: "bpftrace", Sync: "startup", Started: true, Attached: true},
		Events: []EventRecord{
			{Record: eventRecordKind, Event: "exec", Timestamp: at, PID: 4242, TID: 4242, Starttime: "555",
				RawPath: "/server", Path: "/server", Resolved: true, OK: true, ContainerID: "c1", Attribution: "container"},
			{Record: eventRecordKind, Event: "open", Timestamp: at.Add(time.Second), PID: 4242, TID: 4242, Starttime: "555",
				RawPath: "/app/node_modules/lodash/lodash.js", Path: "/app/node_modules/lodash/lodash.js",
				Resolved: true, OK: true, ContainerID: "c1", Attribution: "container"},
			{Record: eventRecordKind, Event: "open", Timestamp: at.Add(2 * time.Second), PID: 4242, TID: 4242, Starttime: "555",
				RawPath: "/some/other/container/file.js", Path: "/some/other/container/file.js",
				Resolved: true, OK: true, ContainerID: "other", Attribution: "container"},
		},
		Trailer: EventsTrailer{Record: eventsTrailerKind, Drops: drops},
	}
}

type seriesOutcome struct {
	verdict Verdict
	factor  string
}

func runSeries(t *testing.T, rec ContainerRecord, events *EventLog) (map[string]map[string]seriesOutcome, *evidenceSet) {
	t.Helper()
	scan, err := scanner.ParseReport([]byte(mappingReport))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	idx := mappingIndex(t)
	wv := computeWindowValidity(&rec)
	obsState := observationState(&rec, wv)
	set := newResolverSet(idx, auxForWindow(&rec, wv))
	groups := groupFindings(scan.Findings)
	ev := buildEvidenceSet(&rec, wv, groups, set, idx, events, true)

	out := map[string]map[string]seriesOutcome{seriesS0: {}, seriesS1: {}, seriesS2: {}}
	for _, g := range groups {
		for _, series := range []string{seriesS0, seriesS1, seriesS2} {
			sv := decideSeries(series, g, &rec, Case{CaseID: "SERIES"}, obsState, wv, ev, set, idx)
			out[series][g.key.Package] = seriesOutcome{sv.Verdict, sv.Factor}
		}
	}
	return out, ev
}

// TestSeriesSeparatesWhatEachLayerRecovers checks the three evaluation
// series against one window.
//
// The first stage's rules confirm only what a package database resolves,
// and report every language package as unreachable by construction. The
// read-only mapping reaches the compiled binary, the archive held open and
// the compiled extension, without any event collection. The event
// evidence reaches the module-tree file, which is read and closed and so
// appears in neither the descriptors nor the mappings.
func TestSeriesSeparatesWhatEachLayerRecovers(t *testing.T) {
	out, _ := runSeries(t, seriesRecord(), seriesEventLog(EventDropCounts{}))

	// The operating-system package is confirmed in every series: adding
	// evidence sources never takes a positive away.
	for _, series := range []string{seriesS0, seriesS1, seriesS2} {
		if got := out[series]["libssl3"].verdict; got != VerdictConfirmed {
			t.Errorf("%s libssl3 = %q, want confirmed", series, got)
		}
	}

	// Every language package is unreachable under the first stage's rules
	// alone, for the stated reason.
	for _, pkg := range []string{"golang.org/x/text", "org.apache.logging.log4j:log4j-core", "lodash", "cryptography"} {
		got := out[seriesS0][pkg]
		if got.verdict != VerdictUnobserved || got.factor != factorLangPkg {
			t.Errorf("S0 %s = %q/%q, want unobserved/%s", pkg, got.verdict, got.factor, factorLangPkg)
		}
	}

	// The read-only mapping recovers three of them, and not the fourth.
	for _, pkg := range []string{"golang.org/x/text", "stdlib", "org.apache.logging.log4j:log4j-core", "cryptography"} {
		if got := out[seriesS1][pkg].verdict; got != VerdictConfirmed {
			t.Errorf("S1 %s = %q, want confirmed by the read-only mapping", pkg, got)
		}
	}
	if got := out[seriesS1]["lodash"]; got.verdict == VerdictConfirmed {
		t.Error("S1 confirmed the module-tree package, which is read and closed and appears in neither the descriptors nor the mappings")
	}

	// The event evidence recovers the fourth.
	if got := out[seriesS2]["lodash"].verdict; got != VerdictConfirmed {
		t.Errorf("S2 lodash = %q, want confirmed by the event evidence", got)
	}
}

// TestEventsAttributedElsewhereAreNotClaimed checks that an event credited
// to another container never confirms anything here. Without this, running
// two containers side by side would make each confirm the other's work.
func TestEventsAttributedElsewhereAreNotClaimed(t *testing.T) {
	events := seriesEventLog(EventDropCounts{})
	// Re-point the module-tree read at another container.
	events.Events[1].ContainerID = "someone-else"
	out, _ := runSeries(t, seriesRecord(), events)
	if got := out[seriesS2]["lodash"].verdict; got == VerdictConfirmed {
		t.Error("an event credited to another container confirmed a package here")
	}
	if got := out[seriesS2]["lodash"].factor; got != factorEventNoObservation {
		t.Errorf("factor = %q, want %s: the collection worked and saw nothing for this package", got, factorEventNoObservation)
	}
}

// TestOneSourcesMissingInputDoesNotDiscardAnother checks the revised first
// rule. A window whose package database could not be read has no sampling
// evidence at all, but the compiled-binary mapping does not need a package
// database — and discarding its positives because a different source's
// input failed would report the wrong answer to the question the series
// exists to answer.
func TestOneSourcesMissingInputDoesNotDiscardAnother(t *testing.T) {
	rec := seriesRecord()
	for i := range rec.CollectionResults {
		rec.CollectionResults[i].PkgdbRead = "error"
		rec.CollectionResults[i].Valid = false
		rec.CollectionResults[i].Views = []SampleDBView{{MountViewID: "mnt:[1]", PkgdbRead: "error"}}
	}
	rec.Failures = append(rec.Failures, Failure{Step: factorRootfsDenied, Message: "package database unreadable"})

	scan, err := scanner.ParseReport([]byte(mappingReport))
	if err != nil {
		t.Fatal(err)
	}
	idx := mappingIndex(t)
	wv := computeWindowValidity(&rec)
	obsState := observationState(&rec, wv)
	if obsState != "observation_failed" {
		t.Fatalf("observation_state = %q, want observation_failed for this record", obsState)
	}
	set := newResolverSet(idx, rec.AuxiliaryInputs)
	groups := groupFindings(scan.Findings)
	ev := buildEvidenceSet(&rec, wv, groups, set, idx, seriesEventLog(EventDropCounts{}), true)

	for _, g := range groups {
		s0 := decideSeries(seriesS0, g, &rec, Case{}, obsState, wv, ev, set, idx)
		if s0.Verdict != VerdictNotDetermined {
			t.Errorf("S0 %s = %q, want not_determined: the first stage's rule is unchanged", g.key.Package, s0.Verdict)
		}
		s2 := decideSeries(seriesS2, g, &rec, Case{}, obsState, wv, ev, set, idx)
		if g.key.Package == "golang.org/x/text" && s2.Verdict != VerdictConfirmed {
			t.Errorf("S2 %s = %q, want confirmed: the compiled-binary mapping needs no package database", g.key.Package, s2.Verdict)
		}
	}
}

// TestEveryInputMissingStaysUndetermined checks the other half of the
// revised first rule: when no source has what it needs, the window is
// undetermined and is not pushed towards "nothing was used".
func TestEveryInputMissingStaysUndetermined(t *testing.T) {
	rec := seriesRecord()
	rec.CollectionResults = nil
	rec.PathResolution = nil
	rec.Processes = nil
	rec.AuxiliaryInputs = nil

	scan, _ := scanner.ParseReport([]byte(mappingReport))
	idx := mappingIndex(t)
	wv := computeWindowValidity(&rec)
	obsState := observationState(&rec, wv)
	set := newResolverSet(idx, nil)
	groups := groupFindings(scan.Findings)
	ev := buildEvidenceSet(&rec, wv, groups, set, idx, nil, false)

	for _, g := range groups {
		for _, series := range []string{seriesS0, seriesS1, seriesS2} {
			sv := decideSeries(series, g, &rec, Case{}, obsState, wv, ev, set, idx)
			if sv.Verdict != VerdictNotDetermined {
				t.Errorf("%s %s = %q, want not_determined", series, g.key.Package, sv.Verdict)
			}
		}
	}
}

// TestLanguagePackageShortfallSeparatesItsCauses checks that the three
// reasons a language package can go unconfirmed stay apart: the report
// offers no path at all, the layout information was never saved, and
// everything was in place but nothing used it.
func TestLanguagePackageShortfallSeparatesItsCauses(t *testing.T) {
	rec := seriesRecord()
	rec.PathResolution = rec.PathResolution[:1] // keep only the binary's own path
	rec.Processes[0].FileDescriptors = nil
	rec.AuxiliaryInputs = nil // the layout information was never saved

	scan, _ := scanner.ParseReport([]byte(mappingReport))
	idx := mappingIndex(t)
	wv := computeWindowValidity(&rec)
	set := newResolverSet(idx, nil)
	groups := groupFindings(scan.Findings)
	ev := buildEvidenceSet(&rec, wv, groups, set, idx, nil, true)

	byPkg := map[string]seriesVerdict{}
	for _, g := range groups {
		byPkg[g.key.Package] = decideSeries(seriesS1, g, &rec, Case{}, "observed", wv, ev, set, idx)
	}
	if got := byPkg["cryptography"]; got.Verdict != VerdictUnresolved || got.Factor != factorMappingInputMissing {
		t.Errorf("cryptography = %q/%q, want unresolved/%s: no installed-file manifest was saved", got.Verdict, got.Factor, factorMappingInputMissing)
	}
	if got := byPkg["lodash"]; got.Verdict != VerdictUnresolved || got.Factor != factorMappingInputMissing {
		t.Errorf("lodash = %q/%q, want unresolved/%s: no module-tree layout was saved", got.Verdict, got.Factor, factorMappingInputMissing)
	}
	// An archive needs nothing beyond the path the report gives, so its
	// shortfall is "nothing read it", not "the inputs are missing".
	if got := byPkg["org.apache.logging.log4j:log4j-core"]; got.Verdict != VerdictUnobserved || got.Factor != factorNoObserved {
		t.Errorf("log4j-core = %q/%q, want unobserved/%s", got.Verdict, got.Factor, factorNoObserved)
	}
}

// TestEventCollectionStateIsItsOwnDimension checks that losses in the
// event collection degrade the collection's own state without discarding
// the positives it did produce, and that a window which collected no
// events keeps everything the earlier layers found.
func TestEventCollectionStateIsItsOwnDimension(t *testing.T) {
	degraded := seriesEventLog(EventDropCounts{LostEvents: 12, LostNotifications: 2})
	out, ev := runSeries(t, seriesRecord(), degraded)
	if ev.eventState != eventStateDegraded {
		t.Errorf("event_state = %q, want degraded", ev.eventState)
	}
	if got := out[seriesS2]["lodash"].verdict; got != VerdictConfirmed {
		t.Error("a positive observed before the losses was discarded because of them")
	}

	none, evNone := runSeries(t, seriesRecord(), nil)
	if evNone.eventState != eventStateNotAttempted {
		t.Errorf("event_state = %q, want not_attempted", evNone.eventState)
	}
	if got := none[seriesS2]["cryptography"].verdict; got != VerdictConfirmed {
		t.Error("a window that collected no events lost what the read-only mapping had already confirmed")
	}
}

// TestEventIncrementIsUnavailableRatherThanZero checks that a window which
// never collected events reports the event layer's increment as
// unavailable. Reporting zero would say the events were collected and
// added nothing, when what happened is that the chance was never had.
func TestEventIncrementIsUnavailableRatherThanZero(t *testing.T) {
	packages := []PackageVerdict{
		{Package: "a", FindingCount: 3, Verdict: VerdictUnobserved, S1Verdict: VerdictConfirmed, S2Verdict: VerdictConfirmed},
	}
	deltas := computeSeriesDeltas(packages, eventStateNotAttempted)
	if len(deltas) != 2 {
		t.Fatalf("got %d increments, want one per layer", len(deltas))
	}
	if !deltas[0].Available || deltas[0].Findings != 3 {
		t.Errorf("read-only mapping increment = %+v, want 3 findings", deltas[0])
	}
	if deltas[1].Available {
		t.Error("the event increment was reported as a number for a window that collected no events")
	}
	if deltas[1].Reason == "" {
		t.Error("no reason was given for the unavailable increment")
	}

	measured := computeSeriesDeltas(packages, eventStateObserved)
	if !measured[1].Available || measured[1].Findings != 0 {
		t.Errorf("with events collected, the increment should be a measured zero: %+v", measured[1])
	}
}

// TestEvidenceGranularityIsRecorded checks that a positive resting on a
// compiled binary is marked as covering the whole binary. Every module
// built into it is reported, and none of them is shown to have run, so a
// description of the evidence has to keep the difference.
func TestEvidenceGranularityIsRecorded(t *testing.T) {
	rec := seriesRecord()
	scan, _ := scanner.ParseReport([]byte(mappingReport))
	idx := mappingIndex(t)
	wv := computeWindowValidity(&rec)
	set := newResolverSet(idx, rec.AuxiliaryInputs)
	groups := groupFindings(scan.Findings)
	ev := buildEvidenceSet(&rec, wv, groups, set, idx, seriesEventLog(EventDropCounts{}), true)

	for _, g := range groups {
		sv := decideSeries(seriesS2, g, &rec, Case{}, "observed", wv, ev, set, idx)
		switch g.key.Package {
		case "golang.org/x/text", "stdlib":
			if sv.Grain != grainBinary {
				t.Errorf("%s granularity = %q, want the whole-binary one", g.key.Package, sv.Grain)
			}
			if len(sv.Notes) == 0 {
				t.Errorf("%s carries no qualification about what the evidence covers", g.key.Package)
			}
		case "org.apache.logging.log4j:log4j-core", "cryptography", "lodash":
			if sv.Verdict == VerdictConfirmed && sv.Grain != grainFile {
				t.Errorf("%s granularity = %q, want the per-file one", g.key.Package, sv.Grain)
			}
		}
	}
}

// TestCompiledBinaryRecoversWithoutADatabaseOrEvents is the case the
// per-source input test exists for.
//
// The package database could not be read, so the sampling source has
// nothing; no events were collected, so that source has nothing either.
// The compiled binary's own path needs neither: the scan report names the
// binary and the process's executable link names the same file. If a
// window like this reported nothing, the measurement would say the added
// mapping recovers less than it does, for a reason that has nothing to do
// with the mapping.
func TestCompiledBinaryRecoversWithoutADatabaseOrEvents(t *testing.T) {
	rec := seriesRecord()
	for i := range rec.CollectionResults {
		rec.CollectionResults[i].PkgdbRead = "error"
		rec.CollectionResults[i].Valid = false
		rec.CollectionResults[i].Views = []SampleDBView{{MountViewID: "mnt:[1]", PkgdbRead: "error"}}
	}
	rec.PkgDBs = nil
	rec.PackageLedger = nil
	rec.Failures = append(rec.Failures, Failure{Step: factorRootfsDenied, Message: "package database unreadable"})

	out, ev := runSeries(t, rec, nil) // no events at all

	if ev.eventState != eventStateNotAttempted {
		t.Fatalf("event_state = %q, want not_attempted for this window", ev.eventState)
	}
	if st := ev.inputStates[sourceSampling]; st == nil || st.State == inputOK {
		t.Fatal("the sampling source was reported as having its inputs; this window's database could not be read")
	}
	if st := ev.inputStates[sourceGoBinary]; st == nil || st.State != inputOK {
		t.Fatalf("the compiled-binary source was reported as %v; it needs no package database", st)
	}

	if got := out[seriesS0]["golang.org/x/text"].verdict; got != VerdictNotDetermined {
		t.Errorf("S0 = %q, want not_determined: the first stage's own rule is unchanged", got)
	}
	for _, pkg := range []string{"golang.org/x/text", "stdlib"} {
		if got := out[seriesS1][pkg].verdict; got != VerdictConfirmed {
			t.Errorf("S1 %s = %q, want confirmed by the binary's own path alone", pkg, got)
		}
		if got := out[seriesS2][pkg].verdict; got != VerdictConfirmed {
			t.Errorf("S2 %s = %q, want the positive kept once events are added", pkg, got)
		}
	}
}

// TestASeriesIsNotCarriedByASourceItDoesNotUse checks the other half of
// the rule: an event collection that worked says nothing about a series
// that does not use events. A window where only the events had their
// inputs must still be undetermined under the read-only series, or that
// series would report a judgement no source it admits could support.
func TestASeriesIsNotCarriedByASourceItDoesNotUse(t *testing.T) {
	rec := seriesRecord()
	// Nothing was read from any process, so every source that rests on a
	// process read is without its inputs. The saved layout is kept, so the
	// mapping itself is possible and the only thing missing is the
	// observation each read-only source needs.
	rec.CollectionResults = nil
	rec.PathResolution = nil
	rec.Processes = nil

	out, ev := runSeries(t, rec, seriesEventLog(EventDropCounts{}))
	for _, source := range []string{sourceSampling, sourceGoBinary, sourceJarFD, sourceNodeFile, sourcePythonExt, sourceOSPathIndex} {
		if st := ev.inputStates[source]; st != nil && st.State == inputOK {
			t.Errorf("%s was reported as having its inputs; no process read was recorded", source)
		}
	}
	if st := ev.inputStates[sourceEventOpen]; st == nil || st.State != inputOK {
		t.Fatalf("the event source was reported as %v; this window collected events", st)
	}
	if got := out[seriesS1]["lodash"].verdict; got != VerdictNotDetermined {
		t.Errorf("S1 lodash = %q, want not_determined: no source this series admits had its inputs", got)
	}
	if got := out[seriesS2]["lodash"].verdict; got != VerdictConfirmed {
		t.Errorf("S2 lodash = %q, want confirmed: the source this series adds did have its inputs", got)
	}
}

// TestOpenDescriptorsAreNotFirstStageEvidence checks that a file seen only
// in a process's descriptor table does not confirm anything under the
// first stage's rule.
//
// Recording open descriptors was a later addition. Letting them into that
// rule would move the baseline the later series are measured against: a
// file that only ever appeared in a descriptor table would start counting
// as a first-stage confirmation, and the increment credited to the added
// mapping would shrink by exactly that much.
func TestOpenDescriptorsAreNotFirstStageEvidence(t *testing.T) {
	rec := seriesRecord()
	gen := ProcessGeneration{PID: 1, Starttime: "555"}
	// An operating-system package's file, seen only as an open descriptor.
	rec.PathResolution = append(rec.PathResolution, PathResolutionRecord{
		SampleID: "s0", Generation: gen, Source: "fd",
		Path: "/usr/bin/gzip", Resolved: "/usr/bin/gzip",
		Ownership: OwnershipOwned, DBKind: dpkgKind, Package: "gzip", DBVersion: "1.12-1",
		MountViewID: "mnt:[1]", DBGeneration: "gen1",
	})
	rec.PackageLedger = append(rec.PackageLedger, LedgerEntry{
		MountViewID: "mnt:[1]", DBGeneration: "gen1", Name: "gzip", Version: "1.12-1",
		FileListPresent: true, FileCount: 4,
	})

	scan, err := scanner.ParseReport([]byte(mappingReport))
	if err != nil {
		t.Fatal(err)
	}
	scan.Findings = append(scan.Findings, scanner.Finding{
		Class: scanner.ClassOS, Package: "gzip", InstalledVer: "1.12-1",
		VulnID: "CVE-2030-2000", Severity: scanner.SeverityHigh, Status: scanner.StatusFixed,
	})
	wv := computeWindowValidity(&rec)
	confirmedSamples, _, _, _ := searchOwned(&rec, wv.ValidSampleIDs,
		pkgGroupKey{Class: scanner.ClassOS, Package: "gzip", InstalledVer: "1.12-1"})
	if len(confirmedSamples) != 0 {
		t.Error("a file seen only in a descriptor table confirmed a package under the first stage's rule")
	}

	// The same record, seen as a memory mapping, does confirm it: the
	// exclusion is about which read produced the path, not about the path.
	rec.PathResolution[len(rec.PathResolution)-1].Source = "maps"
	confirmedSamples, _, _, _ = searchOwned(&rec, wv.ValidSampleIDs,
		pkgGroupKey{Class: scanner.ClassOS, Package: "gzip", InstalledVer: "1.12-1"})
	if len(confirmedSamples) == 0 {
		t.Error("a mapped file did not confirm its package under the first stage's rule")
	}

	// A record written before the three reads were told apart carries no
	// source, and is read as what such a record actually held.
	rec.PathResolution[len(rec.PathResolution)-1].Source = ""
	confirmedSamples, _, _, _ = searchOwned(&rec, wv.ValidSampleIDs,
		pkgGroupKey{Class: scanner.ClassOS, Package: "gzip", InstalledVer: "1.12-1"})
	if len(confirmedSamples) == 0 {
		t.Error("a record predating the source field stopped confirming its package")
	}
}
