package main

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// loadSyntheticEventRun reads the hand-written end-to-end window: one
// package per mapping rule, one that is used and reachable only through an
// event, and one that is installed and never touched.
func loadSyntheticEventRun(t *testing.T) (ContainerRecord, scanner.ImageScan, *scanFileIndex, Case, *GroundTruthB, *EventLog) {
	t.Helper()
	rec, err := readContainerRecord("testdata/synthetic_events_observation.json")
	if err != nil {
		t.Fatalf("read observation: %v", err)
	}
	trivyData, err := os.ReadFile("testdata/synthetic_events_trivy.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(trivyData)
	if err != nil {
		t.Fatalf("parse scan report: %v", err)
	}
	idx, err := buildScanFileIndex(trivyData)
	if err != nil {
		t.Fatalf("index the scan report's paths: %v", err)
	}
	def, err := readCase("testdata/synthetic_events_case.json")
	if err != nil {
		t.Fatalf("read case: %v", err)
	}
	gtb, err := readGTB("testdata/synthetic_events_gtb.json")
	if err != nil {
		t.Fatalf("read ground truth: %v", err)
	}
	events, err := readEventLog("testdata/synthetic_events.jsonl")
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}
	return rec, scan, idx, def, gtb, events
}

func syntheticIntel() *IntelSnapshot {
	return &IntelSnapshot{
		KEVOK: true, EPSSOK: true, Condition: "normal",
		Enrichment: map[string]FindingIntel{
			"CVE-2021-44228": {KEV: true, EPSS: 0.97, EPSSKnown: true},
			"CVE-2024-0001":  {EPSS: 0.42, EPSSKnown: true},
			"CVE-2024-0002":  {EPSS: 0.02, EPSSKnown: true},
			"CVE-2020-14040": {EPSS: 0.15, EPSSKnown: true},
			"CVE-2024-0003":  {EPSS: 0.005, EPSSKnown: true},
			"CVE-2021-23337": {EPSS: 0.30, EPSSKnown: true},
			"CVE-2023-38325": {EPSS: 0.05, EPSSKnown: true},
		},
	}
}

func runSyntheticEventPipeline(t *testing.T) MatchResult {
	t.Helper()
	rec, scan, idx, def, gtb, events := loadSyntheticEventRun(t)
	result, err := runMatchPipeline(context.Background(), rec, scan, idx, def, gtb, events,
		syntheticIntel(), t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return result
}

func seriesByName(t *testing.T, r MatchResult, name string) SeriesMetrics {
	t.Helper()
	for _, s := range r.Series {
		if s.Series == name {
			return s
		}
	}
	t.Fatalf("no %s series in the result", name)
	return SeriesMetrics{}
}

// TestEndToEndWindowSeparatesEachLayersContribution runs the whole pipeline
// over one saved window and checks the three series against what the
// window was built to contain. Every series keeps the same population: a
// denominator that shrinks when the observation fails would turn a failure
// to look into a better-looking result.
func TestEndToEndWindowSeparatesEachLayersContribution(t *testing.T) {
	r := runSyntheticEventPipeline(t)

	s0 := seriesByName(t, r, seriesS0)
	s1 := seriesByName(t, r, seriesS1)
	s2 := seriesByName(t, r, seriesS2)
	for _, s := range []SeriesMetrics{s0, s1, s2} {
		if s.Overall.FindingDenominator != 8 {
			t.Errorf("%s denominator = %d, want every finding in all three series", s.Series, s.Overall.FindingDenominator)
		}
	}
	if s0.Overall.FindingConfirmed != 1 {
		t.Errorf("S0 confirmed = %d, want only what a package database resolves", s0.Overall.FindingConfirmed)
	}
	if s1.Overall.FindingConfirmed <= s0.Overall.FindingConfirmed {
		t.Errorf("the read-only mapping added nothing: S0=%d S1=%d", s0.Overall.FindingConfirmed, s1.Overall.FindingConfirmed)
	}
	if s2.Overall.FindingConfirmed <= s1.Overall.FindingConfirmed {
		t.Errorf("the event evidence added nothing: S1=%d S2=%d", s1.Overall.FindingConfirmed, s2.Overall.FindingConfirmed)
	}

	if len(r.SeriesDeltas) != 2 {
		t.Fatalf("got %d increments, want one per layer", len(r.SeriesDeltas))
	}
	for _, d := range r.SeriesDeltas {
		if !d.Available {
			t.Errorf("increment %s->%s reported unavailable: %s", d.From, d.To, d.Reason)
		}
	}

	// Every rate is reported with the number of files the positives rest
	// on: a hundred findings confirmed by one binary is a different result
	// from a hundred confirmed by a hundred files.
	if s2.ObservedBinaries != 1 {
		t.Errorf("observed binaries = %d, want 1", s2.ObservedBinaries)
	}
	if s2.ObservedFiles < 3 {
		t.Errorf("observed files = %d, want the archive, the extension and the module-tree file", s2.ObservedFiles)
	}
	for _, eco := range []string{ecoOS, ecoGoBinary, ecoJar, ecoNodePkg, ecoPythonPkg} {
		if _, ok := s2.ByEco[eco]; !ok {
			t.Errorf("no per-ecosystem row for %s; a combined rate says nothing on its own", eco)
		}
	}
}

// TestEndToEndPackagesReachedByTheExpectedRoute checks that each package
// was confirmed through the route it was placed in the window to exercise,
// and that the one which is read and closed is reached only by an event.
func TestEndToEndPackagesReachedByTheExpectedRoute(t *testing.T) {
	r := runSyntheticEventPipeline(t)
	byName := map[string]PackageVerdict{}
	for _, p := range r.Packages {
		byName[p.Package] = p
	}

	cases := []struct {
		pkg        string
		wantSource string
		reachedByA bool
	}{
		{"libssl3", sourceSampling, true},
		{"golang.org/x/text", sourceGoBinary, true},
		{"org.apache.logging.log4j:log4j-core", sourceJarFD, true},
		{"cryptography", sourcePythonExt, true},
		{"lodash", sourceEventOpen, false},
		// An operating-system package the scan report carries no path for,
		// run briefly between two samples. It is reached only by matching
		// an execution record against the container's own package path
		// index as it was saved.
		{"curl", sourceEventExec, false},
	}
	for _, tt := range cases {
		p, ok := byName[tt.pkg]
		if !ok {
			t.Fatalf("no result for %s", tt.pkg)
		}
		if p.S2Verdict != VerdictConfirmed {
			t.Errorf("%s was not confirmed even with every layer: %q/%q", tt.pkg, p.S2Verdict, p.S2Factor)
			continue
		}
		found := false
		for _, s := range p.S2Sources {
			if s == tt.wantSource {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was confirmed by %v, want the %s route", tt.pkg, p.S2Sources, tt.wantSource)
		}
		if got := p.S1Verdict == VerdictConfirmed; got != tt.reachedByA {
			t.Errorf("%s reachable without events = %v, want %v", tt.pkg, got, tt.reachedByA)
		}
	}

	if got := byName["gzip"]; got.S2Verdict == VerdictConfirmed {
		t.Error("a package that is installed and never touched was confirmed")
	}
}

// TestEndToEndCaptureRatesAndLosses checks the per-occurrence rates and the
// loss accounting against a window built to contain one of each case.
func TestEndToEndCaptureRatesAndLosses(t *testing.T) {
	r := runSyntheticEventPipeline(t)

	if r.EventState != eventStateDegraded {
		t.Errorf("event_state = %q, want degraded: this window's log records losses", r.EventState)
	}
	d := r.EventDrops
	if d.LostEvents != 12 || d.LostNotifications != 2 {
		t.Errorf("losses = %d event(s) over %d notification(s), want 12/2 — the two are different numbers", d.LostEvents, d.LostNotifications)
	}

	o := r.Occurrence
	if !o.Available {
		t.Fatal("capture rates reported unavailable despite an independent log")
	}
	if o.Exec.Eligible != 2 || o.Exec.OneToOne != 2 {
		t.Errorf("executions: eligible=%d paired=%d, want 2/2", o.Exec.Eligible, o.Exec.OneToOne)
	}
	// Two loads are eligible: one read files and was seen, one read files
	// and was not. The third was satisfied from memory and the fourth
	// failed, so neither belongs in the denominator.
	if o.Load.Eligible != 2 || o.Load.WithEvidence != 1 {
		t.Errorf("loads: eligible=%d with evidence=%d, want 2/1", o.Load.Eligible, o.Load.WithEvidence)
	}
	if o.Excluded.CacheHit != 1 {
		t.Errorf("cache-hit exclusions = %d, want 1", o.Excluded.CacheHit)
	}
	if o.Excluded.Failed != 1 {
		t.Errorf("failed-operation exclusions = %d, want 1", o.Excluded.Failed)
	}
	if !o.RealOpen.NA {
		t.Error("the system-call rate was reported although nothing recorded the calls independently")
	}
	if o.MatchRule != "container_generation_and_thread" {
		t.Errorf("pairing rule = %q, want the rule this case's log enables", o.MatchRule)
	}

	// Both attribution directions are reported, and an event belonging to
	// another container never counts here.
	if r.Attribution.CorrectAttributionRate < 0 {
		t.Error("the correct-attribution rate is unavailable; it must accompany the wrong-attribution one")
	}
	if r.EventsAttributed != 7 {
		t.Errorf("events credited to this container = %d, want every event carrying its identifier", r.EventsAttributed)
	}
}

// TestEndToEndWritesEveryTable renders the result and checks that the
// tables a reader needs are all there and carry the run key's full set of
// dimensions — including the ordering condition and the collection
// configuration, without which two different conditions would be added up
// together.
func TestEndToEndWritesEveryTable(t *testing.T) {
	r := runSyntheticEventPipeline(t)
	dir := t.TempDir()
	if err := writeMatchCSVs(dir, r); err != nil {
		t.Fatalf("write tables: %v", err)
	}
	for _, name := range []string{
		"case_summary.csv", "classification.csv", "series.csv", "source_inputs.csv",
		"mapping.csv", "occurrence_capture.csv", "event_drops.csv", "attribution.csv",
	} {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		rows, err := csv.NewReader(f).ReadAll()
		f.Close()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(rows) < 2 {
			t.Errorf("%s has a header and no rows", name)
			continue
		}
		header := strings.Join(rows[0], ",")
		for _, col := range []string{"sync", "config_id"} {
			if !strings.Contains(header, col) {
				t.Errorf("%s does not carry the %s dimension, so two different conditions would be combined", name, col)
			}
		}
	}

	series := filepath.Join(dir, "series.csv")
	data, err := os.ReadFile(series)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"S0", "S1", "S2", "S0->S1", "S1->S2", "ecosystem:", "grain:"} {
		if !strings.Contains(text, want) {
			t.Errorf("the series table has no %q rows", want)
		}
	}
}

// TestEventLogIsNotAcceptedAsGroundTruth checks that an event log fed to
// the ground-truth input is refused. The two formats look alike, and
// ground truth built from the observation it is meant to judge makes every
// capture rate and every false-positive count meaningless — so the mistake
// is made impossible rather than merely unlikely.
func TestEventLogIsNotAcceptedAsGroundTruth(t *testing.T) {
	_, err := readGTB("testdata/synthetic_events.jsonl")
	if err == nil {
		t.Fatal("an event log was accepted as ground truth")
	}
	if !strings.Contains(err.Error(), "event log") {
		t.Errorf("error = %v, want it to say the file is an event log", err)
	}
}

// TestGroundTruthIsNotAcceptedAsAnEventLog checks the refusal in the other
// direction, so neither input can stand in for the other.
func TestGroundTruthIsNotAcceptedAsAnEventLog(t *testing.T) {
	if _, err := readEventLog("testdata/synthetic_events_gtb.json"); err == nil {
		t.Fatal("a ground-truth record was read as an event log")
	}
	if _, err := readEventLog("testdata/synthetic_gtb.json"); err == nil {
		t.Fatal("a ground-truth record was read as an event log")
	}
}

// TestMatchReadsNoLiveState checks the condition that makes a result
// reproducible: everything the match needs is in the saved inputs, so the
// same inputs give the same result after the container is gone. Running it
// twice over the same files must agree on every number.
func TestMatchReadsNoLiveState(t *testing.T) {
	first := runSyntheticEventPipeline(t)
	second := runSyntheticEventPipeline(t)

	if len(first.Packages) != len(second.Packages) {
		t.Fatalf("package counts differ: %d vs %d", len(first.Packages), len(second.Packages))
	}
	for i := range first.Packages {
		a, b := first.Packages[i], second.Packages[i]
		if a.Package != b.Package || a.Verdict != b.Verdict || a.S1Verdict != b.S1Verdict || a.S2Verdict != b.S2Verdict {
			t.Errorf("%s differs between runs: %v/%v/%v vs %v/%v/%v",
				a.Package, a.Verdict, a.S1Verdict, a.S2Verdict, b.Verdict, b.S1Verdict, b.S2Verdict)
		}
	}
	if first.Occurrence.Exec.OneToOne != second.Occurrence.Exec.OneToOne ||
		first.Occurrence.Load.WithEvidence != second.Occurrence.Load.WithEvidence {
		t.Error("the capture rates differ between two runs over the same saved inputs")
	}
}

// TestImageIdentityMismatchIsRefused checks that a window observed running
// one image is not matched against a scan of another. Without it, every
// path comparison would be against a filesystem the container never had.
func TestImageIdentityMismatchIsRefused(t *testing.T) {
	rec, scan, idx, def, gtb, events := loadSyntheticEventRun(t)
	rec.Subject.Docker.ImageID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	_, err := runMatchPipeline(context.Background(), rec, scan, idx, def, gtb, events,
		syntheticIntel(), t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err == nil {
		t.Fatal("a window was matched against a scan of a different image")
	}
	if !strings.Contains(err.Error(), "image identity mismatch") {
		t.Errorf("error = %v, want it to name the identity mismatch", err)
	}
}
