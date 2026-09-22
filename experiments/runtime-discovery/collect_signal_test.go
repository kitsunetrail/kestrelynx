package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// TestSIGTERMFlushesThePartialRecordInsteadOfLosingIt is the direct proof
// that a stop-condition monitor sending this process SIGTERM (the same
// signal a watcher sends when a run needs to stop early - too much CPU,
// too much lost data, too little disk) no longer discards every sample
// collect already took. Before the signal handler this file's
// collect_signal_test.go's fix added, an unhandled SIGTERM terminated the
// process immediately: nothing was written, because collect only wrote its
// records once, at the very end of a run that reached its own scheduled
// end.
//
// This runs runCollect itself - the same function main() calls for the
// collect subcommand - against a fake Docker Engine API, with a window far
// longer than the signal will let it run, and sends SIGTERM to this test
// process (the same process runCollect executes in; there is no
// subprocess here to signal) partway through. runCollect must return
// promptly with no error, and the record it wrote must show fewer samples
// than the window called for and carry a collector_stopped_early Failure.
func TestSIGTERMFlushesThePartialRecordInsteadOfLosingIt(t *testing.T) {
	api, _, sockPath := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "steady-id", Names: []string{"/steady"}, Image: "app:1"}}
	api.inspectFor["steady-id"] = mustSetStartedAt(dockerInspect{Id: "steady-id", Image: "sha256:img"}, "2026-09-22T00:00:00Z")
	api.topFor["steady-id"] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"999999999", "0", "root"}}}

	outDir := t.TempDir()
	done := make(chan error, 1)
	go func() {
		done <- runCollect([]string{
			"-socket", sockPath,
			"-containers", "steady",
			"-case-variant", "sigtest",
			"-permission", "root",
			"-sync", "attach_running",
			"-interval", "1",
			"-window", "30", // 30 planned samples at 1s apart - far more than the signal will allow
			"-out-dir", outDir,
			"-aux-inputs=false",
		})
	}()

	// Give it time to take a couple of samples, then ask it to stop the
	// way a watcher would: SIGTERM to this same process, since runCollect
	// is running in a goroutine of it, not a child process.
	time.Sleep(2500 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to self: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runCollect returned an error after SIGTERM: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runCollect did not return within 15s of SIGTERM; the signal handler did not stop the sampling loop")
	}

	files, err := filepath.Glob(filepath.Join(outDir, "steady__*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("glob record file: %v, %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var rec ContainerRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("parse record: %v", err)
	}

	if len(rec.CollectionResults) == 0 {
		t.Fatal("the record has no collection results at all; SIGTERM lost everything instead of flushing what was taken")
	}
	// The record now always shows the full 30 planned samples - the tail
	// beyond what was actually taken is filled with explicit, invalid
	// placeholder entries (see collect.go's stoppedEarly handling) so
	// match's own completeness judgment can tell a truncated window from
	// one that was simply given a smaller sample count on purpose. What
	// distinguishes a truncated run is that not every one of those 30 is
	// real: at least one must be a placeholder.
	if len(rec.CollectionResults) != 30 {
		t.Errorf("collection results = %d, want all 30 planned slots present (real ones and stopped-early placeholders alike)", len(rec.CollectionResults))
	}
	placeholders := 0
	for _, cr := range rec.CollectionResults {
		if !cr.Valid && cr.ProcObserve == "top_failed" && cr.PkgdbRead == "error" {
			placeholders++
		}
	}
	if placeholders == 0 || placeholders == 30 {
		t.Errorf("placeholder (never-attempted) sample count = %d out of 30, want strictly between 0 and 30 - some samples should have actually run before the signal arrived", placeholders)
	}
	found := false
	for _, f := range rec.Failures {
		if f.Step == "collector_stopped_early" {
			found = true
		}
	}
	if !found {
		t.Errorf("no collector_stopped_early failure recorded; failures: %+v", rec.Failures)
	}
}

// TestSIGTERMTruncationIsReportedAsIncompleteByMatch checks that a window
// collect.go stopped early on SIGTERM, after some genuinely valid samples,
// does not read as a complete observation once match evaluates it. It runs
// the real collect -> match pipeline
// (runCollect against a fake Docker Engine API, then runMatchPipeline and
// writeMatchCSVs against the record runCollect actually wrote) and checks
// both the in-memory result and the series.csv match itself writes.
func TestSIGTERMTruncationIsReportedAsIncompleteByMatch(t *testing.T) {
	const imageID = "sha256:030688c3b2961c28a9acad68958fd13c8d81665458b8ab69fdc0a5d95ec8ade0" // testdata/synthetic_events_trivy.json's own Metadata.ImageID
	api, _, sockPath := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "steady-id", Names: []string{"/steady"}, Image: "app:1"}}
	api.inspectFor["steady-id"] = mustSetStartedAt(dockerInspect{Id: "steady-id", Image: imageID}, "2026-09-22T00:00:00Z")
	// This test's own PID is used so the samples runCollect does complete
	// before the signal arrives are genuinely valid ones (a real, readable
	// process), not just more invalid entries indistinguishable from the
	// stopped-early placeholders under test.
	api.topFor["steady-id"] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{strconv.Itoa(os.Getpid()), "0", "root"}}}

	outDir := t.TempDir()
	done := make(chan error, 1)
	go func() {
		done <- runCollect([]string{
			"-socket", sockPath,
			"-containers", "steady",
			"-case-variant", "SYNTH-EV",
			"-permission", "root",
			"-sync", "attach_running",
			"-interval", "1",
			"-window", "30",
			"-out-dir", outDir,
			"-aux-inputs=false",
		})
	}()
	time.Sleep(2500 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to self: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runCollect returned an error after SIGTERM: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runCollect did not return within 15s of SIGTERM")
	}

	files, err := filepath.Glob(filepath.Join(outDir, "steady__*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("glob record file: %v, %v", files, err)
	}
	rec, err := readContainerRecord(files[0])
	if err != nil {
		t.Fatalf("read observation: %v", err)
	}
	validSamples := 0
	for _, cr := range rec.CollectionResults {
		if cr.Valid {
			validSamples++
		}
	}
	if validSamples == 0 {
		t.Fatal("no valid sample was recorded before the signal arrived; this test needs at least one so a truncated-but-otherwise-good window is what is actually being checked")
	}

	trivyData, err := os.ReadFile("testdata/synthetic_events_trivy.json")
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.ParseReport(trivyData)
	if err != nil {
		t.Fatalf("parse scan report: %v", err)
	}
	idx, _, err := buildScanFileIndex(trivyData, false)
	if err != nil {
		t.Fatalf("index the scan report's paths: %v", err)
	}
	def, err := readCase("testdata/synthetic_events_case.json")
	if err != nil {
		t.Fatalf("read case: %v", err)
	}

	result, err := runMatchPipeline(context.Background(), rec, scan, idx, nil, def, nil, nil,
		syntheticIntel(), t.TempDir(), defaultActNowEPSS, defaultWatchEPSS, defaultOccurrenceToleranceMS)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	s0 := seriesByName(t, result, "S0")
	if s0.CollectionComplete {
		t.Error("S0 series reports collection_complete=true for a window collect.go stopped early - the stopped-early placeholders were not carried through to match's own completeness judgment")
	}

	csvDir := t.TempDir()
	if err := writeMatchCSVs(csvDir, result); err != nil {
		t.Fatalf("writeMatchCSVs: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(csvDir, "series.csv"))
	if err != nil {
		t.Fatalf("read series.csv: %v", err)
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ",")
		// series,classification are two of the leading columns after the
		// run_key columns; rather than hard-code their index (which shifts
		// if runKeyHeader ever changes), just look for a line naming the S0
		// overall row and check it ends up with collection_complete=false
		// somewhere in it.
		if strings.Contains(line, "S0") && strings.Contains(line, "overall") {
			found = true
			if !strings.Contains(line, "false") {
				t.Errorf("series.csv's S0/overall row does not contain collection_complete=false: %v", fields)
			}
		}
	}
	if !found {
		t.Fatalf("no S0/overall row found in series.csv:\n%s", data)
	}
}

// TestLoadUnmeasuredFlagSkipsCgroupReadingEntirely checks -load-unmeasured:
// the resulting record's steady-state and Docker-daemon load tiers must
// both read not_measured with the given reason, rather than whatever
// /proc/self/cgroup happens to resolve to for this test process (a cgroup
// this run did not create and does not own).
func TestLoadUnmeasuredFlagSkipsCgroupReadingEntirely(t *testing.T) {
	api, _, sockPath := newFakeDockerAPI(t)
	api.list = []dockerContainerSummary{{ID: "steady-id", Names: []string{"/steady"}, Image: "app:1"}}
	api.inspectFor["steady-id"] = mustSetStartedAt(dockerInspect{Id: "steady-id", Image: "sha256:img"}, "2026-09-22T00:00:00Z")
	api.topFor["steady-id"] = dockerTop{Titles: []string{"PID", "PPID", "USER"}, Processes: [][]string{{"999999999", "0", "root"}}}

	outDir := t.TempDir()
	const reason = "supervise -no-cgroup: this run was not placed in a cgroup of its own"
	if err := runCollect([]string{
		"-socket", sockPath,
		"-containers", "steady",
		"-case-variant", "loadtest",
		"-permission", "root",
		"-sync", "attach_running",
		"-interval", "1",
		"-window", "1",
		"-out-dir", outDir,
		"-aux-inputs=false",
		"-load-unmeasured", reason,
	}); err != nil {
		t.Fatalf("runCollect: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(outDir, "steady__*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("glob record file: %v, %v", files, err)
	}
	rec, err := readContainerRecord(files[0])
	if err != nil {
		t.Fatalf("read observation: %v", err)
	}
	if rec.Load.SteadyState.Measured {
		t.Error("SteadyState.Measured = true, want false under -load-unmeasured")
	}
	if rec.Load.SteadyState.Error != reason {
		t.Errorf("SteadyState.Error = %q, want %q", rec.Load.SteadyState.Error, reason)
	}
	if rec.Load.SteadyState.MemoryPeakMeasured {
		t.Error("SteadyState.MemoryPeakMeasured = true, want false under -load-unmeasured")
	}
	if rec.Load.DockerDaemon.Measured {
		t.Error("DockerDaemon.Measured = true, want false under -load-unmeasured")
	}
	if rec.Load.DockerDaemon.Error != reason {
		t.Errorf("DockerDaemon.Error = %q, want %q", rec.Load.DockerDaemon.Error, reason)
	}
}
