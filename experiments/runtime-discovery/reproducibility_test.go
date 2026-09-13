package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// seedIntelCache pre-populates an intel.Source cache directory with
// minimal, already-fresh KEV/EPSS files, so a test calling match's pipeline
// never performs a network fetch. epssRows is the CSV body after the
// header, which lets a test replace the feed contents and check what a run
// does when the data underneath it changes.
func seedIntelCache(t *testing.T, dir, epssRows string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kev.json"), []byte(`{"vulnerabilities":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	epssPath := filepath.Join(dir, "epss.csv.gz")
	f, err := os.Create(epssPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte("cve,epss,percentile\n" + epssRows)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	meta := map[string]time.Time{"kev_fetched_at": time.Now(), "epss_fetched_at": time.Now()}
	data, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMatchReproducibleFromSavedInputs verifies the harness's acceptance
// condition: match run twice from the same saved inputs (and never touching
// any rootfs, since ContainerRecord/GroundTruthB/Case are all just
// in-memory values here, not live procfs reads) produces the same result.
// This stands in for "run match again after the container has been
// destroyed" — the inputs are all that's left, and that must be enough.
//
// The intel snapshot is part of those inputs. The first run performs a
// lookup and records the snapshot it classified against; the second and
// third runs are given that snapshot instead, and the KEV/EPSS cache is
// replaced with different data in between. A run that still consulted the
// feeds would classify differently; one that uses the snapshot cannot.
func TestMatchReproducibleFromSavedInputs(t *testing.T) {
	scan, err := scanner.ParseReport([]byte(syntheticTrivyReport))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	rec := ContainerRecord{
		Subject:           Subject{Runtime: "docker", Docker: DockerSubject{ContainerID: "c1", ImageID: "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732"}},
		RunKey:            RunKey{CaseVariant: "REPRO-1", Permission: "root", Interval: 30, Window: 300, Phase: 0, Replicate: 1},
		Window:            Window{Samples: []SampleTiming{{SampleID: "s0", ActualStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}},
		CollectionResults: []CollectionResult{{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "ok", Valid: true}},
		Processes:         []ProcessRecord{{SampleID: "s0", Generation: ProcessGeneration{PID: 1}, Exe: "/usr/sbin/nginx"}},
		PathResolution: []PathResolutionRecord{
			{SampleID: "s0", Generation: ProcessGeneration{PID: 1}, Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Resolved: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Ownership: OwnershipOwned, DBKind: dpkgKind, Package: "libssl3", DBVersion: "3.0.13-1"},
		},
		PackageLedger: []LedgerEntry{
			{Name: "libssl3", Version: "3.0.13-1", FileListPresent: true},
			{Name: "gzip", Version: "1.12-1", FileListPresent: true},
		},
		PkgDBs: []PkgDBGenerationInfo{{DBKind: dpkgKind}},
	}
	def := Case{CaseID: "REPRO-1", Image: "kl-integration-test:1", GTBScope: []string{"libssl3", "gzip"}}
	gtb := &GroundTruthB{Kind: "limited", ResidentPackages: []ResidentPackage{{Package: "libssl3", Used: true}}}

	cacheDir := t.TempDir()
	seedIntelCache(t, cacheDir, "CVE-0000-0000,0.01,0.1\n")

	first, err := runMatchPipeline(context.Background(), rec, scan, def, gtb, nil, cacheDir, defaultActNowEPSS, defaultWatchEPSS)
	if err != nil {
		t.Fatalf("first runMatchPipeline: %v", err)
	}
	if first.IntelSource != "lookup" {
		t.Errorf("IntelSource = %q, want lookup for a run with no snapshot input", first.IntelSource)
	}

	// Everything a later run is given: the saved snapshot, and a feed cache
	// that no longer says what it said.
	snapshot := first.Intel
	seedIntelCache(t, cacheDir, "CVE-2030-0001,0.99,0.99\nCVE-2030-0002,0.98,0.98\n")

	second, err := runMatchPipeline(context.Background(), rec, scan, def, gtb, &snapshot, cacheDir, defaultActNowEPSS, defaultWatchEPSS)
	if err != nil {
		t.Fatalf("second runMatchPipeline: %v", err)
	}
	third, err := runMatchPipeline(context.Background(), rec, scan, def, gtb, &snapshot, cacheDir, defaultActNowEPSS, defaultWatchEPSS)
	if err != nil {
		t.Fatalf("third runMatchPipeline: %v", err)
	}
	if second.IntelSource != "snapshot" {
		t.Errorf("IntelSource = %q, want snapshot", second.IntelSource)
	}

	// GeneratedAt is the only thing allowed to differ between two runs of
	// the same inputs: it is the wall clock at computation time, not a fact
	// about the saved inputs. Every Evidence record's ObservedAt is a
	// capture time taken from the observation, so it must already agree.
	second.GeneratedAt = time.Time{}
	third.GeneratedAt = time.Time{}
	if !reflect.DeepEqual(second, third) {
		t.Errorf("match result differs between two runs of the same saved inputs:\nsecond: %+v\nthird:  %+v", second, third)
	}

	// The snapshot run must also reproduce the classification the snapshot
	// came from, rather than the one the replaced feed data would give.
	firstPrio, secondPrio := priorityCounts(first), priorityCounts(second)
	if !reflect.DeepEqual(firstPrio, secondPrio) {
		t.Errorf("priorities changed after the feeds did, despite a snapshot input: %v vs %v", firstPrio, secondPrio)
	}
}

func priorityCounts(r MatchResult) map[string]int {
	out := map[string]int{}
	for _, pv := range r.Packages {
		for prio, n := range pv.Priorities {
			out[prio] += n
		}
	}
	return out
}
