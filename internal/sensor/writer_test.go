package sensor

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// hexID returns a distinct, valid 64-hex-character container ID for index
// i, standing in for a container ID in tests that need many distinct ones
// (strings64, used elsewhere in this package's tests, only ever repeats a
// single byte 64 times, which cannot produce more than 16 distinct IDs).
func hexID(i int) string { return fmt.Sprintf("%064x", i) }

// writeAndReadBack writes gens (after enforceWriteLimits) to a fresh
// temporary evidence file via the real evidence.WriteFD/evidence.NewReader
// pair — proving genuine round-trip readability against the actual reader
// this Sensor's own output has to satisfy, not merely this package's own
// assumptions about what that reader's limits are.
func writeAndReadBack(t *testing.T, gens []evidence.Generation) (evidence.Snapshot, bool) {
	t.Helper()
	trimmed, modified := enforceWriteLimits(gens)

	dir := t.TempDir()
	f, err := os.OpenFile(dir+"/"+evidence.FileName, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	snap := evidence.Snapshot{
		Schema: evidence.Schema,
		Sensor: evidence.SensorInfo{
			SessionID: "test", HeartbeatAt: time.Now(), IntervalSeconds: 30,
			Status: evidence.SensorOK,
		},
		Generations: trimmed,
	}
	if err := evidence.WriteFD(int(f.Fd()), snap); err != nil {
		t.Fatalf("WriteFD: %v", err)
	}

	r := evidence.NewReader(dir)
	got, err := r.Read(time.Now(), nil)
	if err != nil {
		t.Fatalf("Read back the file this test just wrote: %v (the write side and the read side disagree about what fits)", err)
	}
	return got, modified
}

func genWithEntities(id string, ended bool, executables, unavailable, osPackages int) evidence.Generation {
	g := evidence.Generation{Container: evidence.ContainerRef{Runtime: "docker", ID: id}, StartedAt: time.Unix(0, 0)}
	if ended {
		endedAt := time.Unix(1, 0)
		g.EndedAt = &endedAt
	}
	for i := 0; i < executables; i++ {
		g.Executables = append(g.Executables, evidence.ExecutableEvidence{Path: "/bin/x", Dev: "08:01"})
	}
	for i := 0; i < unavailable; i++ {
		g.Unavailable = append(g.Unavailable, evidence.UnavailablePackage{Name: "pkg", Version: "1.0"})
	}
	for i := 0; i < osPackages; i++ {
		g.OSPackages = append(g.OSPackages, evidence.OSPackageEvidence{Name: "pkg", Version: "1.0"})
	}
	return g
}

// TestWriteSnapshot_RoundTripsUnderEveryLimit covers the three ways a
// snapshot can exceed evidence.Reader's own hard limits — a single
// generation with too many entities, too many live generations, and live
// generations alone totaling too many bytes — confirming enforceWriteLimits
// leaves a file the real reader accepts in every case, and that each one
// is reported as "modified" (loop's own trigger for SensorDegraded).
func TestWriteSnapshot_RoundTripsUnderEveryLimit(t *testing.T) {
	t.Run("60,000 entities in one generation", func(t *testing.T) {
		gens := []evidence.Generation{genWithEntities(hexID(0), false, 60000, 0, 0)}
		got, modified := writeAndReadBack(t, gens)
		if !modified {
			t.Errorf("modified = false, want true")
		}
		if len(got.Generations) != 1 {
			t.Fatalf("len(Generations) = %d, want 1", len(got.Generations))
		}
		count := len(got.Generations[0].Executables) + len(got.Generations[0].Unavailable) + len(got.Generations[0].OSPackages)
		if count > mirrorMaxEntitiesPerGeneration {
			t.Errorf("entity count = %d, want at most %d", count, mirrorMaxEntitiesPerGeneration)
		}
		if !got.Generations[0].Truncated {
			t.Errorf("Truncated = false, want true")
		}
	})

	t.Run("6,000 live generations", func(t *testing.T) {
		var gens []evidence.Generation
		for i := 0; i < 6000; i++ {
			gens = append(gens, genWithEntities(hexID(i), false, 1, 0, 0))
		}
		got, modified := writeAndReadBack(t, gens)
		if !modified {
			t.Errorf("modified = false, want true")
		}
		if len(got.Generations) > mirrorMaxGenerations {
			t.Errorf("len(Generations) = %d, want at most %d", len(got.Generations), mirrorMaxGenerations)
		}
	})

	t.Run("live generations alone exceed 64 MiB", func(t *testing.T) {
		// Well under both the 5,000-generation cap and the 50,000-
		// entity-per-generation cap individually (2,000 entities each),
		// but with long (valid, <=512-byte) name/version strings on each
		// one, enough combined bytes across 100 generations to exceed the
		// file-size budget on its own.
		longName := fmt.Sprintf("pkg-%0350d", 0)
		longVersion := fmt.Sprintf("%0350d", 0)
		var gens []evidence.Generation
		for i := 0; i < 100; i++ {
			g := evidence.Generation{Container: evidence.ContainerRef{Runtime: "docker", ID: hexID(i)}, StartedAt: time.Unix(0, 0)}
			for j := 0; j < 2000; j++ {
				g.Unavailable = append(g.Unavailable, evidence.UnavailablePackage{Name: longName, Version: longVersion})
			}
			gens = append(gens, g)
		}
		got, modified := writeAndReadBack(t, gens)
		if !modified {
			t.Errorf("modified = false, want true")
		}
		_ = got // the fatal check is writeAndReadBack's own Read call not erroring at all
	})
}

// TestEnforceWriteLimits_TrimsEntitiesAndMarksTruncated covers the
// per-generation entity cap: a generation whose combined OSPackages/
// Unavailable/Executables count exceeds mirrorMaxEntitiesPerGeneration must
// have its Executables trimmed down to fit and be marked Truncated — never
// silently written oversized and left to the reader's own validation to
// reject outright.
func TestEnforceWriteLimits_TrimsEntitiesAndMarksTruncated(t *testing.T) {
	over := mirrorMaxEntitiesPerGeneration + 10
	gen := evidence.Generation{Container: evidence.ContainerRef{ID: "a"}}
	for i := 0; i < over; i++ {
		gen.Executables = append(gen.Executables, evidence.ExecutableEvidence{Path: "/bin/x"})
	}

	out, modified := enforceWriteLimits([]evidence.Generation{gen})
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	count := len(out[0].OSPackages) + len(out[0].Unavailable) + len(out[0].Executables)
	if count > mirrorMaxEntitiesPerGeneration {
		t.Errorf("entity count = %d, want at most %d", count, mirrorMaxEntitiesPerGeneration)
	}
	if !out[0].Truncated {
		t.Errorf("Truncated = false, want true once entities were trimmed")
	}
	if !modified {
		t.Errorf("modified = false, want true once entities were trimmed")
	}
}

// TestEnforceWriteLimits_DropsOldestEndedGenerationsOverCount covers the
// whole-snapshot generation cap: once over mirrorMaxGenerations, the
// oldest-ended generations are dropped first, never a still-live one, and
// never anything but the exact overage.
func TestEnforceWriteLimits_DropsOldestEndedGenerationsOverCount(t *testing.T) {
	var gens []evidence.Generation
	liveEnd := time.Unix(0, 0)
	for i := 0; i < mirrorMaxGenerations+5; i++ {
		endedAt := time.Unix(int64(i), 0)
		gens = append(gens, evidence.Generation{
			Container: evidence.ContainerRef{ID: string(rune('a' + i%26))},
			EndedAt:   &endedAt,
		})
	}
	// One live generation (EndedAt nil) must never be dropped by the count
	// cap alone, however old its own StartedAt is.
	liveGen := evidence.Generation{Container: evidence.ContainerRef{ID: "live"}, StartedAt: liveEnd}
	gens = append(gens, liveGen)

	out, modified := enforceWriteLimits(gens)
	if len(out) != mirrorMaxGenerations {
		t.Fatalf("len(out) = %d, want exactly %d", len(out), mirrorMaxGenerations)
	}
	if !modified {
		t.Errorf("modified = false, want true once generations were dropped")
	}
	var sawLive bool
	oldestKept := time.Unix(1<<62, 0)
	for _, g := range out {
		if g.Container.ID == "live" {
			sawLive = true
			continue
		}
		if g.EndedAt.Before(oldestKept) {
			oldestKept = *g.EndedAt
		}
	}
	if !sawLive {
		t.Errorf("the live (never-ended) generation was dropped; only ended generations should ever be")
	}
	// The 5 oldest-ended generations (EndedAt 0..4) must be exactly the ones
	// dropped, since 5 is the exact overage.
	if oldestKept.Unix() < 5 {
		t.Errorf("oldest kept ended generation's EndedAt = %v, want >= unix(5) (the 5 oldest should have been dropped)", oldestKept)
	}
}

// TestTrimToByteBudget_ZeroEntitiesStillOverBudgetDropsTheGeneration covers
// trimToByteBudget's own fallback once entity-trimming has nothing left to
// remove: a generation with zero OSPackages/Unavailable/Executables can
// still be oversized entirely on its own through fields entity-trimming
// never touches (here, PackageDB.NoFileList) — trimGenerationBySize finds
// no entities at all (count == 0) and reports no change, so the whole
// generation must be dropped outright instead of the loop spinning forever
// or leaving the write over budget.
func TestTrimToByteBudget_ZeroEntitiesStillOverBudgetDropsTheGeneration(t *testing.T) {
	// No single string is validated/capped at this layer (evidence.Generation
	// values are constructed directly here, bypassing generationState's own
	// recordParseFailure-time string limits) — 10 one-megabyte-ish entries
	// comfortably exceed the whole 64 MiB budget on their own, with zero
	// entities anywhere in the generation.
	bigName := make([]byte, 1<<20)
	for i := range bigName {
		bigName[i] = 'x'
	}
	gen := evidence.Generation{
		Container: evidence.ContainerRef{Runtime: "docker", ID: strings64('a')},
		StartedAt: time.Unix(0, 0),
	}
	for i := 0; i < 70; i++ {
		gen.PackageDB.NoFileList = append(gen.PackageDB.NoFileList, string(bigName))
	}
	if len(gen.Executables)+len(gen.Unavailable)+len(gen.OSPackages) != 0 {
		t.Fatalf("test precondition: gen must have zero entities")
	}

	out, modified := enforceWriteLimits([]evidence.Generation{gen})
	if !modified {
		t.Errorf("modified = false, want true — the only generation was entirely over budget with nothing to trim")
	}
	if len(out) != 0 {
		t.Errorf("len(out) = %d, want 0 — the only generation (live, zero entities, still over budget) must be dropped outright, not left oversized", len(out))
	}
}

// TestRunWriter_FinalWriteDoesNotDeadlockOnFullReportChannel covers the
// deadlock an earlier version of runWriter could reach: reportCh's own
// single-slot buffer already holding one undrained ordinary report, with
// nothing left to ever read it — exactly loop's own real situation once it
// is blocked waiting on a later, final job's own done channel (see
// submitFinalSnapshot's own doc comment). No goroutine in this test ever
// reads reportCh at all, matching production (only loop's own main select
// does, and this scenario is specifically the one where it has stopped):
// this test proves runWriter's own non-blocking report send is what
// prevents the deadlock, not a reader this test supplies that production
// does not.
func TestRunWriter_FinalWriteDoesNotDeadlockOnFullReportChannel(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(dir+"/"+evidence.FileName, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	jobCh := make(chan writerJob, 1)
	reportCh := make(chan writeReport, 1)
	reportCh <- writeReport{} // an earlier ordinary report nobody has drained — reportCh starts full

	go runWriter(int(f.Fd()), jobCh, reportCh)

	validSnap := evidence.Snapshot{Schema: evidence.Schema, Sensor: evidence.SensorInfo{IntervalSeconds: 30}}

	// An ordinary job, sent directly to jobCh rather than through
	// submitSnapshot's own evicting helper: that helper could otherwise
	// race this send against the final job below and let the final job
	// steal this buffer slot before runWriter ever touches this one — this
	// test specifically needs runWriter to dequeue and start processing
	// this ordinary job first, so its own report send is what meets the
	// already-full reportCh.
	jobCh <- writerJob{snap: validSnap}

	// A raw blocking send of the final job onto the same capacity-1
	// channel: it can only succeed once runWriter has dequeued the
	// ordinary job above, freeing the buffer slot — which happens exactly
	// when runWriter's own `for job := range jobCh` loops back around,
	// i.e. only after that ordinary job's whole body, including its own
	// report send, has already run to completion.
	done := make(chan writeReport, 1)
	sent := make(chan struct{})
	go func() {
		jobCh <- writerJob{snap: validSnap, done: done}
		close(sent)
	}()

	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("the final job was never even accepted onto jobCh — runWriter appears stuck sending the ordinary job's own report")
	}

	select {
	case rep := <-done:
		if rep.err != nil {
			t.Errorf("final write err = %v, want nil", rep.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the final job was accepted but never completed — runWriter deadlocked before reaching it")
	}
}

// TestRunWriter_ConsecutiveFailuresCountedCorrectlyDespiteReportCoalescing
// covers writeReport.consecutiveFailures' own reason for existing: loop
// cannot safely count a failure streak from how many failure reports it
// happens to receive, because submitSnapshot's own single-slot "latest
// wins" coalescing can silently replace an ordinary report before loop
// ever reads it (see writeReport's own doc comment). This test submits
// three genuinely consecutive failing writes directly to jobCh, without
// ever draining reportCh in between — coalescing every earlier report away
// — and confirms the one report that does survive still carries the true
// count (3), not 1 (as a naive "count received reports" scheme would); a
// fourth, synchronizing write (whose own outcome is read through its own
// done channel, not reportCh, so it cannot itself be coalesced away)
// confirms the running count continues correctly to 4 across that same
// coalesced stretch.
func TestRunWriter_ConsecutiveFailuresCountedCorrectlyDespiteReportCoalescing(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(dir+"/"+evidence.FileName, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	badFD := int(f.Fd())
	f.Close() // the fd number is now invalid: every write through it fails

	jobCh := make(chan writerJob, 8)
	reportCh := make(chan writeReport, 1)
	go runWriter(badFD, jobCh, reportCh)

	failingSnap := evidence.Snapshot{Schema: evidence.Schema, Sensor: evidence.SensorInfo{IntervalSeconds: 30}}

	// Three ordinary submissions, sent directly (never through
	// submitSnapshot, and never drained from reportCh in between) so every
	// one of their own reports but the last is coalesced away before this
	// test ever reads reportCh at all.
	jobCh <- writerJob{snap: failingSnap}
	jobCh <- writerJob{snap: failingSnap}
	jobCh <- writerJob{snap: failingSnap}

	// A fourth, synchronizing write: its own report goes through its own
	// done channel, never reportCh, so waiting for it here also guarantees
	// the three ordinary jobs above have already been fully processed (and
	// their own reportCh sends already made and overwritten) by the time
	// this proceeds.
	done := make(chan writeReport, 1)
	jobCh <- writerJob{snap: failingSnap, done: done}
	rep4 := <-done
	if rep4.err == nil {
		t.Fatalf("4th write err = nil, want an error (the fd is invalid)")
	}
	if rep4.consecutiveFailures != 4 {
		t.Errorf("4th write consecutiveFailures = %d, want 4", rep4.consecutiveFailures)
	}

	select {
	case rep3 := <-reportCh:
		if rep3.err == nil {
			t.Fatalf("coalesced report's own err = nil, want an error")
		}
		if rep3.consecutiveFailures != 3 {
			t.Errorf("coalesced report's own consecutiveFailures = %d, want 3 — three genuinely consecutive failures were coalesced into one surviving report, and it must still carry the true count, not 1", rep3.consecutiveFailures)
		}
	default:
		t.Fatalf("reportCh is empty — the three ordinary jobs' own ordinary reports never reached it at all")
	}
}
