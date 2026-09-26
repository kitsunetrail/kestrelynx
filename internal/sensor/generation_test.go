package sensor

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

func TestRecordOSPackage_MergesKindsAndObservations(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	t1 := time.Unix(100, 0)
	t2 := time.Unix(200, 0)
	obs1 := evidence.ProcessObservation{Exe: "/usr/sbin/nginx", EffectiveUID: 0, LastSeen: t1}
	obs2 := evidence.ProcessObservation{Exe: "/usr/sbin/nginx", EffectiveUID: 0, LastSeen: t2}

	g.recordOSPackage("libssl3", "3.0.15", evidence.KindExe, t1, &obs1)
	g.recordOSPackage("libssl3", "3.0.15", evidence.KindMappedLibrary, t2, &obs2)

	p, ok := g.osPackages[pkgKey{Name: "libssl3", Version: "3.0.15"}]
	if !ok {
		t.Fatalf("libssl3 not recorded")
	}
	if _, ok := p.Kinds[evidence.KindExe]; !ok {
		t.Errorf("missing KindExe")
	}
	if _, ok := p.Kinds[evidence.KindMappedLibrary]; !ok {
		t.Errorf("missing KindMappedLibrary")
	}
	// Same exe/uid observed at two different times is deduplicated (same
	// process identity), keeping the latest LastSeen.
	if len(p.Observations) != 1 {
		t.Fatalf("Observations = %d, want 1 (deduplicated)", len(p.Observations))
	}
	if !p.Observations[0].LastSeen.Equal(t2) {
		t.Errorf("Observations[0].LastSeen = %v, want %v", p.Observations[0].LastSeen, t2)
	}
}

func TestRecordOSPackage_ResolvesPreviousAmbiguity(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	g.recordUnavailableOSPackage("libssl3", "3.0.15", evidence.ReasonAttributionAmbiguous)
	if _, ok := g.unavailable[pkgKey{Name: "libssl3", Version: "3.0.15"}]; !ok {
		t.Fatalf("expected unavailable entry before resolution")
	}

	g.recordOSPackage("libssl3", "3.0.15", evidence.KindExe, time.Unix(1, 0), nil)
	if _, ok := g.unavailable[pkgKey{Name: "libssl3", Version: "3.0.15"}]; ok {
		t.Errorf("unavailable entry should have been cleared once resolved")
	}
	if _, ok := g.osPackages[pkgKey{Name: "libssl3", Version: "3.0.15"}]; !ok {
		t.Errorf("expected os package entry after resolution")
	}
}

func TestRecordUnavailableOSPackage_NeverShadowsInUse(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	g.recordOSPackage("libssl3", "3.0.15", evidence.KindExe, time.Unix(1, 0), nil)
	g.recordUnavailableOSPackage("libssl3", "3.0.15", evidence.ReasonAttributionAmbiguous)

	if _, ok := g.unavailable[pkgKey{Name: "libssl3", Version: "3.0.15"}]; ok {
		t.Errorf("an in-use package must never be shadowed by a later ambiguous verdict for the same key")
	}
}

func TestRecordExecutable_AlwaysRecordedRegardlessOfOwnership(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	obs := evidence.ProcessObservation{Exe: "/usr/local/bin/trivy", LastSeen: time.Unix(1, 0)}
	g.recordExecutable("/usr/local/bin/trivy", "08:01", 12345, evidence.KindExe, time.Unix(1, 0), &obs)

	e, ok := g.executables["/usr/local/bin/trivy"]
	if !ok {
		t.Fatalf("executable not recorded")
	}
	if e.Dev != "08:01" || e.Inode != 12345 {
		t.Errorf("Dev/Inode = %q/%d, want 08:01/12345", e.Dev, e.Inode)
	}
}

func TestMergeProcessObservation_CapsAtMaxAndDropsOldest(t *testing.T) {
	var obs []evidence.ProcessObservation
	for i := 0; i < maxProcessObservations+2; i++ {
		o := evidence.ProcessObservation{
			EffectiveUID: i, // distinct identity each time, so none dedupe
			LastSeen:     time.Unix(int64(i), 0),
		}
		obs = mergeProcessObservation(obs, o)
	}
	if len(obs) != maxProcessObservations {
		t.Fatalf("len(obs) = %d, want %d", len(obs), maxProcessObservations)
	}
	// The two oldest (EffectiveUID 0 and 1) must have been evicted.
	for _, o := range obs {
		if o.EffectiveUID < 2 {
			t.Errorf("oldest observation (uid %d) should have been evicted", o.EffectiveUID)
		}
	}
}

func TestMergeKindObservation_SamplesOncePerDistinctSample(t *testing.T) {
	kinds := map[evidence.EvidenceKind]evidence.KindObservation{}
	t1 := time.Unix(1, 0)
	mergeKindObservation(kinds, evidence.KindExe, t1, true)
	mergeKindObservation(kinds, evidence.KindExe, t1, true) // same sample, second process
	if kinds[evidence.KindExe].Samples != 1 {
		t.Errorf("Samples = %d after two calls at the same instant, want 1", kinds[evidence.KindExe].Samples)
	}
	t2 := time.Unix(2, 0)
	mergeKindObservation(kinds, evidence.KindExe, t2, true)
	if kinds[evidence.KindExe].Samples != 2 {
		t.Errorf("Samples = %d after a later sample, want 2", kinds[evidence.KindExe].Samples)
	}
}

func TestGenerationState_ToEvidence_RoundTripsIdentity(t *testing.T) {
	init := InitProcess{PID: 42, Starttime: 100}
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, init, time.Unix(0, 0))
	g.idxState = indexReady
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}
	g.recordOSPackage("libssl3", "3.0.15", evidence.KindExe, time.Unix(1, 0), nil)
	g.recordExecutable("/bin/app", "", 0, evidence.KindExe, time.Unix(1, 0), nil)

	ev := g.toEvidence()
	if ev.Init.PID != 42 || ev.Init.Starttime != 100 {
		t.Errorf("Init = %+v, want PID 42 Starttime 100", ev.Init)
	}
	if len(ev.OSPackages) != 1 || ev.OSPackages[0].Name != "libssl3" {
		t.Errorf("OSPackages = %+v", ev.OSPackages)
	}
	if len(ev.Executables) != 1 || ev.Executables[0].Path != "/bin/app" {
		t.Errorf("Executables = %+v", ev.Executables)
	}
}

// TestToEvidence_SurvivesLaterMutationOfTheSourceGeneration covers the
// whole reason toEvidence deep-clones every Kinds map and Observations
// slice (see its own doc comment): loop keeps mutating a generationState on
// later samples even after handing a snapshot off to the writer goroutine,
// so a value toEvidence already returned must be completely unaffected by
// anything recorded — or mutated in place — against the generationState
// afterward.
func TestToEvidence_SurvivesLaterMutationOfTheSourceGeneration(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	g.recordOSPackage("libssl3", "3.0.15", evidence.KindExe, time.Unix(1, 0), &evidence.ProcessObservation{Listeners: []string{"0.0.0.0:443"}, LastSeen: time.Unix(1, 0)})
	g.recordExecutable("/bin/app", "8:1", 99, evidence.KindExe, time.Unix(1, 0), &evidence.ProcessObservation{Listeners: []string{"0.0.0.0:80"}, LastSeen: time.Unix(1, 0)})

	snap := g.toEvidence()
	if len(snap.OSPackages) != 1 || len(snap.OSPackages[0].Observations) != 1 {
		t.Fatalf("OSPackages = %+v, want exactly one package with one observation", snap.OSPackages)
	}
	if len(snap.Executables) != 1 || len(snap.Executables[0].Observations) != 1 {
		t.Fatalf("Executables = %+v, want exactly one executable with one observation", snap.Executables)
	}
	wantSamples := snap.OSPackages[0].Kinds[evidence.KindExe].Samples
	wantPkgListener := snap.OSPackages[0].Observations[0].Listeners[0]
	wantExeListener := snap.Executables[0].Observations[0].Listeners[0]

	// Mutate the SOURCE generationState after toEvidence already returned:
	// a later sample recording the same package/executable again (which
	// mergeKindObservation/mergeProcessObservation update in place), plus
	// reaching directly into the live map/slice's own backing arrays,
	// exactly mirrors what loop's own goroutine keeps doing to g while the
	// writer goroutine concurrently marshals the value already returned.
	g.recordOSPackage("libssl3", "3.0.15", evidence.KindExe, time.Unix(2, 0), &evidence.ProcessObservation{Listeners: []string{"0.0.0.0:9999"}, LastSeen: time.Unix(2, 0)})
	g.recordExecutable("/bin/app", "8:1", 99, evidence.KindExe, time.Unix(2, 0), &evidence.ProcessObservation{Listeners: []string{"0.0.0.0:9999"}, LastSeen: time.Unix(2, 0)})
	g.osPackages[pkgKey{Name: "libssl3", Version: "3.0.15"}].Observations[0].Listeners[0] = "mutated"
	g.executables["/bin/app"].Observations[0].Listeners[0] = "mutated"

	if got := snap.OSPackages[0].Kinds[evidence.KindExe].Samples; got != wantSamples {
		t.Errorf("OSPackages[0].Kinds[exe].Samples in the already-returned snapshot changed to %d after a later mutation, want it to stay %d", got, wantSamples)
	}
	if got := snap.OSPackages[0].Observations[0].Listeners[0]; got != wantPkgListener {
		t.Errorf("OSPackages[0].Observations[0].Listeners[0] in the already-returned snapshot changed to %q after a later mutation, want it to stay %q", got, wantPkgListener)
	}
	if got := snap.Executables[0].Observations[0].Listeners[0]; got != wantExeListener {
		t.Errorf("Executables[0].Observations[0].Listeners[0] in the already-returned snapshot changed to %q after a later mutation, want it to stay %q", got, wantExeListener)
	}
	if len(snap.OSPackages) != 1 {
		t.Errorf("OSPackages grew to %d entries after a later mutation, want the already-returned snapshot to stay at 1", len(snap.OSPackages))
	}
}

func TestParseFailureBackoff_FirstFailureUsesTenTimesInterval(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	now := time.Unix(1000, 0)
	interval := 30 * time.Second

	g.recordParseFailure("dpkg_list", "/var/lib/dpkg/info/x.list", "08:01", 111, 500, now, interval)

	pf, ok := g.parseFailureFor("dpkg_list", "/var/lib/dpkg/info/x.list")
	if !ok {
		t.Fatalf("no ParseFailure recorded")
	}
	if pf.Count != 1 {
		t.Errorf("Count = %d, want 1", pf.Count)
	}
	wantRetry := now.Add(10 * interval)
	if !pf.RetryAfter.Equal(wantRetry) {
		t.Errorf("RetryAfter = %v, want %v (10x interval)", pf.RetryAfter, wantRetry)
	}
}

func TestParseFailureBackoff_RepeatSameInputDoublesAndCaps(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	interval := 30 * time.Second
	now := time.Unix(1000, 0)

	g.recordParseFailure("dpkg_list", "/x.list", "08:01", 111, 500, now, interval) // backoff 300s
	now = now.Add(400 * time.Second)
	g.recordParseFailure("dpkg_list", "/x.list", "08:01", 111, 500, now, interval) // backoff 600s
	pf, _ := g.parseFailureFor("dpkg_list", "/x.list")
	if pf.Count != 2 {
		t.Fatalf("Count = %d, want 2", pf.Count)
	}
	wantBackoff := 600 * time.Second
	if got := pf.RetryAfter.Sub(pf.FailedAt); got != wantBackoff {
		t.Errorf("backoff = %v, want %v (doubled)", got, wantBackoff)
	}

	// Keep failing until the backoff would exceed 24h; it must cap there.
	for i := 0; i < 20; i++ {
		now = pf.RetryAfter.Add(time.Second)
		g.recordParseFailure("dpkg_list", "/x.list", "08:01", 111, 500, now, interval)
		pf, _ = g.parseFailureFor("dpkg_list", "/x.list")
	}
	if got := pf.RetryAfter.Sub(pf.FailedAt); got != maxParseRetryBackoff {
		t.Errorf("backoff after many repeats = %v, want capped at %v", got, maxParseRetryBackoff)
	}
}

func TestParseFailureBackoff_ChangedIdentityResetsSchedule(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	interval := 30 * time.Second
	now := time.Unix(1000, 0)

	g.recordParseFailure("dpkg_list", "/x.list", "08:01", 111, 500, now, interval)
	pf, _ := g.parseFailureFor("dpkg_list", "/x.list")
	if pf.Count != 1 {
		t.Fatalf("Count = %d, want 1", pf.Count)
	}

	// A different file (changed inode) now sits at the same path: treated
	// as a brand new input, not a second failure of the old one.
	now = now.Add(time.Second)
	g.recordParseFailure("dpkg_list", "/x.list", "08:01", 222, 700, now, interval)
	pf, _ = g.parseFailureFor("dpkg_list", "/x.list")
	if pf.Count != 1 {
		t.Errorf("Count = %d, want 1 (reset for a changed identity)", pf.Count)
	}
	if pf.Inode != 222 || pf.Size != 700 {
		t.Errorf("identity = (inode=%d, size=%d), want (222, 700)", pf.Inode, pf.Size)
	}
	if got := pf.RetryAfter.Sub(pf.FailedAt); got != 10*interval {
		t.Errorf("backoff = %v, want %v (reset to 10x interval)", got, 10*interval)
	}
}

func TestShouldSkipForBackoff(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	interval := 30 * time.Second
	now := time.Unix(1000, 0)
	g.recordParseFailure("dpkg_list", "/x.list", "08:01", 111, 500, now, interval)

	if !g.shouldSkipForBackoff("dpkg_list", "/x.list", "08:01", 111, 500, now.Add(time.Second)) {
		t.Errorf("should skip: same identity, retry_after not yet reached")
	}
	if g.shouldSkipForBackoff("dpkg_list", "/x.list", "08:01", 111, 500, now.Add(10*interval+time.Second)) {
		t.Errorf("should not skip: retry_after has passed")
	}
	if g.shouldSkipForBackoff("dpkg_list", "/x.list", "08:01", 999, 500, now.Add(time.Second)) {
		t.Errorf("should not skip: different inode means a different input")
	}
	if g.shouldSkipForBackoff("dpkg_list", "/other.list", "08:01", 111, 500, now.Add(time.Second)) {
		t.Errorf("should not skip: different path entirely")
	}
}

func TestRecordParseSuccess_RemovesEntry(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	now := time.Unix(1000, 0)
	g.recordParseFailure("dpkg_list", "/x.list", "08:01", 111, 500, now, 30*time.Second)
	g.recordParseFailure("dpkg_list", "/y.list", "08:01", 222, 600, now, 30*time.Second)

	g.recordParseSuccess("dpkg_list", "/x.list")

	if _, ok := g.parseFailureFor("dpkg_list", "/x.list"); ok {
		t.Errorf("/x.list still has a ParseFailure after succeeding")
	}
	if _, ok := g.parseFailureFor("dpkg_list", "/y.list"); !ok {
		t.Errorf("/y.list's ParseFailure was removed even though it was not the one that succeeded")
	}
}

func TestNextRetryTime_PicksEarliest(t *testing.T) {
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0))
	if !g.nextRetryTime().IsZero() {
		t.Fatalf("nextRetryTime with no failures should be zero")
	}
	now := time.Unix(1000, 0)
	g.recordParseFailure("dpkg_list", "/late.list", "08:01", 1, 1, now, 100*time.Second) // retry at now+1000s
	g.recordParseFailure("dpkg_list", "/early.list", "08:01", 2, 2, now, 10*time.Second) // retry at now+100s

	want := now.Add(10 * 10 * time.Second)
	if got := g.nextRetryTime(); !got.Equal(want) {
		t.Errorf("nextRetryTime = %v, want %v (the earliest of the two)", got, want)
	}
}
