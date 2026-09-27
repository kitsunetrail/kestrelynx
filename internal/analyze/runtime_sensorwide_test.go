package analyze

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// osScanAndContainer builds the one-package, one-container fixture every
// test below starts from: an OS package Finding matching the OSPackageEvidence
// name/version baseGeneration's caller sets up, on a single container.
func osScanAndContainer(t *testing.T) (Report, inventory.Container) {
	t.Helper()
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	return Build(scans, []inventory.Container{container}, Triage{}, runtimeNow), container
}

// TestGroupRuntime_SensorIsolationFailedForcesUnavailable covers the
// isolation_failed case: with no generation for this container at all
// (matchGeneration would otherwise report container_not_observed), a
// Sensor-wide isolation_failed status must instead report unavailable/
// isolation_failed — the specific, more accurate diagnosis of why nothing
// was observed.
func TestGroupRuntime_SensorIsolationFailedForcesUnavailable(t *testing.T) {
	r, _ := osScanAndContainer(t)
	sensor := okSensor()
	sensor.Status = evidence.SensorIsolationFailed
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: sensor} // no generations at all
	insp := GenerationInspect{ByContainer: map[string]docker.InspectResult{}, BootTime: runtimeBootTime}

	AttachRuntime(&r, RuntimeInfo{Sensor: sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonIsolationFailed {
		t.Fatalf("Runtime = %+v, want unavailable/isolation_failed", g.Runtime)
	}
}

// TestGroupRuntime_SensorPermissionDeniedDowngradesNotObserved covers a
// Sensor-wide permission_denied status: a package that would otherwise
// cleanly resolve to not_observed (a matched, fresh generation that simply
// never saw this package) must instead be unavailable/permission_denied —
// only an already-confirmed verdict survives a Sensor-wide permission
// problem.
func TestGroupRuntime_SensorPermissionDeniedDowngradesNotObserved(t *testing.T) {
	r, _ := osScanAndContainer(t)
	gen := baseGeneration() // no OSPackages at all -> would be not_observed
	sensor := okSensor()
	sensor.Status = evidence.SensorPermissionDenied
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: sensor, Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}

	AttachRuntime(&r, RuntimeInfo{Sensor: sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonPermissionDenied {
		t.Fatalf("Runtime = %+v, want unavailable/permission_denied", g.Runtime)
	}
}

// TestGroupRuntime_SensorPermissionDeniedDowngradesExistingUnavailable
// covers the broader half of the Sensor-wide override: a package whose
// matched generation already resolves to a *specific* unavailable reason —
// here initializing, from GenerationEligibleForNotObserved, which
// JudgeOSPackage returns as UsageUnavailable, never UsageNotObserved — must
// still be replaced by the Sensor-wide permission_denied reason. Overriding
// only not_observed (and the no-generation-matched case) would leave this
// one showing initializing while the Sensor itself reports its reads are
// being refused.
func TestGroupRuntime_SensorPermissionDeniedDowngradesExistingUnavailable(t *testing.T) {
	r, _ := osScanAndContainer(t)
	gen := baseGeneration()
	gen.State = evidence.StateInitializing // -> JudgeOSPackage returns unavailable/initializing, not not_observed
	sensor := okSensor()
	sensor.Status = evidence.SensorPermissionDenied
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: sensor, Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}

	AttachRuntime(&r, RuntimeInfo{Sensor: sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonPermissionDenied {
		t.Fatalf("Runtime = %+v, want unavailable/permission_denied (not initializing)", g.Runtime)
	}
}

// TestGroupRuntime_SensorWideStatusNeverOverridesInUse confirms the one
// carve-out that matters most: whatever the Sensor's current self-report
// says, a package this generation actually observed running stays in_use.
// isolation_failed/permission_denied here is
// deliberately not a realistic combination with a populated generation
// (isolation_failed in particular means the Sensor never started observing
// at all) — it exercises the override's own restraint directly, at the level
// of the code path rather than a end-to-end-realistic scenario.
func TestGroupRuntime_SensorWideStatusNeverOverridesInUse(t *testing.T) {
	for _, status := range []evidence.SensorStatus{evidence.SensorIsolationFailed, evidence.SensorPermissionDenied} {
		r, _ := osScanAndContainer(t)
		gen := baseGeneration()
		gen.OSPackages = []evidence.OSPackageEvidence{{
			Name: "openssl", Version: "3.0.7",
			Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1}},
		}}
		sensor := okSensor()
		sensor.Status = status
		snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: sensor, Generations: []evidence.Generation{gen}}
		insp := GenerationInspect{
			ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
			BootTime:    runtimeBootTime,
		}

		AttachRuntime(&r, RuntimeInfo{Sensor: sensor}, snap, insp, runtimeNow)
		g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
		if g.Runtime.Usage != evidence.UsageInUse {
			t.Errorf("sensor status %q: Runtime.Usage = %q, want in_use (an already-observed fact must survive a Sensor-wide status change)", status, g.Runtime.Usage)
		}
	}
}

// TestGroupRuntime_SensorHeartbeatStaleDowngradesEvenFreshGeneration covers
// a generation whose own LastVerifiedAt looks recent, from a Sensor whose
// heartbeat_at is old. Checking only the
// generation's own freshness (evidence.GenerationFresh) would let this
// through as not_observed; the Sensor-wide heartbeat check must catch it
// too.
func TestGroupRuntime_SensorHeartbeatStaleDowngradesEvenFreshGeneration(t *testing.T) {
	r, _ := osScanAndContainer(t)
	gen := baseGeneration()
	gen.LastVerifiedAt = runtimeNow // looks fresh on its own
	sensor := okSensor()
	sensor.HeartbeatAt = runtimeNow.Add(-time.Hour) // stale at a 30s interval
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: sensor, Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}

	AttachRuntime(&r, RuntimeInfo{Sensor: sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonSensorStale {
		t.Fatalf("Runtime = %+v, want unavailable/sensor_stale even though the generation's own LastVerifiedAt looked fresh", g.Runtime)
	}
}

// TestMatchGeneration_StartedAtMismatchNeverMatches covers the other half of
// the generation-matching contract (TestAttachRuntime_
// DifferentGenerationNeverInUse covers a PID mismatch): the same PID, but a
// StartedAt more than the 2-second tolerance away from the generation's own
// (converted) Starttime, must not match either — a same-PID coincidence
// across a fast restart is exactly what the timestamp check exists to catch.
func TestMatchGeneration_StartedAtMismatchNeverMatches(t *testing.T) {
	r, _ := osScanAndContainer(t)
	gen := baseGeneration()
	gen.OSPackages = []evidence.OSPackageEvidence{{
		Name: "openssl", Version: "3.0.7",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1}},
	}}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}

	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: {
			Pid:       gen.Init.PID,                                                                          // same PID
			StartedAt: runtimeBootTime.Add(time.Duration(gen.Init.Starttime)*starttimeTick + 10*time.Second), // 10s off, past the 2s tolerance
			Image:     r.Watch[0].Subject.Key.Digest,
		}},
		BootTime: runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage == evidence.UsageInUse {
		t.Fatal("Runtime.Usage = in_use, want anything but in_use for a StartedAt mismatch beyond tolerance")
	}
	if g.Runtime.Reason != evidence.ReasonGenerationUnverified {
		t.Errorf("Runtime.Reason = %q, want generation_unverified", g.Runtime.Reason)
	}
}

// TestGroupRuntime_ExcludedContainerSkipped covers the
// io.kestrelynx.runtime.exclude=true label: a container so labeled
// contributes nothing to a group's runtime verdict at all, even when it
// would otherwise have been the one container establishing in_use. The
// second, unexcluded container's own not_observed is what the group must
// show.
func TestGroupRuntime_ExcludedContainerSkipped(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	excludedID := testContainerID
	otherID := strings40("e")
	containers := []inventory.Container{
		{ID: excludedID, Name: "excluded", RuntimeExcluded: true, Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)}},
		{ID: otherID, Name: "other", Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)}},
	}
	r := Build(scans, containers, Triage{}, runtimeNow)

	genExcluded := baseGeneration()
	genExcluded.OSPackages = []evidence.OSPackageEvidence{{
		Name: "openssl", Version: "3.0.7",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1}},
	}}
	genOther := baseGeneration()
	genOther.Container.ID = otherID
	// genOther has no OSPackages entry for openssl -> not_observed on its own.

	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{genExcluded, genOther}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			excludedID: matchedInspect(genExcluded, r.Watch[0].Subject),
			otherID:    matchedInspect(genOther, r.Watch[0].Subject),
		},
		BootTime: runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageNotObserved {
		t.Fatalf("Runtime.Usage = %q, want not_observed (the excluded container's in_use evidence must never be considered)", g.Runtime.Usage)
	}
	for _, cr := range g.Runtime.Containers {
		if cr.ContainerID == excludedID {
			t.Errorf("Runtime.Containers contains the excluded container %s: %+v", excludedID, cr)
		}
	}
}

// TestGroupRuntime_RepresentativeContainerConsistency checks that different
// containers' facts are never mixed into one display: container A is in_use
// with a non-public, ordinary-UID process; container B is in_use with a
// published, root process. The group's own Exposure/HighPrivilege — and
// every per-container fact a display line would read (Process.Exe,
// EvidenceKinds) — must come from the *same* container (B, the strongest),
// never A's executable paired with B's exposure or privilege.
func TestGroupRuntime_RepresentativeContainerConsistency(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	idA, idB := testContainerID, strings40("b")
	containers := []inventory.Container{
		{ID: idA, Name: "worker", Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)}},
		{ID: idB, Name: "server", Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)}},
	}
	r := Build(scans, containers, Triage{}, runtimeNow)

	genA := baseGeneration()
	genA.OSPackages = []evidence.OSPackageEvidence{{
		Name: "openssl", Version: "3.0.7",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1}},
		Observations: []evidence.ProcessObservation{
			{Exe: "/app/worker", EffectiveUID: 1000, LastSeen: runtimeNow}, // no listeners, ordinary UID
		},
	}}
	genB := baseGeneration()
	genB.Container.ID = idB
	genB.Init = evidence.InitProcess{PID: 9999, Starttime: 700}
	genB.OSPackages = []evidence.OSPackageEvidence{{
		Name: "openssl", Version: "3.0.7",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExe:       {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
			evidence.KindExecEvent: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Count: 1},
		},
		Observations: []evidence.ProcessObservation{
			{Exe: "/app/server", EffectiveUID: 0, Listeners: []string{"tcp:0.0.0.0:443"}, LastSeen: runtimeNow},
		},
	}}

	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{genA, genB}}
	inspA := matchedInspect(genA, r.Watch[0].Subject)
	inspB := matchedInspect(genB, r.Watch[0].Subject)
	inspB.Ports = map[string][]docker.PortBinding{"443/tcp": {{HostIP: "0.0.0.0", HostPort: "443"}}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{idA: inspA, idB: inspB},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")

	if g.Runtime.Usage != evidence.UsageInUse {
		t.Fatalf("Runtime.Usage = %q, want in_use", g.Runtime.Usage)
	}
	if g.Runtime.Exposure != ExposureHostPublishedAll || !g.Runtime.HighPrivilege {
		t.Fatalf("Runtime = %+v, want the group's own Exposure/HighPrivilege to be server's (host_published_all, high privilege)", g.Runtime)
	}
	if len(g.Runtime.Containers) == 0 || g.Runtime.Containers[0].ContainerID != idB {
		t.Fatalf("Containers[0] = %+v, want container B (server) sorted first as the strongest in-use container", g.Runtime.Containers)
	}
	rep := g.Runtime.Containers[0]
	if rep.Process.Exe != "/app/server" {
		t.Errorf("representative container Process.Exe = %q, want /app/server (never worker's)", rep.Process.Exe)
	}
	if rep.Exposure != ExposureHostPublishedAll || !rep.HighPrivilege {
		t.Errorf("representative container Exposure/HighPrivilege = %v/%v, want host_published_all/true", rep.Exposure, rep.HighPrivilege)
	}
}
