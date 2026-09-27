package analyze

import (
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var runtimeNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
var runtimeBootTime = runtimeNow.Add(-24 * time.Hour)

const testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// matchedInspect builds a docker.InspectResult that matchGeneration accepts
// against gen: same Pid, StartedAt within tolerance of gen's boot-relative
// Starttime, and (when subject is a resolved config digest) the same image
// digest.
func matchedInspect(gen evidence.Generation, subject inventory.ImageSubject) docker.InspectResult {
	insp := docker.InspectResult{
		Pid:       gen.Init.PID,
		StartedAt: runtimeBootTime.Add(time.Duration(gen.Init.Starttime) * starttimeTick),
	}
	if subject.Resolved && subject.Key.Digest.Kind == inventory.DigestConfig {
		insp.Image = subject.Key.Digest
	}
	return insp
}

// baseSnapshot returns a minimal, otherwise-valid evidence.Snapshot with one
// generation for testContainerID, ready for the caller to add OSPackages/
// Executables to.
func baseGeneration() evidence.Generation {
	return evidence.Generation{
		Container:      evidence.ContainerRef{Runtime: "docker", ID: testContainerID},
		Init:           evidence.InitProcess{PID: 4242, Starttime: 100},
		State:          evidence.StateObserving,
		LastVerifiedAt: runtimeNow,
		PackageDB:      evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK},
		EventsCoverage: evidence.CoverageSinceStart,
	}
}

func okSensor() evidence.SensorInfo {
	return evidence.SensorInfo{IntervalSeconds: 30, HeartbeatAt: runtimeNow, Status: evidence.SensorOK}
}

// TestAttachRuntime_EmbeddedBinaryInstanceProjection covers a notable case:
// the same Go module vendored into two binaries, /app/api and
// /app/tool. Only /app/api is currently running, so the group as a whole
// must be in_use (the projection rule: any in-use Instance wins), while the
// per-container, per-Instance breakdown must still show /app/tool as
// not_observed rather than silently folding it into the group's in_use
// verdict.
func TestAttachRuntime_EmbeddedBinaryInstanceProjection(t *testing.T) {
	find1 := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
		InstalledVer: "v0.1.0", FixedVer: "v0.2.0", Status: scanner.StatusFixed,
		Severity: scanner.SeverityHigh, VulnID: "CVE-GO-1", Type: "gobinary", Target: "app/api",
	}
	find2 := find1
	find2.Target = "app/tool"
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find1, find2)}

	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)
	g := pkgGroup(t, r.Actionable, "demo:1.0", "golang.org/x/net")
	if len(g.Instances) != 2 {
		t.Fatalf("Instances = %+v, want 2 (app/api, app/tool)", g.Instances)
	}

	gen := baseGeneration()
	gen.Executables = []evidence.ExecutableEvidence{
		{Path: "/app/api", Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
		}},
	}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Actionable[0].Subject)},
		BootTime:    runtimeBootTime,
	}

	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g = pkgGroup(t, r.Actionable, "demo:1.0", "golang.org/x/net")

	if g.Runtime.Usage != evidence.UsageInUse {
		t.Fatalf("group Runtime.Usage = %q, want in_use (app/api is running)", g.Runtime.Usage)
	}
	if len(g.Runtime.Containers) != 1 || len(g.Runtime.Containers[0].Instances) != 2 {
		t.Fatalf("Containers = %+v, want 1 container with 2 Instances", g.Runtime.Containers)
	}
	got := map[string]evidence.Usage{}
	for _, inst := range g.Runtime.Containers[0].Instances {
		got[inst.Target] = inst.Usage
	}
	if got["app/api"] != evidence.UsageInUse {
		t.Errorf("app/api Instance usage = %q, want in_use", got["app/api"])
	}
	if got["app/tool"] != evidence.UsageNotObserved {
		t.Errorf("app/tool Instance usage = %q, want not_observed", got["app/tool"])
	}
}

// TestAttachRuntime_TargetMissingInstanceMixed covers the projection rule
// for a *single* group whose Instances genuinely mix a Target-less element
// (ReasonBinaryPathUnknown) with one the Sensor did observe — the same
// vendored module found twice in one image, once at a path Trivy could
// report a Target for (app/api) and once where it could not (e.g. a
// statically-linked plugin object Trivy only identified by content, never a
// path). Both Instances share one PackageRef, so Build folds them into one
// PackageGroup with two Instances, not two groups: whichever branch of the
// projection rule fires, it fires on that single group's Runtime.
func TestAttachRuntime_TargetMissingInstanceMixed(t *testing.T) {
	newMixedScan := func(t *testing.T, apiRunning bool) (Report, evidence.Snapshot, GenerationInspect) {
		t.Helper()
		findMissing := scanner.Finding{
			Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
			InstalledVer: "v0.1.0", Status: scanner.StatusAffected,
			Severity: scanner.SeverityHigh, VulnID: "CVE-GO-1", Type: "gobinary", Target: "",
		}
		findAPI := findMissing
		findAPI.Target = "app/api"
		scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, findMissing, findAPI)}
		container := inventory.Container{
			ID: testContainerID, Name: "demo-1",
			Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
		}
		r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)
		gen := baseGeneration()
		if apiRunning {
			gen.Executables = []evidence.ExecutableEvidence{
				{Path: "/app/api", Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
					evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
				}, Observations: []evidence.ProcessObservation{
					{Exe: "/app/api", LastSeen: runtimeNow},
				}},
			}
		}
		snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
		insp := GenerationInspect{
			ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
			BootTime:    runtimeBootTime,
		}
		return r, snap, insp
	}

	t.Run("neither instance running", func(t *testing.T) {
		r, snap, insp := newMixedScan(t, false)
		g := pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")
		if len(g.Instances) != 2 {
			t.Fatalf("Instances = %+v, want 2 (missing-Target and app/api)", g.Instances)
		}
		AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
		g = pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")
		// The missing-Target Instance is unavailable/binary_path_unknown;
		// the app/api Instance is cleanly not_observed. evidence.ProjectGroup's
		// own order takes "observed nothing to conclude from" over a clean
		// not-observed, so the single group's Runtime is unavailable, never
		// not_observed.
		if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonBinaryPathUnknown {
			t.Fatalf("Runtime = %+v, want unavailable/binary_path_unknown", g.Runtime)
		}
	})

	t.Run("app/api instance running", func(t *testing.T) {
		r, snap, insp := newMixedScan(t, true)
		AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
		g := pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")
		// The app/api Instance is in_use; the missing-Target Instance is
		// still unavailable on its own. Any in-use Instance wins the whole
		// group regardless of what the other Instances say.
		if g.Runtime.Usage != evidence.UsageInUse {
			t.Fatalf("Runtime.Usage = %q, want in_use (any-in-use-wins over the group's other, unavailable Instance)", g.Runtime.Usage)
		}
	})
}

// TestAttachRuntime_EvidenceKindNeverMixedWithWrongExecutable covers a
// notable mixed case: the same Go module vendored into two binaries,
// /app/api (confirmed only by sampling: KindExe) and /app/tool (confirmed
// only by an exec event: KindExecEvent), with /app/tool the stronger
// same-sample/same-process combination (root, no user namespace) so it wins
// the representative-container selection. The winning source's own kind
// (binary_executed, from the exec event) must be shown paired with its own
// executable (/app/tool) — never api's binary_running kind attributed to
// tool's path, and never tool's binary_executed kind attributed to api's
// path.
func TestAttachRuntime_EvidenceKindNeverMixedWithWrongExecutable(t *testing.T) {
	findAPI := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
		InstalledVer: "v0.1.0", Status: scanner.StatusAffected,
		Severity: scanner.SeverityHigh, VulnID: "CVE-GO-1", Type: "gobinary", Target: "app/api",
	}
	findTool := findAPI
	findTool.Target = "app/tool"
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, findAPI, findTool)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")
	if len(g.Instances) != 2 {
		t.Fatalf("Instances = %+v, want 2 (app/api, app/tool)", g.Instances)
	}

	gen := baseGeneration()
	gen.Executables = []evidence.ExecutableEvidence{
		{Path: "/app/api", Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
		}, Observations: []evidence.ProcessObservation{
			{Exe: "/app/api", EffectiveUID: 1000, LastSeen: runtimeNow}, // ordinary UID: the weaker combo
		}},
		{Path: "/app/tool", Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExecEvent: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Count: 1},
		}, Observations: []evidence.ProcessObservation{
			{Exe: "/app/tool", EffectiveUID: 0, LastSeen: runtimeNow}, // root, no userns: the stronger combo
		}},
	}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g = pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")

	if g.Runtime.Usage != evidence.UsageInUse {
		t.Fatalf("Runtime.Usage = %q, want in_use", g.Runtime.Usage)
	}
	if len(g.Runtime.Containers) != 1 {
		t.Fatalf("Containers = %+v, want 1", g.Runtime.Containers)
	}
	rep := g.Runtime.Containers[0]
	if rep.Process.Exe != "/app/tool" {
		t.Fatalf("representative Process.Exe = %q, want /app/tool (the stronger combo)", rep.Process.Exe)
	}
	if len(rep.EvidenceKinds) != 1 || rep.EvidenceKinds[0] != evidence.KindBinaryExecuted {
		t.Errorf("representative EvidenceKinds = %v, want exactly [binary_executed] (tool's own kind, not api's binary_running)", rep.EvidenceKinds)
	}
}

// TestNormalizeRuntimePath_LeadingSlash covers the path-normalization
// contract: Trivy's Result.Target (no leading "/") and
// the Sensor's executables[].path (always a leading "/", a container-root-
// relative absolute path) must compare equal regardless of which form
// either side happens to carry.
func TestNormalizeRuntimePath_LeadingSlash(t *testing.T) {
	cases := []struct{ a, b string }{
		{"usr/local/bin/trivy", "/usr/local/bin/trivy"},
		{"/usr/local/bin/trivy", "usr/local/bin/trivy"},
		{"usr/local/bin/trivy", "usr/local/bin/trivy"},
		{"/usr/local/bin/trivy", "/usr/local/bin/trivy"},
	}
	for _, c := range cases {
		if normalizeRuntimePath(c.a) != normalizeRuntimePath(c.b) {
			t.Errorf("normalizeRuntimePath(%q)=%q != normalizeRuntimePath(%q)=%q", c.a, normalizeRuntimePath(c.a), c.b, normalizeRuntimePath(c.b))
		}
	}
	// A symlink is expected to have already been resolved to its target's
	// own path by the time it reaches this comparison: this
	// function itself does no resolution, it only strips one leading "/".
	if got := normalizeRuntimePath("/usr/bin/python3.11"); got != "usr/bin/python3.11" {
		t.Errorf("normalizeRuntimePath(resolved symlink) = %q, want the same path with the leading slash stripped", got)
	}
}

// TestAttachRuntime_HostSidePathNeverMatches guards against a host-side path
// (e.g. what /proc/<pid>/root/... or an overlay lower-dir path would look
// like) ever being treated as equal to a container-rooted Target: since
// JudgeEmbeddedBinary compares full normalized paths, a path with an extra
// host-visible prefix segment simply never matches a container-root path
// with the same suffix, and the group must fall back to not_observed rather
// than a false in_use.
func TestAttachRuntime_HostSidePathNeverMatches(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
		InstalledVer: "v0.1.0", Status: scanner.StatusAffected,
		Severity: scanner.SeverityHigh, VulnID: "CVE-GO-1", Type: "gobinary", Target: "app/api",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)

	gen := baseGeneration()
	// A host-visible path for the same file, e.g. what a naive /proc/<pid>/
	// root/-based read might have recorded — never what the Sensor's own
	// read contract actually produces, but exactly the mistake path
	// normalization must not paper over.
	gen.Executables = []evidence.ExecutableEvidence{
		{Path: "/proc/4242/root/app/api", Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
		}},
	}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")
	if g.Runtime.Usage != evidence.UsageNotObserved {
		t.Fatalf("Runtime.Usage = %q, want not_observed (host-side path must not match a container-root Target)", g.Runtime.Usage)
	}
}

// TestAttachRuntime_DifferentGenerationNeverInUse covers the
// generation-matching contract: an evidence generation whose init PID/
// starttime don't agree with what inspect reports right now is a different
// container generation (a restart, most likely) and must never be judged
// in_use even though it has evidence naming the exact package by name and
// version.
func TestAttachRuntime_DifferentGenerationNeverInUse(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)

	gen := baseGeneration()
	gen.OSPackages = []evidence.OSPackageEvidence{{
		Name: "openssl", Version: "3.0.7",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1}},
	}}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}

	// The currently-inspected container has a different Pid (a restart since
	// the Sensor last sampled this generation) — the evidence's own PID/
	// starttime never match this inspect.
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: {
			Pid: gen.Init.PID + 1, StartedAt: runtimeBootTime.Add(time.Duration(gen.Init.Starttime) * starttimeTick),
			Image: r.Watch[0].Subject.Key.Digest,
		}},
		BootTime: runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage == evidence.UsageInUse {
		t.Fatalf("Runtime.Usage = in_use, want anything but in_use for a mismatched generation")
	}
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonGenerationUnverified {
		t.Errorf("Runtime = %+v, want unavailable/generation_unverified", g.Runtime)
	}
}

// TestAttachRuntime_NoContainerObservedYieldsContainerNotObserved covers the
// empty-input case: an entity Build found no
// containers for at all (or none had a resolvable ID) projects to
// unavailable/container_not_observed, never a vacuous not_observed.
func TestAttachRuntime_NoContainerObservedYieldsContainerNotObserved(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	r := Build(scans, nil, Triage{}, runtimeNow)

	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor()}
	insp := GenerationInspect{ByContainer: map[string]docker.InspectResult{}, BootTime: runtimeBootTime}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonContainerNotObserved {
		t.Fatalf("Runtime = %+v, want unavailable/container_not_observed", g.Runtime)
	}
}

// TestAttachRuntime_SensorNotReportingMarksEveryGroupUnavailable and its
// sibling below cover RuntimeInfo's own short-circuit: a Sensor that has
// never reported, or whose evidence file failed validation, must never let
// AttachRuntime attempt generation matching at all (it has nothing
// trustworthy to match against), and every group must end up unavailable
// with the matching reason.
func TestAttachRuntime_SensorNotReportingMarksEveryGroupUnavailable(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	r := Build(scans, nil, Triage{}, runtimeNow)

	AttachRuntime(&r, RuntimeInfo{NotReporting: true, LoadFailed: true}, evidence.Snapshot{}, GenerationInspect{}, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonSensorNotReporting {
		t.Fatalf("Runtime = %+v, want unavailable/sensor_not_reporting", g.Runtime)
	}
	if r.Runtime == nil {
		t.Fatal("Report.Runtime is nil after AttachRuntime; want it set even when the Sensor is not reporting")
	}
}

func TestAttachRuntime_EvidenceInvalidMarksEveryGroupUnavailable(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	r := Build(scans, nil, Triage{}, runtimeNow)

	AttachRuntime(&r, RuntimeInfo{LoadFailed: true}, evidence.Snapshot{}, GenerationInspect{}, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonEvidenceInvalid {
		t.Fatalf("Runtime = %+v, want unavailable/evidence_invalid", g.Runtime)
	}
}

// TestAttachRuntime_OSPackageExactNameAndVersionMatch is the OS-package half
// of the judgement rule: a name/version match to a Finding is
// in_use, a name match with a different version is unavailable/
// version_mismatch (never a silent in_use or not_observed).
func TestAttachRuntime_OSPackageExactNameAndVersionMatch(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)

	gen := baseGeneration()
	gen.OSPackages = []evidence.OSPackageEvidence{{
		Name: "openssl", Version: "3.0.8", // different version than the Finding
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1}},
	}}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonVersionMismatch {
		t.Fatalf("Runtime = %+v, want unavailable/version_mismatch for a name match with a different version", g.Runtime)
	}
}

// TestAttachRuntime_OSPackageMultipleKindsFromDifferentProcessesNeverPaired
// covers the exact case an OS package's evidence record can produce: one
// process (/usr/bin/helper) is the package's own executable (exe), a
// completely different process (/app/server) merely maps the package's
// shared library (mapped_library) — both folded into the one
// OSPackageEvidence record's Kinds map and Observations list, since that
// record aggregates across every process that ever touched the package
// rather than keeping one process's own facts together the way an
// ExecutableEvidence record does. The representative container must report
// this as ambiguous, list both kinds, and list both observed executables
// without pairing either one to a specific kind.
func TestAttachRuntime_OSPackageMultipleKindsFromDifferentProcessesNeverPaired(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
		InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)

	gen := baseGeneration()
	gen.OSPackages = []evidence.OSPackageEvidence{{
		Name: "openssl", Version: "3.0.7",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExe:           {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
			evidence.KindMappedLibrary: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
		},
		Observations: []evidence.ProcessObservation{
			{Exe: "/usr/bin/helper", EffectiveUID: 1000, LastSeen: runtimeNow}, // ordinary UID: the weaker combo
			{Exe: "/app/server", EffectiveUID: 0, LastSeen: runtimeNow},        // root, no userns: the stronger combo
		},
	}}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "openssl")

	if g.Runtime.Usage != evidence.UsageInUse {
		t.Fatalf("Runtime.Usage = %q, want in_use", g.Runtime.Usage)
	}
	if len(g.Runtime.Containers) != 1 {
		t.Fatalf("Containers = %+v, want 1", g.Runtime.Containers)
	}
	rep := g.Runtime.Containers[0]
	if !rep.KindsAmbiguous {
		t.Fatal("KindsAmbiguous = false, want true for a record with 2 kinds aggregated across 2 processes")
	}
	if len(rep.EvidenceKinds) != 2 {
		t.Errorf("EvidenceKinds = %v, want both exe and mapped_library", rep.EvidenceKinds)
	}
	if want := []string{"/usr/bin/helper", "/app/server"}; !equalStrings(rep.ProcessExes, want) {
		t.Errorf("ProcessExes = %v, want %v (both observed processes, in Observations order)", rep.ProcessExes, want)
	}
	// The strongest combo (root, /app/server) still legitimately backs
	// Process/Exposure/HighPrivilege — that pairing (one specific
	// ProcessObservation's own facts) is not what is ambiguous.
	if !rep.HasProcess || rep.Process.Exe != "/app/server" {
		t.Errorf("Process = %+v, HasProcess=%v, want the strongest combo (/app/server, root)", rep.Process, rep.HasProcess)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAttachRuntime_KindsWithNoObservationNeverUsesGenerationLastVerifiedAt
// covers an in-use verdict whose only evidence is a Kinds entry with no
// ProcessObservation behind it at all (e.g. an exec_event the Sensor
// recorded without a same-sample identity snapshot): the "last confirmed"
// time shown must come from that kind's own LastSeen, never from the
// generation's own LastVerifiedAt (which can be arbitrarily more recent,
// from a completely unrelated sample), and no Process fact may be reported
// at all since none was ever observed.
func TestAttachRuntime_KindsWithNoObservationNeverUsesGenerationLastVerifiedAt(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
		InstalledVer: "v0.1.0", Status: scanner.StatusAffected,
		Severity: scanner.SeverityHigh, VulnID: "CVE-GO-1", Type: "gobinary", Target: "app/api",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)

	kindLastSeen := runtimeNow.Add(-2 * time.Hour)
	gen := baseGeneration()
	gen.LastVerifiedAt = runtimeNow // deliberately later/different than kindLastSeen below
	gen.Executables = []evidence.ExecutableEvidence{{
		Path:  "/app/api",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: kindLastSeen, LastSeen: kindLastSeen, Samples: 1}},
		// No Observations at all.
	}}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")

	if g.Runtime.Usage != evidence.UsageInUse {
		t.Fatalf("Runtime.Usage = %q, want in_use", g.Runtime.Usage)
	}
	if len(g.Runtime.Containers) != 1 {
		t.Fatalf("Containers = %+v, want 1", g.Runtime.Containers)
	}
	rep := g.Runtime.Containers[0]
	if rep.HasProcess {
		t.Errorf("HasProcess = true, want false: no ProcessObservation exists at all")
	}
	if rep.Process.Exe != "" || rep.Process.EffectiveUID != 0 || rep.Process.Userns || rep.Process.DangerousCaps != nil || rep.Process.Privileged {
		t.Errorf("Process = %+v, want the zero value", rep.Process)
	}
	if !rep.LastSeen.Equal(kindLastSeen) {
		t.Errorf("LastSeen = %v, want the kind's own LastSeen %v (never the generation's LastVerifiedAt %v)", rep.LastSeen, kindLastSeen, gen.LastVerifiedAt)
	}
	if len(rep.EvidenceKinds) != 1 || rep.EvidenceKinds[0] != evidence.KindBinaryRunning {
		t.Errorf("EvidenceKinds = %v, want [binary_running] carried through even with no observation behind it", rep.EvidenceKinds)
	}
}

// TestAttachRuntime_LanguageLastSeenIgnoresLoadOnlyKindTimestamp covers a
// language package's executable record that carries both an execution kind
// (exe) and a load kind (mapped_library) with different timestamps: the
// "last confirmed" time must come from exe alone (the kind langKindsOf
// actually turns into this package's display kind), never from
// mapped_library's own, later timestamp — mapped_library never backs a
// language package's in-use judgement at all (see hasExecutionEvidence),
// so its timestamp must not leak into what the judgement's own time claims.
func TestAttachRuntime_LanguageLastSeenIgnoresLoadOnlyKindTimestamp(t *testing.T) {
	find := scanner.Finding{
		Image: "demo:1.0", Class: scanner.ClassLang, Package: "golang.org/x/net",
		InstalledVer: "v0.1.0", Status: scanner.StatusAffected,
		Severity: scanner.SeverityHigh, VulnID: "CVE-GO-1", Type: "gobinary", Target: "app/api",
	}
	scans := []scanner.ImageScan{resolvedScan("demo:1.0", contentA, nil, find)}
	container := inventory.Container{
		ID: testContainerID, Name: "demo-1",
		Image: inventory.RunningImage{Ref: "demo:1.0", Config: configDigest(t, contentA)},
	}
	r := Build(scans, []inventory.Container{container}, Triage{}, runtimeNow)

	exeLastSeen := runtimeNow.Add(-4 * time.Hour)       // 08:00 in the review's example
	mappedLibLastSeen := runtimeNow.Add(-2 * time.Hour) // 10:00 in the review's example: later, but must be ignored
	gen := baseGeneration()
	gen.Executables = []evidence.ExecutableEvidence{{
		Path: "/app/api",
		Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExe:           {FirstSeen: exeLastSeen, LastSeen: exeLastSeen, Samples: 1},
			evidence.KindMappedLibrary: {FirstSeen: mappedLibLastSeen, LastSeen: mappedLibLastSeen, Samples: 1},
		},
		// No Observations at all: exercises the no-observation LastSeen path.
	}}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Watch[0].Subject)},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	g := pkgGroup(t, r.Watch, "demo:1.0", "golang.org/x/net")

	if g.Runtime.Usage != evidence.UsageInUse {
		t.Fatalf("Runtime.Usage = %q, want in_use", g.Runtime.Usage)
	}
	if len(g.Runtime.Containers) != 1 {
		t.Fatalf("Containers = %+v, want 1", g.Runtime.Containers)
	}
	rep := g.Runtime.Containers[0]
	if !rep.LastSeen.Equal(exeLastSeen) {
		t.Errorf("LastSeen = %v, want exe's own LastSeen %v (never mapped_library's later %v)", rep.LastSeen, exeLastSeen, mappedLibLastSeen)
	}
}
