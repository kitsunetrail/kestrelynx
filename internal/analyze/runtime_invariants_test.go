package analyze

import (
	"reflect"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// buildRuntimeInvariantScans is the shared fixture for every invariant test
// below: two images, three packages, spread across act_now (KEV), watch
// (EPSS above the watch threshold) and low (no signal) so every priority
// bucket is exercised by the same input regardless of what runtime
// evidence — if any — is later attached.
func buildRuntimeInvariantScans() []scanner.ImageScan {
	return []scanner.ImageScan{
		resolvedScan("web:1.0", contentA, nil,
			scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
			scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "curl", InstalledVer: "7.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-2"},
		),
		resolvedScan("api:2.0", contentB, nil,
			scanner.Finding{Image: "api:2.0", Class: scanner.ClassLang, Package: "setuptools", InstalledVer: "1.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-3", Type: "python-pkg"},
		),
	}
}

func runtimeInvariantEnrich() map[string]Enrichment {
	return map[string]Enrichment{
		"CVE-1": {KEV: true},                    // act_now
		"CVE-2": {EPSS: 0.02, EPSSKnown: true},  // watch
		"CVE-3": {EPSS: 0.001, EPSSKnown: true}, // low
	}
}

func runtimeInvariantContainers(t *testing.T) []inventory.Container {
	t.Helper()
	return []inventory.Container{
		{ID: testContainerID, Name: "web-1", Image: inventory.RunningImage{Ref: "web:1.0", Config: configDigest(t, contentA)}},
		{ID: strings40("b"), Name: "api-1", Image: inventory.RunningImage{Ref: "api:2.0", Config: configDigest(t, contentB)}},
	}
}

// strings40 pads c into a well-formed 64-hex container ID, distinct from
// testContainerID (which is all "a").
func strings40(c string) string {
	out := ""
	for len(out) < 64 {
		out += c
	}
	return out
}

// priorityCountsSnapshot captures ByPriority()'s bucket sizes and every
// group's own Priority, keyed by (image, package) — everything that must
// never move because of runtime evidence.
type prioritySnapshot struct {
	actNow, watch, low int
	priorities         map[string]Priority
	sectionLens        [4]int // Actionable, Watch, WontFix, EOLPackages
}

func snapshotPriorities(r Report) prioritySnapshot {
	pv := r.ByPriority()
	s := prioritySnapshot{
		actNow: GroupCount(pv.ActNow), watch: GroupCount(pv.Watch), low: GroupCount(pv.Low),
		priorities: map[string]Priority{},
	}
	for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			for _, g := range img.Packages {
				s.priorities[img.Image+"\t"+g.Package] = g.Priority
			}
		}
	}
	s.sectionLens = [4]int{len(r.Actionable), len(r.Watch), len(r.WontFix), len(r.EOLPackages)}
	return s
}

// TestRuntimeInvariant_PriorityCountsAndSectionsUnaffected checks the first
// two ordering invariants: attaching runtime evidence — in_use, not_observed
// and unavailable all mixed in — must never change any VulnRef/PackageGroup
// Priority, any ByPriority() bucket's group count, or any status section's
// length.
func TestRuntimeInvariant_PriorityCountsAndSectionsUnaffected(t *testing.T) {
	scans := buildRuntimeInvariantScans()
	containers := runtimeInvariantContainers(t)

	before := Build(scans, containers, tr(runtimeInvariantEnrich()), runtimeNow)
	beforeSnap := snapshotPriorities(before)

	after := Build(scans, containers, tr(runtimeInvariantEnrich()), runtimeNow)
	genWeb := baseGeneration()
	genWeb.OSPackages = []evidence.OSPackageEvidence{
		{Name: "openssl", Version: "3.0.7", Kinds: map[evidence.EvidenceKind]evidence.KindObservation{evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1}}},
		// curl: no matching OSPackageEvidence and no Unavailable entry -> not_observed.
	}
	genAPI := baseGeneration()
	genAPI.Container.ID = strings40("b")
	// StateDenied blocks both classes (GenerationEligibleForNotObserved):
	// unlike parse_failed/initializing, which only hold up the OS class, a
	// denied generation gives language-package judgement nothing to work
	// with either, so setuptools ends up unavailable rather than
	// not_observed.
	genAPI.State = evidence.StateDenied

	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{genWeb, genAPI}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			testContainerID: matchedInspect(genWeb, subjectFor(after, "web:1.0")),
			strings40("b"):  matchedInspect(genAPI, subjectFor(after, "api:2.0")),
		},
		BootTime: runtimeBootTime,
	}
	AttachRuntime(&after, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	afterSnap := snapshotPriorities(after)

	if !reflect.DeepEqual(beforeSnap, afterSnap) {
		t.Fatalf("runtime attachment changed priority/count/section shape:\nbefore: %+v\nafter:  %+v", beforeSnap, afterSnap)
	}

	// Sanity: the fixture actually produced a mix of in_use/not_observed/
	// unavailable, otherwise this test would pass vacuously.
	g := pkgGroup(t, after.Watch, "web:1.0", "openssl")
	if g.Runtime.Usage != evidence.UsageInUse {
		t.Fatalf("fixture sanity: openssl Runtime.Usage = %q, want in_use", g.Runtime.Usage)
	}
	g = pkgGroup(t, after.Watch, "web:1.0", "curl")
	if g.Runtime.Usage != evidence.UsageNotObserved {
		t.Fatalf("fixture sanity: curl Runtime.Usage = %q, want not_observed", g.Runtime.Usage)
	}
	g = pkgGroup(t, after.Watch, "api:2.0", "setuptools")
	if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != evidence.ReasonPermissionDenied {
		t.Fatalf("fixture sanity: setuptools Runtime = %+v, want unavailable/permission_denied", g.Runtime)
	}
}

// subjectFor returns the Subject of image's single ImageFindings entry in
// r.Watch, for tests that need it to build a matching inspect.
func subjectFor(r Report, image string) inventory.ImageSubject {
	for _, img := range r.Watch {
		if img.Image == image {
			return img.Subject
		}
	}
	return inventory.ImageSubject{}
}

// TestRuntimeInvariant_AllNegativeDoesNotChangeOrder checks the third
// ordering invariant: when every package group ends up not_observed or
// unavailable (never in_use), the priority-view order must be identical to
// runtime being disabled entirely — a negative result must never itself
// become a sort key.
func TestRuntimeInvariant_AllNegativeDoesNotChangeOrder(t *testing.T) {
	scans := buildRuntimeInvariantScans()
	containers := runtimeInvariantContainers(t)

	disabled := Build(scans, containers, tr(runtimeInvariantEnrich()), runtimeNow)
	disabledOrder := priorityOrder(disabled.ByPriority())

	withRuntime := Build(scans, containers, tr(runtimeInvariantEnrich()), runtimeNow)
	// No generations at all -> every group is unavailable/container_not_observed
	// (or sensor_not_reporting, equally negative) — never in_use.
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor()}
	insp := GenerationInspect{ByContainer: map[string]docker.InspectResult{}, BootTime: runtimeBootTime}
	AttachRuntime(&withRuntime, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	runtimeOrder := priorityOrder(withRuntime.ByPriority())

	if !reflect.DeepEqual(disabledOrder, runtimeOrder) {
		t.Fatalf("all-negative runtime evidence changed priority-view order:\ndisabled: %+v\nruntime:  %+v", disabledOrder, runtimeOrder)
	}
}

// priorityOrder flattens a PriorityView into the (image, package) sequence
// every bucket renders in, for an order-sensitive comparison.
func priorityOrder(pv PriorityView) [3][]string {
	flatten := func(imgs []ImageFindings) []string {
		var out []string
		for _, img := range imgs {
			for _, g := range img.Packages {
				out = append(out, img.Image+"\t"+g.Package)
			}
		}
		return out
	}
	return [3][]string{flatten(pv.ActNow), flatten(pv.Watch), flatten(pv.Low)}
}

// TestRuntimeInvariant_MalformedEvidenceDoesNotPanic feeds AttachRuntime an
// adversarial snapshot — a generation for a runtime this schema doesn't
// recognize, an empty container ID, a zero BootTime, a nil inspect map —
// and only asserts it returns without panicking and leaves every group in
// some UnavailableReason, never in_use: the read-time validation that
// rejects a genuinely malformed evidence file lives in internal/evidence
// (already covered by its own tests); this test is about AttachRuntime's
// own robustness once a *structurally valid but unhelpful* snapshot reaches
// it (an empty snapshot is exactly what a freshly-started Sensor, or one
// whose container ID this cycle simply isn't there yet, would produce).
func TestRuntimeInvariant_MalformedEvidenceDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("AttachRuntime panicked: %v", r)
		}
	}()

	scans := buildRuntimeInvariantScans()
	containers := runtimeInvariantContainers(t)
	r := Build(scans, containers, tr(runtimeInvariantEnrich()), runtimeNow)

	snap := evidence.Snapshot{
		Schema: evidence.Schema,
		Sensor: okSensor(),
		Generations: []evidence.Generation{
			{Container: evidence.ContainerRef{Runtime: "kubernetes", ID: testContainerID}}, // wrong runtime value
			{Container: evidence.ContainerRef{Runtime: "docker", ID: ""}},                  // empty ID
		},
	}
	insp := GenerationInspect{ByContainer: nil, BootTime: time.Time{}} // nil map, zero BootTime
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)

	for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			for _, g := range img.Packages {
				if g.Runtime.Usage == evidence.UsageInUse {
					t.Errorf("%s/%s: Runtime.Usage = in_use from a malformed/empty snapshot, want anything else", img.Image, g.Package)
				}
			}
		}
	}
}
