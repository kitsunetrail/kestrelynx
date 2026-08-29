package analyze

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// TestBuild_NilContainersLeavesOutputUnchanged guards the "containers is an
// additive input" contract: every caller that predates the Environment/
// Workload model passes nil, and Build must produce exactly the shape it did
// before Containers existed (nil Containers everywhere, nothing else
// disturbed).
func TestBuild_NilContainersLeavesOutputUnchanged(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "libc-bin", "2.28-10", "2.28-10+deb10u2", scanner.StatusFixed, scanner.SeverityCritical, "CVE-1"),
		},
	}}
	r := Build(scans, nil, Triage{}, fixedTime)

	if len(r.Actionable) != 1 {
		t.Fatalf("Actionable = %+v, want 1 entry", r.Actionable)
	}
	if r.Actionable[0].Containers != nil {
		t.Errorf("ImageFindings.Containers = %+v, want nil when Build received no containers", r.Actionable[0].Containers)
	}
	o := imgObs(t, r.Images, "demo:1.0")
	if o.Containers != nil {
		t.Errorf("ImageObservation.Containers = %+v, want nil when Build received no containers", o.Containers)
	}
	if r.Environment != (inventory.Environment{}) {
		t.Errorf("Report.Environment = %+v, want the zero value (Build never sets it)", r.Environment)
	}
}

// TestBuild_ContainersAttachByEntityAndByRef exercises an Ambiguous
// reference (two distinct verified ContentIDs under one ref) to prove the
// entity-level join is exact: each ImageFindings entry gets only the
// containers running its own ContentID, while ImageObservation gets the
// union across both.
func TestBuild_ContainersAttachByEntityAndByRef(t *testing.T) {
	pipA := f("web:1", scanner.ClassLang, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-A")
	pipB := f("web:1", scanner.ClassLang, "pip", "1.0.0", "1.0.1", scanner.StatusFixed, scanner.SeverityHigh, "CVE-B")
	scans := []scanner.ImageScan{
		resolvedScan("web:1", contentA, nil, pipA),
		resolvedScan("web:1", contentB, nil, pipB),
	}
	ctrA := inventory.Container{Name: "web-a", Image: inventory.RunningImage{Ref: "web:1", ContentID: contentA}}
	ctrB1 := inventory.Container{Name: "web-b1", Image: inventory.RunningImage{Ref: "web:1", ContentID: contentB}}
	ctrB2 := inventory.Container{Name: "web-b2", Image: inventory.RunningImage{Ref: "web:1", ContentID: contentB}}
	other := inventory.Container{Name: "other", Image: inventory.RunningImage{Ref: "other:1", ContentID: contentA}}
	containers := []inventory.Container{ctrA, ctrB1, ctrB2, other}

	r := Build(scans, containers, Triage{}, fixedTime)

	if len(r.Actionable) != 2 {
		t.Fatalf("Actionable = %+v, want 2 entries (one per ContentID)", r.Actionable)
	}
	var byContentID = map[string]ImageFindings{}
	for _, e := range r.Actionable {
		byContentID[e.ContentID] = e
	}
	entA, ok := byContentID[contentA]
	if !ok {
		t.Fatalf("no ImageFindings entry for contentA in %+v", r.Actionable)
	}
	if len(entA.Containers) != 1 || entA.Containers[0].Name != "web-a" {
		t.Errorf("contentA entity Containers = %+v, want exactly [web-a]", entA.Containers)
	}
	entB, ok := byContentID[contentB]
	if !ok {
		t.Fatalf("no ImageFindings entry for contentB in %+v", r.Actionable)
	}
	if len(entB.Containers) != 2 {
		t.Fatalf("contentB entity Containers = %+v, want 2 (web-b1, web-b2)", entB.Containers)
	}
	names := map[string]bool{}
	for _, c := range entB.Containers {
		names[c.Name] = true
	}
	if !names["web-b1"] || !names["web-b2"] {
		t.Errorf("contentB entity Containers = %+v, want web-b1 and web-b2", entB.Containers)
	}

	o := imgObs(t, r.Images, "web:1")
	if len(o.Containers) != 3 {
		t.Fatalf("ImageObservation.Containers = %+v, want the 3-container union across both entities", o.Containers)
	}
	unionNames := map[string]bool{}
	for _, c := range o.Containers {
		unionNames[c.Name] = true
	}
	if !unionNames["web-a"] || !unionNames["web-b1"] || !unionNames["web-b2"] {
		t.Errorf("ImageObservation.Containers = %+v, want web-a, web-b1, web-b2", o.Containers)
	}
	if unionNames["other"] {
		t.Errorf("ImageObservation.Containers leaked a container from a different ref: %+v", o.Containers)
	}
}

// TestBuild_ContainersUnresolvedEntityMatchesByRefOnly exercises a ref that
// carries both a resolved entity and an unresolved (reference-fallback,
// ContentID == "") entity at once — the same shape as an Ambiguous
// reference's split, but with one side never having resolved an identity.
// The unresolved ImageFindings entry must attach only the container whose
// own Image.ContentID is likewise empty, and the resolved entry only the
// container running its matching ContentID: a join that degraded to
// "match by ref alone" would attach both containers to both entries and
// fail this test.
func TestBuild_ContainersUnresolvedEntityMatchesByRefOnly(t *testing.T) {
	scans := []scanner.ImageScan{
		resolvedScan("legacy:1", contentA, nil,
			f("legacy:1", scanner.ClassOS, "libc", "1", "2", scanner.StatusFixed, scanner.SeverityHigh, "CVE-1")),
		{
			Image: "legacy:1", // no ExpectedContentID: reference-fallback
			Findings: []scanner.Finding{
				f("legacy:1", scanner.ClassOS, "zlib", "1", "2", scanner.StatusFixed, scanner.SeverityHigh, "CVE-2"),
			},
		},
	}
	resolved := inventory.Container{Name: "legacy-resolved", Image: inventory.RunningImage{Ref: "legacy:1", ContentID: contentA}}
	unresolved := inventory.Container{Name: "legacy-unresolved", Image: inventory.RunningImage{Ref: "legacy:1"}}
	containers := []inventory.Container{resolved, unresolved}

	r := Build(scans, containers, Triage{}, fixedTime)

	if len(r.Actionable) != 2 {
		t.Fatalf("Actionable = %+v, want 2 entries (resolved + unresolved)", r.Actionable)
	}
	byContentID := map[string]ImageFindings{}
	for _, e := range r.Actionable {
		byContentID[e.ContentID] = e
	}
	resolvedEnt, ok := byContentID[contentA]
	if !ok {
		t.Fatalf("no resolved entry (ContentID %s) in %+v", contentA, r.Actionable)
	}
	if len(resolvedEnt.Containers) != 1 || resolvedEnt.Containers[0].Name != "legacy-resolved" {
		t.Errorf("resolved entry Containers = %+v, want exactly [legacy-resolved]", resolvedEnt.Containers)
	}
	unresolvedEnt, ok := byContentID[""]
	if !ok {
		t.Fatalf("no unresolved entry (empty ContentID) in %+v", r.Actionable)
	}
	if len(unresolvedEnt.Containers) != 1 || unresolvedEnt.Containers[0].Name != "legacy-unresolved" {
		t.Errorf("unresolved entry Containers = %+v, want exactly [legacy-unresolved]", unresolvedEnt.Containers)
	}
}

// TestBuild_ContainersEmptyRefExcluded guards the same "nothing to scan"
// rule DistinctImages already applies: a container with no Ref must never
// join any entity or reference-level union.
func TestBuild_ContainersEmptyRefExcluded(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			f("demo:1.0", scanner.ClassOS, "libc-bin", "1", "2", scanner.StatusFixed, scanner.SeverityHigh, "CVE-1"),
		},
	}}
	containers := []inventory.Container{{Name: "no-ref"}} // Image.Ref == ""

	r := Build(scans, containers, Triage{}, fixedTime)

	if len(r.Actionable) != 1 || r.Actionable[0].Containers != nil {
		t.Errorf("Actionable = %+v, want the sole entry to carry no containers", r.Actionable)
	}
	o := imgObs(t, r.Images, "demo:1.0")
	if o.Containers != nil {
		t.Errorf("ImageObservation.Containers = %+v, want nil (no container had a matching ref)", o.Containers)
	}
}
