package state

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// TestCompute_EcosystemCollisionMergedUnderStateKey pins the contract the
// PackageRef aggregation relies on: analyze now aggregates by PackageRef (name+ecosystem+version),
// so an OS package and a same-named language package become two distinct
// analyze.PackageGroup entries — but state's own key stays (image, package
// name) unchanged, and mergeSections must fold the two groups back together
// under that one key rather than the second one silently overwriting the
// first, or the two producing two separate state entries (which would
// change the persisted format's key space).
func TestCompute_EcosystemCollisionMergedUnderStateKey(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{
				Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl",
				InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh,
				VulnID: "CVE-OS-1", Type: "debian",
			},
			{
				Image: "demo:1.0", Class: scanner.ClassLang, Package: "openssl",
				InstalledVer: "0.10.55", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical,
				VulnID: "CVE-RUST-1", Type: "cargo",
			},
		},
	}}
	r := analyze.Build(scans, nil, analyze.Triage{}, day1)

	// analyze itself must keep them separate: this is the regression the
	// PackageRef aggregation fixes, re-asserted here as the premise mergeSections is
	// tested against (analyze/package_ref_test.go covers it directly).
	if len(r.Watch) != 1 || len(r.Watch[0].Packages) != 2 {
		t.Fatalf("premise failed: r.Watch = %+v, want 1 image with 2 package groups", r.Watch)
	}

	d, next := Compute(State{}, r)

	// Exactly one state entry under the (image, package-name) key — not two.
	if len(next.Findings) != 1 {
		t.Fatalf("len(next.Findings) = %d, want 1 (mergeSections must fold both groups under one key)", len(next.Findings))
	}
	entry, ok := next.Findings[key("demo:1.0", "openssl")]
	if !ok {
		t.Fatalf("no entry under key(demo:1.0, openssl); got keys %v", func() []string {
			var ks []string
			for k := range next.Findings {
				ks = append(ks, k)
			}
			return ks
		}())
	}
	// Both CVEs (one from each colliding group) must be present — a naive
	// last-write-wins merge would drop one.
	if len(entry.VulnIDs) != 2 {
		t.Fatalf("entry.VulnIDs = %v, want both CVE-OS-1 and CVE-RUST-1", entry.VulnIDs)
	}

	// Exactly one diff.Change for this cycle's first sighting, and its
	// Groups slice carries both analyze.PackageGroup entries (this is what
	// notify's ecosystems field is built from — see
	// internal/notify/package_ref_test.go).
	if len(d.Changes) != 1 {
		t.Fatalf("len(d.Changes) = %d, want 1", len(d.Changes))
	}
	c := d.Changes[0]
	if c.Package != "openssl" || c.Image != "demo:1.0" {
		t.Fatalf("change = %+v, want image demo:1.0 package openssl", c)
	}
	if len(c.Groups) != 2 {
		t.Fatalf("len(c.Groups) = %d, want 2 (both the OS and the cargo group)", len(c.Groups))
	}
}
