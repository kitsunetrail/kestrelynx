// Tests for the three-cycle "unconfirmed" scenarios the identity model's
// registry-fetch path (ScanSource == remote) introduces: an unpinned but
// successful scan must never let state quietly drop or falsely resolve a
// finding a previous, pinned cycle established — and Docker (ScanSource ==
// local) must go on behaving exactly as it always has, since it never
// produces an unconfirmed result this way.
package state

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// remotePinnedScan builds the shape a confirmed remote (registry) scan
// produces: Source == remote, Pinned == true.
func remotePinnedScan(ref, contentID string, finds ...scanner.Finding) scanner.ImageScan {
	scan := resolvedScan(ref, contentID, finds...)
	scan.Source = scanner.SourceRemote
	return scan
}

// remoteUnconfirmedScan builds the shape a remote scan that could not be
// pinned produces: Source == remote, Pinned == false, Err == nil (the scan
// itself succeeded — it just can't vouch for which entity it actually saw).
func remoteUnconfirmedScan(ref string, finds ...scanner.Finding) scanner.ImageScan {
	return scanner.ImageScan{Image: ref, Pinned: false, Source: scanner.SourceRemote, Findings: finds}
}

// Scenario 1: an unconfirmed cycle that happens to see fewer CVEs than a
// prior pinned cycle must not lose the ones it didn't see, and a pin
// recovering afterward must not misreport them as new.
func TestCompute_UnconfirmedScenario1_CVEUnionRetainedAcrossUnconfirmedCycle(t *testing.T) {
	cveA := finding("web:1", "openssl", "CVE-A", scanner.StatusFixed)
	cveB := finding("web:1", "openssl", "CVE-B", scanner.StatusFixed)

	// Cycle 1: pinned, both CVEs present.
	_, st1 := Compute(empty(), report(day1, remotePinnedScan("web:1", contentA, cveA, cveB)))
	if e := st1.Findings["web:1\topenssl"]; len(e.VulnIDs) != 2 {
		t.Fatalf("cycle1 VulnIDs = %v, want both CVEs", e.VulnIDs)
	}

	// Cycle 2: unconfirmed fallback only turns up CVE-B.
	d2, st2 := Compute(st1, report(day2, remoteUnconfirmedScan("web:1", cveB)))
	if d2.HasChanges() {
		t.Errorf("cycle2: an unconfirmed cycle must not report any change, got %+v", d2)
	}
	e2 := st2.Findings["web:1\topenssl"]
	if len(e2.VulnIDs) != 2 || e2.VulnIDs[0] != "CVE-A" || e2.VulnIDs[1] != "CVE-B" {
		t.Errorf("cycle2: VulnIDs = %v, want the union [CVE-A CVE-B] retained despite the unconfirmed cycle", e2.VulnIDs)
	}
	if !e2.Fixable {
		t.Error("cycle2: Fixable should remain true via the conservative merge")
	}

	// Cycle 3: pin recovers with both CVEs again.
	d3, st3 := Compute(st2, report(day2.AddDate(0, 0, 1), remotePinnedScan("web:1", contentA, cveA, cveB)))
	for _, c := range d3.Changes {
		if c.Package == "openssl" {
			t.Errorf("cycle3: openssl must not appear as any Change kind (esp. new_cves) once the pin recovers, got %+v", c)
		}
	}
	e3 := st3.Findings["web:1\topenssl"]
	if !e3.FirstSeen.Equal(day1) {
		t.Errorf("cycle3: FirstSeen = %v, want preserved %v (no re-announcement)", e3.FirstSeen, day1)
	}
	if len(e3.VulnIDs) != 2 {
		t.Errorf("cycle3: VulnIDs = %v, want both CVEs still on record", e3.VulnIDs)
	}
}

// TestCompute_UnconfirmedScenario1_PriorityAndFixableDoNotRegress is scenario
// 1's triage variant: an unconfirmed cycle that only turns up the
// lower-priority half of a package's CVEs must not let the stored priority or
// fixability regress, mirroring the existing Err-based partial-failure merge
// but exercised through the unconfirmed (remote, not pinned, no Err) path.
func TestCompute_UnconfirmedScenario1_PriorityAndFixableDoNotRegress(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-B": {KEV: true}} // B is act_now; A is not
	cveA := finding("web:1", "openssl", "CVE-A", scanner.StatusAffected)
	cveB := finding("web:1", "openssl", "CVE-B", scanner.StatusFixed)

	// Cycle 1: pinned, both CVEs present — act_now (B's KEV) and fixable (B).
	_, st1 := Compute(empty(), triaged(day1, enrich, remotePinnedScan("web:1", contentA, cveA, cveB)))
	e1 := st1.Findings["web:1\topenssl"]
	if len(e1.VulnIDs) != 2 || e1.Priority != string(analyze.PriorityActNow) || !e1.Fixable {
		t.Fatalf("cycle1 openssl = %+v, want both CVEs, act_now, fixable", e1)
	}

	// Cycle 2: unconfirmed fallback only turns up CVE-A (unfixed, non-KEV) —
	// the merge must keep CVE-B, act_now, and Fixable=true alive.
	d2, st2 := Compute(st1, triaged(day2, enrich, remoteUnconfirmedScan("web:1", cveA)))
	if d2.HasChanges() {
		t.Errorf("cycle2: an unconfirmed cycle must not report any change, got %+v", d2)
	}
	e2 := st2.Findings["web:1\topenssl"]
	if len(e2.VulnIDs) != 2 || e2.VulnIDs[0] != "CVE-A" || e2.VulnIDs[1] != "CVE-B" {
		t.Errorf("cycle2: VulnIDs = %v, want the merge to preserve [CVE-A CVE-B]", e2.VulnIDs)
	}
	if e2.Priority != string(analyze.PriorityActNow) {
		t.Errorf("cycle2: Priority = %q, want the merge to preserve act_now", e2.Priority)
	}
	if !e2.Fixable {
		t.Error("cycle2: Fixable should stay true via the merge")
	}

	// Cycle 3: pin recovers with the exact same finding as cycle 1 — nothing
	// must misfire as new/new_cves/now_fixable/escalated.
	d3, st3 := Compute(st2, triaged(day2.AddDate(0, 0, 1), enrich, remotePinnedScan("web:1", contentA, cveA, cveB)))
	if d3.HasChanges() {
		t.Errorf("cycle3: B's recovery must not misfire any change, got %+v", d3)
	}
	e3 := st3.Findings["web:1\topenssl"]
	if !e3.FirstSeen.Equal(day1) {
		t.Errorf("cycle3: FirstSeen = %v, want preserved %v", e3.FirstSeen, day1)
	}
	if !e3.Fixable {
		t.Error("cycle3: Fixable should still be true after B's recovery")
	}
}

// Scenario 2: an unconfirmed cycle that happens to see zero findings must
// not report the finding as Resolved — only a genuinely pinned, clean cycle
// may do that, and it must do so exactly once.
func TestCompute_UnconfirmedScenario2_NoFalseResolveUntilReallyConfirmedClean(t *testing.T) {
	cveA := finding("web:1", "openssl", "CVE-A", scanner.StatusFixed)

	// Cycle 1: pinned, finding present.
	_, st1 := Compute(empty(), report(day1, remotePinnedScan("web:1", contentA, cveA)))

	// Cycle 2: unconfirmed, and this cycle's scan happens to turn up nothing.
	d2, st2 := Compute(st1, report(day2, remoteUnconfirmedScan("web:1")))
	if len(d2.Resolved) != 0 {
		t.Errorf("cycle2: an unconfirmed cycle must never report Resolved, got %+v", d2.Resolved)
	}
	if _, ok := st2.Findings["web:1\topenssl"]; !ok {
		t.Error("cycle2: the finding must be carried over, not dropped, during an unconfirmed cycle")
	}

	// Cycle 3: pin recovers and genuinely finds nothing — Resolved fires once.
	d3, st3 := Compute(st2, report(day2.AddDate(0, 0, 1), remotePinnedScan("web:1", contentA)))
	if len(d3.Resolved) != 1 || d3.Resolved[0].Package != "openssl" {
		t.Fatalf("cycle3: Resolved = %+v, want exactly one entry for openssl", d3.Resolved)
	}
	if _, ok := st3.Findings["web:1\topenssl"]; ok {
		t.Error("cycle3: the finding must leave state once genuinely confirmed clean")
	}
}

// Scenario 3: the same three-cycle shape run over Docker (Source == local)
// must keep behaving exactly as before — no merge on an unpinned cycle, and
// a CVE dropped by that cycle really does come back as new_cves. This is the
// deliberate contrast with scenario 1: local's own reference-fallback path
// was never meant to carry the "unconfirmed" protection, since Docker has no
// mutable registry tag to be fooled by.
func TestCompute_UnconfirmedScenario3_DockerNeverMergesOnUnpinnedFallback(t *testing.T) {
	cveA := finding("web:1", "openssl", "CVE-A", scanner.StatusFixed)
	cveB := finding("web:1", "openssl", "CVE-B", scanner.StatusFixed)

	// Cycle 1: Docker resolves and scans successfully; both CVEs present.
	_, st1 := Compute(empty(), report(day1, resolvedScan("web:1", contentA, cveA, cveB)))

	// Cycle 2: Docker's own reference-fallback shape (Source local, unpinned,
	// no Err) must not be treated as unconfirmed, so no merge happens: the
	// raw (unmerged) view for this cycle replaces the stored VulnIDs.
	dockerFallback := scanner.ImageScan{Image: "web:1", Pinned: false, Source: scanner.SourceLocal, Findings: []scanner.Finding{cveB}}
	d2, st2 := Compute(st1, report(day2, dockerFallback))
	e2 := st2.Findings["web:1\topenssl"]
	if len(e2.VulnIDs) != 1 || e2.VulnIDs[0] != "CVE-B" {
		t.Errorf("cycle2: VulnIDs = %v, want just [CVE-B] (current Docker behavior: no merge)", e2.VulnIDs)
	}
	if d2.HasChanges() {
		t.Errorf("cycle2: no new/resolved change expected (CVE-B already known), got %+v", d2)
	}

	// Cycle 3: both CVEs reappear — CVE-A must now report as new_cves, since
	// cycle 2 already dropped it from state (contrast with scenario 1, which
	// retains it across the remote-unconfirmed cycle).
	d3, _ := Compute(st2, report(day2.AddDate(0, 0, 1), resolvedScan("web:1", contentA, cveA, cveB)))
	var sawNewCVEs bool
	for _, c := range d3.Changes {
		if c.Package == "openssl" && c.Kind == KindNewCVEs {
			sawNewCVEs = true
		}
	}
	if !sawNewCVEs {
		t.Errorf("cycle3: expected KindNewCVEs for openssl (Docker path does not retain CVE-A across the unpinned cycle), got %+v", d3.Changes)
	}
}
