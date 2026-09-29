package state

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

var (
	day1 = time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)
	day2 = time.Date(2026, 6, 25, 9, 0, 0, 0, time.UTC)
)

func report(t time.Time, scans ...scanner.ImageScan) analyze.Report {
	return analyze.Build(scans, nil, analyze.Triage{}, t)
}

func finding(image, pkg, vulnID string, status scanner.Status) scanner.Finding {
	fixed := ""
	if status == scanner.StatusFixed {
		fixed = "2.0.0"
	}
	return scanner.Finding{
		Image: image, Class: scanner.ClassLang, Package: pkg,
		InstalledVer: "1.0.0", FixedVer: fixed, Status: status,
		Severity: scanner.SeverityHigh, VulnID: vulnID,
	}
}

func TestFileStore_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json")
	store := FileStore{Path: path}

	// Missing file loads as empty without error.
	st, err := store.Load()
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if len(st.Findings) != 0 {
		t.Errorf("expected empty state, got %d findings", len(st.Findings))
	}

	st.Findings["img\tpkg"] = Entry{FirstSeen: day1, Fixable: true, VulnIDs: []string{"CVE-1"}}
	st.EOSL["img"] = day1
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := got.Findings["img\tpkg"]
	if !e.FirstSeen.Equal(day1) || !e.Fixable || len(e.VulnIDs) != 1 {
		t.Errorf("roundtrip entry = %+v", e)
	}
	if !got.EOSL["img"].Equal(day1) {
		t.Errorf("roundtrip EOSL = %+v", got.EOSL)
	}
}

func TestFileStore_CorruptFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Path: path}).Load(); err == nil {
		t.Fatal("corrupt state should surface an error")
	}
}

func TestFileStore_VersionMismatchIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"version": 99, "findings": {"a\tb": {}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := (FileStore{Path: path}).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(st.Findings) != 0 {
		t.Error("version mismatch should discard old state")
	}
}

func TestCompute_FirstRunAllNew(t *testing.T) {
	r := report(day1, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}})
	d, next := Compute(empty(), r)

	if len(d.Changes) != 1 || d.Changes[0].Kind != KindNew {
		t.Fatalf("Changes = %+v, want one KindNew", d.Changes)
	}
	if d.Changes[0].Image != "web:1" || d.Changes[0].Package != "openssl" {
		t.Errorf("change identity = %+v", d.Changes[0])
	}
	if len(d.Resolved) != 0 {
		t.Errorf("Resolved = %+v, want none", d.Resolved)
	}
	e := next.Findings["web:1\topenssl"]
	if !e.FirstSeen.Equal(day1) || !e.Fixable {
		t.Errorf("next entry = %+v", e)
	}
	if d.OpenHigh != 1 || d.OpenCritical != 0 || d.OpenImages != 1 {
		t.Errorf("open counts = %+v", d)
	}
}

func TestCompute_UnchangedKeepsFirstSeenAndNoChanges(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}}
	_, st := Compute(empty(), report(day1, scan))
	d, next := Compute(st, report(day2, scan))

	if d.HasChanges() {
		t.Errorf("unchanged scan should have no changes: %+v", d)
	}
	if got := next.Findings["web:1\topenssl"].FirstSeen; !got.Equal(day1) {
		t.Errorf("FirstSeen = %v, want preserved %v", got, day1)
	}
	if !d.OldestOpen.Equal(day1) {
		t.Errorf("OldestOpen = %v, want %v", d.OldestOpen, day1)
	}
	if d.OldestOpenDays(day2) != 1 {
		t.Errorf("OldestOpenDays = %d, want 1", d.OldestOpenDays(day2))
	}
}

func TestCompute_NewCVEOnKnownPackage(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}}))
	d, _ := Compute(st, report(day2, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
		finding("web:1", "openssl", "CVE-2", scanner.StatusFixed),
	}}))

	if len(d.Changes) != 1 || d.Changes[0].Kind != KindNewCVEs || d.Changes[0].NewCVEs != 1 {
		t.Fatalf("Changes = %+v, want one KindNewCVEs with 1 new", d.Changes)
	}
}

// TestCompute_NewCVEsCarriesTheNewIDs checks NewIDs itself, not just the
// count: only ids absent from the previous scan, sorted the same way
// analyze.PackageGroup.VulnIDs is.
func TestCompute_NewCVEsCarriesTheNewIDs(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-2", scanner.StatusFixed),
		finding("web:1", "openssl", "CVE-4", scanner.StatusFixed),
	}}))
	d, _ := Compute(st, report(day2, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
		finding("web:1", "openssl", "CVE-2", scanner.StatusFixed),
		finding("web:1", "openssl", "CVE-3", scanner.StatusFixed),
		finding("web:1", "openssl", "CVE-4", scanner.StatusFixed),
	}}))

	if len(d.Changes) != 1 || d.Changes[0].Kind != KindNewCVEs {
		t.Fatalf("Changes = %+v, want one KindNewCVEs", d.Changes)
	}
	want := []string{"CVE-1", "CVE-3"}
	if got := d.Changes[0].NewIDs; !reflect.DeepEqual(got, want) {
		t.Errorf("NewIDs = %v, want %v (sorted, only ids absent from the previous scan)", got, want)
	}
	if got := d.Changes[0].NewCVEs; got != len(want) {
		t.Errorf("NewCVEs = %d, want %d (len(NewIDs), kept for webhook compatibility)", got, len(want))
	}
}

func TestCompute_FixBecomesAvailable(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusAffected),
	}}))
	d, next := Compute(st, report(day2, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}}))

	if len(d.Changes) != 1 || d.Changes[0].Kind != KindNowFixable {
		t.Fatalf("Changes = %+v, want one KindNowFixable", d.Changes)
	}
	if len(d.Resolved) != 0 {
		t.Errorf("status transition must not be reported as resolved: %+v", d.Resolved)
	}
	if got := next.Findings["web:1\topenssl"].FirstSeen; !got.Equal(day1) {
		t.Errorf("FirstSeen = %v, want preserved %v", got, day1)
	}
}

func TestCompute_ResolvedFinding(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
		finding("web:1", "zlib", "CVE-2", scanner.StatusFixed),
	}}))
	d, next := Compute(st, report(day2, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}}))

	if len(d.Resolved) != 1 || d.Resolved[0].Package != "zlib" {
		t.Fatalf("Resolved = %+v, want zlib", d.Resolved)
	}
	if _, ok := next.Findings["web:1\tzlib"]; ok {
		t.Error("resolved finding must leave the state")
	}
}

func TestCompute_ScanFailurePreservesFindings(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}}))
	d, next := Compute(st, report(day2, scanner.ImageScan{Image: "web:1", Err: errString("pull failed")}))

	if len(d.Resolved) != 0 {
		t.Errorf("scan failure must not resolve findings: %+v", d.Resolved)
	}
	if _, ok := next.Findings["web:1\topenssl"]; !ok {
		t.Error("scan failure must carry findings over in state")
	}
}

func TestCompute_EOSLLifecycle(t *testing.T) {
	d1, st := Compute(empty(), report(day1, scanner.ImageScan{Image: "old:1", OSEOSL: true}))
	if len(d1.NewEOSL) != 1 || d1.NewEOSL[0] != "old:1" {
		t.Fatalf("NewEOSL = %+v", d1.NewEOSL)
	}

	// Unchanged EOSL: no change reported, first-seen kept.
	d2, st2 := Compute(st, report(day2, scanner.ImageScan{Image: "old:1", OSEOSL: true}))
	if d2.HasChanges() {
		t.Errorf("unchanged EOSL should not be a change: %+v", d2)
	}
	if !st2.EOSL["old:1"].Equal(day1) {
		t.Errorf("EOSL first seen = %v, want %v", st2.EOSL["old:1"], day1)
	}

	// Image gone (rebased or stopped): resolved.
	d3, st3 := Compute(st2, report(day2, scanner.ImageScan{Image: "old:1"}))
	if len(d3.ResolvedEOSL) != 1 {
		t.Errorf("ResolvedEOSL = %+v, want old:1", d3.ResolvedEOSL)
	}
	if len(st3.EOSL) != 0 {
		t.Errorf("EOSL state should be cleared, got %+v", st3.EOSL)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// --- content-digest identity model ---

const (
	contentA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contentB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// mustConfigKey parses s as a config digest EntityKey or panics — only ever
// used to build well-formed test fixtures, never production data.
func mustConfigKey(s string) inventory.EntityKey {
	d, ok := inventory.ParseDigest(inventory.DigestConfig, s)
	if !ok {
		panic("test fixture: invalid digest " + s)
	}
	return inventory.EntityKey{Digest: d}
}

// resolvedScan builds a Pinned ImageScan confirmed against contentID, the
// shape runner.scanAll produces for a running entity whose EntityKey
// resolved and was confirmed.
func resolvedScan(ref, contentID string, finds ...scanner.Finding) scanner.ImageScan {
	key := mustConfigKey(contentID)
	return scanner.ImageScan{
		Image:      ref,
		Subject:    inventory.ImageSubject{Ref: ref, Key: key, Resolved: true},
		ScannedKey: key,
		Pinned:     true,
		Source:     scanner.SourceLocal,
		Findings:   finds,
	}
}

// failedResolvedScan builds a scan whose Subject resolved to contentID but
// whose Trivy scan itself failed — Subject.Resolved survives the failure
// unchanged, while Pinned stays false (Err != nil fails the pin check
// regardless).
func failedResolvedScan(ref, contentID string, err error) scanner.ImageScan {
	return scanner.ImageScan{
		Image:   ref,
		Subject: inventory.ImageSubject{Ref: ref, Key: mustConfigKey(contentID), Resolved: true},
		Err:     err,
	}
}

func TestFileStore_LegacyStateMigratesCleanly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	// version 1, findings/eosl only — no images/content_id fields at all, the
	// exact shape written before the content-digest identity model.
	legacy := `{"version":1,"findings":{"web:1\topenssl":{"first_seen":"2026-06-24T09:00:00Z","fixable":true,"vuln_ids":["CVE-1"]}},"eosl":{}}`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	store := FileStore{Path: path}

	prev, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if prev.Images == nil || len(prev.Images) != 0 {
		t.Errorf("legacy Images = %+v, want a non-nil empty map", prev.Images)
	}

	// The running binary already has the content-digest identity model: this
	// cycle's scan resolves a ContentID even though the persisted state
	// predates it.
	scan := resolvedScan("web:1", contentA, finding("web:1", "openssl", "CVE-1", scanner.StatusFixed))
	d, next := Compute(prev, report(day1, scan))

	if d.HasChanges() {
		t.Errorf("one cycle over unchanged legacy state must report no changes: %+v", d)
	}
	gotEntry := next.Findings["web:1\topenssl"]
	if !gotEntry.FirstSeen.Equal(day1) {
		t.Errorf("FirstSeen = %v, want the legacy entry's %v preserved", gotEntry.FirstSeen, day1)
	}
	if gotEntry.ContentID != contentA {
		t.Errorf("Entry.ContentID = %q, want %q recorded on the first cycle with the identity model", gotEntry.ContentID, contentA)
	}
	meta, ok := next.Images["web:1"]
	if !ok || len(meta.ContentIDs) != 1 || meta.ContentIDs[0] != contentA || !meta.LastSeen.Equal(day1) {
		t.Errorf("Images[web:1] = %+v, ok=%v, want the current cycle's inventory recorded ([%s], LastSeen=%v)", meta, ok, contentA, day1)
	}
	if len(d.Replaced) != 0 {
		t.Errorf("first cycle over legacy (image-less) state must not fire Replaced: %+v", d.Replaced)
	}

	if err := store.Save(next); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload after Save: %v", err)
	}
	if got := reloaded.Findings["web:1\topenssl"]; got.ContentID != contentA || !got.FirstSeen.Equal(day1) {
		t.Errorf("round-tripped entry = %+v, want ContentID %q and FirstSeen %v", got, contentA, day1)
	}
	if got := reloaded.Images["web:1"]; len(got.ContentIDs) != 1 || got.ContentIDs[0] != contentA || !got.LastSeen.Equal(day1) {
		t.Errorf("round-tripped Images[web:1] = %+v, want ContentIDs [%s] and LastSeen %v", got, contentA, day1)
	}
}

func TestCompute_ImageReplacementFiresOnDistinctNonEmptySets(t *testing.T) {
	_, st := Compute(empty(), report(day1, resolvedScan("web:1", contentA)))
	d, next := Compute(st, report(day2, resolvedScan("web:1", contentB)))

	if len(d.Replaced) != 1 {
		t.Fatalf("Replaced = %+v, want one entry", d.Replaced)
	}
	got := d.Replaced[0]
	if got.Ref != "web:1" || len(got.PrevContentIDs) != 1 || got.PrevContentIDs[0] != contentA ||
		len(got.ContentIDs) != 1 || got.ContentIDs[0] != contentB {
		t.Errorf("Replaced[0] = %+v", got)
	}
	if !d.HasChanges() {
		t.Error("HasChanges should be true when a replacement fired")
	}
	if !next.Images["web:1"].LastSeen.Equal(day2) {
		t.Errorf("LastSeen = %v, want %v", next.Images["web:1"].LastSeen, day2)
	}
}

func TestCompute_ImageReplacementNotOnFirstObservation(t *testing.T) {
	d, next := Compute(empty(), report(day1, resolvedScan("web:1", contentA)))

	if len(d.Replaced) != 0 {
		t.Errorf("Replaced = %+v, want none on first observation (empty -> non-empty)", d.Replaced)
	}
	meta := next.Images["web:1"]
	if len(meta.ContentIDs) != 1 || meta.ContentIDs[0] != contentA {
		t.Errorf("Images[web:1] = %+v, want [%s] recorded", meta, contentA)
	}
}

func TestCompute_ImageReplacementNotWhenSetUnchanged(t *testing.T) {
	_, st := Compute(empty(), report(day1, resolvedScan("web:1", contentA)))
	d, _ := Compute(st, report(day2, resolvedScan("web:1", contentA)))

	if len(d.Replaced) != 0 {
		t.Errorf("Replaced = %+v, want none when the set is unchanged", d.Replaced)
	}
}

func TestCompute_AmbiguousReferenceRecordsSetAndUnionsFindings(t *testing.T) {
	scanA := resolvedScan("web:1", contentA, finding("web:1", "pip", "CVE-A", scanner.StatusFixed))
	scanB := resolvedScan("web:1", contentB, finding("web:1", "pip", "CVE-B", scanner.StatusFixed))
	d, next := Compute(empty(), report(day1, scanA, scanB))

	meta := next.Images["web:1"]
	if !meta.Ambiguous || len(meta.ContentIDs) != 2 || meta.ContentIDs[0] != contentA || meta.ContentIDs[1] != contentB {
		t.Errorf("Images[web:1] = %+v, want Ambiguous with both sorted ContentIDs", meta)
	}

	e := next.Findings["web:1\tpip"]
	if e.ContentID != "" {
		t.Errorf("Entry.ContentID = %q, want empty for an Ambiguous reference", e.ContentID)
	}
	if len(e.VulnIDs) != 2 || e.VulnIDs[0] != "CVE-A" || e.VulnIDs[1] != "CVE-B" {
		t.Errorf("VulnIDs = %v, want the union [CVE-A CVE-B]", e.VulnIDs)
	}

	// The two entities' groups for the same (ref, package) must land as one
	// unioned finding, not two separate "new" changes.
	var newCount int
	for _, c := range d.Changes {
		if c.Package == "pip" && c.Kind == KindNew {
			newCount++
		}
	}
	if newCount != 1 {
		t.Errorf("expected exactly one KindNew change for the unioned pip finding, got %d (Changes=%+v)", newCount, d.Changes)
	}
}

func TestCompute_PartialFailureCarriesOverTheFailedEntityOnlyPackage(t *testing.T) {
	cveA := finding("web:1", "pkgA", "CVE-A", scanner.StatusFixed)
	cveB := finding("web:1", "pkgB", "CVE-B", scanner.StatusFixed)

	// Cycle 1: both entities under web:1 succeed.
	_, st1 := Compute(empty(), report(day1, resolvedScan("web:1", contentA, cveA), resolvedScan("web:1", contentB, cveB)))
	if e := st1.Findings["web:1\tpkgB"]; len(e.VulnIDs) != 1 || e.VulnIDs[0] != "CVE-B" {
		t.Fatalf("cycle1 pkgB = %+v", e)
	}

	// Cycle 2: B fails to scan (partial failure: A still succeeds).
	scanBFailed := failedResolvedScan("web:1", contentB, errString("pull failed"))
	d2, st2 := Compute(st1, report(day2, resolvedScan("web:1", contentA, cveA), scanBFailed))

	for _, c := range d2.Changes {
		if c.Package == "pkgB" {
			t.Errorf("cycle2: pkgB must not appear in Changes during partial failure, got %+v", c)
		}
	}
	for _, res := range d2.Resolved {
		if res.Package == "pkgB" {
			t.Errorf("cycle2: pkgB must not be Resolved during partial failure, got %+v", res)
		}
	}
	e2 := st2.Findings["web:1\tpkgB"]
	if len(e2.VulnIDs) != 1 || e2.VulnIDs[0] != "CVE-B" {
		t.Errorf("cycle2: pkgB VulnIDs should survive the conservative carryover, got %+v", e2)
	}
	if e2.ContentID != "" {
		t.Errorf("cycle2: ContentID should be empty during partial failure, got %q", e2.ContentID)
	}

	// Cycle 3: B recovers with the exact same finding as cycle 1.
	d3, st3 := Compute(st2, report(day2.AddDate(0, 0, 1), resolvedScan("web:1", contentA, cveA), resolvedScan("web:1", contentB, cveB)))
	for _, c := range d3.Changes {
		if c.Package == "pkgB" {
			t.Errorf("cycle3: pkgB recovery must not misfire any change kind, got %+v", c)
		}
	}
	e3 := st3.Findings["web:1\tpkgB"]
	if !e3.FirstSeen.Equal(day1) {
		t.Errorf("cycle3: pkgB FirstSeen = %v, want preserved %v", e3.FirstSeen, day1)
	}
}

// TestCompute_PartialFailureMergeAcrossThreeCycles covers the scenario where
// two entities under one reference contribute to the *same*
// package name, so a sibling's scan failure must not just vanish a whole
// package (covered above) but also not silently regress the merged
// VulnIDs/Fixable/Priority that both entities jointly established — and
// none of new/new_cves/now_fixable/escalated may misfire when the failed
// entity comes back with unchanged findings.
//
// A's CVE is StatusAffected (not fixable) and B's is StatusFixed (fixable):
// with B failing in cycle 2, the raw (unmerged) view of this cycle would be
// fixable=false, and — without the prev||cur merge — persisting that would
// make cycle 3's genuine false->true fixable transition misfire
// KindNowFixable. Using StatusFixed for both (as an earlier version of this
// test did) can't distinguish a correct merge from a missing one, since both
// entities already agree on Fixable=true every cycle.
func TestCompute_PartialFailureMergeAcrossThreeCycles(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-B": {KEV: true}} // B's CVE is act_now; A's is not
	cveA := finding("web:1", "openssl", "CVE-A", scanner.StatusAffected)
	cveB := finding("web:1", "openssl", "CVE-B", scanner.StatusFixed)

	// Cycle 1: both entities succeed; the shared package unions to both CVEs
	// at the stronger (act_now) priority, and is fixable because B's CVE is.
	_, st1 := Compute(empty(), triaged(day1, enrich, resolvedScan("web:1", contentA, cveA), resolvedScan("web:1", contentB, cveB)))
	e1 := st1.Findings["web:1\topenssl"]
	if len(e1.VulnIDs) != 2 || e1.Priority != string(analyze.PriorityActNow) || !e1.Fixable {
		t.Fatalf("cycle1 openssl = %+v, want both CVEs, act_now, fixable", e1)
	}

	// Cycle 2: B (the KEV/fixable entity) fails. A alone contributes only its
	// unfixed, non-KEV CVE this cycle; the merge must keep CVE-B, act_now,
	// and Fixable=true alive so cycle 3 doesn't see any of them as new.
	scanBFailed := failedResolvedScan("web:1", contentB, errString("pull failed"))
	d2, st2 := Compute(st1, triaged(day2, enrich, resolvedScan("web:1", contentA, cveA), scanBFailed))
	if d2.HasChanges() {
		t.Errorf("cycle2: partial failure must not report any change, got %+v", d2)
	}
	e2 := st2.Findings["web:1\topenssl"]
	if len(e2.VulnIDs) != 2 || e2.VulnIDs[0] != "CVE-A" || e2.VulnIDs[1] != "CVE-B" {
		t.Errorf("cycle2: VulnIDs = %v, want the merge to preserve [CVE-A CVE-B]", e2.VulnIDs)
	}
	if e2.Priority != string(analyze.PriorityActNow) {
		t.Errorf("cycle2: Priority = %q, want the merge to preserve act_now", e2.Priority)
	}
	if !e2.Fixable {
		t.Error("cycle2: Fixable should stay true via the merge, even though only the unfixed entity scanned this cycle")
	}
	if e2.ContentID != "" {
		t.Errorf("cycle2: ContentID should be empty during partial failure, got %q", e2.ContentID)
	}

	// Cycle 3: B recovers with the exact same finding as cycle 1 — nothing
	// must be reported as new / new_cves / now_fixable / escalated.
	d3, st3 := Compute(st2, triaged(day2.AddDate(0, 0, 1), enrich, resolvedScan("web:1", contentA, cveA), resolvedScan("web:1", contentB, cveB)))
	if d3.HasChanges() {
		t.Errorf("cycle3: B's recovery must not misfire any change, got %+v", d3)
	}
	for _, c := range d3.Changes {
		if c.Package == "openssl" {
			t.Errorf("cycle3: openssl must not appear as any Change kind (esp. now_fixable), got %+v", c)
		}
	}
	e3 := st3.Findings["web:1\topenssl"]
	if !e3.FirstSeen.Equal(day1) {
		t.Errorf("cycle3: FirstSeen = %v, want preserved %v", e3.FirstSeen, day1)
	}
	if !e3.Fixable {
		t.Error("cycle3: Fixable should still be true after B's recovery")
	}
}

// markMuted flips Muted on every PackageGroup matching (image, pkg)
// across every status section of r — a direct-fixture shortcut for a state
// package test that only needs Compute's own reaction to an
// already-muted group, not the full runtime-evidence pipeline
// analyze.ApplyMuting would otherwise judge it from (which needs a
// Sensor snapshot, Docker inspects and a matched container generation —
// none of which state.Compute itself ever looks at).
func markMuted(t *testing.T, r *analyze.Report, image, pkg string) {
	t.Helper()
	found := false
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for i := range section {
			if section[i].Image != image {
				continue
			}
			for j := range section[i].Packages {
				if section[i].Packages[j].Package != pkg {
					continue
				}
				section[i].Packages[j].Muted = true
				section[i].Packages[j].MutedReason = analyze.MutedNoFixNotInUse7d
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("markMuted: no group found for %s/%s", image, pkg)
	}
}

// markMutedForEntity is markMuted's per-entity counterpart: it flips
// Muted only on the PackageGroup matching (image, pkg) within the one
// ImageFindings whose Subject.Key resolves from contentID — needed for a
// test that controls two different entities' groups under the same
// (image, pkg) state key independently (an Ambiguous reference, or two
// entities that happen to run the same reference).
func markMutedForEntity(t *testing.T, r *analyze.Report, image, pkg, contentID string, muted bool) {
	t.Helper()
	entity := mustConfigKey(contentID)
	found := false
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for i := range section {
			if section[i].Image != image || section[i].Subject.Key != entity {
				continue
			}
			for j := range section[i].Packages {
				if section[i].Packages[j].Package != pkg {
					continue
				}
				section[i].Packages[j].Muted = muted
				if muted {
					section[i].Packages[j].MutedReason = analyze.MutedNoFixNotInUse7d
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("markMutedForEntity: no group found for %s/%s@%s", image, pkg, contentID)
	}
}

// TestCompute_PartialFailureRecoveryTriggersUnmuted reproduces the
// path a partial-failure carry-over can otherwise lose entirely: entity A's
// curl group is muted; A alone fails to scan for one cycle (held over,
// unchanged, while sibling entity B keeps the key muted); A then
// recovers, but now in use. Because neither the CVEs, the fix status nor
// the priority ever changed, no ordinary Kind would fire on its own —
// KindUnmuted is the only way this transition is ever reported.
func TestCompute_PartialFailureRecoveryTriggersUnmuted(t *testing.T) {
	cve := finding("web:1", "curl", "CVE-1", scanner.StatusAffected)

	// Cycle 1: both entities succeed and both are muted.
	report1 := triaged(day1, nil, resolvedScan("web:1", contentA, cve), resolvedScan("web:1", contentB, cve))
	markMuted(t, &report1, "web:1", "curl")
	_, st1 := Compute(empty(), report1)
	if !st1.Muted["web:1\tcurl"] {
		t.Fatalf("cycle1: curl not recorded as muted: %+v", st1.Muted)
	}

	// Cycle 2: A fails to scan; B alone succeeds and is still muted. The
	// key's muted flag must be held over unchanged, not freshly
	// recomputed from B's group alone.
	report2 := triaged(day2, nil, failedResolvedScan("web:1", contentA, errString("pull failed")), resolvedScan("web:1", contentB, cve))
	markMuted(t, &report2, "web:1", "curl")
	d2, st2 := Compute(st1, report2)
	if !st2.Muted["web:1\tcurl"] {
		t.Fatalf("cycle2: curl muted flag not held over during A's failure: %+v", st2.Muted)
	}
	for _, c := range d2.Changes {
		if c.Package == "curl" {
			t.Errorf("cycle2: curl must not appear in Changes during A's failure, got %+v", c)
		}
	}

	// Cycle 3: A recovers, but is now in use (not muted); B is unchanged
	// and still individually looks muted. The whole key must lose its
	// muted status, and — since nothing else about it changed — the only
	// way that shows up is KindUnmuted.
	report3 := triaged(day2.AddDate(0, 0, 1), nil, resolvedScan("web:1", contentA, cve), resolvedScan("web:1", contentB, cve))
	markMuted(t, &report3, "web:1", "curl")
	markMutedForEntity(t, &report3, "web:1", "curl", contentA, false)
	d3, st3 := Compute(st2, report3)
	if st3.Muted["web:1\tcurl"] {
		t.Error("cycle3: curl still recorded as muted after A's in-use recovery")
	}
	var found *Change
	for i, c := range d3.Changes {
		if c.Package == "curl" {
			found = &d3.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("cycle3: no Changes entry for curl's recovery:\n%+v", d3.Changes)
	}
	if found.Kind != KindUnmuted {
		t.Errorf("cycle3: Kind = %q, want %q", found.Kind, KindUnmuted)
	}
}

// TestCompute_PartialFailureDoesNotPrematurelyReportUnmuted shows why
// a held key's muted flag must be carried over unchanged rather than
// freshly recomputed from whichever entity happens to still be observable:
// entity A fails to scan the same cycle entity B's own group independently
// becomes disqualified (now in use). A fresh computation from B alone would
// already see a disqualified group and report unmuted one cycle
// early, off incomplete data; the correct behavior is to defer judgment
// until both entities are observable again.
func TestCompute_PartialFailureDoesNotPrematurelyReportUnmuted(t *testing.T) {
	cve := finding("web:1", "curl", "CVE-1", scanner.StatusAffected)

	report1 := triaged(day1, nil, resolvedScan("web:1", contentA, cve), resolvedScan("web:1", contentB, cve))
	markMuted(t, &report1, "web:1", "curl")
	_, st1 := Compute(empty(), report1)

	// Cycle 2: A fails to scan; B succeeds but is no longer individually
	// eligible (now in use) — incomplete information, since A's own current
	// state is simply unknown this cycle.
	report2 := triaged(day2, nil, failedResolvedScan("web:1", contentA, errString("pull failed")), resolvedScan("web:1", contentB, cve))
	markMutedForEntity(t, &report2, "web:1", "curl", contentB, false)
	d2, st2 := Compute(st1, report2)
	if !st2.Muted["web:1\tcurl"] {
		t.Fatalf("cycle2: curl muted flag not held over during A's failure: %+v", st2.Muted)
	}
	for _, c := range d2.Changes {
		if c.Package == "curl" {
			t.Errorf("cycle2: unmuted (or any other change) must not fire from incomplete data during A's failure, got %+v", c)
		}
	}

	// Cycle 3: both entities observable again; B is still disqualified. Now
	// that the full key can actually be judged, unmuted fires.
	report3 := triaged(day2.AddDate(0, 0, 1), nil, resolvedScan("web:1", contentA, cve), resolvedScan("web:1", contentB, cve))
	markMuted(t, &report3, "web:1", "curl")
	markMutedForEntity(t, &report3, "web:1", "curl", contentB, false)
	d3, st3 := Compute(st2, report3)
	if st3.Muted["web:1\tcurl"] {
		t.Error("cycle3: curl still recorded as muted once fully observed and disqualified")
	}
	var found *Change
	for i, c := range d3.Changes {
		if c.Package == "curl" {
			found = &d3.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("cycle3: no Changes entry for curl once both entities are observable:\n%+v", d3.Changes)
	}
	if found.Kind != KindUnmuted {
		t.Errorf("cycle3: Kind = %q, want %q", found.Kind, KindUnmuted)
	}
}

// TestCompute_StatusChangeTriggersUnmuted reproduces a de-muting
// that an ordinary status change causes without ever touching Fixable,
// VulnIDs or Priority in a way any existing Kind would catch on its own: an
// muted, will_not_fix-only package additionally becomes end-of-life
// (the base OS ages out from under it) while its own CVEs and fix status
// stay exactly the same. end-of-life is always reported, so the key's
// muting must be lost — and since the ordinary (non-EOL) view alone
// shows no CVE/fixable/priority change at all, only KindUnmuted can
// carry that news.
func TestCompute_StatusChangeTriggersUnmuted(t *testing.T) {
	cve := finding("web:1", "curl", "CVE-1", scanner.StatusWontFix)

	report1 := triaged(day1, nil, resolvedScan("web:1", contentA, cve))
	markMuted(t, &report1, "web:1", "curl")
	_, st1 := Compute(empty(), report1)
	if !st1.Muted["web:1\tcurl"] {
		t.Fatalf("cycle1: curl not recorded as muted: %+v", st1.Muted)
	}

	// Cycle 2: the exact same CVE, same will_not_fix status, same priority —
	// but the package is now also reported end-of-life (a second group under
	// the same key, in EOLPackages). A real analyze.ApplyMuting run
	// would never mute either group in this state (end-of-life always
	// blocks the whole key), so — unlike cycle 1 — this fixture leaves the
	// will_not_fix group's Muted at its natural false rather than calling
	// markMuted for it.
	scan2 := resolvedScan("web:1", contentA, cve)
	eolFind := finding("web:1", "curl", "CVE-1", scanner.StatusEndOfLife)
	scan2.Findings = append(scan2.Findings, eolFind)
	report2 := triaged(day2, nil, scan2)

	d2, st2 := Compute(st1, report2)
	if st2.Muted["web:1\tcurl"] {
		t.Error("cycle2: curl still recorded as muted once it also became end-of-life")
	}
	var found *Change
	for i, c := range d2.Changes {
		if c.Package == "curl" {
			found = &d2.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("cycle2: no ordinary Changes entry for curl:\n%+v", d2.Changes)
	}
	if found.Kind != KindUnmuted {
		t.Errorf("cycle2: Kind = %q, want %q (no ordinary CVE/fixable/priority change exists to report this any other way)", found.Kind, KindUnmuted)
	}
}

// TestCompute_MixedKeyNeverExcludedFromHeartbeat is the "open now" heartbeat
// counterpart of TestApplyMuting_MixedKeyNeverMuted: a package with
// both a fixed CVE and an unfixed one lands as two PackageGroups under one
// state key (fixed in Actionable, unfixed in Watch). analyze.ApplyMuting
// never mutes either side of a mixed key like this — neither group here is
// ever marked Muted — so the heartbeat must count the key at its own true
// priority (watch) and the diff must still report it as new, never silently
// dropping or downgrading it because the unfixed side looks individually
// eligible on its own.
func TestCompute_MixedKeyNeverExcludedFromHeartbeat(t *testing.T) {
	// CVE-2's EPSS (5%) clears the watch threshold (1%) but not act_now
	// (10%), so the unfixed group's own priority is watch, not low.
	enrich := map[string]analyze.Enrichment{"CVE-2": {EPSS: 0.05, EPSSKnown: true}}
	scan := resolvedScan("web:1", contentA,
		finding("web:1", "curl", "CVE-1", scanner.StatusFixed),
		finding("web:1", "curl", "CVE-2", scanner.StatusAffected),
	)
	report := triaged(day1, enrich, scan)
	// Neither group is marked Muted: a real analyze.ApplyMuting run
	// would never mute either side of this mixed key (see
	// TestApplyMuting_MixedKeyNeverMuted), so this direct fixture
	// simply leaves both at their natural zero value.
	d, _ := Compute(empty(), report)

	if d.OpenWatch != 1 {
		t.Errorf("OpenWatch = %d, want 1 (the unfixed CVE's own priority, uncounted as muted)", d.OpenWatch)
	}
	if d.OpenLow != 0 || d.OpenActNow != 0 {
		t.Errorf("OpenLow = %d, OpenActNow = %d, want both 0", d.OpenLow, d.OpenActNow)
	}
	var found *Change
	for i, c := range d.Changes {
		if c.Package == "curl" {
			found = &d.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("no Changes entry for curl:\n%+v", d.Changes)
	}
	if found.Kind != KindNew {
		t.Errorf("Kind = %q, want %q", found.Kind, KindNew)
	}
	if len(found.Groups) != 2 {
		t.Errorf("Groups = %+v, want both the fixed and unfixed groups merged under one Change", found.Groups)
	}
}

// muteIntegrationGroups builds one cycle's Watch section for
// TestApplyMutingAndCompute_HeldReferenceStaysConsistent: aPresent
// controls whether entity A's own group is present at all this cycle (a
// scan failure contributes none), and aInUse/bEligible control each
// present entity's own Runtime verdict — bEligible's container generation
// is always well past the 7-day window.
func muteIntegrationGroups(now time.Time, aPresent bool, extraBCVE bool) []analyze.ImageFindings {
	old := now.Add(-8 * 24 * time.Hour)
	bVulns := []string{"CVE-B"}
	if extraBCVE {
		bVulns = append(bVulns, "CVE-B2")
	}
	bGroup := func() analyze.PackageGroup {
		g := analyze.PackageGroup{
			Package: "curl", Status: scanner.StatusAffected,
			Runtime: analyze.Runtime{
				Usage: evidence.UsageNotObserved,
				Containers: []analyze.ContainerRuntime{
					{ContainerID: "b", GenerationStartedAt: old, Usage: evidence.UsageNotObserved},
				},
			},
		}
		for _, id := range bVulns {
			g.Vulns = append(g.Vulns, analyze.VulnRef{ID: id, Severity: scanner.SeverityHigh})
		}
		g.High = len(g.Vulns)
		return g
	}
	var out []analyze.ImageFindings
	if aPresent {
		out = append(out, analyze.ImageFindings{Image: "web:1", Packages: []analyze.PackageGroup{
			{
				Package: "curl", Status: scanner.StatusAffected,
				Runtime: analyze.Runtime{Usage: evidence.UsageInUse},
				Vulns:   []analyze.VulnRef{{ID: "CVE-A", Severity: scanner.SeverityHigh}},
				High:    1,
			},
		}})
	}
	out = append(out, analyze.ImageFindings{Image: "web:1", Packages: []analyze.PackageGroup{bGroup()}})
	return out
}

// TestApplyMutingAndCompute_HeldReferenceStaysConsistent covers, end to
// end, a path that can otherwise make display and stored state disagree:
// it chains analyze.ApplyMuting and Compute across four cycles the same
// way runner.RunOnce and runner.sendDiff do every real cycle:
//
//  1. Entity A (in use, blocking) and entity B (individually eligible)
//     both report "curl" under the same key; the mixed key is not muted.
//  2. A alone fails to scan (a partial failure of the reference); B alone
//     is left in the Report. Without the fix, ApplyMuting would judge
//     B's group in isolation and mute it — hiding its row while state's
//     own held value stays false, a display/state mismatch. With the fix,
//     the reference's PartialFailure blocks muting here too, so B's row
//     renders normally and state's stored value doesn't move.
//  3. A recovers, still in use (still blocking). Nothing was ever muted,
//     so state.Muted for the key stays exactly as it was — no
//     unmuted fires over a transition that never happened.
//  4. B gains a new CVE. Because the key was never muted, this shows up
//     as an ordinary KindNewCVEs change, not silently absorbed.
func TestApplyMutingAndCompute_HeldReferenceStaysConsistent(t *testing.T) {
	now := day1
	st := empty()

	// Cycle 1: A and B both observed, reference healthy. The mixed key must
	// not be muted.
	report1 := analyze.Report{
		Runtime: &analyze.RuntimeInfo{},
		Images:  []analyze.ImageObservation{{Ref: "web:1"}},
		Watch:   muteIntegrationGroups(now, true, false),
	}
	analyze.ApplyMuting(&report1, now)
	_, st = Compute(st, report1)
	if st.Muted["web:1\tcurl"] {
		t.Fatalf("cycle1: curl recorded as muted while A (in use) blocks the key")
	}

	// Cycle 2: A fails to scan (partial failure); only B's group remains in
	// the Report. B must not be muted, and its row (via the ordinary
	// diff machinery) is unaffected — nothing here was ever hidden.
	now = now.AddDate(0, 0, 1)
	report2 := analyze.Report{
		Runtime: &analyze.RuntimeInfo{},
		Images:  []analyze.ImageObservation{{Ref: "web:1", PartialFailure: true}},
		Watch:   muteIntegrationGroups(now, false, false),
	}
	analyze.ApplyMuting(&report2, now)
	for _, img := range report2.Watch {
		for _, g := range img.Packages {
			if g.Muted {
				t.Errorf("cycle2: %s/%s Muted = true during A's failure, want false (the reference is held, not fully observed)", img.Image, g.Package)
			}
		}
	}
	d2, st2 := Compute(st, report2)
	if st2.Muted["web:1\tcurl"] {
		t.Fatalf("cycle2: curl recorded as muted from B's isolated view during A's failure")
	}
	for _, c := range d2.Changes {
		if c.Package == "curl" {
			t.Errorf("cycle2: curl must not appear in Changes during A's failure (held, unobserved), got %+v", c)
		}
	}
	st = st2

	// Cycle 3: A recovers, still in use (still blocking). Nothing changes.
	now = now.AddDate(0, 0, 1)
	report3 := analyze.Report{
		Runtime: &analyze.RuntimeInfo{},
		Images:  []analyze.ImageObservation{{Ref: "web:1"}},
		Watch:   muteIntegrationGroups(now, true, false),
	}
	analyze.ApplyMuting(&report3, now)
	d3, st3 := Compute(st, report3)
	if st3.Muted["web:1\tcurl"] {
		t.Fatalf("cycle3: curl recorded as muted after A's in-use recovery")
	}
	for _, c := range d3.Changes {
		if c.Package == "curl" {
			t.Errorf("cycle3: curl must not appear in Changes on A's unchanged recovery (nothing was ever muted to lose), got %+v", c)
		}
	}
	st = st3

	// Cycle 4: B gains a new CVE. Since the key was never muted, this
	// must show up as an ordinary new_cves change.
	now = now.AddDate(0, 0, 1)
	report4 := analyze.Report{
		Runtime: &analyze.RuntimeInfo{},
		Images:  []analyze.ImageObservation{{Ref: "web:1"}},
		Watch:   muteIntegrationGroups(now, true, true),
	}
	analyze.ApplyMuting(&report4, now)
	d4, _ := Compute(st, report4)
	var found *Change
	for i, c := range d4.Changes {
		if c.Package == "curl" {
			found = &d4.Changes[i]
		}
	}
	if found == nil {
		t.Fatalf("cycle4: no Changes entry for curl's new CVE:\n%+v", d4.Changes)
	}
	if found.Kind != KindNewCVEs {
		t.Errorf("cycle4: Kind = %q, want %q", found.Kind, KindNewCVEs)
	}
}

// TestCompute_PartialFailureDoesNotHideHeldActNowBehindMutedSibling
// covers an Ambiguous reference's two entities reporting the same package
// name under one state key. Entity A's finding is act_now and fails to scan
// this cycle (held over by the same conservative merge
// TestCompute_PartialFailureMergeAcrossThreeCycles above exercises), while
// entity B succeeds with an unrelated, muted finding for the very same
// package name. The merged key's stored Priority must still read act_now, and the
// "open now" heartbeat must still count it — muting B's own group must
// never make a held act_now silently vanish from the count just because
// today's only live sibling happens to look fully muted.
func TestCompute_PartialFailureDoesNotHideHeldActNowBehindMutedSibling(t *testing.T) {
	enrich := map[string]analyze.Enrichment{"CVE-A": {KEV: true}} // A's CVE is act_now; B's is not
	cveA := finding("web:1", "curl", "CVE-A", scanner.StatusAffected)
	cveB := finding("web:1", "curl", "CVE-B", scanner.StatusAffected)

	// Cycle 1: both entities succeed. The merged key is act_now (A's CVE
	// wins over B's low-priority one).
	_, st1 := Compute(empty(), triaged(day1, enrich, resolvedScan("web:1", contentA, cveA), resolvedScan("web:1", contentB, cveB)))
	e1 := st1.Findings["web:1\tcurl"]
	if e1.Priority != string(analyze.PriorityActNow) {
		t.Fatalf("cycle1: curl priority = %q, want act_now", e1.Priority)
	}

	// Cycle 2: A fails to scan (contributes nothing this cycle; its act_now
	// finding only survives via the partial-failure merge). B succeeds again
	// with the same CVE-B, and B's own group is now Muted — simulating
	// runtime.mute_unfixable_not_in_use judging it not observed, no fix,
	// non-act_now and old enough.
	scanAFailed := failedResolvedScan("web:1", contentA, errString("pull failed"))
	report2 := triaged(day2, enrich, scanAFailed, resolvedScan("web:1", contentB, cveB))
	markMuted(t, &report2, "web:1", "curl")

	d2, st2 := Compute(st1, report2)

	e2 := st2.Findings["web:1\tcurl"]
	if e2.Priority != string(analyze.PriorityActNow) {
		t.Fatalf("cycle2: curl priority = %q, want the merge to preserve act_now (held from the failed entity)", e2.Priority)
	}
	if d2.OpenActNow != 1 {
		t.Errorf("cycle2: OpenActNow = %d, want 1 — a held act_now must not disappear from the heartbeat just because the only live sibling's own group looks muted", d2.OpenActNow)
	}
	if d2.OpenWatch != 0 || d2.OpenLow != 0 {
		t.Errorf("cycle2: OpenWatch=%d OpenLow=%d, want both 0 — the key counts once, as act_now", d2.OpenWatch, d2.OpenLow)
	}
	for _, c := range d2.Changes {
		if c.Package == "curl" {
			t.Errorf("cycle2: curl must not appear in Changes during partial failure, got %+v", c)
		}
	}
}

func TestCompute_FullFailureCarriesOverFindingsAndContentIDButNotLastSeen(t *testing.T) {
	_, st := Compute(empty(), report(day1, resolvedScan("web:1", contentA, finding("web:1", "openssl", "CVE-1", scanner.StatusFixed))))
	d, next := Compute(st, report(day2, failedResolvedScan("web:1", contentA, errString("pull failed"))))

	if len(d.Resolved) != 0 {
		t.Errorf("full failure must not resolve findings: %+v", d.Resolved)
	}
	if len(d.Replaced) != 0 {
		t.Errorf("Replaced = %+v, want none (the observed ContentID set is unchanged)", d.Replaced)
	}
	got, ok := next.Findings["web:1\topenssl"]
	if !ok {
		t.Fatal("full failure must carry findings over in state")
	}
	// Existing full-failure behavior: the entry (ContentID included) is
	// carried over exactly as it was — there is no sibling entity whose
	// success this cycle would make that ContentID misleading (contrast the
	// partial-failure case, which does blank it).
	if got.ContentID != contentA {
		t.Errorf("full failure ContentID = %q, want the untouched carryover %q", got.ContentID, contentA)
	}
	// ContentIDs/Ambiguous are Docker-observed and independent of scan
	// success, so they still reflect this cycle's inventory; only LastSeen
	// (scan-success-gated) carries over unchanged.
	meta := next.Images["web:1"]
	if len(meta.ContentIDs) != 1 || meta.ContentIDs[0] != contentA {
		t.Errorf("Images[web:1].ContentIDs = %v, want [%s] (Docker-observed, independent of scan failure)", meta.ContentIDs, contentA)
	}
	if !meta.LastSeen.Equal(day1) {
		t.Errorf("LastSeen = %v, want carried over from the last successful cycle %v", meta.LastSeen, day1)
	}
}

// TestCompute_ImageReplacementFiresEvenOnScanFailure is the corrected
// counterpart to the (mistaken) assumption that a failed scan means an
// unreliable ContentID set: ExpectedContentID is Docker-observed and survives
// a Trivy failure unchanged (chunk1), so a genuine replacement must still be
// detected even though the new content's scan itself failed.
func TestCompute_ImageReplacementFiresEvenOnScanFailure(t *testing.T) {
	_, st := Compute(empty(), report(day1, resolvedScan("web:1", contentA, finding("web:1", "openssl", "CVE-1", scanner.StatusFixed))))
	d, next := Compute(st, report(day2, failedResolvedScan("web:1", contentB, errString("pull failed"))))

	if len(d.Replaced) != 1 {
		t.Fatalf("Replaced = %+v, want one entry even though the new content's scan failed", d.Replaced)
	}
	got := d.Replaced[0]
	if got.Ref != "web:1" || len(got.PrevContentIDs) != 1 || got.PrevContentIDs[0] != contentA ||
		len(got.ContentIDs) != 1 || got.ContentIDs[0] != contentB {
		t.Errorf("Replaced[0] = %+v", got)
	}
	// The old finding is still carried over untouched (full failure: no
	// successful scan of anything under this ref this cycle).
	if _, ok := next.Findings["web:1\topenssl"]; !ok {
		t.Error("full failure must still carry the previous finding over")
	}
	if !next.Images["web:1"].LastSeen.Equal(day1) {
		t.Errorf("LastSeen = %v, want carried over (this cycle's scan failed)", next.Images["web:1"].LastSeen)
	}
}

func TestDiff_HasChangesTrueForReplacedOnly(t *testing.T) {
	d := Diff{Replaced: []ImageReplacement{{Ref: "web:1"}}}
	if !d.HasChanges() {
		t.Error("HasChanges should be true when only Replaced is set")
	}
}

// --- triage ---

// triaged builds a report with triage enabled and the given enrichment.
func triaged(t time.Time, enrich map[string]analyze.Enrichment, scans ...scanner.ImageScan) analyze.Report {
	tr := analyze.Triage{
		Enabled: true, ActNowEPSS: 0.10, WatchEPSS: 0.01,
		Enrich: enrich, Intel: analyze.IntelStatus{KEVOK: true, EPSSOK: true},
	}
	return analyze.Build(scans, nil, tr, t)
}

func TestCompute_EscalationWhenCVEEntersKEV(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed), // HIGH, no signal → low
	}}
	_, st := Compute(empty(), triaged(day1, nil, scan))
	if got := st.Findings["web:1\topenssl"].Priority; got != "low" {
		t.Fatalf("stored priority = %q, want low", got)
	}

	// Next day the same CVE is listed in KEV.
	d, next := Compute(st, triaged(day2, map[string]analyze.Enrichment{"CVE-1": {KEV: true}}, scan))
	if len(d.Changes) != 1 || d.Changes[0].Kind != KindEscalated {
		t.Fatalf("Changes = %+v, want one KindEscalated", d.Changes)
	}
	if got := next.Findings["web:1\topenssl"].Priority; got != "act_now" {
		t.Errorf("stored priority = %q, want act_now", got)
	}
	if got := next.Findings["web:1\topenssl"].FirstSeen; !got.Equal(day1) {
		t.Errorf("FirstSeen = %v, want preserved %v (escalation is not a new finding)", got, day1)
	}
}

func TestCompute_EscalationOutranksNewCVEs(t *testing.T) {
	_, st := Compute(empty(), triaged(day1, nil, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}}))
	// A new KEV-listed CVE lands on the known package: both "new CVEs" and
	// "escalated" are true; escalated is the headline.
	d, _ := Compute(st, triaged(day2, map[string]analyze.Enrichment{"CVE-2": {KEV: true}}, scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
		finding("web:1", "openssl", "CVE-2", scanner.StatusFixed),
	}}))
	if len(d.Changes) != 1 || d.Changes[0].Kind != KindEscalated {
		t.Fatalf("Changes = %+v, want one KindEscalated", d.Changes)
	}
}

func TestCompute_NoEscalationFromPreTriageState(t *testing.T) {
	scan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
	}}
	// day1 state was written without triage (upgrade scenario): empty priority.
	_, st := Compute(empty(), report(day1, scan))
	if got := st.Findings["web:1\topenssl"].Priority; got != "" {
		t.Fatalf("pre-triage priority = %q, want empty", got)
	}
	d, next := Compute(st, triaged(day2, map[string]analyze.Enrichment{"CVE-1": {KEV: true}}, scan))
	if d.HasChanges() {
		t.Errorf("first triaged run over legacy state must not announce escalations: %+v", d.Changes)
	}
	if got := next.Findings["web:1\topenssl"].Priority; got != "act_now" {
		t.Errorf("stored priority = %q, want act_now (baseline established)", got)
	}
}

func TestCompute_PriorityBreakdownAndOldestUrgent(t *testing.T) {
	lowScan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "zlib", "CVE-LOW", scanner.StatusFixed), // HIGH, no signal → low
	}}
	_, st := Compute(empty(), triaged(day1, nil, lowScan))

	// day2 a KEV finding appears; the low finding is now a day old.
	bothScan := scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
		finding("web:1", "zlib", "CVE-LOW", scanner.StatusFixed),
		finding("web:1", "openssl", "CVE-KEV", scanner.StatusFixed),
	}}
	d, _ := Compute(st, triaged(day2, map[string]analyze.Enrichment{"CVE-KEV": {KEV: true}}, bothScan))

	if d.OpenActNow != 1 || d.OpenWatch != 0 || d.OpenLow != 1 {
		t.Errorf("open breakdown = act_now %d / watch %d / low %d, want 1/0/1", d.OpenActNow, d.OpenWatch, d.OpenLow)
	}
	if d.OldestOpenDays(day2) != 1 {
		t.Errorf("OldestOpenDays = %d, want 1 (the low finding)", d.OldestOpenDays(day2))
	}
	if d.OldestUrgentDays(day2) != 0 {
		t.Errorf("OldestUrgentDays = %d, want 0 (old low findings are not urgent debt)", d.OldestUrgentDays(day2))
	}
}
