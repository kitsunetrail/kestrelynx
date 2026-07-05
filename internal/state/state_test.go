package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
)

var (
	day1 = time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)
	day2 = time.Date(2026, 6, 25, 9, 0, 0, 0, time.UTC)
)

func report(t time.Time, scans ...scanner.ImageScan) analyze.Report {
	return analyze.Build(scans, t)
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
