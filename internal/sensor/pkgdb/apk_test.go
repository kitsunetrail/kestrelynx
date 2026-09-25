package pkgdb

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// apkFixture is Alpine 3.20's real /lib/apk/db/installed, extracted from
// the public alpine:3.20 image in full (16 KiB) — not a hand-written
// approximation. VERIFIED against that image.
const apkFixture = "testdata/apk/installed"

func loadApkFixture(t *testing.T) (*Index, Diagnostics) {
	t.Helper()
	idx, diag, err := ParseApk(openNamed(t, apkFixture), DefaultLimits())
	if err != nil {
		t.Fatalf("ParseApk: %v", err)
	}
	return idx, diag
}

func TestParseApk_RealFixture_NotTruncated(t *testing.T) {
	_, diag := loadApkFixture(t)
	if diag.Truncated {
		t.Errorf("Truncated = true, want false: %+v", diag.Errors)
	}
	if len(diag.Errors) != 0 {
		t.Errorf("Errors = %+v, want none", diag.Errors)
	}
}

func TestParseApk_RealFixture_Ownership(t *testing.T) {
	idx, _ := loadApkFixture(t)

	// alpine-baselayout's record (F:etc/modprobe.d, R:aliases.conf, per the
	// real fixture) owns /etc/modprobe.d/aliases.conf.
	owners, ok := idx.Lookup("/etc/modprobe.d/aliases.conf")
	if !ok || len(owners) != 1 || owners[0].Name != "alpine-baselayout" || owners[0].DBKind != evidence.DBKindApk {
		t.Errorf("Lookup(/etc/modprobe.d/aliases.conf) = %v (ok=%v), want single owner alpine-baselayout", owners, ok)
	}
}

func TestParseApk_RealFixture_Versions(t *testing.T) {
	idx, _ := loadApkFixture(t)
	cases := []struct {
		name string
		want string
	}{
		{"alpine-baselayout", "3.6.5-r0"},
		{"busybox", "1.36.1-r31"},
		{"musl", "1.2.5-r3"},
	}
	for _, tc := range cases {
		got, ok := idx.Version(evidence.DBKindApk, tc.name)
		if !ok || got != tc.want {
			t.Errorf("Version(apk, %q) = (%q, %v), want (%q, true)", tc.name, got, ok, tc.want)
		}
	}
}

func TestParseApk_RealFixture_Ledger(t *testing.T) {
	idx, _ := loadApkFixture(t)
	byName := map[string]LedgerEntry{}
	for _, e := range idx.Ledger {
		byName[e.Name] = e
	}
	e, ok := byName["alpine-baselayout"]
	if !ok {
		t.Fatal("Ledger has no entry for alpine-baselayout")
	}
	if !e.FileListPresent {
		t.Error("FileListPresent = false, want true")
	}
	if e.FileCount == 0 {
		t.Error("FileCount = 0, want > 0")
	}
	if e.Arch != "x86_64" {
		t.Errorf("Arch = %q, want %q", e.Arch, "x86_64")
	}
}

func TestParseApk_RMissingFRecordIsMalformed(t *testing.T) {
	data := "P:broken\nV:1.0-r0\nR:file-without-f\n"
	idx, diag, err := ParseApk(NamedReader{Name: "installed", R: strings.NewReader(data)}, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseApk: %v", err)
	}
	if len(diag.Errors) == 0 {
		t.Error("Errors is empty, want an entry for the R without a preceding F")
	}
	var ledger LedgerEntry
	for _, e := range idx.Ledger {
		if e.Name == "broken" {
			ledger = e
		}
	}
	if ledger.FileListPresent {
		t.Error("FileListPresent = true, want false for a record with a malformed R line")
	}
}

func TestParseApk_VirtualPackageHasEmptyCompleteFileList(t *testing.T) {
	// A virtual package (apk add --virtual) has a P/V/A record with no F/R
	// lines at all — a complete, empty file list, not an unreadable one.
	data := "P:.virtual-deps\nV:0\nA:x86_64\n"
	idx, _, err := ParseApk(NamedReader{Name: "installed", R: strings.NewReader(data)}, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseApk: %v", err)
	}
	if len(idx.Ledger) != 1 {
		t.Fatalf("Ledger = %+v, want exactly one entry", idx.Ledger)
	}
	if !idx.Ledger[0].FileListPresent {
		t.Error("FileListPresent = false, want true (empty is complete, not missing)")
	}
	if idx.Ledger[0].FileCount != 0 {
		t.Errorf("FileCount = %d, want 0", idx.Ledger[0].FileCount)
	}
}
