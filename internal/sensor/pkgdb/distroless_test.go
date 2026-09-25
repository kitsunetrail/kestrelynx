package pkgdb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// distrolessFixtureDir holds gcr.io/distroless/cc-debian12's real
// /var/lib/dpkg/status.d directory in full (9 packages, both the control
// stanza and .md5sums file for each), extracted from that public image —
// not a hand-written approximation. VERIFIED against that image.
const distrolessFixtureDir = "testdata/distroless/status.d"

func loadDistrolessFixture(t *testing.T) (*Index, Diagnostics) {
	t.Helper()
	entries, err := os.ReadDir(distrolessFixtureDir)
	if err != nil {
		t.Fatalf("read fixture dir: %v", err)
	}
	var files []NamedReader
	for _, e := range entries {
		files = append(files, openNamed(t, filepath.Join(distrolessFixtureDir, e.Name())))
	}
	idx, diag, err := ParseDistroless(files, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseDistroless: %v", err)
	}
	return idx, diag
}

func TestParseDistroless_RealFixture_NotTruncated(t *testing.T) {
	_, diag := loadDistrolessFixture(t)
	if diag.Truncated {
		t.Errorf("Truncated = true, want false: %+v", diag.Errors)
	}
	if len(diag.Errors) != 0 {
		t.Errorf("Errors = %+v, want none", diag.Errors)
	}
}

func TestParseDistroless_RealFixture_Ownership(t *testing.T) {
	idx, _ := loadDistrolessFixture(t)

	// base-files.md5sums (real content) lists "usr/lib/os-release" relative
	// to "/".
	owners, ok := idx.Lookup("/usr/lib/os-release")
	if !ok || len(owners) != 1 || owners[0].Name != "base-files" || owners[0].DBKind != evidence.DBKindDistroless {
		t.Errorf("Lookup(/usr/lib/os-release) = %v (ok=%v), want single owner base-files", owners, ok)
	}
}

func TestParseDistroless_RealFixture_Versions(t *testing.T) {
	idx, _ := loadDistrolessFixture(t)
	got, ok := idx.Version(evidence.DBKindDistroless, "base-files")
	if !ok || got != "12.4+deb12u15" {
		t.Errorf("Version(distroless, base-files) = (%q, %v), want (%q, true)", got, ok, "12.4+deb12u15")
	}
}

func TestParseDistroless_RealFixture_Ledger(t *testing.T) {
	idx, _ := loadDistrolessFixture(t)
	found := false
	for _, e := range idx.Ledger {
		if e.Name != "base-files" {
			continue
		}
		found = true
		if !e.FileListPresent {
			t.Error("FileListPresent = false, want true")
		}
		if e.FileCount == 0 {
			t.Error("FileCount = 0, want > 0")
		}
		if e.Arch != "amd64" {
			t.Errorf("Arch = %q, want %q", e.Arch, "amd64")
		}
	}
	if !found {
		t.Error("Ledger has no entry for base-files")
	}
}

func TestParseDistroless_MissingMd5sums_FileListAbsent(t *testing.T) {
	// Only the control stanza is handed over, no matching .md5sums — the
	// one case this database format genuinely cannot answer about a
	// package's files.
	files := []NamedReader{
		openNamed(t, filepath.Join(distrolessFixtureDir, "base-files")),
	}
	idx, _, err := ParseDistroless(files, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseDistroless: %v", err)
	}
	if len(idx.Ledger) != 1 {
		t.Fatalf("Ledger = %+v, want exactly one entry", idx.Ledger)
	}
	if idx.Ledger[0].FileListPresent {
		t.Error("FileListPresent = true, want false (no .md5sums was given)")
	}
	if _, ok := idx.Lookup("/usr/lib/os-release"); ok {
		t.Error("Lookup succeeded despite no .md5sums being read")
	}
}
