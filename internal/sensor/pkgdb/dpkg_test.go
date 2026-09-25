package pkgdb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// openNamed opens path as a NamedReader whose Name is its base name, the
// shape the observer is expected to hand pkgdb. t.Cleanup closes it.
func openNamed(t *testing.T, path string) NamedReader {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture %s: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })
	return NamedReader{Name: filepath.Base(path), R: f}
}

// dpkgFixtureDir holds a real dpkg database extracted from the public
// debian:12-slim image (docker cp'd var/lib/dpkg/{status,info}, trimmed to
// four packages: base-files, bash, dash, gcc-12-base:amd64), not a
// hand-written approximation of the format. VERIFIED against that image.
const dpkgFixtureDir = "testdata/dpkg"

func loadDpkgFixture(t *testing.T) (*Index, Diagnostics) {
	t.Helper()
	status := openNamed(t, filepath.Join(dpkgFixtureDir, "status"))
	infoDir := filepath.Join(dpkgFixtureDir, "info")
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		t.Fatalf("read fixture info dir: %v", err)
	}
	var lists []NamedReader
	for _, e := range entries {
		lists = append(lists, openNamed(t, filepath.Join(infoDir, e.Name())))
	}
	idx, diag, err := ParseDpkg(status, lists, DefaultLimits())
	if err != nil {
		t.Fatalf("ParseDpkg: %v", err)
	}
	return idx, diag
}

func TestParseDpkg_RealFixture_NotTruncated(t *testing.T) {
	_, diag := loadDpkgFixture(t)
	if diag.Truncated {
		t.Errorf("Truncated = true, want false: %+v", diag.Errors)
	}
	if len(diag.Errors) != 0 {
		t.Errorf("Errors = %+v, want none", diag.Errors)
	}
}

func TestParseDpkg_RealFixture_Ownership(t *testing.T) {
	idx, _ := loadDpkgFixture(t)

	// dash's own .list names both its binary and the /bin/sh symlink to it
	// (two paths, one package) — a real record of the "package ships a
	// versioned file and a separate symlink to it" pattern.
	for _, path := range []string{"/bin/dash", "/bin/sh"} {
		owners, ok := idx.Lookup(path)
		if !ok || len(owners) != 1 || owners[0].Name != "dash" || owners[0].DBKind != evidence.DBKindDpkg {
			t.Errorf("Lookup(%q) = %v (ok=%v), want single owner dash", path, owners, ok)
		}
	}

	if _, ok := idx.Lookup("/does/not/exist"); ok {
		t.Error("Lookup of an unowned path returned ok=true")
	}
}

func TestParseDpkg_RealFixture_Versions(t *testing.T) {
	idx, _ := loadDpkgFixture(t)

	cases := []struct {
		name string
		want string
	}{
		{"dash", "0.5.12-2"},
		{"base-files", "12.4+deb12u15"},
		{"bash", "5.2.15-2+b13"},
		{"gcc-12-base", "12.2.0-14+deb12u1"},
	}
	for _, tc := range cases {
		got, ok := idx.Version(evidence.DBKindDpkg, tc.name)
		if !ok || got != tc.want {
			t.Errorf("Version(dpkg, %q) = (%q, %v), want (%q, true)", tc.name, got, ok, tc.want)
		}
	}
}

func TestParseDpkg_RealFixture_MultiarchNameStripped(t *testing.T) {
	idx, _ := loadDpkgFixture(t)
	// gcc-12-base:amd64.list is named with a ":amd64" multiarch suffix; the
	// package identity recorded must be "gcc-12-base", not
	// "gcc-12-base:amd64".
	owners, ok := idx.Lookup("/usr/share/doc/gcc-12-base/copyright")
	if !ok || len(owners) != 1 || owners[0].Name != "gcc-12-base" {
		t.Errorf("Lookup(copyright) = %v (ok=%v), want single owner %q", owners, ok, "gcc-12-base")
	}
}

func TestParseDpkg_RealFixture_Ledger(t *testing.T) {
	idx, _ := loadDpkgFixture(t)
	byName := map[string]LedgerEntry{}
	for _, e := range idx.Ledger {
		byName[e.Name] = e
	}
	for _, name := range []string{"base-files", "bash", "dash", "gcc-12-base"} {
		e, ok := byName[name]
		if !ok {
			t.Errorf("Ledger has no entry for %q", name)
			continue
		}
		if !e.FileListPresent {
			t.Errorf("Ledger[%q].FileListPresent = false, want true", name)
		}
		if e.FileCount == 0 {
			t.Errorf("Ledger[%q].FileCount = 0, want > 0", name)
		}
		if e.Arch != "amd64" {
			t.Errorf("Ledger[%q].Arch = %q, want %q", name, e.Arch, "amd64")
		}
	}
}

func TestParseDpkg_ListSizeLimitTruncatesThatFile(t *testing.T) {
	status := NamedReader{Name: "status", R: mustOpen(t, filepath.Join(dpkgFixtureDir, "status"))}
	list := NamedReader{Name: "dash.list", R: mustOpen(t, filepath.Join(dpkgFixtureDir, "info", "dash.list"))}

	limits := DefaultLimits()
	limits.MaxListBytes = 10 // dash.list is much larger than 10 bytes

	idx, diag, err := ParseDpkg(status, []NamedReader{list}, limits)
	if err != nil {
		t.Fatalf("ParseDpkg: %v", err)
	}
	if !diag.Truncated {
		t.Error("Truncated = false, want true (list exceeded the byte limit)")
	}
	if len(diag.Errors) == 0 {
		t.Error("Errors is empty, want at least one entry for the oversized list")
	}
	if _, ok := idx.Lookup("/bin/dash"); ok {
		t.Error("Lookup(/bin/dash) succeeded from a file that should have been rejected as truncated")
	}
}

func TestParseDpkg_MaxPathsPerPackage(t *testing.T) {
	status := NamedReader{Name: "status", R: mustOpen(t, filepath.Join(dpkgFixtureDir, "status"))}
	list := NamedReader{Name: "bash.list", R: mustOpen(t, filepath.Join(dpkgFixtureDir, "info", "bash.list"))}

	limits := DefaultLimits()
	limits.MaxPathsPerPackage = 3 // bash.list has far more than 3 entries

	idx, diag, err := ParseDpkg(status, []NamedReader{list}, limits)
	if err != nil {
		t.Fatalf("ParseDpkg: %v", err)
	}
	if !diag.Truncated {
		t.Error("Truncated = false, want true (MaxPathsPerPackage was exceeded)")
	}
	count := 0
	for _, owners := range idx.byPath {
		for _, o := range owners {
			if o.Name == "bash" {
				count++
			}
		}
	}
	if count != 3 {
		t.Errorf("recorded %d bash-owned paths, want exactly 3 (the limit)", count)
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
