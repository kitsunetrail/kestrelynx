package sensor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/pkgdb"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/rootfs"
)

// openTestRoot builds a rootfs.Reader confined to a fresh temp directory
// laid out however the caller likes — a stand-in for a container's rootfs
// that requires no container at all, since rootfs.Reader only needs an
// O_PATH directory descriptor to whatever root it is given.
func openTestRoot(t *testing.T) (*rootfs.Reader, string) {
	t.Helper()
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	return rootfs.Open(f), dir
}

func writeTestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

func TestDetectPackageDB_Dpkg(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)

	kind, status := detectPackageDB(r)
	if kind != evidence.DBKindDpkg || status != evidence.DBStatusOK {
		t.Errorf("detectPackageDB = (%q, %q), want (dpkg, ok)", kind, status)
	}
}

func TestDetectPackageDB_Apk(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "lib/apk/db/installed", "P:musl\nV:1.2.4-r2\n\n")

	kind, status := detectPackageDB(r)
	if kind != evidence.DBKindApk || status != evidence.DBStatusOK {
		t.Errorf("detectPackageDB = (%q, %q), want (apk, ok)", kind, status)
	}
}

func TestDetectPackageDB_Distroless(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status.d/libssl3", "Package: libssl3\nVersion: 3.0.15\n")

	kind, status := detectPackageDB(r)
	if kind != evidence.DBKindDistroless || status != evidence.DBStatusOK {
		t.Errorf("detectPackageDB = (%q, %q), want (distroless, ok)", kind, status)
	}
}

func TestDetectPackageDB_DpkgTakesPriorityOverDistroless(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	writeTestFile(t, dir, "var/lib/dpkg/status.d/extra", "Package: extra\n")

	kind, _ := detectPackageDB(r)
	if kind != evidence.DBKindDpkg {
		t.Errorf("detectPackageDB kind = %q, want dpkg (a real status file takes priority)", kind)
	}
}

func TestDetectPackageDB_RpmUnsupported(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/rpm/Packages", "not parsed")

	kind, status := detectPackageDB(r)
	if status != evidence.DBStatusUnsupported {
		t.Errorf("detectPackageDB status = %q, want unsupported", status)
	}
	if kind != "" {
		t.Errorf("detectPackageDB kind = %q, want empty for an unsupported db", kind)
	}
}

func TestDetectPackageDB_AbsentForBareGoContainer(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "app", "not a package db")

	kind, status := detectPackageDB(r)
	if status != evidence.DBStatusAbsent {
		t.Errorf("detectPackageDB status = %q, want absent", status)
	}
	if kind != "" {
		t.Errorf("detectPackageDB kind = %q, want empty when absent", kind)
	}
}

// TestDetectPackageDB_ExistsButUnreadableIsRetryableError covers the
// "database exists but this Sensor cannot open it right now" case
// (existsButUnreadable): unlike DBStatusAbsent (never retried), this must be
// DBStatusError, on the backoff schedule, since presence is confirmed —
// only a transient read failure (a permission mismatch this Sensor's own
// capabilities do not cover, a race with the container's own filesystem)
// stands between here and a real read.
func TestDetectPackageDB_ExistsButUnreadableIsRetryableError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: a mode-0000 file is still readable, so this test cannot observe EACCES")
	}
	r, dir := openTestRoot(t)
	defer r.Close()
	full := filepath.Join(dir, "var/lib/dpkg/status")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(testDpkgStatus), 0o000); err != nil {
		t.Fatal(err)
	}

	kind, status := detectPackageDB(r)
	if kind != evidence.DBKindDpkg {
		t.Errorf("kind = %q, want dpkg (the candidate path itself was found)", kind)
	}
	if status != evidence.DBStatusError {
		t.Errorf("status = %q, want error (present but unreadable, not absent)", status)
	}
}

func TestGatherIndexFiles_Dpkg(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)
	writeTestFile(t, dir, "var/lib/dpkg/info/zlib1g.list", testZlibList)
	writeTestFile(t, dir, "var/lib/dpkg/info/not-a-list.md5sums", "ignored")

	outcome, err := gatherIndexFiles(r, evidence.DBKindDpkg, pkgdb.DefaultLimits())
	if err != nil {
		t.Fatalf("gatherIndexFiles: %v", err)
	}
	if len(outcome.Files) != 3 { // status + 2 .list files (the .md5sums is skipped)
		t.Fatalf("got %d files, want 3: %+v", len(outcome.Files), outcome.Files)
	}
	var sawStatus bool
	for _, f := range outcome.Files {
		if f.Role == roleStatus {
			sawStatus = true
		}
	}
	if !sawStatus {
		t.Errorf("no status-role file among %+v", outcome.Files)
	}
}

// TestGatherIndexFiles_DpkgNamesStatusRegardlessOfExistence covers
// gatherIndexFiles' own contract now that it only enumerates candidates and
// never opens any of them (see its own doc comment): dpkg's mandatory
// status candidate is always named, whether or not the file actually
// exists on disk — discovering that is streamBuildFiles' own job, at the
// moment it tries to open it (see TestBuildFromRoot_MandatoryFileMissingRetries
// for the end-to-end "mandatory file cannot be opened" behavior, exercised
// there via distroless since dpkg/apk need a real race to reach it).
func TestGatherIndexFiles_DpkgNamesStatusRegardlessOfExistence(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)

	outcome, err := gatherIndexFiles(r, evidence.DBKindDpkg, pkgdb.DefaultLimits())
	if err != nil {
		t.Fatalf("gatherIndexFiles: %v", err)
	}
	var sawStatus bool
	for _, f := range outcome.Files {
		if f.Role == roleStatus {
			sawStatus = true
		}
	}
	if !sawStatus {
		t.Errorf("no status-role candidate among %+v, want one named even though the file itself does not exist", outcome.Files)
	}
}

func TestGatherIndexFiles_Distroless(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status.d/libssl3", "Package: libssl3\nVersion: 3.0.15\n")
	writeTestFile(t, dir, "var/lib/dpkg/status.d/libssl3.md5sums", "abc  usr/lib/libssl.so.3\n")

	outcome, err := gatherIndexFiles(r, evidence.DBKindDistroless, pkgdb.DefaultLimits())
	if err != nil {
		t.Fatalf("gatherIndexFiles: %v", err)
	}
	if len(outcome.Files) != 2 {
		t.Fatalf("got %d files, want 2: %+v", len(outcome.Files), outcome.Files)
	}
}
