package rootfs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// TestClassifyCalibration_Linux6_6RealRecord replays a real collected
// record: experiments/runtime-discovery out/13-root-30-300-p0-r1-
// attach_running-nofilter512p/collect/case13_*.json's inode_calibration
// object, taken on a 6.6.x kernel over OverlayFS. maps recorded dev 08:30
// for libc.so.6, but a fresh stat through the container's rootfs reported
// dev 00:54 for the same inode — pre-6.8 OverlayFS reporting the lower
// layer's dev in one place and the overlay's own dev in the other. VERIFIED
// against that real record.
func TestClassifyCalibration_Linux6_6RealRecord(t *testing.T) {
	got := ClassifyCalibration("08:30", 972676, "00:54", 972676)
	if got != CalibrationInodeOnly {
		t.Errorf("ClassifyCalibration = %q, want %q", got, CalibrationInodeOnly)
	}
}

// TestClassifyCalibration_Linux7_0RealRecord replays a real collected
// record from a container running a publicly available Elasticsearch image,
// captured on a 7.0.x kernel host: libc.so.6 (the same candidate file name
// the 6.6 case above used) read through the same inode_calibration capture
// method, with both dev and inode agreeing. VERIFIED against that real
// record.
//
// What is captured so far: the 6.6 case above (a generic Debian-based test
// container, kernel 6.6.x) and this 7.0 case (a public Elasticsearch image,
// kernel 7.0.x) are two different images on two different real hosts, each
// measured once, not the same image measured on both kernels.
//
// What is not yet verified: a direct 6.6-vs-7.0 comparison of the *same*
// public image, which would isolate the kernel as the only variable. No
// 7.0.x kernel host was available to take that measurement while building
// this fixture; it is left for a later real-machine verification pass
// (ASSUMED until then).
func TestClassifyCalibration_Linux7_0RealRecord(t *testing.T) {
	got := ClassifyCalibration("00:27", 17849987, "00:27", 17849987)
	if got != CalibrationDevInode {
		t.Errorf("ClassifyCalibration = %q, want %q", got, CalibrationDevInode)
	}
}

// TestClassifyCalibration_NeitherAgrees has no real record to replay (ASSUMED):
// it only exercises the third branch of a three-way comparison the two real
// records above don't reach.
func TestClassifyCalibration_NeitherAgrees(t *testing.T) {
	got := ClassifyCalibration("08:01", 111, "08:02", 222)
	if got != CalibrationUnknown {
		t.Errorf("ClassifyCalibration = %q, want %q", got, CalibrationUnknown)
	}
}

// TestCalibrate_AgreesOnRealFile exercises Calibrate end-to-end against a
// real file on this host's own filesystem: since nothing here is a
// container over OverlayFS, dev and inode both agree, which is itself a
// real (if less interesting) recorded combination — this is not a
// substitute for the 6.6/7.0 fixtures above, which are what establishes the
// inode-only case is real.
func TestCalibrate_AgreesOnRealFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prog")
	if err := os.WriteFile(path, []byte("binary content"), 0o755); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	candidates := []procfs.MapEntry{
		{Path: "/prog", Dev: formatDev(st.Dev), Inode: st.Ino, Perms: "r-xp"},
	}
	got, err := Calibrate(r, candidates)
	if err != nil {
		t.Fatalf("Calibrate: %v", err)
	}
	if got.Mode != CalibrationDevInode {
		t.Errorf("Mode = %q, want %q", got.Mode, CalibrationDevInode)
	}
	if got.Path != "/prog" {
		t.Errorf("Path = %q, want %q", got.Path, "/prog")
	}
}

func TestCalibrate_SkipsDeletedCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "real")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	candidates := []procfs.MapEntry{
		{Path: "/gone", Dev: "08:01", Inode: 1, Deleted: true},
		{Path: "/real", Dev: formatDev(st.Dev), Inode: st.Ino},
	}
	got, err := Calibrate(r, candidates)
	if err != nil {
		t.Fatalf("Calibrate: %v", err)
	}
	if got.Path != "/real" {
		t.Errorf("Path = %q, want the non-deleted candidate %q", got.Path, "/real")
	}
}

func TestCalibrate_SkipsUnresolvableCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "real")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	candidates := []procfs.MapEntry{
		{Path: "/does-not-exist", Dev: "08:01", Inode: 1},
		{Path: "/real", Dev: formatDev(st.Dev), Inode: st.Ino},
	}
	got, err := Calibrate(r, candidates)
	if err != nil {
		t.Fatalf("Calibrate: %v", err)
	}
	if got.Path != "/real" {
		t.Errorf("Path = %q, want the resolvable candidate %q", got.Path, "/real")
	}
}

func TestCalibrate_NoUsableCandidate(t *testing.T) {
	dir := t.TempDir()
	r := openRoot(t, dir)
	defer r.Close()

	candidates := []procfs.MapEntry{
		{Path: "/gone", Dev: "08:01", Inode: 1, Deleted: true},
		{Path: "/missing", Dev: "08:01", Inode: 2},
	}
	if _, err := Calibrate(r, candidates); err != ErrNoCalibrationCandidate {
		t.Errorf("Calibrate error = %v, want ErrNoCalibrationCandidate", err)
	}
}
