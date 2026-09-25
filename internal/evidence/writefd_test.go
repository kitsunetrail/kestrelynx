package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestWriteFD_RoundTrip confirms WriteFD produces bytes Reader.Read accepts,
// exercising the pwrite/ftruncate/fsync path a Sensor holding the evidence
// file as a bare descriptor would use instead of WriteTo's *os.File path.
func TestWriteFD_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()

	want := baseSnapshot(testNow)
	if err := WriteFD(int(f.Fd()), want); err != nil {
		t.Fatalf("WriteFD: %v", err)
	}

	r := Reader{Dir: dir}
	got, err := r.Read(testNow, nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Sensor.SessionID != want.Sensor.SessionID {
		t.Errorf("SessionID = %q, want %q", got.Sensor.SessionID, want.Sensor.SessionID)
	}
}

// TestWriteFD_SameBytesAsWriteTo pins WriteFD to producing byte-for-byte the
// same file content as WriteTo for the same snapshot: the two are two ways
// to reach the identical on-disk contract, not two formats.
func TestWriteFD_SameBytesAsWriteTo(t *testing.T) {
	dir := t.TempDir()
	snap := baseSnapshot(testNow)

	pathA := filepath.Join(dir, "a.json")
	fa, err := os.OpenFile(pathA, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	defer fa.Close()
	if err := WriteTo(fa, snap); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	pathB := filepath.Join(dir, "b.json")
	fb, err := os.OpenFile(pathB, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer fb.Close()
	if err := WriteFD(int(fb.Fd()), snap); err != nil {
		t.Fatalf("WriteFD: %v", err)
	}

	wantBytes, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatalf("read a: %v", err)
	}
	gotBytes, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatalf("read b: %v", err)
	}
	if string(gotBytes) != string(wantBytes) {
		t.Errorf("WriteFD produced different bytes than WriteTo:\nWriteFD: %q\nWriteTo: %q", gotBytes, wantBytes)
	}
}

// TestWriteFD_OverwritesShorterPreviousContent confirms the ftruncate step
// actually shortens the file when the new content is smaller than what was
// there before, matching WriteTo's contract (overwrite-in-place, not append).
func TestWriteFD_OverwritesShorterPreviousContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	big := baseSnapshot(testNow)
	big.Generations = make([]Generation, 5)
	id := hexID64('a')
	for i := range big.Generations {
		big.Generations[i] = Generation{
			Container:      ContainerRef{Runtime: "docker", ID: id},
			Init:           InitProcess{PID: 1000 + i, Starttime: 1},
			State:          StateObserving,
			PackageDB:      PackageDBInfo{Kind: DBKindDpkg, Status: DBStatusOK},
			StartedAt:      testNow.Add(-time.Hour),
			LastVerifiedAt: testNow,
			EventsCoverage: CoverageSinceStart,
		}
	}
	if err := WriteFD(int(f.Fd()), big); err != nil {
		t.Fatalf("WriteFD big: %v", err)
	}

	small := baseSnapshot(testNow)
	if err := WriteFD(int(f.Fd()), small); err != nil {
		t.Fatalf("WriteFD small: %v", err)
	}

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat: %v", err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if st.Size != int64(len(want)) {
		t.Errorf("file size %d does not match its own content length %d (ftruncate did not shrink the file)", st.Size, len(want))
	}

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); err != nil {
		t.Fatalf("Read after shrink: %v", err)
	}
}

// TestWriteFD_TornWriteDetectedViaTrailerMismatch confirms a file written by
// WriteFD is subject to the exact same torn-write detection Reader.Read
// applies to a WriteTo-written one: a same-length content change (the
// realistic shape of a reader observing a write mid-flight, between
// WriteFD's pwrite completing and its ftruncate/fsync — see corrupt())
// leaves the trailer's recorded checksum not matching the body, which Read
// catches and falls back to the last known-good value for rather than
// trusting. This mirrors TestRead_TrailerMismatchUsesPreviousValue, but
// through the raw-fd pwrite/ftruncate/fsync path the Sensor's observer
// actually uses instead of WriteTo's *os.File path.
func TestWriteFD_TornWriteDetectedViaTrailerMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	prev := baseSnapshot(testNow.Add(-time.Minute))

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := WriteFD(int(f.Fd()), prev); err != nil {
		t.Fatalf("WriteFD (previous value): %v", err)
	}
	f.Close()

	f2, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := WriteFD(int(f2.Fd()), baseSnapshot(testNow)); err != nil {
		t.Fatalf("WriteFD (next value): %v", err)
	}
	f2.Close()
	corrupt(t, path)

	r := Reader{Dir: dir} // RetryDelay zero: no real sleep in the test
	got, err := r.Read(testNow, &prev)
	if err != nil {
		t.Fatalf("Read after simulated torn write: %v (want fallback to previous value, not an error)", err)
	}
	if !got.Sensor.HeartbeatAt.Equal(prev.Sensor.HeartbeatAt) {
		t.Errorf("got heartbeat %v, want the previous value's %v (torn write was not detected)",
			got.Sensor.HeartbeatAt, prev.Sensor.HeartbeatAt)
	}
}
