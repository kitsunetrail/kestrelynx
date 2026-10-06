package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

var testNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// hexID64 returns a 64-hex-digit string built from a single repeated digit,
// which is all these tests need from a syntactically valid container ID.
func hexID64(digit byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = digit
	}
	return string(b)
}

// baseSnapshot builds a minimal, otherwise-valid snapshot for a fixed clock,
// so each test only has to override the one field it cares about.
func baseSnapshot(now time.Time) Snapshot {
	return Snapshot{
		Schema: Schema,
		Sensor: SensorInfo{
			Version:          "test",
			SessionID:        "session-1",
			SessionStartedAt: now.Add(-time.Hour),
			HeartbeatAt:      now,
			IntervalSeconds:  30,
			Status:           SensorOK,
			Events:           EventsInfo{Status: EventsUnavailable, Reason: EventsReasonKernelUnsupported},
		},
	}
}

// writeEvidence writes snap into dir/procfs.json using the same WriteTo path
// a Sensor would use, via an ordinary O_RDWR|O_CREATE open (there is no
// Sensor process here to open the fd under capability drop; only the byte
// format WriteTo produces is under test here).
func writeEvidence(t *testing.T, dir string, snap Snapshot) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	defer f.Close()
	if err := WriteTo(f, snap); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
}

func TestReadWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := baseSnapshot(testNow)
	// Build a valid 64-hex id without relying on a literal 64-char string.
	id := ""
	for i := 0; i < 64; i++ {
		id += "0"
	}
	want.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: id},
	}}
	want.Generations[0].Init = InitProcess{PID: 1234, Starttime: 5678}
	want.Generations[0].State = StateObserving
	want.Generations[0].PackageDB = PackageDBInfo{Kind: DBKindDpkg, Status: DBStatusOK}
	want.Generations[0].StartedAt = testNow.Add(-time.Hour)
	want.Generations[0].LastVerifiedAt = testNow
	want.Generations[0].EventsCoverage = CoverageSinceStart
	want.Generations[0].OSPackages = []OSPackageEvidence{{
		Name: "libssl3", Version: "3.0.15-1~deb12u1",
		Kinds: map[EvidenceKind]KindObservation{
			KindMappedLibrary: {FirstSeen: testNow.Add(-time.Minute), LastSeen: testNow, Samples: 3},
		},
		Observations: []ProcessObservation{{Exe: "/usr/sbin/nginx", EffectiveUID: 0, Listeners: []string{"tcp:0.0.0.0:443"}, LastSeen: testNow}},
	}}

	writeEvidence(t, dir, want)

	r := Reader{Dir: dir}
	got, err := r.Read(testNow, nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Generations) != 1 {
		t.Fatalf("got %d generations, want 1", len(got.Generations))
	}
	g := got.Generations[0]
	if g.Container.ID != id || g.Init.PID != 1234 || g.Init.Starttime != 5678 {
		t.Errorf("generation identity mismatch: %+v", g.Container)
	}
	if len(g.OSPackages) != 1 || g.OSPackages[0].Name != "libssl3" {
		t.Fatalf("os_packages not round-tripped: %+v", g.OSPackages)
	}
	if g.Incomplete || g.Truncated {
		t.Errorf("valid input marked incomplete/truncated: %+v", g)
	}
}

func TestRead_NoFile(t *testing.T) {
	dir := t.TempDir()
	r := Reader{Dir: dir}
	_, err := r.Read(testNow, nil)
	if !errors.Is(err, ErrNotReporting) {
		t.Fatalf("got %v, want ErrNotReporting", err)
	}
}

func TestRead_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	writeEvidence(t, dir, baseSnapshot(testNow))
	if err := os.Rename(filepath.Join(dir, FileName), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}

	r := Reader{Dir: dir}
	_, err := r.Read(testNow, nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (symlink)", err)
	}
}

func TestRead_RejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, FileName), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	r := Reader{Dir: dir}
	_, err := r.Read(testNow, nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (FIFO)", err)
	}
}

func TestRead_RejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, FileName), 0o755); err != nil {
		t.Fatal(err)
	}

	r := Reader{Dir: dir}
	_, err := r.Read(testNow, nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (directory)", err)
	}
}

func TestRead_TooLarge(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r := Reader{Dir: dir}
	_, err = r.Read(testNow, nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (too large)", err)
	}
}

func TestRead_TooManyGenerations(t *testing.T) {
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	snap.Generations = make([]Generation, maxGenerations+1)
	for i := range snap.Generations {
		id := ""
		for j := 0; j < 64; j++ {
			id += "0"
		}
		snap.Generations[i] = Generation{
			Container: ContainerRef{Runtime: "docker", ID: id}, Init: InitProcess{PID: i + 1},
			State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
		}
	}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	_, err := r.Read(testNow, nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (too many generations)", err)
	}
}

func TestRead_IntervalSecondsOutOfRange(t *testing.T) {
	for _, interval := range []int{0, 9, 301, 3600} {
		dir := t.TempDir()
		snap := baseSnapshot(testNow)
		snap.Sensor.IntervalSeconds = interval
		writeEvidence(t, dir, snap)

		r := Reader{Dir: dir}
		if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("interval %d: got %v, want ErrInvalid", interval, err)
		}
	}
}

func TestRead_FutureHeartbeatRejected(t *testing.T) {
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	snap.Sensor.HeartbeatAt = testNow.Add(10 * time.Minute)
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (future heartbeat)", err)
	}
}

func TestRead_RetryAfterFutureException(t *testing.T) {
	id := ""
	for i := 0; i < 64; i++ {
		id += "0"
	}
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: id}, Init: InitProcess{PID: 1},
		State: StateParseFailed, PackageDB: PackageDBInfo{Status: DBStatusError},
		ParseFailed: []ParseFailure{{
			Input: "dpkg_status", Path: "/var/lib/dpkg/status",
			FailedAt: testNow, Count: 1,
			// 10 hours ahead: within the retry-after backoff window, must
			// not be treated as an ordinary future timestamp.
			RetryAfter: testNow.Add(10 * time.Hour),
		}},
	}}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	got, err := r.Read(testNow, nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Generations) != 1 || len(got.Generations[0].ParseFailed) != 1 {
		t.Fatalf("parse_failed with in-window retry_after was dropped: %+v", got.Generations)
	}
}

// TestRead_RetryAfterBeyondBackoffCapRejectsWholeFile checks that a
// retry_after outside its allowed window is a future-timestamp violation,
// not a string violation: it invalidates the whole file (ErrInvalid) rather
// than being dropped as an individual bad record.
func TestRead_RetryAfterBeyondBackoffCapRejectsWholeFile(t *testing.T) {
	id := ""
	for i := 0; i < 64; i++ {
		id += "0"
	}
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: id}, Init: InitProcess{PID: 1},
		State: StateParseFailed, PackageDB: PackageDBInfo{Status: DBStatusError},
		ParseFailed: []ParseFailure{{
			Input: "dpkg_status", Path: "/var/lib/dpkg/status",
			FailedAt:   testNow,
			Count:      1,
			RetryAfter: testNow.Add(48 * time.Hour), // beyond the 24h backoff cap
		}},
	}}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	_, err := r.Read(testNow, nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (retry_after beyond backoff cap)", err)
	}
}

func TestRead_TrailerMismatchUsesPreviousValue(t *testing.T) {
	dir := t.TempDir()
	prev := baseSnapshot(testNow.Add(-time.Minute))

	good := baseSnapshot(testNow)
	writeEvidence(t, dir, good)
	corrupt(t, filepath.Join(dir, FileName))

	r := Reader{Dir: dir} // RetryDelay zero: no real sleep in the test
	got, err := r.Read(testNow, &prev)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !got.Sensor.HeartbeatAt.Equal(prev.Sensor.HeartbeatAt) {
		t.Fatalf("got heartbeat %v, want previous value's %v", got.Sensor.HeartbeatAt, prev.Sensor.HeartbeatAt)
	}
}

func TestRead_TrailerMismatchNoPreviousValueFails(t *testing.T) {
	dir := t.TempDir()
	writeEvidence(t, dir, baseSnapshot(testNow))
	corrupt(t, filepath.Join(dir, FileName))

	r := Reader{Dir: dir}
	_, err := r.Read(testNow, nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestRead_TrailerMismatchStalePreviousValueFails(t *testing.T) {
	dir := t.TempDir()
	// prev's heartbeat is stale: interval 30s -> staleness threshold 5m, and
	// prev is 10 minutes old as of testNow.
	prev := baseSnapshot(testNow.Add(-10 * time.Minute))
	writeEvidence(t, dir, baseSnapshot(testNow))
	corrupt(t, filepath.Join(dir, FileName))

	r := Reader{Dir: dir}
	_, err := r.Read(testNow, &prev)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (stale previous value)", err)
	}
}

func TestRead_MalformedContainerIDRejected(t *testing.T) {
	cases := map[string]string{
		"too short":     hexID64('0')[:63],
		"too long":      hexID64('0') + "0",
		"uppercase hex": hexID64('0')[:63] + "A",
		"non-hex char":  hexID64('0')[:63] + "g",
		"empty":         "",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			snap := baseSnapshot(testNow)
			snap.Generations = []Generation{{
				Container: ContainerRef{Runtime: "docker", ID: id},
				State:     StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
			}}
			writeEvidence(t, dir, snap)

			r := Reader{Dir: dir}
			if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
				t.Errorf("got %v, want ErrInvalid (malformed container id)", err)
			}
		})
	}
}

// TestRead_UnsupportedRuntimeRejected pins that a container ID is validated
// regardless of what Runtime claims: an unsupported or missing runtime must
// not skip ID validation by falling through as "not docker, so not
// checked".
func TestRead_UnsupportedRuntimeRejected(t *testing.T) {
	cases := []string{"", "kubernetes", "podman"}
	for _, runtime := range cases {
		t.Run(fmt.Sprintf("runtime=%q", runtime), func(t *testing.T) {
			dir := t.TempDir()
			snap := baseSnapshot(testNow)
			snap.Generations = []Generation{{
				Container: ContainerRef{Runtime: runtime, ID: "x"}, // not even hex-shaped
				State:     StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
			}}
			writeEvidence(t, dir, snap)

			r := Reader{Dir: dir}
			if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
				t.Errorf("runtime %q: got %v, want ErrInvalid", runtime, err)
			}
		})
	}
}

func TestRead_DuplicateGenerationKeyRejected(t *testing.T) {
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	gen := Generation{
		Container: ContainerRef{Runtime: "docker", ID: hexID64('0')}, Init: InitProcess{PID: 1, Starttime: 100},
		State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
	}
	snap.Generations = []Generation{gen, gen} // identical (id, pid, starttime) twice
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (duplicate generation key)", err)
	}
}

func TestRead_TooManyEntitiesInGenerationRejected(t *testing.T) {
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	pkgs := make([]OSPackageEvidence, maxEntitiesPerGeneration+1)
	for i := range pkgs {
		pkgs[i] = OSPackageEvidence{Name: fmt.Sprintf("pkg%d", i), Version: "1"}
	}
	snap.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: hexID64('0')},
		State:     StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
		OSPackages: pkgs,
	}}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (too many entities)", err)
	}
}

// TestRead_TooManyObservationsRejectsWholeFile checks that exceeding the
// per-record observation cap invalidates the whole file, rather than
// dropping just that one package and marking the generation incomplete —
// exceeding a count is a format violation like an oversized file, not a
// per-record string problem.
func TestRead_TooManyObservationsRejectsWholeFile(t *testing.T) {
	dir := t.TempDir()
	obs := make([]ProcessObservation, maxObservationsPerEntity+1)
	for i := range obs {
		obs[i] = ProcessObservation{LastSeen: testNow}
	}
	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: hexID64('0')},
		State:     StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
		OSPackages: []OSPackageEvidence{{Name: "libssl3", Version: "1", Observations: obs}},
	}}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (too many observations)", err)
	}
}

// TestRead_FutureKindTimestampRejectsWholeFile checks that a future
// timestamp nested inside a kind observation invalidates the whole file,
// not just the record it's on.
func TestRead_FutureKindTimestampRejectsWholeFile(t *testing.T) {
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: hexID64('0')},
		State:     StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
		OSPackages: []OSPackageEvidence{{
			Name: "libssl3", Version: "1",
			Kinds: map[EvidenceKind]KindObservation{
				KindMappedLibrary: {FirstSeen: testNow, LastSeen: testNow.Add(10 * time.Minute)},
			},
		}},
	}}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (future kind timestamp)", err)
	}
}

// TestRead_FutureObservationTimestampRejectsWholeFile is the same check for
// a process observation's own LastSeen.
func TestRead_FutureObservationTimestampRejectsWholeFile(t *testing.T) {
	dir := t.TempDir()
	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: hexID64('0')},
		State:     StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
		OSPackages: []OSPackageEvidence{{
			Name: "libssl3", Version: "1",
			Observations: []ProcessObservation{{LastSeen: testNow.Add(10 * time.Minute)}},
		}},
	}}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (future observation timestamp)", err)
	}
}

// TestRead_InvalidUTF8InSessionIDRejectsWholeFile checks that an invalid
// UTF-8 byte spliced into sensor.session_id invalidates the whole file.
// session_id has no per-record "drop and continue" home of its own (it
// isn't an element of any list), so a bad byte in it is treated like a
// malformed container ID: the whole file is untrustworthy, not just one
// record.
//
// This can only be tested by writing raw bytes directly: encoding a Go
// struct through WriteTo is not a way to reach this case, because
// json.Marshal itself sanitizes an invalid Go string to U+FFFD on the way
// out, the same way json.Unmarshal does on the way in — the bad byte has to
// be spliced into the file's bytes after encoding, with a trailer computed
// over exactly those bytes.
func TestRead_InvalidUTF8InSessionIDRejectsWholeFile(t *testing.T) {
	valid, err := json.Marshal(baseSnapshot(testNow))
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("session-1")
	idx := bytes.Index(valid, marker)
	if idx < 0 {
		t.Fatal("marker not found in encoded snapshot")
	}
	body := make([]byte, 0, len(valid)+1)
	body = append(body, valid[:idx]...)
	body = append(body, 0x80) // a lone continuation byte: invalid UTF-8 on its own
	body = append(body, valid[idx:]...)

	dir := writeRawEvidence(t, t.TempDir(), body)

	r := Reader{Dir: dir}
	if _, err := r.Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (invalid UTF-8 in session_id)", err)
	}
}

// TestRead_InvalidUTF8InPackageVersionDropsOnlyThatRecord checks the
// opposite scope: an invalid UTF-8 byte inside one package's version — a
// field with a "drop and continue" home (its own OSPackageEvidence record)
// — drops only that record and marks only its own generation Incomplete.
// A sibling package in the same generation, and every package in an
// unrelated generation, are returned unchanged.
func TestRead_InvalidUTF8InPackageVersionDropsOnlyThatRecord(t *testing.T) {
	genAID, genBID := hexID64('1'), hexID64('2')
	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{
		{
			Container: ContainerRef{Runtime: "docker", ID: genAID}, Init: InitProcess{PID: 1},
			State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
			OSPackages: []OSPackageEvidence{
				{Name: "good-pkg", Version: "1.0.0", Kinds: map[EvidenceKind]KindObservation{KindExe: {LastSeen: testNow}}},
				{Name: "bad-pkg", Version: "zzzMARKERzzz", Kinds: map[EvidenceKind]KindObservation{KindExe: {LastSeen: testNow}}},
			},
		},
		{
			Container: ContainerRef{Runtime: "docker", ID: genBID}, Init: InitProcess{PID: 2},
			State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
			OSPackages: []OSPackageEvidence{
				{Name: "other-pkg", Version: "2.0.0", Kinds: map[EvidenceKind]KindObservation{KindExe: {LastSeen: testNow}}},
			},
		},
	}

	valid, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("zzzMARKERzzz")
	idx := bytes.Index(valid, marker)
	if idx < 0 {
		t.Fatal("marker not found in encoded snapshot")
	}
	body := make([]byte, 0, len(valid)+1)
	body = append(body, valid[:idx]...)
	body = append(body, 0x80) // a lone continuation byte: invalid UTF-8 on its own
	body = append(body, valid[idx:]...)

	dir := writeRawEvidence(t, t.TempDir(), body)

	r := Reader{Dir: dir}
	got, err := r.Read(testNow, nil)
	if err != nil {
		t.Fatalf("Read: %v, want success (only the bad record should be dropped)", err)
	}
	if len(got.Generations) != 2 {
		t.Fatalf("got %d generations, want 2 (neither generation is dropped)", len(got.Generations))
	}

	var genA, genB *Generation
	for i := range got.Generations {
		switch got.Generations[i].Container.ID {
		case genAID:
			genA = &got.Generations[i]
		case genBID:
			genB = &got.Generations[i]
		}
	}
	if genA == nil || genB == nil {
		t.Fatalf("expected both generations present: %+v", got.Generations)
	}

	if !genA.Incomplete {
		t.Error("generation A (holding the corrupt record) should be marked incomplete")
	}
	if len(genA.OSPackages) != 1 || genA.OSPackages[0].Name != "good-pkg" {
		t.Errorf("generation A packages = %+v, want only good-pkg (bad-pkg dropped)", genA.OSPackages)
	}

	if genB.Incomplete {
		t.Error("generation B is unrelated and must not be marked incomplete")
	}
	if len(genB.OSPackages) != 1 || genB.OSPackages[0].Name != "other-pkg" {
		t.Errorf("generation B packages = %+v, want other-pkg unchanged", genB.OSPackages)
	}
}

// writeRawEvidence writes body plus a correctly-computed trailer directly,
// bypassing WriteTo/json.Marshal so a test can construct byte sequences no
// valid Go struct could produce. It returns the directory it wrote into.
func writeRawEvidence(t *testing.T, dir string, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	trailer := fmt.Sprintf("\n%slength=%d sha256=%x\n", trailerPrefix, len(body), sum)
	full := append(append([]byte{}, body...), []byte(trailer)...)
	if err := os.WriteFile(filepath.Join(dir, FileName), full, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestRead_RetrySucceedsUsesRetryResult pins the mechanics directly: when
// the first read is a torn write and the retry is not, Read must use the
// retry's own result rather than only ever falling back to a previous
// value.
func TestRead_RetrySucceedsUsesRetryResult(t *testing.T) {
	dir := t.TempDir()
	good := baseSnapshot(testNow)
	writeEvidence(t, dir, good)
	corrupt(t, filepath.Join(dir, FileName))

	r := Reader{Dir: dir}
	if _, err := r.readOnce(testNow); !errors.Is(err, errTornWrite) {
		t.Fatalf("setup: got %v, want errTornWrite", err)
	}

	// The write completes correctly before the retry.
	writeEvidence(t, dir, good)
	got, err := r.readOnce(testNow)
	if err != nil {
		t.Fatalf("retry readOnce: %v", err)
	}
	if !got.Sensor.HeartbeatAt.Equal(good.Sensor.HeartbeatAt) {
		t.Errorf("got heartbeat %v, want %v", got.Sensor.HeartbeatAt, good.Sensor.HeartbeatAt)
	}
}

// TestRead_RetrySucceedsThroughReadEntryPoint exercises the retry sequence
// through the public Read entry point. The unexported afterFirstRead hook —
// not a real sleep and a background writer racing it — is what fixes the
// file between the first read and the retry, so the sequencing is exact
// regardless of how the test machine happens to schedule goroutines. A torn
// write that clears on retry must return the retry's own snapshot, never
// fall back to prev even though prev is available and fresh.
func TestRead_RetrySucceedsThroughReadEntryPoint(t *testing.T) {
	dir := t.TempDir()
	good := baseSnapshot(testNow)
	writeEvidence(t, dir, good)
	corrupt(t, filepath.Join(dir, FileName))
	prev := baseSnapshot(testNow.Add(-time.Minute)) // fresh; must NOT be what's returned

	r := Reader{Dir: dir}
	r.afterFirstRead = func() {
		writeEvidence(t, dir, good)
	}
	got, err := r.Read(testNow, &prev)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !got.Sensor.HeartbeatAt.Equal(good.Sensor.HeartbeatAt) {
		t.Errorf("got heartbeat %v, want the retry's own value %v (not prev's %v)", got.Sensor.HeartbeatAt, good.Sensor.HeartbeatAt, prev.Sensor.HeartbeatAt)
	}
}

// TestRead_RetryDifferentErrorReturnedNotPrev checks that when the retry
// fails a *different* way than the first read (here: an unsupported schema,
// not a torn write), Read surfaces that error directly and never falls back
// to prev — the previous-value exception is for a torn write persisting
// across the retry, not for "the retry failed somehow". The afterFirstRead
// hook fixes the sequencing deterministically, the same way the success case
// above does.
func TestRead_RetryDifferentErrorReturnedNotPrev(t *testing.T) {
	dir := t.TempDir()
	good := baseSnapshot(testNow)
	writeEvidence(t, dir, good)
	corrupt(t, filepath.Join(dir, FileName))
	prev := baseSnapshot(testNow.Add(-time.Minute)) // fresh; must NOT be returned either

	badSchema := good
	badSchema.Schema = 99

	r := Reader{Dir: dir}
	r.afterFirstRead = func() {
		writeEvidence(t, dir, badSchema)
	}
	_, err := r.Read(testNow, &prev)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid (the retry's own schema error)", err)
	}
	if errors.Is(err, errTornWrite) {
		t.Errorf("got a torn-write error, want the retry's own schema error")
	}
}

// TestReadWrite_ObservationsPreserveDistinctSameSampleCombos pins that two
// same-sample/same-process combinations for one package — one recorded
// while a process still ran as root, before it dropped privileges, and one
// recorded afterward once it held a listening socket — round-trip as two
// distinct ProcessObservation entries. Neither Read nor the underlying JSON
// format has any step that could fold or reorder them into a single record,
// which would misattribute the post-drop listener to the root identity (or
// vice versa).
func TestReadWrite_ObservationsPreserveDistinctSameSampleCombos(t *testing.T) {
	dir := t.TempDir()
	beforeDrop := ProcessObservation{Exe: "/usr/sbin/nginx", EffectiveUID: 0, LastSeen: testNow.Add(-time.Minute)}
	afterDrop := ProcessObservation{Exe: "/usr/sbin/nginx", EffectiveUID: 65532, Listeners: []string{"tcp:0.0.0.0:8080"}, LastSeen: testNow}

	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{{
		Container: ContainerRef{Runtime: "docker", ID: hexID64('0')},
		State:     StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
		OSPackages: []OSPackageEvidence{{
			Name: "nginx", Version: "1.25.0",
			Kinds:        map[EvidenceKind]KindObservation{KindExe: {LastSeen: testNow}},
			Observations: []ProcessObservation{beforeDrop, afterDrop},
		}},
	}}
	writeEvidence(t, dir, snap)

	r := Reader{Dir: dir}
	got, err := r.Read(testNow, nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	obs := got.Generations[0].OSPackages[0].Observations
	if len(obs) != 2 {
		t.Fatalf("got %d observations, want 2 (distinct, unmerged)", len(obs))
	}
	if obs[0].EffectiveUID != 0 || len(obs[0].Listeners) != 0 {
		t.Errorf("pre-drop observation changed: %+v", obs[0])
	}
	if obs[1].EffectiveUID != 65532 || len(obs[1].Listeners) != 1 {
		t.Errorf("post-drop observation changed, or was merged with pre-drop's UID: %+v", obs[1])
	}
}

// corrupt flips one byte inside the JSON body (well before the trailer) so
// the trailer's recorded checksum no longer matches — simulating a read
// caught mid-write, without actually racing a writer.
func corrupt(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 2 {
		t.Fatal("file too short to corrupt")
	}
	// The body is JSON starting with '{'; replacing it with another brace
	// keeps the file structurally similar while changing its checksum, which
	// is all verifyTrailer's mismatch check cares about.
	if data[0] == '{' {
		data[0] = '['
	} else {
		data[0] = '{'
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRead_KernelLostRoundTripAndCompatibility pins both directions of the
// kernel_lost field: a snapshot carrying it round-trips, and a body without
// it (written by a Sensor that predates it) is accepted and reads as zero.
func TestRead_KernelLostRoundTripAndCompatibility(t *testing.T) {
	dir := t.TempDir()
	want := baseSnapshot(testNow)
	want.Sensor.Events.Lost = 7
	want.Sensor.Events.KernelLost = 5
	writeEvidence(t, dir, want)
	got, err := Reader{Dir: dir}.Read(testNow, nil)
	if err != nil {
		t.Fatalf("Read with kernel_lost: %v", err)
	}
	if got.Sensor.Events.KernelLost != 5 || got.Sensor.Events.Lost != 7 {
		t.Errorf("events = %+v, want lost 7 and kernel_lost 5", got.Sensor.Events)
	}

	body, err := json.Marshal(baseSnapshot(testNow))
	if err != nil {
		t.Fatal(err)
	}
	legacy := bytes.Replace(body, []byte(`,"kernel_lost":0`), nil, 1)
	if bytes.Equal(legacy, body) {
		t.Fatalf("test setup: kernel_lost not found in %s", body)
	}
	legacyDir := writeRawEvidence(t, t.TempDir(), legacy)
	got, err = Reader{Dir: legacyDir}.Read(testNow, nil)
	if err != nil {
		t.Fatalf("Read without kernel_lost: %v", err)
	}
	if got.Sensor.Events.KernelLost != 0 {
		t.Errorf("KernelLost = %d, want 0 when absent", got.Sensor.Events.KernelLost)
	}

	neg := baseSnapshot(testNow)
	neg.Sensor.Events.KernelLost = -1
	negDir := t.TempDir()
	writeEvidence(t, negDir, neg)
	if _, err := (Reader{Dir: negDir}).Read(testNow, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("negative kernel_lost err = %v, want ErrInvalid", err)
	}
}
