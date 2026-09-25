package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FileName is the one filename Read will ever open inside the evidence
// directory. There is no path assembled from anything a Sensor writes: Read
// always opens exactly this name, relative to a directory file descriptor,
// with O_NOFOLLOW, so a compromised Sensor cannot redirect the read to an
// arbitrary path by replacing that name with a symlink.
const FileName = "procfs.json"

// trailerPrefix opens the trailer line WriteTo appends and Read parses back
// out. It is deliberately not itself JSON, so a torn write can be detected
// before the JSON body is trusted at all.
const trailerPrefix = "#kestrelynx-evidence "

// ErrNotReporting means no evidence file exists yet: the Sensor has never
// written one (not started, or evidence_dir misconfigured). It is distinct
// from ErrInvalid — a missing file is "not reporting", a malformed one is
// "invalid" — because the two are shown differently to the reader.
var ErrNotReporting = errors.New("evidence: sensor not reporting")

// ErrInvalid means an evidence file exists but failed validation: wrong
// type (not a regular file, a symlink), too large, malformed JSON, or a
// value outside a range Read enforces.
var ErrInvalid = errors.New("evidence: invalid")

// errTornWrite is the one failure Read treats as retryable: the trailer's
// recorded length/checksum didn't match the body actually read, which is
// what a write caught mid-flight looks like. Every other failure is
// immediately ErrNotReporting or ErrInvalid, with no retry and no
// previous-value fallback.
var errTornWrite = errors.New("evidence: torn write")

// Reader reads one Sensor's evidence file under a fixed contract: a fixed
// filename opened by name only, a symlink or anything but a regular file
// refused, and size/count/format limits enforced before any of the content
// is trusted.
type Reader struct {
	Dir string
	// RetryDelay is how long Read waits before its one retry on a
	// torn-write failure. NewReader sets the production default (1s); the
	// zero value skips the wait, which is what tests want.
	RetryDelay time.Duration
	// afterFirstRead, when set, runs synchronously right after the first
	// readOnce and before RetryDelay's sleep. It exists only so a test can
	// deterministically arrange what the retry will observe (e.g. fix or
	// further corrupt the file) without racing a real sleep against a
	// background writer. Production code never sets it, and Read's behavior
	// is unchanged when it is nil.
	afterFirstRead func()
}

// NewReader builds a Reader with the production retry delay.
func NewReader(dir string) Reader {
	return Reader{Dir: dir, RetryDelay: time.Second}
}

// Read returns the current, validated snapshot. On a torn-write failure it
// waits RetryDelay and reads once more. The previous-value fallback is only
// reached when that retry fails with the *same* torn-write condition: if the
// retry instead fails a different way (a schema change, a symlink swapped
// in between the two reads, and so on), that error is what Read returns —
// prev is never substituted for a failure other than a torn write persisting
// across the retry. When the retry is itself a torn-write failure, and prev
// is non-nil and its own heartbeat is still fresh as of now
// (StalenessThreshold, re-evaluated here rather than assumed), Read returns
// *prev instead of an error.
func (r Reader) Read(now time.Time, prev *Snapshot) (Snapshot, error) {
	snap, err := r.readOnce(now)
	if err == nil {
		return snap, nil
	}
	if !errors.Is(err, errTornWrite) {
		return Snapshot{}, err
	}

	if r.afterFirstRead != nil {
		r.afterFirstRead()
	}
	if r.RetryDelay > 0 {
		time.Sleep(r.RetryDelay)
	}
	snap, retryErr := r.readOnce(now)
	if retryErr == nil {
		return snap, nil
	}
	if !errors.Is(retryErr, errTornWrite) {
		return Snapshot{}, retryErr
	}
	if prev != nil && !IsStale(prev.Sensor.HeartbeatAt, now, prev.Sensor.IntervalSeconds) {
		return *prev, nil
	}
	return Snapshot{}, fmt.Errorf("%w: torn write persisted after retry (%v)", ErrInvalid, retryErr)
}

// readOnce performs exactly one open-validate-parse pass.
func (r Reader) readOnce(now time.Time) (Snapshot, error) {
	dirFD, err := syscall.Open(r.Dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return Snapshot{}, ErrNotReporting
		}
		return Snapshot{}, fmt.Errorf("%w: open evidence dir %s: %v", ErrInvalid, r.Dir, err)
	}
	defer syscall.Close(dirFD)

	// O_NOFOLLOW rejects a symlink at FileName outright (ELOOP). O_NONBLOCK
	// keeps a FIFO placed at that name from blocking the open call itself;
	// the regular-file check just below is what actually rejects a FIFO,
	// device or directory once the open has succeeded.
	fd, err := syscall.Openat(dirFD, FileName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return Snapshot{}, ErrNotReporting
		}
		return Snapshot{}, fmt.Errorf("%w: open %s: %v", ErrInvalid, FileName, err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(r.Dir, FileName))
	defer f.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return Snapshot{}, fmt.Errorf("%w: stat %s: %v", ErrInvalid, FileName, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return Snapshot{}, fmt.Errorf("%w: %s is not a regular file", ErrInvalid, FileName)
	}
	if st.Size > maxFileBytes {
		return Snapshot{}, fmt.Errorf("%w: %s is %d bytes, over the %d limit", ErrInvalid, FileName, st.Size, maxFileBytes)
	}

	// The size cap is enforced again while reading (not just via the Fstat
	// above) in case the underlying file grows between the two calls.
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: read %s: %v", ErrInvalid, FileName, err)
	}
	if len(data) > maxFileBytes {
		return Snapshot{}, fmt.Errorf("%w: %s exceeds the %d byte limit while reading", ErrInvalid, FileName, maxFileBytes)
	}

	body, err := verifyTrailer(data)
	if err != nil {
		return Snapshot{}, err
	}

	// json.Unmarshal silently replaces an invalid UTF-8 byte inside a JSON
	// string with U+FFFD rather than erroring — including one the Sensor's
	// own Go JSON encoder produced from a string it read with invalid bytes
	// in it, since Go sanitizes on the way out the same way it does on the
	// way in. That replacement character is what validateSnapshot's string
	// checks reject afterward (see validString), which is what turns a bad
	// byte in one path or version into that one record being dropped and its
	// generation marked incomplete, rather than every record needing to be
	// checked here against the raw bytes before trusting any of it as text.
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("%w: parse %s: %v", ErrInvalid, FileName, err)
	}
	if err := validateSnapshot(&snap, now); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// verifyTrailer locates the trailer line, checks it against the body it
// claims to describe, and returns just the body on success. A mismatch is
// errTornWrite (retryable); a missing or malformed trailer is ErrInvalid
// (not retryable — that is not what a torn write in progress looks like).
func verifyTrailer(data []byte) ([]byte, error) {
	idx := bytes.LastIndex(data, []byte("\n"+trailerPrefix))
	if idx < 0 {
		return nil, fmt.Errorf("%w: no trailer found in %s", ErrInvalid, FileName)
	}
	body := data[:idx]
	line := string(bytes.TrimSuffix(data[idx+1:], []byte("\n")))

	length, sum, err := parseTrailerLine(line)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed trailer %q: %v", ErrInvalid, line, err)
	}
	if length != len(body) {
		return nil, fmt.Errorf("%w: trailer length %d does not match body length %d", errTornWrite, length, len(body))
	}
	got := sha256.Sum256(body)
	if fmt.Sprintf("%x", got) != sum {
		return nil, fmt.Errorf("%w: trailer checksum does not match body", errTornWrite)
	}
	return body, nil
}

// parseTrailerLine parses "#kestrelynx-evidence length=<n> sha256=<hex>"
// without regexp/Sscanf, whose %x verb does not scan into a string the way
// this format needs.
func parseTrailerLine(line string) (length int, sum string, err error) {
	rest, ok := strings.CutPrefix(line, trailerPrefix)
	if !ok {
		return 0, "", fmt.Errorf("missing %q prefix", trailerPrefix)
	}
	fields := strings.Fields(rest)
	if len(fields) != 2 {
		return 0, "", fmt.Errorf("expected 2 fields, got %d", len(fields))
	}
	lengthStr, ok := strings.CutPrefix(fields[0], "length=")
	if !ok {
		return 0, "", fmt.Errorf("missing length= field")
	}
	sumStr, ok := strings.CutPrefix(fields[1], "sha256=")
	if !ok {
		return 0, "", fmt.Errorf("missing sha256= field")
	}
	n, err := strconv.Atoi(lengthStr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid length: %w", err)
	}
	if n < 0 {
		return 0, "", fmt.Errorf("negative length")
	}
	if len(sumStr) != sha256.Size*2 {
		return 0, "", fmt.Errorf("sha256 field is %d hex chars, want %d", len(sumStr), sha256.Size*2)
	}
	for _, r := range sumStr {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return 0, "", fmt.Errorf("sha256 field is not lowercase hex")
		}
	}
	return n, sumStr, nil
}
