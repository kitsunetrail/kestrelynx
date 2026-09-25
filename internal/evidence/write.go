package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

// WriteTo serializes snap and writes it to f as the evidence file format: the
// JSON body, followed by a trailer line recording the body's exact length and
// SHA-256, so a reader can detect a torn write (the file overwritten in place,
// observed mid-write) before trusting any of the JSON.
//
// f is expected to already be open for read/write at the fixed evidence path
// (the Sensor opens it once, before it drops capabilities, and keeps writing
// to that same descriptor for its whole session). WriteTo itself only
// performs the three operations that contract calls for: overwrite from the
// start, truncate to the new length, and fsync. It never renames or reopens
// the file.
func WriteTo(f *os.File, snap Snapshot) error {
	body, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	sum := sha256.Sum256(body)
	trailer := fmt.Sprintf("\n%slength=%d sha256=%x\n", trailerPrefix, len(body), sum)
	full := append(body, []byte(trailer)...)

	if _, err := f.WriteAt(full, 0); err != nil {
		return fmt.Errorf("write evidence: %w", err)
	}
	if err := f.Truncate(int64(len(full))); err != nil {
		return fmt.Errorf("truncate evidence: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync evidence: %w", err)
	}
	return nil
}
