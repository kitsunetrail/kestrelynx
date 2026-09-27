package evidence

import (
	"context"
	"time"
)

// Provider supplies the current Snapshot the main body projects runtime
// usage from. FileProvider (below) is the only implementation today, backed
// by a Sensor's evidence file; the interface exists so a future Kubernetes
// deployment (the Sensor and this schema are already runtime-agnostic — see
// ContainerRef) can supply its own without any caller needing to change.
type Provider interface {
	// Load returns the current validated Snapshot, or an error identifying
	// why none is available. A caller that gets ErrNotReporting or
	// ErrInvalid must not treat that as a cycle failure — it means "nothing
	// trustworthy to show for runtime usage this cycle", not "the scan
	// failed".
	Load(ctx context.Context) (Snapshot, error)
}

// FileProvider reads the evidence file a Sensor writes to Dir, via the same
// Reader every caller of this package uses. It keeps the last snapshot it
// successfully validated so that Reader.Read's own torn-write fallback (see
// Read's doc comment) works across calls, the same way it would within a
// long-running Sensor reading its own prior write — not just within one
// Read call: a caller that constructs a fresh FileProvider every cycle only
// gets that fallback once a first successful read has happened.
type FileProvider struct {
	reader Reader
	// Now, when set, replaces time.Now for Load's own use (tests only); the
	// zero value uses the real clock.
	Now func() time.Time

	prev *Snapshot
}

// NewFileProvider builds a FileProvider reading dir with the production
// retry delay (NewReader).
func NewFileProvider(dir string) *FileProvider {
	return &FileProvider{reader: NewReader(dir)}
}

func (p *FileProvider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Load reads and validates the current snapshot. ctx is accepted for
// interface symmetry with the rest of this codebase's I/O boundaries (docker.
// Client, scanner.Trivy); the read itself is a local filesystem operation
// that does not currently observe cancellation.
func (p *FileProvider) Load(_ context.Context) (Snapshot, error) {
	snap, err := p.reader.Read(p.now(), p.prev)
	if err != nil {
		return Snapshot{}, err
	}
	p.prev = &snap
	return snap, nil
}
