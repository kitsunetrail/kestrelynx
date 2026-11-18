// Package runtimetable keeps the runtime table of the work containers up to
// date without a new build: it fetches the table published in a registry,
// checks it, saves it in the state directory and makes it the table in use.
//
// The table of the build is what the process starts with. A table that was
// fetched replaces it as a whole when it is newer; a table that cannot be
// fetched, or that is refused, leaves the one in use as it is. The table is
// replaced only when Refresh is called, which the caller does at the start of
// a cycle, so that a cycle sees one table from its start to its end.
package runtimetable

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

const (
	// DefaultRepository is where the table is published.
	DefaultRepository = "ghcr.io/kitsunetrail/kestrelynx-runtimes"
	// Tag is the tag of the tables of schema 1. A build reads the tag of the
	// schema it knows; a table of another schema is published under another.
	Tag = "1"
	// MediaType is the artifact type of the published manifest and the media
	// type of its one layer, which is the JSON of the table as it is.
	MediaType = "application/vnd.kestrelynx.runtimes.v1+json"

	// SavedName is the file in the directory of the manager that holds the
	// table that was fetched last.
	SavedName = "table-1.json"

	maxManifestBytes = 64 << 10
	defaultTimeout   = time.Minute
	// maxSavedBytes bounds the saved file: the table in base64 and a few
	// short fields.
	maxSavedBytes = worker.MaxRuntimeTableBytes*4/3 + 64<<10
)

// Sources of the table in use.
const (
	SourceBuild   = "build"
	SourceSaved   = "saved"
	SourceFetched = "fetched"
)

// Registry is the part of the registry client the manager needs.
type Registry interface {
	ArtifactManifest(ctx context.Context, repo, tag string, spec registry.ArtifactSpec) (registry.ArtifactManifest, error)
	ArtifactLayer(ctx context.Context, repo string, m registry.ArtifactManifest, spec registry.ArtifactSpec) ([]byte, error)
}

// Options configures a Manager.
type Options struct {
	// Update turns fetching on. Without it the table of the build is used and
	// a table saved by an earlier run is not read.
	Update bool
	// Registry fetches the published table.
	Registry Registry
	// Repository is the repository the table is published in, without a tag;
	// empty means DefaultRepository.
	Repository string
	// Dir is the directory the fetched table is saved in. It is used as it
	// is; the caller builds the path.
	Dir string
	// Timeout bounds one Refresh; zero means a minute.
	Timeout time.Duration
	Now     func() time.Time
	Log     *slog.Logger
}

// Manager chooses the runtime table in use.
type Manager struct {
	o Options

	mu sync.Mutex
	// source says where the table in use came from, and digest is the digest
	// of the manifest it was published with ("" for the table of the build).
	source string
	digest string
	// olderDigest is the manifest of a table that was fetched and found to be
	// older than the one in use. The table in use only gets newer, so that
	// table is not fetched again by this process.
	olderDigest string
}

// New returns a Manager. It changes nothing until Load is called.
func New(o Options) *Manager {
	if o.Repository == "" {
		o.Repository = DefaultRepository
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Manager{o: o, source: SourceBuild}
}

func (m *Manager) spec() registry.ArtifactSpec {
	return registry.ArtifactSpec{
		ArtifactType: MediaType, LayerMediaType: MediaType,
		MaxManifestBytes: maxManifestBytes, MaxLayerBytes: worker.MaxRuntimeTableBytes,
	}
}

// Source says where the table in use came from: SourceBuild, SourceSaved or
// SourceFetched.
func (m *Manager) Source() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.source
}

// Load chooses the table the process starts with: the table of the build, or
// the table an earlier run saved when that one passes the checks and is the
// newer of the two. With Update off it is always the table of the build.
func (m *Manager) Load() {
	m.mu.Lock()
	defer m.mu.Unlock()
	built := worker.EmbeddedRuntimeTable()
	worker.SetRuntimeTable(built)
	m.source, m.digest = SourceBuild, ""
	if !m.o.Update {
		m.o.Log.Info("runtime table: using the table of the build; fetching is turned off",
			"updated", stamp(built.Updated), "rows", built.Len())
		return
	}
	saved, digest, err := m.readSaved()
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		m.o.Log.Warn("runtime table: the saved table is not used", "err", err)
	default:
		table, dropped, err := worker.AdoptRuntimeTable(saved, m.o.Now())
		switch {
		case err != nil:
			m.o.Log.Warn("runtime table: the saved table is not used", "err", err)
		case !table.Updated.After(built.Updated):
			m.o.Log.Info("runtime table: the saved table is not newer than the table of the build",
				"saved_updated", stamp(table.Updated), "build_updated", stamp(built.Updated))
		default:
			worker.SetRuntimeTable(table)
			m.source, m.digest = SourceSaved, digest
			m.logDropped(dropped)
		}
	}
	m.logInUse("runtime table in use")
}

// Refresh fetches the published table and, when it is newer than the table in
// use and passes the checks, saves it and makes it the table in use. It
// reports whether the table in use changed. Whatever goes wrong, the table in
// use stays and the reason is logged; nothing is returned as an error because
// the cycle goes on either way.
//
// The caller calls it only between cycles and, when it returns true, makes
// again whatever it made from the table.
func (m *Manager) Refresh(ctx context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.o.Update || m.o.Registry == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, m.o.Timeout)
	defer cancel()
	keep := func(msg string, args ...any) bool {
		m.o.Log.Warn("runtime table: "+msg+"; the table in use stays", args...)
		return false
	}

	spec := m.spec()
	man, err := m.o.Registry.ArtifactManifest(ctx, m.o.Repository, Tag, spec)
	if err != nil {
		return keep("the published table could not be looked up", "repository", m.o.Repository, "err", err)
	}
	if man.Digest == m.digest || man.Digest == m.olderDigest {
		return false
	}
	raw, err := m.o.Registry.ArtifactLayer(ctx, m.o.Repository, man, spec)
	if err != nil {
		return keep("the published table could not be fetched", "repository", m.o.Repository, "manifest", man.Digest, "err", err)
	}
	table, dropped, err := worker.AdoptRuntimeTable(raw, m.o.Now())
	if err != nil {
		return keep("the published table is refused", "manifest", man.Digest, "err", err)
	}
	current := worker.CurrentRuntimeTable()
	switch {
	case table.Updated.Before(current.Updated):
		m.olderDigest = man.Digest
		m.o.Log.Info("runtime table: the published table is older than the table in use",
			"published_updated", stamp(table.Updated), "in_use_updated", stamp(current.Updated), "manifest", man.Digest)
		return false
	case table.Updated.Equal(current.Updated):
		// The same time means the same publication: the table of the build,
		// or the saved one, is what is published. A table with the same time
		// and other rows is not what the publisher makes.
		if !reflect.DeepEqual(table.Runtimes(), current.Runtimes()) {
			return keep("the published table has the time of the table in use and other rows", "manifest", man.Digest)
		}
		m.digest = man.Digest
		return false
	}
	if err := m.save(raw, man.Digest); err != nil {
		return keep("the fetched table could not be saved", "err", err)
	}
	worker.SetRuntimeTable(table)
	m.source, m.digest, m.olderDigest = SourceFetched, man.Digest, ""
	m.logDropped(dropped)
	m.logChange(current, table)
	return true
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (m *Manager) logInUse(msg string) {
	t := worker.CurrentRuntimeTable()
	m.o.Log.Info(msg, "source", m.source, "updated", stamp(t.Updated), "manifest", m.digest,
		"rows", t.Len(), "gradle_rows_without_test", untestedGradle(t))
}

func (m *Manager) logDropped(dropped []worker.DroppedRuntime) {
	for _, d := range dropped {
		m.o.Log.Info("runtime table: a row this build cannot run is left out", "id", d.ID, "reason", d.Reason)
	}
}

// untestedGradle counts the Gradle rows no integration test has run on any
// platform. They are in the table and are not run.
func untestedGradle(t worker.RuntimeTable) int {
	n := 0
	for _, r := range t.Runtimes() {
		if r.Kind != worker.KindGradle || !r.HasImage() {
			continue
		}
		tested := false
		for p := range r.Platforms {
			tested = tested || r.IsTestedOn(p)
		}
		if !tested {
			n++
		}
	}
	return n
}

// logChange says what a new table changed: every row that came, went or
// changed its version, one line each, and how many rows changed in another
// way (a digest, a date, a record of a test).
func (m *Manager) logChange(old, table worker.RuntimeTable) {
	before := map[string]worker.RuntimeSpec{}
	for _, r := range old.Runtimes() {
		before[r.ID] = r
	}
	named, other := 0, 0
	for _, r := range table.Runtimes() {
		o, was := before[r.ID]
		delete(before, r.ID)
		switch {
		case !was:
			named++
			m.o.Log.Info("runtime table: a row was added", "id", r.ID, "version", orNone(r.Version))
		case o.Version != r.Version:
			named++
			m.o.Log.Info("runtime table: a row changed its version", "id", r.ID, "from", orNone(o.Version), "to", orNone(r.Version))
		case !reflect.DeepEqual(o, r):
			other++
		}
	}
	gone := make([]string, 0, len(before))
	for id := range before {
		gone = append(gone, id)
	}
	sort.Strings(gone)
	for _, id := range gone {
		named++
		m.o.Log.Info("runtime table: a row was removed", "id", id, "version", orNone(before[id].Version))
	}
	m.o.Log.Info("runtime table replaced", "source", m.source, "updated", stamp(table.Updated), "manifest", m.digest,
		"rows", table.Len(), "gradle_rows_without_test", untestedGradle(table),
		"rows_added_removed_or_with_a_new_version", named, "rows_changed_without_a_new_version", other)
}

func orNone(v string) string {
	if v == "" {
		return "(no image)"
	}
	return v
}

// savedFile is the saved table: the bytes that were fetched, with the digest
// of the manifest they were published with, in one file, so that the two are
// always of the same publication.
type savedFile struct {
	Schema         int    `json:"schema"`
	ManifestDigest string `json:"manifest_digest"`
	TableSHA256    string `json:"table_sha256"`
	FetchedAt      string `json:"fetched_at"`
	Table          string `json:"table"` // the JSON of the table, in base64
}

func (m *Manager) savedPath() string { return filepath.Join(m.o.Dir, SavedName) }

func (m *Manager) save(raw []byte, manifestDigest string) error {
	if m.o.Dir == "" {
		return errors.New("no directory to save the table in")
	}
	sum := sha256.Sum256(raw)
	body, err := json.Marshal(savedFile{
		Schema: 1, ManifestDigest: manifestDigest, TableSHA256: hex.EncodeToString(sum[:]),
		FetchedAt: stamp(m.o.Now()), Table: base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.o.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.o.Dir, SavedName+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), m.savedPath())
}

// readSaved returns the bytes of the saved table and the digest of the
// manifest it was published with. The bytes are checked like fetched ones by
// the caller; here only the file itself is read.
func (m *Manager) readSaved() (raw []byte, manifestDigest string, err error) {
	if m.o.Dir == "" {
		return nil, "", os.ErrNotExist
	}
	f, err := os.Open(m.savedPath())
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxSavedBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > maxSavedBytes {
		return nil, "", errors.New("the saved table is too large")
	}
	var s savedFile
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, "", fmt.Errorf("the saved table is not readable: %w", err)
	}
	if s.Schema != 1 {
		return nil, "", fmt.Errorf("the saved table has the schema %d", s.Schema)
	}
	raw, err = base64.StdEncoding.DecodeString(s.Table)
	if err != nil {
		return nil, "", fmt.Errorf("the saved table is not readable: %w", err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != s.TableSHA256 {
		return nil, "", errors.New("the saved table does not match its hash")
	}
	return raw, s.ManifestDigest, nil
}
