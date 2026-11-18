package runtimetable

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// fakeRegistry serves one published table and counts what is asked of it.
type fakeRegistry struct {
	raw         []byte
	manifestErr error
	layerErr    error
	manifests   int
	layers      int
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (f *fakeRegistry) ArtifactManifest(_ context.Context, repo, tag string, spec registry.ArtifactSpec) (registry.ArtifactManifest, error) {
	f.manifests++
	if repo != DefaultRepository || tag != Tag || spec.ArtifactType != MediaType || spec.LayerMediaType != MediaType || spec.MaxLayerBytes != worker.MaxRuntimeTableBytes {
		return registry.ArtifactManifest{}, errors.New("asked for something else than the published table")
	}
	if f.manifestErr != nil {
		return registry.ArtifactManifest{}, f.manifestErr
	}
	// The manifest digest stands for the publication; any value that changes
	// with the content will do.
	return registry.ArtifactManifest{Digest: digestOf(append([]byte("manifest of "), f.raw...)), LayerDigest: digestOf(f.raw), LayerSize: int64(len(f.raw))}, nil
}

func (f *fakeRegistry) ArtifactLayer(_ context.Context, _ string, m registry.ArtifactManifest, _ registry.ArtifactSpec) ([]byte, error) {
	f.layers++
	if f.layerErr != nil {
		return nil, f.layerErr
	}
	if m.LayerDigest != digestOf(f.raw) {
		return nil, errors.New("asked for another layer")
	}
	return f.raw, nil
}

// published returns the table of the build as it would be published after
// change was applied to it, dated shift after the table of the build.
func published(t *testing.T, shift time.Duration, change func(rows map[string]map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "worker", "runtimes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["updated"] = worker.EmbeddedRuntimeTable().Updated.Add(shift).UTC().Format(time.RFC3339)
	if change != nil {
		rows := map[string]map[string]any{}
		for _, r := range doc["runtimes"].([]any) {
			m := r.(map[string]any)
			rows[m["id"].(string)] = m
		}
		change(rows)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newerNode(rows map[string]map[string]any) { rows["node24"]["version"] = "24.99.0" }

func nodeVersion(t *testing.T) string {
	t.Helper()
	r, ok := worker.LookupRuntime("node24")
	if !ok {
		t.Fatal("no node24")
	}
	return r.Version
}

func newManager(t *testing.T, reg Registry, dir string, update bool) *Manager {
	t.Helper()
	t.Cleanup(func() { worker.SetRuntimeTable(worker.EmbeddedRuntimeTable()) })
	now := worker.EmbeddedRuntimeTable().Updated.Add(48 * time.Hour)
	return New(Options{
		Update: update, Registry: reg, Dir: dir,
		Now: func() time.Time { return now },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestRefreshTakesANewerTable(t *testing.T) {
	built := nodeVersion(t)
	dir := filepath.Join(t.TempDir(), "runtimes")
	reg := &fakeRegistry{raw: published(t, time.Hour, newerNode)}
	m := newManager(t, reg, dir, true)
	m.Load()
	if m.Source() != SourceBuild || nodeVersion(t) != built {
		t.Fatalf("start: source %s, node24 %s", m.Source(), nodeVersion(t))
	}
	if !m.Refresh(context.Background()) {
		t.Fatal("a newer table did not replace the table in use")
	}
	if m.Source() != SourceFetched || nodeVersion(t) != "24.99.0" {
		t.Fatalf("after the fetch: source %s, node24 %s", m.Source(), nodeVersion(t))
	}
	if got := worker.CurrentRuntimeTable().Updated; !got.Equal(worker.EmbeddedRuntimeTable().Updated.Add(time.Hour)) {
		t.Errorf("updated is %s", got)
	}
	st, err := os.Stat(filepath.Join(dir, SavedName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("saved file: %v, mode %v", err, st.Mode())
	}
	if d, _ := os.Stat(dir); d.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", d.Mode().Perm())
	}
	// The same publication is not fetched again.
	if m.Refresh(context.Background()) || reg.layers != 1 || reg.manifests != 2 {
		t.Errorf("second refresh: %d manifests, %d layers", reg.manifests, reg.layers)
	}

	// A later start uses the saved table, and knows which publication it is.
	worker.SetRuntimeTable(worker.EmbeddedRuntimeTable())
	m2 := newManager(t, reg, dir, true)
	m2.Load()
	if m2.Source() != SourceSaved || nodeVersion(t) != "24.99.0" {
		t.Fatalf("restart: source %s, node24 %s", m2.Source(), nodeVersion(t))
	}
	if m2.Refresh(context.Background()) || reg.layers != 1 {
		t.Errorf("restart: the saved publication was fetched again (%d layers)", reg.layers)
	}

	// With fetching off the saved table is not read either.
	m3 := newManager(t, reg, dir, false)
	m3.Load()
	if m3.Source() != SourceBuild || nodeVersion(t) != built {
		t.Fatalf("update off: source %s, node24 %s", m3.Source(), nodeVersion(t))
	}
	before := reg.manifests
	if m3.Refresh(context.Background()) || reg.manifests != before {
		t.Error("update off: the registry was asked")
	}
}

func TestRefreshKeepsTheTableInUse(t *testing.T) {
	built := nodeVersion(t)
	cases := map[string]struct {
		reg *fakeRegistry
		// layers is how many times the layer is fetched by two refreshes.
		layers int
	}{
		"manifest cannot be fetched": {&fakeRegistry{raw: published(t, time.Hour, newerNode), manifestErr: registry.ErrNotFound}, 0},
		"layer cannot be fetched":    {&fakeRegistry{raw: published(t, time.Hour, newerNode), layerErr: registry.ErrDigestMismatch}, 2},
		"a row is refused": {&fakeRegistry{raw: published(t, time.Hour, func(rows map[string]map[string]any) {
			rows["node24"]["image"] = "evil/node"
		})}, 2},
		"dated far ahead": {&fakeRegistry{raw: published(t, 100*time.Hour, newerNode)}, 2},
		// A table that is older stays older: it is fetched once.
		"older than the table in use": {&fakeRegistry{raw: published(t, -time.Hour, newerNode)}, 1},
		// The table of the build as it is published: looked at once.
		"the table in use itself":  {&fakeRegistry{raw: published(t, 0, nil)}, 1},
		"same time and other rows": {&fakeRegistry{raw: published(t, 0, newerNode)}, 2},
		"not a table":              {&fakeRegistry{raw: []byte("<html>")}, 2},
	}
	for name, c := range cases {
		dir := filepath.Join(t.TempDir(), "runtimes")
		m := newManager(t, c.reg, dir, true)
		m.Load()
		for i := 0; i < 2; i++ {
			if m.Refresh(context.Background()) {
				t.Errorf("%s: the table in use changed", name)
			}
		}
		if m.Source() != SourceBuild || nodeVersion(t) != built {
			t.Errorf("%s: source %s, node24 %s", name, m.Source(), nodeVersion(t))
		}
		if c.reg.layers != c.layers {
			t.Errorf("%s: the layer was fetched %d times, want %d", name, c.reg.layers, c.layers)
		}
		if _, err := os.Stat(filepath.Join(dir, SavedName)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: a table was saved (%v)", name, err)
		}
	}
}

func TestRefreshDoesNotSwitchWhenItCannotSave(t *testing.T) {
	built := nodeVersion(t)
	// A file where the directory should be.
	blocked := filepath.Join(t.TempDir(), "runtimes")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistry{raw: published(t, time.Hour, newerNode)}
	m := newManager(t, reg, blocked, true)
	m.Load()
	if m.Refresh(context.Background()) || nodeVersion(t) != built {
		t.Fatalf("the table was replaced without being saved (node24 %s)", nodeVersion(t))
	}
}

func TestLoadIgnoresASavedTableItCannotUse(t *testing.T) {
	built := nodeVersion(t)
	save := func(t *testing.T, raw []byte) string {
		dir := filepath.Join(t.TempDir(), "runtimes")
		m := newManager(t, nil, dir, true)
		if err := m.save(raw, digestOf(raw)); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	damage := func(t *testing.T, dir string, f func(s *savedFile)) {
		p := filepath.Join(dir, SavedName)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var s savedFile
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		f(&s)
		b, _ = json.Marshal(s)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]func(t *testing.T) string{
		// A build that came out after the saved table carries a newer one.
		"older than the table of the build": func(t *testing.T) string { return save(t, published(t, -time.Hour, newerNode)) },
		"as old as the table of the build":  func(t *testing.T) string { return save(t, published(t, 0, newerNode)) },
		"a row this build refuses": func(t *testing.T) string {
			return save(t, published(t, time.Hour, func(rows map[string]map[string]any) { rows["node24"]["index_digest"] = "sha256:0" }))
		},
		"bytes that do not match their hash": func(t *testing.T) string {
			dir := save(t, published(t, time.Hour, newerNode))
			damage(t, dir, func(s *savedFile) { s.TableSHA256 = digestOf(nil)[7:] })
			return dir
		},
		"another schema of the file": func(t *testing.T) string {
			dir := save(t, published(t, time.Hour, newerNode))
			damage(t, dir, func(s *savedFile) { s.Schema = 2 })
			return dir
		},
		"not a file of ours": func(t *testing.T) string {
			dir := save(t, published(t, time.Hour, newerNode))
			if err := os.WriteFile(filepath.Join(dir, SavedName), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		},
	}
	for name, setup := range cases {
		dir := setup(t)
		m := newManager(t, nil, dir, true)
		m.Load()
		if m.Source() != SourceBuild || nodeVersion(t) != built {
			t.Errorf("%s: source %s, node24 %s", name, m.Source(), nodeVersion(t))
		}
	}

	// A saved table that was not used does not stand for its publication: the
	// same publication is fetched and looked at again.
	raw := published(t, -time.Hour, newerNode)
	dir := save(t, raw)
	reg := &fakeRegistry{raw: raw}
	m := newManager(t, reg, dir, true)
	m.Load()
	m.Refresh(context.Background())
	if reg.layers != 1 {
		t.Errorf("the publication of an unused saved table was fetched %d times, want 1", reg.layers)
	}
}

func TestRefreshLeavesOutRowsAndTakesNewOnes(t *testing.T) {
	reg := &fakeRegistry{raw: published(t, time.Hour, func(rows map[string]map[string]any) {
		// One row of a kind this build does not have, in place of a row it has.
		rows["python3.11"]["kind"] = "ruby"
		rows["python3.11"]["id"] = "ruby3.5"
	})}
	m := newManager(t, reg, filepath.Join(t.TempDir(), "runtimes"), true)
	m.Load()
	before := worker.CurrentRuntimeTable().Len()
	if !m.Refresh(context.Background()) {
		t.Fatal("the table was not taken")
	}
	if got := worker.CurrentRuntimeTable().Len(); got != before-1 {
		t.Errorf("%d rows, want %d", got, before-1)
	}
	// The row the published table no longer has is not filled in from the
	// table of the build.
	if _, ok := worker.LookupRuntime("python3.11"); ok {
		t.Error("a row the published table does not have is still in use")
	}
}
