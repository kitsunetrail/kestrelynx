package imagefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCache(t *testing.T) *Cache {
	t.Helper()
	c, err := OpenCache(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func countFiles(t *testing.T, c *Cache) int {
	t.Helper()
	n := 0
	for _, d := range cacheDirs {
		es, err := os.ReadDir(filepath.Join(c.dir, d))
		if err != nil {
			t.Fatal(err)
		}
		n += len(es)
	}
	return n
}

func TestCacheRoundTrips(t *testing.T) {
	c := newCache(t)
	id := digestOf([]byte("layer"))
	blob := digestOf([]byte("blob"))
	cfg := digestOf([]byte("config"))
	sum := LayerSummary{Version: SummaryVersion, Entries: []Entry{{Path: "a", Type: TypeFile}}}

	if _, ok := c.GetLayer(id); ok {
		t.Fatal("empty cache has a layer")
	}
	if err := c.PutLayer(id, sum); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.GetLayer(id); !ok || len(got.Entries) != 1 || got.Entries[0].Path != "a" {
		t.Errorf("layer %+v %v", got, ok)
	}
	if err := c.PutBlob(blob, id); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.GetBlob(blob); !ok || got != id {
		t.Errorf("blob %q %v", got, ok)
	}
	res := ImageResult{DiffIDs: []string{id}, JDKs: []JDK{{Dir: "opt/j", Release: "R", Executables: []Executable{{Declared: "opt/j/bin/java", Path: "opt/j/bin/java", Known: true}}}}}
	if err := c.PutImage(cfg, res); err != nil {
		t.Fatal(err)
	}
	if got, ok := c.GetImage(cfg, []string{id}); !ok || len(got.JDKs) != 1 || got.JDKs[0].Executables[0].Path != "opt/j/bin/java" {
		t.Errorf("image %+v %v", got, ok)
	}
	// The result is used only for the very layer list it was made from.
	if _, ok := c.GetImage(cfg, []string{id, id}); ok {
		t.Error("image result used for other diffIDs")
	}
	if _, ok := c.GetImage(cfg, nil); ok {
		t.Error("image result used for no diffIDs")
	}
	// Anything that is not a digest never reaches the file system.
	if err := c.PutLayer("../../etc/passwd", sum); err == nil {
		t.Error("a path was accepted as a diffID")
	}
	if _, ok := c.GetBlob("sha256:../x"); ok {
		t.Error("a path was accepted as a digest")
	}
}

func TestCacheOtherSummaryVersionIsNotUsed(t *testing.T) {
	c := newCache(t)
	id := digestOf([]byte("layer"))
	h, _ := hexOf(id)
	if err := os.WriteFile(filepath.Join(c.dir, "layers", h+".json"), []byte(`{"v":99,"e":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.GetLayer(id); ok {
		t.Error("a summary of another version was used")
	}
	if err := os.WriteFile(filepath.Join(c.dir, "layers", h+".json"), []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.GetLayer(id); ok {
		t.Error("a broken summary was used")
	}
}

func TestCacheWritesAreAtomic(t *testing.T) {
	c := newCache(t)
	id := digestOf([]byte("layer"))
	for i := 0; i < 3; i++ {
		if err := c.PutLayer(id, LayerSummary{Version: SummaryVersion}); err != nil {
			t.Fatal(err)
		}
	}
	es, _ := os.ReadDir(filepath.Join(c.dir, "layers"))
	for _, e := range es {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			t.Errorf("temporary file %s left", e.Name())
		}
	}
	if len(es) != 1 {
		t.Errorf("%d files, want 1", len(es))
	}
}

func TestCacheFailureRecordKeyedByLimitsAndVersions(t *testing.T) {
	c := newCache(t)
	l := Limits{RegistryBytesPerCycle: 1 << 20}
	if err := c.PutFailure(FailureRecord{Key: "registry|r@d|linux/amd64/", Reason: ReasonLayerTooLarge, Limits: l, ProgramVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	if rec, ok := c.GetFailure("registry|r@d|linux/amd64/", l, "v1"); !ok || rec.Reason != ReasonLayerTooLarge {
		t.Errorf("record %+v %v", rec, ok)
	}
	if _, ok := c.GetFailure("registry|r@d|linux/amd64/", Limits{RegistryBytesPerCycle: 2 << 20}, "v1"); ok {
		t.Error("record used under other limits")
	}
	if _, ok := c.GetFailure("registry|r@d|linux/amd64/", l, "v2"); ok {
		t.Error("record used by another program version")
	}
	if _, ok := c.GetFailure("docker|r@d|linux/amd64/", l, "v1"); ok {
		t.Error("record used for another route")
	}
}

func TestCacheTimeoutCounter(t *testing.T) {
	c := newCache(t)
	if c.Timeouts("k") != 0 {
		t.Fatal("fresh counter not zero")
	}
	c.SetTimeouts("k", 2)
	if got := c.Timeouts("k"); got != 2 {
		t.Errorf("count %d", got)
	}
	c.SetTimeouts("k", 0)
	if got := c.Timeouts("k"); got != 0 {
		t.Errorf("count %d after reset", got)
	}
}

func TestCachePruneEvictsLeastRecentlyUsed(t *testing.T) {
	c := newCache(t)
	c.MaxFiles = 3
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	var ids []string
	for i := 0; i < 5; i++ {
		id := digestOf([]byte{byte(i)})
		ids = append(ids, id)
		if err := c.PutLayer(id, LayerSummary{Version: SummaryVersion}); err != nil {
			t.Fatal(err)
		}
	}
	// Reading the oldest makes it the most recently used.
	if _, ok := c.GetLayer(ids[0]); !ok {
		t.Fatal("missing")
	}
	if err := c.Prune(); err != nil {
		t.Fatal(err)
	}
	if n := countFiles(t, c); n != 3 {
		t.Fatalf("%d files after prune, want 3", n)
	}
	for i, want := range []bool{true, false, false, true, true} {
		if _, ok := c.GetLayer(ids[i]); ok != want {
			t.Errorf("layer %d present = %v, want %v", i, ok, want)
		}
	}
}

func TestCachePruneKeepsFreshTempFilesAndRemovesStaleOnes(t *testing.T) {
	c := newCache(t)
	fresh := filepath.Join(c.dir, "layers", tempPrefix+"fresh")
	stale := filepath.Join(c.dir, "layers", tempPrefix+"stale")
	for _, p := range []string{fresh, stale} {
		os.WriteFile(p, []byte("x"), 0o600)
	}
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, old, old)
	c.Prune()
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a temporary file of a write in progress was removed")
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a stale temporary file was kept")
	}
}

func TestNilCacheHoldsNothing(t *testing.T) {
	var c *Cache
	id := digestOf([]byte("x"))
	if err := c.PutLayer(id, LayerSummary{}); err != nil {
		t.Error(err)
	}
	if _, ok := c.GetLayer(id); ok {
		t.Error("nil cache returned a layer")
	}
	if c.Timeouts("k") != 0 || c.Prune() != nil {
		t.Error("nil cache misbehaves")
	}
}
