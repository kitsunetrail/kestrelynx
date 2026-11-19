package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// refreshFake is a shell script standing in for trivy's database download:
// "image --download-db-only --cache-dir D" writes D/db/trivy.db with the
// content of the content file and D/db/metadata.json, unless the fail file
// exists (it then leaves half a download behind) or the nometa file exists.
type refreshFake struct {
	bin, log, content, fail, nometa string
}

func newRefreshFake(t *testing.T) refreshFake {
	t.Helper()
	dir := t.TempDir()
	f := refreshFake{
		bin: filepath.Join(dir, "trivy"), log: filepath.Join(dir, "log"),
		content: filepath.Join(dir, "content"), fail: filepath.Join(dir, "fail"), nometa: filepath.Join(dir, "nometa"),
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %[1]q
for last; do :; done
mkdir -p "$last/db"
if [ -e %[3]q ]; then echo partial > "$last/db/trivy.db"; echo "download failed" >&2; exit 1; fi
cp %[2]q "$last/db/trivy.db"
if [ -e %[4]q ]; then exit 0; fi
echo '{"Version":2,"NextUpdate":"2026-11-19T19:07:09Z","UpdatedAt":"2026-11-18T19:07:09Z","DownloadedAt":"2026-11-19T00:41:17Z"}' > "$last/db/metadata.json"
`, f.log, f.content, f.fail, f.nometa)
	if err := os.WriteFile(f.bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	f.publish(t, "db-new")
	return f
}

func (f refreshFake) publish(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(f.content, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeDB puts a database with the given content and download time in dir.
func writeDB(t *testing.T, dir, content string, downloaded time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := fmt.Sprintf(`{"Version":2,"UpdatedAt":"2026-11-18T07:15:21Z","DownloadedAt":%q}`, downloaded.UTC().Format(time.RFC3339Nano))
	for name, data := range map[string]string{"trivy.db": content, "metadata.json": meta} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// cacheEntries lists the cache directory, so a test can tell nothing was left
// behind.
func cacheEntries(t *testing.T, cache string) string {
	t.Helper()
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, " ")
}

func TestRefreshDB(t *testing.T) {
	ctx := context.Background()
	old := time.Now().Add(-14 * time.Hour)
	newBuilt := time.Date(2026, 11, 18, 19, 7, 9, 0, time.UTC)

	t.Run("an empty cache gets the database", func(t *testing.T) {
		f := newRefreshFake(t)
		cache := filepath.Join(t.TempDir(), "trivy")
		res, err := Trivy{BinPath: f.bin, CacheDir: cache}.RefreshDB(ctx)
		if err != nil || !res.Fetched || !res.UpdatedAt.Equal(newBuilt) {
			t.Fatalf("RefreshDB = %+v, %v", res, err)
		}
		if got := read(t, filepath.Join(cache, "db", "trivy.db")); got != "db-new" {
			t.Errorf("database = %q", got)
		}
		if got := cacheEntries(t, cache); got != "db" {
			t.Errorf("cache holds %q, want only db", got)
		}
	})

	t.Run("a database Trivy would still call fresh is replaced", func(t *testing.T) {
		f := newRefreshFake(t)
		cache := t.TempDir()
		// Downloaded 14 hours ago: Trivy's own update would skip it.
		writeDB(t, filepath.Join(cache, "db"), "db-old", old)
		writeCache(t, filepath.Join(cache, "unrelated"))
		tr := Trivy{BinPath: f.bin, CacheDir: cache}
		res, err := tr.RefreshDB(ctx)
		if err != nil || !res.Fetched {
			t.Fatalf("RefreshDB = %+v, %v", res, err)
		}
		if got := read(t, filepath.Join(cache, "db", "trivy.db")); got != "db-new" {
			t.Errorf("database = %q, want the new one", got)
		}
		if m, ok := readDBMetadata(filepath.Join(cache, "db", "metadata.json")); !ok || !m.UpdatedAt.Equal(newBuilt) {
			t.Errorf("metadata = %+v, want that of the new database", m)
		}
		if got := cacheEntries(t, cache); got != "db unrelated" {
			t.Errorf("cache holds %q", got)
		}
		// The download went to a directory of its own inside the cache.
		line := readLog(t, f.log)[0]
		if !strings.HasPrefix(line, "image --quiet --download-db-only --cache-dir "+filepath.Join(cache, refreshPrefix)) {
			t.Errorf("command = %q", line)
		}
	})

	t.Run("a failed download leaves the database alone", func(t *testing.T) {
		f := newRefreshFake(t)
		touch(t, f.fail)
		cache := t.TempDir()
		writeDB(t, filepath.Join(cache, "db"), "db-old", old)
		before := read(t, filepath.Join(cache, "db", "metadata.json"))
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err == nil || !strings.Contains(err.Error(), "download failed") {
			t.Fatalf("err = %v", err)
		}
		if got := read(t, filepath.Join(cache, "db", "trivy.db")); got != "db-old" {
			t.Errorf("database = %q, want the old one", got)
		}
		if got := read(t, filepath.Join(cache, "db", "metadata.json")); got != before {
			t.Errorf("metadata changed: %q", got)
		}
		if got := cacheEntries(t, cache); got != "db" {
			t.Errorf("cache holds %q, want only db", got)
		}
	})

	t.Run("an incomplete download is not put in place", func(t *testing.T) {
		f := newRefreshFake(t)
		cache := t.TempDir()
		writeDB(t, filepath.Join(cache, "db"), "db-old", old)
		touch(t, f.nometa)
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err == nil {
			t.Fatal("a download without metadata was accepted")
		}
		os.Remove(f.nometa)
		f.publish(t, "")
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err == nil {
			t.Fatal("an empty database file was accepted")
		}
		if got := read(t, filepath.Join(cache, "db", "trivy.db")); got != "db-old" {
			t.Errorf("database = %q, want the old one", got)
		}
		if got := cacheEntries(t, cache); got != "db" {
			t.Errorf("cache holds %q, want only db", got)
		}
	})

	t.Run("a database downloaded within the hour is left alone", func(t *testing.T) {
		f := newRefreshFake(t)
		cache := t.TempDir()
		writeDB(t, filepath.Join(cache, "db"), "db-recent", time.Now().Add(-20*time.Minute))
		res, err := Trivy{BinPath: f.bin, CacheDir: cache}.RefreshDB(ctx)
		if err != nil || res.Fetched || res.UpdatedAt.IsZero() {
			t.Fatalf("RefreshDB = %+v, %v", res, err)
		}
		if _, err := os.Stat(f.log); err == nil {
			t.Errorf("trivy was run: %v", readLog(t, f.log))
		}
		// Metadata saying so without a database file does not count, nor
		// does a download time in the future.
		os.Remove(filepath.Join(cache, "db", "trivy.db"))
		if res, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err != nil || !res.Fetched {
			t.Fatalf("without a database file RefreshDB = %+v, %v", res, err)
		}
		writeDB(t, filepath.Join(cache, "db"), "db-future", time.Now().Add(3*time.Hour))
		if res, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err != nil || !res.Fetched {
			t.Fatalf("with a download time in the future RefreshDB = %+v, %v", res, err)
		}
	})

	t.Run("an interrupted exchange is undone", func(t *testing.T) {
		f := newRefreshFake(t)
		cache := t.TempDir()
		// The database in use had stepped aside and nothing took its place.
		writeDB(t, filepath.Join(cache, previousDB), "db-old", old)
		if err := os.MkdirAll(filepath.Join(cache, refreshPrefix+"123", "db"), 0o755); err != nil {
			t.Fatal(err)
		}
		touch(t, f.fail)
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err == nil {
			t.Fatal("the download was meant to fail")
		}
		if got := read(t, filepath.Join(cache, "db", "trivy.db")); got != "db-old" {
			t.Errorf("database = %q, want the one that had stepped aside", got)
		}
		if got := cacheEntries(t, cache); got != "db" {
			t.Errorf("cache holds %q, want only db", got)
		}
	})

	t.Run("a finished exchange drops what stepped aside", func(t *testing.T) {
		f := newRefreshFake(t)
		cache := t.TempDir()
		writeDB(t, filepath.Join(cache, previousDB), "db-older", old)
		writeDB(t, filepath.Join(cache, "db"), "db-old", old)
		touch(t, f.fail)
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err == nil {
			t.Fatal("the download was meant to fail")
		}
		if got := read(t, filepath.Join(cache, "db", "trivy.db")); got != "db-old" {
			t.Errorf("database = %q", got)
		}
		if got := cacheEntries(t, cache); got != "db" {
			t.Errorf("cache holds %q, want only db", got)
		}
	})

	t.Run("scans after a refresh use the new database", func(t *testing.T) {
		// PrepareDB hashes what is in the cache: after a refresh that is
		// the new database.
		f := newRefreshFake(t)
		bin, _, versionFile, _ := writeDBFakeTrivy(t)
		copyVersionFixture(t, versionFile)
		cache := t.TempDir()
		writeCache(t, cache)
		if _, err := (Trivy{BinPath: f.bin, CacheDir: cache}).RefreshDB(ctx); err != nil {
			t.Fatal(err)
		}
		c, err := Trivy{BinPath: bin, CacheDir: cache, SkipDBUpdate: true}.PrepareDB(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if c.VulnerabilityDBSHA != sha256Hex("db-new") || c.JavaDBSHA != sha256Hex("java-db-v1") {
			t.Errorf("conditions name another database: %+v", c)
		}
	})
}
