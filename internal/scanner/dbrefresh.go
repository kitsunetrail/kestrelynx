package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// refreshSkip is how recently the cached database must have been
	// downloaded for RefreshDB to leave it alone, so that a process restarting
	// in a loop does not download it every time.
	refreshSkip = time.Hour
	// refreshPrefix names the directories RefreshDB downloads into, inside
	// the cache directory so that the database can be moved into place.
	refreshPrefix = "db-refresh-"
	// previousDB is where the database in use waits while the new one is
	// moved into place.
	previousDB = "db-previous"
)

// DBRefresh is what RefreshDB did.
type DBRefresh struct {
	// Fetched is false when the cached database was downloaded within the
	// last hour and was left alone.
	Fetched bool
	// UpdatedAt is when the database now in the cache was built.
	UpdatedAt time.Time
}

// dbMetadata is the part of Trivy's db/metadata.json in use.
type dbMetadata struct {
	UpdatedAt    time.Time `json:"UpdatedAt"`
	DownloadedAt time.Time `json:"DownloadedAt"`
}

func readDBMetadata(path string) (dbMetadata, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return dbMetadata{}, false
	}
	var m dbMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		return dbMetadata{}, false
	}
	return m, true
}

// RefreshDB replaces the vulnerability database in the cache with the newest
// published one. Trivy on its own downloads a database only once the cached
// one is a day old, so without this a scan can miss what the newest database
// already knows. The download goes to a directory of its own, and the
// database directory is exchanged for the downloaded one only when that one
// is complete: a failed download leaves the cached database as it was, and
// returns an error. An exchange that was interrupted is undone by the next
// call. The Java database is not touched.
//
// The cache directory is CacheDir, else TRIVY_CACHE_DIR, else Trivy's
// default; one set only in a Trivy configuration file is not seen.
func (t Trivy) RefreshDB(ctx context.Context) (DBRefresh, error) {
	t, err := t.resolved()
	if err != nil {
		return DBRefresh{}, err
	}
	dbDir := filepath.Join(t.CacheDir, "db")
	prevDir := filepath.Join(t.CacheDir, previousDB)
	if err := restorePreviousDB(dbDir, prevDir); err != nil {
		return DBRefresh{}, err
	}
	if m, ok := readDBMetadata(filepath.Join(dbDir, "metadata.json")); ok && hasDBFile(dbDir) {
		if age := time.Since(m.DownloadedAt); age >= 0 && age < refreshSkip {
			return DBRefresh{UpdatedAt: m.UpdatedAt}, nil
		}
	}
	if err := os.MkdirAll(t.CacheDir, 0o700); err != nil {
		return DBRefresh{}, fmt.Errorf("create trivy cache: %w", err)
	}
	// What an interrupted refresh left behind.
	if old, err := filepath.Glob(filepath.Join(t.CacheDir, refreshPrefix+"*")); err == nil {
		for _, d := range old {
			os.RemoveAll(d)
		}
	}
	tmp, err := os.MkdirTemp(t.CacheDir, refreshPrefix)
	if err != nil {
		return DBRefresh{}, fmt.Errorf("create download directory: %w", err)
	}
	defer os.RemoveAll(tmp)
	// An empty cache directory has no database to consider fresh, so Trivy
	// downloads the newest one.
	if _, err := t.run(ctx, "image", "--quiet", "--download-db-only", "--cache-dir", tmp); err != nil {
		return DBRefresh{}, err
	}
	newDir := filepath.Join(tmp, "db")
	m, ok := readDBMetadata(filepath.Join(newDir, "metadata.json"))
	if !ok || m.UpdatedAt.IsZero() {
		return DBRefresh{}, fmt.Errorf("the downloaded database has no readable metadata")
	}
	if !hasDBFile(newDir) {
		return DBRefresh{}, fmt.Errorf("the download left no database file")
	}
	// The database in use steps aside, the new one takes its place, and only
	// then is the old one removed. restorePreviousDB undoes a first step
	// whose second never happened.
	had := false
	if _, err := os.Lstat(dbDir); err == nil {
		if err := os.Rename(dbDir, prevDir); err != nil {
			return DBRefresh{}, fmt.Errorf("move the database in use aside: %w", err)
		}
		had = true
	}
	if err := os.Rename(newDir, dbDir); err != nil {
		if had {
			if back := os.Rename(prevDir, dbDir); back != nil {
				return DBRefresh{}, fmt.Errorf("put the new database in place: %w (and the one in use could not be put back: %v)", err, back)
			}
		}
		return DBRefresh{}, fmt.Errorf("put the new database in place: %w", err)
	}
	os.RemoveAll(prevDir)
	return DBRefresh{Fetched: true, UpdatedAt: m.UpdatedAt}, nil
}

// hasDBFile reports whether dir holds a non-empty database file.
func hasDBFile(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "trivy.db"))
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// restorePreviousDB finishes or undoes an exchange a previous RefreshDB did
// not complete: the database that stepped aside goes back when nothing took
// its place, and is removed when something did.
func restorePreviousDB(dbDir, prevDir string) error {
	if _, err := os.Lstat(prevDir); err != nil {
		return nil
	}
	if _, err := os.Lstat(dbDir); err == nil {
		return os.RemoveAll(prevDir)
	}
	if err := os.Rename(prevDir, dbDir); err != nil {
		return fmt.Errorf("put the previous database back: %w", err)
	}
	return nil
}
