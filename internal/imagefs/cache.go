package imagefs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMaxCacheFiles is the number of files the cache keeps.
const DefaultMaxCacheFiles = 20000

const tempPrefix = ".tmp-"

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ImageResult is the cached result of reading one image: the JDKs found and
// the diffIDs of the layers it was computed from.
type ImageResult struct {
	Version int      `json:"v"`
	DiffIDs []string `json:"diff_ids"`
	JDKs    []JDK    `json:"jdks"`
	// JavaHomeInput is the JAVA_HOME the result was computed for and JavaHome
	// what it resolved to in the image (see Outcome.JavaHome).
	JavaHomeInput string `json:"java_home_input,omitempty"`
	JavaHome      string `json:"java_home,omitempty"`
}

// FailureRecord says that reading an image through one route cannot
// complete. It holds only while the limits, the summary format and the
// program are the ones it was made under.
type FailureRecord struct {
	Key            string    `json:"key"`
	Reason         Reason    `json:"reason"`
	Detail         string    `json:"detail"`
	Limits         Limits    `json:"limits"`
	SummaryVersion int       `json:"summary_version"`
	ProgramVersion string    `json:"program_version"`
	Time           time.Time `json:"time"`
}

// Cache keeps verified results in a directory:
//
//	layers/<diffID>.json    layer summaries, by diffID
//	blobs/<digest>          the diffID of a verified registry blob
//	images/<config>.json    the result for an image config
//	failures/<key>.json     "cannot complete" records
//	counters/<key>.json     consecutive Docker timeouts
//
// A file is written to a temporary name and renamed, so a reader never sees
// half of one. Reading a file marks it as used; beyond MaxFiles files the
// least recently used ones are deleted by Prune. A nil *Cache is a cache that
// holds nothing. It is safe for concurrent use.
type Cache struct {
	dir string
	// MaxFiles is the number of files Prune leaves; 0 means 20,000.
	MaxFiles int

	mu    sync.Mutex
	dirty bool // a file was written since the last prune
	now   func() time.Time

	// A cache without a directory (NewMemoryCache) keeps only the strike
	// counts and the "cannot complete" records, in memory.
	memCount map[string]int
	memFail  map[string]FailureRecord
}

// NewMemoryCache returns a cache for when no directory can be used: it holds
// no layer, blob or image result, but remembers the strike counts and the
// "cannot complete" records until the program stops, so the rule of three
// consecutive strikes still works.
func NewMemoryCache() *Cache {
	return &Cache{now: time.Now, memCount: map[string]int{}, memFail: map[string]FailureRecord{}}
}

// off reports whether the cache holds nothing on disk: a nil cache, or one
// without a directory.
func (c *Cache) off() bool { return c == nil || c.dir == "" }

var cacheDirs = []string{"layers", "blobs", "images", "failures", "counters"}

// OpenCache opens the cache in dir, creating it when it does not exist.
func OpenCache(dir string) (*Cache, error) {
	if dir == "" {
		return nil, errors.New("imagefs: cache directory is empty")
	}
	for _, d := range cacheDirs {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, fmt.Errorf("imagefs: create cache directory: %w", err)
		}
	}
	return &Cache{dir: dir, now: time.Now}, nil
}

func (c *Cache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func hexOf(digest string) (string, bool) {
	if !digestRE.MatchString(digest) {
		return "", false
	}
	return strings.TrimPrefix(digest, "sha256:"), true
}

func keyName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (c *Cache) path(kind, name, ext string) string {
	return filepath.Join(c.dir, kind, name+ext)
}

// read returns the content of a cache file and marks it as used.
func (c *Cache) read(p string) ([]byte, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	now := c.clock()
	_ = os.Chtimes(p, now, now)
	return b, true
}

func (c *Cache) readJSON(p string, v any) bool {
	b, ok := c.read(p)
	if !ok {
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		_ = os.Remove(p)
		return false
	}
	return true
}

// write stores data at p through a temporary file in the same directory.
func (c *Cache) write(p string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), tempPrefix+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	now := c.clock()
	_ = os.Chtimes(p, now, now)
	c.mu.Lock()
	c.dirty = true
	c.mu.Unlock()
	return nil
}

func (c *Cache) writeJSON(p string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.write(p, b)
}

// GetLayer returns the cached summary of the layer with this diffID.
func (c *Cache) GetLayer(diffID string) (LayerSummary, bool) {
	h, ok := hexOf(diffID)
	if c.off() || !ok {
		return LayerSummary{}, false
	}
	var lf layerFile
	p := c.path("layers", h, ".json")
	if !c.readJSON(p, &lf) {
		return LayerSummary{}, false
	}
	if lf.Version != SummaryVersion {
		_ = os.Remove(p)
		return LayerSummary{}, false
	}
	return lf.LayerSummary, true
}

// layerFile is a layer summary as stored: the cost of holding it decoded
// comes first, so it can be read without decoding the rest.
type layerFile struct {
	RestoreCost int64 `json:"restore_cost"`
	LayerSummary
}

var costPrefixRE = regexp.MustCompile(`^\{"restore_cost":([0-9]{1,15}),`)

// LayerCost is the cost of holding the stored summary of a layer decoded (see
// summaryCost), read from the head of its file without decoding it.
func (c *Cache) LayerCost(diffID string) (int64, bool) {
	h, ok := hexOf(diffID)
	if c.off() || !ok {
		return 0, false
	}
	f, err := os.Open(c.path("layers", h, ".json"))
	if err != nil {
		return 0, false
	}
	defer f.Close()
	head := make([]byte, 64)
	n, _ := io.ReadFull(f, head)
	m := costPrefixRE.FindSubmatch(head[:n])
	if m == nil {
		return 0, false
	}
	cost, err := strconv.ParseInt(string(m[1]), 10, 64)
	return cost, err == nil
}

// PutLayer stores the summary of a layer whose diffID was computed.
func (c *Cache) PutLayer(diffID string, s LayerSummary) error {
	h, ok := hexOf(diffID)
	if c.off() {
		return nil
	}
	if !ok {
		return fmt.Errorf("imagefs: bad diffID %q", diffID)
	}
	return c.writeJSON(c.path("layers", h, ".json"), layerFile{RestoreCost: summaryCost(s), LayerSummary: s})
}

// GetBlob returns the diffID a blob digest was verified to decompress to.
func (c *Cache) GetBlob(blobDigest string) (string, bool) {
	h, ok := hexOf(blobDigest)
	if c.off() || !ok {
		return "", false
	}
	b, ok := c.read(c.path("blobs", h, ""))
	if !ok {
		return "", false
	}
	d := strings.TrimSpace(string(b))
	return d, digestRE.MatchString(d)
}

// PutBlob records that the blob with this digest decompresses to this diffID.
// The caller has verified both.
func (c *Cache) PutBlob(blobDigest, diffID string) error {
	h, ok := hexOf(blobDigest)
	if c.off() {
		return nil
	}
	if _, ok2 := hexOf(diffID); !ok || !ok2 {
		return fmt.Errorf("imagefs: bad digest %q or diffID %q", blobDigest, diffID)
	}
	return c.write(c.path("blobs", h, ""), []byte(diffID))
}

// GetImage returns the result for the image config, if it was computed from
// exactly these diffIDs.
func (c *Cache) GetImage(configDigest string, diffIDs []string) (ImageResult, bool) {
	h, ok := hexOf(configDigest)
	if c.off() || !ok {
		return ImageResult{}, false
	}
	var r ImageResult
	if !c.readJSON(c.path("images", h, ".json"), &r) {
		return ImageResult{}, false
	}
	if r.Version != SummaryVersion || !slices.Equal(r.DiffIDs, diffIDs) {
		return ImageResult{}, false
	}
	return r, true
}

// PutImage stores the result for an image config.
func (c *Cache) PutImage(configDigest string, r ImageResult) error {
	h, ok := hexOf(configDigest)
	if c.off() {
		return nil
	}
	if !ok {
		return fmt.Errorf("imagefs: bad config digest %q", configDigest)
	}
	r.Version = SummaryVersion
	return c.writeJSON(c.path("images", h, ".json"), r)
}

// GetFailure returns the record for a route key when it was made under the
// given limits, summary format and program version.
func (c *Cache) GetFailure(key string, l Limits, program string) (FailureRecord, bool) {
	if c == nil {
		return FailureRecord{}, false
	}
	if c.dir == "" {
		c.mu.Lock()
		r, ok := c.memFail[key]
		c.mu.Unlock()
		if !ok || r.Key != key || r.Limits != l.withDefaults() || r.SummaryVersion != SummaryVersion || r.ProgramVersion != program {
			return FailureRecord{}, false
		}
		return r, true
	}
	var r FailureRecord
	if !c.readJSON(c.path("failures", keyName(key), ".json"), &r) {
		return FailureRecord{}, false
	}
	if r.Key != key || r.Limits != l.withDefaults() || r.SummaryVersion != SummaryVersion || r.ProgramVersion != program {
		return FailureRecord{}, false
	}
	return r, true
}

// PutFailure stores a record.
func (c *Cache) PutFailure(r FailureRecord) error {
	if c == nil {
		return nil
	}
	r.SummaryVersion = SummaryVersion
	r.Limits = r.Limits.withDefaults()
	if r.Time.IsZero() {
		r.Time = c.clock()
	}
	if c.dir == "" {
		c.mu.Lock()
		c.memFail[r.Key] = r
		c.mu.Unlock()
		return nil
	}
	return c.writeJSON(c.path("failures", keyName(r.Key), ".json"), r)
}

type counterFile struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Timeouts returns how many Docker reads of the route in a row timed out.
func (c *Cache) Timeouts(key string) int {
	if c == nil {
		return 0
	}
	if c.dir == "" {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.memCount[key]
	}
	var f counterFile
	if !c.readJSON(c.path("counters", keyName(key), ".json"), &f) || f.Key != key {
		return 0
	}
	return f.Count
}

// SetTimeouts stores the count; 0 removes it.
func (c *Cache) SetTimeouts(key string, n int) error {
	if c == nil {
		return nil
	}
	if c.dir == "" {
		c.mu.Lock()
		defer c.mu.Unlock()
		if n <= 0 {
			delete(c.memCount, key)
		} else {
			c.memCount[key] = n
		}
		return nil
	}
	p := c.path("counters", keyName(key), ".json")
	if n <= 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return c.writeJSON(p, counterFile{Key: key, Count: n})
}

// pruneIfWritten is Prune when something was written since the last prune.
func (c *Cache) pruneIfWritten() error {
	if c.off() {
		return nil
	}
	c.mu.Lock()
	d := c.dirty
	c.mu.Unlock()
	if !d {
		return nil
	}
	return c.Prune()
}

// Prune deletes the least recently used files beyond MaxFiles, and temporary
// files left by an interrupted write.
func (c *Cache) Prune() error {
	if c.off() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dirty = false
	max := c.MaxFiles
	if max <= 0 {
		max = DefaultMaxCacheFiles
	}
	type file struct {
		path string
		mod  time.Time
	}
	var files []file
	var firstErr error
	for _, d := range cacheDirs {
		entries, err := os.ReadDir(filepath.Join(c.dir, d))
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			p := filepath.Join(c.dir, d, e.Name())
			if strings.HasPrefix(e.Name(), tempPrefix) {
				if c.clock().Sub(info.ModTime()) > time.Hour {
					_ = os.Remove(p)
				}
				continue
			}
			files = append(files, file{p, info.ModTime()})
		}
	}
	if len(files) <= max {
		return nil
	}
	slices.SortFunc(files, func(a, b file) int {
		if d := a.mod.Compare(b.mod); d != 0 {
			return d
		}
		return strings.Compare(a.path, b.path)
	})
	for _, f := range files[:len(files)-max] {
		if err := os.Remove(f.path); err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
