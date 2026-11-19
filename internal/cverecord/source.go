package cverecord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// refreshAfter is the age past which a cached answer is asked for again
	// (see the same constant of the other advisory caches).
	refreshAfter = 20 * time.Hour
	// dropAfter is how long an answer nothing asked for stays in the cache.
	dropAfter = 30 * 24 * time.Hour
	// usedStep is how far the recorded last use may lag, so that using an
	// answer does not rewrite the cache every time.
	usedStep = 12 * time.Hour

	// maxRecordBytes bounds one record. It only guards against a rogue
	// endpoint; real records are far below it.
	maxRecordBytes = 2 << 20
	// maxCallFetches and maxCycleFetches bound the record requests of one
	// Severities call and of one cycle, whatever the scan reports name. The
	// limit of a call keeps one report from using up what the others need.
	maxCallFetches  = 200
	maxCycleFetches = 2000
	// maxCycleIDs bounds the answers kept for a cycle.
	maxCycleIDs = 50000
	// maxCacheEntries bounds the cache file. A full cache takes no new
	// answer, and an ID without one is then not looked up: a severity that
	// could not be kept must not be given in the first place.
	maxCacheEntries = 20000
	// resolveTimeout bounds the requests of one Severities call.
	resolveTimeout = time.Minute
	// maxLogged bounds the answers one log line names.
	maxLogged = 20

	cacheFile = "severity.json"
)

// Source answers which severity the CVE record of a vulnerability states,
// from the CVE list repository, with a cache of the answers under CacheDir.
// CacheDir should be a directory of its own. The zero value of the other
// fields is ready to use. A Source is used through a pointer.
//
// An answer that was read once is kept for as long as something asks for it:
// when its record cannot be read again, the cached answer stands, however old.
// A finding that got its severity here therefore never loses it to an outage,
// which the notification state would report as the vulnerability being gone.
type Source struct {
	CacheDir string
	BaseURL  string
	Client   *http.Client
	Now      func() time.Time
	Log      *slog.Logger

	// Overrides of the limits above for tests; zero uses the limit.
	callLimit  int
	cycleLimit int
	idLimit    int
	cacheLimit int
	timeout    time.Duration

	mu sync.Mutex
	// cycle holds the answer given for each ID since BeginCycle, "" for
	// none, so that every scan of a cycle sees the same severity.
	cycle map[string]string
	// cache is the cache file as this cycle has changed it; loaded says it
	// was read. base is the severities it held when the cycle first read it,
	// which answer for the IDs that no longer fit in cycle.
	cache   map[string]entry
	base    map[string]string
	loaded  bool
	fetches int
}

// entry is the cached answer for one CVE ID.
type entry struct {
	// Severity is "" when the record states none.
	Severity string    `json:"severity"`
	Fetched  time.Time `json:"fetched"`
	ETag     string    `json:"etag,omitempty"`
	Used     time.Time `json:"used"`
}

var (
	errNotFound  = errors.New("no record")
	errBudget    = errors.New("the record requests of this scan or cycle are used up")
	errCacheFull = errors.New("the cache of answers is full")
)

// BeginCycle forgets the answers given so far. The scan cycle calls it before
// its first scan; every scan up to the next call gets the same answer for the
// same ID.
func (s *Source) BeginCycle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cycle, s.cache, s.base, s.loaded = nil, nil, nil, false
	s.fetches = 0
}

// Severities returns the severity (LOW, MEDIUM, HIGH or CRITICAL) the CVE
// record states for each of ids that has one. An ID that is not a CVE ID,
// whose record states no severity, or whose record could not be read and was
// never read before is left out. It never fails: a record that cannot be read
// is logged, and the answer read earlier is used in its place.
func (s *Source) Severities(ctx context.Context, ids []string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cycle == nil {
		s.cycle = map[string]string{}
	}
	asked := map[string]bool{}
	var need []string
	for _, id := range ids {
		if asked[id] || !ValidID(id) {
			continue
		}
		asked[id] = true
		if _, ok := s.cycle[id]; !ok {
			need = append(need, id)
		}
	}
	if len(need) > 0 {
		s.resolve(ctx, need)
	}
	out := map[string]string{}
	used := false
	now := s.now()
	for id := range asked {
		sev, ok := s.cycle[id]
		if !ok {
			// More IDs than a cycle keeps answers for: what the cache held
			// at the start of the cycle answers, and nothing is asked for.
			// Answering is still a use, or the answer would be dropped as
			// one nothing asks for.
			if sev = s.base[id]; sev != "" && s.touch(id, now) {
				used = true
			}
		}
		if sev != "" {
			out[id] = sev
		}
	}
	if used {
		if err := s.save(); err != nil {
			s.log().Warn("write the CVE record severity cache failed", "err", err)
		}
	}
	return out
}

// touch records that the cached answer for id was used at now, and reports
// whether that changed the cache: the recorded time may lag by usedStep.
func (s *Source) touch(id string, now time.Time) bool {
	e, ok := s.cache[id]
	if !ok || now.Sub(e.Used) < usedStep {
		return false
	}
	e.Used = now
	s.cache[id] = e
	return true
}

// open reads the cache for the cycle, once, dropping the answers nothing
// asked for in dropAfter.
func (s *Source) open(now time.Time) {
	if s.loaded {
		return
	}
	s.loaded = true
	s.cache = s.load()
	s.base = map[string]string{}
	for id, e := range s.cache {
		if now.Sub(e.Used) > dropAfter {
			delete(s.cache, id)
			continue
		}
		if e.Severity != "" {
			s.base[id] = e.Severity
		}
	}
}

// resolve settles the cycle's answer for each of need, as far as the cycle
// keeps answers.
func (s *Source) resolve(ctx context.Context, need []string) {
	ctx, cancel := context.WithTimeout(ctx, s.resolveTimeout())
	defer cancel()
	log := s.log()
	now := s.now()
	s.open(now)
	// IDs never read come first: when the requests run out, an ID read
	// before still has its earlier answer, and a new one has nothing.
	sort.Slice(need, func(i, j int) bool {
		_, a := s.cache[need[i]]
		_, b := s.cache[need[j]]
		if a != b {
			return !a
		}
		return need[i] < need[j]
	})
	changed := false
	fetched, failed, unkept := 0, 0, 0
	var firstErr error
	var resolved []string
	for _, id := range need {
		if len(s.cycle) >= s.maxIDs() {
			unkept++
			continue
		}
		e, ok := s.cache[id]
		if !ok || now.Sub(e.Fetched) >= refreshAfter {
			var got entry
			var err error
			switch {
			case !ok && len(s.cache) >= s.maxCache():
				err = errCacheFull
			case fetched >= s.maxCallFetches() || s.fetches >= s.maxCycleFetches():
				err = errBudget
			default:
				fetched++
				s.fetches++
				got, err = s.fetch(ctx, id, e, ok, now)
			}
			switch {
			case err == nil:
				got.Used = e.Used
				e, ok = got, true
				s.cache[id] = e
				changed = true
			case ok:
				log.Debug("the CVE record could not be read again; the answer read earlier stands", "cve", id, "fetched_at", e.Fetched, "err", err)
			case errors.Is(err, errNotFound):
				// An ID the list has no record for (reserved, or not a CVE
				// that was ever published) is not a failure to report: there
				// is nothing to read, today or tomorrow.
				log.Debug("no CVE record exists for this ID; its severity stays UNKNOWN", "cve", id)
			default:
				failed++
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", id, err)
				}
			}
		}
		sev := ""
		if ok {
			sev = e.Severity
			if s.touch(id, now) {
				changed = true
			}
		}
		s.cycle[id] = sev
		if sev != "" {
			resolved = append(resolved, id+"="+sev)
		}
	}
	if n := len(resolved); n > 0 {
		if n > maxLogged {
			resolved = resolved[:maxLogged]
		}
		log.Info("severity taken from CVE records for vulnerabilities Trivy reports without one", "count", n, "cves", strings.Join(resolved, " "))
	}
	if failed > 0 {
		log.Warn("CVE records could not be read; these vulnerabilities keep the severity UNKNOWN in this cycle", "count", failed, "first", firstErr)
	}
	if unkept > 0 {
		log.Warn("more vulnerabilities without a severity than a cycle looks up; the rest keep the severity UNKNOWN unless it was read before", "not_looked_up", unkept)
	}
	if changed {
		if err := s.save(); err != nil {
			log.Warn("write the CVE record severity cache failed", "err", err)
		}
	}
}

// fetch asks for the record of id and returns the answer to cache. cached is
// the previous answer when has is set; a record that has not changed since
// keeps its severity.
func (s *Source) fetch(ctx context.Context, id string, cached entry, has bool, now time.Time) (entry, error) {
	base := s.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	url, _ := RecordURL(base, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return entry{}, fmt.Errorf("build request: %w", err)
	}
	if has && cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return entry{}, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && has && cached.ETag != "":
		cached.Fetched = now
		return cached, nil
	case resp.StatusCode == http.StatusNotFound:
		return entry{}, errNotFound
	case resp.StatusCode != http.StatusOK:
		return entry{}, fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRecordBytes+1))
	if err != nil {
		return entry{}, fmt.Errorf("download %s: %w", url, err)
	}
	if len(data) > maxRecordBytes {
		return entry{}, fmt.Errorf("download %s: larger than %d bytes", url, maxRecordBytes)
	}
	sev, err := severityOfRecord(id, data)
	if err != nil {
		return entry{}, fmt.Errorf("download %s: %w", url, err)
	}
	return entry{Severity: sev, Fetched: now, ETag: resp.Header.Get("ETag")}, nil
}

// load reads the cache. A missing or unreadable cache is empty: the answers
// are asked for again.
func (s *Source) load() map[string]entry {
	cache := map[string]entry{}
	data, err := os.ReadFile(filepath.Join(s.CacheDir, cacheFile))
	if err != nil {
		return cache
	}
	var loaded map[string]entry
	if err := json.Unmarshal(data, &loaded); err != nil {
		return cache
	}
	for id, e := range loaded {
		if ValidID(id) && (e.Severity == "" || levels[e.Severity]) {
			cache[id] = e
		}
	}
	return cache
}

// save replaces the cache file atomically with the cycle's cache.
func (s *Source) save() error {
	data, err := json.Marshal(s.cache)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.CacheDir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	path := filepath.Join(s.CacheDir, cacheFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func (s *Source) maxCache() int {
	if s.cacheLimit > 0 {
		return s.cacheLimit
	}
	return maxCacheEntries
}

func (s *Source) maxCallFetches() int {
	if s.callLimit > 0 {
		return s.callLimit
	}
	return maxCallFetches
}

func (s *Source) maxCycleFetches() int {
	if s.cycleLimit > 0 {
		return s.cycleLimit
	}
	return maxCycleFetches
}

func (s *Source) maxIDs() int {
	if s.idLimit > 0 {
		return s.idLimit
	}
	return maxCycleIDs
}

func (s *Source) resolveTimeout() time.Duration {
	if s.timeout > 0 {
		return s.timeout
	}
	return resolveTimeout
}

var defaultClient = &http.Client{Timeout: 20 * time.Second}

func (s *Source) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return defaultClient
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Source) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}
