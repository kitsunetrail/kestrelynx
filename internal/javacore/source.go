package javacore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// refreshAfter is the cache age past which a dataset is re-downloaded at
	// the start of a scan cycle (see the same constant in package intel).
	refreshAfter = 20 * time.Hour
	// maxStale is how old a cached dataset may be and still be used when
	// re-downloading fails. Past this the dataset is unusable.
	maxStale = 7 * 24 * time.Hour
	// recentWindow is how long after its date an advisory may still be
	// corrected, so it is downloaded again; an older one is read from the
	// cache when there is one.
	recentWindow = 180 * 24 * time.Hour
	// maxPageErrors is how many advisory failures a Load reports in full.
	maxPageErrors = 5
	// loadTimeout bounds one Load, all downloads included.
	loadTimeout = 10 * time.Minute
)

// cache file names under CacheDir.
const (
	indexFile     = "advisories.html"
	advisoriesDir = "advisories"
	releasesFile  = "releases.json"
	availableFile = "available-releases.json"
	metaFile      = "meta.json"
)

// Source fetches and caches the advisory datasets. Only CacheDir is
// required; it should be a directory of its own, since the datasets and
// their meta.json are kept directly in it. Empty URLs fall back to the
// defaults.
type Source struct {
	CacheDir           string
	AdvisoriesURL      string
	ReleasesURL        string
	FeatureReleasesURL string
	Client             *http.Client
	Now                func() time.Time
	Log                *slog.Logger

	// Override of the limit above for tests; zero uses the limit.
	timeout time.Duration
}

// notFoundError is a 404 from a dataset URL.
type notFoundError struct{ url string }

func (e *notFoundError) Error() string { return fmt.Sprintf("fetch %s: not found", e.url) }

// cacheMeta records when each cached file was fetched, by file name relative
// to the dataset directory.
type cacheMeta struct {
	Fetched map[string]time.Time `json:"fetched"`
}

func newCacheMeta() *cacheMeta {
	return &cacheMeta{Fetched: map[string]time.Time{}}
}

// Load refreshes the cached datasets as needed and parses them. It returns a
// non-nil Snapshot only when all four datasets (the advisory list, the
// advisories, the Temurin release list and the release series list) are
// usable; the error explains which were not.
//
// A downloaded dataset that has lost something the cached copy had is not
// accepted, and the cached copy is used: an advisory is corrected by adding
// to it, so a loss means a truncated or rolled-back download, and matching
// without what was lost would make a detected CVE look resolved. To take in a
// correction that really removes something, delete the cache directory.
func (s *Source) Load(ctx context.Context) (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, s.loadTimeout())
	defer cancel()

	dir := s.CacheDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	meta := s.loadMeta(dir)
	defer func() { s.saveMeta(dir, meta) }()

	var problems []error
	fail := func(dataset string, err error) {
		problems = append(problems, fmt.Errorf("%s: %w", dataset, err))
	}

	var dates []string
	if data, err := s.dataset(ctx, dir, meta, indexFile, s.advisoriesBase(), maxIndexBytes, s.indexValidator(dir)); err != nil {
		fail("advisory list", err)
	} else if dates, err = parseIndex(data); err != nil {
		fail("advisory list", err)
	}

	releases, err := s.releases(ctx, dir, meta)
	if err != nil {
		fail("release list", err)
	}

	var avail availableReleases
	if data, err := s.dataset(ctx, dir, meta, availableFile, s.featureReleasesURL(), maxAvailableReleasesLen, s.availableValidator(dir)); err != nil {
		fail("release series list", err)
	} else if avail, err = parseAvailableReleases(data); err != nil {
		fail("release series list", err)
	}

	var pages []*page
	pageFailures := 0
	for _, date := range dates {
		p, err := s.advisory(ctx, dir, meta, date)
		if err != nil {
			// Only a few are kept in full; the rest are counted.
			if pageFailures++; pageFailures <= maxPageErrors {
				fail("advisory", err)
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		pages = append(pages, p)
	}
	if pageFailures > maxPageErrors {
		problems = append(problems, fmt.Errorf("advisory: %d more failed", pageFailures-maxPageErrors))
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("java advisories unavailable: %w", errors.Join(problems...))
	}
	snap := newSnapshot(pages, releases, avail, redactURL(s.advisoriesBase()))
	s.log().Info("java advisories loaded", "advisories", len(pages), "releases", len(releases),
		"unchecked_lines", len(snap.unchecked))
	return snap, nil
}

// advisory returns one parsed advisory. A recent one is downloaded again once
// the cache is older than refreshAfter; an old one only when there is no
// cache. A download that fails, 404 included, or is not accepted leaves the
// cached copy in use, and with no cached copy the advisory is unavailable.
func (s *Source) advisory(ctx context.Context, dir string, meta *cacheMeta, date string) (*page, error) {
	name := advisoriesDir + "/" + date + ".html"
	path := filepath.Join(dir, advisoriesDir, date+".html")
	var cached *page
	at := meta.Fetched[name]
	if data, err := os.ReadFile(path); err == nil {
		cached, err = parsePage(date, data)
		if err != nil {
			s.log().Warn("ignoring unreadable cached java advisory", "date", date, "err", err)
			cached = nil
		}
	}
	if cached == nil {
		at = time.Time{} // meta may lie (deleted or damaged cache); treat as absent
	}
	now := s.now()
	if cached != nil && (!s.recent(date, now) || now.Sub(at) < refreshAfter) {
		return cached, nil
	}

	url := s.advisoryURL(date)
	res, err := s.get(ctx, url, maxPageBytes)
	var fresh *page
	if err == nil {
		if fresh, err = parsePage(date, res.data); err == nil && cached != nil {
			err = checkPageUpdate(cached, fresh)
		}
		if err != nil {
			err = fmt.Errorf("download %s: %w", redactURL(url), err)
		}
	}
	if err == nil {
		if err = writeFile(path, res.data); err == nil {
			meta.Fetched[name] = now
			return fresh, nil
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s: %w", date, err)
	}
	if cached != nil {
		s.log().Warn("using cached java advisory", "date", date, "fetched_at", at, "err", err)
		return cached, nil
	}
	return nil, fmt.Errorf("%s: %w", date, err)
}

// recent reports whether an advisory of the given date is young enough to be
// corrected still.
func (s *Source) recent(date string, now time.Time) bool {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return true
	}
	return now.Sub(t) < recentWindow
}

// checkPageUpdate decides whether a downloaded advisory may replace the cached
// one: it must keep every affected version (not lower), every CVE and every
// line a CVE was marked for.
func checkPageUpdate(old, fresh *page) error {
	lines := make([]int, 0, len(old.ceilings))
	for l := range old.ceilings {
		lines = append(lines, l)
	}
	sort.Ints(lines)
	for _, l := range lines {
		oc := old.ceilings[l]
		nc, ok := fresh.ceilings[l]
		if !ok {
			return fmt.Errorf("advisory %s lost the affected version of line %d (%s)", old.date, l, oc)
		}
		if c, ok := nc.compare(oc); !ok || c < 0 {
			return fmt.Errorf("advisory %s lowered the affected version of line %d from %s to %s", old.date, l, oc, nc)
		}
	}
	marks := map[string]map[int]bool{}
	for _, r := range fresh.rows {
		if marks[r.cve] == nil {
			marks[r.cve] = map[int]bool{}
		}
		for l := range r.marked {
			marks[r.cve][l] = true
		}
	}
	for _, r := range old.rows {
		have, ok := marks[r.cve]
		if !ok {
			return fmt.Errorf("advisory %s lost %s", old.date, r.cve)
		}
		var ls []int
		for l := range r.marked {
			ls = append(ls, l)
		}
		sort.Ints(ls)
		for _, l := range ls {
			if !have[l] {
				return fmt.Errorf("advisory %s: %s lost its mark for line %d", old.date, r.cve, l)
			}
		}
	}
	return nil
}

// indexValidator returns the check a downloaded advisory list must pass: it
// parses, and has every date the cached list has.
func (s *Source) indexValidator(dir string) func([]byte) error {
	cached := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(dir, indexFile)); err == nil {
		if dates, err := parseIndex(data); err == nil {
			for _, d := range dates {
				cached[d] = true
			}
		}
	}
	return func(data []byte) error {
		dates, err := parseIndex(data)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for _, d := range dates {
			have[d] = true
		}
		var missing []string
		for d := range cached {
			if !have[d] {
				missing = append(missing, d)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return fmt.Errorf("advisory list lacks %d advisories the cached copy has (first: %s)", len(missing), missing[0])
		}
		return nil
	}
}

// releases returns the Temurin release list: the cached one while it is
// younger than refreshAfter, else a downloaded one. A downloaded list that
// lacks a version the cached one has is not accepted.
func (s *Source) releases(ctx context.Context, dir string, meta *cacheMeta) ([]version, error) {
	path := filepath.Join(dir, releasesFile)
	var cached []version
	at := meta.Fetched[releasesFile]
	if data, err := os.ReadFile(path); err == nil {
		if cached, err = decodeReleases(data); err != nil {
			cached = nil
		}
	}
	if cached == nil {
		at = time.Time{}
	}
	now := s.now()
	if cached != nil && now.Sub(at) < refreshAfter {
		return cached, nil
	}

	fresh, err := s.fetchReleases(ctx)
	if err == nil {
		err = checkReleasesUpdate(cached, fresh)
	}
	if err == nil {
		var data []byte
		if data, err = encodeReleases(fresh); err == nil {
			err = writeFile(path, data)
		}
	}
	if err == nil {
		meta.Fetched[releasesFile] = now
		return fresh, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	if !usable(at, now) {
		if at.IsZero() {
			return nil, err
		}
		return nil, fmt.Errorf("cache from %s is older than %s: %w", at.Format(time.RFC3339), maxStale, err)
	}
	s.log().Warn("using stale java release list", "fetched_at", at, "err", err)
	return cached, nil
}

// checkReleasesUpdate refuses a release list that lacks a version the cached
// one has. Versions are compared as versions, so 27.0.1.0 and 27.0.1 are one.
func checkReleasesUpdate(cached, fresh []version) error {
	for _, v := range cached {
		found := false
		for _, f := range fresh {
			if c, ok := f.compare(v); ok && c == 0 {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("release list lacks %s, which the cached copy has", v)
		}
	}
	return nil
}

// fetchReleases reads the pages of the Temurin release list until the list
// ends: an empty page or a 404. A 404 right after a page that was full is
// asked for once more, since the entries could be an exact multiple of the
// page size or the answer could be a transient miss. A list that has not ended
// after maxReleasePages pages is not one this package can trust.
func (s *Source) fetchReleases(ctx context.Context) ([]version, error) {
	var all []version
	prevFull := false
	for n := 0; n < maxReleasePages; n++ {
		url := s.releasePageURL(n)
		res, err := s.get(ctx, url, maxReleasePageBytes)
		var nf *notFoundError
		if errors.As(err, &nf) && n > 0 && prevFull {
			res, err = s.get(ctx, url, maxReleasePageBytes)
		}
		if errors.As(err, &nf) {
			if n == 0 {
				return nil, err
			}
			return uniqueVersions(all), nil
		}
		if err != nil {
			return nil, err
		}
		vs, size, err := parseReleasePage(res.data)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", redactURL(url), err)
		}
		if size == 0 {
			if n == 0 {
				return nil, fmt.Errorf("download %s: release list is empty", redactURL(url))
			}
			return uniqueVersions(all), nil
		}
		all = append(all, vs...)
		prevFull = size == releasePageSize
	}
	return nil, fmt.Errorf("release list did not end within %d pages", maxReleasePages)
}

// dataset returns the content of a cached file, re-downloading it first when
// the cache is older than refreshAfter. A failed download, a 404 included,
// falls back to the cache while it is within maxStale.
func (s *Source) dataset(ctx context.Context, dir string, meta *cacheMeta, name, url string, limit int64, validate func([]byte) error) ([]byte, error) {
	path := filepath.Join(dir, filepath.FromSlash(name))
	at := meta.Fetched[name]
	if _, err := os.Stat(path); err != nil {
		at = time.Time{} // meta may lie (deleted cache); treat as absent
	}
	now := s.now()
	if at.IsZero() || now.Sub(at) >= refreshAfter {
		err := s.download(ctx, url, path, limit, validate)
		if err == nil {
			at = now
			meta.Fetched[name] = at
		} else {
			if ctx.Err() != nil {
				return nil, err
			}
			if !usable(at, now) {
				if at.IsZero() {
					return nil, err
				}
				return nil, fmt.Errorf("cache from %s is older than %s: %w", at.Format(time.RFC3339), maxStale, err)
			}
			s.log().Warn("using stale java advisory data", "file", name, "fetched_at", at, "err", err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// download fetches url into path atomically. The payload is validated before
// it replaces the previous cache, so a bad response can never clobber a good
// dataset.
func (s *Source) download(ctx context.Context, url, path string, limit int64, validate func([]byte) error) error {
	res, err := s.get(ctx, url, limit)
	if err != nil {
		return err
	}
	if err := validate(res.data); err != nil {
		return fmt.Errorf("download %s: %w", redactURL(url), err)
	}
	return writeFile(path, res.data)
}

// response is a successful answer of get.
type response struct {
	data []byte
}

// get requests url. A body larger than limit is an error.
func (s *Source) get(ctx context.Context, url string, limit int64) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return response{}, fmt.Errorf("build request: %w", err)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		// The transport error repeats the URL; keep only its cause.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return response{}, fmt.Errorf("fetch %s: %w", redactURL(url), err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return response{}, &notFoundError{url: redactURL(url)}
	case resp.StatusCode != http.StatusOK:
		return response{}, fmt.Errorf("fetch %s: unexpected status %s", redactURL(url), resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return response{}, fmt.Errorf("download %s: %w", redactURL(url), err)
	}
	if int64(len(data)) > limit {
		return response{}, fmt.Errorf("download %s: larger than %d bytes", redactURL(url), limit)
	}
	return response{data: data}, nil
}

// writeFile replaces path with data atomically.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
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

// availableValidator returns the check a downloaded release series list must
// pass: it parses, its most recent feature release has not gone down and it
// has every LTS line the cached list has. Otherwise lines would turn from
// supported to past their support, or the reverse, from one download to the
// next.
func (s *Source) availableValidator(dir string) func([]byte) error {
	var cached *availableReleases
	if data, err := os.ReadFile(filepath.Join(dir, availableFile)); err == nil {
		if a, err := parseAvailableReleases(data); err == nil {
			cached = &a
		}
	}
	return func(data []byte) error {
		a, err := parseAvailableReleases(data)
		if err != nil {
			return err
		}
		if cached == nil {
			return nil
		}
		if a.latest < cached.latest {
			return fmt.Errorf("most recent feature release went down from %d to %d", cached.latest, a.latest)
		}
		var lost []int
		for l := range cached.lts {
			if !a.lts[l] {
				lost = append(lost, l)
			}
		}
		if len(lost) > 0 {
			sort.Ints(lost)
			return fmt.Errorf("LTS release %d is no longer listed", lost[0])
		}
		return nil
	}
}

// --- meta / freshness helpers ---

func (s *Source) loadMeta(dir string) *cacheMeta {
	m := newCacheMeta()
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return m
	}
	var loaded cacheMeta
	if err := json.Unmarshal(data, &loaded); err != nil {
		return m // corrupt meta = re-fetch, not an error
	}
	if loaded.Fetched != nil {
		m.Fetched = loaded.Fetched
	}
	return m
}

func (s *Source) saveMeta(dir string, m *cacheMeta) {
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	if err := writeFile(filepath.Join(dir, metaFile), data); err != nil {
		s.log().Warn("write java advisory meta failed", "err", err)
	}
}

// usable reports whether a dataset fetched at t may still be served.
func usable(t, now time.Time) bool {
	return !t.IsZero() && now.Sub(t) <= maxStale
}

// advisoriesBase is the advisory list URL with a trailing slash on its path;
// each advisory's URL is the date appended to that path, with the query kept.
func (s *Source) advisoriesBase() string {
	raw := orDefault(s.AdvisoriesURL, DefaultAdvisoriesURL)
	u, err := neturl.Parse(raw)
	if err != nil {
		return raw // the request will fail and say so
	}
	if !strings.HasSuffix(u.Path, "/") {
		appendPath(u, "/")
	}
	return u.String()
}

// appendPath appends an unescaped suffix to the path of u, keeping the
// escaping of the existing path (a mirror may use %2F inside one segment).
func appendPath(u *neturl.URL, suffix string) {
	escaped := u.EscapedPath() + neturl.PathEscape(suffix)
	if suffix == "/" {
		escaped = u.EscapedPath() + "/"
	}
	p, err := neturl.PathUnescape(escaped)
	if err != nil {
		u.Path += suffix
		u.RawPath = ""
		return
	}
	u.Path, u.RawPath = p, escaped
}

// advisoryURL is the URL of the advisory of a date.
func (s *Source) advisoryURL(date string) string {
	u, err := neturl.Parse(s.advisoriesBase())
	if err != nil {
		return s.advisoriesBase() + date
	}
	appendPath(u, date)
	return u.String()
}

func (s *Source) featureReleasesURL() string {
	return orDefault(s.FeatureReleasesURL, DefaultFeatureReleasesURL)
}

// releasePageURL is the release list URL with its page parameter set to n.
func (s *Source) releasePageURL(n int) string {
	raw := orDefault(s.ReleasesURL, DefaultReleasesURL)
	u, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set("page", strconv.Itoa(n))
	u.RawQuery = q.Encode()
	return u.String()
}

// redactURL keeps the scheme, host and path of a URL, for messages and links
// that leave the process: a mirror may be configured with credentials in the
// user information, the query or the fragment.
func redactURL(s string) string {
	u, err := neturl.Parse(s)
	if err != nil {
		return "(unreadable URL)"
	}
	u.User, u.RawQuery, u.Fragment, u.ForceQuery = nil, "", "", false
	return u.String()
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (s *Source) loadTimeout() time.Duration {
	if s.timeout > 0 {
		return s.timeout
	}
	return loadTimeout
}

func (s *Source) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return defaultClient
}

var defaultClient = &http.Client{Timeout: 2 * time.Minute}

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
