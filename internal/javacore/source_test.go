package javacore

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// site is a fake of openjdk.org and api.adoptium.net serving the recorded
// data. Keys are the request path, with "?<query>" when there is a query.
type site struct {
	t   *testing.T
	srv *httptest.Server

	mu     sync.Mutex
	body   map[string][]byte
	status map[string]int
	seq    map[string][]int // statuses to answer successive requests with, then the usual
	hits   map[string]int
	now    time.Time
	logs   bytes.Buffer
}

func newSite(t *testing.T) *site {
	t.Helper()
	s := &site{
		t:      t,
		body:   map[string][]byte{},
		status: map[string]int{},
		seq:    map[string][]int{},
		hits:   map[string]int{},
		now:    time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC),
	}
	s.body["/adv/"] = readFixture(t, "advisories/index.html")
	for _, d := range fixtureDates(t) {
		s.body["/adv/"+d] = readFixture(t, "advisories/"+d+".html")
	}
	for i := 0; i < 3; i++ {
		s.body[fmt.Sprintf("/rel?page=%d", i)] = readFixture(t, fmt.Sprintf("adoptium/release_versions_page%d.json", i))
	}
	s.body["/avail"] = readFixture(t, "adoptium/available_releases.json")
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *site) serve(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Path
	if r.URL.RawQuery != "" {
		key += "?" + r.URL.RawQuery
	}
	s.mu.Lock()
	s.hits[key]++
	code, hasCode := s.status[key]
	if q := s.seq[key]; len(q) > 0 {
		code, hasCode = q[0], true
		s.seq[key] = q[1:]
	}
	body, ok := s.body[key]
	s.mu.Unlock()
	switch {
	case hasCode && code != http.StatusOK:
		http.Error(w, "fixture", code)
	case !ok:
		http.NotFound(w, r)
	default:
		w.Write(body)
	}
}

func (s *site) set(key string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body[key] = body
	delete(s.status, key)
}

func (s *site) remove(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.body, key)
}

func (s *site) fail(key string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status[key] = code
}

func (s *site) failAll(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.body {
		s.status[k] = code
	}
	s.status["/rel?page=3"] = code
}

func (s *site) heal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = map[string]int{}
}

func (s *site) sequence(key string, codes ...int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq[key] = codes
}

func (s *site) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[key]
}

func (s *site) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.hits {
		n += c
	}
	return n
}

func (s *site) resetHits() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = map[string]int{}
}

func (s *site) advance(d time.Duration) { s.now = s.now.Add(d) }

func (s *site) newSource(dir string) *Source {
	return &Source{
		CacheDir:           dir,
		AdvisoriesURL:      s.srv.URL + "/adv",
		ReleasesURL:        s.srv.URL + "/rel",
		FeatureReleasesURL: s.srv.URL + "/avail",
		Client:             s.srv.Client(),
		Now:                func() time.Time { return s.now },
		Log:                slog.New(slog.NewTextHandler(&s.logs, nil)),
	}
}

func (s *site) source(t *testing.T) *Source { return s.newSource(t.TempDir()) }

func pageOf(t *testing.T, sn *Snapshot, date string) *page {
	t.Helper()
	for _, p := range sn.pages {
		if p.date == date {
			return p
		}
	}
	t.Fatalf("no page %s in the snapshot", date)
	return nil
}

func TestLoad_RecordedData(t *testing.T) {
	site := newSite(t)
	sn, err := site.source(t).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sn.pages) != 35 {
		t.Errorf("pages = %d, want 35", len(sn.pages))
	}
	if got := match(t, sn, "21.0.13.1"); len(got) != 0 {
		t.Errorf("21.0.13.1 matched %v", ids(got))
	}
	if got := match(t, sn, "21.0.12.1"); len(got) == 0 {
		t.Error("21.0.12.1 matched nothing")
	}
	// One request per dataset; the release list ended with a 404 after a
	// page of 39, which is not asked again.
	if site.count("/adv/") != 1 || site.count("/avail") != 1 || site.count("/adv/2026-11-17") != 1 {
		t.Errorf("hits = %v", site.hits)
	}
	for i, want := range []int{1, 1, 1, 1} {
		if got := site.count(fmt.Sprintf("/rel?page=%d", i)); got != want {
			t.Errorf("release page %d requested %d times, want %d", i, got, want)
		}
	}
	if site.total() != 1+35+4+1 {
		t.Errorf("requests = %d, want %d", site.total(), 1+35+4+1)
	}
}

func TestLoad_UsesCacheThenRefreshesRecentAdvisoriesOnly(t *testing.T) {
	site := newSite(t)
	src := site.source(t)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	site.resetHits()
	site.advance(19 * time.Hour)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := site.total(); n != 0 {
		t.Errorf("a cache of 19 hours made %d requests", n)
	}

	// Past 20 hours: the three lists and the advisories within 180 days of
	// the date (2026-05-28 on): 2026-07-21, 08-18, 10-20, 10-21, 10-24 and
	// 11-17.
	site.advance(2 * time.Hour)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, d := range fixtureDates(t) {
		want := 0
		if d >= "2026-06" {
			want = 1
		}
		if got := site.count("/adv/" + d); got != want {
			t.Errorf("advisory %s requested %d times, want %d", d, got, want)
		}
	}
	if site.count("/adv/") != 1 || site.count("/avail") != 1 || site.count("/rel?page=0") != 1 {
		t.Errorf("hits = %v", site.hits)
	}
	if site.total() != 1+6+4+1 {
		t.Errorf("requests = %d, want %d", site.total(), 1+6+4+1)
	}
}

func TestLoad_OldAdvisoryWithoutCacheIsFetched(t *testing.T) {
	site := newSite(t)
	dir := t.TempDir()
	src := site.newSource(dir)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "advisories", "2019-04-16.html")); err != nil {
		t.Fatal(err)
	}
	site.resetHits()
	site.advance(time.Hour)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if site.count("/adv/2019-04-16") != 1 || site.count("/adv/2019-07-16") != 0 {
		t.Errorf("hits = %v", site.hits)
	}
}

func TestLoad_FailedDownloadsUseTheCache(t *testing.T) {
	site := newSite(t)
	src := site.source(t)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Everything fails after 21 hours: the cache is used, 404s included.
	site.advance(21 * time.Hour)
	site.failAll(http.StatusInternalServerError)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("stale data within 7 days: %v", err)
	}
	site.failAll(http.StatusNotFound)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("404s with a cache: %v", err)
	}

	// The three lists are usable for 7 days.
	site.advance(7 * 24 * time.Hour)
	if _, err := src.Load(context.Background()); err == nil {
		t.Fatal("lists older than 7 days were used")
	}
	site.heal()
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatalf("after recovery: %v", err)
	}

	// One advisory failing alone keeps its cached copy.
	site.advance(21 * time.Hour)
	site.fail("/adv/2026-11-17", http.StatusNotFound)
	sn, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pageOf(t, sn, "2026-11-17").rows) != 10 {
		t.Error("the cached advisory was not used")
	}
}

func TestLoad_NothingCachedAndAFetchFails(t *testing.T) {
	cases := map[string]func(*site){
		"list":           func(s *site) { s.fail("/adv/", 500) },
		"advisory":       func(s *site) { s.fail("/adv/2019-04-16", 404) },
		"recent":         func(s *site) { s.fail("/adv/2026-11-17", 500) },
		"releases":       func(s *site) { s.fail("/rel?page=0", 404) },
		"series":         func(s *site) { s.fail("/avail", 500) },
		"invalid series": func(s *site) { s.set("/avail", []byte(`{"available_lts_releases":[]}`)) },
		"invalid advisory": func(s *site) {
			s.set("/adv/2026-11-17", []byte("<html></html>"))
		},
	}
	for name, setup := range cases {
		site := newSite(t)
		setup(site)
		sn, err := site.source(t).Load(context.Background())
		if err == nil || sn != nil {
			t.Errorf("%s: Load = %v, %v; want an error", name, sn, err)
			continue
		}
		if !strings.Contains(err.Error(), "java advisories unavailable") {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	site := newSite(t)
	site.fail("/adv/2019-04-16", 404)
	if _, err := site.source(t).Load(context.Background()); err == nil || !strings.Contains(err.Error(), "2019-04-16") {
		t.Errorf("the error does not name the advisory: %v", err)
	}
}

// load2 loads once, advances past the refresh age, and loads again, after
// mutate has changed the site.
func load2(t *testing.T, mutate func(*site)) (*Snapshot, *site, string) {
	t.Helper()
	site := newSite(t)
	dir := t.TempDir()
	src := site.newSource(dir)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	site.advance(21 * time.Hour)
	mutate(site)
	sn, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	return sn, site, dir
}

func TestLoad_RefusesAListThatLostAnAdvisory(t *testing.T) {
	index := string(readFixture(t, "advisories/index.html"))
	cut := strings.Replace(index, `<li><a href="2019-04-16">2019/04/16</a></li>`, "", 1)
	if cut == index {
		t.Fatal("fixture lacks the entry")
	}
	sn, site, dir := load2(t, func(s *site) { s.set("/adv/", []byte(cut)) })
	if len(sn.pages) != 35 {
		t.Errorf("pages = %d, want 35: the cached list was not kept", len(sn.pages))
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "advisories.html")); string(got) != index {
		t.Error("the cached list was replaced")
	}
	if !strings.Contains(site.logs.String(), "2019-04-16") {
		t.Errorf("the log does not name the missing date:\n%s", site.logs.String())
	}

	// A list that only gained an advisory is taken.
	more := strings.Replace(index, `<ul>`, `<ul><li><a href="2026-12-15">2026/12/15 (latest)</a></li>`, 1)
	site2 := newSite(t)
	site2.set("/adv/2026-12-15", bytes.ReplaceAll(readFixture(t, "advisories/2026-11-17.html"), []byte("2026/11/17"), []byte("2026/12/15")))
	site2.set("/adv/", []byte(more))
	sn, err := site2.source(t).Load(context.Background())
	if err != nil || len(sn.pages) != 36 {
		t.Errorf("an extended list: %v, %v", sn, err)
	}
}

func TestLoad_RefusesAReleaseListThatLostAVersion(t *testing.T) {
	page0 := string(readFixture(t, "adoptium/release_versions_page0.json"))
	i := strings.Index(page0, `"openjdk_version": "21.0.13.1+2-LTS"`)
	if i < 0 {
		t.Fatal("fixture lacks 21.0.13.1")
	}
	cut := strings.Replace(page0, `"openjdk_version": "21.0.13.1+2-LTS"`, `"openjdk_version": "21.0.13+9-LTS"`, 1)
	sn, site, dir := load2(t, func(s *site) { s.set("/rel?page=0", []byte(cut)) })
	found := false
	for _, v := range sn.releases[21] {
		if v.String() == "21.0.13.1" {
			found = true
		}
	}
	if !found {
		t.Error("the cached release list was not kept")
	}
	if !strings.Contains(site.logs.String(), "21.0.13.1") {
		t.Errorf("the log does not name the missing version:\n%s", site.logs.String())
	}
	data, _ := os.ReadFile(filepath.Join(dir, "releases.json"))
	if !strings.Contains(string(data), "21.0.13.1") {
		t.Error("the cached release list was replaced")
	}
}

func TestLoad_RefusesAnAdvisoryThatLostSomething(t *testing.T) {
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	row1 := `<tr><td nowrap="nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-114938">CVE-2026-114938</a></td>`
	start := strings.Index(good, row1)
	rowEnd := strings.Index(good[start:], "</tr>") + start + 5
	cases := map[string]struct {
		page  string
		names string // what the log must name
	}{
		"a CVE row": {good[:start] + good[rowEnd:], "CVE-2026-114938"},
		"a mark": {strings.Replace(good, `<td></td><td></td><td>&#8226;</td><td>&#8226;</td><td>&#8226;</td><td>&#8226;</td></tr>`,
			`<td></td><td></td><td></td><td>&#8226;</td><td>&#8226;</td><td>&#8226;</td></tr>`, 1), "CVE-2026-114938"},
		"a line's version": {strings.Replace(good, "11.0.33, ", "", 1), "line 11"},
		"a lower version":  {strings.Replace(good, "27.0.1.0.3,", "27.0.1.0.2,", 1), "line 27"},
		"unreadable":       {strings.Replace(good, "<h2 id=\"risk-matrix\">", "<h2 id=\"risk-matrix\"><b>", 1), "2026-11-17"},
		"too large":        {good + strings.Repeat(" ", maxPageBytes), "larger"},
		"not found":        {"", ""},
	}
	for name, c := range cases {
		if c.page == good {
			t.Fatalf("%s: the page was not changed", name)
		}
		sn, site, dir := load2(t, func(s *site) {
			if name == "not found" {
				s.fail("/adv/2026-11-17", 404)
				return
			}
			s.set("/adv/2026-11-17", []byte(c.page))
		})
		p := pageOf(t, sn, "2026-11-17")
		if len(p.rows) != 10 || p.ceilings[27].String() != "27.0.1.0.3" {
			t.Errorf("%s: the cached advisory was not kept: %d rows", name, len(p.rows))
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "advisories", "2026-11-17.html")); string(got) != good {
			t.Errorf("%s: the cached advisory was replaced", name)
		}
		if c.names != "" && !strings.Contains(site.logs.String(), c.names) {
			t.Errorf("%s: the log does not name %q:\n%s", name, c.names, site.logs.String())
		}
	}
}

func TestLoad_TakesACorrectedAdvisory(t *testing.T) {
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	// A mark added for line 8 on the first CVE, a higher version for 8.
	corrected := strings.Replace(good, `<td></td><td></td><td>&#8226;</td><td>&#8226;</td><td>&#8226;</td><td>&#8226;</td></tr>`,
		`<td>&#8226;</td><td></td><td>&#8226;</td><td>&#8226;</td><td>&#8226;</td><td>&#8226;</td></tr>`, 1)
	corrected = strings.Replace(corrected, "8u512,", "8u513,", 1)
	if corrected == good {
		t.Fatal("the page was not changed")
	}
	sn, _, dir := load2(t, func(s *site) { s.set("/adv/2026-11-17", []byte(corrected)) })
	p := pageOf(t, sn, "2026-11-17")
	if !p.rows[0].marked[8] || p.ceilings[8].String() != "8u513" {
		t.Errorf("the corrected advisory was not taken: %v %v", p.rows[0].marked, p.ceilings[8])
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "advisories", "2026-11-17.html")); string(got) != corrected {
		t.Error("the corrected advisory was not cached")
	}
}

func TestLoad_AnOldAdvisoryIsNotRefetchedEvenIfItChanged(t *testing.T) {
	sn, site, _ := load2(t, func(s *site) {
		s.set("/adv/2019-04-16", []byte("garbage"))
		s.resetHits()
	})
	if site.count("/adv/2019-04-16") != 0 {
		t.Error("an advisory older than 180 days was fetched again")
	}
	if len(pageOf(t, sn, "2019-04-16").rows) != 4 {
		t.Error("the cached advisory was not used")
	}
}

func TestLoad_ARecentAdvisoryThatIsGoneKeepsItsCacheWithoutAnAgeLimit(t *testing.T) {
	site := newSite(t)
	src := site.source(t)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The list itself is served; only the advisory is gone for good.
	for i := 0; i < 3; i++ {
		site.advance(30 * time.Hour)
		site.fail("/adv/2026-11-17", 404)
		if _, err := src.Load(context.Background()); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
}

func TestLoad_InvalidDownloadDoesNotReplaceTheListCache(t *testing.T) {
	sn, _, dir := load2(t, func(s *site) {
		s.set("/adv/", []byte("<html>maintenance</html>"))
		s.set("/avail", []byte("not json"))
	})
	if len(sn.pages) != 35 {
		t.Errorf("pages = %d", len(sn.pages))
	}
	data, _ := os.ReadFile(filepath.Join(dir, "available-releases.json"))
	if !strings.Contains(string(data), "most_recent_feature_release") {
		t.Errorf("the series list cache was replaced: %q", data)
	}
}

func TestLoad_DamagedMetaOrCacheIsRefetched(t *testing.T) {
	site := newSite(t)
	dir := t.TempDir()
	src := site.newSource(dir)
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "advisories", "2026-11-17.html"), []byte("damaged"), 0o644); err != nil {
		t.Fatal(err)
	}
	site.resetHits()
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if site.count("/adv/") != 1 || site.count("/adv/2026-11-17") != 1 {
		t.Errorf("hits = %v", site.hits)
	}
}

func TestFetchReleases_Pagination(t *testing.T) {
	t.Run("a 404 right after a full page is asked once more", func(t *testing.T) {
		site := newSite(t)
		site.sequence("/rel?page=1", 404) // then the usual answer
		sn, err := site.source(t).Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if site.count("/rel?page=1") != 2 {
			t.Errorf("page 1 requested %d times, want 2", site.count("/rel?page=1"))
		}
		if len(sn.releases[21]) == 0 || len(sn.releases[8]) == 0 {
			t.Error("the release list is incomplete")
		}
	})
	t.Run("a repeated 404 after a full page ends the list", func(t *testing.T) {
		site := newSite(t)
		site.remove("/rel?page=1")
		sn, err := site.source(t).Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if site.count("/rel?page=1") != 2 || site.count("/rel?page=2") != 0 {
			t.Errorf("hits = %v", site.hits)
		}
		_ = sn
	})
	t.Run("a 404 after a partial page is final", func(t *testing.T) {
		site := newSite(t)
		if _, err := site.source(t).Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		if site.count("/rel?page=3") != 1 {
			t.Errorf("page 3 requested %d times, want 1", site.count("/rel?page=3"))
		}
	})
	t.Run("an empty page ends the list", func(t *testing.T) {
		for name, body := range map[string]string{"no versions": `{"versions":[]}`, "empty body": ""} {
			site := newSite(t)
			site.set("/rel?page=3", []byte(body))
			if _, err := site.source(t).Load(context.Background()); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
	t.Run("page 0 must have versions", func(t *testing.T) {
		for name, setup := range map[string]func(*site){
			"404":         func(s *site) { s.remove("/rel?page=0") },
			"empty":       func(s *site) { s.set("/rel?page=0", []byte(`{"versions":[]}`)) },
			"empty body":  func(s *site) { s.set("/rel?page=0", nil) },
			"server down": func(s *site) { s.fail("/rel?page=0", 503) },
		} {
			site := newSite(t)
			setup(site)
			if _, err := site.source(t).Load(context.Background()); err == nil {
				t.Errorf("%s: Load succeeded", name)
			}
		}
	})
	t.Run("a list that does not end within 20 pages is rejected", func(t *testing.T) {
		site := newSite(t)
		for i := 3; i < 25; i++ {
			site.set(fmt.Sprintf("/rel?page=%d", i), readFixture(t, "adoptium/release_versions_page1.json"))
		}
		_, err := site.source(t).Load(context.Background())
		if err == nil || !strings.Contains(err.Error(), "did not end") {
			t.Errorf("Load = %v", err)
		}
		if site.count("/rel?page=19") != 1 || site.count("/rel?page=20") != 0 {
			t.Errorf("hits = %v", site.hits)
		}
	})
	t.Run("an end on the 20th page is accepted", func(t *testing.T) {
		site := newSite(t)
		for i := 3; i < 19; i++ {
			site.set(fmt.Sprintf("/rel?page=%d", i), readFixture(t, "adoptium/release_versions_page1.json"))
		}
		site.set("/rel?page=19", []byte(`{"versions":[]}`))
		if _, err := site.source(t).Load(context.Background()); err != nil {
			t.Errorf("Load = %v", err)
		}
	})
	t.Run("an unreadable version rejects the list", func(t *testing.T) {
		site := newSite(t)
		page := string(readFixture(t, "adoptium/release_versions_page2.json"))
		bad := regexp.MustCompile(`"openjdk_version": "[^"]*"`).ReplaceAllString(page, `"openjdk_version": "twenty-seven"`)
		if bad == page {
			t.Fatal("the page was not changed")
		}
		site.set("/rel?page=2", []byte(bad))
		if _, err := site.source(t).Load(context.Background()); err == nil {
			t.Error("Load succeeded")
		}
	})
	t.Run("a 5xx in the middle fails", func(t *testing.T) {
		site := newSite(t)
		site.fail("/rel?page=1", 502)
		if _, err := site.source(t).Load(context.Background()); err == nil {
			t.Error("Load succeeded")
		}
	})
}

func TestSource_URLs(t *testing.T) {
	cases := []struct {
		src          Source
		list, page   string
		release0     string
		featureLists string
	}{
		{Source{}, DefaultAdvisoriesURL, DefaultAdvisoriesURL + "2026-11-17", "https://api.adoptium.net/v3/info/release_versions?page=0&page_size=50&release_type=ga&vendor=eclipse", DefaultFeatureReleasesURL},
		{Source{AdvisoriesURL: "https://m.test/adv", ReleasesURL: "https://m.test/rel", FeatureReleasesURL: "https://m.test/f"},
			"https://m.test/adv/", "https://m.test/adv/2026-11-17", "https://m.test/rel?page=0", "https://m.test/f"},
		{Source{AdvisoriesURL: "https://m.test/adv/", ReleasesURL: "https://m.test/rel?x=1"},
			"https://m.test/adv/", "https://m.test/adv/2026-11-17", "https://m.test/rel?page=0&x=1", DefaultFeatureReleasesURL},
	}
	for i, c := range cases {
		if got := c.src.advisoriesBase(); got != c.list {
			t.Errorf("%d: advisoriesBase = %q, want %q", i, got, c.list)
		}
		if got := c.src.advisoriesBase() + "2026-11-17"; got != c.page {
			t.Errorf("%d: page URL = %q, want %q", i, got, c.page)
		}
		if got := c.src.releasePageURL(0); got != c.release0 {
			t.Errorf("%d: releasePageURL = %q, want %q", i, got, c.release0)
		}
		if got := c.src.featureReleasesURL(); got != c.featureLists {
			t.Errorf("%d: featureReleasesURL = %q, want %q", i, got, c.featureLists)
		}
	}
}

func TestLoad_FindingLinksUseTheConfiguredAdvisoryURL(t *testing.T) {
	site := newSite(t)
	sn, err := site.source(t).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, ok := find(match(t, sn, "21.0.13"), "CVE-2026-91403")
	if !ok || a.URL != site.srv.URL+"/adv/2026-10-21" {
		t.Errorf("advisory = %+v, %v", a, ok)
	}
}

func TestLoad_RefusesAPageOfAnotherDate(t *testing.T) {
	site := newSite(t)
	site.set("/adv/2026-11-17", readFixture(t, "advisories/2026-10-24.html"))
	sn, err := site.source(t).Load(context.Background())
	if err == nil || sn != nil || !strings.Contains(err.Error(), "2026-11-17") {
		t.Errorf("Load = %v, %v", sn, err)
	}
}

func TestLoad_RefusesASeriesListThatWentBack(t *testing.T) {
	good := string(readFixture(t, "adoptium/available_releases.json"))
	cases := map[string]struct{ body, names string }{
		"latest down": {strings.Replace(good, `"most_recent_feature_release": 27`, `"most_recent_feature_release": 26`, 1), "went down"},
		"LTS lost":    {strings.Replace(good, "        25\n", "        24\n", 1), "LTS release 25"},
	}
	for name, c := range cases {
		if c.body == good {
			t.Fatalf("%s: not changed", name)
		}
		sn, site, dir := load2(t, func(s *site) { s.set("/avail", []byte(c.body)) })
		if !sn.endOfLife(26) || sn.avail.latest != 27 || !sn.avail.lts[25] {
			t.Errorf("%s: the cached series list was not kept", name)
		}
		if data, _ := os.ReadFile(filepath.Join(dir, "available-releases.json")); string(data) != good {
			t.Errorf("%s: the cached list was replaced", name)
		}
		if !strings.Contains(site.logs.String(), c.names) {
			t.Errorf("%s: the log does not say why:\n%s", name, site.logs.String())
		}
	}
	// A newer list is taken.
	up := strings.Replace(good, `"most_recent_feature_release": 27`, `"most_recent_feature_release": 28`, 1)
	sn, _, _ := load2(t, func(s *site) { s.set("/avail", []byte(up)) })
	if sn.avail.latest != 28 {
		t.Errorf("latest = %d", sn.avail.latest)
	}
}

func TestLoad_ReleaseListComparedAsVersions(t *testing.T) {
	page0 := string(readFixture(t, "adoptium/release_versions_page0.json"))
	if !strings.Contains(page0, `"openjdk_version": "27.0.1.0"`) {
		t.Fatal("fixture lacks 27.0.1.0")
	}
	renamed := strings.Replace(page0, `"openjdk_version": "27.0.1.0"`, `"openjdk_version": "27.0.1"`, 1)
	sn, site, _ := load2(t, func(s *site) { s.set("/rel?page=0", []byte(renamed)) })
	if strings.Contains(site.logs.String(), "lacks") {
		t.Errorf("a trailing zero was taken for a lost version:\n%s", site.logs.String())
	}
	_ = sn
}

func TestLoad_ReleaseListOnlyTakesGAForms(t *testing.T) {
	site := newSite(t)
	page0 := string(readFixture(t, "adoptium/release_versions_page0.json"))
	bad := strings.Replace(page0, `"openjdk_version": "21.0.13.1+2-LTS"`, `"openjdk_version": "21.0.13.0.4-ea"`, 1)
	if bad == page0 {
		t.Fatal("not changed")
	}
	site.set("/rel?page=0", []byte(bad))
	if _, err := site.source(t).Load(context.Background()); err == nil {
		t.Error("a list with an -ea entry was accepted")
	}
	for _, v := range []string{"21.0.13.0.4-ea", "21.0.13+9-LTS-x", "21.0.13+9-beta", "21.0.13-LTS", "unknown"} {
		if _, ok := parseReleaseVersion(v); ok {
			t.Errorf("parseReleaseVersion(%q) succeeded", v)
		}
	}
}

func TestSource_CredentialsInTheMirrorURLStayOutOfOutput(t *testing.T) {
	site := newSite(t)
	u := strings.Replace(site.srv.URL, "http://", "http://reader:secret@", 1)
	src := site.source(t)
	src.AdvisoriesURL = u + "/adv/"
	src.ReleasesURL = u + "/rel"
	src.FeatureReleasesURL = u + "/avail"
	sn, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, ok := find(match(t, sn, "21.0.13"), "CVE-2026-91403")
	if !ok || a.URL != site.srv.URL+"/adv/2026-10-21" || strings.Contains(a.URL, "secret") {
		t.Errorf("advisory = %+v, %v", a, ok)
	}

	// Failures name no credentials, whether the server answers or not.
	site.failAll(500)
	site.advance(21 * time.Hour)
	src2 := site.source(t)
	src2.AdvisoriesURL, src2.ReleasesURL, src2.FeatureReleasesURL = src.AdvisoriesURL, src.ReleasesURL, src.FeatureReleasesURL
	_, err = src2.Load(context.Background())
	if err == nil {
		t.Fatal("Load succeeded")
	}
	site.srv.Close()
	src3 := site.source(t)
	src3.AdvisoriesURL, src3.ReleasesURL, src3.FeatureReleasesURL = src.AdvisoriesURL, src.ReleasesURL, src.FeatureReleasesURL
	_, err2 := src3.Load(context.Background())
	if err2 == nil {
		t.Fatal("Load succeeded")
	}
	for _, text := range []string{err.Error(), err2.Error(), site.logs.String()} {
		if strings.Contains(text, "secret") || strings.Contains(text, "reader") {
			t.Errorf("credentials in output: %.300s", text)
		}
	}
	if got := redactURL("https://reader:secret@mirror.example/advisories/"); got != "https://mirror.example/advisories/" {
		t.Errorf("redactURL = %q", got)
	}
}

func TestLoad_ReportsFewPageErrorsInFull(t *testing.T) {
	site := newSite(t)
	huge := strings.Repeat("x", 100000)
	for _, d := range fixtureDates(t) {
		site.set("/adv/"+d, []byte(strings.Replace(string(readFixture(t, "advisories/"+d+".html")), "<td nowrap=\"nowrap\">", "<td nowrap=\"nowrap\">"+huge, 1)))
	}
	_, err := site.source(t).Load(context.Background())
	if err == nil {
		t.Fatal("Load succeeded")
	}
	if len(err.Error()) > 10000 {
		t.Errorf("the error is %d bytes", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "30 more failed") {
		t.Errorf("the rest are not counted: %.500s", err.Error())
	}
}

func TestSource_QueryInMirrorURLs(t *testing.T) {
	src := Source{
		AdvisoriesURL: "https://m.test/adv?channel=prod", ReleasesURL: "https://m.test/rel?channel=prod&page=0&page=7",
	}
	if got := src.advisoriesBase(); got != "https://m.test/adv/?channel=prod" {
		t.Errorf("advisoriesBase = %q", got)
	}
	if got := src.advisoryURL("2026-11-17"); got != "https://m.test/adv/2026-11-17?channel=prod" {
		t.Errorf("advisoryURL = %q", got)
	}
	if got := src.releasePageURL(3); got != "https://m.test/rel?channel=prod&page=3" {
		t.Errorf("releasePageURL = %q", got)
	}
	if got := redactURL(src.advisoryURL("2026-11-17")); got != "https://m.test/adv/2026-11-17" {
		t.Errorf("redactURL = %q", got)
	}

	// An escaped slash inside one path segment stays escaped.
	esc := Source{AdvisoriesURL: "https://m.test/projects/team%2Fjdk/advisories"}
	if got := esc.advisoriesBase(); got != "https://m.test/projects/team%2Fjdk/advisories/" {
		t.Errorf("advisoriesBase = %q", got)
	}
	if got := esc.advisoryURL("2026-11-17"); got != "https://m.test/projects/team%2Fjdk/advisories/2026-11-17" {
		t.Errorf("advisoryURL = %q", got)
	}
}

func TestLoad_MirrorWithQueryAndSecrets(t *testing.T) {
	site := newSite(t)
	src := site.source(t)
	src.AdvisoriesURL = site.srv.URL + "/adv/?access_token=secret"
	src.ReleasesURL = site.srv.URL + "/rel?access_token=secret"
	src.FeatureReleasesURL = site.srv.URL + "/avail?access_token=secret"
	// The fake serves by path and query; give it the keys with the token.
	site.mu.Lock()
	for k, v := range site.body {
		if strings.HasPrefix(k, "/rel?") {
			site.body["/rel?access_token=secret&"+strings.TrimPrefix(k, "/rel?")] = v
		} else if k == "/adv/" || strings.HasPrefix(k, "/adv/") || k == "/avail" {
			site.body[k+"?access_token=secret"] = v
		}
	}
	site.mu.Unlock()
	sn, err := src.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, ok := find(match(t, sn, "21.0.13"), "CVE-2026-91403")
	if !ok || a.URL != site.srv.URL+"/adv/2026-10-21" {
		t.Errorf("advisory = %+v, %v", a, ok)
	}

	// Failures and logs carry no query.
	site.failAll(503)
	site.advance(21 * time.Hour)
	src2 := site.source(t)
	src2.AdvisoriesURL, src2.ReleasesURL, src2.FeatureReleasesURL = src.AdvisoriesURL, src.ReleasesURL, src.FeatureReleasesURL
	_, err = src2.Load(context.Background())
	if err == nil {
		t.Fatal("Load succeeded")
	}
	for _, text := range []string{err.Error(), site.logs.String()} {
		if strings.Contains(text, "secret") || strings.Contains(text, "access_token") {
			t.Errorf("a query in output: %.300s", text)
		}
	}
	// A cached copy used for a failed download logs without it either.
	if _, err := src.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(site.logs.String(), "secret") {
		t.Errorf("a query in the log:\n%.500s", site.logs.String())
	}
}

func TestParseAvailableReleases_MostRecentLTSMustBeTheHighest(t *testing.T) {
	good := string(readFixture(t, "adoptium/available_releases.json"))
	if _, err := parseAvailableReleases([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"extra LTS": strings.Replace(good, "        25\n", "        25,\n        26\n", 1),
		"lower":     strings.Replace(good, `"most_recent_lts": 25`, `"most_recent_lts": 21`, 1),
		"missing":   strings.Replace(good, `"most_recent_lts": 25,`, "", 1),
	} {
		if body == good {
			t.Fatalf("%s: not changed", name)
		}
		if _, err := parseAvailableReleases([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoad_RefusesAnInconsistentSeriesList(t *testing.T) {
	good := string(readFixture(t, "adoptium/available_releases.json"))
	bad := strings.Replace(good, "        25\n", "        25,\n        26\n", 1)
	sn, site, dir := load2(t, func(s *site) { s.set("/avail", []byte(bad)) })
	if sn.avail.lts[26] || !sn.endOfLife(26) {
		t.Error("the inconsistent list was used")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "available-releases.json")); string(data) != good {
		t.Error("the cached list was replaced")
	}
	if !strings.Contains(site.logs.String(), "most recent LTS") {
		t.Errorf("the log does not say why:\n%s", site.logs.String())
	}
	// The consistent list is still accepted afterwards.
	site.set("/avail", []byte(strings.Replace(bad, `"most_recent_lts": 25`, `"most_recent_lts": 26`, 1)))
	site.advance(21 * time.Hour)
	src := site.newSource(dir)
	sn2, err := src.Load(context.Background())
	if err != nil || !sn2.avail.lts[26] {
		t.Errorf("a consistent list: %v", err)
	}
}
