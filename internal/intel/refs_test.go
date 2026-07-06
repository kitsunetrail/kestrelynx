package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// hnFixture mirrors the real Algolia response shape (verified live 2026-07-07):
// hits carry points and _highlightResult with matchLevel per attribute. The
// high-score hit matches the query fully via its URL (like the real HAProxy
// story for CVE-2023-44487); the fuzzy hit is a *different* CVE that Algolia's
// typo tolerance returned (like CVE-2024-28123 for a CVE-2024-28182 query).
const hnFixture = `{
  "hits": [
    {
      "title": "Netlify successfully mitigates the CVE",
      "points": 2, "num_comments": 0, "objectID": "111",
      "_highlightResult": {"title": {"matchLevel": "full"}, "url": {"matchLevel": "full"}}
    },
    {
      "title": "HAProxy is not affected by the HTTP/2 Rapid Reset Attack",
      "points": 166, "num_comments": 33, "objectID": "37837043",
      "_highlightResult": {"title": {"matchLevel": "none"}, "url": {"matchLevel": "full"}}
    },
    {
      "title": "Some other CVE that fuzzy-matched",
      "points": 500, "num_comments": 90, "objectID": "999",
      "_highlightResult": {"title": {"matchLevel": "partial"}, "url": {"matchLevel": "partial"}}
    }
  ]
}`

func newHNSource(t *testing.T, now *time.Time, body func() (string, int)) (*Source, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		b, code := body()
		w.WriteHeader(code)
		w.Write([]byte(b))
	}))
	t.Cleanup(srv.Close)
	return &Source{
		CacheDir:    t.TempDir(),
		HNSearchURL: srv.URL,
		Client:      srv.Client(),
		Now:         func() time.Time { return *now },
	}, &hits
}

func TestDiscussions_PicksBestExactMatchAboveThreshold(t *testing.T) {
	now := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	s, _ := newHNSource(t, &now, func() (string, int) { return hnFixture, http.StatusOK })

	got := s.Discussions(context.Background(), []string{"CVE-2023-44487"})
	d, ok := got["CVE-2023-44487"]
	if !ok {
		t.Fatal("expected a discussion")
	}
	if d.Points != 166 || d.URL != "https://news.ycombinator.com/item?id=37837043" {
		t.Errorf("picked %+v, want the 166-point full-match story", d)
	}
	// The 500-point hit was a fuzzy match (another CVE): must never be linked.
	// The 2-point full match is below the substance threshold.
}

func TestDiscussions_CachesResultsAndMisses(t *testing.T) {
	now := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	s, hits := newHNSource(t, &now, func() (string, int) { return `{"hits": []}`, http.StatusOK })

	if got := s.Discussions(context.Background(), []string{"CVE-QUIET"}); len(got) != 0 {
		t.Fatalf("want no discussion, got %v", got)
	}
	// Same day: the miss is cached, no second query.
	s.Discussions(context.Background(), []string{"CVE-QUIET"})
	if *hits != 1 {
		t.Errorf("queries = %d, want 1 (miss cached)", *hits)
	}
	// Next day the negative result expires: discussions can appear late.
	now = now.Add(25 * time.Hour)
	s.Discussions(context.Background(), []string{"CVE-QUIET"})
	if *hits != 2 {
		t.Errorf("queries = %d, want 2 (miss re-checked after TTL)", *hits)
	}
}

func TestDiscussions_FailureFallsBackToCache(t *testing.T) {
	now := time.Date(2026, 7, 7, 9, 0, 0, 0, time.UTC)
	ok := true
	s, _ := newHNSource(t, &now, func() (string, int) {
		if ok {
			return hnFixture, http.StatusOK
		}
		return "", http.StatusServiceUnavailable
	})

	if got := s.Discussions(context.Background(), []string{"CVE-2023-44487"}); len(got) != 1 {
		t.Fatalf("first lookup failed: %v", got)
	}
	ok = false
	now = now.Add(48 * time.Hour) // cache expired AND service down
	got := s.Discussions(context.Background(), []string{"CVE-2023-44487"})
	if d := got["CVE-2023-44487"]; d.Points != 166 {
		t.Errorf("want stale cached discussion on failure, got %+v", got)
	}
}

func TestNoteURL(t *testing.T) {
	cases := []struct{ notes, want string }{
		// Real KEV shapes (verified 2026-07-06).
		{"https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314; https://nvd.nist.gov/vuln/detail/CVE-2024-23897", "https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314"},
		{"https://security.paloaltonetworks.com/CVE-2024-3400 ;   https://nvd.nist.gov/vuln/detail/CVE-2024-3400", "https://security.paloaltonetworks.com/CVE-2024-3400"},
		{"For more information, please see: CISA: https://www.cisa.gov/news-events/alerts/2023/10/10/x ; https://nvd.nist.gov/vuln/detail/CVE-2023-44487", "https://www.cisa.gov/news-events/alerts/2023/10/10/x"},
		{"https://nvd.nist.gov/vuln/detail/CVE-2020-0001", ""}, // NVD only: nothing worth adding
		{"", ""},
	}
	for _, c := range cases {
		if got := noteURL(c.notes); got != c.want {
			t.Errorf("noteURL(%q) = %q, want %q", c.notes, got, c.want)
		}
	}
}

func TestLookupCarriesKEVNoteURL(t *testing.T) {
	feeds := newTestFeeds(t)
	now := time.Date(2026, 7, 6, 9, 0, 0, 0, time.UTC)
	s := newSource(t, feeds, &now)

	got, _, err := s.Lookup(context.Background(), []string{"CVE-2026-1111"})
	if err != nil {
		t.Fatal(err)
	}
	if got["CVE-2026-1111"].KEVNoteURL != "https://vendor.test/advisory" {
		t.Errorf("KEVNoteURL = %q, want the vendor advisory from the notes", got["CVE-2026-1111"].KEVNoteURL)
	}
}
