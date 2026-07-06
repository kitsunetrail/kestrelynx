// Reference-link collection (Phase 1.5, docs/TRIAGE_SPEC.md §8): attach the
// URLs a responder would search for anyway — the vendor advisory from the KEV
// notes and the Hacker News discussion — to act-now findings. No LLM: links
// are verifiable facts, summaries are a later, paid layer.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultHNSearchURL is the Algolia-powered Hacker News search API (free, no
// key, anonymous).
const DefaultHNSearchURL = "https://hn.algolia.com/api/v1/search"

const (
	// minHNPoints is the score below which a story is not worth linking: the
	// promise is "the discussion", not "someone posted the CVE number".
	minHNPoints = 20
	// refsTTL is how long a discussion lookup is trusted before re-checking.
	// Discussions often appear a day or two after a CVE first goes act-now, so
	// a negative result must expire quickly.
	refsTTL = 24 * time.Hour
	// refsPrune drops cache entries not looked up in this long (the CVE left
	// the act-now bucket), keeping refs.json from growing forever.
	refsPrune = 30 * 24 * time.Hour
	refsFile  = "refs.json"
)

// Discussion is one community discussion of a CVE.
type Discussion struct {
	Title    string `json:"title"`
	URL      string `json:"url"`
	Points   int    `json:"points"`
	Comments int    `json:"comments"`
}

// refsCache is the on-disk memory of discussion lookups, keyed by CVE ID.
// Misses are cached too (Found=false) so a quiet CVE costs one query per TTL,
// not one per heartbeat.
type refsCache struct {
	Entries map[string]refEntry `json:"entries"`
}

type refEntry struct {
	CheckedAt  time.Time  `json:"checked_at"`
	Found      bool       `json:"found"`
	Discussion Discussion `json:"discussion,omitempty"`
}

// Discussions returns the best HN discussion per CVE ID, for the IDs that have
// one. Results are cached in refs.json for refsTTL. Lookup failures fall back
// to the cached value regardless of age and are logged, never fatal.
//
// Privacy note (ADR-007 exception): unlike the bulk feeds, this sends the
// given CVE IDs as search queries to an external service. Callers restrict it
// to act-now CVEs, and config can turn it off entirely.
func (s *Source) Discussions(ctx context.Context, ids []string) map[string]Discussion {
	cache := s.loadRefs()
	now := s.now()
	out := map[string]Discussion{}
	dirty := false

	for _, id := range ids {
		e, ok := cache.Entries[id]
		if ok && now.Sub(e.CheckedAt) < refsTTL {
			if e.Found {
				out[id] = e.Discussion
			}
			continue
		}
		d, found, err := s.searchHN(ctx, id)
		if err != nil {
			s.log().Warn("hn discussion lookup failed", "cve", id, "err", err)
			if ok && e.Found { // stale beats absent
				out[id] = e.Discussion
			}
			continue
		}
		cache.Entries[id] = refEntry{CheckedAt: now, Found: found, Discussion: d}
		dirty = true
		if found {
			out[id] = d
		}
	}

	if dirty {
		for id, e := range cache.Entries {
			if now.Sub(e.CheckedAt) > refsPrune {
				delete(cache.Entries, id)
			}
		}
		s.saveRefs(cache)
	}
	return out
}

// algoliaResponse is the subset of the HN search response StackWatch reads.
type algoliaResponse struct {
	Hits []struct {
		Title       string                     `json:"title"`
		Points      int                        `json:"points"`
		NumComments int                        `json:"num_comments"`
		ObjectID    string                     `json:"objectID"`
		Highlight   map[string]json.RawMessage `json:"_highlightResult"`
	} `json:"hits"`
}

// searchHN queries Algolia for stories mentioning the CVE and picks the
// highest-scoring hit that (a) matched every query token exactly somewhere
// (matchLevel "full" — Algolia's typo tolerance would otherwise return
// neighboring CVE numbers) and (b) clears minHNPoints.
func (s *Source) searchHN(ctx context.Context, cve string) (Discussion, bool, error) {
	q := url.Values{"query": {cve}, "tags": {"story"}, "hitsPerPage": {"10"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.hnSearchURL()+"?"+q.Encode(), nil)
	if err != nil {
		return Discussion{}, false, err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return Discussion{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Discussion{}, false, fmt.Errorf("hn search: unexpected status %s", resp.Status)
	}
	var r algoliaResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Discussion{}, false, fmt.Errorf("parse hn search: %w", err)
	}

	best := Discussion{}
	found := false
	for _, h := range r.Hits {
		if h.Points < minHNPoints || !fullMatch(h.Highlight) {
			continue
		}
		if !found || h.Points > best.Points {
			best = Discussion{
				Title:    h.Title,
				URL:      "https://news.ycombinator.com/item?id=" + h.ObjectID,
				Points:   h.Points,
				Comments: h.NumComments,
			}
			found = true
		}
	}
	return best, found, nil
}

// fullMatch reports whether any highlighted attribute matched the whole query
// (matchLevel "full"). Attribute values that aren't single objects (arrays
// etc.) are skipped.
func fullMatch(highlight map[string]json.RawMessage) bool {
	for _, raw := range highlight {
		var h struct {
			MatchLevel string `json:"matchLevel"`
		}
		if json.Unmarshal(raw, &h) == nil && h.MatchLevel == "full" {
			return true
		}
	}
	return false
}

// noteURL extracts the vendor-advisory link from a KEV notes field. The real
// data is "vendor advisory URL; NVD URL" or prose ending in a URL, so: first
// http(s) token that isn't the NVD mirror of the entry itself.
func noteURL(notes string) string {
	for _, tok := range strings.Fields(notes) {
		tok = strings.Trim(tok, ";,")
		if !strings.HasPrefix(tok, "http://") && !strings.HasPrefix(tok, "https://") {
			continue
		}
		if strings.Contains(tok, "nvd.nist.gov") {
			continue
		}
		return tok
	}
	return ""
}

func (s *Source) loadRefs() refsCache {
	c := refsCache{Entries: map[string]refEntry{}}
	data, err := os.ReadFile(filepath.Join(s.CacheDir, refsFile))
	if err != nil {
		return c
	}
	_ = json.Unmarshal(data, &c) // corrupt cache = re-query, not an error
	if c.Entries == nil {
		c.Entries = map[string]refEntry{}
	}
	return c
}

func (s *Source) saveRefs(c refsCache) {
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	if err := os.MkdirAll(s.CacheDir, 0o755); err != nil {
		return
	}
	path := filepath.Join(s.CacheDir, refsFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		s.log().Warn("write refs cache failed", "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.log().Warn("write refs cache failed", "err", err)
	}
}

func (s *Source) hnSearchURL() string {
	if s.HNSearchURL != "" {
		return s.HNSearchURL
	}
	return DefaultHNSearchURL
}
