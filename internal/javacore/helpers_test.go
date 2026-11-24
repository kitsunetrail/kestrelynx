package javacore

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// readFixture returns a recorded response. The advisories are the pages of
// openjdk.org/groups/vulnerability/advisories as fetched on 2026-11-24; the
// Temurin files are the answers of api.adoptium.net of the same day (page 3
// of the release list was a 404 with an empty body).
func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fixtureDates are the advisory dates of the recorded list, ascending.
func fixtureDates(t testing.TB) []string {
	t.Helper()
	dates, err := parseIndex(readFixture(t, "advisories/index.html"))
	if err != nil {
		t.Fatal(err)
	}
	return dates
}

// fixturePages parses every recorded advisory.
func fixturePages(t testing.TB) map[string]*page {
	t.Helper()
	pages := map[string]*page{}
	for _, d := range fixtureDates(t) {
		p, err := parsePage(d, readFixture(t, "advisories/"+d+".html"))
		if err != nil {
			t.Fatalf("parsePage(%s): %v", d, err)
		}
		pages[d] = p
	}
	return pages
}

// fixtureReleases is the recorded Temurin release list, all pages.
func fixtureReleases(t testing.TB) []version {
	t.Helper()
	var all []version
	for i := 0; i < 3; i++ {
		vs, _, err := parseReleasePage(readFixture(t, "adoptium/release_versions_page"+string(rune('0'+i))+".json"))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, vs...)
	}
	return uniqueVersions(all)
}

func fixtureAvailable(t testing.TB) availableReleases {
	t.Helper()
	a, err := parseAvailableReleases(readFixture(t, "adoptium/available_releases.json"))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// fixtureSnapshot is the snapshot of all the recorded data.
func fixtureSnapshot(t testing.TB) *Snapshot {
	t.Helper()
	pages := fixturePages(t)
	var list []*page
	for _, p := range pages {
		list = append(list, p)
	}
	return newSnapshot(list, fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
}

func mustVersion(t testing.TB, s string) version {
	t.Helper()
	v, ok := parseVersion(s)
	if !ok {
		t.Fatalf("parseVersion(%q) failed", s)
	}
	return v
}

// ids are the VulnIDs of advisories, sorted.
func ids(advs []Advisory) []string {
	var out []string
	for _, a := range advs {
		out = append(out, a.VulnID)
	}
	sort.Strings(out)
	return out
}

func find(advs []Advisory, id string) (Advisory, bool) {
	for _, a := range advs {
		if a.VulnID == id {
			return a, true
		}
	}
	return Advisory{}, false
}

// pageIDs are the CVEs of an advisory whose row is marked for the line.
func pageIDs(p *page, line int) []string {
	var out []string
	for _, r := range p.rows {
		if r.marked[line] {
			out = append(out, r.cve)
		}
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hasPrefixAny(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
