package nodecore

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const (
	octoberURL = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
	testNow    = "2026-10-25T12:00:00Z"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var (
	fixtureOnce sync.Once
	fixtureSnap *Snapshot
	fixtureErr  error
)

// fixtureSnapshot builds a snapshot from the recorded datasets: the
// security-wg index, the release list and schedule, and the posts of the
// last 180 days (October, July, June 2026).
func fixtureSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	fixtureOnce.Do(func() {
		log := quietLog()
		wg, skipped, err := parseSecurityWG(readTestdata(t, "core-index.json"), log)
		if err != nil {
			fixtureErr = err
			return
		}
		releases, err := parseReleases(readTestdata(t, "dist-index.json"))
		if err != nil {
			fixtureErr = err
			return
		}
		eol, err := parseSchedule(readTestdata(t, "schedule.json"))
		if err != nil {
			fixtureErr = err
			return
		}
		var blog []blogAdvisory
		dropped := 0
		for _, post := range []string{"october", "july", "june"} {
			slug := post + "-2026-security-releases"
			a, d := parseBlogPost(slug, readTestdata(t, slug+".md"), time.Time{}, log)
			blog = append(blog, a...)
			dropped += d
		}
		fixtureSnap = newSnapshot(wg, skipped, blog, dropped, releases, eol)
	})
	if fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
	return fixtureSnap
}

func byID(advs []Advisory) map[string]Advisory {
	m := map[string]Advisory{}
	for _, a := range advs {
		m[a.VulnID] = a
	}
	return m
}

func TestSecurityWGFixtureParses(t *testing.T) {
	data := readTestdata(t, "core-index.json")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var npm []string
	for id, msg := range raw {
		_, isNPM, err := parseWGEntry(id, msg)
		if err != nil {
			t.Errorf("entry %s does not parse: %v", id, err)
		}
		if isNPM {
			npm = append(npm, id)
		}
	}
	sort.Strings(npm)
	if got, want := strings.Join(npm, ","), "26,78,81,82,87"; got != want {
		t.Errorf("npm-excluded ids = %s, want %s", got, want)
	}

	entries, skipped, err := parseSecurityWG(data, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if got, want := len(entries), len(raw)-len(npm); got != want {
		t.Errorf("entries = %d, want %d", got, want)
	}
}

func TestParseWGEntryUnparseable(t *testing.T) {
	for name, msg := range map[string]string{
		"bad range":   `{"cve":["CVE-1"],"vulnerable":"~1.2.3","patched":"^1.2.4","affectedEnvironments":["all"]}`,
		"bad patched": `{"cve":["CVE-1"],"vulnerable":"1.x","patched":"","affectedEnvironments":["all"]}`,
		"bad json":    `{"cve":"CVE-1"}`,
	} {
		if _, _, err := parseWGEntry("5", json.RawMessage(msg)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, _, err := parseWGEntry("x", json.RawMessage(`{}`)); err == nil {
		t.Error("non-numeric id: want error")
	}

	// One bad entry is counted and skipped; the rest still parse.
	data := `{"1":{"cve":["CVE-1"],"vulnerable":"1.x","patched":"^1.2.4","affectedEnvironments":["all"]},
		"2":{"cve":["CVE-2"],"vulnerable":"wat","patched":"^1.2.4","affectedEnvironments":["all"]}}`
	entries, skipped, err := parseSecurityWG([]byte(data), quietLog())
	if err != nil || len(entries) != 1 || skipped != 1 {
		t.Errorf("entries=%d skipped=%d err=%v, want 1, 1, nil", len(entries), skipped, err)
	}
}

func TestMatchRealData(t *testing.T) {
	sn := fixtureSnapshot(t)
	tests := []struct {
		name    string
		version string
		os      string
		present map[string]string // CVE -> "severity/status/fixed"
		absent  []string
	}{
		{
			name: "22.23.3 gets October fixes", version: "22.23.3",
			present: map[string]string{"CVE-2026-111497": "HIGH/fixed/22.23.4"},
			absent:  []string{"CVE-2026-105483", "CVE-2026-106070", "CVE-2026-58045"},
		},
		{
			name: "24.22.0", version: "24.22.0",
			present: map[string]string{"CVE-2026-105483": "HIGH/fixed/24.22.1", "CVE-2026-111497": "HIGH/fixed/24.22.1"},
		},
		{
			name: "26.12.0 line 26 only advisory", version: "26.12.0",
			present: map[string]string{"CVE-2026-106070": "LOW/fixed/26.12.1"},
		},
		{
			name: "22.23.1 also gets July", version: "22.23.1",
			present: map[string]string{
				"CVE-2026-58045":  "MEDIUM/fixed/22.23.2",
				"CVE-2026-56846":  "HIGH/fixed/22.23.2",
				"CVE-2026-111497": "HIGH/fixed/22.23.4",
			},
		},
		{
			name: "explicit patched range wins over EOL", version: "7.10.1",
			absent: []string{"CVE-2017-1000381"},
			// line 7 ended in 2017; a later advisory is still an EOL finding
			present: map[string]string{"CVE-2026-111497": "HIGH/end_of_life/"},
		},
		{
			name: "EOL line gets October blog CVEs", version: "20.20.0",
			present: map[string]string{
				"CVE-2026-111497": "HIGH/end_of_life/",
				"CVE-2026-105483": "HIGH/end_of_life/",
				"CVE-2026-106070": "LOW/end_of_life/",
			},
		},
		{
			name: "ranges decide over EOL for a line they cover", version: "20.20.0",
			present: map[string]string{"CVE-2026-21637": "HIGH/fixed/20.20.2"},
		},
		{
			name: "patched line is not reported", version: "20.20.2",
			absent: []string{"CVE-2026-21637"},
		},
		{
			name: "win32-only entries are not reported on linux", version: "4.0.0", os: "linux",
			absent: win32OnlyCVEs(t),
		},
		{
			name: "empty os means linux", version: "22.23.3", os: "",
			present: map[string]string{"CVE-2026-111497": "HIGH/fixed/22.23.4"},
		},
		{
			name: "future line gets no EOL rule", version: "28.0.0",
			absent: []string{"CVE-2026-111497", "CVE-2026-58045"},
		},
		{
			name: "unscheduled line gets no EOL rule", version: "3.0.0",
			absent: []string{"CVE-2026-111497"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := byID(sn.Match(tc.version, tc.os))
			for cve, want := range tc.present {
				a, ok := got[cve]
				if !ok {
					t.Errorf("%s missing", cve)
					continue
				}
				if want == "" {
					continue
				}
				if s := a.Severity + "/" + string(a.Status) + "/" + a.FixedVer; s != want {
					t.Errorf("%s = %s, want %s", cve, s, want)
				}
			}
			for _, cve := range tc.absent {
				if _, ok := got[cve]; ok {
					t.Errorf("%s should not be reported", cve)
				}
			}
		})
	}
}

// win32OnlyCVEs lists CVEs that only win32-only entries carry.
func win32OnlyCVEs(t *testing.T) []string {
	t.Helper()
	var raw map[string]wgRaw
	if err := json.Unmarshal(readTestdata(t, "core-index.json"), &raw); err != nil {
		t.Fatal(err)
	}
	other := map[string]bool{}
	for _, e := range raw {
		if !(len(e.AffectedEnvironments) == 1 && e.AffectedEnvironments[0] == "win32") {
			for _, c := range e.CVE {
				other[c] = true
			}
		}
	}
	var out []string
	for _, e := range raw {
		if len(e.AffectedEnvironments) == 1 && e.AffectedEnvironments[0] == "win32" {
			for _, c := range e.CVE {
				if !other[c] {
					out = append(out, c)
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("fixture has no win32-only CVE")
	}
	return out
}

func TestMatchEntryFields(t *testing.T) {
	sn := fixtureSnapshot(t)
	got := byID(sn.Match("22.23.3", "linux"))

	// Blog-sourced (not in security-wg): heading title and the post URL.
	a := got["CVE-2026-111497"]
	if a.URL != octoberURL {
		t.Errorf("URL = %q, want %q", a.URL, octoberURL)
	}
	if want := "Node.js Brotli decoder out-of-bounds write permits remote code execution"; a.Title != want {
		t.Errorf("Title = %q, want %q", a.Title, want)
	}

	// security-wg-sourced: its own description and ref.
	b := byID(sn.Match("22.23.1", "linux"))["CVE-2026-58045"]
	if !strings.HasPrefix(b.Title, "Reachable assertion in node:zlib") || !strings.Contains(b.URL, "july-2026-security-releases") {
		t.Errorf("security-wg advisory = %+v", b)
	}
}

func TestMatchJuneLines(t *testing.T) {
	sn := fixtureSnapshot(t)
	// Fixed in 26.3.1 only for line 26: 26.3.0 is below it.
	if a, ok := byID(sn.Match("26.3.0", "linux"))["CVE-2026-48936"]; !ok || a.FixedVer != "26.3.1" {
		t.Errorf("26.3.0 CVE-2026-48936 = %+v, %v", a, ok)
	}
	for _, v := range []string{"22.22.2", "24.16.0"} {
		if _, ok := byID(sn.Match(v, "linux"))["CVE-2026-48936"]; ok {
			t.Errorf("%s should not get CVE-2026-48936", v)
		}
	}
	for _, v := range []string{"22.22.2", "24.16.0"} {
		if _, ok := byID(sn.Match(v, "linux"))["CVE-2026-48937"]; !ok {
			t.Errorf("%s should get CVE-2026-48937", v)
		}
	}
	if _, ok := byID(sn.Match("26.3.0", "linux"))["CVE-2026-48937"]; ok {
		t.Error("26.3.0 should not get CVE-2026-48937")
	}
}

func TestBlogPostParsing(t *testing.T) {
	log := quietLog()
	t.Run("march uses 20.x and v25.x forms", func(t *testing.T) {
		advs, dropped := parseBlogPost("march-2026-security-releases", readTestdata(t, "march-2026-security-releases.md"), time.Time{}, log)
		if dropped != 0 || len(advs) != 9 {
			t.Fatalf("advs=%d dropped=%d, want 9, 0", len(advs), dropped)
		}
		for _, a := range advs {
			switch a.cves[0] {
			case "CVE-2026-21710":
				if len(a.affected) != 4 || !a.affected[25] || !a.affected[20] {
					t.Errorf("CVE-2026-21710 affected = %v", a.affected)
				}
			case "CVE-2026-21714": // "Node.js 20, 22, 24 and 25"
				if len(a.affected) != 4 || !a.affected[20] || !a.affected[25] {
					t.Errorf("CVE-2026-21714 affected = %v", a.affected)
				}
			case "CVE-2026-21711":
				if len(a.affected) != 1 || !a.affected[25] {
					t.Errorf("CVE-2026-21711 affected = %v", a.affected)
				}
			}
			if a.fixed[20].String() != "20.20.2" {
				t.Errorf("%v fixed[20] = %v", a.cves, a.fixed[20])
			}
		}
	})
	t.Run("june uses Node.js N form and front matter date", func(t *testing.T) {
		advs, _ := parseBlogPost("june-2026-security-releases", readTestdata(t, "june-2026-security-releases.md"), time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), log)
		if len(advs) != 12 {
			t.Fatalf("advs = %d, want 12", len(advs))
		}
		for _, a := range advs {
			if a.posted.Format("2006-01-02") != "2026-06-18" {
				t.Errorf("%v posted = %v", a.cves, a.posted)
			}
		}
	})
}

func TestBlogPostEdgeCases(t *testing.T) {
	fallback := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	post := `## Something (CVE-2026-1) - (HIGH)

No lines named here at all.

## Fix for npm (CVE-2026-2) - (low)

This vulnerability affects Node.js 22.

## Two at once (CVE-2026-3, CVE-2026-4) - (Medium)

Affects 22.x.

## Downloads and release details

- [Node.js v22.1.0](/blog/release/v22.1.0/)
`
	advs, dropped := parseBlogPost("p", []byte(post), fallback, quietLog())
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (the section without affected lines)", dropped)
	}
	if len(advs) != 1 {
		t.Fatalf("advs = %d, want 1 (npm heading is excluded)", len(advs))
	}
	a := advs[0]
	if len(a.cves) != 2 || a.severity != "Medium" || !a.affected[22] || a.fixed[22].String() != "22.1.0" || !a.posted.Equal(fallback) {
		t.Errorf("advisory = %+v", a)
	}

	advs, dropped = parseBlogPost("hashdos", []byte("---\ndate: 2026-03-24\n---\n\n## An analysis article\n\nText.\n"), fallback, quietLog())
	if len(advs) != 0 || dropped != 0 {
		t.Errorf("article without advisory headings: advs=%d dropped=%d", len(advs), dropped)
	}
}

func TestLineMajors(t *testing.T) {
	tests := map[string][]int{
		"This vulnerability affects Node.js **26.x**, **24.x**, and **22.x**.":                                        {22, 24, 26},
		"This vulnerability affects all supported release lines: **Node.js 22**, **Node.js 24**, and **Node.js 26**.": {22, 24, 26},
		"affects HTTP2 users on Node.js 20, 22, 24 and 25.":                                                           {20, 22, 24, 25},
		"affects all Node.js HTTP servers on **20.x, 22.x, 24.x, and v25.x**":                                         {20, 22, 24, 25},
		"affects Node.js 22.23.1 and later":                                                                           nil,
		"affects nothing numbered":                                                                                    nil,
	}
	for line, want := range tests {
		got := lineMajors(line)
		if len(got) != len(want) {
			t.Errorf("%q = %v, want %v", line, got, want)
			continue
		}
		for _, n := range want {
			if !got[n] {
				t.Errorf("%q = %v, want %v", line, got, want)
			}
		}
	}
}

func TestMatchDuplicateCVEUsesLowestID(t *testing.T) {
	data := `{
	  "7": {"cve":["CVE-1"],"vulnerable":"22.x","patched":"^22.23.9","severity":"low","description":"seven","affectedEnvironments":["all"]},
	  "3": {"cve":["CVE-1","CVE-2"],"vulnerable":"22.x","patched":"^22.23.5","severity":"high","description":"three","affectedEnvironments":["all"]},
	  "9": {"cve":[],"vulnerable":"22.x","patched":"^22.23.6","severity":"","description":"","overview":"first line\nsecond","affectedEnvironments":["all"]}
	}`
	wg, _, err := parseSecurityWG([]byte(data), quietLog())
	if err != nil {
		t.Fatal(err)
	}
	sn := newSnapshot(wg, 0, nil, 0, map[version]time.Time{}, map[int]time.Time{})
	got := byID(sn.Match("22.23.0", "linux"))
	if a := got["CVE-1"]; a.Title != "three" || a.FixedVer != "22.23.5" {
		t.Errorf("CVE-1 = %+v, want entry 3", a)
	}
	if _, ok := got["CVE-2"]; !ok {
		t.Error("CVE-2 missing")
	}
	a, ok := got["NSWG-CORE-9"]
	if !ok || a.Severity != "UNKNOWN" || a.Title != "first line" {
		t.Errorf("NSWG-CORE-9 = %+v, %v", a, ok)
	}
}

func TestMatchInvalidVersion(t *testing.T) {
	if got := fixtureSnapshot(t).Match("22.1", "linux"); got != nil {
		t.Errorf("invalid version matched %v", got)
	}
}

// The November 2026 post nests its advisories one level deeper than the
// earlier posts, under a "Patched vulnerabilities" heading.
func TestBlogPostParsingNestedHeadings(t *testing.T) {
	advs, dropped := parseBlogPost("november-2026-security-releases", readTestdata(t, "november-2026-security-releases.md"), time.Time{}, quietLog())
	if dropped != 0 || len(advs) != 16 {
		t.Fatalf("advs=%d dropped=%d, want 16, 0", len(advs), dropped)
	}
	lines := map[string][]int{
		"CVE-2026-123863": {24, 26},
		"CVE-2026-123864": {22, 24, 26},
		"CVE-2026-106071": {22, 24, 26},
	}
	found := 0
	for _, a := range advs {
		if a.posted.Format("2006-01-02") != "2026-11-11" {
			t.Errorf("%v posted = %v", a.cves, a.posted)
		}
		if a.fixed[22].String() != "22.23.5" || a.fixed[24].String() != "24.22.3" || a.fixed[26].String() != "26.13.1" {
			t.Errorf("%v fixed = %v", a.cves, a.fixed)
		}
		want, ok := lines[a.cves[0]]
		if !ok {
			continue
		}
		found++
		if len(a.affected) != len(want) {
			t.Errorf("%v affected = %v, want %v", a.cves, a.affected, want)
		}
		for _, n := range want {
			if !a.affected[n] {
				t.Errorf("%v affected = %v, want %v", a.cves, a.affected, want)
			}
		}
	}
	if found != len(lines) {
		t.Errorf("found %d of the %d checked advisories", found, len(lines))
	}
}

func TestBlogPostSectionBounds(t *testing.T) {
	post := `# Security releases available

## Patched vulnerabilities

### Nested one (CVE-2026-1) - (high)

Text.

#### Impact

- This vulnerability affects all users in active release lines: 22.x, 24.x

### Nested two (CVE-2026-2) - (low)

Nothing about lines before the next section.

## Downloads and release details

- [Node.js v22.1.0](/blog/release/v22.1.0/)
- [Node.js v24.1.0](/blog/release/v24.1.0/)

## Impact

Every supported line is affected: 22.x, 24.x, 26.x.

## Flat (CVE-2026-3) - (medium)

### Details

Affects 26.x.
`
	advs, dropped := parseBlogPost("p", []byte(post), time.Time{}, quietLog())
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1 (the nested section must not read the lines of a later section)", dropped)
	}
	if len(advs) != 2 {
		t.Fatalf("advs = %d, want 2", len(advs))
	}
	nested, flat := advs[0], advs[1]
	if nested.cves[0] != "CVE-2026-1" || len(nested.affected) != 2 || !nested.affected[22] || !nested.affected[24] {
		t.Errorf("nested advisory = %+v (a deeper heading stays inside its section)", nested)
	}
	if flat.cves[0] != "CVE-2026-3" || len(flat.affected) != 1 || !flat.affected[26] {
		t.Errorf("flat advisory = %+v (a deeper heading stays inside its section)", flat)
	}
	for _, a := range advs {
		if a.fixed[22].String() != "22.1.0" || a.fixed[24].String() != "24.1.0" {
			t.Errorf("%v fixed = %v", a.cves, a.fixed)
		}
	}
}

func TestRefSlug(t *testing.T) {
	tests := map[string]string{
		"https://nodejs.org/en/blog/vulnerability/october-2026-security-releases":  "october-2026-security-releases",
		"https://nodejs.org/en/blog/vulnerability/october-2026-security-releases/": "october-2026-security-releases",
		"https://nodejs.org/en/blog/vulnerability/openssl-may-2016/#cve-2016-2107": "openssl-may-2016",
		"https://nodejs.org/en/blog/vulnerability/first?x=1":                       "first",
		" http://www.nodejs.org/blog/vulnerability/first ":                         "first",
		"https://example.org/blog/vulnerability/first":                             "",
		"https://github.com/nodejs/node/pull/8714?next=/blog/vulnerability/first":  "",
		"https://github.com/nodejs/node/issues/7047#/blog/vulnerability/first":     "",
		"https://nodejs.org/en/about?next=/blog/vulnerability/first":               "",
		"https://nodejs.org/en/about#/blog/vulnerability/first":                    "",
		"https://nodejs.org/en/blog/release/v22.1.0":                               "",
		"https://nodejs.org/en/blog/vulnerability/":                                "",
		"":       "",
		"://bad": "",
	}
	for ref, want := range tests {
		if got := refSlug(ref); got != want {
			t.Errorf("refSlug(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestHeadingLevel(t *testing.T) {
	tests := map[string]int{
		"# One":         1,
		"### Three":     3,
		"###### Six":    6,
		"####### Seven": 0,
		"##":            0,
		"##NoSpace":     0,
		"Text # here":   0,
		" ## Indented":  0,
		"":              0,
	}
	for line, want := range tests {
		if got := headingLevel(line); got != want {
			t.Errorf("headingLevel(%q) = %d, want %d", line, got, want)
		}
	}
}

// novemberSnapshot joins the October and November 2026 posts with an index
// that carries CVE-2026-106071 the way it stood after the October release:
// line 26 only, referring to the October post. The November post names lines
// 22 and 24 for the same CVE.
func novemberSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	log := quietLog()
	wg, _, err := parseSecurityWG([]byte(`{
	  "200": {"cve":["CVE-2026-106071"],"vulnerable":"26.x","patched":"^26.12.1","ref":"`+octoberURL+`","severity":"low","description":"Permission Model filesystem over-grant via wildcard radix lookup","affectedEnvironments":["all"]}
	}`), log)
	if err != nil {
		t.Fatal(err)
	}
	releases, err := parseReleases(readTestdata(t, "dist-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	eol, err := parseSchedule(readTestdata(t, "schedule.json"))
	if err != nil {
		t.Fatal(err)
	}
	var blog []blogAdvisory
	for _, post := range []string{"november", "october"} {
		slug := post + "-2026-security-releases"
		a, d := parseBlogPost(slug, readTestdata(t, slug+".md"), time.Time{}, log)
		if d != 0 {
			t.Fatalf("%s dropped %d advisories", slug, d)
		}
		blog = append(blog, a...)
	}
	return newSnapshot(wg, 0, blog, 0, releases, eol)
}

func TestMatchNovemberRelease(t *testing.T) {
	sn := novemberSnapshot(t)
	november := func(advs []Advisory) map[string]Advisory {
		out := map[string]Advisory{}
		for _, a := range advs {
			if strings.HasSuffix(a.URL, "/november-2026-security-releases") {
				out[a.VulnID] = a
			}
		}
		return out
	}

	for _, v := range []string{"22.23.4", "24.22.2", "26.12.0"} {
		count := map[string]int{}
		for _, a := range sn.Match(v, "linux") {
			if count[a.VulnID]++; count[a.VulnID] == 2 {
				t.Errorf("%s reports %s more than once", v, a.VulnID)
			}
		}
	}

	got := november(sn.Match("22.23.4", "linux"))
	if len(got) != 11 {
		t.Errorf("22.23.4 gets %d November advisories, want 11: %v", len(got), got)
	}
	for id, a := range got {
		if a.Status != scanner.StatusFixed || a.FixedVer != "22.23.5" {
			t.Errorf("22.23.4 %s = %+v, want fixed in 22.23.5", id, a)
		}
	}
	if a := got["CVE-2026-123864"]; a.Severity != "HIGH" {
		t.Errorf("CVE-2026-123864 = %+v, want HIGH", a)
	}
	if _, ok := got["CVE-2026-123863"]; ok {
		t.Error("22.23.4 should not get CVE-2026-123863 (lines 24 and 26 only)")
	}
	// The index names line 26 only for this CVE; the later post adds line 22.
	if a, ok := got["CVE-2026-106071"]; !ok || a.Severity != "LOW" {
		t.Errorf("22.23.4 CVE-2026-106071 = %+v, %v", a, ok)
	}

	got = november(sn.Match("24.22.2", "linux"))
	if len(got) != 16 {
		t.Errorf("24.22.2 gets %d November advisories, want 16", len(got))
	}
	for id, a := range got {
		if a.Status != scanner.StatusFixed || a.FixedVer != "24.22.3" {
			t.Errorf("24.22.2 %s = %+v, want fixed in 24.22.3", id, a)
		}
	}

	for _, v := range []string{"22.23.5", "24.22.3", "26.13.1"} {
		if got := november(sn.Match(v, "linux")); len(got) != 0 {
			t.Errorf("%s gets November advisories: %v", v, got)
		}
	}

	// Line 26 stays the index's: fixed in 26.12.1, whatever the post says.
	all := byID(sn.Match("26.12.0", "linux"))
	if a := all["CVE-2026-106071"]; a.FixedVer != "26.12.1" || a.URL != octoberURL {
		t.Errorf("26.12.0 CVE-2026-106071 = %+v, want the index entry", a)
	}
	if _, ok := byID(sn.Match("26.12.1", "linux"))["CVE-2026-106071"]; ok {
		t.Error("26.12.1 should not get CVE-2026-106071: the index names line 26 as patched there")
	}
}

func TestBlogAddsToIndexedCVE(t *testing.T) {
	const laterPost = `## Widened (CVE-2026-1) - (high)

This vulnerability affects 22.x, 24.x, 26.x.

## Downloads and release details

- [Node.js v22.5.0](/blog/release/v22.5.0/)
- [Node.js v24.5.0](/blog/release/v24.5.0/)
- [Node.js v26.5.0](/blog/release/v26.5.0/)
`
	const base = "https://nodejs.org/en/blog/vulnerability/"
	tests := []struct {
		name    string
		entries string
		slug    string
		version string
		os      string
		want    string // "" for no finding, else the fixed version
	}{
		{
			name:    "a later post adds a line the index is silent about",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "22.5.0",
		},
		{
			name:    "the index decides a line it names",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "26.4.0", want: "",
		},
		{
			name:    "the post the entry was written from adds nothing",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `later/","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "a reference to the same post with a fragment adds nothing",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `later/#cve-2026-1","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "a reference to the same post with a query adds nothing",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `later?x=1","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "a reference that is not a post keeps the CVE to the index",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"https://github.com/nodejs/node/pull/8714","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "a reference to a post on another site keeps the CVE to the index",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"https://example.org/blog/vulnerability/first","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "a post older than the entry adds nothing",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","publish_date":"2026-07-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "an entry without a publication date keeps the CVE to the index",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "an entry without a reference keeps the CVE to the index",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "22.4.0", want: "",
		},
		{
			name:    "an entry for another environment keeps the CVE off this one",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","publish_date":"2026-03-01","affectedEnvironments":["win32"]}}`,
			slug:    "later", version: "22.4.0", os: "linux", want: "",
		},
		{
			name:    "the same entry applies on its own environment",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","publish_date":"2026-03-01","affectedEnvironments":["win32"]}}`,
			slug:    "later", version: "22.4.0", os: "win32", want: "22.5.0",
		},
		{
			name: "every entry of the CVE has to leave the line open",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","publish_date":"2026-03-01","affectedEnvironments":["all"]},
			           "2": {"cve":["CVE-2026-1"],"vulnerable":"22.x","patched":"^22.3.0","ref":"` + base + `second","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug: "later", version: "22.4.0", want: "",
		},
		{
			name:    "a line the post does not name is not reported from it",
			entries: `{"1": {"cve":["CVE-2026-1"],"vulnerable":"26.x","patched":"^26.4.0","ref":"` + base + `first","publish_date":"2026-03-01","affectedEnvironments":["all"]}}`,
			slug:    "later", version: "20.19.0", want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wg, _, err := parseSecurityWG([]byte(tt.entries), quietLog())
			if err != nil {
				t.Fatal(err)
			}
			blog, dropped := parseBlogPost(tt.slug, []byte(laterPost), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), quietLog())
			if len(blog) != 1 || dropped != 0 {
				t.Fatalf("blog=%d dropped=%d", len(blog), dropped)
			}
			// Line 20 ended between the entries' publication and the post:
			// the index does not count it as end of life, and without an
			// index entry the post alone would.
			eol := map[int]time.Time{20: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)}
			sn := newSnapshot(wg, 0, blog, 0, map[version]time.Time{}, eol)
			a, ok := byID(sn.Match(tt.version, tt.os))["CVE-2026-1"]
			if tt.want == "" {
				if ok {
					t.Errorf("%s got %+v, want no finding", tt.version, a)
				}
				return
			}
			if !ok || a.Status != scanner.StatusFixed || a.FixedVer != tt.want || a.URL != blogPostURLBase+tt.slug {
				t.Errorf("%s got %+v, %v, want fixed in %s from the post", tt.version, a, ok, tt.want)
			}
		})
	}
}
