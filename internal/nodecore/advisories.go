package nodecore

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// blogPostURLBase is where a blog-sourced advisory's article lives.
const blogPostURLBase = "https://nodejs.org/en/blog/vulnerability/"

// npmWordRe selects the advisories about npm itself or a module bundled in
// npm. Trivy reports those separately as packages under node_modules/npm.
var npmWordRe = regexp.MustCompile(`(?i)\bnpm\b`)

// Advisory is one vulnerability that applies to an installed Node.js version.
type Advisory struct {
	VulnID   string
	Title    string
	URL      string
	Severity string // upper case; "UNKNOWN" when the source gave none
	Status   scanner.Status
	FixedVer string // set only for scanner.StatusFixed
}

// Snapshot is one consistent set of the parsed datasets.
type Snapshot struct {
	wg      []wgEntry // ascending id
	blog    []blogAdvisory
	covered map[string][]int // CVE -> indexes into wg of the entries that carry it
	eol     map[int]time.Time

	// Counts for the load log.
	wgSkipped   int
	blogDropped int
}

// wgEntry is one parsed security-wg entry.
type wgEntry struct {
	id         int
	cves       []string
	vulnerable versionRange
	patched    versionRange
	severity   string
	title      string
	url        string
	envs       []string
	published  time.Time // zero when it cannot be determined
}

// blogAdvisory is one advisory section of a security blog post.
type blogAdvisory struct {
	cves     []string
	title    string
	severity string
	slug     string
	posted   time.Time
	affected map[int]bool
	fixed    map[int]version
}

// wgRaw is the subset of a security-wg entry that is read.
type wgRaw struct {
	CVE                  []string `json:"cve"`
	Vulnerable           string   `json:"vulnerable"`
	Patched              string   `json:"patched"`
	Severity             string   `json:"severity"`
	Description          string   `json:"description"`
	Overview             string   `json:"overview"`
	Ref                  string   `json:"ref"`
	AffectedEnvironments []string `json:"affectedEnvironments"`
	PublishDate          string   `json:"publish_date"`
}

// parseSecurityWG parses the security-wg index into entries sorted by id.
// Entries about npm are left out; entries that cannot be parsed are counted
// and logged.
func parseSecurityWG(data []byte, log *slog.Logger) (entries []wgEntry, skipped int, err error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("parse security-wg index: %w", err)
	}
	if len(raw) == 0 {
		return nil, 0, fmt.Errorf("security-wg index has no entries")
	}
	for key, msg := range raw {
		e, npm, err := parseWGEntry(key, msg)
		if err != nil {
			skipped++
			log.Warn("skip unparseable security-wg entry", "id", key, "err", err)
			continue
		}
		if npm {
			continue
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	return entries, skipped, nil
}

// parseWGEntry parses one entry. npm reports an entry about npm, which is
// not a Node.js runtime advisory.
func parseWGEntry(key string, msg json.RawMessage) (e wgEntry, npm bool, err error) {
	id, err := strconv.Atoi(key)
	if err != nil {
		return e, false, fmt.Errorf("non-numeric id")
	}
	var r wgRaw
	if err := json.Unmarshal(msg, &r); err != nil {
		return e, false, err
	}
	if npmWordRe.MatchString(r.Description) || npmWordRe.MatchString(r.Overview) {
		return e, true, nil
	}
	vuln, err := parseRange(r.Vulnerable, false)
	if err != nil {
		return e, false, fmt.Errorf("vulnerable: %w", err)
	}
	patched, err := parseRange(r.Patched, true)
	if err != nil {
		return e, false, fmt.Errorf("patched: %w", err)
	}
	e = wgEntry{
		id:         id,
		cves:       r.CVE,
		vulnerable: vuln,
		patched:    patched,
		severity:   r.Severity,
		title:      r.Description,
		url:        r.Ref,
		envs:       r.AffectedEnvironments,
	}
	if e.title == "" {
		e.title, _, _ = strings.Cut(strings.TrimSpace(r.Overview), "\n")
		e.title = strings.TrimSpace(e.title)
	}
	if r.PublishDate != "" {
		if t, ok := parseDate(r.PublishDate); ok {
			e.published = t
		}
	}
	return e, false, nil
}

// parseDate parses an ISO date or timestamp.
func parseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// releaseRaw is one entry of the nodejs.org release list.
type releaseRaw struct {
	Version string `json:"version"`
	Date    string `json:"date"`
}

// parseReleases parses the release list into version -> release date.
func parseReleases(data []byte) (map[version]time.Time, error) {
	var raw []releaseRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse release list: %w", err)
	}
	out := make(map[version]time.Time, len(raw))
	for _, r := range raw {
		v, ok := parseVersion(strings.TrimPrefix(r.Version, "v"))
		if !ok {
			continue
		}
		if t, ok := parseDate(r.Date); ok {
			out[v] = t
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("release list has no usable releases")
	}
	return out, nil
}

// parseSchedule parses the release schedule into major -> end-of-life date.
func parseSchedule(data []byte) (map[int]time.Time, error) {
	var raw map[string]struct {
		End string `json:"end"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse release schedule: %w", err)
	}
	out := map[int]time.Time{}
	for k, r := range raw {
		n, err := strconv.Atoi(strings.TrimPrefix(k, "v"))
		if err != nil || !strings.HasPrefix(k, "v") {
			continue // "v0.10" and the like predate the major-per-year scheme
		}
		if t, ok := parseDate(r.End); ok {
			out[n] = t
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("release schedule has no usable lines")
	}
	return out, nil
}

// newSnapshot joins the parsed datasets.
func newSnapshot(wg []wgEntry, wgSkipped int, blog []blogAdvisory, blogDropped int, releases map[version]time.Time, eol map[int]time.Time) *Snapshot {
	sn := &Snapshot{
		wg:          wg,
		covered:     map[string][]int{},
		eol:         eol,
		wgSkipped:   wgSkipped,
		blogDropped: blogDropped,
		blog:        blog,
	}
	for i := range sn.wg {
		e := &sn.wg[i]
		for _, c := range e.cves {
			sn.covered[c] = append(sn.covered[c], i)
		}
		if e.published.IsZero() {
			e.published = earliestRelease(e.patched.lowerBounds(), releases)
		}
	}
	return sn
}

// earliestRelease is the earliest release date among versions, or the zero
// time when none is a known release.
func earliestRelease(versions []version, releases map[version]time.Time) time.Time {
	var best time.Time
	for _, v := range versions {
		if t, ok := releases[v]; ok && (best.IsZero() || t.Before(best)) {
			best = t
		}
	}
	return best
}

func (e wgEntry) appliesTo(osName string) bool {
	for _, env := range e.envs {
		env = strings.ToLower(env)
		if env == "all" || env == osName {
			return true
		}
	}
	return false
}

// Match returns the advisories that apply to Node.js version ver on osName
// (empty means linux), ordered by security-wg id and then by blog post. An
// invalid version matches nothing.
func (sn *Snapshot) Match(ver, osName string) []Advisory {
	v, ok := parseVersion(ver)
	if !ok {
		return nil
	}
	osName = strings.ToLower(osName)
	if osName == "" {
		osName = "linux"
	}
	var out []Advisory
	seen := map[string]bool{}     // CVEs an index entry has been tried for
	reported := map[string]bool{} // CVEs in out

	for _, e := range sn.wg {
		if !e.appliesTo(osName) {
			continue
		}
		ids := e.cves
		if len(ids) == 0 {
			ids = []string{"NSWG-CORE-" + strconv.Itoa(e.id)}
		}
		for _, id := range ids {
			if seen[id] {
				continue // the lowest id owns a CVE
			}
			seen[id] = true
			status, fixed, ok := sn.matchWG(e, v)
			if !ok {
				continue
			}
			reported[id] = true
			out = append(out, Advisory{
				VulnID:   id,
				Title:    e.title,
				URL:      e.url,
				Severity: upperSeverity(e.severity),
				Status:   status,
				FixedVer: fixed,
			})
		}
	}

	for _, b := range sn.blog {
		status, fixed, ok := sn.matchBlog(b, v)
		if !ok {
			continue
		}
		for _, id := range b.cves {
			if reported[id] || !sn.blogAdds(b, id, v[0], osName) {
				continue
			}
			reported[id] = true
			out = append(out, Advisory{
				VulnID:   id,
				Title:    b.title,
				URL:      blogPostURLBase + b.slug,
				Severity: upperSeverity(b.severity),
				Status:   status,
				FixedVer: fixed,
			})
		}
	}
	return out
}

// blogAdds reports whether post advisory b may report CVE id for the line
// major on osName. A CVE the index does not carry is the post's to report.
// For a CVE the index carries, the index decides the environments and every
// line it names. A post adds a line it names that the index is silent about
// only when it was published after the index entry and is not the post the
// entry refers to: a release that extends a fix to more lines is announced
// in a new post before the index entry follows. An entry whose publication
// date or post is unknown keeps the CVE to the index.
func (sn *Snapshot) blogAdds(b blogAdvisory, id string, major int, osName string) bool {
	entries, ok := sn.covered[id]
	if !ok {
		return true
	}
	if !b.affected[major] {
		return false
	}
	for _, i := range entries {
		e := sn.wg[i]
		if !e.appliesTo(osName) || e.vulnerable.touchesMajor(major) || e.patched.touchesMajor(major) {
			return false
		}
		if ref := refSlug(e.url); ref == "" || ref == b.slug {
			return false
		}
		if e.published.IsZero() || !b.posted.After(e.published) {
			return false
		}
	}
	return true
}

// refSlug is the slug of the nodejs.org security blog post an index entry
// refers to, or "" when the entry refers to no such post (no reference, or a
// pull request, a report or another site).
func refSlug(ref string) string {
	u, err := url.Parse(strings.TrimSpace(ref))
	if err != nil || (u.Host != "nodejs.org" && u.Host != "www.nodejs.org") {
		return ""
	}
	_, rest, ok := strings.Cut(u.Path, "/blog/vulnerability/")
	if !ok {
		return ""
	}
	slug, _, _ := strings.Cut(rest, "/")
	return slug
}

func upperSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "UNKNOWN"
	}
	return s
}

// matchWG applies a security-wg entry to v. fixed is the version that fixes
// v's line, set only with scanner.StatusFixed.
func (sn *Snapshot) matchWG(e wgEntry, v version) (status scanner.Status, fixed string, ok bool) {
	major := v[0]
	if e.vulnerable.contains(v) && !e.patched.contains(v) {
		var best *version
		for _, lo := range e.patched.lowerBounds() {
			lo := lo
			if lo[0] == major && lo.compare(v) > 0 && (best == nil || lo.compare(*best) < 0) {
				best = &lo
			}
		}
		if best != nil {
			return scanner.StatusFixed, best.String(), true
		}
		return scanner.StatusAffected, "", true
	}
	if !e.vulnerable.touchesMajor(major) && !e.patched.touchesMajor(major) && sn.endedBefore(major, e.published) {
		return scanner.StatusEndOfLife, "", true
	}
	return "", "", false
}

// matchBlog applies a blog advisory to v.
func (sn *Snapshot) matchBlog(b blogAdvisory, v version) (status scanner.Status, fixed string, ok bool) {
	major := v[0]
	f, hasFix := b.fixed[major]
	if b.affected[major] {
		if !hasFix {
			return scanner.StatusAffected, "", true
		}
		if v.compare(f) < 0 {
			return scanner.StatusFixed, f.String(), true
		}
		return "", "", false
	}
	if !hasFix && sn.endedBefore(major, b.posted) {
		return scanner.StatusEndOfLife, "", true
	}
	return "", "", false
}

// endedBefore reports whether the line's end of life is known and earlier
// than the advisory's publication date. An unknown line or an unknown
// publication date never counts: absence of data is not an end of life.
func (sn *Snapshot) endedBefore(major int, published time.Time) bool {
	end, ok := sn.eol[major]
	return ok && !published.IsZero() && end.Before(published)
}
