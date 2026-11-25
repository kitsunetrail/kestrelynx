package javacore

import (
	"fmt"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Vendor is who built the JDK being matched. Fixes that a distribution made
// differently from OpenJDK are specific to its vendor.
type Vendor string

// VendorTemurin is Eclipse Temurin and the AdoptOpenJDK HotSpot builds it
// continues, whose JAVA_VERSION has the form jdk-21.0.13.1+2 or jdk8u512-b09.
const VendorTemurin Vendor = "temurin"

// temurinFixes lists the CVEs that Temurin fixed in a different version from
// the one the OpenJDK advisory implies, by CVE and line: the first Temurin
// version that is not affected. Temurin carries its own certificate store, so
// it fixed CVE-2026-114820 (the eMudhra roots) in these versions rather than
// in the OpenJDK versions that follow the advisory
// (https://adoptium.net/news/2026/10/temurin-october-2026-emudhra). Only a
// CVE the Adoptium announcement names belongs here.
var temurinFixes = map[string]map[int]string{
	"CVE-2026-114820": {17: "17.0.21", 21: "21.0.13", 25: "25.0.5", 27: "27.0.1.0.2"},
}

// Snapshot is one consistent set of the parsed datasets.
type Snapshot struct {
	pages    []*page // ascending by date
	releases map[int][]version
	avail    availableReleases
	// unchecked are the lines whose advisories cannot be matched.
	unchecked map[int]bool
	// exceptions are temurinFixes, parsed.
	exceptions map[string]map[int]version
	// pageBase is the URL an advisory's date is appended to.
	pageBase string
}

// Advisory is one matched CVE for a version.
type Advisory struct {
	VulnID   string
	Title    string
	URL      string
	Severity string // upper case
	Status   scanner.Status
	FixedVer string // set only with scanner.StatusFixed
}

func newSnapshot(pages []*page, releases []version, avail availableReleases, pageBase string) *Snapshot {
	sn := &Snapshot{
		pages:      append([]*page(nil), pages...),
		releases:   map[int][]version{},
		avail:      avail,
		unchecked:  map[int]bool{},
		exceptions: map[string]map[int]version{},
		pageBase:   pageBase,
	}
	sort.Slice(sn.pages, func(i, j int) bool { return sn.pages[i].date < sn.pages[j].date })
	for _, v := range uniqueVersions(append([]version(nil), releases...)) {
		sn.releases[v.series()] = append(sn.releases[v.series()], v)
	}
	for cve, byLine := range temurinFixes {
		sn.exceptions[cve] = map[int]version{}
		for line, s := range byLine {
			v, ok := parseVersion(s)
			if !ok || v.series() != line {
				panic(fmt.Sprintf("javacore: bad Temurin fix %s %d %q", cve, line, s))
			}
			sn.exceptions[cve][line] = v
		}
	}
	for _, p := range sn.pages {
		// A line the table has a column for but the sentence has no version
		// for cannot be matched against this advisory.
		for _, line := range p.noCeiling {
			sn.unchecked[line] = true
		}
		// A line the sentence has a version for but the table has no column
		// for is read as a line past its end of support (see Match); when
		// the line is still supported nothing can be said about it.
		for line := range p.ceilings {
			if !p.hasColumn(line) && !sn.endOfLife(line) {
				sn.unchecked[line] = true
			}
		}
	}
	return sn
}

// Unchecked reports whether the advisories cannot be matched for a version of
// the given line, so that the absence of findings would say nothing.
func (sn *Snapshot) Unchecked(series int) bool { return sn.unchecked[series] }

// endOfLife reports whether the line is a feature release that is no longer
// supported: it is not an LTS line and a newer feature release is out.
func (sn *Snapshot) endOfLife(series int) bool {
	return !sn.avail.lts[series] && series < sn.avail.latest
}

// fixedAfter is the smallest Temurin release of the line above ceiling.
func (sn *Snapshot) fixedAfter(series int, ceiling version) (version, bool) {
	for _, r := range sn.releases[series] {
		if c, ok := r.compare(ceiling); ok && c > 0 {
			return r, true
		}
	}
	return version{}, false
}

// hit is one advisory's finding of a CVE for a version.
type hit struct {
	p        *page
	r        row
	inferred bool
	fixed    version
	hasFix   bool
	lower    int // lines the inference was made from
	upper    int
	// ceiling is the advisory's affected version of the line, when it has
	// one (an inferred hit may not).
	ceiling    version
	hasCeiling bool
}

// Match returns the CVEs that affect v, each with its status and the version
// that fixes it. Every advisory is judged on its own and the results are then
// merged per CVE: a CVE that any advisory says affects v does, and its fixed
// version is the highest the advisories give. The caller has checked that
// Unchecked is false for v's line.
//
// An advisory with a column for the line says the CVE affects the line when
// the row is marked and v is at most the advisory's affected version. An
// advisory with no column for a line that is past its support is read
// differently: a CVE marked on both the nearest lines below and above the
// line is taken to affect it too, with no fix (end_of_life).
func (sn *Snapshot) Match(vendor Vendor, v version) []Advisory {
	return sn.match(vendor, v).advisories
}

// matchResult is what match finds besides the advisories.
type matchResult struct {
	advisories []Advisory
	// components is the advisory component of each CVE shown.
	components map[string]string
	// suppressed are the CVEs a VendorUnknown JDK is not told about because
	// the vendor exception table splits them by version, with their
	// severity.
	suppressed map[string]string
}

// match is Match with the component of each advisory and the CVEs suppressed
// for a vendor-less JDK. VendorTemurin applies the exception table;
// VendorOracleOpenJDK and VendorUnknown apply the upstream rules, and
// VendorUnknown leaves out the CVEs whose conclusion depends on the vendor.
func (sn *Snapshot) match(vendor Vendor, v version) matchResult {
	line := v.series()
	res := matchResult{components: map[string]string{}, suppressed: map[string]string{}}
	suppressedPage := map[string]*page{}
	suppressedScore := map[string]int{}
	byCVE := map[string][]hit{}
	for _, p := range sn.pages {
		ceiling, hasCeiling := p.ceilings[line]
		if p.hasColumn(line) {
			if !hasCeiling || !v.atMost(ceiling) {
				continue
			}
			for _, r := range p.rows {
				if !r.marked[line] {
					continue
				}
				h := hit{p: p, r: r}
				if fix, ok := sn.fixedAfter(line, ceiling); ok {
					h.fixed, h.hasFix = fix, true
				}
				if exc, ok := sn.exceptions[r.cve][line]; ok {
					switch vendor {
					case VendorTemurin:
						if c, ok := v.compare(exc); ok && c >= 0 {
							continue
						}
						h.fixed, h.hasFix = exc, true
					case VendorUnknown:
						if c, ok := v.compare(exc); ok && c >= 0 {
							if old := suppressedPage[r.cve]; old == nil || p.date > old.date {
								suppressedPage[r.cve], suppressedScore[r.cve] = p, r.score10
							}
							continue
						}
					}
				}
				byCVE[r.cve] = append(byCVE[r.cve], h)
			}
			continue
		}
		if !sn.endOfLife(line) || (hasCeiling && !v.atMost(ceiling)) {
			continue
		}
		lower, upper := 0, 0
		for _, c := range p.columns {
			if c < line {
				lower = c
			}
			if c > line && upper == 0 {
				upper = c
			}
		}
		if lower == 0 || upper == 0 {
			continue
		}
		for _, r := range p.rows {
			if r.marked[lower] && r.marked[upper] {
				byCVE[r.cve] = append(byCVE[r.cve], hit{p: p, r: r, inferred: true, lower: lower, upper: upper, ceiling: ceiling, hasCeiling: hasCeiling})
			}
		}
	}

	var out []Advisory
	for cve, hits := range byCVE {
		adv, component := sn.mergeHits(cve, line, hits)
		out = append(out, adv)
		res.components[cve] = component
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VulnID < out[j].VulnID })
	res.advisories = out
	for cve, score := range suppressedScore {
		// A CVE some other hit still reports is not suppressed.
		if _, shown := byCVE[cve]; !shown {
			res.suppressed[cve] = severityOf(score)
		}
	}
	return res
}

// mergeHits combines the advisories' hits of one CVE. The status and the
// fixed version are decided first: hits read from a column outweigh inferred
// ones, and an inferred hit that covers the version the column hits would
// move to leaves no fix. What is shown is chosen separately, from every hit
// that matched the installed version: the newest advisory gives the link and
// the component, and the highest score among them the severity, so that a
// newer advisory's higher score is not lost.
func (sn *Snapshot) mergeHits(cve string, line int, hits []hit) (Advisory, string) {
	real := hits[:0:0]
	for _, h := range hits {
		if !h.inferred {
			real = append(real, h)
		}
	}
	use := real
	if len(use) == 0 {
		use = hits
	}
	newest := func(hs []hit) hit {
		n := hs[0]
		for _, h := range hs {
			if h.p.date > n.p.date {
				n = h
			}
		}
		return n
	}
	var highest version
	fixed := true
	for _, h := range use {
		if !h.hasFix {
			fixed = false
			continue
		}
		if highest.parts == nil {
			highest = h.fixed
		} else if c, ok := h.fixed.compare(highest); ok && c > 0 {
			highest = h.fixed
		}
	}
	// decider is the inferred hit the status came from, if it did.
	var decider *hit
	if len(real) == 0 {
		d := newest(hits)
		decider = &d
	} else if fixed && len(real) < len(hits) {
		var over []hit
		for _, h := range hits {
			if !h.inferred {
				continue
			}
			if !h.hasCeiling {
				over = append(over, h)
			} else if c, ok := highest.compare(h.ceiling); ok && c <= 0 {
				over = append(over, h)
			}
		}
		if len(over) > 0 {
			d := newest(over)
			decider, fixed = &d, false
		}
	}

	// The newest advisory that matched is the latest assessment, a corrected
	// score included.
	rep := newest(hits)
	adv := Advisory{
		VulnID:   cve,
		Title:    "OpenJDK: " + rep.r.component,
		URL:      sn.pageBase + rep.p.date,
		Severity: severityOf(rep.r.score10),
	}
	switch {
	case fixed:
		adv.Status, adv.FixedVer = scanner.StatusFixed, highest.String()
	case decider != nil:
		adv.Status = scanner.StatusEndOfLife
		adv.Title += fmt.Sprintf(" (inferred for end-of-life Java %d from %d and %d)", line, decider.lower, decider.upper)
	case sn.endOfLife(line):
		// No release of a line whose support has ended will fix it.
		adv.Status = scanner.StatusEndOfLife
	default:
		adv.Status = scanner.StatusAffected
	}
	return adv, rep.r.component
}

// severityOf maps a CVSS base score (times ten) to a severity. A score of 0
// is UNKNOWN, as NONE is not used for CVEs.
func severityOf(score10 int) string {
	switch {
	case score10 >= 90:
		return "CRITICAL"
	case score10 >= 70:
		return "HIGH"
	case score10 >= 40:
		return "MEDIUM"
	case score10 >= 1:
		return "LOW"
	}
	return "UNKNOWN"
}
