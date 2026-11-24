package javacore

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func match(t *testing.T, sn *Snapshot, ver string) []Advisory {
	t.Helper()
	return sn.Match(VendorTemurin, mustVersion(t, ver))
}

// november are the CVEs of the 2026-11-17 advisory.
var november = []string{
	"CVE-2026-114938", "CVE-2026-114939", "CVE-2026-114940", "CVE-2026-114941", "CVE-2026-114942",
	"CVE-2026-114943", "CVE-2026-114944", "CVE-2026-114945", "CVE-2026-114946", "CVE-2026-114947",
}

func TestMatch_NoLineIsUnchecked(t *testing.T) {
	sn := fixtureSnapshot(t)
	if len(sn.unchecked) != 0 {
		t.Errorf("unchecked lines = %v", sn.unchecked)
	}
	for _, line := range []int{8, 11, 17, 21, 25, 26, 27, 16, 9} {
		if sn.Unchecked(line) {
			t.Errorf("line %d is unchecked", line)
		}
	}
}

func TestMatch_CurrentReleaseHasNoNovemberCVEs(t *testing.T) {
	sn := fixtureSnapshot(t)
	if got := match(t, sn, "21.0.13.1"); len(got) != 0 {
		t.Errorf("21.0.13.1 matched %v", ids(got))
	}
}

func TestMatch_OlderMaven(t *testing.T) {
	// maven:3.9-eclipse-temurin-21 at 21.0.12.1.
	sn := fixtureSnapshot(t)
	advs := match(t, sn, "21.0.12.1")
	if len(advs) == 0 {
		t.Fatal("21.0.12.1 matched nothing")
	}
	for _, a := range advs {
		if a.Status != scanner.StatusFixed {
			t.Errorf("%s status = %s", a.VulnID, a.Status)
		}
	}
	// 2026-10-20 CVEs (ceiling 21.0.12.1) are fixed by 21.0.13, and those of
	// 2026-10-21 and later by 21.0.13.1; the group is aligned later.
	if a, ok := find(advs, "CVE-2026-91403"); !ok || a.FixedVer != "21.0.13.1" {
		t.Errorf("CVE-2026-91403 = %+v, %v", a, ok)
	}
	for _, id := range november {
		if id == "CVE-2026-114947" { // line 21 is not marked
			continue
		}
		if a, ok := find(advs, id); !ok || a.FixedVer != "21.0.13.1" {
			t.Errorf("%s = %+v, %v", id, a, ok)
		}
	}
	p := fixturePages(t)["2026-10-20"]
	for _, id := range pageIDs(p, 21) {
		a, ok := find(advs, id)
		if !ok {
			t.Errorf("%s (2026-10-20, line 21) not matched", id)
			continue
		}
		if a.FixedVer != "21.0.13" {
			t.Errorf("%s fixed version = %s, want 21.0.13", id, a.FixedVer)
		}
	}
}

func TestMatch_TemurinCertificateException(t *testing.T) {
	sn := fixtureSnapshot(t)

	// 21.0.13 and 27.0.1.0.2 are the first Temurin versions without
	// CVE-2026-114820, though the advisory lists them as affected; the
	// 2026-11-17 CVEs still affect them.
	for _, ver := range []string{"21.0.13", "27.0.1.0.2"} {
		advs := match(t, sn, ver)
		if _, ok := find(advs, "CVE-2026-114820"); ok {
			t.Errorf("%s matched CVE-2026-114820", ver)
		}
		for _, id := range november {
			if id == "CVE-2026-114947" && ver == "21.0.13" {
				continue
			}
			if _, ok := find(advs, id); !ok {
				t.Errorf("%s did not match %s", ver, id)
			}
		}
	}

	// 27 is before the Temurin fix: CVE-2026-114820 is fixed by 27.0.1.0.2
	// (Match gives each CVE its own fix, before the group is aligned).
	advs := match(t, sn, "27")
	a, ok := find(advs, "CVE-2026-114820")
	if !ok {
		t.Fatal("27 did not match CVE-2026-114820")
	}
	if a.Status != scanner.StatusFixed || a.FixedVer != "27.0.1.0.2" {
		t.Errorf("CVE-2026-114820 = %+v, want fixed by 27.0.1.0.2", a)
	}
	if b, _ := find(advs, "CVE-2026-114938"); b.FixedVer != "27.0.1.1" {
		t.Errorf("CVE-2026-114938 fixed by %s, want 27.0.1.1", b.FixedVer)
	}

	// For the other lines the exception names, and a vendor with no
	// exception, the upstream version decides.
	for line, fix := range map[string]string{"17.0.20": "17.0.21", "21.0.12": "21.0.13", "25.0.4": "25.0.5"} {
		a, ok := find(match(t, sn, line), "CVE-2026-114820")
		if !ok || a.FixedVer != fix {
			t.Errorf("%s: CVE-2026-114820 = %+v, %v; want fixed by %s", line, a, ok, fix)
		}
	}
	// Another vendor is judged by the advisory: it is affected up to the
	// advisory's version and the fix is the next published release.
	other, ok := find(sn.Match(Vendor("other"), mustVersion(t, "21.0.13")), "CVE-2026-114820")
	if !ok {
		t.Error("a vendor without an exception was not matched by the advisory's version")
	} else if other.FixedVer == "21.0.13" {
		t.Errorf("fixed version = %s", other.FixedVer)
	}
	// 8 and 11 have no exception.
	if _, ok := find(match(t, sn, "8u512"), "CVE-2026-114820"); ok {
		if !contains(pageIDs(fixturePages(t)["2026-10-24"], 8), "CVE-2026-114820") {
			t.Error("8u512 matched CVE-2026-114820 that the advisory does not mark for line 8")
		}
	}
}

func TestMatch_ExceptionsAreCoveredByTheAdvisory(t *testing.T) {
	// Every exception names a CVE and lines the advisories list, and its
	// version is one Temurin published.
	sn := fixtureSnapshot(t)
	for cve, lines := range sn.exceptions {
		for line, v := range lines {
			marked := false
			for _, p := range sn.pages {
				if contains(pageIDs(p, line), cve) {
					marked = true
				}
			}
			if !marked {
				t.Errorf("%s: no advisory marks line %d", cve, line)
			}
			published := false
			for _, r := range sn.releases[line] {
				if c, _ := r.compare(v); c == 0 {
					published = true
				}
			}
			if !published {
				t.Errorf("%s: %s is not in the release list", cve, v)
			}
		}
	}
}

func TestMatch_Eight(t *testing.T) {
	sn := fixtureSnapshot(t)
	advs := match(t, sn, "8u512")
	// Five of the ten CVEs of 2026-11-17 affect line 8; nothing else does at
	// 8u512 (the others' versions are lower).
	want := []string{"CVE-2026-114939", "CVE-2026-114940", "CVE-2026-114943", "CVE-2026-114944", "CVE-2026-114946"}
	if got := ids(advs); !reflect.DeepEqual(got, want) {
		t.Errorf("8u512 matched %v, want %v", got, want)
	}
	for _, a := range advs {
		if a.Status != scanner.StatusFixed || a.FixedVer != "8u514" {
			t.Errorf("%s = %s %s, want fixed by 8u514", a.VulnID, a.Status, a.FixedVer)
		}
	}
	if got := match(t, sn, "8u514"); len(got) != 0 {
		t.Errorf("8u514 matched %v", ids(got))
	}
}

func TestMatch_OldVersionsAndDuplicateCVE(t *testing.T) {
	// CVE-2020-14803 is in 2020-10 (marked for every line) and 2021-01 (for
	// none): the old advisory still applies to the versions it covers.
	sn := fixtureSnapshot(t)
	for _, ver := range []string{"8u262", "11.0.8"} {
		a, ok := find(match(t, sn, ver), "CVE-2020-14803")
		if !ok {
			t.Errorf("%s did not match CVE-2020-14803", ver)
			continue
		}
		if a.Status != scanner.StatusFixed {
			t.Errorf("%s: CVE-2020-14803 = %+v", ver, a)
		}
		if !strings.HasSuffix(a.URL, "/2020-10-20") {
			t.Errorf("%s: CVE-2020-14803 links %s, want the 2020-10-20 advisory", ver, a.URL)
		}
	}
	// A version above the 2020-10 affected versions is not hit.
	if _, ok := find(match(t, sn, "8u272"), "CVE-2020-14803"); ok {
		t.Error("8u272 matched CVE-2020-14803")
	}
	if _, ok := find(match(t, sn, "11.0.9"), "CVE-2020-14803"); ok {
		t.Error("11.0.9 matched CVE-2020-14803")
	}
}

func TestMatch_EndOfLifeLines(t *testing.T) {
	sn := fixtureSnapshot(t)
	for _, line := range []int{16, 26, 9, 18} {
		if !sn.endOfLife(line) {
			t.Errorf("line %d is not end-of-life", line)
		}
	}
	for _, line := range []int{8, 11, 17, 21, 25, 27, 28} {
		if sn.endOfLife(line) {
			t.Errorf("line %d is end-of-life", line)
		}
	}

	// 26: after 2026-10-20 (no column), only CVEs marked on both 25 and 27
	// are inferred; CVE-2026-91417, marked for 8 only, is not.
	pages := fixturePages(t)
	for _, d := range []string{"2026-10-20", "2026-10-21", "2026-10-24", "2026-11-17"} {
		p := pages[d]
		if p.hasColumn(26) {
			t.Fatalf("%s has a column for 26", d)
		}
	}
	// A version above the last advisory that has a 26 column, so only the
	// inferences apply to it.
	advs := match(t, sn, "26.0.2.1")
	var inferred []Advisory
	for _, a := range advs {
		if a.Status == scanner.StatusEndOfLife {
			inferred = append(inferred, a)
		}
	}
	if len(inferred) == 0 {
		t.Fatal("no inferred end-of-life CVEs for 26.0.2.1")
	}
	if _, ok := find(advs, "CVE-2026-91417"); ok {
		t.Error("26 matched CVE-2026-91417")
	}
	want := map[string]bool{}
	for _, d := range []string{"2026-10-20", "2026-10-21", "2026-10-24", "2026-11-17"} {
		p := pages[d]
		for _, r := range p.rows {
			if r.marked[25] && r.marked[27] {
				want[r.cve] = true
			}
		}
	}
	for _, a := range inferred {
		if !want[a.VulnID] {
			t.Errorf("%s was inferred for 26 without marks on 25 and 27", a.VulnID)
		}
		if a.FixedVer != "" {
			t.Errorf("%s has a fixed version %q", a.VulnID, a.FixedVer)
		}
		if !strings.Contains(a.Title, "(inferred for end-of-life Java 26 from 25 and 27)") || !strings.HasPrefix(a.Title, "OpenJDK: ") {
			t.Errorf("%s title = %q", a.VulnID, a.Title)
		}
	}
	if len(inferred) != len(want) {
		t.Errorf("inferred %d CVEs, want %d", len(inferred), len(want))
	}
	// CVE-2026-114947 is marked for 25 and 27 on 2026-11-17.
	if _, ok := find(advs, "CVE-2026-114947"); !ok {
		t.Error("26 did not match CVE-2026-114947")
	}
}

func TestMatch_EndOfLifeLineWithAffectedVersionAndNoColumn(t *testing.T) {
	// 2021-10-19 states 16.0.2 for line 16 but has no column for it: the
	// CVEs marked on both 15 and 17 are inferred, for 16.0.2 and below only.
	sn := fixtureSnapshot(t)
	p := fixturePages(t)["2021-10-19"]
	want := map[string]bool{}
	for _, r := range p.rows {
		if r.marked[15] && r.marked[17] {
			want[r.cve] = true
		}
	}
	if len(want) != 8 {
		t.Fatalf("2021-10-19 CVEs marked for 15 and 17 = %d, want 8", len(want))
	}
	advs := match(t, sn, "16.0.2")
	got := 0
	for _, a := range advs {
		if want[a.VulnID] {
			got++
			if a.Status != scanner.StatusEndOfLife || a.FixedVer != "" ||
				!strings.HasSuffix(a.Title, "(inferred for end-of-life Java 16 from 15 and 17)") {
				t.Errorf("%s = %+v", a.VulnID, a)
			}
		}
	}
	if got != 8 {
		t.Errorf("16.0.2 matched %d of the 8 CVEs", got)
	}
	// The 2021-10-19 inference stops at the stated version.
	for _, a := range match(t, sn, "16.0.3") {
		if want[a.VulnID] && strings.HasSuffix(a.URL, "/2021-10-19") {
			t.Errorf("16.0.3 matched %s from 2021-10-19", a.VulnID)
		}
	}
	// Line 16 has a column on 2021-04-20 and 2021-07-20 and is judged there
	// by the ordinary rule.
	advs = match(t, sn, "16")
	if len(advs) == 0 {
		t.Error("16 matched nothing")
	}
}

func TestMatch_LTSLinesAreNotInferred(t *testing.T) {
	// An advisory without a column for an LTS line says nothing about it.
	sn := fixtureSnapshot(t)
	p := &page{
		date: "2026-12-15", columns: []int{8, 21}, order: []int{8, 21},
		ceilings: map[int]version{8: mustVersion(t, "8u520"), 21: mustVersion(t, "21.0.14")},
		rows:     []row{{cve: "CVE-2026-1", component: "x", score10: 50, marked: map[int]bool{8: true, 21: true}}},
	}
	sn2 := newSnapshot(append(sn.pages, p), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	if _, ok := find(sn2.Match(VendorTemurin, mustVersion(t, "11.0.20")), "CVE-2026-1"); ok {
		t.Error("an LTS line without a column was inferred")
	}
	// Line 9 is not LTS and is below the latest: it is inferred from the
	// nearest lines of the advisory, here 8 and 21.
	a, ok := find(sn2.Match(VendorTemurin, mustVersion(t, "9.0.4")), "CVE-2026-1")
	if !ok || a.Status != scanner.StatusEndOfLife || !strings.HasSuffix(a.Title, "(inferred for end-of-life Java 9 from 8 and 21)") {
		t.Errorf("line 9 = %+v, %v", a, ok)
	}
	// With no line above, nothing is inferred.
	p2 := &page{
		date: "2026-12-16", columns: []int{8}, order: []int{8},
		ceilings: map[int]version{8: mustVersion(t, "8u520")},
		rows:     []row{{cve: "CVE-2026-3", component: "x", score10: 50, marked: map[int]bool{8: true}}},
	}
	sn3 := newSnapshot(append(sn.pages, p2), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	if _, ok := find(sn3.Match(VendorTemurin, mustVersion(t, "9.0.4")), "CVE-2026-3"); ok {
		t.Error("inferred for line 9 with no line above")
	}
}

func TestMatch_UncheckedLines(t *testing.T) {
	sn := fixtureSnapshot(t)
	mk := func(columns []int, ceilings map[int]string) *page {
		p := &page{date: "2026-12-15", columns: columns, order: columns, ceilings: map[int]version{}}
		for l, s := range ceilings {
			p.ceilings[l] = mustVersion(t, s)
		}
		for _, c := range columns {
			if _, ok := p.ceilings[c]; !ok {
				p.noCeiling = append(p.noCeiling, c)
			}
		}
		p.rows = []row{{cve: "CVE-2026-2", component: "x", score10: 50, marked: map[int]bool{}}}
		return p
	}
	build := func(p *page) *Snapshot {
		return newSnapshot(append(append([]*page(nil), sn.pages...), p), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	}

	// A column with no version in the sentence: that line only.
	s1 := build(mk([]int{11, 21}, map[int]string{11: "11.0.34"}))
	if !s1.Unchecked(21) || s1.Unchecked(11) || s1.Unchecked(17) {
		t.Errorf("unchecked = %v, want only 21", s1.unchecked)
	}
	// A supported line with a version and no column: unchecked.
	s2 := build(mk([]int{11}, map[int]string{11: "11.0.34", 21: "21.0.14"}))
	if !s2.Unchecked(21) || len(s2.unchecked) != 1 {
		t.Errorf("unchecked = %v, want only 21", s2.unchecked)
	}
	// The latest line counts as supported; a line that is past its end does
	// not (it is read by inference).
	s3 := build(mk([]int{11}, map[int]string{11: "11.0.34", 27: "27.0.2"}))
	if !s3.Unchecked(27) {
		t.Errorf("unchecked = %v, want 27", s3.unchecked)
	}
	s4 := build(mk([]int{11}, map[int]string{11: "11.0.34", 26: "26.0.3"}))
	if s4.Unchecked(26) || len(s4.unchecked) != 0 {
		t.Errorf("unchecked = %v, want none", s4.unchecked)
	}
}

// A CVE marked for an end-of-life line with no later release of that line is
// end_of_life, not affected: no fix will come.
func TestMatch_EndOfLifeLineWithoutFix(t *testing.T) {
	var releases []version
	for _, v := range fixtureReleases(t) {
		if v.String() != "26.0.2.1" {
			releases = append(releases, v)
		}
	}
	var list []*page
	for _, p := range fixturePages(t) {
		list = append(list, p)
	}
	sn := newSnapshot(list, releases, fixtureAvailable(t), DefaultAdvisoriesURL)
	advs := match(t, sn, "26.0.2")
	a, ok := find(advs, "CVE-2026-61308")
	if !ok {
		t.Fatalf("CVE-2026-61308 (2026-08-18, marked for 26) missing: %v", ids(advs))
	}
	if a.Status != scanner.StatusEndOfLife || a.FixedVer != "" || strings.Contains(a.Title, "inferred") {
		t.Errorf("got %+v, want end_of_life without a fix and without the inferred title", a)
	}
}

// A CVE the column of an advisory says is fixed by a release, which a later
// advisory's inference says still affects: the line is past its support, so
// there is no fix.
func TestMatch_InferredHitCoveringTheFixIsNotFixed(t *testing.T) {
	sn := fixtureSnapshot(t)
	line := func(date string, cols []int, ceilings map[int]string, marks map[int]bool) *page {
		p := &page{date: date, columns: cols, order: cols, ceilings: map[int]version{}}
		for l, s := range ceilings {
			p.ceilings[l] = mustVersion(t, s)
		}
		p.rows = []row{{cve: "CVE-2030-1", component: "core-libs", score10: 75, marked: marks}}
		return p
	}
	// 2030-01-01: line 16 has a column, affected up to 16.0.1, so 16.0.2 is
	// the fix the release list gives.
	real := line("2030-01-01", []int{15, 16, 17}, map[int]string{15: "15.0.3", 16: "16.0.1", 17: "17.0.1"}, map[int]bool{16: true})
	build := func(inferred *page) *Snapshot {
		return newSnapshot(append(append([]*page(nil), sn.pages...), real, inferred), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	}
	// Check that the premise holds: the column hit alone is fixed by 16.0.2.
	alone := newSnapshot(append(append([]*page(nil), sn.pages...), real), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	a, ok := find(alone.Match(VendorTemurin, mustVersion(t, "16.0.1")), "CVE-2030-1")
	if !ok || a.Status != scanner.StatusFixed || a.FixedVer == "" {
		t.Skipf("the release list has no fix after 16.0.1: %+v", a)
	}

	// 2030-02-01 has no column for 16 and no affected version for it: the CVE
	// is marked on 15 and 17, so it covers every 16.x, the fix included.
	later := line("2030-02-01", []int{15, 17}, map[int]string{15: "15.0.4", 17: "17.0.2"}, map[int]bool{15: true, 17: true})
	b, ok := find(build(later).Match(VendorTemurin, mustVersion(t, "16.0.1")), "CVE-2030-1")
	if !ok || b.Status != scanner.StatusEndOfLife || b.FixedVer != "" {
		t.Fatalf("advisory = %+v, %v; want end_of_life", b, ok)
	}
	if !strings.HasSuffix(b.URL, "/2030-02-01") || !strings.Contains(b.Title, "(inferred for end-of-life Java 16 from 15 and 17)") {
		t.Errorf("the link and title come from %s %q", b.URL, b.Title)
	}

	// An inference whose affected version stops below the fix does not count.
	limited := line("2030-02-01", []int{15, 17}, map[int]string{15: "15.0.4", 16: "16.0.1", 17: "17.0.2"}, map[int]bool{15: true, 17: true})
	c, ok := find(build(limited).Match(VendorTemurin, mustVersion(t, "16.0.1")), "CVE-2030-1")
	if !ok || c.Status != scanner.StatusFixed {
		t.Errorf("advisory = %+v, %v; want fixed", c, ok)
	}
}

// The status and the fix come from the deciding hits; the link, component and
// severity come from the newest advisory that matched, so a corrected score
// is the one shown.
func TestMatch_ShownFieldsComeFromTheNewestHit(t *testing.T) {
	sn := fixtureSnapshot(t)
	mk := func(date string, cols []int, ceilings map[int]string, score int, component string, marks map[int]bool) *page {
		p := &page{date: date, columns: cols, order: cols, ceilings: map[int]version{}}
		for l, s := range ceilings {
			p.ceilings[l] = mustVersion(t, s)
		}
		p.rows = []row{{cve: "CVE-2031-1", component: component, score10: score, marked: marks}}
		return p
	}
	old := mk("2031-01-01", []int{15, 16, 17}, map[int]string{15: "15.0.3", 16: "16.0.1", 17: "17.0.1"}, 53, "old-component", map[int]bool{16: true})
	// The newer advisory's inference stops at 16.0.1, below the old fix.
	newer := mk("2031-02-01", []int{15, 17}, map[int]string{15: "15.0.4", 16: "16.0.1", 17: "17.0.2"}, 81, "new-component", map[int]bool{15: true, 17: true})
	s2 := newSnapshot(append(append([]*page(nil), sn.pages...), old, newer), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	a, ok := find(s2.Match(VendorTemurin, mustVersion(t, "16.0.1")), "CVE-2031-1")
	if !ok {
		t.Fatal("not matched")
	}
	if a.Status != scanner.StatusFixed || a.FixedVer == "" {
		t.Errorf("status = %s %s, want fixed", a.Status, a.FixedVer)
	}
	if a.Severity != "HIGH" || !strings.HasSuffix(a.URL, "/2031-02-01") || a.Title != "OpenJDK: new-component" {
		t.Errorf("shown = %s %s %q; want the newest page and its score", a.Severity, a.URL, a.Title)
	}

	// A score lowered in the newer advisory is the one shown.
	oldHigh := mk("2031-01-01", []int{15, 16, 17}, map[int]string{15: "15.0.3", 16: "16.0.1", 17: "17.0.1"}, 81, "old-component", map[int]bool{16: true})
	newerLow := mk("2031-02-01", []int{15, 17}, map[int]string{15: "15.0.4", 16: "16.0.1", 17: "17.0.2"}, 53, "new-component", map[int]bool{15: true, 17: true})
	s4 := newSnapshot(append(append([]*page(nil), sn.pages...), oldHigh, newerLow), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	if c, _ := find(s4.Match(VendorTemurin, mustVersion(t, "16.0.1")), "CVE-2031-1"); c.Severity != "MEDIUM" {
		t.Errorf("severity after a lowered score = %s, want MEDIUM", c.Severity)
	}

	// When the inference decides, the title says so, from the newest page.
	cover := mk("2031-02-01", []int{15, 17}, map[int]string{15: "15.0.4", 17: "17.0.2"}, 81, "new-component", map[int]bool{15: true, 17: true})
	s3 := newSnapshot(append(append([]*page(nil), sn.pages...), old, cover), fixtureReleases(t), fixtureAvailable(t), DefaultAdvisoriesURL)
	b, _ := find(s3.Match(VendorTemurin, mustVersion(t, "16.0.1")), "CVE-2031-1")
	if b.Status != scanner.StatusEndOfLife || b.Severity != "HIGH" || !strings.Contains(b.Title, "(inferred for end-of-life Java 16 from 15 and 17)") {
		t.Errorf("advisory = %+v", b)
	}
}
