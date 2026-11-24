package javacore

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseIndex(t *testing.T) {
	dates := fixtureDates(t)
	if len(dates) != 35 {
		t.Fatalf("dates = %d, want 35", len(dates))
	}
	if dates[0] != "2019-04-16" || dates[34] != "2026-11-17" {
		t.Errorf("dates = %v ... %v", dates[0], dates[34])
	}
	good := `<h2 id="advisories">Advisories</h2><ul><li><a href="2026-11-17">2026/11/17 (latest)</a></li><li><a href="2026-10-24">2026/10/24</a></li></ul>`
	if got, err := parseIndex([]byte(good)); err != nil || !reflect.DeepEqual(got, []string{"2026-10-24", "2026-11-17"}) {
		t.Errorf("parseIndex = %v, %v", got, err)
	}
	for name, in := range map[string]string{
		"empty list":     `<h2 id="advisories">Advisories</h2><ul></ul>`,
		"no heading":     `<ul><li><a href="2026-11-17">x</a></li></ul>`,
		"not closed":     `<h2 id="advisories">Advisories</h2><ul><li><a href="2026-11-17">x</a></li>`,
		"bad date":       `<h2 id="advisories">Advisories</h2><ul><li><a href="2026-13-17">x</a></li></ul>`,
		"duplicate date": `<h2 id="advisories">Advisories</h2><ul><li><a href="2026-11-17">x</a></li><li><a href="2026-11-17">y</a></li></ul>`,
		"other item":     `<h2 id="advisories">Advisories</h2><ul><li><a href="2026-11-17">x</a></li><li>soon</li></ul>`,
		"other link":     `<h2 id="advisories">Advisories</h2><ul><li><a href="../latest">x</a></li></ul>`,
	} {
		if got, err := parseIndex([]byte(in)); err == nil {
			t.Errorf("%s: parseIndex = %v, want an error", name, got)
		}
	}
	var many strings.Builder
	many.WriteString(`<h2 id="advisories">Advisories</h2><ul>`)
	for i := 0; i < maxAdvisories+1; i++ {
		many.WriteString(`<li><a href="` + dateOf(i) + `">x</a></li>`)
	}
	many.WriteString(`</ul>`)
	if _, err := parseIndex([]byte(many.String())); err == nil {
		t.Error("an advisory list over the limit was accepted")
	}
	if _, err := parseIndex(make([]byte, maxIndexBytes+1)); err == nil {
		t.Error("an advisory list over the size limit was accepted")
	}
}

// dateOf is a valid, distinct date for each i below 3650.
func dateOf(i int) string {
	d := 1 + i%28
	m := 1 + (i/28)%12
	y := 2000 + i/(28*12)
	return pad(y, 4) + "-" + pad(m, 2) + "-" + pad(d, 2)
}

func pad(n, w int) string {
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	for len(s) < w {
		s = "0" + s
	}
	return s
}

func TestParsePage_AllRecordedAdvisoriesAreReadable(t *testing.T) {
	pages := fixturePages(t)
	if len(pages) != 35 {
		t.Fatalf("pages = %d, want 35", len(pages))
	}
	for d, p := range pages {
		if len(p.rows) == 0 && !p.none {
			t.Errorf("%s: no rows", d)
		}
		if len(p.noCeiling) != 0 {
			t.Errorf("%s: columns without an affected version: %v", d, p.noCeiling)
		}
		for _, line := range p.columns {
			if _, ok := p.ceilings[line]; !ok {
				t.Errorf("%s: line %d has no affected version", d, line)
			}
		}
		for _, r := range p.rows {
			if r.component == "" || r.cve == "" || r.score10 < 0 || r.score10 > 100 {
				t.Errorf("%s: bad row %+v", d, r)
			}
		}
	}
}

func TestParsePage_RepresentativeRows(t *testing.T) {
	pages := fixturePages(t)

	// 2026-11-17: five of the ten CVEs affect line 8.
	p := pages["2026-11-17"]
	if len(p.rows) != 10 {
		t.Fatalf("2026-11-17 rows = %d, want 10", len(p.rows))
	}
	if got := pageIDs(p, 8); !reflect.DeepEqual(got, []string{"CVE-2026-114939", "CVE-2026-114940", "CVE-2026-114943", "CVE-2026-114944", "CVE-2026-114946"}) {
		t.Errorf("2026-11-17 line 8 = %v", got)
	}
	if got := pageIDs(p, 27); len(got) != 10 {
		t.Errorf("2026-11-17 line 27 = %v", got)
	}
	if got := pageIDs(p, 11); len(got) != 5 {
		t.Errorf("2026-11-17 line 11 = %v", got)
	}
	wantCeil := map[int]string{27: "27.0.1.0.3", 25: "25.0.5.0.3", 21: "21.0.13.0.3", 17: "17.0.21.0.3", 11: "11.0.33", 8: "8u512"}
	for line, s := range wantCeil {
		if got := p.ceilings[line].String(); got != s {
			t.Errorf("2026-11-17 ceiling of %d = %s, want %s", line, got, s)
		}
	}
	r := p.rows[0]
	if r.cve != "CVE-2026-114938" || r.component != "hotspot/compiler" || r.score10 != 81 {
		t.Errorf("first row = %+v", r)
	}
	// The component of a one-word cell, and of a cell ending in a line break.
	for _, c := range []struct{ date, cve, comp string }{
		{"2026-11-17", "CVE-2026-114942", "core-libs"},
		{"2019-10-15", "CVE-2019-2933", "core-libs"},
		{"2026-10-20", "CVE-2026-91397", "core-svc"},
		{"2023-01-17", "CVE-2023-21830", "other-libs"},
	} {
		found := false
		for _, r := range pages[c.date].rows {
			if r.cve == c.cve {
				found = true
				if r.component != c.comp {
					t.Errorf("%s %s component = %q, want %q", c.date, c.cve, r.component, c.comp)
				}
			}
		}
		if !found {
			t.Errorf("%s %s missing", c.date, c.cve)
		}
	}

	// The OpenJFX table is not read.
	for _, c := range []struct{ date, cve string }{{"2026-11-17", "CVE-2026-86144"}, {"2020-04-14", "CVE-2019-18197"}} {
		if !strings.Contains(string(readFixture(t, "advisories/"+c.date+".html")), c.cve) {
			t.Fatalf("%s does not list %s", c.date, c.cve)
		}
		for _, r := range pages[c.date].rows {
			if r.cve == c.cve {
				t.Errorf("%s: JavaFX CVE %s was read as a JDK CVE", c.date, c.cve)
			}
		}
	}

	// CVE-2020-14803 is in two advisories: marked for every line in 2020-10,
	// for none in 2021-01.
	var a, b *row
	for i := range pages["2020-10-20"].rows {
		if pages["2020-10-20"].rows[i].cve == "CVE-2020-14803" {
			a = &pages["2020-10-20"].rows[i]
		}
	}
	for i := range pages["2021-01-19"].rows {
		if pages["2021-01-19"].rows[i].cve == "CVE-2020-14803" {
			b = &pages["2021-01-19"].rows[i]
		}
	}
	if a == nil || b == nil {
		t.Fatal("CVE-2020-14803 not found in both advisories")
	}
	if len(a.marked) != 5 || len(b.marked) != 0 {
		t.Errorf("CVE-2020-14803 marks = %v / %v", a.marked, b.marked)
	}

	// The 2019 pages say "Risk matrix"; their line 7 is read.
	if got := pages["2019-04-16"].ceilings[7].String(); got != "7u211" {
		t.Errorf("2019-04-16 line 7 = %s", got)
	}
	// Four pages state a column span one short of their columns; it is not
	// what the lines are counted from.
	if got := pages["2022-04-19"].columns; !reflect.DeepEqual(got, []int{7, 8, 11, 13, 15, 17, 18}) {
		t.Errorf("2022-04-19 columns = %v", got)
	}
}

func TestParsePage_CeilingException(t *testing.T) {
	p := fixturePages(t)["2021-10-19"]
	// The table has 17 and the sentence has 16: 17 is read as the version 17,
	// 16 has an affected version and no column.
	if got := p.ceilings[17].String(); got != "17" {
		t.Errorf("line 17 = %s, want 17", got)
	}
	if p.hasColumn(16) || p.ceilings[16].String() != "16.0.2" {
		t.Errorf("line 16: column %v, ceiling %v", p.hasColumn(16), p.ceilings[16])
	}
	if len(p.noCeiling) != 0 {
		t.Errorf("noCeiling = %v", p.noCeiling)
	}

	// The same shape on another date is not excused.
	data := readFixture(t, "advisories/2021-10-19.html")
	other := []byte(strings.ReplaceAll(string(data), "2021/10/19", "2021/10/20"))
	q, err := parsePage("2021-10-20", other)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(q.noCeiling, []int{17}) {
		t.Errorf("another date: noCeiling = %v, want [17]", q.noCeiling)
	}
	// A line the exception does not name is not excused on that date either.
	mod := strings.Replace(string(data), "<th>15</th>", "<th>14</th>", 1)
	q, err = parsePage("2021-10-19", []byte(mod))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(q.noCeiling, []int{14}) {
		t.Errorf("column 14: noCeiling = %v, want [14]", q.noCeiling)
	}
}

func TestParsePage_Rejected(t *testing.T) {
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	if _, err := parsePage("2026-11-17", []byte(good)); err != nil {
		t.Fatal(err)
	}
	sub := func(old, new string) string {
		t.Helper()
		if !strings.Contains(good, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	row := `<tr><td nowrap="nowrap"><a href="https://nvd.nist.gov/vuln/detail/CVE-2026-114947">CVE-2026-114947</a></td>`
	cases := map[string]string{
		"unknown mark":           sub("<td>&#8226;</td>", "<td>x</td>"),
		"mark with space":        sub("<td>&#8226;</td>", "<td> &#8226;</td>"),
		"two marks":              sub("<td>&#8226;</td>", "<td>&#8226;&#8226;</td>"),
		"bad CVE ID":             sub(">CVE-2026-114938<", ">CVE-26-114938<"),
		"link not the CVE":       sub("detail/CVE-2026-114938", "detail/CVE-2026-114937"),
		"score out of range":     sub("<td>8.1<br />", "<td>10.1<br />"),
		"score not a number":     sub("<td>8.1<br />", "<td>high<br />"),
		"no vector":              sub("<td>8.1<br />NHNNUHHH</td>", "<td>8.1</td>"),
		"missing cell":           sub(`<td nowrap="nowrap">hotspot/<br />compiler</td><td>8.1<br />NHNNUHHH</td>`, `<td>8.1<br />NHNNUHHH</td>`),
		"extra cell":             sub("</tr><tr>"+row[4:], "<td></td></tr><tr>"+row[4:]),
		"unknown column header":  sub("CVSSv3.1</a>", "CVSSv4</a>"),
		"unknown first header":   sub("Affects ...", "Impacts ..."),
		"duplicate column":       sub("<th>21</th>", "<th>17</th>"),
		"column not a number":    sub("<th>21</th>", "<th>21u</th>"),
		"no matrix heading":      sub("<h2 id=\"risk-matrix\">OpenJDK Risk matrix</h2>", "<h2 id=\"risk-matrix\">Risks</h2>"),
		"heading not followed":   sub(`</h2><table class="risk-matrix" summary="Risk matrix">`, `</h2><p>x</p><table class="risk-matrix" summary="Risk matrix">`),
		"table attributes":       sub(`summary="Risk matrix"><tr><th></th>`, `summary="Matrix"><tr><th></th>`),
		"no sentence":            sub("The affected versions are", "The versions are"),
		"sentence without end":   sub(", and earlier", ", and later"),
		"sentence twice":         sub("<h2 id=\"risk-matrix\">", "<p>The affected versions are 27, and earlier.</p><h2 id=\"risk-matrix\">"),
		"unreadable version":     sub("27.0.1.0.3,", "27.0.1.0.3-ea,"),
		"line in sentence twice": sub("25.0.5.0.3,", "25.0.5.0.3, 25.0.4,"),
		"comment in the page":    sub("<h2 id=\"jfx-risk-matrix\">", "<!-- x --><h2 id=\"jfx-risk-matrix\">"),
		"bare attribute":         sub("<tr><th></th>", "<tr nowrap><th></th>"),
		"single quoted":          sub(`<table class="risk-matrix"`, `<table class='risk-matrix'`),
		"table twice":            sub("<h2 id=\"jfx-risk-matrix\">OpenJFX Risk matrix</h2>", "<h2 id=\"risk-matrix\">OpenJDK Risk matrix</h2>"),
		"stray table":            sub("<h2 id=\"acknowledgements\">", `<table class="risk-matrix" summary="Risk matrix"></table><h2 id="acknowledgements">`),
		"no body":                strings.Replace(good, `<div id="main">`, `<div id="content">`, 1),
		"no CVE rows":            sub(row, `<tr class="x"><td></td></tr>`+row),
	}
	for name, in := range cases {
		if p, err := parsePage("2026-11-17", []byte(in)); err == nil {
			t.Errorf("%s: parsePage accepted the page (%d rows)", name, len(p.rows))
		}
	}
	if _, err := parsePage("2026-11-17", make([]byte, maxPageBytes+1)); err == nil {
		t.Error("a page over the size limit was accepted")
	}
	if _, err := parsePage("2026/11/17", []byte(good)); err == nil {
		t.Error("an invalid date was accepted")
	}
}

// A mark of &#8226; and the character itself are the same mark.
func TestParsePage_MarkEntities(t *testing.T) {
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	want, _ := parsePage("2026-11-17", []byte(good))
	for _, e := range []string{"•", "&#x2022;", "&bull;"} {
		p, err := parsePage("2026-11-17", []byte(strings.ReplaceAll(good, "&#8226;", e)))
		if err != nil {
			t.Fatalf("%q: %v", e, err)
		}
		if !reflect.DeepEqual(p.rows, want.rows) {
			t.Errorf("%q: rows differ", e)
		}
	}
}

func TestParsePage_NoCVEs(t *testing.T) {
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	start := strings.Index(good, `<tr><td nowrap="nowrap"><a href="https://nvd`)
	end := strings.Index(good, `</table><h2 id="jfx-risk-matrix">`)
	none := `<tr><td nowrap="nowrap">None</td><td nowrap="nowrap"></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>`
	page := good[:start] + none + good[end:]
	p, err := parsePage("2026-11-17", []byte(page))
	if err != nil {
		t.Fatal(err)
	}
	if !p.none || len(p.rows) != 0 {
		t.Errorf("none = %v, rows = %d", p.none, len(p.rows))
	}
	// A "None" row beside a CVE row, or with a mark, is not an empty advisory.
	if _, err := parsePage("2026-11-17", []byte(good[:start]+none+good[start:])); err == nil {
		t.Error("None before CVE rows was accepted")
	}
	marked := strings.Replace(none, "<td></td></tr>", "<td>&#8226;</td></tr>", 1)
	if _, err := parsePage("2026-11-17", []byte(good[:start]+marked+good[end:])); err == nil {
		t.Error("a marked None row was accepted")
	}
	// A table with no rows at all is not valid either.
	if _, err := parsePage("2026-11-17", []byte(good[:start]+good[end:])); err == nil {
		t.Error("a risk matrix with no rows was accepted")
	}
}

func TestParsePage_RowLimit(t *testing.T) {
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	start := strings.Index(good, `<tr><td nowrap="nowrap"><a href="https://nvd`)
	end := strings.Index(good, `</table><h2 id="jfx-risk-matrix">`)
	one := good[start : strings.Index(good[start:], "</tr>")+start+5]
	build := func(n int) string {
		return good[:start] + strings.Repeat(one, n) + good[end:]
	}
	if _, err := parsePage("2026-11-17", []byte(build(maxCVEsPerPage))); err != nil {
		t.Errorf("%d rows: %v", maxCVEsPerPage, err)
	}
	if _, err := parsePage("2026-11-17", []byte(build(maxCVEsPerPage+1))); err == nil {
		t.Error("a page over the CVE limit was accepted")
	}
}

func TestParsePage_TitleDateMustBeTheRequestedOne(t *testing.T) {
	// Every recorded page names its own date (the 2019 ones unpadded).
	for _, d := range fixtureDates(t) {
		data := readFixture(t, "advisories/"+d+".html")
		if _, err := parsePage(d, data); err != nil {
			t.Errorf("%s: %v", d, err)
		}
		if _, err := parsePage("2026-12-15", data); err == nil && d != "2026-12-15" {
			t.Errorf("%s was accepted for 2026-12-15", d)
		}
	}
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	for name, in := range map[string]string{
		"no title":     strings.Replace(good, "<h1>OpenJDK Vulnerability Advisory: 2026/11/17</h1>", "", 1),
		"two titles":   strings.Replace(good, "<h1>", "<h1>OpenJDK Vulnerability Advisory: 2026/11/17</h1><h1>", 1),
		"other prefix": strings.Replace(good, "<h1>OpenJDK Vulnerability Advisory:", "<h1>OpenJDK Notes:", 1),
		"not a date":   strings.Replace(good, "<h1>OpenJDK Vulnerability Advisory: 2026/11/17", "<h1>OpenJDK Vulnerability Advisory: latest", 1),
		"nested":       strings.Replace(good, "<h1>OpenJDK Vulnerability Advisory: 2026/11/17</h1>", "<h1><b>OpenJDK Vulnerability Advisory: 2026/11/17</b></h1>", 1),
	} {
		if _, err := parsePage("2026-11-17", []byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseIndex_WhitespaceBetweenItems(t *testing.T) {
	index := string(readFixture(t, "advisories/index.html"))
	spaced := strings.ReplaceAll(index, "</li><li>", "</li>\n  <li>")
	spaced = strings.Replace(spaced, "<ul><li>", "<ul>\n<li>", 1)
	spaced = strings.Replace(spaced, "</li></ul>", "</li>\r\n</ul>", 1)
	spaced = strings.Replace(spaced, "</h2><ul>", "</h2>\n<ul>", 1)
	got, err := parseIndex([]byte(spaced))
	if err != nil || len(got) != 35 {
		t.Fatalf("parseIndex = %d dates, %v", len(got), err)
	}
	for name, in := range map[string]string{
		"unknown element": strings.Replace(index, "</li><li>", "</li>\n<p>x</p>\n<li>", 1),
		"text between":    strings.Replace(index, "</li><li>", "</li>and<li>", 1),
		"duplicate":       strings.Replace(spaced, "2026-10-24", "2026-11-17", 1),
	} {
		if _, err := parseIndex([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestErrorsQuoteLittleInput(t *testing.T) {
	good := string(readFixture(t, "advisories/2026-11-17.html"))
	huge := strings.Repeat("x", 300000)
	for name, in := range map[string]string{
		"component": strings.Replace(good, "hotspot/<br />compiler", huge, 1),
		"score":     strings.Replace(good, "<td>8.1<br />", "<td>"+huge+"<br />", 1),
		"CVE":       strings.Replace(good, ">CVE-2026-114938<", ">"+huge+"<", 1),
		"version":   strings.Replace(good, "27.0.1.0.3,", huge+",", 1),
		"tag":       strings.Replace(good, "<h2 id=\"jfx-risk-matrix\">", "<h2 "+huge+">", 1),
	} {
		_, err := parsePage("2026-11-17", []byte(in))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if len(err.Error()) > 1000 {
			t.Errorf("%s: the error is %d bytes", name, len(err.Error()))
		}
	}
	if _, err := parseReleaseVersionError(huge); err == nil || len(err.Error()) > 1000 {
		t.Errorf("release version error: %v", err)
	}
}

func parseReleaseVersionError(s string) (struct{}, error) {
	_, _, err := parseReleasePage([]byte(`{"versions":[{"openjdk_version":"` + s + `"}]}`))
	return struct{}{}, err
}

func TestParseIndex_WhitespaceInsideItems(t *testing.T) {
	index := string(readFixture(t, "advisories/index.html"))
	spaced := strings.Replace(index, `<li><a href="2026-11-17">2026/11/17 (latest)</a></li>`, "<li>\n  <a href=\"2026-11-17\">2026/11/17 (latest)</a>\r\n</li>", 1)
	if spaced == index {
		t.Fatal("not changed")
	}
	if got, err := parseIndex([]byte(spaced)); err != nil || len(got) != 35 {
		t.Fatalf("parseIndex = %d dates, %v", len(got), err)
	}
	for name, in := range map[string]string{
		"text in the item": strings.Replace(index, "<li><a", "<li>x<a", 1),
		"extra link":       strings.Replace(index, "</a></li>", "</a><a href=\"x\">y</a></li>", 1),
		"other attribute":  strings.Replace(index, `<a href="2026-11-17"`, `<a class="x" href="2026-11-17"`, 1),
	} {
		if _, err := parseIndex([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
