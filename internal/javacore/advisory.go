package javacore

import (
	"errors"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Bounds on what is read from the OpenJDK site. They only guard against a
// rogue endpoint; the real pages are far below them.
const (
	maxPageBytes     = 1 << 20
	maxIndexBytes    = 1 << 20
	maxAdvisories    = 500
	maxCVEsPerPage   = 500
	maxComponentLen  = 200
	maxSeriesColumns = 64
)

// maxQuote bounds how much of the input an error quotes.
const maxQuote = 200

// clip shortens s for an error message.
func clip(s string) string {
	if len(s) <= maxQuote {
		return s
	}
	return s[:maxQuote] + "..."
}

// mark is the cell content of a line an advisory's CVE affects.
const mark = "•"

// page is one parsed advisory: for each release line the last version the
// advisory says is affected, and a table of the CVEs with the lines each one
// affects.
type page struct {
	date string // YYYY-MM-DD
	// ceilings are the affected versions of the advisory's sentence, by line.
	ceilings map[int]version
	// columns are the lines of the risk matrix, ascending; order is the
	// same lines as the table lists them.
	columns []int
	order   []int
	rows    []row
	// none is set for an advisory without CVEs, whose table is one empty row.
	none bool
	// noCeiling are the columns the sentence has no version for.
	noCeiling []int
}

// row is one CVE of the risk matrix.
type row struct {
	cve       string
	component string
	score10   int // CVSS base score times ten
	marked    map[int]bool
}

func (p *page) hasColumn(series int) bool {
	for _, c := range p.columns {
		if c == series {
			return true
		}
	}
	return false
}

// A line the advisory's table has a column for but whose sentence has no
// version, other than this one, makes the line unusable. The 2021-10-19
// advisory lists 17 in the table and 16 in the sentence; 17 was released a
// month earlier and its first fix is 17.0.1, so its affected version is 17.
const (
	ceilingExceptionDate   = "2021-10-19"
	ceilingExceptionSeries = 17
)

var (
	cveIDRe   = regexp.MustCompile(`^CVE-\d{4}-\d{4,8}$`)
	scoreRe   = regexp.MustCompile(`^(?:[0-9]|10)\.[0-9]$`)
	columnRe  = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)
	dateRe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	indexItem = regexp.MustCompile(`<li><a href="(\d{4}-\d{2}-\d{2})">[^<>]*</a></li>`)
)

const (
	nvdPrefix  = "https://nvd.nist.gov/vuln/detail/"
	cvssLink   = "https://www.first.org/cvss/"
	sentenceAt = "The affected versions are "
	sentenceTo = ", and earlier"
)

var (
	indexHeadRe = regexp.MustCompile(`<h2 id="advisories">Advisories</h2>\s*<ul>`)
	indexItemRe = regexp.MustCompile(`^<li>\s*<a href="(\d{4}-\d{2}-\d{2})">[^<>]*</a>\s*</li>`)
)

// parseIndex reads the advisory dates from the list page, ascending. Only
// whitespace may separate the list items.
func parseIndex(data []byte) ([]string, error) {
	if len(data) > maxIndexBytes {
		return nil, fmt.Errorf("advisory list is larger than %d bytes", maxIndexBytes)
	}
	s := string(data)
	heads := indexHeadRe.FindAllStringIndex(s, -1)
	if len(heads) != 1 {
		return nil, errors.New("advisory list not found")
	}
	body := s[heads[0][1]:]
	end := strings.Index(body, "</ul>")
	if end < 0 {
		return nil, errors.New("advisory list is not closed")
	}
	body = body[:end]
	var dates []string
	seen := map[string]bool{}
	for {
		body = strings.TrimLeft(body, " \t\r\n")
		if body == "" {
			break
		}
		m := indexItemRe.FindStringSubmatch(body)
		if m == nil {
			return nil, fmt.Errorf("unexpected markup in the advisory list: %q", clip(body))
		}
		body = body[len(m[0]):]
		d := m[1]
		if _, err := time.Parse("2006-01-02", d); err != nil {
			return nil, fmt.Errorf("advisory list has the invalid date %q", d)
		}
		if seen[d] {
			return nil, fmt.Errorf("advisory list has %s twice", d)
		}
		seen[d] = true
		dates = append(dates, d)
		if len(dates) > maxAdvisories {
			return nil, fmt.Errorf("advisory list has more than %d advisories", maxAdvisories)
		}
	}
	if len(dates) == 0 {
		return nil, errors.New("advisory list is empty")
	}
	sort.Strings(dates)
	return dates, nil
}

// --- lexical reading of an advisory page ---

type tokenKind int

const (
	tokText tokenKind = iota
	tokStart
	tokEnd
	tokVoid // <br />
)

type token struct {
	kind  tokenKind
	name  string
	attrs map[string]string
	text  string // text, with entities decoded
}

var (
	tagNameRe = regexp.MustCompile(`^[a-z][a-z0-9]*`)
	attrRe    = regexp.MustCompile(`^ ([a-z][a-z-]*)="([^"<>]*)"`)
)

// lex splits markup into tags and text. It accepts only plain lower-case
// tags with double-quoted attributes, the form the advisory pages use;
// anything else (comments, declarations, bare attributes) is an error.
func lex(src string) ([]token, error) {
	var toks []token
	for i := 0; i < len(src); {
		if src[i] != '<' {
			j := strings.IndexByte(src[i:], '<')
			if j < 0 {
				j = len(src) - i
			}
			toks = append(toks, token{kind: tokText, text: html.UnescapeString(src[i : i+j])})
			i += j
			continue
		}
		j := strings.IndexByte(src[i:], '>')
		if j < 0 {
			return nil, fmt.Errorf("unterminated tag at byte %d", i)
		}
		inner := src[i+1 : i+j]
		i += j + 1
		if strings.HasPrefix(inner, "/") {
			name := inner[1:]
			if !tagNameRe.MatchString(name) || tagNameRe.FindString(name) != name {
				return nil, fmt.Errorf("unsupported end tag </%s>", clip(name))
			}
			toks = append(toks, token{kind: tokEnd, name: name})
			continue
		}
		void := false
		if strings.HasSuffix(inner, " /") {
			void = true
			inner = strings.TrimSuffix(inner, " /")
		}
		name := tagNameRe.FindString(inner)
		if name == "" {
			return nil, fmt.Errorf("unsupported markup <%s>", clip(inner))
		}
		rest := inner[len(name):]
		attrs := map[string]string{}
		for rest != "" {
			m := attrRe.FindStringSubmatch(rest)
			if m == nil {
				return nil, fmt.Errorf("unsupported attributes in <%s>", clip(inner))
			}
			if _, dup := attrs[m[1]]; dup {
				return nil, fmt.Errorf("attribute %s repeated in <%s>", clip(m[1]), clip(inner))
			}
			attrs[m[1]] = html.UnescapeString(m[2])
			rest = rest[len(m[0]):]
		}
		kind := tokStart
		if void {
			kind = tokVoid
		}
		toks = append(toks, token{kind: kind, name: name, attrs: attrs})
	}
	return toks, nil
}

func isSpace(t token) bool {
	return t.kind == tokText && strings.TrimSpace(t.text) == ""
}

// parsePage reads one advisory page. Only the form of the pages published
// since 2019 is accepted; a page that departs from it is an error, so that
// advisory data is never matched from a page read wrongly.
func parsePage(date string, data []byte) (*page, error) {
	if !dateRe.MatchString(date) {
		return nil, fmt.Errorf("invalid advisory date %q", clip(date))
	}
	if len(data) > maxPageBytes {
		return nil, fmt.Errorf("advisory %s is larger than %d bytes", date, maxPageBytes)
	}
	s := string(data)
	const open, closeMarker = `<div id="main">`, `<div id="sidebar">`
	if strings.Count(s, open) != 1 || strings.Count(s, closeMarker) != 1 {
		return nil, fmt.Errorf("advisory %s: page body not found", date)
	}
	a, b := strings.Index(s, open), strings.Index(s, closeMarker)
	if a > b {
		return nil, fmt.Errorf("advisory %s: page body not found", date)
	}
	toks, err := lex(s[a+len(open) : b])
	if err != nil {
		return nil, fmt.Errorf("advisory %s: %w", date, err)
	}
	if err := checkTitleDate(date, toks); err != nil {
		return nil, fmt.Errorf("advisory %s: %w", date, err)
	}
	p := &page{date: date}
	if err := p.read(toks); err != nil {
		return nil, fmt.Errorf("advisory %s: %w", date, err)
	}
	return p, nil
}

const titlePrefix = "OpenJDK Vulnerability Advisory: "

// checkTitleDate checks that the page's heading ("OpenJDK Vulnerability
// Advisory: 2026/11/17", with unpadded month and day on the older pages) is
// the date it was requested for, so that a mirror answering with another
// advisory is not taken for this one.
func checkTitleDate(date string, toks []token) error {
	var title string
	n := 0
	for i, t := range toks {
		if t.kind == tokStart && t.name == "h1" {
			n++
			if i+2 < len(toks) && toks[i+1].kind == tokText && toks[i+2].kind == tokEnd && toks[i+2].name == "h1" {
				title = strings.Join(strings.Fields(toks[i+1].text), " ")
			}
		}
	}
	if n != 1 || !strings.HasPrefix(title, titlePrefix) {
		return errors.New("the page has no advisory title")
	}
	parts := strings.Split(strings.TrimPrefix(title, titlePrefix), "/")
	if len(parts) != 3 {
		return fmt.Errorf("unreadable advisory title %q", clip(title))
	}
	var nums [3]int
	for i, f := range parts {
		v, err := strconv.Atoi(f)
		if err != nil || len(f) > 4 {
			return fmt.Errorf("unreadable advisory title %q", clip(title))
		}
		nums[i] = v
	}
	want, err := time.Parse("2006-01-02", date)
	if err != nil || nums[0] != want.Year() || nums[1] != int(want.Month()) || nums[2] != want.Day() {
		return fmt.Errorf("the page is the advisory of %q, not of %s", clip(title), date)
	}
	return nil
}

// read walks the page: the sentence of affected versions, and the table that
// follows the JDK risk matrix heading.
func (p *page) read(toks []token) error {
	const (
		jdkHeading = "OpenJDK Risk matrix"
		jdkOld     = "Risk matrix" // the 2019 pages
		jfxHeading = "OpenJFX Risk matrix"
	)
	var sentences []string
	sawJDK := false
	allowTable := "" // "jdk" or "jfx" right after a matrix heading
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.kind == tokStart && t.name == "h2":
			if i+2 >= len(toks) || toks[i+1].kind != tokText || toks[i+2].kind != tokEnd || toks[i+2].name != "h2" {
				return errors.New("a heading is not plain text")
			}
			heading := strings.Join(strings.Fields(toks[i+1].text), " ")
			i += 2
			allowTable = ""
			switch heading {
			case jdkHeading, jdkOld:
				if sawJDK {
					return errors.New("more than one JDK risk matrix")
				}
				sawJDK, allowTable = true, "jdk"
			case jfxHeading:
				allowTable = "jfx"
			default:
				continue
			}
			next := i + 1
			for next < len(toks) && isSpace(toks[next]) {
				next++
			}
			if next >= len(toks) || toks[next].kind != tokStart || toks[next].name != "table" {
				return fmt.Errorf("%q is not followed by a table", clip(heading))
			}
		case t.kind == tokStart && t.name == "table":
			if allowTable == "" {
				return errors.New("a table without a risk matrix heading")
			}
			end := -1
			for j := i + 1; j < len(toks); j++ {
				if toks[j].kind == tokStart && toks[j].name == "table" {
					return errors.New("nested tables")
				}
				if toks[j].kind == tokEnd && toks[j].name == "table" {
					end = j
					break
				}
			}
			if end < 0 {
				return errors.New("a table is not closed")
			}
			if allowTable == "jdk" {
				if err := p.readTable(t, toks[i+1:end]); err != nil {
					return err
				}
			}
			allowTable = ""
			i = end
		case t.kind == tokText:
			norm := strings.Join(strings.Fields(t.text), " ")
			if strings.Contains(norm, sentenceAt) {
				sentences = append(sentences, norm)
			}
		}
	}
	if !sawJDK || len(p.columns) == 0 {
		return errors.New("no JDK risk matrix")
	}
	if len(sentences) != 1 || strings.Count(sentences[0], sentenceAt) != 1 {
		return errors.New("the sentence of affected versions is not found exactly once")
	}
	if err := p.readSentence(sentences[0]); err != nil {
		return err
	}
	return p.checkColumns()
}

// readSentence reads "The affected versions are 27, 25.0.4.1, 8u504, and
// earlier." into the affected version of each line.
func (p *page) readSentence(s string) error {
	rest := s[strings.Index(s, sentenceAt)+len(sentenceAt):]
	end := strings.Index(rest, sentenceTo)
	if end < 0 {
		return errors.New("the sentence of affected versions does not end with \"and earlier\"")
	}
	p.ceilings = map[int]version{}
	for _, el := range strings.Split(rest[:end], ", ") {
		v, ok := parseVersion(el)
		if !ok {
			return fmt.Errorf("unreadable affected version %q", clip(el))
		}
		if _, dup := p.ceilings[v.series()]; dup {
			return fmt.Errorf("two affected versions for line %d", v.series())
		}
		p.ceilings[v.series()] = v
	}
	return nil
}

// checkColumns reconciles the table's lines with the sentence's.
func (p *page) checkColumns() error {
	for _, c := range p.columns {
		if _, ok := p.ceilings[c]; ok {
			continue
		}
		if p.date == ceilingExceptionDate && c == ceilingExceptionSeries {
			p.ceilings[c] = version{parts: []int{c}}
			continue
		}
		p.noCeiling = append(p.noCeiling, c)
	}
	return nil
}

// --- the risk matrix ---

type cell struct {
	tag   string
	attrs map[string]string
	inner []token
}

func attrsEqual(got map[string]string, want ...string) bool {
	if len(got) != len(want)/2 {
		return false
	}
	for i := 0; i < len(want); i += 2 {
		if v, ok := got[want[i]]; !ok || v != want[i+1] {
			return false
		}
	}
	return true
}

// text returns the cell's content when it is plain text; "" for no content.
func (c cell) text() (string, bool) {
	switch len(c.inner) {
	case 0:
		return "", true
	case 1:
		if c.inner[0].kind == tokText {
			return c.inner[0].text, true
		}
	}
	return "", false
}

// readRows splits the tokens inside a table into rows of cells.
func readRows(toks []token) ([][]cell, error) {
	var rows [][]cell
	i := 0
	skip := func() {
		for i < len(toks) && isSpace(toks[i]) {
			i++
		}
	}
	for {
		skip()
		if i >= len(toks) {
			return rows, nil
		}
		if toks[i].kind != tokStart || toks[i].name != "tr" || len(toks[i].attrs) != 0 {
			return nil, errors.New("a table has something other than rows")
		}
		i++
		var cells []cell
		for {
			skip()
			if i >= len(toks) {
				return nil, errors.New("a row is not closed")
			}
			if toks[i].kind == tokEnd && toks[i].name == "tr" {
				i++
				break
			}
			t := toks[i]
			if t.kind != tokStart || (t.name != "td" && t.name != "th") {
				return nil, errors.New("a row has something other than cells")
			}
			c := cell{tag: t.name, attrs: t.attrs}
			i++
			closed := false
			for ; i < len(toks); i++ {
				if toks[i].kind == tokEnd && toks[i].name == c.tag {
					closed = true
					i++
					break
				}
				if toks[i].kind == tokStart && (toks[i].name == "td" || toks[i].name == "th" || toks[i].name == "tr") {
					return nil, errors.New("a cell is not closed")
				}
				c.inner = append(c.inner, toks[i])
			}
			if !closed {
				return nil, errors.New("a cell is not closed")
			}
			cells = append(cells, c)
		}
		rows = append(rows, cells)
	}
}

// readTable reads the JDK risk matrix: the "Affects" header row, the row of
// column names and line numbers, and one row per CVE.
func (p *page) readTable(table token, toks []token) error {
	if !attrsEqual(table.attrs, "class", "risk-matrix", "summary", "Risk matrix") {
		return errors.New("the risk matrix table has unexpected attributes")
	}
	rows, err := readRows(toks)
	if err != nil {
		return err
	}
	if len(rows) < 3 {
		return errors.New("the risk matrix has no rows")
	}
	if err := readAffectsRow(rows[0]); err != nil {
		return err
	}
	n, err := p.readColumnsRow(rows[1])
	if err != nil {
		return err
	}
	for _, r := range rows[2:] {
		if err := p.readCVERow(r, n); err != nil {
			return err
		}
	}
	if len(p.rows) == 0 && !p.none {
		return errors.New("the risk matrix has no CVEs")
	}
	if len(p.rows) > maxCVEsPerPage {
		return fmt.Errorf("more than %d CVEs", maxCVEsPerPage)
	}
	return nil
}

// readAffectsRow checks the "Affects ..." header row. Its colspan is only
// presentation (four of the pages count one column too few), so it is read
// as a number and nothing more.
func readAffectsRow(cells []cell) error {
	bad := errors.New("the first row of the risk matrix has an unexpected shape")
	if len(cells) != 4 {
		return bad
	}
	for _, c := range cells[:3] {
		if c.tag != "th" || len(c.attrs) != 0 || len(c.inner) != 0 {
			return bad
		}
	}
	c := cells[3]
	txt, ok := c.text()
	if c.tag != "th" || !ok || txt != "Affects ..." || len(c.attrs) != 1 {
		return bad
	}
	if n, err := strconv.Atoi(c.attrs["colspan"]); err != nil || n < 1 {
		return errors.New("the risk matrix has an unreadable column span")
	}
	return nil
}

// readColumnsRow reads the row of column names and the lines after them, and
// returns how many lines there are.
func (p *page) readColumnsRow(cells []cell) (int, error) {
	bad := errors.New("the column names of the risk matrix are unexpected")
	n := len(cells) - 3
	if n < 1 || n > maxSeriesColumns {
		return 0, bad
	}
	for i, want := range []string{"CVE ID", "Component"} {
		txt, ok := cells[i].text()
		if cells[i].tag != "th" || !attrsEqual(cells[i].attrs, "nowrap", "nowrap") || !ok || txt != want {
			return 0, bad
		}
	}
	// "CVSSv3.1<br />Vector": the score column.
	sc := cells[2]
	if sc.tag != "th" || len(sc.attrs) != 0 || len(sc.inner) != 5 {
		return 0, bad
	}
	a, label, end, br, vec := sc.inner[0], sc.inner[1], sc.inner[2], sc.inner[3], sc.inner[4]
	if a.kind != tokStart || a.name != "a" || !attrsEqual(a.attrs, "href", cvssLink) ||
		label.kind != tokText || (label.text != "CVSSv3" && label.text != "CVSSv3.1") ||
		end.kind != tokEnd || end.name != "a" || br.kind != tokVoid || br.name != "br" ||
		vec.kind != tokText || vec.text != "Vector" {
		return 0, bad
	}
	seen := map[int]bool{}
	for _, c := range cells[3:] {
		txt, ok := c.text()
		if c.tag != "th" || len(c.attrs) != 0 || !ok || !columnRe.MatchString(txt) {
			return 0, bad
		}
		series, _ := strconv.Atoi(txt)
		if seen[series] {
			return 0, fmt.Errorf("line %d has two columns in the risk matrix", series)
		}
		seen[series] = true
		p.order = append(p.order, series)
	}
	p.columns = append([]int(nil), p.order...)
	sort.Ints(p.columns)
	return n, nil
}

func (p *page) readCVERow(cells []cell, n int) error {
	if len(cells) != 3+n {
		return errors.New("a row of the risk matrix has an unexpected number of cells")
	}
	for i, c := range cells {
		if c.tag != "td" {
			return errors.New("a row of the risk matrix has a header cell")
		}
		if i < 2 && !attrsEqual(c.attrs, "nowrap", "nowrap") || i >= 2 && len(c.attrs) != 0 {
			return errors.New("a row of the risk matrix has unexpected cell attributes")
		}
	}
	marked := map[int]bool{}
	for i, c := range cells[3:] {
		txt, ok := c.text()
		if !ok || (txt != "" && txt != mark) {
			return fmt.Errorf("a row of the risk matrix has an unknown mark in column %d", i+1)
		}
		if txt == mark {
			marked[p.columnAt(i)] = true
		}
	}

	// The first cell is a link to the CVE, or "None" for an advisory
	// without CVEs.
	id := cells[0].inner
	if len(id) == 1 && id[0].kind == tokText && id[0].text == "None" {
		if p.none || len(p.rows) != 0 || len(marked) != 0 || len(cells[1].inner) != 0 || len(cells[2].inner) != 0 {
			return errors.New("a row of the risk matrix without a CVE is not empty")
		}
		p.none = true
		return nil
	}
	if len(id) != 3 || id[0].kind != tokStart || id[0].name != "a" || id[1].kind != tokText ||
		id[2].kind != tokEnd || id[2].name != "a" {
		return errors.New("the CVE cell of the risk matrix has an unexpected shape")
	}
	cve := id[1].text
	if !cveIDRe.MatchString(cve) || !attrsEqual(id[0].attrs, "href", nvdPrefix+cve) {
		return fmt.Errorf("unexpected CVE ID %q", clip(cve))
	}
	if p.none {
		return errors.New("a CVE row after a row without a CVE")
	}

	// "hotspot/<br />compiler", "core-libs", or "core-libs<br />".
	var comp strings.Builder
	for i, t := range cells[1].inner {
		switch {
		case t.kind == tokText && (i == 0 || i == 2):
			comp.WriteString(t.text)
		case t.kind == tokVoid && t.name == "br" && i == 1:
		default:
			return fmt.Errorf("%s: the component cell has an unexpected shape", cve)
		}
	}
	component := comp.String()
	if component == "" || len(component) > maxComponentLen || strings.ContainsFunc(component, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s: unreadable component", cve)
	}

	// "8.1<br />NHNNUHHH": the score; the vector is not read.
	sc := cells[2].inner
	if len(sc) != 3 || sc[0].kind != tokText || sc[1].kind != tokVoid || sc[1].name != "br" || sc[2].kind != tokText || sc[2].text == "" {
		return fmt.Errorf("%s: the score cell has an unexpected shape", cve)
	}
	if !scoreRe.MatchString(sc[0].text) {
		return fmt.Errorf("%s: unreadable score %q", cve, clip(sc[0].text))
	}
	whole, frac, _ := strings.Cut(sc[0].text, ".")
	score10 := 10*atoiSmall(whole) + atoiSmall(frac)
	if score10 > 100 {
		return fmt.Errorf("%s: score %q is above 10.0", cve, clip(sc[0].text))
	}
	p.rows = append(p.rows, row{cve: cve, component: component, score10: score10, marked: marked})
	return nil
}

// columnAt is the line of the i-th mark cell of a row.
func (p *page) columnAt(i int) int {
	return p.order[i]
}

func atoiSmall(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
