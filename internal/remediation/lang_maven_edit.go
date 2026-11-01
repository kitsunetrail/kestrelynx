package remediation

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file edits a pom.xml without reformatting it. The elements are located
// by their byte offsets, only the character data of a version or property is
// replaced and new elements are inserted as whole lines, so everything else
// (comments, blank lines, attribute layout, line endings) stays as it was.
// After the edit both files are read again and must differ by the edits and
// nothing more.

// mavenEditKind says what one edit of a pom.xml does.
type mavenEditKind int

const (
	mavenEditDependencyVersion mavenEditKind = iota // the <version> text of the Index-th top-level <dependencies> entry
	mavenEditManagedVersion                         // the <version> text of the Index-th <dependencyManagement><dependencies> entry
	mavenSetProperty                                // set top-level <properties><Name> to Value, adding it when absent
	mavenAddManaged                                 // add a <dependency> with GroupID, ArtifactID, Value as version first in <dependencyManagement><dependencies>
)

// mavenEdit is one edit. Index counts the entries of the original file.
type mavenEdit struct {
	Kind                mavenEditKind
	Index               int
	Name, Value         string
	GroupID, ArtifactID string
}

var mavenPropertyNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// maxMavenEditValue bounds a version, a property value and a coordinate.
const maxMavenEditValue = 256

// validMavenEditValue accepts the text of a version or a coordinate: not
// empty, short, without whitespace, control characters or markup characters,
// so that it never needs escaping.
func validMavenEditValue(s string) bool {
	if s == "" || len(s) > maxMavenEditValue || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("<>&\"'", r) {
			return false
		}
	}
	return true
}

func validateMavenEdit(e mavenEdit) error {
	switch e.Kind {
	case mavenEditDependencyVersion, mavenEditManagedVersion:
		if e.Index < 0 {
			return fmt.Errorf("pom edit has a negative index %d", e.Index)
		}
	case mavenSetProperty:
		if !mavenPropertyNameRE.MatchString(e.Name) || len(e.Name) > maxMavenEditValue {
			return fmt.Errorf("pom edit has an invalid property name %q", e.Name)
		}
	case mavenAddManaged:
		if !validMavenEditValue(e.GroupID) {
			return fmt.Errorf("pom edit has an invalid groupId %q", e.GroupID)
		}
		if !validMavenEditValue(e.ArtifactID) {
			return fmt.Errorf("pom edit has an invalid artifactId %q", e.ArtifactID)
		}
	default:
		return fmt.Errorf("pom edit has an unknown kind %d", e.Kind)
	}
	if !validMavenEditValue(e.Value) {
		return fmt.Errorf("pom edit has an invalid value %q", e.Value)
	}
	return nil
}

// --- locating elements ---

// pomEl is an element of the document with the byte offsets of its tags.
type pomEl struct {
	local, raw  string // local name; the name as written, with any prefix
	prefixed    bool
	start       int // offset of '<' of the start tag
	openEnd     int // offset after the start tag
	closeStart  int // offset of the end tag; equals end for a self-closing element
	end         int // offset after the element
	selfClosing bool
	children    []*pomEl
}

// pomScan is a document with the offsets of its elements and the layout
// conventions (line ending, indent unit) its new lines follow.
type pomScan struct {
	data      []byte
	root      *pomEl
	eol, unit string
}

func (e *pomEl) kids(local string) []*pomEl {
	var out []*pomEl
	for _, c := range e.children {
		if c.local == local {
			out = append(out, c)
		}
	}
	return out
}

// unique returns the only child named local, nil when there is none. Several
// of them, or one with a namespace prefix, are an error.
func (e *pomEl) unique(local string) (*pomEl, error) {
	ks := e.kids(local)
	switch {
	case len(ks) == 0:
		return nil, nil
	case len(ks) > 1:
		return nil, fmt.Errorf("pom has more than one <%s> in <%s>", local, e.local)
	case ks[0].prefixed:
		return nil, fmt.Errorf("pom element <%s> carries a namespace prefix", ks[0].raw)
	}
	return ks[0], nil
}

func scanPOMOffsets(data []byte) (*pomScan, error) {
	if len(data) > maxMavenPOMBytes {
		return nil, fmt.Errorf("pom is larger than %d bytes", maxMavenPOMBytes)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	recoded := false
	dec.CharsetReader = func(label string, in io.Reader) (io.Reader, error) {
		recoded = true
		return pomCharsetReader(label, in)
	}
	var root *pomEl
	var stack []*pomEl
	for {
		before := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("pom is not well-formed XML: %w", err)
		}
		after := int(dec.InputOffset())
		if before < 0 || before > after || after > len(data) {
			return nil, errors.New("pom offsets cannot be followed")
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, errors.New("pom has a DOCTYPE, which is refused")
		case xml.StartElement:
			if len(stack) >= maxMavenPOMDepth {
				return nil, errors.New("pom is nested too deeply")
			}
			tag := data[before:after]
			if len(tag) < 2 || tag[0] != '<' {
				return nil, errors.New("pom offsets cannot be followed")
			}
			nameEnd := bytes.IndexAny(tag[1:], " \t\r\n/>")
			if nameEnd < 0 {
				return nil, errors.New("pom offsets cannot be followed")
			}
			raw := string(tag[1 : 1+nameEnd])
			n := &pomEl{
				local:       t.Name.Local,
				raw:         raw,
				prefixed:    strings.Contains(raw, ":"),
				start:       before,
				openEnd:     after,
				selfClosing: bytes.HasSuffix(tag, []byte("/>")),
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, errors.New("pom has more than one root element")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			n.end = after
			if n.selfClosing {
				n.closeStart = after
			} else {
				n.closeStart = before
			}
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errors.New("pom has no complete root element")
	}
	if recoded && bytes.ContainsFunc(data, func(r rune) bool { return r >= 0x80 }) {
		return nil, errors.New("pom declares a non-UTF-8 encoding and holds non-ASCII bytes, whose offsets cannot be followed")
	}
	if root.local != "project" || root.prefixed {
		return nil, fmt.Errorf("pom root element is %q, not an unprefixed project", root.raw)
	}
	return &pomScan{data: data, root: root, eol: detectPOMEOL(data), unit: detectPOMIndentUnit(data)}, nil
}

func detectPOMEOL(data []byte) string {
	if i := bytes.IndexByte(data, '\n'); i > 0 && data[i-1] == '\r' {
		return "\r\n"
	}
	return "\n"
}

// detectPOMIndentUnit reads the indent unit from the lines that start an
// element: a tab when any of them is indented by a tab, else the smallest
// positive number of spaces, else two spaces.
func detectPOMIndentUnit(data []byte) string {
	smallest := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 || (line[0] != ' ' && line[0] != '\t') {
			continue
		}
		rest := bytes.TrimLeft(line, " \t")
		if len(rest) == 0 || rest[0] != '<' {
			continue
		}
		if line[0] == '\t' {
			return "\t"
		}
		if n := len(line) - len(rest); smallest == 0 || n < smallest {
			smallest = n
		}
	}
	if smallest <= 0 || smallest > 8 {
		return "  "
	}
	return strings.Repeat(" ", smallest)
}

// lineIndent returns the whitespace between the start of the line and off,
// and false when something else precedes off on its line.
func (s *pomScan) lineIndent(off int) (string, bool) {
	i := off
	for i > 0 && s.data[i-1] != '\n' {
		i--
	}
	seg := s.data[i:off]
	if len(bytes.Trim(seg, " \t")) != 0 {
		return "", false
	}
	return string(seg), true
}

// --- spans ---

// pomSpan replaces data[start:end] by text. Insertions have start == end.
type pomSpan struct {
	start, end int
	text       string
	prio       int // order of insertions at the same offset
}

// textSpan replaces the whole character data of an element that holds text
// only.
func (s *pomScan) textSpan(el *pomEl, value string) (pomSpan, error) {
	if el.selfClosing {
		return s.expandSpan(el, ">"+value+"</"+el.raw+">"), nil
	}
	if bytes.IndexByte(s.data[el.openEnd:el.closeStart], '<') >= 0 {
		return pomSpan{}, fmt.Errorf("pom element <%s> holds a comment, CDATA or child element", el.raw)
	}
	return pomSpan{start: el.openEnd, end: el.closeStart, text: value}, nil
}

// expandSpan turns a self-closing element into an open tag followed by
// content, keeping its attributes.
func (s *pomScan) expandSpan(el *pomEl, tail string) pomSpan {
	tag := s.data[el.start:el.openEnd]
	j := len(tag) - 2
	for j > 0 && (tag[j-1] == ' ' || tag[j-1] == '\t') {
		j--
	}
	return pomSpan{start: el.start + j, end: el.end, text: tail}
}

func joinPOMLines(lines []string, ind, eol string) string {
	return strings.Join(lines, eol+ind)
}

func prefixPOMLines(lines []string, p string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = p + l
	}
	return out
}

// containerInsert adds items (each a list of lines) as children of c: first
// when atStart, else last.
func (s *pomScan) containerInsert(c *pomEl, atStart bool, items [][]string, prio int) pomSpan {
	cInd, _ := s.lineIndent(c.start)
	if len(c.children) == 0 {
		ind := cInd + s.unit
		var body strings.Builder
		for _, it := range items {
			body.WriteString(s.eol + ind + joinPOMLines(it, ind, s.eol))
		}
		var sp pomSpan
		switch {
		case c.selfClosing:
			sp = s.expandSpan(c, ">"+body.String()+s.eol+cInd+"</"+c.raw+">")
		case len(bytes.TrimSpace(s.data[c.openEnd:c.closeStart])) == 0:
			sp = pomSpan{start: c.openEnd, end: c.closeStart, text: body.String() + s.eol + cInd}
		default:
			sp = pomSpan{start: c.openEnd, end: c.openEnd, text: body.String()}
		}
		sp.prio = prio
		return sp
	}
	ref, pos := c.children[len(c.children)-1], c.children[len(c.children)-1].end
	if atStart {
		ref, pos = c.children[0], c.openEnd
	}
	ind, ok := s.lineIndent(ref.start)
	if !ok {
		ind = cInd + s.unit
	}
	var body strings.Builder
	for _, it := range items {
		body.WriteString(s.eol + ind + joinPOMLines(it, ind, s.eol))
	}
	return pomSpan{start: pos, end: pos, text: body.String(), prio: prio}
}

// insertBefore puts a block of lines on its own lines before anchor.
func (s *pomScan) insertBefore(anchor *pomEl, lines []string, prio int) pomSpan {
	ind, _ := s.lineIndent(anchor.start)
	return pomSpan{start: anchor.start, end: anchor.start, text: joinPOMLines(lines, ind, s.eol) + s.eol + ind, prio: prio}
}

// firstChild returns the first child of the root named one of names, in
// document order.
func (s *pomScan) firstChild(names ...string) *pomEl {
	for _, c := range s.root.children {
		if slices.Contains(names, c.local) {
			return c
		}
	}
	return nil
}

func (s *pomScan) depLines(g, a, v string) []string {
	return []string{
		"<dependency>",
		s.unit + "<groupId>" + g + "</groupId>",
		s.unit + "<artifactId>" + a + "</artifactId>",
		s.unit + "<version>" + v + "</version>",
		"</dependency>",
	}
}

// applyMavenEdits applies the edits to one pom file and checks the result
// (see verifyMavenEdits). The bytes outside the changed spans are kept.
func applyMavenEdits(data []byte, edits []mavenEdit) ([]byte, error) {
	if len(edits) > maxManifestEdits {
		return nil, errManifestEditLimit
	}
	for _, e := range edits {
		if err := validateMavenEdit(e); err != nil {
			return nil, err
		}
	}
	s, err := scanPOMOffsets(data)
	if err != nil {
		return nil, err
	}
	var spans []pomSpan
	touched := map[*pomEl]bool{}
	named := map[string]bool{}
	var newProps []mavenEdit
	var adds []mavenEdit
	var props *pomEl
	propsLooked := false

	versionEdit := func(container *pomEl, idx int, value string) error {
		if container == nil {
			return fmt.Errorf("pom has no dependency at index %d", idx)
		}
		deps := container.kids("dependency")
		if idx >= len(deps) {
			return fmt.Errorf("pom has no dependency at index %d", idx)
		}
		dep := deps[idx]
		if dep.prefixed {
			return fmt.Errorf("pom element <%s> carries a namespace prefix", dep.raw)
		}
		v, err := dep.unique("version")
		if err != nil {
			return err
		}
		if v == nil {
			return fmt.Errorf("pom dependency at index %d has no <version>", idx)
		}
		if touched[v] {
			return fmt.Errorf("pom edits the version of dependency %d twice", idx)
		}
		touched[v] = true
		sp, err := s.textSpan(v, value)
		if err != nil {
			return err
		}
		spans = append(spans, sp)
		return nil
	}

	for _, e := range edits {
		switch e.Kind {
		case mavenEditDependencyVersion:
			c, err := s.root.unique("dependencies")
			if err != nil {
				return nil, err
			}
			if err := versionEdit(c, e.Index, e.Value); err != nil {
				return nil, err
			}
		case mavenEditManagedVersion:
			dm, err := s.root.unique("dependencyManagement")
			if err != nil {
				return nil, err
			}
			var c *pomEl
			if dm != nil {
				if c, err = dm.unique("dependencies"); err != nil {
					return nil, err
				}
			}
			if err := versionEdit(c, e.Index, e.Value); err != nil {
				return nil, err
			}
		case mavenSetProperty:
			if named[e.Name] {
				return nil, fmt.Errorf("pom sets property %q twice", e.Name)
			}
			named[e.Name] = true
			if !propsLooked {
				propsLooked = true
				if props, err = s.root.unique("properties"); err != nil {
					return nil, err
				}
			}
			var existing []*pomEl
			if props != nil {
				existing = props.kids(e.Name)
			}
			switch {
			case len(existing) > 1:
				return nil, fmt.Errorf("pom declares property %q more than once", e.Name)
			case len(existing) == 1:
				if existing[0].prefixed {
					return nil, fmt.Errorf("pom element <%s> carries a namespace prefix", existing[0].raw)
				}
				sp, err := s.textSpan(existing[0], e.Value)
				if err != nil {
					return nil, err
				}
				spans = append(spans, sp)
			default:
				newProps = append(newProps, e)
			}
		case mavenAddManaged:
			adds = append(adds, e)
		}
	}

	if len(newProps) > 0 {
		var items [][]string
		for _, e := range newProps {
			items = append(items, []string{"<" + e.Name + ">" + e.Value + "</" + e.Name + ">"})
		}
		if props != nil {
			spans = append(spans, s.containerInsert(props, false, items, 0))
		} else {
			lines := []string{"<properties>"}
			for _, it := range items {
				lines = append(lines, prefixPOMLines(it, s.unit)...)
			}
			lines = append(lines, "</properties>")
			if anchor := s.firstChild("dependencyManagement", "dependencies", "build"); anchor != nil {
				spans = append(spans, s.insertBefore(anchor, lines, 0))
			} else {
				spans = append(spans, s.containerInsert(s.root, false, [][]string{lines}, 0))
			}
		}
	}

	if len(adds) > 0 {
		var items [][]string
		for _, e := range adds {
			items = append(items, s.depLines(e.GroupID, e.ArtifactID, e.Value))
		}
		dm, err := s.root.unique("dependencyManagement")
		if err != nil {
			return nil, err
		}
		var deps *pomEl
		if dm != nil {
			if deps, err = dm.unique("dependencies"); err != nil {
				return nil, err
			}
		}
		wrapDeps := func() []string {
			lines := []string{"<dependencies>"}
			for _, it := range items {
				lines = append(lines, prefixPOMLines(it, s.unit)...)
			}
			return append(lines, "</dependencies>")
		}
		switch {
		case deps != nil:
			spans = append(spans, s.containerInsert(deps, true, items, 1))
		case dm != nil:
			spans = append(spans, s.containerInsert(dm, true, [][]string{wrapDeps()}, 1))
		default:
			lines := append([]string{"<dependencyManagement>"}, prefixPOMLines(wrapDeps(), s.unit)...)
			lines = append(lines, "</dependencyManagement>")
			anchor := s.firstChild("dependencies")
			if anchor == nil {
				anchor = s.firstChild("build")
			}
			if anchor != nil {
				spans = append(spans, s.insertBefore(anchor, lines, 1))
			} else {
				spans = append(spans, s.containerInsert(s.root, false, [][]string{lines}, 1))
			}
		}
	}

	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].prio < spans[j].prio
	})
	var out bytes.Buffer
	pos := 0
	for _, sp := range spans {
		if sp.start < pos {
			return nil, errors.New("pom edits touch the same element")
		}
		out.Write(data[pos:sp.start])
		out.WriteString(sp.text)
		pos = sp.end
	}
	out.Write(data[pos:])
	result := out.Bytes()
	if err := verifyMavenEdits(data, result, edits); err != nil {
		return nil, err
	}
	return result, nil
}

// verifyMavenEdits parses both files and requires the models to differ by
// exactly the edits: every field of mavenPOM equal except the edited version
// texts, the set or added properties (names and values exactly as asked; no
// other property changed, added or removed), and the added managed
// dependencies (first in DependencyManagement, in the order given, the rest
// unchanged).
func verifyMavenEdits(before, after []byte, edits []mavenEdit) error {
	pb, err := parseMavenPOM(before)
	if err != nil {
		return fmt.Errorf("pom before the edit: %w", err)
	}
	pa, err := parseMavenPOM(after)
	if err != nil {
		return fmt.Errorf("pom after the edit: %w", err)
	}
	want := *pb
	want.Dependencies = slices.Clone(pb.Dependencies)
	want.DependencyManagement = slices.Clone(pb.DependencyManagement)
	want.PropertyOrder = slices.Clone(pb.PropertyOrder)
	want.Properties = make(map[string]string, len(pb.Properties)+len(edits))
	for k, v := range pb.Properties {
		want.Properties[k] = v
	}
	var added []mavenDep
	for _, e := range edits {
		if err := validateMavenEdit(e); err != nil {
			return err
		}
		switch e.Kind {
		case mavenEditDependencyVersion:
			if e.Index >= len(want.Dependencies) {
				return fmt.Errorf("pom has no dependency at index %d", e.Index)
			}
			want.Dependencies[e.Index].Version = e.Value
		case mavenEditManagedVersion:
			if e.Index >= len(want.DependencyManagement) {
				return fmt.Errorf("pom has no managed dependency at index %d", e.Index)
			}
			want.DependencyManagement[e.Index].Version = e.Value
		case mavenSetProperty:
			if _, ok := want.Properties[e.Name]; !ok {
				want.PropertyOrder = append(want.PropertyOrder, e.Name)
			}
			want.Properties[e.Name] = e.Value
		case mavenAddManaged:
			added = append(added, mavenDep{GroupID: e.GroupID, ArtifactID: e.ArtifactID, Version: e.Value})
		}
	}
	if len(added) > 0 {
		want.DependencyManagement = append(added, want.DependencyManagement...)
	}
	if reflect.DeepEqual(&want, pa) {
		return nil
	}
	wv, av := reflect.ValueOf(want), reflect.ValueOf(*pa)
	for i := 0; i < wv.NumField(); i++ {
		if !reflect.DeepEqual(wv.Field(i).Interface(), av.Field(i).Interface()) {
			return fmt.Errorf("pom differs from the requested edits in %s", wv.Type().Field(i).Name)
		}
	}
	return errors.New("pom differs from the requested edits")
}
