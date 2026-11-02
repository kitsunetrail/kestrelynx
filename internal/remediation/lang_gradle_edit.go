package remediation

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The edits of a Gradle project's files are made on the text, so that the
// layout and the comments of the file stay as they are. Each edit finds the
// one place it is for and refuses when there is not exactly one; the caller
// reads the result again with the recognizers of the plan and compares it
// with what the edit was meant to do.

const utf8BOM = "\xef\xbb\xbf"

// gradleScriptText cuts a build script into tokens for an edit. text is the
// script without its byte order mark, the string the offsets of the tokens
// are in.
func gradleScriptText(src []byte, kotlin bool) (text string, toks []gradleTok, err error) {
	toks, err = lexGradle(src, kotlin)
	if err != nil {
		return "", nil, err
	}
	return strings.TrimPrefix(string(src), utf8BOM), toks, nil
}

// withBOM gives back the byte order mark the original script had.
func withBOM(orig []byte, text string) []byte {
	if bytes.HasPrefix(orig, []byte(utf8BOM)) {
		return append([]byte(utf8BOM), text...)
	}
	return []byte(text)
}

// replaceGradleCoordinate changes the version of the one string
// "name:from" the script holds, in any statement. It refuses a script that
// holds the string more than once, or not at all: a copy elsewhere would be
// left at the old version, or the declaration is not the one the plan read.
func replaceGradleCoordinate(src []byte, kotlin bool, name, from, to string) ([]byte, error) {
	text, toks, err := gradleScriptText(src, kotlin)
	if err != nil {
		return nil, err
	}
	want := name + ":" + from
	var hit []gradleTok
	for _, t := range toks {
		if t.kind == gtString && t.text == want {
			hit = append(hit, t)
		}
	}
	if len(hit) != 1 {
		return nil, fmt.Errorf("the script holds the string %q %d times, and the edit needs exactly one", want, len(hit))
	}
	t := hit[0]
	// The string without its quotes sits between the offsets.
	out := text[:t.start+1] + name + ":" + to + text[t.end-1:]
	return withBOM(src, out), nil
}

// setGradleExtra changes the value of the one property the script sets with
// extra["name"] = "from" (Kotlin) or ext["name"] = "from" and ext.name =
// "from" (Groovy).
func setGradleExtra(src []byte, kotlin bool, name, from, to string) ([]byte, error) {
	text, toks, err := gradleScriptText(src, kotlin)
	if err != nil {
		return nil, err
	}
	holder := "ext"
	if kotlin {
		holder = "extra"
	}
	var hit []gradleTok
	for i := range toks {
		if !toks[i].plainIdent(holder) {
			continue
		}
		rest := toks[i+1:]
		var val gradleTok
		switch {
		case len(rest) >= 5 && rest[0].isPunct("[") && rest[1].kind == gtString && rest[1].text == name && rest[2].isPunct("]") && rest[3].isPunct("=") && rest[4].kind == gtString:
			val = rest[4]
		case !kotlin && len(rest) >= 4 && rest[0].isPunct(".") && rest[1].kind == gtIdent && rest[1].text == name && rest[2].isPunct("=") && rest[3].kind == gtString:
			val = rest[3]
		default:
			continue
		}
		hit = append(hit, val)
	}
	if len(hit) != 1 {
		return nil, fmt.Errorf("the script sets the property %q %d times, and the edit needs exactly one", name, len(hit))
	}
	t := hit[0]
	if t.text != from {
		return nil, fmt.Errorf("the property %q is %q in the script, not %q", name, t.text, from)
	}
	return withBOM(src, text[:t.start+1]+to+text[t.end-1:]), nil
}

// gradleConstraint is a dependency constraint the update adds.
type gradleConstraint struct{ name, version string }

// appendGradleConstraints adds a dependencies block with one constraint on
// implementation for each entry at the end of the script, and touches
// nothing else. The line breaks and the indentation follow the script.
func appendGradleConstraints(src []byte, kotlin bool, cs []gradleConstraint) []byte {
	text := strings.TrimPrefix(string(src), utf8BOM)
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	unit := "    "
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "\t") {
			unit = "\t"
			break
		}
		if strings.HasPrefix(l, " ") {
			break
		}
	}
	sorted := append([]gradleConstraint(nil), cs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	var b strings.Builder
	b.WriteString(text)
	if text != "" && !strings.HasSuffix(text, "\n") {
		b.WriteString(eol)
	}
	b.WriteString(eol + "dependencies {" + eol + unit + "constraints {" + eol)
	for _, c := range sorted {
		if kotlin {
			fmt.Fprintf(&b, "%s%simplementation(%q)%s", unit, unit, c.name+":"+c.version, eol)
		} else {
			fmt.Fprintf(&b, "%s%simplementation '%s'%s", unit, unit, c.name+":"+c.version, eol)
		}
	}
	b.WriteString(unit + "}" + eol + "}" + eol)
	return withBOM(src, b.String())
}

// setPropertiesValue changes the value of the key gradle.properties sets,
// which must be "from" now.
func setPropertiesValue(src []byte, key, from, to string) ([]byte, error) {
	props, err := parseJavaProperties(src, "")
	if err != nil {
		return nil, err
	}
	line := 0
	for _, p := range props {
		if p.key == key {
			if p.value != from {
				return nil, fmt.Errorf("%s is %q in gradle.properties, not %q", key, p.value, from)
			}
			line = p.line
		}
	}
	if line == 0 {
		return nil, fmt.Errorf("gradle.properties does not set %s", key)
	}
	text := strings.TrimPrefix(string(src), utf8BOM)
	lines := strings.Split(text, "\n")
	raw := lines[line-1]
	cr := ""
	if strings.HasSuffix(raw, "\r") {
		raw, cr = strings.TrimSuffix(raw, "\r"), "\r"
	}
	// The value starts where the parser starts it: after the key, the blanks,
	// one separator and the blanks again.
	i := 0
	for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\f') {
		i++
	}
	i += len(key)
	for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\f') {
		i++
	}
	if i < len(raw) && (raw[i] == '=' || raw[i] == ':') {
		i++
	}
	for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\f') {
		i++
	}
	if raw[i:] != from {
		return nil, fmt.Errorf("line %d of gradle.properties is not the one for %s", line, key)
	}
	lines[line-1] = raw[:i] + to + cr
	return withBOM(src, strings.Join(lines, "\n")), nil
}

// appendProperty adds "key=value" at the end of gradle.properties; src is
// nil for a file that does not exist yet.
func appendProperty(src []byte, key, value string) []byte {
	text := strings.TrimPrefix(string(src), utf8BOM)
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	var b strings.Builder
	b.WriteString(text)
	if text != "" && !strings.HasSuffix(text, "\n") {
		b.WriteString(eol)
	}
	b.WriteString(key + "=" + value + eol)
	return withBOM(src, b.String())
}

var (
	tomlHeaderRe = regexp.MustCompile(`^\s*\[([^\[\]]*)\]\s*(#.*)?$`)
	// tomlVersionLineRe matches a version of [versions] written as a basic
	// string: key = "value".
	tomlStringLineRe = `^(\s*)(["']?)%s(["']?)(\s*=\s*)"([^"\\]*)"(\s*(#.*)?)$`
	tomlInlineVerRe  = regexp.MustCompile(`(\bversion\s*=\s*)"([^"\\]*)"`)
)

// catalogLines cuts the catalog into lines and gives, for each, the table
// it is in. It refuses a catalog written in forms the edit does not follow:
// multi-line strings, and arrays of tables.
func catalogLines(src []byte) (lines []string, sections []string, err error) {
	text := strings.TrimPrefix(string(src), utf8BOM)
	if strings.Contains(text, `"""`) || strings.Contains(text, `'''`) {
		return nil, nil, errors.New("the catalog has a multi-line string")
	}
	lines = strings.Split(text, "\n")
	section := ""
	for _, l := range lines {
		trimmed := strings.TrimRight(l, "\r")
		if t := strings.TrimSpace(trimmed); strings.HasPrefix(t, "[[") {
			return nil, nil, errors.New("the catalog has an array of tables")
		}
		if m := tomlHeaderRe.FindStringSubmatch(trimmed); m != nil {
			section = strings.TrimSpace(m[1])
		}
		sections = append(sections, section)
	}
	return lines, sections, nil
}

// setCatalogVersion changes the value of one entry of [versions].
func setCatalogVersion(src []byte, name, from, to string) ([]byte, error) {
	lines, sections, err := catalogLines(src)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(fmt.Sprintf(tomlStringLineRe, regexp.QuoteMeta(name)))
	hit := -1
	for i, l := range lines {
		if sections[i] != "versions" {
			continue
		}
		m := re.FindStringSubmatch(strings.TrimRight(l, "\r"))
		if m == nil {
			continue
		}
		if hit >= 0 {
			return nil, fmt.Errorf("the version %q is set twice in [versions]", name)
		}
		if m[5] != from {
			return nil, fmt.Errorf("the version %q is %q in the catalog, not %q", name, m[5], from)
		}
		hit = i
	}
	if hit < 0 {
		return nil, fmt.Errorf("[versions] has no entry %q written as key = \"value\"", name)
	}
	cr := ""
	l := lines[hit]
	if strings.HasSuffix(l, "\r") {
		l, cr = strings.TrimSuffix(l, "\r"), "\r"
	}
	m := re.FindStringSubmatch(l)
	lines[hit] = m[1] + m[2] + name + m[3] + m[4] + `"` + to + `"` + m[6] + cr
	return withBOM(src, strings.Join(lines, "\n")), nil
}

// setCatalogLibrary changes the version a library of [libraries] writes
// itself: the version of "group:artifact:version", or the version = "..." of
// an inline table.
func setCatalogLibrary(src []byte, alias, name, from, to string) ([]byte, error) {
	lines, sections, err := catalogLines(src)
	if err != nil {
		return nil, err
	}
	keyRe := regexp.MustCompile(`^(\s*)(["']?)` + regexp.QuoteMeta(alias) + `(["']?)(\s*=\s*)(.*)$`)
	hit := -1
	var rest []string
	for i, l := range lines {
		if sections[i] != "libraries" {
			continue
		}
		m := keyRe.FindStringSubmatch(strings.TrimRight(l, "\r"))
		if m == nil {
			continue
		}
		if hit >= 0 {
			return nil, fmt.Errorf("the library %q is set twice", alias)
		}
		hit, rest = i, m
	}
	if hit < 0 {
		return nil, fmt.Errorf("[libraries] has no entry %q on one line", alias)
	}
	value := rest[5]
	cr := ""
	if strings.HasSuffix(lines[hit], "\r") {
		cr = "\r"
	}
	var newValue string
	switch {
	case strings.HasPrefix(value, `"`+name+":"+from+`"`):
		newValue = `"` + name + ":" + to + `"` + strings.TrimPrefix(value, `"`+name+":"+from+`"`)
	case strings.HasPrefix(strings.TrimSpace(value), "{"):
		ms := tomlInlineVerRe.FindAllStringSubmatchIndex(value, -1)
		if len(ms) != 1 {
			return nil, fmt.Errorf("the library %q has %d literal versions", alias, len(ms))
		}
		m := ms[0]
		if got := value[m[4]:m[5]]; got != from {
			return nil, fmt.Errorf("the library %q is at %q in the catalog, not %q", alias, got, from)
		}
		newValue = value[:m[4]] + to + value[m[5]:]
	default:
		return nil, fmt.Errorf("the library %q is not written as a string or an inline table", alias)
	}
	lines[hit] = rest[1] + rest[2] + alias + rest[3] + rest[4] + newValue + cr
	return withBOM(src, strings.Join(lines, "\n")), nil
}
