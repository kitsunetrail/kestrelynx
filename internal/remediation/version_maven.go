package remediation

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxMavenVersionBytes bounds the length of a version string.
const maxMavenVersionBytes = 128

// Maven orders versions with its ComparableVersion: a version is a list of
// numbers, qualifier strings and nested lists, and two versions are compared
// item by item. This is a port of that algorithm, so "5.2.24.RELEASE" equals
// "5.2.24", "11.0.0-M11" is below "11.0.0" and "32.0.0-android" is below
// "32.0.0-jre".

type mvnKind int

const (
	mvnInt mvnKind = iota
	mvnStr
	mvnList
)

// mvnItem is one element of a parsed version.
type mvnItem struct {
	kind mvnKind
	num  string     // mvnInt: decimal digits without leading zeros
	qual string     // mvnStr: the comparable form of the qualifier
	raw  string     // mvnStr: the qualifier after aliasing, lower case
	list []*mvnItem // mvnList
}

// mvnQualifiers are the known qualifiers in ascending order; the empty one is
// the release itself. Any other qualifier sorts above all of these.
var mvnQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// mvnReleaseIndex is the comparable form of the empty (release) qualifier.
const mvnReleaseIndex = "5"

// newMvnString builds a qualifier item. A lone a, b or m followed by a digit
// stands for alpha, beta or milestone.
func newMvnString(s string, followedByDigit bool) *mvnItem {
	if followedByDigit && len(s) == 1 {
		switch s[0] {
		case 'a':
			s = "alpha"
		case 'b':
			s = "beta"
		case 'm':
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	q := "7-" + s
	for i, k := range mvnQualifiers {
		if k == s {
			q = string(rune('0' + i))
			break
		}
	}
	return &mvnItem{kind: mvnStr, qual: q, raw: s}
}

func newMvnInt(digits string) *mvnItem {
	return &mvnItem{kind: mvnInt, num: trimZeros(digits)}
}

var mvnZero = &mvnItem{kind: mvnInt, num: "0"}

// isNull reports an item equal to a missing one: 0, the release qualifier or
// an empty list.
func (it *mvnItem) isNull() bool {
	switch it.kind {
	case mvnInt:
		return it.num == "0"
	case mvnStr:
		return it.qual == mvnReleaseIndex
	}
	return len(it.list) == 0
}

// normalize drops trailing null items, stopping at the last item that is
// neither null nor a list.
func (it *mvnItem) normalize() {
	for i := len(it.list) - 1; i >= 0; i-- {
		last := it.list[i]
		if last.isNull() {
			it.list = append(it.list[:i], it.list[i+1:]...)
		} else if last.kind != mvnList {
			break
		}
	}
}

// cmp compares the item with o, which is nil for a missing item.
func (it *mvnItem) cmp(o *mvnItem) int {
	switch it.kind {
	case mvnInt:
		switch {
		case o == nil:
			if it.num == "0" {
				return 0
			}
			return 1
		case o.kind == mvnInt:
			return cmpNum(it.num, o.num)
		}
		return 1
	case mvnStr:
		switch {
		case o == nil:
			return strings.Compare(it.qual, mvnReleaseIndex)
		case o.kind == mvnStr:
			return strings.Compare(it.qual, o.qual)
		}
		return -1
	}
	// list
	if o == nil {
		for _, x := range it.list {
			if c := x.cmp(nil); c != 0 {
				return c
			}
		}
		return 0
	}
	switch o.kind {
	case mvnInt:
		return -1
	case mvnStr:
		return 1
	}
	for i := 0; i < len(it.list) || i < len(o.list); i++ {
		var l, r *mvnItem
		if i < len(it.list) {
			l = it.list[i]
		}
		if i < len(o.list) {
			r = o.list[i]
		}
		var c int
		switch {
		case l == nil:
			c = -r.cmp(nil)
		default:
			c = l.cmp(r)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

// mavenVersion is a parsed Maven version.
type mavenVersion struct {
	root *mvnItem
}

func (a mavenVersion) compare(o version) int {
	return a.root.cmp(o.(mavenVersion).root)
}

// mavenVersionOK reports a string Maven's ComparableVersion would take as a
// version here: non-empty, short, valid UTF-8, with no whitespace or control
// characters.
func mavenVersionOK(s string) bool {
	if s == "" || len(s) > maxMavenVersionBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseMavenVersion parses s the way ComparableVersion does.
func parseMavenVersion(s string) (mavenVersion, bool) {
	if !mavenVersionOK(s) {
		return mavenVersion{}, false
	}
	s = strings.ToLower(s)
	root := &mvnItem{kind: mvnList}
	list := root
	lists := []*mvnItem{root} // every list, parents before children
	push := func() {
		n := &mvnItem{kind: mvnList}
		list.list = append(list.list, n)
		list = n
		lists = append(lists, n)
	}
	item := func(digit bool, text string) *mvnItem {
		if digit {
			return newMvnInt(text)
		}
		return newMvnString(text, false)
	}
	isDigit := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if i == start {
				list.list = append(list.list, mvnZero)
			} else {
				list.list = append(list.list, item(isDigit, s[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.list = append(list.list, mvnZero)
			} else {
				list.list = append(list.list, item(isDigit, s[start:i]))
			}
			start = i + 1
			push()
		case isASCIIDigit(c):
			if !isDigit && i > start {
				// "1.0.0.X1" is read as "1.0.0-X1".
				if len(list.list) > 0 {
					push()
				}
				list.list = append(list.list, newMvnString(s[start:i], true))
				start = i
				push()
			}
			isDigit = true
		default:
			if isDigit && i > start {
				list.list = append(list.list, newMvnInt(s[start:i]))
				start = i
				push()
			}
			isDigit = false
		}
	}
	if len(s) > start {
		if !isDigit && len(list.list) > 0 {
			push()
		}
		list.list = append(list.list, item(isDigit, s[start:]))
	}
	for i := len(lists) - 1; i >= 0; i-- {
		lists[i].normalize()
	}
	return mavenVersion{root: root}, true
}

// mavenIsPrerelease reports a version with a qualifier that orders below the
// release: alpha, beta, milestone, rc (cr) or snapshot, including the a, b
// and m forms before a digit.
func mavenIsPrerelease(v string) bool {
	mv, ok := parseMavenVersion(v)
	if !ok {
		return false
	}
	var walk func(it *mvnItem) bool
	walk = func(it *mvnItem) bool {
		switch it.kind {
		case mvnStr:
			return it.qual < mvnReleaseIndex
		case mvnList:
			for _, x := range it.list {
				if walk(x) {
					return true
				}
			}
		}
		return false
	}
	return walk(mv.root)
}

// mavenMajor returns the leading number of v as a decimal string without
// leading zeros; ok is false when v does not start with a digit.
func mavenMajor(v string) (string, bool) {
	n := 0
	for n < len(v) && isASCIIDigit(v[n]) {
		n++
	}
	if n == 0 {
		return "", false
	}
	return trimZeros(v[:n]), true
}

// mavenFlavor returns the suffix after the last '-' of v when it is a plain
// word that names a variant ("jre", "android") rather than a stage of the
// release: not a pre-release or release qualifier, not a service pack. It is
// empty otherwise.
func mavenFlavor(v string) string {
	i := strings.LastIndexByte(v, '-')
	if i <= 0 || i == len(v)-1 {
		return ""
	}
	suffix := strings.ToLower(v[i+1:])
	for j := 0; j < len(suffix); j++ {
		if suffix[j] < 'a' || suffix[j] > 'z' {
			return ""
		}
	}
	q := newMvnString(suffix, false)
	if q.qual <= "6" { // a known qualifier: alpha ... release, sp
		return ""
	}
	return suffix
}
