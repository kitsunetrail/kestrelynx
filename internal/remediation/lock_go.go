package remediation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Reasons of the Go modules part.
const (
	// ReasonGoReplace: go.mod has a replace directive. A local replacement
	// is not in the inputs and cannot be reproduced; one to another module
	// changes what is resolved in a way the plan does not follow.
	ReasonGoReplace Reason = "go_replace_unsupported"
	// ReasonGoExclude: go.mod has an exclude directive, which changes the
	// version that is selected.
	ReasonGoExclude Reason = "go_exclude_unsupported"
	// ReasonGoVersionTooOld: go.mod declares no go version, or one below
	// 1.21; such a go.mod need not list every module the build uses.
	ReasonGoVersionTooOld Reason = "go_version_too_old"
	// ReasonGoToolchainUnsupported: the toolchain line is not a released
	// Go version (default, a custom suffix, a release candidate).
	ReasonGoToolchainUnsupported Reason = "go_toolchain_unsupported"
	// ReasonGoBinaryNotFromSource: a Go binary of the image runs a module
	// other than the one go.mod declares, or a version of a dependency go.mod
	// does not require, so it is not known to be built from these files.
	ReasonGoBinaryNotFromSource Reason = "go_binary_not_from_source"
	// ReasonGoStdlib: the vulnerability is in the Go standard library the
	// binary was built with; building it with a newer Go fixes it, not
	// go.mod.
	ReasonGoStdlib Reason = "go_stdlib_needs_newer_go"
	// ReasonFixInOtherMajor: every fixed version is of another major
	// version, which Go names as another module path.
	ReasonFixInOtherMajor Reason = "fix_in_other_major_version"
)

// minGoDirective is the lowest go line the part accepts: from Go 1.17 a
// go.mod lists every module that provides a package to the main module, and
// 1.21 is the first version whose go line is a full release version.
var minGoDirective = goRelease{1, 21, 0}

// goMod is a parsed go.mod.
type goMod struct {
	module    string
	goVersion string // the go line's value, "" when there is none
	toolchain string // the toolchain line's value, "" when there is none
	requires  []goRequire
	// others are the directives other than module, go, toolchain and
	// require, each as its keyword and tokens joined by spaces, in file
	// order. An update may change none of them.
	others []string
	// counts of the directives the part refuses.
	replaces, excludes int
}

// goRequire is one requirement of a go.mod.
type goRequire struct {
	path     string
	version  string
	indirect bool
	line     int
}

var goDirectives = map[string]bool{
	"module": true, "go": true, "toolchain": true, "godebug": true, "require": true,
	"exclude": true, "replace": true, "retract": true, "tool": true, "ignore": true,
}

// goBlockDirectives are the directives that may be grouped in a block.
var goBlockDirectives = map[string]bool{
	"module": true, "godebug": true, "require": true, "exclude": true, "replace": true, "retract": true, "tool": true, "ignore": true,
}

// parseGoMod reads a go.mod by the grammar of the Go modules reference:
// directives one per line or grouped in a block "keyword ( ... )", tokens
// separated by white space, interpreted ("...") and raw (`...`) strings, and
// "//" comments. A require line whose comment starts with "indirect" is an
// indirect requirement. A directive the grammar does not have is refused
// rather than skipped, since it could change what is built.
func parseGoMod(data []byte) (*goMod, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("go.mod is not valid UTF-8")
	}
	m := &goMod{}
	block := ""
	blockLine := 0
	for i, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		n := i + 1
		toks, comment, err := goModTokens(raw)
		if err != nil {
			return nil, fmt.Errorf("go.mod line %d: %v", n, err)
		}
		if len(toks) == 0 {
			continue
		}
		if block != "" {
			if len(toks) == 1 && toks[0] == ")" {
				block = ""
				continue
			}
			if err := m.directive(block, toks, comment, n); err != nil {
				return nil, err
			}
			continue
		}
		kw := toks[0]
		if !goDirectives[kw] {
			return nil, unsupported(ReasonUnsupportedLockfile, "go.mod line %d has the directive %q, which is not part of the go.mod grammar this version reads", n, kw)
		}
		if len(toks) >= 2 && toks[1] == "(" {
			if !goBlockDirectives[kw] {
				return nil, fmt.Errorf("go.mod line %d: %s is not written as a block", n, kw)
			}
			switch {
			case len(toks) == 2:
				block, blockLine = kw, n
			case len(toks) == 3 && toks[2] == ")":
				// An empty block.
			default:
				return nil, fmt.Errorf("go.mod line %d: a block opens with its keyword and \"(\" alone", n)
			}
			continue
		}
		if err := m.directive(kw, toks[1:], comment, n); err != nil {
			return nil, err
		}
	}
	if block != "" {
		return nil, fmt.Errorf("go.mod line %d opens a %s block that is never closed", blockLine, block)
	}
	if m.module == "" {
		return nil, fmt.Errorf("go.mod has no module line")
	}
	return m, nil
}

func (m *goMod) directive(kw string, args []string, comment string, n int) error {
	switch kw {
	case "module":
		if len(args) != 1 || m.module != "" {
			return fmt.Errorf("go.mod line %d: a module line names one path, once", n)
		}
		m.module = args[0]
	case "go":
		if len(args) != 1 || m.goVersion != "" {
			return fmt.Errorf("go.mod line %d: a go line names one version, once", n)
		}
		m.goVersion = args[0]
	case "toolchain":
		if len(args) != 1 || m.toolchain != "" {
			return fmt.Errorf("go.mod line %d: a toolchain line names one toolchain, once", n)
		}
		m.toolchain = args[0]
	case "require":
		if len(args) != 2 {
			return fmt.Errorf("go.mod line %d: a requirement names a module and a version", n)
		}
		m.requires = append(m.requires, goRequire{path: args[0], version: args[1], indirect: isIndirectComment(comment), line: n})
	default:
		if !goOtherArgsOK(kw, args) {
			return fmt.Errorf("go.mod line %d: %s %s is not a %s directive of the go.mod grammar", n, kw, strings.Join(args, " "), kw)
		}
		switch kw {
		case "replace":
			m.replaces++
		case "exclude":
			m.excludes++
		}
		m.others = append(m.others, kw+" "+strings.Join(args, " "))
	}
	return nil
}

// goOtherArgsOK checks the shape of a directive the part keeps unchanged:
// godebug key=value, exclude module version, replace module [version] =>
// target [version], retract version or [low, high], tool and ignore one
// path.
func goOtherArgsOK(kw string, args []string) bool {
	isVersion := func(v string) bool {
		_, ok := parseVersion(schemeGo, v)
		return ok && strings.HasPrefix(v, "v")
	}
	switch kw {
	case "godebug":
		k, v, ok := strings.Cut(strings.Join(args, ""), "=")
		return len(args) == 1 && ok && k != "" && v != ""
	case "exclude":
		return len(args) == 2 && isVersion(args[1])
	case "replace":
		arrow := -1
		for i, a := range args {
			if a == "=>" {
				arrow = i
			}
		}
		if arrow != 1 && arrow != 2 {
			return false
		}
		if arrow == 2 && !isVersion(args[1]) {
			return false
		}
		rest := args[arrow+1:]
		return len(rest) == 1 || (len(rest) == 2 && isVersion(rest[1]))
	case "retract":
		if len(args) == 1 {
			return isVersion(args[0])
		}
		return len(args) == 5 && args[0] == "[" && isVersion(args[1]) && args[2] == "," && isVersion(args[3]) && args[4] == "]"
	case "tool", "ignore":
		return len(args) == 1
	}
	return false
}

// isIndirectComment reports whether a require line's comment marks it
// indirect as the go command reads it: the comment is the word "indirect"
// alone, or its first word is "indirect;" followed by more words.
func isIndirectComment(c string) bool {
	f := strings.Fields(c)
	return (len(f) == 1 && f[0] == "indirect") || (len(f) > 1 && f[0] == "indirect;")
}

// goModTokens splits one go.mod line into tokens and the text of its
// trailing comment. Parentheses, brackets, braces and commas are tokens of
// their own, as in the go command's reader.
func goModTokens(line string) (toks []string, comment string, err error) {
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case strings.HasPrefix(line[i:], "//"):
			return toks, line[i+2:], nil
		case strings.IndexByte("()[]{},", c) >= 0:
			toks = append(toks, string(c))
			i++
		case c == '"':
			j := i + 1
			for ; j < len(line); j++ {
				if line[j] == '\\' {
					j++
					continue
				}
				if line[j] == '"' {
					break
				}
			}
			if j >= len(line) {
				return nil, "", fmt.Errorf("unterminated string")
			}
			s, uerr := strconv.Unquote(line[i : j+1])
			if uerr != nil {
				return nil, "", fmt.Errorf("bad string %s", line[i:j+1])
			}
			toks = append(toks, s)
			i = j + 1
		case c == '`':
			j := strings.IndexByte(line[i+1:], '`')
			if j < 0 {
				return nil, "", fmt.Errorf("unterminated raw string")
			}
			toks = append(toks, line[i+1:i+1+j])
			i += j + 2
		default:
			j := i
			for j < len(line) && !strings.ContainsRune(" \t\r()[]{},\"`", rune(line[j])) && !strings.HasPrefix(line[j:], "//") {
				j++
			}
			toks = append(toks, line[i:j])
			i = j
		}
	}
	return toks, "", nil
}

// goRelease is a released Go version: go1.N.M, or a go line's 1.N or 1.N.M.
type goRelease struct{ major, minor, patch int }

var goReleaseRE = regexp.MustCompile(`^(?:go)?([1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$`)

// goToolchainRE is a toolchain line the part accepts: a released Go,
// go1.N.M, with its patch number.
var goToolchainRE = regexp.MustCompile(`^go[1-9][0-9]*\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// parseGoRelease reads a Go release version. A release candidate, a beta,
// a custom suffix or "default" is not one.
func parseGoRelease(s string) (goRelease, bool) {
	m := goReleaseRE.FindStringSubmatch(s)
	if m == nil {
		return goRelease{}, false
	}
	var r goRelease
	r.major, _ = strconv.Atoi(m[1])
	r.minor, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		r.patch, _ = strconv.Atoi(m[3])
	}
	return r, true
}

func (a goRelease) compare(b goRelease) int {
	for _, d := range [][2]int{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (a goRelease) String() string { return fmt.Sprintf("%d.%d.%d", a.major, a.minor, a.patch) }

// checkGoSum makes sure go.sum is a list of "module version hash" lines,
// which is all the plan needs of it; the hashes are checked when an update
// is made.
func checkGoSum(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("go.sum is not valid UTF-8")
	}
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if len(strings.Fields(line)) != 3 {
			return fmt.Errorf("go.sum line %d is not \"module version hash\"", i+1)
		}
	}
	return nil
}

// parseGo reads a Go module's go.mod and go.sum into the lockfile the plan
// matches against (see goLockfile). The forms the part does not handle
// (replace, exclude, a go line below 1.21, an unreleased toolchain) make the
// whole unit go to a person.
func parseGo(sum, mod []byte) (*lockfile, *goMod, error) {
	gm, err := parseGoMod(mod)
	if err != nil {
		return nil, nil, err
	}
	if err := checkGoSum(sum); err != nil {
		return nil, nil, err
	}
	if err := goModRefusal(gm); err != nil {
		return nil, nil, err
	}
	l, err := goLockfile(gm)
	if err != nil {
		return nil, nil, err
	}
	return l, gm, nil
}

// goModRefusal says, as an UnsupportedError, why the part does not handle a
// go.mod it has read, or returns nil.
func goModRefusal(gm *goMod) error {
	if gm.replaces > 0 {
		return unsupported(ReasonGoReplace, "go.mod has %d replace directive(s)", gm.replaces)
	}
	if gm.excludes > 0 {
		return unsupported(ReasonGoExclude, "go.mod has %d exclude directive(s)", gm.excludes)
	}
	gv, ok := parseGoRelease(gm.goVersion)
	if !ok || gv.compare(minGoDirective) < 0 {
		return unsupported(ReasonGoVersionTooOld, "go.mod declares go %q; go 1.21 or later is needed", gm.goVersion)
	}
	if gm.toolchain != "" && !goToolchainRE.MatchString(gm.toolchain) {
		return unsupported(ReasonGoToolchainUnsupported, "go.mod declares the toolchain %q, which is not a released Go version", gm.toolchain)
	}
	return nil
}

// goLockfile is the lockfile of a go.mod: every requirement is an occurrence
// at go.mod with its version, direct unless marked indirect.
func goLockfile(gm *goMod) (*lockfile, error) {
	l := newLockfile(ManagerGo)
	seen := map[string]bool{}
	for _, r := range gm.requires {
		if seen[r.path] {
			return nil, fmt.Errorf("go.mod requires %s more than once", r.path)
		}
		seen[r.path] = true
		if _, ok := parseVersion(schemeGo, r.version); !ok || !strings.HasPrefix(r.version, "v") {
			return nil, fmt.Errorf("go.mod line %d requires %s at %q, which is not a module version", r.line, r.path, r.version)
		}
		l.add(r.path, SourceOccurrence{Path: fmt.Sprintf("go.mod:%d", r.line), Version: r.version, Direct: !r.indirect})
	}
	return l.finish(), nil
}
