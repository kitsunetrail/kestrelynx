package remediation

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// cratesIOSource is the source Cargo.lock writes for a crate of crates.io.
const cratesIOSource = "registry+https://github.com/rust-lang/crates.io-index"

// cargoChecksumRE is the checksum of a crate of crates.io: the SHA-256 of the
// crate file in lower-case hexadecimal.
var cargoChecksumRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// cargoNameRE is what a crate name may be made of.
var cargoNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// cargoCrate is one [[package]] of a Cargo.lock: a crate of crates.io, or a
// package of the workspace itself, which has no source (and no checksum).
type cargoCrate struct {
	name     string
	version  string
	source   string // "" for a package of the workspace, else cratesIOSource
	checksum string
	deps     []int // the crates its dependencies resolve to, in file order
}

// registry reports whether the crate comes from crates.io.
func (c cargoCrate) registry() bool { return c.source == cratesIOSource }

// id is the crate as a Cargo.lock names it: name, version and source.
func (c cargoCrate) id() string { return c.name + "@" + c.version }

// cargoLock is a parsed Cargo.lock with every dependency resolved to the one
// crate it names.
type cargoLock struct {
	version int // the format version, 3 or 4
	crates  []cargoCrate
	byName  map[string][]int
	// byVersion holds the crates of a name at a version, by name and version
	// joined with a NUL: one from crates.io and one of the workspace at most.
	byVersion map[string][]int
}

// find returns the index of the crate with the name, version and source, or
// -1.
func (l *cargoLock) find(name, version, source string) int {
	for _, i := range l.byVersion[name+"\x00"+version] {
		if c := l.crates[i]; c.version == version && c.source == source {
			return i
		}
	}
	return -1
}

// reach returns the set of crates that can be reached from the crate at index
// from along the dependency edges, from itself included.
func (l *cargoLock) reach(from int) map[int]bool {
	seen := map[int]bool{from: true}
	stack := []int{from}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, d := range l.crates[i].deps {
			if !seen[d] {
				seen[d] = true
				stack = append(stack, d)
			}
		}
	}
	return seen
}

// cargoLockKeys and cargoPackageKeys are the keys of a Cargo.lock the parser
// reads; any other is refused rather than skipped, since it could change what
// is built.
var (
	cargoLockKeys    = map[string]bool{"version": true, "package": true}
	cargoPackageKeys = map[string]bool{"name": true, "version": true, "source": true, "checksum": true, "dependencies": true}
)

// parseCargoLock reads a Cargo.lock of format version 3 or 4. The sources it
// accepts are crates.io and none (a package of the workspace), and every
// crate of crates.io must carry its checksum. Each entry of a dependencies
// list is resolved by the parts it gives (the name, the name and version, or
// those and the source) to exactly one crate of the file; one that matches
// none or several, or two entries of one crate that match the same one, is
// refused. A file in which two versions of a crate of the same source are
// compatible (see cargoSeries) is refused too, as Cargo resolves one version
// for each series.
func parseCargoLock(data []byte) (*cargoLock, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, fmt.Errorf("Cargo.lock: %w", err)
	}
	for k := range doc {
		if !cargoLockKeys[k] {
			return nil, unsupported(ReasonUnsupportedLockfile, "Cargo.lock has the key %q, which is not part of the format this version reads", k)
		}
	}
	ver, ok := doc["version"].(int64)
	if !ok {
		return nil, unsupported(ReasonUnsupportedLockfile, "Cargo.lock has no version line; only versions 3 and 4 are handled")
	}
	if ver != 3 && ver != 4 {
		return nil, unsupported(ReasonUnsupportedLockfile, "Cargo.lock is of version %d; only versions 3 and 4 are handled", ver)
	}
	l := &cargoLock{version: int(ver), byName: map[string][]int{}, byVersion: map[string][]int{}}
	var rawDeps [][]string
	var pkgs []any
	if v, present := doc["package"]; present {
		if pkgs, ok = v.([]any); !ok {
			return nil, fmt.Errorf("Cargo.lock: package is not an array of tables")
		}
	}
	seen := map[string]bool{}
	for n, p := range pkgs {
		t, ok := p.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("Cargo.lock: package %d is not a table", n+1)
		}
		for k := range t {
			if !cargoPackageKeys[k] {
				return nil, unsupported(ReasonUnsupportedLockfile, "Cargo.lock has the package key %q, which is not part of the format this version reads", k)
			}
		}
		str := func(key string, required bool) (string, error) {
			v, present := t[key]
			if !present {
				if required {
					return "", fmt.Errorf("Cargo.lock: package %d has no %s", n+1, key)
				}
				return "", nil
			}
			s, ok := v.(string)
			if !ok || s == "" {
				return "", fmt.Errorf("Cargo.lock: package %d has a %s that is not a string", n+1, key)
			}
			return s, nil
		}
		var c cargoCrate
		if c.name, err = str("name", true); err != nil {
			return nil, err
		}
		if !cargoNameRE.MatchString(c.name) || len(c.name) > 64 {
			return nil, fmt.Errorf("Cargo.lock: %q is not a crate name", c.name)
		}
		if c.version, err = str("version", true); err != nil {
			return nil, err
		}
		if _, ok := parseCargoVersion(c.version); !ok {
			return nil, fmt.Errorf("Cargo.lock: %s has the version %q, which is not a version", c.name, c.version)
		}
		if c.source, err = str("source", false); err != nil {
			return nil, err
		}
		if c.checksum, err = str("checksum", false); err != nil {
			return nil, err
		}
		switch {
		case c.source == "":
			if c.checksum != "" {
				return nil, fmt.Errorf("Cargo.lock: %s %s has a checksum but no source", c.name, c.version)
			}
		case c.source == cratesIOSource:
			if !cargoChecksumRE.MatchString(c.checksum) {
				return nil, fmt.Errorf("Cargo.lock: %s %s of crates.io has no valid checksum", c.name, c.version)
			}
		default:
			return nil, unsupported(ReasonUnsupportedSource, "Cargo.lock has %s %s from %s, which is not crates.io", c.name, c.version, clip(c.source, 100))
		}
		key := c.name + "\x00" + c.version + "\x00" + c.source
		if seen[key] {
			return nil, fmt.Errorf("Cargo.lock: %s %s is listed twice", c.name, c.version)
		}
		seen[key] = true
		var deps []string
		if v, present := t["dependencies"]; present {
			list, ok := v.([]any)
			if !ok {
				return nil, fmt.Errorf("Cargo.lock: %s %s has dependencies that are not an array", c.name, c.version)
			}
			for _, e := range list {
				s, ok := e.(string)
				if !ok || s == "" {
					return nil, fmt.Errorf("Cargo.lock: %s %s has a dependency that is not a string", c.name, c.version)
				}
				deps = append(deps, s)
			}
		}
		l.byName[c.name] = append(l.byName[c.name], len(l.crates))
		l.byVersion[c.name+"\x00"+c.version] = append(l.byVersion[c.name+"\x00"+c.version], len(l.crates))
		l.crates = append(l.crates, c)
		rawDeps = append(rawDeps, deps)
	}

	for i, raw := range rawDeps {
		resolved := map[int]string{}
		for _, entry := range raw {
			j, err := l.resolve(entry)
			if err != nil {
				return nil, fmt.Errorf("Cargo.lock: %s %s: %w", l.crates[i].name, l.crates[i].version, err)
			}
			if prev, dup := resolved[j]; dup {
				return nil, fmt.Errorf("Cargo.lock: %s %s lists %q and %q, which are the same crate", l.crates[i].name, l.crates[i].version, prev, entry)
			}
			resolved[j] = entry
			l.crates[i].deps = append(l.crates[i].deps, j)
		}
	}

	type seriesKey struct{ name, source, series string }
	series := map[seriesKey]string{}
	for _, c := range l.crates {
		v, _ := parseCargoVersion(c.version)
		k := seriesKey{c.name, c.source, cargoSeries(v)}
		if other, dup := series[k]; dup {
			return nil, fmt.Errorf("Cargo.lock: %s is locked at %s and %s, which are of one series", c.name, other, c.version)
		}
		series[k] = c.version
	}
	return l, nil
}

// resolve finds the one crate a dependencies entry names. An entry is "name",
// "name version" or "name version (source)"; the parts it gives narrow the
// crates of that name down. It looks at no more than the two crates of a name
// and version, so that a file with many versions of one crate is not read in
// time that grows with their number for each dependency.
func (l *cargoLock) resolve(entry string) (int, error) {
	parts := strings.Split(entry, " ")
	if len(parts) > 3 {
		return 0, fmt.Errorf("the dependency %q is not in a form this version reads", entry)
	}
	for _, p := range parts {
		if p == "" {
			return 0, fmt.Errorf("the dependency %q is not in a form this version reads", entry)
		}
	}
	name := parts[0]
	version, source, hasSource := "", "", false
	if len(parts) >= 2 {
		version = parts[1]
	}
	if len(parts) == 3 {
		s := parts[2]
		if len(s) < 3 || s[0] != '(' || s[len(s)-1] != ')' {
			return 0, fmt.Errorf("the dependency %q is not in a form this version reads", entry)
		}
		source, hasSource = s[1:len(s)-1], true
	}
	if version == "" {
		switch hits := l.byName[name]; len(hits) {
		case 0:
			return 0, fmt.Errorf("the dependency %q is not a crate of the file", entry)
		case 1:
			return hits[0], nil
		}
		return 0, fmt.Errorf("the dependency %q names more than one crate of the file", entry)
	}
	var hits []int
	for _, i := range l.byVersion[name+"\x00"+version] {
		if hasSource && l.crates[i].source != source {
			continue
		}
		hits = append(hits, i)
	}
	switch len(hits) {
	case 0:
		return 0, fmt.Errorf("the dependency %q is not a crate of the file", entry)
	case 1:
		return hits[0], nil
	}
	return 0, fmt.Errorf("the dependency %q names more than one crate of the file", entry)
}

// versionsOf lists the versions the lock holds of the crates named name, in
// order, with the workspace's own packages marked.
func (l *cargoLock) versionsOf(name string) []string {
	var out []string
	for _, i := range l.byName[name] {
		c := l.crates[i]
		v := c.version
		if !c.registry() {
			v += " (workspace)"
		}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
