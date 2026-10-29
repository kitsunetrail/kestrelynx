package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// goModChange is what an update did to go.mod, once it is known to have
// done nothing it may not.
type goModChange struct {
	raised    map[string][2]string // path -> old and new version of a requirement that went up
	added     map[string]string    // path -> version of a requirement that was not there
	goBefore  string
	goAfter   string
	tcBefore  string
	tcAfter   string
	unchanged map[string]string // path -> version of the requirements that stayed
}

// diffGoMod compares the go.mod an update returned with the original. Only
// the requirements and the go and toolchain lines may change: the module,
// every other directive (replace, exclude, retract, godebug, tool, ignore)
// must read the same; a requirement may go up or be added, never go down or
// go away; and the indirect mark of a requirement that was there stays as it
// was.
func diffGoMod(before, after *goMod) (*goModChange, error) {
	if after.module != before.module {
		return nil, fmt.Errorf("the module line changed from %s to %s", before.module, after.module)
	}
	if strings.Join(after.others, "\n") != strings.Join(before.others, "\n") {
		return nil, fmt.Errorf("a directive other than require, go and toolchain changed")
	}
	if after.replaces != before.replaces || after.excludes != before.excludes {
		return nil, fmt.Errorf("the replace or exclude directives changed")
	}
	c := &goModChange{raised: map[string][2]string{}, added: map[string]string{}, unchanged: map[string]string{},
		goBefore: before.goVersion, goAfter: after.goVersion, tcBefore: before.toolchain, tcAfter: after.toolchain}
	now := map[string]goRequire{}
	for _, r := range after.requires {
		if _, dup := now[r.path]; dup {
			return nil, fmt.Errorf("%s is required more than once", r.path)
		}
		if _, ok := parseVersion(schemeGo, r.version); !ok || !strings.HasPrefix(r.version, "v") {
			return nil, fmt.Errorf("%s is required at %q, which is not a module version", r.path, r.version)
		}
		now[r.path] = r
	}
	for _, r := range before.requires {
		n, ok := now[r.path]
		if !ok {
			return nil, fmt.Errorf("the requirement of %s was removed", r.path)
		}
		if n.indirect != r.indirect {
			return nil, fmt.Errorf("the indirect mark of %s changed", r.path)
		}
		cmp, _ := compareVersions(schemeGo, n.version, r.version)
		switch {
		case cmp < 0:
			return nil, fmt.Errorf("%s went down from %s to %s", r.path, r.version, n.version)
		case cmp > 0:
			c.raised[r.path] = [2]string{r.version, n.version}
		default:
			if n.version != r.version {
				return nil, fmt.Errorf("%s is written %s, not %s", r.path, n.version, r.version)
			}
			c.unchanged[r.path] = r.version
		}
		delete(now, r.path)
	}
	for p, r := range now {
		c.added[p] = r.version
	}
	return c, nil
}

// moved lists the requirements an update raised or added, by path.
func (c *goModChange) moved() map[string]string {
	out := map[string]string{}
	for p, v := range c.raised {
		out[p] = v[1]
	}
	for p, v := range c.added {
		out[p] = v
	}
	return out
}

// written is every requirement after the update.
func (c *goModChange) written() map[string]string {
	out := c.moved()
	for p, v := range c.unchanged {
		out[p] = v
	}
	return out
}

// goSumLine is one line of a go.sum.
type goSumLine struct {
	path, version string // version carries "/go.mod" for a go.mod hash
	hash          string
}

func (l goSumLine) key() string  { return l.path + " " + l.version }
func (l goSumLine) text() string { return l.path + " " + l.version + " " + l.hash }

func parseGoSumLines(data []byte) ([]goSumLine, error) {
	var out []goSumLine
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 || !goHashRE.MatchString(f[2]) {
			return nil, fmt.Errorf("go.sum line %d is not \"module version h1:hash\"", i+1)
		}
		out = append(out, goSumLine{f[0], f[1], f[2]})
	}
	return out, nil
}

// goSumResult is a checked and completed go.sum.
type goSumResult struct {
	content []byte
	added   []string // lines this program added from the checksum database
	checked int
}

// checkGoSum checks the go.sum an update returned against the checksum
// database and completes it. The lines checked are every line that is new
// or changed, and both hashes of every version the update moved to, whether
// the line was new or already there (the go command does not ask the
// database about a hash go.sum already has). A hash the database does not
// record is refused. A moved version whose zip or go.mod hash is missing
// gets it from the database. No line of the original may go away, and two
// lines for one version and kind of hash must agree.
func checkGoSumLines(ctx context.Context, reg GoModuleRegistry, orig, updated []byte, moved map[string]string, budget func() error) (*goSumResult, error) {
	before, err := parseGoSumLines(orig)
	if err != nil {
		return nil, fmt.Errorf("the original %v", err)
	}
	after, err := parseGoSumLines(updated)
	if err != nil {
		return nil, err
	}
	byKey := map[string]string{}
	var order []string
	for _, l := range after {
		if h, ok := byKey[l.key()]; ok {
			if h != l.hash {
				return nil, fmt.Errorf("go.sum has two different hashes for %s", l.key())
			}
			continue
		}
		byKey[l.key()] = l.hash
		order = append(order, l.key())
	}
	origKeys := map[string]string{}
	for _, l := range before {
		origKeys[l.key()] = l.hash
		h, ok := byKey[l.key()]
		if !ok {
			return nil, fmt.Errorf("the line of %s was removed from go.sum", l.key())
		}
		if h != l.hash {
			return nil, fmt.Errorf("the hash of %s changed in go.sum", l.key())
		}
	}
	// What to ask the database about, by module version.
	ask := map[string][2]string{} // "path version" -> path, version
	for k := range byKey {
		if _, ok := origKeys[k]; ok {
			continue
		}
		path, ver, _ := strings.Cut(k, " ")
		ver = strings.TrimSuffix(ver, "/go.mod")
		ask[path+" "+ver] = [2]string{path, ver}
	}
	for p, v := range moved {
		ask[p+" "+v] = [2]string{p, v}
	}
	keys := make([]string, 0, len(ask))
	for k := range ask {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := &goSumResult{}
	extra := map[string]string{}
	for _, k := range keys {
		pv := ask[k]
		if err := budget(); err != nil {
			return nil, err
		}
		sums, err := reg.Sums(ctx, pv[0], pv[1])
		if err != nil {
			if errors.Is(err, ErrReleaseNotFound) {
				return nil, fmt.Errorf("the checksum database has no record of %s %s", pv[0], pv[1])
			}
			return nil, &goLookupError{what: pv[0] + " " + pv[1] + " in the checksum database", err: err}
		}
		res.checked++
		zipKey, modKey := pv[0]+" "+pv[1], pv[0]+" "+pv[1]+"/go.mod"
		for _, kh := range [][2]string{{zipKey, sums.Zip}, {modKey, sums.Mod}} {
			h, have := byKey[kh[0]]
			switch {
			case have && h != kh[1]:
				return nil, fmt.Errorf("go.sum gives %s the hash %s; the checksum database records %s", kh[0], h, kh[1])
			case !have:
				if _, isMoved := moved[pv[0]]; isMoved && moved[pv[0]] == pv[1] {
					extra[kh[0]] = kh[1]
				}
			}
		}
	}
	// The completed file: the returned lines in their order, then the added
	// ones, sorted as go.sum is.
	var lines []string
	for _, k := range order {
		lines = append(lines, k+" "+byKey[k])
	}
	for k, h := range extra {
		lines = append(lines, k+" "+h)
		res.added = append(res.added, k+" "+h)
	}
	sort.Strings(res.added)
	sort.SliceStable(lines, func(i, j int) bool { return goSumOrder(lines[i], lines[j]) })
	res.content = []byte(strings.Join(lines, "\n") + "\n")
	return res, nil
}

// goSumOrder sorts go.sum lines as the go command writes them: by module
// path, then by version, the go.mod hash of a version after its zip hash.
func goSumOrder(a, b string) bool {
	fa, fb := strings.Fields(a), strings.Fields(b)
	if fa[0] != fb[0] {
		return fa[0] < fb[0]
	}
	va, vb := strings.TrimSuffix(fa[1], "/go.mod"), strings.TrimSuffix(fb[1], "/go.mod")
	if va != vb {
		if c, ok := compareVersions(schemeGo, va, vb); ok && c != 0 {
			return c < 0
		}
		return va < vb
	}
	return !strings.HasSuffix(fa[1], "/go.mod") && strings.HasSuffix(fb[1], "/go.mod")
}
