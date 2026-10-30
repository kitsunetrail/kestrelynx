package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// maxGoModFetches bounds the module versions one Go update follows the
// requirements of; past it the update goes to a person.
const maxGoModFetches = 2000

// errGoFetchLimit is returned when the bound is reached.
var errGoFetchLimit = fmt.Errorf("more than %d module versions would be read to follow the requirements", maxGoModFetches)

// goModHash is the h1: hash go.sum records for a go.mod file: the SHA-256 of
// a one-line summary that names the file's SHA-256 and "go.mod", in base64.
func goModHash(content []byte) string {
	sum := sha256.Sum256(content)
	summary := fmt.Sprintf("%x  go.mod\n", sum)
	h := sha256.Sum256([]byte(summary))
	return "h1:" + base64.StdEncoding.EncodeToString(h[:])
}

// goModEntry is what a module version's go.mod says, as the proxy served it.
type goModEntry struct {
	reqs   []goRequire
	goLine string
	synth  bool   // the proxy made the file up: a module line and nothing else
	hash   string // its h1: hash
}

// goModCache keeps the go.mod files read in one pass of the update stage, by
// module version, so the items of a cycle read each once.
type goModCache struct {
	mu sync.Mutex
	m  map[string]*goModEntry
}

func newGoModCache() *goModCache { return &goModCache{m: map[string]*goModEntry{}} }

// goModGraph follows the requirements of module versions for one update. A
// go.mod is checked against the hash the update's go.sum records for it, when
// it records one.
type goModGraph struct {
	ctx     context.Context
	reg     GoModuleRegistry
	cache   *goModCache
	sums    map[string]string // "path version/go.mod" -> h1: hash
	visited map[string]bool
}

func newGoModGraph(ctx context.Context, reg GoModuleRegistry, cache *goModCache, goSum []byte) (*goModGraph, error) {
	lines, err := parseGoSumLines(goSum)
	if err != nil {
		return nil, err
	}
	g := &goModGraph{ctx: ctx, reg: reg, cache: cache, sums: map[string]string{}, visited: map[string]bool{}}
	for _, l := range lines {
		if strings.HasSuffix(l.version, "/go.mod") {
			g.sums[l.key()] = l.hash
		}
	}
	return g, nil
}

// entry returns what path@version's go.mod says.
func (g *goModGraph) entry(path, version string) (*goModEntry, error) {
	k := path + "@" + version
	if !g.visited[k] {
		if len(g.visited) >= maxGoModFetches {
			return nil, errGoFetchLimit
		}
		g.visited[k] = true
	}
	g.cache.mu.Lock()
	e := g.cache.m[k]
	g.cache.mu.Unlock()
	if e == nil {
		data, err := g.reg.GoMod(g.ctx, path, version)
		if err != nil {
			return nil, &goLookupError{what: "the go.mod of " + path + "@" + version + " on the Go module proxy", err: err}
		}
		gm, err := parseGoMod(data)
		if err != nil {
			return nil, fmt.Errorf("the go.mod of %s@%s: %v", path, version, err)
		}
		if gm.module != path {
			return nil, fmt.Errorf("the go.mod of %s@%s declares the module %s", path, version, gm.module)
		}
		e = &goModEntry{reqs: gm.requires, goLine: gm.goVersion, hash: goModHash(data),
			synth: gm.goVersion == "" && gm.toolchain == "" && len(gm.requires) == 0 && len(gm.others) == 0}
		g.cache.mu.Lock()
		g.cache.m[k] = e
		g.cache.mu.Unlock()
	}
	if want, ok := g.sums[path+" "+version+"/go.mod"]; ok && e.hash != want {
		return nil, fmt.Errorf("the go.mod the proxy serves for %s@%s does not have the hash go.sum records", path, version)
	}
	return e, nil
}

// requires returns the requirements path@version declares.
func (g *goModGraph) requires(path, version string) ([]goRequire, error) {
	e, err := g.entry(path, version)
	if err != nil {
		return nil, err
	}
	return e.reqs, nil
}

// explainGoMoves checks what an update moved, against the go.mod files of
// the new versions:
//
//   - every requirement that moved is a target at the version it was asked
//     for, or is required, at least at the version it moved to, by a module
//     version reached from those through such moves (a move nothing explains
//     is refused, a target that went past its version included);
//   - every written requirement is at least the version any module version
//     the walk read (the targets at the versions asked for and the new
//     versions of the moved modules) requires of it, so a move is explained
//     only up to a version some requirement asks for, and every requirement
//     followed holds in the result;
//   - no moved module's new version has a go.mod the proxy made up (a module
//     without one declares no requirements to follow).
//
// It returns why the update is refused, or "".
func explainGoMoves(g *goModGraph, ch *goModChange, targets map[string]string) (string, error) {
	moved := ch.moved()
	written := ch.written()

	// The walk starts from the targets at the versions they were asked for,
	// whatever the output wrote for them.
	explained := map[string]bool{}
	var queue, visited [][2]string
	for _, p := range goSortedKeys(targets) {
		queue = append(queue, [2]string{p, targets[p]})
		if v, ok := moved[p]; ok && v == targets[p] {
			explained[p] = true
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		visited = append(visited, cur)
		reqs, err := g.requires(cur[0], cur[1])
		if err != nil {
			return "", err
		}
		for _, r := range reqs {
			v, isMoved := moved[r.path]
			if !isMoved || explained[r.path] {
				continue
			}
			if c, ok := compareVersions(schemeGo, r.version, v); ok && c >= 0 {
				explained[r.path] = true
				queue = append(queue, [2]string{r.path, v})
			}
		}
	}
	var unexplained []string
	for p, v := range moved {
		if !explained[p] {
			unexplained = append(unexplained, p+" "+v)
		}
	}
	if len(unexplained) > 0 {
		sort.Strings(unexplained)
		return fmt.Sprintf("the update moved %s, which no requirement of the updated targets explains", strings.Join(unexplained, ", ")), nil
	}

	for _, p := range goSortedKeys(moved) {
		e, err := g.entry(p, moved[p])
		if err != nil {
			return "", err
		}
		if e.synth {
			return fmt.Sprintf("%s@%s has no go.mod of its own, so its requirements are not declared", p, moved[p]), nil
		}
	}
	for _, pv := range visited {
		p, v := pv[0], pv[1]
		e, err := g.entry(p, v)
		if err != nil {
			return "", err
		}
		for _, r := range e.reqs {
			w, ok := written[r.path]
			if !ok {
				continue
			}
			if c, ok := compareVersions(schemeGo, w, r.version); !ok || c < 0 {
				return fmt.Sprintf("%s@%s requires %s %s, but go.mod writes %s", p, v, r.path, r.version, w), nil
			}
		}
	}
	return "", nil
}

// goRaisedTargets returns, for each target that another target's go.mod (at
// the version asked for) requires at a higher version than asked for, the
// highest version so required. go get, told the exact version of every
// target, fails on such a requirement ("requires X, not Y"); left out of the
// command, the target is raised to it by the requirement, as the go command
// selects versions. The go.mod requirements of the targets are part of every
// module graph the go command builds from the updated go.mod, pruned or not.
func goRaisedTargets(g *goModGraph, targets map[string]string) (map[string]string, error) {
	raised := map[string]string{}
	for _, p := range goSortedKeys(targets) {
		reqs, err := g.requires(p, targets[p])
		if err != nil {
			return nil, err
		}
		for _, r := range reqs {
			want, isTarget := targets[r.path]
			if !isTarget || r.path == p {
				continue
			}
			hi := want
			if v, ok := raised[r.path]; ok {
				hi = v
			}
			if c, ok := compareVersions(schemeGo, r.version, hi); ok && c > 0 {
				raised[r.path] = r.version
			}
		}
	}
	return raised, nil
}

// goLineNeeded is the highest go line of the go.mod files of the versions an
// update moved to: what go get raises the module's go line to.
func goLineNeeded(g *goModGraph, moved map[string]string) (goRelease, error) {
	var need goRelease
	for _, p := range goSortedKeys(moved) {
		e, err := g.entry(p, moved[p])
		if err != nil {
			return goRelease{}, err
		}
		if e.goLine == "" {
			continue
		}
		gl, ok := parseGoRelease(e.goLine)
		if !ok {
			return goRelease{}, fmt.Errorf("the go.mod of %s@%s declares go %q, which is not a Go release", p, moved[p], e.goLine)
		}
		if gl.compare(need) > 0 {
			need = gl
		}
	}
	return need, nil
}

// goSortedKeys lists the keys of a map in order.
func goSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
