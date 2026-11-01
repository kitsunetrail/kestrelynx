package remediation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mavenRelayFetchTimeout bounds one pom fetch from the repository.
const mavenRelayFetchTimeout = 30 * time.Second

// mavenRelayRepoURLs are the repository addresses a pom may declare: both
// name Maven Central, which is where the relay fetches from.
var mavenRelayRepoURLs = map[string]bool{
	"https://repo.maven.apache.org/maven2": true,
	"https://repo1.maven.org/maven2":       true,
}

// mavenPOMEntry is one fetched pom with the outcome of its checks.
type mavenPOMEntry struct {
	once     sync.Once
	raw      []byte
	pom      *mavenPOM // nil when the file did not parse
	problems []string  // fetch failure or failed checks
	failed   bool      // nothing to serve
	retry    bool      // the failure may pass; do not keep it
}

// mavenPOMCache keeps the pom files fetched in one cycle, by coordinates, with their check results.
type mavenPOMCache struct {
	mu      sync.Mutex
	entries map[string]*mavenPOMEntry
}

func newMavenPOMCache() *mavenPOMCache {
	return &mavenPOMCache{entries: map[string]*mavenPOMEntry{}}
}

// get returns the entry of key, running fetch once for it. An entry whose
// failure may pass (not "not found") is dropped so a later request asks again.
func (c *mavenPOMCache) get(key string, fetch func(e *mavenPOMEntry)) *mavenPOMEntry {
	c.mu.Lock()
	e := c.entries[key]
	if e == nil {
		e = &mavenPOMEntry{}
		c.entries[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() { fetch(e) })
	if e.retry {
		c.mu.Lock()
		if c.entries[key] == e {
			delete(c.entries, key)
		}
		c.mu.Unlock()
	}
	return e
}

// mavenRelay serves the pom files of Maven Central to one scan, on loopback,
// and records what went wrong.
type mavenRelay struct {
	reg         MavenRegistry
	cache       *mavenPOMCache
	reactor     map[string]string
	maxRequests int

	ln  net.Listener
	srv *http.Server

	mu       sync.Mutex
	requests int
	problems map[string]bool
	fetched  []*mavenPOM
	seen     map[string]bool
}

// startMavenRelay serves GET /maven2/<group path>/<artifact>/<version>/<artifact>-<version>.pom on 127.0.0.1 (a free port), fetching from reg and checking each pom.
//
// reactor maps "groupId:artifactId" of the project's own modules to their
// version: a request for one of them at that version is answered 404 without
// being forwarded (the scanner reads those modules from files, and their
// names must not leave the host) and is not a problem; at another version it
// is a problem. At most maxRequests pom requests are taken.
func startMavenRelay(reg MavenRegistry, cache *mavenPOMCache, reactor map[string]string, maxRequests int) (*mavenRelay, error) {
	if reg == nil || cache == nil {
		return nil, errors.New("maven relay needs a registry and a cache")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start maven relay: %w", err)
	}
	r := &mavenRelay{
		reg: reg, cache: cache, reactor: reactor, maxRequests: maxRequests,
		ln: ln, problems: map[string]bool{}, seen: map[string]bool{},
	}
	r.srv = &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second}
	go r.srv.Serve(ln)
	return r, nil
}

// URL is the address to give the scan as its Maven repository.
func (r *mavenRelay) URL() string { return "http://" + r.ln.Addr().String() + "/maven2" }

// Close stops the relay.
func (r *mavenRelay) Close() { r.srv.Close() }

// Problems lists every failure and refused check, sorted and without
// repeats; when it is not empty the scan through the relay is incomplete.
func (r *mavenRelay) Problems() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.problems))
	for p := range r.problems {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Fetched lists the pom files served, each once, in the order of their first request.
func (r *mavenRelay) Fetched() []*mavenPOM {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*mavenPOM(nil), r.fetched...)
}

func (r *mavenRelay) problem(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.problems[msg] = true
	r.mu.Unlock()
}

func shortPath(p string) string {
	if len(p) > 200 {
		p = p[:200] + "..."
	}
	return fmt.Sprintf("%q", p)
}

// parseMavenRelayPath splits /maven2/<group path>/<artifact>/<version>/<artifact>-<version>.pom.
func parseMavenRelayPath(p string) (group, artifact, version string, ok bool) {
	rest, found := strings.CutPrefix(p, "/maven2/")
	if !found {
		return "", "", "", false
	}
	segs := strings.Split(rest, "/")
	n := len(segs)
	if n < 4 {
		return "", "", "", false
	}
	group, artifact, version = strings.Join(segs[:n-3], "."), segs[n-3], segs[n-2]
	if !mavenGroupOK(group) || !mavenArtifactOK(artifact) || !mavenPathVersionOK(version) {
		return "", "", "", false
	}
	if segs[n-1] != artifact+"-"+version+".pom" {
		return "", "", "", false
	}
	return group, artifact, version, true
}

func (r *mavenRelay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.problem("maven relay: %s request for %s refused", req.Method, shortPath(req.URL.Path))
		http.NotFound(w, req)
		return
	}
	group, artifact, version, ok := parseMavenRelayPath(req.URL.Path)
	if !ok {
		r.problem("maven relay: request for %s is not a pom file of a coordinate", shortPath(req.URL.Path))
		http.NotFound(w, req)
		return
	}
	name := group + ":" + artifact
	coord := name + ":" + version
	if rv, in := r.reactor[name]; in {
		if rv != version {
			r.problem("maven relay: %s is requested at version %s but the project's own module is at %s", name, version, rv)
		}
		http.NotFound(w, req)
		return
	}
	r.mu.Lock()
	r.requests++
	over := r.requests > r.maxRequests
	r.mu.Unlock()
	if over {
		r.problem("maven relay: more than %d pom requests; %s was not fetched", r.maxRequests, coord)
		http.NotFound(w, req)
		return
	}
	e := r.cache.get(coord, func(e *mavenPOMEntry) {
		ctx, cancel := context.WithTimeout(context.Background(), mavenRelayFetchTimeout)
		defer cancel()
		data, err := r.reg.POM(ctx, group, artifact, version)
		if err != nil {
			e.failed = true
			if errors.Is(err, ErrReleaseNotFound) {
				e.problems = []string{fmt.Sprintf("maven relay: %s was not found in the repository", coord)}
			} else {
				e.retry = true
				e.problems = []string{fmt.Sprintf("maven relay: fetching %s failed: %v", coord, err)}
			}
			return
		}
		e.raw = data
		e.pom, e.problems = checkRelayedPOM(data, group, artifact, version)
	})
	r.mu.Lock()
	for _, p := range e.problems {
		r.problems[p] = true
	}
	if !e.failed && e.pom != nil && !r.seen[coord] {
		r.seen[coord] = true
		r.fetched = append(r.fetched, e.pom)
	}
	r.mu.Unlock()
	if e.failed {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Write(e.raw)
}

// checkRelayedPOM parses a pom fetched for group:artifact:version and
// returns what is wrong with it for a scan that resolves dependencies the
// way Trivy does.
func checkRelayedPOM(data []byte, group, artifact, version string) (*mavenPOM, []string) {
	coord := group + ":" + artifact + ":" + version
	p, err := parseMavenPOM(data)
	if err != nil {
		return nil, []string{fmt.Sprintf("maven relay: pom of %s cannot be read: %v", coord, err)}
	}
	var probs []string
	add := func(format string, args ...any) {
		probs = append(probs, fmt.Sprintf("maven relay: pom of %s %s", coord, fmt.Sprintf(format, args...)))
	}
	if g, a, v := p.EffectiveGroupID(), p.ArtifactID, p.EffectiveVersion(); g != group || a != artifact || v != version {
		add("declares the coordinates %s:%s:%s", g, a, v)
	}
	// A profile of a pom resolved as a dependency or a parent is used only
	// when its condition holds; one without a condition is not used. What an
	// active profile manages or sets is judged with the other poms (see
	// mavenAggregateProblems).
	for _, pr := range p.Profiles {
		if !pr.Activation {
			continue
		}
		if pr.RuntimeDependencies || pr.Parent || pr.Modules {
			add("has profile %q, which can turn on and changes the dependencies, the parent or the modules", pr.ID)
		}
		for _, u := range pr.ReleaseRepositories {
			if !mavenRelayRepoURLs[strings.TrimRight(strings.TrimSpace(u), "/")] {
				add("has profile %q, which can turn on and adds the repository %q", pr.ID, u)
			}
		}
	}
	// A repository that serves snapshots only is never asked for a release.
	for _, u := range p.ReleaseRepositories {
		if !mavenRelayRepoURLs[strings.TrimRight(strings.TrimSpace(u), "/")] {
			add("declares the repository %q, which is not Maven Central", u)
		}
	}
	if p.Relocation {
		add("is relocated")
	}
	for _, list := range []struct {
		name string
		deps []mavenDep
	}{{"dependencies", p.Dependencies}, {"dependencyManagement", p.DependencyManagement}} {
		for _, d := range list.deps {
			if isMavenVersionRange(d.Version) {
				add("has the version range %q for %s:%s in %s", d.Version, d.GroupID, d.ArtifactID, list.name)
			}
		}
	}
	// The scanner reads optional as a boolean when it parses the pom: any
	// other text (a property, say) makes the pom unreadable to it, and it
	// goes on without what the pom declares.
	for _, d := range append(append([]mavenDep(nil), p.Dependencies...), p.DependencyManagement...) {
		if !mavenOptionalReadable(d.Optional) {
			add("writes optional %q for %s:%s, which the scanner cannot read", d.Optional, d.GroupID, d.ArtifactID)
		}
	}
	managed := map[string]bool{}
	for _, d := range p.DependencyManagement {
		typ := d.Type
		if typ == "" {
			typ = "jar"
		}
		k := d.GroupID + ":" + d.ArtifactID + ":" + typ + ":" + d.Classifier
		if managed[k] {
			add("manages %s more than once", k)
		}
		managed[k] = true
	}
	return p, probs
}

// resolveMavenName resolves ${...} in s against the pom's own properties and
// its project.groupId, project.artifactId; s is returned as written when a
// reference cannot be resolved.
func resolveMavenName(p *mavenPOM, s string) string {
	cur := s
	for i := 0; i < 5 && strings.Contains(cur, "${"); i++ {
		failed := false
		cur = mavenPropertyRefRE.ReplaceAllStringFunc(cur, func(ref string) string {
			name := ref[2 : len(ref)-1]
			switch name {
			case "project.groupId", "pom.groupId":
				if g := p.EffectiveGroupID(); g != "" {
					return g
				}
			case "project.artifactId", "pom.artifactId":
				if p.ArtifactID != "" {
					return p.ArtifactID
				}
			default:
				if v, ok := p.Properties[name]; ok {
					return v
				}
			}
			failed = true
			return ref
		})
		if failed {
			return s
		}
	}
	if strings.Contains(cur, "${") {
		return s
	}
	return cur
}

func mavenDepName(p *mavenPOM, d mavenDep) string {
	return resolveMavenName(p, d.GroupID) + ":" + resolveMavenName(p, d.ArtifactID)
}

func mavenPOMLabel(p *mavenPOM) string {
	return p.EffectiveGroupID() + ":" + p.ArtifactID + ":" + p.EffectiveVersion()
}

// mavenAggregateProblems checks the poms of one scan together for the forms
// in which the scanner resolves differently from Maven. The scanner matches
// and merges by groupId:artifactId alone, keeps the first declaration or
// management entry of a name, takes optional and exclusions from management,
// and does not read profiles; Maven tells type and classifier apart, takes
// the entry of the dependency's kind, takes neither optional nor (for a
// declaration with its own) exclusions from management, and applies a
// profile whose condition holds. A used name is one declared as a
// dependency the application gets (compile or runtime scope, not optional).
// The problems are:
//   - in one pom, a declaration of a used name that is not of a runtime
//     scope before the runtime one, or two runtime declarations of it;
//   - in one pom, a first management entry of a used name of another kind
//     than the plain jar, unless the pom's plain entry has the same version
//     and settings;
//   - runtime declarations of a name in several kinds with different
//     versions;
//   - a profile with a condition that manages a used name or sets a property
//     a version or groupId reads;
//   - management with optional, or with exclusions where the declaration has
//     its own, of a name a runtime declaration of the managing pom or of a
//     pom that inherits from it declares.
//
// groupId and artifactId are taken as written, except that a ${...} is
// resolved against the pom's own properties and project.groupId when
// possible; otherwise the text counts as its own name.
func mavenAggregateProblems(poms []*mavenPOM) []string {
	set := map[string]bool{}
	// used are the names declared as dependencies the application gets
	// (compile or runtime scope, not optional).
	used := map[string]bool{}
	runtime := func(d mavenDep) bool {
		return (d.Scope == "" || d.Scope == "compile" || d.Scope == "runtime") && !mavenOptional(d.Optional)
	}
	// scoped reads a declaration's scope with its pom's own properties; the
	// scanner reads optional as written.
	scoped := func(p *mavenPOM, d mavenDep) mavenDep {
		d.Scope = resolveMavenName(p, d.Scope)
		return d
	}
	for _, p := range poms {
		if p == nil {
			continue
		}
		// The scanner keeps the first declaration of a name and only then drops
		// what is not of a runtime scope: a test declaration before the runtime
		// one hides it, and two runtime declarations leave one of them out.
		first := map[string]mavenDep{}
		runtimeSeen := map[string]int{}
		for _, d := range p.Dependencies {
			if d.IsImport() {
				continue
			}
			d = scoped(p, d)
			n := mavenDepName(p, d)
			if _, ok := first[n]; !ok {
				first[n] = d
			}
			if runtime(d) {
				used[n] = true
				runtimeSeen[n]++
				if f := first[n]; !runtime(f) {
					set[fmt.Sprintf("pom %s declares %s first with the scope %q, before the declaration the application gets", mavenPOMLabel(p), n, f.Scope)] = true
				}
			}
		}
		for n, c := range runtimeSeen {
			if c > 1 {
				set[fmt.Sprintf("pom %s declares %s %d times among the dependencies the application gets", mavenPOMLabel(p), n, c)] = true
			}
		}
	}
	for _, p := range mavenManagementDivergences(poms, runtime) {
		set[p] = true
	}
	written := map[string]map[string]bool{}
	kinds := map[string]map[string]bool{}
	for _, p := range poms {
		if p == nil {
			continue
		}
		for _, d := range p.Dependencies {
			d = scoped(p, d)
			n := mavenDepName(p, d)
			if d.IsImport() || !runtime(d) {
				continue
			}
			if written[n] == nil {
				written[n], kinds[n] = map[string]bool{}, map[string]bool{}
			}
			written[n][d.Version] = true
			kinds[n][d.Type+"|"+d.Classifier] = true
		}
	}
	for n, ks := range kinds {
		if len(ks) > 1 && len(written[n]) > 1 {
			set[fmt.Sprintf("%s is declared at runtime as more than one kind with different versions", n)] = true
		}
	}
	// The properties the versions and groupIds of the poms read, followed
	// through the values of the properties they name.
	refs := map[string]bool{}
	for _, p := range poms {
		if p == nil {
			continue
		}
		for _, d := range append(append([]mavenDep(nil), p.Dependencies...), p.DependencyManagement...) {
			for _, r := range mavenPropertyRefs(d.Version + d.GroupID) {
				refs[r] = true
			}
		}
	}
	for grew := true; grew; {
		grew = false
		for _, p := range poms {
			if p == nil {
				continue
			}
			for name, v := range p.Properties {
				if !refs[name] {
					continue
				}
				for _, r := range mavenPropertyRefs(v) {
					if !refs[r] {
						refs[r], grew = true, true
					}
				}
			}
		}
	}
	// A profile that can turn on and manages a used name, imports a BOM, or
	// sets a property a version reads, changes what Maven resolves, which the
	// scanner does not see.
	for _, p := range poms {
		if p == nil {
			continue
		}
		for _, pr := range p.Profiles {
			if !pr.Activation {
				continue
			}
			if pr.ImportsBOM {
				set[fmt.Sprintf("pom %s has profile %q, which can turn on and imports a BOM", mavenPOMLabel(p), pr.ID)] = true
			}
			for _, n := range pr.ManagedNames {
				if used[resolveMavenName(p, n)] {
					set[fmt.Sprintf("pom %s has profile %q, which can turn on and manages %s", mavenPOMLabel(p), pr.ID, n)] = true
				}
			}
			for _, n := range pr.PropertyNames {
				if refs[n] {
					set[fmt.Sprintf("pom %s has profile %q, which can turn on and sets %s, which a version reads", mavenPOMLabel(p), pr.ID, n)] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// mavenOptionalReadable reports whether an optional text reads as a
// boolean the way the scanner reads it (absent, or true or false in any of
// the forms strconv.ParseBool takes).
func mavenOptionalReadable(s string) bool {
	if s = strings.TrimSpace(s); s == "" {
		return true
	}
	_, err := strconv.ParseBool(s)
	return err == nil
}

// mavenOptional reports whether an optional text says true.
func mavenOptional(s string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(s))
	return err == nil && b
}

// mavenEntry is a management entry with the pom it was read from and the
// properties its texts are read with.
type mavenEntry struct {
	dep   mavenDep
	pom   *mavenPOM
	props map[string]string
}

// mavenView is a pom as it stands after inheritance: its properties (the
// parents' with its own over them, and its coordinates), its management
// (child first) and its dependencies (child first, one per name, as the
// scanner merges them).
type mavenView struct {
	props map[string]string
	chain []*mavenPOM
}

func mavenViewOf(p *mavenPOM, byCoord map[string]*mavenPOM) mavenView {
	v := mavenView{props: map[string]string{}}
	for cur, depth := p, 0; cur != nil && depth < 16; depth++ {
		v.chain = append(v.chain, cur)
		if cur.Parent == nil {
			break
		}
		cur = byCoord[cur.Parent.GroupID+":"+cur.Parent.ArtifactID+":"+cur.Parent.Version]
	}
	for i := len(v.chain) - 1; i >= 0; i-- {
		for k, val := range v.chain[i].Properties {
			v.props[k] = val
		}
	}
	for _, k := range []string{"project.", "pom."} {
		v.props[k+"groupId"], v.props[k+"artifactId"], v.props[k+"version"] = p.EffectiveGroupID(), p.ArtifactID, p.EffectiveVersion()
	}
	return v
}

// resolveWith resolves the ${...} of s with props; ok is false when one is
// left.
func resolveWith(props map[string]string, s string) (string, bool) {
	cur := s
	for i := 0; i < 8 && strings.Contains(cur, "${"); i++ {
		cur = mavenPropertyRefRE.ReplaceAllStringFunc(cur, func(ref string) string {
			if v, ok := props[ref[2:len(ref)-1]]; ok {
				return v
			}
			return ref
		})
	}
	return cur, !strings.Contains(cur, "${")
}

// entryName is the groupId:artifactId of an entry, resolved with its
// properties.
func entryName(e mavenEntry) string {
	g, _ := resolveWith(e.props, e.dep.GroupID)
	a, _ := resolveWith(e.props, e.dep.ArtifactID)
	return g + ":" + a
}

// mavenManagementLists gives the management a pom's dependencies are
// managed by, as the scanner reads it and as Maven reads it. The scanner
// merges the management of the pom and its parents by name (child first),
// then appends each imported BOM's own management, again by name; Maven
// keeps the explicit entries of the pom and its parents, child first, ahead
// of the imported ones, and matches type and classifier too. ok is false
// when an import cannot be followed (its coordinates do not resolve, or the
// BOM was not among the poms read).
func mavenManagementLists(p *mavenPOM, byCoord map[string]*mavenPOM) (scanner, maven []mavenEntry, ok bool) {
	return mavenMgmt(p, byCoord, nil, 0)
}

func mavenMgmt(p *mavenPOM, byCoord map[string]*mavenPOM, outer map[string]string, depth int) (scanner, maven []mavenEntry, ok bool) {
	if depth > 8 {
		return nil, nil, false
	}
	v := mavenViewOf(p, byCoord)
	props := map[string]string{}
	for k, val := range outer {
		props[k] = val
	}
	for k, val := range v.props {
		props[k] = val
	}
	seen := map[string]bool{}
	var imports []mavenEntry
	for _, c := range v.chain {
		for _, d := range c.DependencyManagement {
			e := mavenEntry{dep: d, pom: c, props: props}
			n := entryName(e)
			if d.IsImport() {
				if !seen[n] {
					seen[n] = true
					imports = append(imports, e)
				}
				continue
			}
			maven = append(maven, e)
			if !seen[n] {
				seen[n] = true
				scanner = append(scanner, e)
			}
		}
	}
	ok = true
	for _, imp := range imports {
		g, ok1 := resolveWith(props, imp.dep.GroupID)
		a, ok2 := resolveWith(props, imp.dep.ArtifactID)
		ver, ok3 := resolveWith(props, imp.dep.Version)
		bom := byCoord[g+":"+a+":"+ver]
		if !ok1 || !ok2 || !ok3 || bom == nil {
			return scanner, maven, false
		}
		bs, bm, bok := mavenMgmt(bom, byCoord, props, depth+1)
		if !bok {
			return scanner, maven, false
		}
		for _, e := range bs {
			if n := entryName(e); !seen[n] {
				seen[n] = true
				scanner = append(scanner, e)
			}
		}
		maven = append(maven, bm...)
	}
	return scanner, maven, ok
}

// mavenApplied is what management leaves on a declaration: its version,
// scope, whether it is optional and what it excludes.
func mavenApplied(d mavenDep, m *mavenEntry, scannerRules bool) string {
	version, scope, optional := d.Version, d.Scope, mavenOptional(d.Optional)
	excl := append([]string(nil), d.Exclusions...)
	if m != nil {
		if version == "" {
			version, _ = resolveWith(m.props, m.dep.Version)
		}
		if scope == "" {
			scope, _ = resolveWith(m.props, m.dep.Scope)
		}
		if scannerRules {
			// The scanner takes optional from management and always adds its
			// exclusions.
			optional = optional || mavenOptional(m.dep.Optional)
			excl = append(excl, m.dep.Exclusions...)
		} else if len(d.Exclusions) == 0 {
			// Maven takes the managed exclusions only for a declaration without
			// its own, and never takes optional from management.
			excl = append(excl, m.dep.Exclusions...)
		}
	}
	sort.Strings(excl)
	return fmt.Sprintf("version %q scope %q optional %v exclusions %v", version, scope, optional, excl)
}

// mavenManagementDivergences lists the declarations that management leaves
// differently in the scanner and in Maven: the entry each picks (the first
// of the name, or the entry of the declaration's kind) or the way each
// applies it differs in what it leaves. A pom's declarations include those it
// inherits, judged in its own context. Only declarations the application
// gets are judged.
func mavenManagementDivergences(poms []*mavenPOM, runtime func(mavenDep) bool) []string {
	byCoord := map[string]*mavenPOM{}
	for _, p := range poms {
		if p != nil {
			byCoord[p.EffectiveGroupID()+":"+p.ArtifactID+":"+p.EffectiveVersion()] = p
		}
	}
	kind := func(d mavenDep) string {
		typ := d.Type
		if typ == "" {
			typ = "jar"
		}
		return typ + ":" + d.Classifier
	}
	var out []string
	for _, p := range poms {
		if p == nil {
			continue
		}
		sc, mv, ok := mavenManagementLists(p, byCoord)
		if !ok {
			out = append(out, fmt.Sprintf("pom %s imports a BOM that cannot be followed", mavenPOMLabel(p)))
			continue
		}
		view := mavenViewOf(p, byCoord)
		seen := map[string]bool{}
		for _, c := range view.chain {
			for _, d := range c.Dependencies {
				if d.IsImport() {
					continue
				}
				g, _ := resolveWith(view.props, d.GroupID)
				a, _ := resolveWith(view.props, d.ArtifactID)
				n := g + ":" + a
				// The scanner keeps a pom's own declaration of a name over an
				// inherited one.
				if seen[n] {
					continue
				}
				seen[n] = true
				// The scope is read with the pom's properties before anything is
				// decided on it, as the scanner reads it; optional is read as
				// written (see mavenOptional).
				d.Scope, _ = resolveWith(view.props, d.Scope)
				if !runtime(d) {
					continue
				}
				var tm, mm *mavenEntry
				for i := range sc {
					if entryName(sc[i]) == n {
						tm = &sc[i]
						break
					}
				}
				for i := range mv {
					if entryName(mv[i]) == n && kind(mv[i].dep) == kind(d) {
						mm = &mv[i]
						break
					}
				}
				if t, m := mavenApplied(d, tm, true), mavenApplied(d, mm, false); t != m {
					out = append(out, fmt.Sprintf("pom %s declares %s, which the scanner manages to %s and Maven to %s", mavenPOMLabel(p), n, t, m))
				}
			}
		}
	}
	return out
}
