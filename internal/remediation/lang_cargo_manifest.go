package remediation

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Reasons of the Rust (Cargo) part.
const (
	// ReasonRustBinaryNotFromSource: a Rust binary of the image has a root
	// crate that is not a package of the workspace, cannot be told, or builds
	// in crates that Cargo.lock does not lead to from the workspace's package,
	// so it is not known to be built from these files.
	ReasonRustBinaryNotFromSource Reason = "rust_binary_not_from_source"
	// ReasonCargoManifestUnsupported: a Cargo.toml is written in a form the
	// plan does not interpret (a table or key it does not know, an old
	// spelling, a dependency it cannot read).
	ReasonCargoManifestUnsupported Reason = "cargo_manifest_unsupported"
	// ReasonCargoReleaseNotFound: crates.io lists no release the update can
	// take: none at or above the target, compatible with the installed
	// version, not a pre-release and not yanked.
	ReasonCargoReleaseNotFound Reason = "cargo_release_not_found"
)

// Bounds on how much of a repository one Rust unit may read.
const maxCargoMembers = 64

// maxCargoFiles is a variable so that a test can lower it.
var maxCargoFiles = 200

// cargoManifestKeys are the top-level keys of a Cargo.toml the plan reads.
var cargoManifestKeys = map[string]bool{
	"package": true, "lib": true, "bin": true, "example": true, "test": true, "bench": true,
	"dependencies": true, "dev-dependencies": true, "build-dependencies": true, "target": true,
	"features": true, "workspace": true, "profile": true, "badges": true, "lints": true,
}

// cargoWorkspaceKeys are the keys of the [workspace] table the plan reads.
var cargoWorkspaceKeys = map[string]bool{
	"members": true, "exclude": true, "default-members": true, "resolver": true,
	"package": true, "dependencies": true, "metadata": true, "lints": true,
}

// cargoDepTables are the tables a dependency is declared in.
var cargoDepTables = []string{"dependencies", "dev-dependencies", "build-dependencies"}

// cargoDepKeys are the keys of a dependency written as a table; the ones of
// cargoSourceKeys name another place to get the crate from.
var (
	cargoDepKeys    = map[string]bool{"version": true, "features": true, "optional": true, "default-features": true, "default_features": true, "package": true, "path": true, "workspace": true}
	cargoSourceKeys = map[string]bool{"git": true, "branch": true, "tag": true, "rev": true, "registry": true, "registry-index": true}
)

// cargoRustVersionRE is a rust-version: one to three numeric parts.
var cargoRustVersionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)

// cargoDep is one dependency of a Cargo.toml.
type cargoDep struct {
	table string // the table it is in, for messages
	key   string // the key it is written under
	pkg   string // the crate it names: the package key, else the key
	req   string // the version requirement, "" when it names none
	// path is the repository path of the directory a path dependency names,
	// cleaned; "" for a dependency without one.
	path string
	// inherit marks "workspace = true": req, pkg and path come from the
	// workspace's [workspace.dependencies] entry of the same key.
	inherit bool
	// pkgKey marks an explicit package key.
	pkgKey bool
}

// cargoWorkspace is the [workspace] table of a root Cargo.toml.
type cargoWorkspace struct {
	members, exclude []string
	defaultMembers   []string
	deps             []cargoDep
	// version and rustVersion are those of [workspace.package], "" when it
	// sets none.
	version, rustVersion string
}

// cargoManifest is what the plan reads of one Cargo.toml.
type cargoManifest struct {
	file string // its repository path
	dir  string // the repository path of its directory

	hasPackage bool
	name       string
	// version is the package's version, "0.0.0" when it sets none; with
	// versionInherited it is that of [workspace.package] and still to be
	// filled in.
	version          string
	versionInherited bool
	// rustVersion is the declared rust-version, "" when there is none; with
	// rustVersionInherited it is that of [workspace.package].
	rustVersion          string
	rustVersionInherited bool

	deps []cargoDep
	ws   *cargoWorkspace // set when the file has a [workspace] table
}

// cargoSorted lists the keys of a table in order.
func cargoSorted(t map[string]any) []string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseCargoManifest reads a Cargo.toml for what the plan needs: the package,
// the workspace and every dependency. It refuses what could change where
// crates come from or how they resolve (patch, replace, cargo-features, a git
// or other-registry dependency), the old underscore spellings of the
// dependency tables, and every key it does not know, with the reason that
// fits; anything that is not what Cargo reads is an error without one.
func parseCargoManifest(file string, data []byte) (*cargoManifest, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	m := &cargoManifest{file: file, dir: path.Dir(file)}
	for _, k := range cargoSorted(doc) {
		switch {
		case k == "patch" || k == "replace" || k == "cargo-features":
			return nil, unsupported(ReasonUnsupportedSource, "%s has [%s], which changes how crates are resolved", file, k)
		case k == "dev_dependencies" || k == "build_dependencies":
			return nil, unsupported(ReasonCargoManifestUnsupported, "%s uses the old spelling [%s]", file, k)
		case !cargoManifestKeys[k]:
			return nil, unsupported(ReasonCargoManifestUnsupported, "%s has the key %q, which is not read by this version", file, k)
		}
	}
	if v, ok := doc["package"]; ok {
		t, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: package is not a table", file)
		}
		if err := m.readPackage(t); err != nil {
			return nil, err
		}
	}
	for _, tb := range cargoDepTables {
		if v, ok := doc[tb]; ok {
			deps, err := parseCargoDeps(m.file, tb, v, false)
			if err != nil {
				return nil, err
			}
			m.deps = append(m.deps, deps...)
		}
	}
	if v, ok := doc["target"]; ok {
		t, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: target is not a table", file)
		}
		for _, cfg := range cargoSorted(t) {
			sub, ok := t[cfg].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: target.%s is not a table", file, cfg)
			}
			for _, k := range cargoSorted(sub) {
				switch {
				case k == "dev_dependencies" || k == "build_dependencies":
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s uses the old spelling [target.%s.%s]", file, cfg, k)
				case k != "dependencies" && k != "dev-dependencies" && k != "build-dependencies":
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s has the key %q in [target.%s], which is not read by this version", file, k, cfg)
				}
				deps, err := parseCargoDeps(m.file, "target."+cfg+"."+k, sub[k], false)
				if err != nil {
					return nil, err
				}
				m.deps = append(m.deps, deps...)
			}
		}
	}
	if v, ok := doc["workspace"]; ok {
		t, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: workspace is not a table", file)
		}
		if m.ws, err = m.readWorkspace(t); err != nil {
			return nil, err
		}
	}
	if !m.hasPackage && m.ws == nil {
		return nil, fmt.Errorf("%s has neither a [package] nor a [workspace]", file)
	}
	if !m.hasPackage {
		// A workspace root without a [package] is a virtual manifest, which
		// Cargo refuses when it has the tables of a package.
		for _, k := range cargoSorted(doc) {
			if k != "workspace" && k != "profile" {
				return nil, unsupported(ReasonCargoManifestUnsupported, "%s has no [package] but has [%s], which only a package has", file, k)
			}
		}
	}
	return m, nil
}

// readPackage reads the [package] table: the name, the version and the
// rust-version, each of which may be inherited from the workspace. A package
// that names a workspace root of its own is refused.
func (m *cargoManifest) readPackage(t map[string]any) error {
	if _, ok := t["workspace"]; ok {
		return unsupported(ReasonWorkspaceUnsupported, "%s sets package.workspace, so it is a member of a workspace whose root is elsewhere", m.file)
	}
	name, ok := t["name"].(string)
	if !ok || !cargoNameRE.MatchString(name) || len(name) > 64 {
		return fmt.Errorf("%s: package.name is not a crate name", m.file)
	}
	m.hasPackage, m.name, m.version = true, name, "0.0.0"
	inherited := func(v any) bool {
		w, ok := v.(map[string]any)
		on, _ := w["workspace"].(bool)
		return ok && len(w) == 1 && on
	}
	switch v := t["version"].(type) {
	case nil:
	case string:
		if _, ok := parseCargoVersion(v); !ok {
			return fmt.Errorf("%s: package.version %q is not a version", m.file, v)
		}
		m.version = v
	default:
		if !inherited(v) {
			return fmt.Errorf("%s: package.version is not a version", m.file)
		}
		m.versionInherited, m.version = true, ""
	}
	switch v := t["rust-version"].(type) {
	case nil:
	case string:
		if !cargoRustVersionRE.MatchString(v) {
			return unsupported(ReasonCargoManifestUnsupported, "%s has the rust-version %q, which is not read by this version", m.file, v)
		}
		m.rustVersion = v
	default:
		if !inherited(v) {
			return fmt.Errorf("%s: package.rust-version is not a version", m.file)
		}
		m.rustVersionInherited = true
	}
	return nil
}

// readWorkspace reads a [workspace] table.
func (m *cargoManifest) readWorkspace(t map[string]any) (*cargoWorkspace, error) {
	for _, k := range cargoSorted(t) {
		if !cargoWorkspaceKeys[k] {
			return nil, unsupported(ReasonCargoManifestUnsupported, "%s has the key %q in [workspace], which is not read by this version", m.file, k)
		}
	}
	ws := &cargoWorkspace{}
	list := func(key string) ([]string, error) {
		v, ok := t[key]
		if !ok {
			return nil, nil
		}
		items, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("%s: workspace.%s is not an array", m.file, key)
		}
		var out []string
		for _, it := range items {
			s, ok := it.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("%s: workspace.%s has an entry that is not a path", m.file, key)
			}
			out = append(out, s)
		}
		return out, nil
	}
	var err error
	if ws.members, err = list("members"); err != nil {
		return nil, err
	}
	if ws.exclude, err = list("exclude"); err != nil {
		return nil, err
	}
	if ws.defaultMembers, err = list("default-members"); err != nil {
		return nil, err
	}
	if v, ok := t["package"]; ok {
		p, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: workspace.package is not a table", m.file)
		}
		if s, ok := p["version"].(string); ok {
			if _, ok := parseCargoVersion(s); !ok {
				return nil, fmt.Errorf("%s: workspace.package.version %q is not a version", m.file, s)
			}
			ws.version = s
		}
		if s, ok := p["rust-version"].(string); ok {
			if !cargoRustVersionRE.MatchString(s) {
				return nil, unsupported(ReasonCargoManifestUnsupported, "%s has the rust-version %q, which is not read by this version", m.file, s)
			}
			ws.rustVersion = s
		}
	}
	if v, ok := t["dependencies"]; ok {
		if ws.deps, err = parseCargoDeps(m.file, "workspace.dependencies", v, true); err != nil {
			return nil, err
		}
	}
	return ws, nil
}

// parseCargoDeps reads one table of dependencies of the Cargo.toml at file.
// A dependency is a version requirement, or a table of version, features,
// optional, default-features, package, path and workspace; a table that has
// git, branch, tag, rev, registry or registry-index, or a key not listed, is
// refused. In the table of the workspace's own dependencies "workspace = true"
// is not allowed.
func parseCargoDeps(file, table string, v any, inWorkspace bool) ([]cargoDep, error) {
	t, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: %s is not a table", file, table)
	}
	dir := path.Dir(file)
	var out []cargoDep
	for _, key := range cargoSorted(t) {
		d := cargoDep{table: table, key: key, pkg: key}
		switch e := t[key].(type) {
		case string:
			if e == "" {
				return nil, fmt.Errorf("%s: %s %s has an empty version requirement", file, table, key)
			}
			d.req = e
		case map[string]any:
			for _, k := range cargoSorted(e) {
				switch {
				case cargoSourceKeys[k]:
					return nil, unsupported(ReasonUnsupportedSource, "%s: %s %s is given by %s, not by crates.io", file, table, key, k)
				case !cargoDepKeys[k]:
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s: %s %s has the key %q, which is not read by this version", file, table, key, k)
				}
			}
			if w, ok := e["workspace"]; ok {
				if on, _ := w.(bool); !on || inWorkspace {
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s: %s %s sets workspace in a form that is not read by this version", file, table, key)
				}
				if _, a := e["version"]; a {
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s: %s %s inherits from the workspace and also sets a version", file, table, key)
				}
				if _, a := e["path"]; a {
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s: %s %s inherits from the workspace and also sets a path", file, table, key)
				}
				if _, a := e["package"]; a {
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s: %s %s inherits from the workspace and also sets a package", file, table, key)
				}
				d.inherit = true
			}
			if p, present := e["package"]; present {
				s, ok := p.(string)
				if !ok || !cargoNameRE.MatchString(s) || len(s) > 64 {
					return nil, fmt.Errorf("%s: %s %s has a package that is not a crate name", file, table, key)
				}
				d.pkg, d.pkgKey = s, true
			}
			if r, present := e["version"]; present {
				s, ok := r.(string)
				if !ok || s == "" {
					return nil, fmt.Errorf("%s: %s %s has a version that is not a requirement", file, table, key)
				}
				d.req = s
			}
			if p, present := e["path"]; present {
				s, ok := p.(string)
				if !ok || s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, "\\") {
					return nil, unsupported(ReasonCargoManifestUnsupported, "%s: %s %s has a path that is not read by this version", file, table, key)
				}
				d.path = path.Join(dir, s)
			}
			if d.req == "" && d.path == "" && !d.inherit {
				return nil, unsupported(ReasonCargoManifestUnsupported, "%s: %s %s names neither a version nor a path", file, table, key)
			}
		default:
			return nil, fmt.Errorf("%s: %s %s is neither a requirement nor a table", file, table, key)
		}
		if !cargoNameRE.MatchString(key) || len(key) > 64 {
			return nil, fmt.Errorf("%s: %s %s is not a crate name", file, table, key)
		}
		out = append(out, d)
	}
	return out, nil
}

// inherited fills a dependency that says "workspace = true" in from the root's
// [workspace.dependencies]; ok is false when the root has no entry of the key.
func (ws *cargoWorkspace) inherited(d cargoDep) (cargoDep, bool) {
	if ws == nil {
		return d, false
	}
	for _, w := range ws.deps {
		if w.key == d.key {
			d.pkg, d.req, d.path, d.inherit = w.pkg, w.req, w.path, false
			return d, true
		}
	}
	return d, false
}

// cargoPathInside reports whether the repository path p is dir or below it.
func cargoPathInside(dir, p string) bool {
	if p == ".." || strings.HasPrefix(p, "../") {
		return false
	}
	return dir == "." || p == dir || strings.HasPrefix(p, dir+"/")
}

// cargoMemberPath turns a path of members or exclude, written relative to the
// workspace root dir, into a repository path inside it. glob allows the last
// element to be "*". The path may not be absolute, reach outside the root or
// use any other pattern.
func cargoMemberPath(root, entry string, glob bool) (string, error) {
	if strings.HasPrefix(entry, "/") || strings.Contains(entry, "\\") {
		return "", fmt.Errorf("%q is not a path inside the workspace", entry)
	}
	segs := strings.Split(entry, "/")
	for i, s := range segs {
		if !strings.ContainsAny(s, "*?[]{}") {
			continue
		}
		if !glob || i != len(segs)-1 || s != "*" {
			return "", fmt.Errorf("%q is a pattern other than a last element of *", entry)
		}
	}
	p := path.Join(root, entry)
	if !cargoPathInside(root, p) {
		return "", fmt.Errorf("%q is outside the workspace", entry)
	}
	return p, nil
}

// cargoVersionParts reads a rust-version or a toolchain version of one to three
// numeric parts; a part left out is zero.
func cargoVersionParts(s string) ([3]int, bool) {
	var out [3]int
	if !cargoRustVersionRE.MatchString(s) {
		return out, false
	}
	for i, f := range strings.Split(s, ".") {
		n, err := strconv.Atoi(f)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// cargoVersionLess orders two versions made by cargoVersionParts.
func cargoVersionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
