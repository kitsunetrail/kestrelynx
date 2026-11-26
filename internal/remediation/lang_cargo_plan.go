package remediation

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// typeRustBinary is the scanner result type of the crates built into a
// binary that cargo-auditable made, and typeCargo that of a Cargo.lock
// scanned as a file (in an image, or in the source).
const (
	typeRustBinary = "rustbinary"
	typeCargo      = "cargo"
)

// isRustType reports whether a scanner result type is one of the Rust ones.
func isRustType(t string) bool { return t == typeRustBinary || t == typeCargo }

// rustCrate is a crate as an image's binary lists it.
type rustCrate struct{ name, version string }

func (c rustCrate) key() string { return c.name + "@" + c.version }

// rustBinary is what a scan says about one Rust binary of a running image:
// its root crate and the other crates built into it.
type rustBinary struct {
	roots     []rustCrate // the crate the binary was built from (one for a binary Trivy read whole)
	deps      []rustCrate
	truncated bool // the scan's package list was cut short
	// duplicate marks a target the scan lists twice, whichever list is which.
	duplicate bool
}

// rustBinariesOf reads the Rust binaries of the scan of input from its
// package lists.
func rustBinariesOf(input int, s scanner.ImageScan, into map[string]*rustBinary) {
	for _, rp := range s.Packages {
		if rp.Type != typeRustBinary {
			continue
		}
		b := &rustBinary{truncated: s.PackagesTruncated}
		for _, p := range rp.Packages {
			c := rustCrate{p.Name, p.Version}
			if p.Relationship == "root" {
				b.roots = append(b.roots, c)
			} else {
				b.deps = append(b.deps, c)
			}
		}
		k := goBinaryKey(input, rp.Target)
		if prev := into[k]; prev != nil {
			prev.duplicate = true
			continue
		}
		into[k] = b
	}
}

// cargoMemberKey names a package of the workspace by name and version.
func cargoMemberKey(name, version string) string { return name + "@" + version }

// rustSelect keeps, of the Rust findings of a unit, those the workspace can
// have produced. A finding of a Cargo.lock in the image is kept as it is. A
// finding of a binary is kept when the binary's one root crate is a package of
// the workspace (members, by cargoMemberKey): the findings of other binaries
// (a tool that came with the base image, say) are not this source's and are
// dropped without a trace. This is done per running image and binary, before
// findings are grouped by name and version, so that a tool's findings for a
// crate at the same version never join the workspace's own.
//
// A binary whose package list was cut short, or that names no root crate or
// more than one, cannot be compared with the workspace; its findings are kept
// and why says so. So is a finding of a crate that is not in its binary's
// list. The binaries that pass are returned by their key, for the check
// against Cargo.lock (see rustBinaryProblem).
func rustSelect(fs []srcFinding, bins map[string]*rustBinary, members map[string]bool) (kept []srcFinding, passed map[string]*rustBinary, why string) {
	passed = map[string]*rustBinary{}
	type verdict struct {
		keep bool
		ok   bool // the binary can be checked against Cargo.lock
	}
	seen := map[string]verdict{}
	note := func(p string) {
		if why == "" {
			why = p
		}
	}
	for _, lf := range fs {
		if lf.f.Type == typeCargo {
			kept = append(kept, lf)
			continue
		}
		key := goBinaryKey(lf.rank, lf.f.Target)
		b := bins[key]
		v, done := seen[key]
		if !done {
			switch {
			case b == nil:
				v = verdict{keep: true}
				note(fmt.Sprintf("the package list of %s is not available, so it cannot be compared with Cargo.lock", lf.f.Target))
			case b.duplicate:
				v = verdict{keep: true}
				note(fmt.Sprintf("the scan lists the packages of %s more than once, so it cannot be compared with Cargo.lock", lf.f.Target))
			case b.truncated:
				v = verdict{keep: true}
				note(fmt.Sprintf("the package list of %s was cut short, so it cannot be compared with Cargo.lock", lf.f.Target))
			case len(b.roots) != 1:
				v = verdict{keep: true}
				var names []string
				for _, r := range b.roots {
					names = append(names, r.key())
				}
				note(fmt.Sprintf("%s names %d root crates (%s), so it cannot be compared with Cargo.lock", lf.f.Target, len(b.roots), strings.Join(names, ", ")))
			case members[b.roots[0].key()]:
				v = verdict{keep: true, ok: true}
				passed[key] = b
			}
			seen[key] = v
		}
		if !v.keep {
			continue
		}
		kept = append(kept, lf)
		if !v.ok {
			continue
		}
		// A finding of the root crate itself is the workspace's own, not one of
		// its dependencies'.
		if c := (rustCrate{lf.f.Package, lf.f.InstalledVer}); c != b.roots[0] && !containsCrate(b.deps, c) {
			note(fmt.Sprintf("%s reports %s %s, which is not in the binary's crate list", lf.f.Target, lf.f.Package, lf.f.InstalledVer))
		}
	}
	return kept, passed, why
}

func containsCrate(cs []rustCrate, c rustCrate) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

// rustBinaryProblem says why a binary whose root crate is a package of the
// workspace cannot be shown to be built from this Cargo.lock, or "": its root
// crate is a package of the lock, and every other crate built into it is a
// crate of the lock that the lock leads to from the root crate.
func rustBinaryProblem(target string, b *rustBinary, lock *cargoLock) string {
	root := b.roots[0]
	from := lock.find(root.name, root.version, "")
	if from < 0 {
		return fmt.Sprintf("%s was built from %s, which Cargo.lock does not list as a package of the workspace", target, root.key())
	}
	reach := lock.reach(from)
	var bad []string
	for _, d := range b.deps {
		found, reached := false, false
		for _, src := range []string{cratesIOSource, ""} {
			if i := lock.find(d.name, d.version, src); i >= 0 {
				found = true
				reached = reached || reach[i]
			}
		}
		switch {
		case !found:
			bad = append(bad, fmt.Sprintf("%s is built in but Cargo.lock does not list it", d.key()))
		case !reached:
			bad = append(bad, fmt.Sprintf("%s is built in but Cargo.lock does not lead to it from %s", d.key(), root.key()))
		}
	}
	if len(bad) == 0 {
		return ""
	}
	sort.Strings(bad)
	if len(bad) > 5 {
		bad = append(bad[:5], fmt.Sprintf("and %d more", len(bad)-5))
	}
	return fmt.Sprintf("%s, built from %s, does not match this Cargo.lock: %s", target, root.key(), strings.Join(bad, "; "))
}

// CargoRecord is what the plan read of a Rust workspace that the later stages
// go on from.
type CargoRecord struct {
	// LockVersion is the format version of Cargo.lock, 3 or 4.
	LockVersion int `json:"lock_version"`
	// Members are the packages of the workspace, by the directory of their
	// Cargo.toml, with the package ones of the root included.
	Members []CargoMember `json:"members"`
	// GlobDirs are the directories a members entry of the form "dir/*" was
	// expanded in.
	GlobDirs []string `json:"glob_dirs,omitempty"`
	// RustVersion is the lowest rust-version a member declares ("" when none
	// does), and Toolchains are the rust-toolchain files that apply.
	RustVersion string           `json:"rust_version,omitempty"`
	Toolchains  []CargoToolchain `json:"toolchains,omitempty"`
}

// CargoMember is a package of the workspace.
type CargoMember struct {
	Path    string `json:"path"` // the repository path of its directory
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CargoToolchain is the toolchain a rust-toolchain file names. Version is the
// channel when it is a release ("1.N" or "1.N.M") and empty for any other
// (stable, nightly, a dated one).
type CargoToolchain struct {
	Path    string `json:"path"`
	Channel string `json:"channel,omitempty"`
	Version string `json:"version,omitempty"`
}

// cargoReleaseRE is a toolchain channel that names a release.
var cargoReleaseRE = regexp.MustCompile(`^1\.[0-9]+(\.[0-9]+)?$`)

// parseRustToolchain reads a rust-toolchain or rust-toolchain.toml. The TOML
// form has the channel under [toolchain]; a rust-toolchain without that table
// is the old form, whose one line is the channel.
func parseRustToolchain(file string, data []byte) (CargoToolchain, error) {
	tc := CargoToolchain{Path: file}
	text := strings.TrimSpace(string(data))
	if strings.HasSuffix(file, ".toml") || strings.HasPrefix(text, "[") || strings.Contains(text, "\n[toolchain]") {
		doc, err := parseTOML(data)
		if err != nil {
			return tc, fmt.Errorf("%s: %w", file, err)
		}
		if v, ok := doc["toolchain"]; ok {
			t, ok := v.(map[string]any)
			if !ok {
				return tc, fmt.Errorf("%s: toolchain is not a table", file)
			}
			if c, present := t["channel"]; present {
				s, ok := c.(string)
				if !ok {
					return tc, fmt.Errorf("%s: toolchain.channel is not a string", file)
				}
				tc.Channel = s
			}
		}
	} else if text != "" {
		tc.Channel = strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	}
	if cargoReleaseRE.MatchString(tc.Channel) {
		tc.Version = tc.Channel
	}
	return tc, nil
}

// cargoUnit is the state of the reading of one Rust unit's files. A method
// that returns false has given the item its outcome.
type cargoUnit struct {
	r      *run
	it     *LanguageItem
	u      *depUnit
	sha    string
	groups []*findingGroup // what an outcome of the unit lists
	reads  int
}

// manual gives the unit the outcome "manual" with the groups it has.
func (c *cargoUnit) manual(reason Reason, format string, args ...any) {
	unitManual(c.it, c.groups, reason, fmt.Sprintf(format, args...))
}

// refuse gives the unit the outcome of a file that cannot be used.
func (c *cargoUnit) refuse(err error) {
	var ue *UnsupportedError
	if errors.As(err, &ue) {
		c.manual(ue.Reason, "%s", ue.Detail)
		return
	}
	c.manual(ReasonUnparsableSource, "%v", err)
}

// read reads the file at a repository path and records its blob. A file that
// is not there is not an error with missingOK.
func (c *cargoUnit) read(p string, missingOK bool) (content []byte, found, ok bool) {
	if c.reads >= maxCargoFiles {
		c.manual(ReasonWorkspaceUnsupported, "the workspace needs more than %d files to be read", maxCargoFiles)
		return nil, false, false
	}
	if h := c.r.stopReason(); h != nil {
		c.r.deferUnit(c.it, c.groups, h.reason, h.detail)
		return nil, false, false
	}
	c.reads++
	f, err := c.r.p.cfg.GitHub.ReadFile(c.r.ctx, c.u.repo, c.sha, p)
	switch {
	case err == nil:
	case missingOK && errors.Is(err, github.ErrNotFound):
		return nil, false, true
	default:
		c.r.sourceFailure(c.it, c.groups, err, true)
		return nil, false, false
	}
	c.it.Source.Files = append(c.it.Source.Files, SourceFile{Path: f.Path, BlobSHA: f.SHA})
	return f.Content, true, true
}

// list lists a directory; one that is not there is empty.
func (c *cargoUnit) list(dir string) ([]github.Entry, bool) {
	if h := c.r.stopReason(); h != nil {
		c.r.deferUnit(c.it, c.groups, h.reason, h.detail)
		return nil, false
	}
	es, err := c.r.p.cfg.GitHub.ListDirectory(c.r.ctx, c.u.repo, c.sha, dir)
	switch {
	case errors.Is(err, github.ErrNotFound):
		return nil, true
	case err != nil:
		c.r.sourceFailure(c.it, c.groups, err, false)
		return nil, false
	}
	return es, true
}

// cargoWorkspaceInfo is the workspace a unit's directory is the root of.
type cargoWorkspaceInfo struct {
	root     *cargoManifest
	members  []*cargoManifest // the packages, the root's first when it has one
	globDirs []string
}

// keys are the members by cargoMemberKey.
func (w *cargoWorkspaceInfo) keys() map[string]bool {
	out := map[string]bool{}
	for _, m := range w.members {
		out[cargoMemberKey(m.name, m.version)] = true
	}
	return out
}

// loadWorkspace reads the root Cargo.toml and the packages of the workspace:
// the members it lists (paths, and directories under a "dir/*" less the
// ones it excludes), and every package a path dependency of the root or a
// member names inside the root, which Cargo adds as a member. A path
// dependency outside the root or in an excluded directory, a member without a
// Cargo.toml, or a package that is the root of another workspace is not
// handled.
func (c *cargoUnit) loadWorkspace(data []byte) (*cargoWorkspaceInfo, bool) {
	rootDir := c.u.dir
	rm, err := parseCargoManifest(pathIn(rootDir, "Cargo.toml"), data)
	if err != nil {
		c.refuse(err)
		return nil, false
	}
	info := &cargoWorkspaceInfo{root: rm}
	var exclude []string
	if rm.ws != nil {
		for _, e := range rm.ws.exclude {
			p, err := cargoMemberPath(rootDir, e, false)
			if err != nil {
				c.manual(ReasonWorkspaceUnsupported, "%s: workspace.exclude has %v", rm.file, err)
				return nil, false
			}
			exclude = append(exclude, p)
		}
	}
	// Cargo excludes a package when the path of its Cargo.toml starts with an
	// excluded path, so an exclude entry may name the directory or the file.
	excluded := func(dir string) bool {
		file := pathIn(dir, "Cargo.toml")
		for _, e := range exclude {
			if cargoPathInside(e, file) {
				return true
			}
		}
		return false
	}
	dirs := map[string]bool{}
	add := func(m *cargoManifest, isRoot bool) bool {
		if len(info.members) >= maxCargoMembers {
			c.manual(ReasonWorkspaceUnsupported, "the workspace has more than %d packages", maxCargoMembers)
			return false
		}
		switch {
		case !m.hasPackage:
			c.manual(ReasonWorkspaceUnsupported, "%s is a member of the workspace and has no [package]", m.file)
			return false
		case m.ws != nil && !isRoot:
			c.manual(ReasonWorkspaceUnsupported, "%s has a [workspace] of its own and is also a member of the workspace of %s", m.file, rm.file)
			return false
		}
		if !c.inherit(m, rm) {
			return false
		}
		dirs[m.dir] = true
		info.members = append(info.members, m)
		return true
	}
	// open reads and parses the Cargo.toml of a package directory.
	open := func(dir, why string) (*cargoManifest, bool) {
		file := pathIn(dir, "Cargo.toml")
		b, found, ok := c.read(file, true)
		if !ok {
			return nil, false
		}
		if !found {
			c.manual(ReasonDependencyFilesNotFound, "%s has no Cargo.toml, but %s", dir, why)
			return nil, false
		}
		m, err := parseCargoManifest(file, b)
		if err != nil {
			c.refuse(err)
			return nil, false
		}
		return m, true
	}

	// An exclude entry that takes in the root's own Cargo.toml makes Cargo
	// treat the root as outside its workspace.
	if rm.ws != nil && excluded(rootDir) {
		c.manual(ReasonWorkspaceUnsupported, "%s: workspace.exclude takes in the root's own Cargo.toml", rm.file)
		return nil, false
	}
	if rm.hasPackage && !add(rm, true) {
		return nil, false
	}
	if rm.ws != nil {
		for _, e := range rm.ws.members {
			p, err := cargoMemberPath(rootDir, e, true)
			if err != nil {
				c.manual(ReasonWorkspaceUnsupported, "%s: workspace.members has %v", rm.file, err)
				return nil, false
			}
			if path.Base(p) == "*" {
				parent := path.Dir(p)
				es, ok := c.list(parent)
				if !ok {
					return nil, false
				}
				if len(es) == 0 {
					c.manual(ReasonDependencyFilesNotFound, "%s matches nothing; Cargo stops on a pattern that matches no path", e)
					return nil, false
				}
				info.globDirs = append(info.globDirs, parent)
				for _, ent := range es {
					child := pathIn(parent, ent.Name)
					// Cargo skips a file the pattern matches, and stops on a
					// directory without a Cargo.toml. A symlink is not followed
					// here, so what Cargo makes of it is not known.
					switch {
					case ent.Type == github.EntryFile:
						continue
					case ent.Type != github.EntryDir:
						c.manual(ReasonWorkspaceUnsupported, "%s matches %s, which is a %s", e, child, ent.Type)
						return nil, false
					case excluded(child) || dirs[child]:
						continue
					}
					file := pathIn(child, "Cargo.toml")
					b, found, ok := c.read(file, true)
					if !ok {
						return nil, false
					}
					if !found {
						c.manual(ReasonDependencyFilesNotFound, "%s matches the directory %s, which has no Cargo.toml; Cargo stops on it", e, child)
						return nil, false
					}
					m, err := parseCargoManifest(file, b)
					if err != nil {
						c.refuse(err)
						return nil, false
					}
					if !add(m, false) {
						return nil, false
					}
				}
				continue
			}
			// A directory members names is a member even when exclude also
			// names it.
			if dirs[p] {
				continue
			}
			m, ok := open(p, "workspace.members lists it")
			if !ok || !add(m, false) {
				return nil, false
			}
		}
		for _, d := range rm.ws.deps {
			if d.path == "" {
				continue
			}
			if !cargoPathInside(rootDir, d.path) || (excluded(d.path) && !dirs[d.path]) {
				c.manual(ReasonWorkspaceUnsupported, "%s: [workspace.dependencies] %s is at %s, outside the workspace or in an excluded directory", rm.file, d.key, d.path)
				return nil, false
			}
		}
	}
	if rm.ws == nil {
		// A package without a [workspace] is a member of nothing but itself,
		// and what a path dependency of it is built from is not read here.
		for _, d := range rm.deps {
			if d.path != "" {
				c.manual(ReasonWorkspaceUnsupported, "%s: %s %s is a path dependency on %s; path dependencies of a package without a [workspace] are not handled", rm.file, d.table, d.key, d.path)
				return nil, false
			}
		}
	}
	// With a [workspace], a path dependency inside the root makes its package
	// a member, and its own path dependencies are followed in turn.
	for i := 0; rm.ws != nil && i < len(info.members); i++ {
		m := info.members[i]
		for _, d := range m.deps {
			if d.path == "" {
				continue
			}
			if !cargoPathInside(rootDir, d.path) || (excluded(d.path) && !dirs[d.path]) {
				c.manual(ReasonWorkspaceUnsupported, "%s: %s %s is a path dependency on %s, outside the workspace or in an excluded directory", m.file, d.table, d.key, d.path)
				return nil, false
			}
			if dirs[d.path] {
				continue
			}
			dm, ok := open(d.path, fmt.Sprintf("%s depends on it by path", m.file))
			if !ok || !add(dm, false) {
				return nil, false
			}
		}
	}
	seen := map[string]string{}
	for _, m := range info.members {
		if other, dup := seen[m.name]; dup {
			c.manual(ReasonWorkspaceUnsupported, "%s and %s are both a package named %s", other, m.file, m.name)
			return nil, false
		}
		seen[m.name] = m.file
	}
	if rm.ws != nil {
		for _, e := range rm.ws.defaultMembers {
			p, err := cargoMemberPath(rootDir, e, false)
			if err != nil || !dirs[p] {
				c.manual(ReasonWorkspaceUnsupported, "%s: workspace.default-members has %q, which is not a path of a member", rm.file, e)
				return nil, false
			}
		}
	}
	return info, true
}

// inherit fills in what a package takes from the workspace root rm: the
// version and rust-version it says "workspace = true" for, and the
// dependencies it inherits.
func (c *cargoUnit) inherit(m, rm *cargoManifest) bool {
	if m.versionInherited {
		if rm.ws == nil || rm.ws.version == "" {
			c.manual(ReasonCargoManifestUnsupported, "%s inherits its version, and [workspace.package] of %s sets none", m.file, rm.file)
			return false
		}
		m.version = rm.ws.version
	}
	if m.rustVersionInherited {
		if rm.ws == nil || rm.ws.rustVersion == "" {
			c.manual(ReasonCargoManifestUnsupported, "%s inherits its rust-version, and [workspace.package] of %s sets none", m.file, rm.file)
			return false
		}
		m.rustVersion = rm.ws.rustVersion
	}
	for i, d := range m.deps {
		if !d.inherit {
			continue
		}
		nd, ok := rm.ws.inherited(d)
		if !ok {
			c.manual(ReasonCargoManifestUnsupported, "%s: %s %s inherits from the workspace, and [workspace.dependencies] of %s has no %s", m.file, d.table, d.key, rm.file, d.key)
			return false
		}
		m.deps[i] = nd
	}
	return true
}

// surroundings records what lies around the unit's directory that changes
// what Cargo does there, and gives the unit its outcome when something is in
// the way: the Cargo.toml of a directory above (a workspace root it may
// belong to), a .cargo/config.toml or .cargo/config in the directory or above
// it, and the rust-toolchain files. What is not there is recorded as looked
// for, since a file added later would change what an update is made from.
// The toolchains found are returned.
func (c *cargoUnit) surroundings(entries []github.Entry) ([]CargoToolchain, bool) {
	dirs := []string{c.u.dir}
	for d := c.u.dir; d != "." && d != ""; {
		d = path.Dir(d)
		if d == "" || d == "/" {
			d = "."
		}
		dirs = append(dirs, d)
	}
	var toolchains []CargoToolchain
	for i, dir := range dirs {
		es := entries
		if i > 0 {
			var ok bool
			if es, ok = c.list(dir); !ok {
				return nil, false
			}
			name := pathIn(dir, "Cargo.toml")
			e, present := byName(es, "Cargo.toml")
			switch {
			case !present:
				c.it.Source.Absent = append(c.it.Source.Absent, name)
			case e.Type != github.EntryFile:
				c.manual(ReasonDependencyFileUnusable, "%s is a %s", name, e.Type)
				return nil, false
			default:
				b, _, ok := c.read(name, false)
				if !ok {
					return nil, false
				}
				doc, err := parseTOML(b)
				if err != nil {
					c.manual(ReasonUnparsableSource, "%s: %v", name, err)
					return nil, false
				}
				if _, has := doc["workspace"]; has {
					c.manual(ReasonWorkspaceUnsupported, "%s has a [workspace], which Cargo applies to the directories below it; the unit's directory may be a member", name)
					return nil, false
				}
			}
		}

		cfgDir := pathIn(dir, ".cargo")
		var sub []github.Entry
		if e, present := byName(es, ".cargo"); present {
			if e.Type != github.EntryDir {
				c.manual(ReasonUnsupportedSource, "%s is a %s, so whether it holds Cargo's configuration is not known", cfgDir, e.Type)
				return nil, false
			}
			var ok bool
			if sub, ok = c.list(cfgDir); !ok {
				return nil, false
			}
		}
		for _, n := range []string{"config.toml", "config"} {
			if _, present := byName(sub, n); present {
				c.manual(ReasonUnsupportedSource, "%s exists; Cargo's configuration can change where crates come from and how they resolve", pathIn(cfgDir, n))
				return nil, false
			}
			c.it.Source.Absent = append(c.it.Source.Absent, pathIn(cfgDir, n))
		}

		for _, n := range []string{"rust-toolchain", "rust-toolchain.toml"} {
			name := pathIn(dir, n)
			e, present := byName(es, n)
			switch {
			case !present:
				c.it.Source.Absent = append(c.it.Source.Absent, name)
			case e.Type != github.EntryFile:
				c.manual(ReasonDependencyFileUnusable, "%s is a %s", name, e.Type)
				return nil, false
			default:
				b, _, ok := c.read(name, false)
				if !ok {
					return nil, false
				}
				tc, err := parseRustToolchain(name, b)
				if err != nil {
					c.refuse(err)
					return nil, false
				}
				toolchains = append(toolchains, tc)
			}
		}
	}
	return toolchains, true
}

// cargoRequirement is a version requirement a Cargo.toml puts on a crate.
type cargoRequirement struct {
	file, pkg, table, key, req string
}

// analyseCargoUnit plans the Rust item of a unit whose directory has a
// Cargo.toml: it reads the workspace the directory is the root of, keeps the
// findings of the binaries built from one of its packages (rustSelect), and
// matches the findings against Cargo.lock by name and version. The files that
// could change what Cargo does (patch, replace, a source other than crates.io,
// a configuration file, a Cargo.toml above that has a workspace) send the
// unit to a person; the absence of the ones looked for is recorded. Nothing
// is resolved or updated here.
//
// It returns the packages of the workspace by cargoMemberKey (nil when the
// workspace was not read) and whether the unit has an item (none when no
// finding comes from a binary built from the workspace). Until the workspace
// has been read an outcome carries every Rust finding of the unit.
func (r *run) analyseCargoUnit(it *LanguageItem, u *depUnit, entries []github.Entry) (map[string]bool, bool) {
	intel := r.p.cfg.Intel
	all := groupLanguageFindings(u.rustPinned, intel)
	setPriorityOf(it, all)
	it.Manager = ManagerCargo
	it.Key = u.key + "#" + string(ManagerCargo)
	c := &cargoUnit{r: r, it: it, u: u, sha: it.Source.CommitSHA, groups: all}
	keepAll := len(all) > 0

	rootFile := pathIn(u.dir, "Cargo.toml")
	if e, _ := byName(entries, "Cargo.toml"); e.Type != github.EntryFile {
		c.manual(ReasonDependencyFileUnusable, "%s is a %s", rootFile, e.Type)
		return nil, keepAll
	}
	data, _, ok := c.read(rootFile, false)
	if !ok {
		return nil, keepAll
	}
	ws, ok := c.loadWorkspace(data)
	if !ok {
		return nil, keepAll
	}
	members := ws.keys()

	kept, bins, why := rustSelect(u.rustPinned, u.rustBins, members)
	groups := groupLanguageFindings(kept, intel)
	if len(groups) == 0 {
		return members, false
	}
	c.groups = groups
	setPriorityOf(it, groups)
	if why != "" {
		c.manual(ReasonRustBinaryNotFromSource, "%s", why)
		return members, true
	}

	lockPath := pathIn(u.dir, "Cargo.lock")
	switch e, present := byName(entries, "Cargo.lock"); {
	case !present:
		c.manual(ReasonDependencyFilesNotFound, "the directory has Cargo.toml but no Cargo.lock")
		return members, true
	case e.Type != github.EntryFile:
		c.manual(ReasonDependencyFileUnusable, "%s is a %s", lockPath, e.Type)
		return members, true
	}
	toolchains, ok := c.surroundings(entries)
	if !ok {
		return members, true
	}
	lockData, _, ok := c.read(lockPath, false)
	if !ok {
		return members, true
	}
	lock, err := parseCargoLock(lockData)
	if err != nil {
		c.refuse(err)
		return members, true
	}

	if why := cargoLockMismatch(lock, ws); why != "" {
		c.manual(ReasonDependencyFileUnusable, "%s", why)
		return members, true
	}

	targets := make([]string, 0, len(bins))
	for t := range bins {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, k := range targets {
		if p := rustBinaryProblem(strings.SplitN(k, "\x00", 2)[1], bins[k], lock); p != "" {
			c.manual(ReasonRustBinaryNotFromSource, "%s", p)
			return members, true
		}
	}

	rec := &CargoRecord{LockVersion: lock.version, GlobDirs: ws.globDirs, Toolchains: toolchains}
	var lowest [3]int
	reqs := map[string][]cargoRequirement{}
	for _, m := range ws.members {
		rec.Members = append(rec.Members, CargoMember{Path: m.dir, Name: m.name, Version: m.version})
		if parts, ok := cargoVersionParts(m.rustVersion); ok && (rec.RustVersion == "" || cargoVersionLess(parts, lowest)) {
			rec.RustVersion, lowest = m.rustVersion, parts
		}
		for _, d := range m.deps {
			if d.path == "" && d.req != "" {
				reqs[d.pkg] = append(reqs[d.pkg], cargoRequirement{m.file, m.name, d.table, d.key, d.req})
			}
		}
	}
	sort.Slice(rec.Members, func(i, j int) bool { return rec.Members[i].Path < rec.Members[j].Path })
	it.Cargo = rec

	// The packages of the workspace as the lock lists them.
	var memberIdx []int
	for _, m := range ws.members {
		if i := lock.find(m.name, m.version, ""); i >= 0 {
			memberIdx = append(memberIdx, i)
		}
	}
	pkgs := make([]LanguagePackage, 0, len(groups))
	for _, g := range groups {
		pkgs = append(pkgs, cargoMatch(lock, memberIdx, reqs, lockPath, g))
	}
	it.Packages = pkgs
	classify(it)
	return members, true
}

// cargoMatch matches one running package against Cargo.lock and chooses its
// target version. The package is a candidate when the lock holds exactly one
// version of the crate, at the installed version, from crates.io; it is direct
// when a package of the workspace lists it as a dependency. The target is
// the lowest fix in the installed version's series (see cargoTarget), and
// every requirement a Cargo.toml puts on the crate must allow it.
func cargoMatch(lock *cargoLock, memberIdx []int, reqs map[string][]cargoRequirement, lockPath string, g *findingGroup) LanguagePackage {
	p := LanguagePackage{Name: g.Name, Ecosystem: g.Type, Installed: g.Installed, CVEs: g.cves, Origins: g.origins}
	idx := lock.byName[g.Name]
	if len(idx) == 0 {
		manualPackage(&p, ReasonNotFoundInSource, "Cargo.lock does not list the crate")
		return p
	}
	reg, own := -1, -1
	for _, i := range idx {
		c := lock.crates[i]
		if c.version != g.Installed {
			continue
		}
		if c.registry() {
			reg = i
		} else {
			own = i
		}
	}
	switch {
	case reg < 0 && own < 0:
		manualPackage(&p, ReasonNotFoundInSource, fmt.Sprintf("Cargo.lock locks %s at %s, not %s", g.Name, strings.Join(lock.versionsOf(g.Name), ", "), g.Installed))
		return p
	case reg >= 0 && own >= 0:
		manualPackage(&p, ReasonNonRegistrySource, fmt.Sprintf("Cargo.lock has both a package of the workspace and a crate of crates.io named %s %s, and a finding does not say which it is of", g.Name, g.Installed))
		return p
	case reg < 0:
		manualPackage(&p, ReasonNonRegistrySource, fmt.Sprintf("%s %s is a package of the workspace, not a crate of crates.io", g.Name, g.Installed))
		return p
	}
	if len(idx) > 1 {
		manualPackage(&p, ReasonMultipleVersions, fmt.Sprintf("Cargo.lock locks %s at %s", g.Name, strings.Join(lock.versionsOf(g.Name), ", ")))
		return p
	}
	direct := false
	for _, m := range memberIdx {
		for _, d := range lock.crates[m].deps {
			if d == reg {
				direct = true
			}
		}
	}
	o := SourceOccurrence{Path: lockPath, Version: lock.crates[reg].version, Direct: direct, Matched: true}
	p.Occurrences = []SourceOccurrence{o}
	p.Relation = relationOf(p.Occurrences)

	target, reason, detail := cargoTarget(g.Installed, g.cves)
	if reason != "" {
		manualPackage(&p, reason, detail)
		return p
	}
	p.SelectionLowerBound = target
	tv, _ := parseCargoVersion(target)
	for _, rq := range reqs[g.Name] {
		ok, evaluable := cargoReqAllows(rq.req, tv)
		switch {
		case !evaluable:
			manualPackage(&p, ReasonRangeNotEvaluable, fmt.Sprintf("%s (package %s) requires %s %q, which cannot be judged against %s", rq.file, rq.pkg, g.Name, rq.req, target))
			return p
		case !ok:
			manualPackage(&p, ReasonRangeExcludesFix, fmt.Sprintf("%s (package %s) requires %s %q, which does not allow %s", rq.file, rq.pkg, g.Name, rq.req, target))
			return p
		}
	}
	p.Action, p.Reason = ActionUpdate, ReasonUpdateCandidateInSource
	return p
}

// cargoLockMismatch says why a Cargo.lock does not fit the packages of the
// workspace, or "": every package of the workspace is in the lock once, as an
// entry without a source, every such entry is a package of the workspace, and
// no crate of crates.io has the name and version of one of them (a finding
// does not say which it is of).
func cargoLockMismatch(lock *cargoLock, ws *cargoWorkspaceInfo) string {
	members := ws.keys()
	for _, m := range ws.members {
		if lock.find(m.name, m.version, "") < 0 {
			return fmt.Sprintf("Cargo.lock does not list the package %s %s of %s as a package of the workspace", m.name, m.version, m.file)
		}
	}
	for _, c := range lock.crates {
		switch {
		case c.registry() && members[cargoMemberKey(c.name, c.version)]:
			return fmt.Sprintf("Cargo.lock lists both a package of the workspace and a crate of crates.io named %s %s", c.name, c.version)
		case !c.registry() && !members[cargoMemberKey(c.name, c.version)]:
			return fmt.Sprintf("Cargo.lock lists %s %s without a source, and no package of the workspace is that", c.name, c.version)
		}
	}
	return ""
}
