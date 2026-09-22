package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// auxLimits bounds every read the auxiliary collection makes. A container's
// module trees can hold hundreds of thousands of files, and an unbounded
// read would turn a measurement of a sampling window into a measurement of
// a filesystem walk. Every limit that actually bites is recorded as a
// truncation, so a later lookup miss is never silently mistaken for "no
// package owns this file".
type auxLimits struct {
	// ScanDepth is how many directory levels below each scan root the
	// search for module directories descends.
	ScanDepth int
	// DirEntries is the per-directory-tree cap on recorded paths,
	// RecordFiles the per-distribution cap on RECORD lines, OwnedPaths the
	// cap on package-database index entries, and Symlinks the cap on link
	// targets recorded while a module tree is being listed.
	DirEntries int
	RecordFile int
	OwnedPaths int
	Symlinks   int
	// ExtraSymlinks caps the links recorded from /etc/alternatives,
	// /etc/localtime, the conventional bin/sbin directories, and the
	// operating-system package database's own file list — a separate
	// budget from Symlinks because these come from places a module tree
	// never touches and the package database's file list alone can run to
	// hundreds of thousands of entries.
	ExtraSymlinks int
}

func defaultAuxLimits() auxLimits {
	return auxLimits{ScanDepth: 8, DirEntries: 200000, RecordFile: 100000, OwnedPaths: 400000, Symlinks: 100000, ExtraSymlinks: 20000}
}

// auxScanRoots are the directories searched for language-package layouts.
// The whole filesystem is not walked: the cost is unbounded and the
// interesting trees are installed in a small number of conventional
// places. A layout outside these shows up as an absent mapping input
// rather than as a wrong one, which is the safe direction.
var auxScanRoots = []string{
	"/app", "/srv", "/opt", "/home", "/usr/lib", "/usr/lib64", "/usr/local/lib",
	"/usr/local/lib64", "/usr/share", "/usr/src", "/var/www", "/workspace", "/code", "/lib",
}

// usrMergeLinks are the top-level directories that, on a merged-/usr
// image, are symlinks into /usr. They are recorded by name because they
// are what makes two spellings of one path — /lib/x/libc.so.6 and
// /usr/lib/x/libc.so.6 — name the same file, and an observed path and a
// database path can arrive in either spelling.
var usrMergeLinks = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// topBinDirs are the conventional $PATH directories, read for their own
// direct-entry symlinks in addition to what usrMergeLinks and the package
// database's file list already cover. A tool switched by
// update-alternatives (mawk selected as /usr/bin/awk, say) is a symlink no
// package owns at either hop, so its target is only ever knowable from a
// reading taken while the container still existed.
var topBinDirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}

// collectAuxiliaryInputs reads everything the file-to-package mapping needs
// from one container's filesystem, through one process's view of it. It is
// taken once per (mount view, database generation): a database that changes
// mid-window produces a second generation and a second reading, so a saved
// record always says which layout each sample was looking at.
// ownedPathCache is one already-built operating-system path index, reused
// while the database generation it came from is still the one on disk.
// Rebuilding it every sample would dominate the collection's cost on a
// full distribution image, and it cannot change without the database
// generation changing with it.
type ownedPathCache struct {
	dbGeneration string
	paths        []OwnedPathEntry
	truncated    bool
	// dbPaths is every path the package database's own file list names
	// for this generation, sorted, cached the same way paths above is and
	// for the same reason: which paths the database names cannot change
	// without the generation changing, so enumerating and sorting them is
	// a cost worth paying once per generation rather than once per sample.
	//
	// Which of them currently happen to be symlinks is deliberately never
	// cached alongside this list (see packageDBSymlinks's own comment):
	// a path can turn into a symlink, or stop being one, without the
	// database's own generation changing at all, so every reading
	// re-examines the full list itself rather than trusting an earlier
	// reading's own answer for it.
	dbPaths []string
}

func collectAuxiliaryInputs(root string, pid int, mountViewID string, idx *pkgIndex, info PkgDBGenerationInfo, limits auxLimits, owned *ownedPathCache) AuxiliaryInputs {
	now := time.Now().UTC()
	aux := AuxiliaryInputs{
		MountViewID: mountViewID, DBGeneration: info.DBGeneration,
		CollectedAt: now, FirstSeen: now, LastSeen: now, ReadThroughPID: pid,
	}
	// The generation this reading was taken through. Everything below was
	// read from that process's view of the filesystem, so if the process
	// was replaced while it was being read, the reading describes whatever
	// replaced it.
	if st, err := readStarttime(pid); err == nil {
		aux.ReadThroughStarttime = st
	}
	if mnt, err := readNSLink(pid, "mnt"); err == nil {
		aux.ReadThroughMountView = mnt
	}

	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid)); err == nil {
		aux.Mountinfo = string(data)
	} else {
		aux.Errors = append(aux.Errors, "mountinfo: "+err.Error())
	}

	for _, p := range usrMergeLinks {
		target, err := os.Readlink(path.Join(root, p))
		if err != nil {
			continue // not a symlink, or not present: neither is an error
		}
		entry := SymlinkEntry{Path: p, Target: target}
		if resolved, rerr := resolveInRoot(root, p); rerr == nil {
			entry.Resolved = resolved
		} else {
			entry.Error = rerr.Error()
		}
		aux.UsrMerge = append(aux.UsrMerge, entry)
	}

	// Symlinks no directory listing above would ever find: a tool
	// update-alternatives switched (mawk selected as /usr/bin/awk, say) or
	// a distribution-wide link (/etc/localtime, say) is owned by no
	// package at either hop, and is only ever resolvable at all from a
	// chain saved while the container still existed. The narrow, always-
	// present sources are read first so the shared budget favors them over
	// the package database's own file list, which alone can run to
	// hundreds of thousands of entries.
	extraBudget := limits.ExtraSymlinks
	if e := singleSymlink(root, "/etc/localtime", &extraBudget); e != nil {
		aux.Symlinks = append(aux.Symlinks, *e)
	}
	aux.Symlinks = append(aux.Symlinks, dirSymlinks(root, "/etc/alternatives", &extraBudget, &aux)...)
	for _, d := range topBinDirs {
		aux.Symlinks = append(aux.Symlinks, dirSymlinks(root, d, &extraBudget, &aux)...)
	}

	nodeRoots, pyDirs := findModuleRoots(root, limits, &aux)
	for _, d := range pyDirs {
		aux.PythonSearchDirs = append(aux.PythonSearchDirs, PythonSearchDir{Path: d, Derivation: "filesystem_scan"})
	}

	symlinkBudget := limits.Symlinks
	for _, r := range nodeRoots {
		listing, links := listTree(root, r, "node_modules", limits.DirEntries, &symlinkBudget)
		aux.ModuleDirs = append(aux.ModuleDirs, listing)
		aux.Symlinks = append(aux.Symlinks, links...)
		if listing.Truncated {
			aux.Truncations = append(aux.Truncations, AuxTruncation{
				Kind: "module_dir", Path: r, Limit: limits.DirEntries,
				Reason: "directory listing stopped at the entry limit; a path absent from it may still exist",
			})
		}
	}
	for _, r := range pyDirs {
		listing, links := listTree(root, r, "python_search_dir", limits.DirEntries, &symlinkBudget)
		aux.ModuleDirs = append(aux.ModuleDirs, listing)
		aux.Symlinks = append(aux.Symlinks, links...)
		if listing.Truncated {
			aux.Truncations = append(aux.Truncations, AuxTruncation{
				Kind: "module_dir", Path: r, Limit: limits.DirEntries,
				Reason: "directory listing stopped at the entry limit; a path absent from it may still exist",
			})
		}
		records, eggs := readDistributions(root, r, limits.RecordFile, &aux)
		aux.DistInfoRecords = append(aux.DistInfoRecords, records...)
		aux.EggInfoDists = append(aux.EggInfoDists, eggs...)
	}
	if symlinkBudget <= 0 {
		aux.Truncations = append(aux.Truncations, AuxTruncation{
			Kind: "symlinks", Limit: limits.Symlinks,
			Reason: "the symlink budget was exhausted; some link targets were not recorded",
		})
	}

	// The language layout above is re-read on every sample: a package
	// manager for a language installs and removes packages without
	// touching the operating system's database, so waiting for that
	// database to change would miss every such update. The operating
	// system's own (path, owner) list is not re-read that way — it cannot
	// change without its database generation changing, and rebuilding it
	// each time would dominate the collection's cost on a full image.
	var dbPaths []string
	switch {
	case owned != nil && owned.dbGeneration == info.DBGeneration && owned.paths != nil:
		aux.OwnedPaths, aux.OwnedPathsTruncated = owned.paths, owned.truncated
		dbPaths = owned.dbPaths
	default:
		aux.OwnedPaths, aux.OwnedPathsTruncated = ownedPathIndex(idx, limits.OwnedPaths)
		dbPaths = sortedDBPaths(idx)
		if owned != nil {
			owned.dbGeneration, owned.paths, owned.truncated, owned.dbPaths = info.DBGeneration, aux.OwnedPaths, aux.OwnedPathsTruncated, dbPaths
		}
	}
	// Which of dbPaths are currently directories, and which are currently
	// symlinks (and what each currently points at), is found fresh on
	// every reading, cache hit or not, and the symlink half scored against
	// this sample's own shared budget: see packageDBFileInfo's own comment
	// for why neither answer is cached alongside the (path, owner) list,
	// and why a truncation here has to be recorded on every reading it
	// actually affects, not only remembered from whichever reading first
	// cached dbPaths.
	//
	// aux.OwnedPaths is never annotated in place: it may be the cached
	// slice a previous reading (or another reading sharing this same
	// generation) also holds, and mutating it there would leak this
	// reading's own directory findings into every one of them.
	dirs, dbSymlinks, dbTruncated := packageDBFileInfo(root, dbPaths, &extraBudget)
	annotated := make([]OwnedPathEntry, len(aux.OwnedPaths))
	for i, e := range aux.OwnedPaths {
		e.IsDir = dirs[e.Path]
		annotated[i] = e
	}
	aux.OwnedPaths = annotated
	aux.Symlinks = append(aux.Symlinks, dbSymlinks...)
	if aux.OwnedPathsTruncated {
		aux.Truncations = append(aux.Truncations, AuxTruncation{
			Kind: "owned_paths", Limit: limits.OwnedPaths,
			Reason: "the package-database path index was cut short; a path absent from it may still be owned",
		})
	}
	if extraBudget <= 0 || dbTruncated {
		aux.Truncations = append(aux.Truncations, AuxTruncation{
			Kind: "extra_symlinks", Limit: limits.ExtraSymlinks,
			Reason: "the alternatives/bin-directory/package-database symlink budget was exhausted; some link targets were not recorded",
		})
	}
	aux.AuxGeneration = auxGeneration(root, aux)
	return aux
}

// singleSymlink reads one exact path's own link, decrementing budget only on
// success: a path that is not a symlink, or is not there at all, is neither
// an error nor a use of the budget.
func singleSymlink(root, p string, budget *int) *SymlinkEntry {
	if *budget <= 0 {
		return nil
	}
	// p's own parent directory is resolved inside root first (see
	// resolveInRoot): an intermediate component that is itself an
	// absolute symlink in the container (the container's own /etc, say,
	// in the unlikely case it is one) must never be followed by a plain
	// host path join, which would escape root and read whatever that
	// absolute path happens to be on the host instead. p's own final
	// component is read directly with a plain Readlink, never through
	// resolveInRoot, since that would follow p itself rather than report
	// what it is a link to.
	resolvedDir, rerr := resolveInRoot(root, path.Dir(p))
	if rerr != nil {
		return nil
	}
	target, err := os.Readlink(path.Join(root, resolvedDir, path.Base(p)))
	if err != nil {
		return nil
	}
	entry := SymlinkEntry{Path: p, Target: target}
	if resolved, rerr := resolveInRoot(root, p); rerr == nil {
		entry.Resolved = resolved
	}
	*budget--
	return &entry
}

// dirSymlinks records the target of every direct child of dir that is
// itself a symlink, without descending into any subdirectory: this is used
// for /etc/alternatives and the conventional bin/sbin directories, both of
// which are flat by convention, not module trees that need a recursive
// listing of their own. A directory that is not there is not an error; one
// that is there and cannot be read is, since whatever it holds would
// otherwise be silently absent from every later lookup.
//
// dir itself is resolved inside root before it is ever joined onto a host
// path (see resolveInRoot and singleSymlink's own comment): on a
// merged-/usr image dir may be /bin or /sbin, themselves absolute symlinks
// to /usr/bin or /usr/sbin inside the container, and a plain path.Join
// would have the host's own path resolution follow that absolute target
// against the host's real root instead of the container's.
func dirSymlinks(root, dir string, budget *int, aux *AuxiliaryInputs) []SymlinkEntry {
	resolvedDir, rerr := resolveInRoot(root, dir)
	if rerr != nil {
		// dir does not resolve inside the container at all (a dangling
		// intermediate link, say) — nothing under it can be listed, which
		// is a fact about the path's own layout, not a read failure worth
		// recording as one.
		return nil
	}
	entries, err := os.ReadDir(path.Join(root, resolvedDir))
	if err != nil {
		if !os.IsNotExist(err) {
			aux.Errors = append(aux.Errors, fmt.Sprintf("symlink scan %s: %v", dir, err))
		}
		return nil
	}
	var out []SymlinkEntry
	for _, e := range entries {
		if e.Type()&os.ModeSymlink == 0 {
			continue
		}
		if *budget <= 0 {
			break
		}
		child := path.Join(dir, e.Name())
		target, lerr := os.Readlink(path.Join(root, resolvedDir, e.Name()))
		if lerr != nil {
			// readdir already said this entry is a symlink; a readlink
			// failure here is its own file-level problem, not evidence
			// that the entry is something else, and is skipped the same
			// way listTree already skips one.
			continue
		}
		entry := SymlinkEntry{Path: child, Target: target}
		if resolved, rerr := resolveInRoot(root, child); rerr == nil {
			entry.Resolved = resolved
		}
		out = append(out, entry)
		*budget--
	}
	return out
}

// dbSymlinkDirs memoizes directory resolutions across many
// package-database paths that share a parent directory, the same
// justification dbPathNormalizer's own cache gives (a database lists tens
// of thousands of paths across a few thousand directories) and reused here
// for the same reason: resolving the same directory once per unique value
// rather than once per path keeps packageDBSymlinks from paying
// resolveInRoot's own cost per path when most paths share a handful of
// directories.
//
// Unlike dbPathNormalizer's own cache, a directory that fails to resolve
// is never silently joined onto its own unresolved spelling. That
// fallback is safe for dbPathNormalizer's own use — comparing strings — but
// not here, where the resolved value is joined onto root and read with a
// live syscall: an intermediate absolute symlink the container itself
// cannot resolve (a dangling /opt/redirect -> /usr on an image with no
// /usr at all, say) would otherwise fall through to whatever the host's
// own real directory of that name happens to hold instead of failing
// closed.
type dbSymlinkDirs struct {
	root  string
	cache map[string]dbSymlinkDirResolution
}

type dbSymlinkDirResolution struct {
	path string
	err  error
}

func (d *dbSymlinkDirs) resolve(dir string) (string, error) {
	if r, ok := d.cache[dir]; ok {
		return r.path, r.err
	}
	resolved, err := resolveInRoot(d.root, dir)
	d.cache[dir] = dbSymlinkDirResolution{resolved, err}
	return resolved, err
}

func (d *dbSymlinkDirs) readlink(p string) (string, error) {
	resolvedDir, err := d.resolve(path.Dir(p))
	if err != nil {
		return "", err
	}
	return os.Readlink(path.Join(d.root, resolvedDir, path.Base(p)))
}

// lstat reports p's own file info, p's own parent directory resolved
// inside root first for the same reason readlink's own does: an
// intermediate absolute symlink must never be joined onto a plain host
// path. p's own final component is lstat'd directly, never itself
// resolved, so a symlink's own type is reported, not whatever it points
// at.
func (d *dbSymlinkDirs) lstat(p string) (os.FileInfo, error) {
	resolvedDir, err := d.resolve(path.Dir(p))
	if err != nil {
		return nil, err
	}
	return os.Lstat(path.Join(d.root, resolvedDir, path.Base(p)))
}

// sortedDBPaths returns every path an operating-system package database's
// own file list names, sorted so two runs over the same database produce
// byte-identical output.
func sortedDBPaths(idx *pkgIndex) []string {
	if idx == nil {
		return nil
	}
	paths := make([]string, 0, len(idx.byPath))
	for p := range idx.byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// packageDBFileInfo re-examines every path among paths (an
// operating-system package database's own file list, see sortedDBPaths)
// on every reading, cache hit or not, for two live filesystem properties
// dpkg's own database generation says nothing about: which are currently
// directories, and which are currently symlinks (recording each symlink's
// current raw target). dbPathNormalizer deliberately never follows a
// listed path's own final component (see its own comment: following it
// invented ownership, crediting one package's symlink to whatever package
// ships the file it happens to point at), so a listed symlink is only
// ever recorded here, for matching to resolve as a chain and, where the
// two hops disagree, report the conflict it is rather than silently
// prefer one side.
//
// Caching either answer across readings of the same generation (as an
// earlier version of this collector did for the symlink half alone) would
// miss a plain file replaced by a directory, or the reverse, or a path
// that turned into a symlink — none of which changes dpkg's own database,
// the only invalidation signal this collector has for the (path, owner)
// list itself (see ownedPathCache.dbPaths, which is cached, and
// ownedPathIndex's own comment). Answering both from the one lstat this
// collector already had to pay per path to answer either costs nothing
// the symlink table alone did not already.
//
// paths is expected in sorted order (as sortedDBPaths returns it) so the
// symlink entries recorded before budget runs out do not depend on map
// iteration order. dirs carries no such limit: a directory flag is not a
// new list entry with a size to bound, only an annotation collectAux
// applies to an OwnedPathEntry the generation-cached list already has.
func packageDBFileInfo(root string, paths []string, budget *int) (dirs map[string]bool, symlinks []SymlinkEntry, truncated bool) {
	d := &dbSymlinkDirs{root: root, cache: map[string]dbSymlinkDirResolution{}}
	dirs = map[string]bool{}
	for _, p := range paths {
		fi, err := d.lstat(p)
		if err != nil {
			// Gone, or its own directory does not resolve inside this
			// container at all (see dbSymlinkDirs's own comment): neither
			// a directory nor a symlink is recorded, and neither is an
			// error — a database listing a path the filesystem no longer
			// has, or has restructured, is not a shortfall in this read.
			continue
		}
		if fi.IsDir() {
			dirs[p] = true
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if *budget <= 0 {
			// The directory pass above never stops for this: only
			// recording this path's own symlink target is skipped, not
			// examining the paths still to come.
			truncated = true
			continue
		}
		target, err := d.readlink(p)
		if err != nil {
			continue
		}
		entry := SymlinkEntry{Path: p, Target: target}
		if resolved, rerr := resolveInRoot(root, p); rerr == nil {
			entry.Resolved = resolved
		}
		symlinks = append(symlinks, entry)
		*budget--
	}
	return dirs, symlinks, truncated
}

// auxGeneration fingerprints everything this reading describes.
//
// It covers the layout — the size and modification time of every
// installed-file manifest and module directory, the link targets, the
// mount table — and it covers the operating-system path index as well, by
// the database generation that produced it.
//
// Both halves belong in it. The layout changes without the database
// changing, which is why the fingerprint is not the database's. But the
// database changes without the layout changing too, and the index this
// reading carries is then a different index: a reading keyed only on the
// layout would keep the old index and merely relabel it, and no later
// re-reading of the saved data could tell that had happened.
func auxGeneration(root string, aux AuxiliaryInputs) string {
	h := sha256.New()
	fmt.Fprintf(h, "db:%s|%d\n", aux.DBGeneration, len(aux.OwnedPaths))
	// Which owned paths are currently directories is a live filesystem
	// property dpkg's own database generation does not track (see
	// packageDBFileInfo), so a directory replaced by a plain file within
	// the same generation has to change this fingerprint on its own
	// account, or a later reading's own re-lstat would go unnoticed by
	// everything that keys a saved reading on its generation.
	for _, e := range aux.OwnedPaths {
		if e.IsDir {
			fmt.Fprintf(h, "od:%s\n", e.Path)
		}
	}
	stat := func(p string) {
		fmt.Fprintf(h, "p:%s", p)
		if fi, err := os.Stat(path.Join(root, p)); err == nil {
			fmt.Fprintf(h, "|%d|%d", fi.Size(), fi.ModTime().UnixNano())
		} else {
			fmt.Fprintf(h, "|absent")
		}
		fmt.Fprint(h, "\n")
	}
	for _, r := range aux.DistInfoRecords {
		stat(r.RecordPath)
		// The manifest's own content decides ownership, so a rewrite that
		// preserved size and time would otherwise go unnoticed.
		fmt.Fprintf(h, "n:%d\n", len(r.Files))
		for _, f := range r.Files {
			fmt.Fprintf(h, "f:%s\n", f)
		}
	}
	for _, e := range aux.EggInfoDists {
		stat(e.Dir)
	}
	for _, m := range aux.ModuleDirs {
		stat(m.Root)
		fmt.Fprintf(h, "e:%d\n", len(m.Entries))
		for _, entry := range m.Entries {
			fmt.Fprintf(h, "d:%s\n", entry)
		}
	}
	for _, l := range append(append([]SymlinkEntry{}, aux.Symlinks...), aux.UsrMerge...) {
		fmt.Fprintf(h, "l:%s->%s|%s\n", l.Path, l.Target, l.Resolved)
	}
	for _, d := range aux.PythonSearchDirs {
		fmt.Fprintf(h, "s:%s\n", d.Path)
	}
	fmt.Fprintf(h, "m:%s\n", aux.Mountinfo)
	return hex.EncodeToString(h.Sum(nil))
}

// ownedPathIndex flattens a package index into the saved form, sorted so
// two runs over the same database produce byte-identical output.
//
// It never touches the filesystem: which paths the database names, and
// which package(s) own each, is exactly what dpkg's own database
// generation already invalidates this cache on — see
// ownedPathCache.paths. Which of those paths are currently directories or
// symlinks is a live filesystem property that generation says nothing
// about at all, so it is read separately, fresh on every reading, by
// packageDBFileInfo instead.
func ownedPathIndex(idx *pkgIndex, limit int) ([]OwnedPathEntry, bool) {
	if idx == nil {
		return nil, false
	}
	paths := make([]string, 0, len(idx.byPath))
	for p := range idx.byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]OwnedPathEntry, 0, len(paths))
	truncated := false
	for _, p := range paths {
		if limit > 0 && len(out) >= limit {
			truncated = true
			break
		}
		for _, owner := range idx.byPath[p] {
			out = append(out, OwnedPathEntry{
				Path: p, DBKind: owner[0], Package: owner[1], Version: idx.versionOf(owner[0], owner[1]),
			})
		}
	}
	return out, truncated
}

// findModuleRoots searches the conventional installation directories for
// node_modules trees and Python search directories. It descends a bounded
// number of levels and does not follow directory symlinks, so a layout
// that links a tree into two places is found once, at the real location.
func findModuleRoots(root string, limits auxLimits, aux *AuxiliaryInputs) (nodeRoots, pythonDirs []string) {
	seenNode, seenPython := map[string]bool{}, map[string]bool{}
	for _, scanRoot := range auxScanRoots {
		var walk func(rel string, depth int)
		walk = func(rel string, depth int) {
			if depth > limits.ScanDepth {
				aux.Truncations = append(aux.Truncations, AuxTruncation{
					Kind: "module_root_scan", Path: rel, Limit: limits.ScanDepth,
					Reason: "the search for module directories stopped at the depth limit",
				})
				return
			}
			entries, err := os.ReadDir(path.Join(root, rel))
			if err != nil {
				// A directory that is there and cannot be read is a gap in
				// the inputs: a module tree under it would never be found,
				// and the packages in it would be reported as unmappable
				// for the wrong reason. One that is simply not there is
				// neither, and is not recorded.
				if !os.IsNotExist(err) {
					aux.Errors = append(aux.Errors, fmt.Sprintf("module directory search %s: %v", rel, err))
				}
				return
			}
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				child := path.Join(rel, e.Name())
				switch e.Name() {
				case "node_modules":
					if !seenNode[child] {
						seenNode[child] = true
						nodeRoots = append(nodeRoots, child)
					}
					// The tree below is listed wholesale by listTree,
					// including its nested node_modules, so the search
					// does not descend into it again.
					continue
				case "site-packages", "dist-packages":
					if !seenPython[child] {
						seenPython[child] = true
						pythonDirs = append(pythonDirs, child)
					}
					continue
				}
				walk(child, depth+1)
			}
		}
		fi, err := os.Lstat(path.Join(root, scanRoot))
		switch {
		case err != nil && os.IsNotExist(err):
			// Not there. Most images carry only a few of these, and an
			// absent one is a fact about the image rather than a gap.
			continue
		case err != nil:
			// There and unreachable. Whatever module trees live under it
			// will never be found, and the packages in them would be
			// reported as unmappable for the wrong reason — so this is a
			// gap in the inputs and is carried into the readiness decision
			// rather than passed over with the absent ones.
			aux.Errors = append(aux.Errors, fmt.Sprintf("module directory search root %s: %v", scanRoot, err))
			continue
		case !fi.IsDir():
			// A link, whose target is walked under its own name.
			continue
		}
		walk(scanRoot, 1)
	}
	sort.Strings(nodeRoots)
	sort.Strings(pythonDirs)
	return nodeRoots, pythonDirs
}

// listTree records the paths under one directory tree, plus the target of
// every symlink it contains. Directories are listed with a trailing "/" so
// a reader can tell a package directory from a file of the same name, and
// symlinked directories are recorded but not descended into, which is what
// keeps a layout that links packages to each other from being walked
// endlessly.
func listTree(root, rel, kind string, limit int, symlinkBudget *int) (ModuleDirListing, []SymlinkEntry) {
	listing := ModuleDirListing{Kind: kind, Root: rel}
	var links []SymlinkEntry

	var walk func(rel string) bool
	walk = func(rel string) bool {
		entries, err := os.ReadDir(path.Join(root, rel))
		if err != nil {
			if listing.Error == "" {
				listing.Error = err.Error()
			}
			return true
		}
		for _, e := range entries {
			if limit > 0 && len(listing.Entries) >= limit {
				listing.Truncated = true
				return false
			}
			child := path.Join(rel, e.Name())
			info, ierr := e.Info()
			if ierr == nil && info.Mode()&os.ModeSymlink != 0 {
				if *symlinkBudget > 0 {
					*symlinkBudget--
					entry := SymlinkEntry{Path: child}
					if target, lerr := os.Readlink(path.Join(root, child)); lerr == nil {
						entry.Target = target
					} else {
						entry.Error = lerr.Error()
					}
					if resolved, rerr := resolveInRoot(root, child); rerr == nil {
						entry.Resolved = resolved
					}
					links = append(links, entry)
				}
				listing.Entries = append(listing.Entries, child)
				continue
			}
			if e.IsDir() {
				listing.Entries = append(listing.Entries, child+"/")
				if !walk(child) {
					return false
				}
				continue
			}
			listing.Entries = append(listing.Entries, child)
		}
		return true
	}
	walk(rel)
	return listing, links
}

// readDistributions reads every installed Python distribution's file
// manifest under one search directory. Distributions recorded in the older
// egg-info form have no manifest at all and are listed separately, so a
// file belonging to one is reported as unmappable for a stated reason
// rather than as belonging to nothing.
func readDistributions(root, searchDir string, limit int, aux *AuxiliaryInputs) ([]DistInfoRecord, []EggInfoDistribution) {
	entries, err := os.ReadDir(path.Join(root, searchDir))
	if err != nil {
		aux.Errors = append(aux.Errors, fmt.Sprintf("python search dir %s: %v", searchDir, err))
		return nil, nil
	}
	var records []DistInfoRecord
	var eggs []EggInfoDistribution
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".dist-info"):
			dir := path.Join(searchDir, name)
			rec := DistInfoRecord{
				DistInfoDir: dir, MetadataPath: path.Join(dir, "METADATA"),
				RecordPath: path.Join(dir, "RECORD"), SearchDir: searchDir,
			}
			files, truncated, rerr := readRecordFile(path.Join(root, rec.RecordPath), limit)
			if rerr != nil {
				rec.Error = rerr.Error()
			}
			rec.Files, rec.Truncated = files, truncated
			if truncated {
				aux.Truncations = append(aux.Truncations, AuxTruncation{
					Kind: "dist_info_record", Path: rec.RecordPath, Limit: limit,
					Reason: "the installed-file manifest was cut short at the line limit",
				})
			}
			records = append(records, rec)
		case strings.HasSuffix(name, ".egg-info"):
			eggs = append(eggs, EggInfoDistribution{Dir: path.Join(searchDir, name), SearchDir: searchDir})
		}
	}
	return records, eggs
}

// readRecordFile reads the first column of an installed-file manifest. The
// file is comma-separated with quoted fields, and its first column may hold
// either a path relative to the directory containing the .dist-info or an
// absolute one; both are returned verbatim and normalized by the consumer,
// since guessing here would fix one interpretation into the saved data.
func readRecordFile(hostPath string, limit int) (files []string, truncated bool, err error) {
	f, oerr := os.Open(hostPath)
	if oerr != nil {
		return nil, false, oerr
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReader(f))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	for {
		if limit > 0 && len(files) >= limit {
			return files, true, nil
		}
		rec, rerr := r.Read()
		if rerr == io.EOF {
			return files, false, nil
		}
		if rerr != nil {
			// A manifest line that cannot be parsed is skipped rather than
			// abandoning the rest of the file, but the fact that something
			// was skipped is returned so the list is not treated as
			// complete.
			return files, true, fmt.Errorf("read %s: %w", hostPath, rerr)
		}
		if len(rec) == 0 || strings.TrimSpace(rec[0]) == "" {
			continue
		}
		files = append(files, rec[0])
	}
}

// fdEntriesForPID reads one process's file descriptor table, returning both
// the socket inodes (used to attribute a listening socket to the process
// holding it) and the ordinary files it has open. The second is what lets a
// runtime that keeps an archive open for its whole life be observed without
// any event collection at all.
//
// A readlink failure on one descriptor does not abandon the rest of the
// table, but it is never silently dropped either: each is returned as a
// message including its errno.
func fdEntriesForPID(pid int) (inodes map[string]bool, files []FDRecord, fdErrors []string, err error) {
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	inodes = map[string]bool{}
	for _, e := range entries {
		target, lerr := os.Readlink(dir + "/" + e.Name())
		if lerr != nil {
			fdErrors = append(fdErrors, fmt.Sprintf("fd %s: %v", e.Name(), lerr))
			continue
		}
		if m := socketInodeRE.FindStringSubmatch(target); m != nil {
			inodes[m[1]] = true
			continue
		}
		if !strings.HasPrefix(target, "/") {
			// pipe:[...], anon_inode:..., and the other kernel-internal
			// objects a descriptor can name. They are not files on the
			// container's filesystem and nothing maps them to a package.
			continue
		}
		fdNum, cerr := strconv.Atoi(e.Name())
		if cerr != nil {
			fdErrors = append(fdErrors, fmt.Sprintf("fd %s: not a descriptor number", e.Name()))
			continue
		}
		cleaned, deleted := splitDeleted(target)
		files = append(files, FDRecord{FD: fdNum, Path: cleaned, Deleted: deleted})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].FD < files[j].FD })
	return inodes, files, fdErrors, nil
}
