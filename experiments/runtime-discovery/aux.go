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
	// cap on package-database index entries, and Symlinks the cap on
	// recorded link targets.
	DirEntries int
	RecordFile int
	OwnedPaths int
	Symlinks   int
}

func defaultAuxLimits() auxLimits {
	return auxLimits{ScanDepth: 8, DirEntries: 200000, RecordFile: 100000, OwnedPaths: 400000, Symlinks: 100000}
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
	// system's own path index is not re-read that way — it cannot change
	// without its database generation changing, and rebuilding it each
	// time would dominate the collection's cost on a full image.
	switch {
	case owned != nil && owned.dbGeneration == info.DBGeneration && owned.paths != nil:
		aux.OwnedPaths, aux.OwnedPathsTruncated = owned.paths, owned.truncated
	default:
		aux.OwnedPaths, aux.OwnedPathsTruncated = ownedPathIndex(idx, limits.OwnedPaths)
		if owned != nil {
			owned.dbGeneration, owned.paths, owned.truncated = info.DBGeneration, aux.OwnedPaths, aux.OwnedPathsTruncated
		}
	}
	if aux.OwnedPathsTruncated {
		aux.Truncations = append(aux.Truncations, AuxTruncation{
			Kind: "owned_paths", Limit: limits.OwnedPaths,
			Reason: "the package-database path index was cut short; a path absent from it may still be owned",
		})
	}
	aux.AuxGeneration = auxGeneration(root, aux)
	return aux
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
