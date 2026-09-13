package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	dpkgKind        = "dpkg"
	dpkgStatusDKind = "dpkg-status.d"
	apkKind         = "apk"
	noDBKind        = "none"
)

// readTally accumulates what a database read actually cost: bytes pulled
// off disk and files opened. It is the load measurement's input, so it
// counts reads, never packages found. Each database file is counted once
// at its full size even where the build reads it twice (parsed for content
// and again to hash it), so the figure is the size of the database that had
// to be read rather than the number of read syscalls made.
type readTally struct {
	Bytes int64
	Files int
}

func (t *readTally) countFile(bytes int64) {
	if t == nil {
		return
	}
	t.Bytes += bytes
	t.Files++
}

// pkgIndex maps an absolute, root-resolved rootfs path to the package(s)
// that own it. Ownership can be ambiguous (multiple_owners), so byPath
// holds every claimant, not just the first.
type pkgIndex struct {
	// byPath maps a resolved path to its distinct owners. The same package
	// routinely claims one resolved path more than once: a .list or
	// .md5sums names both a versioned shared library and the symlink
	// pointing at it, and normalizing that symlink to its target makes both
	// entries land on the same path. Those are one owner, not two, so the
	// owners are a set keyed by (database kind, package name) and
	// multiple_owners means what it says — genuinely different packages
	// claiming one file.
	byPath   map[string][][2]string // resolved path -> distinct [(dbKind, package name), ...]
	ownerSet map[string]bool        // "<path>\x00<dbKind>\x00<package>" membership, for that deduplication
	versions map[string]string      // package name -> installed version ("apk:"+name for apk)
	// fileListComplete is false when this database could not tell us some
	// package's file list. A path this index cannot resolve is then not
	// evidence that no package owns it: the owner's file list may simply
	// be one of the ones that could not be read.
	//
	// A package that installs no files does not make the database
	// incomplete. Its list is complete and empty, and it can never own
	// anything, so a lookup miss remains real evidence that nothing owns
	// the path. Treating those as missing lists turned every unowned path
	// in an image carrying one virtual package into no_file_list.
	fileListComplete bool
}

func newPkgIndex() *pkgIndex {
	return &pkgIndex{
		byPath:   map[string][][2]string{},
		ownerSet: map[string]bool{},
		versions: map[string]string{},

		fileListComplete: true,
	}
}

func (idx *pkgIndex) add(path, dbKind, pkgName string) {
	key := path + "\x00" + dbKind + "\x00" + pkgName
	if idx.ownerSet[key] {
		return
	}
	idx.ownerSet[key] = true
	idx.byPath[path] = append(idx.byPath[path], [2]string{dbKind, pkgName})
}

// lookup resolves an already root-resolved absolute path. owners has more
// than one entry only when multiple packages claim the same path.
func (idx *pkgIndex) lookup(path string) (owners [][2]string, ok bool) {
	e, found := idx.byPath[path]
	return e, found
}

func (idx *pkgIndex) versionOf(dbKind, pkgName string) string {
	if dbKind == apkKind {
		return idx.versions[apkKind+":"+pkgName]
	}
	return idx.versions[pkgName]
}

// errProcRootGone indicates that a candidate PID's /proc/<pid>/root itself
// could not be reached (the process has already exited), as distinct from a
// reachable rootfs that simply has no package database. Callers must try
// the next candidate PID rather than conclude "no package database" from
// this.
var errProcRootGone = errors.New("proc root unavailable (process likely exited)")

// dbPathNormalizer rewrites a path recorded in a package database into the
// same representation an observed path takes. The *directories* of both
// sides go through resolveInRoot, so the two agree by construction rather
// than by a hand-maintained list of equivalent prefixes: on a merged-/usr
// image the database's /lib/x86_64-linux-gnu/libc.so.6 and the kernel's
// /usr/lib/x86_64-linux-gnu/libc.so.6 arrive at the same path, as does any
// other symlinked directory in the image.
//
// The final component is deliberately NOT followed, even when it is itself
// a symlink. A symlink and the file it points at are two different objects
// that packages own separately, and rewriting one onto the other invents
// ownership: on Debian, libc-bin owns the symlink /usr/bin/ld.so while
// libc6 owns the loader it eventually points at, and following that last
// hop made both packages claim the loader — so every process that mapped
// it came back multiple_owners and confirmed nothing. Not following it
// loses nothing, because the kernel reports the file a mapping actually
// backs onto, never a symlink to it, and a package that ships both a
// versioned library and its SONAME symlink lists both paths anyway.
//
// Directory resolutions are memoized because a database lists tens of
// thousands of paths across a few thousand directories.
type dbPathNormalizer struct {
	root     string
	dirCache map[string]string
}

func newDBPathNormalizer(root string) *dbPathNormalizer {
	return &dbPathNormalizer{root: root, dirCache: map[string]string{}}
}

func (n *dbPathNormalizer) normalize(p string) string {
	if n == nil {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	dir, base := "/", ""
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		base = p[i+1:]
		if i > 0 {
			dir = p[:i]
		}
	}

	resolvedDir, cached := n.dirCache[dir]
	if !cached {
		resolvedDir = dir
		if r, err := resolveInRoot(n.root, dir); err == nil {
			resolvedDir = r
		}
		n.dirCache[dir] = resolvedDir
	}
	if base == "" {
		return resolvedDir
	}
	full := resolvedDir + "/" + base
	if resolvedDir == "/" {
		full = "/" + base
	}
	return full
}

// buildContainerPkgIndex resolves the package index for a container by
// reading its rootfs through /proc/<pid>/root, trying each candidate PID in
// turn (they share the same mount namespace, so the first that succeeds is
// enough). A candidate whose root has disappeared is skipped in favor of the
// next one.
func buildContainerPkgIndex(pids []int, mountViewID string) (idx *pkgIndex, info PkgDBGenerationInfo, ledger []LedgerEntry, tally readTally, usedPID int, err error) {
	var lastErr error
	for _, pid := range pids {
		root := fmt.Sprintf("/proc/%d/root", pid)
		i, meta, l, t, e := buildPkgIndexFromRootCounted(root, mountViewID)
		if e == nil {
			return i, meta, l, t, pid, nil
		}
		lastErr = fmt.Errorf("pid %d: %w", pid, e)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidate pid")
	}
	return newPkgIndex(), PkgDBGenerationInfo{}, nil, readTally{}, 0, lastErr
}

// containerPkgDBGeneration computes just the (kind, generation) of a
// container's package database, without building the ownership index: the
// per-sample check that the database an earlier sample read is still the
// database this sample would read. A reachable rootfs with no database at
// all is a result, not an error, and is re-checked on every sample rather
// than remembered — a database can appear during a run.
func containerPkgDBGeneration(pids []int, mountViewID string) (PkgDBGenerationInfo, int, error) {
	var lastErr error
	for _, pid := range pids {
		root := fmt.Sprintf("/proc/%d/root", pid)
		info, err := pkgDBGeneration(root, mountViewID)
		if err == nil {
			return info, pid, nil
		}
		lastErr = fmt.Errorf("pid %d: %w", pid, err)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidate pid")
	}
	return PkgDBGenerationInfo{}, 0, lastErr
}

// detectDBKind decides which package database a rootfs carries, on
// metadata presence alone and in the fixed priority order dpkg,
// distroless's status.d, apk. Whether any file list can be recovered from
// it never enters this decision: a database with metadata but no file
// lists is still that kind of database, not an absent one.
func detectDBKind(root string) (kind, path string, err error) {
	if _, statErr := os.Stat(root); statErr != nil {
		return "", "", fmt.Errorf("%w: %v", errProcRootGone, statErr)
	}

	infoDir := filepath.Join(root, "var/lib/dpkg/info")
	if entries, derr := os.ReadDir(infoDir); derr == nil {
		if len(entries) > 0 {
			return dpkgKind, filepath.Join(root, "var/lib/dpkg/status"), nil
		}
	} else if !errors.Is(derr, os.ErrNotExist) {
		return dpkgKind, infoDir, derr
	}

	statusD := filepath.Join(root, "var/lib/dpkg/status.d")
	if entries, derr := os.ReadDir(statusD); derr == nil {
		if len(entries) > 0 {
			return dpkgStatusDKind, statusD, nil
		}
	} else if !errors.Is(derr, os.ErrNotExist) {
		return dpkgStatusDKind, statusD, derr
	}

	apkPath := filepath.Join(root, "lib/apk/db/installed")
	if _, serr := os.Stat(apkPath); serr == nil {
		return apkKind, apkPath, nil
	} else if !errors.Is(serr, os.ErrNotExist) {
		return apkKind, apkPath, serr
	}

	return noDBKind, "", nil
}

// pkgDBGeneration fingerprints the database currently under root. The
// fingerprint covers everything that decides what the ownership index
// would contain, not just the metadata file: for dpkg that is the status
// file's own content plus the size and mtime of every
// /var/lib/dpkg/info/*.list, since a package's file list can change
// without status changing at all.
//
// The file lists and the distroless status.d entries are fingerprinted by
// size and mtime, not by hashing their contents: a rewrite that preserves
// both would not be detected. These measurements hold the database fixed,
// so that is a recorded limitation rather than a case being handled.
func pkgDBGeneration(root, mountViewID string) (PkgDBGenerationInfo, error) {
	kind, path, err := detectDBKind(root)
	if err != nil {
		return PkgDBGenerationInfo{MountViewID: mountViewID, DBKind: kind, Path: path, ReadAt: time.Now(), Error: err.Error()}, err
	}

	switch kind {
	case dpkgKind:
		info, err := statPkgDBFile(dpkgKind, mountViewID, path, nil)
		if err != nil {
			return info, err
		}
		listDigest, listSize, lerr := hashDirEntries(filepath.Join(root, "var/lib/dpkg/info"), ".list")
		if lerr != nil {
			info.Error = lerr.Error()
			return info, lerr
		}
		info.SizeBytes += listSize
		info.DBGeneration = combineDigests(info.ContentHash, listDigest)
		return info, nil
	case dpkgStatusDKind:
		return hashDirManifest(dpkgStatusDKind, mountViewID, path)
	case apkKind:
		return statPkgDBFile(apkKind, mountViewID, path, nil)
	default:
		return PkgDBGenerationInfo{MountViewID: mountViewID, DBKind: noDBKind, ReadAt: time.Now(), FileListComplete: true}, nil
	}
}

// buildPkgIndexFromRoot builds a pkgIndex by reading whichever package
// database detectDBKind selects under root.
func buildPkgIndexFromRoot(root, mountViewID string) (idx *pkgIndex, info PkgDBGenerationInfo, ledger []LedgerEntry, err error) {
	idx, info, ledger, _, err = buildPkgIndexFromRootCounted(root, mountViewID)
	return idx, info, ledger, err
}

// buildPkgIndexFromRootCounted is buildPkgIndexFromRoot plus the read cost
// it incurred (bytes and files), which is the initial-database-read load
// measurement.
func buildPkgIndexFromRootCounted(root, mountViewID string) (idx *pkgIndex, info PkgDBGenerationInfo, ledger []LedgerEntry, tally readTally, err error) {
	kind, _, kerr := detectDBKind(root)
	if kerr != nil {
		return newPkgIndex(), PkgDBGenerationInfo{MountViewID: mountViewID, DBKind: kind}, nil, tally, kerr
	}

	norm := newDBPathNormalizer(root)
	switch kind {
	case dpkgKind:
		idx, info, ledger, err = loadDpkg(root, norm, mountViewID, &tally)
	case dpkgStatusDKind:
		idx, info, ledger, err = loadDistroless(root, norm, mountViewID, &tally)
	case apkKind:
		idx, info, ledger, err = loadApk(root, norm, mountViewID, &tally)
	default:
		return newPkgIndex(), PkgDBGenerationInfo{DBKind: noDBKind, MountViewID: mountViewID, ReadAt: time.Now(), FileListComplete: true}, nil, tally, nil
	}

	complete := true
	for _, e := range ledger {
		if !e.FileListPresent {
			complete = false
			break
		}
	}
	if idx != nil {
		idx.fileListComplete = complete
	}
	info.FileListComplete = complete
	for i := range ledger {
		ledger[i].DBGeneration = info.DBGeneration
	}
	return idx, info, ledger, tally, err
}

// --- Debian (dpkg) ---

// dpkgControlEntry is one parsed stanza (Package/Version/Architecture) of a
// dpkg-control-format file.
type dpkgControlEntry struct {
	Package, Version, Architecture string
}

// loadDpkg reads /var/lib/dpkg/info/*.list (path ownership) and
// /var/lib/dpkg/status (per-package metadata) under root.
func loadDpkg(root string, norm *dbPathNormalizer, mountViewID string, tally *readTally) (idx *pkgIndex, info PkgDBGenerationInfo, ledger []LedgerEntry, err error) {
	infoDir := filepath.Join(root, "var/lib/dpkg/info")
	entries, direrr := os.ReadDir(infoDir)
	if direrr != nil {
		return newPkgIndex(), PkgDBGenerationInfo{DBKind: dpkgKind, MountViewID: mountViewID}, nil, direrr
	}
	idx = newPkgIndex()
	var errs []string

	listedPkgs := map[string]bool{}
	fileCounts := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".list") {
			continue
		}
		pkgName := strings.TrimSuffix(name, ".list")
		if i := strings.IndexByte(pkgName, ':'); i >= 0 {
			pkgName = pkgName[:i]
		}
		paths, perr := readLines(filepath.Join(infoDir, name), tally)
		if perr != nil {
			// The list exists but could not be read, which is exactly the
			// case file_list_present is false for: we do not know what
			// this package owns.
			errs = append(errs, perr.Error())
			continue
		}
		// An empty .list is a metapackage's complete list, not a missing
		// one: dpkg writes a list for every installed package.
		listedPkgs[pkgName] = true
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" || p == "/." {
				continue
			}
			fileCounts[pkgName]++
			idx.add(norm.normalize(p), dpkgKind, pkgName)
		}
	}

	statusPath := filepath.Join(root, "var/lib/dpkg/status")
	stanzas, statusErr := readDpkgControlEntries(statusPath, tally)
	if statusErr != nil {
		errs = append(errs, statusErr.Error())
	}
	for _, s := range stanzas {
		if s.Package == "" {
			continue
		}
		idx.versions[s.Package] = s.Version
		ledger = append(ledger, LedgerEntry{
			MountViewID: mountViewID, Name: s.Package, Version: s.Version, Arch: s.Architecture,
			FileListPresent: listedPkgs[s.Package], FileCount: fileCounts[s.Package],
		})
	}

	info, hashErr := statPkgDBFile(dpkgKind, mountViewID, statusPath, nil)
	if hashErr != nil {
		errs = append(errs, hashErr.Error())
	} else {
		listDigest, listSize, lerr := hashDirEntries(infoDir, ".list")
		if lerr != nil {
			errs = append(errs, lerr.Error())
		} else {
			info.SizeBytes += listSize
			info.DBGeneration = combineDigests(info.ContentHash, listDigest)
		}
	}

	if len(errs) > 0 {
		return idx, info, ledger, &multiError{errs}
	}
	return idx, info, ledger, nil
}

// readDpkgControlEntries parses a dpkg-control-format file (RFC822-like
// stanzas separated by blank lines) into one entry per stanza. Continuation
// lines (leading whitespace) are ignored since none of the three fields
// read here ever wrap.
func readDpkgControlEntries(path string, tally *readTally) ([]dpkgControlEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []dpkgControlEntry
	var read int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var cur dpkgControlEntry
	flush := func() {
		if cur.Package != "" {
			out = append(out, cur)
		}
		cur = dpkgControlEntry{}
	}
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package:"):
			cur.Package = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			cur.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Architecture:"):
			cur.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		}
	}
	flush()
	tally.countFile(read)
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// --- distroless (status.d) ---

// loadDistroless reads /var/lib/dpkg/status.d/<package> (a single dpkg
// control stanza per package) and /var/lib/dpkg/status.d/<package>.md5sums
// (one "<md5>  <relative-path>" line per file the package installed,
// relative to "/") under root. A missing .md5sums for one package only
// marks that package's own file_list as absent.
func loadDistroless(root string, norm *dbPathNormalizer, mountViewID string, tally *readTally) (idx *pkgIndex, info PkgDBGenerationInfo, ledger []LedgerEntry, err error) {
	dir := filepath.Join(root, "var/lib/dpkg/status.d")
	entries, direrr := os.ReadDir(dir)
	if direrr != nil {
		return newPkgIndex(), PkgDBGenerationInfo{DBKind: dpkgStatusDKind, MountViewID: mountViewID}, nil, direrr
	}
	idx = newPkgIndex()
	var errs []string

	var metaFiles []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".md5sums") {
			metaFiles = append(metaFiles, e.Name())
		}
	}
	sort.Strings(metaFiles)

	for _, pkgFile := range metaFiles {
		stanzas, verr := readDpkgControlEntries(filepath.Join(dir, pkgFile), tally)
		var pkgName, pkgVer, pkgArch string
		if len(stanzas) > 0 {
			pkgName, pkgVer, pkgArch = stanzas[0].Package, stanzas[0].Version, stanzas[0].Architecture
		}
		if verr != nil || pkgName == "" {
			pkgName = pkgFile // fall back to the filename when the stanza has no Package: line
			if verr != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", pkgFile, verr))
			}
		}
		if pkgVer != "" {
			idx.versions[pkgName] = pkgVer
		}

		sumsPath := filepath.Join(dir, pkgFile+".md5sums")
		lines, lerr := readLines(sumsPath, tally)
		// A .md5sums that is absent is the one case this database format
		// genuinely cannot answer: distroless carries no other record of
		// what a package installed.
		fileListPresent := lerr == nil
		if lerr != nil && !errors.Is(lerr, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("%s: %v", sumsPath, lerr))
		}
		fileCount := 0
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			rel := strings.Join(fields[1:], " ")
			p := "/" + strings.TrimPrefix(rel, "/")
			fileCount++
			idx.add(norm.normalize(p), dpkgStatusDKind, pkgName)
		}
		ledger = append(ledger, LedgerEntry{
			MountViewID: mountViewID, Name: pkgName, Version: pkgVer, Arch: pkgArch,
			FileListPresent: fileListPresent, FileCount: fileCount,
		})
	}

	info, hashErr := hashDirManifest(dpkgStatusDKind, mountViewID, dir)
	if hashErr != nil {
		errs = append(errs, hashErr.Error())
	}

	if len(errs) > 0 {
		return idx, info, ledger, &multiError{errs}
	}
	return idx, info, ledger, nil
}

// --- Alpine (apk) ---

// loadApk reads /lib/apk/db/installed under root: stanzas separated by
// blank lines, each line "<letter>:<value>". P is the package name, V its
// version, A its architecture, F sets the "current directory" for the R
// entry lines that follow until the next F or blank line — F never carries
// over a blank-line record boundary. An R line with no F line before it in
// the same record has no directory to be relative to and is a malformed
// record, not a file at the root: it is recorded as a parse error and
// indexed nowhere, and only that discards the package's file list.
//
// A record with no F/R lines at all is a package that installs no files —
// apk's virtual packages, which `apk add --virtual` creates to bundle a
// set of dependencies under one name (conventionally with a leading ".",
// as the official redis image's .redis-rundeps does). The installed
// database enumerates files inline, so such a record is a complete and
// empty file list, not an unreadable one.
func loadApk(root string, norm *dbPathNormalizer, mountViewID string, tally *readTally) (idx *pkgIndex, info PkgDBGenerationInfo, ledger []LedgerEntry, err error) {
	path := filepath.Join(root, "lib/apk/db/installed")
	f, ferr := os.Open(path)
	if ferr != nil {
		return newPkgIndex(), PkgDBGenerationInfo{DBKind: apkKind, MountViewID: mountViewID}, nil, ferr
	}
	defer f.Close()
	idx = newPkgIndex()
	var errs []string
	var read int64

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var pkg, ver, arch, dir string
	var fileCount int
	dirSet, listBroken := false, false
	flush := func() {
		if pkg != "" {
			ledger = append(ledger, LedgerEntry{
				MountViewID: mountViewID, Name: pkg, Version: ver, Arch: arch,
				FileListPresent: !listBroken, FileCount: fileCount,
			})
		}
		pkg, ver, arch, dir = "", "", "", ""
		fileCount = 0
		dirSet, listBroken = false, false
	}
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		field, value := line[0], line[2:]
		switch field {
		case 'P':
			pkg = value
		case 'V':
			ver = value
			if pkg != "" {
				idx.versions[apkKind+":"+pkg] = ver
			}
		case 'A':
			arch = value
		case 'F':
			dir, dirSet = value, true
		case 'R':
			if pkg == "" {
				continue
			}
			if !dirSet {
				errs = append(errs, fmt.Sprintf("%s: package %q: R:%s has no preceding F: in its record", path, pkg, value))
				listBroken = true
				continue
			}
			fileCount++
			full := "/" + value
			if dir != "" {
				full = "/" + strings.TrimPrefix(dir, "/") + "/" + value
			}
			idx.add(norm.normalize(full), apkKind, pkg)
		}
	}
	flush()
	tally.countFile(read)
	if scanErr := sc.Err(); scanErr != nil {
		return idx, PkgDBGenerationInfo{DBKind: apkKind, MountViewID: mountViewID}, ledger, scanErr
	}

	info, hashErr := statPkgDBFile(apkKind, mountViewID, path, nil)
	if hashErr != nil {
		errs = append(errs, hashErr.Error())
	}
	if len(errs) > 0 {
		return idx, info, ledger, &multiError{errs}
	}
	return idx, info, ledger, nil
}

// --- shared helpers ---

func readLines(path string, tally *readTally) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	var read int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		out = append(out, line)
	}
	tally.countFile(read)
	return out, sc.Err()
}

// statPkgDBFile stats and hashes a single representative database file
// (dpkg's status, apk's installed). DBGeneration starts as the content
// hash; callers whose database is more than that one file extend it.
func statPkgDBFile(dbKind, mountViewID, path string, tally *readTally) (PkgDBGenerationInfo, error) {
	info := PkgDBGenerationInfo{DBKind: dbKind, MountViewID: mountViewID, Path: path, ReadAt: time.Now()}
	fi, err := os.Stat(path)
	if err != nil {
		info.Error = err.Error()
		return info, err
	}
	info.SizeBytes = fi.Size()
	info.ModTime = fi.ModTime()
	f, err := os.Open(path)
	if err != nil {
		info.Error = err.Error()
		return info, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	tally.countFile(n)
	if err != nil {
		info.Error = err.Error()
		return info, err
	}
	info.ContentHash = hex.EncodeToString(h.Sum(nil))
	info.DBGeneration = info.ContentHash
	return info, nil
}

// hashDirEntries fingerprints a directory's entries with the given suffix
// by their sorted "name:size:mtime" list, and reports their total size.
// Used for dpkg's /var/lib/dpkg/info/*.list, whose contents decide path
// ownership but whose changes leave /var/lib/dpkg/status untouched.
func hashDirEntries(dir, suffix string) (digest string, totalSize int64, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, err
	}
	type entryInfo struct {
		name  string
		size  int64
		mtime time.Time
	}
	var infos []entryInfo
	for _, e := range entries {
		if suffix != "" && !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		fi, ferr := e.Info()
		if ferr != nil {
			return "", 0, ferr
		}
		infos = append(infos, entryInfo{e.Name(), fi.Size(), fi.ModTime()})
		totalSize += fi.Size()
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].name < infos[j].name })
	h := sha256.New()
	for _, e := range infos {
		fmt.Fprintf(h, "%s:%d:%s\n", e.name, e.size, e.mtime.UTC().Format(time.RFC3339Nano))
	}
	return hex.EncodeToString(h.Sum(nil)), totalSize, nil
}

// combineDigests folds several component digests into one generation key.
func combineDigests(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%s\n", p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashDirManifest fingerprints a directory (distroless's status.d) by
// hashing a sorted "name:size:mtime" list of its entries.
func hashDirManifest(dbKind, mountViewID, dir string) (PkgDBGenerationInfo, error) {
	info := PkgDBGenerationInfo{DBKind: dbKind, MountViewID: mountViewID, Path: dir, ReadAt: time.Now()}
	digest, totalSize, err := hashDirEntries(dir, "")
	if err != nil {
		info.Error = err.Error()
		return info, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		info.Error = err.Error()
		return info, err
	}
	var newest time.Time
	for _, e := range entries {
		fi, ferr := e.Info()
		if ferr != nil {
			continue
		}
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	info.SizeBytes = totalSize
	info.ModTime = newest
	info.ContentHash = digest
	info.DBGeneration = digest
	return info, nil
}

type multiError struct{ msgs []string }

func (e *multiError) Error() string { return strings.Join(e.msgs, "; ") }
