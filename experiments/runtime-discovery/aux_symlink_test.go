package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDirSymlinksResolvesAnAbsoluteIntermediateLinkInsideRoot checks that
// dirSymlinks never lets an intermediate absolute symlink (the container's
// own /bin -> /usr/bin, say) escape to the host's own filesystem.
//
// The intermediate link's own target is absolute and names a path that is
// most likely not present at all on the host running this test
// (kl-test-marker-dir), the same shape the real bug takes: a plain
// path.Join of root and "/bin" hands the kernel a path whose "bin"
// component is a symlink to an ABSOLUTE target, and the kernel restarts
// resolution of an absolute symlink target at the calling process's own
// real "/" — the host's, since this test process is not chrooted — never
// at root. If dirSymlinks ever did that, it would try to open the host's
// own "/kl-test-marker-dir", which does not exist, and silently return no
// entries at all (the same as "not there" is already treated) rather than
// the one entry this test placed under root's own copy of that directory.
func TestDirSymlinksResolvesAnAbsoluteIntermediateLinkInsideRoot(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "kl-test-marker-dir"))
	if err := os.Symlink("/kl-test-marker-dir", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mawk", filepath.Join(root, "kl-test-marker-dir/kl-test-awk")); err != nil {
		t.Fatal(err)
	}

	budget := 100
	var aux AuxiliaryInputs
	got := dirSymlinks(root, "/bin", &budget, &aux)
	if len(got) != 1 {
		t.Fatalf("dirSymlinks(/bin) = %v, want exactly the one symlink placed under this root's own marker directory (a host escape would find nothing there instead)", got)
	}
	if got[0].Path != "/bin/kl-test-awk" || got[0].Target != "mawk" {
		t.Errorf("got %+v, want Path /bin/kl-test-awk, Target mawk", got[0])
	}
}

// TestSingleSymlinkResolvesAnAbsoluteIntermediateLinkInsideRoot is
// singleSymlink's own version of the same check, with the same
// guaranteed-absent-on-the-host marker path standing in for an
// intermediate absolute symlink's target.
func TestSingleSymlinkResolvesAnAbsoluteIntermediateLinkInsideRoot(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "kl-test-marker-etc"))
	if err := os.Symlink("/kl-test-marker-etc", filepath.Join(root, "etc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/share/zoneinfo/Etc/UTC", filepath.Join(root, "kl-test-marker-etc/localtime")); err != nil {
		t.Fatal(err)
	}

	budget := 100
	entry := singleSymlink(root, "/etc/localtime", &budget)
	if entry == nil {
		t.Fatalf("singleSymlink(/etc/localtime) = nil, want the link found through the container's own /etc -> marker directory (a host escape would find nothing there)")
	}
	if entry.Target != "/usr/share/zoneinfo/Etc/UTC" {
		t.Errorf("target = %q, want /usr/share/zoneinfo/Etc/UTC", entry.Target)
	}
}

// TestDBSymlinkDirsNeverFallsBackToAnUnresolvedDirectory checks that a
// package-database path whose own directory does not resolve inside the
// container at all (a dangling intermediate link — /opt/redirect -> /usr
// on an image with no /usr, with something expected beneath it, say) is
// skipped rather than read through its own unresolved spelling, which on
// a host that genuinely has a /usr of its own would otherwise read the
// host's real file instead of failing closed.
//
// The path goes one level deeper than the dangling link itself
// (/opt/redirect/deep/tool, not /opt/redirect/tool): resolveInRoot itself
// does not treat a plain missing FINAL component as an error — a
// resolution ending exactly at the symlink's own absent target is
// reported as that path, unresolved but not erroring, since the caller
// may be classifying a path that simply does not exist. It is a missing
// INTERMEDIATE component — something still expected below the dangling
// target — that resolveInRoot itself refuses to guess through, and that
// is what a real "column beneath a dangling redirect" path shape hits.
func TestDBSymlinkDirsNeverFallsBackToAnUnresolvedDirectory(t *testing.T) {
	root := t.TempDir()
	// /opt/redirect -> /usr, but this root has no /usr at all: nothing
	// beneath the dangling link can resolve inside root.
	mustMkdirAll(t, filepath.Join(root, "opt"))
	if err := os.Symlink("/usr", filepath.Join(root, "opt/redirect")); err != nil {
		t.Fatal(err)
	}

	dirs := &dbSymlinkDirs{root: root, cache: map[string]dbSymlinkDirResolution{}}
	if _, err := dirs.readlink("/opt/redirect/deep/tool"); err == nil {
		t.Fatalf("readlink of a path under an unresolvable directory returned no error, so a caller cannot tell it apart from a genuine link")
	}

	// packageDBFileInfo itself must skip such a path rather than record
	// whatever a plain, unresolved join happened to find (which, on a
	// host that has a real /usr/deep/tool of its own, would be the host's
	// own file having nothing to do with this container).
	budget := 10
	dirSet, symlinks, truncated := packageDBFileInfo(root, []string{"/opt/redirect/deep/tool"}, &budget)
	if len(dirSet) != 0 || len(symlinks) != 0 || truncated {
		t.Fatalf("packageDBFileInfo(/opt/redirect/deep/tool) = dirs=%v symlinks=%v (truncated=%v), want it skipped with nothing recorded", dirSet, symlinks, truncated)
	}
}

// TestPackageDBFileInfoReexaminesEveryReadingForDirectoryChanges checks
// that IsDir is never fixed to whatever it was at the first reading of a
// database generation: a directory the database lists can be replaced by
// a plain file without the database's own generation changing at all
// (dpkg's own database records ownership, not the current type of what it
// owns), and a reading has to notice that on its own, every time — the
// same requirement TestPackageDBSymlinksReexaminesEveryReadingForNewSymlinks
// already holds a listed path's symlink status to. The type change must
// also be reflected in AuxGeneration's own fingerprint, since nothing else
// about this generation changed for anything keyed on it to notice
// otherwise.
func TestPackageDBFileInfoReexaminesEveryReadingForDirectoryChanges(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "usr/share/kl-test/kl-dir"))

	idx := newPkgIndex()
	idx.add("/usr/share/kl-test/kl-dir", "dpkg", "pkg-a")

	limits := auxLimits{ExtraSymlinks: 100}
	info := PkgDBGenerationInfo{DBGeneration: "gen1"}
	owned := &ownedPathCache{}
	pid := os.Getpid()

	isDirOf := func(aux AuxiliaryInputs, p string) (isDir, found bool) {
		for _, e := range aux.OwnedPaths {
			if e.Path == p {
				return e.IsDir, true
			}
		}
		return false, false
	}

	first := collectAuxiliaryInputs(root, pid, "mnt:[1]", idx, info, limits, owned)
	isDir, found := isDirOf(first, "/usr/share/kl-test/kl-dir")
	if !found {
		t.Fatalf("first reading is missing the owned path entirely")
	}
	if !isDir {
		t.Errorf("first reading reported a real directory as not one")
	}

	// The directory is replaced by a plain file without the database's
	// own generation changing at all — the same idx and info are read
	// again below.
	if err := os.RemoveAll(filepath.Join(root, "usr/share/kl-test/kl-dir")); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, filepath.Join(root, "usr/share/kl-test/kl-dir"), "no longer a directory")

	second := collectAuxiliaryInputs(root, pid, "mnt:[1]", idx, info, limits, owned)
	isDir, found = isDirOf(second, "/usr/share/kl-test/kl-dir")
	if !found {
		t.Fatalf("second reading is missing the owned path entirely")
	}
	if isDir {
		t.Errorf("second reading still reported the now-plain file as a directory")
	}
	if second.AuxGeneration == first.AuxGeneration {
		t.Errorf("AuxGeneration did not change when a directory turned into a plain file within the same database generation")
	}
}

// TestPackageDBSymlinksReexaminesEveryReadingForNewSymlinks checks the
// review fix for (2): the cached per-generation list is only ever which
// paths the database names, never which of them are symlinks — a plain
// file the database lists can turn into a symlink without the database's
// own generation changing at all, and a reading has to notice that on its
// own, every time.
func TestPackageDBSymlinksReexaminesEveryReadingForNewSymlinks(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "usr/share/kl-test"))
	mustWriteFile(t, filepath.Join(root, "usr/share/kl-test/real"), "x")
	if err := os.Symlink("real", filepath.Join(root, "usr/share/kl-test/kl-a")); err != nil {
		t.Fatal(err)
	}
	// kl-b starts out as an ordinary file, not a symlink at all.
	mustWriteFile(t, filepath.Join(root, "usr/share/kl-test/kl-b"), "not a link yet")

	idx := newPkgIndex()
	idx.add("/usr/share/kl-test/kl-a", "dpkg", "pkg-a")
	idx.add("/usr/share/kl-test/kl-b", "dpkg", "pkg-b")

	limits := auxLimits{ExtraSymlinks: 100}
	info := PkgDBGenerationInfo{DBGeneration: "gen1"}
	owned := &ownedPathCache{}
	pid := os.Getpid()

	hasPath := func(aux AuxiliaryInputs, p string) bool {
		for _, l := range aux.Symlinks {
			if l.Path == p {
				return true
			}
		}
		return false
	}

	first := collectAuxiliaryInputs(root, pid, "mnt:[1]", idx, info, limits, owned)
	if !hasPath(first, "/usr/share/kl-test/kl-a") {
		t.Errorf("first reading did not find kl-a, an existing symlink")
	}
	if hasPath(first, "/usr/share/kl-test/kl-b") {
		t.Errorf("first reading found kl-b as a symlink before it ever became one")
	}
	if len(owned.dbPaths) != 2 {
		t.Fatalf("cached dbPaths = %v, want both database-listed paths regardless of which are symlinks", owned.dbPaths)
	}

	// kl-b turns into a symlink without the database's own generation
	// changing at all — the same database generation (info.DBGeneration
	// and idx) is read again below.
	if err := os.Remove(filepath.Join(root, "usr/share/kl-test/kl-b")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "usr/share/kl-test/kl-b")); err != nil {
		t.Fatal(err)
	}

	second := collectAuxiliaryInputs(root, pid, "mnt:[1]", idx, info, limits, owned)
	if !hasPath(second, "/usr/share/kl-test/kl-a") {
		t.Errorf("second reading lost kl-a")
	}
	if !hasPath(second, "/usr/share/kl-test/kl-b") {
		t.Errorf("second reading did not notice kl-b becoming a symlink within the same database generation")
	}
}

// TestPackageDBSymlinkCacheReuseStillRespectsThisSampleOwnBudget checks
// the review fix for (7): the cached per-generation path list (see
// TestPackageDBSymlinksReexaminesEveryReadingForNewSymlinks) is still
// scored against each reading's own current, shared budget — a reading
// whose narrower sources (alternatives, the bin directories) already used
// most of the budget never gets to add every database-derived entry
// regardless, on a cache hit or not.
func TestPackageDBSymlinkCacheReuseStillRespectsThisSampleOwnBudget(t *testing.T) {
	root := t.TempDir()
	// Placed under /usr/share rather than one of topBinDirs, so the only
	// source competing with these for the shared budget is the
	// alternatives directory below, keeping the budget arithmetic this
	// test relies on exact.
	mustMkdirAll(t, filepath.Join(root, "usr/share/kl-test"))
	mustMkdirAll(t, filepath.Join(root, "etc/alternatives"))
	mustWriteFile(t, filepath.Join(root, "usr/share/kl-test/real"), "x")
	for _, name := range []string{"kl-a", "kl-b", "kl-c"} {
		if err := os.Symlink("real", filepath.Join(root, "usr/share/kl-test", name)); err != nil {
			t.Fatal(err)
		}
	}
	// Nine unrelated alternatives entries, read fresh on every sample
	// (never cached), that eat into the shared per-sample budget before
	// the package database's own paths are ever examined.
	for i := 0; i < 9; i++ {
		name := filepath.Join(root, "etc/alternatives", string(rune('a'+i)))
		if err := os.Symlink("/does/not/matter", name); err != nil {
			t.Fatal(err)
		}
	}

	idx := newPkgIndex()
	idx.add("/usr/share/kl-test/kl-a", "dpkg", "pkg-a")
	idx.add("/usr/share/kl-test/kl-b", "dpkg", "pkg-b")
	idx.add("/usr/share/kl-test/kl-c", "dpkg", "pkg-c")

	limits := auxLimits{ExtraSymlinks: 10}
	info := PkgDBGenerationInfo{DBGeneration: "gen1"}
	owned := &ownedPathCache{}
	pid := os.Getpid()

	countDBEntries := func(aux AuxiliaryInputs) int {
		n := 0
		for _, l := range aux.Symlinks {
			switch l.Path {
			case "/usr/share/kl-test/kl-a", "/usr/share/kl-test/kl-b", "/usr/share/kl-test/kl-c":
				n++
			}
		}
		return n
	}
	hasExtraSymlinksTruncation := func(aux AuxiliaryInputs) bool {
		for _, tr := range aux.Truncations {
			if tr.Kind == "extra_symlinks" {
				return true
			}
		}
		return false
	}

	first := collectAuxiliaryInputs(root, pid, "mnt:[1]", idx, info, limits, owned)
	if len(owned.dbPaths) != 3 {
		t.Fatalf("cached dbPaths = %v, want all 3 database-listed paths", owned.dbPaths)
	}
	// Nine alternatives entries leave room for exactly one of the three
	// database-derived symlinks under the shared budget of 10.
	if n := countDBEntries(first); n != 1 {
		t.Errorf("first reading recorded %d database-derived symlink(s), want exactly 1 (the leftover budget)", n)
	}
	if !hasExtraSymlinksTruncation(first) {
		t.Errorf("first reading did not record an extra_symlinks truncation despite the database paths exceeding the leftover budget")
	}

	second := collectAuxiliaryInputs(root, pid, "mnt:[1]", idx, info, limits, owned)
	if n := countDBEntries(second); n != 1 {
		t.Errorf("second (cache-reusing) reading recorded %d database-derived symlink(s), want exactly 1 — reuse must not bypass this reading's own budget", n)
	}
	if !hasExtraSymlinksTruncation(second) {
		t.Errorf("second (cache-reusing) reading did not record an extra_symlinks truncation despite reusing a path list larger than its own leftover budget")
	}
}
