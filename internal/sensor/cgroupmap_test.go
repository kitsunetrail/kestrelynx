package sensor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCgroupRouteApplyCgroupMkdirTopLevelScope(t *testing.T) {
	var rt cgroupRoute
	id := strings64('a')
	path := "/system.slice/docker-" + id + ".scope"

	gotID, ok := rt.applyCgroupMkdir(1000, path)
	if !ok {
		t.Fatalf("applyCgroupMkdir(%q) resolved = false, want true", path)
	}
	if gotID != id {
		t.Errorf("applyCgroupMkdir(%q) container ID = %q, want %q", path, gotID, id)
	}
	if got, ok := rt.lookup(1000); !ok || got != id {
		t.Errorf("lookup(1000) = (%q, %v), want (%q, true)", got, ok, id)
	}
}

func TestCgroupRouteApplyCgroupMkdirNestedUnderKnownAncestor(t *testing.T) {
	var rt cgroupRoute
	id := strings64('b')
	scope := "/system.slice/docker-" + id + ".scope"
	rt.applyCgroupMkdir(2000, scope)

	nested := scope + "/init.scope"
	gotID, ok := rt.applyCgroupMkdir(2001, nested)
	if !ok {
		t.Fatalf("applyCgroupMkdir(%q) resolved = false, want true (child of a known container scope)", nested)
	}
	if gotID != id {
		t.Errorf("nested cgroup container ID = %q, want %q", gotID, id)
	}
	if got, ok := rt.lookup(2001); !ok || got != id {
		t.Errorf("lookup(2001) = (%q, %v), want (%q, true)", got, ok, id)
	}

	// A grandchild resolves through the same ancestor chain, without ever
	// having applyCgroupMkdir called on the intermediate "init.scope"
	// level's own further descendants explicitly registered first — it is
	// registered here, so this exercises the multi-hop ancestor walk.
	grandchild := nested + "/deeper"
	gotID, ok = rt.applyCgroupMkdir(2002, grandchild)
	if !ok || gotID != id {
		t.Errorf("applyCgroupMkdir(%q) = (%q, %v), want (%q, true)", grandchild, gotID, ok, id)
	}
}

func TestCgroupRouteApplyCgroupMkdirUnknown(t *testing.T) {
	var rt cgroupRoute
	_, ok := rt.applyCgroupMkdir(3000, "/system.slice/some-other.service")
	if ok {
		t.Error("applyCgroupMkdir resolved a path with no container scope ancestor, want false")
	}
	if _, ok := rt.lookup(3000); ok {
		t.Error("lookup(3000) found an entry for a cgroup that was never resolved")
	}
}

// TestCgroupRouteApplyCgroupMkdirEmptyPathNeverConfirmsNonContainer confirms
// an empty path (kl_cgroup_mkdir's own bpf_probe_read_kernel_str failed
// outright) is refused outright rather than ancestor-matching the cgroup
// root itself — see applyCgroupMkdir's own doc comment on why that would
// wrongly confirm a cgroup whose real path simply could not be read as a
// non-container.
func TestCgroupRouteApplyCgroupMkdirEmptyPathNeverConfirmsNonContainer(t *testing.T) {
	var rt cgroupRoute
	// Seed the table the same way a clean scanCgroupTree does: the cgroup
	// root itself recorded as a confirmed non-container.
	rt.set(1, "", "")

	if _, ok := rt.applyCgroupMkdir(4000, ""); ok {
		t.Error("applyCgroupMkdir(\"\") resolved = true, want false -- an empty path must never be classified at all")
	}
	if _, ok := rt.lookup(4000); ok {
		t.Error("lookup(4000) found an entry after an empty-path applyCgroupMkdir -- it must stay unclassified")
	}
}

func TestCgroupRouteEvictionBounded(t *testing.T) {
	var rt cgroupRoute
	// One more than the cap, each a distinct top-level container scope, so
	// every insert actually creates a new entry.
	for i := 0; i < maxCgroupRouteEntries+10; i++ {
		id := paddedHexID(i)
		path := "/system.slice/docker-" + id + ".scope"
		rt.set(uint64(i), path, id)
	}
	if len(rt.pathToContainer) > maxCgroupRouteEntries {
		t.Errorf("pathToContainer size = %d, want <= %d", len(rt.pathToContainer), maxCgroupRouteEntries)
	}
	if len(rt.idToContainer) > maxCgroupRouteEntries {
		t.Errorf("idToContainer size = %d, want <= %d", len(rt.idToContainer), maxCgroupRouteEntries)
	}
	// The oldest entries (0..9) must have been evicted; the newest
	// (maxCgroupRouteEntries..maxCgroupRouteEntries+9) must still be there.
	if _, ok := rt.lookup(0); ok {
		t.Error("lookup(0) still found after eviction should have removed the oldest entries")
	}
	newest := uint64(maxCgroupRouteEntries + 9)
	if _, ok := rt.lookup(newest); !ok {
		t.Errorf("lookup(%d) not found, want the most recently inserted entry to survive eviction", newest)
	}
}

// paddedHexID returns a distinct 64-hex-character string for each i, so
// TestCgroupRouteEvictionBounded's insertions are all distinct container
// IDs/paths rather than colliding on strings64's single-repeated-byte shape.
func paddedHexID(i int) string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 64)
	for j := range buf {
		buf[j] = hex[0]
	}
	// Encode i into the low bytes so every i in this test's range produces
	// a distinct string.
	n := i
	for j := len(buf) - 1; j >= 0 && n > 0; j-- {
		buf[j] = hex[n%16]
		n /= 16
	}
	return string(buf)
}

// TestCgroupRouteEvictionBoundedAcrossPathReuse fixes the eviction gap a
// deleted-and-recreated cgroup exposes: reusing the same path for a new
// cgroup ID overwrites pathToContainer's own entry (its size does not grow)
// while idToContainer still gains a new entry every time, so eviction must
// be driven by idToContainer's own size, not pathToContainer's.
func TestCgroupRouteEvictionBoundedAcrossPathReuse(t *testing.T) {
	var rt cgroupRoute
	const reusedPath = "/system.slice/docker-reused.scope"
	for i := 0; i < maxCgroupRouteEntries+10; i++ {
		rt.set(uint64(i), reusedPath, paddedHexID(i))
	}
	if len(rt.idToContainer) > maxCgroupRouteEntries {
		t.Errorf("idToContainer size = %d, want <= %d", len(rt.idToContainer), maxCgroupRouteEntries)
	}
	if len(rt.insertOrder) > maxCgroupRouteEntries {
		t.Errorf("insertOrder length = %d, want <= %d", len(rt.insertOrder), maxCgroupRouteEntries)
	}
	// The path itself must still resolve to the newest id's own container,
	// never deleted out from under it by an older id's own eviction.
	newestID := paddedHexID(maxCgroupRouteEntries + 9)
	if got, ok := rt.pathToContainer[reusedPath]; !ok || got != newestID {
		t.Errorf("pathToContainer[%q] = (%q, %v), want (%q, true)", reusedPath, got, ok, newestID)
	}
}

func TestCgroupRoutePruneContainer(t *testing.T) {
	var rt cgroupRoute
	idA := strings64('e')
	idB := strings64('f')
	scopeA := "/system.slice/docker-" + idA + ".scope"
	scopeB := "/system.slice/docker-" + idB + ".scope"
	rt.applyCgroupMkdir(9000, scopeA)
	rt.applyCgroupMkdir(9001, scopeA+"/init.scope")
	rt.applyCgroupMkdir(9002, scopeB)

	rt.pruneContainer(idA)

	if _, ok := rt.lookup(9000); ok {
		t.Error("lookup(9000) still resolves after pruning its container")
	}
	if _, ok := rt.lookup(9001); ok {
		t.Error("lookup(9001) (a descendant of the pruned container) still resolves")
	}
	if got, ok := rt.lookup(9002); !ok || got != idB {
		t.Errorf("lookup(9002) = (%q, %v), want (%q, true) -- an unrelated container must survive pruning", got, ok, idB)
	}
	if _, ok := rt.pathToContainer[scopeA]; ok {
		t.Error("pathToContainer still has an entry for the pruned container's own scope path")
	}
	for _, e := range rt.insertOrder {
		if e.id == 9000 || e.id == 9001 {
			t.Errorf("insertOrder still references pruned id %d", e.id)
		}
	}

	// Pruning a container with no entries at all must not panic.
	rt.pruneContainer(strings64('z'))
}

func TestScanCgroupTree(t *testing.T) {
	root := t.TempDir()
	id := strings64('c')
	scopeRel := "/system.slice/docker-" + id + ".scope"
	nestedRel := scopeRel + "/init.scope"
	unrelatedRel := "/user.slice"

	for _, rel := range []string{scopeRel, nestedRel, unrelatedRel} {
		if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", rel, err)
		}
	}

	rt, truncated, failed := scanCgroupTree(root)
	if truncated {
		t.Error("scanCgroupTree reported truncated for a small test tree")
	}
	if failed {
		t.Error("scanCgroupTree reported failed for a small test tree with no permission/IO errors")
	}

	scopeIno, err := statDirInode(filepath.Join(root, scopeRel))
	if err != nil {
		t.Fatalf("statDirInode(scope): %v", err)
	}
	nestedIno, err := statDirInode(filepath.Join(root, nestedRel))
	if err != nil {
		t.Fatalf("statDirInode(nested): %v", err)
	}
	unrelatedIno, err := statDirInode(filepath.Join(root, unrelatedRel))
	if err != nil {
		t.Fatalf("statDirInode(unrelated): %v", err)
	}

	if got, ok := rt.lookup(scopeIno); !ok || got != id {
		t.Errorf("lookup(scope inode) = (%q, %v), want (%q, true)", got, ok, id)
	}
	if got, ok := rt.lookup(nestedIno); !ok || got != id {
		t.Errorf("lookup(nested inode) = (%q, %v), want (%q, true) -- a descendant of a container scope must inherit its container ID", got, ok, id)
	}
	// A non-container cgroup is still explicitly classified after a clean
	// scan — known=true with an empty container ID — never left merely
	// unresolved (see cgroupRoute's own doc comment on why "" is itself a
	// meaningful, recorded value distinct from the key being absent).
	if got, known := rt.lookup(unrelatedIno); !known || got != "" {
		t.Errorf("lookup(unrelated inode) = (%q, %v), want (\"\", true) -- a scanned non-container cgroup must be confirmed classified, not merely unresolved", got, known)
	}
}

// TestScanCgroupTreeReportsFailedOnPermissionError confirms that a scan
// which could not fully classify the host's own cgroup tree is
// distinguishable from a clean one, so the caller (session.go's own startup
// sequence) can refuse to report events.status as ok over it.
func TestScanCgroupTreeReportsFailedOnPermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: running as root, which ignores directory permission bits")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Mkdir(filepath.Join(blocked, "child"), 0o755); err != nil {
		t.Fatalf("Mkdir(child): %v", err)
	}
	if err := unix.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("Chmod(blocked, 0): %v", err)
	}
	defer os.Chmod(blocked, 0o755) // restore so t.TempDir's own cleanup can remove it

	_, truncated, failed := scanCgroupTree(root)
	if truncated {
		t.Error("scanCgroupTree reported truncated, want only failed for a permission error")
	}
	if !failed {
		t.Error("scanCgroupTree did not report failed for a directory it could not read at all")
	}
}
