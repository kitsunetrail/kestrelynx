package rootfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// openRoot opens dir as an O_PATH directory descriptor and returns a Reader
// confined to it, the same way procfs.Handle.OpenRoot's result would be
// used.
func openRoot(t *testing.T, dir string) *Reader {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %q as root: %v", dir, err)
	}
	return Open(os.NewFile(uintptr(fd), dir))
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}

func TestOpenFile_PlainPath(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "a", "b", "file.txt"), "hello")

	r := openRoot(t, dir)
	defer r.Close()

	f, err := r.OpenFile("a/b/file.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := readAll(t, f); got != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
}

func TestOpenFile_LeadingDotAndDoubleSlash(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "a", "file.txt"), "hello")

	r := openRoot(t, dir)
	defer r.Close()

	f, err := r.OpenFile("./a//./file.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := readAll(t, f); got != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
}

func TestOpenFile_RelativeSymlink(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "real.txt"), "target content")
	if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	f, err := r.OpenFile("link.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := readAll(t, f); got != "target content" {
		t.Errorf("content = %q, want %q", got, "target content")
	}
}

// TestOpenFile_AbsoluteSymlinkIsRebased is the core confinement property: an
// absolute symlink inside the container must resolve against the
// container's own root, never against the host's real "/".
func TestOpenFile_AbsoluteSymlinkIsRebased(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "etc", "hostname"), "container-hostname")
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "abslink")); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	f, err := r.OpenFile("abslink")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got := readAll(t, f)
	if got != "container-hostname" {
		t.Errorf("content = %q, want the container's own /etc/hostname, not the host's", got)
	}
}

// TestOpenFile_DotDotClampsAtRoot proves a symlink with more ".." components
// than there is depth cannot climb above the container root: resolution
// clamps at root rather than escaping to the host filesystem above the
// directory t.TempDir() happens to sit under.
func TestOpenFile_DotDotClampsAtRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// However many ".." components, escape can reach at most the root
	// itself, which has no file named "escaped-secret" — so this must fail
	// to resolve, not succeed by reading some real file outside dir.
	if err := os.Symlink("../../../../../../../../escaped-secret", filepath.Join(dir, "sub", "escape")); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	if _, err := r.OpenFile("sub/escape"); err == nil {
		t.Fatal("OpenFile: expected an error (clamped path has nothing named escaped-secret at root)")
	}
}

// TestOpenFile_DotDotWithinRootStillWorks confirms ".." popping isn't simply
// disabled — it still moves up a real directory when there's somewhere
// real to go.
func TestOpenFile_DotDotWithinRootStillWorks(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "file.txt"), "hello")
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	f, err := r.OpenFile("a/../file.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if got := readAll(t, f); got != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
}

func TestOpenFile_SymlinkCycle(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("b", filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	_, err := r.OpenFile("a")
	if err == nil {
		t.Fatal("OpenFile: expected an error for a symlink cycle")
	}
	if !errors.Is(err, ErrTooManySymlinks) {
		t.Errorf("error = %v, want it to wrap ErrTooManySymlinks", err)
	}
}

func TestOpenFile_FIFOIsRefused(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	_, err := r.OpenFile("fifo")
	if err == nil {
		t.Fatal("OpenFile: expected an error for a FIFO")
	}
	if !errors.Is(err, ErrNotRegularFile) {
		t.Errorf("error = %v, want it to wrap ErrNotRegularFile", err)
	}
}

func TestOpenFile_DeviceIsRefused(t *testing.T) {
	dir := t.TempDir()
	devPath := filepath.Join(dir, "null")
	// A character device matching /dev/null (1:3). Creating device nodes
	// needs CAP_MKNOD; this environment may not have it.
	if err := unix.Mknod(devPath, unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3))); err != nil {
		t.Skipf("Mknod: %v (needs CAP_MKNOD; skipping device test)", err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	_, err := r.OpenFile("null")
	if err == nil {
		t.Fatal("OpenFile: expected an error for a device node")
	}
	if !errors.Is(err, ErrNotRegularFile) {
		t.Errorf("error = %v, want it to wrap ErrNotRegularFile", err)
	}
}

func TestOpenFile_DirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := openRoot(t, dir)
	defer r.Close()

	_, err := r.OpenFile("adir")
	if err == nil {
		t.Fatal("OpenFile: expected an error for a directory")
	}
	if !errors.Is(err, ErrNotRegularFile) {
		t.Errorf("error = %v, want it to wrap ErrNotRegularFile", err)
	}
}

func TestOpenFile_MissingPath(t *testing.T) {
	dir := t.TempDir()
	r := openRoot(t, dir)
	defer r.Close()

	if _, err := r.OpenFile("nope"); err == nil {
		t.Fatal("OpenFile: expected an error for a missing path")
	}
}

// TestOpenFile_DisallowedFilesystem uses procfs itself as the "container
// root": every regular file under it (e.g. self/stat) is on PROC_SUPER_MAGIC,
// which is not in the allowlist, so opening one through this package must be
// refused regardless of the file otherwise looking normal. This is a real
// kernel filesystem the test environment always has, so it needs no
// privilege or mount setup to exercise the allowlist check for real.
func TestOpenFile_DisallowedFilesystem(t *testing.T) {
	r := openRoot(t, "/proc")
	defer r.Close()

	_, err := r.OpenFile("self/stat")
	if err == nil {
		t.Fatal("OpenFile: expected an error for a disallowed filesystem type")
	}
	if !errors.Is(err, ErrFSNotAllowed) {
		t.Errorf("error = %v, want it to wrap ErrFSNotAllowed", err)
	}
}

func TestReadDir_ListsEntries(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "sub", "a.list"), "")
	mustWriteFile(t, filepath.Join(dir, "sub", "b.list"), "")
	mustWriteFile(t, filepath.Join(dir, "sub", "c.list"), "")

	r := openRoot(t, dir)
	defer r.Close()

	names, truncated, err := r.ReadDir("sub")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if truncated {
		t.Error("truncated = true, want false: well under MaxDirEntries")
	}
	want := []string{"a.list", "b.list", "c.list"}
	if len(names) != len(want) {
		t.Fatalf("ReadDir = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("ReadDir[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestReadDir_NotADirectory(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "file.txt"), "hello")

	r := openRoot(t, dir)
	defer r.Close()

	_, _, err := r.ReadDir("file.txt")
	if !errors.Is(err, ErrNotDirectory) {
		t.Errorf("error = %v, want it to wrap ErrNotDirectory", err)
	}
}

// TestReadDir_ManyEmptyFilesIsBoundedAndTruncated is the resource-
// consumption case ReadDir's batch-and-bound logic exists for: a directory
// with far more entries than MaxDirEntries must stop early and report
// truncated, rather than reading every entry into memory before anyone
// gets a chance to notice the count is too large.
func TestReadDir_ManyEmptyFilesIsBoundedAndTruncated(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "many")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	const total = MaxDirEntries + 50
	for i := 0; i < total; i++ {
		name := filepath.Join(sub, "f"+strconv.Itoa(i))
		if err := os.WriteFile(name, nil, 0o644); err != nil {
			t.Fatalf("create fixture file %d: %v", i, err)
		}
	}

	r := openRoot(t, dir)
	defer r.Close()

	names, truncated, err := r.ReadDir("many")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if !truncated {
		t.Error("truncated = false, want true: the directory has more than MaxDirEntries entries")
	}
	if len(names) != MaxDirEntries {
		t.Errorf("len(names) = %d, want exactly MaxDirEntries (%d)", len(names), MaxDirEntries)
	}
}

// TestReplaceAfterResolve_ReopenUsesOriginalFile is the anti-TOCTOU property
// the read contract's reopen-through-/proc/self/fd step exists for: even if
// the directory entry a path resolved to is replaced after the O_PATH
// descriptor was obtained but before it is reopened for content, the reopen
// still reaches the exact file that was resolved and fstat-checked, never
// whatever now occupies that name.
func TestReplaceAfterResolve_ReopenUsesOriginalFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	mustWriteFile(t, target, "original")

	r := openRoot(t, dir)
	defer r.Close()

	fd, err := r.resolve("target")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, target, "replacement")

	f, err := checkAndReopen(fd, "target", unix.S_IFREG, unix.O_RDONLY)
	if err != nil {
		t.Fatalf("checkAndReopen: %v", err)
	}
	if got := readAll(t, f); got != "original" {
		t.Errorf("content = %q, want %q (the file resolved before the replacement, not after)", got, "original")
	}
}

func TestReader_Close_ClosesRoot(t *testing.T) {
	dir := t.TempDir()
	r := openRoot(t, dir)
	rootFD := int(r.root.Fd())
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The fd should now be invalid; fstat on it must fail.
	var st unix.Stat_t
	if err := unix.Fstat(rootFD, &st); err == nil {
		t.Error("root fd is still valid after Close")
	}
}

func TestStat_SameDirViaSymlinkMatches(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(dir, "bin")); err != nil {
		t.Fatal(err)
	}
	r := openRoot(t, dir)
	defer r.Close()

	dev1, ino1, err := r.Stat("/bin")
	if err != nil {
		t.Fatalf("Stat(/bin): %v", err)
	}
	dev2, ino2, err := r.Stat("/usr/bin")
	if err != nil {
		t.Fatalf("Stat(/usr/bin): %v", err)
	}
	if dev1 != dev2 || ino1 != ino2 {
		t.Errorf("Stat(/bin) = (%s,%d), Stat(/usr/bin) = (%s,%d), want equal (merged-usr symlink)", dev1, ino1, dev2, ino2)
	}
}

func TestStat_DistinctDirsDoNotMatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := openRoot(t, dir)
	defer r.Close()

	dev1, ino1, err := r.Stat("/bin")
	if err != nil {
		t.Fatalf("Stat(/bin): %v", err)
	}
	dev2, ino2, err := r.Stat("/usr/bin")
	if err != nil {
		t.Fatalf("Stat(/usr/bin): %v", err)
	}
	if dev1 == dev2 && ino1 == ino2 {
		t.Errorf("Stat(/bin) and Stat(/usr/bin) unexpectedly matched for two distinct real directories")
	}
}

func TestStat_MissingPathErrors(t *testing.T) {
	dir := t.TempDir()
	r := openRoot(t, dir)
	defer r.Close()
	if _, _, err := r.Stat("/no/such/path"); err == nil {
		t.Error("expected an error for a missing path")
	}
}
