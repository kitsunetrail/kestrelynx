// Package rootfs implements the observer's read contract for a container's
// own filesystem: everything under it is untrusted input, since the
// container decides what lives there. A Reader is confined to the root
// descriptor it was opened from (a process's /proc/<pid>/root, opened by
// package procfs) and resolves every path one element at a time —
// following symlinks by hand, rebasing an absolute one under the same
// root, and never letting ".." climb above it — so that a symlink swapped
// mid-resolution cannot redirect a read outside the container. The final
// component must fstat as a regular file (OpenFile) or a directory
// (ReadDir) on an allowed filesystem type before it is used for anything
// else; a FIFO, device, socket, or symlink left unresolved is refused
// outright rather than opened and found out about later.
//
// This package only opens files. It never reads their content — that is
// package pkgdb's job, working from the descriptors this package hands
// back — and it never decides which paths in a container are worth
// reading, which is the Sensor's job.
package rootfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// MaxSymlinkExpansions bounds how many symlinks one resolve call will
// follow, the same defense a real path-resolution loop needs against a
// symlink cycle (mirrors the runtime-discovery harness's resolveInRoot,
// which used the same bound for the same reason).
const MaxSymlinkExpansions = 40

// MaxDirEntries bounds how many names ReadDir will collect from one
// directory before reporting truncated. A container's own directory
// contents are untrusted input like everything else under its rootfs: a
// directory holding far more entries than any real package database's file
// list ever names is read for its names alone, at no cost proportional to
// file content, so nothing else in the read contract's per-file byte caps
// would ever stop it.
const MaxDirEntries = 20_000

// dirReadBatch is how many names one Readdirnames call asks for while
// ReadDir counts toward MaxDirEntries. Reading in bounded batches, rather
// than asking for everything with Readdirnames(-1), means an oversized
// directory is stopped as soon as MaxDirEntries is crossed instead of
// first being read into memory in full.
const dirReadBatch = 512

// allowedFSMagic is the filesystem types a resolved file may live on
// (linux/magic.h): overlay, ext4 (ext2's magic is the same value), xfs,
// btrfs, tmpfs. Anything else — including procfs, sysfs, or a filesystem
// this Sensor has no reason to expect inside a container's rootfs — is
// refused regardless of how the other checks come out.
var allowedFSMagic = map[int64]bool{
	unix.OVERLAYFS_SUPER_MAGIC: true,
	unix.EXT4_SUPER_MAGIC:      true, // == EXT2_SUPER_MAGIC on Linux
	unix.XFS_SUPER_MAGIC:       true,
	unix.BTRFS_SUPER_MAGIC:     true,
	unix.TMPFS_MAGIC:           true,
}

var (
	// ErrNotRegularFile is returned by OpenFile when the resolved path's
	// final component is not a regular file (a FIFO, device, socket,
	// directory, or an unresolved symlink).
	ErrNotRegularFile = errors.New("rootfs: not a regular file")
	// ErrNotDirectory is returned by ReadDir when the resolved path's final
	// component is not a directory.
	ErrNotDirectory = errors.New("rootfs: not a directory")
	// ErrFSNotAllowed is returned when the resolved file's filesystem type
	// is not in allowedFSMagic.
	ErrFSNotAllowed = errors.New("rootfs: filesystem type not allowed")
	// ErrTooManySymlinks is returned when resolving a path follows more
	// than MaxSymlinkExpansions symlinks (a cycle, or a deliberately long
	// chain).
	ErrTooManySymlinks = errors.New("rootfs: too many symlink expansions")
	// ErrReopenMismatch is returned when reopening a resolved file through
	// /proc/self/fd yields a different device, inode, or file type than the
	// O_PATH descriptor it was resolved to — the read-contract's final
	// consistency check.
	ErrReopenMismatch = errors.New("rootfs: reopened file does not match the resolved file")
)

// Reader resolves paths inside one container's rootfs, confined to the root
// descriptor it was opened from.
type Reader struct {
	// root is kept as an *os.File (not just its raw fd) so the descriptor
	// stays open for as long as the Reader is reachable: os.File closes its
	// fd from a finalizer once the value itself is unreachable, and this
	// Reader must not let that happen out from under a resolve in progress.
	root *os.File
}

// Open returns a Reader confined to root, an O_PATH directory descriptor
// for a container's own root (as procfs.Handle.OpenRoot returns). The
// Reader takes ownership of root: closing the Reader closes it, and the
// caller must not use root directly afterward.
func Open(root *os.File) *Reader {
	return &Reader{root: root}
}

// Close releases the root descriptor this Reader was opened with.
func (r *Reader) Close() error {
	return r.root.Close()
}

// splitPath breaks p into its non-empty, non-"." components.
func splitPath(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." {
			continue
		}
		out = append(out, c)
	}
	return out
}

// resolve walks path component by component starting from r.root, following
// symlinks by hand and never letting ".." pop above the root or an absolute
// symlink point outside it. It returns an O_PATH descriptor for the final
// component — unopened for reading, unfollowed past that point — which the
// caller owns and must close.
func (r *Reader) resolve(path string) (fd int, err error) {
	rootFD := int(r.root.Fd())

	// stack holds every directory fd opened between the root and the
	// current position, root itself excluded so a ".." can never close or
	// pop past it.
	var stack []int
	closeStack := func() {
		for _, f := range stack {
			unix.Close(f)
		}
		stack = nil
	}
	cur := func() int {
		if len(stack) == 0 {
			return rootFD
		}
		return stack[len(stack)-1]
	}

	queue := splitPath(path)
	expansions := 0

	for len(queue) > 0 {
		comp := queue[0]
		queue = queue[1:]

		if comp == ".." {
			if len(stack) > 0 {
				unix.Close(stack[len(stack)-1])
				stack = stack[:len(stack)-1]
			}
			// ".." above root is clamped to root, never an error and never
			// an escape — the same behavior openat2's RESOLVE_IN_ROOT gives.
			continue
		}

		child, oerr := unix.Openat(cur(), comp, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oerr != nil {
			closeStack()
			return -1, fmt.Errorf("rootfs: openat %q: %w", comp, oerr)
		}

		// With O_PATH, O_NOFOLLOW does not fail with ELOOP on a symbolic
		// link the way it would without O_PATH (open(2)): it succeeds and
		// hands back a descriptor referring to the symlink object itself.
		// fstat is the only way to notice that happened, and it must be
		// checked before this descriptor is trusted as "the next directory
		// to resolve against" — pushing a symlink's own O_PATH fd onto the
		// stack would make the next openat fail with ENOTDIR instead of
		// being followed, silently breaking every symlink in the path.
		var st unix.Stat_t
		if err := unix.Fstat(child, &st); err != nil {
			unix.Close(child)
			closeStack()
			return -1, fmt.Errorf("rootfs: fstat %q: %w", comp, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFLNK {
			stack = append(stack, child)
			continue
		}

		// comp is a symlink: read its target through the fd we already
		// have (readlinkat with an empty pathname reads the fd's own
		// target — the O_PATH analogue of readlink(2) on a path) rather
		// than re-resolving comp by name, so a rename racing this read
		// cannot substitute a different link.
		buf := make([]byte, 4096)
		n, rlerr := unix.Readlinkat(child, "", buf)
		unix.Close(child)
		if rlerr != nil {
			closeStack()
			return -1, fmt.Errorf("rootfs: readlink %q: %w", comp, rlerr)
		}
		target := string(buf[:n])
		expansions++
		if expansions > MaxSymlinkExpansions {
			closeStack()
			return -1, ErrTooManySymlinks
		}
		targetComps := splitPath(target)
		if strings.HasPrefix(target, "/") {
			// Absolute symlink: rebase under root, discarding whatever
			// directory chain got us here — never resolved against a host
			// "/".
			closeStack()
			queue = append(targetComps, queue...)
		} else {
			// Resolved against its own containing directory, i.e. "stack"
			// as it stands (the symlink's own final component was never
			// pushed onto it).
			queue = append(targetComps, queue...)
		}
	}

	if len(stack) == 0 {
		dupFD, derr := unix.Dup(rootFD)
		if derr != nil {
			return -1, fmt.Errorf("rootfs: dup root: %w", derr)
		}
		return dupFD, nil
	}
	final := stack[len(stack)-1]
	for _, f := range stack[:len(stack)-1] {
		unix.Close(f)
	}
	return final, nil
}

// checkAndReopen implements steps 3-5 of the read contract shared by
// OpenFile and ReadDir: fstat the resolved O_PATH descriptor against
// wantType, fstatfs it against the filesystem allowlist, reopen it through
// /proc/self/fd (the only way to get a descriptor actually usable for
// read()/getdents(), since O_PATH descriptors support neither), and
// re-verify the reopened descriptor still agrees on device, inode, and
// type. fd is always closed by this function; the returned *os.File is the
// caller's to close.
func checkAndReopen(fd int, path string, wantType uint32, openFlags int) (*os.File, error) {
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("rootfs: fstat %q: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != wantType {
		if wantType == unix.S_IFDIR {
			return nil, fmt.Errorf("rootfs: %q: %w", path, ErrNotDirectory)
		}
		return nil, fmt.Errorf("rootfs: %q: %w", path, ErrNotRegularFile)
	}

	var stfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &stfs); err != nil {
		return nil, fmt.Errorf("rootfs: fstatfs %q: %w", path, err)
	}
	if !allowedFSMagic[stfs.Type] {
		return nil, fmt.Errorf("rootfs: %q: %w (fs type %#x)", path, ErrFSNotAllowed, stfs.Type)
	}

	reopened, err := reopenSelfFD(fd, openFlags)
	if err != nil {
		return nil, fmt.Errorf("rootfs: reopen %q: %w", path, err)
	}

	var st2 unix.Stat_t
	if err := unix.Fstat(int(reopened.Fd()), &st2); err != nil {
		reopened.Close()
		return nil, fmt.Errorf("rootfs: fstat reopened %q: %w", path, err)
	}
	if st2.Dev != st.Dev || st2.Ino != st.Ino || st2.Mode&unix.S_IFMT != st.Mode&unix.S_IFMT {
		reopened.Close()
		return nil, fmt.Errorf("rootfs: %q: %w", path, ErrReopenMismatch)
	}
	return reopened, nil
}

// reopenSelfFD reopens fd through /proc/self/fd/<fd>, the only route from an
// O_PATH descriptor (which read()/getdents() refuse outright) to one usable
// for content.
func reopenSelfFD(fd int, flags int) (*os.File, error) {
	name := fmt.Sprintf("/proc/self/fd/%d", fd)
	newFD, err := unix.Open(name, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(newFD), name), nil
}

// Stat resolves path against the container root, the same symlink-safe way
// OpenFile and ReadDir do, and reports the resolved object's device and
// inode — without requiring it to be a regular file or a directory the way
// those two do. It exists for a caller that needs to compare two paths for
// referring to the same underlying object (e.g. confirming that /bin is
// actually a symlink into /usr/bin in this specific container, rather than
// assuming a merged-/usr layout from the path spelling alone) rather than
// to read or list one. The returned dev is formatted the same "MM:mm" hex
// way /proc/<pid>/maps and Calibration.StatDev are, so it compares directly
// against those.
func (r *Reader) Stat(path string) (dev string, ino uint64, err error) {
	fd, err := r.resolve(path)
	if err != nil {
		return "", 0, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", 0, fmt.Errorf("rootfs: fstat %q: %w", path, err)
	}
	return formatDev(st.Dev), st.Ino, nil
}

// OpenFile resolves path against the container root and returns a
// read-only handle to it, once every step of the read contract has agreed
// it is safe to open: the final component must be a regular file (not a
// FIFO, device, socket, or unresolved symlink) on an allowed filesystem
// type, and reopening it through /proc/self/fd must land on the exact same
// file. The returned *os.File is opened O_RDONLY|O_NONBLOCK|O_NOCTTY:
// O_NONBLOCK so a FIFO that somehow reached this point (it should not have —
// the fstat check above rejects it) cannot block waiting for a writer, and
// O_NOCTTY so a maliciously-placed tty device cannot become this process's
// controlling terminal.
func (r *Reader) OpenFile(path string) (*os.File, error) {
	fd, err := r.resolve(path)
	if err != nil {
		return nil, err
	}
	return checkAndReopen(fd, path, unix.S_IFREG, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY)
}

// ReadDir resolves path against the container root and returns the names of
// its entries (excluding "." and ".."), sorted. The final component must be
// a directory on an allowed filesystem type, checked and reopened exactly
// as OpenFile does for a regular file.
//
// Entries are read in bounded batches rather than all at once (Go's
// Readdirnames(-1) reads the whole directory into memory before returning):
// once MaxDirEntries names have been collected, reading stops and truncated
// is reported, so a directory engineered to hold far more entries than any
// real package database ever would cannot make the observer read and hold
// an unbounded number of names before the caller's own file-count limit
// (e.g. pkgdb's Limits.MaxFiles) ever gets a chance to apply. The returned
// names are sorted within whatever was collected, never a full sort of
// entries that were never read.
func (r *Reader) ReadDir(path string) (names []string, truncated bool, err error) {
	fd, err := r.resolve(path)
	if err != nil {
		return nil, false, err
	}
	dir, err := checkAndReopen(fd, path, unix.S_IFDIR, unix.O_RDONLY)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()

	for {
		batch, rerr := dir.Readdirnames(dirReadBatch)
		names = append(names, batch...)
		if len(names) > MaxDirEntries {
			names = names[:MaxDirEntries]
			truncated = true
			break
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return nil, false, fmt.Errorf("rootfs: readdirnames %q: %w", path, rerr)
		}
		if len(batch) == 0 {
			// Defensive: Readdirnames(n>0) is documented to return io.EOF
			// once nothing more remains, but an empty, error-free batch is
			// treated as "nothing more to read" too, rather than looping
			// forever on it.
			break
		}
	}
	sort.Strings(names)
	return names, truncated, nil
}
