// Package procfs reads one process's own procfs entries — exe, maps,
// status, cgroup, namespace links, uid_map, and listening sockets — through
// a single directory descriptor opened for that process, rather than
// through path strings built fresh for every read. Every read after Open
// goes through that descriptor with openat/readlinkat, so a PID reused by
// an unrelated process between two reads cannot make this package read the
// wrong process's files under the old PID's name; Recheck lets a caller
// confirm the process behind the descriptor is still the one it started
// with.
//
// This package only reads procfs itself. It does not read into a
// container's rootfs (that is package rootfs) and it does not decide
// whether a read failure means "denied" or "gone" for anything beyond the
// classification Classify provides — assembling those into a sample, a
// generation, or evidence is the Sensor's job, not this package's.
package procfs

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// maxSmallFileBytes bounds the procfs files this package reads whole into
// memory (stat, status, cgroup, uid_map): all are kernel-synthesized text
// with sizes in the hundreds of bytes in practice. A read that hits this
// bound is treated as malformed input, not a legitimately large file — a
// real procfs entry never approaches it.
const maxSmallFileBytes = 1 << 20 // 1 MiB

// MaxMapsLines bounds how many file-backed executable mappings Maps will
// collect from one /proc/<pid>/maps before reporting truncated. It is a
// starting point pending measurement against real container mapping counts,
// not a measured limit.
const MaxMapsLines = 100_000

// Handle is /proc/<pid> opened once as an O_PATH directory descriptor and
// kept open for as long as the caller needs to read that process's files.
// Every read method resolves its target relative to this descriptor with
// openat/readlinkat, never by formatting a fresh "/proc/<pid>/..." path, so
// none of them can be redirected by the original PID having been recycled
// after Open returned.
type Handle struct {
	pid       int
	dir       *os.File
	starttime int64
}

// Open opens /proc/<pid> and captures its starttime (field 22 of
// /proc/<pid>/stat) as the generation identity Recheck later confirms is
// unchanged. The directory is opened O_PATH: this only requires search
// permission on /proc/<pid> itself (granted to everyone, per proc(5)), not
// read permission, and every subsequent read still goes through the
// kernel's own ptrace/DAC checks on the specific entry being read (see
// fs/proc/base.c; O_PATH fds are valid dirfd arguments to the *at() family
// since Linux 3.6, per open(2)).
func Open(pid int) (*Handle, error) {
	fd, err := unix.Openat(unix.AT_FDCWD, procDir(pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("procfs: open %d: %w", pid, err)
	}
	h := &Handle{pid: pid, dir: os.NewFile(uintptr(fd), procDir(pid))}
	st, err := h.readStarttime()
	if err != nil {
		h.dir.Close()
		return nil, err
	}
	h.starttime = st
	return h, nil
}

func procDir(pid int) string { return fmt.Sprintf("/proc/%d", pid) }

// PID returns the process ID this Handle was opened for.
func (h *Handle) PID() int { return h.pid }

// Starttime returns the starttime this Handle captured when it was opened.
func (h *Handle) Starttime() int64 { return h.starttime }

// Close releases the underlying directory descriptor.
func (h *Handle) Close() error { return h.dir.Close() }

// Recheck re-reads the process's current starttime and reports an error if
// it no longer matches the one captured at Open: the PID has been reused by
// a different process (or the kernel's counter otherwise disagrees), and
// whatever was read through this Handle since Open must be discarded rather
// than attributed to the process this Handle was meant to observe.
func (h *Handle) Recheck() error {
	cur, err := h.readStarttime()
	if err != nil {
		return err
	}
	if cur != h.starttime {
		return fmt.Errorf("procfs: pid %d generation changed (starttime %d, now %d): %w",
			h.pid, h.starttime, cur, ErrGenerationChanged)
	}
	return nil
}

// dirFD returns the raw descriptor number backing h.dir, for use as the
// dirfd argument to the unix package's *at() calls below.
func (h *Handle) dirFD() int { return int(h.dir.Fd()) }

// FD returns the same raw descriptor number as dirFD, exported for a caller
// that needs to name this Handle's own open directory descriptor in a path
// string — e.g. "/proc/self/fd/<FD()>/root/…" — for an operation (such as
// connect(2) to a UNIX socket, which takes a pathname and has no *at()
// form) that cannot go through openat/readlinkat directly. Resolving
// through /proc/self/fd/<FD()> keeps the same guarantee OpenRelativeRaw
// documents: the path stays bound to the exact process Open verified, not
// to whatever process the PID number names by the time the path is
// resolved.
func (h *Handle) FD() int { return h.dirFD() }

// OpenRelativeRaw opens name (a path relative to /proc/<pid>, e.g. "mem" or
// "root/tmp/foo") through h's own directory descriptor, exactly like
// openRelative but with caller-chosen flags/mode and returning a raw fd
// instead of an *os.File. It exists for a caller that must open something
// this package's own read-only methods do not cover (a write-flagged open,
// or a multi-component path under "root/…"), while still getting this
// package's core guarantee: because the resolution starts from h's already
// -open directory descriptor rather than a freshly formatted "/proc/<pid>/…"
// string, it stays bound to the exact process Open verified — even a
// multi-component path like "root/tmp/foo" resolves against that same
// descriptor in one openat(2) call, so a symlink swap or a PID reused by an
// unrelated process between Open and this call cannot redirect it. The
// caller owns the returned fd and must close it.
func (h *Handle) OpenRelativeRaw(name string, flags int, mode uint32) (int, error) {
	fd, err := unix.Openat(h.dirFD(), name, flags|unix.O_CLOEXEC, mode)
	if err != nil {
		return -1, fmt.Errorf("procfs: openat %s/%s: %w", procDir(h.pid), name, err)
	}
	return fd, nil
}

// openRelative opens name relative to h's directory descriptor.
// O_NOFOLLOW is not set: every name this package opens this way (stat,
// maps, status, cgroup, uid_map, net/tcp{,6}) is a plain file the kernel
// synthesizes directly under /proc/<pid>, never itself a symlink.
func (h *Handle) openRelative(name string, flags int) (*os.File, error) {
	fd, err := unix.Openat(h.dirFD(), name, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), procDir(h.pid)+"/"+name), nil
}

// readSmallFile reads name (relative to h) whole, bounded by
// maxSmallFileBytes.
func (h *Handle) readSmallFile(name string) ([]byte, error) {
	f, err := h.openRelative(name, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSmallFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSmallFileBytes {
		return nil, fmt.Errorf("procfs: %s: exceeds %d bytes", name, maxSmallFileBytes)
	}
	return data, nil
}

func (h *Handle) readStarttime() (int64, error) {
	data, err := h.readSmallFile("stat")
	if err != nil {
		return 0, fmt.Errorf("procfs: read stat for %d: %w", h.pid, err)
	}
	return ParseStarttime(string(data))
}

// PPID reads /proc/<pid>/stat fresh (not cached the way Starttime is, since
// a parent can change across samples — e.g. a reparented orphan — without
// the child's own generation changing) and returns its parent PID.
func (h *Handle) PPID() (int, error) {
	data, err := h.readSmallFile("stat")
	if err != nil {
		return 0, fmt.Errorf("procfs: read stat for %d: %w", h.pid, err)
	}
	return ParsePPID(string(data))
}

// State reads /proc/<pid>/stat fresh (not cached — a process can transition
// into a zombie at any moment after Open) and returns its current
// proc_pid_stat(5) state code. See ParseState's own doc comment for why this
// is checked separately from Starttime wherever "is this process still
// alive" needs to be more than "has this PID not yet been reused".
func (h *Handle) State() (byte, error) {
	data, err := h.readSmallFile("stat")
	if err != nil {
		return 0, fmt.Errorf("procfs: read stat for %d: %w", h.pid, err)
	}
	return ParseState(string(data))
}

// Exe resolves /proc/<pid>/exe and reports the (possibly deleted) target
// path.
func (h *Handle) Exe() (path string, deleted bool, err error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(h.dirFD(), "exe", buf)
	if err != nil {
		return "", false, err
	}
	path, deleted = SplitDeleted(string(buf[:n]))
	return path, deleted, nil
}

// Maps reads /proc/<pid>/maps and returns the deduplicated set of
// file-backed executable mappings, keyed by (path, dev, inode). Truncated
// is set once more than MaxMapsLines raw lines have been read, regardless of
// how many of them parsed as an executable mapping — see ParseMapsStream.
func (h *Handle) Maps() (entries []MapEntry, truncated bool, err error) {
	f, err := h.openRelative("maps", unix.O_RDONLY)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	return ParseMapsStream(f)
}

// Status returns the effective UID (2nd field of "Uid:") and the raw
// "CapEff:" hex string from /proc/<pid>/status.
func (h *Handle) Status() (effectiveUID int, capEff string, err error) {
	data, err := h.readSmallFile("status")
	if err != nil {
		return 0, "", err
	}
	return ParseStatus(data)
}

// Cgroup returns the raw contents of /proc/<pid>/cgroup.
func (h *Handle) Cgroup() ([]byte, error) {
	return h.readSmallFile("cgroup")
}

// ContainerID reads /proc/<pid>/cgroup and extracts the container ID it
// names, if any (see ContainerIDFromCgroup).
func (h *Handle) ContainerID() (id string, ok bool, err error) {
	data, err := h.Cgroup()
	if err != nil {
		return "", false, err
	}
	id, ok = ContainerIDFromCgroup(data)
	return id, ok, nil
}

// NSLink reads the readlink target of /proc/<pid>/ns/<kind> (e.g. "net",
// "mnt", "user"), one of the per-PID namespace identifiers used to detect a
// namespace change across samples (man 7 namespaces).
func (h *Handle) NSLink(kind string) (string, error) {
	buf := make([]byte, 128)
	n, err := unix.Readlinkat(h.dirFD(), "ns/"+kind, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// UIDMap reads the raw contents of /proc/<pid>/uid_map (man 7
// user_namespaces), verbatim (including its trailing newline handling, left
// to the caller) rather than interpreted: an empty/absent mapping (the
// ordinary non-remapped case) reads back as a single line mapping the full
// UID range 1:1 on most kernels.
func (h *Handle) UIDMap() (string, error) {
	data, err := h.readSmallFile("uid_map")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// NetTCPListens reads /proc/<pid>/net/tcp or /proc/<pid>/net/tcp6 (kind must
// be "tcp" or "tcp6") and returns its LISTEN rows.
func (h *Handle) NetTCPListens(kind string) ([]NetTCPListen, error) {
	if kind != "tcp" && kind != "tcp6" {
		return nil, fmt.Errorf("procfs: NetTCPListens: kind must be tcp or tcp6, got %q", kind)
	}
	f, err := h.openRelative("net/"+kind, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []NetTCPListen
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header row
		}
		if l, ok := ParseNetTCPLine(sc.Text()); ok {
			out = append(out, l)
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// OpenRoot opens /proc/<pid>/root as an O_PATH directory descriptor and
// hands it to the caller, which is expected to pass it to
// internal/sensor/rootfs.Open. O_NOFOLLOW is deliberately not set: "root" is
// a magic symlink (like "exe"), and the kernel only produces the process's
// actual root directory by following it, not by returning the symlink
// object itself.
func (h *Handle) OpenRoot() (*os.File, error) {
	fd, err := unix.Openat(h.dirFD(), "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("procfs: open root for %d: %w", h.pid, err)
	}
	return os.NewFile(uintptr(fd), procDir(h.pid)+"/root"), nil
}
