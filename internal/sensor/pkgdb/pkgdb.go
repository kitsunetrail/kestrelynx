// Package pkgdb parses the OS package databases the Sensor recognizes —
// dpkg, distroless's status.d, and apk — into an ownership index: which
// package(s) claim which recorded path. It never opens a file itself.
// Every input arrives as an already-open io.Reader the observer produced by
// resolving a path through package rootfs's read contract; this package's
// only job is to make sense of bytes it is handed, which is also what lets
// it run inside the parser process, which has no filesystem access at all
// once its sandbox is in place.
//
// Nothing here resolves a database-recorded path through the container's
// filesystem (no symlink following, no merged-/usr normalization): that
// requires the rootfs access this package never has, so an Index's paths
// are exactly what the database itself recorded, and matching them against
// a path observed elsewhere in the container is left to the observer, which
// can resolve both sides through the same Reader.
package pkgdb

import (
	"io"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// NamedReader is one already-opened input file, named exactly as the
// observer found it (e.g. "curl.list", "curl.md5sums", "installed"). This
// package trusts the name it's given for each reader and never revisits the
// filesystem to check it.
type NamedReader struct {
	Name string
	R    io.Reader
}

// Owner identifies one package that claims a path in an Index: which
// database recorded it, and under what name.
type Owner struct {
	DBKind evidence.PackageDBKind
	Name   string
}

// LedgerEntry is one package record found while building an Index: its
// identity, and whether this specific package's own file list could be
// recovered at all. An empty file list and a missing one are not the same
// thing — a metapackage that installs no files is not incomplete for having
// none, while a package whose .list/.md5sums could not be read is.
type LedgerEntry struct {
	DBKind          evidence.PackageDBKind
	Name            string
	Version         string
	Arch            string
	FileListPresent bool
	FileCount       int
}

// Index maps a package database's recorded paths to the package(s) that
// claim them, exactly as the database recorded them. The same resolved path
// can have more than one owner (Debian's libc-bin ships the /usr/bin/ld.so
// symlink while libc6 ships the loader it points at — two real packages,
// one path, because dpkg's .list files name both) — Lookup reports every
// distinct (DBKind, Name) that claimed a path, never just the first.
type Index struct {
	byPath   map[string][]Owner
	ownerSet map[string]bool   // "<path>\x00<dbKind>\x00<name>" membership, for byPath's dedup
	versions map[string]string // "<dbKind>\x00<name>" -> installed version
	// Ledger lists every package this Index found metadata for, regardless
	// of whether its file list could be read.
	Ledger []LedgerEntry
}

func newIndex() *Index {
	return &Index{
		byPath:   map[string][]Owner{},
		ownerSet: map[string]bool{},
		versions: map[string]string{},
	}
}

// add records path as owned by (dbKind, name), ignoring a repeat of an
// owner this Index has already recorded for that exact path (a .list or
// .md5sums routinely names both a versioned file and a symlink to it, and
// without dedup a single package could appear to multiply-own its own
// path).
func (idx *Index) add(path string, dbKind evidence.PackageDBKind, name string) {
	key := path + "\x00" + string(dbKind) + "\x00" + name
	if idx.ownerSet[key] {
		return
	}
	idx.ownerSet[key] = true
	idx.byPath[path] = append(idx.byPath[path], Owner{DBKind: dbKind, Name: name})
}

// Lookup resolves a path exactly as some database recorded it (no symlink
// resolution — see the package doc). owners has more than one entry only
// when multiple packages claim the same path.
func (idx *Index) Lookup(path string) (owners []Owner, ok bool) {
	o, found := idx.byPath[path]
	return o, found
}

func (idx *Index) setVersion(dbKind evidence.PackageDBKind, name, version string) {
	if version == "" {
		return
	}
	idx.versions[string(dbKind)+"\x00"+name] = version
}

// Version returns the installed version an Index recorded for (dbKind,
// name), if any.
func (idx *Index) Version(dbKind evidence.PackageDBKind, name string) (string, bool) {
	v, ok := idx.versions[string(dbKind)+"\x00"+name]
	return v, ok
}

// Limits bounds how much a Parse* function will read before it stops and
// reports Truncated instead of continuing, mirroring the read contract's
// per-file and per-index budgets. These are initial values, starting points
// pending integration testing against real package counts, not measured
// limits (ASSUMED).
type Limits struct {
	MaxStatusBytes     int64 // dpkg status / one distroless control stanza file
	MaxListBytes       int64 // dpkg .list / one distroless .md5sums file
	MaxApkBytes        int64 // apk installed
	MaxTotalBytes      int64 // total content bytes read while building one Index
	MaxFiles           int   // most list/md5sums-equivalent files read
	MaxPathsPerPackage int   // most path entries kept for one package from one file
}

// DefaultLimits are the read contract's initial per-file and per-index
// budgets.
func DefaultLimits() Limits {
	return Limits{
		MaxStatusBytes:     32 << 20,
		MaxListBytes:       1 << 20,
		MaxApkBytes:        32 << 20,
		MaxTotalBytes:      256 << 20,
		MaxFiles:           20000,
		MaxPathsPerPackage: 50000,
	}
}

// FileError is one input file a Parse* function could not read or parse.
type FileError struct {
	Name string
	Err  error
}

// Diagnostics reports what went wrong (if anything) while building an
// Index, kept apart from the Index itself so "every input was read" and
// "reading stopped before every input could be seen" are never confused —
// the latter means the Index's absence of a package from some path is not
// evidence that nothing owns it.
type Diagnostics struct {
	// Truncated is set when a size, count, or per-package path limit
	// stopped this parse before every input could be read.
	Truncated bool
	Errors    []FileError
}
