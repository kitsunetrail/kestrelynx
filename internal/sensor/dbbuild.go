package sensor

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/pkgdb"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/rootfs"
)

// rpmCandidatePaths are the on-disk locations an rpm-based image keeps its
// package database at, checked only to tell "a database exists here but
// this Sensor cannot parse it" (DBStatusUnsupported) apart from "no
// database at all" (DBStatusAbsent) — this Sensor never reads their
// content.
var rpmCandidatePaths = []string{
	"var/lib/rpm/rpmdb.sqlite",
	"var/lib/rpm/Packages",
	"var/lib/rpm/Packages.db",
}

// existsButUnreadable reports whether err is rootfs refusing a candidate
// path for a reason other than "nothing is there at all" — a permission
// problem, the wrong file type (a FIFO, a device), a disallowed filesystem,
// a symlink cycle, or a reopen mismatch. Any of these means the database
// most likely does exist, just not in a form this read contract will open
// right now; the caller must not conclude DBStatusAbsent from it (which
// would never be retried), only DBStatusError (which is).
func existsButUnreadable(err error) bool {
	return err != nil && !errors.Is(err, unix.ENOENT)
}

// detectPackageDB looks for a supported OS package database under a
// container's rootfs, trying dpkg first (a status file), then apk (an
// installed file), then distroless (a status.d directory with no plain
// status file — checked after dpkg specifically so a real dpkg install is
// never misclassified as distroless), then rpm (recognized but unsupported).
// A container with none of these is DBStatusAbsent, never an error: plenty
// of real images (a from-scratch Go binary, for instance) have no OS package
// database at all, and that is not itself a failure. A candidate that
// resolves to something this read contract refuses for any reason other
// than not existing at all is DBStatusError instead — see
// existsButUnreadable — which the caller retries on the same backoff
// schedule as any other failed input, rather than settling on a status that
// is never revisited.
func detectPackageDB(r *rootfs.Reader) (evidence.PackageDBKind, evidence.PackageDBStatus) {
	if f, err := r.OpenFile("var/lib/dpkg/status"); err == nil {
		f.Close()
		return evidence.DBKindDpkg, evidence.DBStatusOK
	} else if existsButUnreadable(err) {
		return evidence.DBKindDpkg, evidence.DBStatusError
	}
	for _, p := range []string{"lib/apk/db/installed", "usr/lib/apk/db/installed"} {
		if f, err := r.OpenFile(p); err == nil {
			f.Close()
			return evidence.DBKindApk, evidence.DBStatusOK
		} else if existsButUnreadable(err) {
			return evidence.DBKindApk, evidence.DBStatusError
		}
	}
	if _, _, err := r.ReadDir("var/lib/dpkg/status.d"); err == nil {
		return evidence.DBKindDistroless, evidence.DBStatusOK
	} else if existsButUnreadable(err) {
		return evidence.DBKindDistroless, evidence.DBStatusError
	}
	for _, p := range rpmCandidatePaths {
		if f, err := r.OpenFile(p); err == nil {
			f.Close()
			return "", evidence.DBStatusUnsupported
		} else if existsButUnreadable(err) {
			// Still unsupported either way (this Sensor never parses rpm
			// regardless of whether it can open the file), but worth
			// recording as "found, not just guessed" for anyone reading
			// this code later.
			return "", evidence.DBStatusUnsupported
		}
	}
	return "", evidence.DBStatusAbsent
}

// openIndexFile opens path through r, fstats the result, and returns a
// fully-identified indexFile — Dev/Inode/Size come from that fstat, not from
// anything the container's own database claims about itself, since they are
// what lets a later repeat failure be told apart from a genuinely different
// file placed at the same path (see generationState.recordParseFailure).
// Called exactly once per candidate, immediately before that candidate is
// either sent to the parser or closed again for backing off — see
// streamBuildFiles' own doc comment for why this function itself never
// accumulates a batch of open files on a caller's behalf.
func openIndexFile(r *rootfs.Reader, role, name, path string) (indexFile, error) {
	f, err := r.OpenFile(path)
	if err != nil {
		return indexFile{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return indexFile{}, fmt.Errorf("fstat %s: %w", path, err)
	}
	return indexFile{
		Role: role, Name: name, Path: "/" + path,
		Dev: formatDevForCompare(st.Dev), Inode: st.Ino, Size: st.Size,
		File: f,
	}, nil
}

// candidateFile is one package-database input this Sensor knows about by
// name and role alone — enumerated (a directory listing, a fixed expected
// path) but deliberately not yet opened. PkgName is the package name this
// candidate names, once a .list/.md5sums suffix is stripped off — used only
// for UnreadablePackages bookkeeping when this particular candidate later
// turns out not to be openable at all; empty for a mandatory candidate
// (roleStatus/roleInstalled), which is never itself an "unreadable package"
// (its own failure to open is a build-level failure — see
// streamBuildFiles' own doc comment).
type candidateFile struct {
	Role    string
	Name    string
	Path    string
	PkgName string
}

// candidateOutcome is gatherIndexFiles' result: every input path kind's own
// build might need, named but not yet opened. Truncated means some part of
// the directory listing itself was cut short (ReadDir's own truncation, or
// this function's own MaxFiles cutoff) — in either case, there is no way to
// know which package names were affected, so the caller has nothing more
// precise to record than the whole generation's own Truncated flag.
type candidateOutcome struct {
	Files     []candidateFile
	Truncated bool
}

// gatherIndexFiles enumerates every input a package database's Parse*
// function will eventually need, for kind, without opening any of them:
// only a directory listing (ReadDir) or, for apk, a momentary existence
// check (rootfs.Reader.Stat, which itself opens, fstats, and closes before
// returning — never held). Deliberately kept apart from actually opening
// these inputs (see streamBuildFiles, which does the opening, one input at
// a time, immediately before sending it to the parser and closing it again)
// so a database with tens of thousands of tiny per-package files never has
// more than one or two descriptors open at once on this Sensor's own side,
// no matter how many candidates there are in total.
//
// Unlike eagerly opening every file up front, this never fails for a
// missing or unreadable file, including the one mandatory per-database file
// (dpkg's status, apk's installed): whether each candidate can actually be
// opened is discovered later, by streamBuildFiles, at the moment it tries.
func gatherIndexFiles(r *rootfs.Reader, kind evidence.PackageDBKind, limits pkgdb.Limits) (candidateOutcome, error) {
	switch kind {
	case evidence.DBKindDpkg:
		out := candidateOutcome{Files: []candidateFile{{Role: roleStatus, Name: "status", Path: "var/lib/dpkg/status"}}}
		names, dirTruncated, err := r.ReadDir("var/lib/dpkg/info")
		if dirTruncated {
			out.Truncated = true
		}
		if err == nil {
			for _, name := range names {
				if !strings.HasSuffix(name, ".list") {
					continue
				}
				if len(out.Files) >= limits.MaxFiles {
					out.Truncated = true
					break
				}
				out.Files = append(out.Files, candidateFile{
					Role: roleList, Name: name, Path: "var/lib/dpkg/info/" + name,
					PkgName: strings.TrimSuffix(name, ".list"),
				})
			}
		}
		return out, nil

	case evidence.DBKindApk:
		// Both candidate paths are only ever probed for existence here
		// (Stat, not Open) — the actual read this build depends on happens
		// once, later, in streamBuildFiles.
		for _, p := range []string{"lib/apk/db/installed", "usr/lib/apk/db/installed"} {
			if _, _, err := r.Stat(p); err == nil {
				return candidateOutcome{Files: []candidateFile{{Role: roleInstalled, Name: "installed", Path: p}}}, nil
			}
		}
		return candidateOutcome{}, fmt.Errorf("apk installed: not found")

	case evidence.DBKindDistroless:
		names, dirTruncated, err := r.ReadDir("var/lib/dpkg/status.d")
		if err != nil {
			return candidateOutcome{}, fmt.Errorf("read distroless status.d: %w", err)
		}
		var out candidateOutcome
		out.Truncated = dirTruncated
		for _, name := range names {
			if len(out.Files) >= limits.MaxFiles {
				out.Truncated = true
				break
			}
			role := roleControl
			pkgName := name
			if strings.HasSuffix(name, ".md5sums") {
				role = roleMD5Sums
				pkgName = strings.TrimSuffix(name, ".md5sums")
			}
			out.Files = append(out.Files, candidateFile{Role: role, Name: name, Path: "var/lib/dpkg/status.d/" + name, PkgName: pkgName})
		}
		if len(out.Files) == 0 {
			return candidateOutcome{}, fmt.Errorf("distroless status.d has no entries")
		}
		return out, nil

	default:
		return candidateOutcome{}, fmt.Errorf("dbbuild: unsupported db kind %q", kind)
	}
}
