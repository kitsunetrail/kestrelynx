package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxSymlinkExpansions bounds symlink-following during resolveInRoot, the
// same defense a real path-resolution loop needs against a symlink cycle.
const maxSymlinkExpansions = 40

// resolveInRoot resolves target (an absolute or relative path as observed
// inside a container, e.g. a /proc/<pid>/maps pathname) against root (a
// container rootfs reached via /proc/<pid>/root), confining every step to
// root: an absolute symlink inside the container is rebased under root
// rather than escaping to the host's own "/", and a ".." component can
// never climb above root. It is reimplemented here in pure Go (component
// by component, following symlinks by hand) because openat2's
// RESOLVE_IN_ROOT has no wrapper in the standard library and this harness
// adds no dependencies.
//
// What it does not provide is RESOLVE_IN_ROOT's atomicity, and the
// difference is stronger than a wrong answer. openat2 resolves inside the
// kernel against a fixed root, so a directory swapped mid-resolution
// cannot redirect it. This implementation lstats and readlinks one
// component at a time and then hands the finished string to a caller that
// opens or stats it separately, through an ordinary path that follows
// whatever symlinks exist at that moment. A container that replaces one of
// its own directories with a symlink between the resolution and the use
// can therefore make the caller read a file outside the container's root:
// the confinement here is textual, applied to the path being built, not
// enforced on the file the kernel finally opens.
//
// This is sound for what it is used for and nothing else. The observed
// containers are the harness's own cooperative fixtures, which do not
// rewrite their directory tree while a sample is being taken, and the one
// judgement drawn from a resolution failure is to record it. It is not a
// sandbox, and a collector pointed at containers that are not trusted to
// leave their own filesystem alone during a sample needs openat2's
// RESOLVE_IN_ROOT rather than this.
//
// The return value is the resolved path relative to root, always beginning
// with "/" (root itself resolves to "/"). A path that cannot be resolved
// (a dangling symlink, a component that isn't a directory, too many
// symlink expansions) is reported via err rather than guessed at. The same
// function normalizes the paths recorded in a package database (see
// dbPathNormalizer), so the observed side and the database side are
// brought into one representation by one rule.
func resolveInRoot(root, target string) (resolved string, err error) {
	// Component queue still to be consumed. The target's own components are
	// pushed first; a symlink's components are spliced in front of it as
	// they're encountered, so the queue always reflects "what remains to be
	// resolved" in the right order.
	queue := splitPath(target)
	var out []string
	expansions := 0

	for len(queue) > 0 {
		comp := queue[0]
		queue = queue[1:]

		switch comp {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			// ".." above root is clamped to root, never an error and never
			// escapes: this is exactly RESOLVE_IN_ROOT's behavior.
			continue
		}

		candidateRel := "/" + strings.Join(append(append([]string{}, out...), comp), "/")
		hostPath := filepath.Join(root, candidateRel)

		fi, statErr := os.Lstat(hostPath)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				// The component itself doesn't exist. If it's the final
				// component, that alone isn't a resolution failure (the
				// caller may be resolving a path that no longer exists,
				// e.g. to classify it as "deleted"): report the path as
				// resolved with the component appended. If it's an
				// intermediate component, the path truly cannot be
				// resolved.
				if len(queue) == 0 {
					out = append(out, comp)
					return "/" + strings.Join(out, "/"), nil
				}
				return "", fmt.Errorf("resolve %q under %q: %q does not exist", target, root, candidateRel)
			}
			return "", fmt.Errorf("resolve %q under %q: lstat %q: %w", target, root, candidateRel, statErr)
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			out = append(out, comp)
			continue
		}

		expansions++
		if expansions > maxSymlinkExpansions {
			return "", fmt.Errorf("resolve %q under %q: too many symlink expansions (possible cycle)", target, root)
		}
		linkTarget, rlErr := os.Readlink(hostPath)
		if rlErr != nil {
			return "", fmt.Errorf("resolve %q under %q: readlink %q: %w", target, root, candidateRel, rlErr)
		}
		linkComps := splitPath(linkTarget)
		if filepath.IsAbs(linkTarget) {
			// An absolute symlink is rebased under root, never resolved
			// against the host's own "/" — the defining property this
			// function exists to provide.
			out = nil
			queue = append(linkComps, queue...)
		} else {
			// A relative symlink is resolved against its own containing
			// directory, i.e. "out" as it stands (the symlink's own final
			// component is not part of that directory).
			queue = append(linkComps, queue...)
		}
	}

	if len(out) == 0 {
		return "/", nil
	}
	return "/" + strings.Join(out, "/"), nil
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// devIno is the (device, inode) pair used to tell whether an observed
// mapping and the file currently on disk are the same file ("dev/inode
// scoped to same-file detection only" — see match_metrics.go's use: an
// agreement is never treated as proof of package identity by itself, only
// as evidence that a path has or hasn't been replaced since it was
// observed).
type devIno struct {
	Dev   string
	Inode string
}

// statDevIno stats hostPath (a path already resolved under some root, e.g.
// via resolveInRoot) and returns its current (dev, inode) in the same
// "MM:mm" / decimal-string form procfs uses, so it can be compared directly
// against a maps line's recorded dev/inode.
func statDevIno(hostPath string) (devIno, error) {
	fi, err := os.Stat(hostPath)
	if err != nil {
		return devIno{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return devIno{}, fmt.Errorf("stat %q: unsupported Sys() type", hostPath)
	}
	major := (st.Dev >> 8) & 0xfff
	minor := (st.Dev & 0xff) | ((st.Dev >> 12) & 0xfff00)
	return devIno{
		Dev:   fmt.Sprintf("%02x:%02x", major, minor),
		Inode: fmt.Sprintf("%d", st.Ino),
	}, nil
}

// calibrateInodes picks a maps entry believed not to change after the
// container starts (a shared library whose basename contains "libc", the
// most reliably-present unchanged file across every test case here) and
// compares its recorded maps dev/inode against a fresh stat through root.
// Agreement calibrates dev/inode comparison as trustworthy for this
// container; disagreement, or no candidate found at all, leaves it
// uncalibrated, so path_inode_changed is never evaluated on unverified
// ground (OverlayFS may present stat results that don't match what maps
// recorded, independent of any real file replacement).
func calibrateInodes(root string, candidates []MapEntry) InodeCalibration {
	for _, m := range candidates {
		if m.Deleted || !strings.Contains(m.Path, "libc") {
			continue
		}
		resolved, err := resolveInRoot(root, m.Path)
		if err != nil {
			continue
		}
		cur, err := statDevIno(filepath.Join(root, resolved))
		if err != nil {
			continue
		}
		return InodeCalibration{
			Calibrated:      cur.Dev == m.Dev && cur.Inode == m.Inode,
			CalibrationPath: m.Path,
			MapsDev:         m.Dev, MapsInode: m.Inode,
			StatDev: cur.Dev, StatInode: cur.Inode,
		}
	}
	return InodeCalibration{Calibrated: false, Error: "no unchanged-file candidate (e.g. libc) found among observed mappings"}
}
