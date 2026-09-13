package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInRootPlainPath(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "usr/sbin"))
	mustWriteFile(t, filepath.Join(root, "usr/sbin/nginx"), "x")

	got, err := resolveInRoot(root, "/usr/sbin/nginx")
	if err != nil {
		t.Fatalf("resolveInRoot: %v", err)
	}
	if got != "/usr/sbin/nginx" {
		t.Errorf("resolveInRoot = %q, want /usr/sbin/nginx", got)
	}
}

func TestResolveInRootMergedUsrSymlink(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "usr/lib"))
	mustWriteFile(t, filepath.Join(root, "usr/lib/libc.so.6"), "x")
	// /lib -> /usr/lib, the merged-/usr layout.
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}

	got, err := resolveInRoot(root, "/lib/libc.so.6")
	if err != nil {
		t.Fatalf("resolveInRoot: %v", err)
	}
	if got != "/usr/lib/libc.so.6" {
		t.Errorf("resolveInRoot = %q, want /usr/lib/libc.so.6 (merged-/usr collapsed)", got)
	}
}

func TestResolveInRootAbsoluteSymlinkStaysInRoot(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "real"))
	mustWriteFile(t, filepath.Join(root, "real/target"), "x")
	// An absolute symlink inside the container root pointing at "/real/target"
	// must resolve *within* root, never escape to the host's own "/real/target".
	if err := os.Symlink("/real/target", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	got, err := resolveInRoot(root, "/link")
	if err != nil {
		t.Fatalf("resolveInRoot: %v", err)
	}
	if got != "/real/target" {
		t.Errorf("resolveInRoot = %q, want /real/target (rebased under root)", got)
	}
	// Confirm this genuinely resolved under root, not the host filesystem:
	// there must be no host file at the absolute symlink target unrelated
	// to root (best-effort sanity: the resolved host path is under root).
	if hostPath := filepath.Join(root, got); filepath.Dir(hostPath) != filepath.Join(root, "real") {
		t.Errorf("resolved host path %q is not under root/real", hostPath)
	}
}

func TestResolveInRootDotDotClampedAtRoot(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "a"))
	mustWriteFile(t, filepath.Join(root, "escaped"), "x") // would only be reachable if ".." escaped root

	// "/../../escaped" from root must clamp at root, not escape to a
	// sibling of root on the host.
	got, err := resolveInRoot(root, "/a/../../escaped")
	if err != nil {
		t.Fatalf("resolveInRoot: %v", err)
	}
	if got != "/escaped" {
		t.Errorf("resolveInRoot = %q, want /escaped (.. clamped at root)", got)
	}
}

func TestResolveInRootDanglingFinalComponent(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "usr/sbin"))
	// nginx does not exist under usr/sbin: resolving a path to a file that
	// no longer exists (e.g. classifying a deleted path) must still
	// succeed for the final component.
	got, err := resolveInRoot(root, "/usr/sbin/nginx")
	if err != nil {
		t.Fatalf("resolveInRoot: %v", err)
	}
	if got != "/usr/sbin/nginx" {
		t.Errorf("resolveInRoot = %q, want /usr/sbin/nginx even though it doesn't exist", got)
	}
}

func TestResolveInRootMissingIntermediateComponent(t *testing.T) {
	root := t.TempDir()
	if _, err := resolveInRoot(root, "/no/such/dir/file"); err == nil {
		t.Fatal("expected an error when an intermediate path component doesn't exist")
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
