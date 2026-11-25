package imagefs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mustExist(t *testing.T, v *View, p string) Resolved {
	t.Helper()
	r, ok := exists(t, v, p)
	if !ok {
		t.Fatalf("%s should exist", p)
	}
	return r
}

func mustNotExist(t *testing.T, v *View, p string) {
	t.Helper()
	if _, ok := exists(t, v, p); ok {
		t.Fatalf("%s should not exist", p)
	}
}

func TestOverlayWhiteout(t *testing.T) {
	v := overlayOf(t,
		[]fe{dir("a"), file("a/x", "1"), file("a/y", "1"), dir("b"), file("b/z", "1")},
		[]fe{wh("a", "x"), wh(".", "b")},
	)
	mustNotExist(t, v, "a/x")
	mustExist(t, v, "a/y")
	mustNotExist(t, v, "b")
	mustNotExist(t, v, "b/z")
}

// A whiteout hides what is below its layer; what the same layer adds stays,
// whichever comes first in the tar.
func TestOverlayDeletionsBeforeAdditionsInALayer(t *testing.T) {
	lower := []fe{dir("a"), file("a/old", "1"), file("f", "1")}
	for name, upper := range map[string][]fe{
		"whiteout first": {wh(".", "a"), dir("a"), file("a/new", "2")},
		"addition first": {dir("a"), file("a/new", "2"), wh(".", "a")},
		"file whiteout":  {file("f", "2"), wh(".", "f")},
	} {
		v := overlayOf(t, lower, upper)
		if name == "file whiteout" {
			mustExist(t, v, "f")
			continue
		}
		mustNotExist(t, v, "a/old")
		mustExist(t, v, "a/new")
	}
}

func TestOverlayOpaque(t *testing.T) {
	lower := []fe{dir("d"), file("d/a", "1"), dir("d/sub"), file("d/sub/b", "1"), dir("e"), file("e/keep", "1")}
	for name, upper := range map[string][]fe{
		"marker first": {dir("d"), opaque("d"), file("d/c", "2")},
		"marker last":  {dir("d"), file("d/c", "2"), opaque("d")},
	} {
		v := overlayOf(t, lower, upper)
		for _, gone := range []string{"d/a", "d/sub", "d/sub/b"} {
			if _, ok := exists(t, v, gone); ok {
				t.Errorf("%s: %s survived the opaque marker", name, gone)
			}
		}
		mustExist(t, v, "d/c") // added by the same layer
		mustExist(t, v, "e/keep")
	}
}

func TestOverlayTypeReplacement(t *testing.T) {
	// symlink -> empty directory
	v := overlayOf(t,
		[]fe{dir("lib"), file("lib/x", "1"), sym("jvm", "lib")},
		[]fe{dir("jvm")},
	)
	r := mustExist(t, v, "jvm")
	if r.Type != TypeDir {
		t.Errorf("jvm is %q, want a directory", r.Type)
	}
	mustNotExist(t, v, "jvm/x") // the link's target did not become the directory's content

	// directory -> symlink drops the children
	v = overlayOf(t,
		[]fe{dir("d"), file("d/x", "1")},
		[]fe{sym("d", "/elsewhere")},
	)
	if r := mustExist(t, v, "d"); r.Type != TypeSymlink {
		t.Errorf("d is %q", r.Type)
	}
	if rr, err := v.ResolvePath("d/x"); err != nil || rr.Exists {
		t.Errorf("d/x resolves to %+v %v, want nothing", rr, err)
	}

	// directory -> file
	v = overlayOf(t,
		[]fe{dir("d"), file("d/x", "1")},
		[]fe{file("d", "now a file")},
	)
	if r := mustExist(t, v, "d"); r.Type != TypeFile {
		t.Errorf("d is %q", r.Type)
	}
	mustNotExist(t, v, "d/x")

	// file -> directory, and directory over directory keeps the children
	v = overlayOf(t,
		[]fe{file("f", "1"), dir("d"), file("d/x", "1")},
		[]fe{dir("f"), file("f/y", "2"), dir("d"), file("d/z", "2")},
	)
	mustExist(t, v, "f/y")
	mustExist(t, v, "d/x")
	mustExist(t, v, "d/z")
}

func TestOverlayLaterLayerReplacesFile(t *testing.T) {
	v := overlayOf(t, []fe{file("etc/release", "old")}, []fe{file("etc/release", "new")})
	r := mustExist(t, v, "etc/release")
	if v.layers[r.node.layer] != digestOf([]byte{1}) || r.node.content != "new" {
		t.Errorf("layer %d", r.node.layer)
	}
}

func TestResolvePathSymlinks(t *testing.T) {
	v := overlayOf(t,
		[]fe{
			dir("usr"), dir("usr/lib"), dir("usr/lib/jvm"), dir("usr/lib/jvm/zulu21-ca-amd64"), dir("usr/lib/jvm/zulu21-ca-amd64/bin"),
			file("usr/lib/jvm/zulu21-ca-amd64/bin/java", "elf"),
			sym("usr/lib/jvm/zulu21", "zulu21-ca-amd64"),  // relative
			sym("usr/lib/jvm/abs", "/usr/lib/jvm/zulu21"), // absolute, through another link
			sym("usr/lib/jvm/up", "../jvm/zulu21/bin"),    // relative with ..
			dir("etc"), dir("etc/alternatives"),
			sym("etc/alternatives/java", "/usr/lib/jvm/zulu21/bin/java"),
			dir("usr/bin"), sym("usr/bin/java", "/etc/alternatives/java"),
			sym("bin", "usr/bin"),
			sym("loop1", "loop2"), sym("loop2", "loop1"),
			sym("out", "../../../etc"),
			sym("empty", ""),
		},
	)
	for p, want := range map[string]string{
		"/usr/lib/jvm/zulu21/bin/java": "usr/lib/jvm/zulu21-ca-amd64/bin/java",
		"usr/lib/jvm/abs/bin/java":     "usr/lib/jvm/zulu21-ca-amd64/bin/java",
		"usr/lib/jvm/up/java":          "usr/lib/jvm/zulu21-ca-amd64/bin/java",
		"bin/java":                     "usr/lib/jvm/zulu21-ca-amd64/bin/java", // alternatives chain
		"usr/lib/jvm/zulu21":           "usr/lib/jvm/zulu21-ca-amd64",
		"/":                            "",
	} {
		r, err := v.ResolvePath(p)
		if err != nil || !r.Exists || r.Path != want {
			t.Errorf("ResolvePath(%q) = %+v, %v; want %q", p, r, err, want)
		}
	}
	if r, err := v.Lstat("usr/lib/jvm/zulu21"); err != nil || r.Type != TypeSymlink || r.Path != "usr/lib/jvm/zulu21" {
		t.Errorf("Lstat of a link: %+v %v", r, err)
	}
	if _, err := v.ResolvePath("loop1"); !errors.Is(err, ErrSymlinkLoop) {
		t.Errorf("loop: %v", err)
	}
	if _, err := v.ResolvePath("out/passwd"); !errors.Is(err, ErrPathEscape) {
		t.Errorf("escape: %v", err)
	}
	if _, err := v.ResolvePath("empty"); !errors.Is(err, ErrBadLink) {
		t.Errorf("empty link: %v", err)
	}
	// A missing target is not an error; it just does not exist.
	r, err := v.ResolvePath("usr/lib/jvm/zulu21/bin/nothing")
	if err != nil || r.Exists || r.Path != "usr/lib/jvm/zulu21-ca-amd64/bin/nothing" {
		t.Errorf("missing: %+v %v", r, err)
	}
	// 41 links in a row is too many, 40 is fine.
	var chain []fe
	for i := 0; i < 41; i++ {
		chain = append(chain, sym("l"+string(rune('A'+i)), "l"+string(rune('A'+i+1))))
	}
	chain = append(chain, file("l"+string(rune('A'+41)), "end"))
	v = overlayOf(t, chain)
	if _, err := v.ResolvePath("lA"); !errors.Is(err, ErrSymlinkLoop) {
		t.Errorf("41 hops: %v", err)
	}
	if r, err := v.ResolvePath("lB"); err != nil || !r.Exists {
		t.Errorf("40 hops: %+v %v", r, err)
	}
}

func TestOverlayRejectsOtherSummaryVersion(t *testing.T) {
	ref := summarize(t, tarOf(t, file("a", "x")))
	ref.Summary.Version = SummaryVersion + 1
	if _, err := Overlay([]LayerRef{ref}); !errors.Is(err, ErrSummaryVersion) {
		t.Errorf("err = %v", err)
	}
}

func manyEntries(n int) LayerRef {
	entries := make([]Entry, n)
	for i := range entries {
		entries[i] = Entry{Path: fmt.Sprintf("d%d", i), Type: TypeDir}
	}
	return LayerRef{DiffID: digestOf([]byte("many")), Summary: LayerSummary{Version: SummaryVersion, Entries: entries}}
}

func TestOverlayPathDepthLimit(t *testing.T) {
	deep := func(n int) LayerRef {
		return LayerRef{DiffID: digestOf([]byte("deep")), Summary: LayerSummary{Version: SummaryVersion,
			Entries: []Entry{{Path: strings.TrimSuffix(strings.Repeat("a/", n), "/"), Type: TypeFile}}}}
	}
	if _, err := Overlay([]LayerRef{deep(256)}); err != nil {
		t.Errorf("256 components: %v", err)
	}
	if _, err := Overlay([]LayerRef{deep(257)}); !errors.Is(err, ErrOverlayLimit) {
		t.Errorf("257 components: %v", err)
	}
}

func TestOverlayNodeLimitCountsImplicitParents(t *testing.T) {
	defer func(n int) { maxOverlayNodes = n }(maxOverlayNodes)
	maxOverlayNodes = 10
	one := LayerRef{DiffID: digestOf([]byte("one")), Summary: LayerSummary{Version: SummaryVersion,
		Entries: []Entry{{Path: "a/b/c/d/e/f/g/h/i/j/k", Type: TypeFile}}}} // 11 nodes, one entry
	if _, err := Overlay([]LayerRef{one}); !errors.Is(err, ErrOverlayLimit) {
		t.Errorf("one deep entry: %v", err)
	}
	// The count is of the tree as it stands: what a layer deletes is free.
	rm := LayerRef{DiffID: digestOf([]byte("rm")), Summary: LayerSummary{Version: SummaryVersion,
		Entries: []Entry{{Path: "a", Type: TypeWhiteout}}}}
	six := LayerRef{DiffID: digestOf([]byte("six")), Summary: LayerSummary{Version: SummaryVersion,
		Entries: []Entry{{Path: "a/b/c/d/e/f", Type: TypeFile}}}}
	if _, err := Overlay([]LayerRef{six, rm, six, rm, six}); err != nil {
		t.Errorf("churn within the limit: %v", err)
	}
	if _, err := Overlay([]LayerRef{manyEntries(11)}); !errors.Is(err, ErrOverlayLimit) {
		t.Errorf("11 directories: %v", err)
	}
}

func TestOverlayAndFindJDKsStopWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OverlayContext(ctx, []LayerRef{manyEntries(3000)}); !errors.Is(err, context.Canceled) {
		t.Errorf("overlay: %v", err)
	}
	v, err := Overlay([]LayerRef{manyEntries(3000)})
	if err != nil {
		t.Fatal(err)
	}
	if jdks, err := v.FindJDKsContext(ctx); !errors.Is(err, context.Canceled) || jdks != nil {
		t.Errorf("find: %+v %v", jdks, err)
	}
}

// A cycle of links with a long tail to resolve is refused by its size, not
// after the 40 hops have built a huge list.
func TestResolvePathBoundsItsExpansion(t *testing.T) {
	longTail := strings.Repeat("a/", 3000) + "z"
	v := overlayOf(t, []fe{
		sym("loop", "loop/"+strings.Repeat("b/", 1500)+"y"),
	})
	if _, err := v.ResolvePath("loop/" + longTail); !errors.Is(err, ErrPathTooLong) {
		t.Errorf("a long tail through a loop: %v", err)
	}
	// By the length of the path itself.
	if _, err := v.ResolvePath(strings.Repeat("x", maxResolvedPathBytes+1)); !errors.Is(err, ErrPathTooLong) {
		t.Errorf("a very long path: %v", err)
	}
	// By the count of components.
	if _, err := v.ResolvePath(strings.Repeat("a/", maxPendingComponents+1)); !errors.Is(err, ErrPathTooLong) {
		t.Errorf("too many components: %v", err)
	}
	// A short loop is still a loop.
	v = overlayOf(t, []fe{sym("l", "l")})
	if _, err := v.ResolvePath("l"); !errors.Is(err, ErrSymlinkLoop) {
		t.Errorf("loop: %v", err)
	}
	// Ordinary links resolve.
	v = overlayOf(t, []fe{dir("real"), file("real/f", "x"), sym("link", "real")})
	if r, err := v.ResolvePath("link/f"); err != nil || r.Path != "real/f" {
		t.Errorf("%+v %v", r, err)
	}
}
