package remediation

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

// rootTreeReader is the part of a source reader that gives the tree SHA of
// the root of a commit.
type rootTreeReader interface {
	RootTree(ctx context.Context, repo, sha string) (string, error)
}

var (
	_ rootTreeReader  = (*github.Client)(nil)
	_ directoryLister = (*github.Client)(nil)
)

// errNoRootTree says a source cannot give the tree of a commit's root.
var errNoRootTree = errors.New("the source cannot give the tree SHA of the repository root")

// dirTreeSHA is the SHA of the git tree of the directory dir ("." for the
// root) at the commit sha. A directory other than the root takes it from the
// listing of its parent, where it is an entry; the root takes it from the
// commit. A directory that is not there, or is another kind of entry, is an
// error that wraps github.ErrNotFound or github.ErrNotDirectory.
func dirTreeSHA(ctx context.Context, src directoryLister, repo, sha, dir string) (string, error) {
	if dir == "" || dir == "." {
		rt, ok := src.(rootTreeReader)
		if !ok {
			return "", errNoRootTree
		}
		tree, err := rt.RootTree(ctx, repo, sha)
		if err != nil {
			return "", err
		}
		if !isSHA(tree) {
			return "", fmt.Errorf("the tree SHA %q of the repository root is malformed", tree)
		}
		return tree, nil
	}
	parent := path.Dir(dir)
	es, err := src.ListDirectory(ctx, repo, sha, parent)
	if err != nil {
		return "", err
	}
	e, ok := byName(es, path.Base(dir))
	switch {
	case !ok:
		return "", fmt.Errorf("%w: %s", github.ErrNotFound, dir)
	case e.Type != github.EntryDir:
		return "", fmt.Errorf("%w: %s is a %s", github.ErrNotDirectory, dir, e.Type)
	case !isSHA(e.SHA):
		return "", fmt.Errorf("the listing of %s gives no tree SHA for %s", parent, e.Name)
	}
	return e.SHA, nil
}

// sameTrees reports whether two lists name the same directories with the same
// tree SHAs, in any order.
func sameTrees(a, b []SourceTree) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]SourceTree(nil), a...), append([]SourceTree(nil), b...)
	for _, s := range [][]SourceTree{a, b} {
		s := s
		sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
