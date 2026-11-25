package imagefs

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// maxSymlinkHops is how many symbolic links one path resolution follows.
const maxSymlinkHops = 40

// Bounds on what one path resolution expands to: the total length of the
// path and of the links followed, and the components still to resolve.
const (
	maxResolvedPathBytes = 64 << 10
	maxPendingComponents = 4096
)

// Bounds on the stacked filesystem: a path may have at most maxPathDepth
// components and the whole tree at most maxOverlayNodes nodes (the implicit
// parent directories of a path included). A layer within its own entry limit
// can still ask for far more nodes through deep paths, so the stack has limits
// of its own.
//
// They are variables so that a test can lower them.
var (
	maxPathDepth    = 256
	maxOverlayNodes = 2_000_000
)

// ctxCheckEvery is how many entries or directories are handled between two
// looks at the context.
const ctxCheckEvery = 1024

var (
	// ErrSummaryVersion: a layer summary has another format version.
	ErrSummaryVersion = errors.New("imagefs: layer summary of another version")
	// ErrSymlinkLoop: a path passes more than 40 symbolic links.
	ErrSymlinkLoop = errors.New("imagefs: too many symbolic links")
	// ErrPathEscape: a path leaves the image root.
	ErrPathEscape = errors.New("imagefs: path leaves the image root")
	// ErrOverlayLimit: the stacked layers pass the depth or the node limit.
	ErrOverlayLimit = errors.New("imagefs: the image filesystem passes the depth or node limit")
	// ErrPathTooLong: resolving a path grew it past the length or the count of
	// components allowed; the path is unresolvable.
	ErrPathTooLong = errors.New("imagefs: path grows too long while its links are resolved")
	// ErrBadLink: a symbolic link with no target.
	ErrBadLink = errors.New("imagefs: symbolic link without a target")
)

type node struct {
	typ        string
	link       string
	content    string
	hasContent bool
	big        bool
	unreadable bool
	layer      int // index into View.layers
	kids       map[string]*node
}

// View is the filesystem of an image after all its layers are applied.
type View struct {
	root   *node
	layers []string // diffID per layer index
	nodes  int      // nodes in the tree, the root excluded
}

// LayerRef is a layer summary together with the diffID that names it.
type LayerRef struct {
	DiffID  string
	Summary LayerSummary
}

// Overlay stacks the layers, bottom first, under the OCI rules. For each
// layer the deletions it makes in the layers below are applied first, and its
// own additions after: a whiteout removes its target, an opaque marker removes
// everything below it in a directory, and an entry that differs in kind from
// what lies below it (a symbolic link where a directory was, a file where a
// directory was, a directory where a link was) replaces the old path
// entirely, children included. Entries a layer adds are never removed by that
// layer's own whiteouts or markers.
func Overlay(layers []LayerRef) (*View, error) {
	return OverlayContext(context.Background(), layers)
}

// OverlayContext is Overlay that stops with the context's error when ctx
// ends, and with ErrOverlayLimit when a path is deeper than 256 components or
// the tree would hold more than 2,000,000 nodes.
func OverlayContext(ctx context.Context, layers []LayerRef) (*View, error) {
	v := &View{root: &node{typ: TypeDir}}
	handled := 0
	for i, l := range layers {
		if l.Summary.Version != SummaryVersion {
			return nil, fmt.Errorf("%w: %d", ErrSummaryVersion, l.Summary.Version)
		}
		v.layers = append(v.layers, l.DiffID)
		for _, e := range l.Summary.Entries {
			if handled++; handled%ctxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if strings.Count(e.Path, "/")+1 > maxPathDepth {
				return nil, fmt.Errorf("%w: a path has more than %d components", ErrOverlayLimit, maxPathDepth)
			}
			switch e.Type {
			case TypeWhiteout:
				v.remove(e.Path)
			case TypeOpaque:
				if n := v.lookup(e.Path); n != nil && n.typ == TypeDir {
					v.nodes -= countKids(n)
					n.kids = nil
				}
			default:
				if n := v.lookup(e.Path); n != nil && (n.typ != TypeDir || e.Type != TypeDir) {
					v.remove(e.Path)
				}
			}
		}
		for _, e := range l.Summary.Entries {
			if e.Type == TypeWhiteout || e.Type == TypeOpaque {
				continue
			}
			if handled++; handled%ctxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if err := v.add(e, i); err != nil {
				return nil, err
			}
		}
	}
	return v, nil
}

// countKids is the number of nodes below n.
func countKids(n *node) int {
	c := 0
	for _, k := range n.kids {
		c += 1 + countKids(k)
	}
	return c
}

func split(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// lookup finds the node at the literal path p of the tree, nil if none.
func (v *View) lookup(p string) *node {
	n := v.root
	for _, c := range split(p) {
		if n.typ != TypeDir {
			return nil
		}
		n = n.kids[c]
		if n == nil {
			return nil
		}
	}
	return n
}

func (v *View) remove(p string) {
	if p == "" {
		return
	}
	parent := v.lookup(path.Dir(p))
	if path.Dir(p) == "." {
		parent = v.root
	}
	if parent != nil && parent.typ == TypeDir {
		name := path.Base(p)
		if old := parent.kids[name]; old != nil {
			v.nodes -= 1 + countKids(old)
			delete(parent.kids, name)
		}
	}
}

// add puts entry e of layer i into the tree. Missing parent directories are
// made implicitly; an entry below a parent that is not a directory is dropped.
func (v *View) add(e Entry, i int) error {
	comps := split(e.Path)
	if len(comps) == 0 {
		return nil
	}
	cur := v.root
	for _, c := range comps[:len(comps)-1] {
		child := cur.kids[c]
		if child == nil {
			if err := v.grow(1); err != nil {
				return err
			}
			child = &node{typ: TypeDir, layer: i}
			if cur.kids == nil {
				cur.kids = map[string]*node{}
			}
			cur.kids[c] = child
		}
		if child.typ != TypeDir {
			return nil
		}
		cur = child
	}
	last := comps[len(comps)-1]
	old := cur.kids[last]
	if old != nil && old.typ == TypeDir && e.Type == TypeDir {
		return nil // the directory stays, with what it holds
	}
	if old != nil {
		v.nodes -= 1 + countKids(old)
	}
	if err := v.grow(1); err != nil {
		return err
	}
	if cur.kids == nil {
		cur.kids = map[string]*node{}
	}
	cur.kids[last] = &node{
		typ: e.Type, link: e.Link, content: e.Content, hasContent: e.HasContent,
		big: e.Big, unreadable: e.Unreadable, layer: i,
	}
	return nil
}

// grow counts n new nodes against the limit.
func (v *View) grow(n int) error {
	if v.nodes += n; v.nodes > maxOverlayNodes {
		return fmt.Errorf("%w: more than %d nodes", ErrOverlayLimit, maxOverlayNodes)
	}
	return nil
}

// Resolved is the result of resolving a path inside the image.
type Resolved struct {
	// Path is the real path, without a leading "/". When Exists is false it
	// is the path as far as it could be followed, with the rest appended.
	Path string
	// Type is the entry type (the Type constants) of the final element; ""
	// when it does not exist.
	Type   string
	Exists bool

	node *node
}

// ResolvePath resolves p inside the image root, following every symbolic
// link, the last element too. Absolute links start at the root and relative
// ones at the directory that holds the link. More than 40 links, a loop, or a
// path that goes above the root is an error.
func (v *View) ResolvePath(p string) (Resolved, error) { return v.resolve(p, true) }

// Lstat is ResolvePath that leaves the last element alone when it is a
// symbolic link.
func (v *View) Lstat(p string) (Resolved, error) { return v.resolve(p, false) }

func (v *View) resolve(p string, followLast bool) (Resolved, error) {
	stack := []*node{v.root}
	var real []string
	todo := split(p)
	hops := 0
	expanded := len(p)
	if expanded > maxResolvedPathBytes || len(todo) > maxPendingComponents {
		return Resolved{}, fmt.Errorf("%w", ErrPathTooLong)
	}
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(real) == 0 {
				return Resolved{}, fmt.Errorf("%w: %s", ErrPathEscape, p)
			}
			real = real[:len(real)-1]
			stack = stack[:len(stack)-1]
			continue
		}
		cur := stack[len(stack)-1]
		var child *node
		if cur.typ == TypeDir {
			child = cur.kids[c]
		}
		if child == nil {
			rest := path.Join(append(append(append([]string{}, real...), c), todo...)...)
			return Resolved{Path: NormalizePath(rest)}, nil
		}
		if child.typ == TypeSymlink && (followLast || remaining(todo)) {
			if hops++; hops > maxSymlinkHops {
				return Resolved{}, fmt.Errorf("%w: %s", ErrSymlinkLoop, p)
			}
			if child.link == "" {
				return Resolved{}, fmt.Errorf("%w: %s", ErrBadLink, strings.Join(append(append([]string{}, real...), c), "/"))
			}
			// Bounded before the link is split and joined to what is left.
			if expanded += len(child.link) + 1; expanded > maxResolvedPathBytes || len(todo)+strings.Count(child.link, "/")+1 > maxPendingComponents {
				return Resolved{}, fmt.Errorf("%w", ErrPathTooLong)
			}
			if strings.HasPrefix(child.link, "/") {
				stack, real = stack[:1], nil
			}
			todo = append(split(child.link), todo...)
			continue
		}
		real = append(real, c)
		stack = append(stack, child)
	}
	n := stack[len(stack)-1]
	return Resolved{Path: strings.Join(real, "/"), Type: n.typ, Exists: true, node: n}, nil
}

// remaining reports whether any path element is left to resolve.
func remaining(todo []string) bool {
	for _, c := range todo {
		if c != "" && c != "." {
			return true
		}
	}
	return false
}

// childNames returns the names under n in sorted order.
func (n *node) childNames() []string {
	names := make([]string, 0, len(n.kids))
	for k := range n.kids {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// resolveHome resolves the JAVA_HOME value of an image's environment inside
// the image: the real path of the directory it names, without a leading "/".
// It is "" when home is empty, relative, or not a directory of the image.
func (v *View) resolveHome(home string) string {
	if home == "" || len(home) > 4096 || !path.IsAbs(home) || strings.ContainsRune(home, 0) {
		return ""
	}
	r, err := v.ResolvePath(home)
	if err != nil || !r.Exists || r.Type != TypeDir {
		return ""
	}
	return r.Path
}
