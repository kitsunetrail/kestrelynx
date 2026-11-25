package imagefs

import (
	"context"
	"errors"
	"path"
	"sort"
	"strings"
)

// ErrReleaseUnreadable: a hardlinked "release" of a JDK has a content this
// package cannot read (the link points to something that is not a small file
// named "release" of the same layer). It is permanent for the image.
var ErrReleaseUnreadable = errors.New("imagefs: the content of a hardlinked release cannot be read")

// ErrTooManyJDKs: the image holds more Java runtimes than maxJDKs. No partial
// list is returned.
var ErrTooManyJDKs = errors.New("imagefs: the image holds too many Java runtimes")

// maxJDKs bounds the Java runtimes read from one image; it is a variable so
// that a test can lower it.
var maxJDKs = 16

// Executable is a java launcher of a JDK.
type Executable struct {
	// Declared is where the launcher is by the JDK's own layout, for example
	// "opt/java/openjdk/bin/java".
	Declared string `json:"declared"`
	// Path is Declared with every symbolic link resolved inside the image,
	// without a leading "/". Known is false when it cannot be resolved (a
	// loop, a link out of the root, a missing target); Path is then "".
	Path  string `json:"path,omitempty"`
	Known bool   `json:"known"`
}

// JDK is a Java runtime found in an image.
type JDK struct {
	// Dir is the directory that holds the release file, without a leading
	// "/". It is a real path: no part of it is a symbolic link.
	Dir string `json:"dir"`
	// Release is the release file's content.
	Release string `json:"release"`
	// Executables are Dir's bin/java and jre/bin/java, those that exist.
	Executables []Executable `json:"executables,omitempty"`
	// LayerDiffID is the layer that last wrote the release file, the module
	// image (lib/modules, or rt.jar), the launcher and the JVM libraries, when
	// they all come from one layer. It is "" otherwise, and MixedLayers says so.
	LayerDiffID string `json:"layer_diff_id,omitempty"`
	MixedLayers bool   `json:"mixed_layers,omitempty"`
}

// FindJDKs returns the Java runtimes of the view, ordered by directory. A
// JDK is a directory whose release file is a regular file with a
// JAVA_VERSION= line and which holds the module image of that Java series:
// lib/modules for Java 9 and later, lib/rt.jar or jre/lib/rt.jar for Java 8
// and earlier.
//
// A hardlinked release file whose content is unreadable makes the result an
// ErrReleaseUnreadable when its directory holds the files of a JDK.
func (v *View) FindJDKs() ([]JDK, error) { return v.FindJDKsContext(context.Background()) }

// FindJDKsContext is FindJDKs that stops with the context's error when ctx
// ends; no partial list is returned then.
func (v *View) FindJDKsContext(ctx context.Context) ([]JDK, error) {
	var out []JDK
	var firstErr error
	visited := 0
	var walk func(n *node, dir string) error
	walk = func(n *node, dir string) error {
		if visited++; visited%ctxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		for _, name := range n.childNames() {
			c := n.kids[name]
			if c.typ == TypeDir {
				if err := walk(c, path.Join(dir, name)); err != nil {
					return err
				}
				continue
			}
			if name != "release" || (c.typ != TypeFile && c.typ != TypeHardlink) {
				continue
			}
			jdk, ok, err := v.jdkAt(dir, c)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if ok {
				if out = append(out, jdk); len(out) > maxJDKs {
					return ErrTooManyJDKs
				}
			}
		}
		return nil
	}
	if err := walk(v.root, ""); err != nil {
		return nil, err
	}
	if firstErr != nil {
		return nil, firstErr
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
}

// maxReleaseLine bounds one line of a release file; a longer one is ignored.
const maxReleaseLine = 64 << 10

// ReleaseValue returns the value of the key in the KEY="value" lines of a
// release file. A line is trimmed and split at its first "="; a value in
// double quotes loses them; the last assignment of a key wins; blank lines,
// lines that are not assignments and lines over 64 KiB are ignored. It is the
// one rule by which the release file's version is read, here and when the
// release is checked against advisories.
func ReleaseValue(content, key string) (string, bool) {
	val, found := "", false
	for _, line := range strings.Split(content, "\n") {
		if len(line) > maxReleaseLine {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		val, found = v, true
	}
	return val, found
}

// javaVersionOf returns the JAVA_VERSION value of a release file.
func javaVersionOf(content string) (string, bool) { return ReleaseValue(content, "JAVA_VERSION") }

// hasJavaVersion reports whether a release file has a JAVA_VERSION= line.
func hasJavaVersion(content string) bool {
	_, ok := javaVersionOf(content)
	return ok
}

// javaMajor is the series of a JAVA_VERSION value: 8 for "1.8.0_514", 21 for
// "21.0.13.1". ok is false when it cannot be told.
func javaMajor(version string) (major int, ok bool) {
	rest := version
	if r, found := strings.CutPrefix(rest, "1."); found {
		rest = r
	}
	n := 0
	digits := 0
	for _, c := range rest {
		if c < '0' || c > '9' || digits >= 4 {
			break
		}
		n = n*10 + int(c-'0')
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	return n, true
}

func (v *View) isFile(p string) (*node, bool) {
	r, err := v.ResolvePath(p)
	if err != nil || !r.Exists || (r.Type != TypeFile && r.Type != TypeHardlink) {
		return nil, false
	}
	return r.node, true
}

// markers are the module image files of a JDK, by series: Java 9 and later
// have lib/modules, Java 8 and earlier lib/rt.jar (jre/lib/rt.jar for a JDK
// that holds its JRE in a subdirectory).
var (
	modernMarkers = []string{"lib/modules"}
	legacyMarkers = []string{"lib/rt.jar", "jre/lib/rt.jar"}
)

// marker returns the first of the markers that is a file of dir.
func (v *View) marker(dir string, names []string) (string, bool) {
	for _, m := range names {
		p := path.Join(dir, m)
		if _, ok := v.isFile(p); ok {
			return p, true
		}
	}
	return "", false
}

// addLayers adds the layer that wrote the entry at p and the layer that wrote
// what it resolves to (the same for a regular file). It is false when either
// cannot be determined.
func (v *View) addLayers(p string, layers map[int]bool) bool {
	st, err := v.Lstat(p)
	if err != nil || !st.Exists {
		return false
	}
	layers[st.node.layer] = true
	r, err := v.ResolvePath(p)
	if err != nil || !r.Exists {
		return false
	}
	layers[r.node.layer] = true
	return true
}

func (v *View) jdkAt(dir string, rel *node) (JDK, bool, error) {
	if rel.big {
		return JDK{}, false, nil
	}
	if rel.unreadable || !rel.hasContent {
		// The series is not known; any module image makes it a JDK's release.
		if _, ok := v.marker(dir, modernMarkers); !ok {
			if _, ok := v.marker(dir, legacyMarkers); !ok {
				return JDK{}, false, nil
			}
		}
		if rel.typ == TypeHardlink {
			return JDK{}, false, ErrReleaseUnreadable
		}
		return JDK{}, false, nil
	}
	version, ok := javaVersionOf(rel.content)
	if !ok {
		return JDK{}, false, nil
	}
	var markerPath string
	if major, known := javaMajor(version); !known {
		// A version that does not say its series: either kind of module image.
		if markerPath, ok = v.marker(dir, modernMarkers); !ok {
			markerPath, ok = v.marker(dir, legacyMarkers)
		}
	} else if major >= 9 {
		markerPath, ok = v.marker(dir, modernMarkers)
	} else {
		markerPath, ok = v.marker(dir, legacyMarkers)
	}
	if !ok {
		return JDK{}, false, nil
	}
	jdk := JDK{Dir: dir, Release: rel.content}
	layers := map[int]bool{rel.layer: true}
	determined := v.addLayers(markerPath, layers)
	for _, exe := range []string{"bin/java", "jre/bin/java"} {
		declared := path.Join(dir, exe)
		st, err := v.Lstat(declared)
		if err != nil || !st.Exists {
			continue
		}
		ex := Executable{Declared: declared}
		if r, err := v.ResolvePath(declared); err == nil && r.Exists {
			ex.Path, ex.Known = r.Path, true
		}
		jdk.Executables = append(jdk.Executables, ex)
		if !v.addLayers(declared, layers) {
			determined = false
		}
	}
	for _, lib := range []string{"lib", "jre/lib"} {
		if r, err := v.Lstat(path.Join(dir, lib)); err == nil && r.Exists && r.Type == TypeDir {
			if !v.collectJVM(r.node, r.Path, 0, layers) {
				determined = false
			}
		}
	}
	if len(layers) == 1 && determined {
		for l := range layers {
			jdk.LayerDiffID = v.layers[l]
		}
	} else {
		jdk.MixedLayers = true
	}
	return jdk, true, nil
}

// collectJVM adds the layers of every server/libjvm.so under n (at path p),
// to a depth of three directories. It is false when one of them cannot be
// determined.
func (v *View) collectJVM(n *node, p string, depth int, layers map[int]bool) bool {
	if depth > 3 {
		return true
	}
	ok := true
	for name, c := range n.kids {
		if c.typ != TypeDir {
			continue
		}
		cp := path.Join(p, name)
		if name == "server" {
			if so := c.kids["libjvm.so"]; so != nil && !v.addLayers(path.Join(cp, "libjvm.so"), layers) {
				ok = false
			}
		}
		if !v.collectJVM(c, cp, depth+1, layers) {
			ok = false
		}
	}
	return ok
}
