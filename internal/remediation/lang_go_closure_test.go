package remediation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goModHash is checked against the go.sum of this repository, which records
// the hash of the go.mod of each version it uses, with go.mod files the go
// command downloaded (copies in testdata/update/go).
func TestGoModHashMatchesGoSum(t *testing.T) {
	sum, err := os.ReadFile(filepath.Join("..", "..", "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	lines, err := parseGoSumLines(sum)
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{}
	for _, l := range lines {
		recorded[l.key()] = l.hash
	}
	for _, f := range []struct{ file, path, version string }{
		{"go-cmp-v0.7.0.mod", "github.com/google/go-cmp", "v0.7.0"},
		{"ebpf-v0.22.0.mod", "github.com/cilium/ebpf", "v0.22.0"},
	} {
		data, err := os.ReadFile(filepath.Join("testdata", "update", "go", f.file))
		if err != nil {
			t.Fatal(err)
		}
		want, ok := recorded[f.path+" "+f.version+"/go.mod"]
		if !ok {
			t.Fatalf("go.sum has no go.mod line for %s %s", f.path, f.version)
		}
		if got := goModHash(data); got != want {
			t.Errorf("goModHash(%s) = %s, go.sum records %s", f.file, got, want)
		}
		// Any change to the file changes the hash.
		if goModHash(append(data, '\n')) == want {
			t.Errorf("goModHash(%s) does not depend on the content", f.file)
		}
	}
}

// goChange is the comparison of two go.mod files.
func goChange(t *testing.T, before, after string) *goModChange {
	t.Helper()
	ch, err := diffGoMod(mustGoMod(t, before), mustGoMod(t, after))
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	return ch
}

func goGraphOf(t *testing.T, reg GoModuleRegistry, cache *goModCache, sum string) *goModGraph {
	t.Helper()
	if cache == nil {
		cache = newGoModCache()
	}
	g, err := newGoModGraph(bg, reg, cache, []byte(sum))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

const (
	pNet  = "golang.org/x/net"
	pText = "golang.org/x/text"
	pErr  = "github.com/pkg/errors"
)

// netWorld is a registry with x/net 0.20.0 and 0.23.0, which requires a newer
// x/text.
func netWorld() *fakeGoReg {
	return newFakeGoReg().
		mod(pNet, "v0.20.0", goModText(pNet, "1.18", pText+" v0.14.0")).
		mod(pNet, "v0.23.0", goModText(pNet, "1.18", pText+" v0.15.0")).
		mod(pText, "v0.14.0", goModText(pText, "1.18")).
		mod(pText, "v0.15.0", goModText(pText, "1.18")).
		mod(pText, "v0.16.0", goModText(pText, "1.18")).
		mod(pErr, "v0.9.1", goModText(pErr, "")).
		mod(pErr, "v0.9.2", goModText(pErr, "1.13"))
}

func appMod(reqs ...string) string { return goModText("example.com/app", "1.22", reqs...) }

func TestExplainGoMoves(t *testing.T) {
	before := appMod(pNet+" v0.20.0", pText+" v0.14.0 // indirect", pErr+" v0.9.1 // indirect")
	targets := map[string]string{pNet: "v0.23.0"}
	explain := func(t *testing.T, reg *fakeGoReg, after, sum string) (string, error) {
		t.Helper()
		return explainGoMoves(goGraphOf(t, reg, nil, sum), goChange(t, before, after), targets)
	}

	t.Run("a collateral move the target requires is allowed", func(t *testing.T) {
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pErr+" v0.9.1 // indirect")
		if why, err := explain(t, netWorld(), after, ""); err != nil || why != "" {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a collateral move above what the target requires is not explained", func(t *testing.T) {
		// A requirement explains a move up to the version it asks for, no
		// further.
		after := appMod(pNet+" v0.23.0", pText+" v0.16.0 // indirect", pErr+" v0.9.1 // indirect")
		why, err := explain(t, netWorld(), after, "")
		if err != nil || !strings.Contains(why, pText+" v0.16.0") {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a move the targets do not explain is refused", func(t *testing.T) {
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pErr+" v0.9.2 // indirect")
		why, err := explain(t, netWorld(), after, "")
		if err != nil || !strings.Contains(why, pErr+" v0.9.2") || strings.Contains(why, pText) {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a move below what the target requires is refused as a written version too low", func(t *testing.T) {
		// x/net 0.23.0 requires x/text 0.15.0; x/text written at 0.14.5 is
		// below that.
		reg := netWorld().mod(pText, "v0.14.5", goModText(pText, "1.18"))
		before := appMod(pNet+" v0.20.0", pText+" v0.14.0 // indirect")
		after := appMod(pNet+" v0.23.0", pText+" v0.14.5 // indirect")
		why, err := explainGoMoves(goGraphOf(t, reg, nil, ""), goChange(t, before, after), targets)
		if err != nil || !strings.Contains(why, "requires "+pText+" v0.15.0") {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("the walk starts from the version asked for", func(t *testing.T) {
		// The target staying where it was is caught by the check of the
		// versions; the requirements followed are those of v0.23.0.
		after := appMod(pNet+" v0.20.0", pText+" v0.15.0 // indirect", pErr+" v0.9.1 // indirect")
		if why, err := explain(t, netWorld(), after, ""); err != nil || why != "" {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a target past the version asked for is not explained by itself", func(t *testing.T) {
		// The output writes x/net 0.24.0, whose go.mod requires x/text
		// 0.16.0; neither move is explained by x/net 0.23.0.
		reg := netWorld().mod(pNet, "v0.24.0", goModText(pNet, "1.18", pText+" v0.16.0"))
		after := appMod(pNet+" v0.24.0", pText+" v0.16.0 // indirect", pErr+" v0.9.1 // indirect")
		why, err := explain(t, reg, after, "")
		if err != nil || !strings.Contains(why, pNet+" v0.24.0") || !strings.Contains(why, pText+" v0.16.0") {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a move explained through a moved module is allowed", func(t *testing.T) {
		const pTools = "golang.org/x/tools"
		reg := netWorld().
			mod(pText, "v0.15.0", goModText(pText, "1.18", pTools+" v0.2.0")).
			mod(pTools, "v0.1.0", goModText(pTools, "1.18")).
			mod(pTools, "v0.2.0", goModText(pTools, "1.18"))
		before := appMod(pNet+" v0.20.0", pText+" v0.14.0 // indirect", pTools+" v0.1.0 // indirect")
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pTools+" v0.2.0 // indirect")
		if why, err := explainGoMoves(goGraphOf(t, reg, nil, ""), goChange(t, before, after), targets); err != nil || why != "" {
			t.Errorf("why = %q, err = %v", why, err)
		}
		// The same moves without the link from x/text to x/tools.
		reg.mod(pText, "v0.15.0", goModText(pText, "1.18"))
		why, err := explainGoMoves(goGraphOf(t, reg, newGoModCache(), ""), goChange(t, before, after), targets)
		if err != nil || !strings.Contains(why, pTools) {
			t.Errorf("without the link: why = %q, err = %v", why, err)
		}
	})
	t.Run("moves that require each other but are not reached from a target are refused", func(t *testing.T) {
		const a, b = "example.com/a", "example.com/b"
		reg := netWorld().
			mod(a, "v1.0.0", goModText(a, "1.18")).
			mod(a, "v1.1.0", goModText(a, "1.18", b+" v1.1.0")).
			mod(b, "v1.0.0", goModText(b, "1.18")).
			mod(b, "v1.1.0", goModText(b, "1.18", a+" v1.1.0"))
		before := appMod(pNet+" v0.20.0", pText+" v0.14.0 // indirect", a+" v1.0.0", b+" v1.0.0")
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", a+" v1.1.0", b+" v1.1.0")
		why, err := explainGoMoves(goGraphOf(t, reg, nil, ""), goChange(t, before, after), targets)
		if err != nil || !strings.Contains(why, a) || !strings.Contains(why, b) {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a requirement of the version asked for holds in the result", func(t *testing.T) {
		// The target asked for is A@v1.1.0, which requires B@v1.9.0. The
		// output writes B@v1.5.0, which requires A@v1.2.0, and A@v1.2.0.
		// Each move would be explained by a requirement at or above it, but
		// B@v1.5.0 is no version a requirement asks for: A@v1.1.0's
		// requirement of B is not met.
		const a, b = "example.com/a", "example.com/b"
		reg := newFakeGoReg().
			mod(a, "v1.0.0", goModText(a, "1.18")).
			mod(a, "v1.1.0", goModText(a, "1.18", b+" v1.9.0")).
			mod(a, "v1.2.0", goModText(a, "1.18", b+" v1.0.0")).
			mod(b, "v1.0.0", goModText(b, "1.18")).
			mod(b, "v1.5.0", goModText(b, "1.18", a+" v1.2.0")).
			mod(b, "v1.9.0", goModText(b, "1.18"))
		before := appMod(a+" v1.0.0", b+" v1.0.0")
		after := appMod(a+" v1.2.0", b+" v1.5.0")
		why, err := explainGoMoves(goGraphOf(t, reg, nil, ""), goChange(t, before, after), map[string]string{a: "v1.1.0"})
		if err != nil || !strings.Contains(why, a+"@v1.1.0 requires "+b+" v1.9.0") {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a written version below a requirement of a new version is refused", func(t *testing.T) {
		// x/net 0.23.0 requires x/text 0.15.0, but x/text stays at 0.14.0.
		after := appMod(pNet+" v0.23.0", pText+" v0.14.0 // indirect", pErr+" v0.9.1 // indirect")
		why, err := explain(t, netWorld(), after, "")
		if err != nil || !strings.Contains(why, "requires "+pText+" v0.15.0") || !strings.Contains(why, "writes v0.14.0") {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a requirement of a module that did not move is not held against the written version", func(t *testing.T) {
		// errors v0.9.1 does not move; what it requires is not checked.
		reg := netWorld().mod(pErr, "v0.9.1", goModText(pErr, "1.13", pText+" v0.16.0"))
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pErr+" v0.9.1 // indirect")
		if why, err := explain(t, reg, after, ""); err != nil || why != "" {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a requirement on a module that is not written is not checked against a version", func(t *testing.T) {
		reg := netWorld().mod(pNet, "v0.23.0", goModText(pNet, "1.18", pText+" v0.15.0", "example.com/unwritten v9.0.0"))
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pErr+" v0.9.1 // indirect")
		if why, err := explain(t, reg, after, ""); err != nil || why != "" {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a go.mod the proxy made up is refused", func(t *testing.T) {
		reg := netWorld().mod(pNet, "v0.23.0", "module "+pNet+"\n")
		after := appMod(pNet+" v0.23.0", pText+" v0.14.0 // indirect", pErr+" v0.9.1 // indirect")
		why, err := explain(t, reg, after, "")
		if err != nil || !strings.Contains(why, "no go.mod of its own") {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a go.mod with only a go line is not made up", func(t *testing.T) {
		reg := netWorld().mod(pNet, "v0.23.0", goModText(pNet, "1.18"))
		after := appMod(pNet+" v0.23.0", pText+" v0.14.0 // indirect", pErr+" v0.9.1 // indirect")
		if why, err := explain(t, reg, after, ""); err != nil || why != "" {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("a made-up go.mod of a collateral module is refused too", func(t *testing.T) {
		reg := netWorld().mod(pText, "v0.15.0", "module "+pText+"\n")
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pErr+" v0.9.1 // indirect")
		why, err := explain(t, reg, after, "")
		if err != nil || !strings.Contains(why, pText) || !strings.Contains(why, "no go.mod of its own") {
			t.Errorf("why = %q, err = %v", why, err)
		}
	})
	t.Run("the go.mod the proxy serves must have the hash go.sum records", func(t *testing.T) {
		reg := netWorld()
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pErr+" v0.9.1 // indirect")
		good := reg.modLine(pNet, "v0.23.0") + reg.modLine(pText, "v0.15.0")
		if why, err := explain(t, reg, after, good); err != nil || why != "" {
			t.Fatalf("with the right hashes: why = %q, err = %v", why, err)
		}
		bad := pNet + " v0.23.0/go.mod " + fakeH1("forged") + "\n" + reg.modLine(pText, "v0.15.0")
		_, err := explain(t, netWorld(), after, bad)
		if err == nil || !strings.Contains(err.Error(), "hash go.sum records") {
			t.Errorf("a forged hash of the target: err = %v", err)
		}
		bad = reg.modLine(pNet, "v0.23.0") + pText + " v0.15.0/go.mod " + fakeH1("forged") + "\n"
		if _, err := explain(t, netWorld(), after, bad); err == nil {
			t.Error("a forged hash of a collateral module was accepted")
		}
		// A zip line is not a go.mod line.
		zipOnly := pNet + " v0.23.0 " + fakeH1("whatever") + "\n"
		if why, err := explain(t, netWorld(), after, zipOnly); err != nil || why != "" {
			t.Errorf("a zip line was compared with the go.mod: why = %q, err = %v", why, err)
		}
	})
	t.Run("a go.mod of another module, or one that is not readable, is an error", func(t *testing.T) {
		after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect", pErr+" v0.9.1 // indirect")
		reg := netWorld().mod(pNet, "v0.23.0", goModText("example.com/other", "1.18", pText+" v0.15.0"))
		if _, err := explain(t, reg, after, ""); err == nil || !strings.Contains(err.Error(), "declares the module") {
			t.Errorf("another module: %v", err)
		}
		reg = netWorld().mod(pNet, "v0.23.0", "module (\n")
		if _, err := explain(t, reg, after, ""); err == nil {
			t.Error("an unreadable go.mod was accepted")
		}
		reg = newFakeGoReg()
		if _, err := explain(t, reg, after, ""); !errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("a version the proxy lacks: %v", err)
		}
	})
}

func TestGoModGraphCache(t *testing.T) {
	reg := netWorld()
	cache := newGoModCache()
	before := appMod(pNet+" v0.20.0", pText+" v0.14.0 // indirect")
	after := appMod(pNet+" v0.23.0", pText+" v0.15.0 // indirect")
	targets := map[string]string{pNet: "v0.23.0"}
	for i := 0; i < 2; i++ {
		g := goGraphOf(t, reg, cache, "")
		if why, err := explainGoMoves(g, goChange(t, before, after), targets); err != nil || why != "" {
			t.Fatalf("pass %d: %q %v", i, why, err)
		}
		if _, err := g.requires(pText, "v0.15.0"); err != nil {
			t.Fatal(err)
		}
	}
	for k, n := range reg.gomodCalls {
		if n != 1 {
			t.Errorf("%s was fetched %d times", k, n)
		}
	}
	if reg.gomods == 0 {
		t.Error("nothing was fetched")
	}
	// A graph with a cache of its own reads again.
	g := goGraphOf(t, reg, newGoModCache(), "")
	if _, err := g.requires(pNet, "v0.23.0"); err != nil {
		t.Fatal(err)
	}
	if reg.gomodCalls[pNet+"@v0.23.0"] != 2 {
		t.Errorf("fetches of x/net = %d, want 2", reg.gomodCalls[pNet+"@v0.23.0"])
	}
	// The hash check applies to a cached entry as well: another go.sum, the
	// same cache.
	bad := pNet + " v0.23.0/go.mod " + fakeH1("forged") + "\n"
	if _, err := goGraphOf(t, reg, cache, bad).requires(pNet, "v0.23.0"); err == nil {
		t.Error("a cached go.mod was not checked against the hash of this go.sum")
	}
}

func goWorld(reg *fakeGoReg, path, version string, reqs ...string) *fakeGoReg {
	return reg.mod(path, version, goModText(path, "1.18", reqs...))
}

func TestGoModGraphFetchLimit(t *testing.T) {
	build := func(n int) *fakeGoReg {
		reg := newFakeGoReg()
		for i := 0; i < n; i++ {
			goWorld(reg, fmt.Sprintf("example.com/m%04d", i), "v1.0.0")
		}
		return reg
	}
	read := func(reg *fakeGoReg, n int) error {
		g := goGraphOf(t, reg, nil, "")
		for i := 0; i < n; i++ {
			if _, err := g.requires(fmt.Sprintf("example.com/m%04d", i), "v1.0.0"); err != nil {
				return err
			}
		}
		return nil
	}
	if err := read(build(maxGoModFetches), maxGoModFetches); err != nil {
		t.Errorf("at the limit: %v", err)
	}
	reg := build(maxGoModFetches + 1)
	if err := read(reg, maxGoModFetches+1); !errors.Is(err, errGoFetchLimit) {
		t.Errorf("over the limit: %v", err)
	}
	if reg.gomods > maxGoModFetches {
		t.Errorf("%d go.mod files were read past the limit of %d", reg.gomods, maxGoModFetches)
	}
	// Reading a version again is not a new fetch.
	g := goGraphOf(t, build(3), nil, "")
	for i := 0; i < maxGoModFetches*2; i++ {
		if _, err := g.requires("example.com/m0000", "v1.0.0"); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
}
