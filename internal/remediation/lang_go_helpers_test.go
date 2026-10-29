package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
)

// fakeH1 is a hash in the h1: form that depends on s only.
func fakeH1(s string) string {
	h := sha256.Sum256([]byte(s))
	return "h1:" + base64.StdEncoding.EncodeToString(h[:])
}

// goModText writes a go.mod: the module, the go line (none when empty) and
// the requirements, each as "path version" or "path version // indirect".
func goModText(module, goLine string, reqs ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "module %s\n", module)
	if goLine != "" {
		fmt.Fprintf(&b, "\ngo %s\n", goLine)
	}
	if len(reqs) > 0 {
		b.WriteString("\nrequire (\n")
		for _, r := range reqs {
			fmt.Fprintf(&b, "\t%s\n", r)
		}
		b.WriteString(")\n")
	}
	return b.String()
}

// fakeGoReg is a Go module proxy and checksum database that serves the
// go.mod files it is given.
type fakeGoReg struct {
	mu sync.Mutex
	// mods are the go.mod files by "path@version"; a version without one is
	// unknown to the proxy.
	mods map[string]string
	// latest are the versions @latest answers, by path.
	latest map[string]string
	// reported replaces the version Info answers with, by "path@version".
	reported map[string]string
	// sums replaces the hashes of the checksum database, by "path@version";
	// noSums lists the versions it has no record of.
	sums   map[string]GoSums
	noSums map[string]bool
	// err is returned by every request when set.
	err error

	infos, gomods, latests, sumCalls int
	gomodCalls                       map[string]int
	sumKeys                          []string
}

func newFakeGoReg() *fakeGoReg {
	return &fakeGoReg{mods: map[string]string{}, latest: map[string]string{}, reported: map[string]string{},
		sums: map[string]GoSums{}, noSums: map[string]bool{}, gomodCalls: map[string]int{}}
}

// mod registers the go.mod of path@version and returns the registry.
func (f *fakeGoReg) mod(path, version, text string) *fakeGoReg {
	f.mods[path+"@"+version] = text
	return f
}

func (f *fakeGoReg) Info(_ context.Context, path, version string) (GoInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.infos++
	if f.err != nil {
		return GoInfo{}, f.err
	}
	k := path + "@" + version
	if _, ok := f.mods[k]; !ok {
		return GoInfo{}, ErrReleaseNotFound
	}
	if v, ok := f.reported[k]; ok {
		version = v
	}
	return GoInfo{Version: version}, nil
}

func (f *fakeGoReg) GoMod(_ context.Context, path, version string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gomods++
	k := path + "@" + version
	f.gomodCalls[k]++
	if f.err != nil {
		return nil, f.err
	}
	m, ok := f.mods[k]
	if !ok {
		return nil, ErrReleaseNotFound
	}
	return []byte(m), nil
}

func (f *fakeGoReg) Latest(_ context.Context, path string) (GoInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latests++
	if f.err != nil {
		return GoInfo{}, f.err
	}
	v, ok := f.latest[path]
	if !ok {
		return GoInfo{}, ErrReleaseNotFound
	}
	return GoInfo{Version: v}, nil
}

// zipHash and modHash are the hashes the fake database records for a
// version: the go.mod hash is the real one of the go.mod the proxy serves.
func (f *fakeGoReg) zipHash(path, version string) string {
	return fakeH1("zip " + path + "@" + version)
}

func (f *fakeGoReg) modHash(path, version string) string {
	if m, ok := f.mods[path+"@"+version]; ok {
		return goModHash([]byte(m))
	}
	return fakeH1("mod " + path + "@" + version)
}

func (f *fakeGoReg) Sums(_ context.Context, path, version string) (GoSums, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sumCalls++
	k := path + "@" + version
	f.sumKeys = append(f.sumKeys, k)
	if f.err != nil {
		return GoSums{}, f.err
	}
	if f.noSums[k] {
		return GoSums{}, ErrReleaseNotFound
	}
	if s, ok := f.sums[k]; ok {
		return s, nil
	}
	return GoSums{Zip: f.zipHash(path, version), Mod: f.modHash(path, version)}, nil
}

// sumLines writes the two go.sum lines of a version as the fake database
// records them.
func (f *fakeGoReg) sumLines(path, version string) string {
	return path + " " + version + " " + f.zipHash(path, version) + "\n" +
		path + " " + version + "/go.mod " + f.modHash(path, version) + "\n"
}

// modLine writes only the go.mod line of a version.
func (f *fakeGoReg) modLine(path, version string) string {
	return path + " " + version + "/go.mod " + f.modHash(path, version) + "\n"
}
