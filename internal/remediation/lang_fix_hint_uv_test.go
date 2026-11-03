package remediation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// hintPyPI is an index of package versions and the requires_dist of each.
type hintPyPI struct {
	versions map[string][]string // name -> versions offered
	requires map[string][]string // name==version -> requires_dist
	lookups  map[string]int      // name or name==version -> lookups
}

func (f *hintPyPI) Versions(ctx context.Context, name string) ([]string, int64, error) {
	f.count(name)
	vs, ok := f.versions[name]
	if !ok {
		return nil, 0, ErrReleaseNotFound
	}
	return vs, 100, nil
}

func (f *hintPyPI) Release(ctx context.Context, name, version string) (PyPIRelease, error) {
	f.count(name + "==" + version)
	rd, ok := f.requires[name+"=="+version]
	if !ok {
		return PyPIRelease{}, fmt.Errorf("%s %s: %w", name, version, ErrReleaseNotFound)
	}
	return PyPIRelease{RequiresDist: rd}, nil
}

func (f *hintPyPI) count(k string) {
	if f.lookups == nil {
		f.lookups = map[string]int{}
	}
	f.lookups[k]++
}

// urllib3Index is an index where requests 2.29.0 holds urllib3 below 1.27 and
// requests from 2.30.0 allow urllib3 2: the vulnerability is fixed in 1.26.19
// and 2.2.2.
func urllib3Index() *hintPyPI {
	return &hintPyPI{
		versions: map[string][]string{
			"requests": {"2.28.2", "2.29.0", "2.30.0", "2.32.3", "2.33.0rc1"},
			"urllib3":  {"1.26.18", "1.26.19", "2.2.1", "2.2.2", "2.3.0b1"},
		},
		requires: map[string][]string{
			"requests==2.32.3": {"charset-normalizer<4,>=2", "idna<4,>=2.5", "urllib3<3,>=1.21.1", "certifi>=2017.4.17", `PySocks!=1.5.7,>=1.5.6; extra == "socks"`},
		},
	}
}

// uvHintItem is a uv item with urllib3 held back by requests at version, which
// the project declares with spec ("" for a dependent it does not declare).
func uvHintItem(version, spec string) (*LanguageItem, updateSet, *chainScope, *ChainUpdate) {
	it := &LanguageItem{Manager: ManagerUv, Packages: []LanguagePackage{{CVEs: []CVERef{{VulnID: "CVE-2024-37891", FixedVers: []string{"1.26.19", "2.2.2"}}}}}}
	set := updateSet{byName: map[string][]int{"urllib3": {0}}}
	scope := &chainScope{directParents: map[string]bool{}}
	via := []string{"boto3"}
	if spec != "" {
		scope.Tops = []chainTop{{Name: "requests", Group: "project", Spec: spec}}
		scope.directParents["requests@"+version] = true
		via = []string{"requests"}
	}
	chain := &ChainUpdate{Outcome: ChainNotFixed, Blocked: []ChainBlock{{Package: "urllib3", Version: "1.26.18", Parent: "requests", ParentVersion: version, Range: "<1.27,>=1.21.1", Proof: proofUpperBound, Via: via}}}
	return it, set, scope, chain
}

func TestFixHints_Uv(t *testing.T) {
	idx := urllib3Index()
	u := &LangUpdater{cfg: LangUpdateConfig{PyPI: idx}}
	it, set, scope, chain := uvHintItem("2.29.0", ">=2.28")
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	want := []ChainHint{{
		Package: "urllib3", Parent: "requests", ParentVersion: "2.29.0", Via: []string{"requests"}, Direct: true, Spec: ">=2.28",
		InSpec: &ChainHintRelease{Version: "2.32.3", Range: "<3,>=1.21.1", Fixes: true},
	}}
	if !reflect.DeepEqual(chain.Hints, want) {
		t.Errorf("hints = %+v, want %+v", chain.Hints, want)
	}
	if idx.lookups["requests==2.33.0rc1"] != 0 {
		t.Errorf("a pre-release was read: %v", idx.lookups)
	}
}

// The project's range keeps requests below 2.30: the newest release it allows
// and the newest of all are both told. The range of 2.29.0 allows 1.26.19, the
// fix of the 1.26 line.
func TestFixHints_UvInSpecAndLatest(t *testing.T) {
	idx := urllib3Index()
	idx.requires["requests==2.29.0"] = []string{"urllib3<1.27,>=1.21.1"}
	u := &LangUpdater{cfg: LangUpdateConfig{PyPI: idx}}
	it, set, scope, chain := uvHintItem("2.28.2", "<2.30")
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 1 {
		t.Fatalf("hints = %+v", chain.Hints)
	}
	h := chain.Hints[0]
	if want := (&ChainHintRelease{Version: "2.29.0", Range: "<1.27,>=1.21.1", Fixes: true}); !reflect.DeepEqual(h.InSpec, want) {
		t.Errorf("in spec = %+v, want %+v", h.InSpec, want)
	}
	if want := (&ChainHintRelease{Version: "2.32.3", Range: "<3,>=1.21.1", Fixes: true}); !reflect.DeepEqual(h.Latest, want) {
		t.Errorf("latest = %+v, want %+v", h.Latest, want)
	}
}

// A requirement counts whatever its marker says; one package required with
// different specifiers, or a requirement that cannot be read, is not judged;
// no requirement at all reads as dropped; names compare in their PEP 503 form.
func TestFixHints_UvRequirements(t *testing.T) {
	cases := []struct {
		name     string
		requires []string
		want     *ChainHintRelease
	}{
		{"marker", []string{`urllib3<3,>=1.21.1; python_version >= "3.8"`}, &ChainHintRelease{Version: "2.32.3", Range: "<3,>=1.21.1", Fixes: true}},
		{"name form", []string{"URLLib3 (<3,>=1.21.1)"}, &ChainHintRelease{Version: "2.32.3", Range: "<3,>=1.21.1", Fixes: true}},
		{"no upper bound", []string{"urllib3"}, &ChainHintRelease{Version: "2.32.3", Fixes: true}},
		{"still below", []string{"urllib3<1.26.19"}, &ChainHintRelease{Version: "2.32.3", Range: "<1.26.19"}},
		{"dropped", []string{"idna<4"}, &ChainHintRelease{Version: "2.32.3", Dropped: true}},
		{"different specifiers", []string{`urllib3<1.27; python_version < "3.10"`, `urllib3<3; python_version >= "3.10"`}, nil},
		{"unreadable", []string{"urllib3 @ https://example.com/urllib3.whl"}, nil},
		{"unevaluable", []string{"urllib3===2.2.2"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx := urllib3Index()
			idx.requires["requests==2.32.3"] = c.requires
			u := &LangUpdater{cfg: LangUpdateConfig{PyPI: idx}}
			it, set, scope, chain := uvHintItem("2.29.0", "")
			u.fixHints(context.Background(), it, set, scope, nil, chain)
			var got *ChainHintRelease
			if len(chain.Hints) == 1 {
				got = chain.Hints[0].Latest
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("latest = %+v, want %+v (hints %+v)", got, c.want, chain.Hints)
			}
		})
	}
}

// An index client that cannot list versions gives no hints.
func TestFixHints_UvWithoutVersions(t *testing.T) {
	u := &LangUpdater{cfg: LangUpdateConfig{PyPI: releasesOnly{}}}
	it, set, scope, chain := uvHintItem("2.29.0", ">=2.28")
	u.fixHints(context.Background(), it, set, scope, nil, chain)
	if len(chain.Hints) != 0 {
		t.Errorf("hints = %+v", chain.Hints)
	}
}

type releasesOnly struct{}

func (releasesOnly) Release(ctx context.Context, name, version string) (PyPIRelease, error) {
	return PyPIRelease{}, errors.New("not used")
}

func TestPyPIClientVersions(t *testing.T) {
	doc := `{"info":{"name":"urllib3","version":"2.2.2"},"last_serial":1,
"releases":{
 "1.26.18":[{"filename":"a.whl","yanked":false}],
 "2.0.0":[{"filename":"b.whl","yanked":true},{"filename":"b.tar.gz","yanked":true}],
 "2.1.0":[],
 "2.2.1":[{"filename":"c.whl","yanked":true},{"filename":"c.tar.gz","yanked":false}],
 "2.2.2":[{"filename":"d.whl"}]
},
"urls":[],"vulnerabilities":[]}`
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if strings.Contains(r.URL.Path, "missing") {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, doc)
	}))
	defer srv.Close()
	c := &PyPIClient{HTTP: srv.Client(), BaseURL: srv.URL}
	got, n, err := c.Versions(context.Background(), "URLLib3")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1.26.18", "2.2.1", "2.2.2"}; !reflect.DeepEqual(got, want) || n == 0 || path != "/pypi/urllib3/json" {
		t.Errorf("versions = %v (%d bytes, %s), want %v", got, n, path, want)
	}
	if _, _, err := c.Versions(context.Background(), "missing"); !errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("missing: %v", err)
	}
	for _, bad := range []string{`[]`, `{"info":{}}`, `{"releases":[]}`, `{"releases":{"1.0":{}}}`} {
		if _, err := readPyPIVersions(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

// versionedPyPI is a fakePyPI that also lists versions.
type versionedPyPI struct {
	*fakePyPI
	versions map[string][]string
}

func (v versionedPyPI) Versions(ctx context.Context, name string) ([]string, int64, error) {
	vs, ok := v.versions[name]
	if !ok {
		return nil, 0, ErrReleaseNotFound
	}
	return vs, 0, nil
}

// A uv chain update the item settles with records the hints: a, which the
// project declares >=1,<2, requires t ==1.0.0 at 1.0.0 and t >=1.2 at 1.1.0.
func TestUvChainRecordsHints(t *testing.T) {
	var after string
	h, _, a := uvChainHarnessWith(t, true, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"uv.lock": []byte(after)}}}
	})
	after = a
	h.cfg.PyPI = versionedPyPI{h.pypi, map[string][]string{"a": {"1.0.0", "1.1.0", "2.0.0a1"}, "t": {"1.0.0", "1.2.0"}}}
	it := h.runUv()
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainRejected {
		t.Fatalf("chain = %+v", c)
	}
	want := []ChainHint{{Package: "t", Parent: "a", ParentVersion: "1.0.0", Via: []string{"a"}, Direct: true, Spec: ">=1,<2",
		InSpec: &ChainHintRelease{Version: "1.1.0", Range: ">=1.2", Fixes: true}}}
	if !reflect.DeepEqual(c.Hints, want) {
		t.Errorf("hints = %+v, want %+v", c.Hints, want)
	}
}

// A document cut short after a release, or inside the releases, is not a list.
func TestReadPyPIVersionsCutShort(t *testing.T) {
	for _, doc := range []string{
		`{"releases":{"1.0":[{"yanked":false}]`,
		`{"releases":{"1.0":[{"yanked":false}],`,
		`{"releases":{"1.0":[{"yanked":false}`,
	} {
		if vs, err := readPyPIVersions(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: %v, no error", doc, vs)
		}
	}
}

// Python versions are ordered with their epochs, post-releases count as
// releases, and pre- and dev-releases are left out.
func TestFixHints_UvVersionOrder(t *testing.T) {
	l := &hintLookup{ctx: context.Background(), sc: schemePEP440, rels: map[string][]string{},
		src: &pyHints{vers: &hintPyPI{versions: map[string][]string{"p": {"2.0.0", "2.0.0.post1", "2.1.0.dev1", "2.1.0rc1", "1!0.1", "10.0"}}}}}
	got, ok := l.releases("p")
	if want := []string{"1!0.1", "10.0", "2.0.0.post1", "2.0.0"}; !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("releases = %v, want %v", got, want)
	}
}

// A direct dependency declared without a range allows every release, and the
// documents the item's runs read are not read again.
func TestFixHints_UvNoRangeAndCache(t *testing.T) {
	idx := urllib3Index()
	u := &LangUpdater{cfg: LangUpdateConfig{PyPI: idx}}
	it, set, scope, chain := uvHintItem("2.29.0", "")
	scope.Tops = []chainTop{{Name: "requests", Group: "project"}}
	scope.directParents["requests@2.29.0"] = true
	sh := newItemShared()
	sh.cache.py["requests==2.32.3"] = PyPIRelease{RequiresDist: []string{"urllib3<3,>=1.21.1"}}
	idx.requires = map[string][]string{}
	u.fixHints(context.Background(), it, set, scope, sh, chain)
	want := []ChainHint{{Package: "urllib3", Parent: "requests", ParentVersion: "2.29.0", Via: []string{"boto3"}, Direct: true,
		InSpec: &ChainHintRelease{Version: "2.32.3", Range: "<3,>=1.21.1", Fixes: true}}}
	if !reflect.DeepEqual(chain.Hints, want) || idx.lookups["requests==2.32.3"] != 0 {
		t.Errorf("hints = %+v, lookups = %v", chain.Hints, idx.lookups)
	}
}

// uvNoSolution is what uv prints when the project's ranges let no version of
// the dependents reach the fixed version, with a hint after the reason.
const uvNoSolution = `  × No solution found when resolving dependencies:
  ╰─▶ Because only the following versions of a are available:
          a<=1.0.0
          a>=2.0.0
      and your project depends on a>=1,<2, we can conclude that your project's requirements are unsatisfiable.

      hint: Pre-releases are available for a in the requested range (e.g., 2.0.0a1), but pre-releases weren't selected.
`

// A uv chain job that finds no resolution is the update not reaching the fix
// within the project's ranges: the item records it as not fixed, with hints;
// any other failure of the update step stays a failure.
func TestUvChainWithNoResolutionIsNotFixed(t *testing.T) {
	run := func(stderr string) LanguageItem {
		h, _, _ := uvChainHarness(t, func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
			return fakeOutcome{failStep: "update", failReason: "exit", stderr: map[string]string{"update": stderr}}
		})
		h.pypi.requires["a==2.0.0"] = []string{"t>=1.2"}
		h.cfg.PyPI = versionedPyPI{h.pypi, map[string][]string{"a": {"1.0.0", "1.1.0", "2.0.0"}, "t": {"1.0.0", "1.2.0"}}}
		h.pypi.requires["a==1.1.0"] = []string{"t==1.0.0"}
		return h.runUv()
	}
	it := run(uvNoSolution)
	c := it.Update.Chain
	if c == nil || c.Outcome != ChainNotFixed || c.Reason != ReasonNoResolution || !strings.Contains(c.Detail, "exited with 1") {
		t.Fatalf("chain = %+v", c)
	}
	if p := packageOf(t, it, "t"); p.Reason != ReasonDependentsNotFixed {
		t.Errorf("t = %+v", p)
	}
	want := []ChainHint{{Package: "t", Parent: "a", ParentVersion: "1.0.0", Via: []string{"a"}, Direct: true, Spec: ">=1,<2",
		InSpec: &ChainHintRelease{Version: "1.1.0", Range: "==1.0.0"},
		Latest: &ChainHintRelease{Version: "2.0.0", Range: ">=1.2", Fixes: true}}}
	if !reflect.DeepEqual(c.Hints, want) {
		t.Errorf("hints = %+v, want %+v", c.Hints, want)
	}

	other := run("error: Failed to fetch: `https://pypi.org/simple/a/`\n  Caused by: connection reset\n")
	if c := other.Update.Chain; c == nil || c.Outcome != ChainFailed || len(c.Hints) != 0 {
		t.Errorf("another failure: chain = %+v", c)
	}
}

func TestUvUnsatisfiable(t *testing.T) {
	for out, want := range map[string]bool{
		uvNoSolution: true,
		"  ╰─▶ ... we can conclude that the requirements are unsatisfiable.\n": true,
		"error: Failed to fetch": false,
		"":                       false,
	} {
		if got := uvUnsatisfiable(out); got != want {
			t.Errorf("uvUnsatisfiable(%q) = %v, want %v", out, got, want)
		}
	}
}
