package remediation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type relayFakeRegistry struct {
	mu    sync.Mutex
	poms  map[string]string // group:artifact:version -> pom
	errs  map[string]error
	calls []string
}

func (f *relayFakeRegistry) Versions(context.Context, string, string) ([]string, error) {
	return nil, errors.New("not used")
}

func (f *relayFakeRegistry) POM(_ context.Context, g, a, v string) ([]byte, error) {
	k := g + ":" + a + ":" + v
	f.mu.Lock()
	f.calls = append(f.calls, k)
	f.mu.Unlock()
	if err := f.errs[k]; err != nil {
		return nil, err
	}
	if s, ok := f.poms[k]; ok {
		return []byte(s), nil
	}
	return nil, ErrReleaseNotFound
}

func relayPOM(g, a, v, body string) string {
	return `<project><groupId>` + g + `</groupId><artifactId>` + a + `</artifactId><version>` + v + `</version>` + body + `</project>`
}

func relayGet(t *testing.T, r *mavenRelay, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, strings.TrimSuffix(r.URL(), "/maven2")+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func newRelayForTest(t *testing.T, reg MavenRegistry, cache *mavenPOMCache, reactor map[string]string, max int) *mavenRelay {
	t.Helper()
	r, err := startMavenRelay(reg, cache, reactor, max)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func hasProblem(r *mavenRelay, sub string) bool {
	for _, p := range r.Problems() {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func TestMavenRelayServes(t *testing.T) {
	reg := &relayFakeRegistry{poms: map[string]string{
		"org.x:a:1.0": relayPOM("org.x", "a", "1.0", `<dependencies><dependency><groupId>org.y</groupId><artifactId>b</artifactId><version>2</version></dependency></dependencies>`),
		"org.x:b:1.0": relayPOM("org.x", "b", "1.0", ``),
	}}
	r := newRelayForTest(t, reg, newMavenPOMCache(), nil, 10)
	if !strings.HasPrefix(r.URL(), "http://127.0.0.1:") || !strings.HasSuffix(r.URL(), "/maven2") {
		t.Fatalf("URL = %s", r.URL())
	}
	code, body := relayGet(t, r, "GET", "/maven2/org/x/a/1.0/a-1.0.pom")
	if code != 200 || !strings.Contains(body, "<artifactId>a</artifactId>") {
		t.Fatalf("%d %s", code, body)
	}
	relayGet(t, r, "GET", "/maven2/org/x/b/1.0/b-1.0.pom")
	relayGet(t, r, "GET", "/maven2/org/x/a/1.0/a-1.0.pom")
	if len(r.Problems()) != 0 {
		t.Errorf("problems = %v", r.Problems())
	}
	f := r.Fetched()
	if len(f) != 2 || f[0].ArtifactID != "a" || f[1].ArtifactID != "b" {
		t.Errorf("fetched = %+v", f)
	}
}

func TestMavenRelayRefusals(t *testing.T) {
	reg := &relayFakeRegistry{poms: map[string]string{"org.x:a:1.0": relayPOM("org.x", "a", "1.0", "")}}
	for name, c := range map[string]struct{ method, path string }{
		"post":             {"POST", "/maven2/org/x/a/1.0/a-1.0.pom"},
		"head":             {"HEAD", "/maven2/org/x/a/1.0/a-1.0.pom"},
		"jar":              {"GET", "/maven2/org/x/a/1.0/a-1.0.jar"},
		"metadata":         {"GET", "/maven2/org/x/a/maven-metadata.xml"},
		"sha1":             {"GET", "/maven2/org/x/a/1.0/a-1.0.pom.sha1"},
		"other root":       {"GET", "/other/org/x/a/1.0/a-1.0.pom"},
		"short":            {"GET", "/maven2/a/1.0/a-1.0.pom"},
		"artifact differs": {"GET", "/maven2/org/x/a/1.0/b-1.0.pom"},
		"version differs":  {"GET", "/maven2/org/x/a/1.0/a-1.1.pom"},
		"dotdot":           {"GET", "/maven2/org/../a/1.0/a-1.0.pom"},
		"empty segment":    {"GET", "/maven2/org//x/a/1.0/a-1.0.pom"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRelayForTest(t, reg, newMavenPOMCache(), nil, 10)
			if code, _ := relayGet(t, r, c.method, c.path); code != 404 {
				t.Errorf("status %d", code)
			}
			if len(r.Problems()) != 1 {
				t.Errorf("problems = %v", r.Problems())
			}
		})
	}
	if len(reg.calls) != 0 {
		t.Errorf("registry was asked: %v", reg.calls)
	}
}

func TestMavenRelayReactor(t *testing.T) {
	reg := &relayFakeRegistry{}
	r := newRelayForTest(t, reg, newMavenPOMCache(), map[string]string{"com.acme:core": "1.0-SNAPSHOT"}, 10)
	if code, _ := relayGet(t, r, "GET", "/maven2/com/acme/core/1.0-SNAPSHOT/core-1.0-SNAPSHOT.pom"); code != 404 {
		t.Errorf("status %d", code)
	}
	if len(r.Problems()) != 0 {
		t.Errorf("a request for a module at its version is a problem: %v", r.Problems())
	}
	if code, _ := relayGet(t, r, "GET", "/maven2/com/acme/core/2.0/core-2.0.pom"); code != 404 {
		t.Errorf("status %d", code)
	}
	if !hasProblem(r, "com.acme:core is requested at version 2.0") {
		t.Errorf("problems = %v", r.Problems())
	}
	if len(reg.calls) != 0 {
		t.Errorf("reactor coordinates left the host: %v", reg.calls)
	}
}

func TestMavenRelayFailures(t *testing.T) {
	reg := &relayFakeRegistry{
		poms: map[string]string{"org.x:a:1.0": relayPOM("org.x", "a", "1.0", "")},
		errs: map[string]error{"org.x:boom:1.0": errors.New("connection reset")},
	}
	r := newRelayForTest(t, reg, newMavenPOMCache(), nil, 10)
	if code, _ := relayGet(t, r, "GET", "/maven2/org/x/missing/1.0/missing-1.0.pom"); code != 404 {
		t.Errorf("status %d", code)
	}
	if code, _ := relayGet(t, r, "GET", "/maven2/org/x/boom/1.0/boom-1.0.pom"); code != 404 {
		t.Errorf("status %d", code)
	}
	if len(r.Problems()) != 2 || !hasProblem(r, "org.x:missing:1.0 was not found") || !hasProblem(r, "connection reset") {
		t.Errorf("problems = %v", r.Problems())
	}
	if len(r.Fetched()) != 0 {
		t.Errorf("fetched = %v", r.Fetched())
	}
}

func TestMavenRelayMaxRequests(t *testing.T) {
	reg := &relayFakeRegistry{poms: map[string]string{
		"org.x:a:1": relayPOM("org.x", "a", "1", ""),
		"org.x:b:1": relayPOM("org.x", "b", "1", ""),
	}}
	r := newRelayForTest(t, reg, newMavenPOMCache(), nil, 1)
	if code, _ := relayGet(t, r, "GET", "/maven2/org/x/a/1/a-1.pom"); code != 200 {
		t.Errorf("status %d", code)
	}
	if code, _ := relayGet(t, r, "GET", "/maven2/org/x/b/1/b-1.pom"); code != 404 {
		t.Errorf("status %d", code)
	}
	if !hasProblem(r, "more than 1 pom requests") || len(reg.calls) != 1 {
		t.Errorf("problems = %v, calls = %v", r.Problems(), reg.calls)
	}
}

func TestMavenRelayCacheKeepsProblems(t *testing.T) {
	bad := relayPOM("org.x", "a", "1.0", `<profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation><dependencies><dependency><groupId>g</groupId><artifactId>h</artifactId></dependency></dependencies></profile></profiles>`)
	reg := &relayFakeRegistry{
		poms: map[string]string{"org.x:a:1.0": bad},
		errs: map[string]error{"org.x:flaky:1": errors.New("timeout")},
	}
	cache := newMavenPOMCache()
	r1 := newRelayForTest(t, reg, cache, nil, 10)
	relayGet(t, r1, "GET", "/maven2/org/x/a/1.0/a-1.0.pom")
	relayGet(t, r1, "GET", "/maven2/org/x/missing/1/missing-1.pom")
	relayGet(t, r1, "GET", "/maven2/org/x/flaky/1/flaky-1.pom")
	if !hasProblem(r1, "profile") {
		t.Fatalf("problems = %v", r1.Problems())
	}
	reg.mu.Lock()
	reg.calls = nil
	reg.errs = nil
	reg.mu.Unlock()
	r2 := newRelayForTest(t, reg, cache, nil, 10)
	if code, body := relayGet(t, r2, "GET", "/maven2/org/x/a/1.0/a-1.0.pom"); code != 200 || body != bad {
		t.Errorf("%d %s", code, body)
	}
	relayGet(t, r2, "GET", "/maven2/org/x/missing/1/missing-1.pom")
	if !hasProblem(r2, "profile") || !hasProblem(r2, "missing:1 was not found") {
		t.Errorf("problems of the cached pom were lost: %v", r2.Problems())
	}
	if len(r2.Fetched()) != 1 {
		t.Errorf("fetched = %v", r2.Fetched())
	}
	// Only the failure that may pass is asked again.
	if strings.Join(reg.calls, ",") != "" {
		t.Errorf("registry asked again: %v", reg.calls)
	}
	relayGet(t, r2, "GET", "/maven2/org/x/flaky/1/flaky-1.pom")
	if strings.Join(reg.calls, ",") != "org.x:flaky:1" {
		t.Errorf("calls = %v", reg.calls)
	}
}

func TestMavenRelayChecks(t *testing.T) {
	dm := func(entries string) string {
		return `<dependencyManagement><dependencies>` + entries + `</dependencies></dependencyManagement>`
	}
	ent := func(g, a, extra string) string {
		return `<dependency><groupId>` + g + `</groupId><artifactId>` + a + `</artifactId><version>1</version>` + extra + `</dependency>`
	}
	cases := []struct {
		name, pom, want string // want "" means no problem
	}{
		{"clean", relayPOM("org.x", "a", "1.0", `<repositories><repository><id>c</id><url>https://repo.maven.apache.org/maven2/</url></repository><repository><id>d</id><url>https://repo1.maven.org/maven2</url></repository></repositories>`+dm(ent("g", "h", "")+ent("g", "h", "<classifier>x</classifier>"))), ""},
		{"not xml", `<project>`, "cannot be read"},
		{"wrong artifact", relayPOM("org.x", "other", "1.0", ""), "declares the coordinates org.x:other:1.0"},
		{"wrong version", relayPOM("org.x", "a", "2.0", ""), "declares the coordinates org.x:a:2.0"},
		{"wrong group", relayPOM("org.z", "a", "1.0", ""), "declares the coordinates org.z:a:1.0"},
		{"inherits group and version", `<project><parent><groupId>org.x</groupId><artifactId>p</artifactId><version>1.0</version></parent><artifactId>a</artifactId></project>`, ""},
		{"parent group but own version differs", `<project><parent><groupId>org.x</groupId><artifactId>p</artifactId><version>1.0</version></parent><artifactId>a</artifactId><version>3</version></project>`, "declares the coordinates org.x:a:3"},
		{"active profile adding a dependency", relayPOM("org.x", "a", "1.0", `<profiles><profile><id>p</id><activation><jdk>17</jdk></activation><dependencies><dependency><groupId>g</groupId></dependency></dependencies></profile></profiles>`), "profile"},
		{"active profile adding a test dependency", relayPOM("org.x", "a", "1.0", `<profiles><profile><id>p</id><activation><jdk>17</jdk></activation><dependencies><dependency><groupId>g</groupId><scope>test</scope></dependency></dependencies></profile></profiles>`), ""},
		{"profile without a condition", relayPOM("org.x", "a", "1.0", `<profiles><profile><id>release</id><dependencies><dependency><groupId>g</groupId></dependency></dependencies><repositories><repository><url>https://r</url></repository></repositories></profile></profiles>`), ""},
		{"active profile modules", relayPOM("org.x", "a", "1.0", `<profiles><profile><id>p</id><activation><activeByDefault>true</activeByDefault></activation><modules><module>m</module></modules></profile></profiles>`), "profile"},
		{"active profile repository", relayPOM("org.x", "a", "1.0", `<profiles><profile><id>p</id><activation><property><name>x</name></property></activation><repositories><repository><url>https://r</url></repository></repositories></profile></profiles>`), "profile"},
		{"active profile properties are judged with the other poms", relayPOM("org.x", "a", "1.0", `<profiles><profile><id>p</id><activation><jdk>17</jdk></activation><properties><a>b</a></properties></profile></profiles>`), ""},
		{"profile with only build", relayPOM("org.x", "a", "1.0", `<profiles><profile><id>p</id><build><finalName>x</finalName></build></profile></profiles>`), ""},
		{"snapshot repository", relayPOM("org.x", "a", "1.0", `<repositories><repository><id>s</id><url>https://oss.sonatype.org/content/repositories/snapshots</url><releases><enabled>false</enabled></releases></repository></repositories>`), ""},
		{"other repository", relayPOM("org.x", "a", "1.0", `<repositories><repository><id>r</id><url>https://jitpack.io</url></repository></repositories>`), "https://jitpack.io"},
		{"relocation", relayPOM("org.x", "a", "1.0", `<distributionManagement><relocation><groupId>n</groupId></relocation></distributionManagement>`), "is relocated"},
		{"range in dependencies", relayPOM("org.x", "a", "1.0", `<dependencies><dependency><groupId>g</groupId><artifactId>h</artifactId><version>[1.0,2.0)</version></dependency></dependencies>`), "version range"},
		{"range in management", relayPOM("org.x", "a", "1.0", dm(`<dependency><groupId>g</groupId><artifactId>h</artifactId><version>(,1.0]</version></dependency>`)), "version range"},
		{"duplicate management", relayPOM("org.x", "a", "1.0", dm(ent("g", "h", "")+ent("g", "h", "<type>jar</type>"))), "manages g:h:jar: more than once"},
		{"management optional is judged with the other poms", relayPOM("org.x", "a", "1.0", dm(ent("g", "h", "<optional>true</optional>"))), ""},
		{"management exclusions are judged with the other poms", relayPOM("org.x", "a", "1.0", dm(ent("g", "h", "<exclusions><exclusion><groupId>e</groupId><artifactId>f</artifactId></exclusion></exclusions>"))), ""},
		{"optional written as a property", relayPOM("org.x", "a", "1.0", `<dependencies><dependency><groupId>g</groupId><artifactId>h</artifactId><version>1</version><optional>${flag}</optional></dependency></dependencies>`), "cannot read"},
		{"optional written as 1", relayPOM("org.x", "a", "1.0", dm(ent("g", "h", "<optional>1</optional>"))), ""},
		{"dependency exclusions are fine", relayPOM("org.x", "a", "1.0", `<dependencies><dependency><groupId>g</groupId><artifactId>h</artifactId><version>1</version><optional>true</optional><exclusions><exclusion><groupId>e</groupId><artifactId>f</artifactId></exclusion></exclusions></dependency></dependencies>`), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := &relayFakeRegistry{poms: map[string]string{"org.x:a:1.0": c.pom}}
			r := newRelayForTest(t, reg, newMavenPOMCache(), nil, 10)
			code, body := relayGet(t, r, "GET", "/maven2/org/x/a/1.0/a-1.0.pom")
			if code != 200 || body != c.pom {
				t.Errorf("a pom with a problem is still served: %d", code)
			}
			if c.want == "" {
				if len(r.Problems()) != 0 {
					t.Errorf("problems = %v", r.Problems())
				}
				return
			}
			if !hasProblem(r, c.want) {
				t.Errorf("want %q in %v", c.want, r.Problems())
			}
		})
	}
}

func mustPOM(t *testing.T, s string) *mavenPOM {
	t.Helper()
	p, err := parseMavenPOM([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func aggDep(g, a, extra string) string {
	return `<dependency><groupId>` + g + `</groupId><artifactId>` + a + `</artifactId><version>1</version>` + extra + `</dependency>`
}

// child is a pom of g:child:1 whose parent is g:parent:1.
func child(body string) string {
	return `<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId>` + body + `</project>`
}

// noVer is a dependency without a version.
func noVer(g, a, extra string) string {
	return `<dependency><groupId>` + g + `</groupId><artifactId>` + a + `</artifactId>` + extra + `</dependency>`
}

func TestMavenAggregateProblems(t *testing.T) {
	deps := func(s string) string { return `<dependencies>` + s + `</dependencies>` }
	mgmt := func(s string) string {
		return `<dependencyManagement><dependencies>` + s + `</dependencies></dependencyManagement>`
	}
	cls := `<classifier>linux</classifier>`
	cases := []struct {
		name  string
		poms  []string
		wants []string // substrings, one problem each; none means no problem
	}{
		{"nothing", []string{relayPOM("g", "p", "1", deps(aggDep("a", "b", "")))}, nil},
		{"a test declaration after the runtime one", []string{relayPOM("g", "p", "1", deps(aggDep("a", "b", "")+aggDep("a", "b", "<type>test-jar</type><scope>test</scope>")))}, nil},
		{"a test declaration before the runtime one", []string{relayPOM("g", "p", "1", deps(aggDep("a", "b", "<type>test-jar</type><scope>test</scope>")+aggDep("a", "b", "")))}, []string{"declares a:b first with the scope"}},
		{"two runtime declarations", []string{relayPOM("g", "p", "1", deps(aggDep("a", "b", "")+aggDep("a", "b", cls)))}, []string{"declares a:b 2 times among"}},
		{"runtime kinds with different versions", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "q", "1", deps(`<dependency><groupId>a</groupId><artifactId>b</artifactId><version>2</version><classifier>linux</classifier></dependency>`)),
		}, []string{"a:b is declared at runtime as more than one kind"}},
		{"same name in two poms is fine", []string{relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))), relayPOM("g", "q", "1", deps(aggDep("a", "b", "<scope>test</scope>")))}, nil},
		{"a used name managed only with a classifier", []string{
			child(deps(noVer("io.netty", "native", ""))),
			relayPOM("g", "parent", "1", mgmt(aggDep("io.netty", "native", cls))),
		}, []string{"declares io.netty:native, which the scanner manages"}},
		{"a classifier management in an imported BOM", []string{
			relayPOM("g", "p", "1", deps(noVer("io.netty", "native", ""))+mgmt(aggDep("g", "bom", "<type>pom</type><scope>import</scope>"))),
			relayPOM("g", "bom", "1", mgmt(aggDep("io.netty", "native", cls))),
		}, []string{"declares io.netty:native, which the scanner manages"}},
		{"a BOM no pom imports", []string{
			relayPOM("g", "p", "1", deps(noVer("io.netty", "native", ""))),
			relayPOM("g", "bom", "1", mgmt(aggDep("io.netty", "native", cls))),
		}, nil},
		{"an unused name managed with a classifier", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "bom", "1", mgmt(aggDep("io.netty", "native", "")+aggDep("io.netty", "native", cls))),
		}, nil},
		{"plain management first, test-jar after", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "bom", "1", mgmt(aggDep("a", "b", "")+aggDep("a", "b", "<type>test-jar</type><scope>test</scope>"))),
		}, nil},
		{"test-jar management first", []string{
			child(deps(aggDep("a", "b", ""))),
			relayPOM("g", "parent", "1", mgmt(aggDep("a", "b", "<type>test-jar</type><scope>test</scope>")+aggDep("a", "b", ""))),
		}, []string{"declares a:b, which the scanner manages"}},
		{"different exclusions in the entry each picks", []string{
			child(deps(noVer("a", "b", ""))),
			relayPOM("g", "parent", "1", mgmt(aggDep("a", "b", cls+"<exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions>")+aggDep("a", "b", "<exclusions><exclusion><groupId>z</groupId><artifactId>w</artifactId></exclusion></exclusions>"))),
		}, []string{"declares a:b, which the scanner manages"}},
		{"another kind first with the same settings", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "bom", "1", mgmt(aggDep("a", "b", cls)+aggDep("a", "b", ""))),
		}, nil},
		{"explicit jar equals the default", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", "<type>jar</type>"))),
			relayPOM("g", "bom", "1", mgmt(aggDep("a", "b", ""))),
		}, nil},
		{"an import of a BOM that was read", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "q", "1", mgmt(aggDep("a", "b", "<type>pom</type><scope>import</scope>"))),
			relayPOM("a", "b", "1", ""),
		}, nil},
		{"an import of a BOM that was not read", []string{
			relayPOM("g", "q", "1", mgmt(aggDep("a", "b", "<type>pom</type><scope>import</scope>"))),
		}, []string{"imports a BOM that cannot be followed"}},
		{"explicit management of another kind ahead of an imported plain one", []string{
			relayPOM("g", "p", "1", deps(noVer("x", "y", ""))+mgmt(aggDep("g", "bom", "<type>pom</type><scope>import</scope>")+
				`<dependency><groupId>x</groupId><artifactId>y</artifactId><version>2</version><classifier>c</classifier></dependency>`+aggDep("x", "y", ""))),
			relayPOM("g", "bom", "1", mgmt(aggDep("x", "y", ""))),
		}, []string{"declares x:y, which the scanner manages"}},
		{"a scope written as a property", []string{
			relayPOM("g", "p", "1", `<properties><s>runtime</s></properties>`+deps(noVer("x", "y", "<scope>${s}</scope>"))+mgmt(aggDep("x", "y", "<optional>true</optional>"))),
		}, []string{"declares x:y, which the scanner manages"}},
		{"a pom of packaging pom that something depends on is judged on its own", []string{
			relayPOM("g", "p", "1", deps(aggDep("g", "agg", "<type>pom</type>"))),
			relayPOM("g", "agg", "1", `<packaging>pom</packaging>`+deps(noVer("x", "y", ""))+mgmt(aggDep("x", "y", "<optional>true</optional>"))),
		}, []string{"pom g:agg:1 declares x:y, which the scanner manages"}},
		{"a dependency named through an inherited property", []string{
			child(deps(noVer("g", "${bundle}", "<type>pom</type>")) + mgmt(aggDep("g", "agg", "<type>pom</type><scope>import</scope>"))),
			relayPOM("g", "parent", "1", `<packaging>pom</packaging><properties><bundle>agg</bundle></properties>`),
			relayPOM("g", "agg", "1", `<packaging>pom</packaging>`+deps(noVer("x", "y", ""))+mgmt(aggDep("x", "y", "<optional>true</optional>"))),
		}, []string{"pom g:agg:1 declares x:y, which the scanner manages"}},
		{"a parent only is judged through its child", []string{
			child(""),
			relayPOM("g", "parent", "1", `<packaging>pom</packaging><properties><v>1</v></properties>`+mgmt(`<dependency><groupId>g</groupId><artifactId>missing</artifactId><version>${v}</version><type>pom</type><scope>import</scope></dependency>`)),
		}, []string{"pom g:child:1 imports a BOM that cannot be followed"}},
		{"an inherited declaration managed optional by the child", []string{
			child(mgmt(aggDep("x", "y", "<optional>true</optional>"))),
			relayPOM("g", "parent", "1", deps(aggDep("x", "y", ""))),
		}, []string{"pom g:child:1 declares x:y, which the scanner manages"}},
		{"a BOM imported through a parent's property", []string{
			child(deps(noVer("x", "y", ""))),
			relayPOM("g", "parent", "1", `<properties><bom.version>1</bom.version></properties>`+mgmt(`<dependency><groupId>g</groupId><artifactId>bom</artifactId><version>${bom.version}</version><type>pom</type><scope>import</scope></dependency>`)),
			relayPOM("g", "bom", "1", mgmt(aggDep("x", "y", "<optional>true</optional>"))),
		}, []string{"pom g:child:1 declares x:y, which the scanner manages"}},
		{"property names are resolved", []string{
			relayPOM("g", "p", "1", `<properties><n>b</n></properties>`+deps(noVer("${project.groupId}", "${n}", ""))+mgmt(aggDep("g", "b", cls))),
		}, []string{"declares g:b, which the scanner manages"}},
		{"unresolved names count as themselves", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "${x}", "")+aggDep("a", "${x}", ""))),
		}, []string{"a:${x} 2 times"}},
		{"an active profile importing a BOM", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "q", "1", `<profiles><profile><id>x</id><activation><activeByDefault>true</activeByDefault></activation>`+mgmt(aggDep("g", "bom", "<type>pom</type><scope>import</scope>"))+`</profile></profiles>`),
		}, []string{"imports a BOM"}},
		{"an active profile setting a property a version reads through another", []string{
			relayPOM("g", "p", "1", `<properties><a>${b}</a></properties>`+deps(`<dependency><groupId>x</groupId><artifactId>y</artifactId><version>${a}</version></dependency>`)),
			relayPOM("g", "q", "1", `<profiles><profile><id>x</id><activation><jdk>17</jdk></activation><properties><b>2</b></properties></profile></profiles>`),
		}, []string{"sets b, which a version reads"}},
		{"an active profile managing a used name", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "bom", "1", `<profiles><profile><id>x</id><activation><activeByDefault>true</activeByDefault></activation>`+mgmt(aggDep("a", "b", ""))+`</profile></profiles>`),
		}, []string{"can turn on and manages a:b"}},
		{"an inactive profile managing a used name", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))),
			relayPOM("g", "bom", "1", `<profiles><profile><id>x</id>`+mgmt(aggDep("a", "b", ""))+`</profile></profiles>`),
		}, nil},
		{"an active profile setting a property a version reads", []string{
			relayPOM("g", "p", "1", deps(`<dependency><groupId>a</groupId><artifactId>b</artifactId><version>${v}</version></dependency>`)),
			relayPOM("g", "q", "1", `<profiles><profile><id>x</id><activation><jdk>17</jdk></activation><properties><v>2</v></properties></profile></profiles>`),
		}, []string{"sets v, which a version reads"}},
		{"optional management and a runtime declaration below it", []string{
			`<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId>` + deps(`<dependency><groupId>a</groupId><artifactId>b</artifactId></dependency>`) + `</project>`,
			relayPOM("g", "parent", "1", mgmt(aggDep("a", "b", "<optional>true</optional>"))),
		}, []string{"declares a:b, which the scanner manages"}},
		{"optional management and a test declaration below it", []string{
			`<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId>` + deps(`<dependency><groupId>a</groupId><artifactId>b</artifactId><scope>test</scope></dependency>`) + `</project>`,
			relayPOM("g", "parent", "1", mgmt(aggDep("a", "b", "<optional>true</optional>"))),
		}, nil},
		{"managed exclusions and a declaration with its own", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", "<exclusions><exclusion><groupId>e</groupId><artifactId>f</artifactId></exclusion></exclusions>"))+mgmt(aggDep("a", "b", "<exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions>"))),
		}, []string{"declares a:b, which the scanner manages"}},
		{"managed exclusions and a declaration without", []string{
			relayPOM("g", "p", "1", deps(aggDep("a", "b", ""))+mgmt(aggDep("a", "b", "<exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions>"))),
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var poms []*mavenPOM
			for _, s := range c.poms {
				poms = append(poms, mustPOM(t, s))
			}
			got := mavenAggregateProblems(poms)
			if len(got) != len(c.wants) {
				t.Fatalf("problems = %v, want %v", got, c.wants)
			}
			for _, w := range c.wants {
				found := false
				for _, g := range got {
					found = found || strings.Contains(g, w)
				}
				if !found {
					t.Errorf("no %q in %v", w, got)
				}
			}
		})
	}
	// Sorted and without repeats.
	p := mustPOM(t, relayPOM("g", "p", "1", deps(aggDep("z", "z", "")+aggDep("z", "z", "")+aggDep("a", "a", "")+aggDep("a", "a", ""))))
	got := mavenAggregateProblems([]*mavenPOM{p, nil, p})
	if len(got) != 2 || got[0] > got[1] {
		t.Errorf("problems = %v", got)
	}
}
