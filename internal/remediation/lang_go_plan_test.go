package remediation

import (
	"errors"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const goModApp = `module example.com/app

go 1.22

toolchain go1.22.5

require (
	golang.org/x/net v0.20.0
	github.com/pkg/errors v0.9.1 // indirect
)

require golang.org/x/text v0.14.0 // indirect; kept for x/net
`

const goSumApp = `golang.org/x/net v0.20.0 h1:aCL9BSgETF1k+blQaYUBx9hJ9LOGP3gAVemcZlf1Kpo=
golang.org/x/net v0.20.0/go.mod h1:z8BVo6PvndSri0LbOE3hAn0apkU+1YvI6E70E9jsnvY=
`

func TestParseGoMod(t *testing.T) {
	gm, err := parseGoMod([]byte(goModApp))
	if err != nil {
		t.Fatal(err)
	}
	if gm.module != "example.com/app" || gm.goVersion != "1.22" || gm.toolchain != "go1.22.5" || len(gm.others) != 0 {
		t.Errorf("go.mod = %+v", gm)
	}
	want := []goRequire{
		{path: "golang.org/x/net", version: "v0.20.0", line: 8},
		{path: "github.com/pkg/errors", version: "v0.9.1", indirect: true, line: 9},
		{path: "golang.org/x/text", version: "v0.14.0", indirect: true, line: 12},
	}
	if len(gm.requires) != len(want) {
		t.Fatalf("requires = %+v", gm.requires)
	}
	for i, r := range want {
		if gm.requires[i] != r {
			t.Errorf("require %d = %+v, want %+v", i, gm.requires[i], r)
		}
	}

	quoted, err := parseGoMod([]byte("module \"example.com/q\" // the module\ngo 1.23.4\nrequire `example.com/r` v1.0.0\ngodebug (\n\tpanicnil=1\n)\nretract v1.0.1\ntool example.com/t\n"))
	if err != nil {
		t.Fatal(err)
	}
	if quoted.module != "example.com/q" || quoted.requires[0].path != "example.com/r" ||
		strings.Join(quoted.others, "|") != "godebug panicnil=1|retract v1.0.1|tool example.com/t" {
		t.Errorf("go.mod = %+v", quoted)
	}

	for name, src := range map[string]string{
		"no module":         "go 1.22\n",
		"open block":        "module m\nrequire (\n\ta v1.0.0\n",
		"bad string":        "module \"m\n",
		"two modules":       "module a\nmodule b\n",
		"short requirement": "module m\nrequire a\n",
	} {
		if _, err := parseGoMod([]byte(src)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	for name, src := range map[string]string{
		"empty block on one line": "module m\nrequire ()\n",
		"empty block":             "module m\nrequire (\n)\n",
		"retract interval":        "module m\nretract [v1.0.0, v1.0.5] // broken\n",
		"replace with versions":   "module m\nreplace a v1.0.0 => b v1.1.0\n",
		"module block":            "module (\n\tm\n)\n",
	} {
		gm, err := parseGoMod([]byte(src))
		if err != nil || len(gm.requires) != 0 {
			t.Errorf("%s: %+v %v", name, gm, err)
		}
	}
	for name, src := range map[string]string{
		"retract without a version": "module m\nretract\n",
		"retract of no version":     "module m\nretract latest\n",
		"tool without a path":       "module m\ntool\n",
		"exclude without a version": "module m\nexclude a\n",
		"replace without an arrow":  "module m\nreplace a b\n",
		"godebug without a value":   "module m\ngodebug panicnil\n",
		"go in a block":             "module m\ngo (\n1.22\n)\n",
		"two modules in a block":    "module (\n\tm\n\tn\n)\n",
	} {
		if _, err := parseGoMod([]byte(src)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	for c, want := range map[string]bool{
		" indirect": true, "indirect": true, " indirect; kept": true,
		" indirect;": false, " indirect;kept": false, " indirectly": false, " not indirect": false,
	} {
		if got := isIndirectComment(c); got != want {
			t.Errorf("indirect(%q) = %v", c, got)
		}
	}
	var ue *UnsupportedError
	if _, err := parseGoMod([]byte("module m\nfrobnicate x\n")); !errors.As(err, &ue) {
		t.Errorf("an unknown directive is not refused: %v", err)
	}
}

func TestParseGoRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		mod, sum string
		reason   Reason
	}{
		"replace":            {"module m\ngo 1.22\nreplace a => ../a\n", "", ReasonGoReplace},
		"exclude":            {"module m\ngo 1.22\nexclude a v1.0.0\n", "", ReasonGoExclude},
		"old go line":        {"module m\ngo 1.20\n", "", ReasonGoVersionTooOld},
		"no go line":         {"module m\n", "", ReasonGoVersionTooOld},
		"default toolchain":  {"module m\ngo 1.22\ntoolchain default\n", "", ReasonGoToolchainUnsupported},
		"rc toolchain":       {"module m\ngo 1.22\ntoolchain go1.23rc1\n", "", ReasonGoToolchainUnsupported},
		"suffixed toolchain": {"module m\ngo 1.22\ntoolchain go1.22.5+custom\n", "", ReasonGoToolchainUnsupported},
		"toolchain no patch": {"module m\ngo 1.22\ntoolchain go1.22\n", "", ReasonGoToolchainUnsupported},
	} {
		_, _, err := parseGo([]byte(c.sum), []byte(c.mod))
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Reason != c.reason {
			t.Errorf("%s: err = %v, want %s", name, err, c.reason)
		}
	}
	for name, c := range map[string]struct{ mod, sum string }{
		"version without v": {"module m\ngo 1.22\nrequire a 1.0.0\n", ""},
		"twice":             {"module m\ngo 1.22\nrequire a v1.0.0\nrequire a v1.1.0\n", ""},
		"bad go.sum":        {"module m\ngo 1.22\n", "a v1.0.0\n"},
	} {
		if _, _, err := parseGo([]byte(c.sum), []byte(c.mod)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	l, gm, err := parseGo([]byte(goSumApp), []byte(goModApp))
	if err != nil || gm.module != "example.com/app" {
		t.Fatalf("err = %v", err)
	}
	if p := l.lookup("golang.org/x/net"); p == nil || len(p.occs) != 1 || !p.occs[0].Direct || p.occs[0].Version != "v0.20.0" {
		t.Errorf("x/net = %+v", p)
	}
	if p := l.lookup("github.com/pkg/errors"); p == nil || p.occs[0].Direct {
		t.Errorf("errors = %+v", p)
	}
}

func TestGoVersionScheme(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v0.20.0", "0.23.0", -1},
		{"v1.2.3", "1.2.3", 0},
		{"v0.0.0-20240101000000-abcdef123456", "v0.0.1", -1},
		{"v0.0.0-20240101000000-abcdef123456", "v0.0.0-20250101000000-abcdef123456", -1},
		{"v2.0.0+incompatible", "2.0.1", -1},
		{"v2.0.0+incompatible", "v2.0.0", 0},
	} {
		got, ok := compareVersions(schemeGo, c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("%s vs %s = %d %v, want %d", c.a, c.b, got, ok, c.want)
		}
	}
	for _, c := range []struct {
		path, installed, target string
		ok                      bool
	}{
		{"example.com/m", "v1.5.0", "2.0.0", false},
		{"example.com/m", "v0.9.0", "1.0.0", true},
		{"example.com/m/v2", "v2.3.1", "2.3.2", true},
		{"example.com/m/v2", "v2.3.1", "3.0.0", false},
		{"example.com/m", "v2.0.0+incompatible", "3.0.0", true},
		{"example.com/m", "v1.0.0", "2.0.0+incompatible", true},
		{"gopkg.in/yaml.v2", "v2.2.1", "2.2.8", true},
		{"gopkg.in/foo.v0", "v0.1.0", "1.0.0", false},
		{"gopkg.in/yaml.v1", "v0.0.0-20140101000000-abcdef123456", "v0.0.0-20150101000000-abcdef123456", true},
		{"gopkg.in/yaml.v2", "v2.2.1", "3.0.0", false},
	} {
		if p := goMajorProblem(c.path, c.installed, c.target); (p == "") != c.ok {
			t.Errorf("%s %s -> %s: %q", c.path, c.installed, c.target, p)
		}
	}
}

func TestGoStdlibFix(t *testing.T) {
	cves := []CVERef{
		{VulnID: "A", FixedVers: []string{"1.26.5, 1.27.1"}},
		{VulnID: "B", FixedVers: []string{"1.26.10", "1.27.3"}},
	}
	if got := goStdlibFix("v1.26.4", cves); got != "1.26.10" {
		t.Errorf("same series = %q", got)
	}
	// The series has no fix: the lowest above it.
	if got := goStdlibFix("v1.25.9", []CVERef{{VulnID: "A", FixedVers: []string{"1.26.5, 1.27.1"}}}); got != "1.26.5" {
		t.Errorf("other series = %q", got)
	}
	if got := goStdlibFix("v1.26.4", []CVERef{{VulnID: "A", FixedVers: []string{"1.26.5-rc1"}}}); got != "" {
		t.Errorf("a fix that is not a release = %q", got)
	}
	// A is fixed in 1.25 and 1.26, B in 1.26 only: 1.25 cannot fix both, and
	// in 1.26 A needs 1.26.4.
	if got := goStdlibFix("v1.25.1", []CVERef{
		{VulnID: "A", FixedVers: []string{"1.25.3, 1.26.4"}},
		{VulnID: "B", FixedVers: []string{"1.26.2"}},
	}); got != "1.26.4" {
		t.Errorf("mixed series = %q", got)
	}
	// A series above every listed one has the fix from its first release.
	if got := goStdlibFix("v1.25.1", []CVERef{
		{VulnID: "A", FixedVers: []string{"1.25.3"}},
		{VulnID: "B", FixedVers: []string{"1.27.1"}},
	}); got != "1.27.1" {
		t.Errorf("series above = %q", got)
	}
}

// --- planning ---

// goFinding is a fixed finding of a module built into a Go binary.
func goFinding(vuln, target, module, installed, fixed string) scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: typeGoBinary, Target: target, Package: module,
		InstalledVer: installed, FixedVer: fixed, Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

// goBinaryPackages is the package list of a Go binary: its main module, the
// Go it was built with and the modules built into it.
func goBinaryPackages(target, root, stdlib string, deps ...string) scanner.ResultPackages {
	rp := scanner.ResultPackages{Target: target, Class: inventory.ClassLang, Type: typeGoBinary}
	if root != "" {
		rp.Packages = append(rp.Packages, scanner.Package{Name: root, Relationship: "root"})
	}
	rp.Packages = append(rp.Packages, scanner.Package{Name: goStdlib, Version: stdlib, Relationship: "direct"})
	for i := 0; i+1 < len(deps); i += 2 {
		rp.Packages = append(rp.Packages, scanner.Package{Name: deps[i], Version: deps[i+1]})
	}
	return rp
}

// goInput is a scanned image with an application binary built from
// example.com/app and a tool built from another module.
func goInput(fs ...scanner.Finding) ImageInput {
	in := langInput("shop", "api", fs...)
	in.Scan.Packages = []scanner.ResultPackages{
		goBinaryPackages("usr/local/bin/app", "example.com/app", "v1.22.5", "golang.org/x/net", "v0.20.0", "github.com/pkg/errors", "v0.9.1", "golang.org/x/text", "v0.14.0"),
		goBinaryPackages("usr/local/bin/tool", "example.com/tool", "v1.26.4", "golang.org/x/net", "v0.10.0"),
	}
	return in
}

func goRepo(f *fakeGitHub, repo, dir, mod string) {
	f.put(repo, dir, "go.mod", mod)
	f.put(repo, dir, "go.sum", goSumApp)
}

func goPlanItem(t *testing.T, gh *fakeGitHub, in ImageInput) (LanguageItem, bool) {
	t.Helper()
	plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}, nil, in)
	for _, it := range plan.LanguageItems {
		if it.Manager == ManagerGo || strings.HasSuffix(it.Key, "#"+typeGoBinary) {
			return it, true
		}
	}
	return LanguageItem{}, false
}

func TestLanguagePlan_GoCandidate(t *testing.T) {
	gh := newFakeGitHub()
	goRepo(gh, "ex/app", "svc", goModApp)
	it, ok := goPlanItem(t, gh, goInput(
		goFinding("CVE-NET", "usr/local/bin/app", "golang.org/x/net", "v0.20.0", "0.23.0"),
		goFinding("CVE-ERR", "usr/local/bin/app", "github.com/pkg/errors", "v0.9.1", "0.9.2"),
		goFinding("CVE-TOOL", "usr/local/bin/tool", "golang.org/x/net", "v0.10.0", "0.23.0"),
		goFinding("CVE-STD", "usr/local/bin/app", goStdlib, "v1.22.5", "1.22.7, 1.23.1"),
	))
	if !ok {
		t.Fatal("no Go item")
	}
	if it.Manager != ManagerGo || it.Category != CategoryDependencyUpdateCandidate || it.Key != "deps:ex/app@main:svc#go" {
		t.Fatalf("item = %s %s %s (%s)", it.Key, it.Category, it.Reason, it.Detail)
	}
	got := map[string]LanguagePackage{}
	for _, p := range it.Packages {
		got[p.Name+"@"+p.Installed] = p
	}
	if len(got) != 2 {
		t.Fatalf("packages = %+v; the tool's finding and the standard library's must be left out", it.Packages)
	}
	net := got["golang.org/x/net@v0.20.0"]
	if net.Action != ActionUpdate || net.SelectionLowerBound != "0.23.0" || net.Relation != RelationDirect {
		t.Errorf("x/net = %+v", net)
	}
	for _, o := range net.Origins {
		if o.Target != "usr/local/bin/app" {
			t.Errorf("x/net keeps an origin of another binary: %+v", o)
		}
	}
	if e := got["github.com/pkg/errors@v0.9.1"]; e.Action != ActionUpdate || e.Relation != RelationTransitive {
		t.Errorf("errors = %+v", e)
	}
	if it.GoBuiltWith != "1.22.5" {
		t.Errorf("built with = %q", it.GoBuiltWith)
	}
	// The standard library is an item of its own, which stays when the
	// module's item becomes a pull request.
	plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}, nil, goInput(
		goFinding("CVE-NET", "usr/local/bin/app", "golang.org/x/net", "v0.20.0", "0.23.0"),
		goFinding("CVE-STD", "usr/local/bin/app", goStdlib, "v1.22.5", "1.22.7, 1.23.1"),
	))
	var std *LanguageItem
	for i := range plan.LanguageItems {
		if plan.LanguageItems[i].Key == "deps:ex/app@main:svc#go-stdlib" {
			std = &plan.LanguageItems[i]
		}
	}
	if std == nil || std.Category != CategoryManual || std.Reason != ReasonGoStdlib || len(std.Packages) != 1 {
		t.Fatalf("stdlib item = %+v", std)
	}
	if s := std.Packages[0]; s.Action != ActionManual || s.Reason != ReasonGoStdlib || s.SelectionLowerBound != "1.22.7" || !strings.Contains(s.Detail, "Go 1.22.7") {
		t.Errorf("stdlib = %+v", s)
	}
	if len(std.Source.Files) != 2 || std.Manager != ManagerGo {
		t.Errorf("stdlib item = %+v", std)
	}
	for _, want := range []string{"svc/go.work", "svc/vendor"} {
		if !containsString(it.Source.Absent, want) {
			t.Errorf("absent = %v, want %s", it.Source.Absent, want)
		}
	}
	if len(it.Source.Files) != 2 || it.Source.Files[0].Path != "svc/go.mod" || it.Source.Files[1].Path != "svc/go.sum" {
		t.Errorf("files = %+v", it.Source.Files)
	}
}

func TestLanguagePlan_GoBinaryChecks(t *testing.T) {
	net := goFinding("CVE-NET", "usr/local/bin/app", "golang.org/x/net", "v0.20.0", "0.23.0")
	t.Run("only other binaries: no item", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		if it, ok := goPlanItem(t, gh, goInput(goFinding("CVE-TOOL", "usr/local/bin/tool", "golang.org/x/net", "v0.10.0", "0.23.0"))); ok {
			t.Errorf("item for a binary of another module: %+v", it)
		}
	})
	t.Run("no go.mod: no item", func(t *testing.T) {
		gh := newFakeGitHub()
		npmRepo(gh, "ex/app", "svc")
		if it, ok := goPlanItem(t, gh, goInput(net)); ok {
			t.Errorf("item without a go.mod: %+v", it)
		}
	})
	t.Run("go.sum missing", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "go.mod", goModApp)
		it, ok := goPlanItem(t, gh, goInput(net))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonDependencyFilesNotFound {
			t.Errorf("item = %+v", it)
		}
	})
	t.Run("binary built from other versions", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", strings.Replace(goModApp, "golang.org/x/text v0.14.0", "golang.org/x/text v0.15.0", 1))
		it, ok := goPlanItem(t, gh, goInput(net))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonGoBinaryNotFromSource || !strings.Contains(it.Detail, "golang.org/x/text") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
		if len(it.Packages) != 1 {
			t.Errorf("packages = %+v; the other binary's findings must not be listed", it.Packages)
		}
	})
	t.Run("binary with a module go.mod does not require", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		in := goInput(net)
		in.Scan.Packages[0].Packages = append(in.Scan.Packages[0].Packages, scanner.Package{Name: "example.com/extra", Version: "v1.0.0"})
		if it, ok := goPlanItem(t, gh, in); !ok || it.Reason != ReasonGoBinaryNotFromSource {
			t.Errorf("item = %+v", it)
		}
	})
	t.Run("package list cut short", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		in := goInput(net)
		in.Scan.PackagesTruncated = true
		if it, ok := goPlanItem(t, gh, in); !ok || it.Reason != ReasonGoBinaryNotFromSource {
			t.Errorf("item = %+v", it)
		}
	})
	for _, name := range []string{"go.work", "vendor"} {
		t.Run(name+" in the directory", func(t *testing.T) {
			gh := newFakeGitHub()
			goRepo(gh, "ex/app", "svc", goModApp)
			gh.put("ex/app", "svc", name, "x")
			if it, ok := goPlanItem(t, gh, goInput(net)); !ok || it.Reason != ReasonWorkspaceUnsupported {
				t.Errorf("item = %+v", it)
			}
		})
	}
	t.Run("go.work above", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		gh.put("ex/app", ".", "go.work", "go 1.22\n")
		if it, ok := goPlanItem(t, gh, goInput(net)); !ok || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, "go.work") {
			t.Errorf("item = %+v", it)
		}
	})
	t.Run("replace", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp+"replace golang.org/x/net => ../net\n")
		if it, ok := goPlanItem(t, gh, goInput(net)); !ok || it.Reason != ReasonGoReplace {
			t.Errorf("item = %+v", it)
		}
	})
	t.Run("fix of another major", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		it, ok := goPlanItem(t, gh, goInput(goFinding("CVE-ERR", "usr/local/bin/app", "github.com/pkg/errors", "v0.9.1", "2.0.0")))
		if !ok || len(it.Packages) != 1 || it.Packages[0].Reason != ReasonFixInOtherMajor || it.Packages[0].SelectionLowerBound != "" {
			t.Errorf("item = %+v", it)
		}
	})
	t.Run("a tool with the same module version", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		in := goInput(net, goFinding("CVE-TOOLNET", "usr/local/bin/tool", "golang.org/x/net", "v0.20.0", "0.30.0"))
		in.Scan.Packages[1] = goBinaryPackages("usr/local/bin/tool", "example.com/tool", "v1.26.4", "golang.org/x/net", "v0.20.0")
		it, ok := goPlanItem(t, gh, in)
		if !ok || len(it.Packages) != 1 {
			t.Fatalf("item = %+v", it)
		}
		p := it.Packages[0]
		if p.SelectionLowerBound != "0.23.0" || len(p.CVEs) != 1 || p.CVEs[0].VulnID != "CVE-NET" {
			t.Errorf("x/net = %+v; the tool's vulnerability must not count", p)
		}
		for _, o := range p.Origins {
			if o.Target != "usr/local/bin/app" {
				t.Errorf("origin of another binary: %+v", o)
			}
		}
	})
	t.Run("finding of a module missing from the binary's list", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		in := goInput(net)
		in.Scan.Packages[0] = goBinaryPackages("usr/local/bin/app", "example.com/app", "v1.22.5")
		if it, ok := goPlanItem(t, gh, in); !ok || it.Reason != ReasonGoBinaryNotFromSource || !strings.Contains(it.Detail, "not in the binary's module list") {
			t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("only other binaries and a replace: no item", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp+"replace golang.org/x/net => ../net\n")
		if it, ok := goPlanItem(t, gh, goInput(goFinding("CVE-TOOL", "usr/local/bin/tool", "golang.org/x/net", "v0.10.0", "0.23.0"))); ok {
			t.Errorf("item for a binary of another module: %+v", it)
		}
	})
	t.Run("a go.mod that does not parse keeps every Go finding", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", "module (\n")
		it, ok := goPlanItem(t, gh, goInput(net))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonUnparsableSource {
			t.Errorf("item = %+v", it)
		}
	})
	t.Run("a finding of the main module itself", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		it, ok := goPlanItem(t, gh, goInput(net, goFinding("CVE-APP", "usr/local/bin/app", "example.com/app", "v1.0.0", "1.0.1")))
		if !ok || it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
		for _, p := range it.Packages {
			if p.Name == "golang.org/x/net" && p.Action != ActionUpdate {
				t.Errorf("x/net = %+v", p)
			}
			if p.Name == "example.com/app" && p.Action != ActionManual {
				t.Errorf("the main module's own finding = %+v", p)
			}
		}
	})
	t.Run("built with: every binary of the module", func(t *testing.T) {
		for _, c := range []struct {
			name, second string
			want         string
		}{
			{"a lower Go without findings", "v1.21.9", "1.21.9"},
			{"a binary without the Go recorded", "", ""},
		} {
			gh := newFakeGitHub()
			goRepo(gh, "ex/app", "svc", goModApp)
			in := goInput(net)
			second := goBinaryPackages("usr/local/bin/app2", "example.com/app", c.second)
			if c.second == "" {
				second.Packages = second.Packages[:1]
			}
			// A binary of another module built with an older Go does not count.
			in.Scan.Packages = append(in.Scan.Packages, second, goBinaryPackages("usr/local/bin/old", "example.com/old", "v1.20.1"))
			if it, ok := goPlanItem(t, gh, in); !ok || it.GoBuiltWith != c.want {
				t.Errorf("%s: built with = %q, want %q", c.name, it.GoBuiltWith, c.want)
			}
		}
	})
	t.Run("go.sum missing without requirements", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "go.mod", "module example.com/app\n\ngo 1.22\n")
		in := goInput(goFinding("CVE-STD", "usr/local/bin/app", goStdlib, "v1.22.5", "1.22.7"))
		in.Scan.Packages[0] = goBinaryPackages("usr/local/bin/app", "example.com/app", "v1.22.5")
		if it, ok := goPlanItem(t, gh, in); !ok || it.Reason != ReasonDependencyFilesNotFound {
			t.Errorf("item = %+v", it)
		}
	})
	t.Run("only stdlib", func(t *testing.T) {
		gh := newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		it, ok := goPlanItem(t, gh, goInput(goFinding("CVE-STD", "usr/local/bin/app", goStdlib, "v1.22.5", "1.22.7")))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonGoStdlib {
			t.Errorf("item = %+v", it)
		}
	})
}

func TestLanguagePlan_GoUnverified(t *testing.T) {
	unverified := func(fs ...scanner.Finding) ImageInput {
		in := goInput(fs...)
		in.Scan.Pinned = false
		return in
	}
	items := func(gh *fakeGitHub, in ImageInput) []LanguageItem {
		return langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}, nil, in).LanguageItems
	}
	app := goFinding("CVE-NET", "usr/local/bin/app", "golang.org/x/net", "v0.20.0", "0.23.0")
	tool := goFinding("CVE-TOOL", "usr/local/bin/tool", "golang.org/x/net", "v0.10.0", "0.23.0")

	gh := newFakeGitHub()
	goRepo(gh, "ex/app", "svc", goModApp)
	got := items(gh, unverified(app, tool))
	if len(got) != 1 || !strings.HasSuffix(got[0].Key, "#unverified") || len(got[0].Packages) != 1 ||
		got[0].Packages[0].CVEs[0].VulnID != "CVE-NET" {
		t.Errorf("items = %+v; only the application's finding is listed", got)
	}

	gh = newFakeGitHub()
	npmRepo(gh, "ex/app", "svc")
	if got := items(gh, unverified(app)); len(got) != 0 {
		t.Errorf("items without a go.mod = %+v", got)
	}

	// Two unverified scans of different images (both without a confirmed
	// entity) with a binary at the same path: one built from the module, one
	// from another. Only the first's findings are listed, in either order.
	appImage := unverified(app)
	toolImage := langInput("shop", "api", goFinding("CVE-OTHER", "usr/local/bin/app", "golang.org/x/net", "v0.20.0", "0.30.0"))
	toolImage.Scan.Pinned = false
	toolImage.Scan.Packages = []scanner.ResultPackages{goBinaryPackages("usr/local/bin/app", "example.com/other", "v1.26.4", "golang.org/x/net", "v0.20.0")}
	for _, order := range [][]ImageInput{{appImage, toolImage}, {toolImage, appImage}} {
		gh = newFakeGitHub()
		goRepo(gh, "ex/app", "svc", goModApp)
		got := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}, nil, order...).LanguageItems
		if len(got) != 1 || len(got[0].Packages) != 1 || len(got[0].Packages[0].CVEs) != 1 || got[0].Packages[0].CVEs[0].VulnID != "CVE-NET" {
			t.Errorf("items = %+v", got)
		}
	}
}
