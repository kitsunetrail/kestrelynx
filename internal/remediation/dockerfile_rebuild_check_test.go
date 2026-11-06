package remediation

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// The node paths are those of a scan of node:24-alpine with pnpm 10.34.4
// installed globally.
const (
	npmUndici  = "usr/local/lib/node_modules/npm/node_modules/undici/package.json"
	npmBrace   = "usr/local/lib/node_modules/npm/node_modules/brace-expansion/package.json"
	pnpmBrace  = "usr/local/lib/node_modules/pnpm/dist/node_modules/brace-expansion/package.json"
	pnpmTar    = "usr/local/lib/node_modules/pnpm/dist/node_modules/tar/package.json"
	pnpmItself = "usr/local/lib/node_modules/pnpm/package.json"
)

var rbSeverities = []string{"CRITICAL", "HIGH"}

func rbLangFinding(typ, vuln, name, ver, path string) scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: typ, Target: "Node.js", PkgPath: path,
		Package: name, InstalledVer: ver, FixedVer: "99", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

func rbNodeFinding(vuln, name, ver, path string) scanner.Finding {
	return rbLangFinding(typeNodePkg, vuln, name, ver, path)
}

func langPackages(typ string, pk ...scanner.Package) scanner.ResultPackages {
	return scanner.ResultPackages{Target: "Node.js", Class: inventory.ClassLang, Type: typ, Packages: pk}
}

func imageScan(fs []scanner.Finding, pk ...scanner.ResultPackages) scanner.ImageScan {
	return scanner.ImageScan{OSFamily: "alpine", Findings: fs, Packages: pk}
}

func pkgNames(ps []RebuildPackage) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Name+" "+p.Version)
	}
	return out
}

func TestClassifyRebuild_SameNameInTwoPlaces(t *testing.T) {
	running := imageScan([]scanner.Finding{
		rbNodeFinding("CVE-U", "undici", "6.28.0", npmUndici),
		rbNodeFinding("CVE-B", "brace-expansion", "5.0.9", npmBrace),
		rbNodeFinding("CVE-B", "brace-expansion", "2.1.1", pnpmBrace),
		rbNodeFinding("CVE-T", "tar", "7.5.16", pnpmTar),
		rbNodeFinding("CVE-P", "pnpm", "10.34.4", pnpmItself),
	})
	base := imageScan([]scanner.Finding{
		rbNodeFinding("CVE-U", "undici", "6.28.0", npmUndici),
		rbNodeFinding("CVE-B", "brace-expansion", "5.0.9", npmBrace),
	}, langPackages(typeNodePkg,
		scanner.Package{Name: "undici", Version: "6.28.0", PkgPath: npmUndici},
		scanner.Package{Name: "brace-expansion", Version: "5.0.9", PkgPath: npmBrace},
	))
	c := classifyRebuild(running, base, rbSeverities, nil)
	if c.Status != RebuildChecked || c.Undetermined != 0 {
		t.Fatalf("status %s, undetermined %d", c.Status, c.Undetermined)
	}
	if got, want := pkgNames(c.Remaining), []string{"brace-expansion 5.0.9", "undici 6.28.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("remaining %v", got)
	}
	if got, want := pkgNames(c.NotInBase), []string{"brace-expansion 2.1.1", "pnpm 10.34.4", "tar 7.5.16"}; !reflect.DeepEqual(got, want) {
		t.Errorf("not in base %v", got)
	}
	for _, p := range c.NotInBase {
		if p.Owner != "pnpm" {
			t.Errorf("owner of %s = %q", p.Name, p.Owner)
		}
	}
	if len(c.Gone) != 0 || len(c.OnlyInBase) != 0 || c.OtherNotInBase != 0 {
		t.Errorf("gone %v only %v other %d", c.Gone, c.OnlyInBase, c.OtherNotInBase)
	}
}

func TestClassifyRebuild_Outcomes(t *testing.T) {
	t.Run("the base moved to a version without the finding", func(t *testing.T) {
		c := classifyRebuild(
			imageScan([]scanner.Finding{rbNodeFinding("CVE-1", "undici", "6.28.0", npmUndici), rbNodeFinding("CVE-2", "undici", "6.28.0", npmUndici)}),
			imageScan([]scanner.Finding{rbNodeFinding("CVE-2", "undici", "6.29.1", npmUndici)},
				langPackages(typeNodePkg, scanner.Package{Name: "undici", Version: "6.29.1", PkgPath: npmUndici})),
			rbSeverities, nil)
		if len(c.Gone) != 1 || c.Gone[0].BaseVersion != "6.29.1" || !reflect.DeepEqual(c.Gone[0].VulnIDs, []string{"CVE-1"}) {
			t.Errorf("gone %+v", c.Gone)
		}
		if len(c.Remaining) != 1 || !reflect.DeepEqual(c.Remaining[0].VulnIDs, []string{"CVE-2"}) {
			t.Errorf("remaining %+v", c.Remaining)
		}
	})
	t.Run("the same version without the finding is not a fix", func(t *testing.T) {
		c := classifyRebuild(
			imageScan([]scanner.Finding{rbNodeFinding("CVE-1", "undici", "6.28.0", npmUndici)}),
			imageScan(nil, langPackages(typeNodePkg, scanner.Package{Name: "undici", Version: "6.28.0", PkgPath: npmUndici})),
			rbSeverities, nil)
		if c.Status != RebuildPartial || c.Undetermined != 1 || len(c.Gone) != 0 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("a finding the base has without a fix remains", func(t *testing.T) {
		unfixed := rbNodeFinding("CVE-1", "undici", "6.29.1", npmUndici)
		unfixed.Status, unfixed.FixedVer = scanner.StatusAffected, ""
		c := classifyRebuild(
			imageScan([]scanner.Finding{rbNodeFinding("CVE-1", "undici", "6.28.0", npmUndici)}),
			imageScan([]scanner.Finding{unfixed}, langPackages(typeNodePkg, scanner.Package{Name: "undici", Version: "6.29.1", PkgPath: npmUndici})),
			rbSeverities, nil)
		if len(c.Remaining) != 1 || len(c.Gone) != 0 || len(c.OnlyInBase) != 0 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("what the running image has without a fix or out of range is left out", func(t *testing.T) {
		unfixed := rbNodeFinding("CVE-1", "undici", "6.28.0", npmUndici)
		unfixed.Status, unfixed.FixedVer = scanner.StatusAffected, ""
		low := rbNodeFinding("CVE-2", "undici", "6.28.0", npmUndici)
		low.Severity = scanner.SeverityLow
		c := classifyRebuild(imageScan([]scanner.Finding{unfixed, low}), imageScan(nil), rbSeverities, nil)
		if c.Status != RebuildChecked || len(c.NotInBase) != 0 || c.OtherNotInBase != 0 || c.Undetermined != 0 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("new in the base", func(t *testing.T) {
		c := classifyRebuild(
			imageScan([]scanner.Finding{rbNodeFinding("CVE-U", "undici", "6.28.0", npmUndici)}),
			imageScan([]scanner.Finding{rbNodeFinding("CVE-U", "undici", "6.28.0", npmUndici), rbNodeFinding("CVE-N", "undici", "6.28.0", npmUndici), rbNodeFinding("CVE-B", "brace-expansion", "5.0.9", npmBrace)},
				langPackages(typeNodePkg, scanner.Package{Name: "undici", Version: "6.28.0", PkgPath: npmUndici})),
			rbSeverities, nil)
		if got, want := pkgNames(c.OnlyInBase), []string{"brace-expansion 5.0.9", "undici 6.28.0"}; !reflect.DeepEqual(got, want) {
			t.Errorf("only in base %v", got)
		}
	})
	t.Run("the application's dependencies are only counted", func(t *testing.T) {
		c := classifyRebuild(
			imageScan([]scanner.Finding{rbNodeFinding("CVE-1", "multer", "1.0.0", "app/node_modules/multer/package.json")}),
			imageScan(nil), rbSeverities, nil)
		if c.Status != RebuildChecked || c.OtherNotInBase != 1 || len(c.NotInBase) != 0 {
			t.Errorf("%+v", c)
		}
	})
}

func TestClassifyRebuild_OSPackages(t *testing.T) {
	osFinding := func(vuln, name, ver, target string) scanner.Finding {
		f := finding(vuln, name, ver, "9", scanner.SeverityHigh)
		f.Target = target
		return f
	}
	osPackages := func(pairs ...string) scanner.ResultPackages {
		rp := pkgs(pairs...)[0]
		rp.Target = "python:3.12-slim (debian 12)"
		return rp
	}
	running := []scanner.Finding{
		osFinding("CVE-1", "libc", "1", "myapp:1 (debian 12)"),
		osFinding("CVE-2", "openssl", "1", "myapp:1 (debian 12)"),
		osFinding("CVE-3", "curl", "1", "myapp:1 (debian 12)"),
		osFinding("CVE-4", "zlib", "1", "myapp:1 (debian 12)"),
	}
	baseFindings := []scanner.Finding{osFinding("CVE-1", "libc", "1", "python:3.12-slim (debian 12)")}

	base := imageScan(baseFindings, osPackages("libc", "1", "openssl", "2", "zlib", "1"))
	c := classifyRebuild(imageScan(running), base, rbSeverities, nil)
	if got := pkgNames(c.Remaining); !reflect.DeepEqual(got, []string{"libc 1"}) {
		t.Errorf("a different target label: remaining %v", got)
	}
	if len(c.Gone) != 1 || c.Gone[0].Name != "openssl" || c.Gone[0].BaseVersion != "2" {
		t.Errorf("gone %+v", c.Gone)
	}
	if got := pkgNames(c.NotInBase); !reflect.DeepEqual(got, []string{"curl 1"}) {
		t.Errorf("not in base %v", got)
	}
	if c.Status != RebuildPartial || c.Undetermined != 1 {
		t.Errorf("the same version without the finding: %s, %d", c.Status, c.Undetermined)
	}

	base.OSFamily = ""
	c = classifyRebuild(imageScan(running), base, rbSeverities, nil)
	if c.Status != RebuildPartial || c.Undetermined != 4 || len(c.Remaining) != 0 || len(c.NotInBase) != 0 || len(c.Gone) != 0 {
		t.Errorf("an unidentified OS: %+v", c)
	}
}

func TestPlaceOf(t *testing.T) {
	same := func(t *testing.T, typ, verA, pathA, verB, pathB string, want bool) {
		t.Helper()
		a, okA := placeOf(typ, inventory.ClassLang, "foo", verA, pathA, "")
		b, okB := placeOf(typ, inventory.ClassLang, "foo", verB, pathB, "")
		if !okA || !okB || (a == b) != want {
			t.Errorf("%s and %s: %+v, %+v", pathA, pathB, a, b)
		}
	}
	t.Run("python metadata directory", func(t *testing.T) {
		same(t, typePythonPkg, "25.0.1", "usr/local/lib/python3.12/site-packages/pip-25.0.1.dist-info/METADATA",
			"25.3", "usr/local/lib/python3.12/site-packages/pip-25.3.dist-info/METADATA", true)
		same(t, typePythonPkg, "1.0", "site-packages/foo-1.0-py3.12.egg-info/PKG-INFO", "2.0", "site-packages/foo-2.0-py3.12.egg-info/PKG-INFO", true)
		same(t, typePythonPkg, "25.0", "lib/python3.12/site-packages/pip-25.0.dist-info/METADATA", "25.0", "lib/python3.13/site-packages/pip-25.0.dist-info/METADATA", false)
	})
	t.Run("a version in a parent directory is not the package's", func(t *testing.T) {
		same(t, typeJar, "1.0", "opt/app-1.0/lib/foo.jar", "2.0", "opt/app-2.0/lib/foo.jar", false)
		same(t, typeJar, "1.0", "opt/app-1.0/lib/foo-1.0.jar", "2.0", "opt/app-2.0/lib/foo-2.0.jar", false)
		same(t, typePythonPkg, "1.0", "opt/app-1.0/site-packages/foo-1.0.dist-info/METADATA", "2.0", "opt/app-2.0/site-packages/foo-2.0.dist-info/METADATA", false)
	})
	t.Run("the file name of a java archive", func(t *testing.T) {
		same(t, typeJar, "1.0", "app/lib/foo-1.0.jar", "2.0", "app/lib/foo-2.0.jar", true)
		same(t, typeJar, "1.0", "app/app.jar", "2.0", "app/app.jar", true)
	})
	t.Run("digits in the name of the package", func(t *testing.T) {
		same(t, typeJar, "1.0", "app/lib/foo-1.0-1.0.jar", "2.0", "app/lib/foo-1.0-2.0.jar", true)
		same(t, typePythonPkg, "1.0", "site/foo-1.0-1.0.dist-info/METADATA", "2.0", "site/foo-1.0-2.0.dist-info/METADATA", true)
	})
	t.Run("a version that is only a part of a longer one", func(t *testing.T) {
		if got := versionlessPath(typePythonPkg, "1.0", "foo-1.0.1.dist-info/METADATA"); got != "foo-*.1.dist-info/METADATA" {
			// "1.0" followed by "." is taken as the version: the scanner's
			// own version of the package decides, so this does not occur for
			// a package reported as 1.0.1.
			t.Errorf("got %q", got)
		}
		if got := versionlessPath(typePythonPkg, "1.0", "foo-1.01.dist-info/METADATA"); got != "foo-1.01.dist-info/METADATA" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("node paths stay as they are", func(t *testing.T) {
		same(t, typeNodePkg, "1.0", "app-1.0/node_modules/foo/package.json", "2.0", "app-2.0/node_modules/foo/package.json", false)
	})
	t.Run("no place without a path", func(t *testing.T) {
		for _, typ := range []string{typeNodePkg, typePythonPkg, typeJar} {
			if _, ok := placeOf(typ, inventory.ClassLang, "foo", "1", "", "usr/lib/foo"); ok {
				t.Errorf("%s has a place without a path", typ)
			}
		}
		if _, ok := placeOf("gobinary", inventory.ClassLang, "foo", "1", "", "Python"); ok {
			t.Errorf("a label is a place")
		}
		if p, ok := placeOf("gobinary", inventory.ClassLang, "foo", "1", "", "usr/local/bin/app"); !ok || p.place != "usr/local/bin/app" {
			t.Errorf("a binary: %+v", p)
		}
	})
}

func TestClassifyRebuild_Undetermined(t *testing.T) {
	t.Run("an empty path never matches an empty path", func(t *testing.T) {
		c := classifyRebuild(
			imageScan([]scanner.Finding{rbNodeFinding("CVE-1", "undici", "6.28.0", "")}),
			imageScan(nil, langPackages(typeNodePkg, scanner.Package{Name: "undici", Version: "6.29.1"})),
			rbSeverities, nil)
		if c.Status != RebuildPartial || c.Undetermined != 1 || len(c.Gone) != 0 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("two packages in one place", func(t *testing.T) {
		c := classifyRebuild(
			imageScan([]scanner.Finding{rbLangFinding(typeJar, "CVE-1", "foo", "1.0", "app/lib/foo-1.0.jar")}),
			imageScan(nil, langPackages(typeJar,
				scanner.Package{Name: "foo", Version: "2.0", PkgPath: "app/lib/foo-2.0.jar"},
				scanner.Package{Name: "foo", Version: "3.0", PkgPath: "app/lib/foo-3.0.jar"})),
			rbSeverities, nil)
		if c.Status != RebuildPartial || len(c.Gone) != 0 {
			t.Errorf("%+v", c)
		}
		c = classifyRebuild(
			imageScan([]scanner.Finding{rbLangFinding(typeJar, "CVE-1", "foo", "1.0", "app/lib/foo-1.0.jar")}),
			imageScan([]scanner.Finding{rbLangFinding(typeJar, "CVE-1", "foo", "3.0", "app/lib/foo-3.0.jar")}, langPackages(typeJar,
				scanner.Package{Name: "foo", Version: "2.0", PkgPath: "app/lib/foo-2.0.jar"},
				scanner.Package{Name: "foo", Version: "3.0", PkgPath: "app/lib/foo-3.0.jar"})),
			rbSeverities, nil)
		if c.Status != RebuildPartial || c.Undetermined != 1 || len(c.Remaining) != 0 {
			t.Errorf("with the finding in one of them: %+v", c)
		}
	})
	gem := func(path, target string) scanner.Finding {
		f := rbLangFinding("gemspec", "CVE-1", "foo", "1.0", path)
		f.Target = target
		return f
	}
	t.Run("a type of unknown paths with the name elsewhere", func(t *testing.T) {
		c := classifyRebuild(
			imageScan([]scanner.Finding{gem("specs/foo-1.0.gemspec", "")}),
			imageScan(nil, langPackages("gemspec", scanner.Package{Name: "foo", Version: "2.0", PkgPath: "specs/foo-2.0.gemspec"})),
			rbSeverities, nil)
		if c.Status != RebuildPartial || c.OtherNotInBase != 0 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("a type of unknown paths without the name", func(t *testing.T) {
		c := classifyRebuild(imageScan([]scanner.Finding{gem("specs/foo-1.0.gemspec", "")}), imageScan(nil), rbSeverities, nil)
		if c.Status != RebuildChecked || c.OtherNotInBase != 1 {
			t.Errorf("%+v", c)
		}
	})
	t.Run("runtimes are left to their own check", func(t *testing.T) {
		running := imageScan([]scanner.Finding{runtimeFinding("CVE-R", "3.12.3")})
		c := classifyRebuild(running, imageScan(nil), rbSeverities, []RuntimeRebuild{{Package: pyRuntime, Installed: "3.12.3", Remaining: []string{"CVE-R"}}})
		if c.Status != RebuildChecked || c.OtherNotInBase != 0 {
			t.Errorf("checked runtime: %+v", c)
		}
		c = classifyRebuild(running, imageScan(nil), rbSeverities, nil)
		if c.Status != RebuildPartial || c.Undetermined != 1 {
			t.Errorf("unchecked runtime: %+v", c)
		}
		// The rescan found what the runtime's check did not name.
		c = classifyRebuild(imageScan([]scanner.Finding{runtimeFinding("CVE-R", "3.12.3"), runtimeFinding("CVE-S", "3.12.3")}), imageScan(nil), rbSeverities,
			[]RuntimeRebuild{{Package: pyRuntime, Installed: "3.12.3", Disappearing: []string{"CVE-R"}}})
		if c.Status != RebuildPartial || c.Undetermined != 1 {
			t.Errorf("a finding the check does not name: %+v", c)
		}
		c = classifyRebuild(running, imageScan(nil), rbSeverities, []RuntimeRebuild{{Package: pyRuntime, Installed: "3.12.9", Remaining: []string{"CVE-R"}}})
		if c.Status != RebuildPartial {
			t.Errorf("another version: %+v", c)
		}
	})
}

func TestMergeRebuildChecks(t *testing.T) {
	pkg := func(name string, vulns ...string) RebuildPackage {
		return RebuildPackage{Name: name, Version: "1", Class: inventory.ClassLang, Path: name, BaseVersion: "", VulnIDs: vulns}
	}
	ents := func(cs ...*RebuildCheck) []DockerfileEntity {
		var out []DockerfileEntity
		for _, c := range cs {
			out = append(out, DockerfileEntity{RebuildCheck: c})
		}
		return out
	}
	t.Run("a finding gone is gone only when no image has it", func(t *testing.T) {
		got := mergeRebuildChecks(ents(
			&RebuildCheck{Status: RebuildChecked, Gone: []RebuildPackage{pkg("a", "CVE-1", "CVE-2"), pkg("b", "CVE-3"), pkg("c", "CVE-4")}, OtherNotInBase: 2},
			&RebuildCheck{Status: RebuildChecked, Remaining: []RebuildPackage{pkg("a", "CVE-1")}, NotInBase: []RebuildPackage{pkg("b", "CVE-3")}, OtherNotInBase: 1},
		))
		if got.Status != RebuildChecked || len(got.Gone) != 2 || got.Gone[0].Name != "a" || !reflect.DeepEqual(got.Gone[0].VulnIDs, []string{"CVE-2"}) || got.Gone[1].Name != "c" {
			t.Errorf("gone %+v", got.Gone)
		}
		if len(got.Remaining) != 1 || len(got.NotInBase) != 1 || got.OtherNotInBase != 2 {
			t.Errorf("%+v", got)
		}
	})
	t.Run("a finding gone from one image and only counted in another is not gone", func(t *testing.T) {
		goneA := pkg("a", "CVE-1")
		goneA.BaseVersion = "2"
		other := classifyRebuild(
			imageScan([]scanner.Finding{rbLangFinding(typeJar, "CVE-1", "a", "1", "a")}), imageScan(nil), rbSeverities, nil)
		if other.OtherNotInBase != 1 {
			t.Fatalf("%+v", other)
		}
		got := mergeRebuildChecks(ents(&RebuildCheck{Status: RebuildChecked, Gone: []RebuildPackage{goneA}}, other))
		if got.Status != RebuildChecked || len(got.Gone) != 0 || got.OtherNotInBase != 1 {
			t.Errorf("other: %+v", got)
		}
		unknown := classifyRebuild(
			imageScan([]scanner.Finding{rbLangFinding(typeJar, "CVE-1", "a", "1", "")}), imageScan(nil), rbSeverities, nil)
		unknown.unsettled[0].Path = "a"
		got = mergeRebuildChecks(ents(&RebuildCheck{Status: RebuildChecked, Gone: []RebuildPackage{goneA}}, unknown))
		if got.Status != RebuildPartial || len(got.Gone) != 0 {
			t.Errorf("undetermined: %+v", got)
		}
	})
	t.Run("each version the base moved to is kept, in a stable order", func(t *testing.T) {
		to := func(v string) *RebuildCheck {
			p := pkg("openssl", "CVE-1")
			p.BaseVersion = v
			return &RebuildCheck{Status: RebuildChecked, Gone: []RebuildPackage{p}}
		}
		a, b := mergeRebuildChecks(ents(to("2"), to("3"))), mergeRebuildChecks(ents(to("3"), to("2")))
		if len(a.Gone) != 2 || a.Gone[0].BaseVersion != "2" || a.Gone[1].BaseVersion != "3" || !reflect.DeepEqual(a.Gone, b.Gone) {
			t.Errorf("%+v, %+v", a.Gone, b.Gone)
		}
	})
	t.Run("the weakest status decides", func(t *testing.T) {
		got := mergeRebuildChecks(ents(&RebuildCheck{Status: RebuildChecked}, &RebuildCheck{Status: RebuildPartial, Undetermined: 3}))
		if got.Status != RebuildPartial || got.Undetermined != 3 {
			t.Errorf("%+v", got)
		}
		got = mergeRebuildChecks(ents(&RebuildCheck{Status: RebuildPartial, Gone: []RebuildPackage{pkg("a", "CVE-1")}}, &RebuildCheck{Status: RebuildNotChecked, Reason: ReasonScanFailed}))
		if got.Status != RebuildNotChecked || got.Reason != ReasonScanFailed || len(got.Gone) != 0 {
			t.Errorf("%+v", got)
		}
		if got = mergeRebuildChecks(ents(&RebuildCheck{Status: RebuildChecked}, nil)); got.Status != RebuildNotChecked {
			t.Errorf("%+v", got)
		}
	})
}

// floatingEnv is a Dockerfile whose floating tag moved away from the running
// images, with a scan of the base it points at now.
func floatingEnv(baseFindings []scanner.Finding, basePkgs []scanner.ResultPackages) *dfEnv {
	e := newDFEnv()
	e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12-slim\nCOPY . /app\n")
	e.base("3.12-slim", baseResolution('1', '2', '9', 'b'), baseFindings, basePkgs)
	return e
}

func (e *dfEnv) stagePlan(t *testing.T, ctx context.Context, lim Limits, prep scanner.ScanConditions, inputs ...ImageInput) (Plan, RebuildCheckSummary) {
	t.Helper()
	p, err := NewPlanner(Config{
		Registry: e.reg, Scanner: e.scn, Prepared: prep, Limits: lim, GitHub: e.gh,
		Dockerfiles: []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", ""), dfMapping("compose/p/worker", "Dockerfile", "")},
		Now:         func() time.Time { return time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := p.Plan(context.Background(), inputs)
	sum := p.CheckRebuildBases(ctx, &plan, RebuildCheckOptions{})
	return plan, sum
}

func (e *dfEnv) scansOf(ref string) int {
	n := 0
	for _, c := range e.scn.calls {
		if strings.Contains(c, ref) {
			n++
		}
	}
	return n
}

func TestCheckRebuildBases(t *testing.T) {
	libc := func() scanner.Finding { return finding("CVE-A", "libc", "1", "2", scanner.SeverityHigh) }
	openssl := func() scanner.Finding { return finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh) }
	baseFs := []scanner.Finding{libc()}
	basePk := pkgs("libc", "1", "openssl", "2")

	t.Run("recorded on the entity and the item, the outcome unchanged", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		plan, sum := e.stagePlan(t, context.Background(), bigLimits, prepared, dfInput("myapp:1", 'a', "app", appLayers, libc(), openssl()))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryNotComparable || it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Fatalf("item = %s/%s", it.Category, it.Reason)
		}
		c := it.RebuildCheck
		if c == nil || c.Status != RebuildChecked || pkgNames(c.Remaining)[0] != "libc 1" || !c.HasGone() || c.Gone[0].BaseVersion != "2" {
			t.Fatalf("item check %+v", c)
		}
		ec := it.Entities[0].RebuildCheck
		if ec == nil || ec.RunningScan == "" || ec.BaseScan == "" || ec.RunningScan == ec.BaseScan {
			t.Errorf("entity check %+v", ec)
		}
		if sum.Items != 1 || sum.Checked != 1 || sum.BaselineRescans != 1 || plan.Usage.BaselineRescans != 1 {
			t.Errorf("summary %+v usage %+v", sum, plan.Usage)
		}
		if it.FinalImageVerified {
			t.Errorf("the rebuilt image is not verified")
		}
	})
	t.Run("two images share one scan of the base", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		plan, sum := e.stagePlan(t, context.Background(), bigLimits, prepared,
			dfInput("myapp:1", 'a', "app", appLayers, libc()), dfInput("myworker:1", 'b', "worker", []byte{'a', 'd', 'c'}, libc(), openssl()))
		it := onlyDockerfile(t, plan)
		if len(it.Entities) != 2 || it.RebuildCheck.Status != RebuildChecked {
			t.Fatalf("%+v", it.RebuildCheck)
		}
		if n := e.scansOf("python:3.12-slim"); n != 1 || sum.BaselineRescans != 1 {
			t.Errorf("%d scans of the base, summary %+v", n, sum)
		}
	})
	t.Run("the scan limit leaves it not checked", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		lim := bigLimits
		lim.MaxBaselineRescans = 0
		plan, sum := e.stagePlan(t, context.Background(), lim, prepared, dfInput("myapp:1", 'a', "app", appLayers, libc()))
		it := onlyDockerfile(t, plan)
		if it.RebuildCheck.Status != RebuildNotChecked || it.RebuildCheck.Reason != ReasonBaselineRescanLimit || it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Errorf("%+v, %s", it.RebuildCheck, it.Reason)
		}
		if sum.NotChecked != 1 || e.scansOf("python:3.12-slim") != 0 {
			t.Errorf("summary %+v, calls %v", sum, e.scn.calls)
		}
	})
	t.Run("both scans must fit in the limit before either is spent", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		lim := bigLimits
		lim.MaxBaselineRescans = 1
		older := prepared
		older.VulnerabilityDBSHA = "older"
		in := dfInput("myapp:1", 'a', "app", appLayers, libc())
		in.Conditions = older
		plan, _ := e.stagePlan(t, context.Background(), lim, prepared, in)
		if it := onlyDockerfile(t, plan); it.RebuildCheck.Reason != ReasonBaselineRescanLimit {
			t.Errorf("%+v", it.RebuildCheck)
		}
		if plan.Usage.BaselineRescans != 0 {
			t.Errorf("spent %d", plan.Usage.BaselineRescans)
		}
	})
	t.Run("a running scan under other conditions is taken again", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		older := prepared
		older.VulnerabilityDBSHA = "older"
		in := dfInput("myapp:1", 'a', "app", appLayers, libc())
		in.Conditions = older
		e.scn.scans["myapp:1"] = func(tg scanner.ScanTarget) scanner.ImageScan { return in.Scan }
		plan, _ := e.stagePlan(t, context.Background(), bigLimits, prepared, in)
		it := onlyDockerfile(t, plan)
		if it.RebuildCheck.Status != RebuildChecked || plan.Usage.BaselineRescans != 2 {
			t.Errorf("%+v, usage %+v", it.RebuildCheck, plan.Usage)
		}
	})
	t.Run("a failed scan of the base leaves it not checked", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		delete(e.scn.scans, "python:3.12-slim")
		plan, _ := e.stagePlan(t, context.Background(), bigLimits, prepared, dfInput("myapp:1", 'a', "app", appLayers, libc()))
		it := onlyDockerfile(t, plan)
		if it.RebuildCheck.Status != RebuildNotChecked || it.RebuildCheck.Reason != ReasonScanFailed {
			t.Errorf("%+v", it.RebuildCheck)
		}
		if it.Entities[0].RebuildCheck.BaseScan == "" {
			t.Errorf("the failed scan is not named: %+v", it.Entities[0].RebuildCheck)
		}
	})
	t.Run("a stage out of time scans nothing", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		plan, sum := e.stagePlan(t, ctx, bigLimits, prepared, dfInput("myapp:1", 'a', "app", appLayers, libc()))
		if it := onlyDockerfile(t, plan); it.RebuildCheck.Status != RebuildNotChecked || sum.NotChecked != 1 {
			t.Errorf("%+v", it.RebuildCheck)
		}
		if e.scansOf("python:3.12-slim") != 0 {
			t.Errorf("calls %v", e.scn.calls)
		}
	})
	t.Run("no conditions, no check", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		plan, _ := e.stagePlan(t, context.Background(), bigLimits, scanner.ScanConditions{}, dfInput("myapp:1", 'a', "app", appLayers, libc()))
		if it := onlyDockerfile(t, plan); it.RebuildCheck.Reason != ReasonConditionsUnknown {
			t.Errorf("%+v", it.RebuildCheck)
		}
	})
	t.Run("the item only when its images all moved", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		plan, sum := e.stagePlan(t, context.Background(), bigLimits, prepared,
			dfInput("myapp:1", 'a', "app", []byte{'9', 'b', 'c'}, libc()), dfInput("myworker:1", 'b', "worker", appLayers, libc()))
		it := onlyDockerfile(t, plan)
		if it.Category != CategoryManual || it.RebuildCheck != nil || sum.Items != 0 {
			t.Errorf("%s, %+v, %+v", it.Category, it.RebuildCheck, sum)
		}
		if it.Entities[0].RebuildCheck != nil || it.Entities[1].RebuildCheck == nil || it.Entities[1].RebuildCheck.Status != RebuildChecked {
			t.Errorf("each image for itself: %+v, %+v", it.Entities[0].RebuildCheck, it.Entities[1].RebuildCheck)
		}
		e = newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12-slim\nCOPY . /app\n")
		e.base("3.12-slim", baseResolution('1', '2', 'a', 'b'), baseFs, basePk)
		plan, _ = e.stagePlan(t, context.Background(), bigLimits, prepared, dfInput("myapp:1", 'a', "app", appLayers, libc()))
		if it := onlyDockerfile(t, plan); it.Reason != ReasonBaseUnchanged || it.RebuildCheck != nil {
			t.Errorf("an unchanged base: %s, %+v", it.Reason, it.RebuildCheck)
		}
	})
	t.Run("it continues the plan the stages before it left", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		p, err := NewPlanner(Config{
			Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, GitHub: e.gh,
			Dockerfiles: []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")},
			Now:         func() time.Time { return time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatal(err)
		}
		plan := p.Plan(context.Background(), []ImageInput{dfInput("myapp:1", 'a', "app", appLayers, libc())})
		p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{})
		later := Item{Key: "added after the plan"}
		plan.Items = append(plan.Items, later)
		rescans := plan.Usage.BaselineRescans
		sum := p.CheckRebuildBases(context.Background(), &plan, RebuildCheckOptions{})
		if len(plan.Items) == 0 || plan.Items[len(plan.Items)-1].Key != later.Key {
			t.Errorf("a change made after the plan was lost: %+v", plan.Items)
		}
		if it := onlyDockerfile(t, plan); it.RebuildCheck == nil || it.RebuildCheck.Status != RebuildChecked {
			t.Errorf("%+v", it.RebuildCheck)
		}
		if plan.Usage.BaselineRescans != rescans+sum.BaselineRescans || sum.BaselineRescans != 1 {
			t.Errorf("usage %+v, summary %+v, before %d", plan.Usage, sum, rescans)
		}
	})
	t.Run("the time reserved for later work ends it", func(t *testing.T) {
		e := floatingEnv(baseFs, basePk)
		p, err := NewPlanner(Config{
			Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, GitHub: e.gh,
			Dockerfiles: []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")},
			Now:         func() time.Time { return time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatal(err)
		}
		plan := p.Plan(context.Background(), []ImageInput{dfInput("myapp:1", 'a', "app", appLayers, libc())})
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		sum := p.CheckRebuildBases(ctx, &plan, RebuildCheckOptions{ReserveTime: 2 * time.Hour})
		if it := onlyDockerfile(t, plan); it.RebuildCheck.Status != RebuildNotChecked || it.RebuildCheck.Reason != ReasonNewerSeriesReserved || sum.NotChecked != 1 {
			t.Errorf("%+v, %+v", it.RebuildCheck, sum)
		}
		if e.scansOf("python:3.12-slim") != 0 {
			t.Errorf("calls %v", e.scn.calls)
		}
	})
	t.Run("without a Plan call it does nothing", func(t *testing.T) {
		e := newDFEnv()
		p, err := NewPlanner(Config{Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits})
		if err != nil {
			t.Fatal(err)
		}
		var plan Plan
		if sum := p.CheckRebuildBases(context.Background(), &plan, RebuildCheckOptions{}); sum != (RebuildCheckSummary{}) {
			t.Errorf("%+v", sum)
		}
	})
}

func TestFingerprint_RebuildCheck(t *testing.T) {
	plan := func(c *RebuildCheck) Plan {
		return Plan{DockerfileItems: []DockerfileItem{{Key: "k", Category: CategoryNotComparable, Reason: ReasonFloatingBaseUnconfirmed, RebuildCheck: c,
			Entities: []DockerfileEntity{{Running: ImageState{Ref: "a"}, RebuildCheck: c}}}}}
	}
	remaining := func(vulns ...string) []RebuildPackage {
		return []RebuildPackage{{Name: "undici", Version: "6.28.0", Path: npmUndici, VulnIDs: vulns}}
	}
	a := Fingerprint(plan(&RebuildCheck{Status: RebuildChecked, Remaining: remaining("CVE-1"), RunningScan: "s1", BaseScan: "s2"}))
	if b := Fingerprint(plan(&RebuildCheck{Status: RebuildChecked, Remaining: remaining("CVE-1", "CVE-2"), RunningScan: "s3", BaseScan: "s4"})); a != b {
		t.Errorf("a new finding of a package in the same outcome changes the fingerprint")
	}
	for name, c := range map[string]*RebuildCheck{
		"status":  {Status: RebuildPartial, Remaining: remaining("CVE-1")},
		"outcome": {Status: RebuildChecked, Gone: remaining("CVE-1")},
		"none":    nil,
	} {
		if Fingerprint(plan(c)) == a {
			t.Errorf("%s: the fingerprint stays", name)
		}
	}
}
