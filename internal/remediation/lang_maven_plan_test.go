package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func jarFinding(vuln, pkgPath, name, installed, fixed string) scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: typeJar, Target: "Java", Package: name, PkgPath: pkgPath,
		InstalledVer: installed, FixedVer: fixed, Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: vuln,
	}
}

// jarPackages is the archive list of a scan: name, version and path triples.
func jarPackages(triples ...string) scanner.ResultPackages {
	rp := scanner.ResultPackages{Target: "Java", Class: inventory.ClassLang, Type: typeJar}
	for i := 0; i+2 < len(triples); i += 3 {
		rp.Packages = append(rp.Packages, scanner.Package{Name: triples[i], Version: triples[i+1], PkgPath: triples[i+2]})
	}
	return rp
}

const bootLib = "app/app.jar/BOOT-INF/lib/"

// fatJarInput is a scanned image with a Spring Boot archive of
// com.example:demo and a tool's archive outside it.
func fatJarInput(fs ...scanner.Finding) ImageInput {
	in := langInput("shop", "api", fs...)
	in.Scan.Packages = []scanner.ResultPackages{jarPackages(
		"com.example:demo", "0.0.1-SNAPSHOT", "app/app.jar",
		"com.fasterxml.jackson.core:jackson-databind", "2.13.3", bootLib+"jackson-databind-2.13.3.jar",
		"org.yaml:snakeyaml", "1.30", bootLib+"snakeyaml-1.30.jar",
		"org.jctools:jctools-core", "3.1.0", bootLib+"netty-common-4.1.77.Final.jar",
		"org.apache.commons:commons-text", "1.9", "opt/tool/lib/commons-text-1.9.jar",
	)}
	return in
}

const bootPom = `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.0</version>
    <relativePath/>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
  </dependencies>
</project>`

func mavenPlanItem(t *testing.T, gh *fakeGitHub, dir string, in ...ImageInput) (LanguageItem, bool) {
	t.Helper()
	plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", dir)}, nil, in...)
	for _, it := range plan.LanguageItems {
		if it.Manager == ManagerMaven || strings.HasSuffix(it.Key, "#"+typeJar) {
			return it, true
		}
	}
	return LanguageItem{}, false
}

func pkgsByName(it LanguageItem) map[string]LanguagePackage {
	got := map[string]LanguagePackage{}
	for _, p := range it.Packages {
		got[p.Name] = p
	}
	return got
}

func TestLanguagePlan_MavenFatJar(t *testing.T) {
	gh := newFakeGitHub()
	gh.put("ex/app", "svc", "pom.xml", bootPom)
	it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(
		jarFinding("CVE-JACKSON", bootLib+"jackson-databind-2.13.3.jar", "com.fasterxml.jackson.core:jackson-databind", "2.13.3", "2.12.7.1, 2.13.4.2"),
		jarFinding("CVE-YAML", bootLib+"snakeyaml-1.30.jar", "org.yaml:snakeyaml", "1.30", "1.31"),
		jarFinding("CVE-JCT", bootLib+"netty-common-4.1.77.Final.jar", "org.jctools:jctools-core", "3.1.0", "3.1.1"),
		jarFinding("CVE-TOOL", "opt/tool/lib/commons-text-1.9.jar", "org.apache.commons:commons-text", "1.9", "1.10.0"),
	))
	if !ok {
		t.Fatal("no Maven item")
	}
	if it.Manager != ManagerMaven || it.Category != CategoryDependencyUpdateCandidate || it.Key != "deps:ex/app@main:svc#maven" {
		t.Fatalf("item = %s %s %s (%s)", it.Key, it.Category, it.Reason, it.Detail)
	}
	got := pkgsByName(it)
	if len(got) != 3 {
		t.Fatalf("packages = %+v; the tool's archive outside the application must be left out", it.Packages)
	}
	if p := got["com.fasterxml.jackson.core:jackson-databind"]; p.Action != ActionUpdate || p.SelectionLowerBound != "2.13.4.2" || p.Relation != RelationDirect {
		t.Errorf("jackson = %+v", p)
	}
	if p := got["org.yaml:snakeyaml"]; p.Action != ActionUpdate || p.SelectionLowerBound != "1.31" || p.Relation != RelationTransitive {
		t.Errorf("snakeyaml = %+v", p)
	}
	if p := got["org.jctools:jctools-core"]; p.Action != ActionManual || p.Reason != ReasonJarBundled {
		t.Errorf("jctools = %+v", p)
	}
	for _, want := range []string{"svc/.mvn/maven.config", "svc/.mvn/extensions.xml", "pom.xml"} {
		if !containsString(it.Source.Absent, want) {
			t.Errorf("absent = %v, want %s", it.Source.Absent, want)
		}
	}
	if len(it.Source.Files) != 1 || it.Source.Files[0].Path != "svc/pom.xml" {
		t.Errorf("files = %+v", it.Source.Files)
	}
}

func TestLanguagePlan_MavenNoPomNoItem(t *testing.T) {
	gh := newFakeGitHub()
	gh.put("ex/app", "svc", "package.json", `{}`)
	if it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(
		jarFinding("CVE-YAML", bootLib+"snakeyaml-1.30.jar", "org.yaml:snakeyaml", "1.30", "1.31"),
	)); ok {
		t.Fatalf("a directory without pom.xml has a Maven item: %+v", it)
	}
}

const reactorRoot = `<project>
  <groupId>com.example.multi</groupId>
  <artifactId>multi-parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules><module>lib</module><module>app</module></modules>
  <properties><text.version>1.9</text.version></properties>
</project>`

const reactorLib = `<project>
  <parent><groupId>com.example.multi</groupId><artifactId>multi-parent</artifactId><version>1.0.0</version></parent>
  <artifactId>lib</artifactId>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${text.version}</version></dependency>
  </dependencies>
</project>`

const reactorApp = `<project>
  <parent><groupId>com.example.multi</groupId><artifactId>multi-parent</artifactId><version>1.0.0</version></parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency><groupId>${project.groupId}</groupId><artifactId>lib</artifactId><version>${project.version}</version></dependency>
  </dependencies>
</project>`

func reactorRepo(gh *fakeGitHub, lib string) {
	gh.put("ex/app", ".", "pom.xml", reactorRoot)
	gh.putEntry("ex/app", ".", github.Entry{Name: "lib", Type: github.EntryDir})
	gh.putEntry("ex/app", ".", github.Entry{Name: "app", Type: github.EntryDir})
	gh.put("ex/app", "lib", "pom.xml", lib)
	gh.put("ex/app", "app", "pom.xml", reactorApp)
}

// jibInput is a scanned image laid out without an archive of the
// application.
func jibInput(fs ...scanner.Finding) ImageInput {
	in := langInput("shop", "api", fs...)
	in.Scan.Packages = []scanner.ResultPackages{jarPackages(
		"org.apache.commons:commons-text", "1.9", "app/libs/commons-text-1.9.jar",
		"com.example.multi:lib", "1.0.0", "app/libs/lib-1.0.0.jar",
	)}
	return in
}

func TestLanguagePlan_MavenReactor(t *testing.T) {
	text := jarFinding("CVE-TEXT", "app/libs/commons-text-1.9.jar", "org.apache.commons:commons-text", "1.9", "1.10.0")
	t.Run("a module's archive beside the dependencies is a library", func(t *testing.T) {
		gh := newFakeGitHub()
		reactorRepo(gh, reactorLib)
		it, ok := mavenPlanItem(t, gh, ".", jibInput(text))
		if !ok || it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %+v", it)
		}
		if p := pkgsByName(it)["org.apache.commons:commons-text"]; p.Action != ActionUpdate || p.Occurrences[0].Path != "lib/pom.xml" {
			t.Errorf("commons-text = %+v", p)
		}
	})
	t.Run("an application archive with a sibling module nested", func(t *testing.T) {
		gh := newFakeGitHub()
		reactorRepo(gh, reactorLib)
		nested := jarFinding("CVE-TEXT", bootLib+"commons-text-1.9.jar", "org.apache.commons:commons-text", "1.9", "1.10.0")
		in := langInput("shop", "api", nested, jarFinding("CVE-TOOL", "opt/tool/lib/commons-text-1.9.jar", "org.apache.commons:commons-text", "1.9", "1.10.0"))
		in.Scan.Packages = []scanner.ResultPackages{jarPackages(
			"com.example.multi:app", "1.0.0", "app/app.jar",
			"com.example.multi:lib", "1.0.0", bootLib+"lib-1.0.0.jar",
			"org.apache.commons:commons-text", "1.9", bootLib+"commons-text-1.9.jar",
			"org.apache.commons:commons-text", "1.9", "opt/tool/lib/commons-text-1.9.jar",
		)}
		it, ok := mavenPlanItem(t, gh, ".", in)
		if !ok || it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %+v", it)
		}
		p := pkgsByName(it)["org.apache.commons:commons-text"]
		if p.Action != ActionUpdate || p.Occurrences[0].Path != "lib/pom.xml" || len(p.Origins) != 1 || p.Origins[0].PkgPath != bootLib+"commons-text-1.9.jar" {
			t.Errorf("commons-text = %+v", p)
		}
	})
	t.Run("no archive of a module: every module is searched", func(t *testing.T) {
		gh := newFakeGitHub()
		reactorRepo(gh, reactorLib)
		in := jibInput(text)
		in.Scan.Packages = []scanner.ResultPackages{jarPackages("org.apache.commons:commons-text", "1.9", "app/libs/commons-text-1.9.jar")}
		it, ok := mavenPlanItem(t, gh, ".", in)
		if !ok || it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %+v", it)
		}
		p := pkgsByName(it)["org.apache.commons:commons-text"]
		if p.Action != ActionUpdate || p.SelectionLowerBound != "1.10.0" || p.Relation != RelationDirect ||
			len(p.Occurrences) != 1 || p.Occurrences[0].Path != "lib/pom.xml" || p.Occurrences[0].Version != "1.9" {
			t.Errorf("commons-text = %+v", p)
		}
		if len(it.Source.Files) != 3 {
			t.Errorf("files = %+v", it.Source.Files)
		}
	})
	t.Run("the module requires another version than the image runs", func(t *testing.T) {
		gh := newFakeGitHub()
		reactorRepo(gh, strings.Replace(reactorLib, "${text.version}", "1.8", 1))
		in := jibInput(text)
		in.Scan.Packages = nil
		it, ok := mavenPlanItem(t, gh, ".", in)
		if !ok {
			t.Fatal("no item")
		}
		if p := pkgsByName(it)["org.apache.commons:commons-text"]; p.Action != ActionManual || p.Reason != ReasonNotFoundInSource {
			t.Errorf("commons-text = %+v", p)
		}
	})
	t.Run("a test-scope module dependency is not searched", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", ".", "pom.xml", strings.Replace(reactorRoot, "<module>app</module>", "<module>app</module><module>testkit</module>", 1))
		gh.put("ex/app", "lib", "pom.xml", reactorLib)
		gh.put("ex/app", "app", "pom.xml", strings.Replace(reactorApp, "</dependencies>", `<dependency><groupId>com.example.multi</groupId><artifactId>testkit</artifactId><version>1.0.0</version><scope>test</scope></dependency></dependencies>`, 1))
		gh.put("ex/app", "testkit", "pom.xml", strings.Replace(strings.Replace(reactorLib, "<artifactId>lib</artifactId>", "<artifactId>testkit</artifactId>", 1), "${text.version}", "1.8", 1))
		nested := jarFinding("CVE-TEXT", bootLib+"commons-text-1.9.jar", "org.apache.commons:commons-text", "1.9", "1.10.0")
		in := langInput("shop", "api", nested)
		in.Scan.Packages = []scanner.ResultPackages{jarPackages(
			"com.example.multi:app", "1.0.0", "app/app.jar",
			"org.apache.commons:commons-text", "1.9", bootLib+"commons-text-1.9.jar",
		)}
		it, ok := mavenPlanItem(t, gh, ".", in)
		if !ok || it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("parents in a cycle", func(t *testing.T) {
		gh := newFakeGitHub()
		reactorRepo(gh, strings.Replace(reactorLib, "<artifactId>multi-parent</artifactId><version>1.0.0</version></parent>", "<artifactId>lib</artifactId><version>1.0.0</version></parent><groupId>com.example.multi</groupId><version>1.0.0</version>", 1))
		in := jibInput(text)
		in.Scan.Packages = nil
		it, ok := mavenPlanItem(t, gh, ".", in)
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenReactorUnsupported {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a module without a pom", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", ".", "pom.xml", reactorRoot)
		gh.put("ex/app", "app", "pom.xml", reactorApp)
		in := jibInput(text)
		in.Scan.Packages = nil
		it, ok := mavenPlanItem(t, gh, ".", in)
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenReactorUnsupported {
			t.Fatalf("item = %+v", it)
		}
	})
	t.Run("a parent pom with the artifactId and other coordinates", func(t *testing.T) {
		gh := newFakeGitHub()
		reactorRepo(gh, strings.Replace(reactorLib, "<version>1.0.0</version></parent>", "<version>0.9.0</version></parent>", 1))
		in := jibInput(text)
		in.Scan.Packages = nil
		it, ok := mavenPlanItem(t, gh, ".", in)
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenParentMismatch {
			t.Fatalf("item = %+v", it)
		}
	})
}

func TestLanguagePlan_MavenRefusals(t *testing.T) {
	yaml := jarFinding("CVE-YAML", bootLib+"snakeyaml-1.30.jar", "org.yaml:snakeyaml", "1.30", "1.31")
	cases := []struct {
		name   string
		pom    string
		setup  func(gh *fakeGitHub)
		in     func() ImageInput
		reason Reason
	}{
		{"a profile that adds dependencies", strings.Replace(bootPom, "</dependencies>", `</dependencies>
  <profiles><profile><id>extra</id><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>1</version></dependency></dependencies></profile></profiles>`, 1), nil, nil, ReasonMavenModelUnsupported},
		{"repositories", strings.Replace(bootPom, "</dependencies>", `</dependencies>
  <repositories><repository><id>x</id><url>https://repo.example.com/maven</url></repository></repositories>`, 1), nil, nil, ReasonUnsupportedSource},
		{"an optional direct dependency", strings.Replace(bootPom, "<artifactId>jackson-databind</artifactId>", "<artifactId>jackson-databind</artifactId><optional>true</optional>", 1), nil, nil, ReasonMavenModelUnsupported},
		{".mvn/extensions.xml", bootPom, func(gh *fakeGitHub) {
			gh.putEntry("ex/app", "svc", github.Entry{Name: ".mvn", Type: github.EntryDir})
			gh.put("ex/app", "svc/.mvn", "extensions.xml", "<extensions/>")
		}, nil, ReasonUnsupportedSource},
		{"two archives of the project", bootPom, nil, func() ImageInput {
			in := fatJarInput(yaml)
			in.Scan.Packages[0].Packages = append(in.Scan.Packages[0].Packages,
				scanner.Package{Name: "com.example:demo", Version: "0.0.1-SNAPSHOT", PkgPath: "app/other.jar"},
				scanner.Package{Name: "org.yaml:snakeyaml", Version: "1.30", PkgPath: "app/other.jar/BOOT-INF/lib/snakeyaml-1.30.jar"})
			return in
		}, ReasonMavenAppJarAmbiguous},
		{"a pom outside the directory with the parent's artifactId", bootPom, func(gh *fakeGitHub) {
			gh.put("ex/app", ".", "pom.xml", `<project><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.7.0</version></project>`)
		}, nil, ReasonMavenParentMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gh := newFakeGitHub()
			gh.put("ex/app", "svc", "pom.xml", c.pom)
			if c.setup != nil {
				c.setup(gh)
			}
			in := fatJarInput(yaml)
			if c.in != nil {
				in = c.in()
			}
			it, ok := mavenPlanItem(t, gh, "svc", in)
			if !ok || it.Category != CategoryManual || it.Reason != c.reason {
				t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
			}
		})
	}
	t.Run("a parent named outside the repository", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", strings.Replace(bootPom, "<relativePath/>", "<relativePath>../../parent/pom.xml</relativePath>", 1))
		it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(yaml))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenParentMismatch {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a parent file named other than pom.xml", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", strings.Replace(bootPom, "<relativePath/>", "<relativePath>../parent.xml</relativePath>", 1))
		gh.put("ex/app", ".", "parent.xml", `<project><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.7.0</version></project>`)
		it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(yaml))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenParentMismatch {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a parent place that is a symlink", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", strings.Replace(bootPom, "<relativePath/>", "<relativePath>../parent.xml</relativePath>", 1))
		gh.putEntry("ex/app", ".", github.Entry{Name: "parent.xml", Type: github.EntrySymlink})
		it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(yaml))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenParentMismatch {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a relativePath naming a directory", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", strings.Replace(bootPom, "<relativePath/>", "<relativePath>../parents.xml</relativePath>", 1))
		gh.putEntry("ex/app", ".", github.Entry{Name: "parents.xml", Type: github.EntryDir})
		gh.put("ex/app", "parents.xml", "pom.xml", `<project><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.7.0</version></project>`)
		it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(yaml))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenParentMismatch {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("a relativePath naming the repository root", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", `<project><groupId>com.example</groupId><artifactId>agg</artifactId><version>1</version><packaging>pom</packaging><modules><module>app</module></modules></project>`)
		gh.put("ex/app", "svc/app", "pom.xml", strings.Replace(bootPom, "<relativePath/>", "<relativePath>../..</relativePath>", 1))
		gh.put("ex/app", ".", "pom.xml", `<project><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.7.0</version></project>`)
		it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(yaml))
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenParentMismatch {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
		if containsString(it.Source.Absent, ".") {
			t.Errorf("absent = %v", it.Source.Absent)
		}
	})
	t.Run("a cut package list keeps the findings and goes to a person", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", bootPom)
		in := fatJarInput(jarFinding("CVE-B", "app/b.jar/BOOT-INF/lib/snakeyaml-1.30.jar", "org.yaml:snakeyaml", "1.30", "1.31"))
		in.Scan.PackagesTruncated = true
		it, ok := mavenPlanItem(t, gh, "svc", in)
		if !ok || it.Category != CategoryManual || it.Reason != ReasonMavenAppJarAmbiguous || len(it.Packages) != 1 {
			t.Fatalf("item = %s %s (%s) %d", it.Category, it.Reason, it.Detail, len(it.Packages))
		}
	})
	t.Run("a SNAPSHOT the image runs", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", bootPom)
		it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(jarFinding("CVE-S", bootLib+"snakeyaml-1.0-SNAPSHOT.jar", "org.yaml:snakeyaml", "1.0-SNAPSHOT", "1.0")))
		if !ok || it.Category != CategoryManual || it.Packages[0].Reason != ReasonMavenModelUnsupported {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
	})
	t.Run("an unrelated pom above the directory is recorded", func(t *testing.T) {
		gh := newFakeGitHub()
		gh.put("ex/app", "svc", "pom.xml", bootPom)
		gh.put("ex/app", ".", "pom.xml", `<project><groupId>x</groupId><artifactId>other</artifactId><version>1</version></project>`)
		it, ok := mavenPlanItem(t, gh, "svc", fatJarInput(yaml))
		if !ok || it.Category != CategoryDependencyUpdateCandidate {
			t.Fatalf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
		}
		if len(it.Source.Files) != 2 || it.Source.Files[1].Path != "pom.xml" {
			t.Errorf("files = %+v", it.Source.Files)
		}
	})
}

func TestChooseMavenTarget(t *testing.T) {
	cves := func(fixed ...string) []CVERef {
		var out []CVERef
		for i, f := range fixed {
			out = append(out, CVERef{VulnID: "CVE-" + string(rune('A'+i)), FixedVers: []string{f}})
		}
		return out
	}
	cases := []struct {
		installed string
		cves      []CVERef
		want      string
		reason    Reason
	}{
		{"2.13.3", cves("2.12.7.1, 2.13.4.2"), "2.13.4.2", ""},
		{"10.1.10", cves("11.0.0-M11, 10.1.16, 9.0.83, 8.5.96"), "10.1.16", ""},
		{"1.30", cves("1.31", "1.32"), "1.32", ""},
		{"32.0.0-jre", cves("32.0.1-android"), "", ReasonNoFixedVersion},
		{"32.0.0-jre", cves("32.0.1-android, 32.0.1-jre"), "32.0.1-jre", ""},
		{"33.0.0-jre", cves("33.7.2"), "33.7.2", ""},
		{"31.1-jre", cves("32.0.0-jre"), "", ReasonMavenFixInOtherMajor},
		{"5.3.20", cves("6.0.8, 5.3.27, 5.2.24.RELEASE"), "5.3.27", ""},
		{"2.17.0", cves("3.1.4"), "", ReasonMavenFixInOtherMajor},
		{"4.1.77.Final", cves("4.1.86.Final"), "4.1.86.Final", ""},
		{"1.0-rc1", cves("1.0-rc2"), "1.0-rc2", ""},
		{"1.2", cves("1.3-rc1"), "", ReasonNoFixedVersion},
	}
	for _, c := range cases {
		got, reason, detail := chooseMavenTarget(c.installed, c.cves)
		if got != c.want || reason != c.reason {
			t.Errorf("%s %v: got %q %q (%s), want %q %q", c.installed, c.cves, got, reason, detail, c.want, c.reason)
		}
	}
}

func TestJarOwnFile(t *testing.T) {
	cases := []struct {
		name, version, path string
		want                bool
	}{
		{"org.yaml:snakeyaml", "1.30", bootLib + "snakeyaml-1.30.jar", true},
		{"org.yaml:snakeyaml", "1.30", "app/libs/snakeyaml-1.30.jar", true},
		{"org.jctools:jctools-core", "3.1.0", bootLib + "netty-common-4.1.77.Final.jar", false},
		{"org.yaml:snakeyaml", "1.30", "", false},
		{"snakeyaml", "1.30", "app/libs/snakeyaml-1.30.jar", false},
	}
	for _, c := range cases {
		if got := jarOwnFile(c.name, c.version, c.path); got != c.want {
			t.Errorf("%s %s %s = %v", c.name, c.version, c.path, got)
		}
	}
}

func TestMavenModuleDir(t *testing.T) {
	cases := []struct {
		unit, from, name, want string
		bad                    bool
	}{
		{".", ".", "app", "app", false},
		{"svc", "svc", "app", "svc/app", false},
		{"svc", "svc/a", "b/c", "svc/a/b/c", false},
		{".", ".", "../x", "", true},
		{".", ".", ".hidden", "", true},
		{".", ".", "/abs", "", true},
		{".", ".", "app/pom-alt.xml", "", true},
		{"svc", "svc", "", "", true},
	}
	for _, c := range cases {
		got, why := mavenModuleDir(c.unit, c.from, c.name)
		if (why != "") != c.bad || got != c.want {
			t.Errorf("%s %s %q = %q %q", c.unit, c.from, c.name, got, why)
		}
	}
}
