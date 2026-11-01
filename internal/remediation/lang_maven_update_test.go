package remediation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// fakeMavenReg serves release lists and pom files by coordinates.
type fakeMavenReg struct {
	versions map[string][]string // g:a
	poms     map[string]string   // g:a:v
	asked    []string
}

func (f *fakeMavenReg) Versions(_ context.Context, g, a string) ([]string, error) {
	f.asked = append(f.asked, "versions "+g+":"+a)
	vs, ok := f.versions[g+":"+a]
	if !ok {
		return nil, ErrReleaseNotFound
	}
	return vs, nil
}

func (f *fakeMavenReg) POM(_ context.Context, g, a, v string) ([]byte, error) {
	f.asked = append(f.asked, "pom "+g+":"+a+":"+v)
	p, ok := f.poms[g+":"+a+":"+v]
	if !ok {
		// A release the version list names has a pom that declares nothing.
		if containsString(f.versions[g+":"+a], v) {
			return []byte("<project><groupId>" + g + "</groupId><artifactId>" + a + "</artifactId><version>" + v + "</version></project>"), nil
		}
		return nil, ErrReleaseNotFound
	}
	return []byte(p), nil
}

// bootParent is a parent pom that sets snakeyaml through a property and
// imports the Jackson BOM through another.
const bootParent = `<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>2.7.0</version>
  <packaging>pom</packaging>
  <properties>
    <snakeyaml.version>1.30</snakeyaml.version>
    <jackson-bom.version>2.13.3</jackson-bom.version>
    <maven-plugin.version>3.1</maven-plugin.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${snakeyaml.version}</version></dependency>
      <dependency><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>${jackson-bom.version}</version><type>pom</type><scope>import</scope></dependency>
    </dependencies>
  </dependencyManagement>
  <build><plugins><plugin><artifactId>x</artifactId><version>${maven-plugin.version}</version></plugin></plugins></build>
</project>`

func jacksonBOM(v, databind string) string {
	return `<project><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>` + v + `</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>` + databind + `</version></dependency>
  </dependencies></dependencyManagement></project>`
}

const appPom = `<project xmlns="http://maven.apache.org/POM/4.0.0">
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
  <properties>
    <text.version>1.9</text.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.11</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>${text.version}</version>
    </dependency>
  </dependencies>
</project>
`

// mavenFlow runs the update of one Maven item against fakes. The scanner
// reports, for each scan, the packages and findings the test gives.
type mavenFlow struct {
	t     *testing.T
	reg   *fakeMavenReg
	files map[string]string
	item  LanguageItem
	fs    *fakeFS
	cfg   LangUpdateConfig
	scans []map[string][]byte
	// report gives the packages (name -> version) and vulnerable packages
	// (name@version -> ids) of a scan by target, from the files.
	resolve func(n int, files map[string][]byte) map[string]map[string]string
	vulns   map[string][]string
}

func newMavenFlow(t *testing.T, files map[string]string, pkgs ...LanguagePackage) *mavenFlow {
	t.Helper()
	f := &mavenFlow{t: t, files: files, reg: &fakeMavenReg{
		versions: map[string][]string{
			"org.yaml:snakeyaml":                          {"1.29", "1.30", "1.31", "1.32", "2.0"},
			"org.apache.commons:commons-text":             {"1.9", "1.10.0", "1.11.0"},
			"org.apache.commons:commons-lang3":            {"3.11", "3.12.0"},
			"com.fasterxml.jackson.core:jackson-databind": {"2.13.3", "2.13.4", "2.13.4.2", "2.14.0"},
			"com.fasterxml.jackson:jackson-bom":           {"2.13.3", "2.13.4", "2.13.4.20221013", "2.14.0"},
			"org.slf4j:slf4j-api":                         {"1.7.36", "1.7.37"},
		},
		poms: map[string]string{
			"org.springframework.boot:spring-boot-starter-parent:2.7.0": bootParent,
			"com.fasterxml.jackson:jackson-bom:2.13.3":                  jacksonBOM("2.13.3", "2.13.3"),
			"com.fasterxml.jackson:jackson-bom:2.13.4":                  jacksonBOM("2.13.4", "2.13.4"),
			"com.fasterxml.jackson:jackson-bom:2.13.4.20221013":         jacksonBOM("2.13.4.20221013", "2.13.4.2"),
		},
	}, vulns: map[string][]string{}}
	src := SourceRecord{Repository: "o/r", BaseBranch: "main", Directory: "svc", CommitSHA: testCommit, Origin: OriginConfig, Confidence: ConfidenceAsserted,
		Absent: []string{"svc/.mvn/maven.config", "svc/.mvn/extensions.xml"}}
	for p, c := range files {
		src.Files = append(src.Files, SourceFile{Path: p, BlobSHA: gitBlobSHA([]byte(c))})
	}
	f.item = LanguageItem{Key: "deps:o/r@main:svc#maven", Workloads: []string{"compose/p/web"}, Manager: ManagerMaven, Source: src, Packages: pkgs}
	classify(&f.item)
	f.fs = &fakeFS{fn: f.scan}
	f.cfg = LangUpdateConfig{Scanner: f.fs, Work: &fakeWork{}, PyPI: &fakePyPI{}, Npm: &fakeNpm{}, Maven: f.reg, GitHub: ghFor(files),
		Prepared: fsConds, MaxJobs: 5, Now: func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }}
	return f
}

func mavenPkg(name, installed, target string, cves ...string) LanguagePackage {
	p := LanguagePackage{Name: name, Ecosystem: typeJar, Installed: installed, SelectionLowerBound: target, Action: ActionUpdate,
		Reason: ReasonUpdateCandidateInSource, Relation: RelationTransitive}
	for _, c := range cves {
		p.CVEs = append(p.CVEs, CVERef{VulnID: c, FixedVers: []string{target}})
	}
	return p
}

func (f *mavenFlow) scan(n int, files map[string][]byte) (scanner.FSScan, error) {
	f.scans = append(f.scans, files)
	rep := scanner.ImageScan{TrivyVersion: "0.71.2"}
	for target, pkgs := range f.resolve(n, files) {
		rp := scanner.ResultPackages{Target: target, Class: inventory.ClassLang, Type: "pom"}
		for name, v := range pkgs {
			rp.Packages = append(rp.Packages, scanner.Package{Name: name, Version: v})
			for _, id := range f.vulns[name+"@"+v] {
				rep.Findings = append(rep.Findings, scanner.Finding{Class: inventory.ClassLang, Type: "pom", Target: target, Package: name,
					InstalledVer: v, VulnID: id, Status: scanner.StatusFixed, Severity: scanner.SeverityHigh})
			}
		}
		rep.Packages = append(rep.Packages, rp)
	}
	return scanner.FSScan{Conditions: fsConds, Report: rep}, nil
}

func (f *mavenFlow) run() LanguageItem {
	f.t.Helper()
	up, err := NewLangUpdater(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{f.item}}
	up.Run(context.Background(), plan)
	return plan.LanguageItems[0]
}

// pomResolves reads, in the root pom a scan is given, the value a pattern
// names, the way the edits leave it.
func pomHas(files map[string][]byte, file, s string) bool {
	return strings.Contains(string(files[file]), s)
}

func TestMavenUpdateParentPropertyOverride(t *testing.T) {
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
	f.vulns["org.yaml:snakeyaml@1.30"] = []string{"CVE-YAML"}
	f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
		v := "1.30"
		if pomHas(files, "pom.xml", "<snakeyaml.version>1.31</snakeyaml.version>") {
			v = "1.31"
		}
		return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": v, "org.apache.commons:commons-text": "1.9"}}
	}
	it := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if len(it.Artifacts) != 1 || it.Artifacts[0].Path != "svc/pom.xml" {
		t.Fatalf("artifacts = %+v", it.Artifacts)
	}
	body := string(it.Artifacts[0].Content)
	if !strings.Contains(body, "    <text.version>1.9</text.version>\n    <snakeyaml.version>1.31</snakeyaml.version>\n  </properties>") {
		t.Errorf("the override is not where it belongs:\n%s", body)
	}
	if it.Packages[0].AdoptedVersion != "1.31" {
		t.Errorf("adopted = %q", it.Packages[0].AdoptedVersion)
	}
	m := it.Update.Maven
	if m == nil || len(m.Edits) != 1 || m.Edits[0].Kind != MavenEditPropertyOverride || m.Edits[0].Property != "snakeyaml.version" || m.Edits[0].From != "1.30" || m.Edits[0].To != "1.31" {
		t.Fatalf("maven = %+v", m)
	}
	if len(f.fs.opts) != 2 || !strings.HasPrefix(f.fs.opts[0].MavenMirror, "http://127.0.0.1:") {
		t.Errorf("scan options = %+v", f.fs.opts)
	}
	if _, ok := f.scans[0]["pom.xml"]; !ok || len(f.scans[0]) != 1 {
		t.Errorf("scan files = %v", f.scans[0])
	}
}

func TestMavenUpdateFormsInTheProject(t *testing.T) {
	t.Run("a written version", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.apache.commons:commons-lang3", "3.11", "3.12.0", "CVE-L"))
		f.vulns["org.apache.commons:commons-lang3@3.11"] = []string{"CVE-L"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "3.11"
			if pomHas(files, "pom.xml", "<version>3.12.0</version>") {
				v = "3.12.0"
			}
			return map[string]map[string]string{"pom.xml": {"org.apache.commons:commons-lang3": v}}
		}
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if e := it.Update.Maven.Edits[0]; e.Kind != MavenEditVersion || e.From != "3.11" || e.To != "3.12.0" {
			t.Errorf("edit = %+v", e)
		}
	})
	t.Run("a property of the project", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.apache.commons:commons-text", "1.9", "1.10.0", "CVE-T"))
		f.vulns["org.apache.commons:commons-text@1.9"] = []string{"CVE-T"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.9"
			if pomHas(files, "pom.xml", "<text.version>1.10.0</text.version>") {
				v = "1.10.0"
			}
			return map[string]map[string]string{"pom.xml": {"org.apache.commons:commons-text": v}}
		}
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if e := it.Update.Maven.Edits[0]; e.Kind != MavenEditProperty || e.Property != "text.version" || e.To != "1.10.0" {
			t.Errorf("edit = %+v", e)
		}
	})
	t.Run("an unmanaged transitive package is pinned", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.slf4j:slf4j-api", "1.7.36", "1.7.37", "CVE-S"))
		f.vulns["org.slf4j:slf4j-api@1.7.36"] = []string{"CVE-S"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.7.36"
			if pomHas(files, "pom.xml", "<artifactId>slf4j-api</artifactId>") {
				v = "1.7.37"
			}
			return map[string]map[string]string{"pom.xml": {"org.slf4j:slf4j-api": v}}
		}
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if e := it.Update.Maven.Edits[0]; e.Kind != MavenEditManagedPin || e.To != "1.7.37" {
			t.Errorf("edit = %+v", e)
		}
		if !strings.Contains(string(it.Artifacts[0].Content), "<dependencyManagement>") {
			t.Errorf("no management added:\n%s", it.Artifacts[0].Content)
		}
	})
	t.Run("a BOM imported through a parent's property", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("com.fasterxml.jackson.core:jackson-databind", "2.13.3", "2.13.4.2", "CVE-J"))
		f.vulns["com.fasterxml.jackson.core:jackson-databind@2.13.3"] = []string{"CVE-J"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "2.13.3"
			if pomHas(files, "pom.xml", "<jackson-bom.version>2.13.4.20221013</jackson-bom.version>") {
				v = "2.13.4.2"
			}
			return map[string]map[string]string{"pom.xml": {"com.fasterxml.jackson.core:jackson-databind": v}}
		}
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if e := it.Update.Maven.Edits[0]; e.Kind != MavenEditPropertyOverride || e.Property != "jackson-bom.version" || e.To != "2.13.4.20221013" {
			t.Errorf("edit = %+v", e)
		}
	})
}

func TestMavenUpdateRefusals(t *testing.T) {
	t.Run("a managed property plugins also use is pinned instead", func(t *testing.T) {
		parent := strings.Replace(bootParent, "${maven-plugin.version}", "${snakeyaml.version}", 1)
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.reg.poms["org.springframework.boot:spring-boot-starter-parent:2.7.0"] = parent
		f.vulns["org.yaml:snakeyaml@1.30"] = []string{"CVE-YAML"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.30"
			if pomHas(files, "pom.xml", "<artifactId>snakeyaml</artifactId>") {
				v = "1.31"
			}
			return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": v}}
		}
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if e := it.Update.Maven.Edits[0]; e.Kind != MavenEditManagedPin || e.To != "1.31" {
			t.Errorf("edit = %+v", e)
		}
		if strings.Contains(string(it.Artifacts[0].Content), "snakeyaml.version") {
			t.Error("the property was changed")
		}
	})
	t.Run("a declared version's property plugins also use", func(t *testing.T) {
		pom := strings.Replace(appPom, "</dependencies>", `  <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>${snakeyaml.version}</version>
    </dependency>
  </dependencies>`, 1)
		parent := strings.Replace(bootParent, "${maven-plugin.version}", "${snakeyaml.version}", 1)
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": pom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.reg.poms["org.springframework.boot:spring-boot-starter-parent:2.7.0"] = parent
		f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
		wantCategory(t, f.run(), CategoryManual, ReasonMavenVersionSourceUnsupported)
	})
	t.Run("a package of a BOM that no release of the BOM fixes is left alone", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("com.fasterxml.jackson.core:jackson-databind", "2.13.3", "2.14.0", "CVE-J"))
		f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonMavenVersionSourceUnsupported)
		if !strings.Contains(it.Detail, "jackson-bom") {
			t.Errorf("detail = %s", it.Detail)
		}
	})
	t.Run("a release whose dependencies the project holds back", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.apache.commons:commons-lang3", "3.11", "3.12.0", "CVE-L"))
		f.reg.poms["org.apache.commons:commons-lang3:3.12.0"] = `<project><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version>
  <properties><y.version>2</y.version></properties>
  <dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>${y.version}</version></dependency></dependencies></project>`
		f.vulns["org.apache.commons:commons-lang3@3.11"] = []string{"CVE-L"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "3.11"
			if pomHas(files, "pom.xml", "<version>3.12.0</version>") {
				v = "3.12.0"
			}
			return map[string]map[string]string{"pom.xml": {"org.apache.commons:commons-lang3": v, "x:y": "1"}}
		}
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonMavenDependencyHeldBack)
		if !strings.Contains(it.Detail, "x:y 1 (org.apache.commons:commons-lang3 3.12.0 declares 2)") {
			t.Errorf("detail = %s", it.Detail)
		}
	})
	t.Run("a release whose parent declares a dependency held back", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.slf4j:slf4j-api", "1.7.36", "1.7.37", "CVE-S"))
		f.reg.poms["org.slf4j:slf4j-api:1.7.37"] = `<project><parent><groupId>org.slf4j</groupId><artifactId>slf4j-parent</artifactId><version>1.7.37</version></parent><artifactId>slf4j-api</artifactId></project>`
		f.reg.poms["org.slf4j:slf4j-parent:1.7.37"] = `<project><groupId>org.slf4j</groupId><artifactId>slf4j-parent</artifactId><version>1.7.37</version>
  <dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>2</version></dependency></dependencies></project>`
		f.vulns["org.slf4j:slf4j-api@1.7.36"] = []string{"CVE-S"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.7.36"
			if pomHas(files, "pom.xml", "<artifactId>slf4j-api</artifactId>") {
				v = "1.7.37"
			}
			return map[string]map[string]string{"pom.xml": {"org.slf4j:slf4j-api": v, "x:y": "1"}}
		}
		wantCategory(t, f.run(), CategoryManual, ReasonMavenDependencyHeldBack)
	})
	t.Run("a release whose BOM's parent gives the version it needs", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.slf4j:slf4j-api", "1.7.36", "1.7.37", "CVE-S"))
		f.reg.poms["org.slf4j:slf4j-api:1.7.37"] = `<project><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.37</version>
  <properties><lib>y</lib></properties>
  <dependencyManagement><dependencies><dependency><groupId>b</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
  <dependencies><dependency><groupId>x</groupId><artifactId>${lib}</artifactId></dependency></dependencies></project>`
		f.reg.poms["b:bom:1"] = `<project><parent><groupId>b</groupId><artifactId>bom-parent</artifactId><version>1</version></parent><artifactId>bom</artifactId>
  <dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>${x.version}</version></dependency></dependencies></dependencyManagement></project>`
		f.reg.poms["b:bom-parent:1"] = `<project><groupId>b</groupId><artifactId>bom-parent</artifactId><version>1</version><properties><x.version>2</x.version></properties></project>`
		f.vulns["org.slf4j:slf4j-api@1.7.36"] = []string{"CVE-S"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.7.36"
			if pomHas(files, "pom.xml", "<artifactId>slf4j-api</artifactId>") {
				v = "1.7.37"
			}
			return map[string]map[string]string{"pom.xml": {"org.slf4j:slf4j-api": v, "x:y": "1"}}
		}
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonMavenDependencyHeldBack)
		if !strings.Contains(it.Detail, "x:y 1") {
			t.Errorf("detail = %s", it.Detail)
		}
	})
	t.Run("a BOM managing a dependency at a version that cannot be read", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.slf4j:slf4j-api", "1.7.36", "1.7.37", "CVE-S"))
		f.reg.poms["org.slf4j:slf4j-api:1.7.37"] = `<project><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.37</version>
  <dependencyManagement><dependencies><dependency><groupId>b</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
  <dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId></dependency></dependencies></project>`
		f.reg.poms["b:bom:1"] = `<project><groupId>b</groupId><artifactId>bom</artifactId><version>1</version>
  <dependencyManagement><dependencies>
    <dependency><groupId>x</groupId><artifactId>y</artifactId><version>${nowhere}</version></dependency>
    <dependency><groupId>b</groupId><artifactId>inner</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement></project>`
		f.reg.poms["b:inner:1"] = `<project><groupId>b</groupId><artifactId>inner</artifactId><version>1</version>
  <dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency></dependencies></dependencyManagement></project>`
		f.vulns["org.slf4j:slf4j-api@1.7.36"] = []string{"CVE-S"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.7.36"
			if pomHas(files, "pom.xml", "<artifactId>slf4j-api</artifactId>") {
				v = "1.7.37"
			}
			return map[string]map[string]string{"pom.xml": {"org.slf4j:slf4j-api": v, "x:y": "1"}}
		}
		wantCategory(t, f.run(), CategoryManual, ReasonMavenDependencyHeldBack)
	})
	t.Run("a property also part of a longer version", func(t *testing.T) {
		pom := strings.Replace(appPom, "</dependencies>", `  <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text-tests</artifactId>
      <version>${text.version}-tests</version>
      <scope>test</scope>
    </dependency>
  </dependencies>`, 1)
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": pom}, mavenPkg("org.apache.commons:commons-text", "1.9", "1.10.0", "CVE-T"))
		f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
		wantCategory(t, f.run(), CategoryManual, ReasonMavenVersionSourceUnsupported)
	})
	t.Run("a module's own declaration overrides the parent's", func(t *testing.T) {
		pom := strings.Replace(appPom, "</dependencies>", `  <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.30</version>
    </dependency>
  </dependencies>`, 1)
		parent := strings.Replace(bootParent, "<dependencyManagement>", `<dependencies><dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.29</version></dependency></dependencies>
  <dependencyManagement>`, 1)
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": pom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.reg.poms["org.springframework.boot:spring-boot-starter-parent:2.7.0"] = parent
		f.vulns["org.yaml:snakeyaml@1.30"] = []string{"CVE-YAML"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.30"
			if pomHas(files, "pom.xml", "<version>1.31</version>") {
				v = "1.31"
			}
			return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": v}}
		}
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if e := it.Update.Maven.Edits[0]; e.Kind != MavenEditVersion || e.From != "1.30" {
			t.Errorf("edit = %+v", e)
		}
	})
	t.Run("a version written in a parent's dependencies", func(t *testing.T) {
		parent := strings.Replace(bootParent, "<dependencyManagement>", `<dependencies><dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.30</version></dependency></dependencies>
  <dependencyManagement>`, 1)
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.reg.poms["org.springframework.boot:spring-boot-starter-parent:2.7.0"] = parent
		f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
		wantCategory(t, f.run(), CategoryManual, ReasonMavenVersionSourceUnsupported)
	})
	t.Run("no release Maven Central lists", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.33", "CVE-YAML"))
		f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
		wantCategory(t, f.run(), CategoryManual, ReasonMavenReleaseNotFound)
	})
	t.Run("a finding new to the files", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.vulns["org.yaml:snakeyaml@1.30"] = []string{"CVE-YAML"}
		f.vulns["org.yaml:snakeyaml@1.31"] = []string{"CVE-NEW"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			v := "1.30"
			if n == 1 {
				v = "1.31"
			}
			return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": v}}
		}
		wantCategory(t, f.run(), CategoryManual, ReasonSourceIntroduced)
	})
	t.Run("a finding new to one module", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.vulns["org.yaml:snakeyaml@1.30"] = []string{"CVE-YAML"}
		f.vulns["org.old:lib@1"] = []string{"CVE-OLD"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			if n == 0 {
				return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": "1.30"}, "lib/pom.xml": {"org.old:lib": "1"}}
			}
			return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": "1.31", "org.old:lib": "1"}, "lib/pom.xml": {"org.old:lib": "1"}}
		}
		wantCategory(t, f.run(), CategoryManual, ReasonSourceIntroduced)
	})
	t.Run("a target that does not reach its release", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.vulns["org.yaml:snakeyaml@1.30"] = []string{"CVE-YAML"}
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": "1.30"}}
		}
		wantCategory(t, f.run(), CategoryManual, ReasonTargetNotUpdated)
	})
	t.Run("an empty version in a scan", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
			return map[string]map[string]string{"pom.xml": {"org.yaml:snakeyaml": "1.30", "x:y": ""}}
		}
		wantCategory(t, f.run(), CategoryNotComparable, ReasonSourceScanIncomplete)
	})
	t.Run("a pom that changed since the plan", func(t *testing.T) {
		f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
		f.cfg.GitHub = ghFor(map[string]string{"svc/pom.xml": appPom + " "})
		f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
		wantCategory(t, f.run(), CategoryFailed, ReasonSourceChanged)
	})
}

func TestChooseRelease(t *testing.T) {
	vs := []string{"31.1-jre", "32.0.0-android", "32.0.0-jre", "32.0.1-jre", "33.0.0-jre", "32.1.0-rc1-jre"}
	if got, ok := chooseRelease(vs, "32.0.0-jre", "32.0.1"); !ok || got != "32.0.1-jre" {
		t.Errorf("got %q %v", got, ok)
	}
	if _, ok := chooseRelease(vs, "31.1-jre", "32.0.0"); ok {
		t.Error("a release of another major version was chosen")
	}
	if got, ok := chooseRelease([]string{"1.0", "1.1-rc1", "1.1"}, "1.0", "1.0.1"); !ok || got != "1.1" {
		t.Errorf("got %q %v", got, ok)
	}
}

func TestChainResolveParentCoordinates(t *testing.T) {
	pom := &mavenPOM{ArtifactID: "a", Parent: &mavenParent{GroupID: "g", ArtifactID: "p", Version: "2.1"}, Properties: map[string]string{}}
	for in, want := range map[string]string{"${project.parent.version}": "2.1", "${project.version}": "2.1", "${project.groupId}": "g", "${parent.artifactId}": "p"} {
		if got, ok := chainResolve([]mavenChainPOM{{pom: pom}}, in); !ok || got != want {
			t.Errorf("%s = %q %v", in, got, ok)
		}
	}
}

// A Maven pull request lists the edits of the pom files, says the versions
// were checked on Maven Central and resolved by Trivy, asks for Maven's own
// resolution and build, and claims no package manager run.
func TestLanguagePRBody_Maven(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		in := languageBodyFixture(lang, "<!-- marker -->", true)
		in.Item.Manager = ManagerMaven
		in.LockPath = "svc/pom.xml"
		in.Files = []FileChange{{Path: "svc/pom.xml"}}
		in.Record.Manager = "maven"
		in.Record.Chain, in.Record.ManifestEdits, in.Record.Tool, in.Record.Runtime = nil, nil, nil, nil
		in.Item.Update.Diff, in.Item.Update.Steps = nil, nil
		in.Item.Update.Maven = &MavenUpdate{
			Edits: []MavenEditRecord{
				{File: "svc/pom.xml", Kind: MavenEditPropertyOverride, Package: "org.apache.tomcat.embed:tomcat-embed-core", Property: "tomcat.version", From: "9.0.63", To: "9.0.121"},
				{File: "svc/pom.xml", Kind: MavenEditVersion, Package: "org.apache.commons:commons-lang3", From: "3.11", To: "3.12.0"},
			},
			Moves: []MavenMove{{Name: "org.apache.tomcat.embed:tomcat-embed-el", From: []string{"9.0.63"}, To: []string{"9.0.121"}}},
		}
		body, err := buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"`tomcat.version`", "`9.0.121`", "`org.apache.tomcat.embed:tomcat-embed-el`", "`mvn -B dependency:tree && mvn -B verify`", "Maven Central"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the body lacks %q:\n%s", lang, want, body)
			}
		}
		for _, not := range []string{"no record of them", "記録を残す前", "installs from the lockfile", "lockfile からのインストール"} {
			if strings.Contains(body, not) {
				t.Errorf("%s: the body says %q:\n%s", lang, not, body)
			}
		}
	}
}

// A package a BOM manages through the BOM's parent is a package of the set,
// not one to pin on its own.
func TestMavenUpdateBOMParentManagement(t *testing.T) {
	pom := strings.Replace(appPom, "</properties>", `</properties>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>b</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency>
    </dependencies>
  </dependencyManagement>`, 1)
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": pom}, mavenPkg("x:y", "1", "2", "CVE-X"))
	f.reg.versions["x:y"] = []string{"1", "2"}
	f.reg.poms["b:bom:1"] = `<project><parent><groupId>b</groupId><artifactId>bom-parent</artifactId><version>1</version></parent><artifactId>bom</artifactId><packaging>pom</packaging></project>`
	f.reg.poms["b:bom-parent:1"] = `<project><groupId>b</groupId><artifactId>bom-parent</artifactId><version>1</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency>
    <dependency><groupId>x</groupId><artifactId>z</artifactId><version>1</version></dependency>
  </dependencies></dependencyManagement></project>`
	f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
	wantCategory(t, f.run(), CategoryManual, ReasonMavenVersionSourceUnsupported)
}

// A BOM that manages the package under an artifactId written as a property
// still manages it.
func TestMavenUpdateBOMManagementByProperty(t *testing.T) {
	pom := strings.Replace(appPom, "</properties>", `</properties>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>b</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency>
    </dependencies>
  </dependencyManagement>`, 1)
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": pom}, mavenPkg("x:y", "1", "2", "CVE-X"))
	f.reg.versions["x:y"] = []string{"1", "2"}
	f.reg.poms["b:bom:1"] = `<project><groupId>b</groupId><artifactId>bom</artifactId><version>1</version><packaging>pom</packaging>
  <properties><lib>y</lib></properties>
  <dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>${lib}</artifactId><version>1</version></dependency></dependencies></dependencyManagement></project>`
	f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
	wantCategory(t, f.run(), CategoryManual, ReasonMavenVersionSourceUnsupported)
}
