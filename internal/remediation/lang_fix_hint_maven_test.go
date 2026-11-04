package remediation

import (
	"reflect"
	"strings"
	"testing"
)

// bootParentDeclaring is bootParent at v with snakeyaml declared at yaml in
// its dependencies, or not declared when yaml is empty.
func bootParentDeclaring(v, yaml string) string {
	p := strings.Replace(bootParent, "<version>2.7.0</version>", "<version>"+v+"</version>", 1)
	if yaml == "" {
		return p
	}
	return strings.Replace(p, "<dependencyManagement>", `<dependencies><dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>`+yaml+`</version></dependency></dependencies>
  <dependencyManagement>`, 1)
}

// A version a parent outside the project declares names that parent, and
// what its newest release in the minor version and its newest release set the
// package to.
func TestMavenParentPOMHint(t *testing.T) {
	const parent = "org.springframework.boot:spring-boot-starter-parent"
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
	f.reg.poms[parent+":2.7.0"] = bootParentDeclaring("2.7.0", "1.30")
	f.reg.poms[parent+":2.7.18"] = bootParentDeclaring("2.7.18", "1.31")
	f.reg.poms[parent+":3.0.0"] = bootParentDeclaring("3.0.0", "")
	f.reg.versions[parent] = []string{"2.6.0", "2.7.0", "2.7.5", "2.7.18", "3.0.0-RC1", "3.0.0"}
	f.reg.poms[parent+":2.7.5"] = bootParentDeclaring("2.7.5", "1.30")
	f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
	it := f.run()
	wantCategory(t, it, CategoryManual, ReasonMavenVersionSourceUnsupported)
	want := &FixHint{
		DecidedBy: &FixDecider{Kind: DeciderParentPOM, Name: parent, Version: "2.7.0"},
		Releases: []ChainHint{{Package: "org.yaml:snakeyaml", Parent: parent, ParentVersion: "2.7.0", Direct: true,
			InSpec: &ChainHintRelease{Version: "2.7.18", Range: "1.31", Fixes: true},
			Latest: &ChainHintRelease{Version: "3.0.0", Range: "1.30"}}},
	}
	if got := it.Packages[0].Hint(); !reflect.DeepEqual(got, want) {
		t.Errorf("hint = %+v, want %+v", got, want)
	}
}

// A release of the deciding pom with a profile that may be on and sets
// properties is not judged; a profile only a build asks for by name is no
// matter.
func TestMavenDeciderWithAProfile(t *testing.T) {
	const parent = "org.springframework.boot:spring-boot-starter-parent"
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
	f.reg.poms[parent+":2.7.0"] = bootParentDeclaring("2.7.0", "1.30")
	f.reg.poms[parent+":2.7.18"] = strings.Replace(bootParentDeclaring("2.7.18", "1.31"), "</project>", `<profiles><profile><id>old</id><activation><activeByDefault>true</activeByDefault></activation><properties><snakeyaml.version>1.30</snakeyaml.version></properties></profile></profiles></project>`, 1)
	f.reg.versions[parent] = []string{"2.7.0", "2.7.18"}
	f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
	it := f.run()
	if h := it.Packages[0].Hint(); h == nil || h.DecidedBy == nil || len(h.Releases) != 0 {
		t.Errorf("hint = %+v", h)
	}
	f.reg.poms[parent+":2.7.18"] = strings.Replace(bootParentDeclaring("2.7.18", "1.31"), "</project>", `<profiles><profile><id>release</id><properties><snakeyaml.version>1.30</snakeyaml.version></properties></profile></profiles></project>`, 1)
	it = f.run()
	if h := it.Packages[0].Hint(); h == nil || len(h.Releases) != 1 || h.Releases[0].InSpec == nil || !h.Releases[0].InSpec.Fixes {
		t.Errorf("hint with a profile asked for by name = %+v", h)
	}
}

// The newest release in the minor version is the current one when no later
// release of that minor version exists.
func TestMavenDeciderCurrentIsNewestInItsMinor(t *testing.T) {
	sameMinor, latest := deciderReleases([]string{"1.2.0", "1.2.3", "1.3.0", "1.4.0-RC1"}, "1.2.3")
	if sameMinor != "1.2.3" || latest != "1.3.0" {
		t.Errorf("same minor %q, latest %q", sameMinor, latest)
	}
}

// A Maven version fixes a vulnerability at or above the lowest fix it reports
// in that version's major version, or above every fix when it reports none
// there.
func TestMavenFixedAt(t *testing.T) {
	cves := []CVERef{{VulnID: "A", FixedVers: []string{"2.5.15", "2.6.15", "2.7.12", "3.0.7"}}}
	for v, want := range map[string]bool{"2.7.18": true, "2.5.15": true, "2.5.14": false, "2.6.14": false, "2.7.11": false, "2.8.0": true, "3.0.7": true, "4.0.0": true, "1.9.0": false} {
		if got := mavenFixedAt(v, cves); got != want {
			t.Errorf("%s: %v, want %v", v, got, want)
		}
	}
	if mavenFixedAt("2.7.18", nil) {
		t.Error("no vulnerability is not fixed")
	}
	// The fixes of another flavour do not count.
	flavoured := []CVERef{{VulnID: "A", FixedVers: []string{"2.0-jre", "2.1-android"}}, {VulnID: "B", FixedVers: []string{"2.0.1-android"}}}
	if mavenFixedAt("2.0.1-android", flavoured) || !mavenFixedAt("2.1-android", flavoured) {
		t.Error("a fix of another flavour was counted")
	}
	if got := mavenOtherMajorFix("1.0-android", flavoured); got != "2.1-android" {
		t.Errorf("other major fix = %q", got)
	}
	// A fix written with no flavour counts for every flavour.
	plain := []CVERef{{VulnID: "C", FixedVers: []string{"33.7.2"}}}
	if got := mavenOtherMajorFix("31.0.1-jre", plain); got != "33.7.2" {
		t.Errorf("other major fix of a flavoured version = %q", got)
	}
	if !mavenFixedAt("33.7.2-jre", plain) || mavenFixedAt("33.7.1-jre", plain) {
		t.Error("a fix with no flavour was not read for a flavoured version")
	}
}

// A package the plan left alone because every fix is of another major
// version names the lowest of them that fixes it.
func TestMavenPlannedOtherMajorHint(t *testing.T) {
	p := mavenPkg("org.yaml:snakeyaml", "1.30", "", "CVE-YAML")
	p.CVEs = []CVERef{{VulnID: "CVE-YAML", FixedVers: []string{"2.0"}}, {VulnID: "CVE-Y2", FixedVers: []string{"1.32", "2.1-M1", "2.2"}}}
	p.Action, p.Reason = ActionManual, ReasonMavenFixInOtherMajor
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, p)
	it := f.run()
	if h := it.Packages[0].Hint(); h == nil || h.Fix == nil || h.Fix.Version != "2.2" {
		t.Errorf("hint = %+v", h)
	}
}

// The reads of the hint are bounded and are not the update's own; past the
// bound the pom that decides is still named.
func TestMavenParentPOMHintBound(t *testing.T) {
	const parent = "org.springframework.boot:spring-boot-starter-parent"
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.31", "CVE-YAML"))
	f.reg.poms[parent+":2.7.0"] = bootParentDeclaring("2.7.0", "1.30")
	f.reg.versions[parent] = []string{"2.7.0", "2.7.18"}
	f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
	old := maxDeciderReads
	maxDeciderReads = 1
	defer func() { maxDeciderReads = old }()
	it := f.run()
	h := it.Packages[0].Hint()
	if h == nil || h.DecidedBy == nil || len(h.Releases) != 0 {
		t.Fatalf("hint = %+v", h)
	}
	for _, a := range f.reg.asked {
		if a == "pom "+parent+":2.7.18" {
			t.Error("a pom was read past the bound")
		}
	}
}

// A package a BOM imported by another BOM manages names the outer BOM, and
// what its releases manage the package at, through the BOM it imports.
func TestMavenNestedBOMHint(t *testing.T) {
	outer := func(v, inner string) string {
		return `<project><groupId>org.example</groupId><artifactId>platform-bom</artifactId><version>` + v + `</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>` + inner + `</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement></project>`
	}
	pom := strings.Replace(appPom, "<dependencies>", `<dependencyManagement><dependencies>
    <dependency><groupId>org.example</groupId><artifactId>platform-bom</artifactId><version>${platform.version}</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
  <dependencies>`, 1)
	pom = strings.Replace(pom, "<text.version>1.9</text.version>", "<text.version>1.9</text.version><platform.version>1.2.0</platform.version>", 1)
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": pom}, mavenPkg("com.fasterxml.jackson.core:jackson-databind", "2.13.3", "2.13.4", "CVE-DB"))
	f.reg.poms["org.example:platform-bom:1.2.0"] = outer("1.2.0", "2.13.3")
	f.reg.poms["org.example:platform-bom:1.2.7"] = outer("1.2.7", "2.13.3")
	f.reg.poms["org.example:platform-bom:1.3.0"] = outer("1.3.0", "2.13.4")
	f.reg.versions["org.example:platform-bom"] = []string{"1.2.0", "1.2.7", "1.3.0"}
	f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
	it := f.run()
	wantCategory(t, it, CategoryManual, ReasonMavenVersionSourceUnsupported)
	h := it.Packages[0].Hint()
	if h == nil || h.DecidedBy == nil || *h.DecidedBy != (FixDecider{Kind: DeciderBOM, Name: "org.example:platform-bom", Version: "1.2.0"}) {
		t.Fatalf("hint = %+v", h)
	}
	if len(h.Releases) != 1 || *h.Releases[0].InSpec != (ChainHintRelease{Version: "1.2.7", Range: "2.13.3"}) ||
		*h.Releases[0].Latest != (ChainHintRelease{Version: "1.3.0", Range: "2.13.4", Fixes: true}) {
		t.Errorf("releases = %+v", h.Releases)
	}
}

// A package with no release of its major version at the target names the
// lowest fixing release of another major version.
func TestMavenOtherMajorHint(t *testing.T) {
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.yaml:snakeyaml", "1.30", "1.33", "CVE-YAML"))
	f.reg.versions["org.yaml:snakeyaml"] = []string{"1.30", "1.32", "2.0-M1", "2.0", "2.2"}
	f.resolve = func(int, map[string][]byte) map[string]map[string]string { return nil }
	it := f.run()
	wantCategory(t, it, CategoryManual, ReasonMavenReleaseNotFound)
	if h := it.Packages[0].Hint(); h == nil || h.Fix == nil || h.Fix.Version != "2.0" {
		t.Errorf("hint = %+v", h)
	}
}

// A package the Spring Boot BOM writes a literal version for names the BOM of
// the plugin's version, and what the BOM's newest releases in its minor
// version and of all manage it at.
func TestGradleSpringBootHint(t *testing.T) {
	const boot = "org.springframework.boot:spring-boot-dependencies"
	files := bomProject("", "")
	files["gradle.lockfile"] = strings.Replace(files["gradle.lockfile"], "org.junit.jupiter", "org.example:literal:1.0=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.junit.jupiter", 1)
	f := newGradleFlow(t, files, jarFinding("CVE-LIT", bootLib+"literal-1.0.jar", "org.example:literal", "1.0", "1.1"))
	f.reg.versions["org.example:literal"] = []string{"1.0", "1.1"}
	f.reg.versions[boot] = []string{"4.1.2", "4.1.5", "4.2.0"}
	f.reg.poms[boot+":4.1.5"] = strings.Replace(strings.Replace(bootBOM, "<version>4.1.2</version>", "<version>4.1.5</version>", 1), "<artifactId>literal</artifactId><version>1.0</version>", "<artifactId>literal</artifactId><version>1.1</version>", 1)
	f.reg.poms[boot+":4.2.0"] = strings.Replace(strings.Replace(bootBOM, "<version>4.1.2</version>", "<version>4.2.0</version>", 1), "<dependency><groupId>org.example</groupId><artifactId>literal</artifactId><version>1.0</version></dependency>", "", 1)
	it := f.run()
	wantCategory(t, it, CategoryManual, ReasonGradleVersionSourceUnsupported)
	var p LanguagePackage
	for _, x := range it.Packages {
		if x.Name == "org.example:literal" {
			p = x
		}
	}
	want := &FixHint{
		DecidedBy: &FixDecider{Kind: DeciderSpringBoot, Name: boot, Version: "4.1.2"},
		Releases: []ChainHint{{Package: "org.example:literal", Parent: boot, ParentVersion: "4.1.2", Direct: true,
			InSpec: &ChainHintRelease{Version: "4.1.5", Range: "1.1", Fixes: true},
			Latest: &ChainHintRelease{Version: "4.2.0", Dropped: true}}},
	}
	if got := p.Hint(); !reflect.DeepEqual(got, want) {
		t.Errorf("hint = %+v, want %+v", got, want)
	}
}
