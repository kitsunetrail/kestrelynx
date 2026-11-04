package remediation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// gradleReport is what the dependencies task printed for a project, as
// Gradle 8 prints it.
const gradleReport = `
------------------------------------------------------------
Root project 'gradleapp'
------------------------------------------------------------

annotationProcessor - Annotation processors and their dependencies for source set 'main'.
+--- org.mapstruct:mapstruct-processor:1.5.0
|    \--- org.apache.commons:commons-lang3:3.12.0
\--- org.apache.commons:commons-lang3:3.12.0 (*)

compileClasspath - Compile classpath for source set 'main'.
+--- org.apache.commons:commons-text:1.10.0
|    \--- org.apache.commons:commons-lang3:3.12.0 -> 3.18.0
\--- org.apache.commons:commons-lang3:3.18.0 (c)

developmentClasspath
\--- org.apache.commons:commons-lang3:3.12.0

runtimeClasspath - Runtime classpath of source set 'main'.
No dependencies
`

func TestGradleTree(t *testing.T) {
	got := gradleTree([]byte(gradleReport), "compileClasspath")
	want := []gradleNode{
		{depth: 0, module: "org.apache.commons:commons-text", asked: "1.10.0", resolved: "1.10.0"},
		{depth: 1, module: "org.apache.commons:commons-lang3", asked: "3.12.0", resolved: "3.18.0"},
		{depth: 0, module: "org.apache.commons:commons-lang3", asked: "3.18.0", resolved: "3.18.0", constraint: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tree = %+v", got)
	}
	if gradleTree([]byte(gradleReport), "compile") != nil {
		t.Error("a configuration whose name only starts the same was read")
	}
	if n := gradleTree([]byte(gradleReport), "runtimeClasspath"); len(n) != 0 {
		t.Errorf("no dependencies = %+v", n)
	}
}

// The modules that bring a package in at a version, or the configuration's own
// declaration of it.
func TestGradleHolders(t *testing.T) {
	holders, direct := gradleHolders([]byte(gradleReport), "annotationProcessor", "org.apache.commons:commons-lang3", "3.12.0")
	if !reflect.DeepEqual(holders, []FixHolder{{Parent: "org.mapstruct:mapstruct-processor", ParentVersion: "1.5.0", Range: "3.12.0"}}) || !direct {
		t.Errorf("holders = %+v, direct %v", holders, direct)
	}
	holders, direct = gradleHolders([]byte(gradleReport), "developmentClasspath", "org.apache.commons:commons-lang3", "3.12.0")
	if len(holders) != 0 || !direct {
		t.Errorf("holders = %+v, direct %v", holders, direct)
	}
	if h, d := gradleHolders([]byte("garbage"), "annotationProcessor", "x:y", "1"); h != nil || d {
		t.Errorf("garbage = %+v %v", h, d)
	}
}

// The packages of a pom scan that depend on a package at a version; the
// project's own module declares it.
func TestMavenHolders(t *testing.T) {
	rep := scanner.ImageScan{Packages: []scanner.ResultPackages{{Target: "pom.xml", Type: "pom", Packages: []scanner.Package{
		{Name: "com.example:app", Version: "1.0", ID: "app", Relationship: "root", DependsOn: []string{"starter", "yaml"}},
		{Name: "org.springframework.boot:spring-boot-starter", Version: "2.7.0", ID: "starter", DependsOn: []string{"yaml"}},
		{Name: "org.yaml:snakeyaml", Version: "1.30", ID: "yaml"},
	}}}}
	holders, direct := mavenHolders(rep, "org.yaml:snakeyaml", "1.30")
	if !reflect.DeepEqual(holders, []FixHolder{{Parent: "org.springframework.boot:spring-boot-starter", ParentVersion: "2.7.0", Range: "1.30"}}) || !direct {
		t.Errorf("holders = %+v, direct %v", holders, direct)
	}
	if h, d := mavenHolders(rep, "org.yaml:snakeyaml", "2.0"); h != nil || d {
		t.Errorf("another version = %+v %v", h, d)
	}
}

// A Gradle target left below its release in a configuration names the module
// that brings it in there, and what that module's releases ask for.
func TestGradleTargetNotUpdatedNamesTheHolder(t *testing.T) {
	f := newGradleFlow(t, gradleFiles())
	f.lock = func(src map[string][]byte) string {
		lock := f.defaultLock(src)
		lock = strings.Replace(lock, "commons-lang3:3.12.0=", "commons-lang3:3.18.0=", 1)
		return strings.Replace(lock, "commons-lang3:3.18.0=compileClasspath,productionRuntimeClasspath,runtimeClasspath", "commons-lang3:3.18.0=compileClasspath,productionRuntimeClasspath\norg.apache.commons:commons-lang3:3.12.0=runtimeClasspath", 1)
	}
	f.outcome = func(o *fakeOutcome, lock string) {
		o.reports = map[string][]byte{stepUpdate: []byte("runtimeClasspath - Runtime classpath of source set 'main'.\n+--- org.example:proc:1.5.0\n|    \\--- org.apache.commons:commons-lang3:3.12.0\n")}
	}
	f.reg.versions["org.example:proc"] = []string{"1.5.0", "1.5.3", "2.0.0"}
	f.reg.poms["org.example:proc:1.5.3"] = `<project><groupId>org.example</groupId><artifactId>proc</artifactId><version>1.5.3</version>
  <dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.18.0</version></dependency></dependencies></project>`
	it := f.run()
	wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	h := pkgsByName(it)["org.apache.commons:commons-lang3"].Hint()
	if h == nil || h.Configuration != "runtimeClasspath" || len(h.HeldBy) != 1 || h.HeldBy[0].Parent != "org.example:proc" {
		t.Fatalf("hint = %+v", h)
	}
	if len(h.Releases) != 1 || h.Releases[0].InSpec == nil || !h.Releases[0].InSpec.Fixes || h.Releases[0].Latest == nil || !h.Releases[0].Latest.Dropped {
		t.Errorf("releases = %+v", h.Releases)
	}
}

// A Maven target the updated files still resolve below its release names the
// package that depends on it in the scan's dependency graph.
func TestMavenTargetNotUpdatedNamesTheHolder(t *testing.T) {
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.apache.commons:commons-text", "1.9", "1.10.0", "CVE-TEXT"))
	f.vulns["org.apache.commons:commons-text@1.9"] = []string{"CVE-TEXT"}
	f.resolve = func(n int, files map[string][]byte) map[string]map[string]string {
		return map[string]map[string]string{"pom.xml": {"org.apache.commons:commons-text": "1.9", "org.example:lib": "1.2.0", "org.yaml:snakeyaml": "1.30"}}
	}
	scan := f.fs.fn
	f.fs.fn = func(n int, files map[string][]byte) (scanner.FSScan, error) {
		s, err := scan(n, files)
		for i := range s.Report.Packages {
			for j := range s.Report.Packages[i].Packages {
				p := &s.Report.Packages[i].Packages[j]
				p.ID = p.Name + ":" + p.Version
				if p.Name == "org.example:lib" {
					p.DependsOn = []string{"org.apache.commons:commons-text:1.9"}
				}
			}
		}
		return s, err
	}
	it := f.run()
	wantCategory(t, it, CategoryManual, ReasonTargetNotUpdated)
	h := it.Packages[0].Hint()
	if h == nil || len(h.HeldBy) != 1 || h.HeldBy[0] != (FixHolder{Parent: "org.example:lib", ParentVersion: "1.2.0", Range: "1.9"}) || h.Configuration != "" {
		t.Errorf("hint = %+v", h)
	}
}

// A report larger than a step returns is not read, and many lines of the
// package under one parent name that parent once.
func TestGradleTreeBounds(t *testing.T) {
	big := make([]byte, worker.MaxGradleReportBytes+1)
	if gradleTree(big, "runtimeClasspath") != nil {
		t.Error("an oversized report was read")
	}
	var b strings.Builder
	b.WriteString("runtimeClasspath\n+--- p:q:1.0\n")
	for i := 0; i < 5000; i++ {
		b.WriteString("|    +--- x:y:1.0\n")
	}
	holders, direct := gradleHolders([]byte(b.String()), "runtimeClasspath", "x:y", "1.0")
	if len(holders) != 1 || holders[0].Parent != "p:q" || direct {
		t.Errorf("holders = %+v, direct %v", holders, direct)
	}
	// A line longer than a coordinate can be ends the tree.
	long := "runtimeClasspath\n+--- " + strings.Repeat("a", maxGradleLineBytes) + ":p:1\n|    +--- x:y:1.0\n"
	if holders, _ := gradleHolders([]byte(long), "runtimeClasspath", "x:y", "1.0"); len(holders) != 0 {
		t.Errorf("holders under an overlong line = %+v", holders)
	}
	// A line deeper than its place ends the tree.
	holders, _ = gradleHolders([]byte("runtimeClasspath\n|    |    +--- x:y:1.0\n"), "runtimeClasspath", "x:y", "1.0")
	if len(holders) != 0 {
		t.Errorf("holders of a broken tree = %+v", holders)
	}
}

// The reads of the hint of one package are counted over all its dependents.
func TestMavenHolderReadsAreSharedByThePackage(t *testing.T) {
	f := newMavenFlow(t, map[string]string{"svc/pom.xml": appPom}, mavenPkg("org.apache.commons:commons-text", "1.9", "1.10.0", "CVE-TEXT"))
	p := &f.item.Packages[0]
	p.Action, p.Reason = ActionManual, ReasonTargetNotUpdated
	p.FixHint = &FixHint{HeldBy: []FixHolder{{Parent: "a:one", ParentVersion: "1.0"}, {Parent: "b:two", ParentVersion: "1.0"}}}
	f.reg.versions["a:one"] = []string{"1.0", "1.1"}
	f.reg.versions["b:two"] = []string{"1.0", "1.1"}
	old := maxDeciderReads
	maxDeciderReads = 3
	defer func() { maxDeciderReads = old }()
	classify(&f.item)
	f.run()
	n := 0
	for _, a := range f.reg.asked {
		if strings.Contains(a, "a:one") || strings.Contains(a, "b:two") {
			n++
		}
	}
	if n > 3 {
		t.Errorf("%d reads for one package: %v", n, f.reg.asked)
	}
}
