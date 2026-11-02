package remediation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// bootBOM is a Spring Boot BOM that sets a few packages through properties and
// imports the Jackson BOM through another.
const bootBOM = `<project>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>4.1.2</version>
  <packaging>pom</packaging>
  <properties>
    <commons-lang3.version>3.11</commons-lang3.version>
    <snakeyaml.version>2.6</snakeyaml.version>
    <jackson-bom.version>2.13.3</jackson-bom.version>
    <junit-jupiter.version>5.10.0</junit-jupiter.version>
    <literal.version>1.0</literal.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>${commons-lang3.version}</version></dependency>
      <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${snakeyaml.version}</version></dependency>
      <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml-engine</artifactId><version>${snakeyaml.version}</version></dependency>
      <dependency><groupId>org.example</groupId><artifactId>literal</artifactId><version>1.0</version></dependency>
      <dependency><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>${jackson-bom.version}</version><type>pom</type><scope>import</scope></dependency>
    </dependencies>
  </dependencyManagement>
</project>`

// gradleFlow runs the update of one Gradle item against fakes: a Maven Central
// that lists the releases the test gives, a work container that makes
// gradle.lockfile with a function of the files it was given, and a scanner
// that reports the packages of the lockfile it is given.
type gradleFlow struct {
	t     *testing.T
	reg   *fakeMavenReg
	files map[string]string // relative to the unit's directory
	item  LanguageItem
	work  *fakeWork
	fs    *fakeFS
	cfg   LangUpdateConfig
	vulns map[string][]string
	// lock makes the lockfile the work container returns from the files it
	// was given.
	lock func(src map[string][]byte) string
	// outcome changes what the work container does beyond the lockfile.
	outcome func(o *fakeOutcome, lock string)
}

const gradleDir = "svc"

func newGradleFlow(t *testing.T, files map[string]string, findings ...scanner.Finding) *gradleFlow {
	t.Helper()
	f := &gradleFlow{t: t, files: files, vulns: map[string][]string{
		"org.apache.commons:commons-text@1.9":   {"CVE-TEXT"},
		"org.apache.commons:commons-lang3@3.11": {"CVE-LANG"},
	}}
	f.reg = &fakeMavenReg{
		versions: map[string][]string{
			"org.apache.commons:commons-text":                   {"1.9", "1.10.0", "1.11.0"},
			"org.apache.commons:commons-lang3":                  {"3.11", "3.12.0", "3.18.0", "3.19.0"},
			"org.yaml:snakeyaml":                                {"2.6", "2.7"},
			"org.yaml:snakeyaml-engine":                         {"2.6", "2.7"},
			"com.fasterxml.jackson.core:jackson-databind":       {"2.13.3", "2.13.4", "2.13.4.2"},
			"com.fasterxml.jackson:jackson-bom":                 {"2.13.3", "2.13.4", "2.13.4.20221013", "2.14.0"},
			"org.springframework.boot:spring-boot-dependencies": {"4.1.2"},
			"org.junit.jupiter:junit-jupiter":                   {"5.10.0", "5.10.2"},
		},
		poms: map[string]string{
			"org.springframework.boot:spring-boot-dependencies:4.1.2": bootBOM,
			"com.fasterxml.jackson:jackson-bom:2.13.3":                jacksonBOM("2.13.3", "2.13.3"),
			"com.fasterxml.jackson:jackson-bom:2.13.4":                jacksonBOM("2.13.4", "2.13.4"),
			"com.fasterxml.jackson:jackson-bom:2.13.4.20221013":       jacksonBOM("2.13.4.20221013", "2.13.4.2"),
		},
	}
	gh := newFakeGitHub()
	gradleRepo(gh, gradleDir, files)
	in := gradleInput()
	if len(findings) > 0 {
		in = fatJarInput(findings...)
	}
	plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", gradleDir)}, nil, in)
	found := false
	for _, it := range plan.LanguageItems {
		if it.Manager == ManagerGradle {
			f.item, found = it, true
		}
	}
	if !found || f.item.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("the plan gave %+v (found %v)", f.item, found)
	}
	// The files as the updater reads them: the same text under the blob
	// hashes and the commit of the update's fakes.
	f.item.Source.CommitSHA = testCommit
	for i, sf := range f.item.Source.Files {
		rel := strings.TrimPrefix(sf.Path, gradleDir+"/")
		f.item.Source.Files[i].BlobSHA = gitBlobSHA([]byte(files[rel]))
	}
	f.lock = f.defaultLock
	f.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		lock := f.lock(src)
		o := fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"gradle.lockfile": []byte(lock)}}}
		if f.outcome != nil {
			f.outcome(&o, lock)
		}
		return o
	}}
	f.fs = &fakeFS{fn: f.scan}
	ghFiles := map[string]string{}
	for rel, c := range files {
		ghFiles[gradleDir+"/"+rel] = c
	}
	f.cfg = LangUpdateConfig{Scanner: f.fs, Work: f.work, PyPI: &fakePyPI{}, Npm: &fakeNpm{}, Maven: f.reg, GitHub: ghFor(ghFiles),
		Prepared: fsConds, MaxJobs: 5, Platform: "linux/amd64", Now: func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }}
	f.cfg = withTestTools(t, f.cfg)
	return f
}

// defaultLock is the lockfile Gradle would make from the files: commons-text
// at the version the build writes, commons-lang3 at the version commons-text
// needs unless the files raise it.
func (f *gradleFlow) defaultLock(src map[string][]byte) string {
	all := ""
	for name, c := range src {
		if name != "gradle.lockfile" {
			all += string(c) + "\n"
		}
	}
	lock := string(src["gradle.lockfile"])
	if strings.Contains(all, "1.10.0") {
		lock = strings.Replace(lock, "commons-text:1.9=", "commons-text:1.10.0=", 1)
		lock = strings.Replace(lock, "commons-lang3:3.11=", "commons-lang3:3.12.0=", 1)
	}
	for _, v := range []string{"3.18.0", "3.19.0"} {
		if strings.Contains(all, v) {
			for _, old := range []string{"3.11", "3.12.0"} {
				lock = strings.Replace(lock, "commons-lang3:"+old+"=", "commons-lang3:"+v+"=", 1)
			}
		}
	}
	return lock
}

func (f *gradleFlow) scan(n int, files map[string][]byte) (scanner.FSScan, error) {
	lock, err := parseGradleLockfile("gradle.lockfile", files["gradle.lockfile"])
	if err != nil {
		return scanner.FSScan{}, err
	}
	rep := scanner.ImageScan{TrivyVersion: "0.71.2"}
	rp := scanner.ResultPackages{Target: "gradle.lockfile", Class: inventory.ClassLang, Type: "gradle"}
	seen := map[string]bool{}
	for _, e := range lock.entries {
		if seen[e.name+"@"+e.version] {
			continue
		}
		seen[e.name+"@"+e.version] = true
		rp.Packages = append(rp.Packages, scanner.Package{Name: e.name, Version: e.version})
		for _, id := range f.vulns[e.name+"@"+e.version] {
			rep.Findings = append(rep.Findings, scanner.Finding{Class: inventory.ClassLang, Type: "gradle", Target: "gradle.lockfile", Package: e.name,
				InstalledVer: e.version, VulnID: id, Status: scanner.StatusFixed, Severity: scanner.SeverityHigh})
		}
	}
	rep.Packages = append(rep.Packages, rp)
	return scanner.FSScan{Conditions: fsConds, Report: rep}, nil
}

func (f *gradleFlow) run() LanguageItem {
	f.t.Helper()
	up, err := NewLangUpdater(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{f.item}}
	up.Run(context.Background(), plan)
	return plan.LanguageItems[0]
}

func artifactsByPath(it LanguageItem) map[string]string {
	out := map[string]string{}
	for _, a := range it.Artifacts {
		out[a.Path] = string(a.Content)
	}
	return out
}

func wantReason(t *testing.T, it LanguageItem, c Category, r Reason) {
	t.Helper()
	wantCategory(t, it, c, r)
}

func TestGradleUpdateDirectDeclarationAndBOMProperty(t *testing.T) {
	f := newGradleFlow(t, gradleFiles())
	it := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	art := artifactsByPath(it)
	if len(art) != 3 || art["svc/gradle.lockfile"] == "" {
		t.Fatalf("artifacts = %v", art)
	}
	if !strings.Contains(art["svc/build.gradle.kts"], `implementation("org.apache.commons:commons-text:1.10.0")`) {
		t.Errorf("the declaration is not changed:\n%s", art["svc/build.gradle.kts"])
	}
	if art["svc/gradle.properties"] != "commons-lang3.version=3.18.0\n" {
		t.Errorf("gradle.properties = %q", art["svc/gradle.properties"])
	}
	lock := art["svc/gradle.lockfile"]
	if !strings.Contains(lock, "commons-text:1.10.0=") || !strings.Contains(lock, "commons-lang3:3.18.0=") {
		t.Errorf("lockfile:\n%s", lock)
	}
	for _, a := range it.Artifacts {
		if a.Mode != "100644" {
			t.Errorf("%s has mode %q", a.Path, a.Mode)
		}
	}
	got := pkgsByName(it)
	if got["org.apache.commons:commons-text"].AdoptedVersion != "1.10.0" || got["org.apache.commons:commons-lang3"].AdoptedVersion != "3.18.0" {
		t.Errorf("adopted = %+v", got)
	}
	g := it.Update.Gradle
	if g == nil || len(g.Edits) != 2 || g.BOM != "org.springframework.boot:spring-boot-dependencies:4.1.2" {
		t.Fatalf("gradle = %+v", g)
	}
	kinds := map[string]GradleEditRecord{}
	for _, e := range g.Edits {
		kinds[e.Kind] = e
	}
	if e := kinds[GradleEditDeclaration]; e.File != "svc/build.gradle.kts" || e.From != "1.9" || e.To != "1.10.0" {
		t.Errorf("declaration edit = %+v", e)
	}
	if e := kinds[GradleEditPropertyOverride]; e.File != "svc/gradle.properties" || e.Property != "commons-lang3.version" || e.From != "3.11" || e.To != "3.18.0" {
		t.Errorf("override edit = %+v", e)
	}
	// The job: the unit's files as edited, at their paths relative to the
	// unit, one gradle.update_locks step for the targets.
	if len(f.work.jobs) != 1 {
		t.Fatalf("jobs = %d", len(f.work.jobs))
	}
	job := f.work.jobs[0]
	if job.Manager != worker.ManagerGradle || job.Runtime.ID != "gradle9.8.2-jdk17" || len(job.Steps) != 1 || job.Steps[0].Op != worker.OpGradleUpdateLocks {
		t.Fatalf("job = %+v", job)
	}
	var names []string
	for _, p := range job.Steps[0].Packages {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "org.apache.commons:commons-lang3,org.apache.commons:commons-text" {
		t.Errorf("step packages = %v", names)
	}
	src := f.work.srcs[0]
	for _, name := range []string{"gradle.lockfile", "build.gradle.kts", "settings.gradle.kts", "gradle/wrapper/gradle-wrapper.properties", "gradle.properties"} {
		if _, ok := src[name]; !ok {
			t.Errorf("the job lacks %s: %v", name, keysOfBytes(src))
		}
	}
	if string(src["gradle.properties"]) != art["svc/gradle.properties"] || string(src["build.gradle.kts"]) != art["svc/build.gradle.kts"] {
		t.Error("the job was not given the edited files")
	}
	if len(f.fs.opts) != 0 && f.fs.opts[0].MavenMirror != "" {
		t.Errorf("the scan of a lockfile goes through a relay: %+v", f.fs.opts)
	}
	if !it.UpdateExecuted || !it.PostUpdateCheckExecuted || it.SourceCheck == nil || !it.SourceCheck.Passed {
		t.Errorf("item = %+v", it)
	}
	if it.SourceCheck.Counts != [3]int{2, 0, 0} {
		t.Errorf("counts = %v", it.SourceCheck.Counts)
	}
	if it.Update.Runtime == nil || it.Update.Runtime.ID != "gradle9.8.2-jdk17" || it.Update.Runtime.Digest == "" {
		t.Errorf("runtime = %+v", it.Update.Runtime)
	}
	if len(g.Moves) != 0 {
		t.Errorf("moves = %+v", g.Moves)
	}
}

func keysOfBytes(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
