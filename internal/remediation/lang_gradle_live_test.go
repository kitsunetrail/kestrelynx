package remediation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The Gradle tests that run for real use the real Maven Central, the official
// Gradle images the runtime table pins in a real Docker daemon, the work
// program built from this source and a real Trivy with its database cached.
// TestGradleUpdateLive runs when KESTRELYNX_GRADLE_IT=1 and
// TestGradleUpdateThroughTheWorkProgram when KESTRELYNX_DOCKER_IT=1;
// KESTRELYNX_DOCKER_SOCK, KESTRELYNX_TRIVY_BIN and KESTRELYNX_TRIVY_CACHE are
// as in the other integration tests. No pull request is made, and no GitHub
// request: the files the update reads are served from memory.

type gradleLiveEnv struct {
	work     WorkRunner
	trivy    scanner.Trivy
	prepared scanner.ScanConditions
	platform string
	program  func() ([]byte, error)
	// ran are the runtimes a job ran in.
	ran []string
}

func gradleLiveSetup(t *testing.T, gate string) *gradleLiveEnv {
	t.Helper()
	if os.Getenv(gate) != "1" {
		t.Skipf("set %s=1 to run a Gradle update against Maven Central, Docker and Trivy", gate)
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	home, _ := os.UserHomeDir()
	bin := os.Getenv("KESTRELYNX_TRIVY_BIN")
	if bin == "" {
		bin = filepath.Join(home, ".local", "bin", "trivy")
	}
	cache := os.Getenv("KESTRELYNX_TRIVY_CACHE")
	if cache == "" {
		cache = filepath.Join(home, ".cache", "trivy")
	}
	platform := "linux/" + runtime.GOARCH
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		t.Fatal(err)
	}
	instance := hex.EncodeToString(idb[:])
	e := &gradleLiveEnv{platform: platform, program: itProgram(t, runtime.GOARCH)}
	set := docker.NewWorkSet()
	set.SetFactory(func(key string) (*docker.WorkClient, error) {
		spec, ok := worker.LookupRuntime(key)
		if !ok || spec.Kind != worker.KindGradle {
			t.Fatalf("the factory is asked for %q", key)
		}
		var cover []string
		for _, p := range spec.CoveredPaths {
			if !slices.Contains([]string{"/tmp", "/var/tmp", "/run/lock", "/go"}, p) {
				cover = append(cover, p)
			}
		}
		return docker.NewWork(sock, docker.WorkConfig{
			Image: spec.ImageRef(), Platform: platform,
			ExpectEnv:      map[string]string{spec.VersionEnv(): spec.Version, "JAVA_HOME": worker.GradleJavaHome},
			CoverPaths:     cover,
			Entrypoint:     []string{worker.ProgramPath, "run", worker.JobFile},
			Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + worker.HomeDir},
			AllowedEnvKeys: []string{"PATH", "HOME"}, InstanceID: instance,
			Limits: docker.TransferLimits{
				MaxInputBytes: 8 << 20, MaxInputTarBytes: 128 << 20, MaxInputFiles: worker.MaxInputs + 4, MaxInputPathBytes: 256,
				MaxToolBytes: worker.MaxToolArchiveBytes, MaxProgramBytes: 16 << 20, LogMaxBytes: 8 << 20, MaxStdoutBytes: 8 << 20,
			},
			PullTimeout: 15 * time.Minute,
		})
	})
	t.Cleanup(func() {
		if _, err := set.CleanupStale(context.Background()); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		out, err := exec.Command("docker", "ps", "-a", "-q", "--filter", "label=io.kestrelynx.work.instance="+instance).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			t.Errorf("work containers left behind: %s", out)
		}
	})
	e.work = &recordingWork{inner: set, ran: &e.ran}
	e.trivy = scanner.Trivy{BinPath: bin, Severity: []string{"HIGH", "CRITICAL"}, CacheDir: cache, SkipDBUpdate: true}
	prepared, err := e.trivy.CurrentConditions(context.Background())
	if err != nil {
		t.Fatalf("trivy conditions: %v", err)
	}
	e.prepared = prepared
	return e
}

// recordingWork runs jobs with the real client and notes the runtime of each.
type recordingWork struct {
	inner WorkRunner
	ran   *[]string
}

func (w *recordingWork) RunJob(ctx context.Context, spec docker.JobSpec) (docker.JobResult, error) {
	*w.ran = append(*w.ran, spec.Runtime)
	return w.inner.RunJob(ctx, spec)
}

// liveProject reads a project of testdata/gradle-live.
func liveProject(t *testing.T, name string) map[string]string {
	t.Helper()
	root := filepath.Join("testdata", "gradle-live", name)
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// injectingScanner is a real Trivy that also reports a finding the database
// has none for: id for the lockfile entries of package at version, as the
// scan of the image the plan is made from would have.
type injectingScanner struct {
	scanner.Trivy
	pkg, version, id, fixed string
}

func (s injectingScanner) ScanFS(ctx context.Context, files map[string][]byte, p scanner.ScanConditions) (scanner.FSScan, error) {
	return s.ScanFSWith(ctx, files, p, scanner.FSOptions{})
}

func (s injectingScanner) ScanFSWith(ctx context.Context, files map[string][]byte, p scanner.ScanConditions, o scanner.FSOptions) (scanner.FSScan, error) {
	res, err := s.Trivy.ScanFSWith(ctx, files, p, o)
	if err != nil {
		return res, err
	}
	if strings.Contains(string(files["gradle.lockfile"]), s.pkg+":"+s.version+"=") {
		res.Report.Findings = append(res.Report.Findings, scanner.Finding{Class: inventory.ClassLang, Type: "gradle", Target: "gradle.lockfile",
			Package: s.pkg, InstalledVer: s.version, FixedVer: s.fixed, VulnID: s.id, Status: scanner.StatusFixed, Severity: scanner.SeverityHigh})
	}
	return res, nil
}

// liveItem is the item the plan would leave for a project: the findings of a
// scan of its lockfile (the stand-in for the findings of the running image)
// become the packages to update.
func liveItem(t *testing.T, ctx context.Context, sc FSScanner, prepared scanner.ScanConditions, files map[string]string, direct map[string]bool, only ...string) LanguageItem {
	t.Helper()
	base, err := sc.ScanFS(ctx, map[string][]byte{"gradle.lockfile": []byte(files["gradle.lockfile"])}, prepared)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	groups := map[string]*LanguagePackage{}
	var order []string
	for _, f := range base.Report.Findings {
		if f.Type != "gradle" || f.FixedVer == "" || (len(only) > 0 && !slices.Contains(only, f.Package)) {
			continue
		}
		k := f.Package + "@" + f.InstalledVer
		g := groups[k]
		if g == nil {
			g = &LanguagePackage{Name: f.Package, Ecosystem: typeJar, Installed: f.InstalledVer}
			groups[k] = g
			order = append(order, k)
		}
		g.CVEs = append(g.CVEs, CVERef{VulnID: f.VulnID, Severity: f.Severity, FixedVers: splitFixed(f.FixedVer)})
	}
	sort.Strings(order)
	src := SourceRecord{Repository: "o/r", BaseBranch: "main", Directory: ".", CommitSHA: testCommit, Origin: OriginConfig, Confidence: ConfidenceAsserted}
	for _, rel := range sortedMapKeys(files) {
		src.Files = append(src.Files, SourceFile{Path: rel, BlobSHA: gitBlobSHA([]byte(files[rel]))})
	}
	src.Absent = []string{"gradle.properties", "settings-gradle.lockfile", "buildscript-gradle.lockfile", "buildSrc", "gradle/dependency-locks", "gradle/libs.versions.toml"}
	src.Absent = slices.DeleteFunc(src.Absent, func(p string) bool { _, ok := files[p]; return ok })
	it := LanguageItem{Key: "deps:o/r@main:.#gradle", Workloads: []string{"compose/p/web"}, Manager: ManagerGradle, Source: src}
	for _, k := range order {
		g := groups[k]
		target, reason, detail := chooseMavenTarget(g.Installed, g.CVEs)
		if reason != "" {
			t.Logf("%s %s: %s (%s)", g.Name, g.Installed, reason, detail)
			continue
		}
		g.SelectionLowerBound, g.Action, g.Reason = target, ActionUpdate, ReasonUpdateCandidateInSource
		g.Relation = RelationTransitive
		if direct[g.Name] {
			g.Relation = RelationDirect
		}
		it.Packages = append(it.Packages, *g)
	}
	if len(it.Packages) == 0 {
		t.Fatalf("no package to update among %d findings", len(base.Report.Findings))
	}
	classify(&it)
	return it
}

func (e *gradleLiveEnv) update(t *testing.T, ctx context.Context, sc FSScanner, work WorkRunner, files map[string]string, it LanguageItem) LanguageItem {
	t.Helper()
	ghFiles := map[string]string{}
	for p, c := range files {
		ghFiles[p] = c
	}
	cfg := LangUpdateConfig{Scanner: sc, Work: work, PyPI: &PyPIClient{}, Npm: &NpmClient{}, Maven: &MavenClient{}, GitHub: ghFor(ghFiles),
		Prepared: e.prepared, MaxJobs: 1, Platform: e.platform, Program: e.program}
	up, err := NewLangUpdater(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{it}}
	up.Run(ctx, plan)
	return plan.LanguageItems[0]
}

// logLiveResult prints what a live update came to, builds the body of the
// pull request it would make, and returns the lockfile.
func logLiveResult(t *testing.T, got LanguageItem) string {
	t.Helper()
	if got.Category != CategoryPRCandidate {
		t.Fatalf("category = %s %s (%s)", got.Category, got.Reason, got.Detail)
	}
	art := artifactsByPath(got)
	for _, p := range sortedMapKeys(art) {
		if p != "gradle.lockfile" {
			t.Logf("--- %s\n%s", p, art[p])
		}
	}
	for _, p := range got.Packages {
		if p.Action == ActionUpdate {
			t.Logf("%s %s -> %s", p.Name, p.Installed, p.AdoptedVersion)
			for _, line := range strings.Split(art["gradle.lockfile"], "\n") {
				if strings.HasPrefix(line, p.Name+":") {
					t.Logf("   lockfile: %s", line)
				}
			}
		}
	}
	for _, e := range got.Update.Gradle.Edits {
		t.Logf("edit: %+v", e)
	}
	t.Logf("companions: %+v", got.Update.Gradle.Companions)
	t.Logf("other moves: %d, e.g. %+v", len(got.Update.Gradle.Moves), got.Update.Gradle.Moves)
	sc := got.SourceCheck
	t.Logf("trivy: resolved %d, remaining %d, introduced %d", sc.Counts[0], sc.Counts[1], sc.Counts[2])
	if sc.Counts[0] == 0 || sc.Counts[2] != 0 || !sc.Passed {
		t.Errorf("source check = %+v", sc)
	}
	u := buildLanguageUnit(&got, 0)
	if u.manual {
		t.Fatalf("the pull request unit is manual: %s", u.manualDetail)
	}
	var files []FileChange
	for p := range u.lang.artifacts {
		files = append(files, FileChange{Path: p})
	}
	body, err := buildLanguagePRBody(languageBodyInput{
		Repo: "o/r", BaseBranch: "main", BaseSHA: strings.Repeat("1", 40), LockPath: u.lang.lockPath, Root: ".",
		Item: &got, Record: u.lang.record, Files: files, Workloads: got.Workloads, Marker: "<!-- marker -->", Language: BodyEN,
	})
	if err != nil {
		t.Fatalf("pull request body: %v", err)
	}
	for _, want := range []string{"Gradle update", "gradle.update_locks", "--write-locks", "Maven Central"} {
		if !strings.Contains(body, want) {
			t.Errorf("the body lacks %q", want)
		}
	}
	t.Logf("pull request body:\n%s", body)
	return art["gradle.lockfile"]
}

func lockHas(t *testing.T, lock, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(lock, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	t.Errorf("the lockfile has no line %s...", prefix)
	return ""
}

func TestGradleUpdateLive(t *testing.T) {
	e := gradleLiveSetup(t, "KESTRELYNX_GRADLE_IT")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	t.Run("commons-text: a declaration and a constraint", func(t *testing.T) {
		// The finding of commons-lang3 is of medium severity, so this run
		// scans for medium findings too.
		tr := e.trivy
		tr.Severity = []string{"MEDIUM", "HIGH", "CRITICAL"}
		med := *e
		var err error
		if med.prepared, err = tr.CurrentConditions(ctx); err != nil {
			t.Fatal(err)
		}
		files := liveProject(t, "commons-text")
		it := liveItem(t, ctx, tr, med.prepared, files, map[string]bool{"org.apache.commons:commons-text": true})
		got := med.update(t, ctx, tr, e.work, files, it)
		lock := logLiveResult(t, got)
		if l := lockHas(t, lock, "org.apache.commons:commons-text:"); !strings.HasPrefix(l, "org.apache.commons:commons-text:1.10.0=") {
			t.Errorf("commons-text line = %q", l)
		}
		if l := lockHas(t, lock, "org.apache.commons:commons-lang3:"); strings.HasPrefix(l, "org.apache.commons:commons-lang3:3.11=") || strings.HasPrefix(l, "org.apache.commons:commons-lang3:3.12") {
			t.Errorf("commons-lang3 line = %q", l)
		}
		build := artifactsByPath(got)["build.gradle"]
		if !strings.Contains(build, "commons-text:1.10.0'") || !strings.Contains(build, "constraints {") {
			t.Errorf("build.gradle:\n%s", build)
		}
	})

	tomcat := []string{"org.apache.tomcat.embed:tomcat-embed-core", "org.apache.tomcat.embed:tomcat-embed-el", "org.apache.tomcat.embed:tomcat-embed-websocket"}
	t.Run("Spring Boot: the property is set in the build script", func(t *testing.T) {
		files := liveProject(t, "boot-tomcat")
		it := liveItem(t, ctx, e.trivy, e.prepared, files, nil, tomcat...)
		got := e.update(t, ctx, e.trivy, e.work, files, it)
		lock := logLiveResult(t, got)
		for _, n := range tomcat {
			if l := lockHas(t, lock, n+":"); strings.HasPrefix(l, n+":11.0.5=") {
				t.Errorf("%s was not updated: %q", n, l)
			}
		}
		if e := got.Update.Gradle.Edits[0]; e.Kind != GradleEditProperty || e.Property != "tomcat.version" || e.From != "11.0.5" {
			t.Errorf("edit = %+v", e)
		}
		if _, ok := artifactsByPath(got)["gradle.properties"]; ok {
			t.Error("gradle.properties was made")
		}
	})

	t.Run("Spring Boot: the property is set in gradle.properties", func(t *testing.T) {
		files := liveProject(t, "boot-tomcat")
		files["build.gradle.kts"] = strings.Replace(files["build.gradle.kts"], "\nextra[\"tomcat.version\"] = \"11.0.5\"\n", "", 1)
		files["gradle.properties"] = "org.gradle.parallel=true\ntomcat.version=11.0.5\n"
		it := liveItem(t, ctx, e.trivy, e.prepared, files, nil, tomcat...)
		got := e.update(t, ctx, e.trivy, e.work, files, it)
		logLiveResult(t, got)
		if p := artifactsByPath(got)["gradle.properties"]; !strings.HasPrefix(p, "org.gradle.parallel=true\ntomcat.version=11.0.") || strings.Contains(p, "11.0.5\n") {
			t.Errorf("gradle.properties = %q", p)
		}
	})

	// The scaffold's lockfile is clean in the local database, so these scans
	// report a finding for a package of the scaffold, as the scan of an image
	// with a vulnerable one would, and the real Trivy judges the rest.
	cleanBoot := func() map[string]string {
		files := liveProject(t, "boot-tomcat")
		files["build.gradle.kts"] = strings.Replace(files["build.gradle.kts"], "\nextra[\"tomcat.version\"] = \"11.0.5\"\n", "", 1)
		for _, n := range []string{"core", "el", "websocket"} {
			files["gradle.lockfile"] = strings.ReplaceAll(files["gradle.lockfile"], "tomcat-embed-"+n+":11.0.5=", "tomcat-embed-"+n+":11.0.27=")
		}
		return files
	}
	t.Run("Spring Boot: a property written into a gradle.properties that is made", func(t *testing.T) {
		files := cleanBoot()
		sc := injectingScanner{Trivy: e.trivy, pkg: "org.yaml:snakeyaml", version: "2.6", id: "CVE-0000-SNAKEYAML", fixed: "2.7"}
		it := liveItem(t, ctx, sc, e.prepared, files, nil, "org.yaml:snakeyaml")
		got := e.update(t, ctx, sc, e.work, files, it)
		lock := logLiveResult(t, got)
		if l := lockHas(t, lock, "org.yaml:snakeyaml:"); !strings.HasPrefix(l, "org.yaml:snakeyaml:2.7=") {
			t.Errorf("snakeyaml line = %q", l)
		}
		if p := artifactsByPath(got)["gradle.properties"]; p != "snakeyaml.version=2.7\n" {
			t.Errorf("gradle.properties = %q", p)
		}
		if e := got.Update.Gradle.Edits[0]; e.Kind != GradleEditPropertyOverride {
			t.Errorf("edit = %+v", e)
		}
	})
	t.Run("Spring Boot: the property of a BOM the Spring Boot BOM imports", func(t *testing.T) {
		files := cleanBoot()
		sc := injectingScanner{Trivy: e.trivy, pkg: "tools.jackson.core:jackson-databind", version: "3.1.7", id: "CVE-0000-JACKSON", fixed: "3.1.8"}
		it := liveItem(t, ctx, sc, e.prepared, files, nil, "tools.jackson.core:jackson-databind")
		got := e.update(t, ctx, sc, e.work, files, it)
		lock := logLiveResult(t, got)
		if l := lockHas(t, lock, "tools.jackson.core:jackson-databind:"); !strings.HasPrefix(l, "tools.jackson.core:jackson-databind:3.1.8=") {
			t.Errorf("jackson-databind line = %q", l)
		}
		if p := artifactsByPath(got)["gradle.properties"]; p != "jackson-bom.version=3.1.8\n" {
			t.Errorf("gradle.properties = %q", p)
		}
	})

	for _, rt := range e.ran {
		if !strings.HasPrefix(rt, "gradle9.8.2-jdk") {
			t.Errorf("a job ran in %s", rt)
		}
	}
}

// replaceResultFile changes a file of a decoded result and the size and hash
// result.json declares for it, as a work container that wanted the change
// accepted would.
func replaceResultFile(t *testing.T, files map[string][]byte, name string, content []byte) {
	t.Helper()
	var res worker.Result
	if err := json.Unmarshal(files[worker.ResultName], &res); err != nil {
		t.Fatal(err)
	}
	fix := func(prefix string, list []worker.OutputFile) {
		for i := range list {
			if prefix+"/"+list[i].Path == name {
				list[i].Size, list[i].SHA256 = int64(len(content)), sha256Hex(content)
			}
		}
	}
	for i := range res.Steps {
		fix(worker.StepsDir+"/"+res.Steps[i].ID, res.Steps[i].Outputs)
	}
	fix(worker.FinalDir, res.Final)
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files[worker.ResultName] = raw
	files[name] = content
}

// tamperingWork runs the first job with the real client and answers every
// job with that job's result, changed by mutate: what a work container that
// returned something else would have returned, in the real result format.
type tamperingWork struct {
	t      *testing.T
	inner  WorkRunner
	first  map[string][]byte
	mutate func(files map[string][]byte)
	calls  int
}

func (w *tamperingWork) RunJob(ctx context.Context, spec docker.JobSpec) (docker.JobResult, error) {
	w.calls++
	if w.first == nil {
		res, err := w.inner.RunJob(ctx, spec)
		if err != nil || res.ExitCode != 0 {
			return res, err
		}
		files, derr := worker.DecodeResult(res.Stdout, worker.DefaultResultLimits())
		if derr != nil {
			w.t.Fatalf("the real result: %v", derr)
		}
		w.first = files
	}
	files := map[string][]byte{}
	for k, v := range w.first {
		files[k] = v
	}
	if w.mutate != nil {
		w.mutate(files)
	}
	block, err := worker.EncodeResult(files)
	if err != nil {
		w.t.Fatal(err)
	}
	return docker.JobResult{Stdout: block}, nil
}

// TestGradleUpdateThroughTheWorkProgram runs the work program in a real
// container once, and checks what the update does with the result as it is and
// with the result changed the ways the checks of the output are for.
func TestGradleUpdateThroughTheWorkProgram(t *testing.T) {
	e := gradleLiveSetup(t, "KESTRELYNX_DOCKER_IT")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	files := liveProject(t, "commons-text")
	it := liveItem(t, ctx, e.trivy, e.prepared, files, map[string]bool{"org.apache.commons:commons-text": true}, "org.apache.commons:commons-text")
	real := &tamperingWork{t: t, inner: e.work}

	lockOf := func(f map[string][]byte) string { return string(f[worker.FinalDir+"/gradle.lockfile"]) }
	setLock := func(f map[string][]byte, lock string) {
		replaceResultFile(t, f, worker.FinalDir+"/gradle.lockfile", []byte(lock))
		replaceResultFile(t, f, worker.StepsDir+"/"+stepUpdate+"/gradle.lockfile", []byte(lock))
	}
	cases := []struct {
		name   string
		mutate func(f map[string][]byte)
		cat    Category
		reason Reason
	}{
		{"as the container returned it", nil, CategoryPRCandidate, ReasonUpdateVerified},
		{"an entry taken out", func(f map[string][]byte) {
			var kept []string
			for _, l := range strings.Split(lockOf(f), "\n") {
				if !strings.HasPrefix(l, "org.apache.commons:commons-lang3:") {
					kept = append(kept, l)
				}
			}
			setLock(f, strings.Join(kept, "\n"))
		}, CategoryManual, ReasonGradleLockEntryRemoved},
		{"a configuration that vanished", func(f map[string][]byte) {
			setLock(f, strings.ReplaceAll(lockOf(f), ",testRuntimeClasspath", ""))
		}, CategoryManual, ReasonGradleLockConfigurationsChanged},
		{"another file changed", func(f map[string][]byte) {
			replaceResultFile(t, f, worker.FinalDir+"/settings.gradle", []byte("rootProject.name = 'x'\n"))
		}, CategoryManual, ReasonOutputFilesInvalid},
		{"a coordinate Maven Central does not have", func(f map[string][]byte) {
			setLock(f, strings.Replace(lockOf(f), "empty=", "org.example.nothing:ghost:9.9.9=compileClasspath\nempty=", 1))
		}, CategoryManual, ReasonDistributionMismatch},
		{"a partial output", func(f map[string][]byte) { delete(f, worker.FinalDir+"/settings.gradle") }, CategoryFailed, ReasonUpdateResultInvalid},
		{"the same entry twice", func(f map[string][]byte) {
			setLock(f, strings.Replace(lockOf(f), "empty=", "org.apache.commons:commons-text:1.10.0=compileClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath\nempty=", 1))
		}, CategoryManual, ReasonOutputFilesInvalid},
		{"two versions in one configuration", func(f map[string][]byte) {
			setLock(f, strings.Replace(lockOf(f), "empty=", "org.apache.commons:commons-text:1.11.0=compileClasspath\nempty=", 1))
		}, CategoryManual, ReasonOutputFilesInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			real.mutate = c.mutate
			item := it
			item.Packages = append([]LanguagePackage(nil), it.Packages...)
			got := e.update(t, ctx, e.trivy, real, files, item)
			wantCategory(t, got, c.cat, c.reason)
			if c.cat != CategoryPRCandidate && got.Artifacts != nil {
				t.Error("the item keeps files of a refused update")
			}
			t.Logf("%s %s: %s", got.Category, got.Reason, got.Detail)
		})
	}
}
