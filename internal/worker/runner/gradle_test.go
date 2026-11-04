//go:build unix

package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func TestGradleChildEnv(t *testing.T) {
	// Settings of the program's own environment must not reach the command.
	for k, v := range map[string]string{"GRADLE_OPTS": "-Dx=1", "JAVA_OPTS": "-Dy=2", "GRADLE_USER_HOME": "/x", "JAVA_HOME": "/other", "https_proxy": "http://p"} {
		t.Setenv(k, v)
	}
	c := Config{TmpDir: "/tmp", HomeDir: "/home/worker", Path: "/opt/kestrelynx-tools/bin:/usr/bin:/bin"}
	got := map[string]string{}
	for _, kv := range c.childEnv(worker.ManagerGradle) {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if got["JAVA_HOME"] != "/opt/java/openjdk" || got["GRADLE_USER_HOME"] != "/tmp/kestrelynx-cache/gradle" || got["HOME"] != "/home/worker" {
		t.Errorf("env %v", got)
	}
	if !strings.HasPrefix(got["GRADLE_USER_HOME"], c.cacheDir()+"/") {
		t.Errorf("the user home %s is outside %s", got["GRADLE_USER_HOME"], c.cacheDir())
	}
	for _, k := range []string{"GRADLE_OPTS", "JAVA_OPTS", "https_proxy"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s reached the command", k)
		}
	}
	// The other managers get none of it.
	for _, m := range []worker.Manager{worker.ManagerNpm, worker.ManagerPnpm, worker.ManagerUv, worker.ManagerPip, worker.ManagerGo} {
		for _, kv := range c.childEnv(m) {
			if strings.HasPrefix(kv, "GRADLE") || strings.HasPrefix(kv, "JAVA_") {
				t.Errorf("%s env has %s", m, kv)
			}
		}
	}
}

// gradleFiles are the inputs of a project that has every file a job may carry.
var gradleFiles = map[string]string{
	"gradle.lockfile":                          "org.yaml:snakeyaml:2.2=runtimeClasspath\nempty=annotationProcessor\n",
	"build.gradle.kts":                         "plugins { java }\n",
	"settings.gradle.kts":                      "rootProject.name = \"x\"\n",
	"gradle.properties":                        "org.gradle.jvmargs=-Xmx512m\n",
	"gradle/libs.versions.toml":                "[versions]\n",
	"gradle/wrapper/gradle-wrapper.properties": "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip\n",
	"settings-gradle.lockfile":                 "empty=incomingCatalogForLibs0\n",
	"buildscript-gradle.lockfile":              "empty=classpath\n",
}

// gradleScript is a fake gradle: it records what it was started with, makes
// the directories Gradle makes in a project, and rewrites the lockfile.
const gradleScript = `
echo "$@" > "$GRADLE_USER_HOME_RECORD"
{ echo "JAVA_HOME=$JAVA_HOME"; echo "GRADLE_USER_HOME=$GRADLE_USER_HOME"; echo "GRADLE_OPTS=$GRADLE_OPTS"; echo "PWD=$PWD"; } >> "$GRADLE_USER_HOME_RECORD"
mkdir -p .gradle/8 build/tmp
echo x > .gradle/8/state
echo "org.yaml:snakeyaml:2.7=runtimeClasspath" > gradle.lockfile
%s
`

func gradleFixture(t *testing.T, extra string) (*env, *worker.Job, string) {
	t.Helper()
	e := newEnv(t)
	record := filepath.Join(t.TempDir(), "record")
	t.Setenv("GRADLE_OPTS", "-Dnot=inherited")
	// The record path is given to the script by the script text, not by the
	// environment, which the program does not pass on.
	script := strings.Replace(gradleScript, "$GRADLE_USER_HOME_RECORD", record, 2)
	e.program("gradle", strings.Replace(script, "%s", extra, 1))
	job := &worker.Job{
		Protocol: worker.ProtocolVersion, Manager: worker.ManagerGradle, Runtime: testRuntime("gradle9.8.2-jdk21"),
		Steps:   []worker.Step{{ID: "locks", Op: worker.OpGradleUpdateLocks, Packages: []worker.Package{{Name: "org.yaml:snakeyaml"}}}},
		Outputs: worker.OutputNames(worker.ManagerGradle), DeadlineSeconds: 30,
	}
	for _, name := range worker.InputNames(worker.ManagerGradle) {
		content, ok := gradleFiles[name]
		if !ok {
			continue // the other form of a script
		}
		p := filepath.Join(e.cfg.WorkDir, "src", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		e.write(p, content)
		job.Inputs = append(job.Inputs, worker.Input{Path: name, Size: int64(len(content)), SHA256: sum(content)})
	}
	return e, job, record
}

func TestGradleRunsInTheNestedProjectAndReturnsEveryInput(t *testing.T) {
	e, job, record := gradleFixture(t, "")
	res, err := e.run(job)
	if err != nil || res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("err %v result %+v", err, res)
	}
	if len(res.Steps) != 1 || strings.Join(res.Steps[0].Argv, " ") !=
		"gradle --no-daemon --no-build-cache -q -Porg.gradle.java.installations.auto-download=false dependencies --update-locks org.yaml:snakeyaml" {
		t.Errorf("steps %+v", res.Steps)
	}
	if got := e.read("final", "gradle.lockfile"); got != "org.yaml:snakeyaml:2.7=runtimeClasspath\n" {
		t.Errorf("lockfile %q", got)
	}
	// Every other input comes back as it was, at its own path.
	for name, content := range gradleFiles {
		if name == "gradle.lockfile" {
			continue
		}
		if got := e.read("final", name); got != content {
			t.Errorf("%s = %q", name, got)
		}
	}
	// What Gradle makes in the project is not returned.
	for name := range e.files {
		if strings.Contains(name, ".gradle/") || strings.Contains(name, "build/") {
			t.Errorf("the result holds %s", name)
		}
	}
	rec, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"JAVA_HOME=/opt/java/openjdk", "GRADLE_USER_HOME=" + e.cfg.TmpDir + "/kestrelynx-cache/gradle", "GRADLE_OPTS=\n"} {
		if !strings.Contains(string(rec), want) {
			t.Errorf("the command's environment lacks %q:\n%s", want, rec)
		}
	}
	if strings.Contains(string(rec), e.cfg.WorkDir) {
		t.Errorf("gradle ran in /work:\n%s", rec)
	}
}

func TestGradleInputsTheStepChangedAreReturnedAsTheyAre(t *testing.T) {
	// The program does not judge the files; the caller compares them.
	e, job, _ := gradleFixture(t, "echo 'org.gradle.jvmargs=-Xmx9g' > gradle.properties; rm -f gradle/libs.versions.toml")
	res, err := e.run(job)
	if err != nil || res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("err %v result %+v", err, res)
	}
	if got := e.read("final", "gradle.properties"); got != "org.gradle.jvmargs=-Xmx9g\n" {
		t.Errorf("gradle.properties %q", got)
	}
	if _, ok := e.files["final/gradle/libs.versions.toml"]; ok {
		t.Error("a removed input is returned")
	}
	for _, o := range res.Final {
		if o.Path == "gradle/libs.versions.toml" {
			t.Error("a removed input is listed")
		}
	}
}

func TestGradleFailureCarriesTheStreamTails(t *testing.T) {
	e, job, _ := gradleFixture(t, "echo 'FAILURE: Build failed' >&2; exit 1")
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusStepFailed || len(res.Steps) != 1 || res.Steps[0].ExitCode != 1 ||
		!strings.Contains(res.Steps[0].Stderr, "Build failed") || len(res.Final) != 0 {
		t.Errorf("%+v", res)
	}
}

func TestGradleUnexpectedEntriesStillFailTheStep(t *testing.T) {
	e, job, _ := gradleFixture(t, "echo x > init.gradle")
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusStepFailed || res.Steps[0].Reason != worker.ReasonUnexpectedFiles ||
		len(res.Steps[0].UnexpectedPaths) != 1 || res.Steps[0].UnexpectedPaths[0] != "init.gradle" {
		t.Errorf("%+v", res)
	}
}

func TestGradleADirectoryReplacedByALinkIsNotFollowed(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "libs.versions.toml"), []byte("stolen"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, job, _ := gradleFixture(t, "rm -rf gradle; ln -s "+secret+" gradle")
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusStepFailed {
		t.Fatalf("%+v", res)
	}
	for name, content := range e.files {
		if strings.Contains(string(content), "stolen") {
			t.Errorf("%s holds what the link pointed at", name)
		}
	}
}

func TestGradleInputRejections(t *testing.T) {
	cases := map[string]func(e *env, job *worker.Job){
		"a directory that is a link": func(e *env, job *worker.Job) {
			src := filepath.Join(e.cfg.WorkDir, "src")
			real := filepath.Join(e.cfg.WorkDir, "elsewhere")
			if err := os.Rename(filepath.Join(src, "gradle"), real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, filepath.Join(src, "gradle")); err != nil {
				t.Fatal(err)
			}
		},
		"an undeclared file in a directory": func(e *env, job *worker.Job) {
			e.write(filepath.Join(e.cfg.WorkDir, "src", "gradle", "init.gradle"), "x")
		},
		"an undeclared directory": func(e *env, job *worker.Job) {
			if err := os.MkdirAll(filepath.Join(e.cfg.WorkDir, "src", "buildSrc"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a file where a directory is declared": func(e *env, job *worker.Job) {
			p := filepath.Join(e.cfg.WorkDir, "src", "gradle", "wrapper")
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			e.write(p, "x")
		},
		"a changed nested file": func(e *env, job *worker.Job) {
			e.write(filepath.Join(e.cfg.WorkDir, "src", "gradle", "libs.versions.toml"), "[versions]\nx = \"1\"\n")
		},
		"a nested file that is a link": func(e *env, job *worker.Job) {
			p := filepath.Join(e.cfg.WorkDir, "src", "gradle", "libs.versions.toml")
			os.Remove(p)
			if err := os.Symlink(filepath.Join(e.cfg.WorkDir, "src", "gradle.properties"), p); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			e, job, _ := gradleFixture(t, "")
			mut(e, job)
			res, _ := e.run(job)
			if res == nil || res.Status != worker.StatusInputRejected || len(res.Steps) != 0 {
				t.Errorf("%+v", res)
			}
		})
	}
}

// gradleVersionScript is a fake gradle for the check of the runtime.
const gradleVersionScript = `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo
  echo "------------------------------------------------------------"
  echo "Gradle %s"
  echo "------------------------------------------------------------"
  echo
  echo "Launcher JVM:  %s.0.13 (Eclipse Adoptium %s.0.13+9-LTS)"
  echo "Daemon JVM:    /opt/java/openjdk (no Daemon JVM specified, using current Java home)"
  exit 0
fi
`

func TestEnvironmentGradleVersionAndJDKAreChecked(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bin", "java"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, _ := worker.LookupRuntime("gradle9.8.2-jdk21")
	for name, c := range map[string]struct {
		version, jdk string
		ok           bool
	}{
		"the version and the JDK of the row": {spec.Version, spec.JDK, true},
		"another version":                    {"9.8.1", spec.JDK, false},
		"another JDK":                        {spec.Version, "17", false},
	} {
		e, job, _ := gradleFixture(t, "")
		bin := filepath.Join(t.TempDir(), "gradle")
		script := strings.NewReplacer("%s.0.13", c.jdk+".0.13").Replace(gradleVersionScript)
		script = strings.Replace(script, "Gradle %s", "Gradle "+c.version, 1)
		e.write(bin, script)
		if err := os.Chmod(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		e.cfg.Environment = &EnvironmentConfig{
			SkipSelfCheck: true, ToolsRoot: filepath.Join(e.cfg.TmpDir, "tools"), VersionTimeout: 10e9,
			Interpreter: func(worker.RuntimeSpec) string { return bin }, JavaHome: home,
		}
		e.cfg.BinDir = filepath.Join(e.cfg.TmpDir, "tools", "bin")
		e.cfg.Path = e.cfg.BinDir + ":/usr/bin:/bin"
		if err := os.MkdirAll(e.cfg.Environment.ToolsRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		res, _ := e.run(job)
		switch {
		case res == nil:
			t.Errorf("%s: no result", name)
		case c.ok && res.Status != worker.StatusCompleted && len(res.Steps) == 0:
			// The fake answers --version only, so the step itself may fail; the
			// check of the runtime must have passed.
			t.Errorf("%s: %+v", name, res)
		case !c.ok && (res.Status != worker.StatusEnvironmentRejected || len(res.Steps) != 0):
			t.Errorf("%s: %+v", name, res)
		}
	}
}

// What the gradle run printed is returned as the report of the step, from its
// start and up to the bound, with control characters taken out.
func TestGradleStepReturnsWhatItPrinted(t *testing.T) {
	e, job, _ := gradleFixture(t, `printf 'runtimeClasspath - Runtime classpath.\n+--- a:b:1.0\n|    \\--- c:d:2.0\n\033[0m'`)
	res, err := e.run(job)
	if err != nil || res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("err %v result %+v", err, res)
	}
	want := "runtimeClasspath - Runtime classpath.\n+--- a:b:1.0\n|    \\--- c:d:2.0\n[0m"
	if got := e.read("steps/locks", worker.GradleReportName); got != want {
		t.Errorf("report = %q", got)
	}
	found := false
	for _, o := range res.Steps[0].Outputs {
		found = found || o.Path == worker.GradleReportName && o.Size == int64(len(want))
	}
	if !found {
		t.Errorf("outputs = %+v", res.Steps[0].Outputs)
	}
	if _, ok := e.files["final/"+worker.GradleReportName]; ok {
		t.Error("the report is in the final tree")
	}
}

func TestHeadBufferKeepsTheStart(t *testing.T) {
	h := &headBuffer{max: 5}
	h.Write([]byte("abc"))
	h.Write([]byte("defg"))
	if n, _ := h.Write([]byte("h")); n != 1 || string(h.buf) != "abcde" {
		t.Errorf("buf = %q", h.buf)
	}
}
