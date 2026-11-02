//go:build unix

package docker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

// These tests run gradle.update_locks through the work program in the official
// Gradle images the runtime table pins, in a real Docker container, with the
// real Maven Central and Gradle Plugin Portal. They run only when
// KESTRELYNX_DOCKER_IT=1.

// gradleResources are the limits the update jobs of every manager run under. A
// Spring Boot project in a Gradle job peaks at about 0.9 GiB of memory (the
// tmpfs counted), 124 processes and 55 MiB of /tmp, well inside them.
func gradleResources() Resources {
	return workexec.Resources{
		MemoryBytes: 2 << 30, NanoCPUs: 2_000_000_000, PidsLimit: 512, NofileLimit: 4096,
		ShmSizeBytes: 64 << 20, TmpSizeBytes: 512 << 20, HomeSizeBytes: 512 << 20, ToolsSizeBytes: 256 << 20,
	}
}

func TestIntegrationGradleUpdateLocks(t *testing.T) {
	if os.Getenv("KESTRELYNX_DOCKER_IT") != "1" {
		t.Skip("set KESTRELYNX_DOCKER_IT=1 to run against a real Docker daemon")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	goarch := runtime.GOARCH
	program := filepath.Join(t.TempDir(), "kestrelynx-worker")
	build := exec.Command("go", "build", "-trimpath", "-o", program, "./cmd/kestrelynx-worker")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the work program: %v\n%s", err, out)
	}
	programBytes, err := os.ReadFile(program)
	if err != nil {
		t.Fatal(err)
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	instance := hex.EncodeToString(b[:])
	// The set makes the client of a Gradle runtime when its first job arrives,
	// as the main process does.
	set := NewWorkSet()
	var made []string
	set.SetFactory(func(key string) (*WorkClient, error) {
		spec, ok := worker.LookupRuntime(key)
		if !ok || spec.Kind != worker.KindGradle {
			t.Fatalf("the factory is asked for %q", key)
		}
		made = append(made, key)
		var cover []string
		for _, p := range spec.CoveredPaths {
			if !slices.Contains([]string{"/tmp", "/var/tmp", "/run/lock", "/go"}, p) {
				cover = append(cover, p)
			}
		}
		return NewWork(sock, WorkConfig{
			Image: spec.ImageRef(), Platform: "linux/" + goarch,
			ExpectEnv:      map[string]string{spec.VersionEnv(): spec.Version, "JAVA_HOME": worker.GradleJavaHome},
			CoverPaths:     cover,
			Entrypoint:     []string{worker.ProgramPath, "run", worker.JobFile},
			Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + worker.HomeDir},
			AllowedEnvKeys: []string{"PATH", "HOME"}, InstanceID: instance,
			Limits: TransferLimits{
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
	})

	passed := map[string]bool{}
	cases := []struct {
		name, runtime, dir string
		targets            []string
		// before and after are lines of the lockfile.
		before, after []string
	}{
		{"commons-text on JDK 21", "gradle9.8.2-jdk21", "commons-text", []string{"org.apache.commons:commons-text"},
			[]string{"org.apache.commons:commons-lang3:3.11=", "org.apache.commons:commons-text:1.9="},
			[]string{"org.apache.commons:commons-lang3:3.12.0=", "org.apache.commons:commons-text:1.10.0="}},
		{"commons-text on Gradle 8 and JDK 21", "gradle8.14.6-jdk21", "commons-text", []string{"org.apache.commons:commons-text"},
			[]string{"org.apache.commons:commons-lang3:3.11=", "org.apache.commons:commons-text:1.9="},
			[]string{"org.apache.commons:commons-lang3:3.12.0=", "org.apache.commons:commons-text:1.10.0="}},
		{"Spring Boot with an overridden BOM property on JDK 17", "gradle9.8.2-jdk17", "spring-boot", []string{"org.yaml:snakeyaml"},
			[]string{"org.yaml:snakeyaml:2.6="}, []string{"org.yaml:snakeyaml:2.7="}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, ok := worker.LookupRuntime(c.runtime)
			if !ok || !spec.HasImage() {
				t.Fatalf("no runtime %s", c.runtime)
			}
			dir := filepath.Join("testdata", "gradle", c.dir)
			job := worker.Job{
				Protocol: worker.ProtocolVersion, Manager: worker.ManagerGradle, Runtime: spec.JobRuntime(),
				Outputs: worker.OutputNames(worker.ManagerGradle), DeadlineSeconds: 330, StepTimeoutSeconds: 300,
				Steps: []worker.Step{{ID: "locks", Op: worker.OpGradleUpdateLocks}},
			}
			for _, tg := range c.targets {
				job.Steps[0].Packages = append(job.Steps[0].Packages, worker.Package{Name: tg})
			}
			inputs := []InputFile{{Path: worker.ProgramInputPath, Content: programBytes, Kind: KindProgram, Executable: true}}
			content := map[string]string{}
			for _, name := range worker.InputNames(worker.ManagerGradle) {
				data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
				if os.IsNotExist(err) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(data)
				job.Inputs = append(job.Inputs, worker.Input{Path: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
				inputs = append(inputs, InputFile{Path: worker.SrcDirName + "/" + name, Content: data})
				content[name] = string(data)
			}
			for _, line := range c.before {
				if !strings.Contains(content["gradle.lockfile"], line) {
					t.Fatalf("the lockfile before has no %q", line)
				}
			}
			if err := job.Validate(); err != nil {
				t.Fatal(err)
			}
			jobJSON, err := json.Marshal(job)
			if err != nil {
				t.Fatal(err)
			}
			res, err := set.RunJob(context.Background(), JobSpec{
				JobID: "it-gradle-" + c.runtime, Runtime: c.runtime, Timeout: 6 * time.Minute,
				Inputs: append(inputs, InputFile{Path: "job.json", Content: jobJSON}), Resources: gradleResources(),
			})
			if err != nil {
				t.Fatalf("RunJob: %v", err)
			}
			files, derr := worker.DecodeResult(res.Stdout, worker.DefaultResultLimits())
			if derr != nil {
				t.Fatalf("exit %d, stdout %q: %v", res.ExitCode, clip(res.Stdout), derr)
			}
			var result worker.Result
			if err := json.Unmarshal(files[worker.ResultName], &result); err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 0 || result.Status != worker.StatusCompleted {
				t.Fatalf("exit %d, result %+v", res.ExitCode, result)
			}
			if len(result.Steps) != 1 || result.Steps[0].ExitCode != 0 {
				t.Fatalf("steps %+v", result.Steps)
			}
			lock := string(files["final/gradle.lockfile"])
			for _, line := range c.after {
				if !strings.Contains(lock, line) {
					t.Errorf("the lockfile after has no %q:\n%s", line, lock)
				}
			}
			// Every other input comes back exactly as it was sent.
			for name, before := range content {
				if name == "gradle.lockfile" {
					continue
				}
				if got := string(files["final/"+name]); got != before {
					t.Errorf("%s came back changed:\n%s", name, got)
				}
			}
			for name := range files {
				if strings.Contains(name, ".gradle/") || strings.Contains(name, "build/") {
					t.Errorf("the result holds %s", name)
				}
			}
			t.Logf("%s, %dms, stderr tail %q", strings.Join(result.Steps[0].Argv, " "), result.Steps[0].DurationMS, result.Steps[0].Stderr)
			passed[c.runtime] = !t.Failed()
		})
	}
	// One client for each runtime a job asked for, and not one for the rest.
	if len(made) != len(cases) {
		t.Errorf("the factory made %v", made)
	}
	for _, sc := range set.clients {
		assertNoLeftovers(t, sc.client)
		break
	}
	// The table update records the runtimes that were run and passed, and no
	// others, as tested: the ids are added to the file of the other test.
	if path := os.Getenv("KESTRELYNX_IT_TESTED_RUNTIMES"); path != "" && !t.Failed() {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		for id, ok := range passed {
			if ok {
				if _, err := f.WriteString(id + "\n"); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
