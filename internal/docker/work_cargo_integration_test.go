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
)

// These tests run cargo.update through the work program in the official Rust
// image the runtime table pins, in a real Docker container, with the real
// index of crates.io. They run only when KESTRELYNX_DOCKER_IT=1.

func TestIntegrationCargoUpdate(t *testing.T) {
	if os.Getenv("KESTRELYNX_DOCKER_IT") != "1" {
		t.Skip("set KESTRELYNX_DOCKER_IT=1 to run against a real Docker daemon")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	goarch := runtime.GOARCH
	program := filepath.Join(t.TempDir(), "kestrelynx-worker")
	build := exec.Command("go", "build", "-trimpath", "-tags", "kestrelynx_worker", "-o", program, "./cmd/kestrelynx-worker")
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

	spec, ok := worker.LookupRuntime("rust1.100")
	if !ok || !spec.HasImage() {
		t.Fatal("no runtime rust1.100")
	}
	var cover []string
	for _, p := range spec.CoveredPaths {
		if !slices.Contains([]string{"/tmp", "/var/tmp", "/run/lock", "/go"}, p) {
			cover = append(cover, p)
		}
	}
	wc, err := NewWork(sock, WorkConfig{
		Image: spec.ImageRef(), Platform: "linux/" + goarch,
		ExpectEnv:      map[string]string{spec.VersionEnv(): spec.Version},
		CoverPaths:     cover,
		ReadOnlyRoot:   true,
		Entrypoint:     []string{worker.ProgramPath, "run", worker.JobFile},
		Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + worker.HomeDir},
		AllowedEnvKeys: []string{"PATH", "HOME"}, InstanceID: instance,
		Limits: TransferLimits{
			MaxInputBytes: 8 << 20, MaxInputTarBytes: 128 << 20, MaxInputFiles: worker.MaxCargoInputs + 4, MaxInputPathBytes: worker.MaxInputPathBytes,
			MaxToolBytes: worker.MaxToolArchiveBytes, MaxProgramBytes: 16 << 20, LogMaxBytes: 8 << 20, MaxStdoutBytes: 8 << 20,
		},
		PullTimeout: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	set := NewWorkSet()
	if err := set.Add(spec.ID, wc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := set.CleanupStale(context.Background()); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	// A file of a project: its path, the role it has in the job and, for the
	// empty files that stand for the build targets, no content.
	type file struct{ path, role string }
	cases := []struct {
		name, dir string
		files     []file
		crate     worker.Package
		// before and after are lines of the lockfile.
		before, after []string
	}{
		{"a single crate", "single",
			[]file{{"Cargo.lock", worker.RoleLockfile}, {"Cargo.toml", worker.RoleManifest}, {"src/main.rs", worker.RoleEmpty}},
			worker.Package{Name: "tokio", From: "1.18.0", Version: "1.18.4"},
			[]string{`version = "1.18.0"`}, []string{`version = "1.18.4"`}},
		{"a workspace with members in directories", "workspace",
			[]file{{"Cargo.lock", worker.RoleLockfile}, {"Cargo.toml", worker.RoleManifest}, {"a/Cargo.toml", worker.RoleManifest}, {"b/Cargo.toml", worker.RoleManifest},
				{"a/src/main.rs", worker.RoleEmpty}, {"b/src/lib.rs", worker.RoleEmpty}},
			worker.Package{Name: "smallvec", From: "1.6.0", Version: "1.6.1"},
			[]string{`version = "1.6.0"`}, []string{`version = "1.6.1"`}},
	}
	passed := map[string]bool{}
	volumesBefore := dockerVolumes(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join("testdata", "cargo", c.dir)
			job := worker.Job{
				Protocol: worker.ProtocolVersion, Manager: worker.ManagerCargo, Runtime: spec.JobRuntime(),
				DeadlineSeconds: 330, StepTimeoutSeconds: 300,
				Steps: []worker.Step{{ID: "update", Op: worker.OpCargoUpdate, Packages: []worker.Package{c.crate}}},
			}
			inputs := []InputFile{{Path: worker.ProgramInputPath, Content: programBytes, Kind: KindProgram, Executable: true}}
			content := map[string]string{}
			for _, f := range c.files {
				var data []byte
				if f.role != worker.RoleEmpty {
					if data, err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.path))); err != nil {
						t.Fatal(err)
					}
				}
				sum := sha256.Sum256(data)
				job.Inputs = append(job.Inputs, worker.Input{Path: f.path, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Role: f.role})
				job.Outputs = append(job.Outputs, f.path)
				inputs = append(inputs, InputFile{Path: worker.SrcDirName + "/" + f.path, Content: data})
				content[f.path] = string(data)
			}
			for _, line := range c.before {
				if !strings.Contains(content["Cargo.lock"], line) {
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
				JobID: "it-cargo-" + c.dir, Runtime: spec.ID, Timeout: 6 * time.Minute,
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
			// The crate moved, in the lockfile of the step and the final one.
			for _, name := range []string{"final/Cargo.lock", "steps/update/Cargo.lock"} {
				lock := string(files[name])
				for _, line := range c.after {
					if !strings.Contains(lock, line) {
						t.Errorf("%s after has no %q:\n%s", name, line, lock)
					}
				}
				if strings.Contains(lock, c.before[0]) && c.before[0] != c.after[0] && strings.Contains(lock, `name = "`+c.crate.Name+`"`+"\n"+c.before[0]) {
					t.Errorf("%s still has %s at %s", name, c.crate.Name, c.crate.From)
				}
			}
			// Every other input comes back exactly as it was sent, the empty
			// files empty.
			for name, before := range content {
				if name == "Cargo.lock" {
					continue
				}
				if got, ok := files["final/"+name]; !ok || string(got) != before {
					t.Errorf("%s came back as %q (present: %v), sent %q", name, got, ok, before)
				}
			}
			// Nothing but the files that were sent comes back.
			for name := range files {
				if name == worker.ResultName {
					continue
				}
				_, rel, _ := strings.Cut(name, "/")
				if strings.HasPrefix(name, "steps/") {
					_, rel, _ = strings.Cut(rel, "/")
				}
				if _, ok := content[rel]; !ok {
					t.Errorf("the result holds %s", name)
				}
			}
			t.Logf("%s, %dms, stderr %q", strings.Join(result.Steps[0].Argv, " "), result.Steps[0].DurationMS, result.Steps[0].Stderr)
			passed[spec.ID] = !t.Failed()
		})
	}
	assertNoLeftovers(t, wc)
	// The volume of /work went with each container.
	if after := dockerVolumes(t); !slices.Equal(after, volumesBefore) {
		t.Errorf("volumes before %v, after %v", volumesBefore, after)
	}
	// The table update records the runtime that was run and passed, and no
	// other, as tested: the id is added to the file of the other tests.
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

// dockerVolumes lists the names of the volumes of the daemon, ordered.
func dockerVolumes(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("docker", "volume", "ls", "-q").Output()
	if err != nil {
		t.Fatalf("docker volume ls: %v", err)
	}
	v := strings.Fields(string(out))
	slices.Sort(v)
	return v
}
