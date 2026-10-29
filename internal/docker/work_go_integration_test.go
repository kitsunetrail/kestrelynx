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
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// These tests run the work program in the official Go images the runtime table
// pins, in a real Docker container, with the real module proxy. They run only
// when KESTRELYNX_DOCKER_IT=1.

const goModBefore = "module example.com/it\n\ngo 1.22\n\nrequire golang.org/x/net v0.20.0\n"

func TestIntegrationGoGet(t *testing.T) {
	if os.Getenv("KESTRELYNX_DOCKER_IT") != "1" {
		t.Skip("set KESTRELYNX_DOCKER_IT=1 to run against a real Docker daemon")
	}
	sock := os.Getenv("KESTRELYNX_DOCKER_SOCK")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	goarch := runtime.GOARCH
	dir := t.TempDir()
	program := filepath.Join(dir, "kestrelynx-worker")
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

	for _, id := range []string{"golang1.26", "golang1.27"} {
		t.Run(id, func(t *testing.T) {
			spec, ok := worker.LookupRuntime(id)
			if !ok || !spec.HasImage() {
				t.Fatalf("no runtime %s", id)
			}
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				t.Fatal(err)
			}
			c, err := NewWork(sock, WorkConfig{
				Image: spec.ImageRef(), Platform: "linux/" + goarch,
				ExpectEnv:      map[string]string{spec.VersionEnv(): spec.Version},
				Entrypoint:     []string{worker.ProgramPath, "run", worker.JobFile},
				Env:            []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + worker.HomeDir},
				AllowedEnvKeys: []string{"PATH", "HOME"},
				InstanceID:     hex.EncodeToString(b[:]),
				Limits: TransferLimits{
					MaxInputBytes: 8 << 20, MaxInputTarBytes: 128 << 20, MaxInputFiles: 16, MaxInputPathBytes: 256,
					MaxToolBytes: worker.MaxToolArchiveBytes, MaxProgramBytes: 16 << 20, LogMaxBytes: 8 << 20, MaxStdoutBytes: 8 << 20,
				},
				PullTimeout: 15 * time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := c.CleanupStale(context.Background()); err != nil {
					t.Errorf("cleanup: %v", err)
				}
				assertNoLeftovers(t, c)
			})
			if err := c.EnsureImage(context.Background()); err != nil {
				t.Fatalf("EnsureImage: %v", err)
			}

			hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
			job := worker.Job{
				Protocol: worker.ProtocolVersion, Manager: worker.ManagerGo, Runtime: spec.JobRuntime(),
				Inputs: []worker.Input{
					{Path: "go.mod", Size: int64(len(goModBefore)), SHA256: hash(goModBefore)},
					{Path: "go.sum", Size: 0, SHA256: hash("")},
				},
				Steps:   []worker.Step{{ID: "get", Op: worker.OpGoGet, Packages: []worker.Package{{Name: "golang.org/x/net", Version: "v0.23.0"}}}},
				Outputs: []string{"go.mod", "go.sum"}, DeadlineSeconds: 240, StepTimeoutSeconds: 200,
			}
			if err := job.Validate(); err != nil {
				t.Fatal(err)
			}
			jobJSON, err := json.Marshal(job)
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.RunJob(context.Background(), JobSpec{
				JobID: "it-go-get", Timeout: 5 * time.Minute,
				Inputs: []InputFile{
					{Path: "job.json", Content: jobJSON},
					{Path: worker.ProgramInputPath, Content: programBytes, Kind: KindProgram, Executable: true},
					{Path: worker.SrcDirName + "/go.mod", Content: []byte(goModBefore)},
					{Path: worker.SrcDirName + "/go.sum"},
				},
				Resources: Resources{
					MemoryBytes: 2 << 30, NanoCPUs: 2_000_000_000, PidsLimit: 512, NofileLimit: 4096,
					ShmSizeBytes: 64 << 20, TmpSizeBytes: 512 << 20, HomeSizeBytes: 64 << 20, ToolsSizeBytes: 64 << 20,
				},
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
			if len(result.Steps) != 1 || strings.Join(result.Steps[0].Argv, " ") != "go get golang.org/x/net@v0.23.0" || result.Steps[0].ExitCode != 0 {
				t.Fatalf("steps %+v", result.Steps)
			}
			gomod, gosum := string(files["final/go.mod"]), string(files["final/go.sum"])
			if gomod == goModBefore || !strings.Contains(gomod, "golang.org/x/net v0.23.0") {
				t.Errorf("go.mod after:\n%s", gomod)
			}
			if !strings.Contains(gosum, "golang.org/x/net v0.23.0 h1:") {
				t.Errorf("go.sum after:\n%s", gosum)
			}
			t.Logf("go.mod:\n%s", gomod)
		})
	}
}

func clip(b []byte) string {
	if len(b) > 400 {
		b = b[:400]
	}
	return string(b)
}
