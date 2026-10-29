//go:build unix

package runner

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func TestGoChildEnv(t *testing.T) {
	// Settings of the program's own environment must not reach the command.
	for k, v := range map[string]string{"GOFLAGS": "-x", "GOPRIVATE": "corp.example", "GOPROXY": "direct", "GOTOOLCHAIN": "auto", "GOENV": "/x", "GOWORK": "/w/go.work", "GONOSUMDB": "*", "GOINSECURE": "*"} {
		t.Setenv(k, v)
	}
	c := Config{TmpDir: "/tmp", HomeDir: "/home/worker", Path: "/opt/kestrelynx-tools/bin"}
	got := map[string]string{}
	for _, kv := range c.childEnv(worker.ManagerGo) {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Errorf("%s is set twice", k)
		}
		got[k] = v
	}
	want := map[string]string{
		"GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
		"GOPRIVATE": "", "GONOPROXY": "", "GONOSUMDB": "", "GOINSECURE": "",
		"GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "CGO_ENABLED": "0",
		"GOPATH": "/tmp/kestrelynx-cache/go", "GOMODCACHE": "/tmp/kestrelynx-cache/go/pkg/mod", "GOCACHE": "/tmp/kestrelynx-cache/go-build",
		"HOME": "/home/worker", "PATH": "/opt/kestrelynx-tools/bin",
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %q (set: %v), want %q", k, g, ok, v)
		}
	}
	// Every GO* variable is one of the fixed list.
	for k := range got {
		if strings.HasPrefix(k, "GO") {
			if _, ok := want[k]; !ok {
				t.Errorf("unexpected variable %s", k)
			}
		}
	}
	// The other managers get none of them.
	for _, m := range []worker.Manager{worker.ManagerNpm, worker.ManagerPnpm, worker.ManagerUv, worker.ManagerPip} {
		for _, kv := range c.childEnv(m) {
			if strings.HasPrefix(kv, "GO") || strings.HasPrefix(kv, "CGO_") {
				t.Errorf("%s env has %s", m, kv)
			}
		}
	}
	// The directories are under the cache, which is under the tmpfs.
	for _, k := range []string{"GOPATH", "GOMODCACHE", "GOCACHE"} {
		if !strings.HasPrefix(got[k], c.cacheDir()+"/") {
			t.Errorf("%s = %s is outside %s", k, got[k], c.cacheDir())
		}
	}
}

const goScript = `#!/bin/sh
case "$1" in
  version) echo "go version go%s linux/%s" ;;
  get) shift; echo "$@" > go.mod; echo "$GOPROXY $GOFLAGS $GOTOOLCHAIN $GOPRIVATE" > go.sum ;;
esac
`

// goFixture is a work directory with a fake go command in place of the one of
// the image.
func goFixture(t *testing.T, version string) (*env, *worker.Job) {
	t.Helper()
	e := newEnv(t)
	e.cfg.BinDir = filepath.Join(e.cfg.TmpDir, "tools", "bin")
	e.cfg.Path = e.cfg.BinDir + ":/usr/bin:/bin"
	goBin := filepath.Join(t.TempDir(), "go")
	e.write(goBin, strings.Replace(strings.Replace(goScript, "%s", version, 1), "%s", runtime.GOARCH, 1))
	if err := os.Chmod(goBin, 0o755); err != nil {
		t.Fatal(err)
	}
	e.cfg.Environment = &EnvironmentConfig{
		SkipSelfCheck: true, ToolsRoot: filepath.Join(e.cfg.TmpDir, "tools"), VersionTimeout: 10e9,
		Interpreter: func(spec worker.RuntimeSpec) string {
			if spec.Kind != worker.KindGolang {
				t.Errorf("interpreter asked for %s", spec.ID)
			}
			return goBin
		},
	}
	if err := os.MkdirAll(e.cfg.Environment.ToolsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	job := &worker.Job{
		Protocol: worker.ProtocolVersion, Manager: worker.ManagerGo, Runtime: testRuntime("golang1.26"),
		Steps:   []worker.Step{{ID: "get", Op: worker.OpGoGet, Packages: []worker.Package{{Name: "golang.org/x/net", Version: "v0.23.0"}}}},
		Outputs: []string{"go.mod", "go.sum"}, DeadlineSeconds: 30,
	}
	for name, content := range map[string]string{"go.mod": "module example.com/m\n", "go.sum": ""} {
		e.write(filepath.Join(e.cfg.WorkDir, "src", name), content)
		job.Inputs = append(job.Inputs, worker.Input{Path: name, Size: int64(len(content)), SHA256: sum(content)})
	}
	return e, job
}

func TestEnvironmentGoJobNeedsNoTool(t *testing.T) {
	spec, _ := worker.LookupRuntime("golang1.26")
	e, job := goFixture(t, spec.Version)
	t.Setenv("GOPRIVATE", "corp.example")
	res, err := e.run(job)
	if err != nil || res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("err %v result %+v", err, res)
	}
	if got := e.read("final", "go.mod"); got != "golang.org/x/net@v0.23.0\n" {
		t.Errorf("go.mod = %q", got)
	}
	if got := e.read("final", "go.sum"); got != "https://proxy.golang.org -mod=mod local \n" {
		t.Errorf("go.sum = %q", got)
	}
	if len(res.Steps) != 1 || strings.Join(res.Steps[0].Argv, " ") != "go get golang.org/x/net@v0.23.0" {
		t.Errorf("steps %+v", res.Steps)
	}
}

func TestEnvironmentGoVersionIsChecked(t *testing.T) {
	spec, _ := worker.LookupRuntime("golang1.26")
	for name, c := range map[string]struct{ version, want string }{
		"another patch version": {"1.26.0", "reports"},
		"another series":        {"1.27.3", "reports"},
	} {
		e, job := goFixture(t, c.version)
		res, _ := e.run(job)
		if res == nil || res.Status != worker.StatusEnvironmentRejected || !strings.Contains(res.Error, c.want) {
			t.Errorf("%s: %+v", name, res)
		}
		if res != nil && len(res.Steps) != 0 {
			t.Errorf("%s: a step ran", name)
		}
	}
	// Another platform than the one the program runs on.
	e, job := goFixture(t, spec.Version)
	goBin := e.cfg.Environment.Interpreter(spec)
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}
	e.write(goBin, strings.Replace(strings.Replace(goScript, "%s", spec.Version, 1), "%s", other, 1))
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusEnvironmentRejected || !strings.Contains(res.Error, "reports") {
		t.Errorf("another platform: %+v", res)
	}
}

func TestEnvironmentGoJobWithAToolIsRefused(t *testing.T) {
	spec, _ := worker.LookupRuntime("golang1.26")
	e, job := goFixture(t, spec.Version)
	job.Tool = testTool(worker.ManagerNpm, "11.19.0")
	res, _ := e.run(job)
	if res == nil || res.Status != worker.StatusInputRejected {
		t.Errorf("%+v", res)
	}
}

// goImage is a small Go image: its GOPATH is writable by everyone, as in the
// official one.
func goImage() fakeFS {
	i := cleanImage()
	i["/"].children = append(i["/"].children, "go", "usr")
	i["/go"] = &fakeEntry{mode: fs.ModeDir | 0o1777, writable: true, children: []string{"src"}}
	i["/go/src"] = &fakeEntry{mode: fs.ModeDir | 0o1777, writable: true}
	i["/usr"] = dir("local")
	i["/usr/local"] = dir("go")
	i["/usr/local/go"] = dir()
	return i
}

func TestSelfCheckGoPathIsCoveredByATmpfs(t *testing.T) {
	covered := goodMountInfo + "9 1 0:30 / /go rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=1024k,mode=755\n"
	cfg := func(mounts string) *SelfCheckConfig {
		c := checkCfg(t, mounts, goImage())
		c.Tmpfs = append(c.Tmpfs, TmpfsMount{Path: "/go"})
		return c
	}
	if err := cfg(covered).selfCheck(); err != nil {
		t.Errorf("covered /go: %v", err)
	}
	// Without the mount the writable GOPATH is refused.
	if err := cfg(goodMountInfo).selfCheck(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("uncovered /go: %v", err)
	}
	// And the mount is refused when the config does not list it.
	if err := checkCfg(t, covered, goImage()).selfCheck(); err == nil || !strings.Contains(err.Error(), "unexpected mount") {
		t.Errorf("unlisted /go mount: %v", err)
	}
	// The default layout of the Docker container lists it.
	listed := false
	for _, m := range DefaultEnvironment().SelfCheck.Tmpfs {
		if m.Path == "/go" && !m.Exec {
			listed = true
		}
	}
	if !listed {
		t.Error("DefaultEnvironment does not list /go")
	}
}
