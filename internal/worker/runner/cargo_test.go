//go:build unix

package runner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// cargoFiles are the inputs of a workspace: the lockfile, a manifest at the
// root and one in a member, and the empty files that stand for the targets.
var cargoFiles = []struct{ path, role, content string }{
	{"Cargo.lock", worker.RoleLockfile, "version = 4\n"},
	{"Cargo.toml", worker.RoleManifest, "[workspace]\nmembers = [\"crates/app\"]\n"},
	{"crates/app/Cargo.toml", worker.RoleManifest, "[package]\nname = \"app\"\n"},
	{"crates/app/src/main.rs", worker.RoleEmpty, ""},
}

// cargoScript is a fake cargo: it records its command line and environment,
// and appends to the lockfile. %s is a place for what a test adds.
const cargoScript = `#!/bin/sh
if [ "$1" = "--version" ]; then echo "cargo %[1]s (3acc79c0c 2026-11-05)"; exit 0; fi
{ echo "ARGS=$*"; echo "PWD=$PWD"; echo "HOME_ENTRIES=$(ls -A "$CARGO_HOME" | wc -l)"; env | sort; } > %[2]s
echo "# updated" >> Cargo.lock
%[3]s
`

const rustcScript = "#!/bin/sh\necho \"rustc %s (0ef1bc386 2026-11-09)\"\n"

type cargoEnv struct {
	*env
	record  string
	bin     string
	version string
}

// cargoFixture is a work directory with a fake toolchain, where the program
// looks for it, in place of the one of the image.
func cargoFixture(t *testing.T, extra string) (*cargoEnv, *worker.Job) {
	t.Helper()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("no Rust toolchain for this architecture")
	}
	spec, ok := worker.LookupRuntime("rust1.100")
	if !ok {
		t.Fatal("no rust1.100 in the table")
	}
	e := newEnv(t)
	old := worker.CargoToolchainsDir
	worker.CargoToolchainsDir = filepath.Join(t.TempDir(), "toolchains")
	t.Cleanup(func() { worker.CargoToolchainsDir = old })
	bin, err := worker.CargoToolchainBin(spec.Version, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	c := &cargoEnv{env: e, record: filepath.Join(t.TempDir(), "record"), bin: bin, version: spec.Version}
	c.tool("cargo", fmt.Sprintf(cargoScript, spec.Version, c.record, extra))
	c.tool("rustc", fmt.Sprintf(rustcScript, spec.Version))
	e.cfg.Environment = &EnvironmentConfig{SkipSelfCheck: true, ToolsRoot: filepath.Join(e.cfg.TmpDir, "tools"), VersionTimeout: 10e9}
	if err := os.MkdirAll(e.cfg.Environment.ToolsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	job := &worker.Job{
		Protocol: worker.ProtocolVersion, Manager: worker.ManagerCargo, Runtime: testRuntime("rust1.100"),
		Steps:           []worker.Step{{ID: "update", Op: worker.OpCargoUpdate, Packages: []worker.Package{{Name: "tokio", From: "1.18.0", Version: "1.18.4"}}}},
		DeadlineSeconds: 30,
	}
	for _, f := range cargoFiles {
		p := filepath.Join(e.cfg.WorkDir, "src", filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		e.write(p, f.content)
		job.Inputs = append(job.Inputs, worker.Input{Path: f.path, Size: int64(len(f.content)), SHA256: sum(f.content), Role: f.role})
		job.Outputs = append(job.Outputs, f.path)
	}
	return c, job
}

func (c *cargoEnv) tool(name, script string) {
	c.t.Helper()
	p := filepath.Join(c.bin, name)
	c.write(p, script)
	if err := os.Chmod(p, 0o755); err != nil {
		c.t.Fatal(err)
	}
}

// recorded returns the command line and the environment the fake cargo saw.
func (c *cargoEnv) recorded() (args string, env map[string]string) {
	c.t.Helper()
	b, err := os.ReadFile(c.record)
	if err != nil {
		c.t.Fatalf("cargo did not run: %v", err)
	}
	env = map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		if k == "ARGS" {
			args = v
		}
		env[k] = v
	}
	return args, env
}

func TestCargoChildEnv(t *testing.T) {
	// Settings of the program's own environment must not reach the command.
	for k, v := range map[string]string{
		"CARGO_HOME": "/x", "RUSTUP_HOME": "/r", "RUSTUP_TOOLCHAIN": "nightly", "RUSTC_WRAPPER": "sccache", "RUSTFLAGS": "-C x",
		"CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "git", "CARGO_REGISTRY_TOKEN": "secret", "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
		"CARGO_HTTP_PROXY": "http://p", "https_proxy": "http://p", "CARGO_BUILD_TARGET_DIR": "/t", "CARGO_TARGET_DIR": "/t",
	} {
		t.Setenv(k, v)
	}
	c := Config{TmpDir: "/tmp", HomeDir: "/home/worker", Path: "/opt/kestrelynx-tools/bin:/usr/bin:/bin", rustBin: "/usr/local/rustup/toolchains/1.100.0-x86_64-unknown-linux-gnu/bin"}
	got := map[string]string{}
	for _, kv := range c.childEnv(worker.ManagerCargo) {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Errorf("%s is set twice", k)
		}
		got[k] = v
	}
	want := map[string]string{
		"CARGO_HOME": "/home/worker/cargo-home", "RUSTC": c.rustBin + "/rustc", "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
		"CARGO_TERM_COLOR": "never", "HOME": "/home/worker", "PATH": c.rustBin + ":/usr/bin:/bin",
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %q (set: %v), want %q", k, g, ok, v)
		}
	}
	for k := range got {
		if (strings.HasPrefix(k, "CARGO") || strings.HasPrefix(k, "RUST")) && want[k] == "" {
			t.Errorf("unexpected variable %s", k)
		}
	}
	for _, k := range []string{"https_proxy", "HTTPS_PROXY"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s reached the command", k)
		}
	}
	// The other managers get none of it.
	for _, m := range []worker.Manager{worker.ManagerNpm, worker.ManagerPnpm, worker.ManagerUv, worker.ManagerPip, worker.ManagerGo, worker.ManagerGradle} {
		for _, kv := range c.childEnv(m) {
			if strings.HasPrefix(kv, "CARGO") || strings.HasPrefix(kv, "RUST") {
				t.Errorf("%s env has %s", m, kv)
			}
		}
	}
}

func TestCargoUpdateRunsTheToolchainByItsPathAndReturnsEveryInput(t *testing.T) {
	c, job := cargoFixture(t, "")
	t.Setenv("RUSTUP_TOOLCHAIN", "nightly")
	t.Setenv("RUSTC_WRAPPER", "sccache")
	res, err := c.run(job)
	if err != nil || res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("err %v result %+v", err, res)
	}
	wantArgv := c.bin + "/cargo update --manifest-path Cargo.toml -p tokio@1.18.0 --precise 1.18.4"
	if len(res.Steps) != 1 || strings.Join(res.Steps[0].Argv, " ") != wantArgv {
		t.Errorf("steps %+v, want %s", res.Steps, wantArgv)
	}
	args, env := c.recorded()
	if args != "update --manifest-path Cargo.toml -p tokio@1.18.0 --precise 1.18.4" {
		t.Errorf("args %q", args)
	}
	if env["RUSTC"] != c.bin+"/rustc" || env["CARGO_HOME"] != filepath.Join(c.cfg.HomeDir, "cargo-home") || env["HOME_ENTRIES"] != "0" ||
		env["CARGO_REGISTRIES_CRATES_IO_PROTOCOL"] != "sparse" || env["CARGO_TERM_COLOR"] != "never" || !strings.HasPrefix(env["PATH"], c.bin+":") {
		t.Errorf("env %v", env)
	}
	for _, k := range []string{"RUSTUP_TOOLCHAIN", "RUSTC_WRAPPER", "RUSTUP_HOME"} {
		if v, ok := env[k]; ok {
			t.Errorf("%s=%s reached cargo", k, v)
		}
	}
	if !strings.HasSuffix(env["PWD"], "/main") {
		t.Errorf("cargo ran in %s", env["PWD"])
	}
	// The lockfile changed; every other file, at its own path, comes back as
	// it was, and so does the lockfile in the copy of the step.
	if got := c.read("final", "Cargo.lock"); got != "version = 4\n# updated\n" {
		t.Errorf("lockfile %q", got)
	}
	for _, f := range cargoFiles[1:] {
		if got := c.read("final", f.path); got != f.content {
			t.Errorf("%s = %q", f.path, got)
		}
		if got := c.read("steps", "update", f.path); got != f.content {
			t.Errorf("step copy of %s = %q", f.path, got)
		}
	}
	if len(res.Final) != len(cargoFiles) {
		t.Errorf("final %+v", res.Final)
	}
}

func TestCargoToolchainVersionIsChecked(t *testing.T) {
	for name, tool := range map[string]string{"cargo": "cargo", "rustc": "rustc"} {
		c, job := cargoFixture(t, "")
		c.tool(tool, "#!/bin/sh\necho \""+tool+" 1.99.0 (abc 2026-01-01)\"\n")
		res, _ := c.run(job)
		if res == nil || res.Status != worker.StatusEnvironmentRejected || !strings.Contains(res.Error, "reports") {
			t.Errorf("%s: %+v", name, res)
		}
		if res != nil && len(res.Steps) != 0 {
			t.Errorf("%s: a step ran", name)
		}
	}
	// A program that names another tool in its version line.
	c, job := cargoFixture(t, "")
	c.tool("cargo", "#!/bin/sh\necho \"rustc "+c.version+" (abc 2026-01-01)\"\n")
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusEnvironmentRejected {
		t.Errorf("another name: %+v", res)
	}
	// A prefix of the version is not the version.
	c, job = cargoFixture(t, "")
	c.tool("rustc", "#!/bin/sh\necho \"rustc "+c.version+"1 (abc 2026-01-01)\"\n")
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusEnvironmentRejected {
		t.Errorf("a longer version: %+v", res)
	}
	for _, missing := range []string{"cargo", "rustc"} {
		c, job = cargoFixture(t, "")
		if err := os.Remove(filepath.Join(c.bin, missing)); err != nil {
			t.Fatal(err)
		}
		res, _ := c.run(job)
		if res == nil || res.Status != worker.StatusEnvironmentRejected || !strings.Contains(res.Error, "not there") {
			t.Errorf("no %s: %+v", missing, res)
		}
	}
	// The toolchain of another version is no toolchain for the job.
	c, job = cargoFixture(t, "")
	if err := os.Rename(filepath.Dir(c.bin), filepath.Join(filepath.Dir(filepath.Dir(c.bin)), "1.0.0-x")); err != nil {
		t.Fatal(err)
	}
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusEnvironmentRejected {
		t.Errorf("a toolchain of another version: %+v", res)
	}
}

func TestCargoConfigFilesAboveTheWorkingTreeAreRefused(t *testing.T) {
	for name, place := range map[string]func(c *cargoEnv) string{
		"in the temporary directory": func(c *cargoEnv) string { return filepath.Join(c.cfg.TmpDir, ".cargo") },
		"above it":                   func(c *cargoEnv) string { return filepath.Join(filepath.Dir(c.cfg.TmpDir), ".cargo") },
		"in the home":                func(c *cargoEnv) string { return filepath.Join(c.cfg.HomeDir, "cargo-home") },
	} {
		for _, file := range []string{"config.toml", "config"} {
			c, job := cargoFixture(t, "")
			dir := place(c)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			c.write(filepath.Join(dir, file), "[net]\ngit-fetch-with-cli = true\n")
			res, _ := c.run(job)
			if res == nil || res.Status != worker.StatusEnvironmentRejected || !(strings.Contains(res.Error, "configuration file") || strings.Contains(res.Error, "CARGO_HOME")) {
				t.Errorf("%s, %s: %+v", name, file, res)
			}
			if res != nil && len(res.Steps) != 0 {
				t.Errorf("%s, %s: a step ran", name, file)
			}
			if _, err := os.Stat(c.record); err == nil {
				t.Errorf("%s, %s: cargo ran", name, file)
			}
		}
	}
	// A link that points nowhere counts as a file that is there.
	c, job := cargoFixture(t, "")
	if err := os.MkdirAll(filepath.Join(c.cfg.TmpDir, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent", filepath.Join(c.cfg.TmpDir, ".cargo", "config.toml")); err != nil {
		t.Fatal(err)
	}
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusEnvironmentRejected {
		t.Errorf("a dangling link: %+v", res)
	}
	// A .cargo directory without those two files is nothing to cargo.
	c, job = cargoFixture(t, "")
	if err := os.MkdirAll(filepath.Join(c.cfg.TmpDir, ".cargo", "registry"), 0o755); err != nil {
		t.Fatal(err)
	}
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusCompleted {
		t.Errorf("a .cargo directory with no configuration: %+v", res)
	}
}

func TestCargoHomeMustBeEmpty(t *testing.T) {
	c, job := cargoFixture(t, "")
	home := filepath.Join(c.cfg.HomeDir, "cargo-home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	c.write(filepath.Join(home, "credentials.toml"), "[registry]\ntoken = \"x\"\n")
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusEnvironmentRejected || !strings.Contains(res.Error, "CARGO_HOME") {
		t.Errorf("a home with a file: %+v", res)
	}
}

func TestCargoStepResultIsChecked(t *testing.T) {
	// cargo builds into target/ at the top of the working tree.
	c, job := cargoFixture(t, "mkdir target; echo x > target/f")
	res, _ := c.run(job)
	if res == nil || res.Status != worker.StatusStepFailed || len(res.Steps) != 1 || res.Steps[0].Reason != worker.ReasonUnexpectedFiles ||
		len(res.Steps[0].UnexpectedPaths) != 1 || res.Steps[0].UnexpectedPaths[0] != "target" {
		t.Errorf("target/: %+v", res)
	}
	// A file that is not an output and is changed is a settings file that was
	// touched.
	c, job = cargoFixture(t, "echo '[package]' >> crates/app/Cargo.toml")
	job.Outputs = []string{"Cargo.lock"}
	res, _ = c.run(job)
	if res == nil || res.Status != worker.StatusStepFailed || res.Steps[0].Reason != worker.ReasonInputModified {
		t.Errorf("a manifest changed: %+v", res)
	}
	// An output that is changed is returned as it is, for the main process to
	// compare with what it sent.
	c, job = cargoFixture(t, "echo '[package]' >> crates/app/Cargo.toml")
	res, _ = c.run(job)
	if res == nil || res.Status != worker.StatusCompleted {
		t.Fatalf("a manifest changed, returned: %+v", res)
	}
	if got := c.read("final", "crates/app/Cargo.toml"); !strings.HasSuffix(got, "[package]\n") || got == cargoFiles[2].content {
		t.Errorf("the changed manifest %q", got)
	}
	// A failing cargo is a failed step.
	c, job = cargoFixture(t, "exit 101")
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusStepFailed || res.Steps[0].ExitCode != 101 {
		t.Errorf("a failing cargo: %+v", res)
	}
}

func TestCargoJobsThatAreRefused(t *testing.T) {
	for name, mut := range map[string]func(*worker.Job){
		"a tool":         func(j *worker.Job) { j.Tool = testTool(worker.ManagerNpm, "11.19.0") },
		"a node runtime": func(j *worker.Job) { j.Runtime = testRuntime("node24") },
		"two packages": func(j *worker.Job) {
			j.Steps[0].Packages = append(j.Steps[0].Packages, worker.Package{Name: "syn", From: "2.0.0", Version: "2.0.1"})
		},
		"a scratch step":     func(j *worker.Job) { j.Steps[0].Scratch = true },
		"a target directory": func(j *worker.Job) { j.Inputs[3].Path = "target/main.rs"; j.Outputs[3] = "target/main.rs" },
	} {
		c, job := cargoFixture(t, "")
		mut(job)
		res, _ := c.run(job)
		if res == nil || res.Status != worker.StatusInputRejected {
			t.Errorf("%s: %+v", name, res)
		}
		if _, err := os.Stat(c.record); err == nil {
			t.Errorf("%s: cargo ran", name)
		}
	}
	// A file that is not as declared is refused before anything runs.
	c, job := cargoFixture(t, "")
	c.write(filepath.Join(c.cfg.WorkDir, "src", "Cargo.toml"), "changed")
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusInputRejected {
		t.Errorf("a changed input: %+v", res)
	}
	c, job = cargoFixture(t, "")
	c.write(filepath.Join(c.cfg.WorkDir, "src", "crates", "extra.rs"), "")
	if res, _ := c.run(job); res == nil || res.Status != worker.StatusInputRejected {
		t.Errorf("an undeclared file: %+v", res)
	}
}

func TestCargoProgramIsStartedByAnAbsolutePathOnly(t *testing.T) {
	c := Config{TmpDir: t.TempDir(), HomeDir: t.TempDir(), BinDir: t.TempDir(), rustBin: t.TempDir()}
	pr := runProcKeeping(t.Context(), &c, worker.ManagerCargo, []string{"cargo", "--version"}, c.TmpDir, 0)
	if pr.err == nil || !strings.Contains(pr.err.Error(), "absolute") {
		t.Errorf("a name found by the path: %+v", pr)
	}
	// Whatever is in the directory of the tools is not looked at.
	if err := os.WriteFile(filepath.Join(c.BinDir, "cargo"), []byte("#!/bin/sh\necho x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if pr := runProcKeeping(t.Context(), &c, worker.ManagerCargo, []string{"cargo", "--version"}, c.TmpDir, 0); pr.err == nil {
		t.Errorf("a program of the tools directory ran: %+v", pr)
	}
}

// rustImage is a small Rust image: the directories of cargo and rustup are
// writable by everyone, as in the official one (writable says whether a write
// to them can succeed, which a read-only root filesystem does not allow).
func rustImage(writable bool) fakeFS {
	i := cleanImage()
	i["/"].children = append(i["/"].children, "usr")
	i["/usr"] = dir("local")
	i["/usr/local"] = dir("cargo", "rustup")
	i["/usr/local/cargo"] = &fakeEntry{mode: fs.ModeDir | 0o777, writable: writable, children: []string{"bin"}}
	i["/usr/local/cargo/bin"] = &fakeEntry{mode: fs.ModeDir | 0o777, writable: writable}
	i["/usr/local/rustup"] = &fakeEntry{mode: fs.ModeDir | 0o777, writable: writable}
	return i
}

func TestSelfCheckOfARustImageNeedsItsToolchainDirectoriesNotToBeWritable(t *testing.T) {
	if err := checkCfg(t, goodMountInfo, rustImage(false)).selfCheck(); err != nil {
		t.Errorf("a root filesystem that cannot be written: %v", err)
	}
	err := checkCfg(t, goodMountInfo, rustImage(true)).selfCheck()
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a root filesystem that can be written: %v", err)
	}
}

// A Docker container with a read-only root has a volume at /work for the input.
func TestSelfCheckOfAReadOnlyRootWithTheWorkVolume(t *testing.T) {
	ro := strings.Replace(goodMountInfo, "1 0 8:1 / / rw,relatime", "1 0 8:1 / / ro,relatime", 1)
	if ro == goodMountInfo {
		t.Fatal("the mount info has no root line to make read only")
	}
	vol := ro + "20 1 8:1 /var/lib/docker/volumes/x/_data /work rw,relatime - ext4 /dev/sda1 rw\n"
	image := func(workWritable bool) fakeFS {
		i := rustImage(false)
		i["/"].children = append(i["/"].children, "work")
		i["/work"] = &fakeEntry{mode: fs.ModeDir | 0o755, writable: workWritable, children: []string{"job.json"}}
		i["/work/job.json"] = &fakeEntry{mode: 0o644}
		return i
	}
	ok, err := checkCfg(t, vol, image(false)).selfCheckMode()
	if err != nil || !ok {
		t.Errorf("read-only root with the volume: %v, %v", ok, err)
	}
	// The volume is walked like the rest: the job user may not write it.
	if _, err := checkCfg(t, vol, image(true)).selfCheckMode(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a writable /work: %v", err)
	}
	if _, err := checkCfg(t, ro, image(false)).selfCheckMode(); err == nil || !strings.Contains(err.Error(), "no volume") {
		t.Errorf("no volume: %v", err)
	}
	tmpfs := ro + "20 1 0:40 / /work rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=1024k\n"
	if _, err := checkCfg(t, tmpfs, image(false)).selfCheckMode(); err == nil {
		t.Error("a tmpfs at /work accepted")
	}
	rovol := ro + "20 1 8:1 /v /work ro,relatime - ext4 /dev/sda1 rw\n"
	if _, err := checkCfg(t, rovol, image(false)).selfCheckMode(); err == nil {
		t.Error("a read-only volume accepted")
	}
	// With a writable root a mount at /work is an unexpected one, as before.
	rw := goodMountInfo + "20 1 8:1 /v /work rw,relatime - ext4 /dev/sda1 rw\n"
	if _, err := checkCfg(t, rw, image(false)).selfCheckMode(); err == nil || !strings.Contains(err.Error(), "unexpected mount") {
		t.Errorf("a volume with a writable root: %v", err)
	}
	if ro, err := checkCfg(t, goodMountInfo, cleanImage()).selfCheckMode(); err != nil || ro {
		t.Errorf("an ordinary container: %v, %v", ro, err)
	}
}

// Only a Cargo job goes with a read-only root, and it needs one.
func TestCargoJobAndReadOnlyRootGoTogether(t *testing.T) {
	ro := strings.Replace(goodMountInfo, "1 0 8:1 / / rw,relatime", "1 0 8:1 / / ro,relatime", 1) +
		"20 1 8:1 /v /work rw,relatime - ext4 /dev/sda1 rw\n"
	for name, c := range map[string]struct {
		mounts   string
		cargo    bool
		rejected bool
	}{
		"cargo, read-only root": {ro, true, false},
		"cargo, writable root":  {goodMountInfo, true, true},
		"npm, read-only root":   {ro, false, true},
		"npm, writable root":    {goodMountInfo, false, false},
	} {
		var e *env
		var job *worker.Job
		if c.cargo {
			ce, j := cargoFixture(t, "")
			e, job = ce.env, j
		} else {
			e = newEnv(t)
			e.program("npm", "echo ok\n")
			job = e.npmJob()
			job.Steps = []worker.Step{{ID: "relock", Op: worker.OpNpmRelock}}
		}
		i := rustImage(false)
		i["/"].children = append(i["/"].children, "work")
		i["/work"] = &fakeEntry{mode: fs.ModeDir | 0o755}
		sc := checkCfg(t, c.mounts, i)
		e.cfg.Environment = &EnvironmentConfig{SelfCheck: *sc, ToolsRoot: filepath.Join(e.cfg.TmpDir, "tools"), VersionTimeout: 10e9}
		if err := os.MkdirAll(e.cfg.Environment.ToolsRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		res, _ := e.run(job)
		if res == nil {
			t.Fatalf("%s: no result", name)
		}
		if got := res.Status == worker.StatusEnvironmentRejected && strings.Contains(res.Error, "read-only root"); got != c.rejected {
			t.Errorf("%s: %+v", name, res)
		}
	}
}
