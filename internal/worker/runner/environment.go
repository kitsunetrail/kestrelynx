//go:build unix

package runner

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// environmentError is a failure of the container itself, as against the
// input of the job.
type environmentError struct{ err error }

func (e *environmentError) Error() string { return e.err.Error() }
func (e *environmentError) Unwrap() error { return e.err }

// EnvironmentConfig holds what the program checks and prepares before it runs
// the steps of a job in the container.
type EnvironmentConfig struct {
	// SelfCheck are the rules of the check of the container's filesystem.
	SelfCheck SelfCheckConfig
	// SkipSelfCheck leaves out the check of the container's filesystem. It is
	// for tests that run the program outside a container.
	SkipSelfCheck bool
	// ToolsRoot is the tmpfs the tool archive is unpacked into; its bin
	// directory is Config.BinDir.
	ToolsRoot string
	// Interpreter returns the path of the node or python executable of a
	// runtime; nil means the one the official image has.
	Interpreter func(worker.RuntimeSpec) string
	// ArchiveUID is the owner the tool archive must have: root, as the main
	// process puts it.
	ArchiveUID uint32
	// VersionTimeout bounds each of the version checks.
	VersionTimeout time.Duration
	// JavaHome is where a Gradle runtime has its JDK; empty means the place in
	// the official image.
	JavaHome string
}

// DefaultEnvironment is the layout inside the work container.
func DefaultEnvironment() *EnvironmentConfig {
	return &EnvironmentConfig{
		SelfCheck: SelfCheckConfig{
			Root: "/", MountInfo: "/proc/self/mountinfo", UID: worker.UID,
			Tmpfs: []TmpfsMount{
				{Path: worker.TmpDir},
				{Path: "/var/tmp"},
				{Path: "/run/lock"},
				{Path: "/go"},
				// What the Gradle images need covered: the home of their user,
				// the volume they declare below it and the directory of their
				// service manager.
				{Path: "/home/gradle"},
				{Path: "/home/gradle/.gradle"},
				{Path: "/var/lib/pebble/default"},
				{Path: worker.HomeDir},
				{Path: worker.ToolsRoot, Exec: true},
			},
			MaxEntries: selfCheckMaxEntries, MaxTime: selfCheckMaxTime,
		},
		ToolsRoot:      worker.ToolsRoot,
		VersionTimeout: 30 * time.Second,
	}
}

// KubernetesEnvironment is the layout inside a work Pod's work container: the
// scratch directories are memory volumes, and the tool archive belongs to the
// receiving container's user.
func KubernetesEnvironment() *EnvironmentConfig {
	return &EnvironmentConfig{
		SelfCheck: SelfCheckConfig{
			Root: "/", MountInfo: "/proc/self/mountinfo", UID: worker.UID,
			Tmpfs: []TmpfsMount{
				{Path: worker.TmpDir},
				{Path: worker.HomeDir},
				{Path: worker.ToolsRoot, Exec: true},
			},
			MaxEntries: selfCheckMaxEntries, MaxTime: selfCheckMaxTime,
			Kubernetes: DefaultKubernetesCheck(),
		},
		ToolsRoot:      worker.ToolsRoot,
		ArchiveUID:     worker.ReceiverUID,
		VersionTimeout: 30 * time.Second,
	}
}

func (e *EnvironmentConfig) selfCheck() error {
	if e.SkipSelfCheck {
		return nil
	}
	if err := e.SelfCheck.selfCheck(); err != nil {
		return &environmentError{err}
	}
	return nil
}

func (e *EnvironmentConfig) interpreter(spec worker.RuntimeSpec) string {
	if e.Interpreter != nil {
		return e.Interpreter(spec)
	}
	return spec.Interpreter()
}

// prepareEnvironment checks that the runtime is the one the job names and
// unpacks and checks the tool, so that the directory of the tools holds the
// interpreter and the manager when the first step starts. A failure of the
// runtime is an environmentError; one of the tool is not.
func (c *Config) prepareEnvironment(job *worker.Job) error {
	env := c.Environment
	spec, ok := worker.LookupRuntime(job.Runtime.ID)
	if !ok {
		return &environmentError{fmt.Errorf("unknown runtime %q", job.Runtime.ID)}
	}
	interp := env.interpreter(spec)
	timeout := env.VersionTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if err := c.checkRuntime(spec, job, interp, timeout); err != nil {
		return &environmentError{err}
	}
	if err := os.MkdirAll(c.BinDir, 0o755); err != nil {
		return &environmentError{fmt.Errorf("create the directory of the tools: %w", err)}
	}
	if err := os.Symlink(interp, filepath.Join(c.BinDir, spec.InterpreterName())); err != nil {
		return &environmentError{fmt.Errorf("link the interpreter: %w", err)}
	}
	if job.Tool == nil {
		return nil
	}
	return c.installTool(job, timeout)
}

// checkRuntime requires the interpreter, and for Python the pip of it, to
// report exactly the versions the job names.
func (c *Config) checkRuntime(spec worker.RuntimeSpec, job *worker.Job, interp string, timeout time.Duration) error {
	if st, err := os.Stat(interp); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("the %s executable %s is not there", spec.Label(), interp)
	}
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		pr := runExe(ctx, c, job.Manager, interp, append([]string{filepath.Base(interp)}, args...), c.TmpDir, 0)
		if pr.err != nil || pr.timedOut || pr.exitCode != 0 {
			return "", fmt.Errorf("%s %s did not report its version (exit %d)", filepath.Base(interp), strings.Join(args, " "), pr.exitCode)
		}
		return strings.TrimSpace(pr.stdout), nil
	}
	// node and python print their version for --version; go has the command
	// "go version", which names the platform too.
	var got, want string
	var err error
	switch spec.Kind {
	case worker.KindNode:
		want = "v" + job.Runtime.Version
		got, err = run("--version")
	case worker.KindPython:
		want = "Python " + job.Runtime.Version
		got, err = run("--version")
	case worker.KindGolang:
		want = "go version go" + job.Runtime.Version + " linux/" + runtime.GOARCH
		got, err = run("version")
	case worker.KindGradle:
		return c.checkGradle(spec, job, interp, timeout)
	default:
		return fmt.Errorf("the runtime %s is of the unknown kind %q", spec.ID, spec.Kind)
	}
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s reports %q, the job asks for %q", spec.Label(), clipVersion(got), want)
	}
	if spec.Kind != worker.KindPython || job.Runtime.Pip == "" {
		return nil
	}
	got, err = run("-m", "pip", "--version")
	if err != nil {
		return err
	}
	if f := strings.Fields(got); len(f) < 2 || f[0] != "pip" || f[1] != job.Runtime.Pip {
		return fmt.Errorf("pip reports %q, the job asks for %s", clipVersion(got), job.Runtime.Pip)
	}
	return nil
}

// gradleVersionRE and gradleJVMRE pick the version of Gradle and the JDK out
// of the output of "gradle --version". Gradle 9 names the JVM that launches it
// "Launcher JVM", Gradle 8 "JVM".
var (
	gradleVersionRE = regexp.MustCompile(`(?m)^Gradle (\S+)\s*$`)
	gradleJVMRE     = regexp.MustCompile(`(?m)^(?:Launcher )?JVM:\s+(\d+)[.\d_+-]*\s`)
)

// checkGradle requires gradle to report exactly the version of the job and to
// run on the JDK of the row.
func (c *Config) checkGradle(spec worker.RuntimeSpec, job *worker.Job, interp string, timeout time.Duration) error {
	home := c.Environment.JavaHome
	if home == "" {
		home = worker.GradleJavaHome
	}
	if st, err := os.Stat(filepath.Join(home, "bin", "java")); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("the JDK of the %s image is not in %s", spec.Label(), home)
	}
	// gradle makes its user home on its own, but the cache directory above it
	// is made here.
	if err := c.prepareCache(); err != nil {
		return fmt.Errorf("prepare cache: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pr := runExe(ctx, c, job.Manager, interp, []string{"gradle", "--version"}, c.TmpDir, 0)
	if pr.err != nil || pr.timedOut || pr.exitCode != 0 {
		return fmt.Errorf("gradle --version did not report its version (exit %d)", pr.exitCode)
	}
	v := gradleVersionRE.FindStringSubmatch(pr.stdout)
	if v == nil || v[1] != job.Runtime.Version {
		return fmt.Errorf("%s reports %q, the job asks for Gradle %s", spec.Label(), clipVersion(strings.TrimSpace(pr.stdout)), job.Runtime.Version)
	}
	jvm := gradleJVMRE.FindStringSubmatch(pr.stdout)
	if jvm == nil || jvm[1] != spec.JDK {
		return fmt.Errorf("%s runs on another JDK than %s", spec.Label(), spec.JDK)
	}
	return nil
}

func clipVersion(s string) string {
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// installTool checks the archive against the size and hashes of the job,
// unpacks it, links its entry into the directory of the tools and requires the
// program to report exactly the version the job names.
func (c *Config) installTool(job *worker.Job, timeout time.Duration) error {
	t := job.Tool
	path := filepath.Join(c.WorkDir, filepath.FromSlash(t.Path))
	if err := checkArchive(path, t, c.Environment.ArchiveUID); err != nil {
		return fmt.Errorf("tool %s: %w", t.Name, err)
	}
	root := filepath.Join(c.Environment.ToolsRoot, string(t.Name))
	if err := os.Mkdir(root, 0o755); err != nil {
		return fmt.Errorf("tool %s: create its directory: %w", t.Name, err)
	}
	limits := unpackLimits{Files: worker.MaxToolFiles, Bytes: worker.MaxToolUnpackedBytes}
	var err error
	switch t.Format {
	case worker.FormatNpmTgz:
		err = unpackNpmTgz(path, root, t.Entry, limits)
	case worker.FormatWheel:
		err = unpackWheel(path, root, t.Entry, limits)
	default:
		err = fmt.Errorf("unknown format %q", t.Format)
	}
	if err != nil {
		return fmt.Errorf("tool %s: unpack: %w", t.Name, err)
	}
	if err := os.Symlink(filepath.Join(root, filepath.FromSlash(t.Entry)), filepath.Join(c.BinDir, string(t.Name))); err != nil {
		return fmt.Errorf("tool %s: link its entry: %w", t.Name, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pr := runProc(ctx, c, job.Manager, []string{string(t.Name), "--version"}, c.TmpDir)
	if pr.err != nil || pr.timedOut || pr.exitCode != 0 {
		return fmt.Errorf("tool %s did not report its version (exit %d)", t.Name, pr.exitCode)
	}
	if got := strings.TrimSpace(pr.stdout); !toolVersionMatches(t, got) {
		return fmt.Errorf("tool %s reports %q, the job asks for %s", t.Name, clipVersion(got), t.Version)
	}
	return nil
}

// toolVersionMatches compares the output of --version with the version asked
// for: npm and pnpm print the version alone, uv prints "uv <version> (...)".
func toolVersionMatches(t *worker.Tool, out string) bool {
	line, _, _ := strings.Cut(out, "\n")
	line = strings.TrimSpace(line)
	if t.Name == worker.ManagerUv {
		f := strings.Fields(line)
		return len(f) >= 2 && f[0] == "uv" && f[1] == t.Version
	}
	return line == t.Version
}

// checkArchive requires the file to be a regular file with one link, of the
// size and the hashes the job declares.
func checkArchive(path string, t *worker.Tool, owner uint32) error {
	f, fi, err := regularFile(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi.Size() != t.Size {
		return fmt.Errorf("the archive is %d bytes, the job declares %d", fi.Size(), t.Size)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != owner {
		return fmt.Errorf("the archive is owned by uid %d, not %d", st.Uid, owner)
	}
	h256, h512 := sha256.New(), sha512.New()
	n, err := io.Copy(io.MultiWriter(h256, h512), io.LimitReader(f, t.Size+1))
	if err != nil {
		return err
	}
	if n != t.Size {
		return fmt.Errorf("the archive is %d bytes, the job declares %d", n, t.Size)
	}
	if hex.EncodeToString(h256.Sum(nil)) != t.SHA256 || hex.EncodeToString(h512.Sum(nil)) != t.SHA512 {
		return errors.New("the archive does not match the hashes of the job")
	}
	return nil
}
