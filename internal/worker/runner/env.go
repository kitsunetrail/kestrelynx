//go:build unix

package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// npmRegistry is the only registry npm and pnpm use.
const npmRegistry = "https://registry.npmjs.org/"

// The proxy and the checksum database go uses.
const (
	goProxy = "https://proxy.golang.org"
	goSumDB = "sum.golang.org"
)

// Names of the empty files npm and pnpm are told to read as their user and
// global configuration. They must be two different paths: npm refuses to load
// the same file as both.
const (
	npmUserConfig   = "npmrc-user"
	npmGlobalConfig = "npmrc-global"
)

// cacheDir is where the children keep caches, stores and configuration. It is
// under TmpDir, so it lives and dies with the container's tmpfs.
func (c *Config) cacheDir() string { return filepath.Join(c.TmpDir, "kestrelynx-cache") }

// cargoHome is the CARGO_HOME of a Cargo job: a directory of its own in the
// tmpfs of the home, empty when the job starts.
func (c *Config) cargoHome() string { return filepath.Join(c.HomeDir, "cargo-home") }

// prepareCargoHome creates the empty CARGO_HOME. A directory that is already
// there must be empty.
func (c *Config) prepareCargoHome() error {
	dir := c.cargoHome()
	if err := os.Mkdir(dir, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create CARGO_HOME: %w", err)
		}
		li, lerr := os.Lstat(dir)
		entries, rerr := os.ReadDir(dir)
		if lerr != nil || !li.IsDir() || rerr != nil || len(entries) != 0 {
			return fmt.Errorf("CARGO_HOME %s is not an empty directory", dir)
		}
	}
	return nil
}

// checkCargoConfigs requires that cargo finds no configuration file: it reads
// .cargo/config.toml and .cargo/config in the working directory and every
// directory above it, and in its home. Whatever is there, of any type, or
// cannot be told to be absent, makes the container one the job does not run in.
func (c *Config) checkCargoConfigs(tree string) error {
	var dirs []string
	for d := filepath.Clean(tree); ; d = filepath.Dir(d) {
		dirs = append(dirs, filepath.Join(d, ".cargo"))
		if d == filepath.Dir(d) {
			break
		}
	}
	dirs = append(dirs, c.cargoHome())
	for _, dir := range dirs {
		for _, name := range []string{"config.toml", "config"} {
			p := filepath.Join(dir, name)
			if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("cargo would read the configuration file %s", p)
			}
		}
	}
	return nil
}

// prepareCache creates the cache directory and the empty npm configuration
// files the environment points at.
func (c *Config) prepareCache() error {
	if err := os.MkdirAll(c.cacheDir(), 0o700); err != nil {
		return err
	}
	for _, n := range []string{npmUserConfig, npmGlobalConfig} {
		if err := os.WriteFile(filepath.Join(c.cacheDir(), n), nil, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// childEnv builds the environment of a child process from a fixed list. The
// program's own environment is never copied, so nothing the container was
// started with, and no repository file, can add a variable. Package-manager
// configuration files are pointed at /dev/null so only these values count.
func (c *Config) childEnv(m worker.Manager) []string {
	cache := c.cacheDir()
	env := map[string]string{
		"PATH":            c.Path,
		"HOME":            c.HomeDir,
		"TMPDIR":          c.TmpDir,
		"LANG":            "C.UTF-8",
		"TERM":            "dumb",
		"NO_COLOR":        "1",
		"XDG_CACHE_HOME":  filepath.Join(cache, "xdg-cache"),
		"XDG_DATA_HOME":   filepath.Join(cache, "xdg-data"),
		"XDG_CONFIG_HOME": filepath.Join(cache, "xdg-config"),
		"XDG_STATE_HOME":  filepath.Join(cache, "xdg-state"),
	}
	switch m {
	case worker.ManagerNpm, worker.ManagerPnpm:
		env["npm_config_userconfig"] = filepath.Join(cache, npmUserConfig)
		env["npm_config_globalconfig"] = filepath.Join(cache, npmGlobalConfig)
		env["npm_config_registry"] = npmRegistry
		env["npm_config_update_notifier"] = "false"
		env["npm_config_fund"] = "false"
		env["npm_config_audit"] = "false"
		env["npm_config_ignore_scripts"] = "true"
		env["npm_config_progress"] = "false"
		env["COREPACK_ENABLE_NETWORK"] = "0"
		env["COREPACK_ENABLE_AUTO_PIN"] = "0"
		env["COREPACK_ENABLE_DOWNLOAD_PROMPT"] = "0"
		env["COREPACK_ENABLE_STRICT"] = "0"
		if m == worker.ManagerNpm {
			env["npm_config_cache"] = filepath.Join(cache, "npm")
			env["npm_config_prefix"] = filepath.Join(cache, "npm-prefix")
		} else {
			// pnpm reads its own settings from pnpm_config_* variables; the
			// npm_config_* names above only matter for the shared files. The
			// settings that stop pnpm from fetching another version of itself
			// are not set here: pnpm 10 does not read them from the
			// environment, so they are arguments of the command line (see
			// worker.PnpmFixedConfig).
			env["pnpm_config_registry"] = npmRegistry
			env["pnpm_config_store_dir"] = filepath.Join(cache, "pnpm-store")
			env["pnpm_config_cache_dir"] = filepath.Join(cache, "pnpm-cache")
			env["pnpm_config_update_notifier"] = "false"
			env["PNPM_HOME"] = filepath.Join(cache, "pnpm-home")
		}
	case worker.ManagerUv:
		env["UV_NO_CONFIG"] = "1"
		env["UV_PYTHON_DOWNLOADS"] = "never"
		env["UV_PYTHON_PREFERENCE"] = "only-system"
		env["UV_CACHE_DIR"] = filepath.Join(cache, "uv")
		env["UV_NO_PROGRESS"] = "1"
	case worker.ManagerPip:
		env["PIP_CONFIG_FILE"] = "/dev/null"
		env["PIP_CACHE_DIR"] = filepath.Join(cache, "pip")
		env["PIP_NO_INPUT"] = "1"
		env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
		env["PYTHONDONTWRITEBYTECODE"] = "1"
		env["PYTHONNOUSERSITE"] = "1"
	case worker.ManagerGradle:
		// The gradle of the image runs without a daemon, with the JDK of the
		// image and with its user home, the cache of its downloads and its
		// settings in the tmpfs, so that no init script or property of the
		// image's user is read. Nothing else reaches it: no GRADLE_OPTS,
		// JAVA_OPTS or proxy setting.
		env["JAVA_HOME"] = worker.GradleJavaHome
		env["GRADLE_USER_HOME"] = filepath.Join(cache, "gradle")
	case worker.ManagerCargo:
		// cargo and rustc of the toolchain are named by their absolute paths,
		// so rustup's proxies, which read a toolchain file and fetch
		// toolchains, are not involved. The home is an empty directory, the
		// registry is the index of crates.io, and no wrapper, registry login
		// or proxy setting reaches the command.
		env["PATH"] = c.rustBin + ":/usr/bin:/bin"
		env["CARGO_HOME"] = c.cargoHome()
		env["RUSTC"] = filepath.Join(c.rustBin, "rustc")
		env["CARGO_REGISTRIES_CRATES_IO_PROTOCOL"] = "sparse"
		env["CARGO_TERM_COLOR"] = "never"
	case worker.ManagerGo:
		// Only these go settings reach the command: modules come from the
		// public proxy and are checked against the public checksum database,
		// nothing is excluded from either, no other toolchain is fetched and
		// no configuration file or workspace is read. The module cache, the
		// build cache and GOPATH are in the tmpfs.
		env["GOPROXY"] = goProxy
		env["GOSUMDB"] = goSumDB
		env["GOPRIVATE"] = ""
		env["GONOPROXY"] = ""
		env["GONOSUMDB"] = ""
		env["GOINSECURE"] = ""
		env["GOFLAGS"] = "-mod=mod"
		env["GOTOOLCHAIN"] = "local"
		env["GOENV"] = "off"
		env["GOWORK"] = "off"
		env["CGO_ENABLED"] = "0"
		env["GOPATH"] = filepath.Join(cache, "go")
		env["GOMODCACHE"] = filepath.Join(cache, "go", "pkg", "mod")
		env["GOCACHE"] = filepath.Join(cache, "go-build")
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
