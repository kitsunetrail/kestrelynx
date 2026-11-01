package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// fsAnalysisBase identifies the scan settings KestreLynx fixes for a
// filesystem scan of dependency files: the vulnerability scanner only, every
// package listed, development dependencies included, and no configuration,
// ignore or VEX input. A change to the arguments that alters what is reported
// must change this value.
const fsAnalysisBase = "fs;scanners=vuln;pkg-types=default;ignore-unfixed=false;list-all-pkgs=true;dev-deps=included;config=none;ignorefile=none;vex=none"

// Limits of a filesystem scan.
const (
	maxFSFiles       = 128
	maxFSPathParts   = 8
	maxFSPathBytes   = 255
	maxFSFileBytes   = 32 << 20
	maxFSReportBytes = 64 << 20
)

var (
	// ErrConditionsUnknown: the conditions the scan was to be taken under are
	// incomplete, so nothing can be compared with them.
	ErrConditionsUnknown = errors.New("scan conditions are not known")
	// ErrConditionsDiffer: Trivy, its databases or its settings are not those
	// of the prepared conditions.
	ErrConditionsDiffer = errors.New("scan conditions differ from the prepared conditions")
)

// FSScan is the result of scanning a set of dependency files.
type FSScan struct {
	// Conditions are the conditions measured immediately before the scan. Its
	// AnalysisSettings names the filesystem settings; every other field is
	// equal to the prepared conditions the scan was checked against.
	Conditions ScanConditions
	// Report is the parsed report: Findings and Packages are the filesystem
	// scan's. It carries no image identity.
	Report ImageScan
}

// fsSegmentRE is one path segment of a scanned file: no leading dot, so
// neither "." nor ".." nor hidden files.
var fsSegmentRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// fsMirrorRE is the only Maven mirror address a scan takes: the loopback
// address with a port and the fixed path.
var fsMirrorRE = regexp.MustCompile(`^http://127\.0\.0\.1:([0-9]{1,5})/maven2$`)

// FSOptions are settings of one filesystem scan.
type FSOptions struct {
	// MavenMirror, when set, is the base URL (http://127.0.0.1:port/maven2) every Maven repository request of the scan goes to.
	MavenMirror string
}

// checkFSName reports why name is not a relative path the scan takes: at most
// maxFSPathParts segments of plain characters, within maxFSPathBytes.
func checkFSName(name string) error {
	if name == "" || len(name) > maxFSPathBytes {
		return fmt.Errorf("filesystem scan file name %q is empty or over %d bytes", name, maxFSPathBytes)
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxFSPathParts {
		return fmt.Errorf("filesystem scan file name %q has more than %d segments", name, maxFSPathParts)
	}
	for _, seg := range parts {
		if !fsSegmentRE.MatchString(seg) {
			return fmt.Errorf("filesystem scan file name %q is not a plain relative path", name)
		}
	}
	return nil
}

// checkFSMirror reports why mirror is not the loopback Maven address a scan
// takes.
func checkFSMirror(mirror string) error {
	m := fsMirrorRE.FindStringSubmatch(mirror)
	if m == nil {
		return fmt.Errorf("maven mirror %q is not http://127.0.0.1:<port>/maven2", mirror)
	}
	port := 0
	for _, c := range m[1] {
		port = port*10 + int(c-'0')
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("maven mirror %q has no valid port", mirror)
	}
	return nil
}

// withEnv returns env with each key set to the given value, replacing any
// inherited one (case-sensitive match, as the environment is).
func withEnv(env []string, set map[string]string) []string {
	out := make([]string, 0, len(env)+len(set))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if _, replaced := set[k]; !replaced {
			out = append(out, e)
		}
	}
	for k, v := range set {
		out = append(out, k+"="+v)
	}
	return out
}

// noProxyWith returns the NO_PROXY list v with the loopback address added.
func noProxyWith(v string) string {
	if v == "" {
		return "127.0.0.1"
	}
	return v + ",127.0.0.1"
}

// ScanFS scans dependency files that the caller holds in memory (name to
// content) for vulnerabilities, under the databases, severities and Trivy of
// prepared (the conditions of the cycle's image scans). Only the given files
// are put in a private temporary directory and scanned; Trivy runs in another
// empty directory with no TRIVY_* variable, and its configuration file and
// ignore file are pointed at empty files, so nothing from the repository the
// files came from or from the host can change what is reported. Databases are
// never updated. It fails with ErrConditionsUnknown or ErrConditionsDiffer
// when the conditions cannot be shown to be those of prepared.
//
// t must be in comparison mode (SkipDBUpdate).
func (t Trivy) ScanFS(ctx context.Context, files map[string][]byte, prepared ScanConditions) (FSScan, error) {
	return t.ScanFSWith(ctx, files, prepared, FSOptions{})
}

// ScanFSWith is ScanFS with the settings in opts. File names may be relative
// paths of up to maxFSPathParts plain segments; the directories are created
// inside the private scan directory. With opts.MavenMirror, Trivy runs with
// a HOME and MAVEN_HOME of its own whose only Maven setting is a mirror of
// every repository to that address and an empty local repository, so Maven
// requests go nowhere else and nothing persists; the analysis settings name
// that.
func (t Trivy) ScanFSWith(ctx context.Context, files map[string][]byte, prepared ScanConditions, opts FSOptions) (FSScan, error) {
	if !t.SkipDBUpdate {
		return FSScan{}, errors.New("filesystem scans need the comparison mode (databases fixed)")
	}
	if len(files) == 0 || len(files) > maxFSFiles {
		return FSScan{}, fmt.Errorf("filesystem scan needs 1..%d files, got %d", maxFSFiles, len(files))
	}
	for name, content := range files {
		if err := checkFSName(name); err != nil {
			return FSScan{}, err
		}
		if len(content) > maxFSFileBytes {
			return FSScan{}, fmt.Errorf("filesystem scan file %q is over %d bytes", name, maxFSFileBytes)
		}
	}
	if opts.MavenMirror != "" {
		if err := checkFSMirror(opts.MavenMirror); err != nil {
			return FSScan{}, err
		}
	}
	if !prepared.Known() {
		return FSScan{}, ErrConditionsUnknown
	}
	rt, err := t.resolved()
	if err != nil {
		return FSScan{}, err
	}
	now, err := rt.current(ctx)
	if err != nil {
		return FSScan{}, err
	}
	now.Severities = normalizeSeverities(strings.Split(rt.severity(), ","))
	// The prepared conditions come from image scans in comparison mode; the
	// filesystem settings are the only field allowed to differ from them.
	if prepared.AnalysisSettings != analysisBase+";env=sanitized;workdir=isolated" {
		return FSScan{}, fmt.Errorf("%w: the prepared analysis settings are not those of a comparison-mode scan", ErrConditionsDiffer)
	}
	now.AnalysisSettings = fsAnalysisBase + ";env=sanitized;workdir=isolated"
	if opts.MavenMirror != "" {
		now.AnalysisSettings += ";maven=relay"
	}
	want := prepared
	want.AnalysisSettings = now.AnalysisSettings
	if !now.Equal(want) {
		return FSScan{}, ErrConditionsDiffer
	}

	root, err := os.MkdirTemp("", "kestrelynx-trivyfs-")
	if err != nil {
		return FSScan{}, fmt.Errorf("create scan directory: %w", err)
	}
	defer os.RemoveAll(root)
	scanDir := filepath.Join(root, "scan")
	cwd := filepath.Join(root, "cwd")
	for _, d := range []string{scanDir, cwd} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return FSScan{}, fmt.Errorf("create scan directory: %w", err)
		}
	}
	for name, content := range files {
		path := filepath.Join(scanDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return FSScan{}, fmt.Errorf("create scan directory: %w", err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return FSScan{}, fmt.Errorf("write scan file: %w", err)
		}
	}
	cfgPath := filepath.Join(root, "config.yaml")
	ignorePath := filepath.Join(root, "ignore")
	for _, p := range []string{cfgPath, ignorePath} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			return FSScan{}, fmt.Errorf("write scan settings: %w", err)
		}
	}

	args := []string{
		"fs", "--quiet", "--format", "json",
		"--severity", rt.severity(),
		"--scanners", "vuln",
		"--list-all-pkgs", "--include-dev-deps",
		"--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update",
		"--skip-version-check", "--disable-telemetry", "--no-progress",
		"--cache-dir", rt.CacheDir,
		"--config", cfgPath, "--ignorefile", ignorePath,
		scanDir,
	}
	cmd := exec.CommandContext(ctx, rt.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: maxFSReportBytes}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	cmd.Dir = cwd
	cmd.Env = withoutTrivyEnv(os.Environ())
	if opts.MavenMirror != "" {
		home := filepath.Join(root, "home")
		mavenHome := filepath.Join(root, "mavenhome")
		repo := filepath.Join(root, "m2repo")
		for _, d := range []string{filepath.Join(home, ".m2"), mavenHome, repo} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return FSScan{}, fmt.Errorf("create maven settings: %w", err)
			}
		}
		if err := os.WriteFile(filepath.Join(home, ".m2", "settings.xml"), []byte(mavenSettingsXML(repo, opts.MavenMirror)), 0o600); err != nil {
			return FSScan{}, fmt.Errorf("write maven settings: %w", err)
		}
		cmd.Env = withEnv(cmd.Env, map[string]string{
			"HOME":       home,
			"MAVEN_HOME": mavenHome,
			"NO_PROXY":   noProxyWith(os.Getenv("NO_PROXY")),
			"no_proxy":   noProxyWith(os.Getenv("no_proxy")),
		})
	}
	if err := cmd.Run(); err != nil {
		return FSScan{}, fmt.Errorf("trivy fs scan: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	report, err := ParseReport(stdout.Bytes())
	if err != nil {
		return FSScan{}, fmt.Errorf("trivy fs scan: %w", err)
	}
	if report.TrivyVersion != now.TrivyVersion {
		return FSScan{}, fmt.Errorf("%w: the report names Trivy %q, not %q", ErrConditionsDiffer, report.TrivyVersion, now.TrivyVersion)
	}
	return FSScan{Conditions: now, Report: report}, nil
}

// CurrentConditions reads the conditions of Trivy, its databases and its
// settings as they are now, with the severities this Trivy scans, without
// downloading or changing anything. In comparison mode (SkipDBUpdate) the
// result equals what PrepareDB returned when the databases have not changed
// since.
func (t Trivy) CurrentConditions(ctx context.Context) (ScanConditions, error) {
	if !t.SkipDBUpdate {
		return ScanConditions{}, errors.New("current conditions are read in the comparison mode (databases fixed)")
	}
	rt, err := t.resolved()
	if err != nil {
		return ScanConditions{}, err
	}
	c, err := rt.current(ctx)
	if err != nil {
		return ScanConditions{}, err
	}
	c.Severities = normalizeSeverities(strings.Split(rt.severity(), ","))
	return c, nil
}

// mavenSettingsXML is the whole Maven settings of a relayed scan: an empty
// local repository and one mirror of every repository.
func mavenSettingsXML(localRepo, mirrorURL string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<settings>
  <localRepository>` + xmlEscape(localRepo) + `</localRepository>
  <mirrors>
    <mirror>
      <id>kestrelynx</id>
      <mirrorOf>*</mirrorOf>
      <url>` + xmlEscape(mirrorURL) + `</url>
    </mirror>
  </mirrors>
</settings>
`
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return ""
	}
	return b.String()
}
