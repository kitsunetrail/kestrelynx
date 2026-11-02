package worker

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runtimesJSON is the table of runtimes (official Node.js, Python, Go and Gradle images)
// jobs may run in. It is part of the build: a runtime is selected only when
// the table pins an image for it.
//
//go:embed runtimes.json
var runtimesJSON []byte

// RuntimeKind says which language a runtime is.
type RuntimeKind string

const (
	KindNode   RuntimeKind = "node"
	KindPython RuntimeKind = "python"
	KindGolang RuntimeKind = "golang"
	// KindGradle is one version of Gradle on one JDK, in the official gradle
	// image of that pair.
	KindGradle RuntimeKind = "gradle"
)

// RuntimeSpec is one row of the runtime table.
type RuntimeSpec struct {
	// ID names the runtime in a job ("node24", "python3.13", "golang1.26",
	// "gradle9.8.2-jdk21").
	ID   string      `json:"id"`
	Kind RuntimeKind `json:"kind"`
	// Series is the major version of Node.js and Gradle or the X.Y of Python
	// and Go.
	Series string `json:"series"`
	// Version is the exact Node.js, Python, Go or Gradle version of the pinned
	// image, and Pip the version of the pip it carries (Python only). Both are
	// empty for a runtime that has no image.
	Version string `json:"version,omitempty"`
	Pip     string `json:"pip,omitempty"`
	// JDK is the major version of the JDK a Gradle image carries.
	JDK string `json:"jdk,omitempty"`
	// Image is the repository of the official image on Docker Hub, Tag the
	// series tag the table is updated from and ExactTag the tag of the exact
	// version. IndexDigest is the digest of the image index, and Platforms
	// the digest of the manifest of each platform. A runtime without an image
	// (one that is already out of support) has none of these.
	Image       string            `json:"image,omitempty"`
	Tag         string            `json:"tag,omitempty"`
	ExactTag    string            `json:"exact_tag,omitempty"`
	IndexDigest string            `json:"index_digest,omitempty"`
	Platforms   map[string]string `json:"platforms,omitempty"`
	// CoveredPaths are the paths of the image that are writable by everyone
	// and that the container covers with a tmpfs of its own.
	CoveredPaths []string `json:"covered_paths,omitempty"`
	// VolumesEmpty and Healthcheck record what the image's configuration
	// holds: no declared volumes, and whether it declares a health check. An
	// image that declares volumes lists them in Volumes instead, each also one
	// of the CoveredPaths, so that the container's own tmpfs takes its place.
	VolumesEmpty bool     `json:"volumes_empty,omitempty"`
	Volumes      []string `json:"volumes,omitempty"`
	Healthcheck  bool     `json:"healthcheck,omitempty"`
	// Support is the maintenance state and EOL the date support ends (the
	// first of the month where only the month is published, EOLMonthOnly). A
	// Gradle row has neither: Gradle publishes no end of support.
	Support      string `json:"support"`
	EOL          string `json:"eol"`
	EOLMonthOnly bool   `json:"eol_month_only,omitempty"`
	// LTSFrom is the date a Node.js series enters long-term support; it is
	// empty for a series that never does and for Python.
	LTSFrom string `json:"lts_from,omitempty"`
	// Checked is the date the row was last confirmed. Tested holds, per
	// platform, the manifest digest that passed the integration tests.
	Checked string            `json:"checked"`
	Tested  map[string]string `json:"tested,omitempty"`
}

type runtimeTable struct {
	Schema   int           `json:"schema"`
	Runtimes []RuntimeSpec `json:"runtimes"`
}

var runtimeSpecs = mustLoadRuntimes(runtimesJSON)

func mustLoadRuntimes(raw []byte) []RuntimeSpec {
	specs, err := parseRuntimes(raw)
	if err != nil {
		panic("worker: runtimes.json: " + err.Error())
	}
	return specs
}

// parseRuntimes decodes and checks a runtime table.
func parseRuntimes(raw []byte) ([]RuntimeSpec, error) {
	var t runtimeTable
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	if t.Schema != 1 {
		return nil, fmt.Errorf("schema %d is not 1", t.Schema)
	}
	seen := map[string]bool{}
	for _, r := range t.Runtimes {
		if r.ID == "" || seen[r.ID] {
			return nil, fmt.Errorf("runtime id %q is empty or repeated", r.ID)
		}
		seen[r.ID] = true
		switch r.Kind {
		case KindNode:
			if r.ID != "node"+r.Series {
				return nil, fmt.Errorf("runtime %q does not match its series %q", r.ID, r.Series)
			}
		case KindPython:
			if r.ID != "python"+r.Series {
				return nil, fmt.Errorf("runtime %q does not match its series %q", r.ID, r.Series)
			}
		case KindGolang:
			if r.ID != "golang"+r.Series {
				return nil, fmt.Errorf("runtime %q does not match its series %q", r.ID, r.Series)
			}
		case KindGradle:
			if !ValidGradleVersion(r.Version) || !jdkRe.MatchString(r.JDK) || r.ID != "gradle"+r.Version+"-jdk"+r.JDK ||
				!strings.HasPrefix(r.Version, r.Series+".") {
				return nil, fmt.Errorf("runtime %q does not match its Gradle version %q, JDK %q and series %q", r.ID, r.Version, r.JDK, r.Series)
			}
		default:
			return nil, fmt.Errorf("runtime %q has the unknown kind %q", r.ID, r.Kind)
		}
		if r.Kind != KindGradle {
			if _, err := time.Parse("2006-01-02", r.EOL); err != nil {
				return nil, fmt.Errorf("runtime %q: eol %q is not a date", r.ID, r.EOL)
			}
		} else if r.EOL != "" || r.Support != "" || r.LTSFrom != "" || r.Pip != "" {
			return nil, fmt.Errorf("runtime %q: a Gradle row has no end of support, long-term support or pip", r.ID)
		}
		if r.Kind != KindGradle && r.JDK != "" {
			return nil, fmt.Errorf("runtime %q: only a Gradle row has a JDK", r.ID)
		}
		if r.LTSFrom != "" {
			if _, err := time.Parse("2006-01-02", r.LTSFrom); err != nil || r.Kind != KindNode {
				return nil, fmt.Errorf("runtime %q: lts_from %q is not a date of a Node.js series", r.ID, r.LTSFrom)
			}
		}
		if r.Image == "" {
			if r.IndexDigest != "" || len(r.Platforms) != 0 || r.Version != "" {
				return nil, fmt.Errorf("runtime %q has no image but carries image fields", r.ID)
			}
			continue
		}
		if r.Kind != KindGradle && (!ValidSemver(r.Version) || !strings.HasPrefix(r.Version, r.Series+".")) {
			return nil, fmt.Errorf("runtime %q: version %q is not in the series %q", r.ID, r.Version, r.Series)
		}
		if r.Kind == KindPython && !ValidPythonVersion(r.Pip) {
			return nil, fmt.Errorf("runtime %q: pip version %q is invalid", r.ID, r.Pip)
		}
		if !digestRe.MatchString(r.IndexDigest) {
			return nil, fmt.Errorf("runtime %q: index digest %q is invalid", r.ID, r.IndexDigest)
		}
		for _, p := range []string{"linux/amd64", "linux/arm64"} {
			if !digestRe.MatchString(r.Platforms[p]) {
				return nil, fmt.Errorf("runtime %q: no valid manifest digest for %s", r.ID, p)
			}
		}
		if len(r.CoveredPaths) == 0 || !volumesRecorded(r) {
			return nil, fmt.Errorf("runtime %q: its safety record is incomplete", r.ID)
		}
		if r.Kind == KindGradle && r.ExactTag != r.Tag {
			return nil, fmt.Errorf("runtime %q: the tag of a Gradle image names its exact version", r.ID)
		}
	}
	out := append([]RuntimeSpec(nil), t.Runtimes...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// volumesRecorded reports whether the row says what the image does about
// volumes: it declares none, or it lists the ones it declares and each is
// covered by a tmpfs of the container.
func volumesRecorded(r RuntimeSpec) bool {
	if r.VolumesEmpty {
		return len(r.Volumes) == 0
	}
	if len(r.Volumes) == 0 {
		return false
	}
	for _, v := range r.Volumes {
		if !contains(r.CoveredPaths, v) {
			return false
		}
	}
	return true
}

// Runtimes returns every row of the table, ordered by id.
func Runtimes() []RuntimeSpec {
	return append([]RuntimeSpec(nil), runtimeSpecs...)
}

// LookupRuntime returns the row with the given id.
func LookupRuntime(id string) (RuntimeSpec, bool) {
	for _, r := range runtimeSpecs {
		if r.ID == id {
			return r, true
		}
	}
	return RuntimeSpec{}, false
}

// HasImage reports whether the table pins an image for the runtime, which is
// what makes it selectable.
func (r RuntimeSpec) HasImage() bool { return r.Image != "" }

// ImageRef is the pinned reference of the runtime's image in the familiar form
// "node@sha256:<index digest>".
func (r RuntimeSpec) ImageRef() string { return r.Image + "@" + r.IndexDigest }

// VersionEnv is the environment variable of the image that holds the exact
// version of the language. It is empty for a kind the table does not have.
func (r RuntimeSpec) VersionEnv() string {
	switch r.Kind {
	case KindNode:
		return "NODE_VERSION"
	case KindPython:
		return "PYTHON_VERSION"
	case KindGolang:
		return "GOLANG_VERSION"
	case KindGradle:
		return "GRADLE_VERSION"
	}
	return ""
}

// Interpreter is the absolute path of the node, python or go executable the
// official image provides. It is empty for a kind the table does not have.
func (r RuntimeSpec) Interpreter() string {
	switch r.Kind {
	case KindNode:
		return "/usr/local/bin/node"
	case KindPython:
		return "/usr/local/bin/" + r.ID
	case KindGolang:
		return "/usr/local/go/bin/go"
	case KindGradle:
		return GradleExecutable
	}
	return ""
}

// InterpreterName is the name the interpreter is linked as in the directory of
// the tools. It is empty for a kind the table does not have.
func (r RuntimeSpec) InterpreterName() string {
	switch r.Kind {
	case KindNode:
		return "node"
	case KindPython:
		return r.ID
	case KindGolang:
		return "go"
	case KindGradle:
		return "gradle"
	}
	return ""
}

// The places of the official gradle image: the command, and the JDK it
// carries, which the command finds through JAVA_HOME.
const (
	GradleExecutable = "/opt/gradle/bin/gradle"
	GradleJavaHome   = "/opt/java/openjdk"
)

// EOLDate is the date support for the runtime ends.
func (r RuntimeSpec) EOLDate() time.Time {
	t, _ := time.Parse("2006-01-02", r.EOL)
	return t
}

// EndOfLife reports whether the date of now is past the end of support.
func (r RuntimeSpec) EndOfLife(now time.Time) bool {
	if r.EOL == "" {
		return false
	}
	y, m, d := now.UTC().Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return today.After(r.EOLDate())
}

// InLTS reports whether the series is in long-term support at the time now:
// its long-term support has begun and its support has not ended.
func (r RuntimeSpec) InLTS(now time.Time) bool {
	if r.LTSFrom == "" || r.EndOfLife(now) {
		return false
	}
	from, err := time.Parse("2006-01-02", r.LTSFrom)
	if err != nil {
		return false
	}
	y, m, d := now.UTC().Date()
	return !time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Before(from)
}

// DefaultNodeRuntime is the id of the Node.js runtime used when a project
// declares nothing about Node.js: the newest series of the table that has an
// image and is in long-term support at the time now. When none is, it is the
// newest series that has an image and is in support, and when the support of
// every series has ended, the newest series that has an image.
func DefaultNodeRuntime(now time.Time) (string, bool) {
	var lts, supported, newest RuntimeSpec
	for _, r := range runtimeSpecs {
		if r.Kind != KindNode || !r.HasImage() {
			continue
		}
		if seriesOrder(r.Series, newest.Series) {
			newest = r
		}
		if r.EndOfLife(now) {
			continue
		}
		if seriesOrder(r.Series, supported.Series) {
			supported = r
		}
		if r.InLTS(now) && seriesOrder(r.Series, lts.Series) {
			lts = r
		}
	}
	for _, r := range []RuntimeSpec{lts, supported, newest} {
		if r.ID != "" {
			return r.ID, true
		}
	}
	return "", false
}

// seriesOrder reports whether the Node.js series a is newer than b; an empty
// b is older than every series.
func seriesOrder(a, b string) bool {
	if b == "" {
		return true
	}
	x, ex := strconv.Atoi(a)
	y, ey := strconv.Atoi(b)
	return ex == nil && ey == nil && x > y
}

// Label is how the runtime is named to a person.
func (r RuntimeSpec) Label() string {
	switch r.Kind {
	case KindNode:
		return "Node.js " + r.Series
	case KindPython:
		return "Python " + r.Series
	case KindGolang:
		return "Go " + r.Series
	case KindGradle:
		return "Gradle " + r.Version + " on JDK " + r.JDK
	}
	return string(r.Kind) + " " + r.Series
}

// JobRuntime is the Runtime a job for this runtime carries.
func (r RuntimeSpec) JobRuntime() Runtime {
	return Runtime{ID: r.ID, Version: r.Version, Pip: r.Pip}
}

// KindFor is the kind of runtime a manager needs. A manager the protocol does
// not have gets the empty kind, which no row of the table has.
func KindFor(m Manager) RuntimeKind {
	switch m {
	case ManagerNpm, ManagerPnpm:
		return KindNode
	case ManagerUv, ManagerPip:
		return KindPython
	case ManagerGo:
		return KindGolang
	case ManagerGradle:
		return KindGradle
	}
	return ""
}

// IsTestedOn reports whether an integration test has run the row's image on
// the platform (such as linux/amd64): the platform's manifest digest is
// recorded and is the one the row pins. A run on another platform does not
// count.
func (r RuntimeSpec) IsTestedOn(platform string) bool {
	d := r.Tested[platform]
	return d != "" && r.Platforms[platform] == d
}

// Why a Gradle runtime was not found.
var (
	// ErrGradleVersionUnsupported: the table has no tested image for the
	// version of Gradle on any JDK.
	ErrGradleVersionUnsupported = errors.New("no runtime for this version of Gradle")
	// ErrGradleToolchainUnsupported: the table has tested images for the
	// version of Gradle, but none on this JDK.
	ErrGradleToolchainUnsupported = errors.New("no runtime for this version of Gradle on this JDK")
)

// FindGradleRuntime returns the row for exactly this version of Gradle on this
// major version of the JDK, for jobs on the platform. Only a row that has an
// image and has been run by an integration test on that platform is trusted:
// of the rows the table lists for the compatible pairs, the ones nobody ran
// there are not found. The error is
// ErrGradleVersionUnsupported when no trusted row has the version and
// ErrGradleToolchainUnsupported when some do but none has the JDK.
func FindGradleRuntime(version string, jdk int, platform string) (RuntimeSpec, error) {
	known := false
	for _, r := range runtimeSpecs {
		if r.Kind != KindGradle || !r.HasImage() || !r.IsTestedOn(platform) || r.Version != version {
			continue
		}
		known = true
		if r.JDK == strconv.Itoa(jdk) {
			return r, nil
		}
	}
	if known {
		return RuntimeSpec{}, ErrGradleToolchainUnsupported
	}
	return RuntimeSpec{}, ErrGradleVersionUnsupported
}
