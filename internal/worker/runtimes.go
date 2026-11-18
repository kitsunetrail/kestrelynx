package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

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

// RuntimeTable is a table of runtimes (official Node.js, Python, Go and Gradle
// images) jobs may run in, and the time it was made. A runtime is selected
// only when the table in use pins an image for it. A table is not changed
// after it is made: every accessor hands out copies.
type RuntimeTable struct {
	// Updated is the time of the update that last changed the table; the zero
	// time for a table that does not say.
	Updated time.Time
	specs   []RuntimeSpec // ordered by id
}

// Len is the number of rows.
func (t RuntimeTable) Len() int { return len(t.specs) }

// Runtimes returns a copy of every row, ordered by id.
func (t RuntimeTable) Runtimes() []RuntimeSpec {
	out := make([]RuntimeSpec, len(t.specs))
	for i, r := range t.specs {
		out[i] = r.clone()
	}
	return out
}

// clone copies the row with its maps and slices, so that the copy can be
// changed without touching the table it came from.
func (r RuntimeSpec) clone() RuntimeSpec {
	r.Platforms = cloneMap(r.Platforms)
	r.Tested = cloneMap(r.Tested)
	r.CoveredPaths = slices.Clone(r.CoveredPaths)
	r.Volumes = slices.Clone(r.Volumes)
	return r
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// currentTable is the table every lookup reads. The main process starts with
// the table of its build and replaces it between cycles, never during one
// (SetRuntimeTable); the program in a work container has none and reads what
// it needs from the id of the job's runtime (RuntimeFromID).
var currentTable atomic.Pointer[RuntimeTable]

// CurrentRuntimeTable returns the table in use.
func CurrentRuntimeTable() RuntimeTable {
	if t := currentTable.Load(); t != nil {
		return *t
	}
	return RuntimeTable{}
}

// SetRuntimeTable makes t the table in use. A cycle must see one table from
// its start to its end, so the caller replaces the table only between cycles,
// together with everything it made from the previous one.
func SetRuntimeTable(t RuntimeTable) {
	currentTable.Store(&t)
	tableGeneration.Add(1)
}

// tableGeneration counts the times the table in use was set.
var tableGeneration atomic.Uint64

// RuntimeTableGeneration changes whenever the table in use is replaced. What
// is made from the table (the clients of the work containers) remembers the
// generation it was made from and is made again when it has changed.
func RuntimeTableGeneration() uint64 { return tableGeneration.Load() }

// currentSpecs is the rows of the table in use. The slice and its rows belong
// to the table: callers read them and hand out copies only.
func currentSpecs() []RuntimeSpec {
	if t := currentTable.Load(); t != nil {
		return t.specs
	}
	return nil
}

type runtimeTableFile struct {
	Schema   int           `json:"schema"`
	Updated  string        `json:"updated,omitempty"`
	Runtimes []RuntimeSpec `json:"runtimes"`
}

// runtimeImages is the repository of the official image of each kind on Docker
// Hub. A row that pins an image names exactly this one.
var runtimeImages = map[RuntimeKind]string{
	KindNode: "node", KindPython: "python", KindGolang: "golang", KindGradle: "gradle",
}

// imageCoverPaths are the paths of an official image that a work container may
// cover with a tmpfs of its own: the places the images in use leave writable
// by everyone, the volume the Gradle images declare and the directory of their
// service manager. A row whose image needs another place covered cannot be run
// by this build. The program in the container allows a tmpfs at exactly these
// and at its own directories.
var imageCoverPaths = []string{
	TmpDir, "/var/tmp", "/run/lock", "/go",
	"/home/gradle", "/home/gradle/.gradle", "/var/lib/pebble/default",
}

// ImageCoverPaths returns the paths of an official image that a work container
// may cover with a tmpfs.
func ImageCoverPaths() []string { return slices.Clone(imageCoverPaths) }

func mustLoadRuntimes(raw []byte) RuntimeTable {
	t, err := parseRuntimeTable(raw)
	if err != nil {
		panic("worker: runtimes.json: " + err.Error())
	}
	return t
}

// parseRuntimeTable decodes and checks the table of a build: every row must
// be one this build can use.
func parseRuntimeTable(raw []byte) (RuntimeTable, error) {
	var f runtimeTableFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return RuntimeTable{}, err
	}
	if f.Schema != 1 {
		return RuntimeTable{}, fmt.Errorf("schema %d is not 1", f.Schema)
	}
	var updated time.Time
	if f.Updated != "" {
		var err error
		if updated, err = parseTableTime(f.Updated); err != nil {
			return RuntimeTable{}, err
		}
	}
	specs, err := checkRuntimeRows(f.Runtimes)
	if err != nil {
		return RuntimeTable{}, err
	}
	return RuntimeTable{Updated: updated, specs: specs}, nil
}

// parseTableTime reads the time a table was updated: RFC 3339 in UTC.
func parseTableTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !strings.HasSuffix(s, "Z") {
		return time.Time{}, fmt.Errorf("updated %q is not a time in UTC", s)
	}
	return t, nil
}

// parseRuntimes decodes and checks the rows of a table of a build.
func parseRuntimes(raw []byte) ([]RuntimeSpec, error) {
	t, err := parseRuntimeTable(raw)
	if err != nil {
		return nil, err
	}
	return t.specs, nil
}

// checkRuntimeRows checks every row and that no id is repeated, and returns
// the rows ordered by id.
func checkRuntimeRows(rows []RuntimeSpec) ([]RuntimeSpec, error) {
	seen := map[string]bool{}
	for _, r := range rows {
		if r.ID == "" || seen[r.ID] {
			return nil, fmt.Errorf("runtime id %q is empty or repeated", r.ID)
		}
		seen[r.ID] = true
		if err := checkRuntimeRow(r); err != nil {
			return nil, err
		}
	}
	out := make([]RuntimeSpec, len(rows))
	for i, r := range rows {
		out[i] = r.clone()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// checkRuntimeRow checks one row: its id says the same as its fields, the
// fields a kind may carry, and for a row that pins an image the image, the
// versions, the digests and the record of what the container has to cover.
func checkRuntimeRow(r RuntimeSpec) error {
	id, ok := RuntimeFromID(r.ID)
	if !ok {
		return fmt.Errorf("runtime id %q is not the id of a runtime", r.ID)
	}
	if id.Kind != r.Kind {
		return fmt.Errorf("runtime %q has the kind %q", r.ID, r.Kind)
	}
	if id.Series != r.Series {
		return fmt.Errorf("runtime %q does not match its series %q", r.ID, r.Series)
	}
	if r.Kind == KindGradle && (id.Version != r.Version || id.JDK != r.JDK) {
		return fmt.Errorf("runtime %q does not match its Gradle version %q and JDK %q", r.ID, r.Version, r.JDK)
	}
	if r.Kind != KindGradle {
		if _, err := time.Parse("2006-01-02", r.EOL); err != nil {
			return fmt.Errorf("runtime %q: eol %q is not a date", r.ID, r.EOL)
		}
	} else if r.EOL != "" || r.Support != "" || r.LTSFrom != "" || r.Pip != "" {
		return fmt.Errorf("runtime %q: a Gradle row has no end of support, long-term support or pip", r.ID)
	}
	if r.Kind != KindGradle && r.JDK != "" {
		return fmt.Errorf("runtime %q: only a Gradle row has a JDK", r.ID)
	}
	if r.LTSFrom != "" {
		if _, err := time.Parse("2006-01-02", r.LTSFrom); err != nil || r.Kind != KindNode {
			return fmt.Errorf("runtime %q: lts_from %q is not a date of a Node.js series", r.ID, r.LTSFrom)
		}
	}
	if r.Image == "" {
		// A series that is out of support has its dates and nothing of an
		// image. A Gradle row cannot be written this way: its version is part
		// of its id.
		if r.IndexDigest != "" || len(r.Platforms) != 0 || r.Version != "" {
			return fmt.Errorf("runtime %q has no image but carries image fields", r.ID)
		}
		return nil
	}
	if r.Image != runtimeImages[r.Kind] {
		return fmt.Errorf("runtime %q: the image %q is not the official image of its kind", r.ID, r.Image)
	}
	if r.Kind != KindGradle && (!ValidSemver(r.Version) || !strings.HasPrefix(r.Version, r.Series+".")) {
		return fmt.Errorf("runtime %q: version %q is not in the series %q", r.ID, r.Version, r.Series)
	}
	if r.Kind == KindPython && !ValidPythonVersion(r.Pip) {
		return fmt.Errorf("runtime %q: pip version %q is invalid", r.ID, r.Pip)
	}
	if !digestRe.MatchString(r.IndexDigest) {
		return fmt.Errorf("runtime %q: index digest %q is invalid", r.ID, r.IndexDigest)
	}
	for _, p := range []string{"linux/amd64", "linux/arm64"} {
		if !digestRe.MatchString(r.Platforms[p]) {
			return fmt.Errorf("runtime %q: no valid manifest digest for %s", r.ID, p)
		}
	}
	if len(r.CoveredPaths) == 0 || !volumesRecorded(r) {
		return fmt.Errorf("runtime %q: its safety record is incomplete", r.ID)
	}
	if repeats(r.CoveredPaths) || repeats(r.Volumes) {
		return fmt.Errorf("runtime %q: a covered path or a volume is listed twice", r.ID)
	}
	if p, ok := uncoverablePath(r); ok {
		return fmt.Errorf("runtime %q: a work container cannot cover %q", r.ID, p)
	}
	if r.Kind == KindGradle && r.ExactTag != r.Tag {
		return fmt.Errorf("runtime %q: the tag of a Gradle image names its exact version", r.ID)
	}
	return nil
}

// repeats reports whether a value is in the list more than once.
func repeats(list []string) bool {
	seen := map[string]bool{}
	for _, v := range list {
		if seen[v] {
			return true
		}
		seen[v] = true
	}
	return false
}

// uncoverablePath returns a covered path of the row that this build does not
// cover with a tmpfs.
func uncoverablePath(r RuntimeSpec) (string, bool) {
	for _, p := range r.CoveredPaths {
		if !slices.Contains(imageCoverPaths, p) {
			return p, true
		}
	}
	return "", false
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

// Runtimes returns a copy of every row of the table in use, ordered by id.
func Runtimes() []RuntimeSpec {
	return CurrentRuntimeTable().Runtimes()
}

// LookupRuntime returns a copy of the row of the table in use with the given
// id.
func LookupRuntime(id string) (RuntimeSpec, bool) {
	for _, r := range currentSpecs() {
		if r.ID == id {
			return r.clone(), true
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
	for _, r := range currentSpecs() {
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
	for _, r := range currentSpecs() {
		if r.Kind != KindGradle || !r.HasImage() || !r.IsTestedOn(platform) || r.Version != version {
			continue
		}
		known = true
		if r.JDK == strconv.Itoa(jdk) {
			return r.clone(), nil
		}
	}
	if known {
		return RuntimeSpec{}, ErrGradleToolchainUnsupported
	}
	return RuntimeSpec{}, ErrGradleVersionUnsupported
}
