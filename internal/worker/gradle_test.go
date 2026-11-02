package worker

import (
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	gradleDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	gradleDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// gradleRow is a row of the table as the script writes it.
func gradleRow(version, jdk string) string {
	id := "gradle" + version + "-jdk" + jdk
	series, _, _ := strings.Cut(version, ".")
	return `{"id":"` + id + `","kind":"gradle","series":"` + series + `","version":"` + version + `","jdk":"` + jdk +
		`","image":"gradle","tag":"` + version + `-jdk` + jdk + `","exact_tag":"` + version + `-jdk` + jdk +
		`","index_digest":"` + gradleDigestA + `","platforms":{"linux/amd64":"` + gradleDigestA + `","linux/arm64":"` + gradleDigestB + `"},` +
		`"covered_paths":["/home/gradle","/home/gradle/.gradle","/tmp"],"volumes":["/home/gradle/.gradle"],"healthcheck":false,"checked":"2026-11-02"}`
}

func tableOf(rows ...string) []byte {
	return []byte(`{"schema":1,"runtimes":[` + strings.Join(rows, ",") + `]}`)
}

func TestParseRuntimesGradleRows(t *testing.T) {
	good := gradleRow("9.8.2", "21")
	specs, err := parseRuntimes(tableOf(good))
	if err != nil {
		t.Fatal(err)
	}
	if r := specs[0]; r.Kind != KindGradle || r.Version != "9.8.2" || r.JDK != "21" || r.Label() != "Gradle 9.8.2 on JDK 21" ||
		r.EndOfLife(mustDay("2100-01-01")) || r.ImageRef() != "gradle@"+gradleDigestA {
		t.Errorf("%+v", r)
	}
	if _, err := parseRuntimes(tableOf(gradleRow("8.14", "17"))); err != nil {
		t.Errorf("a two-number version: %v", err)
	}
	for name, bad := range map[string]string{
		"id without the jdk":     strings.Replace(good, `"id":"gradle9.8.2-jdk21"`, `"id":"gradle9.8.2"`, 1),
		"id with another jdk":    strings.Replace(good, `"id":"gradle9.8.2-jdk21"`, `"id":"gradle9.8.2-jdk17"`, 1),
		"series off the version": strings.Replace(good, `"series":"9"`, `"series":"8"`, 1),
		"no jdk":                 strings.Replace(good, `"jdk":"21",`, ``, 1),
		"jdk not a number":       strings.Replace(strings.Replace(good, `"jdk":"21"`, `"jdk":"lts"`, 1), `-jdk21"`, `-jdklts"`, 1),
		"an end of support":      strings.Replace(good, `"checked"`, `"eol":"2030-01-01","checked"`, 1),
		"tag is not the exact":   strings.Replace(good, `"tag":"9.8.2-jdk21"`, `"tag":"9-jdk21"`, 1),
		"volume not covered":     strings.Replace(good, `"volumes":["/home/gradle/.gradle"]`, `"volumes":["/home/gradle/.gradle","/data"]`, 1),
		"no volume record":       strings.Replace(good, `"volumes":["/home/gradle/.gradle"],`, ``, 1),
		"a jdk on a node row":    `{"schema":1,"runtimes":[{"id":"node20","kind":"node","series":"20","jdk":"21","support":"end_of_life","eol":"2026-04-30","checked":"2026-10-12"}]}`,
		"digest of the platform": strings.Replace(good, `"linux/arm64":"`+gradleDigestB+`"`, `"linux/arm64":"x"`, 1),
	} {
		if _, err := parseRuntimes(tableOf(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A row that declares no volume says so with volumes_empty, not with a list.
	empty := strings.Replace(good, `"volumes":["/home/gradle/.gradle"],`, `"volumes_empty":true,`, 1)
	if _, err := parseRuntimes(tableOf(empty)); err != nil {
		t.Errorf("a row without volumes: %v", err)
	}
	both := strings.Replace(good, `"volumes":`, `"volumes_empty":true,"volumes":`, 1)
	if _, err := parseRuntimes(tableOf(both)); err == nil {
		t.Error("volumes_empty with a list of volumes accepted")
	}
}

func mustDay(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func TestFindGradleRuntime(t *testing.T) {
	tested := func(row string) string {
		return strings.Replace(row, `"checked"`, `"tested":{"linux/amd64":"`+gradleDigestA+`"},"checked"`, 1)
	}
	old := runtimeSpecs
	t.Cleanup(func() { runtimeSpecs = old })
	var err error
	runtimeSpecs, err = parseRuntimes(tableOf(
		tested(gradleRow("9.8.2", "21")), tested(gradleRow("9.8.2", "17")),
		gradleRow("9.8.2", "25"), // not run by a test
		strings.Replace(gradleRow("8.14.6", "17"), `"checked"`, `"tested":{"linux/amd64":"`+gradleDigestB+`"},"checked"`, 1), // a digest that is not the pinned one
		tested(gradleRow("8.14", "17")),
		strings.Replace(gradleRow("8.14", "21"), `"checked"`, `"tested":{"linux/arm64":"`+gradleDigestB+`"},"checked"`, 1), // run on arm64 only
	))
	if err != nil {
		t.Fatal(err)
	}
	const amd64, arm64 = "linux/amd64", "linux/arm64"
	for _, c := range []struct {
		version  string
		jdk      int
		platform string
		want     string
		err      error
	}{
		{"9.8.2", 21, amd64, "gradle9.8.2-jdk21", nil},
		{"9.8.2", 17, amd64, "gradle9.8.2-jdk17", nil},
		{"8.14", 17, amd64, "gradle8.14-jdk17", nil},
		{"9.8.2", 25, amd64, "", ErrGradleToolchainUnsupported}, // the row exists, nobody ran it
		{"9.8.2", 11, amd64, "", ErrGradleToolchainUnsupported}, // no row on this JDK
		{"9.8.2", 0, amd64, "", ErrGradleToolchainUnsupported},
		{"8.14.6", 17, amd64, "", ErrGradleVersionUnsupported}, // tested digest is not the pinned one
		{"7.6", 17, amd64, "", ErrGradleVersionUnsupported},
		{"9.8", 21, amd64, "", ErrGradleVersionUnsupported}, // exactly the version, not a prefix
		{"", 21, amd64, "", ErrGradleVersionUnsupported},
		{"8.14", 21, amd64, "", ErrGradleToolchainUnsupported}, // run on arm64 only
		// A run on amd64 does not make the arm64 image of the row trusted.
		{"9.8.2", 21, arm64, "", ErrGradleVersionUnsupported},
		{"8.14", 17, arm64, "", ErrGradleToolchainUnsupported},
		{"8.14", 21, arm64, "gradle8.14-jdk21", nil},
		{"8.14.6", 17, arm64, "", ErrGradleVersionUnsupported}, // the amd64 record names the arm64 digest
		{"9.8.2", 21, "", "", ErrGradleVersionUnsupported},
	} {
		got, err := FindGradleRuntime(c.version, c.jdk, c.platform)
		if !errors.Is(err, c.err) || got.ID != c.want {
			t.Errorf("FindGradleRuntime(%q, %d, %q) = %q, %v; want %q, %v", c.version, c.jdk, c.platform, got.ID, err, c.want, c.err)
		}
	}
}

func TestGradleRowsOfTheTable(t *testing.T) {
	n := 0
	for _, r := range Runtimes() {
		if r.Kind != KindGradle {
			continue
		}
		n++
		// A row is found exactly when an integration test has run its image;
		// which rows those are is whatever the table update last recorded.
		for _, p := range []string{"linux/amd64", "linux/arm64"} {
			got, err := FindGradleRuntime(r.Version, atoi(r.JDK), p)
			if r.IsTestedOn(p) != (err == nil) || (err == nil && got.ID != r.ID) {
				t.Errorf("%s on %s: tested %v, found %q (%v)", r.ID, p, r.IsTestedOn(p), got.ID, err)
			}
		}
	}
	for _, id := range []string{"gradle9.8.2-jdk21", "gradle9.8.2-jdk17"} {
		if _, ok := LookupRuntime(id); !ok {
			t.Errorf("%s is not in the table", id)
		}
	}
	if n == 0 {
		t.Fatal("the table has no Gradle row")
	}
	if _, err := FindGradleRuntime("1.0", 21, "linux/amd64"); !errors.Is(err, ErrGradleVersionUnsupported) {
		t.Errorf("an unknown version: %v", err)
	}
}

func goodGradleJob() *Job {
	h := strings.Repeat("a", 64)
	return &Job{
		Protocol: ProtocolVersion, Manager: ManagerGradle, Runtime: testRuntime(ManagerGradle),
		Inputs: []Input{
			{Path: "gradle.lockfile", Size: 10, SHA256: h}, {Path: "build.gradle.kts", Size: 10, SHA256: h},
			{Path: "settings.gradle.kts", Size: 10, SHA256: h}, {Path: "gradle.properties", Size: 10, SHA256: h},
			{Path: "gradle/libs.versions.toml", Size: 10, SHA256: h}, {Path: "gradle/wrapper/gradle-wrapper.properties", Size: 10, SHA256: h},
			{Path: "settings-gradle.lockfile", Size: 10, SHA256: h}, {Path: "buildscript-gradle.lockfile", Size: 10, SHA256: h},
		},
		Steps:   []Step{{ID: "locks", Op: OpGradleUpdateLocks, Packages: []Package{{Name: "org.yaml:snakeyaml"}, {Name: "org.apache.commons:commons-text"}}}},
		Outputs: OutputNames(ManagerGradle), DeadlineSeconds: 300, StepTimeoutSeconds: 280,
	}
}

func TestGradleJobValidate(t *testing.T) {
	if err := goodGradleJob().Validate(); err != nil {
		t.Fatalf("good gradle job: %v", err)
	}
	if got := RequiredInputNames(ManagerGradle); !reflect.DeepEqual(got, []string{"gradle.lockfile"}) {
		t.Errorf("required inputs %v", got)
	}
	// Every input is a possible output, and the full set is within the limit
	// when the scripts are counted once.
	if got := OutputNames(ManagerGradle); !reflect.DeepEqual(got, InputNames(ManagerGradle)) {
		t.Errorf("outputs %v", got)
	}
	if len(goodGradleJob().Inputs) > MaxInputs {
		t.Errorf("the largest job has %d inputs, over %d", len(goodGradleJob().Inputs), MaxInputs)
	}
	h := strings.Repeat("a", 64)
	mutations := map[string]func(*Job){
		"no lockfile":       func(j *Job) { j.Inputs = j.Inputs[1:] },
		"both settings":     func(j *Job) { j.Inputs = append(j.Inputs, Input{Path: "settings.gradle", SHA256: h}) },
		"both builds":       func(j *Job) { j.Inputs = append(j.Inputs, Input{Path: "build.gradle", SHA256: h}) },
		"the wrapper jar":   func(j *Job) { j.Inputs = append(j.Inputs, Input{Path: "gradle/wrapper/gradle-wrapper.jar", SHA256: h}) },
		"a script":          func(j *Job) { j.Inputs = append(j.Inputs, Input{Path: "gradlew", SHA256: h}) },
		"an init script":    func(j *Job) { j.Inputs = append(j.Inputs, Input{Path: "init.gradle", SHA256: h}) },
		"a dotted path":     func(j *Job) { j.Inputs[1].Path = "gradle/../build.gradle.kts" },
		"absolute":          func(j *Job) { j.Inputs[1].Path = "/gradle.properties" },
		"a nested lockfile": func(j *Job) { j.Inputs[0].Path = "app/gradle.lockfile" },
		"a tool":            func(j *Job) { j.Tool = testTool(ManagerNpm, "11.19.0") },
		"node runtime":      func(j *Job) { j.Runtime = testRuntime(ManagerNpm) },
		"a version off":     func(j *Job) { j.Runtime.Version = "9.8.1" },
		"pip":               func(j *Job) { j.Runtime.Pip = "26.2.1" },
		"a foreign output":  func(j *Job) { j.Outputs = []string{"gradlew"} },
		"replacement":       func(j *Job) { j.Replacements = []Input{{Path: "gradle.lockfile", SHA256: h}} },
		"go op":             func(j *Job) { j.Steps[0] = Step{ID: "get", Op: OpGoGet, Packages: j.Steps[0].Packages} },
		"no targets":        func(j *Job) { j.Steps[0].Packages = nil },
		"a version":         func(j *Job) { j.Steps[0].Packages[0].Version = "2.7" },
		"a lowest version":  func(j *Job) { j.Steps[0].Packages[0].AtLeast = "2.7" },
		"a duplicate":       func(j *Job) { j.Steps[0].Packages[1].Name = j.Steps[0].Packages[0].Name },
	}
	for name, mut := range mutations {
		j := goodGradleJob()
		mut(j)
		if err := j.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGradleDependencyNames(t *testing.T) {
	for s, want := range map[string]bool{
		"org.yaml:snakeyaml": true, "org.apache.commons:commons-text": true, "io.netty:netty-codec-http2": true,
		"com.fasterxml.jackson.core:jackson-databind": true, "javax.servlet:javax.servlet-api": true, "a:b": true,
		"": false, "snakeyaml": false, "org.yaml:": false, ":snakeyaml": false, "-Porg:x": false, "org.yaml:-x": false,
		"org.yaml:snakeyaml:2.7": false, "org.yaml:snake yaml": false, "org.yaml:snake,yaml": false, "org.yaml:*": false,
		"org.yaml:snakeyaml\n": false, "org.yaml:snake$yaml": false, "../x:y": false, "org/yaml:snakeyaml": false,
		"org.yaml:" + strings.Repeat("a", 200): false,
	} {
		if got := ValidGradleDependency(s); got != want {
			t.Errorf("ValidGradleDependency(%q) = %v, want %v", s, got, want)
		}
	}
	for s, want := range map[string]bool{
		"9.8.2": true, "8.14": true, "8.0.2": true, "10.0": true, "9": false, "9.8.2.1": false, "9.8.2-rc-1": false, "v9.8.2": false, "09.1": false, "": false,
	} {
		if got := ValidGradleVersion(s); got != want {
			t.Errorf("ValidGradleVersion(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestArgvGradle(t *testing.T) {
	j := goodGradleJob()
	a, err := Argv(*j, j.Steps[0])
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gradle", "--no-daemon", "--no-build-cache", "-q", "-Porg.gradle.java.installations.auto-download=false",
		"dependencies", "--update-locks", "org.yaml:snakeyaml,org.apache.commons:commons-text"}
	if !slices.Equal(a, want) {
		t.Errorf("argv %q", a)
	}
	// The wrapper is never the program.
	for _, x := range a {
		if strings.Contains(x, "gradlew") {
			t.Errorf("argv names the wrapper: %q", a)
		}
	}
	// A runtime of another kind does not run it.
	j.Runtime = testRuntime(ManagerGo)
	if _, err := Argv(*j, j.Steps[0]); err == nil {
		t.Error("gradle in a Go runtime accepted")
	}
	k := goodGradleJob()
	k.Steps[0].Packages[0].Name = "-Dfoo:bar"
	if _, err := Argv(*k, k.Steps[0]); err == nil {
		t.Error("a name that starts with '-' accepted")
	}
}

func TestManagerKindOfGradle(t *testing.T) {
	if KindFor(ManagerGradle) != KindGradle || !ManagerGradle.Known() || !RunsFromImage(ManagerGradle) {
		t.Error("gradle is not a manager that runs from the image of its Gradle runtime")
	}
}
