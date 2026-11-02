package main

import (
	"slices"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func TestDockerCoverPathsAreTheOnesTheContainerDoesNotCoverForEveryRuntime(t *testing.T) {
	gradle, ok := worker.LookupRuntime("gradle9.8.2-jdk21")
	if !ok {
		t.Fatal("no Gradle runtime")
	}
	want := []string{"/home/gradle", "/home/gradle/.gradle", "/var/lib/pebble/default"}
	if got := dockerCoverPaths(gradle); !slices.Equal(got, want) {
		t.Errorf("gradle: %v, want %v", got, want)
	}
	for _, id := range remediation.DefaultRuntimeIDs() {
		spec, _ := worker.LookupRuntime(id)
		if got := dockerCoverPaths(spec); len(got) != 0 {
			t.Errorf("%s: %v", id, got)
		}
	}
}

func TestGradleImagesAreNamedLikeTheOthers(t *testing.T) {
	spec, ok := worker.LookupRuntime("gradle9.8.2-jdk17")
	if !ok {
		t.Fatal("no Gradle runtime")
	}
	if got := workImageRef(spec, ""); got != "gradle@"+spec.IndexDigest {
		t.Errorf("docker: %s", got)
	}
	if got := kubernetesWorkImageRef(spec, ""); got != "docker.io/library/gradle@"+spec.IndexDigest {
		t.Errorf("kubernetes: %s", got)
	}
	if got := kubernetesWorkImageRef(spec, "registry.example.com/dockerhub"); got != "registry.example.com/dockerhub/library/gradle@"+spec.IndexDigest {
		t.Errorf("kubernetes mirror: %s", got)
	}
}

// newDockerWorkClient makes the client of a Gradle row without a daemon being
// there: the image is pinned, the JDK is expected in the environment and the
// declared volume is covered.
func TestNewDockerWorkClientForAGradleRow(t *testing.T) {
	spec, _ := worker.LookupRuntime("gradle9.8.2-jdk21")
	cfg := workTestConfig(t)
	c, err := newDockerWorkClient(cfg, spec, "linux/amd64", "0123456789abcdef0123456789abcdef", quietLog())
	if err != nil || c == nil {
		t.Fatalf("%v %v", c, err)
	}
}

func TestOnDemandRuntimeTakesOnlyGradleRowsTestedOnThePlatform(t *testing.T) {
	var tested, untested worker.RuntimeSpec
	for _, r := range worker.Runtimes() {
		if r.Kind != worker.KindGradle || !r.HasImage() {
			continue
		}
		if r.IsTestedOn("linux/amd64") && tested.ID == "" {
			tested = r
		}
		if !r.IsTestedOn("linux/amd64") && untested.ID == "" {
			untested = r
		}
	}
	if tested.ID == "" || untested.ID == "" {
		t.Fatal("the table needs a Gradle row tested on linux/amd64 and one that is not")
	}
	if got, err := onDemandRuntime(tested.ID, "linux/amd64"); err != nil || got.ID != tested.ID {
		t.Errorf("%s on linux/amd64: %q, %v", tested.ID, got.ID, err)
	}
	if _, err := onDemandRuntime(untested.ID, "linux/amd64"); err == nil {
		t.Errorf("%s was taken although no test has run it on linux/amd64", untested.ID)
	}
	if !tested.IsTestedOn("linux/arm64") {
		if _, err := onDemandRuntime(tested.ID, "linux/arm64"); err == nil {
			t.Errorf("%s was taken on linux/arm64 from a run on linux/amd64", tested.ID)
		}
	}
	for _, id := range append(remediation.DefaultRuntimeIDs(), "gradle0-jdk17") {
		if _, err := onDemandRuntime(id, "linux/amd64"); err == nil {
			t.Errorf("%s was taken as an on-demand runtime", id)
		}
	}
}
