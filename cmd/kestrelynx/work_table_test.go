package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/runtimetable"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

const testInstance = "0123456789abcdef0123456789abcdef"

// withRow puts a copy of the row from with another id, series and version into
// the table in use, until the test ends.
func withRow(t *testing.T, from, id, series, version string) {
	t.Helper()
	row, ok := worker.LookupRuntime(from)
	if !ok {
		t.Fatalf("no row %s", from)
	}
	row.ID, row.Series, row.Version = id, series, version
	t.Cleanup(worker.OverrideRuntimesForTest(append(worker.Runtimes(), row)))
}

func TestDockerWorkFollowsTheRuntimeTable(t *testing.T) {
	cfg := workTestConfig(t)
	w := newDockerWork(cfg, "linux/amd64", testInstance, quietLog())
	if err := w.sync(); err != nil {
		t.Fatal(err)
	}
	first := w.set
	if slices.Contains(first.Keys(), "node28") {
		t.Fatal("node28 is already a runtime")
	}
	// The same table: the clients stay.
	if err := w.sync(); err != nil || w.set != first {
		t.Fatalf("the clients were made again without a new table (%v)", err)
	}

	// A new table with a series the build did not come with.
	withRow(t, "node24", "node28", "28", "28.0.1")
	if w.set != first {
		t.Fatal("the clients changed before the cycle started")
	}
	w.beforeCycle(context.Background())
	if w.set == first || !slices.Contains(w.set.Keys(), "node28") || !slices.Contains(w.set.Keys(), "node24") {
		t.Fatalf("after the new table the runtimes are %v", w.set.Keys())
	}
}

func TestDockerWorkReportsATableItCannotServe(t *testing.T) {
	cfg := workTestConfig(t)
	// A mirror that cannot be part of an image reference: no client can be made.
	cfg.Remediation.Worker.Registry = "bad host"
	w := newDockerWork(cfg, "linux/amd64", testInstance, quietLog())
	if err := w.sync(); err == nil {
		t.Fatal("clients were made for a reference that is not one")
	}
	if _, err := w.RunJob(context.Background(), workexec.JobSpec{Runtime: "node24"}); err == nil {
		t.Fatal("a job ran without clients")
	}
}

func TestWorkImagesInUse(t *testing.T) {
	plain := workImagesInUse("")
	mirrored := workImagesInUse("registry.example.com:5000/hub")
	withImage := 0
	for _, r := range worker.Runtimes() {
		if r.HasImage() {
			withImage++
		}
	}
	if len(plain) != withImage || len(mirrored) != withImage || withImage == 0 {
		t.Fatalf("%d and %d references for %d rows with an image", len(plain), len(mirrored), withImage)
	}
	node, _ := worker.LookupRuntime("node24")
	if !slices.Contains(plain, "node@"+node.IndexDigest) {
		t.Errorf("the image of node24 is not kept: %v", plain[:3])
	}
	if !slices.Contains(mirrored, "registry.example.com:5000/hub/library/node@"+node.IndexDigest) {
		t.Errorf("the mirrored image of node24 is not kept")
	}
	for _, ref := range plain {
		if !strings.Contains(ref, "@sha256:") {
			t.Errorf("%q is not pinned by digest", ref)
		}
	}
}

func TestKubernetesImagesFollowTheRuntimeTable(t *testing.T) {
	imageFor := kubernetesImageFor("", "linux/amd64")
	if _, ok := imageFor("node28"); ok {
		t.Fatal("node28 is already a runtime")
	}
	node, _ := worker.LookupRuntime("node24")
	if img, ok := imageFor("node24"); !ok || img != "docker.io/library/node@"+node.IndexDigest {
		t.Fatalf("node24: %q, %v", img, ok)
	}
	// The Rust row, whatever its release, is looked up like any other.
	rustRows := 0
	for _, r := range worker.Runtimes() {
		if r.Kind != worker.KindRust || !r.HasImage() {
			continue
		}
		rustRows++
		if img, ok := imageFor(r.ID); !ok || img != "docker.io/library/rust@"+r.IndexDigest {
			t.Errorf("%s: %q, %v", r.ID, img, ok)
		}
	}
	if rustRows != 1 {
		t.Errorf("the table has %d Rust rows, want 1", rustRows)
	}
	// A Gradle row no test has run is in the table and has no image to run.
	untested := ""
	for _, r := range worker.Runtimes() {
		if r.Kind == worker.KindGradle && r.HasImage() && !r.IsTestedOn("linux/amd64") {
			untested = r.ID
			break
		}
	}
	if untested == "" {
		t.Fatal("the table has no Gradle row without a test")
	}
	if _, ok := imageFor(untested); ok {
		t.Errorf("%s is run without a test", untested)
	}
	if _, ok := imageFor("node20"); ok {
		t.Error("a runtime without an image is run")
	}

	probes := kubernetesProbeImages(imageFor)
	repos := map[string]bool{}
	for _, img := range probes {
		repo, _, _ := strings.Cut(img, "@")
		if repos[repo] {
			t.Errorf("two probe images of %s", repo)
		}
		repos[repo] = true
	}
	for _, want := range []string{"docker.io/library/node", "docker.io/library/python", "docker.io/library/golang", "docker.io/library/gradle", "docker.io/library/rust"} {
		if !repos[want] {
			t.Errorf("no probe image of %s in %v", want, probes)
		}
	}

	// The lookup made at the start serves a table that came later.
	withRow(t, "node24", "node28", "28", "28.0.1")
	if img, ok := imageFor("node28"); !ok || img != "docker.io/library/node@"+node.IndexDigest {
		t.Fatalf("node28 after the new table: %q, %v", img, ok)
	}

	// A table with Gradle alone still has an image to check the admission
	// policy with.
	var gradle []worker.RuntimeSpec
	for _, r := range worker.Runtimes() {
		if r.Kind == worker.KindGradle {
			gradle = append(gradle, r)
		}
	}
	t.Cleanup(worker.OverrideRuntimesForTest(gradle))
	if probes := kubernetesProbeImages(imageFor); len(probes) != 1 || !strings.HasPrefix(probes[0], "docker.io/library/gradle@") {
		t.Errorf("probe images of a Gradle-only table: %v", probes)
	}
}

// A table the clients cannot be made from stops the updates until a table
// they can be made from replaces it, not for the life of the process.
func TestDockerWorkRecoversWithALaterTable(t *testing.T) {
	cfg := workTestConfig(t)
	withProgramDir(t, &cfg, "program")
	withToolSupply(t, okToolSupply)

	// A row whose image wants one directory covered twice: no container can
	// be made for it. The checks of a fetched table refuse such a row; the
	// test puts it in directly.
	rows := worker.Runtimes()
	for i := range rows {
		if rows[i].ID == "node24" {
			rows[i].CoveredPaths = append(rows[i].CoveredPaths, "/home/gradle", "/home/gradle")
		}
	}
	restore := worker.OverrideRuntimesForTest(rows)
	t.Cleanup(restore)

	lc := buildLanguageConfig(cfg, quietLog())
	if lc.Unavailable != nil || lc.NewUpdater == nil || lc.BeforeCycle == nil {
		t.Fatalf("the stage is turned off for good: %+v", lc)
	}
	in := runner.LanguageUpdateInput{GitHub: nopGitHub{}, Prepared: scanner.ScanConditions{}}
	if _, err := lc.NewUpdater(context.Background(), in); err == nil {
		t.Fatal("the stage runs on a table its clients cannot be made from")
	}

	restore() // a later table without the problem
	lc.BeforeCycle(context.Background())
	if u, err := lc.NewUpdater(context.Background(), in); err != nil || u == nil {
		t.Fatalf("the stage does not recover with the later table: %v", err)
	}
}

func TestRuntimeTableIsFetchedWithoutCredentialsFromItsOwnRepository(t *testing.T) {
	cfg := workTestConfig(t)
	cfg.Registries = []config.RegistryLogin{{Host: "ghcr.io", Username: "u", Password: "p"}, {Host: "registry.example.com", Username: "u", Password: "p"}}
	for _, repo := range []string{"", runtimetable.DefaultRepository} {
		cfg.Remediation.Worker.RuntimeTable.Repository = repo
		if runtimeTableRegistryOptions(cfg).Auth != nil {
			t.Errorf("repository %q: the published table is fetched with a login", repo)
		}
	}
	cfg.Remediation.Worker.RuntimeTable.Repository = "registry.example.com/mirror/kestrelynx-runtimes"
	if runtimeTableRegistryOptions(cfg).Auth == nil {
		t.Error("a mirror is asked without the registry logins")
	}
}
