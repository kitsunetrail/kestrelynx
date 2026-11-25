package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func imageReaderConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Config{}
	cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	cfg.Scan.JavaRuntime = config.JavaRuntimeConfig{
		Enabled: true, ReadImages: true, RegistryBytesPerCycle: 123 << 20, DockerBytesPerCycle: 456 << 20,
	}
	return cfg
}

func TestBuildImageReader_OffMeansNil(t *testing.T) {
	cfg := imageReaderConfig(t)
	cfg.Scan.JavaRuntime.ReadImages = false
	if buildImageReader(cfg, slog.Default()) != nil {
		t.Error("read_images: false still builds a reader")
	}
	cfg = imageReaderConfig(t)
	cfg.Scan.JavaRuntime.Enabled = false
	if buildImageReader(cfg, slog.Default()) != nil {
		t.Error("a disabled Java check still builds a reader")
	}
	// A nil reader leaves the scanner as it is.
	if tr := withImageFiles(scanner.Trivy{}, nil); tr.ImageFiles != nil {
		t.Error("withImageFiles(nil) set a reader")
	}
}

func TestBuildImageReader_WiringAndCycleBudget(t *testing.T) {
	cfg := imageReaderConfig(t)
	r := buildImageReader(cfg, slog.Default())
	if r == nil {
		t.Fatal("no reader")
	}
	if want := filepath.Join(filepath.Dir(cfg.State.Path), "java", "image-cache"); func() bool { _, err := os.Stat(want); return err != nil }() {
		t.Errorf("no cache directory at %s", want)
	}
	if r.base.Docker == nil || r.base.Registry == nil || r.base.Cache == nil || r.base.Version == "" {
		t.Errorf("reader = %+v", r.base)
	}
	if got := r.base.Limits; got.RegistryBytesPerCycle != 123<<20 || got.DockerBytesPerCycle != 456<<20 {
		t.Errorf("limits = %+v", got)
	}
	first := r.budget
	if first == nil || first.RegistryLeft() != 123<<20 || first.DockerLeft() != 456<<20 {
		t.Fatalf("budget = %+v", first)
	}
	r.NewCycle()
	if r.budget == first {
		t.Error("a new cycle kept the old budget")
	}

	// Kubernetes has no Docker Engine to export from.
	cfg.Kubernetes.Enabled = true
	if k := buildImageReader(cfg, slog.Default()); k == nil || k.base.Docker != nil {
		t.Errorf("kubernetes reader = %+v", k)
	}
	if tr := withImageFiles(scanner.Trivy{}, r); tr.ImageFiles == nil {
		t.Error("withImageFiles did not set the reader")
	}
}

// A cache that cannot be opened does not turn the reader off: that would read
// as "no JDK" for images read before and resolve their findings.
func TestBuildImageReader_UnopenableCacheStillReads(t *testing.T) {
	cfg := imageReaderConfig(t)
	cacheDir := filepath.Join(filepath.Dir(cfg.State.Path), "java", "image-cache")
	if err := os.MkdirAll(filepath.Dir(cacheDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacheDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	r := buildImageReader(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if r == nil {
		t.Fatal("an unopenable cache turned the reader off")
	}
	if r.base.Cache == nil || r.base.Registry == nil {
		t.Errorf("reader = %+v", r.base)
	}
	if strings.Count(logs.String(), "level=ERROR") != 1 {
		t.Errorf("want one error line, log:\n%s", logs.String())
	}
	// An image that cannot be reached is put off, not "without a JDK".
	tg := imagefs.RegistryTarget("127.0.0.1:1/app", "sha256:"+strings.Repeat("a", 64),
		inventory.Platform{OS: "linux", Architecture: "amd64"}, []string{"sha256:" + strings.Repeat("b", 64)})
	out := r.Read(context.Background(), tg)
	if out.Kind != imagefs.Deferred {
		t.Errorf("outcome = %v %q, want a deferred read", out.Kind, out.Reason)
	}
}

func TestImageReader_PutOffImagesComeFirstAndSurviveARestart(t *testing.T) {
	cfg := imageReaderConfig(t)
	r := buildImageReader(cfg, slog.Default())
	a := "sha256:" + strings.Repeat("a", 64)
	b := "sha256:" + strings.Repeat("b", 64)
	plat := inventory.Platform{OS: "linux", Architecture: "amd64"}
	arm := inventory.Platform{OS: "linux", Architecture: "arm64"}
	regDigest, _ := inventory.ParseDigest(inventory.DigestRegistry, a)
	img := inventory.RunningImage{Ref: "app:1", Platform: plat, Registry: inventory.RegistryRef{Repository: "127.0.0.1:1/app", Digest: regDigest}}
	imgArm := img
	imgArm.Platform = arm
	if r.Priority(img) {
		t.Fatal("a new image has priority")
	}
	// Unreachable: put off.
	deferred := imagefs.RegistryTarget("127.0.0.1:1/app", a, plat, []string{b})
	if out := r.Read(context.Background(), deferred); out.Kind != imagefs.Deferred {
		t.Fatalf("outcome = %v", out.Kind)
	}
	if !r.Priority(img) {
		t.Error("a put-off image has no priority")
	}
	// The same index read for another platform is another entry.
	if r.Priority(imgArm) {
		t.Error("the other platform of the same digest has priority")
	}
	armTarget := imagefs.RegistryTarget("127.0.0.1:1/app", a, arm, nil) // invalid: permanent
	if out := r.Read(context.Background(), armTarget); out.Kind != imagefs.Permanent {
		t.Fatalf("outcome = %v", out.Kind)
	}
	if !r.Priority(img) {
		t.Error("finishing the other platform removed this one's entry")
	}
	// The set is in a file: another reader (a restart) knows it.
	if r2 := buildImageReader(cfg, slog.Default()); !r2.Priority(img) {
		t.Error("the put-off set did not survive a restart")
	}
	// An end other than Deferred removes it: an invalid target is permanent.
	bad := imagefs.RegistryTarget("127.0.0.1:1/app", a, plat, nil)
	if out := r.Read(context.Background(), bad); out.Kind != imagefs.Permanent {
		t.Fatalf("outcome = %v", out.Kind)
	}
	if r.Priority(img) {
		t.Error("a finished image keeps its priority")
	}
	if buildImageReader(cfg, slog.Default()).Priority(img) {
		t.Error("the removal was not stored")
	}
	var nilReader *cycleImageReader
	if nilReader.Priority(img) {
		t.Error("a nil reader gives priority")
	}
}

// A Docker image is put off with the platform Trivy reported and found again
// from the running list, whose platform is empty for the Docker adapter.
func TestImageReader_DockerPriorityIgnoresThePlatform(t *testing.T) {
	cfg := imageReaderConfig(t)
	r := buildImageReader(cfg, slog.Default())
	id := "sha256:" + strings.Repeat("c", 64)
	cfgDigest, _ := inventory.ParseDigest(inventory.DigestConfig, id)
	running := inventory.RunningImage{Ref: "app:1", Config: cfgDigest} // no platform
	tg := imagefs.DockerTarget(id, inventory.Platform{OS: "linux", Architecture: "amd64"}, []string{"sha256:" + strings.Repeat("d", 64)})
	r.pending.set(pendingID(tg), true)
	if !r.Priority(running) {
		t.Error("the put-off Docker image has no priority")
	}
	if !buildImageReader(cfg, slog.Default()).Priority(running) {
		t.Error("the Docker entry did not survive a restart")
	}
}

// A read that fetched something is logged with its bytes, its time and the
// cycle's total so far; a cached read is not, and a new cycle starts the
// totals again.
func TestImageReader_LogsWhatReadsCost(t *testing.T) {
	cfg := imageReaderConfig(t)
	var logs strings.Builder
	r := buildImageReader(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "registry_bytes_per_cycle=128974848 docker_bytes_per_cycle=478150656") {
		t.Errorf("no line with the limits, log:\n%s", logs.String())
	}
	plat := inventory.Platform{OS: "linux", Architecture: "amd64"}
	reg := imagefs.RegistryTarget("example.test/app", "sha256:"+strings.Repeat("a", 64), plat, nil)
	dock := imagefs.DockerTarget("sha256:"+strings.Repeat("c", 64), plat, nil)
	lines := func() []string {
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
			if strings.Contains(l, "image layers read") {
				out = append(out, l)
			}
		}
		return out
	}

	r.logRead(reg, imagefs.Outcome{Kind: imagefs.Complete, Stats: imagefs.Stats{ImageCached: true}}, time.Second)
	r.logRead(reg, imagefs.Outcome{Kind: imagefs.Complete, Stats: imagefs.Stats{LayersCached: 3}}, time.Second)
	r.logRead(dock, imagefs.Outcome{Kind: imagefs.Deferred, Stats: imagefs.Stats{ExportCalled: true}}, time.Second)
	if got := lines(); len(got) != 0 {
		t.Fatalf("a read that read nothing was logged: %q", got)
	}
	r.logRead(reg, imagefs.Outcome{Kind: imagefs.Complete, Stats: imagefs.Stats{LayersRead: 2, LayersCached: 1, RegistryBytes: 100}}, 1500*time.Millisecond)
	r.logRead(reg, imagefs.Outcome{Kind: imagefs.Deferred, Reason: imagefs.ReasonBudget, Stats: imagefs.Stats{LayersRead: 1, RegistryBytes: 200}}, time.Second)
	r.logRead(dock, imagefs.Outcome{Kind: imagefs.Complete, Stats: imagefs.Stats{ExportCalled: true, DockerBytes: 700}}, time.Second)
	got := lines()
	if len(got) != 3 {
		t.Fatalf("want 3 lines, got %q", got)
	}
	for i, want := range [][]string{
		{"route=registry", "image=example.test/app@sha256:aaaa", "outcome=" + imagefs.Complete.String() + " ", "layers_read=2", "layers_cached=1", "duration=1.5s", "registry_bytes=100 ", "registry_bytes_cycle=100"},
		{"outcome=" + imagefs.Deferred.String() + " ", "reason=" + string(imagefs.ReasonBudget), "registry_bytes=200 ", "registry_bytes_cycle=300"},
		{"route=docker", "image=sha256:cccc", "docker_bytes=700 ", "docker_bytes_cycle=700"},
	} {
		for _, w := range want {
			if !strings.Contains(got[i]+" ", w) {
				t.Errorf("line %d has no %q: %s", i, w, got[i])
			}
		}
	}
	if strings.Contains(got[0], "reason=") || strings.Contains(got[0], "docker_bytes") || strings.Contains(got[2], "registry_bytes") {
		t.Errorf("lines carry fields of another route or an empty reason: %q", got)
	}

	r.NewCycle()
	r.logRead(reg, imagefs.Outcome{Kind: imagefs.Complete, Stats: imagefs.Stats{LayersRead: 1, RegistryBytes: 50}}, time.Second)
	if last := lines()[3]; !strings.Contains(last, "registry_bytes_cycle=50") {
		t.Errorf("a new cycle did not start the total again: %s", last)
	}
}
