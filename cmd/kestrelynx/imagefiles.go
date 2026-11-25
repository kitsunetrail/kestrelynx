package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"runtime/debug"
	"sync"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// version is the program version, set at build time with
// -ldflags "-X main.version=...". A "cannot complete" record of the image
// reader made by another version is not used, so a build that leaves it unset
// falls back to the revision the Go toolchain recorded.
var version = ""

// programVersion is the version the image reader tags its records with.
func programVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return s.Value
			}
		}
	}
	return "dev"
}

// cycleImageReader is the one image reader the cycle's scanners share. Every
// cycle starts with a new read budget (NewCycle), so what one cycle reads
// does not count against the next, and all scans of a cycle draw on the same
// one: those of the running images first, then those of the fix plan.
type cycleImageReader struct {
	base imagefs.Reader

	// pending holds the images whose last read was put off. They are scanned
	// first in the next cycle (see Priority).
	pending *pendingImages

	mu     sync.Mutex
	budget *imagefs.Budget
}

// NewCycle gives the reader a full budget.
func (c *cycleImageReader) NewCycle() {
	c.mu.Lock()
	c.budget = imagefs.NewBudget(c.base.Limits)
	c.mu.Unlock()
}

// Read implements scanner.ImageFileReader.
func (c *cycleImageReader) Read(ctx context.Context, t imagefs.Target) imagefs.Outcome {
	c.mu.Lock()
	r := c.base
	r.Budget = c.budget
	c.mu.Unlock()
	out := r.Read(ctx, t)
	if c.pending != nil {
		c.pending.set(pendingID(t), out.Kind == imagefs.Deferred)
	}
	return out
}

// pendingKey names one read in the pending set: the route and what it
// fetches (the config digest the Docker export is fetched by, or the registry
// manifest digest). A registry digest may be an index, so the platform is part
// of the key there. On Docker it is not: the fetch ID is the whole identity,
// and the platform the running list reports for a Docker image is empty.
func pendingKey(route imagefs.Route, id string, p inventory.Platform) string {
	if route == imagefs.RouteDocker {
		return string(route) + "|" + id
	}
	return string(route) + "|" + id + "|" + p.OS + "/" + p.Architecture + "/" + p.Variant
}

func pendingID(t imagefs.Target) string {
	if t.Route == imagefs.RouteDocker {
		return pendingKey(t.Route, t.FetchID, t.Platform)
	}
	return pendingKey(t.Route, t.ManifestDigest, t.Platform)
}

// Priority reports whether the running image was put off in an earlier read,
// so it gets the cycle's budget before the others. An image that is updated
// every cycle can otherwise use the whole budget before the images behind it
// in the list are reached, cycle after cycle.
func (c *cycleImageReader) Priority(img inventory.RunningImage) bool {
	if c == nil || c.pending == nil {
		return false
	}
	if id := img.ContentID(); id != "" && c.pending.has(pendingKey(imagefs.RouteDocker, id, img.Platform)) {
		return true
	}
	if d := img.Registry.Digest.String(); d != "" && c.pending.has(pendingKey(imagefs.RouteRegistry, d, img.Platform)) {
		return true
	}
	return false
}

// buildImageReader builds the reader of the JDK files of images, or nil when
// the config turns it off (or the Java check altogether). The layers'
// summaries are cached in an image-cache directory under the Java data. It
// reaches registries with the same logins as the scanner, and the Docker
// Engine only when Docker is the runtime.
func buildImageReader(cfg config.Config, log *slog.Logger) *cycleImageReader {
	j := cfg.Scan.JavaRuntime
	if !j.Enabled || !j.ReadImages {
		return nil
	}
	cacheDir := filepath.Join(filepath.Dir(cfg.State.Path), "java", "image-cache")
	cache, err := imagefs.OpenCache(cacheDir)
	if err != nil {
		// Turning the reader off would read as "the image has no JDK" for the
		// images that were read before, and resolve their findings. Without a
		// cache the reads still work, they are only repeated every cycle, and
		// the strike counts are kept in memory.
		log.Error("the Java image cache cannot be opened; images are read without a cache", "dir", cacheDir, "err", err)
		cache = imagefs.NewMemoryCache()
	}
	// Config validation has rejected a host listed twice, the only way the
	// store can fail to build.
	auth, _ := cfg.RegistryCredentials()
	limits := imagefs.Limits{RegistryBytesPerCycle: j.RegistryBytesPerCycle, DockerBytesPerCycle: j.DockerBytesPerCycle}
	c := &cycleImageReader{base: imagefs.Reader{
		Registry: registry.New(registry.Options{Auth: auth}),
		Cache:    cache,
		Limits:   limits,
		Version:  programVersion(),
		Log:      log,
	}, pending: loadPendingImages(filepath.Join(cacheDir, pendingFile), log)}
	if !cfg.Kubernetes.Enabled {
		dc := docker.New(dockerSocket)
		dc.Log = log
		c.base.Docker = dc
	}
	c.NewCycle()
	return c
}

// withImageFiles returns tr reading image layers through r; a nil r leaves tr
// as it is.
func withImageFiles(tr scanner.Trivy, r *cycleImageReader) scanner.Trivy {
	if r != nil {
		tr.ImageFiles = r
	}
	return tr
}
