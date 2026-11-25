package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"runtime/debug"
	"sync"
	"time"

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
	// registryRead and dockerRead are the bytes the cycle has read so far.
	registryRead, dockerRead int64
}

// NewCycle gives the reader a full budget.
func (c *cycleImageReader) NewCycle() {
	c.mu.Lock()
	c.budget = imagefs.NewBudget(c.base.Limits)
	c.registryRead, c.dockerRead = 0, 0
	c.mu.Unlock()
}

// Read implements scanner.ImageFileReader.
func (c *cycleImageReader) Read(ctx context.Context, t imagefs.Target) imagefs.Outcome {
	c.mu.Lock()
	r := c.base
	r.Budget = c.budget
	c.mu.Unlock()
	start := time.Now()
	out := r.Read(ctx, t)
	c.logRead(t, out, time.Since(start))
	if c.pending != nil {
		c.pending.set(pendingID(t), out.Kind == imagefs.Deferred)
	}
	return out
}

// logRead logs a read that read layers or part of an export, with what it
// read, how long it took and what the cycle has read so far, so the per-cycle
// limits can be set from what the images really need. A read answered from
// the cache, or one that read nothing (an export the Docker Engine refused),
// is not logged.
func (c *cycleImageReader) logRead(t imagefs.Target, out imagefs.Outcome, took time.Duration) {
	st := out.Stats
	if st.LayersRead == 0 && st.RegistryBytes == 0 && st.DockerBytes == 0 {
		return
	}
	c.mu.Lock()
	c.registryRead += st.RegistryBytes
	c.dockerRead += st.DockerBytes
	regCycle, dockerCycle := c.registryRead, c.dockerRead
	c.mu.Unlock()
	image := t.Repository + "@" + t.ManifestDigest
	if t.Route == imagefs.RouteDocker {
		image = t.FetchID
	}
	attrs := []any{"route", string(t.Route), "image", image, "outcome", out.Kind.String(),
		"layers_read", st.LayersRead, "layers_cached", st.LayersCached, "duration", took.Round(time.Millisecond)}
	if out.Reason != "" {
		attrs = append(attrs, "reason", string(out.Reason))
	}
	if t.Route == imagefs.RouteDocker {
		attrs = append(attrs, "docker_bytes", st.DockerBytes, "docker_bytes_cycle", dockerCycle)
	} else {
		attrs = append(attrs, "registry_bytes", st.RegistryBytes, "registry_bytes_cycle", regCycle)
	}
	log := c.base.Log
	if log == nil {
		log = slog.Default()
	}
	log.Info("Java runtime: image layers read", attrs...)
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
	log.Info("Java runtime: image reading enabled", "registry_bytes_per_cycle", limits.RegistryBytesPerCycle, "docker_bytes_per_cycle", limits.DockerBytesPerCycle)
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
