package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runtimetable"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

// runtimeTableDirName is the directory under remediation.storage_dir that
// holds the runtime table that was fetched and the record of the work images
// this installation pulled.
const runtimeTableDirName = "runtimes"

// newRuntimeTables chooses the runtime table the process starts with and
// returns the manager that brings it up to date at the start of each cycle.
// The published table is fetched without credentials from the repository the
// project publishes it in; a repository the configuration names instead (a
// mirror) is reached with the registry logins of the configuration.
func newRuntimeTables(cfg config.Config, log *slog.Logger) *runtimetable.Manager {
	rt := cfg.Remediation.Worker.RuntimeTable
	m := runtimetable.New(runtimetable.Options{
		Update:     rt.Update,
		Registry:   registry.New(runtimeTableRegistryOptions(cfg)),
		Repository: rt.Repository,
		Dir:        filepath.Join(cfg.Remediation.StorageDir, runtimeTableDirName),
		Log:        log,
	})
	m.Load()
	return m
}

// runtimeTableRegistryOptions are the options of the client the table is
// fetched with. The repository the project publishes it in is public and is
// asked without credentials, also when the configuration has a login for its
// host; only another repository gets the registry logins.
func runtimeTableRegistryOptions(cfg config.Config) registry.Options {
	opts := registry.Options{}
	if repo := cfg.Remediation.Worker.RuntimeTable.Repository; repo != "" && repo != runtimetable.DefaultRepository {
		// Config validation has rejected a host listed twice, the only way
		// the store can fail to build.
		opts.Auth, _ = cfg.RegistryCredentials()
	}
	return opts
}

// dockerWork runs jobs in the work containers of the runtime table in use. The
// clients are made from the table (each holds the pinned image of one row), so
// they are made again when the table has been replaced: at the start of a
// cycle, never during one.
type dockerWork struct {
	cfg      config.Config
	platform string
	instance string
	log      *slog.Logger
	// pruner removes the work images this installation pulled and the table
	// no longer names; nil when its record cannot be kept.
	pruner *docker.ImagePruner

	mu         sync.Mutex
	set        *docker.WorkSet
	err        error
	generation uint64
	made       bool
}

// workImageKeepTimeout bounds the removal of old work images at the start of
// a cycle.
const workImageKeepTimeout = 2 * time.Minute

func newDockerWork(cfg config.Config, platform, instance string, log *slog.Logger) *dockerWork {
	w := &dockerWork{cfg: cfg, platform: platform, instance: instance, log: log}
	record := filepath.Join(cfg.Remediation.StorageDir, runtimeTableDirName, "pulled-images.json")
	p, err := docker.NewImagePruner(dockerSocket, record, log)
	if err != nil {
		log.Warn("work images that are no longer used will not be removed", "err", err)
	} else {
		w.pruner = p
	}
	return w
}

// sync makes the clients from the table in use when they were made from
// another one, or not yet. It returns the problem that keeps them from being
// made, which stands until the table changes again.
func (w *dockerWork) sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	gen := worker.RuntimeTableGeneration()
	if w.made && gen == w.generation {
		return w.err
	}
	w.set, w.err = w.build()
	w.generation, w.made = gen, true
	if w.err != nil {
		w.log.Warn("the work container clients could not be set up from the runtime table", "err", w.err)
	}
	return w.err
}

// build makes a client for every runtime of the table in use that is not a
// Gradle one. A Gradle runtime is one row for each pair of a version of Gradle
// and a JDK; its client is made, and its image pulled, when the first job for
// it arrives.
func (w *dockerWork) build() (*docker.WorkSet, error) {
	set := docker.NewWorkSet()
	for _, rid := range remediation.DefaultRuntimeIDs() {
		spec, ok := workRuntime(rid, w.platform)
		if !ok {
			return nil, errors.New("the runtime " + rid + " is not in the table")
		}
		wc, err := newDockerWorkClient(w.cfg, spec, w.platform, w.instance, w.pruner, w.log)
		if err == nil {
			err = set.Add(rid, wc)
		}
		if err != nil {
			return nil, errors.New("the work container client for " + rid + " could not be set up: " + err.Error())
		}
	}
	set.SetFactory(func(key string) (*docker.WorkClient, error) {
		spec, err := onDemandRuntime(key, w.platform)
		if err != nil {
			return nil, err
		}
		return newDockerWorkClient(w.cfg, spec, w.platform, w.instance, w.pruner, w.log)
	})
	return set, nil
}

// RunJob runs the job on the client of its runtime.
func (w *dockerWork) RunJob(ctx context.Context, spec workexec.JobSpec) (workexec.JobResult, error) {
	w.mu.Lock()
	set, err := w.set, w.err
	w.mu.Unlock()
	if set == nil {
		if err == nil {
			err = errors.New("the work container clients are not set up")
		}
		return workexec.JobResult{}, err
	}
	return set.RunJob(ctx, spec)
}

// cleanupStale removes the containers an earlier run of this installation
// left. They are found through any one client: what marks them does not
// involve the image.
func (w *dockerWork) cleanupStale(ctx context.Context) (int, error) {
	w.mu.Lock()
	set := w.set
	w.mu.Unlock()
	if set != nil && len(set.Keys()) > 0 {
		return set.CleanupStale(ctx)
	}
	// A table that has only Gradle runtimes has no client yet.
	for _, spec := range worker.Runtimes() {
		if spec, ok := workRuntime(spec.ID, w.platform); ok {
			wc, err := newDockerWorkClient(w.cfg, spec, w.platform, w.instance, nil, w.log)
			if err != nil {
				return 0, err
			}
			return wc.CleanupStale(ctx)
		}
	}
	return 0, nil
}

// beforeCycle brings the clients up to date with the table in use and removes
// the work images this installation pulled that the table no longer names. No
// job runs while it does: it is called at the start of a cycle.
func (w *dockerWork) beforeCycle(ctx context.Context) {
	_ = w.sync() // a problem is logged by sync and reported when the stage runs
	if w.pruner == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, workImageKeepTimeout)
	defer cancel()
	if res := w.pruner.Prune(ctx, workImagesInUse(w.cfg.Remediation.Worker.Registry)); res.Removed > 0 || res.Released > 0 || res.Unfinished > 0 {
		w.log.Info("work images the runtime table no longer names", "removed", res.Removed, "still_recorded", res.Kept,
			"left_to_their_tags", res.Released, "pulls_never_finished", res.Unfinished)
	}
}

// workImagesInUse are the references of the work images the table in use
// names, as the work clients pull them (through the mirror when one is
// configured).
func workImagesInUse(mirror string) []string {
	var out []string
	for _, spec := range worker.Runtimes() {
		if spec.HasImage() {
			out = append(out, workImageRef(spec, mirror))
		}
	}
	return out
}
