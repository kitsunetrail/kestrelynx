package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// targetRegistry holds the pre-registered targets of a run and drives them
// through registration, start detection and acceptance.
//
// It exists because the start-time enumeration cannot see a container that
// does not exist yet. A case whose workload must not begin until the
// observation is in place names its target first; the registry watches for
// it, completes the per-container reads it needs, and only then reports the
// target as accepted — which is the condition a case runner waits on before
// telling the container to start doing anything.
type targetRegistry struct {
	mu      sync.Mutex
	order   []string
	entries map[string]*TargetRegistration

	readyPath string
	runKey    RunKey
	runID     string
	startedAt time.Time
	sync      string
	attach    []string
	errors    []string
}

func newTargetRegistry(wanted []string, readyPath string, runKey RunKey, syncMode, runID string) *targetRegistry {
	r := &targetRegistry{
		entries: map[string]*TargetRegistration{}, readyPath: readyPath,
		runKey: runKey, runID: runID, startedAt: time.Now().UTC(), sync: syncMode,
	}
	now := time.Now().UTC()
	for _, w := range wanted {
		if _, seen := r.entries[w]; seen {
			continue
		}
		r.order = append(r.order, w)
		r.entries[w] = &TargetRegistration{Wanted: w, State: TargetRegistered, RegisteredAt: now}
	}
	return r
}

func (r *targetRegistry) empty() bool { return r == nil || len(r.order) == 0 }

// snapshot returns the registrations in registration order.
func (r *targetRegistry) snapshot() []TargetRegistration {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TargetRegistration, 0, len(r.order))
	for _, w := range r.order {
		out = append(out, *r.entries[w])
	}
	return out
}

func (r *targetRegistry) ready() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.order {
		if r.entries[w].State != TargetAccepted {
			return false
		}
	}
	return true
}

// matches reports which registered name, if any, a container summary
// satisfies. A target is named either by its ID (in full or by a prefix, as
// every container-runtime command line accepts) or by its name.
func (r *targetRegistry) matches(s dockerContainerSummary) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.order {
		if r.entries[w].State == TargetAccepted {
			continue
		}
		if s.ID == w || (len(w) >= 12 && strings.HasPrefix(s.ID, w)) {
			return w
		}
		for _, n := range s.Names {
			if strings.TrimPrefix(n, "/") == w {
				return w
			}
		}
	}
	return ""
}

func (r *targetRegistry) update(wanted string, fn func(*TargetRegistration)) {
	r.mu.Lock()
	if e, ok := r.entries[wanted]; ok {
		fn(e)
	}
	r.mu.Unlock()
	r.writeReady()
}

func (r *targetRegistry) noteAttachRunning(names []string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.attach = append(r.attach, names...)
	r.mu.Unlock()
	r.writeReady()
}

func (r *targetRegistry) noteError(msg string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.errors = append(r.errors, msg)
	r.mu.Unlock()
	r.writeReady()
}

// writeReady rewrites the readiness file. It is written on every state
// change, not only at the end, because the condition a case runner waits on
// is "accepted", and a file that appeared only afterwards would be useless
// for waiting.
//
// The file is written to a temporary name and renamed into place, so a
// reader polling it never sees a half-written state and concludes the run
// is ready when it is not.
func (r *targetRegistry) writeReady() {
	if r == nil || r.readyPath == "" {
		return
	}
	r.mu.Lock()
	report := ReadyReport{
		RunID: r.runID, GeneratedAt: r.startedAt, UpdatedAt: time.Now().UTC(),
		RunKey: r.runKey, Sync: r.sync,
		AttachRunning: append([]string(nil), r.attach...),
		Errors:        append([]string(nil), r.errors...),
	}
	allAccepted := len(r.order) > 0
	for _, w := range r.order {
		e := *r.entries[w]
		if e.State != TargetAccepted {
			allAccepted = false
		}
		report.Targets = append(report.Targets, e)
	}
	report.Ready = allAccepted
	r.mu.Unlock()

	dir := filepath.Dir(r.readyPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".ready-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	if werr := writeJSONTo(tmp, report); werr != nil {
		tmp.Close()
		os.Remove(name)
		return
	}
	if cerr := tmp.Close(); cerr != nil {
		os.Remove(name)
		return
	}
	if rerr := os.Rename(name, r.readyPath); rerr != nil {
		os.Remove(name)
	}
}

// targetAcceptor is what the registration loop needs from the rest of
// collect to finish preparing a target: build its record from an inspect,
// and take the auxiliary mapping inputs it will need later.
type targetAcceptor func(ctx context.Context, summary dockerContainerSummary) (*ContainerRecord, error)

// awaitRegisteredTargets polls the container list until every registered
// target has been accepted or the deadline passes. A target that never
// appeared is recorded as not started — an explicit failure, kept distinct
// from a target that was observed and showed nothing.
func awaitRegisteredTargets(ctx context.Context, client *dockerClient, reg *targetRegistry, accept targetAcceptor, timeout, pollEvery time.Duration) []Failure {
	if reg.empty() {
		return nil
	}
	reg.writeReady()
	deadline := time.Now().Add(timeout)
	for {
		summaries, err := client.listContainers(ctx)
		if err != nil {
			reg.noteError("list containers: " + err.Error())
		}
		for _, s := range summaries {
			wanted := reg.matches(s)
			if wanted == "" {
				continue
			}
			reg.update(wanted, func(e *TargetRegistration) {
				if e.State == TargetRegistered {
					e.State, e.StartDetectedAt, e.ContainerID = TargetPreparing, time.Now().UTC(), s.ID
				}
			})
			rec, aerr := accept(ctx, s)
			if aerr != nil {
				// Acceptance is all or nothing. A target whose inspect or
				// whose mapping-input read did not finish stays in the
				// preparing state and is tried again; reporting it ready
				// would have the workload begin against an observation
				// that cannot resolve what it does.
				reg.update(wanted, func(e *TargetRegistration) { e.Error = aerr.Error() })
				continue
			}
			if rec == nil {
				reg.update(wanted, func(e *TargetRegistration) { e.Error = "no record was produced for this target" })
				continue
			}
			reg.update(wanted, func(e *TargetRegistration) {
				now := time.Now().UTC()
				e.ContainerID = s.ID
				e.InspectedAt, e.AuxCollectedAt, e.AcceptedAt = now, now, now
				e.State, e.Error = TargetAccepted, ""
			})
		}
		if reg.ready() {
			return nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pollEvery):
		}
	}

	var failures []Failure
	for _, e := range reg.snapshot() {
		if e.State == TargetAccepted {
			continue
		}
		reg.update(e.Wanted, func(t *TargetRegistration) {
			if t.State != TargetAccepted {
				t.State = TargetNotStarted
			}
		})
		failures = append(failures, Failure{
			Step: "expected_target_not_started",
			Message: fmt.Sprintf("target %q was registered before the window but never reached the accepted state within %s (last state %q)%s",
				e.Wanted, timeout, e.State, suffixIfSet(e.Error)),
		})
	}
	sort.Slice(failures, func(i, j int) bool { return failures[i].Message < failures[j].Message })
	return failures
}

func suffixIfSet(msg string) string {
	if msg == "" {
		return ""
	}
	return ": " + msg
}
