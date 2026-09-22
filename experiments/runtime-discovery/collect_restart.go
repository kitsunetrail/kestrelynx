package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// target is one container's collection state for the run: its current
// identity, the record its samples are written into, and the collection
// state that reads into that record.
//
// A target's record and the collection state that reads into it are one
// thing and are kept as one. They were separate, and a preparation that
// failed then left the state pointing into a record that was thrown away:
// the next attempt built a fresh record and the state's index into the old
// one no longer addressed anything. Retrying is the ordinary case here — a
// container is watched for until it is ready — so the two have to survive
// a failed attempt together, or not at all.
//
// prior holds every earlier generation of this same target, oldest first,
// once restart tracking has moved a target on from it. Each entry is a
// finished, self-contained record: nothing in it is touched again once it
// is appended here, and nothing recorded against a later generation is
// ever folded back into it.
type target struct {
	id     string
	record *ContainerRecord
	state  *containerCollectState
	prior  []*ContainerRecord
	// prepared is set only when preparation actually completed. It is what
	// a retry consults: a record holding a partial reading from a failed
	// attempt is not a prepared target, and counting readings instead let
	// one such reading stand in for a completed preparation.
	prepared bool
}

// GenerationEvent records one container's identity change detected while it
// was being observed: either the same container restarting (the id stays
// the same, StartedAt does not) or the name being re-created under a new
// id entirely (a removed-and-recreated container, or a redeploy that does
// not reuse the old container). It is the only place an old and a new
// generation are related to each other — the collect records themselves
// are partitioned one per generation, and a later generation's record
// never carries a previous generation's evidence.
type GenerationEvent struct {
	Kind            string    `json:"kind"` // "restart" | "recreate"
	ContainerName   string    `json:"container_name"`
	OldContainerID  string    `json:"old_container_id"`
	NewContainerID  string    `json:"new_container_id"`
	ImageIDBefore   string    `json:"image_id_before"`
	ImageIDAfter    string    `json:"image_id_after"`
	StartedAtBefore string    `json:"started_at_before"`
	StartedAtAfter  string    `json:"started_at_after"`
	DetectedAt      time.Time `json:"detected_at"`
	// SampleID is the sample tick during which the change was noticed, set
	// by the caller once the event is returned; classifyRestart and
	// detectRecreate do not know which sample they were called from.
	SampleID string `json:"sample_id,omitempty"`
}

// classifyRestart reports a restart when a container's StartedAt changed
// while its id did not, and nothing otherwise. An empty StartedAt on
// either side means the comparison could not be made (a container that was
// never inspected before, or an inspect that just failed) and is not
// itself evidence of a restart.
func classifyRestart(name, id, oldImageID, oldStartedAt, newImageID, newStartedAt string, detectedAt time.Time) *GenerationEvent {
	if oldStartedAt == "" || newStartedAt == "" || oldStartedAt == newStartedAt {
		return nil
	}
	return &GenerationEvent{
		Kind: "restart", ContainerName: name,
		OldContainerID: id, NewContainerID: id,
		ImageIDBefore: oldImageID, ImageIDAfter: newImageID,
		StartedAtBefore: oldStartedAt, StartedAtAfter: newStartedAt,
		DetectedAt: detectedAt,
	}
}

// matchRecreatedContainer looks through a freshly listed set of running
// containers for one that answers to a target's name but not to its last
// known id. A container found under the old id is not a re-creation — the
// failure that triggered the search was transient — and containers under
// any other name are not this target at all.
func matchRecreatedContainer(summaries []dockerContainerSummary, name, oldID string) *dockerContainerSummary {
	if name == "" {
		return nil
	}
	for i := range summaries {
		if primaryName(summaries[i].Names) != name {
			continue
		}
		if summaries[i].ID == oldID {
			return nil
		}
		return &summaries[i]
	}
	return nil
}

// detectRecreate is called once a container's id has stopped answering at
// all (docker top on it failed outright): it asks whether a container
// under the same name has taken its place with a different id. A daemon
// that cannot be listed, or a name that matches nothing, is reported as no
// re-creation yet — the caller tries again on the next sample rather than
// treating a transient listing failure as the target having vanished for
// good.
func detectRecreate(ctx context.Context, client *dockerClient, rec *ContainerRecord) *GenerationEvent {
	name := rec.Subject.Docker.ContainerName
	if name == "" {
		return nil
	}
	summaries, err := client.listContainers(ctx)
	if err != nil {
		return nil
	}
	s := matchRecreatedContainer(summaries, name, rec.Subject.Docker.ContainerID)
	if s == nil {
		return nil
	}
	imageID, startedAt := s.Image, ""
	if insp, ierr := client.inspectContainer(ctx, s.ID); ierr == nil {
		imageID, startedAt = insp.Image, insp.State.StartedAt
	}
	return &GenerationEvent{
		Kind: "recreate", ContainerName: name,
		OldContainerID: rec.Subject.Docker.ContainerID, NewContainerID: s.ID,
		ImageIDBefore: rec.Subject.Docker.ImageID, ImageIDAfter: imageID,
		StartedAtBefore: rec.Docker.StartedAt, StartedAtAfter: startedAt,
		DetectedAt: time.Now().UTC(),
	}
}

// appendGenerationEvent appends one event as a line of JSON to path,
// creating it if necessary. It is a plain append because the sample loop
// that calls it is single-threaded — one tick's targets are handled one
// after another, never concurrently — so no lock is needed to keep two
// writers from interleaving.
func appendGenerationEvent(path string, ev GenerationEvent) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create directory for %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode generation event: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// generationBoundary picks the instant one generation's validity ends and
// the next one's begins.
//
// The new container's own StartedAt is used when Docker reported one:
// nothing the previous generation did can postdate the moment its
// replacement actually started, and nothing the replacement did can
// predate it either — this holds for a same-id restart exactly as it does
// for a re-creation under a new id. When StartedAt could not be read (a
// transient inspect gap between detecting the change and building the new
// record), the instant this collector actually noticed the change is used
// instead: a real timestamp taken during this run, still a bound neither
// generation's activity can be shown to cross, only a less precise one
// than the container's own StartedAt.
//
// The boundary returned here is not yet clamped to the run's own window;
// the caller does that once it knows the window's bounds. The second
// return value names which source produced it, empty when neither could —
// which does not happen in practice (DetectedAt is always set by
// classifyRestart and detectRecreate), but is handled rather than assumed
// away, since guessing a boundary would be worse than reporting there
// isn't one.
func generationBoundary(ev GenerationEvent) (time.Time, string) {
	if ev.StartedAtAfter != "" {
		if t, err := time.Parse(time.RFC3339Nano, ev.StartedAtAfter); err == nil {
			return t, "started_at"
		}
	}
	if !ev.DetectedAt.IsZero() {
		return ev.DetectedAt, "detected_at"
	}
	return time.Time{}, ""
}

// clampToWindow keeps a boundary inside [start, end], since a StartedAt or
// a detection instant read with clock skew against the run's own window
// bookkeeping must not produce an inverted or out-of-range interval.
func clampToWindow(t, start, end time.Time) time.Time {
	if t.Before(start) {
		return start
	}
	if t.After(end) {
		return end
	}
	return t
}

// closeGenerationEnd narrows rec's own Window.ScheduledEnd to the instant a
// just-detected generation change puts a hard limit on what this record
// can still be credited with — independent of whether a replacement
// generation is ever successfully committed for it.
//
// This has to happen the moment a change is detected, not only once
// rolloverGeneration finishes building and committing a new record: a new
// generation's own inspect can fail (see rolloverGeneration's doc comment)
// and keep failing for the rest of the run, in which case rec is never
// replaced and is what gets written to disk as this target's only record.
// Closing its window here, unconditionally, is what keeps that record from
// spanning events collected after the container it describes had already
// stopped, whether or not anything ever took its place.
//
// Idempotent: if rec's window was already narrowed by an earlier call for
// the same still-pending change (its ScheduledEnd is already before the
// run's own windowEnd), this does nothing. The first detection's boundary
// is the one that stands — a retry of the same still-unresolved change
// recomputes the identical instant, and a second, later change arriving
// while the first is still pending must not push the first one's own
// boundary back out to something later.
func closeGenerationEnd(rec *ContainerRecord, ev GenerationEvent, windowStart, windowEnd time.Time) {
	if rec.Window.ScheduledEnd.Before(windowEnd) {
		return
	}
	boundary, source := generationBoundary(ev)
	if source == "" {
		// Not observed in practice — DetectedAt is always set by
		// classifyRestart and detectRecreate — but handled rather than
		// assumed away: the window is left spanning the whole run (not
		// narrowed to a guess), and this Failure says why, so a reader
		// does not mistake the wide window for a generation that never
		// changed at all.
		rec.Failures = append(rec.Failures, Failure{
			Step: "generation_boundary_unknown",
			Message: "the instant this generation ended could not be established (no new StartedAt and no detection time); " +
				"its window still spans the whole run rather than being narrowed to this generation's own share of it",
		})
		return
	}
	rec.Window.ScheduledEnd = clampToWindow(boundary, windowStart, windowEnd)
}

// rolloverGeneration finalizes a target's current generation in place —
// its record keeps every sample and reading it already collected, and is
// never written to again — and begins a new one for the container identity
// a GenerationEvent describes.
//
// The new generation starts from empty collection state: no package-index
// cache, no ledger-seen set, no auxiliary-input index carried from the
// generation before it, so nothing the old container did can be attributed
// to the one that replaced it. A fresh layout reading is taken for it
// before its own samples are trusted against anything, the same way the
// very first generation's was taken before the workload it watches for was
// allowed to begin.
//
// The caller is required to have already called closeGenerationEnd on
// t.record for this same ev before calling this function (the per-tick
// loop in collect.go does so unconditionally, whether or not this function
// then goes on to succeed) — that is what actually protects a same-id
// restart's events from crossing generations, and it does not depend on
// rolloverGeneration ever being reached at all: a new generation whose own
// inspect keeps failing leaves t.record exactly as it was, already
// narrowed, as this target's sole and final record if nothing ever
// replaces it. This function only reads that already-closed boundary back
// (t.record.Window.ScheduledEnd) to seed the new record's own start, so a
// retry that eventually succeeds narrows the new generation to the exact
// same instant the old one was closed at, not a second, independently
// recomputed one.
//
// A new generation whose inspect fails is not committed here: the caller
// is told why and the target is left exactly as it was, still on its
// previous (already boundary-closed) generation, so a transient inspect
// gap does not lose the target's ability to notice the same change again
// on the next sample.
//
// The new generation's own start is computed fresh here from the
// generation this function actually ends up committing — never read back
// from the old (already-closed) record's own ScheduledEnd (see the
// pending-rollover case above), and never taken on faith from ev's own
// StartedAtAfter either, which can disagree with a freshly confirmed
// StartedAt in two different ways, told apart below because they call for
// different corrections:
//   - ev's own StartedAtAfter is empty: its own detection-time inspect
//     simply failed to read one (detectRecreate's own separate inspect
//     call can fail even once the new id itself is already known). No
//     further identity change is implied by this - it is the same
//     generation ev already described, now with the StartedAt it could
//     not read before, so the correction keeps ev's own Kind and its own
//     old/new ids, just with the gap filled in.
//   - ev's own StartedAtAfter is non-empty but disagrees with what
//     confirmation just found: the identity ev.NewContainerID answered to
//     has moved on again since detection (it restarted a second time
//     before this rollover ever reached it) - ev already describes a
//     generation that never existed long enough to be observed. The
//     correction's own Kind is decided from its own old/new ids here,
//     never copied from ev's Kind: ev's own Kind describes what ev itself
//     was (e.g. a re-creation, A->B), but this further change is a
//     restart of the very identity ev.NewContainerID names, whatever ev's
//     own Kind was.
//
// Either way the caller is handed the correction (the second return
// value) to append to its own record of these events; ev itself is left
// exactly as detected, since it really was what was seen at the time.
//
// A new generation whose inspect fails is not committed here: the caller
// is told why and the target is left exactly as it was, still on its
// previous (already boundary-closed) generation, so a transient inspect
// gap does not lose the target's ability to notice the same change again
// on the next sample.
func rolloverGeneration(ctx context.Context, client *dockerClient, t *target, ev GenerationEvent, runKey RunKey, windowID string, phaseBase time.Time, phaseBaseFrom string, windowStart, windowEnd time.Time, registrations []TargetRegistration, auxEnabled bool, limits auxLimits, psArgs string) (*GenerationEvent, error) {
	summaries, err := client.listContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("generation change for %q detected but the new container could not be listed: %w", ev.ContainerName, err)
	}
	var summary *dockerContainerSummary
	for i := range summaries {
		if summaries[i].ID == ev.NewContainerID {
			summary = &summaries[i]
			break
		}
	}
	if summary == nil {
		return nil, fmt.Errorf("generation change for %q detected (new id %s) but that container could no longer be found to start observing it", ev.ContainerName, ev.NewContainerID)
	}

	newRec := newContainerRecord(ctx, client, *summary, runKey, windowID, phaseBase, phaseBaseFrom)
	if newRec.InspectError != "" {
		// Left uncommitted on purpose: the target stays on its previous
		// (already boundary-closed) generation, which will fail the same
		// identity check again on the next sample and reach this function
		// again, retrying rather than being stuck forever on a generation
		// the collector never actually observed.
		return nil, fmt.Errorf("generation change for %q detected (new id %s) but it could not be inspected yet (%s); the previous generation stays active and this will be retried at the next sample",
			ev.ContainerName, ev.NewContainerID, newRec.InspectError)
	}

	// The generation actually being committed is described by ev UNLESS the inspect just
	// above disagrees with what ev itself said to expect (see the doc comment above for
	// the two distinct ways that can happen and why each gets a different correction).
	effectiveEv := ev
	var correction *GenerationEvent
	actualStartedAt := newRec.Subject.StartedAt
	switch {
	case actualStartedAt == "":
		// Confirmation could not read a StartedAt either; nothing to correct with.
	case ev.StartedAtAfter == "":
		// Detection's own inspect never got a StartedAt at all - not evidence of a
		// further change, just a gap now filled in. Kind and identity stay ev's own.
		correction = &GenerationEvent{
			Kind: ev.Kind, ContainerName: ev.ContainerName,
			OldContainerID: ev.OldContainerID, NewContainerID: ev.NewContainerID,
			ImageIDBefore: ev.ImageIDBefore, ImageIDAfter: newRec.Subject.Docker.ImageID,
			StartedAtBefore: ev.StartedAtBefore, StartedAtAfter: actualStartedAt,
			DetectedAt: time.Now().UTC(),
		}
		effectiveEv = *correction
	case actualStartedAt != ev.StartedAtAfter:
		// Detection had a StartedAt, and confirmation found a different one: a genuine
		// further change, described from the correction's own old/new ids rather than
		// ev's Kind (see the doc comment above).
		newID := newRec.Subject.Docker.ContainerID
		kind := "restart"
		if ev.NewContainerID != newID {
			kind = "recreate"
		}
		correction = &GenerationEvent{
			Kind: kind, ContainerName: ev.ContainerName,
			OldContainerID: ev.NewContainerID, NewContainerID: newID,
			ImageIDBefore: ev.ImageIDAfter, ImageIDAfter: newRec.Subject.Docker.ImageID,
			StartedAtBefore: ev.StartedAtAfter, StartedAtAfter: actualStartedAt,
			DetectedAt: time.Now().UTC(),
		}
		effectiveEv = *correction
	}

	boundary, boundarySource := generationBoundary(effectiveEv)
	newStart := windowEnd // safe default when the boundary is unknown: credit this generation with (as close as possible to) nothing, never with more than it can be shown to own
	if boundarySource != "" {
		newStart = clampToWindow(boundary, windowStart, windowEnd)
	}

	newRec.Window.ScheduledStart, newRec.Window.ScheduledEnd = newStart, windowEnd
	newRec.TargetRegistrations = registrations
	newState := newContainerCollectState(auxEnabled, limits)
	if perr := prepareTarget(ctx, client, newRec, newState, psArgs); perr != nil {
		newRec.Failures = append(newRec.Failures, Failure{
			Step:    "generation_prepare_failed",
			Message: fmt.Sprintf("a fresh layout reading for the new generation could not be completed: %v", perr),
		})
	}

	// The old generation's initial-database-read cost lives on its own
	// collection state, not on the record; it is copied across now, before
	// that state is replaced, or it would be lost rather than reported
	// against the generation it was actually measured for. This, and the
	// hand-off to t.prior, happen only now that the new generation is
	// confirmed observable — never before, per the inspect check above.
	// The old record's own window was already closed by closeGenerationEnd
	// before this function was ever called, so nothing about its Window
	// changes here.
	old := t.record
	old.Load.InitialDBRead = t.state.initialDBRead
	t.prior = append(t.prior, old)

	t.record, t.state, t.id = newRec, newState, ev.NewContainerID
	return correction, nil
}
