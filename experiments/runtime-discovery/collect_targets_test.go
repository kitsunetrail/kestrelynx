package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readReady(t *testing.T, path string) ReadyReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read readiness file: %v", err)
	}
	var r ReadyReport
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("parse readiness file: %v", err)
	}
	return r
}

func stateOf(r ReadyReport, wanted string) TargetRegistration {
	for _, e := range r.Targets {
		if e.Wanted == wanted {
			return e
		}
	}
	return TargetRegistration{}
}

// TestRegistrationStatesAndTimes walks a registered target through the
// three states and checks each transition is timed.
//
// The states exist because a target named before it exists is not the same
// as a target that is being observed: between the two lies reading its
// configuration and the layout its files will be matched against, and a
// workload told to start before that is finished is measuring the wrong
// thing.
func TestRegistrationStatesAndTimes(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready.json")
	key := RunKey{CaseVariant: "17", Permission: "root", Sync: "startup"}
	reg := newTargetRegistry([]string{"case17"}, ready, key, "startup", "test-run-1")

	reg.writeReady()
	first := readReady(t, ready)
	if first.Ready {
		t.Error("a target that has not started was reported as ready")
	}
	if got := stateOf(first, "case17"); got.State != TargetRegistered {
		t.Errorf("initial state = %q, want %q", got.State, TargetRegistered)
	}
	if stateOf(first, "case17").RegisteredAt.IsZero() {
		t.Error("registration was not timed")
	}

	reg.update("case17", func(e *TargetRegistration) {
		e.State, e.StartDetectedAt, e.ContainerID = TargetPreparing, time.Now().UTC(), "abc123"
	})
	preparing := readReady(t, ready)
	if preparing.Ready {
		t.Error("a target still being prepared was reported as ready; firing the workload here would race the preparation")
	}
	if got := stateOf(preparing, "case17"); got.State != TargetPreparing || got.StartDetectedAt.IsZero() {
		t.Errorf("second state = %q, detected at %v", got.State, got.StartDetectedAt)
	}

	reg.update("case17", func(e *TargetRegistration) {
		now := time.Now().UTC()
		e.State, e.InspectedAt, e.AuxCollectedAt, e.AcceptedAt = TargetAccepted, now, now, now
	})
	accepted := readReady(t, ready)
	if !accepted.Ready {
		t.Error("every target is accepted but the readiness file does not say so")
	}
	got := stateOf(accepted, "case17")
	if got.AcceptedAt.IsZero() || got.AuxCollectedAt.IsZero() {
		t.Errorf("acceptance was not timed: accepted %v, layout read %v", got.AcceptedAt, got.AuxCollectedAt)
	}
	if got.ContainerID != "abc123" {
		t.Errorf("container identity = %q, want the one seen at start detection", got.ContainerID)
	}
}

// TestRegistrationMatchesByNameOrIdentifier checks the ways a target can
// be named: its full identifier, a leading part of it, or its name.
func TestRegistrationMatchesByNameOrIdentifier(t *testing.T) {
	const id = "eb2e2dff3cfa6c0d60ed97ef902110848927aeaea702cb54e8f5813f5122c1ab"
	summary := dockerContainerSummary{ID: id, Names: []string{"/case17"}}
	for _, wanted := range []string{id, id[:12], "case17"} {
		reg := newTargetRegistry([]string{wanted}, filepath.Join(t.TempDir(), "ready.json"), RunKey{}, "startup", "test-run-1")
		if got := reg.matches(summary); got != wanted {
			t.Errorf("a container named %q did not match the registration %q", summary.Names[0], wanted)
		}
	}
	reg := newTargetRegistry([]string{"other"}, filepath.Join(t.TempDir(), "ready.json"), RunKey{}, "startup", "test-run-1")
	if got := reg.matches(summary); got != "" {
		t.Errorf("an unrelated container matched registration %q", got)
	}
}

// TestATargetThatNeverStartsIsAFailure checks that a registered target
// which never appears is recorded as a failure of the run, kept distinct
// from a target that was observed and showed nothing. The two mean
// opposite things, and conflating them would let a broken fixture read as
// an unused package.
func TestATargetThatNeverStartsIsAFailure(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready.json")
	reg := newTargetRegistry([]string{"never-started"}, ready, RunKey{CaseVariant: "17"}, "startup", "test-run-1")

	// A socket that is not there: the container list cannot be read, which
	// is recorded and retried, and is not itself the failure under test.
	client := newDockerClient(filepath.Join(dir, "absent.sock"))
	failures := awaitRegisteredTargets(context.Background(), client, reg,
		func(context.Context, dockerContainerSummary) (*ContainerRecord, error) {
			t.Fatal("acceptance was attempted for a container that never appeared")
			return nil, errors.New("unreachable")
		}, 50*time.Millisecond, 10*time.Millisecond)

	if len(failures) != 1 {
		t.Fatalf("got %d failure(s), want one for the target that never started", len(failures))
	}
	if failures[0].Step != "expected_target_not_started" {
		t.Errorf("failure step = %q, want expected_target_not_started", failures[0].Step)
	}
	final := readReady(t, ready)
	if final.Ready {
		t.Error("the readiness file reports ready although a registered target never started")
	}
	if got := stateOf(final, "never-started"); got.State != TargetNotStarted {
		t.Errorf("final state = %q, want %q", got.State, TargetNotStarted)
	}
}

// TestAttachedContainersAreRecordedBesideRegistrations checks that the
// two ways a container enters a run coexist. Joining containers already
// running and waiting for one that has not started are different
// conditions, and a run may do both.
func TestAttachedContainersAreRecordedBesideRegistrations(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready.json")
	reg := newTargetRegistry([]string{"case13"}, ready, RunKey{Sync: "startup"}, "startup", "test-run-1")
	reg.noteAttachRunning([]string{"already-running-1", "already-running-2"})

	r := readReady(t, ready)
	if len(r.AttachRunning) != 2 {
		t.Errorf("attached containers = %v, want both", r.AttachRunning)
	}
	if len(r.Targets) != 1 {
		t.Errorf("registrations = %d, want the one that was registered", len(r.Targets))
	}
	if r.Ready {
		t.Error("containers already running made the run look ready while a registered target had not started")
	}
}
