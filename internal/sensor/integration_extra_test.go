//go:build integration

// Additional real-Docker scenarios beyond integration_test.go's own
// multi-workload pass: container churn (added after start, restarted,
// recreated), Sensor restart persistence, --exclude-id, a container this
// Sensor's own AppArmor profile cannot read at all, a package-database file
// that is a FIFO rather than a regular file, two containers sampled
// concurrently, and a fresh, empty named volume's first write (validating
// the Dockerfile's own pre-created, pre-owned evidence directory). Same
// build tag, same helpers (dockerT, dockerBestEffort, waitForGenerations,
// repoRoot, requireDocker) as integration_test.go, and the same policy: every
// container, image, and volume a test here creates carries a run-specific
// label/tag and is removed in a deferred cleanup regardless of outcome.
//
// Run with:
//
//	go test -tags=integration -run TestSensorIntegration -v -timeout 40m \
//	  ./internal/sensor/...
package sensor_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// buildIntegrationImage builds this repository's own Dockerfile, tagged
// uniquely for runID, and returns the tag. The caller must defer its
// removal (dockerBestEffort(t, "rmi", "-f", tag)).
func buildIntegrationImage(t *testing.T, runID string) string {
	t.Helper()
	root := repoRoot(t)
	tag := "kestrelynx-sensor-integration-test:" + runID
	t.Logf("building image %s (this can take a while the first time)", tag)
	dockerT(t, "build", "-t", tag, root)
	return tag
}

// distributedSeccompPath returns this repository's own distributed seccomp
// profile's path, failing the test if it is missing.
func distributedSeccompPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "deploy", "docker", "sensor-seccomp.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("distributed seccomp profile missing at %s: %v", path, err)
	}
	return path
}

// startSensorContainer runs the real Sensor daemon, configured the way
// deploy/docker/docker-compose.sensor.yml documents, against evidenceDir
// (bind-mounted unless extraVolumeArgs says otherwise — see
// TestSensorIntegration_FreshNamedVolumeIsWritable, which passes a named
// volume instead). It returns the container ID; the caller must defer its
// removal.
func startSensorContainer(t *testing.T, imageTag, runID, evidenceMount string, extraSensorArgs ...string) string {
	t.Helper()
	args := []string{
		"run", "-d",
		"--label", integrationLabelKey + "=" + runID,
		"--entrypoint", "kestrelynx-sensor",
		"--user", "65532:65532",
		"--pid", "host",
		"--cgroupns", "host",
		"--network", "none",
		"--cap-drop", "ALL",
		"--cap-add", "SYS_PTRACE",
		"--cap-add", "DAC_READ_SEARCH",
		"--cap-add", "BPF",
		"--cap-add", "PERFMON",
		"--security-opt", "seccomp=" + distributedSeccompPath(t),
		"--read-only",
		"-v", evidenceMount + ":/var/lib/kestrelynx-runtime",
		imageTag,
		"sensor", "--interval", "10s", "--evidence-dir", "/var/lib/kestrelynx-runtime",
	}
	args = append(args, extraSensorArgs...)
	return dockerT(t, args...)
}

func runTarget(t *testing.T, runID, image string, cmd ...string) string {
	t.Helper()
	args := []string{"run", "-d", "--label", integrationLabelKey + "=" + runID, image}
	args = append(args, cmd...)
	return dockerT(t, args...)
}

// runPrivilegedTarget is runTarget but with --privileged: for a target that
// needs real write access to its own /sys/fs/cgroup mount, which this Docker
// Engine mounts read-only for an ordinary container regardless of any
// individual --cap-add (confirmed directly against it: neither --cap-add
// SYS_ADMIN nor --cgroupns=host makes it writable; only --privileged does).
func runPrivilegedTarget(t *testing.T, runID, image string, cmd ...string) string {
	t.Helper()
	args := []string{"run", "-d", "--label", integrationLabelKey + "=" + runID, "--privileged", image}
	args = append(args, cmd...)
	return dockerT(t, args...)
}

func generationsByContainer(snap evidence.Snapshot) map[string][]evidence.Generation {
	out := map[string][]evidence.Generation{}
	for _, g := range snap.Generations {
		out[g.Container.ID] = append(out[g.Container.ID], g)
	}
	return out
}

// TestSensorIntegration_ContainerAddedAfterStart covers a container that
// starts after the Sensor: a container started only after
// the Sensor is already running must still be discovered and produce a
// generation, on some sample after its own start — discovery
// (groupContainers/scanProcs) runs fresh every sample, not only at startup.
func TestSensorIntegration_ContainerAddedAfterStart(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-added-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// Let the Sensor complete at least one sample pass with nothing to see
	// yet before the target container exists at all.
	time.Sleep(3 * time.Second)

	targetID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the post-startup container's own generation: %v", err)
	}
	byContainer := generationsByContainer(snap)
	if _, ok := byContainer[targetID]; !ok {
		t.Errorf("no generation recorded for the container added after the Sensor was already running")
	}
}

// TestSensorIntegration_SameIDContainerRestart covers a container restarted
// in place: `docker restart` keeps the container ID but gives it a
// brand-new init process (a different host PID and starttime). Evidence
// does not carry the old generation over onto the new one (see evidence's
// own generation-identity doc comment): the old generation must end (State
// ended) and a second, distinct generation must appear for the same
// container ID once the restarted process is observed.
func TestSensorIntegration_SameIDContainerRestart(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-restart-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	targetID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")

	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	if _, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second); err != nil {
		t.Fatalf("waiting for the initial generation: %v", err)
	}

	dockerT(t, "restart", targetID)

	// Poll until this container ID has two distinct generations recorded:
	// the original (now ended) and a fresh one for the restarted process.
	deadline := time.Now().Add(150 * time.Second)
	var gens []evidence.Generation
	for time.Now().Before(deadline) {
		r := evidence.NewReader(evidenceDir)
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			gens = generationsByContainer(snap)[targetID]
			if len(gens) >= 2 {
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if len(gens) < 2 {
		t.Fatalf("container %s has %d generation(s) recorded after restart, want 2 (ended + fresh)", targetID, len(gens))
	}

	var sawEnded, sawFresh bool
	var endedInit, freshInit evidence.InitProcess
	for _, g := range gens {
		if g.State == evidence.StateEnded {
			sawEnded = true
			endedInit = g.Init
		} else {
			sawFresh = true
			freshInit = g.Init
		}
	}
	if !sawEnded {
		t.Errorf("no ended generation recorded for %s after its restart", targetID)
	}
	if !sawFresh {
		t.Errorf("no fresh (non-ended) generation recorded for %s after its restart", targetID)
	}
	if sawEnded && sawFresh && endedInit == freshInit {
		t.Errorf("ended and fresh generations share the same init identity %+v; restart should have changed it", endedInit)
	}
}

// TestSensorIntegration_ContainerRecreation covers a container recreated
// under the same name: removing a container and running a new one under
// the same name gets a brand-new container ID from Docker. The old ID's
// generation must end; a generation must appear under the new ID.
func TestSensorIntegration_ContainerRecreation(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-recreate-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	name := "kl-recreate-target-" + runID
	firstID := dockerT(t, "run", "-d", "--label", integrationLabelKey+"="+runID,
		"--name", name, "debian:12-slim", "sleep", "99999")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	if _, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second); err != nil {
		t.Fatalf("waiting for the first container's own generation: %v", err)
	}

	dockerBestEffort(t, "rm", "-f", firstID)
	secondID := dockerT(t, "run", "-d", "--label", integrationLabelKey+"="+runID,
		"--name", name, "debian:12-slim", "sleep", "99999")
	if secondID == firstID {
		t.Fatalf("recreated container unexpectedly reused the same ID %s", firstID)
	}

	deadline := time.Now().Add(150 * time.Second)
	var byContainer map[string][]evidence.Generation
	for time.Now().Before(deadline) {
		r := evidence.NewReader(evidenceDir)
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			byContainer = generationsByContainer(snap)
			if len(byContainer[secondID]) > 0 {
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if len(byContainer[secondID]) == 0 {
		t.Fatalf("no generation recorded for the recreated container %s", secondID)
	}
	firstGens := byContainer[firstID]
	if len(firstGens) == 0 {
		t.Fatalf("the removed container %s's own generation disappeared entirely instead of ending", firstID)
	}
	for _, g := range firstGens {
		if g.State != evidence.StateEnded {
			t.Errorf("removed container %s generation state = %q, want ended", firstID, g.State)
		}
	}
}

// TestSensorIntegration_SensorRestartPersistsEvidence covers the Sensor
// process itself being restarted: OSPackages/Executables already recorded
// for a still-running target container must survive that restart (a fresh
// session, a fresh parser, but the same evidence directory) —
// loadPreviousEvidence's whole job.
func TestSensorIntegration_SensorRestartPersistsEvidence(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-sensorrestart-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	targetID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")

	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	cleanedUpFirstSensor := false
	defer func() {
		if !cleanedUpFirstSensor {
			dockerBestEffort(t, "rm", "-f", sensorID)
		}
	}()
	// Captured just before this first Sensor is removed below (rather than
	// deferring a `docker logs` call the way every other test here does),
	// since its own logs would otherwise be gone by the time a deferred call
	// could read them — this container is deliberately removed mid-test, not
	// only in a defer. Printed only if the test ends up failing, whether that
	// happens before or after the restart below.
	var firstSensorLogs string
	defer func() {
		if t.Failed() {
			t.Logf("sensor container %s (pre-restart) logs:\n%s", sensorID, firstSensorLogs)
		}
	}()

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the initial generation: %v", err)
	}
	before, ok := generationsByContainer(snap)[targetID]
	if !ok || len(before) != 1 {
		t.Fatalf("unexpected generations for %s before restart: %+v", targetID, before)
	}
	// The initial generation existing is not enough on its own: this
	// container's package-database index needs its own time to build and be
	// confirmed (state observing) before OSPackages can be trusted to be
	// non-empty at all — see waitForPackageDBReady's own doc comment for why
	// checking this immediately after waitForGenerations' own first success,
	// as an earlier version of this test did, is a race against that build.
	before0, err := waitForPackageDBReady(t, evidenceDir, targetID, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the initial package database to become ready: %v", err)
	}
	if len(before0.OSPackages) == 0 {
		t.Fatalf("expected at least one OS package recorded for a debian:12-slim target before restarting the Sensor (package_db=%+v)", before0.PackageDB)
	}
	wantPackageCount := len(before0.OSPackages)
	wantStartedAt := before0.StartedAt
	wantInit := before0.Init
	oldSessionID := snap.Sensor.SessionID

	firstSensorLogs = dockerBestEffortOutput(t, "logs", sensorID)
	dockerT(t, "rm", "-f", sensorID)
	cleanedUpFirstSensor = true

	sensorID2 := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID2)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID2)

	// A session_id that has actually changed is what proves this is reading
	// the NEW session's own write, not a stale file the old session
	// happened to leave behind (which reading only "one generation exists"
	// could not tell apart from an old file the new session never touched
	// at all — evidence is written strictly on a fixed 60s heartbeat now,
	// see loop's own doc comment, so this can legitimately take a while).
	deadline := time.Now().Add(150 * time.Second)
	var after evidence.Generation
	var newSessionID string
	var found bool
	for time.Now().Before(deadline) {
		r := evidence.NewReader(evidenceDir)
		snap, err := r.Read(time.Now(), nil)
		if err == nil && snap.Sensor.SessionID != oldSessionID {
			gens := generationsByContainer(snap)[targetID]
			if len(gens) == 1 {
				after = gens[0]
				newSessionID = snap.Sensor.SessionID
				found = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !found {
		t.Fatalf("no single generation recorded for %s under a new session_id (still %q) after the Sensor restarted", targetID, oldSessionID)
	}
	if newSessionID == "" || newSessionID == oldSessionID {
		t.Fatalf("session_id = %q, want a new value distinct from the pre-restart one (%q)", newSessionID, oldSessionID)
	}
	if after.Init != wantInit {
		t.Errorf("Init = %+v after the Sensor restart, want unchanged %+v — the target container itself never restarted", after.Init, wantInit)
	}
	if !after.StartedAt.Equal(wantStartedAt) {
		t.Errorf("StartedAt = %v after the Sensor restart, want unchanged %v", after.StartedAt, wantStartedAt)
	}
	if len(after.OSPackages) < wantPackageCount {
		t.Errorf("OSPackages count = %d after the Sensor restart, want at least %d (carried over from before)", len(after.OSPackages), wantPackageCount)
	}
}

// TestSensorIntegration_ExcludedContainerNeverObserved covers --exclude-id:
// a container whose ID prefix is excluded must never appear in the evidence
// file at all, while an un-excluded sibling container started at the same
// time is observed normally.
func TestSensorIntegration_ExcludedContainerNeverObserved(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-exclude-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	excludedID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")
	includedID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")
	excludePrefix := excludedID[:12]

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir, "--exclude-id", excludePrefix)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the included container's own generation: %v", err)
	}
	byContainer := generationsByContainer(snap)
	if _, ok := byContainer[includedID]; !ok {
		t.Errorf("the un-excluded sibling container %s was never observed", includedID)
	}
	if _, ok := byContainer[excludedID]; ok {
		t.Errorf("the excluded container %s (prefix %s) was observed anyway", excludedID, excludePrefix)
	}
}

// startSensorContainerWithCaps is startSensorContainer with an explicit,
// caller-chosen --cap-add list instead of the deploy/docker/
// docker-compose.sensor.yml default (SYS_PTRACE, DAC_READ_SEARCH, BPF,
// PERFMON) — for a test that deliberately runs the Sensor itself with
// fewer capabilities than deployment calls for.
func startSensorContainerWithCaps(t *testing.T, imageTag, runID, evidenceMount string, caps []string, extraSensorArgs ...string) string {
	t.Helper()
	args := []string{
		"run", "-d",
		"--label", integrationLabelKey + "=" + runID,
		"--entrypoint", "kestrelynx-sensor",
		"--user", "65532:65532",
		"--pid", "host",
		"--cgroupns", "host",
		"--network", "none",
		"--cap-drop", "ALL",
	}
	for _, c := range caps {
		args = append(args, "--cap-add", c)
	}
	args = append(args,
		"--security-opt", "seccomp="+distributedSeccompPath(t),
		"--read-only",
		"-v", evidenceMount+":/var/lib/kestrelynx-runtime",
		imageTag,
		"sensor", "--interval", "10s", "--evidence-dir", "/var/lib/kestrelynx-runtime",
	)
	args = append(args, extraSensorArgs...)
	return dockerT(t, args...)
}

// TestSensorIntegration_SensorMissingSysPtraceBecomesPermissionDenied
// covers a Sensor running with reduced permissions directly and
// unconditionally: running the Sensor itself without SYS_PTRACE (the
// capability every exe/maps/root read of another container's process
// depends on) must report sensor.status = permission_denied for the whole
// session — this
// does not depend on any particular target container's own AppArmor
// profile or on how a given Docker/AppArmor configuration happens to
// enforce it, unlike a scenario built around --privileged (see
// TestSensorIntegration_PermissionInsufficientContainerBecomesDenied's own
// doc comment for why that one is a weaker, best-effort check by
// comparison).
func TestSensorIntegration_SensorMissingSysPtraceBecomesPermissionDenied(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-nosysptrace-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	runTarget(t, runID, "debian:12-slim", "sleep", "99999")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainerWithCaps(t, imageTag, runID, evidenceDir, []string{"DAC_READ_SEARCH", "BPF", "PERFMON"})
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	deadline := time.Now().Add(150 * time.Second)
	var status evidence.SensorStatus
	var found bool
	for time.Now().Before(deadline) {
		r := evidence.NewReader(evidenceDir)
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			status = snap.Sensor.Status
			if status == evidence.SensorPermissionDenied {
				found = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !found {
		t.Fatalf("sensor.status never reached permission_denied within the deadline (last observed: %q)", status)
	}
}

// TestSensorIntegration_PermissionInsufficientContainerBecomesDenied covers
// a single container this Sensor's own AppArmor confinement cannot read at
// all, per-generation (StateDenied), while the Sensor itself keeps its own
// full capability set and successfully reads every other container: the
// Sensor runs under the docker-default AppArmor profile, which cannot read
// a privileged/unconfined container's processes, since the confined side of
// a ptrace-style access check is always the one enforced against. This is a
// best-effort check, not a guarantee: whether Docker/AppArmor actually
// denies a confined reader against a --privileged target this way can vary
// by host configuration, which is exactly why
// TestSensorIntegration_SensorMissingSysPtraceBecomesPermissionDenied above
// exists as the reliable, host-independent version of "a permission
// problem" this suite depends on. If the target's reads are never denied at
// all on this host, this test skips rather than failing outright — that
// outcome means the AppArmor behavior this test wants to observe simply
// is not present here, not that this Sensor's own StateDenied logic (which
// the other test already exercises via lastGoodSample) is broken.
func TestSensorIntegration_PermissionInsufficientContainerBecomesDenied(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-denied-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	targetID := dockerT(t, "run", "-d", "--label", integrationLabelKey+"="+runID,
		"--privileged", "debian:12-slim", "sleep", "99999")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	deadline := time.Now().Add(150 * time.Second)
	var gen evidence.Generation
	var found, everObserved bool
	for time.Now().Before(deadline) {
		r := evidence.NewReader(evidenceDir)
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			if gens := generationsByContainer(snap)[targetID]; len(gens) == 1 {
				gen = gens[0]
				if gen.State == evidence.StateDenied {
					found = true
					break
				}
				if len(gen.Executables) > 0 {
					everObserved = true
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !found {
		if everObserved {
			t.Skipf("this host's AppArmor configuration did not deny reads against a --privileged target (executables were observed normally); see this test's own doc comment")
		}
		t.Fatalf("privileged container %s never reached state=denied within the deadline (last observed state=%q)", targetID, gen.State)
	}
	if len(gen.Executables) != 0 {
		t.Errorf("Executables = %+v for a container this Sensor should never be able to read at all", gen.Executables)
	}
}

// TestSensorIntegration_FIFOInPackageDatabaseDoesNotBlock covers a package
// database file replaced by a FIFO: a .list file replaced by a FIFO must
// never hang the observer (rootfs.OpenFile opens with
// O_NONBLOCK and rejects anything that is not a regular file — see its own
// doc comment — so this is really confirming that contract holds end to end
// against a real container, not merely in a unit test against a synthetic
// rootfs) and must not prevent the rest of that same container's real
// packages from being indexed and resolved normally.
func TestSensorIntegration_FIFOInPackageDatabaseDoesNotBlock(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-fifo-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	// mkfifo a file named like a dpkg .list file (nothing ever declares a
	// package by this name, so it is simply an extra, non-matching entry in
	// var/lib/dpkg/info/ — gatherIndexFiles still finds and tries to open it
	// via its *.list glob) before running the container's real, long-lived
	// process.
	targetID := runTarget(t, runID, "debian:12-slim", "sh", "-c",
		"mkfifo /var/lib/dpkg/info/nobody-writes-here.list && exec sleep 99999")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// A generous but still bounded deadline: if the FIFO ever did block the
	// observer the way it must not, this simply times out instead of
	// hanging the test suite forever.
	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for a generation despite the FIFO: %v", err)
	}
	gens := generationsByContainer(snap)[targetID]
	if len(gens) != 1 {
		t.Fatalf("generations for %s = %+v, want exactly one", targetID, gens)
	}
	// A generation existing is not enough: the package database itself still
	// needs its own time to build and be confirmed (state observing) before
	// OSPackages can be trusted to be non-empty — see waitForPackageDBReady's
	// own doc comment for why checking OSPackages immediately here, as an
	// earlier version of this test did, races that build.
	ready, err := waitForPackageDBReady(t, evidenceDir, targetID, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the package database to become ready despite the FIFO: %v", err)
	}
	if len(ready.OSPackages) == 0 {
		t.Errorf("OSPackages is empty for a debian:12-slim target with a FIFO among its .list files; want the container's other, real packages still resolved (package_db=%+v)", ready.PackageDB)
	}
}

// TestSensorIntegration_ConcurrentContainersSampledTogether exercises
// bounded concurrency directly: one container's own package-database build
// is made deliberately heavy (several thousand extra .list files under
// var/lib/dpkg/info, forcing that many more real open/send round trips to
// the parser than an ordinary image needs — a real, reliably-induced cost,
// not a hoped-for one), running alongside an ordinary light one. The light
// container's own last_verified_at must still land inside one ordinary
// heartbeat cycle of "now" regardless of how long the heavy one's own build
// takes — proving the heavy one's own worker cannot hold up the light one's
// results or the heartbeat, which is bounded concurrency's whole point.
// (Comparing the two containers' own last_verified_at values directly, as
// an earlier version of this test did, could not actually distinguish
// concurrent from sequential processing: both were derived from one
// discovery pass's shared timestamp regardless. This Sensor's own
// architecture ties last_verified_at to each worker's real completion time
// instead — see applySampleResult's own doc comment — which is what makes
// the check below meaningful.)
func TestSensorIntegration_ConcurrentContainersSampledTogether(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-concurrent-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	// Several thousand extra, harmless dummy .list files: gatherIndexFiles
	// matches on the *.list glob regardless of whether a real package in
	// status declares them, so each one still costs a real open+send round
	// trip to the parser.
	heavyID := runTarget(t, runID, "debian:12-slim", "sh", "-c",
		"for i in $(seq 1 4000); do echo '/.' > /var/lib/dpkg/info/dummy$i.list; done && exec sleep 99999")
	lightID := runTarget(t, runID, "alpine:3.20", "sleep", "99999")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// Poll until the light container's own last_verified_at appears, then
	// compare it against sensor.session_started_at — not against "now" at
	// observation time, which would always look fresh regardless of when
	// the value itself was actually computed.
	deadline := time.Now().Add(150 * time.Second)
	var lightSeenAt, sessionStartedAt time.Time
	for time.Now().Before(deadline) {
		r := evidence.NewReader(evidenceDir)
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			if gens := generationsByContainer(snap)[lightID]; len(gens) == 1 && !gens[0].LastVerifiedAt.IsZero() {
				lightSeenAt = gens[0].LastVerifiedAt
				sessionStartedAt = snap.Sensor.SessionStartedAt
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if lightSeenAt.IsZero() {
		t.Fatalf("the light container's own last_verified_at never appeared within the deadline")
	}
	delay := lightSeenAt.Sub(sessionStartedAt)
	// --interval is 10s; a light container dispatched in the very first
	// discovery round should be verified within roughly one interval plus
	// margin for the sample itself and this Sensor's own startup sequence
	// — comfortably tighter than "however long the heavy container's own
	// several-thousand-file build takes" if it were serializing in front
	// of it instead of running concurrently.
	if delay > 45*time.Second {
		t.Errorf("the light container's first last_verified_at came %s after session start, want well under that — the heavy container's build should not be able to delay it this much", delay)
	}

	// The heavy container's own build must still complete correctly on its
	// own time, confirming its several-thousand-file load was handled, not
	// merely that it never blocked anything else.
	heavyDeadline := time.Now().Add(150 * time.Second)
	var heavySeen bool
	for time.Now().Before(heavyDeadline) {
		r := evidence.NewReader(evidenceDir)
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			if gens := generationsByContainer(snap)[heavyID]; len(gens) == 1 && len(gens[0].OSPackages) > 0 {
				heavySeen = true
				break
			}
		}
		time.Sleep(2 * time.Second)
	}
	if !heavySeen {
		t.Errorf("the heavy container's own OSPackages never appeared within the deadline")
	}
}

// TestSensorIntegration_FreshNamedVolumeIsWritable validates the Dockerfile's
// own fix for a Sensor that has never run against a given evidence volume
// before: a brand-new, empty named volume (never a bind mount, which always
// carries the host directory's own, pre-existing permissions) must already
// be writable by the Sensor's own non-root UID the first time it is
// mounted, because the image pre-creates /var/lib/kestrelynx-runtime owned
// by that UID and Docker copies a fresh volume's initial content/ownership
// from whatever the image already has at that path.
func TestSensorIntegration_FreshNamedVolumeIsWritable(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-volume-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	volumeName := "kl-sit-runtime-" + runID
	dockerT(t, "volume", "create", volumeName)
	defer dockerBestEffort(t, "volume", "rm", "-f", volumeName)

	sensorID := startSensorContainer(t, imageTag, runID, volumeName)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// Read the evidence file back out of the named volume via a disposable,
	// throwaway reader container rather than trying to resolve the volume's
	// own host-side mountpoint (which requires root outside a Linux VM
	// context Docker Desktop does not expose the same way native Docker
	// does) — cat's own exit status is enough to prove the file exists and
	// is non-empty.
	deadline := time.Now().Add(150 * time.Second)
	var lastErr string
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "run", "--rm",
			"-v", volumeName+":/evidence:ro", "debian:12-slim",
			"sh", "-c", "test -s /evidence/"+evidenceFileNameForTest+" && echo present").CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) == "present" {
			return
		}
		lastErr = string(out)
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("evidence file never appeared, non-empty, in the fresh named volume %s (last check output: %s)", volumeName, lastErr)
}

// evidenceFileNameForTest mirrors evidence.FileName, kept as a local literal
// here (rather than importing evidence just for this) since it is only ever
// interpolated into a shell command string for the disposable reader
// container above, not used as a Go value anywhere else in this file.
const evidenceFileNameForTest = "procfs.json"
