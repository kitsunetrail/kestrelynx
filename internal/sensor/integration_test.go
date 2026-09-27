//go:build integration

// This file requires a real Docker daemon reachable without sudo (the
// invoking user in the docker group is enough — the Sensor container itself
// is what needs elevated capabilities, granted by the daemon via
// docker run --cap-add, not by the host user running this test). It is
// gated behind the "integration" build tag and skipped by a plain
// `go test ./...`.
//
// Run it with:
//
//	go test -tags=integration -run TestSensorIntegration -v -timeout 15m \
//	  ./internal/sensor/...
//
// It builds the repository's own Dockerfile image once, starts one
// container per target workload (a Go binary with no OS package database, a
// node/python/java process, a dpkg-based container, an apk-based container,
// and an rpm-based container this Sensor cannot parse), runs the real
// `kestrelynx sensor` daemon against them in a container configured the way
// deploy/docker/docker-compose.sensor.yml documents (cap_drop ALL plus the
// four cap_add capabilities, pid: host, network_mode: none, the distributed
// seccomp profile, a non-root user), and reads the resulting evidence file
// from a bind-mounted directory. Every container and image this test
// creates carries a run-specific label and is removed in a deferred
// cleanup, regardless of test outcome — it never touches a container or
// image it did not itself create.
package sensor_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

const integrationLabelKey = "kestrelynx.sensor-integration-test"

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not reachable")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(abs, "go.mod")); err != nil {
		t.Fatalf("repo root guess %s does not contain go.mod: %v", abs, err)
	}
	return abs
}

// dockerT runs docker with args, failing the test on error and returning
// trimmed stdout.
func dockerT(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// dockerBestEffort runs docker with args, logging (never failing) on error —
// used for cleanup, which must not abandon removing the rest of a run's
// resources just because one docker call failed.
func dockerBestEffort(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func TestSensorIntegration(t *testing.T) {
	requireDocker(t)
	root := repoRoot(t)
	runID := fmt.Sprintf("klsit%d", time.Now().UnixNano())
	imageTag := "kestrelynx-sensor-integration-test:" + runID

	t.Logf("building image %s (this can take a while the first time)", imageTag)
	dockerT(t, "build", "-t", imageTag, root)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)

	type target struct {
		name          string
		image         string
		cmd           []string
		wantExeSubstr string
		wantOSPackage bool
	}
	targets := []target{
		{name: "go-nopkgdb", image: "prom/node-exporter:latest", wantExeSubstr: "node_exporter"},
		{name: "node", image: "node:20-slim", cmd: []string{"node", "-e", "setInterval(()=>{},1000)"}, wantExeSubstr: "node"},
		{name: "python", image: "python:3.12-slim", cmd: []string{"python3", "-c", "import time; time.sleep(99999)"}, wantExeSubstr: "python3"},
		{name: "java", image: "eclipse-temurin:21-jdk", cmd: []string{"sh", "-c",
			"printf 'public class M{public static void main(String[] a) throws Exception{Thread.sleep(999999999L);}}' > /tmp/M.java && exec java /tmp/M.java"},
			wantExeSubstr: "java"},
		{name: "dpkg", image: "debian:12-slim", cmd: []string{"sleep", "99999"}, wantExeSubstr: "sleep", wantOSPackage: true},
		// Alpine's sleep is a busybox applet: /proc/<pid>/exe resolves to the
		// one real binary, /bin/busybox, not a "sleep"-named path.
		{name: "apk", image: "alpine:3.20", cmd: []string{"sleep", "99999"}, wantExeSubstr: "busybox", wantOSPackage: true},
		// Rocky Linux 9's sleep is likewise a symlink into the GNU coreutils
		// single-binary tool (/usr/bin/coreutils); the resolved exe path
		// never contains "sleep" either.
		{name: "rpm", image: "rockylinux:9", cmd: []string{"sleep", "99999"}, wantExeSubstr: "coreutils"},
	}

	containerIDs := map[string]string{}
	for _, tg := range targets {
		args := []string{"run", "-d", "--label", integrationLabelKey + "=" + runID, tg.image}
		args = append(args, tg.cmd...)
		id := dockerT(t, args...)
		containerIDs[tg.name] = id
	}
	defer cleanupIntegrationContainers(t, runID)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	seccompPath := filepath.Join(root, "deploy", "docker", "sensor-seccomp.json")
	if _, err := os.Stat(seccompPath); err != nil {
		t.Fatalf("distributed seccomp profile missing at %s: %v", seccompPath, err)
	}

	sensorArgs := []string{
		"run", "-d",
		"--label", integrationLabelKey + "=" + runID,
		"--entrypoint", "kestrelynx-sensor",
		"--user", "65532:65532",
		"--pid", "host",
		"--network", "none",
		"--cap-drop", "ALL",
		"--cap-add", "SYS_PTRACE",
		"--cap-add", "DAC_READ_SEARCH",
		"--cap-add", "BPF",
		"--cap-add", "PERFMON",
		"--security-opt", "seccomp=" + seccompPath,
		"--read-only",
		"-v", evidenceDir + ":/var/lib/kestrelynx-runtime",
		imageTag,
		// 10s is --interval's own minimum (see minSensorInterval in
		// cmd/kestrelynx/sensor.go) — the fastest this test can make the
		// daemon sample internally. The evidence file itself is only ever
		// written on its own fixed 60-second heartbeat (see loop's own doc
		// comment), independent of --interval, which is why
		// waitForGenerations' own timeout below has to allow for at least
		// one full heartbeat cycle, not just one sample interval.
		"sensor", "--interval", "10s", "--evidence-dir", "/var/lib/kestrelynx-runtime",
	}
	sensorID := dockerT(t, sensorArgs...)
	// Deferred in this order so they run in the opposite order (LIFO): the
	// logs are captured (for t.Log's benefit on failure) before the
	// container is removed, not after — fetching logs from an already-
	// removed container would always fail.
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, len(targets), 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for evidence: %v", err)
	}

	byContainer := map[string]evidence.Generation{}
	for _, g := range snap.Generations {
		byContainer[g.Container.ID] = g
	}

	for _, tg := range targets {
		id := containerIDs[tg.name]
		gen, ok := byContainer[id]
		if !ok {
			t.Errorf("%s: no generation recorded for container %s", tg.name, id)
			continue
		}
		var found bool
		var paths []string
		for _, e := range gen.Executables {
			paths = append(paths, e.Path)
			if strings.Contains(e.Path, tg.wantExeSubstr) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: executables = %v, want one containing %q", tg.name, paths, tg.wantExeSubstr)
		}
		if !tg.wantOSPackage {
			continue
		}
		// A generation existing (which byContainer/gen already confirm) says
		// nothing about whether its package-database index has finished
		// building and had a sample attribute against it yet — that happens
		// asynchronously, well after discovery first notices the container
		// (see generationState's own idxState/postIndexConfirmed doc
		// comments). Checking gen.OSPackages directly here, as an earlier
		// version of this test did, races that build; waitForPackageDBReady
		// instead polls until state=observing specifically confirms it.
		ready, err := waitForPackageDBReady(t, evidenceDir, id, 150*time.Second)
		if err != nil {
			t.Errorf("%s: %v", tg.name, err)
			continue
		}
		if len(ready.OSPackages) == 0 {
			t.Errorf("%s: os_packages is empty, want at least one (package_db=%+v, state=%v)", tg.name, ready.PackageDB, ready.State)
		}
	}
}

// waitForPackageDBReady polls the evidence file until containerID's own
// generation reaches state=observing — the one published state that
// actually promises its OSPackages reflect a complete, attributed build
// (idxState ready AND postIndexConfirmed; see derivePublishedState's own doc
// comment for the full priority order). A generation merely existing yet
// (waitForGenerations' own condition) says nothing about whether its
// package-database build has even started, let alone finished and had a
// sample's own candidates attributed against it — that is exactly the gap
// this function exists to wait out, rather than a caller racing it by
// reading OSPackages the moment a generation first appears.
func waitForPackageDBReady(t *testing.T, evidenceDir, containerID string, timeout time.Duration) (evidence.Generation, error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	r := evidence.NewReader(evidenceDir)
	var last evidence.Generation
	var found bool
	for {
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			if gens := generationsByContainer(snap)[containerID]; len(gens) > 0 {
				g := gens[len(gens)-1]
				last = g
				found = true
				if g.State == evidence.StateObserving {
					return g, nil
				}
			}
		}
		if time.Now().After(deadline) {
			if !found {
				return evidence.Generation{}, fmt.Errorf("no generation ever appeared for container %s while waiting for its package database", containerID)
			}
			return last, fmt.Errorf("container %s never reached state=observing (last state=%q, package_db=%+v)", containerID, last.State, last.PackageDB)
		}
		time.Sleep(2 * time.Second)
	}
}

// waitForGenerations polls the evidence file until it has at least want
// generations recorded, or timeout elapses.
func waitForGenerations(t *testing.T, evidenceDir string, want int, timeout time.Duration) (evidence.Snapshot, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r := evidence.NewReader(evidenceDir)
	var last evidence.Snapshot
	var lastErr error
	for {
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			last = snap
			if len(snap.Generations) >= want {
				return snap, nil
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return last, fmt.Errorf("timed out after %s waiting for %d generations (last error: %v, last snapshot had %d)",
				timeout, want, lastErr, len(last.Generations))
		case <-time.After(2 * time.Second):
		}
	}
}

// cleanupIntegrationContainers removes every container this test run
// created (matched by the run-specific label), regardless of test outcome.
func cleanupIntegrationContainers(t *testing.T, runID string) {
	t.Helper()
	ids := dockerBestEffortOutput(t, "ps", "-aq", "--filter", "label="+integrationLabelKey+"="+runID)
	for _, id := range strings.Fields(ids) {
		dockerBestEffort(t, "rm", "-f", id)
	}
}

func dockerBestEffortOutput(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Logf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		return ""
	}
	return string(out)
}

// dumpContainerLogsOnFailure writes id's own `docker logs` output via
// t.Logf, but only once t.Failed() is already true — used in place of an
// unconditional `dockerBestEffort(t, "logs", id)` call, which never actually
// surfaces a container's stdout/stderr at all (dockerBestEffort only logs on
// a non-zero exit from the docker CLI itself, not the content of a
// successful `docker logs`). label distinguishes which container id names in
// a test that starts more than one (e.g. "sensor" vs. "target"). Deferred
// immediately after a container starts, before its own removal — the same
// LIFO ordering every call site already relies on for a later
// `dockerBestEffort(t, "rm", "-f", id)` defer.
func dumpContainerLogsOnFailure(t *testing.T, label, id string) {
	t.Helper()
	if !t.Failed() {
		return
	}
	out, err := exec.Command("docker", "logs", id).CombinedOutput()
	if err != nil {
		t.Logf("%s container %s: docker logs failed: %v", label, id, err)
		return
	}
	t.Logf("%s container %s logs:\n%s", label, id, out)
}
