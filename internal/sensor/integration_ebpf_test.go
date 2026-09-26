//go:build integration

// eBPF-specific real-Docker scenarios, on top of integration_test.go's own
// multi-workload pass and integration_extra_test.go's own container-churn
// scenarios: short-lived processes and dlopen'd libraries observed only
// through events (never through procfs sampling, since they are gone
// before any sample could see them), the Sensor's own package-database
// reads never leaking into the evidence it writes, ring-buffer overflow
// downgrading events_coverage to partial, running with eBPF unavailable
// degrading to sampling-only, a failed exec/mmap never becoming "in use", a
// setuid exec's post-exec privilege being what gets recorded, and a child
// cgroup's events attributing to its ancestor container. A container so
// short-lived that a discovery pass never once registers a generation for
// it at all is out of this stage's own scope (the main body does not scan
// such a container's own image either) and is not covered here. Same build
// tag, same helpers as integration_test.go/integration_extra_test.go.
//
// Run with:
//
//	go test -tags=integration -run TestSensorIntegrationEBPF -v -timeout 40m \
//	  ./internal/sensor/...
package sensor_test

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// findGeneration returns the one generation in snap matching containerID,
// failing the test if there is none.
func findGeneration(t *testing.T, snap evidence.Snapshot, containerID string) evidence.Generation {
	t.Helper()
	for _, g := range snap.Generations {
		if g.Container.ID == containerID {
			return g
		}
	}
	t.Fatalf("no generation recorded for container %s", containerID)
	return evidence.Generation{}
}

// TestSensorIntegrationEBPF_ShortLivedProcessesBecomeInUseViaEvents covers
// this stage's own headline completion condition: a container whose only
// OS-package activity is a short-lived curl/git-style exec (gone long
// before any 10s sample could ever observe it in /proc) must still show
// that package in_use, evidenced by exec_event, once eBPF is attached.
func TestSensorIntegrationEBPF_ShortLivedProcessesBecomesInUse(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-shortlived-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	// A container that stays alive (so a generation exists to attribute
	// against) but only ever *exec*s curl and git in short bursts, never
	// running either as its own long-lived process.
	containerID := runTarget(t, runID, "debian:12-slim", "sh", "-c",
		"apt-get update >/dev/null 2>&1; apt-get install -y --no-install-recommends curl git >/dev/null 2>&1; "+
			"while true; do curl --version >/dev/null 2>&1; git --version >/dev/null 2>&1; sleep 1; done")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	// Generous timeout: the target container's own apt-get install has to
	// finish before curl/git even exist to exec.
	snap, err := waitForGenerations(t, evidenceDir, 1, 5*time.Minute)
	if err != nil {
		t.Fatalf("waiting for evidence: %v", err)
	}
	gen := findGeneration(t, snap, containerID)

	if gen.EventsCoverage == evidence.CoverageNone {
		t.Fatal("events_coverage = none, want since_start/partial — eBPF must have attached for this test to mean anything")
	}

	sawCurl, sawGit := false, false
	for _, e := range gen.Executables {
		if strings.Contains(e.Path, "curl") {
			if _, ok := e.Kinds[evidence.KindExecEvent]; ok {
				sawCurl = true
			}
		}
		if strings.Contains(e.Path, "git") {
			if _, ok := e.Kinds[evidence.KindExecEvent]; ok {
				sawGit = true
			}
		}
	}
	if !sawCurl || !sawGit {
		t.Errorf("executables = %+v, want curl and git both recorded with exec_event", gen.Executables)
	}
}

// TestSensorIntegrationEBPF_DlopenedLibraryBecomesInUse covers a runtime
// dlopen (never a static /proc/<pid>/maps entry visible to sampling if the
// dlopen+dlclose cycle completes between samples): the loaded library's
// mmap_success event must still surface it as in_use (library_load_event) —
// and specifically the package that owns libz, not merely "some package or
// other" with that kind, which could just as easily be an unrelated library
// the interpreter itself maps on every startup regardless of this test's
// own dlopen call.
func TestSensorIntegrationEBPF_DlopenedLibraryBecomesInUse(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-dlopen-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	// python3's ctypes.CDLL both dlopen()s and (implicitly, on interpreter
	// exit) dlclose()s libz — a mapping sampling alone would only catch by
	// coincidence if a sample landed during the brief window it stayed
	// mapped.
	containerID := runTarget(t, runID, "python:3.12-slim", "sh", "-c",
		"while true; do python3 -c \"import ctypes; ctypes.CDLL('libz.so.1')\"; sleep 2; done")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for evidence: %v", err)
	}
	gen := findGeneration(t, snap, containerID)

	// Debian's own zlib runtime package is named zlib1g; this identifies
	// specifically that this is the package libz.so.1 actually belongs to,
	// not any package that merely happens to carry a library_load_event.
	var zlib *evidence.OSPackageEvidence
	for i := range gen.OSPackages {
		if strings.Contains(gen.OSPackages[i].Name, "zlib") {
			zlib = &gen.OSPackages[i]
		}
	}
	if zlib == nil {
		t.Fatalf("os_packages = %+v, want a zlib1g package recorded at all", gen.OSPackages)
	}
	if _, ok := zlib.Kinds[evidence.KindLibraryLoadEvent]; !ok {
		t.Errorf("zlib package = %+v, want library_load_event recorded for it specifically", zlib)
	}
}

// TestSensorIntegrationEBPF_SensorOwnReadsNeverAppearInEvidence confirms the
// self-exclusion map (bpf/kestrelynx.c's kl_excluded_cgroup) actually works
// end to end: the Sensor's own repeated opens of every observed container's
// package database must never themselves surface as an executable or
// package entry anywhere in the evidence file — the collector's own reads
// of a container's files must never be mistaken for that container's own
// activity.
func TestSensorIntegrationEBPF_SensorOwnReadsNeverAppearInEvidence(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-selfexclude-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	containerID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for evidence: %v", err)
	}
	for _, g := range snap.Generations {
		if g.Container.ID == containerID {
			continue // the only container this Sensor is meant to observe
		}
		t.Errorf("unexpected generation recorded: %+v (want only the target container, never the Sensor's own)", g)
	}
	// The Sensor's own kestrelynx binary/entrypoint must never show up as an
	// executable of the target container either.
	gen := findGeneration(t, snap, containerID)
	for _, e := range gen.Executables {
		if strings.Contains(e.Path, "kestrelynx") {
			t.Errorf("target container's own executables include %q — the Sensor's own process leaked into this container's evidence", e.Path)
		}
	}
}

// floodScript execs floodPerWorker*floodWorkers freshly-copied, distinct
// executables (a fresh inode each) across floodWorkers parallel shells,
// every one of them exactly once, without ever slowing down to let the
// Sensor drain in between. A repeated exec of the same three binaries would
// not actually stress the ring buffer at all: bpf/kestrelynx.c's own
// kl_usage_seen suppresses every repeat of an already-successfully-sent
// (cgroup, mount namespace, dev, inode, kind, privilege class) tuple before
// a reservation is even attempted, so the same file execed in a tight loop
// only ever produces one real event per 10-minute window, however fast the
// loop spins — distinct dev/inode per iteration is what actually forces
// distinct reservation attempts, and therefore genuine ring-buffer
// (kernel-level) loss rather than any Sensor-side (userspace-level)
// bookkeeping limit.
const (
	floodWorkers   = 8
	floodPerWorker = 2000
)

var floodScript = fmt.Sprintf(`
set -e
mkdir -p /tmp/flood
for w in $(seq 1 %[1]d); do
  (
    i=0
    while [ $i -lt %[2]d ]; do
      cp /bin/true "/tmp/flood/w${w}-${i}"
      chmod +x "/tmp/flood/w${w}-${i}"
      "/tmp/flood/w${w}-${i}"
      i=$((i+1))
    done
  ) &
done
wait`, floodWorkers, floodPerWorker)

// TestSensorIntegrationEBPF_RingBufferOverflowMarksPartial deliberately
// floods a container with far more exec churn than the ring buffer (2 MiB,
// bpf/kestrelynx.c's kl_events) can hold between drains, and confirms:
//
//  1. the target container is registered since_start (eBPF was already
//     attached before it even started, since the Sensor is started first
//     here — see below);
//  2. once flooded, its own events_coverage downgrades to partial and
//     events_lost advances — never silently staying since_start once real
//     loss has occurred.
//
// The Sensor is started *before* the target container even exists, and this
// test waits for the Sensor's own first snapshot (evidence.NewReader can
// read a valid, generation-less snapshot the moment the first heartbeat
// write happens) to confirm events.status is already ok before the target
// is started at all — this is what lets step 1 mean something: a target
// started only after eBPF is already attached is exactly the since_start
// case initialEventsCoverage exists to report. The flood itself is only
// triggered afterward, via `docker exec` into the by-then-already-running
// target, once its own since_start generation is confirmed.
//
// floodWorkers*floodPerWorker (16000) distinct dev/inode pairs, well over
// twice the 2 MiB ring buffer's own few-thousand-record capacity, is what
// actually produces kernel-level (ring-buffer reservation failure) loss
// here. This test has no exported way to read the Sensor's own
// kl_lost_events/kl_lost_by_cgroup BPF maps directly (the Sensor runs as a
// separate process in a separate container) and the evidence file's own
// events_lost is deliberately a single blended total (kernel-side and
// Sensor-side losses both, see buildSnapshot's own doc comment) — so this
// test instead reads reconcileEventLossCounters' own stderr log line
// (readKernelLossFromLogs, via `docker logs`), which reports those same two
// kernel counters' own current values whenever either one changes, and
// requires them to have actually increased around the flood, not just
// events_lost.
func TestSensorIntegrationEBPF_RingBufferOverflowMarksPartial(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-overflow-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}

	// The Sensor starts first, with no target container to observe yet.
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	// want=0: any successful read at all (the Sensor's own first heartbeat
	// write) is enough, since no container exists yet to produce a
	// generation.
	preTarget, err := waitForGenerations(t, evidenceDir, 0, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the Sensor's own first snapshot before the target container even starts: %v", err)
	}
	if preTarget.Sensor.Events.Status != evidence.EventsOK {
		t.Fatalf("sensor.events.status = %q before the target container even starts, want ok — "+
			"this test cannot mean anything about since_start or ring-buffer loss without eBPF actually attached", preTarget.Sensor.Events.Status)
	}

	// Only now does the target container start — eBPF was already attached
	// before it existed at all.
	containerID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")

	sinceStart, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the target's own first generation: %v", err)
	}
	gen := findGeneration(t, sinceStart, containerID)
	if gen.EventsCoverage != evidence.CoverageSinceStart {
		t.Fatalf("events_coverage = %q immediately after discovery, want since_start (eBPF attached before this container even started)", gen.EventsCoverage)
	}

	// The kernel's own loss counters (kl_lost_events/kl_lost_by_cgroup) as of
	// right before the flood — read from this Sensor's own stderr (see
	// reconcileEventLossCounters' own doc comment on why this log line is
	// the only way this test, running as a separate process with no access
	// to this Sensor's own BPF maps, can distinguish a kernel-level
	// reservation failure from a userspace-level one at all).
	kernelBefore, _ := readKernelLossFromLogs(t, sensorID)

	// Only now, with since_start confirmed, does the flood itself start —
	// synchronously, inside the already-running target container.
	dockerT(t, "exec", containerID, "sh", "-c", floodScript)

	deadline := time.After(150 * time.Second)
	r := evidence.NewReader(evidenceDir)
	coveragePartial := false
	for !coveragePartial {
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			if g := findGenerationOrZero(snap, containerID); g.EventsCoverage == evidence.CoveragePartial {
				if g.EventsLost == 0 {
					t.Fatal("events_coverage = partial but events_lost = 0, want > 0 once coverage reports partial")
				}
				coveragePartial = true
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for events_coverage to downgrade to partial after the flood — " +
				"if this genuinely never lost a single event on this host, the flood needs to be heavier, not the assertion weaker")
		case <-time.After(2 * time.Second):
		}
	}

	// Confirm the kernel's own counters actually increased — not merely
	// events_lost (which also counts Sensor-side/userspace losses; see
	// reconcileEventLossCounters' own doc comment) — so this test verifies
	// genuine ring-buffer loss, not just that *some* loss of *some* kind was
	// recorded.
	kernelAfter, ok := readKernelLossFromLogs(t, sensorID)
	if !ok {
		t.Fatal("this Sensor's own stderr never logged its kernel loss counters at all — " +
			"cannot confirm the loss just observed is kernel-level rather than Sensor-side; " +
			"see reconcileEventLossCounters' own logging (ASSUMED: this test cannot verify the kernel counters directly)")
	}
	if kernelAfter.byCgroupTotal <= kernelBefore.byCgroupTotal && kernelAfter.fallback <= kernelBefore.fallback {
		t.Fatalf("kernel loss counters did not increase (before=%+v after=%+v) despite events_coverage reporting partial — "+
			"the loss just observed may be entirely Sensor-side (userspace), not the ring-buffer overflow this test exists to force",
			kernelBefore, kernelAfter)
	}
}

// kernelLossCounters is one reading of reconcileEventLossCounters' own
// stderr log line (events.go), as this test's own external observer of it.
type kernelLossCounters struct {
	byCgroupTotal uint64
	fallback      uint64
}

// kernelLossLogPattern matches reconcileEventLossCounters' own log line
// ("kestrelynx sensor: ebpf kernel loss counters: by_cgroup_total=%d fallback=%d").
var kernelLossLogPattern = regexp.MustCompile(`ebpf kernel loss counters: by_cgroup_total=(\d+) fallback=(\d+)`)

// readKernelLossFromLogs reads sensorID's own container logs and returns the
// *last* (most recent) kernel loss counter reading logged so far, or
// ok=false if this Sensor has never logged one at all (e.g. it has not lost
// a single kernel-side event yet — see reconcileEventLossCounters' own doc
// comment on why it only logs on a change).
func readKernelLossFromLogs(t *testing.T, sensorID string) (kernelLossCounters, bool) {
	t.Helper()
	logs := dockerBestEffortOutput(t, "logs", sensorID)
	matches := kernelLossLogPattern.FindAllStringSubmatch(logs, -1)
	if len(matches) == 0 {
		return kernelLossCounters{}, false
	}
	last := matches[len(matches)-1]
	byCgroupTotal, err1 := strconv.ParseUint(last[1], 10, 64)
	fallback, err2 := strconv.ParseUint(last[2], 10, 64)
	if err1 != nil || err2 != nil {
		t.Fatalf("parsing kernel loss log line %q: %v / %v", last[0], err1, err2)
	}
	return kernelLossCounters{byCgroupTotal: byCgroupTotal, fallback: fallback}, true
}

// findGenerationOrZero is findGeneration without failing the test when
// containerID is not (yet) present — used by a polling loop that expects to
// see a miss on its own early iterations.
func findGenerationOrZero(snap evidence.Snapshot, containerID string) evidence.Generation {
	for _, g := range snap.Generations {
		if g.Container.ID == containerID {
			return g
		}
	}
	return evidence.Generation{}
}

// TestSensorIntegrationEBPF_UnavailableDegradesToSamplingOnly starts the
// Sensor without cap_add BPF/PERFMON (the file-capability exec itself still
// succeeds — file capabilities are +p on the binary regardless of cap_add —
// but raising CAP_BPF/CAP_PERFMON effective, and therefore attaching eBPF,
// fails): the daemon must still start, self-check must not fail, and
// ordinary procfs sampling must continue to produce generations, just with
// events.status unavailable/permission and events_coverage none.
func TestSensorIntegrationEBPF_UnavailableDegradesToSamplingOnly(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-nobpf-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	containerID := runTarget(t, runID, "debian:12-slim", "sleep", "99999")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	args := []string{
		"run", "-d",
		"--label", integrationLabelKey + "=" + runID,
		"--entrypoint", "kestrelynx-sensor",
		"--user", "65532:65532",
		"--pid", "host",
		"--network", "none",
		"--cap-drop", "ALL",
		"--cap-add", "SYS_PTRACE",
		"--cap-add", "DAC_READ_SEARCH",
		// Deliberately no BPF/PERFMON cap_add: this is the whole point of
		// this test.
		"--security-opt", "seccomp=" + distributedSeccompPath(t),
		"--read-only",
		"-v", evidenceDir + ":/var/lib/kestrelynx-runtime",
		imageTag,
		"sensor", "--interval", "10s", "--evidence-dir", "/var/lib/kestrelynx-runtime",
	}
	sensorID := dockerT(t, args...)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for evidence (sampling-only must still work without eBPF): %v", err)
	}
	if snap.Sensor.Events.Status != evidence.EventsUnavailable {
		t.Errorf("sensor.events.status = %q, want unavailable", snap.Sensor.Events.Status)
	}
	if snap.Sensor.Status == evidence.SensorIsolationFailed {
		t.Error("sensor.status = isolation_failed — missing BPF/PERFMON must degrade eBPF only, never fail the whole self-check")
	}
	gen := findGeneration(t, snap, containerID)
	if gen.EventsCoverage != evidence.CoverageNone {
		t.Errorf("events_coverage = %q, want none", gen.EventsCoverage)
	}
	if len(gen.Executables) == 0 {
		t.Error("no executables recorded — sampling itself must still work with eBPF unavailable")
	}
}

// TestSensorIntegrationEBPF_FailedExecNeverBecomesInUse execs a shebang
// naming a nonexistent interpreter, and a real, existing file with the
// execute bit cleared: sched_process_exec never fires for either, so
// neither must ever contribute an exec_event.
func TestSensorIntegrationEBPF_FailedExecNeverBecomesInUse(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-failexec-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	containerID := runTarget(t, runID, "debian:12-slim", "sh", "-c", `
set -e
printf '#!/no/such/interpreter\n' > /tmp/kl-bad-shebang
chmod +x /tmp/kl-bad-shebang
while true; do /tmp/kl-bad-shebang || true; sleep 1; done`)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for evidence: %v", err)
	}
	gen := findGeneration(t, snap, containerID)
	for _, e := range gen.Executables {
		if strings.Contains(e.Path, "kl-bad-shebang") {
			t.Errorf("executables include %q, want a failed exec (bad interpreter) to never appear", e.Path)
		}
	}
}

// TestSensorIntegrationEBPF_SetuidExecRecordsPostExecPrivilege execs a
// setuid-root helper from an unprivileged shell and confirms the recorded
// observation's own EffectiveUID is 0 (the post-exec, post-setuid identity
// sched_process_exec fires with — see bpf/kestrelynx.c's own comment on
// begin_new_exec), not the unprivileged caller's UID.
func TestSensorIntegrationEBPF_SetuidExecRecordsPostExecPrivilege(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-setuid-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	containerID := runTarget(t, runID, "debian:12-slim", "sh", "-c", `
set -e
cp /usr/bin/id /tmp/kl-setuid-id
chown root:root /tmp/kl-setuid-id
chmod 4755 /tmp/kl-setuid-id
useradd -m klunpriv
while true; do su -s /bin/sh klunpriv -c /tmp/kl-setuid-id; sleep 1; done`)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for evidence: %v", err)
	}
	gen := findGeneration(t, snap, containerID)

	var exe *evidence.ExecutableEvidence
	for i := range gen.Executables {
		if strings.Contains(gen.Executables[i].Path, "kl-setuid-id") {
			exe = &gen.Executables[i]
		}
	}
	if exe == nil {
		t.Fatalf("executables = %+v, want kl-setuid-id recorded", gen.Executables)
	}
	sawRoot := false
	for _, o := range exe.Observations {
		if o.EffectiveUID == 0 {
			sawRoot = true
		}
	}
	if !sawRoot {
		t.Errorf("observations = %+v, want at least one with EffectiveUID 0 (the setuid binary's post-exec identity)", exe.Observations)
	}
}

// TestSensorIntegrationEBPF_ChildCgroupAttributesToAncestorContainer runs a
// process inside the target container that creates and moves itself into
// its own nested cgroup (simulating a container that runs its own cgroup-
// aware supervisor, e.g. a systemd-inside-container setup) and confirms its
// own exec activity still attributes to the outer container, not nowhere.
func TestSensorIntegrationEBPF_ChildCgroupAttributesToAncestorContainer(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-childcgroup-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	// Requires the container's own cgroup namespace to allow creating a
	// child directory under its own cgroup2 mount (true for Docker's
	// default cgroup namespacing on a cgroup v2 host) — mkdir a child
	// cgroup, move this shell into it, then keep execing. Neither step is
	// allowed to fail silently (no "|| true"): if cgroup delegation is not
	// actually available in this environment, the container itself must
	// exit non-zero and this test must fail loudly, rather than silently
	// falling back to running from the container's own top-level cgroup,
	// which would let this test pass without ever having exercised the
	// child-cgroup attribution it exists to check at all.
	containerID := runTarget(t, runID, "debian:12-slim", "sh", "-c", `
set -e
mkdir /sys/fs/cgroup/kl-child
echo $$ > /sys/fs/cgroup/kl-child/cgroup.procs
while true; do /usr/bin/env true; sleep 1; done`)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dockerBestEffort(t, "logs", sensorID)

	snap, err := waitForGenerations(t, evidenceDir, 1, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for evidence: %v", err)
	}
	gen := findGeneration(t, snap, containerID)
	found := false
	for _, e := range gen.Executables {
		if strings.Contains(e.Path, "env") || strings.Contains(e.Path, "true") {
			if _, ok := e.Kinds[evidence.KindExecEvent]; ok {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("executables = %+v, want the child-cgroup process's own exec_event attributed to this container", gen.Executables)
	}
}
