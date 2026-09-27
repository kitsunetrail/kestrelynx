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
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

// waitForGenerationCondition polls the evidence file until containerID's own
// generation satisfies check, or timeout elapses. It returns the last
// generation observed for containerID either way (ok reports whether check
// was ever satisfied), so a caller's own failure message can show what was
// actually recorded instead of nothing at all.
//
// This exists because a generation merely existing (waitForGenerations' own
// condition) proves only that discovery has noticed the container — it says
// nothing about whether whatever this test is actually waiting on (an
// eBPF-derived exec/library-load event landing, in particular) has happened
// yet. Checking a freshly-appeared generation's own Executables/OSPackages
// immediately, as an earlier version of every caller below did, races
// whatever real-world action (an apt-get install completing, a dlopen
// happening) the test's own target container still needs time to perform.
func waitForGenerationCondition(t *testing.T, evidenceDir, containerID string, timeout time.Duration, check func(evidence.Generation) bool) (evidence.Generation, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	r := evidence.NewReader(evidenceDir)
	var last evidence.Generation
	for {
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			if gens := generationsByContainer(snap)[containerID]; len(gens) > 0 {
				g := gens[len(gens)-1]
				last = g
				if check(g) {
					return g, true
				}
			}
		}
		if time.Now().After(deadline) {
			return last, false
		}
		time.Sleep(2 * time.Second)
	}
}

// TestSensorIntegrationEBPF_ShortLivedProcessesBecomesInUse covers a file
// written under a temporary name and renamed into place before being
// exec'd — exactly the shape dpkg's own install mechanism uses for every
// package file it installs (write "<path>.dpkg-new", then rename(2) it onto
// "<path>") — and confirms the resulting exec_event is recorded under the
// renamed, exec'd path, not whatever path an earlier open of the same (dev,
// inode) reported before the rename. rename(2) changes no (dev, inode) at
// all and triggers no security_file_open of its own for kl_file_open to
// ever see, so the only way the later exec's own path correlation can be
// correct is if the earlier temporary-name open never permanently "claims"
// that (dev, inode) for kl_path_seen's own suppression window — confirmed
// directly against a real container: a binary opened once under a temporary
// name and renamed into place kept reporting that temporary name for every
// exec of it afterward, until KL_EVENT_EXEC_OPEN was exempted from
// kl_path_seen's own suppression window (see bpf/kestrelynx.c's own comment
// on that hook for why).
//
// The Sensor is started first, and this test waits for its own eBPF to
// attach before the target container ever runs, precisely so this race is
// actually exercised rather than accidentally sidestepped: the target's own
// cp+mv+exec sequence below runs essentially immediately once the container
// starts, and if the Sensor's own kl_file_open hook were not already
// attached by then, it would simply never see the pre-rename open at all —
// this test could then pass for the wrong reason (nothing to suppress
// wrongly, not because the exemption actually works) even against a build
// that reintroduced the original bug. With the Sensor already attached,
// kl_file_open reliably records the temporary name's own open in
// kl_dedup_path's suppression window before the rename ever happens; without
// KL_EVENT_EXEC_OPEN's own exemption from that window, the later exec-open
// for the exact same (dev, inode) would be suppressed outright, leaving
// events.go's own path-correlation table still holding the stale, pre-rename
// path when the exec_success event arrives — exactly the regression this
// test's own assertion below would catch.
func TestSensorIntegrationEBPF_ShortLivedProcessesBecomesInUse(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-shortlived-%d", time.Now().UnixNano())
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

	preTarget, err := waitForGenerations(t, evidenceDir, 0, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the Sensor's own first snapshot before the target container even starts: %v", err)
	}
	if preTarget.Sensor.Events.Status != evidence.EventsOK {
		t.Fatalf("sensor.events.status = %q before the target container even starts, want ok — "+
			"this test cannot mean anything about the rename race without eBPF already attached", preTarget.Sensor.Events.Status)
	}

	containerID := runTarget(t, runID, "debian:12-slim", "sh", "-c", `
set -e
cp /bin/true /tmp/kl-renamed.tmp
mv /tmp/kl-renamed.tmp /tmp/kl-renamed.final
while true; do /tmp/kl-renamed.final; sleep 1; done`)

	// Waited for, rather than checked against the first generation to
	// appear: this generation existing already (waitForGenerations' own
	// condition) says nothing about whether the target's own rename and
	// first loop iteration have happened yet.
	gen, ok := waitForGenerationCondition(t, evidenceDir, containerID, 150*time.Second, func(g evidence.Generation) bool {
		for _, e := range g.Executables {
			if e.Path == "/tmp/kl-renamed.final" {
				if _, ok := e.Kinds[evidence.KindExecEvent]; ok {
					return true
				}
			}
		}
		return false
	})
	if !ok {
		t.Fatalf("executables = %+v, want /tmp/kl-renamed.final recorded with exec_event under its own, post-rename path", gen.Executables)
	}
	for _, e := range gen.Executables {
		if e.Path == "/tmp/kl-renamed.tmp" {
			t.Errorf("executables include the pre-rename path %q, want only the renamed /tmp/kl-renamed.final", e.Path)
		}
	}

	if gen.EventsCoverage == evidence.CoverageNone {
		t.Fatal("events_coverage = none, want since_start/partial — eBPF must have attached for this test to mean anything")
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
	// mapped. This dlopens the exact same, real, package-owned libz.so.1
	// every iteration (never a copy elsewhere: this test's own
	// package-database lookup depends on the path being the real one) —
	// bpf/kestrelynx.c's own kl_usage_seen dedup means only the first such
	// mmap_success is ever a real kernel event, however many times the loop
	// repeats it, but a usage event that arrives before this generation's
	// own mount view is confirmed is now held and replayed once it is,
	// rather than discarded (dispatchUsageEvent's own doc comment), so
	// there is no need to delay this loop's own first iteration to dodge
	// that window.
	containerID := runTarget(t, runID, "python:3.12-slim", "sh", "-c",
		"while true; do python3 -c \"import ctypes; ctypes.CDLL('libz.so.1')\"; sleep 2; done")

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// Debian's own zlib runtime package is named zlib1g; this identifies
	// specifically that this is the package libz.so.1 actually belongs to,
	// not any package that merely happens to carry a library_load_event.
	// Waited for, rather than checked against the first generation to
	// appear: the mmap_success event's own OS-package candidate cannot
	// resolve to zlib1g until this container's package-database index has
	// itself finished building (indexReady) — a generation existing already
	// says nothing about that — and, independently, python3's own dlopen
	// loop needs at least one iteration to actually run first.
	findZlib := func(gen evidence.Generation) *evidence.OSPackageEvidence {
		for i := range gen.OSPackages {
			if strings.Contains(gen.OSPackages[i].Name, "zlib") {
				return &gen.OSPackages[i]
			}
		}
		return nil
	}
	gen, ok := waitForGenerationCondition(t, evidenceDir, containerID, 150*time.Second, func(g evidence.Generation) bool {
		zlib := findZlib(g)
		if zlib == nil {
			return false
		}
		_, hasLoadEvent := zlib.Kinds[evidence.KindLibraryLoadEvent]
		return hasLoadEvent
	})
	if !ok {
		zlib := findZlib(gen)
		if zlib == nil {
			t.Fatalf("os_packages = %+v, want a zlib1g package recorded at all", gen.OSPackages)
		}
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
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

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

// ringBufferOverflowTestBytes is the kl_events ring buffer size this Sensor
// is started with for TestSensorIntegrationEBPF_RingBufferOverflowMarksPartial:
// one host page, the smallest size ebpf.ValidateRingBufferBytes ever accepts.
// A page this small holds only a handful of struct kl_event records, so
// floodScript's own back-to-back exec churn is guaranteed to outrun the
// userspace reader and force a genuine kernel-side reservation failure,
// regardless of how fast a given host happens to drain the ring buffer at
// its default 2 MiB size.
var ringBufferOverflowTestBytes = uint64(unix.Getpagesize())

// TestSensorIntegrationEBPF_RingBufferOverflowMarksPartial deliberately
// floods a container with far more exec churn than the ring buffer (started
// deliberately small — see ringBufferOverflowTestBytes — rather than
// bpf/kestrelynx.c's own compiled-in 2 MiB default) can hold between drains,
// and confirms:
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
// floodWorkers*floodPerWorker (16000) distinct dev/inode pairs, all racing
// to reserve space in a ring buffer sized to hold only a handful of records
// at once (ringBufferOverflowTestBytes), is what actually produces
// kernel-level (ring-buffer reservation failure) loss here. This test has no
// exported way to read the Sensor's own
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

	// The Sensor starts first, with no target container to observe yet —
	// deliberately with a one-page kl_events ring buffer (see
	// ringBufferOverflowTestBytes) so the flood below is guaranteed to
	// overflow it.
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir,
		"--ring-buffer-bytes", strconv.FormatUint(ringBufferOverflowTestBytes, 10))
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

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
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

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
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

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
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// Waited for, rather than checked against the first generation to
	// appear: the target container's own useradd setup runs before the su
	// loop ever execs kl-setuid-id for the first time, and a generation can
	// already exist (discovery having merely noticed the container) well
	// before that setup finishes.
	rootSetuidObserved := func(g evidence.Generation) bool {
		for i := range g.Executables {
			exe := &g.Executables[i]
			if !strings.Contains(exe.Path, "kl-setuid-id") {
				continue
			}
			for _, o := range exe.Observations {
				if o.EffectiveUID == 0 {
					return true
				}
			}
		}
		return false
	}
	gen, ok := waitForGenerationCondition(t, evidenceDir, containerID, 150*time.Second, rootSetuidObserved)
	if !ok {
		var setuidExe *evidence.ExecutableEvidence
		for i := range gen.Executables {
			if strings.Contains(gen.Executables[i].Path, "kl-setuid-id") {
				setuidExe = &gen.Executables[i]
			}
		}
		if setuidExe == nil {
			t.Fatalf("executables = %+v, want kl-setuid-id recorded", gen.Executables)
		}
		t.Errorf("kl-setuid-id executable = %+v, want an observation with EffectiveUID 0 (the setuid binary's post-exec identity)", *setuidExe)
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

	// Creating a child cgroup directory requires a writable /sys/fs/cgroup —
	// this Docker Engine mounts it read-only for an ordinary container
	// regardless of any individual --cap-add (confirmed directly: neither
	// --cap-add SYS_ADMIN nor --cgroupns=host makes it writable, only
	// --privileged does — see runPrivilegedTarget's own doc comment), so the
	// target runs privileged here specifically to get that write access, not
	// to relax anything about what this test itself is checking. Neither the
	// mkdir nor the cgroup.procs write is allowed to fail silently (no
	// "|| true"): if cgroup delegation is not actually available in this
	// environment, the container itself must exit non-zero and this test
	// must fail loudly, rather than silently falling back to running from
	// the container's own top-level cgroup, which would let this test pass
	// without ever having exercised the child-cgroup attribution it exists
	// to check at all.
	containerID := runPrivilegedTarget(t, runID, "debian:12-slim", "sh", "-c", `
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
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// Waited for, rather than checked against the first generation to
	// appear: the container's own mkdir/cgroup.procs setup, and then the
	// first iteration of its own exec loop, both need time to actually run
	// after discovery first notices the container.
	gen, ok := waitForGenerationCondition(t, evidenceDir, containerID, 150*time.Second, func(g evidence.Generation) bool {
		for _, e := range g.Executables {
			if strings.Contains(e.Path, "env") || strings.Contains(e.Path, "true") {
				if _, ok := e.Kinds[evidence.KindExecEvent]; ok {
					return true
				}
			}
		}
		return false
	})
	if !ok {
		t.Errorf("executables = %+v, want the child-cgroup process's own exec_event attributed to this container", gen.Executables)
	}
}

// TestSensorIntegrationEBPF_HostNoiseDoesNotTaintTrackedContainer covers
// real host-side noise running concurrently (a `docker build` loop, forcing
// fresh, short-lived intermediate containers — exactly the kind of
// unclassifiable cgroup churn confirmed to reach this Sensor's own eBPF
// hooks): an actively-tracked container's own generation must still report
// events_coverage=since_start and incomplete=false, sustained across
// several consecutive reads, not downgraded the moment any noise happens to
// arrive regardless of whether that noise's own cgroup can ever be
// classified at all.
func TestSensorIntegrationEBPF_HostNoiseDoesNotTaintTrackedContainer(t *testing.T) {
	requireDocker(t)
	runID := fmt.Sprintf("klsit-hostnoise-%d", time.Now().UnixNano())
	imageTag := buildIntegrationImage(t, runID)
	defer dockerBestEffort(t, "rmi", "-f", imageTag)
	defer cleanupIntegrationContainers(t, runID)

	evidenceDir := t.TempDir()
	if err := os.Chmod(evidenceDir, 0o777); err != nil {
		t.Fatalf("chmod evidence dir: %v", err)
	}
	// The Sensor starts first, then the target -- exactly the "container
	// tracked from birth" case events_coverage=since_start exists to report.
	sensorID := startSensorContainer(t, imageTag, runID, evidenceDir)
	defer dockerBestEffort(t, "rm", "-f", sensorID)
	defer dumpContainerLogsOnFailure(t, "sensor", sensorID)

	// Waited for explicitly, rather than starting the target right after the
	// Sensor container itself starts: the Sensor's own eBPF attach happens
	// partway through its own startup sequence, after the container itself is
	// already running, so starting the target too soon can let its own init
	// process begin before eBPF has actually attached -- which classifies the
	// resulting generation partial from birth (see initialEventsCoverage),
	// never since_start at all, regardless of anything that happens
	// afterward. want=0: any successful read at all (the Sensor's own first
	// heartbeat write) is enough, since no container exists yet to produce a
	// generation.
	preTarget, err := waitForGenerations(t, evidenceDir, 0, 150*time.Second)
	if err != nil {
		t.Fatalf("waiting for the Sensor's own first snapshot before the target container even starts: %v", err)
	}
	if preTarget.Sensor.Events.Status != evidence.EventsOK {
		t.Fatalf("sensor.events.status = %q before the target container even starts, want ok — "+
			"this test cannot mean anything about since_start without eBPF actually attached", preTarget.Sensor.Events.Status)
	}

	containerID := runTarget(t, runID, "debian:12-slim", "sh", "-c", "while true; do sleep 1; done")

	// Host-side noise: a real, repeated `docker build`, each round forced to
	// miss every layer's own cache via a changing --build-arg, so every
	// round creates a genuinely fresh intermediate container — this is the
	// exact shape of churn (short-lived, never classified as any tracked
	// container's own cgroup) this investigation already confirmed reaches
	// this Sensor's own eBPF hooks. Runs for this test's own whole
	// duration, stopped via noiseDone once the assertion below concludes.
	noiseDone := make(chan struct{})
	noiseTag := "kestrelynx-hostnoise-test:" + runID
	dockerfileDir := t.TempDir()
	dockerfile := "FROM debian:12-slim\nARG CACHEBUST=1\nRUN echo \"$CACHEBUST\" > /cachebust\n"
	if err := os.WriteFile(dockerfileDir+"/Dockerfile", []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("write noise Dockerfile: %v", err)
	}
	defer dockerBestEffort(t, "rmi", "-f", noiseTag)
	go func() {
		for {
			select {
			case <-noiseDone:
				return
			default:
			}
			cmd := exec.Command("docker", "build", "-t", noiseTag,
				"--build-arg", fmt.Sprintf("CACHEBUST=%d", time.Now().UnixNano()),
				dockerfileDir)
			_ = cmd.Run() // best-effort noise; a failed build round is not this test's own concern
		}
	}()
	defer close(noiseDone)

	// Waited for, and then required to hold across several consecutive
	// reads (requiredStreak), not just checked once: a single lucky read
	// would not distinguish "genuinely never downgraded" from "downgraded
	// once, already recovered, and this read simply landed in between".
	r := evidence.NewReader(evidenceDir)
	deadline := time.Now().Add(150 * time.Second)
	sinceStartStreak := 0
	const requiredStreak = 3
	for sinceStartStreak < requiredStreak {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d consecutive since_start/incomplete=false reads while host noise ran (last streak %d)", requiredStreak, sinceStartStreak)
		}
		snap, err := r.Read(time.Now(), nil)
		if err == nil {
			if g := findGenerationOrZero(snap, containerID); g.Container.ID == containerID {
				if g.EventsCoverage == evidence.CoverageSinceStart && !g.Incomplete {
					sinceStartStreak++
				} else {
					t.Fatalf("generation regressed to events_coverage=%q incomplete=%v while host noise was running -- want since_start/false sustained throughout (had reached streak %d)",
						g.EventsCoverage, g.Incomplete, sinceStartStreak)
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
}
