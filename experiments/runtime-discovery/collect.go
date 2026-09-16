package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// defaultPSArgs deliberately does not request "args": the product's data
// handling stance does not collect command-line arguments by default.
const defaultPSArgs = "-eo pid,ppid,user"

func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	socket := fs.String("socket", "/var/run/docker.sock", "Docker Engine API UNIX socket path")
	containersFlag := fs.String("containers", "", "comma-separated container IDs or names to observe (default: all running containers)")
	caseVariant := fs.String("case-variant", "", "run_key case_variant, e.g. 1, 7a (required)")
	permission := fs.String("permission", "root", "run_key permission condition: root | ptrace | ptrace_dac | none (recorded verbatim, never inferred)")
	interval := fs.Int("interval", 30, "seconds between the start of consecutive samples")
	window := fs.Int("window", 300, "total sampling window duration in seconds")
	phase := fs.Int("phase", 0, "seconds to delay the first sample by, measured from -phase-base")
	phaseBaseFlag := fs.String("phase-base", "", "RFC3339 instant the -phase offset is measured from, i.e. the reference point of the observed workload's own cycle (default: collect's start time, recorded as such)")
	replicate := fs.Int("replicate", 1, "replicate number of this run_key combination")
	psArgs := fs.String("ps-args", defaultPSArgs, "ps_args passed to /containers/{id}/top (pid,ppid,user order is assumed by the parser)")
	outDir := fs.String("out-dir", "./out/collect", "output directory: one JSON file per container plus a manifest")
	expectFlag := fs.String("expect", "", "comma-separated container IDs or names to register BEFORE they start: collect waits for each to appear, reads its configuration and mapping inputs, and only then accepts it as an observation target. Use this when the workload must not begin until the observation is in place")
	expectTimeout := fs.Int("expect-timeout", 120, "seconds to wait for every -expect target to reach the accepted state before recording it as never started")
	expectPoll := fs.Int("expect-poll-ms", 200, "milliseconds between container-list polls while waiting for -expect targets")
	readyFile := fs.String("ready-file", "", "path of the readiness file rewritten on every registration state change, so a case runner can tell from outside when every -expect target has been accepted (default: <out-dir>/ready.json)")
	syncMode := fs.String("sync", "", "run_key sync condition: startup (observation first, workload afterwards) | attach_running (join a container already working). Recorded verbatim; defaults to startup when -expect is given and attach_running otherwise")
	configID := fs.String("config-id", "none", "run_key config_id: the event-collection configuration this run belongs to (collection method, script or build version, kernel-side filter, buffer size). \"none\" means this run collected no events")
	auxInputs := fs.Bool("aux-inputs", true, "read and save the file-to-package mapping inputs (installed-file manifests, the package database's full path index, module directory layouts, symlink targets, mount table) once per database generation")
	auxMaxEntries := fs.Int("aux-max-dir-entries", 200000, "per-directory-tree cap on recorded module layout paths")
	auxMaxRecord := fs.Int("aux-max-record-lines", 100000, "per-distribution cap on installed-file manifest lines")
	auxMaxOwned := fs.Int("aux-max-owned-paths", 400000, "cap on package-database path index entries")
	auxScanDepth := fs.Int("aux-scan-depth", 8, "how many directory levels below each conventional installation root to search for module directories")
	cgroupPath := fs.String("cgroup-path", "", "cgroup v2 directory to measure this collector in (default: the collector's own cgroup from /proc/self/cgroup, which is only this collector's cost if it was started in a cgroup of its own)")
	dockerCgroupPath := fs.String("docker-cgroup-path", defaultDockerServiceCgroup, "cgroup v2 directory of the Docker daemon, whose cpu.stat covers the ps processes docker top starts")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s collect [flags]\n\nSamples every running container's procfs-visible evidence over Docker's API, writing one record file per container.\n\nflags:\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caseVariant == "" {
		return fmt.Errorf("-case-variant is required")
	}
	if *interval <= 0 {
		return fmt.Errorf("-interval must be positive")
	}
	if *window < *interval {
		return fmt.Errorf("-window must be at least -interval")
	}
	if *expectTimeout <= 0 {
		return fmt.Errorf("-expect-timeout must be positive")
	}
	if *expectPoll <= 0 {
		return fmt.Errorf("-expect-poll-ms must be positive")
	}
	sampleCount := *window / *interval
	if sampleCount < 1 {
		sampleCount = 1
	}

	var expected []string
	for _, s := range strings.Split(*expectFlag, ",") {
		if s = strings.TrimSpace(s); s != "" {
			expected = append(expected, s)
		}
	}
	sync := strings.TrimSpace(*syncMode)
	if sync == "" {
		sync = "attach_running"
		if len(expected) > 0 {
			sync = "startup"
		}
	}
	switch sync {
	case "startup", "attach_running":
	default:
		return fmt.Errorf("-sync must be startup or attach_running, got %q", sync)
	}
	runKey := RunKey{
		CaseVariant: *caseVariant, Permission: *permission, Interval: *interval, Window: *window,
		Phase: *phase, Replicate: *replicate, Sync: sync, ConfigID: strings.TrimSpace(*configID),
	}
	limits := auxLimits{
		ScanDepth: *auxScanDepth, DirEntries: *auxMaxEntries,
		RecordFile: *auxMaxRecord, OwnedPaths: *auxMaxOwned, Symlinks: defaultAuxLimits().Symlinks,
	}

	runStart := time.Now()
	phaseBase, phaseBaseFrom := runStart, "collect_start"
	if strings.TrimSpace(*phaseBaseFlag) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*phaseBaseFlag))
		if err != nil {
			return fmt.Errorf("-phase-base: %w", err)
		}
		phaseBase, phaseBaseFrom = parsed, "flag"
	}

	var wantIDs map[string]bool
	if strings.TrimSpace(*containersFlag) != "" {
		wantIDs = map[string]bool{}
		for _, s := range strings.Split(*containersFlag, ",") {
			if s = strings.TrimSpace(s); s != "" {
				wantIDs[s] = true
			}
		}
	}

	client := newDockerClient(*socket)
	ctx := context.Background()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	manifest := Manifest{GeneratedAt: time.Now().UTC(), SocketPath: *socket}

	// A target's record and the collection state that reads into it are
	// one thing and are kept as one.
	//
	// They were separate, and a preparation that failed then left the
	// state pointing into a record that was thrown away: the next attempt
	// built a fresh record and the state's index into the old one no
	// longer addressed anything. Retrying is the ordinary case here — a
	// container is watched for until it is ready — so the two have to
	// survive a failed attempt together, or not at all.
	type target struct {
		id     string
		record *ContainerRecord
		state  *containerCollectState
		// prepared is set only when preparation actually completed. It is
		// what a retry consults: a record holding a partial reading from a
		// failed attempt is not a prepared target, and counting readings
		// instead let one such reading stand in for a completed
		// preparation.
		prepared bool
	}
	var order []string
	byID := map[string]*target{}

	windowID := fmt.Sprintf("w-%d", runStart.UnixNano())

	// add takes one container into the run: its Docker-reported identity
	// and configuration, and — for a pre-registered target — the package
	// database generation and mapping inputs it will be matched against.
	// Both entry paths go through it, so a container that was waited for
	// and one that was already running are recorded identically.
	add := func(ctx context.Context, s dockerContainerSummary, prepare bool) (*ContainerRecord, error) {
		t := byID[s.ID]
		if t == nil {
			t = &target{
				id:     s.ID,
				record: newContainerRecord(ctx, client, s, runKey, windowID, phaseBase, phaseBaseFrom),
				state:  newContainerCollectState(*auxInputs, limits),
			}
			byID[s.ID] = t
			order = append(order, s.ID)
		} else if t.record.InspectError != "" {
			// The container is kept in the population, but its failed
			// inspect is not remembered as the answer: the next attempt
			// genuinely asks again, into the same record, so the state
			// that reads into it stays valid.
			fresh := newContainerRecord(ctx, client, s, runKey, windowID, phaseBase, phaseBaseFrom)
			*t.record = *fresh
			t.state = newContainerCollectState(*auxInputs, limits)
		}
		if t.record.InspectError != "" {
			return t.record, fmt.Errorf("inspect: %s", t.record.InspectError)
		}
		if prepare && !t.prepared {
			// The mapping inputs have to exist before the workload is told
			// to start, which is the whole point of registering the target
			// first: a file first touched during startup has nothing to be
			// resolved against otherwise. A preparation that did not
			// finish is a failure, not an acceptance — and the next
			// attempt starts from a state that has forgotten the partial
			// reading the failed one left behind.
			if perr := prepareTarget(ctx, client, t.record, t.state, *psArgs); perr != nil {
				t.record.AuxiliaryInputs = nil
				t.state = newContainerCollectState(*auxInputs, limits)
				return t.record, perr
			}
			t.prepared = true
		}
		return t.record, nil
	}

	registryPath := strings.TrimSpace(*readyFile)
	if registryPath == "" {
		registryPath = filepath.Join(*outDir, "ready.json")
	}
	runID := fmt.Sprintf("%s-%d", runKeyFileTag(runKey), runStart.UnixNano())
	reg := newTargetRegistry(expected, registryPath, runKey, sync, runID)

	// The start-time enumeration is what the attach-running condition uses.
	// It runs alongside registration rather than instead of it: a run may
	// join containers that are already working and also wait for one that
	// has not started. Naming targets to wait for does not implicitly pull
	// in every other running container, so the enumeration contributes
	// nothing extra unless -containers says which.
	var registrationFailures []Failure
	if len(expected) == 0 || wantIDs != nil {
		summaries, err := client.listContainers(ctx)
		if err != nil {
			manifest.Errors = append(manifest.Errors, fmt.Sprintf("list containers: %v", err))
			reg.noteError("list containers: " + err.Error())
			if len(expected) == 0 {
				return writeManifest(*outDir, manifest)
			}
		}
		var attached []string
		for _, s := range summaries {
			if wantIDs != nil && !wantIDs[s.ID] && !matchesAnyName(wantIDs, s) {
				continue
			}
			if _, aerr := add(ctx, s, false); aerr != nil {
				manifest.Errors = append(manifest.Errors, fmt.Sprintf("container %s: %v", s.ID, aerr))
			}
			attached = append(attached, s.ID)
		}
		reg.noteAttachRunning(attached)
	}

	if !reg.empty() {
		registrationFailures = awaitRegisteredTargets(ctx, client, reg,
			func(ctx context.Context, s dockerContainerSummary) (*ContainerRecord, error) {
				// Preparation runs even for a container the start-time
				// enumeration already took in: being registered is what
				// decides whether the mapping inputs have to exist before
				// the workload begins, not which door the container came
				// through. Whether it has already run is a flag on the
				// target, not a count of what happens to be saved.
				return add(ctx, s, true)
			},
			time.Duration(*expectTimeout)*time.Second, time.Duration(*expectPoll)*time.Millisecond)
		// The phase offset is measured from the reference point of the
		// workload's own cycle. When targets were waited for and no
		// reference point was supplied, that point is the instant the last
		// one was accepted: nothing the run is measuring has happened
		// before it, and dating the window from the collector's start
		// would put the wait itself inside the window.
		if phaseBaseFrom == "collect_start" {
			phaseBase, phaseBaseFrom = time.Now(), "targets_accepted"
		}
	}

	registrations := reg.snapshot()
	windowStart := phaseBase.Add(time.Duration(*phase) * time.Second)
	windowEnd := windowStart.Add(time.Duration(*window) * time.Second)
	targets := make([]*target, 0, len(order))
	for _, id := range order {
		t := byID[id]
		targets = append(targets, t)
		t.record.Window.PhaseBase, t.record.Window.PhaseBaseFrom = phaseBase, phaseBaseFrom
		t.record.Window.ScheduledStart, t.record.Window.ScheduledEnd = windowStart, windowEnd
		t.record.TargetRegistrations = registrations
		t.record.Failures = append(t.record.Failures, registrationFailures...)
	}

	// Steady-state load: this collector process's own cgroup v2 accounting,
	// snapshotted before and after the whole sampling loop.
	selfDir := *cgroupPath
	var selfCgroupErr error
	if selfDir == "" {
		selfDir, selfCgroupErr = selfCgroupDir()
	}
	var selfBefore, dockerBefore cgroupSnapshot
	if selfCgroupErr == nil {
		selfBefore = readCgroupSnapshot(selfDir, true)
	} else {
		selfBefore.CPUErr, selfBefore.MemoryErr = selfCgroupErr, selfCgroupErr
	}
	dockerBefore = readCgroupSnapshot(*dockerCgroupPath, false)

	for k := 0; k < sampleCount; k++ {
		sampleID := fmt.Sprintf("s%d", k)
		scheduledStart := windowStart.Add(time.Duration(k**interval) * time.Second)
		if wait := time.Until(scheduledStart); wait > 0 {
			time.Sleep(wait)
		}
		actualStart := time.Now()

		for _, t := range targets {
			if t.record.InspectError != "" {
				continue
			}
			collectContainerSample(ctx, client, t.record, sampleID, *psArgs, t.state)
		}

		endedAt := time.Now()
		delay := actualStart.Sub(scheduledStart)
		if delay < 0 {
			delay = 0
		}
		timing := SampleTiming{SampleID: sampleID, Index: k, ScheduledStart: scheduledStart, ActualStart: actualStart, DelayMS: delay.Milliseconds(), EndedAt: endedAt}
		for _, t := range targets {
			t.record.Window.Samples = append(t.record.Window.Samples, timing)
		}
	}

	selfAfter := cgroupSnapshot{CPUErr: selfCgroupErr, MemoryErr: selfCgroupErr}
	if selfCgroupErr == nil {
		selfAfter = readCgroupSnapshot(selfDir, true)
	}
	dockerAfter := readCgroupSnapshot(*dockerCgroupPath, false)
	steadyState := cgroupLoadDelta(selfDir, selfBefore, selfAfter)
	dockerLoad := cgroupLoadDelta(*dockerCgroupPath, dockerBefore, dockerAfter)

	for _, t := range targets {
		t.record.Load = LoadMeasurement{InitialDBRead: t.state.initialDBRead, SteadyState: steadyState, DockerDaemon: dockerLoad}
		if t.record.InspectError == "" {
			t.record.Failures = append(t.record.Failures, loadFailures(t.record.Load)...)
		}
		fileName := sanitizeFileName(t.record.Subject.Docker.ContainerName, t.id) + "__" + runKeyFileTag(runKey) + ".json"
		if err := writeJSON(filepath.Join(*outDir, fileName), t.record); err != nil {
			manifest.Errors = append(manifest.Errors, fmt.Sprintf("write %s: %v", fileName, err))
			continue
		}
		manifest.Containers = append(manifest.Containers, ManifestEntry{
			ContainerID: t.id, ContainerName: t.record.Subject.Docker.ContainerName, File: fileName,
		})
	}

	return writeManifest(*outDir, manifest)
}

// runKeyFileTag renders a run_key compactly enough for a file name, so
// repeating a case under a second condition into the same output directory
// does not overwrite the first run's records.
//
// Every dimension is in it, the ordering condition and the collection
// configuration included. Two runs that differ in either are not the same
// condition — one catches a load that happens once at startup and the
// other cannot, one filtered its events and the other did not — and
// leaving them out of the name would have the second silently replace the
// first.
func runKeyFileTag(k RunKey) string {
	tag := fmt.Sprintf("%s_%s_i%d_w%d_p%d_r%d", k.CaseVariant, k.Permission, k.Interval, k.Window, k.Phase, k.Replicate)
	if k.Sync != "" {
		tag += "_" + sanitizeFileName(k.Sync, "sync")
	}
	if k.ConfigID != "" {
		tag += "_" + sanitizeFileName(k.ConfigID, "config")
	}
	return tag
}

func loadFailures(l LoadMeasurement) []Failure {
	var out []Failure
	if !l.InitialDBRead.Measured {
		out = append(out, Failure{Step: "load_initial_db_read", Message: "no package database read completed, so its cost was never measured"})
	}
	if !l.SteadyState.Measured {
		out = append(out, Failure{Step: "load_steady_state", Message: l.SteadyState.Error})
	}
	if !l.SteadyState.MemoryPeakMeasured {
		out = append(out, Failure{Step: "load_steady_state_memory", Message: l.SteadyState.MemoryError})
	}
	if !l.DockerDaemon.Measured {
		out = append(out, Failure{Step: "load_docker_daemon", Message: l.DockerDaemon.Error})
	}
	return out
}

// containerCollectState is one container's cross-sample state: the package
// index per mount view, which (mount view, database generation) pairs have
// already had their ledger and auxiliary mapping inputs recorded, the last
// accepted namespace identity per process generation, and the initial
// database read cost.
type containerCollectState struct {
	caches        map[string]*containerPkgCache
	ledgerSeen    map[string]bool
	nsLast        map[genKey]NamespaceRecord
	initialDBRead InitialDBReadLoad

	auxEnabled bool
	auxLimits  auxLimits
	// auxIndex points at the saved reading for each (mount view, layout
	// generation) pair, and ownedCache holds the operating-system path
	// index per mount view so it is rebuilt only when its own database
	// generation changes.
	auxIndex   map[string]int
	ownedCache map[string]*ownedPathCache
}

// generationHeld re-checks the identity of the process a reading was taken
// through, and says why it did not hold when it did not.
func generationHeld(pid int, aux AuxiliaryInputs) string {
	st, err := readStarttime(pid)
	switch {
	case err != nil:
		return fmt.Sprintf("the process the mapping inputs were read through (pid %d) could not be re-checked: %v", pid, err)
	case aux.ReadThroughStarttime != "" && st != aux.ReadThroughStarttime:
		return fmt.Sprintf("the process the mapping inputs were read through (pid %d) was replaced while they were being read", pid)
	}
	mnt, err := readNSLink(pid, "mnt")
	switch {
	case err != nil:
		return fmt.Sprintf("the mount view of the process the mapping inputs were read through (pid %d) could not be re-checked: %v", pid, err)
	case aux.ReadThroughMountView != "" && mnt != aux.ReadThroughMountView:
		return fmt.Sprintf("the mount view of the process the mapping inputs were read through (pid %d) changed while they were being read", pid)
	}
	return ""
}

// viewHasReading reports whether a mapping-input reading exists for one
// mount view. Acceptance needs one for every view the container presents,
// not one somewhere in the record.
func (s *containerCollectState) viewHasReading(rec *ContainerRecord, mv string) bool {
	for _, aux := range rec.AuxiliaryInputs {
		if aux.MountViewID == mv && !aux.Invalid {
			return true
		}
	}
	return false
}

func newContainerCollectState(auxEnabled bool, limits auxLimits) *containerCollectState {
	return &containerCollectState{
		caches:     map[string]*containerPkgCache{},
		ledgerSeen: map[string]bool{},
		nsLast:     map[genKey]NamespaceRecord{},
		auxEnabled: auxEnabled,
		auxLimits:  limits,
		auxIndex:   map[string]int{},
		ownedCache: map[string]*ownedPathCache{},
	}
}

// collectAuxForMountView reads the file-to-package mapping inputs for one
// mount view.
//
// It runs whether or not a package database was found: an image with no
// such database still has module trees and installed distributions to
// describe, and the earlier arrangement — reading these only alongside a
// successful database read — skipped exactly those images.
//
// The reading is returned rather than written into the record. Nothing
// about it can be trusted until the process it was read through is shown
// to have held still, and a reading that folded itself into the record
// first would have to be taken back out again — which, where an earlier
// reading of the same layout was already there, took that earlier one with
// it. Committing happens once, after the check, in commitAux.
func collectAuxForMountView(state *containerCollectState, mv string, pids []int) (aux AuxiliaryInputs, readPID int, err error) {
	if !state.auxEnabled {
		return aux, 0, nil
	}
	if len(pids) == 0 {
		return aux, 0, fmt.Errorf("mount view %s has no process to read the mapping inputs through", mv)
	}
	var info PkgDBGenerationInfo
	var idx *pkgIndex
	if cache := state.caches[mv]; cache != nil {
		info, idx = cache.info, cache.idx
	}
	// The cached index is reused only while the database generation it was
	// built from is still the one on disk.
	owned := state.ownedCache[mv]
	if owned == nil {
		owned = &ownedPathCache{}
		state.ownedCache[mv] = owned
	}

	// Any of the view's processes can reach the same filesystem; the first
	// whose root is still there is used.
	for _, pid := range pids {
		if _, serr := os.Stat(fmt.Sprintf("/proc/%d/root/.", pid)); serr == nil {
			readPID = pid
			break
		}
	}
	if readPID == 0 {
		return aux, 0, fmt.Errorf("no process of mount view %s could be reached to read the mapping inputs through", mv)
	}

	aux = collectAuxiliaryInputs(fmt.Sprintf("/proc/%d/root", readPID), readPID, mv, idx, info, state.auxLimits, owned)
	return aux, readPID, auxReadFailure(mv, aux)
}

// commitAux takes one reading into the record, once its source has been
// checked.
//
// A reading whose source did not hold still is saved on its own, marked
// unusable: it is a record of what was attempted, and it answers nothing.
// It is never folded into an earlier reading, because an earlier reading
// taken cleanly is still good — the later failure says nothing about it,
// and losing it would leave the samples it covered with no layout to
// resolve against.
//
// A verified reading extends an earlier one only when the two describe the
// same layout and came through the same process generation. Two readings
// of one layout through different generations are two readings, kept apart
// so each says what it was actually taken through.
func commitAux(rec *ContainerRecord, state *containerCollectState, aux AuxiliaryInputs, sampleID, invalidReason string) {
	if aux.MountViewID == "" && aux.AuxGeneration == "" {
		return // nothing was read
	}
	if sampleID != "" {
		aux.SampleIDs = []string{sampleID}
	}
	if invalidReason != "" {
		aux.Invalid, aux.InvalidReason = true, invalidReason
		rec.AuxiliaryInputs = append(rec.AuxiliaryInputs, aux)
		return
	}
	key := aux.MountViewID + "\x00" + aux.AuxGeneration + "\x00" + aux.ReadThroughStarttime
	if i, seen := state.auxIndex[key]; seen && i < len(rec.AuxiliaryInputs) && !rec.AuxiliaryInputs[i].Invalid {
		rec.AuxiliaryInputs[i].LastSeen = aux.CollectedAt
		if sampleID != "" {
			rec.AuxiliaryInputs[i].SampleIDs = append(rec.AuxiliaryInputs[i].SampleIDs, sampleID)
		}
		return
	}
	state.auxIndex[key] = len(rec.AuxiliaryInputs)
	rec.AuxiliaryInputs = append(rec.AuxiliaryInputs, aux)
}

// auxReadFailure reports whether a reading is missing something it was
// meant to have read.
//
// A manifest that is not there is a fact about the container, recorded and
// not a failure: a distribution in the older form has none, and that is
// what makes it unmappable. A manifest that exists and could not be read
// is a failure, and so is anything that went wrong while walking the
// layout. The difference matters because one of them is a finding and the
// other is a gap in the inputs, and a run must not begin with a gap it
// could have closed.
func auxReadFailure(mv string, aux AuxiliaryInputs) error {
	if len(aux.Errors) > 0 {
		return fmt.Errorf("mount view %s: %s", mv, strings.Join(aux.Errors, "; "))
	}
	for _, r := range aux.DistInfoRecords {
		if r.Error == "" || strings.Contains(r.Error, "no such file") {
			continue
		}
		return fmt.Errorf("mount view %s: the installed-file manifest %s could not be read: %s", mv, r.RecordPath, r.Error)
	}
	for _, m := range aux.ModuleDirs {
		if m.Error != "" {
			return fmt.Errorf("mount view %s: the layout of %s could not be read: %s", mv, m.Root, m.Error)
		}
	}
	return nil
}

// newContainerRecord builds one container's record from its summary and a
// fresh inspect. An inspect that fails is recorded on the record rather
// than dropping the container: its Findings stay in the population as
// undetermined instead of disappearing from the denominator.
func newContainerRecord(ctx context.Context, client *dockerClient, s dockerContainerSummary, runKey RunKey, windowID string, phaseBase time.Time, phaseBaseFrom string) *ContainerRecord {
	rec := &ContainerRecord{
		Subject: Subject{
			Runtime: "docker",
			Docker:  DockerSubject{ContainerID: s.ID, ContainerName: primaryName(s.Names), ImageRef: s.Image},
		},
		RunKey: runKey,
		Window: Window{ID: windowID, PhaseBase: phaseBase, PhaseBaseFrom: phaseBaseFrom, HostArch: runtime.GOARCH},
	}
	insp, err := client.inspectContainer(ctx, s.ID)
	if err != nil {
		rec.InspectError = err.Error()
		return rec
	}
	rec.Subject.Docker.ImageID = insp.Image
	rec.Subject.StartedAt = insp.State.StartedAt
	networks := map[string]string{}
	for name, n := range insp.NetworkSettings.Networks {
		networks[name] = n.IPAddress
	}
	rec.Docker = DockerConfig{
		NetworkMode:  insp.HostConfig.NetworkMode,
		PortBindings: convertPortBindings(insp.HostConfig.PortBindings),
		NetworkPorts: convertPortBindings(insp.NetworkSettings.Ports),
		Networks:     networks,
		ConfigUser:   insp.Config.User,
		Privileged:   insp.HostConfig.Privileged,
		CapAdd:       insp.HostConfig.CapAdd,
		CapDrop:      insp.HostConfig.CapDrop,
		StartedAt:    insp.State.StartedAt,
	}
	return rec
}

// prepareTarget establishes, before the window opens, which package
// database generation each of a container's mount views presents and reads
// the auxiliary mapping inputs for it. It takes no sample and records no
// collection result: this is preparation, and counting it as an
// observation would put work done before the workload started into the
// window's own numbers.
func prepareTarget(ctx context.Context, client *dockerClient, rec *ContainerRecord, state *containerCollectState, psArgs string) error {
	fail := func(step string, gen ProcessGeneration, err error) {
		rec.Failures = append(rec.Failures, Failure{Step: step, Generation: gen, Message: err.Error()})
	}
	top, err := client.top(ctx, rec.Subject.Docker.ContainerID, psArgs)
	if err != nil {
		fail("prepare_top_failed", ProcessGeneration{}, err)
		return fmt.Errorf("the container's processes could not be listed: %w", err)
	}
	mountViews := map[string][]int{}
	var order []string
	var problems []string
	for _, row := range top.Processes {
		if len(row) == 0 {
			continue
		}
		pid, perr := strconv.Atoi(strings.TrimSpace(row[0]))
		if perr != nil {
			problems = append(problems, fmt.Sprintf("a reported process row does not begin with a process number: %v", row))
			continue
		}
		mv, merr := readNSLink(pid, "mnt")
		if merr != nil {
			// A process whose mount view cannot be read is a view that may
			// never be prepared at all. It is carried into the decision
			// rather than left as a note in the record.
			fail("prepare_proc_denied", ProcessGeneration{PID: pid}, merr)
			problems = append(problems, fmt.Sprintf("pid %d: its mount view could not be read: %v", pid, merr))
			continue
		}
		if _, seen := mountViews[mv]; !seen {
			order = append(order, mv)
		}
		mountViews[mv] = append(mountViews[mv], pid)
	}
	sort.Strings(order)
	if len(order) == 0 {
		return fmt.Errorf("none of the container's %d reported process(es) had a readable mount view, so nothing could be read through them: %s",
			len(top.Processes), strings.Join(problems, "; "))
	}
	// Acceptance is decided per required input, per mount view, and the
	// three possible answers are kept apart: read, confirmed absent, or
	// failed. A count of readings is not one of them — an almost-empty
	// reading for one view would otherwise let the workload begin while
	// another view had read nothing at all.
	for _, mv := range order {
		cache := state.caches[mv]
		if cache == nil {
			cache = &containerPkgCache{}
			state.caches[mv] = cache
		}
		view, _ := resolveMountViewDB(rec, state, cache, mv, mountViews[mv], fail)
		switch view.PkgdbRead {
		case "ok":
			// read
		case "absent":
			// Confirmed absent, which is a finding rather than a gap: an
			// image that carries no package database is a case the
			// measurement covers.
		default:
			problems = append(problems, fmt.Sprintf("mount view %s: the package database could not be read: %s", mv, view.Error))
		}
		aux, auxPID, auxErr := collectAuxForMountView(state, mv, mountViews[mv])
		if auxErr != nil {
			problems = append(problems, auxErr.Error())
			if auxPID != 0 {
				commitAux(rec, state, aux, "", auxErr.Error())
			}
			continue
		}
		if auxPID == 0 {
			if state.auxEnabled {
				problems = append(problems, fmt.Sprintf("mount view %s: no mapping-input reading was produced", mv))
			}
			continue
		}
		// The reading came through a process; that process has to have
		// been the same one throughout, or the reading describes whatever
		// replaced it.
		reason := generationHeld(auxPID, aux)
		if reason != "" {
			problems = append(problems, fmt.Sprintf("mount view %s: %s", mv, reason))
		}
		commitAux(rec, state, aux, "", reason)
		if reason == "" && state.auxEnabled && !state.viewHasReading(rec, mv) {
			problems = append(problems, fmt.Sprintf("mount view %s: no usable mapping-input reading was produced", mv))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the target is not ready to observe: %s", strings.Join(problems, "; "))
	}
	return nil
}

// genKey is a process generation as a map key: a PID alone is not an
// identity, since PIDs are reused.
type genKey struct {
	pid       int
	starttime string
}

// containerPkgCache holds one container's package index for one mount view.
// It is only reused while the database generation it was built from is
// still the generation on disk; every sample re-checks that, so a database
// updated mid-window produces a second generation rather than stale
// ownership answers.
type containerPkgCache struct {
	idx         *pkgIndex
	info        PkgDBGenerationInfo
	lastErr     string
	calibration InodeCalibration
	calibrated  bool
}

func primaryName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func sanitizeFileName(name, fallback string) string {
	base := name
	if base == "" {
		base = fallback
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func matchesAnyName(wantIDs map[string]bool, s dockerContainerSummary) bool {
	for _, n := range s.Names {
		if wantIDs[strings.TrimPrefix(n, "/")] {
			return true
		}
	}
	return false
}

// convertPortBindings copies a Docker port-mapping map, preserving every
// declared key exactly as reported, including a JSON-null value (an
// exposed-but-unpublished port) as a nil slice rather than a dropped key.
func convertPortBindings(in map[string][]dockerPortBinding) map[string][]PortBinding {
	if in == nil {
		return nil
	}
	out := make(map[string][]PortBinding, len(in))
	for k, bindings := range in {
		var converted []PortBinding
		for _, b := range bindings {
			converted = append(converted, PortBinding{HostIP: b.HostIP, HostPort: b.HostPort})
		}
		out[k] = converted
	}
	return out
}

// procReadOutcome classifies one procfs read failure into the collection
// vocabulary. EACCES/EPERM is a permission result; ESRCH (and the ENOENT
// procfs returns for a PID that has gone) is a disappearance. Anything else
// is a failure that is not a disappearance, and is recorded as denied so it
// is never mistaken for "the process was not there".
func procReadOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "denied"
	case errors.Is(err, syscall.ESRCH), errors.Is(err, os.ErrNotExist):
		return "gone"
	default:
		return "denied"
	}
}

// procObservation is everything one sample read about one process
// generation, kept together so the sample's proc_observe value is decided
// after every read has happened rather than from the first of them.
type procObservation struct {
	pid   int
	gen   ProcessGeneration
	row   []string
	nsRec NamespaceRecord

	exe        string
	exeDeleted bool
	exeErr     error

	maps    []MapEntry
	mapsErr error

	effectiveUID string
	capEff       string
	statusErr    error

	cgroup      []byte
	cgroupErr   error
	socketNodes map[string]bool
	fdFiles     []FDRecord
	fdErr       error
	fdErrors    []string

	stable        bool
	invalidReason string
	// invalidKind is the collection-vocabulary classification of whatever
	// made this generation unusable: "denied" when a read was refused,
	// "gone" when the process was not there. It is kept separately from the
	// reason text because proc_observe is decided from it — a generation
	// invalidated by EACCES is a permission result, and reporting it as
	// "gone" would say the process had exited when it was in fact running
	// and unreadable.
	invalidKind string
}

// outcome is this process generation's contribution to proc_observe: ok
// only when both reads that proc_observe is defined over (exe and maps)
// succeeded and the generation held still while they happened.
func (o *procObservation) outcome() string {
	exeRes, mapsRes := procReadOutcome(o.exeErr), procReadOutcome(o.mapsErr)
	if exeRes == "denied" || mapsRes == "denied" {
		// A permission failure is reported as such even if the generation
		// also moved: the permission result is the one that says something
		// about whether this condition can observe at all.
		return "denied"
	}
	if !o.stable {
		// The exe and maps reads are skipped for a generation that could
		// not be established, so their errors are nil here and say nothing.
		// What invalidated the generation is the only evidence there is,
		// and its errno decides: a namespace link that could not be read
		// because of EACCES is a denied observation, not a vanished one.
		if o.invalidKind != "" {
			return o.invalidKind
		}
		return "gone"
	}
	if exeRes == "ok" && mapsRes == "ok" {
		return "ok"
	}
	return "gone"
}

// collectContainerSample takes one sample for one container: PIDs and
// namespace identity verified both before and after the reads, per-process
// procfs evidence, path resolution against the package database generation
// in force at this sample, and listening sockets.
func collectContainerSample(ctx context.Context, client *dockerClient, rec *ContainerRecord, sampleID, psArgs string, state *containerCollectState) {
	fail := func(step string, gen ProcessGeneration, err error) {
		rec.Failures = append(rec.Failures, Failure{Step: step, SampleID: sampleID, Generation: gen, Message: err.Error()})
	}

	result := CollectionResult{SampleID: sampleID}

	top, err := client.top(ctx, rec.Subject.Docker.ContainerID, psArgs)
	if err != nil {
		fail("top_failed", ProcessGeneration{}, err)
		result.ProcObserve = "top_failed"
		result.PkgdbRead = "error" // never attempted: no PIDs to resolve a rootfs through
		rec.CollectionResults = append(rec.CollectionResults, result)
		return
	}

	var pids []int
	rows := make(map[int][]string, len(top.Processes))
	for _, row := range top.Processes {
		if len(row) < 3 {
			fail("top_failed", ProcessGeneration{}, fmt.Errorf("malformed row %v", row))
			continue
		}
		pid, perr := strconv.Atoi(strings.TrimSpace(row[0]))
		if perr != nil {
			fail("top_failed", ProcessGeneration{}, fmt.Errorf("bad pid %q", row[0]))
			continue
		}
		pids = append(pids, pid)
		rows[pid] = row
	}

	// The container itself must still be the one that was inspected: a
	// restart between samples reuses the name and the ID but is a
	// different set of processes and a different rootfs.
	containerStable, startedAtNow := true, rec.Docker.StartedAt
	if insp, ierr := client.inspectContainer(ctx, rec.Subject.Docker.ContainerID); ierr != nil {
		fail("top_failed", ProcessGeneration{}, fmt.Errorf("re-inspect: %w", ierr))
		containerStable = false
	} else {
		startedAtNow = insp.State.StartedAt
		if rec.Docker.StartedAt != "" && startedAtNow != "" && startedAtNow != rec.Docker.StartedAt {
			containerStable = false
			fail("top_failed", ProcessGeneration{}, fmt.Errorf("container restarted during the window: StartedAt was %q, is now %q", rec.Docker.StartedAt, startedAtNow))
		}
	}

	// Pass 1: identity before the reads. A generation whose own identity
	// could not be established is not a generation anything can be
	// attributed to, so the failure invalidates it outright rather than
	// being recorded beside evidence that is then used anyway.
	obs := make([]*procObservation, 0, len(pids))
	for _, pid := range pids {
		o := &procObservation{pid: pid, row: rows[pid], stable: containerStable}
		gen := ProcessGeneration{PID: pid}
		nsRec := NamespaceRecord{SampleID: sampleID}
		var nsErr error
		st, sterr := readStarttime(pid)
		if sterr != nil {
			nsErr = sterr
		} else {
			gen.Starttime = st
		}
		nsRec.Generation = gen
		for _, kind := range []string{"net", "mnt", "user"} {
			v, e := readNSLink(pid, kind)
			if e != nil {
				if nsErr == nil {
					nsErr = e
				}
				continue
			}
			switch kind {
			case "net":
				nsRec.Net = v
			case "mnt":
				nsRec.Mnt = v
			case "user":
				nsRec.User = v
			}
		}
		if v, e := readUIDMap(pid); e == nil {
			nsRec.UIDMap = v
		} else {
			fail("proc_denied", gen, fmt.Errorf("uid_map: %w", e))
		}
		if nsErr != nil {
			nsRec.Error = nsErr.Error()
			kind := procReadOutcome(nsErr)
			step := "proc_denied"
			if kind == "gone" {
				step = "proc_gone"
			}
			fail(step, gen, fmt.Errorf("namespace identity: %w", nsErr))
			o.stable, o.invalidKind = false, kind
			o.invalidReason = fmt.Sprintf("process generation could not be established before the reads (%s): %v", kind, nsErr)
			nsRec.Invalid, nsRec.InvalidReason = true, o.invalidReason
		}
		if !containerStable {
			nsRec.Invalid, nsRec.InvalidReason = true, "container was restarted or could not be re-inspected during this sample"
			o.invalidReason = nsRec.InvalidReason
		}
		o.gen, o.nsRec = gen, nsRec
		obs = append(obs, o)
	}

	// Pass 2: the reads themselves. Everything that is read through a
	// process — its own procfs files, the rootfs behind /proc/<pid>/root,
	// and the network namespace behind /proc/<pid>/net — happens here,
	// before the identity is checked again, so that one check covers every
	// read that could have been redirected by the process being replaced.
	// Only generations still standing after pass 1 are read at all, and
	// only they are candidates for the per-mount-view and per-netns
	// representative reads.
	for _, o := range obs {
		if !o.stable {
			continue
		}
		o.exe, o.exeDeleted, o.exeErr = readExe(o.pid)
		o.maps, o.mapsErr = readMaps(o.pid)
		o.effectiveUID, o.capEff, o.statusErr = readStatus(o.pid)
		o.cgroup, o.cgroupErr = readCgroup(o.pid)
		o.socketNodes, o.fdFiles, o.fdErrors, o.fdErr = fdEntriesForPID(o.pid)
	}

	// Package database, per distinct mount view seen this sample, with the
	// generation re-verified rather than assumed unchanged.
	mountViews := map[string][]int{}
	var mountViewOrder []string
	for _, o := range obs {
		if !o.stable {
			continue
		}
		mv := o.nsRec.Mnt
		if _, seen := mountViews[mv]; !seen {
			mountViewOrder = append(mountViewOrder, mv)
		}
		mountViews[mv] = append(mountViews[mv], o.pid)
	}
	sort.Strings(mountViewOrder)

	if len(pids) > 0 && len(mountViewOrder) == 0 {
		// Every PID was excluded before a rootfs could be reached through
		// any of them, so pkgdb_read below becomes "error" with nothing in
		// the per-view list to explain it. Say so explicitly: "no candidate
		// process" and "the database could not be parsed" are different
		// findings, and only this one is a statement about access.
		fail("pkgdb_no_readable_pid", ProcessGeneration{}, fmt.Errorf(
			"none of the %d reported PIDs had a usable process generation, so no rootfs could be reached to read a package database through", len(pids)))
	}
	var pendingAux []pendingAuxView
	pendingViews := make([]pendingDBView, 0, len(mountViewOrder))
	for _, mv := range mountViewOrder {
		mvPids := mountViews[mv]
		cache := state.caches[mv]
		if cache == nil {
			cache = &containerPkgCache{}
			state.caches[mv] = cache
		}
		view, readPIDs := resolveMountViewDB(rec, state, cache, mv, mvPids, fail)
		pendingViews = append(pendingViews, pendingDBView{view: view, mountView: mv, readPIDs: readPIDs, cache: cache})

		// The mapping inputs are read for this view whatever the database
		// outcome was: an image with no package database still has module
		// trees and installed distributions to describe. Like the database
		// read, this one is held until the generation it came through has
		// been checked again.
		aux, auxPID, auxErr := collectAuxForMountView(state, mv, mvPids)
		if auxErr != nil {
			fail("aux_read_failed", ProcessGeneration{}, auxErr)
		}
		if auxPID != 0 {
			pendingAux = append(pendingAux, pendingAuxView{aux: aux, readPID: auxPID, mountView: mv})
		}

		if !cache.calibrated {
			for _, o := range obs {
				if !o.stable || o.nsRec.Mnt != mv || o.mapsErr != nil || len(o.maps) == 0 {
					continue
				}
				cache.calibrated = true
				cache.calibration = calibrateInodes(fmt.Sprintf("/proc/%d/root", o.pid), o.maps)
				if rec.InodeCalibration == (InodeCalibration{}) {
					rec.InodeCalibration = cache.calibration
				}
				break
			}
		}
	}

	// Socket inode -> every process generation holding it. A listening
	// socket shared by a parent and its workers belongs to all of them.
	inodeToGens := map[string][]ProcessGeneration{}
	for _, o := range obs {
		if !o.stable {
			continue
		}
		if o.fdErr != nil {
			fail("proc_denied", o.gen, fmt.Errorf("fd: %w", o.fdErr))
			continue
		}
		for _, fe := range o.fdErrors {
			fail("proc_denied", o.gen, fmt.Errorf("fd: %s", fe))
		}
		for inode := range o.socketNodes {
			inodeToGens[inode] = append(inodeToGens[inode], o.gen)
		}
	}
	for inode := range inodeToGens {
		gens := inodeToGens[inode]
		sort.Slice(gens, func(i, j int) bool { return gens[i].PID < gens[j].PID })
	}

	repByNetns := map[string]int{}
	var netnsOrder []string
	for _, o := range obs {
		if !o.stable {
			continue
		}
		ns := o.nsRec.Net
		if _, ok := repByNetns[ns]; !ok {
			repByNetns[ns] = o.pid
			netnsOrder = append(netnsOrder, ns)
		}
	}
	sort.Strings(netnsOrder)
	var pendingListeners []pendingListener
	for _, ns := range netnsOrder {
		pid := repByNetns[ns]
		for _, spec := range []struct{ family, path string }{
			{"ipv4", fmt.Sprintf("/proc/%d/net/tcp", pid)},
			{"ipv6", fmt.Sprintf("/proc/%d/net/tcp6", pid)},
		} {
			listenRows, lerr := readNetTCPListens(spec.path)
			if lerr != nil {
				fail("proc_denied", ProcessGeneration{PID: pid}, fmt.Errorf("%s: %w", spec.path, lerr))
				continue
			}
			for _, r := range listenRows {
				gens := inodeToGens[r.Inode]
				primary := ProcessGeneration{}
				if len(gens) > 0 {
					primary = gens[0]
				}
				pendingListeners = append(pendingListeners, pendingListener{
					readPID: pid,
					listener: Listener{
						SampleID: sampleID, NetnsID: ns,
						// The transport protocol is TCP either way: tcp6 is
						// the address family's table, not a separate
						// protocol, and Docker's own port keys say
						// "<port>/tcp" for both.
						Protocol: "tcp", Family: spec.family,
						LocalAddr: r.LocalAddr, LocalPort: r.LocalPort,
						Inode: r.Inode, Generation: primary, Generations: gens,
					},
				})
			}
		}
	}

	// Path resolution reads the rootfs through each generation's own
	// /proc/<pid>/root, so it belongs to the same pass as every other read
	// the identity check has to cover.
	pendingPaths := map[int][]PathResolutionRecord{}
	for _, o := range obs {
		if !o.stable {
			continue
		}
		cache := state.caches[o.nsRec.Mnt]
		root := fmt.Sprintf("/proc/%d/root", o.pid)
		if o.exeErr == nil && o.exe != "" {
			pendingPaths[o.pid] = append(pendingPaths[o.pid], resolvePathRecord(sampleID, o.gen, root, "exe", o.exe, "", "", o.exeDeleted, cache))
		}
		for _, m := range o.maps {
			pendingPaths[o.pid] = append(pendingPaths[o.pid], resolvePathRecord(sampleID, o.gen, root, "maps", m.Path, m.Dev, m.Inode, m.Deleted, cache))
		}
		// An open descriptor says the file is open, which is weaker than a
		// mapping and weaker still than an execution. It is recorded under
		// its own source so nothing downstream can describe it as more
		// than that.
		for i := range o.fdFiles {
			fd := &o.fdFiles[i]
			pr := resolvePathRecord(sampleID, o.gen, root, "fd", fd.Path, "", "", fd.Deleted, cache)
			fd.Resolved, fd.Error = pr.Resolved, pr.Error
			pendingPaths[o.pid] = append(pendingPaths[o.pid], pr)
		}
	}

	// Pass 3: identity after every read. A generation that changed while it
	// was being read cannot have its reads attributed to either generation,
	// and neither can anything read through it — the rootfs behind
	// /proc/<pid>/root and the tables behind /proc/<pid>/net are the
	// replacement's, not the generation the sample believes it observed.
	for _, o := range obs {
		if !o.stable {
			continue
		}
		reason, kind := "", "gone"
		stAfter, sterr := readStarttime(o.pid)
		switch {
		case sterr != nil && procReadOutcome(sterr) == "gone":
			reason = "process exited while it was being read"
		case sterr != nil:
			reason, kind = "starttime could not be re-read after the sample: "+sterr.Error(), procReadOutcome(sterr)
		case o.gen.Starttime != "" && stAfter != o.gen.Starttime:
			reason = "starttime changed during the sample: the PID was reused while it was being read"
		}
		if reason == "" {
			for _, check := range []struct{ kind, before string }{
				{"net", o.nsRec.Net}, {"mnt", o.nsRec.Mnt}, {"user", o.nsRec.User},
			} {
				after, e := readNSLink(o.pid, check.kind)
				if e != nil {
					// The identity cannot be confirmed to have held, which
					// is not the same as confirming that it did.
					reason, kind = check.kind+" namespace could not be re-read after the sample: "+e.Error(), procReadOutcome(e)
					break
				}
				if check.before != "" && after != check.before {
					reason = check.kind + " namespace changed during the sample"
					break
				}
			}
		}
		if reason != "" {
			o.stable, o.invalidKind = false, kind
			o.invalidReason = reason
			o.nsRec.Invalid, o.nsRec.InvalidReason = true, reason
			step := "proc_gone"
			if kind == "denied" {
				step = "proc_denied"
			}
			fail(step, o.gen, errors.New(reason))
		}
	}

	// The container must also still be the one whose processes were just
	// read: a restart during the sample makes every PID above belong to a
	// different container, whatever their own identity says.
	if containerStable {
		if insp, ierr := client.inspectContainer(ctx, rec.Subject.Docker.ContainerID); ierr != nil {
			fail("top_failed", ProcessGeneration{}, fmt.Errorf("re-inspect after the sample: %w", ierr))
			containerStable = false
		} else if rec.Docker.StartedAt != "" && insp.State.StartedAt != "" && insp.State.StartedAt != rec.Docker.StartedAt {
			containerStable = false
			fail("top_failed", ProcessGeneration{}, fmt.Errorf("container restarted during the sample: StartedAt was %q, is now %q", rec.Docker.StartedAt, insp.State.StartedAt))
		}
		if !containerStable {
			for _, o := range obs {
				o.stable = false
				o.invalidReason = "container was restarted or could not be re-inspected during this sample"
				o.nsRec.Invalid, o.nsRec.InvalidReason = true, o.invalidReason
			}
		}
	}

	// A generation that replaced an earlier one between samples is not an
	// error: it is a different generation, recorded on its own terms. Only
	// a disagreement within one generation's own identity invalidates.
	for _, o := range obs {
		key := genKey{pid: o.pid, starttime: o.gen.Starttime}
		if prev, seen := state.nsLast[key]; seen && !o.nsRec.Invalid {
			switch {
			case prev.Net != "" && o.nsRec.Net != "" && prev.Net != o.nsRec.Net:
				o.nsRec.Invalid, o.nsRec.InvalidReason = true, "net namespace changed for an unchanged process generation"
			case prev.Mnt != "" && o.nsRec.Mnt != "" && prev.Mnt != o.nsRec.Mnt:
				o.nsRec.Invalid, o.nsRec.InvalidReason = true, "mnt namespace changed for an unchanged process generation"
			case prev.User != "" && o.nsRec.User != "" && prev.User != o.nsRec.User:
				o.nsRec.Invalid, o.nsRec.InvalidReason = true, "user namespace changed for an unchanged process generation"
			}
			if o.nsRec.Invalid {
				o.stable, o.invalidReason = false, o.nsRec.InvalidReason
			}
		}
		if !o.nsRec.Invalid && o.nsRec.Error == "" {
			state.nsLast[key] = o.nsRec
		}
		rec.Namespaces = append(rec.Namespaces, o.nsRec)
	}

	stablePIDs := map[int]bool{}
	for _, o := range obs {
		if o.stable {
			stablePIDs[o.pid] = true
		}
	}

	// proc_observe is decided only now, with every read's result in hand.
	result.ProcObserve = aggregateProcObserve(obs, len(pids))

	// Commit the database views, dropping any whose rootfs was read through
	// a generation that did not survive the sample: that index describes
	// whatever replaced it, and nothing in the saved record could tell the
	// two apart afterwards.
	anyDBOK, anyDBAbsent, anyDBError := false, false, false
	for _, pv := range pendingViews {
		view := pv.view
		if lost := firstUnstablePID(pv.readPIDs, stablePIDs); lost != 0 {
			reason := fmt.Sprintf("the package database was read through pid %d, whose process generation did not survive the sample", lost)
			view.PkgdbRead, view.Error = "error", reason
			view.DBKind, view.DBGeneration = "", ""
			// Discard the index too: it was built from a rootfs that may
			// already belong to another generation.
			pv.cache.idx, pv.cache.lastErr = nil, reason
			fail("rootfs_denied", ProcessGeneration{PID: lost}, errors.New(reason))
		}
		switch view.PkgdbRead {
		case "ok":
			anyDBOK = true
		case "absent":
			anyDBAbsent = true
		default:
			anyDBError = true
		}
		result.Views = append(result.Views, view)
	}
	switch {
	case anyDBError:
		result.PkgdbRead = "error"
	case anyDBOK:
		result.PkgdbRead = "ok"
	case anyDBAbsent:
		result.PkgdbRead = "absent"
	default:
		result.PkgdbRead = "error"
	}
	result.Valid = result.ProcObserve == "ok" && (result.PkgdbRead == "ok" || result.PkgdbRead == "absent")
	rec.CollectionResults = append(rec.CollectionResults, result)

	// The mapping inputs were read through a process too, and the same
	// check applies: a reading taken through a generation that did not
	// survive describes whatever replaced it.
	for _, pa := range pendingAux {
		reason := ""
		if !stablePIDs[pa.readPID] {
			reason = fmt.Sprintf("the mapping inputs were read through pid %d, whose process generation did not survive the sample", pa.readPID)
			fail("aux_read_failed", ProcessGeneration{PID: pa.readPID}, errors.New(reason))
		}
		// Only now, with that settled, does the reading enter the record —
		// so an earlier reading that was taken cleanly is untouched by
		// this one's failure.
		commitAux(rec, state, pa.aux, sampleID, reason)
	}

	for _, pl := range pendingListeners {
		if !stablePIDs[pl.readPID] {
			fail("proc_gone", ProcessGeneration{PID: pl.readPID},
				fmt.Errorf("listeners were read from the network namespace of pid %d, whose process generation did not survive the sample", pl.readPID))
			continue
		}
		rec.Listeners = append(rec.Listeners, pl.listener)
	}

	for _, o := range obs {
		ppid, _ := strconv.Atoi(strings.TrimSpace(fieldAt(o.row, 1)))
		proc := ProcessRecord{
			SampleID: sampleID, Generation: o.gen, PPID: ppid, User: strings.TrimSpace(fieldAt(o.row, 2)),
			Invalid: !o.stable, InvalidReason: o.invalidReason,
		}

		if o.exeErr != nil {
			proc.ExeError = o.exeErr.Error()
			step := "proc_denied"
			if procReadOutcome(o.exeErr) == "gone" {
				step = "proc_gone"
			}
			fail(step, o.gen, o.exeErr)
		} else {
			proc.Exe, proc.ExeDeleted = o.exe, o.exeDeleted
		}

		if o.cgroupErr != nil {
			proc.CgroupError = o.cgroupErr.Error()
		} else if cgroupContainsID(o.cgroup, rec.Subject.Docker.ContainerID) {
			proc.CgroupContainerID = rec.Subject.Docker.ContainerID
			proc.CgroupMatches = true
		}

		if o.statusErr != nil {
			proc.StatusError = o.statusErr.Error()
			step := "proc_denied"
			if procReadOutcome(o.statusErr) == "gone" {
				step = "proc_gone"
			}
			fail(step, o.gen, o.statusErr)
		} else {
			proc.EffectiveUID, proc.CapEff = o.effectiveUID, o.capEff
		}

		if o.fdErr != nil {
			proc.FDError = o.fdErr.Error()
		} else {
			proc.FileDescriptors = o.fdFiles
		}

		if o.mapsErr != nil {
			proc.MapsError = o.mapsErr.Error()
			step := "proc_denied"
			if procReadOutcome(o.mapsErr) == "gone" {
				step = "proc_gone"
			}
			fail(step, o.gen, o.mapsErr)
		} else {
			proc.Maps = o.maps
		}

		rec.Processes = append(rec.Processes, proc)

		if !o.stable || o.nsRec.Invalid {
			continue
		}
		rec.PathResolution = append(rec.PathResolution, pendingPaths[o.pid]...)
	}
}

// aggregateProcObserve reduces a sample's per-generation outcomes to the
// one proc_observe value for that sample.
//
// One generation observed successfully makes the sample observed: the
// decision table asks whether the sample could see, not whether it saw
// everything. Otherwise a refusal outranks a disappearance, because the two
// are different findings and only one of them is about the permission
// condition under test — a run under a condition that cannot read
// /proc/<pid>/ns/* must report "denied" for every sample, not "gone",
// which would say the container's processes had exited.
func aggregateProcObserve(obs []*procObservation, pidCount int) string {
	if pidCount == 0 {
		return "top_failed"
	}
	anyOK, anyDenied := false, false
	for _, o := range obs {
		switch o.outcome() {
		case "ok":
			anyOK = true
		case "denied":
			anyDenied = true
		}
	}
	switch {
	case anyOK:
		return "ok"
	case anyDenied:
		return "denied"
	default:
		return "gone"
	}
}

// pendingDBView is one mount view's database result, held until the
// generations it was read through have been re-verified.
type pendingDBView struct {
	view      SampleDBView
	mountView string
	readPIDs  []int
	cache     *containerPkgCache
}

// pendingAuxView is one mapping-input reading, held until the generation
// it was read through has been re-verified.
type pendingAuxView struct {
	aux       AuxiliaryInputs
	readPID   int
	mountView string
}

// pendingListener is one observed listening socket, held until the
// generation whose network namespace it was read from has been
// re-verified.
type pendingListener struct {
	readPID  int
	listener Listener
}

// firstUnstablePID returns the first of pids that is not in the stable set,
// or 0 when every one of them survived the sample.
func firstUnstablePID(pids []int, stable map[int]bool) int {
	for _, pid := range pids {
		if pid != 0 && !stable[pid] {
			return pid
		}
	}
	return 0
}

// resolveMountViewDB re-establishes, for this sample, which package
// database generation one mount view presents, rebuilding the ownership
// index when the generation on disk is not the one the cache was built
// from. Database absence is re-checked every sample too rather than
// remembered: a database can appear (or be removed) during a run, and
// "absent" is a finding about this sample alone.
func resolveMountViewDB(rec *ContainerRecord, state *containerCollectState, cache *containerPkgCache, mv string, mvPids []int, fail func(string, ProcessGeneration, error)) (SampleDBView, []int) {
	view := SampleDBView{MountViewID: mv}
	var readPIDs []int

	gen, genPID, gerr := containerPkgDBGeneration(mvPids, mv)
	if genPID != 0 {
		readPIDs = append(readPIDs, genPID)
	}
	if gerr != nil {
		cache.idx, cache.lastErr = nil, gerr.Error()
		cache.info = PkgDBGenerationInfo{MountViewID: mv}
		view.PkgdbRead, view.Error = "error", gerr.Error()
		fail("rootfs_denied", ProcessGeneration{}, gerr)
		return view, readPIDs
	}
	if gen.DBKind == noDBKind {
		cache.idx, cache.lastErr, cache.info = nil, "", gen
		view.PkgdbRead, view.DBKind, view.DBGeneration = "absent", gen.DBKind, gen.DBGeneration
		return view, readPIDs
	}

	if cache.idx == nil || cache.lastErr != "" || cache.info.DBGeneration != gen.DBGeneration || cache.info.DBKind != gen.DBKind {
		readStart := time.Now()
		idx, info, ledger, tally, buildPID, perr := buildContainerPkgIndex(mvPids, mv)
		if buildPID != 0 {
			readPIDs = append(readPIDs, buildPID)
		}
		if perr != nil {
			cache.idx, cache.lastErr, cache.info = nil, perr.Error(), info
			view.PkgdbRead, view.Error = "error", perr.Error()
			fail("rootfs_denied", ProcessGeneration{}, perr)
			return view, readPIDs
		}
		cache.idx, cache.info, cache.lastErr = idx, info, ""
		key := mv + "\x00" + info.DBGeneration
		if !state.ledgerSeen[key] {
			state.ledgerSeen[key] = true
			rec.PackageLedger = append(rec.PackageLedger, ledger...)
			rec.PkgDBs = append(rec.PkgDBs, info)
		}
		if !state.initialDBRead.Measured {
			state.initialDBRead = InitialDBReadLoad{
				DurationMS: time.Since(readStart).Milliseconds(),
				BytesRead:  tally.Bytes, FileCount: tally.Files, Measured: true,
			}
		}
	}
	view.PkgdbRead, view.DBKind, view.DBGeneration = "ok", cache.info.DBKind, cache.info.DBGeneration
	return view, readPIDs
}

func fieldAt(row []string, i int) string {
	if i < len(row) {
		return row[i]
	}
	return ""
}

// resolvePathRecord classifies one observed path against the container's
// package database (collect's own ownership vocabulary; Trivy is never
// consulted here), and independently evaluates path_inode_changed when
// inode calibration succeeded for this container.
func resolvePathRecord(sampleID string, gen ProcessGeneration, root, source, rawPath, obsDev, obsInode string, deletedFlag bool, cache *containerPkgCache) PathResolutionRecord {
	rec := PathResolutionRecord{SampleID: sampleID, Generation: gen, Source: source, Path: rawPath, Dev: obsDev, Inode: obsInode, MapsDeleted: deletedFlag}
	if cache != nil {
		rec.MountViewID, rec.DBGeneration = cache.info.MountViewID, cache.info.DBGeneration
	}

	resolved, rerr := resolveInRoot(root, rawPath)
	if rerr != nil {
		// A deleted mapping's path routinely no longer resolves — that is
		// what deletion means — so a resolution failure never overrides the
		// deleted classification. The failure itself is still recorded.
		rec.Error = rerr.Error()
		if deletedFlag {
			rec.Ownership = OwnershipDeleted
		} else {
			rec.Ownership = OwnershipUnresolvable
		}
		return rec
	}
	rec.Resolved = resolved

	if cache != nil && cache.calibration.Calibrated && obsDev != "" && obsInode != "" {
		if cur, serr := statDevIno(filepath.Join(root, resolved)); serr == nil {
			changed := cur.Dev != obsDev || cur.Inode != obsInode
			rec.PathInodeChanged = &changed
		}
	}

	if deletedFlag {
		rec.Ownership = OwnershipDeleted
		return rec
	}

	if cache == nil || cache.lastErr != "" {
		rec.Ownership = OwnershipDBError
		if cache != nil {
			rec.Error = cache.lastErr
		}
		return rec
	}
	if cache.idx == nil || cache.info.DBKind == "" || cache.info.DBKind == noDBKind {
		rec.Ownership = OwnershipDBAbsent
		return rec
	}

	rec.DBKind = cache.info.DBKind
	owners, ok := cache.idx.lookup(resolved)
	switch {
	case !ok || len(owners) == 0:
		// A database whose file lists are incomplete cannot tell "no
		// package owns this" from "the owner's file list is one of the
		// missing ones", so the path keeps the database's own
		// incompleteness rather than being attributed to neither.
		if cache.idx.fileListComplete {
			rec.Ownership = OwnershipUnowned
		} else {
			rec.Ownership = OwnershipNoFileList
		}
	case len(owners) > 1:
		rec.Ownership = OwnershipMultipleOwners
	default:
		rec.Ownership = OwnershipOwned
		rec.DBKind = owners[0][0]
		rec.Package = owners[0][1]
		rec.DBVersion = cache.idx.versionOf(owners[0][0], owners[0][1])
	}
	return rec
}

// writeJSONTo renders a value as indented JSON into an already-open file,
// used where the write has to land atomically under a name of the caller's
// choosing rather than at a fixed path.
func writeJSONTo(f *os.File, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func writeJSON(path string, v any) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeManifest(outDir string, m Manifest) error {
	return writeJSON(filepath.Join(outDir, "manifest.json"), m)
}
