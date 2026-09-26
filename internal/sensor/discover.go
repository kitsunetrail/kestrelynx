package sensor

import (
	"os"
	"strconv"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

// procInfo is what one host process's /proc/<pid>/{cgroup,stat} says about
// it, captured together in a single scan pass so a container generation's
// init process can be found without reopening every candidate a second
// time.
type procInfo struct {
	PID         int
	PPID        int
	Starttime   int64
	ContainerID string // "" when this process's cgroup names no Docker container
}

// scanResult is one host-wide /proc pass: every process this Sensor could
// read (Procs), and how many it tried to read but could not because the
// read itself was refused (DeniedCount, procfs.OutcomeDenied) rather than
// because the process was simply gone by the time this scan reached it
// (OutcomeGone, which is normal churn and not counted at all). The session
// loop uses DeniedCount against len(Procs) to decide whether this sample as
// a whole looks like a permission problem rather than an empty host.
type scanResult struct {
	Procs       map[int]procInfo
	Attempted   int
	DeniedCount int
}

// scanProcs walks /proc once, reading every numeric entry's cgroup and stat.
// A process that disappears between the directory listing and the read
// (OutcomeGone) is silently skipped — the process list is inherently a
// snapshot of a moving target, and that disappearance is not evidence of
// anything about this Sensor's own permissions. A process whose read is
// refused (OutcomeDenied) is also skipped from the result, but counted in
// DeniedCount.
func scanProcs() (scanResult, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return scanResult{}, err
	}
	res := scanResult{Procs: make(map[int]procInfo, len(entries))}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		res.Attempted++
		info, outcome := readProcInfo(pid)
		switch outcome {
		case procfs.OutcomeOK:
			res.Procs[pid] = info
		case procfs.OutcomeDenied:
			res.DeniedCount++
		case procfs.OutcomeGone:
			// Normal churn; not an error, not counted.
		}
	}
	return res, nil
}

// readProcInfo reads one process's cgroup and stat, classifying the first
// failure it hits (Open, then Cgroup, then PPID) via procfs.Classify.
func readProcInfo(pid int) (procInfo, procfs.Outcome) {
	h, err := procfs.Open(pid)
	if err != nil {
		return procInfo{}, procfs.Classify(err)
	}
	defer h.Close()

	cid, _, err := h.ContainerID()
	if err != nil {
		return procInfo{}, procfs.Classify(err)
	}
	ppid, err := h.PPID()
	if err != nil {
		return procInfo{}, procfs.Classify(err)
	}
	return procInfo{PID: pid, PPID: ppid, Starttime: h.Starttime(), ContainerID: cid}, procfs.OutcomeOK
}

// containerGroup is every host process scanProcs found belonging to one
// container's cgroup, plus whichever of them this sample judges to be that
// container's init process. Processes carries each one's own starttime, not
// just its PID — a worker that only received bare PID numbers could read a
// PID Docker's cgroup handed it a scan ago, but that the kernel has since
// reused for an unrelated process, and misattribute that unrelated
// process's data to this container (see sampleGeneration's own starttime
// recheck, which this is what makes possible at all).
type containerGroup struct {
	ContainerID string
	Processes   []InitProcess // despite the name, one entry per process in the group, not just init
	Init        InitProcess
}

// InitProcess identifies one process generation by its (host PID,
// starttime) pair — the same shape evidence.InitProcess carries, reused here
// for any process this package identifies this way, not only a container's
// own init.
type InitProcess struct {
	PID       int
	Starttime int64
}

// groupContainers partitions procs by ContainerID (empty ContainerID —
// processes outside any Docker container's cgroup — is never a group) and
// resolves each group's init process. excludeSelf and excludeIDs remove the
// Sensor's own container and any operator-excluded container (matched by a
// hex-prefix of at least 12 characters, as --exclude-id documents) before
// init resolution ever runs on them, so neither ever appears in the result.
func groupContainers(procs map[int]procInfo, excludeSelf string, excludeIDs []string) map[string]containerGroup {
	byContainer := map[string][]int{}
	for pid, info := range procs {
		if info.ContainerID == "" {
			continue
		}
		if info.ContainerID == excludeSelf {
			continue
		}
		if matchesExcludedID(info.ContainerID, excludeIDs) {
			continue
		}
		byContainer[info.ContainerID] = append(byContainer[info.ContainerID], pid)
	}

	out := make(map[string]containerGroup, len(byContainer))
	for cid, pids := range byContainer {
		processes := make([]InitProcess, len(pids))
		for i, pid := range pids {
			processes[i] = InitProcess{PID: pid, Starttime: procs[pid].Starttime}
		}
		out[cid] = containerGroup{
			ContainerID: cid,
			Processes:   processes,
			Init:        findInit(procs, cid, pids),
		}
	}
	return out
}

// matchesExcludedID reports whether id (a full 64-hex container ID) is named
// by any prefix in excludeIDs, per --exclude-id's own contract (a prefix of
// at least 12 hex characters).
func matchesExcludedID(id string, excludeIDs []string) bool {
	for _, prefix := range excludeIDs {
		if len(prefix) >= 12 && len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// findInit picks containerID's init process: among pids, the one whose
// parent's own ContainerID (per procs) is not containerID — a process
// reparented within the container's own PID tree is not a candidate, only
// one whose parent is genuinely outside the container's cgroup (the
// container runtime itself, or a parent that no longer exists) — and, among
// those candidates, the one with the smallest starttime. If no strict
// candidate exists (every process's parent happens to also be in this
// container's own process list, which should not occur in a genuine
// container but is not trusted to be impossible for a snapshot read
// mid-churn), the process with the smallest starttime among the whole group
// is used instead, so a generation is never left without an identity purely
// because this one sample's snapshot was momentarily inconsistent.
func findInit(procs map[int]procInfo, containerID string, pids []int) InitProcess {
	var best *InitProcess
	var fallback *InitProcess
	for _, pid := range pids {
		info := procs[pid]
		candidate := InitProcess{PID: pid, Starttime: info.Starttime}
		if fallback == nil || candidate.Starttime < fallback.Starttime {
			fallback = &candidate
		}
		parent, ok := procs[info.PPID]
		if ok && parent.ContainerID == containerID {
			continue // parent is in the same container: not an init candidate
		}
		if best == nil || candidate.Starttime < best.Starttime {
			best = &candidate
		}
	}
	if best != nil {
		return *best
	}
	if fallback != nil {
		return *fallback
	}
	return InitProcess{}
}
