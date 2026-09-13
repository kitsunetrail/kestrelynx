package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// errMemoryNotRequested marks a tier whose memory high-water mark was
// deliberately not read, so it is never mistaken for a tier that was
// measured and found to be using no memory.
var errMemoryNotRequested = errors.New("memory.peak not read for this tier")

// defaultDockerServiceCgroup is the usual cgroup v2 path for
// docker.service's own accounting, used for the daemon-side load tier: the
// docker top calls this harness issues run inside dockerd's own cgroup, so
// dockerd's own process statistics alone would miss that cost. It is only
// a default — a host whose daemon runs under a different unit or slice
// passes its own path on the command line.
const defaultDockerServiceCgroup = "/sys/fs/cgroup/system.slice/docker.service"

// cgroupSnapshot is one point-in-time reading of a cgroup v2 accounting
// file pair, used to compute a before/after delta for the load
// measurement's steady-state and daemon-side tiers. The two readings
// succeed and fail independently.
type cgroupSnapshot struct {
	CPUUsageUsec int64
	CPUErr       error
	MemoryPeak   int64
	MemoryErr    error
}

// selfCgroupDir resolves the current process's own cgroup v2 directory via
// /proc/self/cgroup, used for the steady-state (collector's own) load
// tier. It assumes the unified (v2) hierarchy, a single "0::<path>" line;
// a v1 or hybrid hierarchy is reported as an error rather than guessed at.
func selfCgroupDir() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			return "/sys/fs/cgroup" + strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 (0::) line in /proc/self/cgroup: not a unified hierarchy")
}

// readCgroupSnapshot reads cpu.stat's usage_usec and memory.peak from the
// given cgroup v2 directory. Each missing or unreadable file is recorded as
// its own error; neither is ever reported as a zero value, because a zero
// CPU delta and an unread cpu.stat are different findings.
func readCgroupSnapshot(dir string, wantMemory bool) cgroupSnapshot {
	var snap cgroupSnapshot
	usage, err := readCPUStatUsageUsec(dir + "/cpu.stat")
	if err != nil {
		snap.CPUErr = err
	} else {
		snap.CPUUsageUsec = usage
	}
	if !wantMemory {
		snap.MemoryErr = errMemoryNotRequested
		return snap
	}
	v, merr := readSingleInt(dir + "/memory.peak")
	if merr != nil {
		snap.MemoryErr = merr
	} else {
		snap.MemoryPeak = v
	}
	return snap
}

// readCPUStatUsageUsec parses cgroup v2's cpu.stat "usage_usec <n>" line.
func readCPUStatUsageUsec(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[0] == "usage_usec" {
			return strconv.ParseInt(fields[1], 10, 64)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("cpu.stat: no usage_usec line in %s", path)
}

func readSingleInt(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

// cgroupLoadDelta computes a CgroupLoad from two snapshots. Measured is set
// only when both cpu.stat readings succeeded; MemoryPeakMeasured only when
// the after-reading of memory.peak succeeded. A tier that could not be
// measured records why, and the caller records that as a run failure rather
// than presenting a process-level substitute as equivalent.
func cgroupLoadDelta(dir string, before, after cgroupSnapshot) CgroupLoad {
	out := CgroupLoad{CgroupPath: dir}
	switch {
	case before.CPUErr != nil:
		out.Error = "before: " + before.CPUErr.Error()
	case after.CPUErr != nil:
		out.Error = "after: " + after.CPUErr.Error()
	default:
		out.Measured = true
		out.CPUUsageDeltaUS = after.CPUUsageUsec - before.CPUUsageUsec
	}
	switch {
	case before.MemoryErr != nil && after.MemoryErr != nil:
		out.MemoryError = after.MemoryErr.Error()
	case after.MemoryErr != nil:
		out.MemoryError = "after: " + after.MemoryErr.Error()
	default:
		out.MemoryPeakMeasured = true
		out.MemoryPeakBytes = after.MemoryPeak
	}
	return out
}
