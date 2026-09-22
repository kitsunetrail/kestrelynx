package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// MeasuredInt64 is one integer reading that either succeeded (Measured=true, Value set) or
// did not (Measured=false, Reason set) - a JSON shape used throughout supervise and
// cgroup-stat's own output so a reader can never mistake an unread value for a measured
// zero, the same rule load.go's own CgroupLoad already follows for the collector.
//
// "value" carries no omitempty on purpose: a measured zero (a brand new cgroup's own CPU
// baseline is exactly that) must be emitted as 0, because a reader that finds no "value"
// key at all has no way to tell it from a reading that never happened.
type MeasuredInt64 struct {
	Measured bool   `json:"measured"`
	Value    int64  `json:"value"`
	Reason   string `json:"reason,omitempty"`
}

// MeasuredBool is MeasuredInt64's boolean counterpart, used for cgroup.events' own
// "populated" flag and for the various yes/no verifications supervise performs. Like
// MeasuredInt64.Value, "value" is always emitted: a measured false is a result, not an
// absence.
type MeasuredBool struct {
	Measured bool   `json:"measured"`
	Value    bool   `json:"value"`
	Reason   string `json:"reason,omitempty"`
}

func measuredInt(v int64, err error) MeasuredInt64 {
	if err != nil {
		return MeasuredInt64{Measured: false, Reason: err.Error()}
	}
	return MeasuredInt64{Measured: true, Value: v}
}

func measuredBool(v bool, err error) MeasuredBool {
	if err != nil {
		return MeasuredBool{Measured: false, Reason: err.Error()}
	}
	return MeasuredBool{Measured: true, Value: v}
}

// readCgroupEventsPopulated reads cgroup.events' own "populated" line: 0 once every task
// and every descendant cgroup with a task has left, the only condition under which cgroup
// v2 actually allows removing the directory. A caller must never infer emptiness from
// cgroup.procs' own file *size* - that pseudo-file always reports size 0 from stat(2)
// regardless of how many PIDs it lists, so an emptiness check built on -s (or any other
// size-based test) reports every populated cgroup as empty too.
func readCgroupEventsPopulated(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			v, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return false, fmt.Errorf("cgroup.events: bad populated value %q in %s: %w", fields[1], path, err)
			}
			return v != 0, nil
		}
	}
	return false, fmt.Errorf("cgroup.events: no populated line in %s", path)
}

// CgroupStatResult is cgroup-stat's own JSON output: one cgroup v2 directory's cpu.stat
// usage_usec, memory.peak and cgroup.events populated flag, each independently
// measured/not_measured. load-run.sh (and watch-run.sh) call this at every checkpoint
// (before_start, window_start, window_end, process_exit) rather than parsing these files
// themselves in bash, so the exact same reading logic supervise itself uses for its own
// baseline/final counters is what every checkpoint in between uses too.
type CgroupStatResult struct {
	Path            string        `json:"path"`
	CPUUsageUsec    MeasuredInt64 `json:"cpu_usage_usec"`
	MemoryPeakBytes MeasuredInt64 `json:"memory_peak_bytes"`
	Populated       MeasuredBool  `json:"populated"`
}

func readCgroupStat(path string) CgroupStatResult {
	usec, uerr := readCPUStatUsageUsec(path + "/cpu.stat")
	peak, perr := readSingleInt(path + "/memory.peak")
	populated, poerr := readCgroupEventsPopulated(path + "/cgroup.events")
	return CgroupStatResult{
		Path:            path,
		CPUUsageUsec:    measuredInt(usec, uerr),
		MemoryPeakBytes: measuredInt(peak, perr),
		Populated:       measuredBool(populated, poerr),
	}
}

func runCgroupStat(args []string) error {
	fs := flag.NewFlagSet("cgroup-stat", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s cgroup-stat <cgroup v2 directory>\n\nPrints cpu.stat usage_usec, memory.peak and cgroup.events populated as JSON to stdout, each independently measured/not_measured. Callers (load-run.sh, watch-run.sh) use this at every checkpoint instead of parsing these cgroup files themselves.\n", os.Args[0])
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("cgroup-stat: exactly one cgroup path argument is required")
	}
	result := readCgroupStat(fs.Arg(0))
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(result)
}

// CgroupRemoveResult is cgroup-remove's own JSON output. A caller removing a cgroup it
// asked supervise to keep (-keep-cgroup) needs to know not just whether the directory is
// gone but why it is not, so every step is its own measured/not_measured field rather than
// an exit code standing in for all of them.
type CgroupRemoveResult struct {
	Path      string       `json:"path"`
	Populated MeasuredBool `json:"populated"`
	Removed   MeasuredBool `json:"removed"`
	WaitedS   float64      `json:"waited_s"`
}

// removeCgroup waits up to waitSeconds for the cgroup to report cgroup.events populated=0
// - the only condition under which cgroup v2 allows the directory to be removed at all -
// and then removes it. A directory that is already gone is reported as removed (the caller's
// intent, that nothing of this run is left behind, is satisfied) with the reason saying so,
// never as a failure.
func removeCgroup(path string, waitSeconds int) CgroupRemoveResult {
	res := CgroupRemoveResult{Path: path}
	start := time.Now()
	deadline := start.Add(time.Duration(waitSeconds) * time.Second)
	for {
		if _, serr := os.Stat(path); serr != nil && os.IsNotExist(serr) {
			res.Populated = MeasuredBool{Measured: false, Reason: "the directory no longer exists"}
			res.Removed = MeasuredBool{Measured: true, Value: true, Reason: "already removed before this call"}
			res.WaitedS = time.Since(start).Seconds()
			return res
		}
		populated, perr := readCgroupEventsPopulated(path + "/cgroup.events")
		res.Populated = measuredBool(populated, perr)
		if perr != nil {
			res.Removed = MeasuredBool{Measured: false, Reason: fmt.Sprintf("cannot read cgroup.events: %v", perr)}
			res.WaitedS = time.Since(start).Seconds()
			return res
		}
		if !populated {
			break
		}
		if !time.Now().Before(deadline) {
			res.Removed = MeasuredBool{Measured: true, Value: false,
				Reason: fmt.Sprintf("cgroup.events still reports populated=1 after waiting %ds: a task is still present", waitSeconds)}
			res.WaitedS = time.Since(start).Seconds()
			return res
		}
		time.Sleep(200 * time.Millisecond)
	}
	if rerr := os.Remove(path); rerr != nil {
		res.Removed = MeasuredBool{Measured: true, Value: false, Reason: rerr.Error()}
	} else {
		res.Removed = MeasuredBool{Measured: true, Value: true}
	}
	res.WaitedS = time.Since(start).Seconds()
	return res
}

func runCgroupRemove(args []string) error {
	fs := flag.NewFlagSet("cgroup-remove", flag.ExitOnError)
	wait := fs.Int("wait", 30, "seconds to wait for cgroup.events to report populated=0 before giving up")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s cgroup-remove [-wait SECONDS] <cgroup v2 directory>\n\nRemoves one cgroup v2 directory once cgroup.events reports populated=0, printing the\nattempt as JSON. This is the counterpart of `supervise -keep-cgroup`: the supervisor\nleaves the cgroup and its counters in place so the caller can take its own final\nreadings, and the caller removes it here afterwards - children first, then the parent.\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("cgroup-remove: exactly one cgroup path argument is required")
	}
	res := removeCgroup(fs.Arg(0), *wait)
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		return err
	}
	if !res.Removed.Measured || !res.Removed.Value {
		return fmt.Errorf("cgroup-remove: %s not removed: %s", res.Path, res.Removed.Reason)
	}
	return nil
}
