package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TaskStatus is the subset of /proc/<pid>/task/<tid>/status this package's
// self-checks need: whether NO_NEW_PRIVS and seccomp filtering are active
// on that thread, and its effective capability set. Values default to -1
// (NoNewPrivs, Seccomp) so a field genuinely absent from the status file
// (an unexpected kernel/format difference) is distinguishable from a
// present-and-zero value, rather than silently read as "not set".
type TaskStatus struct {
	TID          int
	NoNewPrivs   int
	Seccomp      int
	CapEffective uint64
	CapPermitted uint64
}

// ReadTaskStatuses reads /proc/<pid>/task/*/status for every thread of pid
// (which may be this process or another one the caller has ptrace-read
// access to) and returns one TaskStatus per thread. It fails closed: any
// thread whose status file cannot be opened or parsed is an error for the
// whole call, since a self-check that silently skipped an unreadable
// thread could miss exactly the thread that was not actually restricted.
func ReadTaskStatuses(pid int) ([]TaskStatus, error) {
	taskDir := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, fmt.Errorf("sandbox: list %s: %w", taskDir, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("sandbox: %s has no threads", taskDir)
	}

	out := make([]TaskStatus, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a tid directory
		}
		st, err := readOneTaskStatus(filepath.Join(taskDir, e.Name(), "status"), tid)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

func readOneTaskStatus(path string, tid int) (TaskStatus, error) {
	st := TaskStatus{TID: tid, NoNewPrivs: -1, Seccomp: -1}
	f, err := os.Open(path)
	if err != nil {
		return st, fmt.Errorf("sandbox: open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "NoNewPrivs":
			n, err := strconv.Atoi(val)
			if err != nil {
				return st, fmt.Errorf("sandbox: parse NoNewPrivs in %s: %w", path, err)
			}
			st.NoNewPrivs = n
		case "Seccomp":
			n, err := strconv.Atoi(val)
			if err != nil {
				return st, fmt.Errorf("sandbox: parse Seccomp in %s: %w", path, err)
			}
			st.Seccomp = n
		case "CapEff":
			n, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return st, fmt.Errorf("sandbox: parse CapEff in %s: %w", path, err)
			}
			st.CapEffective = n
		case "CapPrm":
			n, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return st, fmt.Errorf("sandbox: parse CapPrm in %s: %w", path, err)
			}
			st.CapPermitted = n
		}
	}
	if err := sc.Err(); err != nil {
		return st, fmt.Errorf("sandbox: read %s: %w", path, err)
	}
	return st, nil
}

// AllNoNewPrivsAndSeccomp reports whether every thread in statuses has
// NoNewPrivs == 1 and Seccomp == 2 (SECCOMP_MODE_FILTER). It also returns
// the first thread that fails, for error messages.
func AllNoNewPrivsAndSeccomp(statuses []TaskStatus) (ok bool, offending TaskStatus) {
	for _, st := range statuses {
		if st.NoNewPrivs != 1 || st.Seccomp != 2 {
			return false, st
		}
	}
	return true, TaskStatus{}
}

// AllCapEffEmpty reports whether every thread in statuses has an empty
// effective capability set.
func AllCapEffEmpty(statuses []TaskStatus) (ok bool, offending TaskStatus) {
	for _, st := range statuses {
		if st.CapEffective != 0 {
			return false, st
		}
	}
	return true, TaskStatus{}
}

// AllCapsExclude reports whether every thread in statuses has none of mask
// set in either its effective or its permitted capability set. It is used
// to confirm CAP_BPF/CAP_PERFMON are gone from every thread after DropAll,
// not just lowered on the one thread that called it.
func AllCapsExclude(statuses []TaskStatus, mask uint64) (ok bool, offending TaskStatus) {
	for _, st := range statuses {
		if st.CapEffective&mask != 0 || st.CapPermitted&mask != 0 {
			return false, st
		}
	}
	return true, TaskStatus{}
}
