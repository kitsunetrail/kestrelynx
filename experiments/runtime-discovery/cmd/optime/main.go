// Command optime runs one child command and prints a single JSON line reporting its own
// pid, /proc/<pid>/stat starttime, wall-clock start/end, and CLOCK_MONOTONIC duration in
// microseconds - a tiny, dependency-free replacement for timing a short-lived command
// (curl/git/openssl, each often well under 100ms) from a shell fixture, where the only
// monotonic clock a plain POSIX shell can reach without spawning an extra process
// (/proc/uptime) only reports BOOTTIME to 10ms resolution, coarse enough to distort a
// sub-100ms measurement by a double-digit percentage, and where forking a second process
// (a shell subshell, awk, date) to read a timestamp adds its own latency inside the very
// interval being measured.
//
// The pid and starttime this program reports are the WRAPPED COMMAND's own - not this
// program's own pid - because that identity (pid, starttime) is what this fixture's own
// occurrences.jsonl/usage.jsonl already key on to pair a logged occurrence with the
// matching runtime-events exec record and with the process's own exec/exit pair; this
// program runs the command as its own child (via os/exec, which forks and execs, not
// exec()-replaces-self), so it can and does read /proc/<child pid>/stat before the child
// exits, exactly the value the shell-level "$!"-based version this replaces used to read
// directly.
//
// Go's time.Time already carries a monotonic reading taken via the same CLOCK_MONOTONIC
// vDSO/syscall path the kernel exposes (see the time package's own documentation on
// monotonic clocks); two time.Now() values' own Sub() therefore already IS a
// CLOCK_MONOTONIC-based duration, at whatever resolution the platform's own clock actually
// offers (nanoseconds here, truncated to microseconds for this program's own output) -
// nothing else needs to be done to obtain it.
//
// Usage: optime -- cmd [args...]
// Output (one line, stdout):
//
//	{"pid":N,"starttime":N,"start_wall":...,"end_wall":...,"duration_us":N,"exit_code":N,"clock_source":"CLOCK_MONOTONIC"}
//
// "starttime" is 0 (with the child's own pid still reported) when /proc/<pid>/stat could
// not be read before the child exited - never a fabricated value. The wrapped command's
// own stdout/stderr are discarded (matching os-ops.sh's own prior ">/dev/null 2>&1"
// convention), never mixed into this program's own JSON stdout line.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const wallFormat = "2006-01-02T15:04:05.000000000Z"

// readStarttime parses field 22 (starttime, clock ticks since boot) of /proc/<pid>/stat.
// Field 2 (the command name) is parenthesized and may itself contain ")", so the search
// for the field boundary looks for the LAST ")" on the line, exactly as this fixture's own
// prior shell implementation (starttime_of in os-ops.sh) did.
func readStarttime(pid int) (int64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	line := string(data)
	closeParen := strings.LastIndex(line, ")")
	if closeParen < 0 || closeParen+1 > len(line) {
		return 0, fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}
	fields := strings.Fields(line[closeParen+1:])
	// Fields after the closing paren start at what /proc/pid/stat's own field 3 (state);
	// field 22 (starttime) is therefore index 22-3=19 in this slice.
	const starttimeIndex = 19
	if len(fields) <= starttimeIndex {
		return 0, fmt.Errorf("/proc/%d/stat has too few fields after the command name", pid)
	}
	return strconv.ParseInt(fields[starttimeIndex], 10, 64)
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: optime -- cmd [args...]")
		os.Exit(2)
	}

	cmd := exec.Command(args[0], args[1:]...)
	// Discarded, not inherited: this program's own stdout carries only the one JSON line
	// below, which a caller (os-ops.sh, via command substitution) depends on being the
	// only thing there.
	cmd.Stdout, cmd.Stderr = nil, nil

	startWall := time.Now().UTC()
	startMono := time.Now()
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "optime: %v\n", err)
		fmt.Printf("{\"pid\":0,\"starttime\":0,\"start_wall\":%q,\"end_wall\":%q,\"duration_us\":0,\"exit_code\":-1,\"clock_source\":\"CLOCK_MONOTONIC\"}\n",
			startWall.Format(wallFormat), time.Now().UTC().Format(wallFormat))
		os.Exit(1)
	}
	pid := cmd.Process.Pid
	// Read before Wait(), while /proc/<pid> is guaranteed to still exist: a starttime read
	// attempted after the child has already been reaped would find nothing there at all.
	starttime, stErr := readStarttime(pid)

	err := cmd.Wait()
	endMono := time.Now()
	endWall := time.Now().UTC()

	// endMono.Sub(startMono) resolves to the monotonic-clock difference whenever both
	// operands carry a monotonic reading (true for any two bare time.Now() values, per the
	// time package's own documented behavior) - this is the CLOCK_MONOTONIC duration this
	// program exists to obtain, not a wall-clock subtraction.
	durationUS := endMono.Sub(startMono).Microseconds()

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// Go's own convention for a signal-terminated child (no portable POSIX exit
			// code exists for that case); recorded as-is rather than reverse-engineered
			// into a shell-style 128+signum number this program did not itself observe.
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
			fmt.Fprintf(os.Stderr, "optime: %v\n", err)
		}
	}
	if stErr != nil {
		fmt.Fprintf(os.Stderr, "optime: starttime: %v\n", stErr)
	}

	fmt.Printf("{\"pid\":%d,\"starttime\":%d,\"start_wall\":%q,\"end_wall\":%q,\"duration_us\":%d,\"exit_code\":%d,\"clock_source\":\"CLOCK_MONOTONIC\"}\n",
		pid, starttime, startWall.Format(wallFormat), endWall.Format(wallFormat), durationUS, exitCode)
}
