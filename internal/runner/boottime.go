package runner

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// hostBootTime reads the host's boot time from /proc/stat's "btime" line —
// seconds since the Unix epoch, world-readable, no special privilege needed
// (kernel v6.6 fs/proc/stat.c). It exists to convert a Sensor evidence
// generation's InitProcess.Starttime (a boot-relative clock-tick value) into
// a wall-clock instant comparable with Docker's own StartedAt; see
// analyze.GenerationInspect.BootTime's own doc comment for why that
// conversion happens here, in the runner, rather than inside the (otherwise
// pure) analyze package.
func hostBootTime() (time.Time, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "btime ")
		if !ok {
			continue
		}
		sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse /proc/stat btime %q: %w", rest, err)
		}
		return time.Unix(sec, 0), nil
	}
	if err := sc.Err(); err != nil {
		return time.Time{}, fmt.Errorf("scan /proc/stat: %w", err)
	}
	return time.Time{}, fmt.Errorf("no btime line found in /proc/stat")
}
