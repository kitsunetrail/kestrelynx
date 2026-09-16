// A statically linked server that records its own start as an individually
// identified occurrence, and then waits.
//
// It exists to test whether an execution can be related back to the
// packages a scan report attributes to the binary. A compiled binary
// carries every module built into it, so the report hangs all of them off
// one file — which means executing the binary confirms the file and
// nothing finer. The occurrence log records the execution of the binary,
// and says nothing about which module ran.
//
// The program is started by a wrapper that waits for a signal and then
// replaces itself with this binary, so the execution happens after the
// observation is in place rather than while it is still starting up. The
// execution this program records is its own: it reads its own process
// number and generation start, which is the same generation the wrapper
// had, because replacing a program does not start a new process.
//
// It deliberately depends on a module with known reported vulnerabilities;
// which version and why is recorded in the case definition.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/language"
)

const (
	usageLog      = "/var/log/usage.jsonl"
	occurrenceLog = "/var/log/occurrences.jsonl"
)

func main() {
	caseID := envOr("CASE_ID", "22")
	fireDir := envOr("FIRE_DIR", "/run/fire")

	// Each container start is its own run; a log left by a previous one
	// would be ground truth for nothing. The wrapper that waits for the
	// signal does not write these, so truncating here is safe: this
	// program starts only after the signal.
	for _, p := range []string{usageLog, occurrenceLog} {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "truncate log:", err)
		}
	}

	pid := os.Getpid()
	starttime := selfStarttime()
	exe, err := os.Executable()
	if err != nil {
		exe = "/server"
	}
	containerID := readContainerID(fireDir)
	now := stamp()

	appendJSON(usageLog, map[string]any{
		"ts": now, "pid": pid, "starttime": starttime,
		"event": "exec", "path": exe, "ok": true,
	})
	// The thread identifier equals the process identifier: this is the
	// first thread of the program that has just started running.
	appendJSON(occurrenceLog, map[string]any{
		"id": caseID + "-exec-000001", "kind": "exec",
		"pid": pid, "tid": pid, "starttime": starttime,
		"ts": now, "ok": true, "path": exe, "container_id": containerID,
	})

	// One call into the dependency, so the module is genuinely part of the
	// program rather than an unused import the compiler could drop.
	tag := language.Make(envOr("LANGUAGE_TAG", "en-US"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ok %s\n", tag)
	})
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	if err := http.Serve(ln, mux); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func stamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// selfStarttime reads field 22 of this process's status line. Field 2 is
// parenthesized and may itself contain ")", so parsing starts after the
// last one.
func selfStarttime() int64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	line := string(data)
	idx := strings.LastIndexByte(line, ')')
	if idx < 0 {
		return 0
	}
	fields := strings.Fields(line[idx+1:])
	if len(fields) <= 19 {
		return 0
	}
	v, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func readContainerID(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "container-id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func appendJSON(path string, record map[string]any) {
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "append log:", err)
	}
}
