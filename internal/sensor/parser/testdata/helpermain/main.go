// Command helpermain is the real, standalone parser process every
// internal/sensor/parser test execs as a child, communicating with the
// test (standing in for the observer) over fd 3.
//
// It is a genuinely separate, dependency-minimal binary rather than the
// `go test` binary re-exec'd on itself, for the same reason
// internal/sensor/sandbox's own helpermain is: see that package's
// testdata/helpermain/main.go for the full explanation (in short, a Go
// 1.26 process eventually needs epoll/eventfd machinery regardless of user
// code, and parser.ParserFilter's allow-list already accounts for that —
// this binary is what actually exercises the real, filtered code path
// end-to-end, not a proxy for it).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/parser"
	"golang.org/x/sys/unix"
)

// echoHandler reads up to 256 bytes from the fd it is handed (via a plain
// read(2), never wrapped in *os.File — condition 3 of the parser
// conditions names read/pread64 specifically, and this avoids relying on
// anything *os.File's setup might probe) and reports how much it read and
// the bytes themselves, so a test can confirm the fd it sent is the fd the
// parser actually read from.
type echoHandler struct{}

func (echoHandler) Handle(kind string, fd int) (json.RawMessage, error) {
	buf := make([]byte, 256)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return nil, fmt.Errorf("read fd for kind %q: %w", kind, err)
	}
	return json.Marshal(struct {
		Kind string `json:"kind"`
		Len  int    `json:"len"`
		Data string `json:"data"`
	}{Kind: kind, Len: n, Data: string(buf[:n])})
}

// cpuLoopHandler never returns on its own: it is what
// TestRun_TerminatesOnRequestTimeout uses to prove Run's per-request
// watchdog fires even while Handler.Handle itself is stuck, not just while
// idle between requests. It never touches the fd it is handed at all
// (condition 4 only promises the fd is safe to use, not that every Handler
// has to); the loop itself is call-free on purpose, the same shape as
// sandbox's own async-preemption tests, so the only way anything can ever
// interrupt it is the same asynchronous preemption signal Run's watchdog
// timer goroutine depends on to get scheduled at all under GOMAXPROCS(1).
type cpuLoopHandler struct{}

func (cpuLoopHandler) Handle(kind string, fd int) (json.RawMessage, error) {
	x := 0
	for {
		for j := 0; j < 1<<28; j++ {
			x += j
		}
	}
}

func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	ms, err := strconv.Atoi(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s=%q: %v\n", name, v, err)
		os.Exit(2)
	}
	return time.Duration(ms) * time.Millisecond
}

func main() {
	var handler parser.Handler = echoHandler{}
	if os.Getenv("KL_PARSER_HANDLER") == "cpuloop" {
		handler = cpuLoopHandler{}
	}
	cfg := parser.Config{
		SocketFD:       3,
		Handler:        handler,
		MaxLifetime:    envDuration("KL_PARSER_MAX_LIFETIME_MS", 60*time.Second),
		RequestTimeout: envDuration("KL_PARSER_REQUEST_TIMEOUT_MS", 30*time.Second),
		RecvTimeout:    envDuration("KL_PARSER_RECV_TIMEOUT_MS", 200*time.Millisecond),
	}
	if err := parser.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "parser.Run: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
