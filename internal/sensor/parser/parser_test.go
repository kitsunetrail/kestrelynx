package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// spawnParser creates a SOCK_SEQPACKET socketpair, hands one end to a
// freshly-started copy of testdata/helpermain as fd 3, and returns the
// parent's end (a raw fd, matching how the real observer would hold it)
// plus the running command.
func spawnParser(t *testing.T, extraEnv ...string) (parentFD int, cmd *exec.Cmd) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	childFile := os.NewFile(uintptr(fds[1]), "child-sock")

	cmd = exec.Command(buildHelperBin(t))
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Stderr = os.Stderr // surface any parser.Run error directly in test output

	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	childFile.Close() // child has its own dup; this copy is no longer needed

	if err := unix.SetsockoptTimeval(fds[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		t.Fatalf("set recv timeout: %v", err)
	}

	t.Cleanup(func() {
		unix.Close(fds[0])
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return fds[0], cmd
}

// recvEnvelope reads exactly one message from fd and decodes it as a
// wireEnvelope.
func recvEnvelope(t *testing.T, fd int) wireEnvelope {
	t.Helper()
	buf := make([]byte, maxRequestBytes)
	n, _, _, _, err := unix.Recvmsg(fd, buf, nil, 0)
	if err != nil {
		t.Fatalf("recvmsg: %v", err)
	}
	var env wireEnvelope
	if err := json.Unmarshal(buf[:n], &env); err != nil {
		t.Fatalf("unmarshal envelope %q: %v", buf[:n], err)
	}
	return env
}

// sendRequest sends one Request plus fd as SCM_RIGHTS ancillary data, the
// same shape the real observer will send.
func sendRequest(t *testing.T, sockFD int, kind string, fd int) {
	t.Helper()
	body, err := json.Marshal(Request{Kind: kind})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	oob := unix.UnixRights(fd)
	if err := unix.Sendmsg(sockFD, body, oob, nil, 0); err != nil {
		t.Fatalf("sendmsg request: %v", err)
	}
}

// tempFileWithContent creates a real file (so the fd sent across is a
// genuine, read-only-openable file the way the observer's rootfs package
// would hand one over) and returns an fd opened O_RDONLY on it.
func tempFileWithContent(t *testing.T, content string) int {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "kl-parser-test-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	name := f.Name()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	fd, err := unix.Open(name, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open temp file: %v", err)
	}
	return fd
}

// TestRun_ReportsThenEchoesRequest exercises the IPC contract: the
// parser reports its self-check first, then for each Request+fd it
// receives, reads that exact fd's content and replies with a Response
// carrying it — round-tripping through the real Landlock+seccomp-restricted
// process, not a mock.
func TestRun_ReportsThenEchoesRequest(t *testing.T) {
	sockFD, _ := spawnParser(t)

	env := recvEnvelope(t, sockFD)
	if env.Report == nil {
		t.Fatalf("first message was not a report: %+v", env)
	}
	if !env.Report.LandlockApplied {
		t.Errorf("LandlockApplied = false; this dev environment is expected to support Landlock (ABI reported elsewhere as 3)")
	}
	if env.Report.LandlockABI < 1 {
		t.Errorf("LandlockABI = %d, want >= 1", env.Report.LandlockABI)
	}

	dataFD := tempFileWithContent(t, "hello from the observer")
	sendRequest(t, sockFD, "dpkg_status", dataFD)
	unix.Close(dataFD) // the parser has its own dup via SCM_RIGHTS by now

	respEnv := recvEnvelope(t, sockFD)
	if respEnv.Response == nil {
		t.Fatalf("second message was not a response: %+v", respEnv)
	}
	if !respEnv.Response.OK {
		t.Fatalf("response not OK: %+v", respEnv.Response)
	}
	var got struct {
		Kind string `json:"kind"`
		Len  int    `json:"len"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(respEnv.Response.Result, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got.Kind != "dpkg_status" || got.Data != "hello from the observer" {
		t.Errorf("got %+v, want kind=dpkg_status data=%q", got, "hello from the observer")
	}
}

// TestRun_SelfTerminates covers self-termination: with no further
// requests sent, the parser exits on its own once MaxLifetime elapses,
// rather than waiting indefinitely for the observer.
func TestRun_SelfTerminates(t *testing.T) {
	sockFD, cmd := spawnParser(t,
		"KL_PARSER_MAX_LIFETIME_MS=500",
		"KL_PARSER_RECV_TIMEOUT_MS=100",
	)
	_ = recvEnvelope(t, sockFD) // the initial report

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("parser exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parser did not self-terminate within 5s of a 500ms MaxLifetime")
	}
}

// TestRun_ExitsWhenObserverCloses confirms the parser notices the observer
// closing its end promptly (via the SOCK_SEQPACKET orderly-shutdown
// zero-length read) and exits cleanly, rather than only ever exiting via
// the MaxLifetime path.
func TestRun_ExitsWhenObserverCloses(t *testing.T) {
	sockFD, cmd := spawnParser(t,
		"KL_PARSER_MAX_LIFETIME_MS=60000",
		"KL_PARSER_RECV_TIMEOUT_MS=100",
	)
	_ = recvEnvelope(t, sockFD)
	unix.Close(sockFD)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("parser exited with error after observer closed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parser did not exit within 5s of the observer closing its end")
	}
}

// TestRun_TerminatesOnRequestTimeout covers the completion condition a
// process-lifetime-only test cannot: Run's watchdog must fire even while
// Handler.Handle itself is stuck, not just while idle waiting for the next
// request. It sends one request carrying a genuine read-only fd (condition
// 4 preserved) to a parser whose Handler never returns (a call-free CPU
// loop, testdata/helpermain's cpuLoopHandler), with a MaxLifetime far
// longer than RequestTimeout so only the per-request watchdog — not the
// idle-lifetime path already covered by TestRun_SelfTerminates — could
// possibly account for the process exiting. A pass here also confirms
// GOMAXPROCS(1) does not stop the watchdog goroutine's timer from firing:
// that requires the same asynchronous-preemption signal
// TestAsyncPreemption_SurvivesParserFilter (sandbox package) checks
// directly, exercised here through Run's real code path instead of a
// synthetic busy loop.
func TestRun_TerminatesOnRequestTimeout(t *testing.T) {
	sockFD, cmd := spawnParser(t,
		"KL_PARSER_HANDLER=cpuloop",
		"KL_PARSER_MAX_LIFETIME_MS=60000",
		"KL_PARSER_REQUEST_TIMEOUT_MS=500",
		"KL_PARSER_RECV_TIMEOUT_MS=100",
	)
	_ = recvEnvelope(t, sockFD) // the initial report

	dataFD := tempFileWithContent(t, "irrelevant: the handler never reads it")
	sendRequest(t, sockFD, "cpu-loop", dataFD)
	unix.Close(dataFD)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("parser exited with a non-ExitError: %v", err)
		}
		if exitErr.ExitCode() != exitCodeRequestTimeout {
			t.Errorf("exit code = %d, want %d (exitCodeRequestTimeout)", exitErr.ExitCode(), exitCodeRequestTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parser did not terminate within 5s of a 500ms RequestTimeout, with MaxLifetime=60s (the CPU-loop Handler must have blocked the per-request watchdog, not just the idle path)")
	}
}

// clockTicksPerSec is sysconf(_SC_CLK_TCK), the unit /proc/*/stat's utime
// and stime fields are counted in. This is not read dynamically (there is
// no allocation-free, dependency-free way to call sysconf from a test
// without cgo); 100 is the value on every Linux configuration this
// codebase targets (x86_64 and aarch64, both USER_HZ=100 by convention
// since Linux made this a fixed constant independent of the kernel's own
// internal HZ, specifically so that changing HZ would not require
// recompiling userspace tools that read /proc).
const clockTicksPerSec = 100

// threadCPUTicksTotal sums utime+stime (in clock ticks) across every
// thread listed under /proc/<pid>/task at the moment of the call, which is
// how a denied nanosleep shows up: a second,
// spinning thread shows up here as roughly as many ticks as the one
// actually doing the requested work, not as a rounding error.
func threadCPUTicksTotal(t *testing.T, pid int) uint64 {
	t.Helper()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/task: %v", pid, err)
	}
	var total uint64
	for _, e := range entries {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/stat", pid, e.Name()))
		if err != nil {
			continue // thread exited between the readdir and this read
		}
		// Fields: pid (comm) state ppid ... utime stime ...\n — comm is
		// parenthesized and may itself contain spaces or parens, so the
		// only reliable split point is the *last* ')' in the line (the
		// same approach proc(5)-reading tools use), leaving "state ppid
		// ... utime stime ..." to split on whitespace, 0-indexed from
		// state (field 3 in the full record).
		line := string(data)
		closeParen := strings.LastIndexByte(line, ')')
		if closeParen < 0 {
			t.Fatalf("unparseable stat line for pid %d task %s: %q", pid, e.Name(), line)
		}
		fields := strings.Fields(line[closeParen+1:])
		const (
			utimeIdx = 14 - 3 // field 14 in the full record
			stimeIdx = 15 - 3 // field 15
		)
		if len(fields) <= stimeIdx {
			t.Fatalf("stat line for pid %d task %s has too few fields: %q", pid, e.Name(), line)
		}
		utime, err := strconv.ParseUint(fields[utimeIdx], 10, 64)
		if err != nil {
			t.Fatalf("parse utime for pid %d task %s: %v", pid, e.Name(), err)
		}
		stime, err := strconv.ParseUint(fields[stimeIdx], 10, 64)
		if err != nil {
			t.Fatalf("parse stime for pid %d task %s: %v", pid, e.Name(), err)
		}
		total += utime + stime
	}
	return total
}

// TestRun_DoesNotBusySpinOtherThreadsWhileHandlerRuns covers the
// nanosleep gap found in this package's own filter: with nanosleep denied,
// the Go runtime's monitor thread (sysmon) cannot actually sleep between
// its checks — its own usleep call ignores the syscall's return value —
// so it spins as fast as it can instead, burning close to a full extra
// CPU core for as long as the process runs, entirely independent of
// whatever the Handler itself is doing. This measures total CPU time
// across every thread (via /proc/<pid>/task/*/stat) across a window where
// a real cpuloop Handler is genuinely using one core's worth of CPU, and
// requires the total to stay close to that one core's worth — not
// noticeably closer to two.
func TestRun_DoesNotBusySpinOtherThreadsWhileHandlerRuns(t *testing.T) {
	sockFD, cmd := spawnParser(t,
		"KL_PARSER_HANDLER=cpuloop",
		"KL_PARSER_MAX_LIFETIME_MS=60000",
		"KL_PARSER_REQUEST_TIMEOUT_MS=3000",
		"KL_PARSER_RECV_TIMEOUT_MS=100",
	)
	_ = recvEnvelope(t, sockFD) // the initial report

	dataFD := tempFileWithContent(t, "irrelevant: the handler never reads it")
	sendRequest(t, sockFD, "cpu-loop", dataFD)
	unix.Close(dataFD)

	pid := cmd.Process.Pid
	// A short warm-up so the busy loop is genuinely running (and, if the
	// bug is present, so sysmon has had time to start spinning) before the
	// measurement window starts.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	ticksBefore := threadCPUTicksTotal(t, pid)
	const window = 1500 * time.Millisecond
	time.Sleep(window)
	ticksAfter := threadCPUTicksTotal(t, pid)
	elapsed := time.Since(start)

	cpuSeconds := float64(ticksAfter-ticksBefore) / clockTicksPerSec
	wallSeconds := elapsed.Seconds()

	// The busy-loop thread alone accounts for ~wallSeconds of CPU time
	// (GOMAXPROCS(1): only one goroutine can be running Go code at a
	// time). A second thread spinning on a denied nanosleep would add
	// close to another full wallSeconds on top of that (a reproduction
	// measured 1.69s and 1.68s of CPU across two threads over a 1.7s
	// wall-clock window — essentially 2x). 1.5x wallSeconds
	// is comfortably above legitimate scheduler/GC overhead and
	// comfortably below what a second fully-spinning thread would add.
	if cpuSeconds > wallSeconds*1.5 {
		t.Errorf("total CPU time %.2fs over a %.2fs window (ratio %.2f); want close to 1x wall-clock, not ~2x — a thread appears to be busy-spinning instead of sleeping",
			cpuSeconds, wallSeconds, cpuSeconds/wallSeconds)
	} else {
		t.Logf("total CPU time %.2fs over a %.2fs window (ratio %.2f)", cpuSeconds, wallSeconds, cpuSeconds/wallSeconds)
	}

	_ = cmd.Process.Kill()
}

// TestSendmsg_SeqPacketIgnoresDestinationAddress exercises the IPC channel
// directly at the kernel level, no parser process involved: a
// SOCK_SEQPACKET pair is connected at creation, and sendmsg's destination
// address argument cannot redirect a message to some other socket. This is
// the kernel property (net/unix/af_unix.c: unix_seqpacket_sendmsg forces
// msg_namelen to 0 before handing off to unix_dgram_sendmsg, so a connected
// SOCK_SEQPACKET socket always delivers to its one peer regardless of what
// address the caller passes) that makes treating the observer/parser
// socketpair as a fixed, un-redirectable channel safe; this test checks it
// against the real running kernel instead of only trusting that reading.
func TestSendmsg_SeqPacketIgnoresDestinationAddress(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])

	// A decoy socket that is a syntactically valid sendmsg destination but
	// must never receive anything: an abstract-namespace AF_UNIX datagram
	// socket (no filesystem entry to clean up).
	decoyName := fmt.Sprintf("\x00kl-parser-test-decoy-%d", os.Getpid())
	decoyFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socket(decoy): %v", err)
	}
	defer unix.Close(decoyFD)
	if err := unix.Bind(decoyFD, &unix.SockaddrUnix{Name: decoyName}); err != nil {
		t.Fatalf("bind(decoy): %v", err)
	}
	if err := unix.SetsockoptTimeval(decoyFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000}); err != nil {
		t.Fatalf("set decoy recv timeout: %v", err)
	}

	msg := []byte("do-not-redirect-me")
	to := &unix.SockaddrUnix{Name: decoyName}
	if err := unix.Sendmsg(pair[0], msg, nil, to, 0); err != nil {
		// Some kernels reject a non-nil destination on an already-connected
		// socket outright (EISCONN); that is itself evidence the address
		// had no effect, since the alternative (silently redirecting) is
		// what this test is checking is impossible.
		t.Logf("sendmsg with a destination on a connected SOCK_SEQPACKET returned %v (also acceptable: rejected outright)", err)
	} else {
		buf := make([]byte, 64)
		n, _, _, _, err := unix.Recvmsg(pair[1], buf, nil, 0)
		if err != nil {
			t.Fatalf("recvmsg(true peer): %v", err)
		}
		if string(buf[:n]) != string(msg) {
			t.Errorf("true peer got %q, want %q", buf[:n], msg)
		}
	}

	decoyBuf := make([]byte, 64)
	if n, _, _, _, err := unix.Recvmsg(decoyFD, decoyBuf, nil, 0); err == nil {
		t.Errorf("decoy socket unexpectedly received %q; sendmsg's destination address redirected the message", decoyBuf[:n])
	}
}
