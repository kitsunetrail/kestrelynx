package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// maxRequestBytes bounds one request's JSON body. A Request is just a kind
// string; there is no legitimate reason for it to be large, and an
// oversized read buffer would only give a compromised observer more room to
// do something unexpected with a process that has no capability to defend
// itself with beyond refusing to play along.
const maxRequestBytes = 4096

// exitCodeRequestTimeout is the process exit code used when a single
// request (Handler.Handle plus sending its response) runs past
// cfg.RequestTimeout. It is distinct from other exit paths only for
// whoever is reading logs after the fact; the observer's own reaction to
// any non-zero parser exit is the same regardless of the code (see
// Config.RequestTimeout's doc comment).
const exitCodeRequestTimeout = 3

// Config is everything Run needs to serve requests until it self-terminates.
type Config struct {
	// SocketFD is the SOCK_SEQPACKET end of the socketpair the observer
	// created before spawning this process. Run never opens, closes, or
	// duplicates it other than at the very end of its own run.
	SocketFD int
	// Handler parses whatever fd each Request identifies.
	Handler Handler
	// MaxLifetime is the total time budget for this process, starting from
	// the first call to Run. Once it elapses, Run returns nil (a clean
	// self-termination, not an error) even mid-idle, without waiting for
	// the observer to do anything. Zero means no idle-lifetime limit (only
	// RequestTimeout still applies once a request arrives).
	MaxLifetime time.Duration
	// RequestTimeout bounds a single request end to end: from the moment
	// Run finishes receiving it to the moment it finishes sending the
	// response, including all of Handler.Handle. Unlike MaxLifetime (a
	// clean return from Run), exceeding this calls os.Exit directly, from
	// a timer goroutine running concurrently with whatever Handler.Handle
	// is doing — the whole point being to terminate even if Handle itself
	// never returns (an infinite loop, a hung read on a crafted input). It
	// defaults to 30s if zero or negative.
	RequestTimeout time.Duration
	// RecvTimeout bounds each individual wait for the next request: Run
	// never blocks in a single poll(2) call for longer than this, so
	// MaxLifetime is checked at least this often while idle. It defaults
	// to 1s if zero or negative. It has no bearing on correctness beyond
	// how promptly MaxLifetime is noticed; tests use a short value to keep
	// runtime down.
	RecvTimeout time.Duration
}

// Run reports LockDown's self-check result as the first message on
// cfg.SocketFD (see protocol.go), and then serves requests until one of:
// the observer closes its end (a clean return), cfg.MaxLifetime elapses
// while idle (a clean, self-initiated return), a single request exceeds
// cfg.RequestTimeout (os.Exit(exitCodeRequestTimeout), not a return — see
// handleOneRequest), or an unrecoverable protocol or syscall error (a
// returned error).
//
// Run calls LockDown itself: by the time a caller can reach the request
// loop, containment must already be in effect, so there is no path to call
// Run without also having applied it.
func Run(cfg Config) error {
	if cfg.RecvTimeout <= 0 {
		cfg.RecvTimeout = time.Second
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}

	report, err := LockDown()
	if err != nil {
		return err
	}

	if err := sendReport(cfg.SocketFD, report); err != nil {
		return fmt.Errorf("parser: send self-check report: %w", err)
	}

	var deadline time.Time
	if cfg.MaxLifetime > 0 {
		deadline = time.Now().Add(cfg.MaxLifetime)
	}
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return nil
		}

		ready, err := waitReadable(cfg.SocketFD, cfg.RecvTimeout)
		if err != nil {
			return err
		}
		if !ready {
			continue // poll timed out; recheck the idle deadline above
		}

		req, fd, err := recvRequest(cfg.SocketFD)
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}

		if err := handleOneRequest(cfg, req, fd); err != nil {
			return err
		}
	}
}

// waitReadable blocks until cfg.SocketFD has data to read, an EOF/hangup to
// report, or timeout elapses, using poll(2) — not setsockopt(SO_RCVTIMEO):
// setsockopt is excluded from the Sensor's distributed container-wide
// seccomp profile entirely (it has no legitimate use for a process that
// never touches a socket option after the observer creates the
// socketpair), so a parser that tried to set a receive timeout that way
// would fail before ever reporting its self-check, regardless of what its
// own allow-list permits. poll (via golang.org/x/sys/unix.Poll, which
// calls ppoll(2) on Linux on every architecture this package supports) has
// no such exclusion and is in ParserFilter's own allow-list.
func waitReadable(fd int, timeout time.Duration) (bool, error) {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	ms := int(timeout / time.Millisecond)
	for {
		n, err := unix.Poll(pfd, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("poll: %w", err)
		}
		return n > 0, nil
	}
}

// handleOneRequest runs Handler.Handle and sends its response, under a
// watchdog timer that calls os.Exit if the whole thing — Handle included —
// takes longer than cfg.RequestTimeout. The timer runs in its own
// goroutine, independent of whatever handleOneRequest's own goroutine is
// doing, which is what lets it fire even if Handle never returns: with
// GOMAXPROCS(1) (LockDown sets this), the runtime cannot give the timer's
// goroutine a second P to run on, but it does not need one — the Go
// scheduler's asynchronous preemption (a signal sent from a separate OS
// thread outside any P, forcing the currently running goroutine to yield)
// is what lets the timer goroutine get scheduled at all, and ParserFilter
// already has to allow exactly the two syscalls that mechanism uses
// (tgkill to the process's own thread, then rt_sigreturn) for the runtime
// to keep working under this seccomp filter in the first place.
func handleOneRequest(cfg Config, req Request, fd int) error {
	timer := time.AfterFunc(cfg.RequestTimeout, func() {
		os.Exit(exitCodeRequestTimeout)
	})
	defer timer.Stop()

	result, handleErr := cfg.Handler.Handle(req.Kind, fd)
	unix.Close(fd)

	resp := Response{OK: handleErr == nil}
	if handleErr != nil {
		resp.Error = handleErr.Error()
	} else {
		resp.Result = result
	}
	if err := sendResponse(cfg.SocketFD, resp); err != nil {
		return fmt.Errorf("parser: send response: %w", err)
	}
	return nil
}

// wireEnvelope is the first-message-only wrapper Run sends instead of a
// Response, distinguishing the initial self-check report from every
// Response that follows: a receiver needs to tell the two apart with
// nothing more than the bytes of one SOCK_SEQPACKET message, since there
// is no separate framing layer underneath.
type wireEnvelope struct {
	Report   *Report   `json:"report,omitempty"`
	Response *Response `json:"response,omitempty"`
}

func sendReport(fd int, r Report) error {
	return sendJSON(fd, wireEnvelope{Report: &r})
}

// ReadReport receives the one message Run sends before serving any request:
// the parser's self-check Report (see LockDown). It is the observer side's
// half of sendReport, exported for whatever spawns the parser process and
// needs to know whether the parser came up fully isolated
// (Report.LandlockApplied) before handing it a single fd. It returns an
// error if the message is not a report (a Response arriving first would
// itself be a protocol violation — Run always sends exactly one report
// before its first response) or if the socket closed before one arrived
// (the parser exited during LockDown, which never sends a report at all;
// see ErrPreCheckFailed/ErrPostCheckFailed's doc comments).
func ReadReport(fd int) (Report, error) {
	buf := make([]byte, maxRequestBytes)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return Report{}, fmt.Errorf("parser: read report: %w", err)
	}
	if n == 0 {
		return Report{}, fmt.Errorf("parser: read report: socket closed before a report arrived")
	}
	var env wireEnvelope
	if err := json.Unmarshal(buf[:n], &env); err != nil {
		return Report{}, fmt.Errorf("parser: read report: unmarshal: %w", err)
	}
	if env.Report == nil {
		return Report{}, fmt.Errorf("parser: read report: first message was not a report")
	}
	return *env.Report, nil
}

func sendResponse(fd int, r Response) error {
	return sendJSON(fd, wireEnvelope{Response: &r})
}

func sendJSON(fd int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return unix.Sendmsg(fd, body, nil, nil, 0)
}

// recvRequest reads exactly one SOCK_SEQPACKET message: the JSON Request
// body plus exactly one fd carried as SCM_RIGHTS ancillary data on the same
// message. It rejects (as a protocol error, not silently ignoring the
// extra) a message carrying zero or more than one fd, or one whose control
// data was truncated (MSG_CTRUNC) — the fd is the one thing this package
// promises never to exceed one of per request, so a message it cannot
// account for precisely is treated as fatal rather than guessed at.
func recvRequest(sockFD int) (Request, int, error) {
	buf := make([]byte, maxRequestBytes)
	oob := make([]byte, unix.CmsgSpace(4)) // exactly one int fd

	n, oobn, flags, _, err := unix.Recvmsg(sockFD, buf, oob, 0)
	if err != nil {
		return Request{}, -1, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 && oobn == 0 {
		// SOCK_SEQPACKET's orderly-shutdown signal: the peer closed.
		return Request{}, -1, io.EOF
	}
	if flags&unix.MSG_TRUNC != 0 {
		return Request{}, -1, fmt.Errorf("recvmsg: request body truncated (over %d bytes)", maxRequestBytes)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return Request{}, -1, fmt.Errorf("recvmsg: control data truncated (more than one fd sent)")
	}

	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return Request{}, -1, fmt.Errorf("parse control message: %w", err)
	}
	var fds []int
	for _, c := range cmsgs {
		rights, err := unix.ParseUnixRights(&c)
		if err != nil {
			continue // not a rights message; not this package's concern
		}
		fds = append(fds, rights...)
	}
	if len(fds) != 1 {
		for _, f := range fds {
			unix.Close(f)
		}
		return Request{}, -1, fmt.Errorf("recvmsg: expected exactly one fd, got %d", len(fds))
	}

	var req Request
	if err := json.Unmarshal(buf[:n], &req); err != nil {
		unix.Close(fds[0])
		return Request{}, -1, fmt.Errorf("unmarshal request: %w", err)
	}
	return req, fds[0], nil
}
