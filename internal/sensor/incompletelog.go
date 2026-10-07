package sensor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// incompleteLogWriter is where the Sensor reports why a generation's
// evidence is incomplete. It defaults to stderr, so an operator can read the
// reasons from the container's own log; tests replace it to capture output.
// It is only written from loop's own goroutine (generationState.logIncomplete),
// so it needs no lock of its own.
var incompleteLogWriter io.Writer = os.Stderr

// maxIncompleteDetailBytes caps every untrusted string (a path, the text of
// an error that may embed one) before it is quoted into a log line.
const maxIncompleteDetailBytes = 256

// maxSampleReasons bounds how many distinct reasons one sample result (and
// one candidate resolution) carries back to loop; anything beyond that is
// only counted.
const maxSampleReasons = 4

// quoteDiag renders s for a log line: cut to maxIncompleteDetailBytes,
// then quoted with %q so control characters and invalid UTF-8 in a
// container-supplied string cannot forge or break up a log line.
func quoteDiag(s string) string {
	if len(s) > maxIncompleteDetailBytes {
		return fmt.Sprintf("%q...", s[:maxIncompleteDetailBytes])
	}
	return strconv.Quote(s)
}

// errDiag renders err for a log line: the errno name when err wraps one
// (ENOENT, EACCES, ...), then the quoted, capped error text, since that text
// may embed a container-controlled path.
func errDiag(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return "errno=" + name + " err=" + quoteDiag(err.Error())
		}
	}
	return "err=" + quoteDiag(err.Error())
}

// incompleteReason is one cause of a generation's incompleteness: a short,
// stable snake_case code, and an already-formatted detail (every untrusted
// part quoted and capped by whoever built it).
type incompleteReason struct {
	code   string
	detail string
}

// incompleteReasons is the bounded list of reasons a sample worker reports
// back to loop. A code already present is ignored (loop logs each code once
// per generation anyway); a new code beyond maxSampleReasons only bumps
// dropped.
type incompleteReasons struct {
	list    []incompleteReason
	dropped int
}

func (r *incompleteReasons) add(code, detail string) {
	for _, e := range r.list {
		if e.code == code {
			return
		}
	}
	if len(r.list) >= maxSampleReasons {
		r.dropped++
		return
	}
	r.list = append(r.list, incompleteReason{code: code, detail: detail})
}

func (r *incompleteReasons) merge(o incompleteReasons) {
	for _, e := range o.list {
		r.add(e.code, e.detail)
	}
	r.dropped += o.dropped
}

// markIncomplete sets g.incomplete and records why (see logIncomplete).
func (g *generationState) markIncomplete(code, detail string) {
	g.incomplete = true
	g.logIncomplete(code, detail)
}

// logIncomplete writes one stderr line the first time code is seen for g,
// and never again for the same (generation, code) pair. The bookkeeping
// lives on g, so it is freed with the generation and is bounded by the
// number of distinct codes. Owned by loop, like the rest of g.
func (g *generationState) logIncomplete(code, detail string) {
	if _, seen := g.incompleteLogged[code]; seen {
		return
	}
	if g.incompleteLogged == nil {
		g.incompleteLogged = map[string]struct{}{}
	}
	g.incompleteLogged[code] = struct{}{}
	id := g.container.ID
	if len(id) > 12 {
		id = id[:12]
	}
	if detail != "" {
		detail = " " + detail
	}
	// The init PID and starttime tell apart generations of the same
	// container (a restart keeps the ID), matching the init recorded in
	// the evidence for each generation.
	fmt.Fprintf(incompleteLogWriter, "kestrelynx sensor: generation %s init=%d:%d incomplete: %s%s\n", id, g.init.PID, g.init.Starttime, code, detail)
}

// logTransientIncomplete logs, once per reason, each of the non-sticky
// conditions that currently makes this generation's published Incomplete
// true. buildSnapshot calls it on loop's goroutine right before toEvidence,
// so the log reflects exactly the state the snapshot is built from, and the
// writer goroutine that later marshals the snapshot never touches g.
func (g *generationState) logTransientIncomplete(routeEvent, lossDelta bool) {
	if g.pendingLookup != nil {
		g.logIncomplete("pending_lookup", "")
	}
	if len(g.queuedCandidates) > 0 {
		g.logIncomplete("queued_candidates", fmt.Sprintf("batches=%d", len(g.queuedCandidates)))
	}
	if g.candidatesLostPermanently {
		g.logIncomplete("candidates_lost", "")
	}
	if len(g.pendingMountViewEvents) > 0 {
		g.logIncomplete("pending_mount_view_events", fmt.Sprintf("events=%d", len(g.pendingMountViewEvents)))
	}
	if g.pendingMapsLookups > 0 {
		g.logIncomplete("pending_maps_lookups", fmt.Sprintf("lookups=%d", g.pendingMapsLookups))
	}
	if g.pendingConfirms > 0 {
		g.logIncomplete("pending_confirms", fmt.Sprintf("confirms=%d", g.pendingConfirms))
	}
	if routeEvent {
		g.logIncomplete("pending_route_event", "")
	}
	if lossDelta {
		g.logIncomplete("pending_loss_delta", "")
	}
}
