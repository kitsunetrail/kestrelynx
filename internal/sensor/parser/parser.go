// Package parser is the body of the Sensor's parser process: the child the
// observer spawns over a socketpair, before installing its own seccomp
// filter, whose only job is to turn a file descriptor it is handed into a
// parsed result without ever being able to open a file, execute anything,
// or signal another process itself.
//
// This package does not know how to parse a dpkg status file or an apk
// database — that is the Handler's job, supplied by the caller. Keeping
// the parsing logic out of this package entirely is deliberate: this
// package's whole reason to exist is the sandboxing and IPC around
// whatever Handler ends up doing, which needs to be correct and testable
// independent of what the parser is actually parsing or which package
// implements that parsing.
package parser

import "encoding/json"

// Request is the one message shape the observer sends: a kind string
// naming what the accompanying file descriptor is (interpretation is the
// Handler's), with the fd itself carried out-of-band as SCM_RIGHTS
// ancillary data on the same sendmsg call, never in the JSON body.
//
// This wire shape — one JSON object per SOCK_SEQPACKET message, exactly one
// fd per request — is this package's own choice: nothing about a
// SOCK_SEQPACKET socketpair or SCM_RIGHTS forces this specific framing, so
// it is documented here explicitly, not left implicit, giving whatever
// implements the observer side of this socket a fixed contract to write
// against.
type Request struct {
	Kind string `json:"kind"`
}

// Response is the one message shape the parser sends back, exactly one per
// Request, in order.
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler parses whatever fd identifies, given the request's Kind, and
// returns the result to send back as Response.Result. Handle must not
// retain fd beyond the call: Run closes it immediately after Handle
// returns, whether or not it returned an error.
type Handler interface {
	Handle(kind string, fd int) (json.RawMessage, error)
}
