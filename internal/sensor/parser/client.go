package parser

import (
	"encoding/json"
	"fmt"

	"golang.org/x/sys/unix"
)

// SendRequest sends one Request carrying kind and exactly one fd (dataFD) to
// the parser process listening on sockFD, using the same wire framing Run's
// own recvRequest expects: a JSON body plus dataFD as SCM_RIGHTS ancillary
// data on the same sendmsg call. It never closes dataFD — the caller decides
// when that happens, the same way Run's handleOneRequest closing the fd on
// the receiving end is Run's own decision, not this function's.
func SendRequest(sockFD int, kind string, dataFD int) error {
	body, err := json.Marshal(Request{Kind: kind})
	if err != nil {
		return fmt.Errorf("parser: marshal request: %w", err)
	}
	rights := unix.UnixRights(dataFD)
	if err := unix.Sendmsg(sockFD, body, rights, nil, 0); err != nil {
		return fmt.Errorf("parser: sendmsg request: %w", err)
	}
	return nil
}

// ReadResponse receives one Response from sockFD: the observer side's half
// of sendResponse. It is only ever used after ReadReport has already
// consumed the one-time startup Report (see wireEnvelope's doc comment) —
// calling it before that would see the Report's bytes instead and fail to
// find a "response" key.
func ReadResponse(sockFD int) (Response, error) {
	buf := make([]byte, maxResponseBytes)
	n, err := unix.Read(sockFD, buf)
	if err != nil {
		return Response{}, fmt.Errorf("parser: read response: %w", err)
	}
	if n == 0 {
		return Response{}, fmt.Errorf("parser: read response: socket closed before a response arrived")
	}
	var env wireEnvelope
	if err := json.Unmarshal(buf[:n], &env); err != nil {
		return Response{}, fmt.Errorf("parser: read response: unmarshal: %w", err)
	}
	if env.Response == nil {
		return Response{}, fmt.Errorf("parser: read response: message was not a response")
	}
	return *env.Response, nil
}

// maxResponseBytes bounds one Response message this package will read: large
// enough for a bounded package-ledger or path-lookup result (the only
// payloads the Sensor's own Handler implementations send back), far below
// the AF_UNIX datagram size a default, un-tunable (this container's seccomp
// profile excludes setsockopt entirely) socket buffer can actually carry.
const maxResponseBytes = 1 << 20 // 1 MiB
