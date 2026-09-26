package sensor

import "github.com/kitsunetrail/kestrelynx/internal/sensor/parser"

// RunParserChild is the entry point for a re-exec'd
// `kestrelynx sensor --parser-child` process: the real parser, serving OS
// package-database build/lookup/forget requests (see dbOp) for as long as
// the whole Sensor session runs. socketFD is the SOCK_SEQPACKET end of the
// socketpair SpawnParserChild's caller created (fd 3, since ExtraFiles
// places it there across the exec). MaxLifetime is left at zero (no
// idle-lifetime limit): unlike the probe tool's short-lived parser child,
// this one must keep serving requests for the Sensor's entire uptime.
func RunParserChild(socketFD int) error {
	return parser.Run(parser.Config{
		SocketFD: socketFD,
		Handler:  newDBHandler(),
	})
}
