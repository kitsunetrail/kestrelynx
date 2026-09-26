// Command parserhelper is the real, standalone parser process
// internal/sensor's own tests exec as a child, communicating with the test
// (standing in for the observer) over fd 3 — the same reason
// internal/sensor/parser's own tests exec a helper binary rather than
// calling parser.Run in the test process itself (see that package's
// testdata/helpermain/main.go): parser.Run's own LockDown step requires a
// freshly-exec'd, not-yet-dumpable process.
package main

import (
	"fmt"
	"os"

	"github.com/kitsunetrail/kestrelynx/internal/sensor"
)

func main() {
	if err := sensor.RunParserChild(3); err != nil {
		fmt.Fprintf(os.Stderr, "sensor.RunParserChild: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
