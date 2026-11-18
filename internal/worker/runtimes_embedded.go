//go:build !kestrelynx_worker

package worker

import _ "embed"

// runtimesJSON is the runtime table of this build. The main process starts
// with it and uses it until a newer table has been fetched. The program that
// runs in the work containers is built without it (the kestrelynx_worker
// tag): it reads what a runtime is from the id of the job's runtime.
//
//go:embed runtimes.json
var runtimesJSON []byte

var embeddedTable = mustLoadRuntimes(runtimesJSON)

func init() { SetRuntimeTable(embeddedTable) }

// EmbeddedRuntimeTable returns the runtime table of this build.
func EmbeddedRuntimeTable() RuntimeTable { return embeddedTable }
