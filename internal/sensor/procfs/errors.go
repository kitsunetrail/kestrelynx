package procfs

import "errors"

// ErrGenerationChanged is wrapped into the error Recheck returns when a
// Handle's process generation no longer matches the one Open captured.
var ErrGenerationChanged = errors.New("procfs: process generation changed")
