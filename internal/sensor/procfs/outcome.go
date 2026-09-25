package procfs

import (
	"errors"
	"os"
	"syscall"
)

// Outcome classifies why a procfs read did or didn't succeed, in the
// vocabulary the Sensor's sampling loop needs to tell "this process is gone"
// apart from "this process is there but refuses to be read" — the two never
// mean the same thing to a usage verdict.
type Outcome string

const (
	OutcomeOK     Outcome = "ok"
	OutcomeDenied Outcome = "denied"
	OutcomeGone   Outcome = "gone"
)

// Classify turns a raw read error (from any method on Handle) into an
// Outcome. EACCES/EPERM is a permission result; ESRCH (and the ENOENT
// procfs returns for a PID that no longer exists) is a disappearance.
// Anything else is a failure that is not a disappearance, and is classified
// as denied so it is never mistaken for "the process was not there".
func Classify(err error) Outcome {
	switch {
	case err == nil:
		return OutcomeOK
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return OutcomeDenied
	case errors.Is(err, syscall.ESRCH), errors.Is(err, os.ErrNotExist):
		return OutcomeGone
	default:
		return OutcomeDenied
	}
}
