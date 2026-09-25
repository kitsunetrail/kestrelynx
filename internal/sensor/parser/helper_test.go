package parser

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	helperBinOnce sync.Once
	helperBinPath string
	helperBinErr  error
)

// buildHelperBin compiles testdata/helpermain into a temp binary once per
// test run. It is a real, separate process (not the test binary re-exec'd
// on itself) — see testdata/helpermain/main.go's package comment.
func buildHelperBin(t *testing.T) string {
	t.Helper()
	helperBinOnce.Do(func() {
		outDir, err := os.MkdirTemp("", "kl-parser-helper-*")
		if err != nil {
			helperBinErr = err
			return
		}
		out := filepath.Join(outDir, "parserhelper")
		cmd := exec.Command("go", "build", "-o", out, "./testdata/helpermain")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			helperBinErr = &buildError{err: err, stderr: stderr.String()}
			return
		}
		helperBinPath = out
	})
	if helperBinErr != nil {
		t.Fatalf("build testdata/helpermain: %v", helperBinErr)
	}
	return helperBinPath
}

type buildError struct {
	err    error
	stderr string
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.stderr }
func (e *buildError) Unwrap() error { return e.err }

func asExitError(err error) (code int, ok bool) {
	ee, ok := err.(*exec.ExitError)
	if !ok {
		return 0, false
	}
	return ee.ExitCode(), true
}
