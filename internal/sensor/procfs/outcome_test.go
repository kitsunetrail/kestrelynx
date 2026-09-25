package procfs

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"nil", nil, OutcomeOK},
		{"EACCES", syscall.EACCES, OutcomeDenied},
		{"EPERM", syscall.EPERM, OutcomeDenied},
		{"wrapped EACCES", fmt.Errorf("openat: %w", syscall.EACCES), OutcomeDenied},
		{"ESRCH", syscall.ESRCH, OutcomeGone},
		{"os.ErrNotExist", os.ErrNotExist, OutcomeGone},
		{"wrapped ESRCH", fmt.Errorf("stat: %w", syscall.ESRCH), OutcomeGone},
		{"other errno (EIO)", syscall.EIO, OutcomeDenied},
		{"unrelated error", errors.New("boom"), OutcomeDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Errorf("Classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
