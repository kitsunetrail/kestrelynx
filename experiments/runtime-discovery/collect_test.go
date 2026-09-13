package main

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

// nsReadlinkError builds the error the kernel returns for a
// /proc/<pid>/ns/net readlink the caller has no PTRACE_MODE_READ for,
// which is what a non-root collector sees for every PID of a container it
// does not own.
func nsReadlinkError(pid int, errno syscall.Errno) error {
	return &os.PathError{Op: "readlink", Path: fmt.Sprintf("/proc/%d/ns/net", pid), Err: errno}
}

// invalidatedGeneration is one PID whose identity could not be established
// because reading its namespace link was refused: starttime and uid_map
// read fine, ns/net does not, and the per-process reads are therefore never
// attempted — so their errors are nil and say nothing about what happened.
func invalidatedGeneration(pid int, errno syscall.Errno) *procObservation {
	err := nsReadlinkError(pid, errno)
	return &procObservation{
		pid:           pid,
		gen:           ProcessGeneration{PID: pid, Starttime: "15146798"},
		stable:        false,
		invalidKind:   procReadOutcome(err),
		invalidReason: err.Error(),
	}
}

// TestProcObserveDeniedWhenNamespaceReadIsRefused reproduces a real
// non-root run against nginx: docker top reported 15 PIDs, every
// /proc/<pid>/ns/net readlink returned EACCES, and so every sample recorded
// 15 proc_denied failures. The sample's proc_observe must agree with those
// failures and say "denied". Reporting "gone" would claim the container's
// processes had exited — they were running throughout — and would send the
// shortfall to the wrong not_determined factor.
func TestProcObserveDeniedWhenNamespaceReadIsRefused(t *testing.T) {
	const firstPID = 2479853
	obs := make([]*procObservation, 0, 15)
	for i := 0; i < 15; i++ {
		obs = append(obs, invalidatedGeneration(firstPID+i, syscall.EACCES))
	}

	for _, o := range obs {
		if got := o.outcome(); got != "denied" {
			t.Fatalf("pid %d outcome = %q, want denied", o.pid, got)
		}
	}
	if got := aggregateProcObserve(obs, len(obs)); got != "denied" {
		t.Errorf("proc_observe = %q, want denied: every PID's namespace link was refused, none had exited", got)
	}
}

func TestAggregateProcObserve(t *testing.T) {
	ok := &procObservation{pid: 1, stable: true}
	denied := invalidatedGeneration(2, syscall.EACCES)
	deniedEPERM := invalidatedGeneration(3, syscall.EPERM)
	gone := invalidatedGeneration(4, syscall.ESRCH)
	goneENOENT := invalidatedGeneration(5, syscall.ENOENT)

	tests := []struct {
		name     string
		obs      []*procObservation
		pidCount int
		want     string
	}{
		{"no PIDs at all is a top failure", nil, 0, "top_failed"},
		{"one readable generation makes the sample observed", []*procObservation{ok, denied, gone}, 3, "ok"},
		{"EACCES on every PID is denied", []*procObservation{denied, deniedEPERM}, 2, "denied"},
		{"EPERM counts as denied", []*procObservation{deniedEPERM}, 1, "denied"},
		{"ESRCH on every PID is gone", []*procObservation{gone, goneENOENT}, 2, "gone"},
		{"a refusal outranks a disappearance", []*procObservation{gone, denied}, 2, "denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aggregateProcObserve(tt.obs, tt.pidCount); got != tt.want {
				t.Errorf("aggregateProcObserve = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestProcReadOutcomeClassifiesWrappedErrno checks the classification
// against the error shape procfs reads actually produce — a *os.PathError
// wrapping the errno, never a bare errno.
func TestProcReadOutcomeClassifiesWrappedErrno(t *testing.T) {
	tests := []struct {
		errno syscall.Errno
		want  string
	}{
		{syscall.EACCES, "denied"},
		{syscall.EPERM, "denied"},
		{syscall.ESRCH, "gone"},
		{syscall.ENOENT, "gone"},
	}
	for _, tt := range tests {
		if got := procReadOutcome(nsReadlinkError(42, tt.errno)); got != tt.want {
			t.Errorf("procReadOutcome(%v) = %q, want %q", tt.errno, got, tt.want)
		}
	}
	if got := procReadOutcome(nil); got != "ok" {
		t.Errorf("procReadOutcome(nil) = %q, want ok", got)
	}
}
