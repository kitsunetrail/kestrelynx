package sensor

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// TestCgroupFSTypeErrorRejectsEverythingButCgroup2 confirms
// cgroupFSTypeError's own boundary: cgroup2's magic is the only value that
// passes, and cgroup v1's own real magic (unix.CGROUP_SUPER_MAGIC) — along
// with an arbitrary unrelated filesystem type — both produce an error
// prefixed "cgroup_v1:", the exact string ClassifyEBPFStatus keys off of.
// This is what makes TestCgroupV1HostNeverReportsEventsOK below meaningful
// without needing an actual cgroup v1 host to run on: cgroupFSTypeError is
// the one place OwnCgroupInfo's own real statfs(2) result ever gets turned
// into that classification.
func TestCgroupFSTypeErrorRejectsEverythingButCgroup2(t *testing.T) {
	if err := cgroupFSTypeError(int64(unix.CGROUP2_SUPER_MAGIC)); err != nil {
		t.Errorf("cgroupFSTypeError(cgroup2) = %v, want nil", err)
	}
	for name, magic := range map[string]int64{
		"cgroup v1":            int64(unix.CGROUP_SUPER_MAGIC),
		"unrelated filesystem": int64(unix.TMPFS_MAGIC),
	} {
		err := cgroupFSTypeError(magic)
		if err == nil {
			t.Fatalf("%s: cgroupFSTypeError(%#x) = nil, want an error", name, magic)
		}
		if !hasPrefix(err.Error(), "cgroup_v1:") {
			t.Errorf("%s: cgroupFSTypeError(%#x) = %q, want it to start with \"cgroup_v1:\"", name, magic, err.Error())
		}
	}
}

// TestCgroupV1HostNeverReportsEventsOK chains cgroupFSTypeError's own
// cgroup-v1 classification through ClassifyEBPFStatus exactly the way
// Session.run does (OwnCgroupInfo's cgErr, first in ClassifyEBPFStatus's own
// priority order) and confirms the result is never EventsOK regardless of
// every other input being as healthy as possible (BTF readable, both
// capabilities raised, no load error) — a Docker-free stand-in for
// confirming that a cgroup v1 host never reports events.status as ok, which
// this environment has no real cgroup v1 host to verify against directly.
func TestCgroupV1HostNeverReportsEventsOK(t *testing.T) {
	cgErr := cgroupFSTypeError(int64(unix.CGROUP_SUPER_MAGIC))
	if cgErr == nil {
		t.Fatal("cgroupFSTypeError(cgroup v1 magic) = nil, want an error")
	}
	status, reason := ClassifyEBPFStatus(cgErr, true, true, true, nil)
	if status == evidence.EventsOK {
		t.Fatalf("ClassifyEBPFStatus on a cgroup v1 host = EventsOK, want EventsUnavailable")
	}
	if status != evidence.EventsUnavailable || reason != evidence.EventsReasonCgroupV1 {
		t.Errorf("ClassifyEBPFStatus = (%q, %q), want (unavailable, cgroup_v1)", status, reason)
	}
}

// TestClassifyEBPFStatus covers every branch of the eBPF degradation
// classification this Sensor uses when eBPF cannot attach at all — the
// vocabulary a reader shows as sensor.events.status/reason and
// (indirectly, via each generation's own events_coverage) a warning at the
// top of a notification, when eBPF cannot attach at all. Sampling itself
// (Session.run's own load/attach/drop sequence, which always runs
// regardless of the outcome) is exercised elsewhere; this test is only
// about the pure classification function.
func TestClassifyEBPFStatus(t *testing.T) {
	cases := []struct {
		name                           string
		cgErr                          error
		btfReadable                    bool
		capBPFRaised, capPERFMONRaised bool
		loadErr                        error
		wantStatus                     evidence.EventsStatus
		wantReason                     evidence.EventsReason
	}{
		{
			name: "cgroup v1 host", cgErr: errors.New("cgroup_v1: /sys/fs/cgroup is not cgroup2"),
			btfReadable: true, capBPFRaised: true, capPERFMONRaised: true,
			wantStatus: evidence.EventsUnavailable, wantReason: evidence.EventsReasonCgroupV1,
		},
		{
			name: "own cgroup unresolvable for some other reason", cgErr: errors.New("statfs /sys/fs/cgroup: permission denied"),
			btfReadable: true, capBPFRaised: true, capPERFMONRaised: true,
			wantStatus: evidence.EventsUnavailable, wantReason: evidence.EventsReasonAttachFailed,
		},
		{
			name: "BTF missing", btfReadable: false, capBPFRaised: true, capPERFMONRaised: true,
			wantStatus: evidence.EventsUnavailable, wantReason: evidence.EventsReasonBTFMissing,
		},
		{
			name: "CAP_BPF never raised", btfReadable: true, capBPFRaised: false, capPERFMONRaised: true,
			wantStatus: evidence.EventsUnavailable, wantReason: evidence.EventsReasonPermission,
		},
		{
			name: "CAP_PERFMON never raised", btfReadable: true, capBPFRaised: true, capPERFMONRaised: false,
			wantStatus: evidence.EventsUnavailable, wantReason: evidence.EventsReasonPermission,
		},
		{
			name: "load/attach itself failed", btfReadable: true, capBPFRaised: true, capPERFMONRaised: true,
			loadErr:    errors.New("attach fentry/do_mmap: not supported"),
			wantStatus: evidence.EventsUnavailable, wantReason: evidence.EventsReasonAttachFailed,
		},
		{
			name: "success", btfReadable: true, capBPFRaised: true, capPERFMONRaised: true,
			wantStatus: evidence.EventsOK, wantReason: evidence.EventsReasonNone,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, reason := ClassifyEBPFStatus(c.cgErr, c.btfReadable, c.capBPFRaised, c.capPERFMONRaised, c.loadErr)
			if status != c.wantStatus || reason != c.wantReason {
				t.Errorf("ClassifyEBPFStatus(...) = (%q, %q), want (%q, %q)", status, reason, c.wantStatus, c.wantReason)
			}
		})
	}
}

// TestSessionDegradesToSamplingOnlyWhenEventsUnavailable confirms the
// Session-level consequence of EventsUnavailable: a generation created
// while eventsStatus is not ok starts (and, absent any eBPF activity at
// all, stays) at CoverageNone, and applyEvent/dispatchWork's own event
// machinery is simply never exercised (nothing calls applyEvent when there
// is no eBPF reader goroutine running) — sampling continues warning-free
// through the ordinary sample-worker/dbworker pipeline this test does not
// need to touch to make that point.
func TestSessionDegradesToSamplingOnlyWhenEventsUnavailable(t *testing.T) {
	s := newTestSessionForEvents()
	s.eventsStatus = evidence.EventsUnavailable
	s.eventsReason = evidence.EventsReasonBTFMissing

	groups := map[string]containerGroup{
		strings64('q'): {ContainerID: strings64('q'), Init: InitProcess{PID: 10, Starttime: 5}},
	}
	s.reconcileGenerations(groups, s.now())

	if len(s.generations) != 1 {
		t.Fatalf("len(generations) = %d, want 1", len(s.generations))
	}
	for _, g := range s.generations {
		if g.eventsCoverage != evidence.CoverageNone {
			t.Errorf("eventsCoverage = %q, want none when eBPF never attached", g.eventsCoverage)
		}
	}
}
