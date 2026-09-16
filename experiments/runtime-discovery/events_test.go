package main

import "testing"

// TestDeriveEventStateObservedWhenNothingIsUnmeasured checks that a
// collection which started, attached, and recorded no loss of any kind —
// Unmeasured included — is read as a complete observation rather than
// degraded. This is the case the entry probe's own count of failed
// pending-map insertions is meant to reach: once a trace can report that
// count, and it is zero, EventDropCounts.windowIncomplete() has nothing
// left to name.
func TestDeriveEventStateObservedWhenNothingIsUnmeasured(t *testing.T) {
	log := &EventLog{
		Header: EventHeader{Started: true, Attached: true},
	}
	state, notes := deriveEventState(log)
	if state != eventStateObserved {
		t.Errorf("event state = %q, want %q; notes: %v", state, eventStateObserved, notes)
	}
}

// TestDeriveEventStateDegradedWhenAnythingIsUnmeasured is the contrasting
// case: a single unmeasured loss kind is enough to mark the window
// degraded even with every counted kind at zero, since Unmeasured is a
// gap in what the collection could establish, not a count of zero.
func TestDeriveEventStateDegradedWhenAnythingIsUnmeasured(t *testing.T) {
	log := &EventLog{
		Header: EventHeader{Started: true, Attached: true},
		Trailer: EventsTrailer{
			Drops: EventDropCounts{Unmeasured: []string{"map_overflow: not reported by this collection method"}},
		},
	}
	state, _ := deriveEventState(log)
	if state != eventStateDegraded {
		t.Errorf("event state = %q, want %q", state, eventStateDegraded)
	}
}

// TestDeriveEventStateObservedWithEventLevelDegradationOnly checks that
// path_read_failures and enter_exit_unmatched_boundary — a captured
// event's own attributes going unresolved, or an entry/exit half left
// unpaired by the window's own start or end rather than by a loss inside
// it — do not mark the window degraded. Both kinds show up on every
// nofilter collection (the kernel cannot always read a path string, and a
// stop leaves one entry pending at the boundary), so counting either
// against the window would call every such run degraded regardless of
// whether it actually missed anything.
func TestDeriveEventStateObservedWithEventLevelDegradationOnly(t *testing.T) {
	log := &EventLog{
		Header: EventHeader{Started: true, Attached: true},
		Events: []EventRecord{{Record: eventRecordKind, Event: "exec"}},
		Trailer: EventsTrailer{
			Drops: EventDropCounts{PathReadFailures: 500, EnterExitUnmatchedBoundary: 1},
		},
	}
	state, _ := deriveEventState(log)
	if state != eventStateObserved {
		t.Errorf("event state = %q, want %q", state, eventStateObserved)
	}
}

// TestDeriveEventStateDegradedOnEnterExitUnmatched checks that an
// entry/exit half left unpaired for a reason inside the window still
// degrades it, unlike its boundary counterpart above: the converter
// discards both halves of such a pair, so the open they describe never
// becomes an event at all — a hole in the window, not an attribute
// missing from an event that was captured.
func TestDeriveEventStateDegradedOnEnterExitUnmatched(t *testing.T) {
	log := &EventLog{
		Header: EventHeader{Started: true, Attached: true},
		Events: []EventRecord{{Record: eventRecordKind, Event: "exec"}},
		Trailer: EventsTrailer{
			Drops: EventDropCounts{EnterExitUnmatched: 1},
		},
	}
	state, _ := deriveEventState(log)
	if state != eventStateDegraded {
		t.Errorf("event state = %q, want %q", state, eventStateDegraded)
	}
}

// TestDeriveEventStateDegradedOnMapOverflow checks that map_overflow still
// marks the window degraded even though it is counted alongside the other
// event-level kinds: a failed pending-map insertion drops the open or
// execution it would have produced, so the event itself never enters the
// log — that is a hole in the window, not an unresolved attribute of an
// event that was captured.
func TestDeriveEventStateDegradedOnMapOverflow(t *testing.T) {
	log := &EventLog{
		Header: EventHeader{Started: true, Attached: true},
		Events: []EventRecord{{Record: eventRecordKind, Event: "exec"}},
		Trailer: EventsTrailer{
			Drops: EventDropCounts{MapOverflow: 1},
		},
	}
	state, _ := deriveEventState(log)
	if state != eventStateDegraded {
		t.Errorf("event state = %q, want %q", state, eventStateDegraded)
	}
}

// TestDeriveEventStateDegradedOnLostEvents checks that a window-completeness
// loss still degrades the window even when it is the only one recorded.
func TestDeriveEventStateDegradedOnLostEvents(t *testing.T) {
	log := &EventLog{
		Header: EventHeader{Started: true, Attached: true},
		Events: []EventRecord{{Record: eventRecordKind, Event: "exec"}},
		Trailer: EventsTrailer{
			Drops: EventDropCounts{LostEvents: 3, LostNotifications: 1},
		},
	}
	state, _ := deriveEventState(log)
	if state != eventStateDegraded {
		t.Errorf("event state = %q, want %q", state, eventStateDegraded)
	}
}
