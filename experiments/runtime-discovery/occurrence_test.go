package main

import (
	"testing"
	"time"
)

var occWindowStart = time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
var occWindowEnd = occWindowStart.Add(5 * time.Minute)

func at(offset time.Duration) time.Time { return occWindowStart.Add(offset) }

func execEvent(ts time.Time, pid, tid int, path string) EventRecord {
	return EventRecord{
		Record: eventRecordKind, Event: "exec", Timestamp: ts, PID: pid, TID: tid,
		Starttime: "555", RawPath: path, Path: path, Resolved: true, OK: true,
		ContainerID: "c1", Attribution: "container",
	}
}

func openEvent(ts time.Time, pid, tid int, path string) EventRecord {
	e := execEvent(ts, pid, tid, path)
	e.Event = "open"
	return e
}

// correspondence is the mapping a case runner establishes between the two
// process number spaces. Every pairing rests on it: without it nothing can
// say that an event's process number and an occurrence's are the same
// process, and the pairing is reported as undecidable.
//
// The leading thread's number equals its process number on both sides, so
// an entry naming the process covers it.
func correspondence(pairs ...[3]int) []PIDMapping {
	var out []PIDMapping
	for _, p := range pairs {
		out = append(out, PIDMapping{
			ContainerID: "c1", ContainerPID: p[0], HostPID: p[1],
			ContainerTID: p[0], HostTID: p[1], Starttime: ProcTicks(itoa(p[2])),
		})
	}
	return out
}

func eventLogOf(events ...EventRecord) *EventLog {
	return &EventLog{Header: EventHeader{Record: eventsHeaderKind, Method: "bpftrace", Started: true, Attached: true}, Events: events}
}

// TestExecCaptureRequiresOneToOne checks the point-occurrence rate. A
// successful execution produces exactly one event, so the two can be
// required to pair up one to one; anything that does not pair that way is
// counted separately and is not a capture, because an execution that
// several events answer to has not been identified.
func TestExecCaptureRequiresOneToOne(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:      "usage_log",
		ClockBase: "wall clock, both sides",
		PIDMap:    correspondence([3]int{10, 10, 555}, [3]int{11, 11, 555}, [3]int{12, 12, 555}),
		Occurrences: []Occurrence{
			{ID: "a", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
			{ID: "b", Kind: occurrenceExec, PID: 11, TID: 11, Starttime: "555", Timestamp: at(2 * time.Minute), OK: true, Path: "/usr/bin/git"},
			{ID: "missed", Kind: occurrenceExec, PID: 12, TID: 12, Starttime: "555", Timestamp: at(3 * time.Minute), OK: true, Path: "/usr/bin/wget"},
		},
	}
	events := eventLogOf(
		execEvent(at(time.Minute), 10, 10, "/usr/bin/curl"),
		execEvent(at(2*time.Minute), 11, 11, "/usr/bin/git"),
	)
	m := computeOccurrenceMetrics(gtb, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if !m.Available {
		t.Fatal("metrics reported unavailable despite an independent log")
	}
	if m.Exec.Eligible != 3 || m.Exec.OneToOne != 2 {
		t.Errorf("eligible=%d one-to-one=%d, want 3/2", m.Exec.Eligible, m.Exec.OneToOne)
	}
	if m.Exec.Rate < 0.66 || m.Exec.Rate > 0.67 {
		t.Errorf("rate = %v, want two thirds", m.Exec.Rate)
	}
	if m.Uncaptured.InWindowMissed != 1 {
		t.Errorf("in-window misses = %d, want 1", m.Uncaptured.InWindowMissed)
	}
}

// TestExecCaptureCountsAmbiguousPairingsSeparately checks that an
// execution several events answer to, and an event several executions
// answer to, are both counted as unpairable rather than as captures.
func TestExecCaptureCountsAmbiguousPairingsSeparately(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{10, 10, 555}),
		Occurrences: []Occurrence{
			{ID: "one", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
		},
	}
	// Two events within the tolerance of the same execution.
	events := eventLogOf(
		execEvent(at(time.Minute), 10, 10, "/usr/bin/curl"),
		execEvent(at(time.Minute+100*time.Millisecond), 10, 10, "/usr/bin/curl"),
	)
	m := computeOccurrenceMetrics(gtb, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.OneToOne != 0 || m.Exec.OneToMany != 1 || m.Exec.Unmatchable != 1 {
		t.Errorf("one-to-one=%d one-to-many=%d unmatchable=%d, want 0/1/1", m.Exec.OneToOne, m.Exec.OneToMany, m.Exec.Unmatchable)
	}

	// One event within the tolerance of two executions.
	gtb.Occurrences = append(gtb.Occurrences, Occurrence{
		ID: "two", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555",
		Timestamp: at(time.Minute + 50*time.Millisecond), OK: true, Path: "/usr/bin/curl",
	})
	single := eventLogOf(execEvent(at(time.Minute), 10, 10, "/usr/bin/curl"))
	m = computeOccurrenceMetrics(gtb, single, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.ManyToOne != 2 || m.Exec.OneToOne != 0 {
		t.Errorf("many-to-one=%d one-to-one=%d, want 2/0", m.Exec.ManyToOne, m.Exec.OneToOne)
	}
}

// TestLoadCaptureAcceptsASetOfEvents checks the interval-occurrence rate.
// One load can read several files, and a collector that saw all of them
// has captured it: requiring the counts to agree would give a perfect
// collector a rate of zero.
func TestLoadCaptureAcceptsASetOfEvents(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 1, 555}),
		Occurrences: []Occurrence{{
			ID: "import", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
			Start: at(time.Minute), End: at(time.Minute + 2*time.Second), OK: true,
			Files: []string{"/site-packages/pkg/__init__.py", "/site-packages/pkg/_ext.so"},
		}},
	}
	events := eventLogOf(
		openEvent(at(time.Minute+100*time.Millisecond), 1, 1, "/site-packages/pkg/__init__.py"),
		openEvent(at(time.Minute+200*time.Millisecond), 1, 1, "/site-packages/pkg/_ext.so"),
		openEvent(at(time.Minute+300*time.Millisecond), 1, 1, "/site-packages/pkg/_ext.so"),
	)
	m := computeOccurrenceMetrics(gtb, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Load.Eligible != 1 || m.Load.WithEvidence != 1 {
		t.Errorf("eligible=%d with-evidence=%d, want 1/1: several events for one load is not a miss",
			m.Load.Eligible, m.Load.WithEvidence)
	}
	if m.Load.Rate != 1 {
		t.Errorf("rate = %v, want 1", m.Load.Rate)
	}
}

// TestLoadCaptureRefusesToUseOneEventTwice checks that an event which
// could belong to more than one load is used for none of them. Letting it
// count for each would credit one observation twice.
func TestLoadCaptureRefusesToUseOneEventTwice(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 1, 555}),
		Occurrences: []Occurrence{
			{ID: "first", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
				Start: at(time.Minute), End: at(time.Minute + time.Second), OK: true, Files: []string{"/lib/shared.so"}},
			{ID: "second", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
				Start: at(time.Minute + 500*time.Millisecond), End: at(time.Minute + 1500*time.Millisecond), OK: true, Files: []string{"/lib/shared.so"}},
		},
	}
	events := eventLogOf(openEvent(at(time.Minute+600*time.Millisecond), 1, 1, "/lib/shared.so"))
	m := computeOccurrenceMetrics(gtb, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Load.AttributionConflicts != 1 {
		t.Errorf("conflicts = %d, want 1", m.Load.AttributionConflicts)
	}
	if m.Load.WithEvidence != 0 {
		t.Errorf("with-evidence = %d, want 0: the one event cannot be spent on both loads", m.Load.WithEvidence)
	}
}

// TestDenominatorExcludesWhatCannotProduceAnEvent checks the eligibility
// rules. A load satisfied from memory reads nothing, a failed operation is
// not use, and an occurrence outside the window is outside what is being
// measured — none of the three belongs in a denominator of expected
// observations, and each is counted where it was excluded.
func TestDenominatorExcludesWhatCannotProduceAnEvent(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			{ID: "cached", Kind: occurrenceLoad, PID: 1, Starttime: "555", Start: at(time.Minute), End: at(time.Minute), OK: true, CacheHit: true, Files: []string{"/lib/a.so"}},
			{ID: "failed", Kind: occurrenceLoad, PID: 1, Starttime: "555", Start: at(time.Minute), End: at(time.Minute), OK: false, Files: []string{"/lib/b.so"}},
			{ID: "outside", Kind: occurrenceLoad, PID: 1, Starttime: "555", Start: occWindowEnd.Add(time.Minute), End: occWindowEnd.Add(time.Minute), OK: true, Files: []string{"/lib/c.so"}},
			{ID: "failed-exec", Kind: occurrenceExec, PID: 2, Starttime: "555", Timestamp: at(time.Minute), OK: false, Path: "/bin/nope"},
			{ID: "outside-exec", Kind: occurrenceExec, PID: 3, Starttime: "555", Timestamp: occWindowEnd.Add(time.Minute), OK: true, Path: "/bin/late"},
		},
	}
	m := computeOccurrenceMetrics(gtb, eventLogOf(), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Load.Eligible != 0 || m.Exec.Eligible != 0 {
		t.Errorf("eligible load=%d exec=%d, want 0/0", m.Load.Eligible, m.Exec.Eligible)
	}
	if m.Excluded.CacheHit != 1 {
		t.Errorf("cache-hit exclusions = %d, want 1", m.Excluded.CacheHit)
	}
	if m.Excluded.Failed != 2 {
		t.Errorf("failed exclusions = %d, want 2", m.Excluded.Failed)
	}
	if m.Excluded.OutsideWindow != 2 {
		t.Errorf("outside-window exclusions = %d, want 2", m.Excluded.OutsideWindow)
	}
	if m.Uncaptured.OutsideWindow != 2 {
		t.Errorf("uncaptured-outside-window = %d, want 2", m.Uncaptured.OutsideWindow)
	}
	if m.Load.Rate != -1 || m.Exec.Rate != -1 {
		t.Errorf("rates = %v/%v, want unavailable: a denominator of zero is not a rate of zero or one", m.Load.Rate, m.Exec.Rate)
	}
}

// TestSystemCallRateIsUnavailableWithoutItsOwnTruth checks that the
// system-call level rate is reported as unavailable when nothing recorded
// the calls independently, rather than being replaced by the per-load rate
// — which counts something else.
func TestSystemCallRateIsUnavailableWithoutItsOwnTruth(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 1, 555}),
		Occurrences: []Occurrence{{
			ID: "load", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
			Start: at(time.Minute), End: at(time.Minute), OK: true, Files: []string{"/lib/a.so"},
		}},
	}
	m := computeOccurrenceMetrics(gtb, eventLogOf(openEvent(at(time.Minute), 1, 1, "/lib/a.so")), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if !m.RealOpen.NA || m.RealOpen.Rate != -1 {
		t.Errorf("system-call rate = %v (unavailable=%v), want unavailable", m.RealOpen.Rate, m.RealOpen.NA)
	}

	gtb.RealOpens = []RealOpen{
		{ID: "o1", PID: 1, TID: 1, Starttime: "555", Timestamp: at(time.Minute), Path: "/lib/a.so", OK: true},
		{ID: "o2", PID: 1, TID: 1, Starttime: "555", Timestamp: at(2 * time.Minute), Path: "/lib/b.so", OK: true},
	}
	m = computeOccurrenceMetrics(gtb, eventLogOf(openEvent(at(time.Minute), 1, 1, "/lib/a.so")), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.RealOpen.NA {
		t.Fatal("the rate is still unavailable with an independent record present")
	}
	if m.RealOpen.Occurrences != 2 || m.RealOpen.Captured != 1 {
		t.Errorf("occurrences=%d captured=%d, want 2/1", m.RealOpen.Occurrences, m.RealOpen.Captured)
	}
}

// TestWithoutAnIndependentLogNothingIsConcluded checks that a window with
// no independent record reports the rates as unavailable and counts the
// events it could not check, rather than claiming either success or
// failure. A production sample, where the workload cannot be made to
// record what it is doing, is exactly this case.
func TestWithoutAnIndependentLogNothingIsConcluded(t *testing.T) {
	events := eventLogOf(
		execEvent(at(time.Minute), 10, 10, "/usr/bin/curl"),
		openEvent(at(2*time.Minute), 10, 10, "/lib/a.so"),
	)
	m := computeOccurrenceMetrics(nil, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Available {
		t.Error("rates were reported as available with no independent record")
	}
	if m.Uncaptured.ReasonUnknown != 2 {
		t.Errorf("unexplainable = %d, want 2", m.Uncaptured.ReasonUnknown)
	}
	if len(m.Notes) == 0 {
		t.Error("no note explains why nothing can be concluded")
	}
}

// TestAttributionReportsBothDirections checks the attribution control.
// Both numbers are required: a collector that discarded every event would
// attribute nothing wrongly, so the share of wrong attributions cannot on
// its own show that attribution works.
func TestAttributionReportsBothDirections(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		// Two containers number their processes independently, so the
		// correspondence names which container each entry is about.
		PIDMap: []PIDMapping{
			{ContainerID: "c1", ContainerPID: 10, HostPID: 10, ContainerTID: 10, HostTID: 10, Starttime: "555"},
			{ContainerID: "c2", ContainerPID: 20, HostPID: 20, ContainerTID: 20, HostTID: 20, Starttime: "666"},
		},
		Occurrences: []Occurrence{
			{ID: "mine", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "c1"},
			{ID: "theirs", Kind: occurrenceExec, PID: 20, TID: 20, Starttime: "666", Timestamp: at(2 * time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "c2"},
			{ID: "hosts", Kind: occurrenceExec, PID: 30, TID: 30, Starttime: "777", PIDNamespace: 4026531836, Timestamp: at(3 * time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "host"},
		},
	}
	mine := execEvent(at(time.Minute), 10, 10, "/usr/bin/curl")
	theirs := execEvent(at(2*time.Minute), 20, 20, "/usr/bin/curl")
	theirs.Starttime, theirs.ContainerID = "666", "c2"
	// The host's run wrongly credited to a container: the failure this
	// control exists to detect.
	hosts := execEvent(at(3*time.Minute), 30, 30, "/usr/bin/curl")
	hosts.Starttime, hosts.ContainerID = "777", "c1"
	// sameHostProcess reads the event's own-namespace numbers, not the
	// initial namespace's: a host task's NSPID/NSTID are what the host's
	// own /proc — and so this occurrence's PID/TID — agree with. Both
	// sides also carry the same PID namespace identifier, since NSPID/
	// NSTID only mean anything once that agrees too.
	hosts.NSPID, hosts.NSTID, hosts.PIDNamespace = 30, 30, 4026531836

	a := computeAttributionMetrics(gtb, eventLogOf(mine, theirs, hosts), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.AttributedEvents != 3 {
		t.Errorf("attributed events = %d, want 3", a.AttributedEvents)
	}
	if a.Misattributed != 1 || a.FromHost != 1 {
		t.Errorf("wrong attributions = %d (from the host: %d), want 1/1", a.Misattributed, a.FromHost)
	}
	// LoggedOccurrences is over container occurrences only: the host's run
	// is scored separately below, against the opposite definition of
	// correct.
	if a.LoggedOccurrences != 2 {
		t.Errorf("logged occurrences = %d, want 2: the two containers' own runs", a.LoggedOccurrences)
	}
	// Both containers' own runs were credited to them, so this rate is
	// perfect on its own; it is the host triple below that shows the
	// failure this control exists to detect.
	if a.CorrectlyAttributed != 2 {
		t.Errorf("correctly attributed = %d, want 2: each container's own run was credited to it", a.CorrectlyAttributed)
	}
	if a.CorrectAttributionRate != 1 {
		t.Errorf("correct-attribution rate = %v, want 1", a.CorrectAttributionRate)
	}
	if a.HostOccurrences != 1 {
		t.Errorf("host occurrences = %d, want 1", a.HostOccurrences)
	}
	if a.HostLeftUnattributed != 0 {
		t.Errorf("host left unattributed = %d, want 0: the host's run was credited to a container", a.HostLeftUnattributed)
	}
	if a.HostCorrectRate != 0 {
		t.Errorf("host-correct rate = %v, want 0", a.HostCorrectRate)
	}
}

// TestAttributionRefusesToInheritAcrossGenerations checks that the
// generation keeps two processes apart even where their numbers collide.
func TestAttributionRefusesToInheritAcrossGenerations(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{10, 10, 555}),
		Occurrences: []Occurrence{
			{ID: "mine", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "c1"},
		},
	}
	other := execEvent(at(time.Minute), 10, 10, "/usr/bin/curl")
	other.Starttime = "999" // a different process that happens to share the number
	m := computeOccurrenceMetrics(gtb, eventLogOf(other), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.OneToOne != 0 {
		t.Error("an event from a different process generation was paired with this occurrence")
	}
}

// TestWithoutACorrespondenceNothingIsPaired checks what happens with no
// recorded correspondence between the two process number spaces.
//
// Nothing can then say that an event's process number and an occurrence's
// are the same process. A start time that agrees is not enough: it is
// rounded to a clock tick, and two containers produce their numbers
// independently. Such a pairing is neither a capture nor a miss, and
// counting it either way would put a number on the collection that
// measures something else.
//
// Without a correspondence table the matcher falls back to comparing
// namespace-scoped numbers directly, which is decidable from the
// occurrence's own numbers alone; but none of the fixture's events carry
// one — as none would from a collector never asked to read one — so the
// outcome here is the same as if nothing could be decided at all.
func TestWithoutACorrespondenceNothingIsPaired(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			{ID: "a", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
			{ID: "b", Kind: occurrenceLoad, PID: 10, TID: 10, Starttime: "555", Start: at(2 * time.Minute), End: at(2 * time.Minute), OK: true, Files: []string{"/lib/a.so"}},
		},
	}
	events := eventLogOf(
		execEvent(at(time.Minute), 10, 10, "/usr/bin/curl"),
		openEvent(at(2*time.Minute), 10, 10, "/lib/a.so"),
	)
	m := computeOccurrenceMetrics(gtb, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.OneToOne != 0 || m.Load.WithEvidence != 0 {
		t.Errorf("paired %d execution(s) and %d load(s) with no correspondence to rest on", m.Exec.OneToOne, m.Load.WithEvidence)
	}
	if m.Exec.Undecidable != 1 || m.Load.Undecidable != 1 {
		t.Errorf("undecidable: exec=%d load=%d, want 1/1", m.Exec.Undecidable, m.Load.Undecidable)
	}
	if m.Uncaptured.InWindowMissed != 0 {
		t.Errorf("in-window misses = %d; an undecidable pairing is not a miss of the collection", m.Uncaptured.InWindowMissed)
	}
	if m.MatchRule != ruleNamespacePIDAndTID {
		t.Errorf("match rule = %q, want the namespace-number fallback", m.MatchRule)
	}
}

// TestAnOccurrenceWithNoThreadCannotBeDecided checks the case a runtime
// that cannot report an operating-system thread number leaves behind. The
// thread condition cannot be checked, so the pairing is undecidable rather
// than assumed to hold.
func TestAnOccurrenceWithNoThreadCannotBeDecided(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 4242, 555}),
		Occurrences: []Occurrence{{
			ID: "load", Kind: occurrenceLoad, PID: 1, Starttime: "555",
			Start: at(time.Minute), End: at(time.Minute + time.Second), OK: true,
			Files: []string{"/app/log4j-core-2.14.1.jar"},
		}},
	}
	events := eventLogOf(openEvent(at(time.Minute), 4242, 4242, "/app/log4j-core-2.14.1.jar"))
	m := computeOccurrenceMetrics(gtb, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Load.WithEvidence != 0 {
		t.Error("a load naming no thread was credited with evidence; the thread condition was never checked")
	}
	if m.Load.Undecidable != 1 {
		t.Errorf("undecidable loads = %d, want 1", m.Load.Undecidable)
	}
}

// TestHostProcessNumbersAreUsedWhenSupplied checks that the stronger
// pairing rule is used where the case runner could establish the
// correspondence between the two process number spaces.
func TestHostProcessNumbersAreUsedWhenSupplied(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: []PIDMapping{{ContainerID: "c1", ContainerPID: 10, HostPID: 4242, ContainerTID: 10, HostTID: 4242, Starttime: "555"}},
		Occurrences: []Occurrence{
			{ID: "mine", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
		},
	}
	m := computeOccurrenceMetrics(gtb, eventLogOf(execEvent(at(time.Minute), 4242, 4242, "/usr/bin/curl")),
		"c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.MatchRule != "container_generation_and_thread" {
		t.Errorf("match rule = %q, want the rule the correspondence enables", m.MatchRule)
	}
	if m.Exec.OneToOne != 1 {
		t.Errorf("one-to-one = %d, want 1", m.Exec.OneToOne)
	}
}

// TestNamespaceRuleMatchesWithoutACorrespondenceTable checks the fallback
// rule a case with no recorded correspondence resolves to: comparing an
// event's namespace-scoped numbers directly against the occurrence's own,
// which is what a workload inside a container reports for itself. The
// event's host-wide numbers are deliberately something else, to show that
// this rule does not rest on them at all.
func TestNamespaceRuleMatchesWithoutACorrespondenceTable(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log", // no PIDMap
		Occurrences: []Occurrence{
			{ID: "mine", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
		},
	}
	ev := execEvent(at(time.Minute), 4242, 4242, "/usr/bin/curl") // unrelated host numbers
	ev.NSPID, ev.NSTID, ev.Starttime = 10, 10, "555"
	m := computeOccurrenceMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.MatchRule != ruleNamespacePIDAndTID {
		t.Errorf("match rule = %q, want the namespace-number fallback", m.MatchRule)
	}
	if m.Exec.OneToOne != 1 {
		t.Errorf("one-to-one = %d, want 1: the namespace numbers and the generation agree", m.Exec.OneToOne)
	}
}

// TestNamespaceRuleRefusesAGenerationMismatch checks that the fallback
// rule still keeps two processes apart by their generation even where
// their namespace numbers collide — the same guard
// container_generation_and_thread has, applied to the numbers this rule
// actually compares.
func TestNamespaceRuleRefusesAGenerationMismatch(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			{ID: "a", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
		},
	}
	ev := execEvent(at(time.Minute), 10, 10, "/usr/bin/curl")
	ev.NSPID, ev.NSTID, ev.Starttime = 10, 10, "999" // same namespace numbers, a different process generation
	m := computeOccurrenceMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.OneToOne != 0 {
		t.Error("an event from a different process generation was paired by its namespace numbers alone")
	}
	if m.Uncaptured.InWindowMissed != 1 {
		t.Errorf("in-window misses = %d, want 1: the only candidate was a different process, which is a genuine miss", m.Uncaptured.InWindowMissed)
	}
}

// TestNamespaceRuleWithNoNamespaceNumberIsUndecidable checks that an event
// from a collector never asked to read the namespace-scoped numbers — they
// come back zero, the same as an event in the format that predates them —
// leaves the occurrence undecidable rather than charging the collection
// with a miss for something it may well have observed.
func TestNamespaceRuleWithNoNamespaceNumberIsUndecidable(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			{ID: "a", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
		},
	}
	// Right path, right moment, but no namespace numbers to compare.
	ev := execEvent(at(time.Minute), 10, 10, "/usr/bin/curl")
	m := computeOccurrenceMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.OneToOne != 0 {
		t.Error("an event with no namespace number was paired anyway")
	}
	if m.Exec.Undecidable != 1 {
		t.Errorf("undecidable = %d, want 1: nothing here could place the only candidate", m.Exec.Undecidable)
	}
	if m.Uncaptured.InWindowMissed != 0 {
		t.Error("an event that could not be placed was counted as a miss of the collection")
	}
}

// TestNamespaceRuleCannotConfirmAMisattributionAcrossContainers checks the
// fallback rule's own limit, honestly: a namespace-scoped number is only
// unique within its own container, so this rule can confirm a process's
// identity only against the container an event was actually credited to.
// Where the case says the work happened in one container and the only
// candidate event was credited to a different one, the rule cannot tell a
// genuine misattribution from a coincidental number collision between two
// unrelated containers, and settles neither question: the occurrence stays
// in the denominator with no attribution outcome established for it,
// rather than being called correct or wrong on a guess. Reporting a
// misattribution rate in that state would count the unconfirmable case as
// correct by default, so it is unavailable instead.
func TestNamespaceRuleCannotConfirmAMisattributionAcrossContainers(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log", // no PIDMap
		Occurrences: []Occurrence{
			{ID: "mine", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555",
				Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "c1"},
			// A failed occurrence in c2, present only so c2 is one of the
			// containers this log can judge at all. Without it the event
			// below would never reach the matcher — it would be filtered
			// out earlier as belonging to a container the log says
			// nothing about — and the test would not exercise this
			// rule's own limit at all.
			{ID: "unrelated", Kind: occurrenceExec, PID: 99, TID: 99, Starttime: "999",
				Timestamp: at(time.Minute), OK: false, Path: "/usr/bin/wget", ContainerID: "c2"},
		},
	}
	// Container c2 numbers its own processes independently, so the number
	// 10 there names a process unrelated to c1's.
	ev := execEvent(at(time.Minute), 20, 20, "/usr/bin/curl")
	ev.ContainerID, ev.NSPID, ev.NSTID, ev.Starttime = "c2", 10, 10, "555"
	a := computeAttributionMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.AttributedEvents != 1 {
		t.Errorf("attributed events = %d, want 1: the event is credited to a container this log can judge", a.AttributedEvents)
	}
	if a.CorrectlyAttributed != 0 {
		t.Errorf("correctly attributed = %d, want 0: the only candidate was credited to a different container", a.CorrectlyAttributed)
	}
	if a.Misattributed != 0 {
		t.Errorf("misattributed = %d, want 0: a number collision between two containers is not confirmed evidence of misattribution", a.Misattributed)
	}
	if a.LoggedOccurrences != 1 {
		t.Errorf("logged occurrences = %d, want 1: c1's own occurrence is decidable, even though this rule cannot settle its outcome", a.LoggedOccurrences)
	}
	if a.MatchRule != ruleNamespacePIDAndTID {
		t.Errorf("match rule = %q, want the namespace-number fallback", a.MatchRule)
	}
	if a.CrossContainerEvaluable {
		t.Error("cross-container misattribution reported evaluable under the namespace-number fallback")
	}
	if a.MisattributionRate != -1 {
		t.Errorf("misattribution rate = %v, want unavailable: this rule cannot tell a cross-container misattribution from a coincidental number collision", a.MisattributionRate)
	}
}

// TestNamespaceRuleMatchesARealRunsThreeExecutions checks the fallback
// rule against numbers an actual measurement run produced, not a fixture
// invented for the test: three container executions (two of curl, one of
// git), each occurrence's own process and thread numbers as the
// container's PID namespace has them, and the collector's independently
// observed executions, carrying the host's own numbers plus the same
// namespace-scoped ones — which is the field a run collected before this
// rule existed would not have, and which is filled in here to build the
// fixture. All three pair up by namespace number and generation alone,
// with no correspondence table at all.
func TestNamespaceRuleMatchesARealRunsThreeExecutions(t *testing.T) {
	const container = "76eaaed4f5057c511adeaa1166215b40aa3f5f87a8861385b6513403dbc62323"
	mustParse := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return ts
	}
	gtb := &GroundTruthB{
		Kind: "usage_log", // no PIDMap
		Occurrences: []Occurrence{
			{ID: "13-exec-000001", Kind: occurrenceExec, PID: 3010380, TID: 3010380, Starttime: "29256421",
				Timestamp: mustParse("2026-09-13T14:51:03.368729077Z"), OK: true, Path: "/usr/bin/curl", ContainerID: container},
			{ID: "13-exec-000002", Kind: occurrenceExec, PID: 3010460, TID: 3010460, Starttime: "29256441",
				Timestamp: mustParse("2026-09-13T14:51:03.570810881Z"), OK: true, Path: "/usr/bin/git", ContainerID: container},
			{ID: "13-exec-000003", Kind: occurrenceExec, PID: 3010496, TID: 3010496, Starttime: "29256944",
				Timestamp: mustParse("2026-09-13T14:51:08.599378586Z"), OK: true, Path: "/usr/bin/curl", ContainerID: container},
		},
	}
	events := eventLogOf(
		// Host pid/tid, cgroup attribution and timestamps as the tracer
		// actually reported them; nspid/nstid are the container-side
		// numbers above, which the format this run predates did not carry.
		EventRecord{Record: eventRecordKind, Event: occurrenceExec, Timestamp: mustParse("2026-09-13T14:51:03.373092703Z"),
			PID: 3013915, TID: 3013915, NSPID: 3010380, NSTID: 3010380, Starttime: "29256421",
			RawPath: "/usr/bin/curl", Path: "/usr/bin/curl", Resolved: true, OK: true, ContainerID: container, Attribution: "container"},
		EventRecord{Record: eventRecordKind, Event: occurrenceExec, Timestamp: mustParse("2026-09-13T14:51:03.574529145Z"),
			PID: 3013995, TID: 3013995, NSPID: 3010460, NSTID: 3010460, Starttime: "29256441",
			RawPath: "/usr/bin/git", Path: "/usr/bin/git", Resolved: true, OK: true, ContainerID: container, Attribution: "container"},
		EventRecord{Record: eventRecordKind, Event: occurrenceExec, Timestamp: mustParse("2026-09-13T14:51:08.601955579Z"),
			PID: 3014031, TID: 3014031, NSPID: 3010496, NSTID: 3010496, Starttime: "29256944",
			RawPath: "/usr/bin/curl", Path: "/usr/bin/curl", Resolved: true, OK: true, ContainerID: container, Attribution: "container"},
	)
	windowStart := mustParse("2026-09-13T14:51:00Z")
	windowEnd := mustParse("2026-09-13T14:51:30Z")
	m := computeOccurrenceMetrics(gtb, events, container, windowStart, windowEnd, defaultOccurrenceToleranceMS)
	if m.MatchRule != ruleNamespacePIDAndTID {
		t.Errorf("match rule = %q, want the namespace-number fallback", m.MatchRule)
	}
	if m.Exec.Eligible != 3 || m.Exec.OneToOne != 3 {
		t.Errorf("eligible=%d one-to-one=%d, want 3/3", m.Exec.Eligible, m.Exec.OneToOne)
	}
	if m.Exec.Undecidable != 0 {
		t.Errorf("undecidable = %d, want 0: every occurrence had a matching namespace number", m.Exec.Undecidable)
	}
}

// TestMisattributionToAnotherContainerIsDetected is the failure the
// attribution control exists to find, and the one the folded check could
// not see.
//
// The work really happened in the second container; the collection
// credited it to the first. Asking "is this the same process's work" and
// "which container was it credited to" as one question answers no to the
// first — the containers differ — and the wrong attribution then looks
// like a different process's work and is never counted.
func TestMisattributionToAnotherContainerIsDetected(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PIDMap: []PIDMapping{
			{ContainerID: "c1", ContainerPID: 10, HostPID: 10, ContainerTID: 10, HostTID: 10, Starttime: "555"},
			{ContainerID: "c2", ContainerPID: 20, HostPID: 20, ContainerTID: 20, HostTID: 20, Starttime: "666"},
		},
		Occurrences: []Occurrence{
			{ID: "theirs", Kind: occurrenceExec, PID: 20, TID: 20, Starttime: "666",
				Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "c2"},
		},
	}
	// The second container's run, credited to the first.
	ev := execEvent(at(time.Minute), 20, 20, "/usr/bin/curl")
	ev.Starttime, ev.ContainerID = "666", "c1"

	a := computeAttributionMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.Misattributed != 1 || a.FromOtherContainer != 1 {
		t.Errorf("wrong attributions = %d (from another container: %d), want 1/1", a.Misattributed, a.FromOtherContainer)
	}
	if a.CorrectlyAttributed != 0 {
		t.Errorf("correctly attributed = %d, want 0: the one logged run was credited to the wrong container", a.CorrectlyAttributed)
	}
	if a.MisattributionRate != 1 {
		t.Errorf("wrong-attribution rate = %v, want 1", a.MisattributionRate)
	}
}

// TestALoadSpanningTheWindowIsEvaluated checks that a load which began
// before the window and was still running inside it is work the window
// saw. Taking only its start would drop exactly the long loads a runtime's
// startup produces.
func TestALoadSpanningTheWindowIsEvaluated(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 1, 555}),
		Occurrences: []Occurrence{{
			ID: "spanning", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
			Start: occWindowStart.Add(-time.Minute), End: occWindowStart.Add(time.Minute),
			OK: true, Files: []string{"/lib/a.so"}, ContainerID: "c1",
		}},
	}
	ev := openEvent(occWindowStart.Add(30*time.Second), 1, 1, "/lib/a.so")
	a := computeAttributionMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.LoggedOccurrences != 1 {
		t.Errorf("logged occurrences = %d, want the load that was running inside the window", a.LoggedOccurrences)
	}
	if a.CorrectlyAttributed != 1 {
		t.Errorf("correctly attributed = %d, want 1", a.CorrectlyAttributed)
	}
}

// TestAnEventWithNoGenerationIsNotACapture checks that an event which does
// not say which process generation produced it cannot be paired, and is
// not counted as a miss either.
//
// The same process number an hour later is a different process, so such an
// event cannot confirm the occurrence. It is equally no evidence that a
// different process did the work: charging the collection with a miss here
// would blame it for something it did observe and could not describe
// fully. It belongs with the pairings nothing could decide.
func TestAnEventWithNoGenerationIsNotACapture(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{10, 10, 555}),
		Occurrences: []Occurrence{
			{ID: "a", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555",
				Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
		},
	}
	ev := execEvent(at(time.Minute), 10, 10, "/usr/bin/curl")
	ev.Starttime = "" // the collection could not read the generation
	m := computeOccurrenceMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.OneToOne != 0 {
		t.Error("an event carrying no process generation was paired with an occurrence")
	}
	if m.Uncaptured.InWindowMissed != 0 {
		t.Errorf("in-window misses = %d; an event that cannot be placed is not evidence the collection missed anything", m.Uncaptured.InWindowMissed)
	}
	if m.Exec.Undecidable != 1 {
		t.Errorf("undecidable executions = %d, want 1", m.Exec.Undecidable)
	}
	if m.Exec.Decidable != 0 || m.Exec.Rate != -1 {
		t.Errorf("decidable=%d rate=%v, want nothing decidable and no rate", m.Exec.Decidable, m.Exec.Rate)
	}

	// An occurrence for which no event arrived at all is a genuine miss,
	// and stays one.
	missed := computeOccurrenceMetrics(gtb, eventLogOf(), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if missed.Uncaptured.InWindowMissed != 1 {
		t.Errorf("with no events at all, in-window misses = %d, want 1", missed.Uncaptured.InWindowMissed)
	}
}

// TestRatesAreUnavailableWhenNothingIsDecidable checks that a window where
// no occurrence could be identified reports no rate at all, rather than a
// capture rate of zero — which would be a statement about the collection
// that the measurement never established.
func TestRatesAreUnavailableWhenNothingIsDecidable(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log", // no correspondence at all
		Occurrences: []Occurrence{
			{ID: "a", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555", Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl"},
			{ID: "b", Kind: occurrenceLoad, PID: 10, TID: 10, Starttime: "555", Start: at(2 * time.Minute), End: at(2 * time.Minute), OK: true, Files: []string{"/lib/a.so"}},
		},
	}
	events := eventLogOf(
		execEvent(at(time.Minute), 10, 10, "/usr/bin/curl"),
		openEvent(at(2*time.Minute), 10, 10, "/lib/a.so"),
	)
	m := computeOccurrenceMetrics(gtb, events, "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Exec.Decidable != 0 || m.Load.Decidable != 0 {
		t.Errorf("decidable: exec=%d load=%d, want 0/0", m.Exec.Decidable, m.Load.Decidable)
	}
	if m.Exec.Rate != -1 || m.Load.Rate != -1 {
		t.Errorf("rates = %v/%v, want unavailable rather than zero", m.Exec.Rate, m.Load.Rate)
	}
	if m.Uncaptured.InWindowMissed != 0 {
		t.Errorf("in-window misses = %d; nothing could be judged, so nothing was missed", m.Uncaptured.InWindowMissed)
	}
}

// TestSecondThreadCorrespondenceIsNotOverwritten checks that two threads
// of one process each keep their own entry. Keyed by process alone, the
// second would replace the first and one thread's work would be compared
// against the other's numbers.
func TestSecondThreadCorrespondenceIsNotOverwritten(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PIDMap: []PIDMapping{
			{ContainerID: "c1", ContainerPID: 1, HostPID: 4242, ContainerTID: 1, HostTID: 4242, Starttime: "555"},
			{ContainerID: "c1", ContainerPID: 1, HostPID: 4242, ContainerTID: 7, HostTID: 4251, Starttime: "555"},
		},
		Occurrences: []Occurrence{
			{ID: "leader", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
				Start: at(time.Minute), End: at(time.Minute + time.Second), OK: true, Files: []string{"/lib/a.so"}},
			{ID: "worker", Kind: occurrenceLoad, PID: 1, TID: 7, Starttime: "555",
				Start: at(2 * time.Minute), End: at(2*time.Minute + time.Second), OK: true, Files: []string{"/lib/b.so"}},
		},
	}
	leaderEvent := openEvent(at(time.Minute), 4242, 4242, "/lib/a.so")
	workerEvent := openEvent(at(2*time.Minute), 4242, 4251, "/lib/b.so")
	m := computeOccurrenceMetrics(gtb, eventLogOf(leaderEvent, workerEvent), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.Load.Decidable != 2 {
		t.Errorf("decidable loads = %d, want both threads", m.Load.Decidable)
	}
	if m.Load.WithEvidence != 2 {
		t.Errorf("loads with evidence = %d, want both: each thread's own entry is there", m.Load.WithEvidence)
	}
}

// TestHostAndContainerRunningTheSamePathAtOnce is the control's hardest
// case, and the one a match on path and time alone gets wrong.
//
// The host and a container run the same program, from the same path, at
// almost the same moment. Each event belongs to exactly one of them, and
// which one is settled by the process and thread numbers — not by the path
// or the clock, which are identical on both sides. Matching on those alone
// calls the container's own correctly attributed run a wrong attribution,
// and the control then reports a failure that did not happen.
func TestHostAndContainerRunningTheSamePathAtOnce(t *testing.T) {
	const path = "/usr/bin/curl"
	moment := at(time.Minute)

	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{10, 4242, 555}),
		Occurrences: []Occurrence{
			// The container's own run.
			{ID: "in-container", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555",
				Timestamp: moment, OK: true, Path: path, ContainerID: "c1"},
			// The host's run, a few milliseconds later. The host script
			// records host numbers directly: there is no second number
			// space to translate through.
			{ID: "on-host", Kind: occurrenceExec, PID: 9000, TID: 9000, Starttime: "777", PIDNamespace: 4026531836,
				Timestamp: moment.Add(10 * time.Millisecond), OK: true, Path: path, ContainerID: "host"},
		},
	}

	containerEvent := execEvent(moment, 4242, 4242, path)
	containerEvent.Starttime = "555"
	// The host's run, correctly left unattributed by the collection.
	hostEvent := execEvent(moment.Add(10*time.Millisecond), 9000, 9000, path)
	hostEvent.Starttime, hostEvent.ContainerID, hostEvent.Attribution = "777", "", "unattributed"
	// sameHostProcess reads the event's own-namespace numbers, not the
	// initial namespace's, and requires the PID namespace identifier to
	// agree too: see sameHostProcess's own doc comment.
	hostEvent.NSPID, hostEvent.NSTID, hostEvent.PIDNamespace = 9000, 9000, 4026531836

	a := computeAttributionMetrics(gtb, eventLogOf(containerEvent, hostEvent), "c1",
		occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)

	if a.Misattributed != 0 {
		t.Errorf("wrong attributions = %d (host %d, other container %d), want none: each run was credited to where it happened",
			a.Misattributed, a.FromHost, a.FromOtherContainer)
	}
	if a.CorrectlyAttributed != 1 {
		t.Errorf("correctly attributed = %d, want 1: the container's own run", a.CorrectlyAttributed)
	}
	// The host's run belongs to the host triple, not the container one: an
	// event left unattributed is the host's correct outcome, and it must
	// not count as a container occurrence with no matching event.
	if a.HostOccurrences != 1 || a.HostLeftUnattributed != 1 {
		t.Errorf("host occurrences = %d, left unattributed = %d, want 1/1", a.HostOccurrences, a.HostLeftUnattributed)
	}
	if a.HostCorrectRate != 1 {
		t.Errorf("host-correct rate = %v, want 1", a.HostCorrectRate)
	}

	// Now the failure the control exists to find: the host's run credited
	// to the container.
	hostEvent.ContainerID, hostEvent.Attribution = "c1", "container"
	a = computeAttributionMetrics(gtb, eventLogOf(containerEvent, hostEvent), "c1",
		occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.Misattributed != 1 || a.FromHost != 1 {
		t.Errorf("wrong attributions = %d (from the host: %d), want 1/1", a.Misattributed, a.FromHost)
	}
	if a.CorrectlyAttributed != 1 {
		t.Errorf("correctly attributed = %d, want 1: the container's own run is still right", a.CorrectlyAttributed)
	}
	if a.HostOccurrences != 1 || a.HostLeftUnattributed != 0 {
		t.Errorf("host occurrences = %d, left unattributed = %d, want 1/0: the host's run was credited to the container",
			a.HostOccurrences, a.HostLeftUnattributed)
	}
	if a.HostMisattributedOccurrences != 1 {
		t.Errorf("host misattributed occurrences = %d, want 1", a.HostMisattributedOccurrences)
	}
	if a.HostCorrectRate != 0 {
		t.Errorf("host-correct rate = %v, want 0", a.HostCorrectRate)
	}
}

// TestHostOccurrenceWithNoMatchingEventIsUnobserved checks the third
// outcome a host occurrence can have: its own identity is decidable, but no
// event — neither one left unattributed nor one credited to a container —
// answers for it at all. That is not the same as Undecidable, which is
// reserved for an occurrence nothing could identify in the first place.
func TestHostOccurrenceWithNoMatchingEventIsUnobserved(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			{ID: "on-host", Kind: occurrenceExec, PID: 9000, TID: 9000, Starttime: "777", PIDNamespace: 4026531836,
				Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "host"},
		},
	}
	// The window holds no event at all for this run: the collection missed
	// it completely.
	a := computeAttributionMetrics(gtb, eventLogOf(), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.HostOccurrences != 1 {
		t.Errorf("host occurrences = %d, want 1", a.HostOccurrences)
	}
	if a.HostUnobserved != 1 {
		t.Errorf("host unobserved = %d, want 1", a.HostUnobserved)
	}
	if a.HostLeftUnattributed != 0 || a.FromHost != 0 {
		t.Errorf("host left unattributed = %d, from host = %d, want 0/0: nothing answered for this occurrence",
			a.HostLeftUnattributed, a.FromHost)
	}
	if a.Undecidable != 0 {
		t.Errorf("undecidable = %d, want 0: the occurrence's own identity was decidable, only no event was found", a.Undecidable)
	}
}

// TestHostOccurrenceWithBothOutcomesIsMisattributedNotCorrect checks that
// the three host outcomes are exclusive per occurrence. A single host
// occurrence can produce more than one matching event — here, one left
// unattributed and one wrongly credited to a container — and a caught
// misattribution must outrank the unattributed match: crediting the run to
// a container even once is the failure this control exists to find, and it
// does not become a correct result just because another event also went
// the right way.
func TestHostOccurrenceWithBothOutcomesIsMisattributedNotCorrect(t *testing.T) {
	const path = "/usr/bin/curl"
	moment := at(time.Minute)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			{ID: "on-host", Kind: occurrenceExec, PID: 9000, TID: 9000, Starttime: "777", PIDNamespace: 4026531836,
				Timestamp: moment, OK: true, Path: path, ContainerID: "host"},
		},
	}
	unattributed := execEvent(moment, 9000, 9000, path)
	unattributed.Starttime, unattributed.ContainerID = "777", ""
	unattributed.NSPID, unattributed.NSTID, unattributed.PIDNamespace = 9000, 9000, 4026531836
	misattributed := execEvent(moment.Add(50*time.Millisecond), 9000, 9000, path)
	misattributed.Starttime, misattributed.ContainerID = "777", "c1"
	misattributed.NSPID, misattributed.NSTID, misattributed.PIDNamespace = 9000, 9000, 4026531836

	a := computeAttributionMetrics(gtb, eventLogOf(unattributed, misattributed), "c1",
		occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)

	if a.HostOccurrences != 1 {
		t.Errorf("host occurrences = %d, want 1", a.HostOccurrences)
	}
	if a.HostMisattributedOccurrences != 1 {
		t.Errorf("host misattributed occurrences = %d, want 1", a.HostMisattributedOccurrences)
	}
	if a.HostLeftUnattributed != 0 {
		t.Errorf("host left unattributed = %d, want 0: the misattributed match outranks the unattributed one", a.HostLeftUnattributed)
	}
	if a.HostUnobserved != 0 {
		t.Errorf("host unobserved = %d, want 0", a.HostUnobserved)
	}
	// The three outcomes must sum to HostOccurrences.
	if got := a.HostMisattributedOccurrences + a.HostLeftUnattributed + a.HostUnobserved; got != a.HostOccurrences {
		t.Errorf("misattributed(%d) + left-unattributed(%d) + unobserved(%d) = %d, want host_occurrences = %d",
			a.HostMisattributedOccurrences, a.HostLeftUnattributed, a.HostUnobserved, got, a.HostOccurrences)
	}
}

// TestHostOccurrenceWithSeveralMisattributedEventsCountsOnceAtOccurrenceLevel
// checks that HostMisattributedOccurrences, unlike FromHost, does not grow
// with the number of events one host occurrence produces: it answers "was
// this occurrence's work credited to a container at all", not "how many
// events said so".
func TestHostOccurrenceWithSeveralMisattributedEventsCountsOnceAtOccurrenceLevel(t *testing.T) {
	const path = "/usr/bin/curl"
	moment := at(time.Minute)
	gtb := &GroundTruthB{
		Kind: "usage_log",
		// A correspondence table, unrelated to the host occurrence below,
		// so the container-side match rule is the stronger one and
		// MisattributionRate is actually computed rather than reported
		// unavailable.
		PIDMap: correspondence([3]int{1, 1, 999}),
		Occurrences: []Occurrence{
			{ID: "on-host", Kind: occurrenceExec, PID: 9000, TID: 9000, Starttime: "777", PIDNamespace: 4026531836,
				Timestamp: moment, OK: true, Path: path, ContainerID: "host"},
		},
	}
	first := execEvent(moment, 9000, 9000, path)
	first.Starttime, first.ContainerID = "777", "c1"
	first.NSPID, first.NSTID, first.PIDNamespace = 9000, 9000, 4026531836
	second := execEvent(moment.Add(50*time.Millisecond), 9000, 9000, path)
	second.Starttime, second.ContainerID = "777", "c1"
	second.NSPID, second.NSTID, second.PIDNamespace = 9000, 9000, 4026531836

	a := computeAttributionMetrics(gtb, eventLogOf(first, second), "c1",
		occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)

	if a.HostMisattributedOccurrences != 1 {
		t.Errorf("host misattributed occurrences = %d, want 1: one occurrence, however many events answered for it", a.HostMisattributedOccurrences)
	}
	if a.FromHost != 2 || a.Misattributed != 2 {
		t.Errorf("from host = %d, misattributed = %d, want 2/2: both events are counted at event granularity", a.FromHost, a.Misattributed)
	}
}

// TestHostOccurrenceCreditedToAnUnevaluatedContainerIsStillMisattributed
// checks the scope mismatch between the occurrence-level outcome and the
// event-level one. The ground truth says this was host work regardless of
// which container ended up credited with it, so a match against a
// container this log never otherwise mentions still marks the occurrence
// misattributed — but FromHost and MisattributionRate stay scoped to what
// AttributedEvents itself counts, so such an event must not inflate them,
// or the rate could be reported above one.
func TestHostOccurrenceCreditedToAnUnevaluatedContainerIsStillMisattributed(t *testing.T) {
	const path = "/usr/bin/curl"
	moment := at(time.Minute)
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{10, 10, 555}),
		Occurrences: []Occurrence{
			// The container's own, correctly attributed run — the one
			// event AttributedEvents/MisattributionRate's denominator
			// covers.
			{ID: "in-container", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555",
				Timestamp: moment, OK: true, Path: path, ContainerID: "c1"},
			{ID: "on-host", Kind: occurrenceExec, PID: 9000, TID: 9000, Starttime: "777", PIDNamespace: 4026531836,
				Timestamp: moment.Add(200 * time.Millisecond), OK: true, Path: path, ContainerID: "host"},
		},
	}
	containerEvent := execEvent(moment, 10, 10, path)
	containerEvent.Starttime = "555"
	// Two events for the host's run, each credited to a container this log
	// never mentions on its own — neither "c1" (the container under test)
	// nor any container an occurrence names, so evaluated[...] is false
	// for both.
	toC3 := execEvent(moment.Add(200*time.Millisecond), 9000, 9000, path)
	toC3.Starttime, toC3.ContainerID = "777", "c3"
	toC3.NSPID, toC3.NSTID, toC3.PIDNamespace = 9000, 9000, 4026531836
	toC4 := execEvent(moment.Add(210*time.Millisecond), 9000, 9000, path)
	toC4.Starttime, toC4.ContainerID = "777", "c4"
	toC4.NSPID, toC4.NSTID, toC4.PIDNamespace = 9000, 9000, 4026531836

	a := computeAttributionMetrics(gtb, eventLogOf(containerEvent, toC3, toC4), "c1",
		occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)

	if a.HostMisattributedOccurrences != 1 {
		t.Errorf("host misattributed occurrences = %d, want 1: the run was credited to a container, evaluated or not", a.HostMisattributedOccurrences)
	}
	if a.FromHost != 0 || a.Misattributed != 0 {
		t.Errorf("from host = %d, misattributed = %d, want 0/0: neither credited container is one this log evaluates", a.FromHost, a.Misattributed)
	}
	if a.AttributedEvents != 1 {
		t.Errorf("attributed events = %d, want 1: only the container's own run is in scope", a.AttributedEvents)
	}
	if a.MisattributionRate > 1 {
		t.Errorf("misattribution rate = %v, want <= 1", a.MisattributionRate)
	}
}

// TestAHostOccurrenceWithNoPIDNamespaceIsUndecidable checks that a host
// occurrence missing PIDNamespace is settled as undecidable up front,
// before any search for a matching event — not only when a candidate event
// happens to turn up unplaceable. sameHostProcess already refuses to
// compare without it on both sides; leaving the occurrence-side check out
// here meant one with no candidate event at all fell through as
// host_unobserved, decidable in name only, while nothing had actually
// confirmed its identity could be told from any other process's.
func TestAHostOccurrenceWithNoPIDNamespaceIsUndecidable(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			// PIDNamespace left at zero.
			{ID: "on-host", Kind: occurrenceExec, PID: 9000, TID: 9000, Starttime: "777",
				Timestamp: at(time.Minute), OK: true, Path: "/usr/bin/curl", ContainerID: "host"},
		},
	}
	a := computeAttributionMetrics(gtb, eventLogOf(), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.Undecidable != 1 {
		t.Errorf("undecidable = %d, want 1", a.Undecidable)
	}
	if a.HostOccurrences != 0 {
		t.Errorf("host occurrences = %d, want 0: an occurrence with no PID namespace was never confirmed decidable", a.HostOccurrences)
	}
	if a.HostUnobserved != 0 {
		t.Errorf("host unobserved = %d, want 0", a.HostUnobserved)
	}
}

// TestSameHostProcessRequiresTheEventsOwnNamespaceNumbers checks that an
// event carrying no NSPID or NSTID cannot be placed against a host
// occurrence: PID/TID are the initial namespace's numbers, which are not
// what a host task's own /proc reports on a host that is itself inside a
// child PID namespace (see sameHostProcess's own doc comment), so an
// event missing the numbers that would agree is not usable rather than
// matched on the path and the time alone.
func TestSameHostProcessRequiresTheEventsOwnNamespaceNumbers(t *testing.T) {
	occ := Occurrence{PID: 30, TID: 30, Starttime: "777", PIDNamespace: 4026531836}
	ev := EventRecord{PID: 30, TID: 30, Starttime: "777", PIDNamespace: 4026531836} // NSPID/NSTID left at zero
	if _, usable := sameHostProcess(ev, occ); usable {
		t.Error("usable = true, want false: the event carries no own-namespace numbers")
	}
}

// TestSameHostProcessUsesNamespaceNumbersNotInitialNamespaceOnes checks
// that a match is decided on NSPID/NSTID even where PID/TID disagree with
// the occurrence: on a host that is itself inside a child PID namespace,
// PID/TID are not the host's own numbers, and comparing those instead
// would refuse a genuine match.
func TestSameHostProcessUsesNamespaceNumbersNotInitialNamespaceOnes(t *testing.T) {
	occ := Occurrence{PID: 30, TID: 30, Starttime: "777", PIDNamespace: 4026531836}
	ev := EventRecord{PID: 99999, TID: 99999, NSPID: 30, NSTID: 30, Starttime: "777", PIDNamespace: 4026531836}
	matches, usable := sameHostProcess(ev, occ)
	if !usable {
		t.Fatal("usable = false, want true")
	}
	if !matches {
		t.Error("matches = false, want true: NSPID/NSTID agree with the occurrence even though PID/TID do not")
	}
}

// TestSameHostProcessRequiresBothPIDNamespaceIdentifiers checks that a
// missing PIDNamespace on either side — the occurrence or the event —
// leaves the pairing unusable even when every number and Starttime is
// present, since NSPID/NSTID mean nothing until the namespace they were
// read in is confirmed the same on both sides.
func TestSameHostProcessRequiresBothPIDNamespaceIdentifiers(t *testing.T) {
	occ := Occurrence{PID: 30, TID: 30, Starttime: "777"} // PIDNamespace left at zero
	ev := EventRecord{NSPID: 30, NSTID: 30, Starttime: "777", PIDNamespace: 4026531836}
	if _, usable := sameHostProcess(ev, occ); usable {
		t.Error("usable = true, want false: the occurrence carries no PID namespace identifier")
	}

	occ.PIDNamespace = 4026531836
	ev.PIDNamespace = 0 // now the event is the one missing it
	if _, usable := sameHostProcess(ev, occ); usable {
		t.Error("usable = true, want false: the event carries no PID namespace identifier")
	}
}

// TestSameHostProcessRefusesACollisionAcrossNamespaces is the regression
// this control exists to prevent: a task in some other PID namespace
// whose NSPID, NSTID, and Starttime all happen to agree with the
// occurrence must not read as the same process. Only comparing the
// namespace identifier too tells a genuine host task from this
// coincidence.
func TestSameHostProcessRefusesACollisionAcrossNamespaces(t *testing.T) {
	occ := Occurrence{PID: 30, TID: 30, Starttime: "777", PIDNamespace: 4026531836}
	ev := EventRecord{NSPID: 30, NSTID: 30, Starttime: "777", PIDNamespace: 4026532000} // same numbers and starttime, a different PID namespace
	matches, usable := sameHostProcess(ev, occ)
	if !usable {
		t.Fatal("usable = false, want true: both sides carry a PID namespace identifier, just not the same one")
	}
	if matches {
		t.Error("matches = true, want false: NSPID/NSTID/Starttime agreeing across two different PID namespaces is a coincidence, not an identity")
	}
}

// TestAHostOccurrenceWithoutIdentityIsUndecidable checks that a host-side
// record naming no process cannot produce a wrong-attribution finding. The
// path and the moment are all it has, and both are shared with whatever
// the container was doing.
func TestAHostOccurrenceWithoutIdentityIsUndecidable(t *testing.T) {
	gtb := &GroundTruthB{
		Kind: "usage_log",
		Occurrences: []Occurrence{
			{ID: "on-host", Kind: occurrenceExec, Timestamp: at(time.Minute), OK: true,
				Path: "/usr/bin/curl", ContainerID: "host"},
		},
	}
	ev := execEvent(at(time.Minute), 4242, 4242, "/usr/bin/curl")
	ev.Starttime = "555"
	a := computeAttributionMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if a.Misattributed != 0 {
		t.Errorf("wrong attributions = %d, want none: nothing identified the host's process", a.Misattributed)
	}
	if a.Undecidable != 1 {
		t.Errorf("undecidable = %d, want 1", a.Undecidable)
	}
	if a.LoggedOccurrences != 0 {
		t.Errorf("logged occurrences = %d, want 0: an occurrence nothing can place is not in the denominator", a.LoggedOccurrences)
	}
}

// TestASystemCallWhoseOnlyEventCannotBePlacedIsUndecidable checks the
// system-call level rate against the same rule the other two follow.
//
// The correspondence is there, and an event arrives at the right path and
// the right moment with the right process and thread — but it does not say
// which generation produced it. That is not evidence the call was missed:
// it is an event nothing can place. Counting it as a miss reports a
// capture rate of zero for a collection that did observe the call.
func TestASystemCallWhoseOnlyEventCannotBePlacedIsUndecidable(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 1, 555}),
		Occurrences: []Occurrence{{
			ID: "load", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
			Start: at(time.Minute), End: at(time.Minute), OK: true, Files: []string{"/lib/a.so"},
		}},
		RealOpens: []RealOpen{
			{ID: "o1", PID: 1, TID: 1, Starttime: "555", Timestamp: at(time.Minute), Path: "/lib/a.so", OK: true},
		},
	}
	ev := openEvent(at(time.Minute), 1, 1, "/lib/a.so")
	ev.Starttime = "" // the collection could not read the generation

	m := computeOccurrenceMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.RealOpen.Undecidable != 1 {
		t.Errorf("undecidable system calls = %d, want 1", m.RealOpen.Undecidable)
	}
	if m.RealOpen.Decidable != 0 {
		t.Errorf("decidable system calls = %d, want 0", m.RealOpen.Decidable)
	}
	if m.RealOpen.Rate != -1 {
		t.Errorf("rate = %v, want unavailable rather than zero", m.RealOpen.Rate)
	}

	// The same call with a placeable event is captured, and counts.
	ev.Starttime = "555"
	m = computeOccurrenceMetrics(gtb, eventLogOf(ev), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.RealOpen.Decidable != 1 || m.RealOpen.Captured != 1 || m.RealOpen.Rate != 1 {
		t.Errorf("decidable=%d captured=%d rate=%v, want 1/1/1", m.RealOpen.Decidable, m.RealOpen.Captured, m.RealOpen.Rate)
	}

	// A call no event answers at all is a genuine miss, and stays in the
	// denominator.
	m = computeOccurrenceMetrics(gtb, eventLogOf(), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)
	if m.RealOpen.Decidable != 1 || m.RealOpen.Captured != 0 || m.RealOpen.Rate != 0 {
		t.Errorf("with no events: decidable=%d captured=%d rate=%v, want 1/0/0", m.RealOpen.Decidable, m.RealOpen.Captured, m.RealOpen.Rate)
	}
}

// TestAWrongAttributionStaysInTheDenominator checks that an occurrence
// found credited to the wrong container is a decided outcome.
//
// The window holds three things: one run credited to the wrong container,
// an event for that same run that cannot be placed, and a second run
// credited correctly. The wrong attribution was established — the
// unplaceable event alongside it does not unsettle it — so both runs are
// in the denominator and the share attributed correctly is one in two.
// Dropping the first would report the same collection as perfect.
func TestAWrongAttributionStaysInTheDenominator(t *testing.T) {
	const path = "/usr/bin/curl"
	gtb := &GroundTruthB{
		Kind: "usage_log",
		PIDMap: []PIDMapping{
			{ContainerID: "c1", ContainerPID: 10, HostPID: 10, ContainerTID: 10, HostTID: 10, Starttime: "555"},
			{ContainerID: "c2", ContainerPID: 20, HostPID: 20, ContainerTID: 20, HostTID: 20, Starttime: "666"},
		},
		Occurrences: []Occurrence{
			// The second container's run, which the collection credits to
			// the first.
			{ID: "misattributed", Kind: occurrenceExec, PID: 20, TID: 20, Starttime: "666",
				Timestamp: at(time.Minute), OK: true, Path: path, ContainerID: "c2"},
			// The first container's own run, credited correctly.
			{ID: "correct", Kind: occurrenceExec, PID: 10, TID: 10, Starttime: "555",
				Timestamp: at(2 * time.Minute), OK: true, Path: path, ContainerID: "c1"},
		},
	}

	wrong := execEvent(at(time.Minute), 20, 20, path)
	wrong.Starttime, wrong.ContainerID = "666", "c1"
	// A second event for the same run, carrying no generation.
	unplaceable := execEvent(at(time.Minute), 20, 20, path)
	unplaceable.Starttime, unplaceable.ContainerID = "", "c1"
	right := execEvent(at(2*time.Minute), 10, 10, path)
	right.Starttime, right.ContainerID = "555", "c1"

	a := computeAttributionMetrics(gtb, eventLogOf(wrong, unplaceable, right), "c1",
		occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)

	if a.LoggedOccurrences != 2 {
		t.Errorf("logged occurrences = %d, want both: one was decided wrong, the other right", a.LoggedOccurrences)
	}
	if a.CorrectlyAttributed != 1 {
		t.Errorf("correctly attributed = %d, want 1", a.CorrectlyAttributed)
	}
	if a.CorrectAttributionRate != 0.5 {
		t.Errorf("correct-attribution rate = %v, want 0.5", a.CorrectAttributionRate)
	}
	if a.Misattributed != 1 || a.FromOtherContainer != 1 {
		t.Errorf("wrong attributions = %d (from another container: %d), want 1/1", a.Misattributed, a.FromOtherContainer)
	}
	if a.Undecidable != 0 {
		t.Errorf("undecidable = %d, want 0: both runs were placed", a.Undecidable)
	}
}

// TestAttributionExcludesCacheHitFromTheDenominator checks that a load
// satisfied from cache is kept out of LoggedOccurrences the same way
// OccurrenceMetrics keeps it out of its own denominator: it reads no
// file, so no event corresponds to it, and counting it here would fault
// attribution for an event that was never going to exist. This mirrors a
// real run where, of two logged loads, one was a cache hit and the other
// was correctly attributed — the correct-attribution rate must come out
// as 1, not 0.5.
func TestAttributionExcludesCacheHitFromTheDenominator(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 1, 555}),
		Occurrences: []Occurrence{
			{ID: "real", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
				Start: at(time.Minute), End: at(time.Minute), OK: true,
				Files: []string{"/lib/a.so"}, ContainerID: "c1"},
			// A cache hit: the runtime already held the module, so it read
			// nothing and no event answers for it.
			{ID: "cached", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
				Start: at(2 * time.Minute), End: at(2 * time.Minute), OK: true, CacheHit: true, ContainerID: "c1"},
		},
	}
	a := computeAttributionMetrics(gtb, eventLogOf(openEvent(at(time.Minute), 1, 1, "/lib/a.so")), "c1",
		occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)

	if a.Excluded.CacheHit != 1 {
		t.Errorf("cache-hit exclusions = %d, want 1", a.Excluded.CacheHit)
	}
	if a.LoggedOccurrences != 1 {
		t.Errorf("logged occurrences = %d, want 1: the cache hit does not belong in the denominator", a.LoggedOccurrences)
	}
	if a.CorrectlyAttributed != 1 {
		t.Errorf("correctly attributed = %d, want 1", a.CorrectlyAttributed)
	}
	if a.CorrectAttributionRate != 1 {
		t.Errorf("correct-attribution rate = %v, want 1", a.CorrectAttributionRate)
	}
}

// TestCorrectAttributionRateIsUnavailableWithNoLoggedOccurrences checks
// that when every occurrence is excluded — here, every logged load was a
// cache hit — the rate is reported unavailable rather than as some
// default. A denominator of zero is not a rate of zero, or of one: it is
// a question this run never had a chance to answer.
func TestCorrectAttributionRateIsUnavailableWithNoLoggedOccurrences(t *testing.T) {
	gtb := &GroundTruthB{
		Kind:   "usage_log",
		PIDMap: correspondence([3]int{1, 1, 555}),
		Occurrences: []Occurrence{
			{ID: "cached-1", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
				Start: at(time.Minute), End: at(time.Minute), OK: true, CacheHit: true, ContainerID: "c1"},
			{ID: "cached-2", Kind: occurrenceLoad, PID: 1, TID: 1, Starttime: "555",
				Start: at(2 * time.Minute), End: at(2 * time.Minute), OK: true, CacheHit: true, ContainerID: "c1"},
		},
	}
	a := computeAttributionMetrics(gtb, eventLogOf(), "c1", occWindowStart, occWindowEnd, defaultOccurrenceToleranceMS)

	if a.LoggedOccurrences != 0 {
		t.Errorf("logged occurrences = %d, want 0: both were cache hits", a.LoggedOccurrences)
	}
	if a.CorrectAttributionRate != -1 {
		t.Errorf("correct-attribution rate = %v, want -1 (unavailable)", a.CorrectAttributionRate)
	}
	if a.Excluded.CacheHit != 2 {
		t.Errorf("cache-hit exclusions = %d, want 2", a.Excluded.CacheHit)
	}
}
