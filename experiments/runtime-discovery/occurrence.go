package main

import (
	"fmt"
	"sort"
	"time"
)

// Occurrence kinds in a case's independent log.
const (
	occurrenceExec = "exec"
	occurrenceLoad = "load"
)

// defaultOccurrenceToleranceMS is the time difference allowed between an
// occurrence the workload recorded and the event the collection reported
// for it. It is fixed before a measurement rather than tuned afterwards:
// widening it until the numbers improve would be choosing the answer.
const defaultOccurrenceToleranceMS = 500

// Occurrence is one thing the workload recorded itself doing, with an
// identifier unique within its case.
//
// Two kinds are recorded, and they are counted differently. An execution
// is a point: one successful execution produces exactly one event, so the
// two can be required to pair up one to one. A load is an interval: one
// module load can read several files, or none at all when the runtime
// already has the module in memory, so it is matched against a set of
// events and the set's size is not required to be anything in particular.
type Occurrence struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // "exec" | "load"
	// PID and TID are as the workload sees them, inside its own process
	// number space; HostPID and HostTID are the same processes as the host
	// sees them, filled in only where the case runner could establish the
	// correspondence. Starttime is the process generation's start time in
	// clock ticks, which reads the same on both sides and is therefore the
	// identifier that works when the correspondence is unavailable.
	PID       int       `json:"pid"`
	TID       int       `json:"tid,omitempty"`
	HostPID   int       `json:"host_pid,omitempty"`
	HostTID   int       `json:"host_tid,omitempty"`
	Starttime ProcTicks `json:"starttime,omitempty"`
	// PIDNamespace is the identifier of the PID namespace PID/TID are
	// numbered in, required for a host occurrence (see sameHostProcess):
	// PID/TID alone can collide with a task in an unrelated namespace,
	// and only comparing the namespace identifier too rules that out. A
	// container occurrence does not need it — container attribution goes
	// through the control group instead.
	PIDNamespace uint64 `json:"pid_ns,omitempty"`

	// Timestamp is when a point occurrence happened; Start and End bound
	// an interval occurrence.
	Timestamp time.Time `json:"ts,omitempty"`
	Start     time.Time `json:"start,omitempty"`
	End       time.Time `json:"end,omitempty"`

	OK bool `json:"ok"`
	// CacheHit says the operation succeeded without reading any file,
	// because the runtime already held what was asked for. Such an
	// occurrence is excluded from the denominator: counting it would
	// record a missing event for a file read that never happened.
	CacheHit bool `json:"cache_hit,omitempty"`

	// Path is a point occurrence's target; Files are every file an
	// interval occurrence resolved.
	Path  string   `json:"path,omitempty"`
	Files []string `json:"files,omitempty"`

	// ContainerID is where this occurrence really happened, as the case
	// declares it. The value "host" means it happened outside any
	// container. It is what an attribution claim is checked against.
	ContainerID string `json:"container_id,omitempty"`
	Note        string `json:"note,omitempty"`
}

// RealOpen is one actual file-open system call, recorded independently of
// the collection being measured. Only a case that can record these has a
// denominator for the system-call capture rate at all; the rate is not
// substituted for by the load-level one, which counts something else.
type RealOpen struct {
	ID          string    `json:"id"`
	PID         int       `json:"pid"`
	TID         int       `json:"tid,omitempty"`
	HostPID     int       `json:"host_pid,omitempty"`
	Starttime   ProcTicks `json:"starttime,omitempty"`
	Timestamp   time.Time `json:"ts"`
	Path        string    `json:"path"`
	OK          bool      `json:"ok"`
	ContainerID string    `json:"container_id,omitempty"`
}

// PIDMapping is one process's number in the container and on the host, as
// the case runner established it.
// PIDMapping is one process's numbers in the two number spaces, and its
// generation start time, as the case runner established them.
//
// The thread numbers are separate entries: a thread's number is not
// derivable from its process's, and a comparison that assumed it was would
// pair work done by one thread with work done by another.
type PIDMapping struct {
	// ContainerID is which container the process number belongs to. Two
	// containers number their processes independently, so a table without
	// it answers one container's question with another's process.
	ContainerID  string `json:"container_id,omitempty"`
	ContainerPID int    `json:"container_pid"`
	HostPID      int    `json:"host_pid"`
	ContainerTID int    `json:"container_tid,omitempty"`
	HostTID      int    `json:"host_tid,omitempty"`
	// Starttime is the generation the correspondence was established for.
	// A process number is reused, so an entry without it stops being an
	// answer the moment the process it described exits.
	Starttime ProcTicks `json:"starttime,omitempty"`
}

// ExecCapture is the point-occurrence capture rate.
type ExecCapture struct {
	Eligible int     `json:"eligible"`
	OneToOne int     `json:"one_to_one"`
	Rate     float64 `json:"rate"` // -1 = N/A
	// Unmatchable counts occurrences that could not be paired one to one,
	// split by which side was ambiguous. They are not counted as captured:
	// an execution that several events answer to has not been identified.
	Unmatchable int `json:"unmatchable"`
	OneToMany   int `json:"one_occurrence_many_events"`
	ManyToOne   int `json:"many_occurrences_one_event"`
	// Undecidable counts occurrences whose process could not be identified
	// against the event side at all, because neither the process number
	// correspondence nor a generation start time was available on both
	// sides. They are neither captures nor misses of the collection:
	// nothing here could have told one process from another.
	Undecidable int `json:"undecidable"`
	// Decidable is the denominator the rate is actually over: the eligible
	// occurrences minus the ones nothing could identify.
	Decidable int `json:"decidable"`
}

// LoadCapture is the interval-occurrence evidence rate.
type LoadCapture struct {
	Eligible     int     `json:"eligible"`
	WithEvidence int     `json:"with_evidence"`
	Rate         float64 `json:"rate"` // -1 = N/A
	// AttributionConflicts counts events that could belong to more than
	// one load. Such an event is used for none of them: letting it count
	// for each would credit one observation twice.
	AttributionConflicts int `json:"attribution_conflicts"`
	// Undecidable counts loads whose process could not be identified
	// against the event side at all, and Decidable is the denominator the
	// rate is over once they are taken out.
	Undecidable int `json:"undecidable"`
	Decidable   int `json:"decidable"`
}

// RealOpenCapture is the system-call capture rate, computed only where an
// independent record of the calls exists.
type RealOpenCapture struct {
	Occurrences int     `json:"occurrences"`
	Captured    int     `json:"captured"`
	Rate        float64 `json:"rate"` // -1 = N/A
	NA          bool    `json:"na"`
	Undecidable int     `json:"undecidable"`
	Decidable   int     `json:"decidable"`
}

// ExcludedOccurrences is what was kept out of the denominators, and why.
type ExcludedOccurrences struct {
	CacheHit      int `json:"cache_hit"`
	Failed        int `json:"failed"`
	OutsideWindow int `json:"outside_window"`
}

// UncapturedReasons splits what was not captured into what can be
// explained and what cannot.
//
// The third value is not a failure of the collection. A window where no
// independent log exists — a production sample, where the workload cannot
// be made to record what it is doing — can say nothing about whether
// something happened and was missed or never happened at all, and saying
// the collection failed there would be an unfounded claim in the other
// direction.
type UncapturedReasons struct {
	OutsideWindow  int `json:"outside_window"`
	InWindowMissed int `json:"in_window_missed"`
	ReasonUnknown  int `json:"reason_unknown"`
}

// AttributionMetrics is the container-attribution result. Both rates are
// always reported: an implementation that discards every event attributes
// nothing wrongly, so a misattribution rate alone cannot show that
// attribution works.
//
// A container occurrence and a host occurrence are scored against opposite
// definitions of correct, so they are kept in separate triples rather than
// one shared denominator: crediting a container occurrence to its own
// container is right, while crediting a host occurrence to any container at
// all is wrong. Pooling the two would count every correctly-unattributed
// host occurrence as an uncredited miss and drag the rate down for
// reporting nothing but a correct result.
type AttributionMetrics struct {
	// MatchRule is the same identity rule OccurrenceMetrics reports: the
	// one newOccurrenceMatcher resolved to for this run, decided by
	// whether a process-number correspondence table exists at all.
	MatchRule string `json:"match_rule"`
	// CrossContainerEvaluable says whether MisattributionRate can actually
	// speak to an event wrongly credited to another container.
	//
	// Under container_generation_and_thread a host-wide number identifies
	// a process independently of any container, so an event's real
	// process can be confirmed whichever container it was credited to,
	// and a mismatch there is a decided misattribution.
	//
	// Under container_namespace_pid_and_thread there is no such
	// container-independent number: a namespace-scoped one is only unique
	// within its own container, so confirming a process's identity at all
	// already requires the event's own container to be the one under
	// test (see sameProcess). An event credited to some other container
	// is therefore never confirmed as this occurrence's process — not
	// because it is not misattributed, but because nothing here can tell
	// a genuine misattribution from a coincidental number collision
	// between two containers' own, independent numbering. Reporting a
	// rate in that state would count every such case as correct by
	// default, which is not established.
	CrossContainerEvaluable bool `json:"cross_container_evaluable"`

	AttributedEvents   int     `json:"attributed_events"`
	Misattributed      int     `json:"misattributed"`
	MisattributionRate float64 `json:"misattribution_rate"` // -1 = N/A, including when !CrossContainerEvaluable

	// LoggedOccurrences, CorrectlyAttributed and CorrectAttributionRate are
	// over container occurrences only (ContainerID != "host"). The correct
	// outcome for one of those is being credited to the container it
	// really happened in, which is a different question from the one the
	// host counters below answer, so a host occurrence does not belong in
	// this denominator.
	LoggedOccurrences      int     `json:"logged_occurrences"`
	CorrectlyAttributed    int     `json:"correctly_attributed"`
	CorrectAttributionRate float64 `json:"correct_attribution_rate"` // -1 = N/A

	// HostOccurrences, HostMisattributedOccurrences, HostLeftUnattributed,
	// HostUnobserved and HostCorrectRate are the equivalent triple (plus
	// its own misattribution count) for occurrences the case says happened
	// on the host. The correct outcome there is the opposite of a
	// container's: an event answering for host work is right exactly when
	// no container is credited with it. Sharing LoggedOccurrences'
	// denominator would make every correct host outcome count as a miss.
	//
	// The three outcomes are exclusive per occurrence, and always sum to
	// HostOccurrences: a host occurrence with events on both sides — one
	// left unattributed, another wrongly credited to a container — is a
	// caught misattribution, not also a correct result, so a
	// misattributed match outranks an unattributed one in deciding which
	// bucket the occurrence falls into.
	HostOccurrences int `json:"host_occurrences"`
	// HostMisattributedOccurrences counts a host occurrence for which at
	// least one matching event was credited to some container, at
	// occurrence granularity — one occurrence, one count, however many
	// such events it produced. This is a different question from FromHost
	// below, which counts at event granularity and is scoped to only the
	// containers this log evaluates; a single occurrence with several
	// wrongly-credited events adds one here but can add several there.
	HostMisattributedOccurrences int `json:"host_misattributed_occurrences"`
	HostLeftUnattributed         int `json:"host_left_unattributed"`
	// HostUnobserved counts a host occurrence whose own identity was
	// decidable but for which no event — neither one left unattributed nor
	// one credited to a container — could be found at all. This is not the
	// same as Undecidable: an undecidable case is one where the occurrence
	// itself could not be identified, while an unobserved one was
	// identifiable and simply has no matching event to show for it.
	HostUnobserved  int     `json:"host_unobserved"`
	HostCorrectRate float64 `json:"host_correct_rate"` // -1 = N/A

	FromOtherContainer int `json:"from_other_container"`
	// FromHost counts, at event granularity and only among events credited
	// to a container this log evaluates (the same scope AttributedEvents
	// and MisattributionRate use), an event that answered for host work.
	// It is not HostMisattributedOccurrences under another name: this one
	// can count several events for a single occurrence, and it leaves out
	// an event credited to a container the log does not evaluate, which
	// HostMisattributedOccurrences still counts as a wrong occurrence.
	FromHost     int `json:"from_host"`
	Unattributed int `json:"unattributed_events"`
	// Undecidable counts occurrence-and-event pairs whose process could
	// not be identified against each other at all. They are neither right
	// nor wrong attributions: nothing here could have told one process
	// from another.
	Undecidable int `json:"undecidable"`
	// Excluded is what was kept out of LoggedOccurrences and why, on the
	// same grounds OccurrenceMetrics excludes them from its own
	// denominator: a cache hit reads nothing, a failed operation is not
	// use, and an occurrence outside the window is outside what this run
	// measures. Counting any of them here would fault attribution for an
	// event that was never going to exist.
	Excluded ExcludedOccurrences `json:"excluded"`
}

// OccurrenceMetrics is the whole per-occurrence capture result for one run.
type OccurrenceMetrics struct {
	Available   bool   `json:"available"`
	ToleranceMS int64  `json:"tolerance_ms"`
	ClockBasis  string `json:"clock_basis,omitempty"`
	// MatchRule says what identified a process across the two number
	// spaces: the host process number where the case runner supplied the
	// correspondence, otherwise the generation start time, which reads the
	// same on both sides.
	MatchRule string `json:"match_rule"`

	Exec       ExecCapture         `json:"exec"`
	Load       LoadCapture         `json:"load"`
	RealOpen   RealOpenCapture     `json:"real_open"`
	Excluded   ExcludedOccurrences `json:"excluded"`
	Uncaptured UncapturedReasons   `json:"uncaptured"`
	Notes      []string            `json:"notes,omitempty"`
}

// occurrenceMatcher pairs a case's independent log against an event log.
//
// It resolves to one of two rules, decided once, when it is built, on
// whether a process-number correspondence table exists at all.
//
//   - container_generation_and_thread: the table translates the
//     occurrence's container-native numbers to the event's host-wide
//     ones. It is the stronger rule — a host-wide number is unique across
//     every container — and is used whenever the table has anything in
//     it.
//   - container_namespace_pid_and_thread: without a table, an event's
//     namespace-scoped numbers (NSPID/NSTID) are compared directly
//     against the occurrence's own, which a workload inside a container
//     reports in that same namespace. A namespace-scoped number is only
//     unique within its own container, unlike a host-wide one, so this
//     rule also requires the event's own container to be the one under
//     test: it cannot tell a coincidental match in some other container
//     from the real one, and does not try to.
//
// A case's log either carries a correspondence table or it does not; the
// two rules are never mixed within one matcher.
type occurrenceMatcher struct {
	tolerance time.Duration
	// byThread holds the correspondence between the two process number
	// spaces, keyed by container, generation and thread. All three belong
	// in the key: two containers number their processes independently, a
	// number is reused once the process using it exits, and one process's
	// threads are different threads doing different work.
	byThread map[threadKey]PIDMapping
	rule     string
}

// Matching rule names. See occurrenceMatcher's own comment for what each
// one identifies a process by and why.
const (
	ruleGenerationAndThread = "container_generation_and_thread"
	ruleNamespacePIDAndTID  = "container_namespace_pid_and_thread"
)

type threadKey struct {
	containerID string
	pid         int
	tid         int
	starttime   string
}

func newOccurrenceMatcher(mappings []PIDMapping, tolerance time.Duration, defaultContainer string) *occurrenceMatcher {
	m := &occurrenceMatcher{tolerance: tolerance, byThread: map[threadKey]PIDMapping{}, rule: ruleNamespacePIDAndTID}
	for _, pm := range mappings {
		if pm.HostPID == 0 {
			continue
		}
		container := pm.ContainerID
		if container == "" {
			container = defaultContainer
		}
		entry := pm
		if entry.ContainerTID == 0 {
			// An entry naming only the process describes its leading
			// thread, whose number equals its process number on both
			// sides. That is how threads are numbered, not an assumption
			// about this workload.
			entry.ContainerTID, entry.HostTID = pm.ContainerPID, pm.HostPID
		}
		if entry.HostTID == 0 {
			continue
		}
		// Keyed by thread, so a second thread of the same process adds an
		// entry rather than replacing the first one's.
		m.byThread[threadKey{container, entry.ContainerPID, entry.ContainerTID, entry.Starttime.String()}] = entry
	}
	if len(m.byThread) > 0 {
		// A recorded correspondence is the stronger rule — a host-wide
		// number is unique across every container, so it is preferred
		// whenever it exists.
		m.rule = ruleGenerationAndThread
	}
	return m
}

func (m *occurrenceMatcher) ruleName() string { return m.rule }

// decidable reports whether anything here could tell one process and
// thread from another for a given occurrence.
//
// It is asked before any candidate is looked at. An occurrence nothing can
// identify is neither captured nor missed — the collection was never given
// the chance to be judged on it — and searching for candidates first would
// have to decide afterwards what a match even meant.
//
// Deciding needs, at a minimum, the occurrence's own process, thread and
// generation: a start time that agrees is not enough on its own, since it
// is rounded to a clock tick and two containers produce theirs
// independently.
//
// Under container_generation_and_thread that alone is not enough either:
// deciding needs a recorded correspondence between the two process number
// spaces, for this container, this generation and this thread.
//
// Under container_namespace_pid_and_thread no such table is required — it
// exists for exactly the case where none was recorded — so the
// occurrence's own numbers are all this asks for here. Whether a candidate
// event actually carries a namespace-scoped number to compare them against
// is a separate, per-event question, answered in sameProcess.
func (m *occurrenceMatcher) decidable(containerID string, pid, tid int, starttime ProcTicks) bool {
	if starttime.empty() || tid == 0 {
		return false
	}
	switch m.rule {
	case ruleGenerationAndThread:
		_, ok := m.byThread[threadKey{containerID, pid, tid, starttime.String()}]
		return ok
	case ruleNamespacePIDAndTID:
		return pid != 0
	default:
		return false
	}
}

// sameProcess reports whether an event was produced by the process and
// thread an occurrence names, and whether the event carried enough to
// answer that at all.
//
// The second return matters as much as the first. An event that does not
// say which thread or which generation produced it is not evidence that a
// different process did the work — it is an event nothing can place. Read
// as a plain mismatch, it makes an occurrence look uncaptured, and the
// collection is charged with a miss for something it did observe.
//
// It says nothing about which container the event was credited to. That is
// a separate question with a separate answer — it is the thing an
// attribution check is testing — and answering both here would make a
// wrongly attributed event look like a different process's work, which is
// exactly the failure such a check exists to find.
func (m *occurrenceMatcher) sameProcess(ev EventRecord, containerID string, pid, tid int, starttime ProcTicks) (matches, usable bool) {
	switch m.rule {
	case ruleGenerationAndThread:
		pm, ok := m.byThread[threadKey{containerID, pid, tid, starttime.String()}]
		if !ok {
			return false, false
		}
		if ev.Starttime == "" || ev.TID == 0 {
			// The event carries no generation, or no thread. Neither can be
			// compared, and the same process number an hour later would
			// otherwise pass.
			return false, false
		}
		if ev.PID != pm.HostPID || ev.TID != pm.HostTID {
			return false, true
		}
		return ev.Starttime == starttime.String(), true
	case ruleNamespacePIDAndTID:
		if ev.NSPID == 0 || ev.NSTID == 0 || ev.Starttime == "" {
			// The event carries no namespace-scoped numbers, or no
			// generation. A namespace number is only unique within its own
			// container, so without one there is nothing to compare
			// against at all — this is not evidence that a different
			// process did the work.
			return false, false
		}
		if ev.ContainerID != containerID || ev.NSPID != pid || ev.NSTID != tid {
			// A namespace-scoped number that matches in some other
			// container is not evidence of anything: each container hands
			// its own numbers out independently, so the same number
			// there names an unrelated process. Requiring the event's own
			// container to be the one under test is what keeps such a
			// coincidence from being read as a match.
			return false, true
		}
		return ev.Starttime == starttime.String(), true
	default:
		return false, false
	}
}

// sameHostProcess is the same question for work done outside any
// container, where there are no two number spaces to translate between:
// the occurrence's own numbers, read from the host's own /proc, are host
// numbers. But the event's PID/TID are the initial namespace's numbers,
// and on a host that is itself running inside a child PID namespace — a
// WSL2 distribution, for instance — the initial namespace is not the
// host's own: it is the event's NSPID/NSTID, a task's numbers in its own
// namespace, that read the same as what the host's /proc reports for a
// host task. They are what this compares against the occurrence's
// numbers, not PID/TID.
//
// A number by itself is not an identity, though: NSPID/NSTID are only
// unique inside the namespace they were read in, and a task in some
// unrelated namespace can carry the very same pair, and even the same
// Starttime. PIDNamespace is what tells the two apart, so a comparison
// requires it from both sides and requires them to agree before it ever
// looks at NSPID/NSTID/Starttime — comparing the numbers alone, without
// first establishing they were read in the same namespace, would call a
// coincidence a match. An occurrence or an event missing any of what it
// takes to place this cannot be placed, and says so rather than matching
// on the path and the time alone.
func sameHostProcess(ev EventRecord, occ Occurrence) (matches, usable bool) {
	if occ.PID == 0 || occ.TID == 0 || occ.Starttime.empty() || occ.PIDNamespace == 0 {
		return false, false
	}
	if ev.Starttime == "" || ev.NSPID == 0 || ev.NSTID == 0 || ev.PIDNamespace == 0 {
		return false, false
	}
	if ev.PIDNamespace != occ.PIDNamespace {
		return false, true
	}
	if ev.NSPID != occ.PID || ev.NSTID != occ.TID {
		return false, true
	}
	return ev.Starttime == occ.Starttime.String(), true
}

// identify answers both questions at once, for the capture rates, where
// the events have already been restricted to the container under
// measurement.
func (m *occurrenceMatcher) identify(ev EventRecord, containerID string, pid, tid int, starttime ProcTicks) (matches, usable bool) {
	if ev.ContainerID != "" && containerID != "" && ev.ContainerID != containerID {
		return false, true
	}
	return m.sameProcess(ev, containerID, pid, tid, starttime)
}

// computeOccurrenceMetrics computes the per-occurrence capture rates.
func computeOccurrenceMetrics(gtb *GroundTruthB, events *EventLog, containerID string, windowStart, windowEnd time.Time, toleranceMS int64) OccurrenceMetrics {
	out := OccurrenceMetrics{ToleranceMS: toleranceMS}
	out.Exec.Rate, out.Load.Rate, out.RealOpen.Rate = -1, -1, -1
	out.RealOpen.NA = true
	if events == nil {
		out.Notes = append(out.Notes, "no event log was supplied, so nothing can be said about what the collection captured")
		return out
	}
	if gtb == nil || (len(gtb.Occurrences) == 0 && len(gtb.RealOpens) == 0) {
		// Without an independent record there is no denominator. The
		// events that cannot be checked are counted, and the rates stay
		// unavailable rather than being filled in from the observation
		// itself.
		for _, ev := range events.Events {
			if ev.OK && ev.ContainerID == containerID && inWindow(ev.Timestamp, windowStart, windowEnd) {
				out.Uncaptured.ReasonUnknown++
			}
		}
		out.Notes = append(out.Notes, "no independent occurrence log exists for this run, so an event that matches nothing cannot be told from an occurrence that never happened")
		return out
	}

	out.Available = true
	out.ClockBasis = gtb.ClockBase
	tolerance := time.Duration(toleranceMS) * time.Millisecond
	// The tolerance has to be wider than the clock conversion's own error,
	// or a real pair is called a miss for a reason that has nothing to do
	// with the collection.
	if events.Header.ClockErrorNS > 0 && events.Header.ClockErrorNS >= tolerance.Nanoseconds() {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"the pairing tolerance (%dms) is no wider than the clock conversion's own error (%dns), so a pair could be called a miss for a reason unrelated to the collection",
			toleranceMS, events.Header.ClockErrorNS))
	}

	// Both sides are restricted to the same container and the same window.
	// An event outside either is not evidence about this measurement, and
	// an occurrence outside either is not something this measurement asked
	// to see.
	var ours []EventRecord
	for _, ev := range events.Events {
		if ev.OK && ev.ContainerID == containerID && inWindow(ev.Timestamp, windowStart, windowEnd) {
			ours = append(ours, ev)
		}
	}
	m := newOccurrenceMatcher(gtb.PIDMap, tolerance, containerID)
	out.MatchRule = m.ruleName()

	// Point occurrences, paired one to one.
	claimedBy := map[int][]string{} // event index -> occurrence ids
	candidates := map[string][]int{}
	// An occurrence whose process could not be identified against the
	// event side at all. It is not a capture and not a miss of the
	// collection: nothing here could have told the two apart.
	undecidable := map[string]bool{}
	// An occurrence for which an event arrived at the right path and time
	// but carried too little to be placed against it.
	unplaceable := map[string]bool{}
	var execIDs []string
	for _, occ := range gtb.Occurrences {
		if occ.Kind != occurrenceExec || !occurrenceBelongsTo(occ, containerID) {
			continue
		}
		switch {
		case !occ.OK:
			out.Excluded.Failed++
			continue
		case !inWindow(occ.Timestamp, windowStart, windowEnd):
			out.Excluded.OutsideWindow++
			out.Uncaptured.OutsideWindow++
			continue
		}
		out.Exec.Eligible++
		execIDs = append(execIDs, occ.ID)
		if !m.decidable(containerID, occ.PID, occ.TID, occ.Starttime) {
			// Nothing here can tell this occurrence's process and thread
			// from any other's, so a search over candidates would have
			// nothing to decide. It is settled before the search rather
			// than after it.
			undecidable[occ.ID] = true
			continue
		}
		for i, ev := range ours {
			if ev.Event != occurrenceExec {
				continue // an execution is answered by an execution, not by an open
			}
			if ev.Path != occ.Path {
				continue
			}
			if absDuration(ev.Timestamp.Sub(occ.Timestamp)) > tolerance {
				continue
			}
			matches, usable := m.identify(ev, containerID, occ.PID, occ.TID, occ.Starttime)
			if !usable {
				// An event at the right path and the right moment that
				// cannot be placed. Charging the collection with a miss
				// here would blame it for something it did observe.
				unplaceable[occ.ID] = true
				continue
			}
			if !matches {
				continue
			}
			candidates[occ.ID] = append(candidates[occ.ID], i)
			claimedBy[i] = append(claimedBy[i], occ.ID)
		}
	}
	sort.Strings(execIDs)
	for _, id := range execIDs {
		evs := candidates[id]
		switch {
		case undecidable[id]:
			out.Exec.Undecidable++
		case len(evs) == 0 && unplaceable[id]:
			out.Exec.Undecidable++
		case len(evs) == 0:
			out.Uncaptured.InWindowMissed++
		case len(evs) > 1:
			out.Exec.Unmatchable++
			out.Exec.OneToMany++
		case len(claimedBy[evs[0]]) > 1:
			out.Exec.Unmatchable++
			out.Exec.ManyToOne++
		default:
			out.Exec.OneToOne++
		}
	}
	// The rate is over what could be decided. An occurrence nothing could
	// identify is not a miss of the collection, and leaving it in the
	// denominator would report a window where nothing was decidable as a
	// capture rate of zero — a statement about the collection that the
	// measurement never established.
	out.Exec.Decidable = out.Exec.Eligible - out.Exec.Undecidable
	out.Exec.Rate = rateOrNA(out.Exec.OneToOne, out.Exec.Decidable)

	// Interval occurrences, matched against a set of events. An event that
	// could belong to more than one interval is used for none of them.
	loadCandidates := map[string][]int{}
	loadClaimed := map[int][]string{}
	loadUndecidable := map[string]bool{}
	loadUnplaceable := map[string]bool{}
	var loadIDs []string
	for _, occ := range gtb.Occurrences {
		if occ.Kind != occurrenceLoad || !occurrenceBelongsTo(occ, containerID) {
			continue
		}
		switch {
		case !occ.OK:
			out.Excluded.Failed++
			continue
		case occ.CacheHit:
			out.Excluded.CacheHit++
			continue
		case !intersectsWindow(occ.Start, occurrenceEnd(occ), windowStart, windowEnd):
			out.Excluded.OutsideWindow++
			out.Uncaptured.OutsideWindow++
			continue
		}
		out.Load.Eligible++
		loadIDs = append(loadIDs, occ.ID)
		if !m.decidable(containerID, occ.PID, occ.TID, occ.Starttime) {
			loadUndecidable[occ.ID] = true
			continue
		}
		files := map[string]bool{}
		for _, f := range occ.Files {
			files[f] = true
		}
		lo, hi := occ.Start.Add(-tolerance), occurrenceEnd(occ).Add(tolerance)
		for i, ev := range ours {
			if ev.Event == occurrenceExec {
				continue
			}
			if !files[ev.Path] {
				continue
			}
			if ev.Timestamp.Before(lo) || ev.Timestamp.After(hi) {
				continue
			}
			matches, usable := m.identify(ev, containerID, occ.PID, occ.TID, occ.Starttime)
			if !usable {
				loadUnplaceable[occ.ID] = true
				continue
			}
			if !matches {
				continue
			}
			loadCandidates[occ.ID] = append(loadCandidates[occ.ID], i)
			loadClaimed[i] = append(loadClaimed[i], occ.ID)
		}
	}
	sort.Strings(loadIDs)
	conflicting := map[int]bool{}
	for i, ids := range loadClaimed {
		if len(ids) > 1 {
			conflicting[i] = true
			out.Load.AttributionConflicts++
		}
	}
	for _, id := range loadIDs {
		usable := 0
		for _, i := range loadCandidates[id] {
			if !conflicting[i] {
				usable++
			}
		}
		switch {
		case loadUndecidable[id]:
			out.Load.Undecidable++
		case usable > 0:
			out.Load.WithEvidence++
		case loadUnplaceable[id]:
			out.Load.Undecidable++
		default:
			out.Uncaptured.InWindowMissed++
		}
	}
	out.Load.Decidable = out.Load.Eligible - out.Load.Undecidable
	out.Load.Rate = rateOrNA(out.Load.WithEvidence, out.Load.Decidable)

	// System-call level, only where an independent record of the calls
	// themselves exists.
	if len(gtb.RealOpens) > 0 {
		out.RealOpen.NA = false
		// One event cannot stand for two system calls, so each is claimed
		// at most once: reusing it would report more captured than
		// happened.
		usedEvent := map[int]bool{}
		for _, ro := range gtb.RealOpens {
			if !ro.OK || !inWindow(ro.Timestamp, windowStart, windowEnd) {
				continue
			}
			if ro.ContainerID != "" && ro.ContainerID != containerID {
				continue
			}
			out.RealOpen.Occurrences++
			if !m.decidable(containerID, ro.PID, ro.TID, ro.Starttime) {
				out.RealOpen.Undecidable++
				continue
			}
			captured, unplaceable := false, false
			for i, ev := range ours {
				if usedEvent[i] || ev.Event == occurrenceExec || ev.Path != ro.Path {
					continue
				}
				if absDuration(ev.Timestamp.Sub(ro.Timestamp)) > tolerance {
					continue
				}
				matches, usable := m.identify(ev, containerID, ro.PID, ro.TID, ro.Starttime)
				if !usable {
					// An event at the right path and the right moment that
					// carries too little to be placed against this call.
					// It is not evidence that a different process made the
					// call, so it is held rather than skipped.
					unplaceable = true
					continue
				}
				if !matches {
					continue
				}
				usedEvent[i] = true
				captured = true
				break
			}
			switch {
			case captured:
				out.RealOpen.Decidable++
				out.RealOpen.Captured++
			case unplaceable:
				// Nothing was captured, and the only candidates could not
				// be placed. Counting this as a missed call would charge
				// the collection with something it did observe and could
				// not describe fully.
				out.RealOpen.Undecidable++
			default:
				out.RealOpen.Decidable++
			}
		}
		out.RealOpen.Rate = rateOrNA(out.RealOpen.Captured, out.RealOpen.Decidable)
	}
	return out
}

// occurrenceBelongsTo reports whether an occurrence is one this
// measurement asked to see. An occurrence the case attributes to another
// container is another container's, and counting it here would measure one
// collection against another workload.
func occurrenceBelongsTo(occ Occurrence, containerID string) bool {
	return occ.ContainerID == "" || occ.ContainerID == containerID
}

// occurrenceEnd is an interval occurrence's end, falling back to its start
// when the log recorded no end. A missing end is not treated as "still
// running to the end of the window": that would widen the search until
// something matched.
func occurrenceEnd(occ Occurrence) time.Time {
	if occ.End.IsZero() {
		return occ.Start
	}
	return occ.End
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// computeAttributionMetrics checks which container each event was credited
// to against which container the case says the work really happened in.
//
// Both directions are reported. A collection that threw every event away
// would show no wrong attributions at all, so the share of real
// occurrences that were attributed correctly is what says whether
// attribution works.
//
// The two sides are counted over the one set the independent log can speak
// about: successful events, inside the window, credited to a container the
// log covers. Unrelated activity is left out of the denominator — a busy
// container the case says nothing about would otherwise dilute the rate
// towards zero and make attribution look better the more else is running.
//
// Each event is counted once however many occurrences it answers to: an
// event that matched three logged runs is still one wrong attribution, and
// counting it three times could report a rate above one.
func computeAttributionMetrics(gtb *GroundTruthB, events *EventLog, containerID string, windowStart, windowEnd time.Time, toleranceMS int64) AttributionMetrics {
	out := AttributionMetrics{MisattributionRate: -1, CorrectAttributionRate: -1, HostCorrectRate: -1}
	if events == nil {
		return out
	}
	if gtb == nil || len(gtb.Occurrences) == 0 {
		for _, ev := range events.Events {
			if ev.OK && inWindow(ev.Timestamp, windowStart, windowEnd) && ev.ContainerID == "" {
				out.Unattributed++
			}
		}
		return out
	}

	// The containers the independent log speaks about. An event credited
	// to any other container is outside what this log can judge.
	evaluated := map[string]bool{containerID: true}
	for _, occ := range gtb.Occurrences {
		if occ.ContainerID != "" && occ.ContainerID != "host" {
			evaluated[occ.ContainerID] = true
		}
	}

	inScope := map[int]bool{}
	for i, ev := range events.Events {
		if !ev.OK || !inWindow(ev.Timestamp, windowStart, windowEnd) {
			continue
		}
		if ev.ContainerID == "" {
			out.Unattributed++
			continue
		}
		if !evaluated[ev.ContainerID] {
			continue
		}
		inScope[i] = true
		out.AttributedEvents++
	}

	tolerance := time.Duration(toleranceMS) * time.Millisecond
	m := newOccurrenceMatcher(gtb.PIDMap, tolerance, containerID)
	out.MatchRule = m.ruleName()
	// Only a recorded correspondence identifies a process independently of
	// which container an event was credited to; without one, confirming a
	// process's identity at all already requires the event's own
	// container to agree (see sameProcess), so a wrong-container
	// attribution can never be the decided outcome of the search below.
	out.CrossContainerEvaluable = out.MatchRule == ruleGenerationAndThread

	wrong := map[int]string{} // event index -> where the work really happened
	for _, occ := range gtb.Occurrences {
		if !occ.OK {
			out.Excluded.Failed++
			continue
		}
		// A cache hit read nothing, the same way OccurrenceMetrics treats
		// it: no event corresponds to it, so it belongs in neither the
		// capture denominator nor this one.
		if occ.CacheHit {
			out.Excluded.CacheHit++
			continue
		}
		owner := occ.ContainerID
		if owner == "" {
			owner = containerID
		}
		// A load covers a span. One that began before the window and was
		// still running inside it is work this window saw, and taking only
		// its start would drop it.
		if occ.Kind == occurrenceLoad {
			if !intersectsWindow(occ.Start, occurrenceEnd(occ), windowStart, windowEnd) {
				out.Excluded.OutsideWindow++
				continue
			}
		} else if !inWindow(occ.Timestamp, windowStart, windowEnd) {
			out.Excluded.OutsideWindow++
			continue
		}
		// Work done outside any container has no second number space to
		// translate through: the occurrence's own numbers are host
		// numbers. Work done inside one needs the recorded
		// correspondence.
		onHost := owner == "host"
		decidable := onHost ||
			m.decidable(owner, occ.PID, occ.TID, occ.Starttime)
		if onHost && (occ.PID == 0 || occ.TID == 0 || occ.Starttime.empty() || occ.PIDNamespace == 0) {
			// PIDNamespace is required on both sides of sameHostProcess
			// before it ever compares numbers (see its own doc comment).
			// Checking it here, rather than leaving it to come out as
			// unplaceable once a candidate event turns up, is what keeps
			// an occurrence with no candidate event at all from being
			// read as host_unobserved: without it, nothing here ever
			// confirmed this occurrence's identity was decidable in the
			// first place.
			decidable = false
		}
		if !decidable {
			out.Undecidable++
			continue
		}
		if onHost {
			out.HostOccurrences++
		} else {
			out.LoggedOccurrences++
		}
		matchedCorrect := false
		// hostUnattributedMatch and hostMisattributedMatch are the host's
		// own version of matchedCorrect, one per possible outcome. Both
		// can end up true for the same occurrence — one event left
		// unattributed, another wrongly credited to a container — and
		// hostMisattributedMatch outranks the other when that happens: an
		// occurrence with a caught misattribution is not also a correct
		// result (see the switch below).
		hostUnattributedMatch := false
		hostMisattributedMatch := false
		// Whether any candidate could be placed against this occurrence at
		// all — whichever container it turned out to be credited to, or
		// none. A wrong attribution is a decided outcome just as a right
		// one is, and the occurrence stays in its denominator either way.
		identified := false
		unplaceable := false
		if onHost {
			// A host occurrence is checked against every event, not only
			// those credited to an evaluated container. Its correct
			// outcome is an event left uncredited to any container, and
			// inScope (built above) excludes exactly those: restricting
			// the search to it would make a correctly-unattributed host
			// run invisible to this loop. For the same reason, a match
			// against a container this log does not evaluate still marks
			// the occurrence misattributed — the ground truth says this
			// was host work regardless of which container ended up
			// credited with it, evaluated or not.
			for i, ev := range events.Events {
				if !ev.OK || !inWindow(ev.Timestamp, windowStart, windowEnd) || !attributionEventMatches(occ, ev, tolerance) {
					continue
				}
				// Matching on the path and the moment alone would call a
				// container's own run a wrong attribution whenever the
				// host happened to run the same program at the same time,
				// which is precisely the situation this control sets up —
				// sameHostProcess is what tells the two apart.
				matches, usable := sameHostProcess(ev, occ)
				if !usable {
					unplaceable = true
					continue
				}
				if !matches {
					continue
				}
				identified = true
				if ev.ContainerID == "" {
					hostUnattributedMatch = true
					continue
				}
				// The work was the host's, and a container was credited
				// with it.
				hostMisattributedMatch = true
				// FromHost stays at event granularity and scoped to what
				// this log evaluates — the same scope AttributedEvents and
				// MisattributionRate use — so an event credited to a
				// container outside that scope adds to
				// HostMisattributedOccurrences above but not here.
				if inScope[i] {
					wrong[i] = "host"
				}
			}
		} else {
			for i, ev := range events.Events {
				if !inScope[i] || !attributionEventMatches(occ, ev, tolerance) {
					continue
				}
				// Whether this event is the same process's work is asked
				// first, and on its own. Which container it was credited
				// to is the separate question this check exists to
				// answer — folding the two together made an event
				// credited to the wrong container look like a different
				// process's work, and the wrong attribution it was could
				// never be counted.
				matches, usable := m.sameProcess(ev, owner, occ.PID, occ.TID, occ.Starttime)
				if !usable {
					unplaceable = true
					continue
				}
				if !matches {
					continue
				}
				identified = true
				if ev.ContainerID != owner {
					wrong[i] = "other_container"
				} else {
					matchedCorrect = true
				}
			}
		}
		switch {
		case onHost && hostMisattributedMatch:
			// A caught misattribution outranks an unattributed match found
			// alongside it: the three host outcomes are exclusive per
			// occurrence, and always sum to HostOccurrences.
			out.HostMisattributedOccurrences++
		case onHost && hostUnattributedMatch:
			out.HostLeftUnattributed++
		case onHost && unplaceable:
			// Nothing that could have answered for this occurrence carried
			// enough to be placed against it. Neither a right nor a wrong
			// outcome was established, so it is pulled back out of
			// HostOccurrences the same way an unplaceable container
			// occurrence is pulled out of LoggedOccurrences below.
			out.HostOccurrences--
			out.Undecidable++
		case onHost:
			// The occurrence's own identity was decidable, but no event —
			// neither one left unattributed nor one credited to a
			// container — could be found for it at all.
			out.HostUnobserved++
		case matchedCorrect:
			out.CorrectlyAttributed++
		case identified:
			// The occurrence was placed and found credited elsewhere. That
			// is a decided outcome — a wrong one — and it belongs in the
			// denominator, or a collection that got it wrong would score
			// the same as one that got it right.
		case unplaceable:
			// Nothing that could have answered for this occurrence carried
			// enough to be placed against it. Neither a right nor a wrong
			// attribution was established.
			out.LoggedOccurrences--
			out.Undecidable++
		}
	}
	for _, where := range wrong {
		out.Misattributed++
		if where == "host" {
			out.FromHost++
		} else {
			out.FromOtherContainer++
		}
	}

	out.MisattributionRate = rateOrNA(out.Misattributed, out.AttributedEvents)
	if !out.CrossContainerEvaluable {
		// FromHost is still a decided count — sameHostProcess does not go
		// through the container-scoped check — but FromOtherContainer
		// cannot be, and AttributedEvents counts every credited event
		// whichever container it names. A rate over that denominator would
		// silently treat every unconfirmable cross-container case as
		// correct, which is not established.
		out.MisattributionRate = -1
	}
	out.CorrectAttributionRate = rateOrNA(out.CorrectlyAttributed, out.LoggedOccurrences)
	out.HostCorrectRate = rateOrNA(out.HostLeftUnattributed, out.HostOccurrences)
	return out
}

// attributionEventMatches applies each occurrence kind's own rule.
//
// An execution is answered by an execution at a point in time; a load is
// answered by an open somewhere inside the span the load covered. Using
// one rule for both would compare a span against a point, which either
// misses every load that took longer than the tolerance or accepts opens
// that happened outside it.
func attributionEventMatches(occ Occurrence, ev EventRecord, tolerance time.Duration) bool {
	if !occurrencePathMatches(occ, ev.Path) {
		return false
	}
	switch occ.Kind {
	case occurrenceExec:
		if ev.Event != occurrenceExec {
			return false
		}
		return absDuration(ev.Timestamp.Sub(occ.Timestamp)) <= tolerance
	case occurrenceLoad:
		if ev.Event == occurrenceExec {
			return false
		}
		lo, hi := occ.Start.Add(-tolerance), occurrenceEnd(occ).Add(tolerance)
		return !ev.Timestamp.Before(lo) && !ev.Timestamp.After(hi)
	}
	return false
}

func occurrencePathMatches(occ Occurrence, path string) bool {
	if path == "" {
		return false
	}
	if occ.Path != "" && occ.Path == path {
		return true
	}
	for _, f := range occ.Files {
		if f == path {
			return true
		}
	}
	return false
}
