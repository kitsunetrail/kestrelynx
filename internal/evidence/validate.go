package evidence

import (
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"
)

// generationKey is the identity assigned to a container generation
// (container ID, init PID, init starttime): the tuple validateSnapshot
// checks for duplicates within one snapshot.
type generationKey struct {
	id        string
	pid       int
	starttime int64
}

// validateSnapshot applies every reader-side rule beyond "valid JSON".
// Schema/interval/runtime/id/duplicate-key checks, every future-timestamp
// check (including ones nested inside a kind observation or a process
// observation), and every count limit (generations, entities per
// generation, observations per entity) are outright ErrInvalid for the
// whole file: each of them means the file itself is malformed or
// fabricated, not that one record happens to hold a bad value. An
// identifier with no "drop and continue" home of its own — session_id is
// the one this format has today — is checked the same way, for the same
// reason: there is no single record it belongs to that could be dropped
// instead.
//
// Only the string-content checks on package/executable/parse-failure
// records (validString, applied by the filterFoo functions at the end) drop
// a single offending record and mark its generation Incomplete instead of
// failing the whole file — a corrupt version string on one package does not
// make every other package's evidence untrustworthy the way a forged count
// or a future timestamp does. This is also where an invalid UTF-8 byte
// inside one of those records surfaces: json.Unmarshal already replaced it
// with U+FFFD by the time validateSnapshot runs, and validString treats
// U+FFFD as invalid content on the record it's part of (see validString) —
// it never causes a whole-file failure.
//
// snap is mutated in place: the string-filtered slices replace the
// originals.
func validateSnapshot(snap *Snapshot, now time.Time) error {
	if snap.Schema != Schema {
		return fmt.Errorf("%w: unknown schema %d", ErrInvalid, snap.Schema)
	}
	if !validString(snap.Sensor.SessionID) {
		return fmt.Errorf("%w: sensor.session_id is malformed", ErrInvalid)
	}
	if snap.Sensor.IntervalSeconds < minIntervalSeconds || snap.Sensor.IntervalSeconds > maxIntervalSeconds {
		return fmt.Errorf("%w: interval_seconds %d out of [%d,%d]", ErrInvalid, snap.Sensor.IntervalSeconds, minIntervalSeconds, maxIntervalSeconds)
	}
	if isFuture(snap.Sensor.SessionStartedAt, now, maxFutureSkew) {
		return fmt.Errorf("%w: sensor.session_started_at is in the future", ErrInvalid)
	}
	if isFuture(snap.Sensor.HeartbeatAt, now, maxFutureSkew) {
		return fmt.Errorf("%w: sensor.heartbeat_at is in the future", ErrInvalid)
	}
	if snap.Sensor.Events.Status == EventsOK && isFuture(snap.Sensor.Events.AttachedAt, now, maxFutureSkew) {
		return fmt.Errorf("%w: sensor.events.attached_at is in the future", ErrInvalid)
	}
	// sensor.status, sensor.events.status and sensor.events.reason are
	// Sensor-wide, not per-record: like session_id above, none of them has a
	// single generation or package record it could be dropped from instead,
	// so an unrecognized value rejects the whole file rather than being
	// silently trusted or guessed at. A compromised or buggy Sensor could
	// otherwise smuggle an arbitrary string into these fields, which
	// notify's display layer would have no per-record way to quarantine.
	if !validSensorStatuses[snap.Sensor.Status] {
		return fmt.Errorf("%w: unknown sensor.status %q", ErrInvalid, snap.Sensor.Status)
	}
	if !validEventsStatuses[snap.Sensor.Events.Status] {
		return fmt.Errorf("%w: unknown sensor.events.status %q", ErrInvalid, snap.Sensor.Events.Status)
	}
	if !validEventsReasons[snap.Sensor.Events.Reason] {
		return fmt.Errorf("%w: unknown sensor.events.reason %q", ErrInvalid, snap.Sensor.Events.Reason)
	}
	if snap.Sensor.Events.Unclassified < 0 {
		return fmt.Errorf("%w: sensor.events.unclassified is negative", ErrInvalid)
	}
	if snap.Sensor.Events.KernelLost < 0 {
		return fmt.Errorf("%w: sensor.events.kernel_lost is negative", ErrInvalid)
	}
	if len(snap.Generations) > maxGenerations {
		return fmt.Errorf("%w: %d generations exceeds limit %d", ErrInvalid, len(snap.Generations), maxGenerations)
	}

	seen := make(map[generationKey]bool, len(snap.Generations))
	for i := range snap.Generations {
		gen := &snap.Generations[i]

		// Docker is the only runtime this format currently carries an ID
		// shape for. Requiring the literal value (rather than special-casing
		// just "docker" inside validContainerID's caller) means an empty or
		// unrecognized Runtime can never skip ID validation by falling
		// through as "not docker, so not checked".
		if gen.Container.Runtime != "docker" {
			return fmt.Errorf("%w: unsupported container runtime %q", ErrInvalid, gen.Container.Runtime)
		}
		if !validContainerID(gen.Container.ID) {
			return fmt.Errorf("%w: malformed container id %q", ErrInvalid, gen.Container.ID)
		}
		key := generationKey{id: gen.Container.ID, pid: gen.Init.PID, starttime: gen.Init.Starttime}
		if seen[key] {
			return fmt.Errorf("%w: duplicate generation key %+v", ErrInvalid, key)
		}
		seen[key] = true

		if isFuture(gen.StartedAt, now, maxFutureSkew) || isFuture(gen.LastVerifiedAt, now, maxFutureSkew) {
			return fmt.Errorf("%w: generation timestamp is in the future", ErrInvalid)
		}
		if gen.EndedAt != nil && isFuture(*gen.EndedAt, now, maxFutureSkew) {
			return fmt.Errorf("%w: generation.ended_at is in the future", ErrInvalid)
		}

		if len(gen.OSPackages)+len(gen.Unavailable)+len(gen.Executables) > maxEntitiesPerGeneration {
			return fmt.Errorf("%w: generation has more than %d entities", ErrInvalid, maxEntitiesPerGeneration)
		}

		for _, p := range gen.OSPackages {
			if err := validateKindsAndObservations(p.Kinds, p.Observations, now); err != nil {
				return err
			}
		}
		for _, e := range gen.Executables {
			if err := validateKindsAndObservations(e.Kinds, e.Observations, now); err != nil {
				return err
			}
		}
		if err := validateParseFailedTimes(gen.ParseFailed, now); err != nil {
			return err
		}

		gen.OSPackages, gen.Incomplete = filterOSPackageStrings(gen.OSPackages, gen.Incomplete)
		gen.Unavailable, gen.Incomplete = filterUnavailableStrings(gen.Unavailable, gen.Incomplete)
		gen.Executables, gen.Incomplete = filterExecutableStrings(gen.Executables, gen.Incomplete)
		gen.ParseFailed, gen.Incomplete = filterParseFailedStrings(gen.ParseFailed, gen.Incomplete)

		// events_coverage has a per-generation home but no "drop this record"
		// analogue (there is no list to remove a generation from mid-read), so
		// an unrecognized value is normalized to the most conservative member
		// (CoverageNone: "no claim of coverage") rather than rejecting the
		// whole file over one generation's cosmetic field, or letting a
		// fabricated string reach the webhook's events_coverage key verbatim.
		gen.EventsCoverage = normalizeEventsCoverage(gen.EventsCoverage)
	}
	return nil
}

// validSensorStatuses and validEventsStatuses are the closed sets
// snap.Sensor.Status and snap.Sensor.Events.Status must belong to. The zero
// value ("") is deliberately excluded from both: Session.buildSnapshot
// (internal/sensor) always sets both fields from a real classification
// before any snapshot is ever written, so a file whose sensor.status or
// sensor.events.status reads "" is either torn/malformed or written by
// something other than this Sensor — either way not one whose silence about
// its own state this reader should paper over. Rejecting "" here is a
// distinct case from RuntimeInfo's own zero value (analyze/runtime.go): that
// one represents "no snapshot was available to read at all"
// (Provider.Load itself failed), never a value this validator accepted.
var validSensorStatuses = map[SensorStatus]bool{
	SensorOK: true, SensorDegraded: true, SensorPermissionDenied: true,
	SensorIsolationFailed: true, SensorIsolationDegraded: true,
}

var validEventsStatuses = map[EventsStatus]bool{
	EventsOK: true, EventsUnavailable: true,
}

var validEventsReasons = map[EventsReason]bool{
	EventsReasonNone: true, EventsReasonKernelUnsupported: true, EventsReasonBTFMissing: true,
	EventsReasonPermission: true, EventsReasonAttachFailed: true, EventsReasonCgroupV1: true,
}

// validUnavailableReasons is every UnavailableReason a Sensor may legitimately
// write into an UnavailablePackage record on disk. Reasons analyze computes
// itself from a matched generation's own content (ReasonVersionMismatch,
// ReasonNoFileList, everything GenerationEligibleForNotObserved returns, and
// so on) are included too: the Sensor is free to report any of them as its
// own verdict for a package it already judged unavailable itself, and the
// reader has no way to tell those apart from the ones analyze would have
// derived independently.
var validUnavailableReasons = map[UnavailableReason]bool{
	ReasonSensorNotReporting: true, ReasonSensorStale: true, ReasonEvidenceInvalid: true,
	ReasonIsolationFailed: true, ReasonPermissionDenied: true, ReasonInitializing: true,
	ReasonStalled: true, ReasonParseFailed: true, ReasonTruncated: true, ReasonIncomplete: true,
	ReasonGenerationUnverified: true, ReasonContainerNotObserved: true, ReasonDBAbsent: true,
	ReasonDBError: true, ReasonDBUnsupported: true, ReasonNoFileList: true,
	ReasonAttributionAmbiguous: true, ReasonFileReplaced: true, ReasonVersionMismatch: true,
	ReasonEcosystemUnmapped: true, ReasonBinaryPathUnknown: true,
}

// validRecordedKinds is the closed set of EvidenceKind values a Sensor may
// persist in an OSPackageEvidence or ExecutableEvidence record's Kinds map.
// The four language-package display kinds (binary_running and friends) are
// never written to disk — package.go's langKinds derives them in memory from
// these same four when judging a language package — so they are not valid
// input here even though they are valid EvidenceKind values in general.
var validRecordedKinds = map[EvidenceKind]bool{
	KindExe: true, KindMappedLibrary: true, KindExecEvent: true, KindLibraryLoadEvent: true,
}

// validEventsCoverages is the closed set normalizeEventsCoverage folds
// anything else into CoverageNone.
var validEventsCoverages = map[EventsCoverage]bool{
	CoverageSinceStart: true, CoveragePartial: true, CoverageNone: true,
}

func normalizeEventsCoverage(c EventsCoverage) EventsCoverage {
	if validEventsCoverages[c] {
		return c
	}
	return CoverageNone
}

// filterKinds drops any Kinds map entry whose key is not one of
// validRecordedKinds, so a fabricated kind can never reach a Verdict's
// EvidenceKinds (and from there, a Slack or webhook rendering) as literal
// text. Returns the filtered map (nil, matching this format's omitempty
// contract, if everything was dropped) and whether anything was.
func filterKinds(kinds map[EvidenceKind]KindObservation) (map[EvidenceKind]KindObservation, bool) {
	dropped := false
	for k := range kinds {
		if !validRecordedKinds[k] {
			dropped = true
			break
		}
	}
	if !dropped {
		return kinds, false
	}
	out := make(map[EvidenceKind]KindObservation, len(kinds))
	for k, v := range kinds {
		if validRecordedKinds[k] {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil, true
	}
	return out, true
}

// isFuture reports whether t is more than skew ahead of now. A zero t (a
// field the writer left unset) is never future — it is simply not asserting
// anything about time.
func isFuture(t time.Time, now time.Time, skew time.Duration) bool {
	if t.IsZero() {
		return false
	}
	return t.After(now.Add(skew))
}

// validateKindsAndObservations applies the whole-file-failure checks that
// apply to any package or executable record's Kinds map and Observations
// list: every kind's timestamps must not be in the future, the observation
// count must not exceed the cap, and no observation's timestamp may be in
// the future either. It never drops anything itself — a violation here means
// the whole file is rejected (see validateSnapshot's doc comment).
func validateKindsAndObservations(kinds map[EvidenceKind]KindObservation, obs []ProcessObservation, now time.Time) error {
	for _, k := range kinds {
		if isFuture(k.FirstSeen, now, maxFutureSkew) || isFuture(k.LastSeen, now, maxFutureSkew) {
			return fmt.Errorf("%w: a kind observation timestamp is in the future", ErrInvalid)
		}
	}
	if len(obs) > maxObservationsPerEntity {
		return fmt.Errorf("%w: more than %d process observations on one record", ErrInvalid, maxObservationsPerEntity)
	}
	for _, o := range obs {
		if isFuture(o.LastSeen, now, maxFutureSkew) {
			return fmt.Errorf("%w: a process observation timestamp is in the future", ErrInvalid)
		}
	}
	return nil
}

// validateParseFailedTimes applies the same future-timestamp rule to every
// ParseFailure's FailedAt, and to RetryAfter under its own, wider allowance
// (maxRetryAfterSkew rather than maxFutureSkew): RetryAfter is a scheduled
// retry time, not an observation, and the backoff schedule legitimately
// pushes it up to 24h ahead. Either violation rejects the whole file.
func validateParseFailedTimes(list []ParseFailure, now time.Time) error {
	for _, p := range list {
		if isFuture(p.FailedAt, now, maxFutureSkew) {
			return fmt.Errorf("%w: parse_failed.failed_at is in the future", ErrInvalid)
		}
		if isFuture(p.RetryAfter, now, maxRetryAfterSkew) {
			return fmt.Errorf("%w: parse_failed.retry_after is out of range", ErrInvalid)
		}
	}
	return nil
}

// validString is the shared per-field check: bounded length, no control
// characters (unicode.IsControl, which covers the full Unicode Cc category —
// U+0085 NEL and the rest of the C1 controls, not just the ASCII ones below
// U+0020 and DEL), and no U+FFFD (the Unicode replacement character). It
// applies to every attacker-influenced string the evidence file carries —
// paths and versions most directly, but also names, capability strings and
// listener addresses, since all of them are untrusted regardless of which
// field they landed in.
//
// The U+FFFD check is what actually catches an invalid UTF-8 byte in the
// source file: json.Unmarshal already silently replaced any such byte with
// U+FFFD by the time this function ever sees the string (a plain
// utf8.ValidString check on the decoded string would always pass, since
// U+FFFD is itself valid UTF-8 — that gap is why this check exists,
// specifically, rather than relying on utf8.ValidString alone).
//
// A string that legitimately contains U+FFFD is rejected too, on purpose. The
// sensor writes this file with Go's JSON encoder, which also replaces invalid
// bytes in a procfs path with U+FFFD, so a U+FFFD in a path or version cannot
// be told apart from a lossy encoding and cannot be matched reliably against a
// scan result. Dropping the record and marking the generation incomplete keeps
// such a value from ever producing a "not observed" verdict.
func validString(s string) bool {
	if len(s) > maxStringBytes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// validContainerID checks the "64-hex" shape a Docker container ID must
// have.
func validContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// filterOSPackageStrings drops any record with an invalid name, version or
// observation string, marking incomplete instead of failing the whole file
// — a package's record having an untrustworthy string withdraws its own
// verdict, not every other package's. Count and timestamp violations were
// already rejected outright by validateSnapshot before this runs.
// filterOSPackageStrings drops a record whose Name/Version/Observations
// fail validString, or whose Kinds map — after filterKinds strips any
// unrecognized key — has no valid kind left at all. That second case matters
// on its own, not just as a string-content check: JudgeOSPackage returns
// in_use on a name/version match regardless of whether the matched record's
// Kinds is populated, so a record that named this exact package but carried
// no evidence a reader can trust at all must not survive filtering to still
// be that match — keeping it would manufacture an in_use verdict from
// nothing.
func filterOSPackageStrings(pkgs []OSPackageEvidence, incomplete bool) ([]OSPackageEvidence, bool) {
	out := pkgs[:0]
	for _, p := range pkgs {
		if !validString(p.Name) || !validString(p.Version) || !validObservationStrings(p.Observations) {
			incomplete = true
			continue
		}
		kinds, dropped := filterKinds(p.Kinds)
		if dropped {
			incomplete = true
		}
		if len(kinds) == 0 {
			incomplete = true
			continue
		}
		p.Kinds = kinds
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, incomplete
	}
	return out, incomplete
}

// filterUnavailableStrings drops a record whose Name/Version fails
// validString, or whose Reason is not one of validUnavailableReasons — the
// same per-record treatment: an untrustworthy value withdraws this one
// package's verdict, not every other one's, and it is what keeps a
// fabricated Reason (JudgeOSPackage returns it verbatim as a Verdict.Reason)
// from ever reaching a rendering as literal text.
func filterUnavailableStrings(list []UnavailablePackage, incomplete bool) ([]UnavailablePackage, bool) {
	out := list[:0]
	for _, u := range list {
		if !validString(u.Name) || !validString(u.Version) || !validUnavailableReasons[u.Reason] {
			incomplete = true
			continue
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, incomplete
	}
	return out, incomplete
}

// hasExecutionEvidence reports whether kinds contains at least one kind that
// is itself proof this executable path was actually run — exe (still
// resident in a running process) or exec_event (an execution the eBPF
// observer recorded) — as opposed to mapped_library/library_load_event,
// which only prove some other running process loaded the file as a shared
// library and never that this path itself executed. Unlike an OS package
// (where mapped_library alone remains valid evidence the package is in
// use), a language package's in-use judgement specifically means a binary
// embedding it, or its runtime, ran — so an executable record surviving
// with only load-kinds would manufacture that claim from evidence that
// never supported it.
func hasExecutionEvidence(kinds map[EvidenceKind]KindObservation) bool {
	_, exe := kinds[KindExe]
	_, exec := kinds[KindExecEvent]
	return exe || exec
}

// filterExecutableStrings is filterOSPackageStrings' counterpart for
// executables: the same "no valid kind survives filtering" case is dropped
// here too, since JudgeEmbeddedBinary/JudgeRuntimeLoaded return in_use on a
// path/name match alone, independent of whether Kinds carries anything —
// and, specific to executables, a record whose surviving kinds are only
// mapped_library/library_load_event is dropped as well (see
// hasExecutionEvidence); filterOSPackageStrings does not apply this second
// check, since mapped_library alone is valid evidence an OS package is in
// use.
func filterExecutableStrings(list []ExecutableEvidence, incomplete bool) ([]ExecutableEvidence, bool) {
	out := list[:0]
	for _, e := range list {
		if !validString(e.Path) || !validString(e.Dev) || !validObservationStrings(e.Observations) {
			incomplete = true
			continue
		}
		kinds, dropped := filterKinds(e.Kinds)
		if dropped {
			incomplete = true
		}
		if len(kinds) == 0 || !hasExecutionEvidence(kinds) {
			incomplete = true
			continue
		}
		e.Kinds = kinds
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, incomplete
	}
	return out, incomplete
}

func filterParseFailedStrings(list []ParseFailure, incomplete bool) ([]ParseFailure, bool) {
	out := list[:0]
	for _, p := range list {
		if !validString(p.Input) || !validString(p.Path) || !validString(p.Dev) {
			incomplete = true
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, incomplete
	}
	return out, incomplete
}

// validObservationStrings checks only the string fields of a process
// observation list; the count cap and the timestamp were already checked by
// validateKindsAndObservations as whole-file failures.
func validObservationStrings(obs []ProcessObservation) bool {
	for _, o := range obs {
		if !validString(o.Exe) || !validString(o.CapEff) {
			return false
		}
		for _, l := range o.Listeners {
			if !validString(l) {
				return false
			}
		}
	}
	return true
}
