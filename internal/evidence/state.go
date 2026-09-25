package evidence

import (
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// StalenessThreshold is how old a Sensor's heartbeat may be before the main
// body stops trusting it: interval_seconds times ten, or five minutes,
// whichever is larger.
func StalenessThreshold(intervalSeconds int) time.Duration {
	fromInterval := time.Duration(intervalSeconds) * 10 * time.Second
	const floor = 5 * time.Minute
	if fromInterval > floor {
		return fromInterval
	}
	return floor
}

// IsStale reports whether heartbeatAt is older than StalenessThreshold as of
// now. A zero heartbeatAt (no heartbeat ever recorded) is always stale.
func IsStale(heartbeatAt, now time.Time, intervalSeconds int) bool {
	if heartbeatAt.IsZero() {
		return true
	}
	return now.Sub(heartbeatAt) > StalenessThreshold(intervalSeconds)
}

// GenerationFresh reports whether gen's own LastVerifiedAt is recent enough
// to support a "not observed" conclusion, using the same threshold
// StalenessThreshold derives from intervalSeconds. It is a building block
// for a caller's own not-observed eligibility check, not something Judge*
// calls internally — see the Judge* functions' doc comments for the
// distinction between what every judgement requires (a matched generation)
// and what only a not-observed judgement requires in addition (this
// freshness check). An in_use verdict from a correctly matched generation
// stays valid regardless of what GenerationFresh would say about it now: it
// reports a fact that generation actually observed, not a claim about the
// present moment.
func GenerationFresh(gen Generation, now time.Time, intervalSeconds int) bool {
	return !IsStale(gen.LastVerifiedAt, now, intervalSeconds)
}

// GenerationEligibleForNotObserved reports whether a generation's own state
// rules out "not observed" entirely for a package of the given class. It
// does not decide "not observed" by itself — the caller still needs to have
// found no in_use or unavailable hit for the specific package/instance — it
// only says whether the generation as a whole can support that conclusion.
//
// Truncated and Incomplete block both classes: either one means some
// observation in this generation was discarded, and the discarded part
// could have been the missing evidence. Denied, stalled and ended block
// both classes too: each means this generation's process reads themselves
// did not succeed, which language-package judgement depends on exactly as
// much as OS-package judgement does. Initializing and parse_failed block
// only the OS class — the package database isn't usable yet, but the
// process-level executable list language judgement reads is unaffected by
// that: building the package database index does not hold up a language
// package's verdict. For the OS class specifically, package_db.status must
// be exactly DBStatusOK: an empty string, an unrecognized future value and
// DBStatusAbsent all mean the same thing here — there is no confirmation the
// database was actually read — so all three (and DBStatusError,
// DBStatusUnsupported) block "not observed", and only the literal "ok"
// value passes.
func GenerationEligibleForNotObserved(gen Generation, class inventory.PkgClass) (bool, UnavailableReason) {
	if gen.Truncated {
		return false, ReasonTruncated
	}
	if gen.Incomplete {
		return false, ReasonIncomplete
	}
	switch gen.State {
	case StateDenied:
		return false, ReasonPermissionDenied
	case StateStalled:
		return false, ReasonStalled
	case StateEnded:
		return false, ReasonContainerNotObserved
	case StateInitializing:
		if class == inventory.ClassOS {
			return false, ReasonInitializing
		}
	case StateParseFailed:
		if class == inventory.ClassOS {
			return false, ReasonParseFailed
		}
	case StateObserving:
		// no additional state-level restriction
	default:
		// An empty or unrecognized state is treated the same as
		// "initializing": there is nothing here yet to conclude anything
		// from, and treating an unknown value as the safe, non-claiming
		// state is preferable to guessing it means "observing".
		return false, ReasonInitializing
	}
	if class == inventory.ClassOS && gen.PackageDB.Status != DBStatusOK {
		switch gen.PackageDB.Status {
		case DBStatusError:
			return false, ReasonDBError
		case DBStatusUnsupported:
			return false, ReasonDBUnsupported
		default:
			// DBStatusAbsent, "", or any status value this reader doesn't
			// recognize yet: none of them is evidence the database was
			// actually read, so all default to the same reason absence
			// would.
			return false, ReasonDBAbsent
		}
	}
	return true, ""
}

// kindsOf returns a map's keys, sorted, so a Verdict's EvidenceKinds is
// deterministic regardless of Go's randomized map iteration order.
func kindsOf(kinds map[EvidenceKind]KindObservation) []EvidenceKind {
	if len(kinds) == 0 {
		return nil
	}
	out := make([]EvidenceKind, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// mergeKinds folds kinds into the accumulator set/slice pair in place,
// keeping the accumulator sorted and free of duplicates regardless of what
// order callers merge batches in — the same set of kinds always produces the
// same output slice no matter which executable contributed which kind
// first.
func mergeKinds(acc []EvidenceKind, seen map[EvidenceKind]bool, kinds []EvidenceKind) []EvidenceKind {
	for _, k := range kinds {
		if !seen[k] {
			seen[k] = true
			acc = append(acc, k)
		}
	}
	sort.Slice(acc, func(i, j int) bool { return acc[i] < acc[j] })
	return acc
}

// langKinds converts an executable's Sensor-recorded evidence kinds — exe
// and exec_event, the same vocabulary OS package sampling and events use —
// into the language-package display kinds: a running process's own
// executable (exe) becomes binary_running or runtime_running, a successful
// exec event (exec_event) becomes binary_executed or runtime_executed.
// embedded selects which pair applies. Any other kind recorded on an
// executable (mapped_library, library_load_event) describes a library
// being loaded into some *other* process, not this executable itself
// running, so it has no language-package equivalent and is dropped here.
func langKinds(kinds map[EvidenceKind]KindObservation, embedded bool) []EvidenceKind {
	var out []EvidenceKind
	if _, ok := kinds[KindExe]; ok {
		if embedded {
			out = append(out, KindBinaryRunning)
		} else {
			out = append(out, KindRuntimeRunning)
		}
	}
	if _, ok := kinds[KindExecEvent]; ok {
		if embedded {
			out = append(out, KindBinaryExecuted)
		} else {
			out = append(out, KindRuntimeExecuted)
		}
	}
	return out
}

// JudgeOSPackage returns one generation's verdict for one OS package,
// matched by exact name and version: only an exact match on both counts as
// in use. A record whose name matches but whose version doesn't is
// ReasonVersionMismatch — the generation has positively observed a
// different version of this exact package running, which is a stronger,
// more specific signal than "not observed" and must not be reported as
// such. Callers only call this for inventory.ClassOS refs; a language
// package is judged by JudgeEmbeddedBinary or JudgeRuntimeLoaded instead.
//
// Every judgement this package makes — in_use, unavailable and not_observed
// alike — assumes the caller has already confirmed gen is the generation
// that actually matches the container currently being scanned: the same
// container ID, and the init process's PID/starttime agreeing with what
// inspect reports for it now (StartedAt). A generation that fails that
// match is a different container's or a stale one's evidence and must not
// be judged as this container's at all, in_use included — an in_use
// verdict from the wrong generation is simply wrong, not merely stale.
//
// Heartbeat and LastVerifiedAt freshness (StalenessThreshold,
// GenerationFresh) are a separate, narrower precondition that only gates
// not_observed: a generation that matched correctly but whose evidence has
// since gone stale can no longer support concluding "we looked and didn't
// see it", but an in_use verdict it already reported stays valid regardless
// — it recorded something this generation actually observed, and a stale
// heartbeat afterward doesn't retroactively unobserve it. This function
// does not check either precondition itself; it only judges gen's own
// recorded content once the caller has established that gen is the right,
// matched generation.
func JudgeOSPackage(gen Generation, ref inventory.PackageRef) Verdict {
	nameMatchedOtherVersion := false
	for _, p := range gen.OSPackages {
		if p.Name != ref.Name {
			continue
		}
		if p.Version == ref.Version {
			return Verdict{Usage: UsageInUse, EvidenceKinds: kindsOf(p.Kinds)}
		}
		nameMatchedOtherVersion = true
	}
	if nameMatchedOtherVersion {
		return Verdict{Usage: UsageUnavailable, Reason: ReasonVersionMismatch, EventsCoverage: gen.EventsCoverage}
	}
	for _, u := range gen.Unavailable {
		if u.Name == ref.Name && u.Version == ref.Version {
			return Verdict{Usage: UsageUnavailable, Reason: u.Reason, EventsCoverage: gen.EventsCoverage}
		}
	}
	if ok, reason := GenerationEligibleForNotObserved(gen, inventory.ClassOS); !ok {
		return Verdict{Usage: UsageUnavailable, Reason: reason, EventsCoverage: gen.EventsCoverage}
	}
	for _, name := range gen.PackageDB.NoFileList {
		if name == ref.Name {
			return Verdict{Usage: UsageUnavailable, Reason: ReasonNoFileList, EventsCoverage: gen.EventsCoverage}
		}
	}
	return Verdict{Usage: UsageNotObserved, EventsCoverage: gen.EventsCoverage}
}

// JudgeEmbeddedBinary returns one generation's verdict for a language
// package embedded in a compiled binary (gobinary, rustbinary): in use when
// target (Trivy's Result.Target, normalized) matches one or more observed
// executables' paths (also normalized), unavailable with
// ReasonBinaryPathUnknown when target is empty, otherwise not-observed
// subject to the generation's own eligibility. When more than one observed
// executable matches — the same path recorded under more than one dev/inode
// generation, for instance — every match's evidence kinds are merged
// (mergeKinds), so the result never depends on which matching record
// happened to come first in gen.Executables.
//
// See JudgeOSPackage's doc comment for the generation-matching precondition
// every judgement assumes, and for how that differs from the narrower
// freshness precondition that only gates a not_observed verdict.
func JudgeEmbeddedBinary(gen Generation, target string) Verdict {
	if target == "" {
		return Verdict{Usage: UsageUnavailable, Reason: ReasonBinaryPathUnknown}
	}
	norm := normalizeContainerPath(target)

	var kinds []EvidenceKind
	seen := map[EvidenceKind]bool{}
	matched := false
	for _, exe := range gen.Executables {
		if normalizeContainerPath(exe.Path) != norm {
			continue
		}
		matched = true
		kinds = mergeKinds(kinds, seen, langKinds(exe.Kinds, true))
	}
	if matched {
		return Verdict{Usage: UsageInUse, EvidenceKinds: kinds}
	}

	if ok, reason := GenerationEligibleForNotObserved(gen, inventory.ClassLang); !ok {
		return Verdict{Usage: UsageUnavailable, Reason: reason, EventsCoverage: gen.EventsCoverage}
	}
	return Verdict{Usage: UsageNotObserved, EventsCoverage: gen.EventsCoverage}
}

// JudgeRuntimeLoaded returns one generation's verdict for a language
// package loaded by a runtime process (python-pkg, node-pkg, jar, ...): in
// use when the ecosystem is mapped (see EcosystemMapped) and one or more
// observed executables' resolved names match that ecosystem's runtime
// names, unavailable with ReasonEcosystemUnmapped when the ecosystem has no
// runtime-name entry, otherwise not-observed subject to the generation's
// own eligibility. When more than one observed executable matches — e.g.
// python3.11 seen running in one sample and python3.12 executed once during
// the window — every match's evidence kinds are merged (mergeKinds), so the
// result never depends on which matching executable happened to come first
// in gen.Executables.
//
// See JudgeOSPackage's doc comment for the generation-matching precondition
// every judgement assumes, and for how that differs from the narrower
// freshness precondition that only gates a not_observed verdict.
func JudgeRuntimeLoaded(gen Generation, eco inventory.Ecosystem) Verdict {
	if !EcosystemMapped(eco) {
		return Verdict{Usage: UsageUnavailable, Reason: ReasonEcosystemUnmapped}
	}

	var kinds []EvidenceKind
	seen := map[EvidenceKind]bool{}
	matched := false
	for _, exe := range gen.Executables {
		if !RuntimeNameMatches(eco, exe.Path) {
			continue
		}
		matched = true
		kinds = mergeKinds(kinds, seen, langKinds(exe.Kinds, false))
	}
	if matched {
		return Verdict{Usage: UsageInUse, EvidenceKinds: kinds}
	}

	if ok, reason := GenerationEligibleForNotObserved(gen, inventory.ClassLang); !ok {
		return Verdict{Usage: UsageUnavailable, Reason: reason, EventsCoverage: gen.EventsCoverage}
	}
	return Verdict{Usage: UsageNotObserved, EventsCoverage: gen.EventsCoverage}
}
