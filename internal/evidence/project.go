package evidence

// ProjectGroup combines every Verdict judged for one PackageGroup's Instances
// across every generation into the single usage the group displays: any
// in-use verdict wins outright; failing that, any unavailable verdict
// (including one for a missing Result.Target, ReasonBinaryPathUnknown) marks
// the whole group unavailable; only when every verdict actually reached
// not-observed does the group show not-observed. An empty input — nothing
// was judged at all, e.g. no evidence generation exists for this image — is
// unavailable with ReasonContainerNotObserved rather than a vacuous
// not-observed.
//
// The result never depends on the order verdicts is given in: evidence kinds
// are merged and sorted regardless of which in-use verdict contributed which
// kind first, the unavailable Reason shown when more than one verdict is
// unavailable is chosen by a fixed priority (reasonPriority) rather than by
// which one came first, and EventsCoverage — on both the unavailable and the
// not-observed result — is always the weakest coverage among every
// contributing verdict (worstCoverage), never just whichever verdict's own
// value happened to be picked.
func ProjectGroup(verdicts []Verdict) Verdict {
	if len(verdicts) == 0 {
		return Verdict{Usage: UsageUnavailable, Reason: ReasonContainerNotObserved}
	}

	var kinds []EvidenceKind
	seenKind := map[EvidenceKind]bool{}
	anyInUse := false
	for _, v := range verdicts {
		if v.Usage != UsageInUse {
			continue
		}
		anyInUse = true
		kinds = mergeKinds(kinds, seenKind, v.EvidenceKinds)
	}
	if anyInUse {
		return Verdict{Usage: UsageInUse, EvidenceKinds: kinds}
	}

	if reason, ok := strongestUnavailableReason(verdicts); ok {
		return Verdict{Usage: UsageUnavailable, Reason: reason, EventsCoverage: worstCoverage(verdicts)}
	}

	return Verdict{Usage: UsageNotObserved, EventsCoverage: worstCoverage(verdicts)}
}

// reasonPriority is a fixed, total ordering over UnavailableReason used only
// to pick one reason out of several unavailable verdicts deterministically.
// It carries no meaning beyond "which one wins the tie": sensor- and
// generation-level reasons (nothing here is trustworthy at all) outrank
// database-level reasons, which in turn outrank single-package attribution
// reasons (something about this one entity specifically couldn't be
// judged), reflecting how specific/actionable each reason is, from least to
// most.
var reasonPriority = []UnavailableReason{
	ReasonSensorNotReporting,
	ReasonSensorStale,
	ReasonEvidenceInvalid,
	ReasonIsolationFailed,
	ReasonPermissionDenied,
	ReasonGenerationUnverified,
	ReasonContainerNotObserved,
	ReasonTruncated,
	ReasonIncomplete,
	ReasonStalled,
	ReasonInitializing,
	ReasonParseFailed,
	ReasonDBAbsent,
	ReasonDBError,
	ReasonDBUnsupported,
	ReasonNoFileList,
	ReasonAttributionAmbiguous,
	ReasonFileReplaced,
	ReasonVersionMismatch,
	ReasonEcosystemUnmapped,
	ReasonBinaryPathUnknown,
}

// reasonRank looks up reason's position in reasonPriority. A reason not in
// the table (should not happen for a value this package itself produces)
// ranks after every known one, rather than panicking or silently winning
// ties it has no defined precedence for.
func reasonRank(reason UnavailableReason) int {
	for i, r := range reasonPriority {
		if r == reason {
			return i
		}
	}
	return len(reasonPriority)
}

// strongestUnavailableReason picks one UnavailableReason out of every
// UsageUnavailable verdict in verdicts, by reasonPriority rather than by
// input order, so the same set of verdicts always projects to the same
// reason regardless of how the caller ordered them.
func strongestUnavailableReason(verdicts []Verdict) (UnavailableReason, bool) {
	found := false
	var best UnavailableReason
	bestRank := 0
	for _, v := range verdicts {
		if v.Usage != UsageUnavailable {
			continue
		}
		rank := reasonRank(v.Reason)
		if !found || rank < bestRank {
			best = v.Reason
			bestRank = rank
			found = true
		}
	}
	return best, found
}

// worstCoverage picks the least-complete EventsCoverage among verdicts:
// CoverageNone beats CoveragePartial beats CoverageSinceStart, since a
// not-observed or unavailable verdict is only as trustworthy as its weakest
// contributor. An empty EventsCoverage (a verdict that never carried one,
// e.g. a short-circuited ReasonBinaryPathUnknown) is normalized to
// CoverageNone before comparison — not just ranked alongside it — so that
// which of the two equally-weak verdicts the caller happened to list first
// can never change the literal value this function returns: without the
// normalization, "" and CoverageNone rank equal but are different string
// values, and the first one encountered would win by default.
func worstCoverage(verdicts []Verdict) EventsCoverage {
	rank := map[EventsCoverage]int{
		CoverageNone:       0,
		CoveragePartial:    1,
		CoverageSinceStart: 2,
	}
	worst := CoverageSinceStart
	worstRank := rank[CoverageSinceStart]
	for _, v := range verdicts {
		c := v.EventsCoverage
		if c == "" {
			c = CoverageNone
		}
		if r, ok := rank[c]; ok && r < worstRank {
			worst = c
			worstRank = r
		}
	}
	return worst
}

// ProjectUsages combines several PackageGroups' Usage values into the single
// value a diff-mode element shows when it folds more than one group
// together (the same state key can merge an OS package and a language
// package that happen to share a name, or several versions of the same
// package). The precedence is the same as ProjectGroup's: any in_use
// wins, failing that any unavailable, otherwise not_observed. An empty input
// returns UsageNotObserved — callers are not expected to call this with no
// groups at all.
func ProjectUsages(usages []Usage) Usage {
	sawUnavailable := false
	for _, u := range usages {
		switch u {
		case UsageInUse:
			return UsageInUse
		case UsageUnavailable:
			sawUnavailable = true
		}
	}
	if sawUnavailable {
		return UsageUnavailable
	}
	return UsageNotObserved
}
