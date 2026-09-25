package evidence

import (
	"reflect"
	"testing"
)

func TestProjectGroup_AnyInUseWins(t *testing.T) {
	got := ProjectGroup([]Verdict{
		{Usage: UsageNotObserved},
		{Usage: UsageInUse, EvidenceKinds: []EvidenceKind{KindMappedLibrary}},
		{Usage: UsageUnavailable, Reason: ReasonAttributionAmbiguous},
	})
	if got.Usage != UsageInUse {
		t.Fatalf("got %+v, want in_use", got)
	}
	if !reflect.DeepEqual(got.EvidenceKinds, []EvidenceKind{KindMappedLibrary}) {
		t.Errorf("evidence kinds = %v, want [mapped_library]", got.EvidenceKinds)
	}
}

func TestProjectGroup_InUseMergesKindsAcrossInstances(t *testing.T) {
	// /app/api is running (mapped_library) and /app/tool was executed once
	// during the window (exec_event): both are the same package group's
	// Instances, and the group as a whole should show both kinds.
	got := ProjectGroup([]Verdict{
		{Usage: UsageInUse, EvidenceKinds: []EvidenceKind{KindMappedLibrary}},
		{Usage: UsageInUse, EvidenceKinds: []EvidenceKind{KindExecEvent}},
	})
	want := []EvidenceKind{KindExecEvent, KindMappedLibrary} // sorted
	if !reflect.DeepEqual(got.EvidenceKinds, want) {
		t.Errorf("evidence kinds = %v, want %v", got.EvidenceKinds, want)
	}
}

func TestProjectGroup_UnavailableWinsOverNotObserved(t *testing.T) {
	// A Target-less Instance (binary_path_unknown) mixed with an eligible,
	// unmatched Instance: an unavailable element anywhere in the group
	// withdraws "not observed" for the whole group.
	got := ProjectGroup([]Verdict{
		{Usage: UsageNotObserved},
		{Usage: UsageUnavailable, Reason: ReasonBinaryPathUnknown},
	})
	if got.Usage != UsageUnavailable || got.Reason != ReasonBinaryPathUnknown {
		t.Fatalf("got %+v, want unavailable/binary_path_unknown", got)
	}
}

// TestProjectGroup_UnavailableCoverageNormalizesEmptyToNone pins the exact
// scenario an empty Target produces: JudgeEmbeddedBinary's
// ReasonBinaryPathUnknown verdict never sets EventsCoverage (it's a
// short-circuit before any generation is even consulted), so it carries the
// zero value "" — a different Go string from the literal CoverageNone, even
// though the two mean the same thing. Combining that verdict with an
// eligible, not-observed verdict that does carry CoverageNone must produce
// the same EventsCoverage regardless of which one the caller lists first.
func TestProjectGroup_UnavailableCoverageNormalizesEmptyToNone(t *testing.T) {
	emptyCoverage := Verdict{Usage: UsageUnavailable, Reason: ReasonBinaryPathUnknown} // EventsCoverage == ""
	explicitNone := Verdict{Usage: UsageNotObserved, EventsCoverage: CoverageNone}

	forward := ProjectGroup([]Verdict{emptyCoverage, explicitNone})
	reversed := ProjectGroup([]Verdict{explicitNone, emptyCoverage})

	if !reflect.DeepEqual(forward, reversed) {
		t.Fatalf("order changed the result: forward=%+v reversed=%+v", forward, reversed)
	}
	if forward.EventsCoverage != CoverageNone {
		t.Errorf("events_coverage = %q, want %q (normalized, not the literal \"\")", forward.EventsCoverage, CoverageNone)
	}
}

func TestProjectGroup_AllNotObservedIsNotObserved(t *testing.T) {
	got := ProjectGroup([]Verdict{
		{Usage: UsageNotObserved, EventsCoverage: CoverageSinceStart},
		{Usage: UsageNotObserved, EventsCoverage: CoveragePartial},
	})
	if got.Usage != UsageNotObserved {
		t.Fatalf("got %+v, want not_observed", got)
	}
	if got.EventsCoverage != CoveragePartial {
		t.Errorf("events_coverage = %q, want the weaker (partial) of the two contributors", got.EventsCoverage)
	}
}

func TestProjectGroup_EmptyIsUnavailable(t *testing.T) {
	got := ProjectGroup(nil)
	if got.Usage != UsageUnavailable || got.Reason != ReasonContainerNotObserved {
		t.Fatalf("got %+v, want unavailable/container_not_observed", got)
	}
}

// TestProjectGroup_UnavailableReasonAndCoverageAreOrderIndependent pins that
// combining several unavailable verdicts picks a reason (and a coverage) by
// a fixed rule, never by which verdict the caller happened to list first.
func TestProjectGroup_UnavailableReasonAndCoverageAreOrderIndependent(t *testing.T) {
	forward := []Verdict{
		{Usage: UsageUnavailable, Reason: ReasonDBError, EventsCoverage: CoverageSinceStart},
		{Usage: UsageUnavailable, Reason: ReasonIncomplete, EventsCoverage: CoverageNone},
	}
	reversed := []Verdict{forward[1], forward[0]}

	gotForward := ProjectGroup(forward)
	gotReversed := ProjectGroup(reversed)

	if !reflect.DeepEqual(gotForward, gotReversed) {
		t.Fatalf("order changed the result: forward=%+v reversed=%+v", gotForward, gotReversed)
	}
	// ReasonIncomplete outranks ReasonDBError in reasonPriority (a discarded
	// observation is a more fundamental problem than a database read
	// failure), and CoverageNone is weaker than CoverageSinceStart.
	if gotForward.Reason != ReasonIncomplete {
		t.Errorf("reason = %q, want %q (fixed priority, not input order)", gotForward.Reason, ReasonIncomplete)
	}
	if gotForward.EventsCoverage != CoverageNone {
		t.Errorf("events_coverage = %q, want %q (the weaker of the two)", gotForward.EventsCoverage, CoverageNone)
	}
}

// TestProjectGroup_InUseKindMergeIsOrderIndependent pins the same guarantee
// for the in-use path: which verdict contributed which kind first must not
// change the merged, sorted result.
func TestProjectGroup_InUseKindMergeIsOrderIndependent(t *testing.T) {
	forward := []Verdict{
		{Usage: UsageInUse, EvidenceKinds: []EvidenceKind{KindMappedLibrary}},
		{Usage: UsageInUse, EvidenceKinds: []EvidenceKind{KindExecEvent}},
	}
	reversed := []Verdict{forward[1], forward[0]}

	gotForward := ProjectGroup(forward)
	gotReversed := ProjectGroup(reversed)
	want := []EvidenceKind{KindExecEvent, KindMappedLibrary}

	if !reflect.DeepEqual(gotForward.EvidenceKinds, want) || !reflect.DeepEqual(gotReversed.EvidenceKinds, want) {
		t.Fatalf("got forward=%v reversed=%v, want both %v", gotForward.EvidenceKinds, gotReversed.EvidenceKinds, want)
	}
}

// TestJudgeAndProject_AppApiAndAppToolExample covers a worked example: the
// same vendored Go module embedded in two separately built binaries,
// /app/api and /app/tool, in the same image. Only /app/api
// is actually running. The group as a whole must show in_use (from api),
// while each Instance's own verdict (what a webhook's instances[] would
// project per Target) still shows /app/tool as not observed.
func TestJudgeAndProject_AppApiAndAppToolExample(t *testing.T) {
	gen := Generation{
		State: StateObserving,
		Executables: []ExecutableEvidence{{
			// The Sensor's own vocabulary (exe) — JudgeEmbeddedBinary
			// converts it to binary_running for display.
			Path:  "/app/api",
			Kinds: map[EvidenceKind]KindObservation{KindExe: {Samples: 4}},
		}},
	}

	apiVerdict := JudgeEmbeddedBinary(gen, "app/api")
	toolVerdict := JudgeEmbeddedBinary(gen, "app/tool")

	if apiVerdict.Usage != UsageInUse {
		t.Fatalf("/app/api verdict = %+v, want in_use", apiVerdict)
	}
	if toolVerdict.Usage != UsageNotObserved {
		t.Fatalf("/app/tool verdict = %+v, want not_observed", toolVerdict)
	}

	group := ProjectGroup([]Verdict{apiVerdict, toolVerdict})
	if group.Usage != UsageInUse {
		t.Fatalf("group verdict = %+v, want in_use (api alone is enough)", group)
	}
}

func TestProjectUsages(t *testing.T) {
	cases := []struct {
		name  string
		usage []Usage
		want  Usage
	}{
		{"any in_use wins", []Usage{UsageNotObserved, UsageInUse, UsageUnavailable}, UsageInUse},
		{"unavailable beats not_observed", []Usage{UsageNotObserved, UsageUnavailable}, UsageUnavailable},
		{"all not_observed", []Usage{UsageNotObserved, UsageNotObserved}, UsageNotObserved},
		// The OS openssl / Rust crate openssl collision case: two distinct
		// PackageGroups folded into one diff element by the (image,
		// package) state key, one in use and one not.
		{"os and lang package name collision, one in use", []Usage{UsageInUse, UsageNotObserved}, UsageInUse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ProjectUsages(c.usage); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
