package evidence

import "testing"

// TestValidateSnapshot_UnknownSensorStatus, UnknownEventsStatus and
// UnknownEventsReason cover the Sensor-wide enum fields: none of them has a
// per-record home to drop instead, so an unrecognized value rejects the
// whole snapshot the same way a malformed session_id does.
func TestValidateSnapshot_UnknownSensorStatus(t *testing.T) {
	snap := baseSnapshot(testNow)
	snap.Sensor.Status = SensorStatus("<!channel>")
	if err := validateSnapshot(&snap, testNow); err == nil {
		t.Fatal("validateSnapshot with an unknown sensor.status: want an error")
	}
}

func TestValidateSnapshot_UnknownEventsStatus(t *testing.T) {
	snap := baseSnapshot(testNow)
	snap.Sensor.Events.Status = EventsStatus("bogus")
	if err := validateSnapshot(&snap, testNow); err == nil {
		t.Fatal("validateSnapshot with an unknown sensor.events.status: want an error")
	}
}

func TestValidateSnapshot_UnknownEventsReason(t *testing.T) {
	snap := baseSnapshot(testNow)
	snap.Sensor.Events.Reason = EventsReason("<@U123>")
	if err := validateSnapshot(&snap, testNow); err == nil {
		t.Fatal("validateSnapshot with an unknown sensor.events.reason: want an error")
	}
}

// TestFilterUnavailableStrings_UnknownReasonDropped confirms an
// UnavailablePackage record whose Reason is not one of validUnavailableReasons
// is dropped (and the generation marked incomplete) — the same per-record
// treatment as an invalid Name/Version — rather than reaching a Verdict.Reason
// (and from there a Slack line) as literal, unescaped text.
func TestFilterUnavailableStrings_UnknownReasonDropped(t *testing.T) {
	list := []UnavailablePackage{
		{Name: "libfoo", Version: "1.0", Reason: ReasonVersionMismatch},           // known, kept
		{Name: "libbar", Version: "2.0", Reason: UnavailableReason("<!channel>")}, // unknown, dropped
	}
	out, incomplete := filterUnavailableStrings(list, false)
	if !incomplete {
		t.Error("filterUnavailableStrings: want incomplete=true when a record is dropped")
	}
	if len(out) != 1 || out[0].Name != "libfoo" {
		t.Errorf("filterUnavailableStrings out = %+v, want only the libfoo record", out)
	}
}

// TestFilterKinds_UnknownKindDropped confirms a Kinds map entry keyed by an
// unrecognized EvidenceKind (including one of the language-package display
// kinds, which are never legitimately written to disk) is stripped, keeping
// the record's other, valid kinds.
func TestFilterKinds_UnknownKindDropped(t *testing.T) {
	kinds := map[EvidenceKind]KindObservation{
		KindExe:            {Samples: 1},
		KindBinaryRunning:  {Samples: 1}, // in-memory-only kind, never on disk
		EvidenceKind("hi"): {Samples: 1}, // outright fabricated
	}
	out, dropped := filterKinds(kinds)
	if !dropped {
		t.Fatal("filterKinds: want dropped=true")
	}
	if len(out) != 1 {
		t.Fatalf("filterKinds out = %+v, want only KindExe", out)
	}
	if _, ok := out[KindExe]; !ok {
		t.Errorf("filterKinds out = %+v, want KindExe kept", out)
	}
}

// TestFilterOSPackageStrings_NoValidKindDropsWholeRecord confirms that a
// package record whose Kinds map has no valid entry at all — either because
// it started empty, or because filterKinds stripped every key — is dropped
// entirely (not just marked incomplete): JudgeOSPackage returns in_use on a
// name/version match alone, so a record surviving with an empty Kinds map
// would manufacture an in_use verdict from a package this reader could not
// actually confirm any evidence for.
func TestFilterOSPackageStrings_NoValidKindDropsWholeRecord(t *testing.T) {
	cases := []struct {
		name  string
		kinds map[EvidenceKind]KindObservation
	}{
		{"no kinds at all", nil},
		{"only fabricated kinds", map[EvidenceKind]KindObservation{EvidenceKind("bogus"): {}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgs := []OSPackageEvidence{{Name: "openssl", Version: "3.0.7", Kinds: c.kinds}}
			out, incomplete := filterOSPackageStrings(pkgs, false)
			if len(out) != 0 {
				t.Errorf("filterOSPackageStrings out = %+v, want the record dropped", out)
			}
			if !incomplete {
				t.Error("filterOSPackageStrings: want incomplete=true when a record is dropped for having no valid kind")
			}
		})
	}
}

// TestFilterExecutableStrings_NoValidKindDropsWholeRecord is
// TestFilterOSPackageStrings_NoValidKindDropsWholeRecord's counterpart for
// executables (JudgeEmbeddedBinary/JudgeRuntimeLoaded have the same
// path/name-match-alone behavior).
func TestFilterExecutableStrings_NoValidKindDropsWholeRecord(t *testing.T) {
	list := []ExecutableEvidence{{Path: "/app/api", Kinds: nil}}
	out, incomplete := filterExecutableStrings(list, false)
	if len(out) != 0 {
		t.Errorf("filterExecutableStrings out = %+v, want the record dropped", out)
	}
	if !incomplete {
		t.Error("filterExecutableStrings: want incomplete=true when a record is dropped for having no valid kind")
	}
}

// TestFilterExecutableStrings_LoadOnlyKindsDropsWholeRecord confirms that an
// executable record surviving filterKinds with only load-derived kinds
// (mapped_library, library_load_event) — never exe or exec_event — is
// dropped entirely, the same as a record with no valid kind at all:
// JudgeEmbeddedBinary/JudgeRuntimeLoaded return in_use on a path/name match
// alone, so a record with only "some other process mapped this file as a
// library" would manufacture "this binary ran" from evidence that never
// supported it.
func TestFilterExecutableStrings_LoadOnlyKindsDropsWholeRecord(t *testing.T) {
	cases := []struct {
		name  string
		kinds map[EvidenceKind]KindObservation
	}{
		{"mapped_library alone", map[EvidenceKind]KindObservation{KindMappedLibrary: {}}},
		{"library_load_event alone", map[EvidenceKind]KindObservation{KindLibraryLoadEvent: {}}},
		{"both load kinds, no execution kind", map[EvidenceKind]KindObservation{
			KindMappedLibrary: {}, KindLibraryLoadEvent: {},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			list := []ExecutableEvidence{{Path: "/app/api", Kinds: c.kinds}}
			out, incomplete := filterExecutableStrings(list, false)
			if len(out) != 0 {
				t.Errorf("filterExecutableStrings out = %+v, want the record dropped", out)
			}
			if !incomplete {
				t.Error("filterExecutableStrings: want incomplete=true when a record is dropped for carrying only load evidence")
			}
		})
	}
}

// TestFilterExecutableStrings_ExecutionKindSurvives confirms a record is
// kept whenever at least one execution kind (exe or exec_event) survives,
// even alongside a load kind.
func TestFilterExecutableStrings_ExecutionKindSurvives(t *testing.T) {
	cases := []struct {
		name  string
		kinds map[EvidenceKind]KindObservation
	}{
		{"exe alone", map[EvidenceKind]KindObservation{KindExe: {}}},
		{"exec_event alone", map[EvidenceKind]KindObservation{KindExecEvent: {}}},
		{"exe plus mapped_library", map[EvidenceKind]KindObservation{KindExe: {}, KindMappedLibrary: {}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			list := []ExecutableEvidence{{Path: "/app/api", Kinds: c.kinds}}
			out, incomplete := filterExecutableStrings(list, false)
			if len(out) != 1 {
				t.Fatalf("filterExecutableStrings out = %+v, want the record kept", out)
			}
			if incomplete {
				t.Error("filterExecutableStrings: want incomplete=false, nothing was dropped")
			}
		})
	}
}

func TestFilterKinds_AllKnownUnchanged(t *testing.T) {
	kinds := map[EvidenceKind]KindObservation{KindExe: {Samples: 1}, KindMappedLibrary: {Samples: 2}}
	out, dropped := filterKinds(kinds)
	if dropped {
		t.Error("filterKinds: want dropped=false when every key is known")
	}
	if len(out) != 2 {
		t.Errorf("filterKinds out = %+v, want both kinds kept", out)
	}
}

// TestNormalizeEventsCoverage folds any value outside the three named
// constants to CoverageNone — the most conservative member — rather than
// letting a fabricated value reach the webhook's events_coverage key.
func TestNormalizeEventsCoverage(t *testing.T) {
	cases := []struct {
		in   EventsCoverage
		want EventsCoverage
	}{
		{CoverageSinceStart, CoverageSinceStart},
		{CoveragePartial, CoveragePartial},
		{CoverageNone, CoverageNone},
		{"", CoverageNone},
		{EventsCoverage("<!channel>"), CoverageNone},
	}
	for _, c := range cases {
		if got := normalizeEventsCoverage(c.in); got != c.want {
			t.Errorf("normalizeEventsCoverage(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestValidateSnapshot_UnknownEventsCoverageNormalized confirms the
// normalization actually runs as part of validateSnapshot (not just as a
// standalone function), on a generation that is otherwise entirely valid.
func TestValidateSnapshot_UnknownEventsCoverageNormalized(t *testing.T) {
	snap := baseSnapshot(testNow)
	snap.Generations = []Generation{{
		Container:      ContainerRef{Runtime: "docker", ID: hexID64('1')},
		Init:           InitProcess{PID: 1, Starttime: 1},
		State:          StateObserving,
		PackageDB:      PackageDBInfo{Status: DBStatusOK},
		LastVerifiedAt: testNow,
		EventsCoverage: EventsCoverage("garbage"),
	}}
	if err := validateSnapshot(&snap, testNow); err != nil {
		t.Fatalf("validateSnapshot: %v", err)
	}
	if snap.Generations[0].EventsCoverage != CoverageNone {
		t.Errorf("Generations[0].EventsCoverage = %q, want none (normalized)", snap.Generations[0].EventsCoverage)
	}
}
