package evidence

import (
	"reflect"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestStalenessThreshold(t *testing.T) {
	cases := []struct {
		interval int
		want     time.Duration
	}{
		{interval: 30, want: 5 * time.Minute},   // 10*30s=5m, ties the floor
		{interval: 10, want: 5 * time.Minute},   // 10*10s=100s, floor wins
		{interval: 60, want: 10 * time.Minute},  // 10*60s=10m, beats the floor
		{interval: 300, want: 50 * time.Minute}, // 10*300s=50m
	}
	for _, c := range cases {
		if got := StalenessThreshold(c.interval); got != c.want {
			t.Errorf("StalenessThreshold(%d) = %v, want %v", c.interval, got, c.want)
		}
	}
}

func TestIsStale(t *testing.T) {
	now := testNow
	if IsStale(now.Add(-4*time.Minute), now, 30) {
		t.Error("4m-old heartbeat at 30s interval (5m threshold) should not be stale")
	}
	if !IsStale(now.Add(-6*time.Minute), now, 30) {
		t.Error("6m-old heartbeat at 30s interval (5m threshold) should be stale")
	}
	if !IsStale(time.Time{}, now, 30) {
		t.Error("a zero heartbeat should always be stale")
	}
}

func TestGenerationFresh(t *testing.T) {
	now := testNow
	fresh := Generation{LastVerifiedAt: now.Add(-4 * time.Minute)}
	stale := Generation{LastVerifiedAt: now.Add(-6 * time.Minute)}
	if !GenerationFresh(fresh, now, 30) {
		t.Error("4m-old last_verified_at at 30s interval should be fresh")
	}
	if GenerationFresh(stale, now, 30) {
		t.Error("6m-old last_verified_at at 30s interval should be stale")
	}
}

func TestGenerationEligibleForNotObserved(t *testing.T) {
	base := Generation{State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK}}

	cases := []struct {
		name    string
		gen     Generation
		class   inventory.PkgClass
		wantOK  bool
		wantWhy UnavailableReason
	}{
		{"observing/ok db, OS", base, inventory.ClassOS, true, ""},
		{"observing/ok db, lang", base, inventory.ClassLang, true, ""},
		{"truncated blocks both", withTruncated(base), inventory.ClassOS, false, ReasonTruncated},
		{"incomplete blocks both", withIncomplete(base), inventory.ClassLang, false, ReasonIncomplete},
		{"denied blocks both", withState(base, StateDenied), inventory.ClassLang, false, ReasonPermissionDenied},
		{"stalled blocks both", withState(base, StateStalled), inventory.ClassOS, false, ReasonStalled},
		{"ended blocks both", withState(base, StateEnded), inventory.ClassLang, false, ReasonContainerNotObserved},
		{"initializing blocks OS", withState(base, StateInitializing), inventory.ClassOS, false, ReasonInitializing},
		{"initializing does not block lang", withState(base, StateInitializing), inventory.ClassLang, true, ""},
		{"parse_failed blocks OS", withState(base, StateParseFailed), inventory.ClassOS, false, ReasonParseFailed},
		{"parse_failed does not block lang", withState(base, StateParseFailed), inventory.ClassLang, true, ""},
		{"db absent blocks OS only", withDB(base, DBStatusAbsent), inventory.ClassOS, false, ReasonDBAbsent},
		{"db absent does not block lang", withDB(base, DBStatusAbsent), inventory.ClassLang, true, ""},
		{"db error blocks OS only", withDB(base, DBStatusError), inventory.ClassOS, false, ReasonDBError},
		{"db unsupported blocks OS only", withDB(base, DBStatusUnsupported), inventory.ClassOS, false, ReasonDBUnsupported},
		{"empty db status blocks OS", withDB(base, ""), inventory.ClassOS, false, ReasonDBAbsent},
		{"empty db status does not block lang", withDB(base, ""), inventory.ClassLang, true, ""},
		{"unknown db status blocks OS", withDB(base, PackageDBStatus("future_value")), inventory.ClassOS, false, ReasonDBAbsent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, why := GenerationEligibleForNotObserved(c.gen, c.class)
			if ok != c.wantOK || why != c.wantWhy {
				t.Errorf("got (%v, %q), want (%v, %q)", ok, why, c.wantOK, c.wantWhy)
			}
		})
	}
}

func withTruncated(g Generation) Generation  { g.Truncated = true; return g }
func withIncomplete(g Generation) Generation { g.Incomplete = true; return g }
func withState(g Generation, s GenerationState) Generation {
	g.State = s
	return g
}
func withDB(g Generation, s PackageDBStatus) Generation {
	g.PackageDB.Status = s
	return g
}

func TestJudgeOSPackage(t *testing.T) {
	ref := inventory.PackageRef{Class: inventory.ClassOS, Name: "libssl3", Version: "3.0.15-1~deb12u1"}

	t.Run("in use: name and version match exactly", func(t *testing.T) {
		gen := Generation{
			State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
			OSPackages: []OSPackageEvidence{{
				Name: "libssl3", Version: "3.0.15-1~deb12u1",
				Kinds: map[EvidenceKind]KindObservation{KindMappedLibrary: {Samples: 1}},
			}},
		}
		v := JudgeOSPackage(gen, ref)
		if v.Usage != UsageInUse {
			t.Fatalf("got %+v, want in_use", v)
		}
		if len(v.EvidenceKinds) != 1 || v.EvidenceKinds[0] != KindMappedLibrary {
			t.Errorf("evidence kinds = %v, want [mapped_library]", v.EvidenceKinds)
		}
	})

	t.Run("version mismatch is unavailable, not not_observed", func(t *testing.T) {
		// The generation positively observed libssl3 running, just a
		// different version than the Finding names — a stronger signal than
		// "we never saw this package", and must not collapse into
		// not_observed.
		gen := Generation{
			State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
			OSPackages: []OSPackageEvidence{{Name: "libssl3", Version: "3.0.14-1"}},
		}
		v := JudgeOSPackage(gen, ref)
		if v.Usage != UsageUnavailable || v.Reason != ReasonVersionMismatch {
			t.Fatalf("got %+v, want unavailable/version_mismatch", v)
		}
	})

	t.Run("unavailable list hit", func(t *testing.T) {
		gen := Generation{
			State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK},
			Unavailable: []UnavailablePackage{{Name: "libssl3", Version: "3.0.15-1~deb12u1", Reason: ReasonAttributionAmbiguous}},
		}
		v := JudgeOSPackage(gen, ref)
		if v.Usage != UsageUnavailable || v.Reason != ReasonAttributionAmbiguous {
			t.Fatalf("got %+v, want unavailable/attribution_ambiguous", v)
		}
	})

	t.Run("no file list for this package", func(t *testing.T) {
		gen := Generation{
			State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK, NoFileList: []string{"libssl3"}},
		}
		v := JudgeOSPackage(gen, ref)
		if v.Usage != UsageUnavailable || v.Reason != ReasonNoFileList {
			t.Fatalf("got %+v, want unavailable/no_file_list", v)
		}
	})

	t.Run("eligible and no hit is not observed", func(t *testing.T) {
		gen := Generation{State: StateObserving, PackageDB: PackageDBInfo{Status: DBStatusOK}, EventsCoverage: CoverageSinceStart}
		v := JudgeOSPackage(gen, ref)
		if v.Usage != UsageNotObserved || v.EventsCoverage != CoverageSinceStart {
			t.Fatalf("got %+v, want not_observed/since_start", v)
		}
	})
}

func TestJudgeEmbeddedBinary(t *testing.T) {
	t.Run("empty target is binary_path_unknown", func(t *testing.T) {
		v := JudgeEmbeddedBinary(Generation{State: StateObserving}, "")
		if v.Usage != UsageUnavailable || v.Reason != ReasonBinaryPathUnknown {
			t.Fatalf("got %+v, want unavailable/binary_path_unknown", v)
		}
	})

	t.Run("target matches an observed executable", func(t *testing.T) {
		// The fixture uses the Sensor's own vocabulary (exec_event), the
		// same kind OS package events use — JudgeEmbeddedBinary is
		// responsible for converting it to the language display kind
		// (binary_executed), not just passing it through.
		gen := Generation{
			State: StateObserving,
			Executables: []ExecutableEvidence{{
				Path:  "/usr/local/bin/trivy",
				Kinds: map[EvidenceKind]KindObservation{KindExecEvent: {Count: 1}},
			}},
		}
		v := JudgeEmbeddedBinary(gen, "usr/local/bin/trivy")
		if v.Usage != UsageInUse {
			t.Fatalf("got %+v, want in_use", v)
		}
		if len(v.EvidenceKinds) != 1 || v.EvidenceKinds[0] != KindBinaryExecuted {
			t.Errorf("evidence kinds = %v, want [binary_executed] (exec_event converted for an embedded binary)", v.EvidenceKinds)
		}
	})

	t.Run("multiple matching executables merge kinds, order independent", func(t *testing.T) {
		// Same Target observed twice — e.g. recorded under two dev/inode
		// generations of the same path. Both must contribute their kind,
		// and the merged result must not depend on which one is listed
		// first.
		forward := Generation{
			State: StateObserving,
			Executables: []ExecutableEvidence{
				{Path: "/app/api", Kinds: map[EvidenceKind]KindObservation{KindExe: {Samples: 3}}},
				{Path: "/app/api", Dev: "8:2", Kinds: map[EvidenceKind]KindObservation{KindExecEvent: {Count: 1}}},
			},
		}
		reversed := Generation{
			State: StateObserving,
			Executables: []ExecutableEvidence{
				{Path: "/app/api", Dev: "8:2", Kinds: map[EvidenceKind]KindObservation{KindExecEvent: {Count: 1}}},
				{Path: "/app/api", Kinds: map[EvidenceKind]KindObservation{KindExe: {Samples: 3}}},
			},
		}
		want := []EvidenceKind{KindBinaryExecuted, KindBinaryRunning}

		vf := JudgeEmbeddedBinary(forward, "app/api")
		vr := JudgeEmbeddedBinary(reversed, "app/api")
		if vf.Usage != UsageInUse || !reflect.DeepEqual(vf.EvidenceKinds, want) {
			t.Fatalf("forward order: got %+v, want in_use/%v", vf, want)
		}
		if vr.Usage != UsageInUse || !reflect.DeepEqual(vr.EvidenceKinds, want) {
			t.Fatalf("reversed order: got %+v, want in_use/%v", vr, want)
		}
	})

	t.Run("no match falls through to eligibility", func(t *testing.T) {
		v := JudgeEmbeddedBinary(Generation{State: StateDenied}, "usr/local/bin/trivy")
		if v.Usage != UsageUnavailable || v.Reason != ReasonPermissionDenied {
			t.Fatalf("got %+v, want unavailable/permission_denied", v)
		}
	})

	t.Run("no match and eligible is not observed", func(t *testing.T) {
		v := JudgeEmbeddedBinary(Generation{State: StateObserving}, "usr/local/bin/trivy")
		if v.Usage != UsageNotObserved {
			t.Fatalf("got %+v, want not_observed", v)
		}
	})
}

func TestJudgeRuntimeLoaded(t *testing.T) {
	t.Run("unmapped ecosystem", func(t *testing.T) {
		v := JudgeRuntimeLoaded(Generation{State: StateObserving}, inventory.EcosystemBundler)
		if v.Usage != UsageUnavailable || v.Reason != ReasonEcosystemUnmapped {
			t.Fatalf("got %+v, want unavailable/ecosystem_unmapped", v)
		}
	})

	t.Run("runtime process observed", func(t *testing.T) {
		// The fixture uses the Sensor's own vocabulary (exe), the same kind
		// OS package sampling uses — JudgeRuntimeLoaded converts it to the
		// language display kind (runtime_running). "node" as the exe name is
		// ASSUMED here only in the sense that this test picked it for
		// readability; RuntimeNameMatches's own table test documents which
		// names are and aren't confirmed against a real container.
		gen := Generation{
			State: StateObserving,
			Executables: []ExecutableEvidence{{
				Path:  "/usr/local/bin/node",
				Kinds: map[EvidenceKind]KindObservation{KindExe: {Samples: 5}},
			}},
		}
		v := JudgeRuntimeLoaded(gen, inventory.EcosystemNodePkg)
		if v.Usage != UsageInUse {
			t.Fatalf("got %+v, want in_use", v)
		}
		if len(v.EvidenceKinds) != 1 || v.EvidenceKinds[0] != KindRuntimeRunning {
			t.Errorf("evidence kinds = %v, want [runtime_running] (exe converted for a runtime-loaded ecosystem)", v.EvidenceKinds)
		}
	})

	t.Run("multiple matching executables merge kinds, order independent", func(t *testing.T) {
		// python3.11 seen running in a sample, python3.12 executed once
		// during the window: both count toward the same ecosystem, and the
		// merged result must not depend on which is listed first. The exact
		// versioned names are illustrative (ASSUMED, see
		// TestRuntimeNameMatches); what this test actually pins is the
		// order-independent merge.
		forward := Generation{
			State: StateObserving,
			Executables: []ExecutableEvidence{
				{Path: "/usr/bin/python3.11", Kinds: map[EvidenceKind]KindObservation{KindExe: {Samples: 2}}},
				{Path: "/opt/bin/python3.12", Kinds: map[EvidenceKind]KindObservation{KindExecEvent: {Count: 1}}},
			},
		}
		reversed := Generation{
			State: StateObserving,
			Executables: []ExecutableEvidence{
				{Path: "/opt/bin/python3.12", Kinds: map[EvidenceKind]KindObservation{KindExecEvent: {Count: 1}}},
				{Path: "/usr/bin/python3.11", Kinds: map[EvidenceKind]KindObservation{KindExe: {Samples: 2}}},
			},
		}
		want := []EvidenceKind{KindRuntimeExecuted, KindRuntimeRunning}

		vf := JudgeRuntimeLoaded(forward, inventory.EcosystemPythonPkg)
		vr := JudgeRuntimeLoaded(reversed, inventory.EcosystemPythonPkg)
		if vf.Usage != UsageInUse || !reflect.DeepEqual(vf.EvidenceKinds, want) {
			t.Fatalf("forward order: got %+v, want in_use/%v", vf, want)
		}
		if vr.Usage != UsageInUse || !reflect.DeepEqual(vr.EvidenceKinds, want) {
			t.Fatalf("reversed order: got %+v, want in_use/%v", vr, want)
		}
	})

	t.Run("no runtime process is not observed when eligible", func(t *testing.T) {
		v := JudgeRuntimeLoaded(Generation{State: StateObserving}, inventory.EcosystemNodePkg)
		if v.Usage != UsageNotObserved {
			t.Fatalf("got %+v, want not_observed", v)
		}
	})
}
