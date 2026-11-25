package analyze

import (
	"reflect"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func javaFinding(vuln, target string, alts []string, incomplete bool) scanner.Finding {
	return scanner.Finding{
		Image: "app:1", Class: scanner.ClassLang, Package: inventory.JavaRuntimePackage,
		InstalledVer: "21.0.13", FixedVer: "21.0.14", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh,
		VulnID: vuln, Type: "java-runtime", Target: target, PkgPath: target,
		RuntimeSource: scanner.RuntimeSourceRelease, AltTargets: alts, TargetsIncomplete: incomplete,
	}
}

func javaGroups(r Report) []PackageGroup {
	var out []PackageGroup
	for _, img := range r.Actionable {
		for _, g := range img.Packages {
			if g.Package == inventory.JavaRuntimePackage {
				out = append(out, g)
			}
		}
	}
	return out
}

func TestBuild_JavaRuntimeGroupsSplitByTarget(t *testing.T) {
	scans := []scanner.ImageScan{resolvedScan("app:1", contentA, nil,
		javaFinding("CVE-1", "opt/a/bin/java", nil, false),
		javaFinding("CVE-2", "opt/a/bin/java", nil, false),
		javaFinding("CVE-1", "opt/b/bin/java", nil, false),
	)}
	groups := javaGroups(Build(scans, nil, Triage{}, runtimeNow))
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	byTarget := map[string]int{}
	for _, g := range groups {
		if len(g.Instances) != 1 {
			t.Fatalf("instances = %+v", g.Instances)
		}
		byTarget[g.Instances[0].Target] = g.Total()
	}
	if byTarget["opt/a/bin/java"] != 2 || byTarget["opt/b/bin/java"] != 1 {
		t.Errorf("CVEs per target = %v", byTarget)
	}
	// The order does not depend on map iteration.
	for i := 0; i < 20; i++ {
		again := javaGroups(Build(scans, nil, Triage{}, runtimeNow))
		if again[0].Instances[0].Target != groups[0].Instances[0].Target {
			t.Fatal("group order changes between builds")
		}
	}
}

func TestBuild_OtherEcosystemsAreNotSplitByTarget(t *testing.T) {
	mk := func(target string) scanner.Finding {
		return scanner.Finding{Image: "app:1", Class: scanner.ClassLang, Package: "golang.org/x/net", InstalledVer: "v1",
			Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-1", Type: "gobinary", Target: target}
	}
	r := Build([]scanner.ImageScan{resolvedScan("app:1", contentA, nil, mk("app/api"), mk("app/tool"))}, nil, Triage{}, runtimeNow)
	if len(r.Actionable[0].Packages) != 1 || len(r.Actionable[0].Packages[0].Instances) != 2 {
		t.Errorf("packages = %+v", r.Actionable[0].Packages)
	}
}

func TestBuild_InstanceCarriesAlternativeTargets(t *testing.T) {
	scans := []scanner.ImageScan{resolvedScan("app:1", contentA, nil,
		javaFinding("CVE-1", "opt/a/bin/java", []string{"opt/a/jre/bin/java", "opt/a/x/java"}, true))}
	g := javaGroups(Build(scans, nil, Triage{}, runtimeNow))[0]
	in := g.Instances[0]
	if !reflect.DeepEqual(in.AltTargetList(), []string{"opt/a/jre/bin/java", "opt/a/x/java"}) || !in.TargetsIncomplete {
		t.Errorf("instance = %+v", in)
	}
	if (Instance{}).AltTargetList() != nil {
		t.Error("an instance without alternatives lists some")
	}
}

func TestBuild_RuntimeRetiredAndReasons(t *testing.T) {
	scans := []scanner.ImageScan{
		{Image: "b:1", RuntimeUnchecked: []string{"Java runtime"}, RuntimeUncheckedReason: map[string]string{"Java runtime": "deferred"}},
		{Image: "a:1", RuntimeUnchecked: []string{"Node.js", "Java runtime"}, RuntimeUncheckedReason: map[string]string{"Java runtime": "unreadable"}},
		{Image: "a:1", RuntimeUnchecked: []string{"Java runtime"}, RuntimeUncheckedReason: map[string]string{"Java runtime": "deferred"}}, // second entity
		{Image: "c:1", RuntimeRetired: []string{"Java runtime"}},
		{Image: "c:1", RuntimeRetired: []string{"Java runtime"}},
		{Image: "d:1", RuntimeRetired: []string{"Java runtime"}, Err: errString("scan failed")},
	}
	r := Build(scans, nil, Triage{}, fixedTime)
	wantRetired := []RuntimeUncheckedRef{{Image: "c:1", Package: "Java runtime"}}
	if !reflect.DeepEqual(r.RuntimeRetired, wantRetired) {
		t.Errorf("RuntimeRetired = %v, want %v", r.RuntimeRetired, wantRetired)
	}
	want := map[RuntimeUncheckedRef]string{
		{Image: "a:1", Package: "Java runtime"}: "unreadable",
		{Image: "a:1", Package: "Node.js"}:      "advisories",
		{Image: "b:1", Package: "Java runtime"}: "deferred",
	}
	if !reflect.DeepEqual(r.RuntimeUncheckedReason, want) {
		t.Errorf("RuntimeUncheckedReason = %v, want %v", r.RuntimeUncheckedReason, want)
	}
	if got := Build([]scanner.ImageScan{{Image: "c:1"}}, nil, Triage{}, fixedTime); got.RuntimeRetired != nil || got.RuntimeUncheckedReason != nil {
		t.Errorf("retired %v reasons %v, want nil", got.RuntimeRetired, got.RuntimeUncheckedReason)
	}
}

// javaRuntimeUsage builds the report for the findings, attaches the evidence
// of executables and returns the usage of each Java group by its target.
func javaRuntimeUsage(t *testing.T, observed []string, finds ...scanner.Finding) map[string]evidence.Usage {
	t.Helper()
	r := Build([]scanner.ImageScan{resolvedScan("app:1", contentA, nil, finds...)},
		[]inventory.Container{{ID: testContainerID, Name: "app-1", Image: inventory.RunningImage{Ref: "app:1", Config: configDigest(t, contentA)}}},
		Triage{}, runtimeNow)
	gen := baseGeneration()
	for _, p := range observed {
		gen.Executables = append(gen.Executables, evidence.ExecutableEvidence{Path: p, Kinds: map[evidence.EvidenceKind]evidence.KindObservation{
			evidence.KindExe: {FirstSeen: runtimeNow, LastSeen: runtimeNow, Samples: 1},
		}})
	}
	snap := evidence.Snapshot{Schema: evidence.Schema, Sensor: okSensor(), Generations: []evidence.Generation{gen}}
	insp := GenerationInspect{
		ByContainer: map[string]docker.InspectResult{testContainerID: matchedInspect(gen, r.Actionable[0].Subject)},
		BootTime:    runtimeBootTime,
	}
	AttachRuntime(&r, RuntimeInfo{Sensor: snap.Sensor}, snap, insp, runtimeNow)
	out := map[string]evidence.Usage{}
	for _, g := range javaGroups(r) {
		out[g.Instances[0].Target] = g.Runtime.Usage
	}
	return out
}

func TestAttachRuntime_JavaRuntimeJudgedPerJDK(t *testing.T) {
	a := "opt/a/bin/java"
	b := "opt/b/bin/java"
	got := javaRuntimeUsage(t, []string{"/" + a},
		javaFinding("CVE-1", a, nil, false), javaFinding("CVE-1", b, nil, false))
	if got[a] != evidence.UsageInUse || got[b] != evidence.UsageNotObserved {
		t.Errorf("usage = %v, want the running JDK in use and the other not observed", got)
	}
}

func TestAttachRuntime_JavaRuntimeAlternativeTarget(t *testing.T) {
	a := "opt/a/bin/java"
	alt := "opt/a/jre/bin/java"
	got := javaRuntimeUsage(t, []string{"/" + alt}, javaFinding("CVE-1", a, []string{alt}, false))
	if got[a] != evidence.UsageInUse {
		t.Errorf("usage = %v, want in_use through the alternative launcher", got)
	}
}

func TestAttachRuntime_JavaRuntimeIncompleteTargets(t *testing.T) {
	a := "opt/a/bin/java"
	got := javaRuntimeUsage(t, nil, javaFinding("CVE-1", a, nil, true))
	if got[a] != evidence.UsageUnavailable {
		t.Errorf("usage = %v, want unavailable when a launcher path is unknown", got)
	}
	got = javaRuntimeUsage(t, []string{"/" + a}, javaFinding("CVE-1", a, nil, true))
	if got[a] != evidence.UsageInUse {
		t.Errorf("usage = %v, want in_use when a known launcher runs", got)
	}
	got = javaRuntimeUsage(t, nil, javaFinding("CVE-1", "", nil, false))
	if got[""] != evidence.UsageUnavailable {
		t.Errorf("usage = %v, want unavailable for an unknown target", got)
	}
	got = javaRuntimeUsage(t, nil, javaFinding("CVE-1", a, nil, false))
	if got[a] != evidence.UsageNotObserved {
		t.Errorf("usage = %v, want not_observed when every path is known and none ran", got)
	}
}

// A launcher path may hold a newline; the observed full path still matches.
func TestAttachRuntime_JavaRuntimeAlternativeTargetWithANewline(t *testing.T) {
	a := "opt/a/bin/java"
	alt := "opt/a/jre\nx/bin/java"
	got := javaRuntimeUsage(t, []string{"/" + alt}, javaFinding("CVE-1", a, []string{"opt/a/other/java", alt}, false))
	if got[a] != evidence.UsageInUse {
		t.Errorf("usage = %v, want in_use through a launcher path with a newline", got)
	}
}
