package remediation

import (
	"context"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// javaSide describes how one scan of a comparison saw the Java runtime.
type javaSide struct {
	state scanner.JavaImageState
	// unchecked puts the Java runtime in RuntimeUnchecked.
	unchecked bool
	// rows are the Java package rows of the scan ("" for none).
	rowVersion string
}

func (j javaSide) apply(s *scanner.ImageScan) {
	s.JavaImage = j.state
	if j.unchecked {
		s.RuntimeUnchecked = []string{inventory.JavaRuntimePackage}
	}
	if j.rowVersion != "" {
		s.Packages = append(append([]scanner.ResultPackages(nil), s.Packages...), javaPkgs(j.rowVersion)...)
	}
}

var (
	javaStage1       = javaSide{rowVersion: "jdk-21.0.12+7"}
	javaStage1New    = javaSide{rowVersion: "jdk-21.0.13+9"}
	javaComplete     = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImageComplete, HasJDK: true}, rowVersion: "jdk-21.0.12+7"}
	javaCompleteNew  = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImageComplete, HasJDK: true}, rowVersion: "jdk-21.0.13+9"}
	javaNoJDK        = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImageComplete}}
	javaDeferred     = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImageDeferred}, unchecked: true}
	javaUnreadable   = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImagePermanent}, unchecked: true}
	javaExcluded     = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImageComplete, HasJDK: true, HasExcluded: true}, rowVersion: "jdk-21.0.13+9"}
	javaSuppressed   = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImageComplete, HasJDK: true, Suppressed: true}, rowVersion: "jdk-21.0.13+9"}
	javaEnvFallback  = javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImagePermanent, UsedEnvFallback: true}, rowVersion: "jdk-21.0.13+9"}
	javaAdvisoryHeld = javaSide{unchecked: true}
)

type javaCase struct {
	name     string
	baseline javaSide
	cand     javaSide
	// javaTarget: the baseline has a Java finding that is a target.
	javaTarget bool
	wantPR     bool
	// wantJava is the outcome expected for the Java target ("" when there is none).
	wantJava Outcome
}

func javaCases() []javaCase {
	return []javaCase{
		{"both stage 1: the finding went with the newer JDK", javaStage1, javaStage1New, true, true, OutcomeResolved},
		{"both stage 2, JDK replaced", javaComplete, javaCompleteNew, true, true, OutcomeResolved},
		{"JDK removed from the candidate", javaComplete, javaNoJDK, true, true, OutcomeResolved},
		{"candidate deferred", javaComplete, javaDeferred, true, false, OutcomeUnknown},
		{"candidate unreadable", javaComplete, javaUnreadable, true, false, OutcomeUnknown},
		{"candidate advisories missing", javaStage1, javaAdvisoryHeld, true, false, OutcomeUnknown},
		{"candidate has an excluded JDK", javaComplete, javaExcluded, true, false, OutcomeUnknown},
		{"candidate left a CVE out", javaComplete, javaSuppressed, true, false, OutcomeUnknown},
		{"candidate fell back to the environment, baseline read", javaComplete, javaEnvFallback, true, false, OutcomeUnknown},
		{"candidate fell back to the environment, baseline stage 1", javaStage1, javaEnvFallback, true, true, OutcomeResolved},
		{"both fell back to the environment", javaSide{state: scanner.JavaImageState{Kind: scanner.JavaImagePermanent, UsedEnvFallback: true}, rowVersion: "jdk-21.0.12+7"}, javaEnvFallback, true, true, OutcomeResolved},
		// With no Java target the other improvements are shown, but a side
		// that is held stops the proposal.
		{"no Java target, candidate deferred", javaNoJDK, javaDeferred, false, false, ""},
		{"no Java target, baseline deferred", javaDeferred, javaNoJDK, false, false, ""},
		{"no Java target, baseline unreadable", javaUnreadable, javaNoJDK, false, false, ""},
		{"no Java target, candidate analysed", javaNoJDK, javaNoJDK, false, true, ""},
	}
}

func javaImageFindings(c javaCase) []scanner.Finding {
	fs := []scanner.Finding{fixedA()}
	if c.javaTarget {
		fs = append(fs, javaFinding("CVE-J", "jdk-21.0.12+7"))
	}
	return fs
}

func javaOutcome(vr *VerificationResult) Outcome {
	for _, v := range vr.Verdicts {
		if v.VulnID == "CVE-J" {
			return v.Outcome
		}
	}
	return ""
}

// The image-update path: the comparison of the running image with a candidate
// tag reaches Decide with the Java analysis of both sides.
func TestJavaAnalysisImageUpdatePath(t *testing.T) {
	for _, c := range javaCases() {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv()
			e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.25.3", "1.25.4", "1.25.5", "1.26.0", "1.25.6-rc1"}, Pages: 2}
			e.reg.res["nginx:1.25.5"] = resolution('b', 'c')
			e.scn.scans["nginx:1.25.5"] = func(t scanner.ScanTarget) scanner.ImageScan {
				s := remoteScan(t, nil, pkgs("libc", "2"))
				c.cand.apply(&s)
				return s
			}
			in := input("nginx:1.25.3", 'a', prepared, javaImageFindings(c)...)
			c.baseline.apply(&in.Scan)
			plan := e.planner(t, bigLimits, registry.NewBudget(100)).Plan(context.Background(), []ImageInput{in})
			it := item(t, plan, 0)
			if (it.Category == CategoryPRCandidate) != c.wantPR {
				t.Fatalf("item = %s/%s (%s), want PR %v", it.Category, it.Reason, it.Detail, c.wantPR)
			}
			if it.Decision == nil || it.Decision.Propose != c.wantPR {
				t.Errorf("decision = %+v", it.Decision)
			}
			if !c.wantPR && it.Reason != ReasonAnalysisIncomplete {
				t.Errorf("reason = %s, want %s", it.Reason, ReasonAnalysisIncomplete)
			}
			if got := javaOutcome(it.Comparison); got != c.wantJava {
				t.Errorf("Java outcome = %q, want %q", got, c.wantJava)
			}
		})
	}
}

// The Dockerfile path: the comparison of the current base with the candidate
// base reaches Decide the same way.
func TestJavaAnalysisDockerfilePath(t *testing.T) {
	for _, c := range javaCases() {
		t.Run(c.name, func(t *testing.T) {
			e := newDFEnv()
			e.gh.put("ex/app", ".", "Dockerfile", appDockerfile)
			cur := withBaseEnv(baseResolution('1', '2', 'a', 'b'))
			cur.Env = []string{"JAVA_VERSION=jdk-21.0.12+7", javaHome}
			e.reg.res["python:3.12.3-slim"] = cur
			e.reg.res["python:3.12.5-slim"] = baseResolution('3', '4', 'x', 'y')
			e.scn.scans["python:3.12.3-slim"] = func(t scanner.ScanTarget) scanner.ImageScan {
				s := remoteScan(t, javaImageFindings(c), pkgs("libc", "1"))
				c.baseline.apply(&s)
				return s
			}
			e.scn.scans["python:3.12.5-slim"] = func(t scanner.ScanTarget) scanner.ImageScan {
				s := remoteScan(t, nil, pkgs("libc", "2"))
				c.cand.apply(&s)
				return s
			}
			fs := []scanner.Finding{layered(fixedA(), 'b')}
			if c.javaTarget {
				j := layered(javaFinding("CVE-J", "jdk-21.0.12+7"), 'a')
				j.RuntimeSource = scanner.RuntimeSourceRelease
				fs = append(fs, j)
			}
			in := dfInput("myapp:1", 'a', "app", appLayers, fs...)
			in.Scan.ConfigEnv = cur.Env
			plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in)
			it := onlyDockerfile(t, plan)
			if (it.Category == CategoryPRCandidate) != c.wantPR {
				t.Fatalf("item = %s/%s (%s), want PR %v", it.Category, it.Reason, it.Detail, c.wantPR)
			}
			ent := it.Entities[0]
			if ent.Decision == nil || ent.Decision.Propose != c.wantPR {
				t.Errorf("decision = %+v", ent.Decision)
			}
			if !c.wantPR && it.Reason != ReasonAnalysisIncomplete {
				t.Errorf("reason = %s, want %s", it.Reason, ReasonAnalysisIncomplete)
			}
			if got := javaOutcome(ent.Comparison); got != c.wantJava {
				t.Errorf("Java outcome = %q, want %q", got, c.wantJava)
			}
		})
	}
}

func TestJavaStateOf(t *testing.T) {
	cases := []struct {
		name string
		side javaSide
		want JavaState
	}{
		{"not attempted", javaSide{}, JavaStateNotAttempted},
		{"complete", javaComplete, JavaStateAnalysed},
		{"complete without a JDK", javaNoJDK, JavaStateAnalysed},
		{"excluded", javaExcluded, JavaStateExcluded},
		{"suppressed", javaSuppressed, JavaStateExcluded},
		{"deferred", javaDeferred, JavaStateHeld},
		{"unreadable", javaUnreadable, JavaStateHeld},
		{"advisories missing", javaAdvisoryHeld, JavaStateHeld},
		{"env fallback", javaEnvFallback, JavaStateEnvFallback},
	}
	for _, c := range cases {
		var s scanner.ImageScan
		c.side.apply(&s)
		if got := JavaStateOf(s); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// Another runtime being unchecked says nothing about Java.
	if got := JavaStateOf(scanner.ImageScan{RuntimeUnchecked: []string{inventory.NodeRuntimePackage}}); got != JavaStateNotAttempted {
		t.Errorf("node unchecked: %v", got)
	}
}

func TestDecideHoldsWhenJavaIsHeld(t *testing.T) {
	targets := []Target{{VulnID: "CVE-A", Package: PackageCoord{Class: inventory.ClassOS, Name: "libc"}}}
	vr := VerificationResult{Comparable: true, JavaHeld: true, Verdicts: []VulnVerdict{{VulnID: "CVE-A", Package: targets[0].Package, Outcome: OutcomeResolved}}}
	d := Decide(targets, vr, nil)
	if d.Propose || d.Kind != DecisionAnalysisIncomplete || d.Note != NoteJavaRuntimeHeld {
		t.Errorf("decision = %+v", d)
	}
	vr.JavaHeld = false
	if d := Decide(targets, vr, nil); !d.Propose {
		t.Errorf("without the hold: %+v", d)
	}
}

// Two JDKs with the same version and CVE are one verdict with an occurrence
// per JDK: no CVE is dropped or counted twice.
func TestCompareTwoJDKsOfOneVersion(t *testing.T) {
	two := func(id string) []scanner.Finding {
		a, b := javaFinding(id, "jdk-21.0.12+7"), javaFinding(id, "jdk-21.0.12+7")
		b.Target, b.PkgPath = "opt/other/bin/java", "opt/other/bin/java"
		return []scanner.Finding{a, b}
	}
	base := configScan("x:1", 'a', two("CVE-J"), pkgs("libc", "1"))
	javaComplete.apply(&base)
	cand := configScan("x:2", 'b', two("CVE-J")[:1], pkgs("libc", "1"))
	javaComplete.apply(&cand)
	vr := Compare(ScanRecord{Scan: base, Conditions: prepared}, ScanRecord{Scan: cand, Conditions: prepared})
	if !vr.Comparable {
		t.Fatalf("not comparable: %s %s", vr.Reason, vr.Detail)
	}
	if len(vr.Verdicts) != 1 || vr.Verdicts[0].Outcome != OutcomeRemaining || len(vr.Verdicts[0].Before) != 2 || len(vr.Verdicts[0].After) != 1 {
		t.Errorf("verdicts = %+v", vr.Verdicts)
	}
	targets := SelectTargets(base.Findings, nil)
	if len(targets) != 1 {
		t.Errorf("targets = %+v, want one for the shared CVE", targets)
	}
}

func TestMoveRuntimeFindingsIgnoresReleaseSourced(t *testing.T) {
	env := []string{"JAVA_VERSION=jdk-21.0.12+7", javaHome}
	fromEnv := javaFinding("CVE-ENV", "jdk-21.0.12+7")
	fromEnv.RuntimeSource = scanner.RuntimeSourceEnv
	fromRelease := javaFinding("CVE-REL", "jdk-21.0.12+7")
	fromRelease.RuntimeSource = scanner.RuntimeSourceRelease
	fromReleaseSame := javaFinding("CVE-SAME", "jdk-21.0.12+7")
	fromReleaseSame.RuntimeSource, fromReleaseSame.RuntimeSameAsEnv = scanner.RuntimeSourceRelease, true
	py := runtimeFinding("CVE-P", "3.12.3")

	cl := FindingsByLayer{Unknown: []scanner.Finding{fromEnv, fromRelease, fromReleaseSame, py}}
	moveRuntimeFindings(&cl, append(env, "PYTHON_VERSION=3.12.3"), append(env, "PYTHON_VERSION=3.12.3"))
	moved := map[string]bool{}
	for _, f := range cl.Base {
		moved[f.VulnID] = true
	}
	if !moved["CVE-ENV"] || !moved["CVE-P"] || moved["CVE-REL"] || moved["CVE-SAME"] {
		t.Errorf("moved = %v", moved)
	}
	if len(cl.Unknown) != 2 {
		t.Errorf("unknown = %+v", cl.Unknown)
	}

	// A release-sourced finding with a layer keeps the layer's verdict.
	rel := layered(fromRelease, 'a')
	got := ClassifyFindingsByLayer([]string{diffID('a'), diffID('b')}, 1, []scanner.Finding{rel, fromRelease})
	if len(got.Base) != 1 || got.Base[0].LayerDiffID != diffID('a') || len(got.Unknown) != 1 {
		t.Errorf("classified = %+v", got)
	}
}

// The floating-tag acceptance case: FROM eclipse-temurin:21-jre. The JDK read
// from the image's files is the one the environment names, so the rebuild
// outlook is kept; a second JDK of the same version is left out.
func TestRuntimeRebuildsWithReleaseSourcedFindings(t *testing.T) {
	adv := []scanner.RuntimeAdvisor{fakeJava{vulns: map[string][]string{
		"jdk-21.0.12+7": {"CVE-J1", "CVE-J2", "CVE-J3"},
		"jdk-21.0.13+9": {"CVE-J3", "CVE-J4"},
	}}}
	release := func(id string, same bool, target string) scanner.Finding {
		f := javaFinding(id, "jdk-21.0.12+7")
		f.RuntimeSource, f.RuntimeSameAsEnv = scanner.RuntimeSourceRelease, same
		if target != "" {
			f.Target, f.PkgPath = target, target
		}
		return f
	}
	older, newer := "JAVA_VERSION=jdk-21.0.12+7", "JAVA_VERSION=jdk-21.0.13+9"
	plan := func(fs ...scanner.Finding) DockerfileItem {
		in := dfInput("myapp:1", 'a', "app", appLayers, fs...)
		in.Scan.ConfigEnv = []string{older, javaHome}
		e := newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12-slim\nCOPY . /app\n")
		e.base("3.12-slim", withBaseEnv(baseResolution('1', '2', '9', 'b'), newer, javaHome), nil, pkgs("libc", "2"))
		return onlyDockerfile(t, e.planRuntimes(t, prepared, adv, in))
	}
	want := []RuntimeRebuild{{Package: javaRuntime, Installed: "jdk-21.0.12+7", BaseVersion: "jdk-21.0.13+9", Disappearing: []string{"CVE-J1", "CVE-J2"}, Remaining: []string{"CVE-J3"}, Targets: []string{javaBin}}}

	it := plan(release("CVE-J3", true, ""), release("CVE-J1", true, ""), release("CVE-J2", true, ""))
	if it.Reason != ReasonFloatingBaseUnconfirmed || !equalRebuilds(it.RebuildRuntimes, want) {
		t.Errorf("same as the environment: %s %+v", it.Reason, it.RebuildRuntimes)
	}

	// A second JDK with the same version and CVE is not merged into the first.
	it = plan(release("CVE-J3", true, ""), release("CVE-J1", true, ""), release("CVE-J2", true, ""),
		release("CVE-J3", false, "opt/other/bin/java"), release("CVE-J4", false, "opt/other/bin/java"))
	if !equalRebuilds(it.RebuildRuntimes, want) {
		t.Errorf("with a second JDK: %+v", it.RebuildRuntimes)
	}

	// Only a JDK that is not the environment's: nothing is recorded.
	it = plan(release("CVE-J1", false, "opt/other/bin/java"))
	if len(it.RebuildRuntimes) != 0 {
		t.Errorf("another JDK only: %+v", it.RebuildRuntimes)
	}
}

func equalRebuilds(a, b []RuntimeRebuild) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Package != y.Package || x.Installed != y.Installed || x.BaseVersion != y.BaseVersion ||
			len(x.Disappearing) != len(y.Disappearing) || len(x.Remaining) != len(y.Remaining) {
			return false
		}
		for j := range x.Disappearing {
			if x.Disappearing[j] != y.Disappearing[j] {
				return false
			}
		}
		for j := range x.Remaining {
			if x.Remaining[j] != y.Remaining[j] {
				return false
			}
		}
	}
	return true
}

// The rebuild check leaves a finding of another JDK undetermined even when
// the environment's JDK has the same version and CVE.
func TestClassifyRebuildSecondJDKIsUndetermined(t *testing.T) {
	same := javaFinding("CVE-J", "jdk-21.0.12+7")
	same.RuntimeSource, same.RuntimeSameAsEnv = scanner.RuntimeSourceRelease, true
	other := same
	other.RuntimeSameAsEnv = false
	other.Target = "opt/other/bin/java"
	rr := []RuntimeRebuild{{Package: javaRuntime, Installed: "jdk-21.0.12+7", Remaining: []string{"CVE-J"}, Targets: []string{javaBin}}}

	c := classifyRebuild(imageScan([]scanner.Finding{same}), imageScan(nil), rbSeverities, rr)
	if c.Status != RebuildChecked {
		t.Errorf("environment's JDK: %+v", c)
	}
	c = classifyRebuild(imageScan([]scanner.Finding{same, other}), imageScan(nil), rbSeverities, rr)
	if c.Status != RebuildPartial || c.Undetermined != 1 {
		t.Errorf("with a second JDK: %+v", c)
	}
}

func TestMergeRuntimeRebuildsUnionsTargets(t *testing.T) {
	ents := []DockerfileEntity{
		{RebuildRuntimes: []RuntimeRebuild{{Package: javaRuntime, Installed: "v", BaseVersion: "w", Disappearing: []string{"A"}, Targets: []string{"b/java"}}}},
		{RebuildRuntimes: []RuntimeRebuild{{Package: javaRuntime, Installed: "v", BaseVersion: "w", Disappearing: []string{"A"}, Targets: []string{"a/java", "b/java"}}}},
	}
	got := mergeRuntimeRebuilds(ents)
	if len(got) != 1 || len(got[0].Targets) != 2 || got[0].Targets[0] != "a/java" || got[0].Targets[1] != "b/java" {
		t.Errorf("merged = %+v", got)
	}
}

// The Java runtime of the running image itself is held while both bases were
// read and compared: the base's OS findings may be resolved by the candidate,
// but nothing is proposed for the unit.
func TestJavaHeldOfTheRunningImageStopsTheDockerfilePR(t *testing.T) {
	for _, tc := range []struct {
		name   string
		side   javaSide
		wantPR bool
	}{
		{"running image deferred", javaDeferred, false},
		{"running image unreadable", javaUnreadable, false},
		{"running image complete", javaComplete, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDFEnv()
			e.gh.put("ex/app", ".", "Dockerfile", appDockerfile)
			cur := withBaseEnv(baseResolution('1', '2', 'a', 'b'))
			e.reg.res["python:3.12.3-slim"] = cur
			e.reg.res["python:3.12.5-slim"] = baseResolution('3', '4', 'x', 'y')
			e.scn.scans["python:3.12.3-slim"] = func(t scanner.ScanTarget) scanner.ImageScan {
				return remoteScan(t, []scanner.Finding{fixedA()}, pkgs("libc", "1"))
			}
			e.scn.scans["python:3.12.5-slim"] = func(t scanner.ScanTarget) scanner.ImageScan {
				return remoteScan(t, nil, pkgs("libc", "2"))
			}
			in := dfInput("myapp:1", 'a', "app", appLayers, layered(fixedA(), 'b'))
			tc.side.apply(&in.Scan)
			plan := e.plan(t, bigLimits, []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}, nil, in)
			it := onlyDockerfile(t, plan)
			if (it.Category == CategoryPRCandidate) != tc.wantPR {
				t.Fatalf("item = %s/%s (%s), want PR %v", it.Category, it.Reason, it.Detail, tc.wantPR)
			}
			if !tc.wantPR {
				if d := it.Entities[0].Decision; d == nil || d.Note != NoteJavaRuntimeHeld || d.Propose {
					t.Errorf("decision = %+v", d)
				}
			}
		})
	}
}
