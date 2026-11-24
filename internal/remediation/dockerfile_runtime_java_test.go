package remediation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// The Java runtime has a location variable besides its version one: the
// runtime of the running image is the base's only when both are the same.
// The image names below only decide how the base tag is classified; the
// runtime itself is read from the environment variables.

const (
	javaRuntime = "Java runtime"
	javaBin     = "opt/java/openjdk/bin/java"
	javaHome    = "JAVA_HOME=/opt/java/openjdk"
)

// fakeJava is a scanner.RuntimeAdvisor for the JDK: the vulnerabilities of a
// JAVA_VERSION value are listed in vulns, a value it has no entry for has none.
type fakeJava struct{ vulns map[string][]string }

func (f fakeJava) Augment(scan scanner.ImageScan, severities []string) scanner.RuntimeAugment {
	var ver string
	for _, e := range scan.ConfigEnv {
		if v, ok := strings.CutPrefix(e, "JAVA_VERSION="); ok {
			ver = v
		}
	}
	if ver == "" {
		return scanner.RuntimeAugment{}
	}
	var out scanner.RuntimeAugment
	for _, id := range f.vulns[ver] {
		out.Findings = append(out.Findings, javaFinding(id, ver))
	}
	out.Packages = javaPkgs(ver)
	return out
}

func javaFinding(id, ver string) scanner.Finding {
	return scanner.Finding{
		Class: inventory.ClassLang, Type: string(inventory.EcosystemJavaRuntime), Target: javaBin, PkgPath: javaBin,
		Package: javaRuntime, InstalledVer: ver, FixedVer: "21.0.99", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: id,
	}
}

func javaPkgs(ver string) []scanner.ResultPackages {
	return []scanner.ResultPackages{{
		Target: javaBin, Class: inventory.ClassLang, Type: string(inventory.EcosystemJavaRuntime),
		Packages: []scanner.Package{{Name: javaRuntime, Version: ver}},
	}}
}

// The Java runtime is a known ecosystem to the comparison of bases: a pinned
// base whose environment names the same JDK in the same place adopts, and
// the runtime finding resolves with it.
func TestDockerfileJavaRuntimeFindingsJoinBase(t *testing.T) {
	setup := func(runEnv, curEnv []string) (*dfEnv, ImageInput) {
		e := newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", appDockerfile)
		cur := withBaseEnv(baseResolution('1', '2', 'a', 'b'))
		cur.Env = curEnv
		e.reg.res["python:3.12.3-slim"] = cur
		e.candidateScan("python:3.12.3-slim", []scanner.Finding{javaFinding("CVE-J", "jdk-21.0.12+7")}, joinPkgs(pkgs("libc", "1"), javaPkgs("jdk-21.0.12+7")))
		e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'), nil, joinPkgs(pkgs("libc", "2"), javaPkgs("jdk-21.0.13+9")))
		in := dfInput("myapp:1", 'a', "app", appLayers, javaFinding("CVE-J", "jdk-21.0.12+7"))
		in.Scan.ConfigEnv = runEnv
		return e, in
	}
	version := "JAVA_VERSION=jdk-21.0.12+7"
	mapping := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}

	t.Run("same version and location: adopted", func(t *testing.T) {
		env := []string{"PATH=/x", version, javaHome}
		e, in := setup(env, env)
		it := onlyDockerfile(t, e.plan(t, bigLimits, mapping, nil, in))
		if it.Category != CategoryPRCandidate || it.Reason != ReasonAdopted {
			t.Fatalf("item = %s/%s (%s)", it.Category, it.Reason, it.Detail)
		}
		if it.Counts.Targets != 1 || it.Counts.Resolved != 1 {
			t.Errorf("counts = %+v", it.Counts)
		}
		if got := it.Entities[0].Findings; got != (LayerCounts{Base: 1}) {
			t.Errorf("findings by layer = %+v", got)
		}
	})
	t.Run("last value of a repeated location is used", func(t *testing.T) {
		env := []string{version, javaHome}
		run := []string{version, "JAVA_HOME=/somewhere/else", javaHome}
		e, in := setup(run, env)
		if it := onlyDockerfile(t, e.plan(t, bigLimits, mapping, nil, in)); it.Category != CategoryPRCandidate {
			t.Errorf("item = %s/%s", it.Category, it.Reason)
		}
	})
	for name, c := range map[string]struct{ run, base []string }{
		"location differs":         {[]string{version, "JAVA_HOME=/app/jdk"}, []string{version, javaHome}},
		"unset on the running":     {[]string{version}, []string{version, javaHome}},
		"unset on the base":        {[]string{version, javaHome}, []string{version}},
		"unset on both":            {[]string{version}, []string{version}},
		"empty on both":            {[]string{version, "JAVA_HOME="}, []string{version, "JAVA_HOME="}},
		"relative and equal":       {[]string{version, "JAVA_HOME=jdk"}, []string{version, "JAVA_HOME=jdk"}},
		"relative on the running":  {[]string{version, "JAVA_HOME=opt/java/openjdk"}, []string{version, javaHome}},
		"version differs":          {[]string{"JAVA_VERSION=jdk-21.0.11+10", javaHome}, []string{version, javaHome}},
		"trailing slash is a diff": {[]string{version, javaHome + "/"}, []string{version, javaHome}},
	} {
		t.Run(name+": left unknown", func(t *testing.T) {
			e, in := setup(c.run, c.base)
			it := onlyDockerfile(t, e.plan(t, bigLimits, mapping, nil, in))
			if it.Category != CategoryNoCandidate || it.Reason != ReasonNoBaseFindings {
				t.Errorf("item = %s/%s", it.Category, it.Reason)
			}
		})
	}
}

func TestMoveRuntimeFindingsChecksTheLocation(t *testing.T) {
	java := javaFinding("CVE-J", "jdk-21.0.12+7")
	py := runtimeFinding("CVE-P", "3.12.3")
	version, pyVersion := "JAVA_VERSION=jdk-21.0.12+7", "PYTHON_VERSION=3.12.3"
	cases := []struct {
		name            string
		image, base     []string
		javaMoved, pyOK bool
	}{
		{"same", []string{version, javaHome, pyVersion}, []string{version, javaHome, pyVersion}, true, true},
		{"location differs", []string{version, "JAVA_HOME=/a", pyVersion}, []string{version, javaHome, pyVersion}, false, true},
		{"location unset", []string{version, pyVersion}, []string{version, pyVersion}, false, true},
		{"relative", []string{version, "JAVA_HOME=a", pyVersion}, []string{version, "JAVA_HOME=a", pyVersion}, false, true},
		{"python differs", []string{version, javaHome, "PYTHON_VERSION=3.11.0"}, []string{version, javaHome, pyVersion}, true, false},
	}
	for _, c := range cases {
		cl := FindingsByLayer{Unknown: []scanner.Finding{java, py}}
		moveRuntimeFindings(&cl, c.image, c.base)
		var movedJava, movedPy bool
		for _, f := range cl.Base {
			movedJava = movedJava || f.VulnID == "CVE-J"
			movedPy = movedPy || f.VulnID == "CVE-P"
		}
		if movedJava != c.javaMoved || movedPy != c.pyOK {
			t.Errorf("%s: java moved %v, python moved %v; want %v, %v", c.name, movedJava, movedPy, c.javaMoved, c.pyOK)
		}
		if len(cl.Base)+len(cl.Unknown) != 2 {
			t.Errorf("%s: findings lost: %+v", c.name, cl)
		}
	}
}

func TestSameRuntimeLocation(t *testing.T) {
	java, node, python := string(inventory.EcosystemJavaRuntime), string(inventory.EcosystemNodeRuntime), string(inventory.EcosystemPythonRuntime)
	home := func(v string) []string { return []string{"JAVA_HOME=" + v} }
	cases := []struct {
		name        string
		typ         string
		image, base []string
		want        bool
	}{
		{"node needs no location", node, nil, nil, true},
		{"python needs no location", python, []string{"JAVA_HOME=/a"}, nil, true},
		{"same", java, home("/opt/java/openjdk"), home("/opt/java/openjdk"), true},
		{"different", java, home("/opt/a"), home("/opt/b"), false},
		{"unset", java, nil, nil, false},
		{"unset on one", java, home("/opt/a"), nil, false},
		{"empty", java, home(""), home(""), false},
		{"relative", java, home("a/b"), home("a/b"), false},
		{"root", java, home("/"), home("/"), true},
	}
	for _, c := range cases {
		if got := sameRuntimeLocation(c.typ, c.image, c.base); got != c.want {
			t.Errorf("%s: sameRuntimeLocation = %v, want %v", c.name, got, c.want)
		}
	}
}

// A floating tag that moved on: the JDK of the current base tells what a
// rebuild would pick up, but only when it sits where the running image's does.
func TestDockerfileJavaRuntimeRebuild(t *testing.T) {
	adv := []scanner.RuntimeAdvisor{fakeJava{vulns: map[string][]string{
		"jdk-21.0.12+7": {"CVE-J1", "CVE-J2", "CVE-J3"},
		"jdk-21.0.13+9": {"CVE-J3", "CVE-J4"},
	}}}
	run := func(env ...string) ImageInput {
		in := dfInput("myapp:1", 'a', "app", appLayers,
			javaFinding("CVE-J3", "jdk-21.0.12+7"), javaFinding("CVE-J1", "jdk-21.0.12+7"), javaFinding("CVE-J2", "jdk-21.0.12+7"))
		in.Scan.ConfigEnv = env
		return in
	}
	plan := func(in ImageInput, baseEnv ...string) DockerfileItem {
		e := newDFEnv()
		e.gh.put("ex/app", ".", "Dockerfile", "FROM python:3.12-slim\nCOPY . /app\n")
		e.base("3.12-slim", withBaseEnv(baseResolution('1', '2', '9', 'b'), baseEnv...), nil, pkgs("libc", "2"))
		return onlyDockerfile(t, e.planRuntimes(t, prepared, adv, in))
	}
	want := []RuntimeRebuild{{Package: javaRuntime, Installed: "jdk-21.0.12+7", BaseVersion: "jdk-21.0.13+9", Disappearing: []string{"CVE-J1", "CVE-J2"}, Remaining: []string{"CVE-J3"}}}
	newer := "JAVA_VERSION=jdk-21.0.13+9"
	older := "JAVA_VERSION=jdk-21.0.12+7"

	t.Run("same location: recorded, with different versions", func(t *testing.T) {
		it := plan(run(older, javaHome), newer, javaHome)
		if it.Category != CategoryNotComparable || it.Reason != ReasonFloatingBaseUnconfirmed {
			t.Fatalf("item = %s/%s", it.Category, it.Reason)
		}
		if !reflect.DeepEqual(it.Entities[0].RebuildRuntimes, want) || !reflect.DeepEqual(it.RebuildRuntimes, want) {
			t.Errorf("entity %+v item %+v", it.Entities[0].RebuildRuntimes, it.RebuildRuntimes)
		}
	})
	for name, c := range map[string]struct{ run, base []string }{
		"location differs":     {[]string{older, "JAVA_HOME=/app/jdk"}, []string{newer, javaHome}},
		"unset on the running": {[]string{older}, []string{newer, javaHome}},
		"unset on the base":    {[]string{older, javaHome}, []string{newer}},
		"relative on both":     {[]string{older, "JAVA_HOME=jdk"}, []string{newer, "JAVA_HOME=jdk"}},
		"empty on both":        {[]string{older, "JAVA_HOME="}, []string{newer, "JAVA_HOME="}},
	} {
		t.Run(name+": none", func(t *testing.T) {
			it := plan(run(c.run...), c.base...)
			if len(it.RebuildRuntimes) != 0 || len(it.Entities[0].RebuildRuntimes) != 0 {
				t.Errorf("entity %+v item %+v", it.Entities[0].RebuildRuntimes, it.RebuildRuntimes)
			}
		})
	}
}
