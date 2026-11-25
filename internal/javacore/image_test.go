package javacore

import (
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func exe(declared, p string) imagefs.Executable {
	return imagefs.Executable{Declared: declared, Path: p, Known: p != ""}
}

func jdkOf(dir, release string, execs ...imagefs.Executable) imagefs.JDK {
	return imagefs.JDK{Dir: dir, Release: release, Executables: execs, LayerDiffID: "sha256:" + dir}
}

func completeScan(env []string, jdks ...imagefs.JDK) scanner.ImageScan {
	s := javaScan("21.0.13")
	s.ConfigEnv = env
	// The reader resolves JAVA_HOME in the image; without links in the way that
	// is the path itself.
	home, _ := lastEnv(env, "JAVA_HOME")
	s.ImageFiles = &imagefs.Outcome{Kind: imagefs.Complete, JDKs: jdks, JavaHome: strings.TrimPrefix(path.Clean("/"+home), "/")}
	return s
}

func releaseText(t testing.TB, fixture string) string { return string(releaseFixture(t, fixture)) }

func TestAugmentImage_CompleteOneJDK(t *testing.T) {
	// The environment says 21.0.13 but the release file says 21.0.13.1: the file wins.
	env := []string{"JAVA_HOME=/opt/java/openjdk", "JAVA_VERSION=jdk-21.0.13+9"}
	j := jdkOf("opt/java/openjdk", string(withVersion(t, "temurin21", "21.0.13.1", "21.0.13")),
		exe("opt/java/openjdk/bin/java", "opt/java/openjdk/bin/java"), exe("opt/java/openjdk/jre/bin/java", "opt/java/openjdk/jre/bin/java"))
	aug := advisorWithFixture(t).Augment(completeScan(env, j), allSeverities)
	if len(aug.Unchecked) != 0 || len(aug.Retired) != 0 {
		t.Fatalf("unchecked %v retired %v", aug.Unchecked, aug.Retired)
	}
	if len(aug.Findings) != 10 {
		t.Fatalf("findings = %d, want 10", len(aug.Findings))
	}
	for _, f := range aug.Findings {
		if f.Package != "Java runtime" || f.Type != "java-runtime" || f.InstalledVer != "21.0.13" ||
			f.Target != "opt/java/openjdk/bin/java" || f.PkgPath != f.Target || f.RuntimeSource != "release" ||
			!f.RuntimeSameAsEnv || f.TargetsIncomplete || f.LayerDiffID != "sha256:opt/java/openjdk" ||
			!reflect.DeepEqual(f.AltTargets, []string{"opt/java/openjdk/jre/bin/java"}) {
			t.Fatalf("finding = %+v", f)
		}
	}
	if len(aug.Packages) != 1 || aug.Packages[0].Target != "opt/java/openjdk/bin/java" || aug.Packages[0].Packages[0].Version != "21.0.13" {
		t.Errorf("packages = %+v", aug.Packages)
	}
	if aug.JavaImage == nil || *aug.JavaImage != (scanner.JavaImageState{Kind: "complete", HasJDK: true}) {
		t.Errorf("JavaImage = %+v", aug.JavaImage)
	}
}

func TestAugmentImage_SameAsEnv(t *testing.T) {
	rel := string(withVersion(t, "temurin21", "21.0.13.1", "21.0.13"))
	tests := []struct {
		name  string
		env   []string
		mixed bool
		dir   string
		same  bool
	}{
		{"all match", []string{"JAVA_HOME=/opt/java/openjdk", "JAVA_VERSION=jdk-21.0.13+9"}, false, "opt/java/openjdk", true},
		{"home with trailing slash", []string{"JAVA_HOME=/opt/java/openjdk/", "JAVA_VERSION=jdk-21.0.13+9"}, false, "opt/java/openjdk", true},
		{"other directory", []string{"JAVA_HOME=/opt/other", "JAVA_VERSION=jdk-21.0.13+9"}, false, "opt/java/openjdk", false},
		{"not Temurin form", []string{"JAVA_HOME=/opt/java/openjdk", "JAVA_VERSION=21.0.13"}, false, "opt/java/openjdk", false},
		{"no JAVA_HOME", []string{"JAVA_VERSION=jdk-21.0.13+9"}, false, "opt/java/openjdk", false},
		{"mixed layers", []string{"JAVA_HOME=/opt/java/openjdk", "JAVA_VERSION=jdk-21.0.13+9"}, true, "opt/java/openjdk", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := jdkOf(tt.dir, rel, exe(tt.dir+"/bin/java", tt.dir+"/bin/java"))
			if tt.mixed {
				j.LayerDiffID, j.MixedLayers = "", true
			}
			aug := advisorWithFixture(t).Augment(completeScan(tt.env, j), allSeverities)
			if len(aug.Findings) == 0 {
				t.Fatal("no findings")
			}
			for _, f := range aug.Findings {
				if f.RuntimeSameAsEnv != tt.same {
					t.Fatalf("RuntimeSameAsEnv = %v, want %v", f.RuntimeSameAsEnv, tt.same)
				}
				if tt.mixed && f.LayerDiffID != "" {
					t.Fatalf("LayerDiffID = %q for mixed layers", f.LayerDiffID)
				}
			}
		})
	}
}

func TestAugmentImage_TwoJDKsTwoTargets(t *testing.T) {
	a := jdkOf("opt/java/openjdk", string(withVersion(t, "temurin21", "21.0.13.1", "21.0.13")),
		exe("opt/java/openjdk/bin/java", "opt/java/openjdk/bin/java"))
	b := jdkOf("usr/share/app/jdk", string(withVersion(t, "oracle-openjdk27", "27.0.1.1", "27.0.1.0.3")),
		exe("usr/share/app/jdk/bin/java", "usr/share/app/jdk/bin/java"))
	aug := advisorWithFixture(t).Augment(completeScan([]string{"JAVA_HOME=/opt/java/openjdk"}, a, b), allSeverities)
	targets := map[string]int{}
	versions := map[string]string{}
	for _, f := range aug.Findings {
		targets[f.Target]++
		versions[f.Target] = f.InstalledVer
		if f.Package != "Java runtime" {
			t.Fatalf("Package = %q", f.Package)
		}
	}
	if len(targets) != 2 || versions["opt/java/openjdk/bin/java"] != "21.0.13" || versions["usr/share/app/jdk/bin/java"] != "27.0.1.0.3" {
		t.Fatalf("targets %v versions %v", targets, versions)
	}
	if len(aug.Packages) != 2 {
		t.Errorf("packages = %d, want 2", len(aug.Packages))
	}
	// The fixed version is aligned inside each JDK, never across them.
	for _, tg := range []string{"opt/java/openjdk/bin/java", "usr/share/app/jdk/bin/java"} {
		fixed := map[string]bool{}
		for _, f := range aug.Findings {
			if f.Target == tg && f.Status == scanner.StatusFixed {
				fixed[f.FixedVer] = true
			}
		}
		if len(fixed) != 1 {
			t.Errorf("%s has fixed versions %v", tg, fixed)
		}
	}
}

func TestAugmentImage_UnknownExecutables(t *testing.T) {
	rel := string(withVersion(t, "temurin21", "21.0.13.1", "21.0.13"))
	// bin/java cannot be resolved, jre/bin/java can: the target is empty, the
	// resolved jre launcher is only an alternative.
	j := jdkOf("opt/jdk", rel, exe("opt/jdk/bin/java", ""), exe("opt/jdk/jre/bin/java", "opt/jdk/jre/bin/java"))
	aug := advisorWithFixture(t).Augment(completeScan(nil, j), allSeverities)
	f := aug.Findings[0]
	if f.Target != "" || f.PkgPath != "" || !reflect.DeepEqual(f.AltTargets, []string{"opt/jdk/jre/bin/java"}) || !f.TargetsIncomplete {
		t.Errorf("finding target %q alts %v incomplete %v", f.Target, f.AltTargets, f.TargetsIncomplete)
	}
	// Nothing resolves: the target is empty and the JDK is still checked.
	j = jdkOf("opt/jdk", rel, exe("opt/jdk/bin/java", ""))
	aug = advisorWithFixture(t).Augment(completeScan(nil, j), allSeverities)
	f = aug.Findings[0]
	if f.Target != "" || f.PkgPath != "" || !f.TargetsIncomplete {
		t.Errorf("finding = %+v", f)
	}
	// bin/java is missing altogether: the same.
	j = jdkOf("opt/jdk", rel, exe("opt/jdk/jre/bin/java", "opt/jdk/jre/bin/java"))
	aug = advisorWithFixture(t).Augment(completeScan(nil, j), allSeverities)
	f = aug.Findings[0]
	if f.Target != "" || !f.TargetsIncomplete || !reflect.DeepEqual(f.AltTargets, []string{"opt/jdk/jre/bin/java"}) {
		t.Errorf("no bin/java: %+v", f)
	}
}

func TestAugmentImage_SameAsEnvThroughAJavaHomeLink(t *testing.T) {
	rel := string(withVersion(t, "temurin21", "21.0.13.1", "21.0.13"))
	j := jdkOf("opt/java/openjdk", rel, exe("opt/java/openjdk/bin/java", "opt/java/openjdk/bin/java"))
	env := []string{"JAVA_HOME=/opt/java/current", "JAVA_VERSION=jdk-21.0.13+9"}
	for name, home := range map[string]string{"resolved": "opt/java/openjdk", "not resolved": ""} {
		s := completeScan(env, j)
		s.ImageFiles.JavaHome = home
		aug := advisorWithFixture(t).Augment(s, allSeverities)
		if len(aug.Findings) == 0 {
			t.Fatal("no findings")
		}
		for _, f := range aug.Findings {
			if f.RuntimeSameAsEnv != (home != "") {
				t.Fatalf("%s: RuntimeSameAsEnv = %v", name, f.RuntimeSameAsEnv)
			}
		}
	}
}

func TestAugmentImage_NoJDK(t *testing.T) {
	// The environment names a Temurin JDK, but the layers hold none: the environment is not used.
	s := completeScan([]string{"JAVA_HOME=/opt/java/openjdk", "JAVA_VERSION=jdk-21.0.13+9"})
	aug := advisorWithFixture(t).Augment(s, allSeverities)
	if len(aug.Findings) != 0 || len(aug.Unchecked) != 0 || len(aug.Retired) != 0 || len(aug.Packages) != 0 {
		t.Fatalf("aug = %+v", aug)
	}
	if aug.JavaImage == nil || *aug.JavaImage != (scanner.JavaImageState{Kind: "complete"}) {
		t.Errorf("JavaImage = %+v", aug.JavaImage)
	}
}

func TestAugmentImage_OnlyExcludedJDKsRetire(t *testing.T) {
	for _, fx := range []struct{ fixture, dir string }{
		{"corretto21", "usr/lib/jvm/java-21-amazon-corretto.x86_64"},
		{"zulu21", "usr/lib/jvm/zulu21-ca-amd64"},
		{"oracle-jdk25", "usr/lib/jvm/jdk-25"},
		{"semeru21", "opt/java/openjdk"},
	} {
		t.Run(fx.fixture, func(t *testing.T) {
			j := jdkOf(fx.dir, releaseText(t, fx.fixture), exe(fx.dir+"/bin/java", fx.dir+"/bin/java"))
			// Also without advisory data: nothing needs it to retire.
			for _, a := range []*Advisor{advisorWithFixture(t), {}} {
				aug := a.Augment(completeScan(nil, j), allSeverities)
				if !reflect.DeepEqual(aug.Retired, []string{"Java runtime"}) || len(aug.Findings) != 0 || len(aug.Unchecked) != 0 {
					t.Fatalf("aug = %+v", aug)
				}
				if *aug.JavaImage != (scanner.JavaImageState{Kind: "complete", HasJDK: true, HasExcluded: true}) {
					t.Errorf("JavaImage = %+v", aug.JavaImage)
				}
			}
		})
	}
}

func TestAugmentImage_CheckedAndExcluded(t *testing.T) {
	good := jdkOf("opt/java/openjdk", string(withVersion(t, "temurin21", "21.0.13.1", "21.0.13")), exe("opt/java/openjdk/bin/java", "opt/java/openjdk/bin/java"))
	bad := jdkOf("usr/lib/jvm/zulu21-ca-amd64", releaseText(t, "zulu21"), exe("usr/lib/jvm/zulu21-ca-amd64/bin/java", "usr/lib/jvm/zulu21-ca-amd64/bin/java"))
	aug := advisorWithFixture(t).Augment(completeScan(nil, good, bad), allSeverities)
	if len(aug.Retired) != 0 || len(aug.Findings) == 0 {
		t.Fatalf("aug = %+v", aug)
	}
	if !aug.JavaImage.HasExcluded || !aug.JavaImage.HasJDK {
		t.Errorf("JavaImage = %+v", aug.JavaImage)
	}
}

func TestAugmentImage_SuppressedIsReported(t *testing.T) {
	j := jdkOf("opt/java/openjdk", releaseText(t, "jenkins-jlink21"), exe("opt/java/openjdk/bin/java", "opt/java/openjdk/bin/java"))
	aug := advisorWithFixture(t).Augment(completeScan(nil, j), allSeverities)
	if !aug.JavaImage.Suppressed || len(aug.Findings) == 0 {
		t.Fatalf("JavaImage = %+v, findings %d", aug.JavaImage, len(aug.Findings))
	}
	for _, f := range aug.Findings {
		if f.VulnID == "CVE-2026-114820" {
			t.Error("the vendor-fixed CVE is reported")
		}
	}
}

func TestAugmentImage_AdvisoriesUnavailable(t *testing.T) {
	j := jdkOf("opt/java/openjdk", releaseText(t, "temurin21"), exe("opt/java/openjdk/bin/java", "opt/java/openjdk/bin/java"))
	aug := (&Advisor{}).Augment(completeScan(nil, j), allSeverities)
	if !reflect.DeepEqual(aug.Unchecked, []string{"Java runtime"}) || aug.UncheckedReason["Java runtime"] != "advisories" || len(aug.Findings) != 0 {
		t.Fatalf("aug = %+v", aug)
	}
}

func TestAugmentImage_Deferred(t *testing.T) {
	s := javaScan("jdk-21.0.13+9", "JAVA_HOME=/opt/java/openjdk")
	s.ImageFiles = &imagefs.Outcome{Kind: imagefs.Deferred, Reason: imagefs.ReasonBudget}
	aug := advisorWithFixture(t).Augment(s, allSeverities)
	if !reflect.DeepEqual(aug.Unchecked, []string{"Java runtime"}) || aug.UncheckedReason["Java runtime"] != "deferred" ||
		len(aug.Findings) != 0 || len(aug.Packages) != 0 {
		t.Fatalf("aug = %+v", aug)
	}
	if *aug.JavaImage != (scanner.JavaImageState{Kind: "deferred", Reason: "budget"}) {
		t.Errorf("JavaImage = %+v", aug.JavaImage)
	}
}

func TestAugmentImage_PermanentFallsBackToEnvironment(t *testing.T) {
	s := javaScan("jdk-21.0.13+9", "JAVA_HOME=/opt/java/openjdk")
	s.ImageFiles = &imagefs.Outcome{Kind: imagefs.Permanent, Reason: imagefs.ReasonLayerTooLarge}
	got := advisorWithFixture(t).Augment(s, allSeverities)
	plain := javaScan("jdk-21.0.13+9", "JAVA_HOME=/opt/java/openjdk")
	want := advisorWithFixture(t).Augment(plain, allSeverities)
	if !reflect.DeepEqual(got.Findings, want.Findings) || !reflect.DeepEqual(got.Packages, want.Packages) || len(got.Findings) == 0 {
		t.Fatalf("the fallback differs from the stage 1 result")
	}
	for _, f := range got.Findings {
		if f.RuntimeSource != "env" {
			t.Fatalf("RuntimeSource = %q", f.RuntimeSource)
		}
	}
	if *got.JavaImage != (scanner.JavaImageState{Kind: "permanent", UsedEnvFallback: true, Reason: "layer_too_large"}) {
		t.Errorf("JavaImage = %+v", got.JavaImage)
	}
}

func TestAugmentImage_PermanentWithoutEnvironmentIsUnreadable(t *testing.T) {
	s := javaScan("21.0.13") // not the Temurin form: stage 1 detects nothing
	s.ImageFiles = &imagefs.Outcome{Kind: imagefs.Permanent, Reason: scanner.ReasonRefOnly}
	aug := advisorWithFixture(t).Augment(s, allSeverities)
	if !reflect.DeepEqual(aug.Unchecked, []string{"Java runtime"}) || aug.UncheckedReason["Java runtime"] != "unreadable" || len(aug.Findings) != 0 {
		t.Fatalf("aug = %+v", aug)
	}
	if aug.JavaImage.UsedEnvFallback || aug.JavaImage.Kind != "permanent" || aug.JavaImage.Reason != "ref_only" {
		t.Errorf("JavaImage = %+v", aug.JavaImage)
	}
}

func TestAugment_NotAttemptedIsStage1(t *testing.T) {
	// With no image outcome the result is the one stage 1 always gave, and
	// no image state is set.
	for _, s := range []scanner.ImageScan{
		javaScan("jdk-21.0.13+9", "JAVA_HOME=/opt/java/openjdk"),
		javaScan("21.0.13"),
		{Image: "app:1", Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}},
	} {
		aug := advisorWithFixture(t).Augment(s, allSeverities)
		if aug.JavaImage != nil || len(aug.Retired) != 0 || aug.UncheckedReason != nil {
			t.Errorf("aug = %+v", aug)
		}
		for _, f := range aug.Findings {
			f.RuntimeSource = ""
			if f.RuntimeSameAsEnv || f.AltTargets != nil || f.TargetsIncomplete || f.LayerDiffID != "" {
				t.Errorf("stage 2 field set on a stage 1 finding: %+v", f)
			}
		}
	}
	if aug := (&Advisor{}).Augment(javaScan("jdk-21.0.13+9"), allSeverities); !reflect.DeepEqual(aug.Unchecked, []string{"Java runtime"}) {
		t.Errorf("no data: %+v", aug)
	}
}
