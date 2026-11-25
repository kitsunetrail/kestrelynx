package notify

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func TestRuntimeRebuildCoversOnlyItsOwnExecutable(t *testing.T) {
	group := func(target string) analyze.PackageGroup {
		return analyze.PackageGroup{
			Package: inventory.JavaRuntimePackage, InstalledVer: "v", Ecosystem: inventory.EcosystemJavaRuntime,
			Instances: []analyze.Instance{{Target: target}},
		}
	}
	rr := remediation.RuntimeRebuild{Package: inventory.JavaRuntimePackage, Installed: "v", Targets: []string{"opt/java/openjdk/bin/java"}}
	if !runtimeRebuildCovers(rr, group("opt/java/openjdk/bin/java")) {
		t.Error("the environment's JDK is not covered")
	}
	if runtimeRebuildCovers(rr, group("opt/other/bin/java")) {
		t.Error("a second JDK of the same version is covered")
	}
	rr.Targets = nil
	if !runtimeRebuildCovers(rr, group("opt/other/bin/java")) {
		t.Error("a record without targets must cover every group")
	}
}

func TestFindReportGroupTellsTwoJDKsApart(t *testing.T) {
	jdk := func(target string) analyze.PackageGroup {
		return analyze.PackageGroup{
			Package: inventory.JavaRuntimePackage, Ecosystem: inventory.EcosystemJavaRuntime,
			Class: scanner.ClassLang, InstalledVer: "21.0.13", Status: scanner.StatusFixed,
			Instances: []analyze.Instance{{Target: target}},
		}
	}
	a, b := jdk("opt/a/bin/java"), jdk("opt/b/bin/java")
	v := &chView{r: analyze.Report{Actionable: []analyze.ImageFindings{{Image: "app:1", Packages: []analyze.PackageGroup{a, b}}}}}
	for _, want := range []analyze.PackageGroup{a, b} {
		_, got, n := v.findReportGroup("app:1", want)
		if n != 1 || got.Instances[0].Target != want.Instances[0].Target {
			t.Errorf("%s: n = %d, got %v", want.Instances[0].Target, n, got.Instances)
		}
	}
	// A group of another ecosystem is not told apart by instances.
	os1 := analyze.PackageGroup{Package: "openssl", Ecosystem: inventory.EcosystemAlpine, Class: scanner.ClassOS, InstalledVer: "1", Status: scanner.StatusFixed, Instances: []analyze.Instance{{Target: "x"}}}
	v = &chView{r: analyze.Report{Actionable: []analyze.ImageFindings{{Image: "app:1", Packages: []analyze.PackageGroup{os1}}}}}
	os2 := os1
	os2.Instances = []analyze.Instance{{Target: "y"}}
	if _, _, n := v.findReportGroup("app:1", os2); n != 1 {
		t.Errorf("an OS group: n = %d", n)
	}
}
