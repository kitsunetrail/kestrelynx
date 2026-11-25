package state

import (
	"reflect"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func javaScan(image string, unchecked, retired bool, finds ...scanner.Finding) scanner.ImageScan {
	s := scanOf(image, finds...)
	if unchecked {
		s.RuntimeUnchecked = []string{inventory.JavaRuntimePackage}
		s.RuntimeUncheckedReason = map[string]string{inventory.JavaRuntimePackage: scanner.ReasonDeferred}
	}
	if retired {
		s.RuntimeRetired = []string{inventory.JavaRuntimePackage}
	}
	return s
}

func TestCompute_RetiredJavaRuntimeIsRemovedNotResolved(t *testing.T) {
	const img = "app:1"
	k := img + "\t" + inventory.JavaRuntimePackage
	java := finding(img, inventory.JavaRuntimePackage, "CVE-J", scanner.StatusFixed)
	other := finding(img, "libx", "CVE-X", scanner.StatusFixed)

	_, st1 := Compute(empty(), report(day1, scanOf(img, java, other)))
	st1.Muted[k] = true

	d2, st2 := Compute(st1, report(day2, javaScan(img, false, true, other)))
	if _, ok := st2.Findings[k]; ok {
		t.Error("the retired Java entry was kept")
	}
	if st2.Muted[k] {
		t.Error("the muted flag of the retired entry was kept")
	}
	if len(d2.Resolved) != 0 {
		t.Errorf("Resolved = %v, want none", d2.Resolved)
	}
	want := []Resolved{{Image: img, Package: inventory.JavaRuntimePackage}}
	if !reflect.DeepEqual(d2.Retired, want) {
		t.Errorf("Retired = %v, want %v", d2.Retired, want)
	}
	if !d2.HasChanges() {
		t.Error("HasChanges = false for a retirement")
	}

	// The next cycle still reports it retired, but nothing was removed.
	d3, _ := Compute(st2, report(day2.AddDate(0, 0, 1), javaScan(img, false, true, other)))
	if len(d3.Retired) != 0 || len(d3.Resolved) != 0 || d3.HasChanges() {
		t.Errorf("second cycle: Retired = %v, Resolved = %v, changes = %v", d3.Retired, d3.Resolved, d3.HasChanges())
	}
}

func TestCompute_RetiredJavaRuntimeWithoutRecordHasNoEntry(t *testing.T) {
	const img = "app:1"
	other := finding(img, "libx", "CVE-X", scanner.StatusFixed)
	_, st1 := Compute(empty(), report(day1, scanOf(img, other)))
	d2, _ := Compute(st1, report(day2, javaScan(img, false, true, other)))
	if len(d2.Retired) != 0 || len(d2.Resolved) != 0 || d2.HasChanges() {
		t.Errorf("Retired = %v, Resolved = %v, changes = %v", d2.Retired, d2.Resolved, d2.HasChanges())
	}
}

func TestCompute_RetiredJavaRuntimeEOLIsRemovedNotResolved(t *testing.T) {
	const img = "app:1"
	k := img + "\t" + inventory.JavaRuntimePackage
	_, st1 := Compute(empty(), report(day1, scanOf(img, eolFinding(img, inventory.JavaRuntimePackage, "CVE-E"))))
	if _, ok := st1.EOLPackages[k]; !ok {
		t.Fatal("cycle 1 recorded no end-of-life Java entry")
	}
	st1.Muted[k] = true

	d2, st2 := Compute(st1, report(day2, javaScan(img, false, true)))
	if _, ok := st2.EOLPackages[k]; ok {
		t.Error("the retired end-of-life entry was kept")
	}
	if st2.Muted[k] {
		t.Error("the muted flag of the retired end-of-life entry was kept")
	}
	if len(d2.ResolvedEOLPackages) != 0 {
		t.Errorf("ResolvedEOLPackages = %v, want none", d2.ResolvedEOLPackages)
	}
	want := []Resolved{{Image: img, Package: inventory.JavaRuntimePackage}}
	if !reflect.DeepEqual(d2.Retired, want) {
		t.Errorf("Retired = %v, want %v", d2.Retired, want)
	}
}

func TestCompute_RetiredJavaRuntimeWithBothRecordsIsOneEntry(t *testing.T) {
	const img = "app:1"
	_, st1 := Compute(empty(), report(day1, scanOf(img,
		finding(img, inventory.JavaRuntimePackage, "CVE-J", scanner.StatusFixed),
		eolFinding(img, inventory.JavaRuntimePackage, "CVE-E"))))
	d2, st2 := Compute(st1, report(day2, javaScan(img, false, true)))
	if len(d2.Retired) != 1 || len(st2.Findings) != 0 || len(st2.EOLPackages) != 0 {
		t.Errorf("Retired = %v, Findings = %v, EOL = %v", d2.Retired, st2.Findings, st2.EOLPackages)
	}
}

func TestCompute_HeldJavaRuntimeKeepsEOLPriorityAndMute(t *testing.T) {
	const img = "app:1"
	k := img + "\t" + inventory.JavaRuntimePackage
	_, st1 := Compute(empty(), report(day1, scanOf(img,
		finding(img, inventory.JavaRuntimePackage, "CVE-J", scanner.StatusFixed),
		eolFinding(img, inventory.JavaRuntimePackage, "CVE-E"))))
	st1.Muted[k] = true
	wantF, wantE := st1.Findings[k], st1.EOLPackages[k]

	d2, st2 := Compute(st1, report(day2, javaScan(img, true, false)))
	if !reflect.DeepEqual(st2.Findings[k], wantF) {
		t.Errorf("held entry = %+v, want %+v", st2.Findings[k], wantF)
	}
	if !reflect.DeepEqual(st2.EOLPackages[k], wantE) {
		t.Errorf("held EOL entry = %+v, want %+v", st2.EOLPackages[k], wantE)
	}
	if !st2.Muted[k] {
		t.Error("the muted flag was not carried over")
	}
	if len(d2.Resolved) != 0 || len(d2.ResolvedEOLPackages) != 0 || len(d2.Retired) != 0 {
		t.Errorf("Resolved = %v, ResolvedEOL = %v, Retired = %v, want none", d2.Resolved, d2.ResolvedEOLPackages, d2.Retired)
	}
}

func javaAt(image, id, target string) scanner.Finding {
	f := finding(image, inventory.JavaRuntimePackage, id, scanner.StatusFixed)
	f.Type = string(inventory.EcosystemJavaRuntime)
	f.InstalledVer = "jdk-21.0.12+7"
	f.Target, f.PkgPath = target, target
	return f
}

// One JDK, two, then one again: the key stays (image, "Java runtime"), so the
// same CVE is neither resolved nor new and no CVE is dropped or doubled.
func TestCompute_JavaRuntimeKeyDoesNotDependOnTheNumberOfJDKs(t *testing.T) {
	const img = "app:1"
	k := img + "\t" + inventory.JavaRuntimePackage
	one := report(day1, scanOf(img, javaAt(img, "CVE-J", "opt/a/bin/java")))
	two := report(day2, scanOf(img, javaAt(img, "CVE-J", "opt/a/bin/java"), javaAt(img, "CVE-J", "opt/b/bin/java"), javaAt(img, "CVE-K", "opt/b/bin/java")))
	if len(two.Actionable) != 1 || len(two.Actionable[0].Packages) != 2 {
		t.Fatalf("two JDKs gave %+v, want one image with two groups", two.Actionable)
	}

	_, st1 := Compute(empty(), one)
	d2, st2 := Compute(st1, two)
	if len(d2.Resolved) != 0 || len(d2.Retired) != 0 {
		t.Errorf("1 -> 2: Resolved = %v, Retired = %v", d2.Resolved, d2.Retired)
	}
	if got := st2.Findings[k].VulnIDs; !reflect.DeepEqual(got, []string{"CVE-J", "CVE-K"}) {
		t.Errorf("1 -> 2: VulnIDs = %v", got)
	}
	if len(d2.Changes) != 1 || d2.Changes[0].Kind != KindNewCVEs || !reflect.DeepEqual(d2.Changes[0].NewIDs, []string{"CVE-K"}) {
		t.Errorf("1 -> 2: Changes = %+v, want only CVE-K new", d2.Changes)
	}

	d3, st3 := Compute(st2, report(day2.AddDate(0, 0, 1), scanOf(img, javaAt(img, "CVE-J", "opt/a/bin/java"), javaAt(img, "CVE-K", "opt/b/bin/java"))))
	if len(d3.Resolved) != 0 || len(d3.Changes) != 0 {
		t.Errorf("2 -> 1: Resolved = %v, Changes = %+v", d3.Resolved, d3.Changes)
	}
	if got := st3.Findings[k].VulnIDs; !reflect.DeepEqual(got, []string{"CVE-J", "CVE-K"}) {
		t.Errorf("2 -> 1: VulnIDs = %v", got)
	}
}
