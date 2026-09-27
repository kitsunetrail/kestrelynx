package analyze

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// TestRuntimeSortPackages_InUseFirstWithinBucket checks the ordering
// rule: an in-use package moves ahead of one that is not, within the same
// priority bucket, even though sortPackages' own severity-first order would
// otherwise rank it behind a higher-severity package that isn't in use.
func TestRuntimeSortPackages_InUseFirstWithinBucket(t *testing.T) {
	strong := PackageGroup{Package: "apkg", Critical: 3}
	weak := PackageGroup{Package: "zpkg", Critical: 0, Runtime: Runtime{Usage: evidence.UsageInUse}}
	groups := []PackageGroup{strong, weak}

	sortPackages(groups)
	if groups[0].Package != "apkg" {
		t.Fatalf("sortPackages baseline = %s first, want apkg (more critical) — test fixture assumption broken", groups[0].Package)
	}

	runtimeSortPackages(groups)
	if groups[0].Package != "zpkg" {
		t.Fatalf("runtimeSortPackages = %s first, want zpkg (in use)", groups[0].Package)
	}
}

// TestRuntimeSortPackages_ExposureThenPrivilegeTieBreak covers the second
// and third sort keys among in-use packages: exposure stage first (strongest
// wins), then high privilege, both only ever breaking ties left after
// in-use-first.
func TestRuntimeSortPackages_ExposureThenPrivilegeTieBreak(t *testing.T) {
	a := PackageGroup{Package: "a", Runtime: Runtime{Usage: evidence.UsageInUse, Exposure: ExposureContainerListening}}
	b := PackageGroup{Package: "b", Runtime: Runtime{Usage: evidence.UsageInUse, Exposure: ExposureHostPublishedAll}}
	groups := []PackageGroup{a, b}
	sortPackages(groups)
	runtimeSortPackages(groups)
	if groups[0].Package != "b" {
		t.Fatalf("want the more exposed in-use package first, got %s", groups[0].Package)
	}

	c := PackageGroup{Package: "c", Runtime: Runtime{Usage: evidence.UsageInUse, Exposure: ExposureContainerListening, HighPrivilege: false}}
	d := PackageGroup{Package: "d", Runtime: Runtime{Usage: evidence.UsageInUse, Exposure: ExposureContainerListening, HighPrivilege: true}}
	groups2 := []PackageGroup{c, d}
	sortPackages(groups2)
	runtimeSortPackages(groups2)
	if groups2[0].Package != "d" {
		t.Fatalf("want the high-privilege in-use package first when exposure ties, got %s", groups2[0].Package)
	}
}

// TestRuntimeSortPackages_NegativeStatesNeverReorder is a narrower version
// of the report-level invariant test (runtime_invariants_test.go): with no
// package in use at all, runtimeSortPackages must leave sortPackages' own
// order completely alone, whatever mix of not_observed/unavailable reasons
// the packages carry.
func TestRuntimeSortPackages_NegativeStatesNeverReorder(t *testing.T) {
	a := PackageGroup{Package: "a", Critical: 1, Runtime: Runtime{Usage: evidence.UsageNotObserved}}
	b := PackageGroup{Package: "b", Critical: 1, Runtime: Runtime{Usage: evidence.UsageUnavailable, Reason: evidence.ReasonSensorStale}}
	groups := []PackageGroup{a, b}
	sortPackages(groups)
	before := []string{groups[0].Package, groups[1].Package}
	runtimeSortPackages(groups)
	after := []string{groups[0].Package, groups[1].Package}
	if before[0] != after[0] || before[1] != after[1] {
		t.Fatalf("runtimeSortPackages reordered a not_observed/unavailable pair: before %v, after %v", before, after)
	}
}

// TestRuntimeSortImages_InUseImageFirst mirrors the package-level test at
// the image level: an image containing at least one in-use package moves
// ahead of one that has none, within the same priority bucket.
func TestRuntimeSortImages_InUseImageFirst(t *testing.T) {
	strong := ImageFindings{Image: "strong", Packages: []PackageGroup{{Critical: 5}}}
	weak := ImageFindings{Image: "weak", Packages: []PackageGroup{{Critical: 0, Runtime: Runtime{Usage: evidence.UsageInUse}}}}
	imgs := []ImageFindings{strong, weak}

	sortImages(imgs)
	if imgs[0].Image != "strong" {
		t.Fatalf("sortImages baseline = %s first, want strong (more critical) — test fixture assumption broken", imgs[0].Image)
	}

	runtimeSortImages(imgs)
	if imgs[0].Image != "weak" {
		t.Fatalf("runtimeSortImages = %s first, want weak (has an in-use package)", imgs[0].Image)
	}
}
