package pkgdb

import (
	"strconv"
	"strings"
	"testing"
)

// newlinesReader returns an io.Reader for n bytes of "\n": a .list file
// that costs real read time and counts fully toward the total budget while
// claiming zero paths (every line is blank and skipped), so a count-based
// limit (MaxPathsPerPackage, MaxFiles) never notices it. This is the shape
// of input a size-only defense has to catch.
func newlinesReader(n int) *strings.Reader {
	return strings.NewReader(strings.Repeat("\n", n))
}

// TestParseDpkg_TotalBudget_FinalReadOverage pins an input whose truncation
// used to go unreported: a run of .list files that are
// each individually within MaxListBytes (so the per-file cap is never hit)
// and few enough to stay under MaxFiles, but whose combined size — plus a
// final status read that is itself within MaxStatusBytes — pushes the
// *combined* total past MaxTotalBytes. Before the remaining-budget clamp,
// nothing caught this: the per-file caps were never hit, and the
// totalBytes check only ran between files, so an overage that only became
// visible once the last (status) read was in went unreported. Limits are
// scaled down from the real 256 MiB/1 MiB/32 MiB defaults so the test runs
// quickly; the proportions (list files exactly at the per-file cap, status
// pushing the sum over the total) are what reproduces the overage.
func TestParseDpkg_TotalBudget_FinalReadOverage(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTotalBytes = 3 << 20 // 3 MiB total
	limits.MaxListBytes = 1 << 20  // 1 MiB per file
	limits.MaxStatusBytes = 2 << 20

	const perList = 1 << 20 // exactly MaxListBytes
	const numLists = 2      // 2 MiB of lists leaves 1 MiB of the 3 MiB budget
	lists := make([]NamedReader, numLists)
	for i := range lists {
		lists[i] = NamedReader{Name: "pkg" + strconv.Itoa(i) + ".list", R: newlinesReader(perList)}
	}
	// A well-formed status stanza, then padded past what's left of the
	// budget (1 MiB) with harmless blank lines, while staying under
	// MaxStatusBytes (2 MiB) on its own.
	status := "Package: pkg0\nVersion: 1.0\nArchitecture: amd64\n" + strings.Repeat("\n", (2<<20)-100)

	idx, diag, err := ParseDpkg(NamedReader{Name: "status", R: strings.NewReader(status)}, lists, limits)
	if err != nil {
		t.Fatalf("ParseDpkg: %v", err)
	}
	if !diag.Truncated {
		t.Error("Truncated = false, want true: 2 MiB of lists + ~2 MiB of status exceeds the 3 MiB total budget, " +
			"but no single file or per-package limit was hit")
	}
	if len(diag.Errors) == 0 {
		t.Error("Errors is empty, want at least one entry identifying the file that was cut short")
	}
	// The index built from what could be read is still usable — truncation
	// reports incompleteness, it doesn't discard everything read so far.
	if len(idx.Ledger) == 0 {
		t.Error("Ledger is empty, want the packages that were fully read before the budget ran out")
	}
}

// TestParseDpkg_TotalBudget_StopsReadingFiles confirms the total budget is
// enforced going forward too, not just detected after the fact: once it is
// used up, later files in the list are never opened for content at all
// (readLines is never even called on them), which this test observes
// through Errors never mentioning a file placed after the budget should
// already be exhausted.
func TestParseDpkg_TotalBudget_StopsReadingFiles(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTotalBytes = 3 << 20 // 3 MiB total
	limits.MaxListBytes = 1 << 20  // 1 MiB per file — 3 files exactly exhaust the total

	lists := []NamedReader{
		{Name: "a.list", R: newlinesReader(1 << 20)},
		{Name: "b.list", R: newlinesReader(1 << 20)},
		{Name: "c.list", R: newlinesReader(1 << 20)},
		{Name: "d.list", R: newlinesReader(1 << 20)}, // must never be read: budget is spent by "c"
	}
	status := "Package: p\nVersion: 1\nArchitecture: amd64\n"

	_, diag, err := ParseDpkg(NamedReader{Name: "status", R: strings.NewReader(status)}, lists, limits)
	if err != nil {
		t.Fatalf("ParseDpkg: %v", err)
	}
	if !diag.Truncated {
		t.Error("Truncated = false, want true")
	}
	for _, e := range diag.Errors {
		if e.Name == "d.list" {
			t.Errorf("Errors mentions d.list, want it never opened once the total budget was spent: %v", e)
		}
	}
}

// TestParseDistroless_TotalBudget_FinalReadOverage is the same repro shape
// as TestParseDpkg_TotalBudget_FinalReadOverage, against ParseDistroless's
// independent budget tracking.
func TestParseDistroless_TotalBudget_FinalReadOverage(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTotalBytes = 3 << 20 // 3 MiB total, to keep the test fast
	limits.MaxStatusBytes = 1 << 20
	limits.MaxListBytes = 1 << 20

	var files []NamedReader
	for i := 0; i < 2; i++ {
		name := "pkg" + strconv.Itoa(i)
		files = append(files,
			NamedReader{Name: name, R: strings.NewReader("Package: " + name + "\nVersion: 1\nArchitecture: amd64\n")},
			NamedReader{Name: name + ".md5sums", R: newlinesReader(1 << 20)},
		)
	}
	// A third package's .md5sums alone would fit under MaxListBytes but not
	// under what's left of the 3 MiB total (2 MiB already spent above).
	files = append(files,
		NamedReader{Name: "pkg2", R: strings.NewReader("Package: pkg2\nVersion: 1\nArchitecture: amd64\n")},
		NamedReader{Name: "pkg2.md5sums", R: newlinesReader(1 << 20)},
	)

	idx, diag, err := ParseDistroless(files, limits)
	if err != nil {
		t.Fatalf("ParseDistroless: %v", err)
	}
	if !diag.Truncated {
		t.Error("Truncated = false, want true: combined reads exceed MaxTotalBytes")
	}
	if len(idx.Ledger) == 0 {
		t.Error("Ledger is empty, want the packages read before the budget ran out")
	}
}

// TestParseApk_TotalBudget_SmallerThanPerFileCap confirms ParseApk clamps to
// MaxTotalBytes even when it is smaller than MaxApkBytes: the single input
// file is still one read against the same aggregate budget every Parse*
// function shares.
func TestParseApk_TotalBudget_SmallerThanPerFileCap(t *testing.T) {
	limits := DefaultLimits()      // MaxApkBytes 32 MiB
	limits.MaxTotalBytes = 1 << 10 // 1 KiB — far smaller than MaxApkBytes

	data := "P:pkg\nV:1.0-r0\nA:x86_64\nF:etc\nR:pkg.conf\n" + strings.Repeat("\n", 2<<10)
	_, diag, err := ParseApk(NamedReader{Name: "installed", R: strings.NewReader(data)}, limits)
	if err != nil {
		t.Fatalf("ParseApk: %v", err)
	}
	if !diag.Truncated {
		t.Error("Truncated = false, want true: input exceeds the 1 KiB total budget even though it is well under MaxApkBytes")
	}
}

// TestParseApk_TotalBudget_TinyBudgetTruncates confirms a total budget too
// small to hold even one real record is reported as Truncated rather than
// silently accepting whatever fit within it.
func TestParseApk_TotalBudget_TinyBudgetTruncates(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTotalBytes = 1 // a budget of 1 byte, deliberately smaller than any real input
	data := "PP"             // 2 bytes, over the 1-byte budget
	idx, diag, err := ParseApk(NamedReader{Name: "installed", R: strings.NewReader(data)}, limits)
	if err != nil {
		t.Fatalf("ParseApk: %v", err)
	}
	if !diag.Truncated {
		t.Error("Truncated = false, want true")
	}
	if len(idx.Ledger) != 0 {
		t.Errorf("Ledger = %+v, want empty (nothing parses from a 1-byte budget)", idx.Ledger)
	}
}
