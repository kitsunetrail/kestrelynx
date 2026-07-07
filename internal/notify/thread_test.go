package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
)

// seenDaysAgo builds a firstSeen lookup that reports every finding as first
// seen the given number of days before genTime.
func seenDaysAgo(days int) func(image, pkg string) (time.Time, bool) {
	return func(image, pkg string) (time.Time, bool) {
		return genTime.AddDate(0, 0, -days), true
	}
}

func TestBuildThreadMessages_TriageLayout(t *testing.T) {
	msgs := BuildThreadMessages(triageReport(), seenDaysAgo(3), 0)
	if len(msgs) != 1 {
		t.Fatalf("expected one message, got %d", len(msgs))
	}
	out := msgs[0]

	mustContain := []string{
		"📊 *Full report — 2026-06-24 09:00*",
		"*⛔ EOL base images (1)*",
		"*🚨 URGENT (1)*",
		"openssl 3.0.7 → 3.0.11",
		"CVE-KEV CRITICAL · CISA KEV (exploited in the wild) · EPSS 94%",
		"⏱ open 3 day(s) — first seen 2026-06-21",
		"*👀 WATCH (1)*",
		"e2fsprogs 1.44 (no fix available)",
		"no fix yet, consider mitigation",
		"*🔕 LOW (1)*",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("thread missing %q\n---\n%s", s, out)
		}
	}
	// Low priority is a count, never a listing (spec §2).
	if strings.Contains(out, "dpkg 1.19.7") {
		t.Errorf("low-priority package must not be expanded:\n%s", out)
	}
	// Order: urgent before watch before low.
	if !(strings.Index(out, "URGENT") < strings.Index(out, "WATCH") &&
		strings.Index(out, "WATCH") < strings.Index(out, "LOW")) {
		t.Errorf("bucket order wrong:\n%s", out)
	}
}

func TestBuildThreadMessages_FirstSeenToday(t *testing.T) {
	msgs := BuildThreadMessages(triageReport(), seenDaysAgo(0), 0)
	if !strings.Contains(msgs[0], "⏱ first seen today") {
		t.Errorf("day-zero findings should read 'first seen today':\n%s", msgs[0])
	}
}

func TestBuildThreadMessages_NilFirstSeen(t *testing.T) {
	msgs := BuildThreadMessages(triageReport(), nil, 0)
	if len(msgs) == 0 {
		t.Fatal("expected messages without a firstSeen lookup")
	}
	if strings.Contains(msgs[0], "⏱") {
		t.Errorf("age lines must be omitted without a firstSeen lookup:\n%s", msgs[0])
	}
}

func TestBuildThreadMessages_NothingOpen(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "clean:1"}}, analyze.Triage{}, genTime)
	if msgs := BuildThreadMessages(r, nil, 0); msgs != nil {
		t.Errorf("no open findings must skip the thread (edge case 4), got %d message(s)", len(msgs))
	}
}

func TestBuildThreadMessages_AlsoIDs(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "app:1",
		Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-A"},
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-B"},
			{Image: "app:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-C"},
		},
	}}
	r := analyze.Build(scans, triageRules(map[string]analyze.Enrichment{"CVE-A": {KEV: true}}), genTime)
	out := strings.Join(BuildThreadMessages(r, nil, 0), "\n")
	if !strings.Contains(out, "also: CVE-B, CVE-C") {
		t.Errorf("secondary CVE ids must be listed:\n%s", out)
	}
}

// wideReport builds many single-package images so the packer has plenty of
// image-sized blocks to distribute.
func wideReport(images int) analyze.Report {
	var scans []scanner.ImageScan
	enrich := map[string]analyze.Enrichment{}
	for i := 0; i < images; i++ {
		img := fmt.Sprintf("svc-%02d:1.0", i)
		id := fmt.Sprintf("CVE-%04d", i)
		scans = append(scans, scanner.ImageScan{Image: img, Findings: []scanner.Finding{
			{Image: img, Class: scanner.ClassOS, Package: "libfoo", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: id},
		}})
		enrich[id] = analyze.Enrichment{KEV: true}
	}
	return analyze.Build(scans, triageRules(enrich), genTime)
}

func TestBuildThreadMessages_SplitsAtLimit(t *testing.T) {
	limit := 900
	msgs := BuildThreadMessages(wideReport(12), seenDaysAgo(2), limit)
	if len(msgs) < 2 {
		t.Fatalf("expected the report to split, got %d message(s)", len(msgs))
	}
	for i, m := range msgs {
		if len(m) > limit {
			t.Errorf("message %d exceeds limit: %d > %d\n%s", i, len(m), limit, m)
		}
	}
	// Continuation messages repeat the section header.
	if !strings.Contains(msgs[1], "*🚨 URGENT (12)* _(cont.)_") {
		t.Errorf("continuation must repeat the section title:\n%s", msgs[1])
	}
	// Every image appears exactly once across the whole thread.
	all := strings.Join(msgs, "\n")
	for i := 0; i < 12; i++ {
		img := fmt.Sprintf("svc-%02d:1.0", i)
		if strings.Count(all, img) != 1 {
			t.Errorf("image %s should appear exactly once, got %d", img, strings.Count(all, img))
		}
	}
}

func TestBuildThreadMessages_TriageOffFallback(t *testing.T) {
	out := strings.Join(BuildThreadMessages(sampleReport(), seenDaysAgo(1), 0), "\n")
	mustContain := []string{
		"*✅ Actionable now (fixed)*",
		"libc-bin",
		"setuptools", // low-risk fixes are NOT collapsed in the thread
		"*ℹ️ No fix yet (affected / waiting on upstream)*",
		"e2fsprogs",
		"*🔕 Upstream won't fix (will_not_fix)*",
		"gcc-8-base",
		"⏱ open 1 day(s)",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("triage-off thread missing %q\n---\n%s", s, out)
		}
	}
}
