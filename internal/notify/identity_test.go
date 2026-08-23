// Tests for the Phase 2 identity model's notify wiring: Replaced on the
// Slack diff and the webhook payload, the extra imagePayload identity
// fields, and the Slack annotations for unresolved / ambiguous entities.
package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// --- Replaced on the Slack diff ---

// TestFormatSlackDiffText_Replaced covers: Replaced renders one line per
// image; the short digest is the sha256:-stripped, 12-hex-char prefix; a
// multi-value set is rendered comma-joined in the given (already sorted)
// order; and — critically — Replaced alone (no findings changes at all) must
// still be reported, never absorbed into "No changes since last scan".
func TestFormatSlackDiffText_Replaced(t *testing.T) {
	prevA := "sha256:" + strings.Repeat("1", 64)
	curA := "sha256:" + strings.Repeat("2", 64)
	prevB1 := "sha256:" + strings.Repeat("3", 64)
	prevB2 := "sha256:" + strings.Repeat("4", 64)
	curB1 := "sha256:" + strings.Repeat("5", 64)
	curB2 := "sha256:" + strings.Repeat("6", 64)

	d := state.Diff{Replaced: []state.ImageReplacement{
		{Ref: "nginx:latest", PrevContentIDs: []string{prevA}, ContentIDs: []string{curA}},
		{Ref: "redis:7", PrevContentIDs: []string{prevB1, prevB2}, ContentIDs: []string{curB1, curB2}},
	}}
	// Both images are clean (no findings): a replacement on a clean image must
	// still be reported.
	r := analyze.Build([]scanner.ImageScan{{Image: "nginx:latest"}, {Image: "redis:7"}}, analyze.Triage{}, genTime)
	out := FormatSlackDiffText(r, d, false)

	if !strings.Contains(out, "Image content changed (2)") {
		t.Errorf("expected a Replaced header with count 2:\n%s", out)
	}
	if !strings.Contains(out, "nginx:latest: image updated (111111111111 → 222222222222)") {
		t.Errorf("expected the single-value replaced line:\n%s", out)
	}
	if !strings.Contains(out, "redis:7: image updated (333333333333, 444444444444 → 555555555555, 666666666666)") {
		t.Errorf("expected the multi-value replaced line, comma-joined in the given order:\n%s", out)
	}
	if strings.Contains(out, "No changes since last scan") {
		t.Errorf("a Replaced-only diff must not report No changes:\n%s", out)
	}
}

// TestFormatSlackDiffText_ReplacedAbsentWhenEmpty guards against the header
// appearing when there is nothing to report.
func TestFormatSlackDiffText_ReplacedAbsentWhenEmpty(t *testing.T) {
	r, d := diffFixture()
	out := FormatSlackDiffText(r, d, false)
	if strings.Contains(out, "Image content changed") {
		t.Errorf("no Replaced header expected when d.Replaced is empty:\n%s", out)
	}
}

// --- Replaced on the webhook payload ---

func TestBuildWebhookPayload_Replaced(t *testing.T) {
	prevA := "sha256:" + strings.Repeat("1", 64)
	curA := "sha256:" + strings.Repeat("2", 64)
	d := state.Diff{Replaced: []state.ImageReplacement{
		{Ref: "nginx:latest", PrevContentIDs: []string{prevA}, ContentIDs: []string{curA}},
	}}
	r := analyze.Build([]scanner.ImageScan{{Image: "nginx:latest"}}, analyze.Triage{}, genTime)

	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	diff := p["diff"].(map[string]any)
	replaced, ok := diff["replaced"].([]any)
	if !ok || len(replaced) != 1 {
		t.Fatalf("diff.replaced = %v, want 1 entry", diff["replaced"])
	}
	entry := replaced[0].(map[string]any)
	if entry["ref"] != "nginx:latest" {
		t.Errorf("ref = %v, want nginx:latest", entry["ref"])
	}
	prevIDs := entry["prev_content_ids"].([]any)
	if len(prevIDs) != 1 || prevIDs[0] != prevA {
		t.Errorf("prev_content_ids = %v, want [%s]", prevIDs, prevA)
	}
	curIDs := entry["content_ids"].([]any)
	if len(curIDs) != 1 || curIDs[0] != curA {
		t.Errorf("content_ids = %v, want [%s]", curIDs, curA)
	}
}

// TestBuildWebhookPayload_ReplacedEmptyArrayWhenNone is the always-present,
// never-null convention shared by diff.new/diff.resolved.
func TestBuildWebhookPayload_ReplacedEmptyArrayWhenNone(t *testing.T) {
	r, d := diffFixture()
	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	diff := p["diff"].(map[string]any)
	replaced, ok := diff["replaced"].([]any)
	if !ok {
		t.Fatalf("diff.replaced missing or wrong type: %v", diff["replaced"])
	}
	if len(replaced) != 0 {
		t.Errorf("diff.replaced = %v, want empty", replaced)
	}
}

// --- imagePayload identity fields ---

// TestBuildWebhookPayload_ImageIdentityFields checks content_id,
// registry_digests, identity_resolved and scan_target_kind for both a
// resolved (ContentID-pinned) scan and an unresolved (reference-fallback)
// scan, and that every pre-existing findingPayload/imagePayload field is
// still present and correctly shaped (the existing TestBuildWebhookPayload
// test already pins those field names/types unchanged; this test adds the
// new ones without touching that assertion).
func TestBuildWebhookPayload_ImageIdentityFields(t *testing.T) {
	cid := "sha256:" + strings.Repeat("c", 64)
	regDigest := "app@sha256:" + strings.Repeat("d", 64)
	scans := []scanner.ImageScan{
		{
			Image:             "app:1",
			ExpectedContentID: cid,
			RegistryDigests:   []string{regDigest},
			Findings: []scanner.Finding{
				{Image: "app:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
			},
		},
		{
			Image: "legacy:1", // no ExpectedContentID: reference-fallback scan
			Findings: []scanner.Finding{
				{Image: "legacy:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2"},
			},
		},
	}
	r := analyze.Build(scans, analyze.Triage{}, genTime)
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	byImage := map[string]map[string]any{}
	for _, a := range p["actionable"].([]any) {
		m := a.(map[string]any)
		byImage[m["image"].(string)] = m
	}

	resolved, ok := byImage["app:1"]
	if !ok {
		t.Fatal("app:1 missing from actionable")
	}
	if resolved["content_id"] != cid {
		t.Errorf("app:1 content_id = %v, want %v", resolved["content_id"], cid)
	}
	if resolved["identity_resolved"] != true {
		t.Errorf("app:1 identity_resolved = %v, want true", resolved["identity_resolved"])
	}
	if resolved["scan_target_kind"] != "content_id" {
		t.Errorf("app:1 scan_target_kind = %v, want content_id", resolved["scan_target_kind"])
	}
	digests, ok := resolved["registry_digests"].([]any)
	if !ok || len(digests) != 1 || digests[0] != regDigest {
		t.Errorf("app:1 registry_digests = %v", resolved["registry_digests"])
	}

	unresolved, ok := byImage["legacy:1"]
	if !ok {
		t.Fatal("legacy:1 missing from actionable")
	}
	if _, present := unresolved["content_id"]; present {
		t.Errorf("legacy:1 content_id must be omitted (omitempty) when unresolved, got %v", unresolved["content_id"])
	}
	if unresolved["identity_resolved"] != false {
		t.Errorf("legacy:1 identity_resolved = %v, want false", unresolved["identity_resolved"])
	}
	if unresolved["scan_target_kind"] != "reference" {
		t.Errorf("legacy:1 scan_target_kind = %v, want reference", unresolved["scan_target_kind"])
	}
	rd, ok := unresolved["registry_digests"].([]any)
	if !ok || len(rd) != 0 {
		t.Errorf("legacy:1 registry_digests should be an empty array (never null), got %v", unresolved["registry_digests"])
	}
}

// --- Slack: unresolved-identity warning ---

// TestIdentity_ReferenceFallback is the "reference fallback" test: a scan
// that never had a Docker-observed ContentID to pin to (ExpectedContentID
// empty, so ImageFindings.ContentID is empty too) must surface that on both
// delivery paths — an explicit warning on the Slack heading, and
// scan_target_kind="reference" (identity_resolved=false, content_id omitted)
// in the webhook payload.
//
// The fallback scan still returns real-looking ScannedContentID
// (scanner.ImageScan.ContentID) / RegistryDigests values: whatever Trivy
// happened to resolve on its own when there was no Docker-observed identity
// to pin to. These describe a *different* entity than the one Docker
// reported (or none at all), so they must never leak into the
// identity-resolved payload fields just because ExpectedContentID was never
// set.
func TestIdentity_ReferenceFallback(t *testing.T) {
	otherEntityCID := "sha256:" + strings.Repeat("f", 64)
	otherEntityDigest := "openssl@sha256:" + strings.Repeat("9", 64)
	scans := []scanner.ImageScan{{
		Image:           "legacy:1",
		ContentID:       otherEntityCID, // ScannedContentID: not Docker-observed
		RegistryDigests: []string{otherEntityDigest},
		Findings: []scanner.Finding{
			{Image: "legacy:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
		},
	}}
	r := analyze.Build(scans, analyze.Triage{}, genTime)

	out := FormatSlackText(r)
	if !strings.Contains(out, "legacy:1 — identity unconfirmed: scanned by reference") {
		t.Errorf("expected the unresolved-identity warning on the image heading:\n%s", out)
	}

	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	img := p["actionable"].([]any)[0].(map[string]any)
	if img["identity_resolved"] != false {
		t.Errorf("identity_resolved = %v, want false", img["identity_resolved"])
	}
	if img["scan_target_kind"] != "reference" {
		t.Errorf("scan_target_kind = %v, want reference", img["scan_target_kind"])
	}
	if _, present := img["content_id"]; present {
		t.Errorf("content_id should be omitted when unresolved, got %v", img["content_id"])
	}
	digests, _ := img["registry_digests"].([]any)
	if len(digests) != 0 {
		t.Errorf("the fallback scan's own digest must not leak into registry_digests, got %v", digests)
	}
}

// TestIdentity_MixedResolvedAndFallbackUnderSameRef verifies that
// identity_resolved/scan_target_kind must be entity-level (this
// ImageFindings' own ContentID), not the reference's aggregate
// IdentityResolved. A reference running one entity Docker resolved a
// ContentID for alongside a sibling entity that fell back to reference
// scanning makes the aggregate analyze.ImageObservation.IdentityResolved
// false for the whole reference — but the resolved entity's own
// payload/Slack line must still say resolved, and only the fallback
// entity's line gets the "unconfirmed" treatment.
func TestIdentity_MixedResolvedAndFallbackUnderSameRef(t *testing.T) {
	cid := "sha256:" + strings.Repeat("e", 64)
	scans := []scanner.ImageScan{
		{Image: "mixed:1", ExpectedContentID: cid, Findings: []scanner.Finding{
			{Image: "mixed:1", Class: scanner.ClassOS, Package: "libssl", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-RESOLVED"},
		}},
		{Image: "mixed:1", Findings: []scanner.Finding{ // no ExpectedContentID: reference-fallback sibling
			{Image: "mixed:1", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-FALLBACK"},
		}},
	}
	r := analyze.Build(scans, analyze.Triage{}, genTime)

	// Sanity-check the premise: the reference's aggregate IdentityResolved is
	// false because one of its two entities never resolved.
	var refObs analyze.ImageObservation
	for _, o := range r.Images {
		if o.Ref == "mixed:1" {
			refObs = o
		}
	}
	if refObs.IdentityResolved {
		t.Fatal("test premise broken: expected the mixed reference's aggregate IdentityResolved to be false")
	}

	// Slack: the inline heading annotation must attach only to the fallback
	// entity's heading line, not the resolved entity's. The reference-level
	// cross-cutting summary (writeUnresolvedRefs) is expected to *also*
	// mention mixed:1 (it has an unresolved entity) — that doubling-up is
	// correct, not a bug.
	out := FormatSlackText(r)
	if n := strings.Count(out, "mixed:1 — identity unconfirmed: scanned by reference"); n != 1 {
		t.Errorf("expected the unresolved warning on exactly the fallback entity's heading, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "mixed:1  CRITICAL") {
		t.Errorf("expected the resolved entity's heading to render plainly (no warning, no digest):\n%s", out)
	}
	if !strings.Contains(out, "⚠️ identity unconfirmed: scanned by reference — mixed:1") {
		t.Errorf("expected the cross-cutting unresolved-refs summary to list mixed:1:\n%s", out)
	}

	// Webhook: each entity's own payload entry must carry its own verdict.
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var resolvedEntry, fallbackEntry map[string]any
	for _, a := range p["actionable"].([]any) {
		m := a.(map[string]any)
		findings := m["findings"].([]any)
		pkg := findings[0].(map[string]any)["package"]
		switch pkg {
		case "libssl":
			resolvedEntry = m
		case "zlib":
			fallbackEntry = m
		}
	}
	if resolvedEntry == nil || fallbackEntry == nil {
		t.Fatalf("expected one actionable entry per entity, got %v", p["actionable"])
	}

	if resolvedEntry["content_id"] != cid {
		t.Errorf("resolved entity content_id = %v, want %v", resolvedEntry["content_id"], cid)
	}
	if resolvedEntry["identity_resolved"] != true {
		t.Errorf("resolved entity identity_resolved = %v, want true (must not inherit the sibling's unresolved status)", resolvedEntry["identity_resolved"])
	}
	if resolvedEntry["scan_target_kind"] != "content_id" {
		t.Errorf("resolved entity scan_target_kind = %v, want content_id", resolvedEntry["scan_target_kind"])
	}

	if _, present := fallbackEntry["content_id"]; present {
		t.Errorf("fallback entity content_id should be omitted, got %v", fallbackEntry["content_id"])
	}
	if fallbackEntry["identity_resolved"] != false {
		t.Errorf("fallback entity identity_resolved = %v, want false", fallbackEntry["identity_resolved"])
	}
	if fallbackEntry["scan_target_kind"] != "reference" {
		t.Errorf("fallback entity scan_target_kind = %v, want reference", fallbackEntry["scan_target_kind"])
	}
}

// TestFormatSlackText_TriageUnresolvedWarning is the same warning wired
// through the triage-mode act-now bucket (writeActNow), not just the
// non-triage writeActionable path.
func TestFormatSlackText_TriageUnresolvedWarning(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "legacy:1",
		Findings: []scanner.Finding{
			{Image: "legacy:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-K"},
		},
	}}
	out := FormatSlackText(analyze.Build(scans, triageRules(map[string]analyze.Enrichment{"CVE-K": {KEV: true}}), genTime))
	if !strings.Contains(out, "legacy:1 — identity unconfirmed: scanned by reference") {
		t.Errorf("expected the unresolved-identity warning in the triage act-now heading:\n%s", out)
	}
}

// TestBuildThreadMessages_UnresolvedIdentityWarning wires the same warning
// through the thread report (threadBucket).
func TestBuildThreadMessages_UnresolvedIdentityWarning(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "legacy:1",
		Findings: []scanner.Finding{
			{Image: "legacy:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
		},
	}}
	r := analyze.Build(scans, analyze.Triage{}, genTime)
	out := strings.Join(BuildThreadMessages(r, nil, 0), "\n")
	if !strings.Contains(out, "legacy:1 — identity unconfirmed: scanned by reference") {
		t.Errorf("expected the unresolved-identity warning in the thread report:\n%s", out)
	}
}

// --- Slack: ambiguous-reference digest annotation ---

// TestFormatSlackText_AmbiguousDigest: when the same reference runs more than
// one distinct, verified entity at once, each section entry's heading carries
// its short content digest so the reader can tell them apart.
func TestFormatSlackText_AmbiguousDigest(t *testing.T) {
	cidA := "sha256:" + strings.Repeat("a", 64)
	cidB := "sha256:" + strings.Repeat("b", 64)
	scans := []scanner.ImageScan{
		{Image: "nginx:latest", ExpectedContentID: cidA, Findings: []scanner.Finding{
			{Image: "nginx:latest", Class: scanner.ClassOS, Package: "libssl", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-A"},
		}},
		{Image: "nginx:latest", ExpectedContentID: cidB, Findings: []scanner.Finding{
			{Image: "nginx:latest", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-B"},
		}},
	}
	r := analyze.Build(scans, analyze.Triage{}, genTime)
	out := FormatSlackText(r)

	wantA := "nginx:latest (" + strings.Repeat("a", 12) + ")"
	wantB := "nginx:latest (" + strings.Repeat("b", 12) + ")"
	if !strings.Contains(out, wantA) {
		t.Errorf("expected the ambiguous heading %q:\n%s", wantA, out)
	}
	if !strings.Contains(out, wantB) {
		t.Errorf("expected the ambiguous heading %q:\n%s", wantB, out)
	}
}

// TestFormatSlackText_SingleEntityNoDigestSuffix: the ordinary, single-entity
// case (the vast majority) must render exactly as before — no digest suffix —
// even though its ContentID is resolved and non-empty.
func TestFormatSlackText_SingleEntityNoDigestSuffix(t *testing.T) {
	cid := "sha256:" + strings.Repeat("c", 64)
	scans := []scanner.ImageScan{{
		Image: "app:1", ExpectedContentID: cid, Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
		},
	}}
	r := analyze.Build(scans, analyze.Triage{}, genTime)
	out := FormatSlackText(r)
	if strings.Contains(out, strings.Repeat("c", 12)) {
		t.Errorf("a single resolved entity must not show its digest:\n%s", out)
	}
	if !strings.Contains(out, "app:1  CRITICAL") {
		t.Errorf("expected the unmodified heading for the ordinary case:\n%s", out)
	}
}

// --- diff-mode Ref-level identity annotations ---
//
// state.Change/state.Resolved only ever carry a bare reference string (diff
// history stays reference-keyed on purpose), so the per-entity ContentID
// that imageLabel uses cannot be restored there. refLabel instead annotates
// using the reference's aggregate analyze.ImageObservation.IdentityResolved:
// "does any entity currently running under this reference have an
// unresolved identity this cycle".

// TestFormatSlackDiffText_UnresolvedRefAnnotation_Changes covers the Changes
// heading line for an unresolved reference.
func TestFormatSlackDiffText_UnresolvedRefAnnotation_Changes(t *testing.T) {
	scan := scanner.ImageScan{Image: "legacy:1", Findings: []scanner.Finding{
		{Image: "legacy:1", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
	}}
	r := analyze.Build([]scanner.ImageScan{scan}, analyze.Triage{}, genTime)
	d, _ := state.Compute(state.State{}, r)
	out := FormatSlackDiffText(r, d, false)

	if !strings.Contains(out, "New since last scan") {
		t.Fatalf("expected a Changes section:\n%s", out)
	}
	if !strings.Contains(out, "legacy:1 — identity unconfirmed: scanned by reference") {
		t.Errorf("expected the unresolved warning on the Changes heading line:\n%s", out)
	}
}

// TestFormatSlackDiffText_UnresolvedRefAnnotation_Resolved covers the
// Resolved line: a package that disappeared from a still-unresolved
// reference must carry the warning too.
func TestFormatSlackDiffText_UnresolvedRefAnnotation_Resolved(t *testing.T) {
	prevState := state.State{Version: 1, Findings: map[string]state.Entry{
		"legacy:1\topenssl": {FirstSeen: genTime, Fixable: true, VulnIDs: []string{"CVE-1"}},
	}, EOSL: map[string]time.Time{}}
	// This cycle's scan of the same (still unresolved) reference is clean:
	// the package resolved, but its identity is still never confirmed.
	r := analyze.Build([]scanner.ImageScan{{Image: "legacy:1"}}, analyze.Triage{}, genTime)
	d, _ := state.Compute(prevState, r)
	out := FormatSlackDiffText(r, d, false)

	if !strings.Contains(out, "Resolved since last scan") {
		t.Fatalf("expected a Resolved section:\n%s", out)
	}
	if !strings.Contains(out, "legacy:1 — identity unconfirmed: scanned by reference: openssl") {
		t.Errorf("expected the unresolved warning on the Resolved line:\n%s", out)
	}
}

// TestFormatSlackDiffText_AmbiguousRefNoDigest: an Ambiguous reference's diff
// line is a reference-wide union across every entity running there, so it
// must never carry a single entity's short digest — only imageLabel's
// per-entity view (the full-body headings) can do that meaningfully.
func TestFormatSlackDiffText_AmbiguousRefNoDigest(t *testing.T) {
	cidA := "sha256:" + strings.Repeat("a", 64)
	cidB := "sha256:" + strings.Repeat("b", 64)
	scans := []scanner.ImageScan{
		{Image: "nginx:latest", ExpectedContentID: cidA, Findings: []scanner.Finding{
			{Image: "nginx:latest", Class: scanner.ClassOS, Package: "libssl", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-A"},
		}},
		{Image: "nginx:latest", ExpectedContentID: cidB, Findings: []scanner.Finding{
			{Image: "nginx:latest", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-B"},
		}},
	}
	r := analyze.Build(scans, analyze.Triage{}, genTime)
	d, _ := state.Compute(state.State{}, r)
	out := FormatSlackDiffText(r, d, false)

	if !strings.Contains(out, "New since last scan") {
		t.Fatalf("expected a Changes section:\n%s", out)
	}
	if strings.Contains(out, shortDigest(cidA)) || strings.Contains(out, shortDigest(cidB)) {
		t.Errorf("an Ambiguous reference's diff line must not carry a per-entity digest:\n%s", out)
	}
	// Both entities resolved (just to different content), so the reference
	// itself is not "unresolved" and must not show the warning either.
	if strings.Contains(out, "identity unconfirmed") {
		t.Errorf("a fully-resolved (if ambiguous) reference must not show the unresolved warning:\n%s", out)
	}
}

// --- clean/EOSL/scan-error identity coverage ---

// TestFormatSlackText_CleanUnresolvedStillWarns is a regression test: a
// report with zero findings, built entirely from an unresolved
// (reference-fallback) scan, must not silently say "All clear" with no
// mention of the unconfirmed identity.
func TestFormatSlackText_CleanUnresolvedStillWarns(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "legacy:1"}}, analyze.Triage{}, genTime)
	if r.HasIssues() {
		t.Fatal("test premise broken: expected a clean report with no issues")
	}
	out := FormatSlackText(r)
	if !strings.Contains(out, "All clear") {
		t.Errorf("expected the All clear line to still be present:\n%s", out)
	}
	if !strings.Contains(out, "⚠️ identity unconfirmed: scanned by reference — legacy:1") {
		t.Errorf("expected the unresolved-refs summary even on an all-clear report:\n%s", out)
	}
}

// TestFormatSlackText_TriageCleanUnresolvedStillWarns is the same check with
// triage on, exercising FormatSlackText's shared (mode-agnostic) All-clear
// short-circuit.
func TestFormatSlackText_TriageCleanUnresolvedStillWarns(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "legacy:1"}}, triageRules(nil), genTime)
	out := FormatSlackText(r)
	if !strings.Contains(out, "⚠️ identity unconfirmed: scanned by reference — legacy:1") {
		t.Errorf("expected the unresolved-refs summary in triage mode too:\n%s", out)
	}
}

// TestFormatSlackDiffText_CleanUnresolvedStillWarns is the diff-mode
// (heartbeat / "No changes") counterpart.
func TestFormatSlackDiffText_CleanUnresolvedStillWarns(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "legacy:1"}}, analyze.Triage{}, genTime)
	d, _ := state.Compute(state.State{}, r)
	out := FormatSlackDiffText(r, d, false)
	if !strings.Contains(out, "⚠️ identity unconfirmed: scanned by reference — legacy:1") {
		t.Errorf("expected the unresolved-refs summary on the diff heartbeat:\n%s", out)
	}
}

// TestFormatSlackText_EOSLUnresolvedRef: an EOSL base-image warning for an
// unresolved reference must carry the same annotation inline.
func TestFormatSlackText_EOSLUnresolvedRef(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "legacy:1", OSEOSL: true}}, analyze.Triage{}, genTime)
	out := FormatSlackText(r)
	if !strings.Contains(out, "legacy:1 — identity unconfirmed: scanned by reference — base OS is EOL") {
		t.Errorf("expected the unresolved warning inline on the EOSL line:\n%s", out)
	}
}

// TestFormatSlackText_ScanErrorUnresolvedRef: a scan-failure line for an
// unresolved reference must carry the same annotation inline.
func TestFormatSlackText_ScanErrorUnresolvedRef(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "legacy:1", Err: errString("pull failed")}}, analyze.Triage{}, genTime)
	out := FormatSlackText(r)
	if !strings.Contains(out, "legacy:1 — identity unconfirmed: scanned by reference — pull failed") {
		t.Errorf("expected the unresolved warning inline on the scan-error line:\n%s", out)
	}
}

// TestBuildThreadMessages_UnresolvedRefsSummarySection wires the same
// cross-cutting summary into the thread report.
func TestBuildThreadMessages_UnresolvedRefsSummarySection(t *testing.T) {
	scans := []scanner.ImageScan{{
		Image: "legacy:1",
		Findings: []scanner.Finding{
			{Image: "legacy:1", Class: scanner.ClassOS, Package: "libx", InstalledVer: "1.0", FixedVer: "1.1", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
		},
	}}
	r := analyze.Build(scans, analyze.Triage{}, genTime)
	out := strings.Join(BuildThreadMessages(r, nil, 0), "\n")
	if !strings.Contains(out, "⚠️ identity unconfirmed: scanned by reference — legacy:1") {
		t.Errorf("expected the cross-cutting unresolved-refs summary section in the thread report:\n%s", out)
	}
}
