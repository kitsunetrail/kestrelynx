// Tests locking the additive-only contract for the unconfirmed/holding
// rendering: with analyze.Report.UnconfirmedRefs nil (always the case for
// Docker) and holding false, every touched renderer must contribute exactly
// zero new bytes relative to its prior output.
package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func TestWriteUnresolvedRefs_UnconfirmedRefsNilAddsNoBytes(t *testing.T) {
	r := sampleReport()
	if r.UnconfirmedRefs != nil {
		t.Fatal("test premise broken: want a nil UnconfirmedRefs report")
	}
	var b strings.Builder
	writeUnresolvedRefs(&b, r)
	if strings.Contains(b.String(), "⏳") {
		t.Errorf("unconfirmedRefsLine must contribute nothing when UnconfirmedRefs is nil:\n%s", b.String())
	}
}

func TestWriteOpenNow_HoldingFalseUnchanged(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "ok:1"}}, nil, analyze.Triage{}, genTime)
	d, _ := state.Compute(state.State{}, r)
	var b strings.Builder
	writeOpenNow(&b, r, d, false)
	want := "\n🎉 Open now: none — all clear\n"
	if b.String() != want {
		t.Errorf("writeOpenNow(holding=false) = %q, want %q (byte-identical to pre-holding output)", b.String(), want)
	}
}

// TestBuildWebhookPayload_RegistryDigestScanTargetKind exercises the third
// scan_target_kind value a registry-digest-pinned entity produces: it is not
// reachable via the Docker adapter (which never resolves a registry-kind
// digest), but the webhook mapping must still be correct now that Pinned is
// derived from any identity kind, not just a config digest — content_id
// stays omitted (ContentID() only ever projects a config digest).
func TestBuildWebhookPayload_RegistryDigestScanTargetKind(t *testing.T) {
	reg, ok := inventory.ParseDigest(inventory.DigestRegistry, "sha256:"+strings.Repeat("a", 64))
	if !ok {
		t.Fatal("test fixture: invalid digest")
	}
	key := inventory.EntityKey{Digest: reg, Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}}
	scans := []scanner.ImageScan{{
		Image:      "app:1",
		Subject:    inventory.ImageSubject{Ref: "app:1", Key: key, Resolved: true},
		ScannedKey: key,
		Pinned:     true,
		Source:     scanner.SourceRemote,
		Findings: []scanner.Finding{
			{Image: "app:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
		},
	}}
	r := analyze.Build(scans, nil, analyze.Triage{}, genTime)
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	img := p["actionable"].([]any)[0].(map[string]any)
	if img["scan_target_kind"] != "registry_digest" {
		t.Errorf("scan_target_kind = %v, want registry_digest", img["scan_target_kind"])
	}
	if img["identity_resolved"] != true {
		t.Errorf("identity_resolved = %v, want true", img["identity_resolved"])
	}
	if _, present := img["content_id"]; present {
		t.Errorf("content_id must stay omitted for a registry-digest entity, got %v", img["content_id"])
	}
}

// TestImageLabel_AmbiguousRegistryDigestCarriesPlatform: unlike a config
// digest, a registry digest does not pin a platform on its own, so the
// ambiguous-heading digest annotation must carry the platform alongside it
// or two entities could show the identical short digest.
func TestImageLabel_AmbiguousRegistryDigestCarriesPlatform(t *testing.T) {
	reg, ok := inventory.ParseDigest(inventory.DigestRegistry, "sha256:"+strings.Repeat("a", 64))
	if !ok {
		t.Fatal("test fixture: invalid digest")
	}
	img := analyze.ImageFindings{
		Image: "app:1",
		Subject: inventory.ImageSubject{
			Ref:      "app:1",
			Key:      inventory.EntityKey{Digest: reg, Platform: inventory.Platform{OS: "linux", Architecture: "arm64"}},
			Resolved: true,
		},
		Pinned: true,
	}
	byRef := map[string]analyze.ImageObservation{"app:1": {Ref: "app:1", Ambiguous: true}}
	got := imageLabel(img, byRef)
	want := "app:1 (" + strings.Repeat("a", 12) + " linux/arm64)"
	if got != want {
		t.Errorf("imageLabel = %q, want %q", got, want)
	}
}

func TestWriteTriageOpenNow_HoldingFalseUnchanged(t *testing.T) {
	r := analyze.Build(nil, nil, triageRules(nil), genTime)
	if !r.Triage {
		t.Fatal("test premise broken: want a triaged report")
	}
	d, _ := state.Compute(state.State{}, r)
	var b strings.Builder
	writeTriageOpenNow(&b, r, d, false)
	want := "\n🎉 Open now: none — all clear\n"
	if b.String() != want {
		t.Errorf("writeTriageOpenNow(holding=false) = %q, want %q", b.String(), want)
	}
}
