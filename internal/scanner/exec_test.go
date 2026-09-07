package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// pinnedTarget builds a ScanTarget pinned to a config digest, the shape
// runner.scanAll produces for a Docker-observed running entity.
func pinnedTarget(t *testing.T, ref, contentID string) ScanTarget {
	t.Helper()
	return ScanTarget{
		Subject: inventory.ImageSubject{
			Ref:      ref,
			Key:      inventory.EntityKey{Digest: mustParseDigest(t, contentID)},
			Resolved: true,
		},
		Source: SourceLocal,
	}
}

// refTarget builds an unresolved (reference-fallback) ScanTarget.
func refTarget(ref string) ScanTarget {
	return ScanTarget{Subject: inventory.ImageSubject{Ref: ref}, Source: SourceLocal}
}

// TestScan_Integration runs the real trivy binary against a tiny image.
// Skipped in -short mode or when trivy is not installed, so unit runs stay fast
// and hermetic. Requires network on first run (image pull + vuln DB).
func TestScan_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not on PATH; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	scan := New().Scan(ctx, refTarget("alpine:3.12"))
	if scan.Err != nil {
		t.Fatalf("Scan: %v", scan.Err)
	}
	if scan.Image != "alpine:3.12" {
		t.Errorf("Image = %q, want alpine:3.12", scan.Image)
	}
	if scan.OSFamily != "alpine" {
		t.Errorf("OSFamily = %q, want alpine", scan.OSFamily)
	}
	// Every returned finding must be well-formed.
	for _, f := range scan.Findings {
		if f.VulnID == "" || f.Package == "" {
			t.Errorf("malformed finding: %+v", f)
		}
	}
	t.Logf("alpine:3.12 -> %d findings (eosl=%v)", len(scan.Findings), scan.OSEOSL)
}

func TestScan_BadImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("trivy not on PATH; skipping")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	scan := New().Scan(ctx, refTarget("kestrelynx.invalid/does-not-exist:0"))
	if scan.Err == nil {
		t.Fatal("expected Err for unresolvable image, got nil")
	}
	if scan.Image != "kestrelynx.invalid/does-not-exist:0" {
		t.Errorf("Image = %q, want the requested ref even on failure", scan.Image)
	}
}

// --- trivyArgs ---

func TestTrivyArgs_ContentIDPinned(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	got := New().trivyArgs(pinnedTarget(t, "nginx:1.25", id))
	want := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "--image-src", "docker", id}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v, want %v", got, want)
	}
}

func TestTrivyArgs_RefFallbackUnchanged(t *testing.T) {
	got := New().trivyArgs(refTarget("nginx:1.25"))
	want := []string{"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "nginx:1.25"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v, want %v (Ref fallback must not change existing behavior)", got, want)
	}
}

// --- reconcileTarget: Expected/Scanned identity check ---

func TestReconcileTarget_ContentIDMismatchIsErr(t *testing.T) {
	expected := "sha256:" + strings.Repeat("a", 64)
	scanned := "sha256:" + strings.Repeat("b", 64)
	scan := ImageScan{Image: "ignored-artifact-name", ScannedKey: inventory.EntityKey{Digest: mustParseDigest(t, scanned)}}
	target := pinnedTarget(t, "nginx:1.25", expected)

	got := reconcileTarget(scan, target)
	if got.Err == nil {
		t.Fatal("expected Err on ContentID mismatch")
	}
	if !strings.Contains(got.Err.Error(), expected) || !strings.Contains(got.Err.Error(), scanned) {
		t.Errorf("Err should mention both expected and scanned content ids, got: %v", got.Err)
	}
	if got.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q even on mismatch", got.Image, target.Subject.Ref)
	}
	if !got.Subject.Resolved {
		t.Error("Subject.Resolved should be true: the scan was pinned, even though it mismatched")
	}
	if got.Pinned {
		t.Error("Pinned should be false on a mismatch")
	}
}

func TestReconcileTarget_ContentIDMatchOK(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	target := pinnedTarget(t, "nginx:1.25", id)
	scan := ImageScan{Image: "ignored-artifact-name", ScannedKey: target.Subject.Key, Findings: []Finding{{VulnID: "CVE-1"}}}

	got := reconcileTarget(scan, target)
	if got.Err != nil {
		t.Fatalf("unexpected Err: %v", got.Err)
	}
	if !got.Pinned {
		t.Error("Pinned should be true for a matching config-digest-pinned scan")
	}
	if got.Subject != target.Subject {
		t.Errorf("Subject = %+v, want %+v", got.Subject, target.Subject)
	}
	if got.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q (display name pinned to the reference)", got.Image, target.Subject.Ref)
	}
	if len(got.Findings) != 1 {
		t.Error("findings must be preserved on a match")
	}
}

func TestReconcileTarget_RefFallbackNotResolved(t *testing.T) {
	scan := ImageScan{Image: "ignored-artifact-name"}
	target := refTarget("nginx:1.25")

	got := reconcileTarget(scan, target)
	if got.Subject.Resolved {
		t.Error("Ref fallback scan must not report Subject.Resolved")
	}
	if got.Pinned {
		t.Error("Ref fallback scan must not report Pinned")
	}
	if got.Err != nil {
		t.Errorf("unexpected Err: %v", got.Err)
	}
	if got.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", got.Image, target.Subject.Ref)
	}
}

// --- Scan end-to-end against a fake trivy binary. These drive Trivy.Scan
// through its real exec.CommandContext path — argument construction, stdout
// parsing, and failure handling all together — without a real trivy binary,
// network, or Docker daemon.

// writeFakeTrivy creates an executable shell script at <tempdir>/trivy that
// records every argument it was invoked with (one per line, in order) to
// argsFile, then either prints stdout and exits 0, or prints to stderr and
// exits 1. It stands in for the trivy binary via Trivy.BinPath.
func writeFakeTrivy(t *testing.T, argsFile string, stdout string, fail bool) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "trivy")

	var script string
	if fail {
		script = fmt.Sprintf(`#!/bin/sh
: > %q
for a in "$@"; do printf '%%s\n' "$a" >> %q; done
echo "boom" >&2
exit 1
`, argsFile, argsFile)
	} else {
		stdoutFile := filepath.Join(dir, "stdout.json")
		if err := os.WriteFile(stdoutFile, []byte(stdout), 0o644); err != nil {
			t.Fatalf("write stdout fixture: %v", err)
		}
		script = fmt.Sprintf(`#!/bin/sh
: > %q
for a in "$@"; do printf '%%s\n' "$a" >> %q; done
cat %q
`, argsFile, argsFile, stdoutFile)
	}

	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	return binPath
}

// readArgs reads back the arguments writeFakeTrivy's script recorded.
func readArgs(t *testing.T, argsFile string) []string {
	t.Helper()
	data, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded args: %v", err)
	}
	trimmed := strings.TrimSuffix(string(data), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func trivyJSON(imageID string, repoDigests ...string) string {
	digests, err := json.Marshal(repoDigests)
	if err != nil {
		panic(err) // repoDigests is always a []string literal in test callers
	}
	return fmt.Sprintf(`{"ArtifactName":"whatever","Metadata":{"OS":{"Family":"debian","EOSL":false},"ImageID":%q,"RepoDigests":%s},"Results":[]}`, imageID, digests)
}

func TestScan_FakeBinary_ContentIDPinned_ArgsAndMatch(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "nginx:1.25", id)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, trivyJSON(id, "nginx@sha256:"+strings.Repeat("e", 64)), false)

	tr := Trivy{BinPath: bin, Severity: []string{"HIGH", "CRITICAL"}}
	scan := tr.Scan(context.Background(), target)

	if scan.Err != nil {
		t.Fatalf("Scan: %v", scan.Err)
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", scan.Image, target.Subject.Ref)
	}
	if scan.ScannedKey != target.Subject.Key {
		t.Errorf("ScannedKey = %+v, want %+v", scan.ScannedKey, target.Subject.Key)
	}
	if !scan.Pinned {
		t.Error("Pinned should be true for a matching config-digest-pinned scan")
	}

	gotArgs := readArgs(t, argsFile)
	wantArgs := tr.trivyArgs(target)
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Errorf("args recorded by the fake binary = %v, want %v (--image-src docker + positional ContentID)", gotArgs, wantArgs)
	}
}

func TestScan_FakeBinary_ContentIDPinned_Mismatch(t *testing.T) {
	expected := "sha256:" + strings.Repeat("c", 64)
	scanned := "sha256:" + strings.Repeat("d", 64)
	target := pinnedTarget(t, "nginx:1.25", expected)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, trivyJSON(scanned), false)

	tr := Trivy{BinPath: bin}
	scan := tr.Scan(context.Background(), target)

	if scan.Err == nil {
		t.Fatal("expected Err on ContentID mismatch")
	}
	if !strings.Contains(scan.Err.Error(), expected) || !strings.Contains(scan.Err.Error(), scanned) {
		t.Errorf("Err should mention both expected and scanned content ids, got: %v", scan.Err)
	}
	if scan.Pinned {
		t.Error("Pinned should be false on a mismatch")
	}
	if !scan.Subject.Resolved {
		t.Error("Subject.Resolved should be true: the scan was pinned, even though it mismatched")
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q even on mismatch", scan.Image, target.Subject.Ref)
	}
}

// Regression: a config-digest-pinned scan whose trivy process exits non-zero
// must still carry Subject on the returned ImageScan (with Pinned false),
// since downstream inventory / partial-failure / scan_target_kind logic
// reads them even on failure.
func TestScan_FakeBinary_ContentIDPinned_ExecFailure_PreservesIdentity(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "nginx:1.25", id)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, "", true)

	tr := Trivy{BinPath: bin}
	scan := tr.Scan(context.Background(), target)

	if scan.Err == nil {
		t.Fatal("expected Err when the trivy process fails")
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", scan.Image, target.Subject.Ref)
	}
	if scan.Subject != target.Subject {
		t.Errorf("Subject = %+v, want %+v (must survive exec failure)", scan.Subject, target.Subject)
	}
	if scan.Pinned {
		t.Error("Pinned should be false: the process failed")
	}
}

// Same regression, but for the JSON-parse-failure early return.
func TestScan_FakeBinary_ContentIDPinned_ParseFailure_PreservesIdentity(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "nginx:1.25", id)

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	bin := writeFakeTrivy(t, argsFile, "not valid json", false)

	tr := Trivy{BinPath: bin}
	scan := tr.Scan(context.Background(), target)

	if scan.Err == nil {
		t.Fatal("expected Err when trivy's output doesn't parse")
	}
	if scan.Image != target.Subject.Ref {
		t.Errorf("Image = %q, want %q", scan.Image, target.Subject.Ref)
	}
	if scan.Subject != target.Subject {
		t.Errorf("Subject = %+v, want %+v (must survive parse failure)", scan.Subject, target.Subject)
	}
	if scan.Pinned {
		t.Error("Pinned should be false: parsing failed")
	}
}
