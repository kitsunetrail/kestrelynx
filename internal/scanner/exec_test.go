package scanner

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

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

	scan := New().Scan(ctx, "alpine:3.12")
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

	scan := New().Scan(ctx, "kestrelynx.invalid/does-not-exist:0")
	if scan.Err == nil {
		t.Fatal("expected Err for unresolvable image, got nil")
	}
	if scan.Image != "kestrelynx.invalid/does-not-exist:0" {
		t.Errorf("Image = %q, want the requested ref even on failure", scan.Image)
	}
}
