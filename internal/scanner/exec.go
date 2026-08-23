package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Trivy runs the Trivy CLI. The binary is shelled out to (ADR-002) rather than
// linked as a library, so Trivy can be upgraded independently of KestreLynx.
type Trivy struct {
	// BinPath is the trivy executable; empty means look it up on PATH.
	BinPath string
	// Severity is passed to --severity. Empty means HIGH,CRITICAL.
	Severity []string
}

// New returns a Trivy with KestreLynx defaults (HIGH/CRITICAL, trivy on PATH).
func New() Trivy {
	return Trivy{Severity: []string{"HIGH", "CRITICAL"}}
}

func (t Trivy) bin() string {
	if t.BinPath != "" {
		return t.BinPath
	}
	return "trivy"
}

func (t Trivy) severity() string {
	if len(t.Severity) == 0 {
		return "HIGH,CRITICAL"
	}
	return strings.Join(t.Severity, ",")
}

// trivyArgs builds the CLI arguments for scanning target. When ContentID is
// set, the scan is pinned to that content and restricted to the local Docker
// image store (--image-src docker) so Trivy can never resolve a different
// image than the one Docker reported running. The Ref-only fallback path
// keeps its arguments exactly as before (existing behavior; no
// --image-src is added).
func (t Trivy) trivyArgs(target ScanTarget) []string {
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--severity", t.severity(),
	}
	if target.ContentID != "" {
		return append(args, "--image-src", "docker", target.ContentID)
	}
	return append(args, target.Ref)
}

// reconcileTarget applies the Expected/Scanned identity check to a freshly
// parsed report for a ContentID-pinned scan: a mismatch is an environment
// anomaly, not a finding, so it is surfaced as a scan error rather than
// attributed to the running content.
// scan.Image is always pinned to target.Ref (ArtifactName is the sha256
// string for ContentID-pinned scans, confirmed in production).
func reconcileTarget(scan ImageScan, target ScanTarget) ImageScan {
	scan.Image = target.Ref
	scan.ExpectedContentID = target.ContentID
	scan.IdentityResolved = target.ContentID != ""
	if target.ContentID != "" && scan.ContentID != target.ContentID {
		return ImageScan{
			Image:             target.Ref,
			ExpectedContentID: target.ContentID,
			ContentID:         scan.ContentID,
			IdentityResolved:  true,
			Err: fmt.Errorf("trivy scan %s: scanned content %q does not match expected %q",
				target.Ref, scan.ContentID, target.ContentID),
		}
	}
	return scan
}

// Scan scans a single image target. A scan failure (e.g. the image cannot be
// pulled) is reported via ImageScan.Err rather than a returned error, so one bad
// image never aborts a whole run; callers iterate and surface Err per image.
func (t Trivy) Scan(ctx context.Context, target ScanTarget) ImageScan {
	args := t.trivyArgs(target)
	scanArg := args[len(args)-1]

	cmd := exec.CommandContext(ctx, t.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return ImageScan{
			Image:             target.Ref,
			ExpectedContentID: target.ContentID,
			IdentityResolved:  target.ContentID != "",
			Err:               fmt.Errorf("trivy scan %s: %w: %s", scanArg, err, strings.TrimSpace(stderr.String())),
		}
	}

	scan, err := ParseReport(stdout.Bytes())
	if err != nil {
		return ImageScan{
			Image:             target.Ref,
			ExpectedContentID: target.ContentID,
			IdentityResolved:  target.ContentID != "",
			Err:               fmt.Errorf("trivy scan %s: %w", scanArg, err),
		}
	}
	return reconcileTarget(scan, target)
}
