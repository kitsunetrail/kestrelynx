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

// Scan scans a single image reference. A scan failure (e.g. the image cannot be
// pulled) is reported via ImageScan.Err rather than a returned error, so one bad
// image never aborts a whole run; callers iterate and surface Err per image.
func (t Trivy) Scan(ctx context.Context, image string) ImageScan {
	args := []string{
		"image",
		"--quiet",
		"--format", "json",
		"--severity", t.severity(),
		image,
	}
	cmd := exec.CommandContext(ctx, t.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return ImageScan{Image: image, Err: fmt.Errorf("trivy scan %s: %w: %s", image, err, strings.TrimSpace(stderr.String()))}
	}

	scan, err := ParseReport(stdout.Bytes())
	if err != nil {
		return ImageScan{Image: image, Err: fmt.Errorf("trivy scan %s: %w", image, err)}
	}
	// Trivy's ArtifactName should equal the requested ref, but pin it to what we
	// asked for so downstream labelling is always the caller's reference.
	scan.Image = image
	return scan
}
