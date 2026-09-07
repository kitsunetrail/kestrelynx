package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
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

// pinnedByConfig reports whether target asks for the Docker-style pinned
// invocation: a resolved Subject whose entity key is a config digest. This
// is the sole gate for both the trivyArgs pinned branch and the
// reconcileTarget mismatch check, so the two can never disagree about
// whether a given target was pinned.
func pinnedByConfig(target ScanTarget) bool {
	return target.Subject.Resolved && target.Subject.Key.Digest.Kind == inventory.DigestConfig
}

// trivyArgs builds the CLI arguments for scanning target. When the target is
// pinned to a config digest, the scan is restricted to the local Docker
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
	if pinnedByConfig(target) {
		return append(args, "--image-src", "docker", target.Subject.Key.Digest.String())
	}
	return append(args, target.Subject.Ref)
}

// pinnedOf derives ImageScan.Pinned: Subject.Resolved, the scan succeeded,
// and the entity Trivy actually scanned matches the one requested. It is the
// only place Pinned is computed.
func pinnedOf(scan ImageScan, target ScanTarget) bool {
	return target.Subject.Resolved && scan.Err == nil && scan.ScannedKey == target.Subject.Key
}

// reconcileTarget applies the pin check to a freshly parsed report for a
// config-digest-pinned scan target: a mismatch is an environment anomaly,
// not a finding, so it is surfaced as a scan error rather than attributed to
// the running content.
// scan.Image is always pinned to target.Subject.Ref (ArtifactName is the
// sha256 string for a pinned scan, confirmed in production).
func reconcileTarget(scan ImageScan, target ScanTarget) ImageScan {
	scan.Image = target.Subject.Ref
	scan.Subject = target.Subject
	scan.Source = target.Source
	if pinnedByConfig(target) && scan.ScannedKey != target.Subject.Key {
		return ImageScan{
			Image:      target.Subject.Ref,
			Subject:    target.Subject,
			Source:     target.Source,
			ScannedKey: scan.ScannedKey,
			Err: fmt.Errorf("trivy scan %s: scanned content %q does not match expected %q",
				target.Subject.Ref, scan.ScannedKey.Digest.String(), target.Subject.Key.Digest.String()),
		}
	}
	scan.Pinned = pinnedOf(scan, target)
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
			Image:   target.Subject.Ref,
			Subject: target.Subject,
			Source:  target.Source,
			Err:     fmt.Errorf("trivy scan %s: %w: %s", scanArg, err, strings.TrimSpace(stderr.String())),
		}
	}

	scan, err := ParseReport(stdout.Bytes())
	if err != nil {
		return ImageScan{
			Image:   target.Subject.Ref,
			Subject: target.Subject,
			Source:  target.Source,
			Err:     fmt.Errorf("trivy scan %s: %w", scanArg, err),
		}
	}
	return reconcileTarget(scan, target)
}
