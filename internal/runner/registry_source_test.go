package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// mustRegistryDigest parses s as a registry-kind digest or fails the test —
// only ever used to build well-formed test fixtures, never production data.
func mustRegistryDigest(t *testing.T, s string) inventory.Digest {
	t.Helper()
	d, ok := inventory.ParseDigest(inventory.DigestRegistry, s)
	if !ok {
		t.Fatalf("test fixture: invalid digest %q", s)
	}
	return d
}

// TestScanAll_RegistryEntity_PropagatesSourceAndRegistry is regression test
// (a): a registry-digest entity (no config digest, a valid registry digest,
// and a known platform — the shape a Kubernetes-observed running image
// resolves to) scanned by a Runner configured with Source: SourceRemote must
// reach the Scanner as a ScanTarget carrying both Source == SourceRemote and
// the Registry reference, not the SourceLocal/zero-Registry the pre-fix code
// hard-coded for every target regardless of adapter.
func TestScanAll_RegistryEntity_PropagatesSourceAndRegistry(t *testing.T) {
	digest := mustRegistryDigest(t, "sha256:"+strings.Repeat("a", 64))
	img := inventory.RunningImage{
		Ref:      "app:v1",
		Registry: inventory.RegistryRef{Repository: "example.com/app", Digest: digest},
		Platform: inventory.Platform{OS: "linux", Architecture: "amd64"},
	}

	sc := &fakeScanner{}
	r := Runner{Scanner: sc, Source: scanner.SourceRemote, Now: clock}

	scans := r.scanAll(context.Background(), []inventory.RunningImage{img})

	if len(scans) != 1 {
		t.Fatalf("scans = %d, want 1", len(scans))
	}
	if len(sc.calls) != 1 {
		t.Fatalf("Scan called %d times, want 1", len(sc.calls))
	}
	target := sc.calls[0]
	if !target.Subject.Resolved {
		t.Fatal("test premise broken: entity should resolve to a registry EntityKey")
	}
	if target.Source != scanner.SourceRemote {
		t.Errorf("ScanTarget.Source = %q, want %q", target.Source, scanner.SourceRemote)
	}
	if target.Registry != img.Registry {
		t.Errorf("ScanTarget.Registry = %+v, want %+v", target.Registry, img.Registry)
	}
}

// TestScanAll_UnresolvedEntity_PropagatesSource is regression test (b): an
// entity that resolves neither a config digest nor a registry digest (both
// invalid — e.g. a bare digest fixture that never got imported into the
// local store) still goes through the unresolved (per-reference, never
// EntityKey-deduplicated) path, but must still carry the Runner's Source —
// analyze's unconfirmed-holding contract (docs/development, ScanSource ==
// SourceRemote) depends on every target for that adapter saying so, resolved
// or not.
func TestScanAll_UnresolvedEntity_PropagatesSource(t *testing.T) {
	img := inventory.RunningImage{Ref: "bare@sha256:" + strings.Repeat("b", 64)}

	sc := &fakeScanner{}
	r := Runner{Scanner: sc, Source: scanner.SourceRemote, Now: clock}

	scans := r.scanAll(context.Background(), []inventory.RunningImage{img})

	if len(scans) != 1 {
		t.Fatalf("scans = %d, want 1", len(scans))
	}
	if len(sc.calls) != 1 {
		t.Fatalf("Scan called %d times, want 1", len(sc.calls))
	}
	target := sc.calls[0]
	if target.Subject.Resolved {
		t.Fatal("test premise broken: entity should be unresolved (both digests invalid)")
	}
	if target.Source != scanner.SourceRemote {
		t.Errorf("ScanTarget.Source = %q, want %q (Source must propagate even on the unresolved path)", target.Source, scanner.SourceRemote)
	}
}

// TestScanAll_DockerRunner_ZeroSourceStaysLocal is regression test (c): a
// Runner that never sets Source (every existing Docker caller, including
// every other test in this package) must keep scanning as SourceLocal with a
// zero-value Registry — the zero value normalizes to SourceLocal so this
// field's addition changes nothing for Docker.
func TestScanAll_DockerRunner_ZeroSourceStaysLocal(t *testing.T) {
	cid := "sha256:" + strings.Repeat("c", 64)
	cfg, ok := inventory.ParseDigest(inventory.DigestConfig, cid)
	if !ok {
		t.Fatalf("test fixture: invalid digest %q", cid)
	}
	img := inventory.RunningImage{Ref: "app:v1", Config: cfg}

	sc := &fakeScanner{}
	r := Runner{Scanner: sc, Now: clock} // Source left unset

	r.scanAll(context.Background(), []inventory.RunningImage{img})

	if len(sc.calls) != 1 {
		t.Fatalf("Scan called %d times, want 1", len(sc.calls))
	}
	target := sc.calls[0]
	if target.Source != scanner.SourceLocal {
		t.Errorf("ScanTarget.Source = %q, want %q (zero Runner.Source)", target.Source, scanner.SourceLocal)
	}
	if target.Registry != (inventory.RegistryRef{}) {
		t.Errorf("ScanTarget.Registry = %+v, want zero value for Docker", target.Registry)
	}
}

// writeFakeTrivy creates an executable shell script that records every
// argument it is invoked with (one per line, in order) to argsFile, then
// prints stdout and exits 0. It stands in for the real trivy binary via
// scanner.Trivy.BinPath, exercising the real trivyArgs/Scan code path
// end-to-end rather than reimplementing it.
func writeFakeTrivy(t *testing.T, argsFile, stdout string) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "trivy")
	stdoutFile := filepath.Join(dir, "stdout.json")
	if err := os.WriteFile(stdoutFile, []byte(stdout), 0o644); err != nil {
		t.Fatalf("write stdout fixture: %v", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
: > %q
for a in "$@"; do printf '%%s\n' "$a" >> %q; done
cat %q
`, argsFile, argsFile, stdoutFile)
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

// TestScanAll_RegistryEntity_Integration_TrivyArgsRemotePin guards the
// *boundary* between runner and scanner: the existing tests exercised each
// package alone (scanAll's ScanTarget shape, scanner.trivyArgs's output for
// a hand-built target) and never verified the wiring between them, which is
// where the target's Source and Registry can silently go missing (defect
// found in real-environment verification). This test drives the real
// scanner.Trivy through runner.scanAll end-to-end — a real *exec.Cmd
// invocation of a fake "trivy" binary — and pins the resulting CLI argument
// list to exactly the pinnedByRegistry shape
// (docs/development/image-identity-model.md): --image-src remote,
// --platform <os>/<arch>, and a positional repo@digest built from
// RunningImage.Registry.
func TestScanAll_RegistryEntity_Integration_TrivyArgsRemotePin(t *testing.T) {
	digest := mustRegistryDigest(t, "sha256:"+strings.Repeat("d", 64))
	img := inventory.RunningImage{
		Ref:      "app:v1",
		Registry: inventory.RegistryRef{Repository: "example.com/app", Digest: digest},
		Platform: inventory.Platform{OS: "linux", Architecture: "amd64"},
	}

	argsFile := filepath.Join(t.TempDir(), "args.txt")
	// The fake report confirms the requested registry digest and platform
	// (Metadata.RepoDigests + ImageConfig), the shape reconcileTarget needs
	// to accept the scan as pinned — so a wiring bug that fed the wrong
	// repository or platform into trivyArgs would surface as either a
	// mismatched recorded argument (checked below) or a scan error here.
	stdout := fmt.Sprintf(`{"ArtifactName":"whatever","Metadata":{"RepoDigests":["example.com/app@%s"],"ImageConfig":{"os":"linux","architecture":"amd64"}},"Results":[]}`, digest.String())
	bin := writeFakeTrivy(t, argsFile, stdout)

	r := Runner{
		Scanner: scanner.Trivy{BinPath: bin, Severity: []string{"HIGH", "CRITICAL"}},
		Source:  scanner.SourceRemote,
		Now:     clock,
	}

	scans := r.scanAll(context.Background(), []inventory.RunningImage{img})
	if len(scans) != 1 {
		t.Fatalf("scans = %d, want 1", len(scans))
	}
	if scans[0].Err != nil {
		t.Fatalf("scan: %v", scans[0].Err)
	}
	if !scans[0].Pinned {
		t.Error("scan should be Pinned: the fake report confirms the requested registry digest and platform")
	}

	gotArgs := readArgs(t, argsFile)
	wantArgs := []string{
		"image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL",
		"--image-src", "remote", "--platform", "linux/amd64",
		"example.com/app@" + digest.String(),
	}
	if strings.Join(gotArgs, "|") != strings.Join(wantArgs, "|") {
		t.Errorf("trivy args = %v, want %v", gotArgs, wantArgs)
	}
}
