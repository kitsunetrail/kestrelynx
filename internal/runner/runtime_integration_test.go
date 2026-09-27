package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// fakeInspector is a no-op Inspector: every container ID reports StartedAt/
// Pid as its zero value, so matchGeneration never confirms a generation —
// exactly the "no corroborating inspect available" case these tests want,
// since they are only checking that a bad or absent evidence file degrades
// safely, not exercising a successful match.
type fakeInspector struct{}

func (fakeInspector) Inspect(context.Context, string) (docker.InspectResult, error) {
	return docker.InspectResult{}, nil
}

// runtimeTestReport is the one-package fixture every test below scans: a
// single running container with one OS package finding, so RunOnce always
// has exactly one PackageGroup to check Runtime on.
func runtimeTestReport() (fakeLister, *fakeScanner) {
	container := inventory.Container{
		ID: strings.Repeat("1", 64),
		Image: inventory.RunningImage{
			Ref:    "web:1.0",
			Config: mustDigest("sha256:5555555555555555555555555555555555555555555555555555555555555555"),
		},
	}
	sc := &fakeScanner{byImage: map[string]scanner.ImageScan{
		"web:1.0": pinnedScan("web:1.0", "sha256:5555555555555555555555555555555555555555555555555555555555555555",
			[]scanner.Finding{{
				Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl",
				InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-1",
			}}, nil),
	}}
	return fakeLister{containers: []inventory.Container{container}}, sc
}

func mustDigest(s string) inventory.Digest {
	d, ok := inventory.ParseDigest(inventory.DigestConfig, s)
	if !ok {
		panic("test fixture: invalid digest " + s)
	}
	return d
}

// runtimeTestRunner builds a Runner wired to evidenceDir, a fixed clock and
// a no-op Inspector, notifying through a fakeNotifier the caller inspects
// afterward.
func runtimeTestRunner(t *testing.T, evidenceDir string) (Runner, *fakeNotifier) {
	t.Helper()
	lister, sc := runtimeTestReport()
	notifier := &fakeNotifier{}
	r := Runner{
		Lister:    lister,
		Scanner:   sc,
		Notifier:  notifier,
		Evidence:  evidence.NewFileProvider(evidenceDir),
		Inspector: fakeInspector{},
		BootTime:  func() (time.Time, error) { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nil },
		Now:       clock,
	}
	return r, notifier
}

// TestRunOnce_RuntimeEvidenceAbsent covers the "Sensor has never reported"
// path end to end: no file at evidenceDir at all. RunOnce must still
// complete, and every PackageGroup's Runtime must resolve to unavailable/
// sensor_not_reporting — not a crash, not a silently-ignored runtime.enabled.
func TestRunOnce_RuntimeEvidenceAbsent(t *testing.T) {
	dir := t.TempDir() // never gets an evidence file written into it
	r, notifier := runtimeTestRunner(t, dir)

	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notifier.called {
		t.Fatal("notifier was not called")
	}
	assertOpenSSLUnavailable(t, notifier.msg, evidence.ReasonSensorNotReporting)
	renderWithoutPanic(t, notifier.msg)
}

// TestRunOnce_RuntimeEvidenceMalformedEnum writes a syntactically
// well-formed evidence file (valid trailer, valid JSON) whose sensor.status
// is not one of evidence.Reader's known values — the exact shape a
// compromised or buggy Sensor could produce without failing at the JSON
// level at all. The real evidence.Reader (via evidence.FileProvider, not a
// hand-built Snapshot) must reject it, and RunOnce must still complete with
// every PackageGroup's Runtime unavailable/evidence_invalid.
func TestRunOnce_RuntimeEvidenceMalformedEnum(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	snap := evidence.Snapshot{
		Schema: evidence.Schema,
		Sensor: evidence.SensorInfo{
			SessionID: "s1", HeartbeatAt: now, IntervalSeconds: 30,
			Status: evidence.SensorStatus("<!channel>"), // not one of the known values
		},
	}
	f, err := os.OpenFile(filepath.Join(dir, evidence.FileName), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open evidence file: %v", err)
	}
	if err := evidence.WriteTo(f, snap); err != nil {
		f.Close()
		t.Fatalf("WriteTo: %v", err)
	}
	f.Close()

	r, notifier := runtimeTestRunner(t, dir)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notifier.called {
		t.Fatal("notifier was not called")
	}
	assertOpenSSLUnavailable(t, notifier.msg, evidence.ReasonEvidenceInvalid)
	renderWithoutPanic(t, notifier.msg)
}

// assertOpenSSLUnavailable finds the web:1.0/openssl PackageGroup in msg's
// report and asserts its Runtime is unavailable with the given reason.
func assertOpenSSLUnavailable(t *testing.T, msg notify.Message, want evidence.UnavailableReason) {
	t.Helper()
	for _, img := range msg.Report.Watch {
		if img.Image != "web:1.0" {
			continue
		}
		for _, g := range img.Packages {
			if g.Package != "openssl" {
				continue
			}
			if g.Runtime.Usage != evidence.UsageUnavailable || g.Runtime.Reason != want {
				t.Errorf("openssl Runtime = %+v, want unavailable/%s", g.Runtime, want)
			}
			return
		}
	}
	t.Fatal("web:1.0/openssl PackageGroup not found in report")
}

// renderWithoutPanic exercises the same rendering calls production notify
// paths use, to confirm a degraded runtime snapshot never crashes them.
func renderWithoutPanic(t *testing.T, msg notify.Message) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("rendering panicked: %v", r)
		}
	}()
	_ = notify.FormatSlackText(msg.Report)
	_ = notify.BuildWebhookPayload(msg.Report, nil)
}
