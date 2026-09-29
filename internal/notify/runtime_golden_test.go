package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/docker"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// Runtime-enabled golden fixture: two images exercising every usage kind —
// OS in_use (openssl), OS not_observed (curl), OS unavailable
// (libfoo, version_mismatch), a language runtime in_use (setuptools, python
// running) and the same container's other language ecosystem not_observed
// (leftpad, node not running) — plus separate scenarios for a Sensor that
// has never reported and one whose eBPF event collection is unavailable.

const (
	rtGoldenWebDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	rtGoldenAPIDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

// rtGoldenWebContainer and rtGoldenAPIContainer are built with strings.Repeat
// rather than written out as literals, so their length is never a
// hand-counting mistake: evidence.Reader's own validContainerID requires
// exactly 64 hex digits, and any test that ever round-trips a Snapshot
// through the real Reader (not just constructs one in memory) needs that
// exact length to pass validation at all.
var (
	rtGoldenWebContainer = strings.Repeat("c", 64)
	rtGoldenAPIContainer = strings.Repeat("d", 64)
)

var rtGoldenBoot = genTime.Add(-24 * time.Hour)

func rtGoldenDigest(t *testing.T, hex string) inventory.Digest {
	t.Helper()
	d, ok := inventory.ParseDigest(inventory.DigestConfig, hex)
	if !ok {
		t.Fatalf("test fixture: invalid digest %q", hex)
	}
	return d
}

// rtGoldenScan builds a Pinned ImageScan confirmed against digestHex, the
// shape runner.scanAll produces for a running entity whose EntityKey
// resolved and was confirmed (mirrors identity_test.go's pinned, duplicated
// here since that helper's contentID form differs slightly and this file
// wants its own self-contained fixture).
func rtGoldenScan(t *testing.T, ref, digestHex string, finds ...scanner.Finding) scanner.ImageScan {
	t.Helper()
	key := inventory.EntityKey{Digest: rtGoldenDigest(t, digestHex)}
	return scanner.ImageScan{
		Image: ref, Subject: inventory.ImageSubject{Ref: ref, Key: key, Resolved: true},
		ScannedKey: key, Pinned: true, Source: scanner.SourceLocal, Findings: finds,
	}
}

func rtGoldenContainers(t *testing.T) []inventory.Container {
	return []inventory.Container{
		{ID: rtGoldenWebContainer, Name: "web-1", Image: inventory.RunningImage{Ref: "web:1.0", Config: rtGoldenDigest(t, rtGoldenWebDigest)}},
		{ID: rtGoldenAPIContainer, Name: "api-1", Image: inventory.RunningImage{Ref: "api:2.0", Config: rtGoldenDigest(t, rtGoldenAPIDigest)}},
	}
}

func rtGoldenEnrich() map[string]analyze.Enrichment {
	return map[string]analyze.Enrichment{
		"CVE-OPENSSL": {KEV: true},
		"CVE-CURL":    {EPSS: 0.02, EPSSKnown: true},
		"CVE-LIBFOO":  {EPSS: 0.001, EPSSKnown: true},
		"CVE-SETUP":   {EPSS: 0.02, EPSSKnown: true},
		"CVE-LEFTPAD": {EPSS: 0.001, EPSSKnown: true},
	}
}

// rtGoldenReport builds the Report before any runtime evidence is attached.
func rtGoldenReport(t *testing.T) analyze.Report {
	t.Helper()
	web := rtGoldenScan(t, "web:1.0", rtGoldenWebDigest,
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-OPENSSL", URL: "https://avd.example/CVE-OPENSSL"},
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "curl", InstalledVer: "8.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-CURL"},
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "libfoo", InstalledVer: "1.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-LIBFOO"},
	)
	api := rtGoldenScan(t, "api:2.0", rtGoldenAPIDigest,
		scanner.Finding{Image: "api:2.0", Class: scanner.ClassLang, Package: "setuptools", InstalledVer: "53.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-SETUP", Type: "python-pkg"},
		scanner.Finding{Image: "api:2.0", Class: scanner.ClassLang, Package: "leftpad", InstalledVer: "1.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-LEFTPAD", Type: "node-pkg"},
	)
	scans := []scanner.ImageScan{web, api}
	return analyze.Build(scans, rtGoldenContainers(t), triageRules(rtGoldenEnrich()), genTime)
}

// rtGoldenSensorInfo is a healthy Sensor's self-report.
func rtGoldenSensorInfo() rtevidence.SensorInfo {
	return rtevidence.SensorInfo{
		Version: "test", SessionID: "sess-1", SessionStartedAt: genTime.Add(-time.Hour),
		HeartbeatAt: genTime, IntervalSeconds: 30, Status: rtevidence.SensorOK,
		Events: rtevidence.EventsInfo{Status: rtevidence.EventsOK, AttachedAt: genTime.Add(-time.Hour)},
	}
}

func rtGoldenGenWeb() rtevidence.Generation {
	return rtevidence.Generation{
		Container: rtevidence.ContainerRef{Runtime: "docker", ID: rtGoldenWebContainer},
		Init:      rtevidence.InitProcess{PID: 100, Starttime: 500},
		StartedAt: genTime.Add(-time.Hour), State: rtevidence.StateObserving,
		PackageDB:      rtevidence.PackageDBInfo{Kind: rtevidence.DBKindDpkg, Status: rtevidence.DBStatusOK},
		LastVerifiedAt: genTime, EventsCoverage: rtevidence.CoverageSinceStart,
		OSPackages: []rtevidence.OSPackageEvidence{
			{Name: "openssl", Version: "3.0.7", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
				rtevidence.KindExe: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
			}, Observations: []rtevidence.ProcessObservation{
				{Exe: "/usr/sbin/nginx", EffectiveUID: 0, Listeners: []string{"tcp:0.0.0.0:443"}, LastSeen: genTime},
			}},
			{Name: "libfoo", Version: "9.9.9", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
				rtevidence.KindExe: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
			}},
		},
	}
}

func rtGoldenGenAPI() rtevidence.Generation {
	return rtevidence.Generation{
		Container: rtevidence.ContainerRef{Runtime: "docker", ID: rtGoldenAPIContainer},
		Init:      rtevidence.InitProcess{PID: 200, Starttime: 600},
		StartedAt: genTime.Add(-time.Hour), State: rtevidence.StateObserving,
		PackageDB:      rtevidence.PackageDBInfo{Kind: rtevidence.DBKindDistroless, Status: rtevidence.DBStatusOK},
		LastVerifiedAt: genTime, EventsCoverage: rtevidence.CoverageSinceStart,
		Executables: []rtevidence.ExecutableEvidence{
			{Path: "/usr/bin/python3.11", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
				rtevidence.KindExe: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
			}, Observations: []rtevidence.ProcessObservation{
				{Exe: "/usr/bin/python3.11", EffectiveUID: 1000, LastSeen: genTime},
			}},
		},
	}
}

// rtGoldenInspect builds the matching docker.InspectResult for gen, boot
// time rtGoldenBoot, confirmed against subject's config digest. ports is the
// container's NetworkSettings.Ports (nil when the scenario doesn't need
// published-port exposure).
func rtGoldenInspect(gen rtevidence.Generation, subject inventory.ImageSubject, ports map[string][]docker.PortBinding) docker.InspectResult {
	insp := docker.InspectResult{
		Pid:       gen.Init.PID,
		StartedAt: rtGoldenBoot.Add(time.Duration(gen.Init.Starttime) * 10 * time.Millisecond),
		Ports:     ports,
	}
	if subject.Resolved {
		insp.Image = subject.Key.Digest
	}
	return insp
}

// rtGoldenWebPorts is web:1.0's NetworkSettings.Ports: nginx's 443/tcp
// listener is published to every host interface (0.0.0.0), the
// host_published_all case. Shared by every scenario that wants openssl's
// exposure resolved rather than left unknown.
func rtGoldenWebPorts() map[string][]docker.PortBinding {
	return map[string][]docker.PortBinding{"443/tcp": {{HostIP: "0.0.0.0", HostPort: "443"}}}
}

func rtGoldenSubject(t *testing.T, r analyze.Report, image string) inventory.ImageSubject {
	t.Helper()
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			if img.Image == image {
				return img.Subject
			}
		}
	}
	t.Fatalf("image %q not found in report", image)
	return inventory.ImageSubject{}
}

// TestGolden_RuntimeHealthySensor pins the Slack full-view, thread, and
// webhook rendering for a healthy Sensor reporting a mix of in_use,
// not_observed and unavailable OS and language packages.
func TestGolden_RuntimeHealthySensor(t *testing.T) {
	r := rtGoldenReport(t)
	genWeb, genAPI := rtGoldenGenWeb(), rtGoldenGenAPI()
	snap := rtevidence.Snapshot{
		Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(),
		Generations: []rtevidence.Generation{genWeb, genAPI},
	}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, r, "web:1.0"), rtGoldenWebPorts()),
			rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, r, "api:2.0"), nil),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)

	checkGolden(t, "runtime_healthy_slack_full", FormatSlackText(r))
	checkGolden(t, "runtime_healthy_thread", goldenThread(r, state.State{}, 0))
	checkGolden(t, "runtime_healthy_webhook", mustIndentJSON(t, BuildWebhookPayload(r, nil)))
}

// TestGolden_RuntimeSensorNotReporting pins the warning banner and
// unavailable state shown when the Sensor has never written an evidence
// file at all.
func TestGolden_RuntimeSensorNotReporting(t *testing.T) {
	r := rtGoldenReport(t)
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{NotReporting: true, LoadFailed: true}, rtevidence.Snapshot{}, analyze.GenerationInspect{}, genTime)

	checkGolden(t, "runtime_not_reporting_slack_full", FormatSlackText(r))
	checkGolden(t, "runtime_not_reporting_webhook", mustIndentJSON(t, BuildWebhookPayload(r, nil)))
}

// TestGolden_RuntimeEBPFUnavailable pins the narrower warning shown when the
// Sensor itself is healthy but its eBPF event collection specifically is
// not: sampling continues, so packages can still be judged, but short-lived
// programs are called out as unobserved.
func TestGolden_RuntimeEBPFUnavailable(t *testing.T) {
	r := rtGoldenReport(t)
	genWeb, genAPI := rtGoldenGenWeb(), rtGoldenGenAPI()
	sensor := rtGoldenSensorInfo()
	sensor.Events = rtevidence.EventsInfo{Status: rtevidence.EventsUnavailable, Reason: rtevidence.EventsReasonBTFMissing}
	genWeb.EventsCoverage, genAPI.EventsCoverage = rtevidence.CoverageNone, rtevidence.CoverageNone
	snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: sensor, Generations: []rtevidence.Generation{genWeb, genAPI}}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, r, "web:1.0"), rtGoldenWebPorts()),
			rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, r, "api:2.0"), nil),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)

	checkGolden(t, "runtime_ebpf_unavailable_slack_full", FormatSlackText(r))
}

// TestGolden_RuntimeAmbiguousOSPackage pins the display for the exact case
// an OS package's evidence can produce: /usr/bin/helper is openssl's own
// executable (exe), a completely different process, /app/server, merely
// maps openssl's shared library (mapped_library) — both folded into one
// OSPackageEvidence record's Kinds map and Observations list. The rendering
// must never claim /app/server (the stronger, root combo) produced the exe
// kind; it must show both kinds unattributed and both observed processes
// in a separate, unattributed list.
func TestGolden_RuntimeAmbiguousOSPackage(t *testing.T) {
	r := rtGoldenReport(t)
	genWeb := rtGoldenGenWeb()
	genWeb.OSPackages = []rtevidence.OSPackageEvidence{
		{Name: "openssl", Version: "3.0.7", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
			rtevidence.KindExe:           {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
			rtevidence.KindMappedLibrary: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
		}, Observations: []rtevidence.ProcessObservation{
			{Exe: "/usr/bin/helper", EffectiveUID: 1000, LastSeen: genTime},
			{Exe: "/app/server", EffectiveUID: 0, LastSeen: genTime},
		}},
		{Name: "libfoo", Version: "9.9.9", Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
			rtevidence.KindExe: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
		}},
	}
	genAPI := rtGoldenGenAPI()
	snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(), Generations: []rtevidence.Generation{genWeb, genAPI}}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, r, "web:1.0"), nil),
			rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, r, "api:2.0"), nil),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)

	checkGolden(t, "runtime_ambiguous_os_package_slack", FormatSlackText(r))
	checkGolden(t, "runtime_ambiguous_os_package_webhook", mustIndentJSON(t, BuildWebhookPayload(r, nil)))
}

// TestNoObservationEvidenceReachesNotifyText drives a language package's
// no-observation evidence (a kind present, zero Observations) all the way
// from real evidence through analyze.AttachRuntime to the rendered Slack
// phrase — deliberately not by constructing an analyze.ContainerRuntime
// literal with EvidenceKinds set by hand, since a hand-built fixture cannot
// catch analyze itself forgetting to carry the kind through this branch at
// all (only a real evidence.Generation with no Observations exercises the
// actual code path that has to preserve it).
func TestNoObservationEvidenceReachesNotifyText(t *testing.T) {
	r := rtGoldenReport(t)
	genAPI := rtGoldenGenAPI()
	genAPI.Executables = []rtevidence.ExecutableEvidence{{
		Path: "/usr/bin/python3.11",
		Kinds: map[rtevidence.EvidenceKind]rtevidence.KindObservation{
			rtevidence.KindExe: {FirstSeen: genTime.Add(-time.Hour), LastSeen: genTime, Samples: 10},
		},
		// No Observations at all.
	}}
	snap := rtevidence.Snapshot{Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(), Generations: []rtevidence.Generation{genAPI}}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, r, "api:2.0"), nil),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(&r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)

	g := findPkgGroup(t, r.Watch, "api:2.0", "setuptools")
	if g.Runtime.Usage != rtevidence.UsageInUse {
		t.Fatalf("Runtime.Usage = %q, want in_use", g.Runtime.Usage)
	}
	got := runtimeInUsePhrase(g.Runtime, enMessages)
	if strings.Contains(got, "in use (in use)") {
		t.Errorf("runtimeInUsePhrase = %q, the evidence kind was dropped on the no-observation path", got)
	}
	if !strings.Contains(got, "running") {
		t.Errorf("runtimeInUsePhrase = %q, want it to still name the kind (running)", got)
	}
}

// rtGoldenReportNoTriage builds a triage-disabled Report exercising all
// three status sections (Actionable/Watch/WontFix): openssl is Fixed
// (Actionable, and in use), curl is Affected with no fix (Watch, not
// observed), setuptools is Affected (Watch, and in use via python running),
// and leftpad is WontFix (WontFix, not observed — node isn't running). This
// checks that the runtime-usage annotation reaches every non-triage section,
// never reordering it.
func rtGoldenReportNoTriage(t *testing.T) analyze.Report {
	t.Helper()
	web := rtGoldenScan(t, "web:1.0", rtGoldenWebDigest,
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", FixedVer: "3.0.11", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-OPENSSL"},
		scanner.Finding{Image: "web:1.0", Class: scanner.ClassOS, Package: "curl", InstalledVer: "8.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-CURL"},
	)
	api := rtGoldenScan(t, "api:2.0", rtGoldenAPIDigest,
		scanner.Finding{Image: "api:2.0", Class: scanner.ClassLang, Package: "setuptools", InstalledVer: "53.0.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-SETUP", Type: "python-pkg"},
		scanner.Finding{Image: "api:2.0", Class: scanner.ClassLang, Package: "leftpad", InstalledVer: "1.0.0", Status: scanner.StatusWontFix, Severity: scanner.SeverityHigh, VulnID: "CVE-LEFTPAD", Type: "node-pkg"},
	)
	scans := []scanner.ImageScan{web, api}
	return analyze.Build(scans, rtGoldenContainers(t), analyze.Triage{}, genTime)
}

// rtGoldenAttach is the shared "read the same generations/inspects and call
// AttachRuntime" step every scenario below repeats against its own Report.
func rtGoldenAttach(t *testing.T, r *analyze.Report) rtevidence.Snapshot {
	t.Helper()
	genWeb, genAPI := rtGoldenGenWeb(), rtGoldenGenAPI()
	snap := rtevidence.Snapshot{
		Schema: rtevidence.Schema, Sensor: rtGoldenSensorInfo(),
		Generations: []rtevidence.Generation{genWeb, genAPI},
	}
	insp := analyze.GenerationInspect{
		ByContainer: map[string]docker.InspectResult{
			rtGoldenWebContainer: rtGoldenInspect(genWeb, rtGoldenSubject(t, *r, "web:1.0"), rtGoldenWebPorts()),
			rtGoldenAPIContainer: rtGoldenInspect(genAPI, rtGoldenSubject(t, *r, "api:2.0"), nil),
		},
		BootTime: rtGoldenBoot,
	}
	analyze.AttachRuntime(r, analyze.RuntimeInfo{Sensor: snap.Sensor}, snap, insp, genTime)
	return snap
}

// TestGolden_RuntimeNonTriageFullView pins the triage-off full view: no
// reordering (the status sections keep Build's own order), and the same
// compact " · ▶ in use" suffix the triage watch bucket uses, added to
// Actionable/Watch/WontFix rows alike, present only for the in-use ones.
func TestGolden_RuntimeNonTriageFullView(t *testing.T) {
	r := rtGoldenReportNoTriage(t)
	rtGoldenAttach(t, &r)

	checkGolden(t, "runtime_nontriage_slack_full", FormatSlackText(r))
	checkGolden(t, "runtime_nontriage_webhook", mustIndentJSON(t, BuildWebhookPayload(r, nil)))
}

// TestGolden_RuntimeDiffMode pins diff-mode rendering with runtime attached,
// triage on and off: the Slack "New since last scan" rows carry the same
// runtime annotation as the full view (the compact suffix, or — for an
// act_now triage change — the full in-use phrase under its evidence line),
// and the webhook's diff.new[] carries runtime_usage.
func TestGolden_RuntimeDiffMode(t *testing.T) {
	triageOn := rtGoldenReport(t)
	rtGoldenAttach(t, &triageOn)
	diffOn, _ := state.Compute(state.State{}, triageOn)
	checkGolden(t, "runtime_diff_triage_slack", FormatSlackDiffText(triageOn, diffOn, false, false))
	checkGolden(t, "runtime_diff_triage_webhook", mustIndentJSON(t, BuildWebhookPayload(triageOn, &diffOn)))

	triageOff := rtGoldenReportNoTriage(t)
	rtGoldenAttach(t, &triageOff)
	diffOff, _ := state.Compute(state.State{}, triageOff)
	checkGolden(t, "runtime_diff_nontriage_slack", FormatSlackDiffText(triageOff, diffOff, false, false))
	checkGolden(t, "runtime_diff_nontriage_webhook", mustIndentJSON(t, BuildWebhookPayload(triageOff, &diffOff)))
}

func mustIndentJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data) + "\n"
}
