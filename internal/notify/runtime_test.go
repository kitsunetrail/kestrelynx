package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// TestEscapeRuntimeText_SlackInjection pins the exact escaping contract for
// a Sensor-evidence-derived string: &, < and > replaced with Slack's own
// documented entities, wrapped in inline code with
// any backtick replaced by "'" (a backtick cannot itself be escaped inside
// inline code), and never interpreted as mrkdwn once wrapped.
func TestEscapeRuntimeText_SlackInjection(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"channel mention", "<!channel>", "`&lt;!channel&gt;`"},
		{"user mention", "<@U123>", "`&lt;@U123&gt;`"},
		{"already-escaped-looking ampersand", "&amp;", "`&amp;amp;`"},
		{"backtick", "a`b`c", "`a'b'c`"},
		{"asterisks stay literal inside inline code", "*bold*", "`*bold*`"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := escapeRuntimeText(c.in); got != c.want {
				t.Errorf("escapeRuntimeText(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestEscapeRuntimeText_Truncates guards the 120-byte truncation applied
// before escaping, so a long garbage path from a compromised Sensor cannot
// blow up the message.
func TestEscapeRuntimeText_Truncates(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := escapeRuntimeText(long)
	// backtick + 120 a's + ellipsis + backtick
	want := "`" + strings.Repeat("a", 120) + "…`"
	if got != want {
		t.Errorf("escapeRuntimeText(200 a's) = %q, want truncated to 120 + ellipsis", got)
	}
}

// TestWriteRuntimeWarning_GatesOnRuntime confirms every warning line is a
// pure no-op when Report.Runtime is nil (runtime disabled) — the contract
// every notify rendering in this file depends on for byte-identical output
// when runtime is off.
func TestWriteRuntimeWarning_GatesOnRuntime(t *testing.T) {
	var b strings.Builder
	writeRuntimeWarning(&b, analyze.Report{}, time.Now())
	if b.String() != "" {
		t.Errorf("writeRuntimeWarning with Report.Runtime == nil wrote %q, want nothing", b.String())
	}
}

// TestWriteRuntimeSummary_GatesOnRuntime is writeRuntimeWarning's sibling
// check for the full-view tail line.
func TestWriteRuntimeSummary_GatesOnRuntime(t *testing.T) {
	var b strings.Builder
	writeRuntimeSummary(&b, analyze.Report{})
	if b.String() != "" {
		t.Errorf("writeRuntimeSummary with Report.Runtime == nil wrote %q, want nothing", b.String())
	}
}

// TestRuntimeDisplayStatus_FoldsStaleness confirms notify — not analyze or
// evidence — is what turns a fresh-looking Sensor self-report plus an old
// heartbeat into "stale" (rtevidence.SensorStatus's own doc comment explicitly
// assigns this folding to the renderer).
func TestRuntimeDisplayStatus_FoldsStaleness(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rt := &analyze.RuntimeInfo{Sensor: rtevidence.SensorInfo{
		Status: rtevidence.SensorOK, IntervalSeconds: 30, HeartbeatAt: now.Add(-time.Hour),
	}}
	if got := runtimeDisplayStatus(rt, now); got != "stale" {
		t.Errorf("runtimeDisplayStatus = %q, want stale for a heartbeat an hour old at a 30s interval", got)
	}

	fresh := &analyze.RuntimeInfo{Sensor: rtevidence.SensorInfo{
		Status: rtevidence.SensorOK, IntervalSeconds: 30, HeartbeatAt: now.Add(-time.Second),
	}}
	if got := runtimeDisplayStatus(fresh, now); got != "ok" {
		t.Errorf("runtimeDisplayStatus = %q, want ok for a fresh heartbeat", got)
	}
}

// TestRuntimeInUsePhrase_KindNeverMixedWithWrongExecutable confirms the
// rendered phrase reads its evidence kind(s) and executable from the same
// representative container's own fields: a container whose EvidenceKinds is
// exactly [binary_executed] and whose Process.Exe is /app/tool must render
// "binary executed `/app/tool`", never "binary executed `/app/api`" or any
// mix naming one container's kind against a different executable.
func TestRuntimeInUsePhrase_KindNeverMixedWithWrongExecutable(t *testing.T) {
	rt := analyze.Runtime{
		Usage: rtevidence.UsageInUse,
		Containers: []analyze.ContainerRuntime{{
			ContainerID:   "c1",
			Usage:         rtevidence.UsageInUse,
			EvidenceKinds: []rtevidence.EvidenceKind{rtevidence.KindBinaryExecuted},
			HasProcess:    true,
			Process:       analyze.ContainerProcess{Exe: "/app/tool"},
		}},
	}
	got := runtimeInUsePhrase(rt)
	if strings.Contains(got, "/app/api") {
		t.Errorf("runtimeInUsePhrase = %q, must never mention /app/api (not this container's executable)", got)
	}
	if !strings.Contains(got, "binary executed") || !strings.Contains(got, "/app/tool") {
		t.Errorf("runtimeInUsePhrase = %q, want it to name binary executed and /app/tool together", got)
	}
}

// TestRuntimeUsageOf_ProjectsAcrossMergedGroups covers the webhook diff's
// diff.new[].runtime_usage rule: state's key is (image, package name) only,
// so an OS package and a same-named language package (or two installed
// versions) can land in the same diff element; the projected value must
// follow the same in_use > unavailable > not_observed order
// analyze.Runtime's own projection uses, and must be "" (omitted) when none
// of the merged groups ever had runtime evidence attached at all.
func TestRuntimeUsageOf_ProjectsAcrossMergedGroups(t *testing.T) {
	cases := []struct {
		name   string
		groups []analyze.PackageGroup
		want   string
	}{
		{"none attached", []analyze.PackageGroup{{}, {}}, ""},
		{"any in_use wins", []analyze.PackageGroup{
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}},
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageInUse}},
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageUnavailable}},
		}, "in_use"},
		{"unavailable beats not_observed", []analyze.PackageGroup{
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}},
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageUnavailable}},
		}, "unavailable"},
		{"all not_observed", []analyze.PackageGroup{
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}},
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageNotObserved}},
		}, "not_observed"},
		{"one attached, one not (mixed OS/lang collision before either judged)", []analyze.PackageGroup{
			{Runtime: analyze.Runtime{Usage: rtevidence.UsageInUse}},
			{},
		}, "in_use"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runtimeUsageOf(c.groups); got != c.want {
				t.Errorf("runtimeUsageOf(%+v) = %q, want %q", c.groups, got, c.want)
			}
		})
	}
}

// TestRuntimeWatchSuffix_EmptyWhenNotInUse confirms the compact watch-bucket
// suffix is exactly "" (not, say, a suffix describing not_observed) for
// every usage other than in_use — the watch bucket shows no runtime
// annotation at all for those.
func TestRuntimeWatchSuffix_EmptyWhenNotInUse(t *testing.T) {
	for _, usage := range []rtevidence.Usage{"", rtevidence.UsageNotObserved, rtevidence.UsageUnavailable} {
		if got := runtimeWatchSuffix(analyze.Runtime{Usage: usage}); got != "" {
			t.Errorf("runtimeWatchSuffix(Usage=%q) = %q, want empty", usage, got)
		}
	}
	if got := runtimeWatchSuffix(analyze.Runtime{Usage: rtevidence.UsageInUse, EvidenceKinds: []rtevidence.EvidenceKind{rtevidence.KindExe}}); got == "" {
		t.Error("runtimeWatchSuffix(in_use) is empty, want a suffix")
	}
}

// TestRuntimeInUsePhrase_AmbiguousKindsListProcessesSeparately covers the
// exact case an OS package's evidence can produce: /usr/bin/helper is the
// package's own executable (exe), a different process, /app/server, merely
// maps the package's shared library (mapped_library) — both kinds land on
// the one record's Kinds map, aggregated across both processes, with
// /app/server picked as the strongest combo. The phrase must never claim
// /app/server produced either kind; it must show both kinds unattributed
// and name both observed processes in a separate clause.
func TestRuntimeInUsePhrase_AmbiguousKindsListProcessesSeparately(t *testing.T) {
	rt := analyze.Runtime{
		Usage: rtevidence.UsageInUse,
		Containers: []analyze.ContainerRuntime{{
			ContainerID:    "c1",
			Usage:          rtevidence.UsageInUse,
			EvidenceKinds:  []rtevidence.EvidenceKind{rtevidence.KindExe, rtevidence.KindMappedLibrary},
			KindsAmbiguous: true,
			ProcessExes:    []string{"/usr/bin/helper", "/app/server"},
			HasProcess:     true,
			Process:        analyze.ContainerProcess{Exe: "/app/server", EffectiveUID: 0},
		}},
	}
	got := runtimeInUsePhrase(rt)
	if strings.Contains(got, "running as") || strings.Contains(got, "loaded by") {
		t.Errorf("runtimeInUsePhrase = %q, must never pair a kind with an executable when KindsAmbiguous", got)
	}
	for _, want := range []string{"running", "loaded as a library", "processes:", "/usr/bin/helper", "/app/server"} {
		if !strings.Contains(got, want) {
			t.Errorf("runtimeInUsePhrase = %q, want it to contain %q", got, want)
		}
	}
}

// TestRuntimeInUsePhrase_NoObservationShowsKindsWithoutExecutable covers an
// in-use container whose kinds have no ProcessObservation behind them at
// all (!HasProcess): the phrase must still name the kind(s), but never
// attach an executable (there is none to name) and never list a "processes:"
// clause either (nothing was actually observed).
func TestRuntimeInUsePhrase_NoObservationShowsKindsWithoutExecutable(t *testing.T) {
	rt := analyze.Runtime{
		Usage: rtevidence.UsageInUse,
		Containers: []analyze.ContainerRuntime{{
			ContainerID:   "c1",
			Usage:         rtevidence.UsageInUse,
			EvidenceKinds: []rtevidence.EvidenceKind{rtevidence.KindBinaryRunning},
			HasProcess:    false,
		}},
	}
	got := runtimeInUsePhrase(rt)
	if strings.Contains(got, "processes:") {
		t.Errorf("runtimeInUsePhrase = %q, must not list processes when none was observed", got)
	}
	if !strings.Contains(got, "running") {
		t.Errorf("runtimeInUsePhrase = %q, want it to still name the kind", got)
	}
	if strings.Contains(got, "``") {
		t.Errorf("runtimeInUsePhrase = %q, must never render an empty executable name", got)
	}
}

// TestContainerRuntimePayload_OmitsProcessWhenNoObservation confirms the
// webhook never emits a "process" object built from zero-valued fields for
// an in-use container that has no real ProcessObservation behind it — the
// key must be omitted entirely, not filled with effective_uid: 0, userns:
// false, etc. that would misread as an actual observation.
func TestContainerRuntimePayload_OmitsProcessWhenNoObservation(t *testing.T) {
	c := analyze.ContainerRuntime{
		Usage:         rtevidence.UsageInUse,
		EvidenceKinds: []rtevidence.EvidenceKind{rtevidence.KindBinaryRunning},
		HasProcess:    false,
	}
	p := containerRuntimePayload(c)
	if p.Process != nil {
		t.Errorf("containerRuntimePayload.Process = %+v, want nil when HasProcess is false", p.Process)
	}
}

// TestContainerRuntimePayload_KindsAmbiguousCarriesProcessExes confirms the
// webhook mirrors analyze's ambiguous-kinds signal and its unabridged
// process list, alongside the still-legitimate representative Process.
func TestContainerRuntimePayload_KindsAmbiguousCarriesProcessExes(t *testing.T) {
	c := analyze.ContainerRuntime{
		Usage:          rtevidence.UsageInUse,
		EvidenceKinds:  []rtevidence.EvidenceKind{rtevidence.KindExe, rtevidence.KindMappedLibrary},
		KindsAmbiguous: true,
		ProcessExes:    []string{"/usr/bin/helper", "/app/server"},
		HasProcess:     true,
		Process:        analyze.ContainerProcess{Exe: "/app/server"},
	}
	p := containerRuntimePayload(c)
	if !p.KindsAmbiguous {
		t.Error("containerRuntimePayload.KindsAmbiguous = false, want true")
	}
	if len(p.ProcessExes) != 2 {
		t.Errorf("containerRuntimePayload.ProcessExes = %v, want both observed executables", p.ProcessExes)
	}
	if p.Process == nil || p.Process.Exe != "/app/server" {
		t.Errorf("containerRuntimePayload.Process = %+v, want the representative combo's own exe", p.Process)
	}
}

// TestRuntimeProcessesPhrase_CapsAndCounts covers the display-only cap on
// the unattributed "processes: ..." clause.
func TestRuntimeProcessesPhrase_CapsAndCounts(t *testing.T) {
	got := runtimeProcessesPhrase([]string{"/a", "/b", "/c", "/d"})
	want := "processes: `/a`, `/b`, `/c` (+1 more)"
	if got != want {
		t.Errorf("runtimeProcessesPhrase = %q, want %q", got, want)
	}
	if got := runtimeProcessesPhrase(nil); got != "" {
		t.Errorf("runtimeProcessesPhrase(nil) = %q, want empty", got)
	}
}
