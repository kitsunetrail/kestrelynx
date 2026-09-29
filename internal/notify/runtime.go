// Runtime-usage rendering: additive display of the verdicts
// analyze.AttachRuntime attaches to a PackageGroup/Report. Every function
// here gates on analyze.Runtime/RuntimeInfo being non-zero/non-nil before
// writing anything, so a report AttachRuntime never touched (runtime
// disabled — every existing caller before this file existed) renders
// exactly as it did before.
package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	// Imported as rtevidence: this package (notify) already declares an
	// unexported function named "evidence" (triage.go's writeEvidence
	// helper), which is a package-level identifier shared across every file
	// in the package — importing the evidence package under its own name
	// anywhere in notify would collide with it.
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// runtimeTextMaxLen bounds a Sensor-evidence-derived string (an executable
// path), in runes, before it is escaped and shown. It is a Sensor evidence
// file field, itself already bounded to 512 bytes by the reader (internal/
// evidence/limits.go), but Slack rendering uses a much tighter display
// budget.
const runtimeTextMaxLen = 120

// escapeRuntimeText makes one Sensor-evidence-derived string safe to
// interpolate into Slack mrkdwn. A Sensor is a separately-privileged,
// potentially-compromised process (a known residual risk: what it reads can
// reach the main body only through this evidence file's string fields), so
// any string it contributed — an
// executable path, above all — is treated as untrusted input that could
// carry Slack's own special syntax: a channel/user mention, bold/italic
// markers, a backtick breaking out of inline code.
//
// The string is truncated first, by rune count rather than by byte count —
// a valid multi-byte UTF-8 string cut at a fixed byte offset can land inside
// a rune's encoding and either corrupt it or (silently, since Go string
// slicing never validates UTF-8) produce a value that fails validString
// downstream — truncating already-escaped text could also cut an entity
// reference in half and leave a dangling "&amp" or similar. It is then
// wrapped in inline code — which stops Slack from interpreting mrkdwn
// markers inside it — with any backtick replaced (a backtick cannot itself
// be escaped inside inline code) and &, <, > replaced with the entities
// Slack's own "Escaping text" documentation specifies. & is replaced before
// < and > specifically so that literal input already containing "&lt;" is
// not double-escaped into "&amp;lt;": neither &amp;, &lt; nor &gt; contains
// any of the other two source characters, so this one ordering constraint
// is the only one that matters.
func escapeRuntimeText(s string) string {
	if r := []rune(s); len(r) > runtimeTextMaxLen {
		s = string(r[:runtimeTextMaxLen]) + "…"
	}
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return "`" + s + "`"
}

// runtimeDisplayStatus derives the richer, display-ready Sensor status shown
// in the webhook's "sensor_status" field (ok | degraded | stale |
// not_reporting | permission_denied | evidence_invalid | isolation_failed |
// isolation_degraded), folding in what the Sensor's own raw self-report
// (rtevidence.SensorInfo, carried verbatim on RuntimeInfo.Sensor) cannot know
// about itself: whether the evidence file could be read at all this cycle,
// and whether its heartbeat has since gone stale. rtevidence.SensorStatus's
// own doc comment is explicit that this folding belongs to the renderer,
// not to evidence or analyze — this is that renderer.
func runtimeDisplayStatus(rt *analyze.RuntimeInfo, now time.Time) string {
	switch {
	case rt.NotReporting:
		return "not_reporting"
	case rt.LoadFailed:
		return "evidence_invalid"
	case rtevidence.IsStale(rt.Sensor.HeartbeatAt, now, rt.Sensor.IntervalSeconds):
		return "stale"
	default:
		return string(rt.Sensor.Status)
	}
}

// runtimeStatusText is the human sentence fragment for one runtimeDisplayStatus
// value, used in the top-of-message warning line. It never echoes its input:
// runtimeDisplayStatus's own default branch only ever returns one of
// evidence.SensorStatus's own known constants (evidence.Reader's read-time
// validation rejects any snapshot whose sensor.status is not one of them —
// see validSensorStatuses), so every value this function can actually be
// called with is named here explicitly; anything else — reachable only if
// that guarantee were ever broken by a future change — reads as "unknown"
// rather than surfacing whatever string happened to arrive.
func runtimeStatusText(status string) string {
	switch status {
	case "not_reporting":
		return "the Sensor has not reported yet"
	case "evidence_invalid":
		return "the evidence file failed validation"
	case "stale":
		return "the Sensor's last report is stale"
	case "permission_denied":
		return "the Sensor's reads are being denied"
	case "isolation_failed":
		return "the Sensor's sandbox failed to start"
	case "isolation_degraded":
		return "the Sensor's sandbox is running degraded"
	case "degraded":
		return "the Sensor is degraded"
	case "ok":
		return "ok"
	default:
		return "unknown"
	}
}

// reasonText is the human phrase for one UnavailableReason, used wherever a
// reason reaches a Slack line. It never interpolates the raw value: an
// UnavailableReason attacker-influenced field (UnavailablePackage.Reason,
// the only one a Sensor writes to disk directly) is already restricted by
// evidence.Reader's read-time validation to validUnavailableReasons before
// it ever reaches this package, and this switch is a second, independent
// layer on top of that — a reason outside the set named here (which should
// not be reachable at all) reads as "unknown" rather than as whatever string
// arrived.
func reasonText(r rtevidence.UnavailableReason) string {
	switch r {
	case rtevidence.ReasonSensorNotReporting:
		return "sensor not reporting"
	case rtevidence.ReasonSensorStale:
		return "sensor report is stale"
	case rtevidence.ReasonEvidenceInvalid:
		return "evidence invalid"
	case rtevidence.ReasonIsolationFailed:
		return "sensor isolation failed"
	case rtevidence.ReasonPermissionDenied:
		return "permission denied"
	case rtevidence.ReasonInitializing:
		return "index not built yet"
	case rtevidence.ReasonStalled:
		return "worker stalled"
	case rtevidence.ReasonParseFailed:
		return "package database parse failed"
	case rtevidence.ReasonTruncated:
		return "evidence truncated"
	case rtevidence.ReasonIncomplete:
		return "evidence incomplete"
	case rtevidence.ReasonGenerationUnverified:
		return "container generation unverified"
	case rtevidence.ReasonContainerNotObserved:
		return "container not observed"
	case rtevidence.ReasonDBAbsent:
		return "package database absent"
	case rtevidence.ReasonDBError:
		return "package database error"
	case rtevidence.ReasonDBUnsupported:
		return "package database unsupported"
	case rtevidence.ReasonNoFileList:
		return "no file list for this package"
	case rtevidence.ReasonAttributionAmbiguous:
		return "multiple owners"
	case rtevidence.ReasonFileReplaced:
		return "file replaced"
	case rtevidence.ReasonVersionMismatch:
		return "version mismatch"
	case rtevidence.ReasonEcosystemUnmapped:
		return "ecosystem not mapped"
	case rtevidence.ReasonBinaryPathUnknown:
		return "binary path unknown"
	default:
		return "unknown"
	}
}

// eventsReasonText is reasonText's counterpart for EventsReason, the eBPF
// warning's own attacker-influenced field (sensor.events.reason). The same
// two-layer guarantee applies: evidence.Reader's read-time validation
// (validEventsReasons) already restricts it to this set before analyze or
// notify ever sees it.
func eventsReasonText(r rtevidence.EventsReason) string {
	switch r {
	case rtevidence.EventsReasonKernelUnsupported:
		return "kernel unsupported"
	case rtevidence.EventsReasonBTFMissing:
		return "BTF missing"
	case rtevidence.EventsReasonPermission:
		return "permission denied"
	case rtevidence.EventsReasonAttachFailed:
		return "attach failed"
	case rtevidence.EventsReasonCgroupV1:
		return "cgroup v1"
	default:
		return "unknown"
	}
}

// writeRuntimeWarning renders the near-the-top warning: a general "runtime
// evidence unavailable" line whenever the Sensor
// itself isn't fully healthy, or — when the Sensor is otherwise fine but
// its eBPF event collection specifically is not — the narrower warning that
// short-lived programs are not being observed. No-op when runtime evidence
// was never attached at all.
func writeRuntimeWarning(b *strings.Builder, r analyze.Report, now time.Time) {
	if r.Runtime == nil {
		return
	}
	status := runtimeDisplayStatus(r.Runtime, now)
	switch {
	case status != "ok":
		fmt.Fprintf(b, "⚠️ Runtime evidence unavailable: %s\n", runtimeStatusText(status))
	case r.Runtime.Sensor.Events.Status == rtevidence.EventsUnavailable:
		fmt.Fprintf(b, "⚠️ Short-lived programs are not observed (eBPF unavailable: %s); using sampling only\n", eventsReasonText(r.Runtime.Sensor.Events.Reason))
	}
}

// runtimeInUse reports whether rt is an in-use verdict. It exists so callers
// in files that cannot import the evidence package under its own name (this
// package already declares an unexported "evidence" function — see triage.
// go's writeEvidence) can still compare against rtevidence.UsageInUse.
func runtimeInUse(rt analyze.Runtime) bool {
	return rt.Usage == rtevidence.UsageInUse
}

// representativeContainer picks the container a package-level "in use"
// phrase names as its example: the first in-use entry of rt.Containers
// (already sorted by container ID — analyze/runtime.go's groupRuntime — so
// the choice is deterministic regardless of map/slice iteration order
// upstream). ok is false when rt is not in use at all, or carries no
// per-container detail (RuntimeInfo.LoadFailed/NotReporting short-circuits
// every group before any container is ever judged).
func representativeContainer(rt analyze.Runtime) (analyze.ContainerRuntime, bool) {
	for _, c := range rt.Containers {
		if c.Usage == rtevidence.UsageInUse {
			return c, true
		}
	}
	return analyze.ContainerRuntime{}, false
}

// runtimeKindLabel is one evidence kind's human phrase, naming the
// representative executable when one is known.
func runtimeKindLabel(k rtevidence.EvidenceKind, exe string) string {
	suffix := ""
	if exe != "" {
		suffix = " " + escapeRuntimeText(exe)
	}
	switch k {
	case rtevidence.KindExe:
		return "running as" + suffix
	case rtevidence.KindMappedLibrary:
		return "loaded by" + suffix
	case rtevidence.KindExecEvent:
		return "executed" + suffix
	case rtevidence.KindLibraryLoadEvent:
		return "library loaded" + suffix
	case rtevidence.KindBinaryRunning:
		return "in running binary" + suffix
	case rtevidence.KindBinaryExecuted:
		return "binary executed" + suffix
	case rtevidence.KindRuntimeRunning:
		return "runtime is running" + suffix
	case rtevidence.KindRuntimeExecuted:
		return "runtime executed" + suffix
	default:
		// Unreachable in practice: evidence.Reader's read-time validation
		// (validRecordedKinds) already strips any Kinds map entry outside
		// the four on-disk kinds before analyze ever builds an
		// evidence.Verdict from it, and the other four (the language-package
		// display kinds) are all named above. Kept as a safe fallback rather
		// than a panic, and never echoes k itself.
		return "in use" + suffix
	}
}

// runtimeExposureText is the display phrase for an in-use verdict's
// Exposure. "" for ExposureUnknown — nothing worth a claim either way.
func runtimeExposureText(e analyze.Exposure) string {
	switch e {
	case analyze.ExposureHostPublishedAll:
		return "published on all interfaces"
	case analyze.ExposureHostPublishedLoopback:
		return "published on loopback only"
	case analyze.ExposureContainerListening:
		return "listening (not published)"
	default:
		return ""
	}
}

// lastSeenText is the "last confirmed" clause runtimeInUsePhrase appends to
// every in-use evidence line: the point this codebase actually re-observed
// the fact being shown, so an old sampling result or a past execution event
// is never misread as something happening right now. "" for a zero time
// (should not occur for an in-use container — buildContainerRuntime always
// sets LastSeen alongside a chosen combination — but a renderer must not
// print a zero date over a missing one).
func lastSeenText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return "last confirmed " + t.Format("01-02 15:04")
}

// runtimeKindPhraseUnattributed is one evidence kind's standalone phrase —
// runtimeKindLabel's counterpart for when no executable name can be safely
// attached to it: either c.KindsAmbiguous (an OS package record aggregated
// more than one kind across more than one process; see ContainerRuntime's
// own doc comment) or the container has no observation at all
// (!HasProcess). Every phrase here reads correctly with nothing appended,
// unlike runtimeKindLabel's "running as"/"loaded by", which expect a name to
// follow.
func runtimeKindPhraseUnattributed(k rtevidence.EvidenceKind) string {
	switch k {
	case rtevidence.KindExe, rtevidence.KindBinaryRunning, rtevidence.KindRuntimeRunning:
		return "running"
	case rtevidence.KindMappedLibrary:
		return "loaded as a library"
	case rtevidence.KindExecEvent, rtevidence.KindBinaryExecuted, rtevidence.KindRuntimeExecuted:
		return "executed"
	case rtevidence.KindLibraryLoadEvent:
		return "library load observed"
	default:
		// See runtimeKindLabel's own default branch: unreachable in
		// practice, kept as a safe fallback rather than a panic.
		return "in use"
	}
}

// runtimeProcessesPhraseMax caps how many distinct executables the
// unattributed "processes: ..." clause names before summarizing the rest as
// a count, mirroring newIDsMax's identical role for the diff's new-CVE-ID
// list (internal/notify/format.go) — a display-only cap; the webhook's own
// ContainerRuntime.ProcessExes always carries the full list.
const runtimeProcessesPhraseMax = 3

// runtimeProcessesPhrase is the unattributed "processes: a, b (+N more)"
// clause shown alongside an ambiguous kind list, naming the processes
// actually observed without claiming any one of them produced any one kind.
// "" when exes is empty.
func runtimeProcessesPhrase(exes []string) string {
	if len(exes) == 0 {
		return ""
	}
	n := len(exes)
	if n > runtimeProcessesPhraseMax {
		n = runtimeProcessesPhraseMax
	}
	shown := make([]string, n)
	for i := 0; i < n; i++ {
		shown[i] = escapeRuntimeText(exes[i])
	}
	s := "processes: " + strings.Join(shown, ", ")
	if extra := len(exes) - n; extra > 0 {
		s += fmt.Sprintf(" (+%d more)", extra)
	}
	return s
}

// runtimeKindsPhrase is the "(...)" clause of an in-use phrase: the evidence
// kind(s) paired with the single executable that produced them, when that
// pairing is trustworthy (c.HasProcess and not c.KindsAmbiguous) — or, when
// it is not, the kinds listed on their own plus a separate, unattributed
// list of the processes actually observed. See ContainerRuntime.
// KindsAmbiguous's own doc comment for why an OS package's aggregated
// record cannot always support the pairing, and buildContainerRuntime's for
// why a container can be in_use with kinds but !HasProcess at all.
func runtimeKindsPhrase(c analyze.ContainerRuntime) string {
	if len(c.EvidenceKinds) == 0 {
		return "in use"
	}
	if c.HasProcess && !c.KindsAmbiguous {
		labels := make([]string, 0, len(c.EvidenceKinds))
		for _, k := range c.EvidenceKinds {
			labels = append(labels, runtimeKindLabel(k, c.Process.Exe))
		}
		return strings.Join(labels, ", ")
	}
	labels := make([]string, 0, len(c.EvidenceKinds))
	for _, k := range c.EvidenceKinds {
		labels = append(labels, runtimeKindPhraseUnattributed(k))
	}
	phrase := strings.Join(labels, "; ")
	if procs := runtimeProcessesPhrase(c.ProcessExes); procs != "" {
		phrase += "; " + procs
	}
	return phrase
}

// runtimeInUsePhrase is the full "▶ in use (...) · ..." line shown under an
// act-now package's evidence line and in the thread: the evidence kind(s),
// the exposure stage, a privilege note and the last-confirmed time — all
// four taken from the single strongest in-use container
// (representativeContainer), never mixed across containers. Only ever
// called on an in-use Runtime — callers check rt.Usage ==
// rtevidence.UsageInUse first.
func runtimeInUsePhrase(rt analyze.Runtime) string {
	c, ok := representativeContainer(rt)
	if !ok {
		// Unreachable for a well-formed in-use Runtime (AttachRuntime always
		// records the container(s) it judged in use); kept as a safe,
		// non-panicking fallback.
		return "▶ in use"
	}
	parts := []string{"▶ in use (" + runtimeKindsPhrase(c) + ")"}
	if s := runtimeExposureText(c.Exposure); s != "" {
		parts = append(parts, s)
	}
	if c.HighPrivilege {
		parts = append(parts, "runs with elevated privilege")
	}
	if s := lastSeenText(c.LastSeen); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, " · ")
}

// runtimeShortWord picks the one-word evidence summary the watch bucket and
// the thread's compact lines use: "running"/"loaded" when the process is
// still present (a sampling-derived kind), "executed" when the only
// evidence is a past event.
func runtimeShortWord(kinds []rtevidence.EvidenceKind) string {
	set := make(map[rtevidence.EvidenceKind]bool, len(kinds))
	for _, k := range kinds {
		set[k] = true
	}
	switch {
	case set[rtevidence.KindExe] || set[rtevidence.KindBinaryRunning] || set[rtevidence.KindRuntimeRunning]:
		return "running"
	case set[rtevidence.KindMappedLibrary]:
		return "loaded"
	default:
		return "executed"
	}
}

// runtimeWatchSuffix is the compact " · ▶ in use (running / executed /
// loaded)" suffix appended to a watch-bucket package line. "" when rt is not
// in use (including runtime disabled, where Usage is always "").
func runtimeWatchSuffix(rt analyze.Runtime) string {
	if rt.Usage != rtevidence.UsageInUse {
		return ""
	}
	return " · ▶ in use (" + runtimeShortWord(rt.EvidenceKinds) + ")"
}

// runtimeChangeSuffix is the diff-mode change list's runtime annotation for
// one package group: the same compact suffix the watch bucket uses, except
// for an act_now group, where the caller shows the full "▶ in use (...)"
// phrase right under the evidence line instead (mirroring the act-now bucket
// itself) — so this returns "" there rather than duplicating the note.
func runtimeChangeSuffix(g analyze.PackageGroup) string {
	if g.Priority == analyze.PriorityActNow {
		return ""
	}
	return runtimeWatchSuffix(g.Runtime)
}

// runtimeCounts tallies every package group's Runtime.Usage across every
// status section of r — the full-view summary line's "N in use / N not
// observed / N unavailable" — plus, separately, how many of those groups are
// Accepted. A group whose Runtime was never attached (Usage == "") counts
// toward none of the first three, which is what keeps this a no-op tally
// when runtime is disabled (writeRuntimeSummary never calls it in that case
// regardless, since it also gates on r.Runtime == nil, but the tally itself
// is correct either way). accepted overlaps notObserved by construction
// (analyze.ApplyAcceptance only ever accepts a not-observed group) rather
// than being mutually exclusive with it — the same kind of overlap the
// end-of-life/act-now segments already have elsewhere in this codebase.
func runtimeCounts(r analyze.Report) (inUse, notObserved, unavailable, accepted int) {
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages} {
		for _, img := range section {
			for _, g := range img.Packages {
				switch g.Runtime.Usage {
				case rtevidence.UsageInUse:
					inUse++
				case rtevidence.UsageNotObserved:
					notObserved++
				case rtevidence.UsageUnavailable:
					unavailable++
				}
				if g.Accepted {
					accepted++
				}
			}
		}
	}
	return inUse, notObserved, unavailable, accepted
}

// acceptedCount tallies every Accepted PackageGroup in r — the single number
// every rendering's "✅ Accepted" line shows in place of the rows it hides.
// 0 whenever runtime.accept_unfixable_not_in_use is off, since
// analyze.ApplyAcceptance then never runs and every group's Accepted stays
// at its zero value.
func acceptedCount(r analyze.Report) int {
	_, _, _, accepted := runtimeCounts(r)
	return accepted
}

// acceptedLine is the wording every Slack rendering (channel body, thread,
// full view) shows in place of an accepted finding's own row.
const acceptedLineText = "✅ Accepted — no fix available and not in use for 7+ days: %d\n"

// writeAcceptedCount appends the accepted-findings summary line: the one
// place an accepted finding's existence still shows once its own row has
// been hidden. No-op when nothing is accepted this cycle.
func writeAcceptedCount(b *strings.Builder, r analyze.Report) {
	if n := acceptedCount(r); n > 0 {
		fmt.Fprintf(b, "\n"+acceptedLineText, n)
	}
}

// filterAccepted returns imgs with every Accepted PackageGroup removed, and
// any image left with no packages dropped entirely. Every Slack rendering of
// the open-findings view calls this before laying out rows — an accepted
// finding's row is never shown there, only acceptedCount's tally represents
// it. It never mutates its input: each ImageFindings is copied before its
// Packages field is replaced. The generic webhook never calls this —
// BuildWebhookPayload keeps every group, accepted or not.
func filterAccepted(imgs []analyze.ImageFindings) []analyze.ImageFindings {
	out := make([]analyze.ImageFindings, 0, len(imgs))
	for _, img := range imgs {
		var kept []analyze.PackageGroup
		for _, g := range img.Packages {
			if !g.Accepted {
				kept = append(kept, g)
			}
		}
		if len(kept) == 0 {
			continue
		}
		img.Packages = kept
		out = append(out, img)
	}
	return out
}

// allAccepted reports whether every one of groups is Accepted — used by the
// generic webhook's diff.new[].accepted, the coarsest-possible summary of a
// (image, package) change that can merge more than one PackageGroup. Always
// false for an empty slice.
func allAccepted(groups []analyze.PackageGroup) bool {
	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if !g.Accepted {
			return false
		}
	}
	return true
}

// changeReasonGroups is every group state.Compute recorded for a change's
// key this cycle, ordinary and end-of-life alike: end-of-life lives in its
// own Report section (and its own mergeSections pass), never merged into
// c.Groups, but it is exactly as disqualifying for acceptance as any
// ordinary group — analyze.ApplyAcceptance already blocks a key's
// acceptance over an end-of-life sibling — so acceptanceLostReason must see
// it too, or it names the wrong fact for that exact transition. Both
// notify's Slack rendering (changeSuffixParts) and BuildWebhookPayload
// (buildDiffPayload) call this before calling acceptanceLostReason, so the
// two destinations can never disagree on the reason shown for the same
// change.
func changeReasonGroups(c state.Change) []analyze.PackageGroup {
	if len(c.EOLGroups) == 0 {
		return c.Groups
	}
	out := make([]analyze.PackageGroup, 0, len(c.Groups)+len(c.EOLGroups))
	out = append(out, c.Groups...)
	out = append(out, c.EOLGroups...)
	return out
}

// acceptanceLostReason names, for display and for the webhook's diff
// reason, why a (image, package) key that was accepted under
// runtime.accept_unfixable_not_in_use last cycle no longer is this cycle.
// Acceptance is decided for the whole key at once (analyze.ApplyAcceptance
// only ever marks every one of a key's groups Accepted together), so the
// reason is read from every group currently on record for the key —
// ordinary and end-of-life alike; callers pass changeReasonGroups(c), never
// c.Groups alone — the first fact that applies, checked in this fixed
// order: any group now in use, any group now act_now (only reachable when
// degraded intel suppressed the escalated Kind that would ordinarily
// announce it instead), any group now fixed (only reachable via the same
// kind of suppression, or a sibling group's own transition —
// state.Compute already prefers the more specific now_fixable/escalated
// Kind whenever one fires on its own), any group now end-of-life (the base
// OS or the package itself aging out from under an otherwise-unchanged
// finding), any group whose runtime evidence is no longer trustworthy, and
// any group whose canonical status is none of the above (defensive — every
// status sectionOf produces is covered by one of the cases above it). The
// fallback covers the group actually judged not-observed but too recently:
// its own container generation reset (e.g. a redeploy) and hasn't yet run
// long enough to qualify again.
func acceptanceLostReason(groups []analyze.PackageGroup) string {
	for _, g := range groups {
		if g.Runtime.Usage == rtevidence.UsageInUse {
			return "now in use"
		}
	}
	for _, g := range groups {
		if g.Priority == analyze.PriorityActNow {
			return "act now"
		}
	}
	for _, g := range groups {
		if g.Status == scanner.StatusFixed {
			return "fix available"
		}
	}
	for _, g := range groups {
		if g.Status == scanner.StatusEndOfLife {
			return "now end-of-life"
		}
	}
	for _, g := range groups {
		if g.Runtime.Usage == rtevidence.UsageUnavailable {
			return "insufficient observation"
		}
	}
	for _, g := range groups {
		switch g.Status {
		case scanner.StatusAffected, scanner.StatusWontFix:
		default:
			return "not an eligible status"
		}
	}
	return "insufficient observation"
}

// countInUse is runtimeCounts' first return value restricted to imgs (a
// priority bucket), for the Low bucket's "N in use" suffix.
func countInUse(imgs []analyze.ImageFindings) int {
	n := 0
	for _, img := range imgs {
		for _, g := range img.Packages {
			if g.Runtime.Usage == rtevidence.UsageInUse {
				n++
			}
		}
	}
	return n
}

// writeRuntimeSummary appends the full-view tail line: the three usage
// counts, plus the fixed explanatory note that "not observed" only covers
// the observation window. No-op when runtime evidence was never attached.
func writeRuntimeSummary(b *strings.Builder, r analyze.Report) {
	if r.Runtime == nil {
		return
	}
	inUse, notObserved, unavailable, _ := runtimeCounts(r)
	fmt.Fprintf(b, "\n🔎 Runtime: ▶ %d in use · %d not observed · %d unavailable\n", inUse, notObserved, unavailable)
	b.WriteString("_In use: an OS package is executed or loaded by a running program; a language package is in a running binary or its runtime (python, node, java, …) is running. Not observed covers the observation window only and does not mean unused._\n")
}

// runtimeUsageOf is the webhook diff's projected runtime usage across a set
// of merged analyze.PackageGroups (diff.new[]/new_eol_packages[].
// runtime_usage): in_use if any is, else unavailable if any is, else
// not_observed (evidence.ProjectUsages — the same order analyze.Runtime's
// own projection uses). "" when none of the groups ever had a Runtime
// attached at all (runtime.enabled is false).
func runtimeUsageOf(groups []analyze.PackageGroup) string {
	var usages []rtevidence.Usage
	for _, g := range groups {
		if g.Runtime.Usage == "" {
			continue
		}
		usages = append(usages, g.Runtime.Usage)
	}
	if len(usages) == 0 {
		return ""
	}
	return string(rtevidence.ProjectUsages(usages))
}

// evidenceKindStrings converts a Runtime's EvidenceKinds to their wire
// strings, or nil for an empty/nil input (so omitempty drops the key).
func evidenceKindStrings(kinds []rtevidence.EvidenceKind) []string {
	if len(kinds) == 0 {
		return nil
	}
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}

// runtimeFindingPayload converts one PackageGroup's Runtime (plus its
// Accepted verdict) to the webhook's findings[].runtime object, or nil when
// Runtime was never attached (Usage == "") — the omitempty on
// findingPayload.Runtime then drops the key entirely, which is what keeps a
// disabled deployment's webhook payload identical to one built before this
// field existed.
func runtimeFindingPayload(g analyze.PackageGroup) *findingRuntimePayload {
	rt := g.Runtime
	if rt.Usage == "" {
		return nil
	}
	p := &findingRuntimePayload{
		Usage:          string(rt.Usage),
		Reason:         string(rt.Reason),
		EvidenceKinds:  evidenceKindStrings(rt.EvidenceKinds),
		EventsCoverage: string(rt.EventsCoverage),
		Exposure:       string(rt.Exposure),
		HighPrivilege:  rt.HighPrivilege,
	}
	if g.Accepted {
		p.Accepted = true
		p.AcceptedReason = string(g.AcceptedReason)
	}
	for _, c := range rt.Containers {
		p.Containers = append(p.Containers, containerRuntimePayload(c))
	}
	return p
}

// containerRuntimePayload converts one analyze.ContainerRuntime to its
// webhook form. Process is only populated when c.HasProcess — see
// analyze.ContainerRuntime's own doc comment: an in-use container can carry
// evidence kinds with no ProcessObservation behind them at all, and nil here
// is more honest than a payload full of zeros that would misread as "root,
// no capabilities".
func containerRuntimePayload(c analyze.ContainerRuntime) findingRuntimeContainerPayload {
	p := findingRuntimeContainerPayload{
		Name:                c.Name,
		ContainerID:         c.ContainerID,
		GenerationStartedAt: formatTimeOrEmpty(c.GenerationStartedAt),
		Usage:               string(c.Usage),
		Reason:              string(c.Reason),
		LastSeen:            formatTimeOrEmpty(c.LastSeen),
		Ports:               c.Ports,
		KindsAmbiguous:      c.KindsAmbiguous,
		ProcessExes:         c.ProcessExes,
	}
	if c.HasProcess {
		p.Process = &findingRuntimeProcessPayload{
			Exe:           c.Process.Exe,
			EffectiveUID:  c.Process.EffectiveUID,
			Userns:        c.Process.Userns,
			DangerousCaps: c.Process.DangerousCaps,
			Privileged:    c.Process.Privileged,
		}
	}
	for _, inst := range c.Instances {
		p.Instances = append(p.Instances, findingRuntimeInstancePayload{
			Type: inst.Type, Target: inst.Target, PkgPath: inst.PkgPath,
			Usage: string(inst.Usage), Reason: string(inst.Reason),
		})
	}
	return p
}

// writeRuntimeThreadLine renders the thread's one-line-per-package runtime
// state: the full "in use" phrase, a "not observed" line
// (with a short-lived-programs caveat when event coverage did not span the
// whole generation), or the unavailable reason. No-op when rt was never
// attached.
func writeRuntimeThreadLine(b *strings.Builder, rt analyze.Runtime) {
	switch rt.Usage {
	case rtevidence.UsageInUse:
		fmt.Fprintf(b, "     %s\n", runtimeInUsePhrase(rt))
	case rtevidence.UsageNotObserved:
		line := "▷ not observed"
		if rt.EventsCoverage != rtevidence.CoverageSinceStart {
			line += " — short-lived programs not fully observed"
		}
		fmt.Fprintf(b, "     %s\n", line)
	case rtevidence.UsageUnavailable:
		fmt.Fprintf(b, "     ▷ runtime evidence unavailable (%s)\n", reasonText(rt.Reason))
	}
}
