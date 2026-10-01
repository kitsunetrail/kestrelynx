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
	// Imported as rtevidence to keep it apart from this package's own
	// evidence-line helpers (triage.go).
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
func runtimeStatusText(status string, msg messages) string {
	switch status {
	case "not_reporting":
		return msg.StatusTextNotReporting
	case "evidence_invalid":
		return msg.StatusTextEvidenceInvalid
	case "stale":
		return msg.StatusTextStale
	case "permission_denied":
		return msg.StatusTextPermissionDenied
	case "isolation_failed":
		return msg.StatusTextIsolationFailed
	case "isolation_degraded":
		return msg.StatusTextIsolationDegraded
	case "degraded":
		return msg.StatusTextDegraded
	case "ok":
		return msg.StatusTextOK
	default:
		return msg.StatusTextUnknown
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
func reasonText(r rtevidence.UnavailableReason, msg messages) string {
	switch r {
	case rtevidence.ReasonSensorNotReporting:
		return msg.ReasonSensorNotReporting
	case rtevidence.ReasonSensorStale:
		return msg.ReasonSensorStale
	case rtevidence.ReasonEvidenceInvalid:
		return msg.ReasonEvidenceInvalid
	case rtevidence.ReasonIsolationFailed:
		return msg.ReasonIsolationFailed
	case rtevidence.ReasonPermissionDenied:
		return msg.ReasonPermissionDenied
	case rtevidence.ReasonInitializing:
		return msg.ReasonInitializing
	case rtevidence.ReasonStalled:
		return msg.ReasonStalled
	case rtevidence.ReasonParseFailed:
		return msg.ReasonParseFailed
	case rtevidence.ReasonTruncated:
		return msg.ReasonTruncated
	case rtevidence.ReasonIncomplete:
		return msg.ReasonIncomplete
	case rtevidence.ReasonGenerationUnverified:
		return msg.ReasonGenerationUnverified
	case rtevidence.ReasonContainerNotObserved:
		return msg.ReasonContainerNotObserved
	case rtevidence.ReasonDBAbsent:
		return msg.ReasonDBAbsent
	case rtevidence.ReasonDBError:
		return msg.ReasonDBError
	case rtevidence.ReasonDBUnsupported:
		return msg.ReasonDBUnsupported
	case rtevidence.ReasonNoFileList:
		return msg.ReasonNoFileList
	case rtevidence.ReasonAttributionAmbiguous:
		return msg.ReasonAttributionAmbiguous
	case rtevidence.ReasonFileReplaced:
		return msg.ReasonFileReplaced
	case rtevidence.ReasonVersionMismatch:
		return msg.ReasonVersionMismatch
	case rtevidence.ReasonEcosystemUnmapped:
		return msg.ReasonEcosystemUnmapped
	case rtevidence.ReasonBinaryPathUnknown:
		return msg.ReasonBinaryPathUnknown
	default:
		return msg.ReasonUnknown
	}
}

// eventsReasonText is reasonText's counterpart for EventsReason, the eBPF
// warning's own attacker-influenced field (sensor.events.reason). The same
// two-layer guarantee applies: evidence.Reader's read-time validation
// (validEventsReasons) already restricts it to this set before analyze or
// notify ever sees it.
func eventsReasonText(r rtevidence.EventsReason, msg messages) string {
	switch r {
	case rtevidence.EventsReasonKernelUnsupported:
		return msg.EventsReasonKernelUnsupported
	case rtevidence.EventsReasonBTFMissing:
		return msg.EventsReasonBTFMissing
	case rtevidence.EventsReasonPermission:
		return msg.EventsReasonPermission
	case rtevidence.EventsReasonAttachFailed:
		return msg.EventsReasonAttachFailed
	case rtevidence.EventsReasonCgroupV1:
		return msg.EventsReasonCgroupV1
	default:
		return msg.EventsReasonUnknown
	}
}

// runtimeWarning is the Sensor warning text ("" when there is nothing to
// warn about), newline-terminated like every dictionary line.
func runtimeWarning(r analyze.Report, now time.Time, msg messages) string {
	if r.Runtime == nil {
		return ""
	}
	status := runtimeDisplayStatus(r.Runtime, now)
	switch {
	case status != "ok":
		return fmt.Sprintf(msg.RuntimeWarningUnavailable, runtimeStatusText(status, msg))
	case r.Runtime.Sensor.Events.Status == rtevidence.EventsUnavailable:
		return fmt.Sprintf(msg.RuntimeWarningEventsUnavailable, eventsReasonText(r.Runtime.Sensor.Events.Reason, msg))
	}
	return ""
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

// runtimeKindWord is one evidence kind's human phrase, before any executable
// name is attached to it.
func runtimeKindWord(k rtevidence.EvidenceKind, msg messages) string {
	switch k {
	case rtevidence.KindExe:
		return msg.KindRunningAs
	case rtevidence.KindMappedLibrary:
		return msg.KindLoadedBy
	case rtevidence.KindExecEvent:
		return msg.KindExecutedEvt
	case rtevidence.KindLibraryLoadEvent:
		return msg.KindLibraryLoadEvent
	case rtevidence.KindBinaryRunning:
		return msg.KindBinaryRunning
	case rtevidence.KindBinaryExecuted:
		return msg.KindBinaryExecuted
	case rtevidence.KindRuntimeRunning:
		return msg.KindRuntimeRunning
	case rtevidence.KindRuntimeExecuted:
		return msg.KindRuntimeExecuted
	default:
		// Unreachable in practice: evidence.Reader's read-time validation
		// (validRecordedKinds) already strips any Kinds map entry outside
		// the four on-disk kinds before analyze ever builds an
		// evidence.Verdict from it, and the other four (the language-package
		// display kinds) are all named above. Kept as a safe fallback rather
		// than a panic, and never echoes k itself.
		return msg.RuntimeInUseFallback
	}
}

// runtimeKindLabel is one evidence kind's human phrase, naming the
// representative executable when one is known.
func runtimeKindLabel(k rtevidence.EvidenceKind, exe string, msg messages) string {
	suffix := ""
	if exe != "" {
		suffix = " " + escapeRuntimeText(exe)
	}
	return runtimeKindWord(k, msg) + suffix
}

// runtimeExposureText is the display phrase for an in-use verdict's
// Exposure. "" for ExposureUnknown — nothing worth a claim either way.
func runtimeExposureText(e analyze.Exposure, msg messages) string {
	switch e {
	case analyze.ExposureHostPublishedAll:
		return msg.ExposurePublishedAll
	case analyze.ExposureHostPublishedLoopback:
		return msg.ExposurePublishedLoopback
	case analyze.ExposureContainerListening:
		return msg.ExposureListening
	default:
		return ""
	}
}

// lastSeenText is the "last confirmed" clause the in-use runtime facts carry:
// every in-use evidence block shows it: the point this codebase actually re-observed
// the fact being shown, so an old sampling result or a past execution event
// is never misread as something happening right now. "" for a zero time
// (should not occur for an in-use container — buildContainerRuntime always
// sets LastSeen alongside a chosen combination — but a renderer must not
// print a zero date over a missing one).
func lastSeenText(t time.Time, msg messages) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf(msg.LastConfirmedPrefix, t.Format("01-02 15:04"))
}

// runtimeKindPhraseUnattributed is one evidence kind's standalone phrase —
// runtimeKindLabel's counterpart for when no executable name can be safely
// attached to it: either c.KindsAmbiguous (an OS package record aggregated
// more than one kind across more than one process; see ContainerRuntime's
// own doc comment) or the container has no observation at all
// (!HasProcess). Every phrase here reads correctly with nothing appended,
// unlike runtimeKindLabel's "running as"/"loaded by", which expect a name to
// follow.
func runtimeKindPhraseUnattributed(k rtevidence.EvidenceKind, msg messages) string {
	switch k {
	case rtevidence.KindExe, rtevidence.KindBinaryRunning, rtevidence.KindRuntimeRunning:
		return msg.UnattrRunning
	case rtevidence.KindMappedLibrary:
		return msg.UnattrLoadedAsLibrary
	case rtevidence.KindExecEvent, rtevidence.KindBinaryExecuted, rtevidence.KindRuntimeExecuted:
		return msg.UnattrExecuted
	case rtevidence.KindLibraryLoadEvent:
		return msg.UnattrLibraryLoadObserved
	default:
		// See runtimeKindLabel's own default branch: unreachable in
		// practice, kept as a safe fallback rather than a panic.
		return msg.RuntimeInUseFallback
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
func runtimeProcessesPhrase(exes []string, msg messages) string {
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
	s := fmt.Sprintf(msg.ProcessesPrefix, strings.Join(shown, ", "))
	if extra := len(exes) - n; extra > 0 {
		s += fmt.Sprintf(msg.MoreCount, extra)
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
func runtimeKindsPhrase(c analyze.ContainerRuntime, msg messages) string {
	return kindsPhrase(c, msg, false)
}

// kindsPhrase is runtimeKindsPhrase; bare drops the trailing colon a kind
// phrase may carry before the executable name ("実行中: `/bin/x`" becomes
// "実行中 `/bin/x`"), for views that already put the phrase after a label.
func kindsPhrase(c analyze.ContainerRuntime, msg messages, bare bool) string {
	if len(c.EvidenceKinds) == 0 {
		return msg.RuntimeInUseFallback
	}
	if c.HasProcess && !c.KindsAmbiguous {
		labels := make([]string, 0, len(c.EvidenceKinds))
		for _, k := range c.EvidenceKinds {
			if bare {
				suffix := ""
				if c.Process.Exe != "" {
					suffix = " " + escapeRuntimeText(c.Process.Exe)
				}
				labels = append(labels, strings.TrimSuffix(runtimeKindWord(k, msg), ":")+suffix)
				continue
			}
			labels = append(labels, runtimeKindLabel(k, c.Process.Exe, msg))
		}
		return strings.Join(labels, ", ")
	}
	labels := make([]string, 0, len(c.EvidenceKinds))
	for _, k := range c.EvidenceKinds {
		labels = append(labels, runtimeKindPhraseUnattributed(k, msg))
	}
	phrase := strings.Join(labels, "; ")
	if procs := runtimeProcessesPhrase(c.ProcessExes, msg); procs != "" {
		phrase += "; " + procs
	}
	return phrase
}

// inUseFacts are the separate facts behind an in-use verdict, all taken from
// the single representative container: the evidence kind(s) (with the
// executable that produced them, when that pairing is trustworthy), the
// exposure stage, whether it runs privileged, and the last-confirmed time.
// A card shows each on its own line.
type inUseFacts struct {
	Evidence      string
	EvidenceBare  string // Evidence without a colon before the executable name
	Exposure      string // "" when unknown
	HighPrivilege bool
	LastSeen      time.Time // zero when unknown
}

// runtimeInUseFacts collects the facts of an in-use Runtime from its
// representative container. ok is false when rt carries no such container
// (unreachable for a well-formed in-use Runtime).
func runtimeInUseFacts(rt analyze.Runtime, msg messages) (inUseFacts, bool) {
	c, ok := representativeContainer(rt)
	if !ok {
		return inUseFacts{}, false
	}
	return inUseFacts{
		Evidence:      runtimeKindsPhrase(c, msg),
		EvidenceBare:  kindsPhrase(c, msg, true),
		Exposure:      runtimeExposureText(c.Exposure, msg),
		HighPrivilege: c.HighPrivilege,
		LastSeen:      c.LastSeen,
	}, true
}

// runtimeShortWord picks the one-word evidence summary the watch bucket and
// the thread's compact lines use: "running"/"loaded" when the process is
// still present (a sampling-derived kind), "executed" when the only
// evidence is a past event.
func runtimeShortWord(kinds []rtevidence.EvidenceKind, msg messages) string {
	set := make(map[rtevidence.EvidenceKind]bool, len(kinds))
	for _, k := range kinds {
		set[k] = true
	}
	switch {
	case set[rtevidence.KindExe] || set[rtevidence.KindBinaryRunning] || set[rtevidence.KindRuntimeRunning]:
		return msg.ShortWordRunning
	case set[rtevidence.KindMappedLibrary]:
		return msg.ShortWordLoaded
	default:
		return msg.ShortWordExecuted
	}
}

// runtimeCounts tallies every package group's Runtime.Usage across every
// status section of r — the full-view summary line's "N in use / N not
// observed / N unavailable" — plus, separately, how many of those groups are
// Muted. A group whose Runtime was never attached (Usage == "") counts
// toward none of the first three, which is what keeps this a no-op tally
// when runtime is disabled (the summary line never calls it in that case
// regardless, since it also gates on r.Runtime == nil, but the tally itself
// is correct either way). muted overlaps notObserved by construction
// (analyze.ApplyMuting only ever mutes a not-observed group) rather
// than being mutually exclusive with it — the same kind of overlap the
// end-of-life/act-now segments already have elsewhere in this codebase.
func runtimeCounts(r analyze.Report) (inUse, notObserved, unavailable, muted int) {
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
				if g.Muted {
					muted++
				}
			}
		}
	}
	return inUse, notObserved, unavailable, muted
}

// mutedCount tallies every Muted PackageGroup in r — the single number
// every rendering's "🔇 Muted" line shows in place of the rows it hides.
// 0 whenever runtime.mute_unfixable_not_in_use is off, since
// analyze.ApplyMuting then never runs and every group's Muted stays
// at its zero value.
func mutedCount(r analyze.Report) int {
	_, _, _, muted := runtimeCounts(r)
	return muted
}

// filterMuted returns imgs with every Muted PackageGroup removed, and
// any image left with no packages dropped entirely. Every Slack rendering of
// the open-findings view calls this before laying out rows — a muted
// finding's row is never shown there, only mutedCount's tally represents
// it. It never mutates its input: each ImageFindings is copied before its
// Packages field is replaced. The generic webhook never calls this —
// BuildWebhookPayload keeps every group, muted or not.
func filterMuted(imgs []analyze.ImageFindings) []analyze.ImageFindings {
	out := make([]analyze.ImageFindings, 0, len(imgs))
	for _, img := range imgs {
		var kept []analyze.PackageGroup
		for _, g := range img.Packages {
			if !g.Muted {
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

// allMuted reports whether every one of groups is Muted — used by the
// generic webhook's diff.new[].muted, the coarsest-possible summary of a
// (image, package) change that can merge more than one PackageGroup. Always
// false for an empty slice.
func allMuted(groups []analyze.PackageGroup) bool {
	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if !g.Muted {
			return false
		}
	}
	return true
}

// changeReasonGroups is every group state.Compute recorded for a change's
// key this cycle, ordinary and end-of-life alike: end-of-life lives in its
// own Report section (and its own mergeSections pass), never merged into
// c.Groups, but it is exactly as disqualifying for muting as any
// ordinary group — analyze.ApplyMuting already blocks a key's
// muting over an end-of-life sibling — so unmutedReason must see
// it too, or it names the wrong fact for that exact transition. Both
// notify's Slack rendering (changeSuffixParts) and BuildWebhookPayload
// (buildDiffPayload) call this before calling unmutedReason, so the
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

// unmutedReason names, for display and for the webhook's diff
// reason, why a (image, package) key that was muted under
// runtime.mute_unfixable_not_in_use last cycle no longer is this cycle.
// Muting is decided for the whole key at once (analyze.ApplyMuting
// only ever marks every one of a key's groups Muted together), so the
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
func unmutedReason(groups []analyze.PackageGroup, msg messages) string {
	for _, g := range groups {
		if g.Runtime.Usage == rtevidence.UsageInUse {
			return msg.UnmutedNowInUse
		}
	}
	for _, g := range groups {
		if g.Priority == analyze.PriorityActNow {
			return msg.UnmutedActNow
		}
	}
	for _, g := range groups {
		if g.Status == scanner.StatusFixed {
			return msg.UnmutedFixAvailable
		}
	}
	for _, g := range groups {
		if g.Status == scanner.StatusEndOfLife {
			return msg.UnmutedNowEndOfLife
		}
	}
	for _, g := range groups {
		if g.Runtime.Usage == rtevidence.UsageUnavailable {
			return msg.UnmutedInsufficientObservation
		}
	}
	for _, g := range groups {
		switch g.Status {
		case scanner.StatusAffected, scanner.StatusWontFix:
		default:
			return msg.UnmutedNotEligible
		}
	}
	return msg.UnmutedInsufficientObservation
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
// Muted verdict) to the webhook's findings[].runtime object, or nil when
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
	if g.Muted {
		p.Muted = true
		p.MutedReason = string(g.MutedReason)
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
