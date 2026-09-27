// Runtime-usage projection: AttachRuntime folds one Sensor evidence.Snapshot,
// corroborated against this cycle's own Docker inspects, into every
// PackageGroup's Runtime field and the Report's own Runtime summary. It
// never changes what Build already computed — priority, aggregation,
// section membership are all untouched — it only adds a judgement notify
// can choose to show alongside them.
package analyze

import (
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// starttimeTick is the wall-clock duration one /proc/<pid>/stat starttime
// tick spans: USER_HZ=100 on every architecture this codebase targets
// (x86_64, aarch64) — the same assumption internal/sensor/boottime.go
// documents and relies on for the identical conversion on the Sensor side.
const starttimeTick = 10 * time.Millisecond

// starttimeMatchTolerance is how far apart InitProcess.Starttime (converted
// to wall-clock via GenerationInspect.BootTime) and Docker's own StartedAt
// may be and still be treated as the same container generation.
const starttimeMatchTolerance = 2 * time.Second

// RuntimeInfo is a Report's Sensor-wide runtime status, attached by
// AttachRuntime and mirrored in the webhook's top-level "runtime" object.
// Its zero value is never used on its own — a Report with runtime disabled
// (or that never called AttachRuntime) leaves Report.Runtime nil, which is
// what every notify rendering that shows it gates on.
//
// Sensor is the Sensor's own self-report, kept verbatim: evidence.
// SensorInfo's own doc comment is explicit that this is not the richer
// status a reader derives for display (accounting for a stale or entirely
// missing evidence file) — that folding belongs to the renderer
// (internal/notify/format.go), using LoadFailed/NotReporting below plus a
// staleness check against the current time, not to this package.
type RuntimeInfo struct {
	Sensor evidence.SensorInfo
	// LoadFailed is true when the evidence file could not be read and
	// validated at all this cycle (evidence.ErrInvalid, or any other error
	// the Provider returned that isn't more specifically NotReporting).
	LoadFailed bool
	// NotReporting is true when no evidence file has ever appeared
	// (evidence.ErrNotReporting) — a more specific case of LoadFailed, kept
	// as its own flag because the two read differently ("the Sensor hasn't
	// started" vs. "something is wrong with what it wrote").
	NotReporting bool
}

// unavailableReason is the single UnavailableReason a whole cycle's runtime
// judgement collapses to when the evidence file itself couldn't be trusted
// at all — before any per-container matching is even attempted.
func (rt RuntimeInfo) unavailableReason() evidence.UnavailableReason {
	if rt.NotReporting {
		return evidence.ReasonSensorNotReporting
	}
	return evidence.ReasonEvidenceInvalid
}

// GenerationInspect is what AttachRuntime needs, beyond the evidence
// Snapshot itself, to confirm a generation is still the one actually
// running and to judge its exposure. BootTime is the host's boot time (from
// /proc/stat's "btime" line), used to convert InitProcess.Starttime — a
// boot-relative clock-tick value, the same convention /proc/<pid>/stat
// itself uses — into a wall-clock instant comparable with Docker's own
// StartedAt. AttachRuntime never reads host state itself (it stays a pure
// function of its inputs, like the rest of this package); internal/runner
// reads /proc/stat once per cycle and passes the result in here.
type GenerationInspect struct {
	// ByContainer is this cycle's docker.Client.Inspect result, keyed by
	// container ID. A container with no entry (Inspect was not called for
	// it, or failed) is treated as unmatchable, never as a zero-Pid
	// process — see matchGeneration.
	ByContainer map[string]docker.InspectResult
	// BootTime is the host's boot time. The zero value means "unknown": no
	// generation can be matched, since InitProcess.Starttime cannot be
	// converted to a wall-clock instant at all.
	BootTime time.Time
}

func (gi GenerationInspect) inspect(id string) (docker.InspectResult, bool) {
	insp, ok := gi.ByContainer[id]
	return insp, ok
}

// Exposure and privilege are only meaningful on an in-use verdict; see
// Runtime's own doc comment.

// ContainerProcess is the process facts behind one container's in-use
// verdict: the strongest same-sample/same-process combination
// strongestCombo picked for it. Zero value when the container's own Usage is
// not in_use.
type ContainerProcess struct {
	Exe           string
	EffectiveUID  int
	Userns        bool
	DangerousCaps []string // sorted capability names; nil when none
	Privileged    bool
}

// InstanceRuntime is one language-package Instance's own verdict within one
// container, backing the webhook's findings[].runtime.containers[].
// instances[]: the same version of a package can be embedded in two
// binaries, e.g. /app/api and /app/tool, and only one of them running makes
// that Instance in use while the other stays not_observed — a group-level
// verdict alone would hide that distinction. Only ever populated for a
// language-package group (Class == inventory.ClassLang) — an OS package's
// PackageRef is already the whole identity, so it has nothing this level of
// detail would add beyond ContainerRuntime's own Usage/Reason.
type InstanceRuntime struct {
	Type    string
	Target  string
	PkgPath string
	Usage   evidence.Usage
	Reason  evidence.UnavailableReason
}

// ContainerRuntime is one container's own runtime-usage verdict for a
// PackageGroup, backing the webhook's findings[].runtime.containers[]. It
// exists apart from the PackageGroup-level Runtime because a package can be
// in use in one container of an entity and not another
// (a replicated service where only one replica happens to have exercised
// it), and because the diagnostic reason a specific container failed to
// judge is more useful than the group's single folded reason.
type ContainerRuntime struct {
	ContainerID         string
	Name                string
	GenerationStartedAt time.Time // zero when no generation matched
	Usage               evidence.Usage
	Reason              evidence.UnavailableReason
	// EvidenceKinds is this container's own folded evidence kinds (only
	// meaningful when Usage == UsageInUse) — kept apart from the
	// PackageGroup-level Runtime.EvidenceKinds precisely so a display line
	// can name the kind(s) that came from this same container's own Process,
	// never a kind another container contributed.
	EvidenceKinds []evidence.EvidenceKind
	// KindsAmbiguous is true when EvidenceKinds came from an OS package's
	// record and that record's own Kinds map has more than one entry. An
	// OSPackageEvidence record aggregates every kind and every process
	// observation across every process that ever touched the package into
	// one Kinds map and one Observations list, independently of each other —
	// unlike an ExecutableEvidence record, whose Kinds and Observations both
	// describe the one executable path the record is keyed on. Once more
	// than one kind is present on such a record, no single kind can be
	// safely said to have come from whichever one observation
	// strongestSource picked as strongest, so a rendering must show the
	// kinds and the observed processes as two separate, unattributed lists
	// rather than pairing a kind with Process.Exe. Always false for a
	// language package.
	KindsAmbiguous bool
	// ProcessExes is the distinct executables observed for this record, in
	// the order Observations lists them, populated only when
	// KindsAmbiguous. It is the unattributed "processes: ..." list a
	// rendering shows instead of a kind/executable pairing it cannot
	// support.
	ProcessExes   []string
	LastSeen      time.Time
	Ports         []string // this container's declared/published ports, only ever informative when Usage == UsageInUse
	Exposure      Exposure
	HighPrivilege bool
	// HasProcess is true only when Process was populated from a real
	// ProcessObservation (strongestSource found at least one across every
	// source). A Usage == UsageInUse container can have evidence kinds but
	// no observation behind them at all (e.g. only an exec_event the Sensor
	// recorded without a same-sample identity snapshot) — Process stays the
	// zero value in that case, and a rendering must gate on this field
	// rather than on Usage alone before showing any process fact.
	HasProcess bool
	Process    ContainerProcess  // meaningful only when HasProcess is true
	Instances  []InstanceRuntime // language packages only; see InstanceRuntime's own doc comment
}

// Runtime is the projected runtime-usage verdict analyze.AttachRuntime
// attaches to a PackageGroup, folding every Instance judged in every
// container currently running this entity with evidence.ProjectGroup (used
// at both the per-container and the cross-container level, so the same
// in-use-wins/unavailable-otherwise/not-observed-last order applies no
// matter how many verdicts contributed). See PackageGroup.Runtime's own doc
// comment for the zero-value contract every notify rendering depends on.
type Runtime struct {
	Usage          evidence.Usage
	Reason         evidence.UnavailableReason // only meaningful when Usage == UsageUnavailable
	EvidenceKinds  []evidence.EvidenceKind    // only meaningful when Usage == UsageInUse
	EventsCoverage evidence.EventsCoverage    // only carried when Usage != UsageInUse
	// Exposure and HighPrivilege are the strongest same-sample/same-process
	// combination across every container this group is in use in. Zero
	// values (ExposureUnknown, false) when Usage != UsageInUse.
	Exposure      Exposure
	HighPrivilege bool
	// Containers is the per-container detail behind the folded verdict
	// above, one entry per container in the owning ImageFindings.Containers.
	// Nil when that list was empty (Build received no containers for this
	// entity, or the whole cycle's evidence couldn't be trusted at all —
	// RuntimeInfo.LoadFailed/NotReporting).
	Containers []ContainerRuntime
}

// AttachRuntime judges every PackageGroup in every status section of r
// against snap (already read and validated by an evidence.Provider) and
// insp (this cycle's own docker.Client.Inspect results), and records the
// Sensor-wide status on r.Runtime. rt.LoadFailed/NotReporting short-circuits
// every group straight to UsageUnavailable without attempting any
// generation matching — a Sensor that hasn't produced a trustworthy
// snapshot at all has nothing to corroborate against.
//
// AttachRuntime mutates r's status-section slices in place (their
// PackageGroup elements) rather than rebuilding them: it never changes
// their length, order, or any field it does not itself own, so priority,
// aggregation, and every existing renderer that ignores PackageGroup.Runtime
// see the exact Report Build already produced.
func AttachRuntime(r *Report, rt RuntimeInfo, snap evidence.Snapshot, insp GenerationInspect, now time.Time) {
	r.Runtime = &rt
	sections := [][]ImageFindings{r.Actionable, r.Watch, r.WontFix, r.EOLPackages}
	for _, section := range sections {
		for i := range section {
			img := &section[i]
			for j := range img.Packages {
				img.Packages[j].Runtime = groupRuntime(img.Packages[j], img.Subject, img.Containers, rt, snap, insp, now)
			}
		}
	}
}

// sensorWideStatus summarizes the two Sensor-wide conditions that override a
// per-instance not_observed verdict, or the reason an unmatched container
// gets, regardless of what that instance's own generation otherwise looks
// like:
//
//   - forced/forcedReason is set when the Sensor's own self-report
//     (isolation_failed: it never started observing at all; permission_denied:
//     its reads are being refused) means nothing it wrote this cycle can
//     support "we looked and didn't see it" — every such verdict becomes
//     unavailable with the Sensor's own reason instead. An already-established
//     in_use verdict is never touched by this (callers apply it only to
//     UsageNotObserved and to the "no matching generation" case) — it recorded
//     something the generation actually observed before, and today's Sensor
//     trouble doesn't retroactively unobserve it.
//   - stale is the Sensor-wide heartbeat staleness (evidence.IsStale against
//     rt.Sensor.HeartbeatAt), independent of any one generation's own
//     LastVerifiedAt: a generation record that still looks individually fresh
//     from a Sensor whose heartbeat has otherwise gone stale is not enough on
//     its own to support a not_observed conclusion either — both freshness
//     checks are required, not just the generation's own.
func sensorWideStatus(rt RuntimeInfo, now time.Time) (forcedReason evidence.UnavailableReason, forced bool, stale bool) {
	stale = evidence.IsStale(rt.Sensor.HeartbeatAt, now, rt.Sensor.IntervalSeconds)
	switch rt.Sensor.Status {
	case evidence.SensorIsolationFailed:
		return evidence.ReasonIsolationFailed, true, stale
	case evidence.SensorPermissionDenied:
		return evidence.ReasonPermissionDenied, true, stale
	default:
		return "", false, stale
	}
}

// groupRuntime judges one PackageGroup across every container running its
// entity, folding per-container verdicts (themselves a fold of the group's
// own Instances) with the same evidence.ProjectGroup rule at both levels —
// that rule's result never depends on how many verdicts contributed to it
// or in what order, so nesting the fold this way is safe.
func groupRuntime(g PackageGroup, subject inventory.ImageSubject, containers []inventory.Container, rt RuntimeInfo, snap evidence.Snapshot, insp GenerationInspect, now time.Time) Runtime {
	if rt.LoadFailed || rt.NotReporting {
		return Runtime{Usage: evidence.UsageUnavailable, Reason: rt.unavailableReason()}
	}
	forcedReason, forced, sensorStale := sensorWideStatus(rt, now)

	groupVerdicts := make([]evidence.Verdict, 0, len(containers))
	containerRTs := make([]ContainerRuntime, 0, len(containers))
	for _, c := range containers {
		// A container labeled io.kestrelynx.runtime.exclude=true is left out
		// of runtime judgement, projection, sorting and display entirely — it
		// simply never contributes a verdict, the same as if Build had never
		// been given it.
		if c.RuntimeExcluded {
			continue
		}
		containerInsp, _ := insp.inspect(c.ID)
		gen, unmatchedReason, ok := matchGeneration(snap.Generations, c.ID, containerInsp, subject, insp.BootTime)
		if !ok && forced {
			unmatchedReason = forcedReason
		}

		var instanceVerdicts []evidence.Verdict
		var sourcePool []evidenceSource
		var instanceRTs []InstanceRuntime
		if ok {
			for _, inst := range g.Instances {
				v, srcs := instanceVerdictAndSources(g, inst, gen)
				// Judge* deliberately does not check any freshness or
				// Sensor-wide health itself (see JudgeOSPackage's own doc
				// comment): every verdict short of in_use downgrades to
				// unavailable here, either under the Sensor-wide override
				// above (nothing this cycle's Sensor wrote can be trusted at
				// all) or, for a not_observed verdict specifically, under
				// the narrower generation/heartbeat staleness check. An
				// in_use verdict is never touched by either — it recorded
				// something the generation actually observed, and trouble
				// discovered afterward doesn't retroactively unobserve it.
				if v.Usage != evidence.UsageInUse {
					switch {
					case forced:
						v = evidence.Verdict{Usage: evidence.UsageUnavailable, Reason: forcedReason, EventsCoverage: gen.EventsCoverage}
					case v.Usage == evidence.UsageNotObserved && (sensorStale || !evidence.GenerationFresh(gen, now, snap.Sensor.IntervalSeconds)):
						v = evidence.Verdict{Usage: evidence.UsageUnavailable, Reason: evidence.ReasonSensorStale, EventsCoverage: gen.EventsCoverage}
					}
				}
				instanceVerdicts = append(instanceVerdicts, v)
				if v.Usage == evidence.UsageInUse {
					sourcePool = append(sourcePool, srcs...)
				}
				if g.Class == inventory.ClassLang {
					instanceRTs = append(instanceRTs, InstanceRuntime{
						Type: inst.Type, Target: inst.Target, PkgPath: inst.PkgPath,
						Usage: v.Usage, Reason: v.Reason,
					})
				}
			}
		} else {
			instanceVerdicts = []evidence.Verdict{{Usage: evidence.UsageUnavailable, Reason: unmatchedReason}}
			if g.Class == inventory.ClassLang {
				for _, inst := range g.Instances {
					instanceRTs = append(instanceRTs, InstanceRuntime{
						Type: inst.Type, Target: inst.Target, PkgPath: inst.PkgPath,
						Usage: evidence.UsageUnavailable, Reason: unmatchedReason,
					})
				}
			}
		}

		cv := evidence.ProjectGroup(instanceVerdicts)
		groupVerdicts = append(groupVerdicts, cv)
		cr := buildContainerRuntime(c, gen, ok, cv, sourcePool, containerInsp)
		cr.Instances = instanceRTs
		containerRTs = append(containerRTs, cr)
	}
	// In-use containers sort first, strongest exposure/privilege combination
	// among them next, container ID last as a deterministic tie-break. This
	// is what makes containerRTs[0] — when the group itself is in_use — the
	// single container every display fact (executable, exposure, privilege,
	// evidence kinds, last-seen time) is read from together: never one
	// container's executable paired with another's exposure or privilege.
	sort.Slice(containerRTs, func(i, j int) bool {
		a, b := containerRTs[i], containerRTs[j]
		ai, bi := a.Usage == evidence.UsageInUse, b.Usage == evidence.UsageInUse
		if ai != bi {
			return ai
		}
		if ai {
			if sa, sb := comboScore(a.Exposure, a.HighPrivilege), comboScore(b.Exposure, b.HighPrivilege); sa != sb {
				return sa > sb
			}
		}
		return a.ContainerID < b.ContainerID
	})

	agg := evidence.ProjectGroup(groupVerdicts)
	exposure, highPriv := ExposureUnknown, false
	if agg.Usage == evidence.UsageInUse && len(containerRTs) > 0 && containerRTs[0].Usage == evidence.UsageInUse {
		exposure, highPriv = containerRTs[0].Exposure, containerRTs[0].HighPrivilege
	}
	return Runtime{
		Usage:          agg.Usage,
		Reason:         agg.Reason,
		EvidenceKinds:  agg.EvidenceKinds,
		EventsCoverage: agg.EventsCoverage,
		Exposure:       exposure,
		HighPrivilege:  highPriv,
		Containers:     containerRTs,
	}
}

// evidenceSource is one on-disk record — a single OSPackageEvidence, or a
// single ExecutableEvidence — contributing to an in-use verdict, with its
// own evidence kinds and its own observations kept together as one unit.
// Pooling sources (rather than pooling their observations into one flat
// list, discarding which record each one came from) is what lets the
// display layer show a kind next to the executable that actually produced
// it: converting exec_event into "executed" and pairing it with the exe of
// whichever observation happened to win a cross-record pool would attribute
// that kind to a file it was never observed for. Kinds is already
// display-ready (langKinds' output for a language source, kindsOf's for an
// OS source) — see instanceVerdictAndSources.
type evidenceSource struct {
	kinds        []evidence.EvidenceKind
	observations []evidence.ProcessObservation
	// lastSeen is the max of every one of this record's own Kinds map
	// LastSeen values — the evidence's own time, independent of whether any
	// ProcessObservation happens to survive alongside it. Used as the
	// in-use "last confirmed" time when no observation does (see
	// buildContainerRuntime).
	lastSeen time.Time
	// ambiguous is true only for an OS package record whose own Kinds map
	// has more than one entry — see ContainerRuntime.KindsAmbiguous. Always
	// false for an executable record, whose Kinds and Observations both
	// describe the one path the record is keyed on by construction.
	ambiguous bool
}

// maxKindLastSeen returns the latest LastSeen among kinds' values, or the
// zero time when kinds is empty.
func maxKindLastSeen(kinds map[evidence.EvidenceKind]evidence.KindObservation) time.Time {
	var latest time.Time
	for _, k := range kinds {
		if k.LastSeen.After(latest) {
			latest = k.LastSeen
		}
	}
	return latest
}

// maxLangKindLastSeen is maxKindLastSeen restricted to exe and exec_event —
// the only two on-disk kinds langKindsOf ever turns into a language-package
// display kind (KindBinaryRunning/Executed, KindRuntimeRunning/Executed). An
// ExecutableEvidence record's Kinds map can also carry mapped_library/
// library_load_event (this same file mapped as a library by some process,
// independent of whether it also ran as its own process) — mixing that
// time into a language package's "last confirmed" would claim a fact only
// exe/exec_event actually support.
func maxLangKindLastSeen(kinds map[evidence.EvidenceKind]evidence.KindObservation) time.Time {
	var latest time.Time
	if k, ok := kinds[evidence.KindExe]; ok && k.LastSeen.After(latest) {
		latest = k.LastSeen
	}
	if k, ok := kinds[evidence.KindExecEvent]; ok && k.LastSeen.After(latest) {
		latest = k.LastSeen
	}
	return latest
}

// maxSourceLastSeen returns the latest of every source's own lastSeen, for
// the case where no source has an Observations entry to derive a more
// specific process-level LastSeen from at all.
func maxSourceLastSeen(sources []evidenceSource) time.Time {
	var latest time.Time
	for _, s := range sources {
		if s.lastSeen.After(latest) {
			latest = s.lastSeen
		}
	}
	return latest
}

// mergedSourceKinds is evidenceKindsOf's counterpart for the no-observation
// case: with no source's combination judged strongest, there is no single
// "winning" source to take EvidenceKinds from the way the observed branch
// does, but the kind(s) every source carries are still real evidence and
// must still reach the rendering (unattributed — buildContainerRuntime never
// sets HasProcess alongside this) rather than be dropped. Returns the sorted
// union of every source's own kinds, or nil when none has any.
func mergedSourceKinds(sources []evidenceSource) []evidence.EvidenceKind {
	set := make(map[evidence.EvidenceKind]bool)
	for _, s := range sources {
		for _, k := range s.kinds {
			set[k] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]evidence.EvidenceKind, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// distinctExes returns the distinct, non-empty executable paths observed
// across obs, in the order Observations already lists them (a slice read
// straight from the evidence file, never a map, so this order is already
// deterministic).
func distinctExes(obs []evidence.ProcessObservation) []string {
	seen := make(map[string]bool, len(obs))
	var out []string
	for _, o := range obs {
		if o.Exe == "" || seen[o.Exe] {
			continue
		}
		seen[o.Exe] = true
		out = append(out, o.Exe)
	}
	return out
}

// instanceVerdictAndSources judges one Instance of a PackageGroup against
// gen: an OS package matches by exact name/version, a binary-embedded
// language package by its Instance's own Target, a runtime-loaded language
// package by the ecosystem's runtime-executable-name table (both via
// internal/evidence's existing Judge* functions). sources is only ever
// non-empty alongside an in-use verdict.
func instanceVerdictAndSources(g PackageGroup, inst Instance, gen evidence.Generation) (v evidence.Verdict, sources []evidenceSource) {
	switch {
	case g.Class == inventory.ClassOS:
		v = evidence.JudgeOSPackage(gen, g.PackageRef())
		if v.Usage == evidence.UsageInUse {
			sources = osPackageSources(gen, g.PackageRef())
		}
	case evidence.IsEmbeddedEcosystem(g.Ecosystem):
		v = evidence.JudgeEmbeddedBinary(gen, inst.Target)
		if v.Usage == evidence.UsageInUse {
			sources = executableSourcesForTarget(gen, inst.Target, true)
		}
	default:
		v = evidence.JudgeRuntimeLoaded(gen, g.Ecosystem)
		if v.Usage == evidence.UsageInUse {
			sources = executableSourcesForEcosystem(gen, g.Ecosystem)
		}
	}
	return v, sources
}

// evidenceKindsOf returns a Kinds map's keys, sorted — the OS-side
// counterpart of langKindsOf below, kept as its own small function rather
// than reaching into internal/evidence for its unexported kindsOf.
func evidenceKindsOf(kinds map[evidence.EvidenceKind]evidence.KindObservation) []evidence.EvidenceKind {
	if len(kinds) == 0 {
		return nil
	}
	out := make([]evidence.EvidenceKind, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// langKindsOf converts one executable's on-disk kinds (exe, exec_event) into
// the language-package display kinds (binary_running/executed or
// runtime_running/executed), the same mapping internal/evidence's own
// unexported langKinds applies when judging a language package — repeated
// here, rather than exported from that package, because this package needs
// it paired with a single executable's own identity (see evidenceSource),
// which a Verdict alone does not carry.
func langKindsOf(kinds map[evidence.EvidenceKind]evidence.KindObservation, embedded bool) []evidence.EvidenceKind {
	var out []evidence.EvidenceKind
	if _, ok := kinds[evidence.KindExe]; ok {
		if embedded {
			out = append(out, evidence.KindBinaryRunning)
		} else {
			out = append(out, evidence.KindRuntimeRunning)
		}
	}
	if _, ok := kinds[evidence.KindExecEvent]; ok {
		if embedded {
			out = append(out, evidence.KindBinaryExecuted)
		} else {
			out = append(out, evidence.KindRuntimeExecuted)
		}
	}
	return out
}

// osPackageSources returns the one evidenceSource for the OSPackageEvidence
// record JudgeOSPackage matched ref against — the same exact name/version
// match, done again here rather than threaded back out of Judge*, since
// Judge* deliberately returns only a Verdict.
func osPackageSources(gen evidence.Generation, ref inventory.PackageRef) []evidenceSource {
	for _, p := range gen.OSPackages {
		if p.Name == ref.Name && p.Version == ref.Version {
			kinds := evidenceKindsOf(p.Kinds)
			return []evidenceSource{{
				kinds:        kinds,
				observations: p.Observations,
				lastSeen:     maxKindLastSeen(p.Kinds),
				// This one record aggregates every kind and every process
				// observation across every process that ever touched the
				// package, independently of each other — once more than one
				// kind survives, neither can be safely paired with whichever
				// single observation turns out strongest.
				ambiguous: len(kinds) > 1,
			}}
		}
	}
	return nil
}

// executableSourcesForTarget returns one evidenceSource per executable
// JudgeEmbeddedBinary matched target against (normalized the same way that
// function does) — ordinarily exactly one, but more than one record can
// legitimately exist for the same path across dev/inode variation.
func executableSourcesForTarget(gen evidence.Generation, target string, embedded bool) []evidenceSource {
	if target == "" {
		return nil
	}
	norm := normalizeRuntimePath(target)
	var out []evidenceSource
	for _, exe := range gen.Executables {
		if normalizeRuntimePath(exe.Path) == norm {
			out = append(out, evidenceSource{
				kinds:        langKindsOf(exe.Kinds, embedded),
				observations: exe.Observations,
				lastSeen:     maxLangKindLastSeen(exe.Kinds),
			})
		}
	}
	return out
}

// executableSourcesForEcosystem returns one evidenceSource per executable
// JudgeRuntimeLoaded matched eco's runtime-name table against — possibly
// more than one distinct executable (e.g. "python" and "python3.11" both
// running), each kept as its own source so its own kind(s) never spill onto
// a different executable's identity.
func executableSourcesForEcosystem(gen evidence.Generation, eco inventory.Ecosystem) []evidenceSource {
	var out []evidenceSource
	for _, exe := range gen.Executables {
		if evidence.RuntimeNameMatches(eco, exe.Path) {
			out = append(out, evidenceSource{
				kinds:        langKindsOf(exe.Kinds, false),
				observations: exe.Observations,
				lastSeen:     maxLangKindLastSeen(exe.Kinds),
			})
		}
	}
	return out
}

// normalizeRuntimePath strips exactly one leading "/" so that Trivy's
// Result.Target (recorded without one) and the Sensor's executables[].path
// (a container-root-relative absolute path, which always has one) compare
// equal (evidence.normalizeContainerPath applies the identical rule
// internally; it is unexported, so this package repeats the one-line rule
// rather than reaching into evidence's internals for it).
func normalizeRuntimePath(p string) string {
	if len(p) > 0 && p[0] == '/' {
		return p[1:]
	}
	return p
}

// matchGeneration finds the one evidence.Generation whose identity — the
// same container ID, the init process's PID and starttime agreeing with what
// Docker reports now, and the currently-inspected image digest agreeing with
// the entity subject actually scanned — confirms it is still the generation
// actually running. A generation whose
// container ID matches but nothing else does is reported as
// ReasonGenerationUnverified (this container ID is known, but its evidence
// does not currently correspond to it); no evidence generation for this
// container ID at all is ReasonContainerNotObserved.
func matchGeneration(gens []evidence.Generation, id string, insp docker.InspectResult, subject inventory.ImageSubject, bootTime time.Time) (evidence.Generation, evidence.UnavailableReason, bool) {
	if id == "" {
		return evidence.Generation{}, evidence.ReasonContainerNotObserved, false
	}
	if bootTime.IsZero() {
		return evidence.Generation{}, evidence.ReasonGenerationUnverified, false
	}
	sawID := false
	for _, g := range gens {
		if g.Container.Runtime != "docker" || g.Container.ID != id {
			continue
		}
		sawID = true
		if g.Init.PID != insp.Pid {
			continue
		}
		wallStart := bootTime.Add(time.Duration(g.Init.Starttime) * starttimeTick)
		diff := wallStart.Sub(insp.StartedAt)
		if diff < 0 {
			diff = -diff
		}
		if diff > starttimeMatchTolerance {
			continue
		}
		if !imageMatchesSubject(insp, subject) {
			return evidence.Generation{}, evidence.ReasonGenerationUnverified, false
		}
		return g, "", true
	}
	if sawID {
		return evidence.Generation{}, evidence.ReasonGenerationUnverified, false
	}
	return evidence.Generation{}, evidence.ReasonContainerNotObserved, false
}

// imageMatchesSubject reports whether insp's currently-inspected image
// identity agrees with subject, the entity this cycle's scan actually
// pinned. Only a resolved, config-digest subject can be verified this way —
// a reference-fallback or registry-digest scan has nothing comparable to
// insp.Image (Docker's own inspect always reports a config-kind ImageID),
// so it is never treated as verified.
func imageMatchesSubject(insp docker.InspectResult, subject inventory.ImageSubject) bool {
	if !subject.Resolved || subject.Key.Digest.Kind != inventory.DigestConfig {
		return false
	}
	return insp.Image.Kind == inventory.DigestConfig && insp.Image.String() == subject.Key.Digest.String()
}

// buildContainerRuntime assembles one container's ContainerRuntime record:
// its own folded verdict (cv), plus — only when that verdict is in_use —
// the strongest same-sample/same-process combination among obsPool and the
// ports/privileged facts insp carries.
func buildContainerRuntime(c inventory.Container, gen evidence.Generation, matched bool, cv evidence.Verdict, sources []evidenceSource, insp docker.InspectResult) ContainerRuntime {
	cr := ContainerRuntime{ContainerID: c.ID, Name: c.Name, Usage: cv.Usage, Reason: cv.Reason}
	if matched {
		cr.GenerationStartedAt = gen.StartedAt
		cr.LastSeen = gen.LastVerifiedAt
	}
	if cv.Usage != evidence.UsageInUse {
		return cr
	}
	best, src, ok := strongestSource(sources, insp)
	if !ok {
		// Kinds exist (this container is in_use) but no source has even one
		// ProcessObservation — an exec_event the Sensor recorded without a
		// same-sample identity snapshot, for instance. The evidence's own
		// kind timestamps are still a true "last confirmed" time; the
		// generation's own LastVerifiedAt is not, since it can be far more
		// recent than any actual observation of this specific fact. No
		// Process fact is shown at all: there is nothing observed to name —
		// but the kind(s) themselves are still real evidence and must still
		// reach the rendering (unattributed, exactly as the ambiguous case
		// above already renders them), not be silently dropped into a bare
		// "in use".
		cr.EvidenceKinds = mergedSourceKinds(sources)
		cr.LastSeen = maxSourceLastSeen(sources)
		return cr
	}
	// EvidenceKinds comes from the same source (executable/package record)
	// the winning observation did — never the group's own merged
	// Runtime.EvidenceKinds (evidence.ProjectGroup's union across every
	// Instance) — so a kind is never shown paired with an executable that
	// didn't actually produce it.
	cr.EvidenceKinds = src.kinds
	cr.KindsAmbiguous = src.ambiguous
	if src.ambiguous {
		cr.ProcessExes = distinctExes(src.observations)
	}
	cr.Exposure = best.exposure
	cr.HighPrivilege = best.highPriv
	cr.LastSeen = best.obs.LastSeen
	cr.Ports = formatPorts(best.obs.Listeners)
	cr.HasProcess = true
	cr.Process = ContainerProcess{
		Exe:           best.obs.Exe,
		EffectiveUID:  best.obs.EffectiveUID,
		Userns:        best.obs.Userns,
		DangerousCaps: dangerousCapNames(best.obs.CapEff),
		Privileged:    insp.Privileged,
	}
	return cr
}
