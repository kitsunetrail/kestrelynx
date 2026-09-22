package main

import "time"

// Verdict is match's per-Finding usage judgement. "inferred" is deliberately
// never produced. observation_failed is never a verdict value — that
// concept lives entirely in ObservationState, so the two never collide.
type Verdict string

const (
	VerdictConfirmed     Verdict = "confirmed"
	VerdictUnresolved    Verdict = "unresolved"
	VerdictUnobserved    Verdict = "unobserved"
	VerdictNotDetermined Verdict = "not_determined"
)

// TrivyMatch is match's Trivy-cross-referencing verdict for one path whose
// Ownership is otherwise known. Unlike Ownership, this requires Trivy data,
// so only match computes it.
type TrivyMatch string

const (
	TrivyMatchMatched            TrivyMatch = "matched"
	TrivyMatchVersionMismatch    TrivyMatch = "version_mismatch"
	TrivyMatchNoFinding          TrivyMatch = "no_finding"
	TrivyMatchMultipleCandidates TrivyMatch = "multiple_candidates"
	TrivyMatchNotApplicable      TrivyMatch = "not_applicable"
)

// unresolved/unobserved/not_determined factor vocabulary.
const (
	factorDBAbsent     = "db_absent"
	factorDBError      = "db_error"
	factorNoFileList   = "no_file_list"
	factorShortLived   = "short_lived"
	factorLangPkg      = "lang_pkg_unmappable"
	factorTransient    = "transient_dlopen"
	factorNoObserved   = "no_observation"
	factorTopFailed    = "top_failed"
	factorProcDenied   = "proc_denied"
	factorProcGone     = "proc_gone"
	factorRootfsDenied = "rootfs_denied"
)

// Case is the ground-truth definition for one case variant (GT-A): which
// packages are expected to be in use, and gt_b_scope (the packages GT-B can
// actually confirm used/not-used for this case). FactorHint declares
// periodic-work behavior the case's own test program is known to exercise
// (short_lived, transient_dlopen); it is never used to assign
// db_absent/db_error/unowned/deleted, which are always derived from
// observation.
type Case struct {
	CaseID   string          `json:"case_id"`
	Image    string          `json:"image"`
	Expected []ExpectedUsage `json:"expected"`
	GTBScope []string        `json:"gt_b_scope,omitempty"` // package names GT-B can confirm used/not-used for
	// GapClassHint and GapClassRationale declare a shortfall that applies
	// to the whole case rather than to one named package — a statically
	// linked image, where every package's shortfall has the same single
	// cause and naming them one by one would be a transcription of the
	// package list. It applies only to packages with no declaration of
	// their own, and, like a per-package declaration, is accepted only when
	// the observation bears it out.
	GapClassHint      string `json:"gap_class_hint,omitempty"` // "E4"
	GapClassRationale string `json:"gap_class_rationale,omitempty"`
	// FixtureNotes carries the case's own record of how its fixture was
	// built and why: which version of a dependency was chosen and on what
	// evidence, what the layout is, and what the case cannot establish. It
	// is read through unchanged so the reasoning travels with the result
	// rather than living only in whoever wrote the case.
	FixtureNotes map[string]any `json:"fixture_notes,omitempty"`
}

// ExpectedUsage is one package's GT-A entry. It separates two different
// claims that must never be collapsed into one field:
//
//   - Usage is what the case declares about reality: is this package
//     actually used by the running workload or not. It is a statement about
//     the fixture, made before the run.
//   - Verdict is what this harness is expected to conclude. The two differ
//     wherever the first stage has no way to reach the truth — a language
//     package whose extension module really is loaded still has no path
//     from Trivy's PkgPath to a mapped file, so its expected verdict is
//     "unobserved" while its expected usage is "used".
//
// Recording only the verdict would turn a known limitation of the matcher
// into a claim that the package is unused, and the discrepancy table would
// then report agreement where there is none.
type ExpectedUsage struct {
	Package string `json:"package"`
	Class   string `json:"class"`          // "os" | "lang"
	Usage   string `json:"expected_usage"` // "used" | "not_used" | "unknown"
	// ExpectedVerdict is one of the four verdict values
	// (confirmed/unresolved/unobserved/not_determined), never a usage word.
	ExpectedVerdict string `json:"expected_verdict"`
	ExpectedFactor  string `json:"expected_factor,omitempty"`
	FactorHint      string `json:"factor_hint,omitempty"` // "short_lived" | "transient_dlopen"
	// GapClassHint declares this package's shortfall as structurally
	// unrecoverable (the design's E4 category), the only gap class this
	// harness accepts as a case declaration rather than deriving from
	// observation — E4 requires a per-case, individually justified reason
	// (e.g. "statically linked, links no shared library at all"), which
	// belongs here in Rationale.
	GapClassHint string `json:"gap_class_hint,omitempty"` // "E4"
	Rationale    string `json:"rationale,omitempty"`
}

// UsageEvent is one line of a test program's common-format usage log.
//
// OK records whether the event itself happened, not whether the program it
// describes succeeded: an "exit" with OK true means an exit was actually
// observed, which is what closes a usage interval. The process's exit code
// lives in Status, separately, so a non-zero exit does not discard the
// interval's endpoint and leave the package looking used to the end of the
// window.
type UsageEvent struct {
	Timestamp time.Time `json:"ts"`
	PID       int       `json:"pid"`
	Starttime int64     `json:"starttime"`
	Event     string    `json:"event"` // "exec" | "open" | "dlopen" | "dlclose" | "exit"
	Path      string    `json:"path"`
	OK        bool      `json:"ok"`
	Status    *int      `json:"status,omitempty"`
}

// PackageRef names one package a file belongs to.
type PackageRef struct {
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	Class   string `json:"class,omitempty"` // "os" | "lang"
}

// PathPackage is one independently resolved path -> package mapping, used
// only for GT-B (never for the match verdict itself).
//
// One file can belong to several packages at once, and that is not an
// ambiguity: a compiled binary carries every module built into it, and an
// archive assembled from other archives carries all of them. Packages
// holds them all. The single Package/Version pair is the older one-package
// spelling, still read so existing records keep working, and is folded
// into Packages on load.
//
// Unowned marks a path the independent resolution confirmed belongs to no
// package at all — the workload's own binary or script, say — as distinct
// from a path it simply could not resolve. Both leave Packages empty, but
// only the second should withdraw the completeness guarantee a case's
// scope depends on.
type PathPackage struct {
	Path     string       `json:"path"`
	Packages []PackageRef `json:"packages,omitempty"`
	Package  string       `json:"package,omitempty"`
	Version  string       `json:"version,omitempty"`
	Unowned  bool         `json:"unowned,omitempty"`
}

// all returns every package this path belongs to, whichever spelling the
// record used.
func (p PathPackage) all() []PackageRef {
	out := append([]PackageRef(nil), p.Packages...)
	if p.Package != "" {
		for _, r := range out {
			if r.Package == p.Package {
				return out
			}
		}
		out = append(out, PackageRef{Package: p.Package, Version: p.Version})
	}
	return out
}

// ResidentPackage is one package's directly-declared GT-B truth for a
// limited-GT-B case (official images): only "used" can be confirmed this
// way, per the design's restriction that a post-window spot check cannot
// certify non-use.
type ResidentPackage struct {
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	Used    bool   `json:"used"`
}

// GroundTruthB is the observation-window ground truth for one case: either
// the case's own test program's usage log (Kind == "usage_log") or a
// post-window, resident-process-only spot check (Kind == "limited").
type GroundTruthB struct {
	CaseID           string            `json:"case_id"`
	Kind             string            `json:"kind"` // "usage_log" | "limited"
	UsageLog         []UsageEvent      `json:"usage_log,omitempty"`
	PathPackages     []PathPackage     `json:"path_packages,omitempty"`
	ResidentPackages []ResidentPackage `json:"resident_packages,omitempty"`

	// Occurrences is the workload's own record of each individual thing it
	// did, with an identifier per occurrence. The usage log above answers
	// "was this package used in the window"; this answers "how many times
	// did this happen, and was each one seen", which the usage log cannot:
	// it collapses to a per-package true or false, and one of its lines is
	// not necessarily one system call.
	Occurrences []Occurrence `json:"occurrences,omitempty"`
	// RealOpens is an independent record of the file-open system calls
	// themselves, where a case can produce one. Without it the system-call
	// capture rate is unavailable and is reported as such, never
	// substituted for by the coarser per-load rate.
	RealOpens []RealOpen `json:"real_opens,omitempty"`
	// PIDMap is the correspondence between the process numbers the
	// workload sees and the ones the host sees, where the case runner
	// could establish it.
	PIDMap []PIDMapping `json:"pid_map,omitempty"`
	// ClockBase states which clock the occurrence times are on and how it
	// relates to the event log's, since a pairing tolerance means nothing
	// without it.
	ClockBase string `json:"clock_base,omitempty"`
}

// IntelSnapshot is match's intel input/output record.
type IntelSnapshot struct {
	KEVFetchedAt  time.Time               `json:"kev_fetched_at,omitempty"`
	EPSSFetchedAt time.Time               `json:"epss_fetched_at,omitempty"`
	KEVOK         bool                    `json:"kev_ok"`
	EPSSOK        bool                    `json:"epss_ok"`
	StaleDays     int                     `json:"stale_days"`
	Condition     string                  `json:"condition"` // "normal" | "degraded"
	Enrichment    map[string]FindingIntel `json:"enrichment,omitempty"`
}

// FindingIntel is one vulnerability ID's enrichment, as actually used.
type FindingIntel struct {
	KEV       bool    `json:"kev"`
	EPSS      float64 `json:"epss,omitempty"`
	EPSSKnown bool    `json:"epss_known"`
}

// PathMatchRecord combines one collect-produced PathResolutionRecord with
// match's own TrivyMatch verdict.
type PathMatchRecord struct {
	PathResolutionRecord
	TrivyMatch TrivyMatch `json:"trivy_match"`
}

// PathResolutionTally is one row of the final path-resolution aggregate.
type PathResolutionTally struct {
	Ownership  string `json:"ownership,omitempty"`
	TrivyMatch string `json:"trivy_match,omitempty"`
	Paths      int    `json:"paths"`
}

// PackageVerdict is one Trivy-Finding-group's finished match result.
type PackageVerdict struct {
	Package      string `json:"package"`
	Class        string `json:"class"`
	InstalledVer string `json:"installed_version"`
	FindingCount int    `json:"finding_count"`

	Verdict Verdict `json:"verdict"`
	Factor  string  `json:"factor,omitempty"`

	ObservationState    string `json:"observation_state"` // "observed" | "partially_observed" | "observation_failed"
	ValidSamples        int    `json:"valid_samples"`
	TotalSamples        int    `json:"total_samples"`
	ProcObserveFailures int    `json:"proc_observe_failures"`
	PkgdbReadFailures   int    `json:"pkgdb_read_failures"`

	CaptureSamples       int      `json:"capture_samples"`
	ObservedPaths        []string `json:"observed_paths,omitempty"`
	VersionMismatchPaths []string `json:"version_mismatch_paths,omitempty"`
	// UnknownVersionPaths are owned paths whose database version could not
	// be read at all. They are not version mismatches and they are not
	// confirmations either: an unknown version cannot be said to equal
	// Trivy's InstalledVersion.
	UnknownVersionPaths []string `json:"unknown_version_paths,omitempty"`

	ExpectedUsage   string         `json:"expected_usage,omitempty"`   // GT-A
	ExpectedVerdict string         `json:"expected_verdict,omitempty"` // GT-A
	ExpectedFactor  string         `json:"expected_factor,omitempty"`  // GT-A
	Priorities      map[string]int `json:"priorities,omitempty"`
	MaxPriority     string         `json:"max_priority,omitempty"`

	// GTBTruth is "used" | "not_used" | "undetermined".
	GTBTruth string `json:"gt_b_truth,omitempty"`
	// GTBUndeterminedReason says why, when GTBTruth is "undetermined": out
	// of the case's declared scope, or in scope but with a log too
	// incomplete to certify non-use.
	GTBUndeterminedReason string `json:"gt_b_undetermined_reason,omitempty"`
	// GapClass is the confirmation-gap shortfall classification: "E1" |
	// "E2" | "E3" | "E4" | "unclassified" | "" (verdict == confirmed).
	GapClass          string `json:"confirmation_gap_class,omitempty"`
	GapRecoverability string `json:"confirmation_gap_recoverability,omitempty"` // "confirmed" | "candidate" | "unknown"
	// GapRecoveredBy names the evidence source that closed a shortfall
	// the first stage's rules left open, empty when none did. A package
	// that recovers keeps its original class as well, so which kind of
	// shortfall it was is not lost the moment it stops being one.
	GapRecoveredBy []string `json:"confirmation_gap_recovered_by,omitempty"`

	// Ecosystem is the analyzer that produced this package's findings, and
	// MappingInput what the scan report offers for relating it to a file.
	// Both are reported because a combined confirmation rate across
	// ecosystems says nothing on its own.
	Ecosystem    string `json:"ecosystem,omitempty"`
	MappingInput string `json:"mapping_input,omitempty"`

	// These are this package's outcome once the read-only mapping, and
	// then the event evidence, are added. The fields above stay the first
	// stage's own result, so a re-run reproduces what it produced.
	S1Verdict Verdict  `json:"s1_verdict,omitempty"`
	S1Factor  string   `json:"s1_factor,omitempty"`
	S1Sources []string `json:"s1_sources,omitempty"`
	S2Verdict Verdict  `json:"s2_verdict,omitempty"`
	S2Factor  string   `json:"s2_factor,omitempty"`
	S2Sources []string `json:"s2_sources,omitempty"`
	// EvidenceFiles are the scan-report files whose observation confirmed
	// this package, EvidenceGrain the coarsest granularity among them, and
	// EvidenceNotes the qualifications a description of the evidence has
	// to keep.
	EvidenceFiles []string       `json:"evidence_files,omitempty"`
	EvidenceGrain string         `json:"evidence_grain,omitempty"`
	EvidenceNotes []string       `json:"evidence_notes,omitempty"`
	Confirmations []Confirmation `json:"confirmations,omitempty"`
}

// SeriesMetrics is one evaluation series' aggregate: the same rows the
// first stage reports, plus the ecosystem and evidence-granularity splits
// that keep a combined figure from standing alone.
type SeriesMetrics struct {
	Series  string             `json:"series"`
	Overall Metrics            `json:"overall"`
	ByClass map[string]Metrics `json:"by_class"`
	ByPrio  map[string]Metrics `json:"by_priority,omitempty"`
	ByEco   map[string]Metrics `json:"by_ecosystem,omitempty"`
	ByGrain map[string]Metrics `json:"by_evidence_grain,omitempty"`
	// ObservedBinaries and ObservedFiles are how many distinct scan-report
	// files the positives rest on, reported alongside every rate: a
	// hundred findings confirmed by one binary is a different result from
	// a hundred confirmed by a hundred files.
	ObservedBinaries int `json:"observed_binaries"`
	ObservedFiles    int `json:"observed_files"`

	UnresolvedFactors    []FactorBreakdown `json:"unresolved_factors,omitempty"`
	UnobservedFactors    []FactorBreakdown `json:"unobserved_factors,omitempty"`
	NotDeterminedFactors []FactorBreakdown `json:"not_determined_factors,omitempty"`

	// GTB is this series' own true and false positive and negative count.
	// A layer that raises the confirmation rate by confirming packages the
	// workload never used would otherwise look like the best one.
	GTB GTBCounts `json:"gt_b"`
	// CollectionComplete says whether this window's collection ran to
	// completion, which is the condition the conditional rate is about.
	CollectionComplete bool `json:"collection_complete"`
}

// SeriesDelta is the increment one added evidence layer produced.
//
// The two increments are never added together: "the confirmation rate
// went up" does not say whether the read-only mapping or the event
// collection produced it, and the two cost entirely different things. An
// increment that cannot be computed at all — because the window collected
// no usable events — is reported as unavailable rather than as zero, which
// would claim the events were tried and added nothing.
type SeriesDelta struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Findings  int    `json:"findings,omitempty"`
	Packages  int    `json:"packages,omitempty"`
}

// MappingReport is the per-ecosystem outcome of the two-stage mapping.
type MappingReport struct {
	Rows []MappingRow `json:"rows"`
	// CandidateConflicts counts observed paths that answered to more than
	// one scan-report file. That is the ambiguity the design treats as a
	// failure to resolve; one file carrying several packages is not one.
	CandidateConflicts int `json:"candidate_conflicts"`
	// The three reasons an observation reached no package, kept apart.
	// Only the first is a shortfall in the observation: a path that
	// resolved and simply names nothing the scan reports is what most of a
	// workload's activity looks like, and counting it as a failure would
	// report a broken collection every time.
	UnresolvedPaths   int `json:"unresolved_paths"`
	UnresolvedEvents  int `json:"unresolved_events"`
	UnmappablePaths   int `json:"unmappable_paths"`
	UnmappableEvents  int `json:"unmappable_events"`
	OutsideScanPaths  int `json:"outside_scan_paths"`
	OutsideScanEvents int `json:"outside_scan_events"`
	// DirectoryOpenEvents counts an open event (never an exec, and never a
	// sampled path) whose own path saved layout information records as a
	// directory. Kept apart from OutsideScanEvents: the scan may report
	// plenty about the package that ships the directory, this event just
	// never used it — opening a directory is not use of the package that
	// ships it, the same exclusion ground truth itself applies.
	DirectoryOpenEvents int `json:"directory_open_events"`
}

// MappingRow is one ecosystem's mapping outcome.
type MappingRow struct {
	Ecosystem string `json:"ecosystem"`
	// Stage1Files is how many scan-report files were identified from an
	// observed path, Stage2Packages how many package groups those files
	// carried.
	Stage1Files     int            `json:"stage1_files"`
	Stage2Packages  int            `json:"stage2_packages"`
	ObservedBinary  int            `json:"observed_binaries"`
	ObservedFile    int            `json:"observed_files"`
	UnmappableBy    map[string]int `json:"unmappable_reasons,omitempty"`
	ScanReportFiles int            `json:"scan_report_files"`
}

// Metrics is one confirmation-rate row.
type Metrics struct {
	FindingDenominator       int     `json:"finding_denominator"`
	FindingObservationFailed int     `json:"finding_observation_failed"`
	FindingConfirmed         int     `json:"finding_confirmed"`
	UnconditionalRate        float64 `json:"unconditional_rate"` // -1 = N/A
	ConditionalRate          float64 `json:"conditional_rate"`   // -1 = N/A
	PkgDenominator           int     `json:"pkg_denominator"`
	PkgConfirmed             int     `json:"pkg_confirmed"`
	PkgRate                  float64 `json:"pkg_rate"` // -1 = N/A
}

// FactorBreakdown is one row of the unresolved/unobserved/not_determined
// factor tables, split by priority.
type FactorBreakdown struct {
	Verdict  string `json:"verdict"`
	Factor   string `json:"factor"`
	Packages int    `json:"packages"`
	Findings int    `json:"findings"`
	ActNow   int    `json:"act_now_findings"`
	Watch    int    `json:"watch_findings"`
	Low      int    `json:"low_findings"`
}

// GapClassBreakdown is one row of the E1-E4/unclassified confirmation-gap
// table.
type GapClassBreakdown struct {
	Class          string `json:"class"`
	Recoverability string `json:"recoverability"`
	Packages       int    `json:"packages"`
	Findings       int    `json:"findings"`
	ActNow         int    `json:"act_now_findings"`
	Watch          int    `json:"watch_findings"`
}

// GTBCounts is the TP/FP/TN/FN tally and rates for one case.
type GTBCounts struct {
	Population                                 int     `json:"population"`
	Undetermined                               int     `json:"undetermined_pairs"`
	Coverage                                   float64 `json:"coverage"` // -1 = N/A
	TP, FP, TN, FN                             int
	FPR                                        float64 `json:"fpr"` // -1 = N/A
	FNR                                        float64 `json:"fnr"` // -1 = N/A
	FPRUpperBound                              float64 `json:"fpr_upper_bound"`
	FPRLowerBound                              float64 `json:"fpr_lower_bound"`
	FNRUpperBound                              float64 `json:"fnr_upper_bound"`
	FNRLowerBound                              float64 `json:"fnr_lower_bound"`
	FindingTP, FindingFP, FindingTN, FindingFN int
}

// Discrepancy is one GT-A-declared package whose actual verdict disagrees
// with the declaration — informational only.
type Discrepancy struct {
	Package         string `json:"package"`
	ExpectedUsage   string `json:"expected_usage,omitempty"`
	ExpectedVerdict string `json:"expected_verdict"`
	ExpectedFactor  string `json:"expected_factor,omitempty"`
	ObservedVerdict string `json:"observed_verdict"`
	ObservedFactor  string `json:"observed_factor,omitempty"`
	Findings        int    `json:"findings"`
}

// ExposureVerdict is one container's exposure judgement.
type ExposureVerdict struct {
	Verdict string   `json:"verdict"`
	Reasons []string `json:"reasons"`
}

// GuessDependencyRate is the guess-dependency rate. Because its
// false-positive half inherits GT-B's undetermined pairs, it carries the
// same kind of bounds the FP/FN rates do: the lower bound treats every
// undetermined predicted-positive pair as a true positive, the upper bound
// treats every one of them as a false positive.
type GuessDependencyRate struct {
	Numerator                    int     `json:"numerator"`
	UnownedConfirmed             int     `json:"unowned_confirmed_findings"` // always 0: this harness never attributes on a guess
	FalsePositiveCount           int     `json:"false_positive_findings"`
	Denominator                  int     `json:"denominator"` // confirmed Finding count
	Rate                         float64 `json:"rate"`        // -1 = N/A
	UndeterminedPositiveFindings int     `json:"undetermined_positive_findings"`
	UpperBound                   float64 `json:"upper_bound"` // -1 = N/A
	LowerBound                   float64 `json:"lower_bound"` // -1 = N/A
}

// RankedFinding is one row of the G4 ranking comparison. Class and Version
// are part of the row's identity, not decoration: two Findings can share a
// package name across os-pkgs and lang-pkgs, or across two installed
// versions, and ranking them by name alone would merge them.
type RankedFinding struct {
	Package       string `json:"package"`
	Class         string `json:"class"`
	Version       string `json:"installed_version"`
	VulnID        string `json:"vuln_id"`
	BaselineRank  int    `json:"baseline_rank"`
	AdjustedRank  int    `json:"adjusted_rank"`
	RankChanged   bool   `json:"rank_changed"`
	Confirmed     bool   `json:"confirmed"`
	Exposure      string `json:"exposure"`
	HighPrivilege bool   `json:"high_privilege"`
	Labeled       bool   `json:"labeled"`
}

// G4Result is the G4 additional-judgement output for one priority
// bucket (act_now or watch).
type G4Result struct {
	// Series says which evidence the ranking was computed from: the first
	// stage's own, or everything the added layers established. The pair is
	// what shows whether the extra evidence moves anything, which is the
	// question — not the confirmation rate on its own.
	Series            string          `json:"series"`
	Priority          string          `json:"priority"`
	NA                bool            `json:"na"`
	TotalFindings     int             `json:"total_findings"`
	Top20             []RankedFinding `json:"top20"`
	RankChangedCount  int             `json:"rank_changed_count"`
	LabeledCount      int             `json:"labeled_count"`
	ExampleLabeled    string          `json:"example_labeled,omitempty"`
	ExampleNotLabeled string          `json:"example_not_labeled,omitempty"`
}

// EvidenceTarget is the "target" field of one Evidence record.
type EvidenceTarget struct {
	Kind    string `json:"kind"` // "package" | "port" | "process"
	Class   string `json:"class,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Evidence is the common per-record shape defined for usage, exposure,
// and privilege facts alike. match's primary output remains PackageVerdict
// (which carries fields — FindingCount, per-priority breakdown, observed
// paths — Evidence's flat shape cannot express); Evidence is additionally
// emitted as its own record list so a consumer that only understands the
// generic shape can still read the result.
type Evidence struct {
	Type              string            `json:"type"` // "usage" | "exposure" | "privilege"
	Verdict           string            `json:"verdict"`
	Factor            string            `json:"factor,omitempty"`
	Target            EvidenceTarget    `json:"target"`
	Value             map[string]any    `json:"value,omitempty"`
	Source            string            `json:"source"`
	SampleID          string            `json:"sample_id,omitempty"`
	ProcessGeneration ProcessGeneration `json:"process_generation,omitempty"`
	ObservedAt        time.Time         `json:"observed_at"`
	WindowID          string            `json:"window_id"`
}

// MatchResult is match's primary output for one case run.
type MatchResult struct {
	CaseID      string    `json:"case_id"`
	Image       string    `json:"image"`
	GeneratedAt time.Time `json:"generated_at"`
	Subject     Subject   `json:"subject"`
	RunKey      RunKey    `json:"run_key"`

	ContainerID           string `json:"container_id"`
	ObservedImageID       string `json:"observed_image_id"`
	ScanDigest            string `json:"scan_digest"`
	ImageIdentityVerified bool   `json:"image_identity_verified"`

	Intel IntelSnapshot `json:"intel"`
	// IntelSource is "snapshot" when the KEV/EPSS enrichment came from a
	// saved snapshot supplied as input, and "lookup" when it was fetched
	// through the product's own intel source at match time. Only the first
	// reproduces: a live lookup's answer changes as the feeds do.
	IntelSource string `json:"intel_source"`

	Exposure ExposureVerdict `json:"exposure"`

	Packages []PackageVerdict `json:"packages"`

	Overall Metrics            `json:"overall"`
	ByClass map[string]Metrics `json:"by_class"`
	ByPrio  map[string]Metrics `json:"by_priority,omitempty"`

	UnresolvedFactors    []FactorBreakdown `json:"unresolved_factors"`
	UnobservedFactors    []FactorBreakdown `json:"unobserved_factors"`
	NotDeterminedFactors []FactorBreakdown `json:"not_determined_factors"`

	PathMatches         []PathMatchRecord     `json:"path_matches"`
	PathResolutionTally []PathResolutionTally `json:"path_resolution_tally"`

	GapClasses      []GapClassBreakdown `json:"confirmation_gap_classes"`
	GuessDependency GuessDependencyRate `json:"guess_dependency_rate"`

	GTB GTBCounts `json:"gt_b"`
	// GTBIncomplete lists what stopped the ground-truth log from being able
	// to certify non-use, when anything did. A package whose non-use cannot
	// be certified stays undetermined rather than becoming a true negative.
	GTBIncomplete    []string      `json:"gt_b_incomplete,omitempty"`
	FPFNDetail       []Discrepancy `json:"gt_b_detail,omitempty"`
	GTADiscrepancies []Discrepancy `json:"gt_a_discrepancies,omitempty"`

	G4 []G4Result `json:"g4,omitempty"`

	// Series carries the three evaluation series. The fields above remain
	// the first stage's own result, unchanged, so a re-run of a saved
	// record reproduces what it produced before any of this existed.
	Series       []SeriesMetrics `json:"series,omitempty"`
	SeriesDeltas []SeriesDelta   `json:"series_deltas,omitempty"`

	// EventState is the event collection's own outcome for this window,
	// kept as a separate dimension from the sampling's observation state:
	// neither one failing says anything about the other.
	EventState string          `json:"event_state"`
	EventNotes []string        `json:"event_notes,omitempty"`
	EventDrops EventDropCounts `json:"event_drops"`
	EventHead  EventHeader     `json:"event_collection,omitempty"`
	// EventsAttributed and EventsInWindow describe how much of the event
	// log this container's result actually rests on.
	EventsTotal      int `json:"events_total"`
	EventsAttributed int `json:"events_attributed_to_container"`
	EventsInWindow   int `json:"events_in_window"`

	SourceInputStates []SourceInputState `json:"source_input_states,omitempty"`
	Mapping           MappingReport      `json:"mapping"`
	Occurrence        OccurrenceMetrics  `json:"occurrence_capture"`
	Attribution       AttributionMetrics `json:"attribution"`

	Evidence []Evidence `json:"evidence"`

	Failures      []Failure `json:"failures,omitempty"`
	PermCondition string    `json:"perm_condition,omitempty"`

	Errors []string `json:"errors,omitempty"`
}
