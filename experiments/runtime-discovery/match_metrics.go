package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// pkgGroupKey identifies one (Class, Package, InstalledVer) group of raw
// Trivy Findings — the package-unit denominator.
type pkgGroupKey struct {
	Class        scanner.PkgClass
	Package      string
	InstalledVer string
}

type pkgGroup struct {
	key   pkgGroupKey
	vulns []findingVuln
}

type findingVuln struct {
	VulnID        string
	OriginalIndex int
}

// groupFindings partitions raw ParseReport Findings into package-unit
// groups, deduplicated by (Class, PkgName, InstalledVersion, VulnerabilityID).
func groupFindings(findings []scanner.Finding) []pkgGroup {
	order := []pkgGroupKey{}
	byKey := map[pkgGroupKey]*pkgGroup{}
	seenVuln := map[pkgGroupKey]map[string]bool{}
	for i, f := range findings {
		k := pkgGroupKey{Class: f.Class, Package: f.Package, InstalledVer: f.InstalledVer}
		g, ok := byKey[k]
		if !ok {
			g = &pkgGroup{key: k}
			byKey[k] = g
			seenVuln[k] = map[string]bool{}
			order = append(order, k)
		}
		if seenVuln[k][f.VulnID] {
			continue
		}
		seenVuln[k][f.VulnID] = true
		g.vulns = append(g.vulns, findingVuln{VulnID: f.VulnID, OriginalIndex: i})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].Package != order[j].Package {
			return order[i].Package < order[j].Package
		}
		if order[i].InstalledVer != order[j].InstalledVer {
			return order[i].InstalledVer < order[j].InstalledVer
		}
		return order[i].Class < order[j].Class
	})
	out := make([]pkgGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// priorityUnclassified is the priority of a Finding the product's own
// triage never assigned one to.
//
// The product sorts findings into sections by vulnerability status and
// prioritizes what lands in them: fixed, affected and will_not_fix. Trivy
// emits other statuses too — fix_deferred, end_of_life, unknown — and a
// Finding carrying one of those appears in no section, so no priority
// exists to recover. Deriving one here would be re-implementing the triage
// rules this harness exists to measure, so the gap is named instead: these
// Findings stay in every denominator and are reported as unclassified,
// which is why the per-priority denominators add up to the overall one.
const priorityUnclassified = "unclassified"

// computePriorities calls analyze.Build once per raw Finding, each time with
// an ImageScan containing exactly that one Finding.
func computePriorities(findings []scanner.Finding, artifactName, osFamily string, tr analyze.Triage, now time.Time) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		single := scanner.ImageScan{Image: artifactName, OSFamily: osFamily, Findings: []scanner.Finding{f}}
		report := analyze.Build([]scanner.ImageScan{single}, nil, tr, now)
		prio, found := extractSolePriority(report)
		if !found || prio == "" {
			prio = priorityUnclassified
		}
		out[i] = prio
	}
	return out
}

// extractSolePriority recovers the priority the product assigned to the one
// Finding the report was built from. found is false when the report
// contains no vulnerability at all, which is how a status the product does
// not triage presents itself; an empty priority with found true means the
// product reached it but assigned none.
func extractSolePriority(r analyze.Report) (priority string, found bool) {
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix} {
		for _, img := range section {
			for _, g := range img.Packages {
				for _, v := range g.Vulns {
					return string(v.Priority), true
				}
			}
		}
	}
	return "", false
}

// unclassifiedByStatus counts, per vulnerability status, the Findings that
// came back without a priority — the statuses the product's sections do not
// cover.
func unclassifiedByStatus(findings []scanner.Finding, priorityByIndex []string) map[string]int {
	out := map[string]int{}
	for i, f := range findings {
		if i < len(priorityByIndex) && priorityByIndex[i] == priorityUnclassified {
			status := string(f.Status)
			if status == "" {
				status = "(no status)"
			}
			out[status]++
		}
	}
	return out
}

// windowValidity summarizes a container's collection_results: how many
// samples were valid (proc_observe=ok AND pkgdb_read in {ok,absent}, both
// on the SAME sample) out of the total, and per-operation failure counts.
type windowValidity struct {
	Valid, Total        int
	ProcObserveFailures int
	PkgdbReadFailures   int
	ValidSampleIDs      map[string]bool
	// DBGenerations is the set of (mount view, database generation) pairs
	// the valid samples actually read, as "<mount view>\x00<generation>".
	// The package ledger is consulted only for these, so a window whose
	// database changed halfway through is not answered from whichever
	// generation happened to be recorded first.
	DBGenerations map[string]bool
	// SawDBViews records whether any valid sample carried per-view
	// outcomes at all, which separates "this window read no database" from
	// "this record predates per-sample view recording".
	SawDBViews bool
}

func computeWindowValidity(rec *ContainerRecord) windowValidity {
	wv := windowValidity{ValidSampleIDs: map[string]bool{}, DBGenerations: map[string]bool{}}
	wv.Total = len(rec.CollectionResults)
	for _, cr := range rec.CollectionResults {
		if cr.ProcObserve != "ok" {
			wv.ProcObserveFailures++
		}
		if cr.PkgdbRead == "error" {
			wv.PkgdbReadFailures++
		}
		if !cr.Valid {
			continue
		}
		wv.Valid++
		wv.ValidSampleIDs[cr.SampleID] = true
		if len(cr.Views) > 0 {
			wv.SawDBViews = true
		}
		for _, v := range cr.Views {
			if v.PkgdbRead == "ok" {
				wv.DBGenerations[v.MountViewID+"\x00"+v.DBGeneration] = true
			}
		}
	}
	return wv
}

// observationState computes the container-wide observation_state. A
// container whose inspect failed outright has no samples at all, which is
// observation_failed — it stays in the denominator as a not_determined
// Finding set rather than being dropped from the population.
func observationState(rec *ContainerRecord, wv windowValidity) string {
	if rec.InspectError != "" || wv.Total == 0 {
		return "observation_failed"
	}
	switch {
	case wv.Valid == wv.Total:
		return "observed"
	case wv.Valid == 0:
		return "observation_failed"
	default:
		return "partially_observed"
	}
}

// dominantNotDeterminedFactor picks the most frequent not_determined-style
// failure step recorded for the container, used as the factor when
// observation_state is observation_failed.
func dominantNotDeterminedFactor(rec *ContainerRecord) string {
	if rec.InspectError != "" {
		return factorTopFailed
	}
	counts := map[string]int{}
	for _, f := range rec.Failures {
		switch f.Step {
		case factorTopFailed, factorProcDenied, factorProcGone, "rootfs_denied":
			counts[f.Step]++
		}
	}
	best, bestN := factorProcDenied, 0
	for step, n := range counts {
		if n > bestN {
			best, bestN = step, n
		}
	}
	if best == "rootfs_denied" {
		return factorRootfsDenied
	}
	return best
}

// ownedPathConfirms is the single predicate for "this observed path is
// evidence for this Finding group": the path resolved to exactly one owning
// package, and that package's class, name and database-recorded version all
// equal the Finding's. Every version component must be present and equal —
// a path whose database version could not be read is not a match, because
// an unknown version cannot be said to equal Trivy's InstalledVersion.
func ownedPathConfirms(pr PathResolutionRecord, key pkgGroupKey) bool {
	if pr.Ownership != OwnershipOwned || pr.Package == "" {
		return false
	}
	if pathRecordClass(pr) != key.Class {
		return false
	}
	return pr.Package == key.Package && pr.DBVersion != "" && key.InstalledVer != "" && pr.DBVersion == key.InstalledVer
}

// classOf converts a PackageVerdict's class string back into the scanner's
// own class type, so a verdict can be turned back into the Finding key it
// came from.
func classOf(class string) scanner.PkgClass {
	if class == string(scanner.ClassLang) {
		return scanner.ClassLang
	}
	return scanner.ClassOS
}

// pathRecordClass is the Trivy class an observed path's owning package
// belongs to. Every database this harness reads (dpkg, distroless's
// status.d, apk) is an operating-system package database, so an owned path
// always names an os-class package; a lang-class Finding is never matched
// by a path, which is precisely the gap the decision table records as
// lang_pkg_unmappable.
func pathRecordClass(PathResolutionRecord) scanner.PkgClass { return scanner.ClassOS }

// searchOwned scans rec.PathResolution (restricted to valid samples) for
// "owned" hits naming pkgName, splitting them into confirming paths, paths
// whose database version disagrees with Trivy's, and paths whose database
// version could not be read at all. Only the first group confirms.
func searchOwned(rec *ContainerRecord, validSamples map[string]bool, key pkgGroupKey) (confirmedSamples map[string]bool, confirmedPaths, mismatchPaths, unknownVersionPaths []string) {
	confirmedSamples = map[string]bool{}
	seen, mismatchSeen, unknownSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, pr := range rec.PathResolution {
		if !validSamples[pr.SampleID] {
			continue
		}
		if pr.Ownership != OwnershipOwned || pr.Package != key.Package || pathRecordClass(pr) != key.Class {
			continue
		}
		path := pr.Resolved
		if path == "" {
			path = pr.Path
		}
		switch {
		case pr.DBVersion == "":
			if !unknownSeen[path] {
				unknownSeen[path] = true
				unknownVersionPaths = append(unknownVersionPaths, path)
			}
		case pr.DBVersion != key.InstalledVer:
			if !mismatchSeen[path] {
				mismatchSeen[path] = true
				mismatchPaths = append(mismatchPaths, path)
			}
		default:
			confirmedSamples[pr.SampleID] = true
			if !seen[path] {
				seen[path] = true
				confirmedPaths = append(confirmedPaths, path)
			}
		}
	}
	sort.Strings(confirmedPaths)
	sort.Strings(mismatchPaths)
	sort.Strings(unknownVersionPaths)
	return confirmedSamples, confirmedPaths, mismatchPaths, unknownVersionPaths
}

// packageFileListStatus looks up a package's file_list_present fact from
// the package_ledger, restricted to the database generations the valid
// samples actually read. An entry recorded for some other generation
// describes a database this window's samples never consulted, so it is not
// an answer about them.
//
// Two different situations produce an empty generation set, and they are
// not interchangeable. If the valid samples recorded per-view outcomes but
// none of them read a database — every one was absent — then the ledger
// has nothing to say about this window and the lookup fails outright;
// falling back to the whole ledger there would answer from a database the
// window established was not present. If the record carries no per-sample
// view information at all (one written before views were recorded), there
// is nothing to restrict by and the whole ledger is the best available
// answer.
func packageFileListStatus(rec *ContainerRecord, wv windowValidity, key pkgGroupKey) (present, found bool) {
	if len(wv.DBGenerations) == 0 && wv.SawDBViews {
		return false, false
	}
	restrict := len(wv.DBGenerations) > 0
	for _, e := range rec.PackageLedger {
		if e.Name != key.Package {
			continue
		}
		if restrict && !wv.DBGenerations[e.MountViewID+"\x00"+e.DBGeneration] {
			continue
		}
		if found && e.Version != key.InstalledVer {
			continue // keep the first match unless a later one matches the version exactly
		}
		present, found = e.FileListPresent, true
		if e.Version == key.InstalledVer {
			return present, true
		}
	}
	return present, found
}

// containerHasUsableDB reports whether any pkgdb generation this container
// read had a real kind (dpkg/dpkg-status.d/apk), as opposed to none/absent.
func containerHasUsableDB(rec *ContainerRecord) bool {
	for _, db := range rec.PkgDBs {
		if db.DBKind != "" && db.DBKind != noDBKind {
			return true
		}
	}
	return false
}

// expectedFor returns the case's GT-A entry for a package, if it declared one.
func expectedFor(def Case, pkgName string) (ExpectedUsage, bool) {
	for _, e := range def.Expected {
		if e.Package == pkgName {
			return e, true
		}
	}
	return ExpectedUsage{}, false
}

// declaresE4 reports whether the case declared this package's shortfall as
// structurally unrecoverable, either on the package itself or for the case
// as a whole. A per-package declaration wins, including a per-package
// declaration of something other than E4.
//
// A declaration without a written reason does not count. "Unrecoverable"
// is the one classification that closes off further investigation, so it
// has to say what makes it unrecoverable, in the case definition, where a
// reader of the results can find it.
func declaresE4(def Case, pkgName string) bool {
	if e, ok := expectedFor(def, pkgName); ok && e.GapClassHint != "" {
		return e.GapClassHint == "E4" && e.Rationale != ""
	}
	return def.GapClassHint == "E4" && def.GapClassRationale != ""
}

// assignVerdict computes one package group's Finding-unit usage verdict
// following the fixed 5-rule priority order: observation failure, language
// class, confirmed-by-observation, file-list-present-but-unobserved,
// otherwise unresolved.
func assignVerdict(g pkgGroup, rec *ContainerRecord, def Case, obsState string, wv windowValidity) PackageVerdict {
	expected, _ := expectedFor(def, g.key.Package)
	pv := PackageVerdict{
		Package: g.key.Package, Class: string(g.key.Class), InstalledVer: g.key.InstalledVer,
		FindingCount: len(g.vulns), ExpectedUsage: expected.Usage, ExpectedVerdict: expected.ExpectedVerdict,
		ExpectedFactor: expected.ExpectedFactor, ObservationState: obsState,
		ValidSamples: wv.Valid, TotalSamples: wv.Total,
		ProcObserveFailures: wv.ProcObserveFailures, PkgdbReadFailures: wv.PkgdbReadFailures,
	}

	// Rule 1: observation failure always wins, before any usage judgement.
	if obsState == "observation_failed" {
		pv.Verdict = VerdictNotDetermined
		pv.Factor = dominantNotDeterminedFactor(rec)
		return pv
	}

	// Rule 2: language packages are unmappable by construction in this
	// stage, independent of whether the database could resolve anything.
	// The case's own factor hint never overrides this: the gap is in the
	// matcher, not in the sampling.
	if g.key.Class == scanner.ClassLang {
		pv.Verdict = VerdictUnobserved
		pv.Factor = factorLangPkg
		return pv
	}

	// Rule 3: any valid sample observed an owned, version-matching path.
	confirmedSamples, confirmedPaths, mismatchPaths, unknownVersionPaths := searchOwned(rec, wv.ValidSampleIDs, g.key)
	pv.VersionMismatchPaths = mismatchPaths
	pv.UnknownVersionPaths = unknownVersionPaths
	if len(confirmedSamples) > 0 {
		pv.Verdict = VerdictConfirmed
		pv.CaptureSamples = len(confirmedSamples)
		pv.ObservedPaths = confirmedPaths
		return pv
	}

	// Rule 4 / 5: file_list_present decides unobserved vs. unresolved.
	present, found := packageFileListStatus(rec, wv, g.key)
	if found && present {
		pv.Verdict = VerdictUnobserved
		if expected.FactorHint == factorShortLived || expected.FactorHint == factorTransient {
			pv.Factor = expected.FactorHint
		} else {
			pv.Factor = factorNoObserved
		}
		return pv
	}

	pv.Verdict = VerdictUnresolved
	switch {
	case !containerHasUsableDB(rec):
		pv.Factor = factorDBAbsent
	case wv.PkgdbReadFailures > 0 && !found:
		pv.Factor = factorDBError
	default:
		pv.Factor = factorNoFileList
	}
	return pv
}

func applyPriorities(pv *PackageVerdict, g pkgGroup, priorityByIndex []string) {
	pv.Priorities = map[string]int{}
	// unclassified ranks below low: a package with one triaged Finding and
	// one untriaged one is classified by the triaged one, and only a
	// package with nothing but untriaged Findings is itself unclassified.
	rank := map[string]int{priorityUnclassified: 0, "low": 1, "watch": 2, "act_now": 3}
	maxRank := -1
	for _, v := range g.vulns {
		p := priorityUnclassified
		if v.OriginalIndex < len(priorityByIndex) && priorityByIndex[v.OriginalIndex] != "" {
			p = priorityByIndex[v.OriginalIndex]
		}
		pv.Priorities[p]++
		if r := rank[p]; r > maxRank {
			maxRank, pv.MaxPriority = r, p
		}
	}
}

// gapEvidence is what the observation itself says about a case's declared
// structural-unrecoverability claim, evaluated once per run.
type gapEvidence struct {
	StaticallyLinked  bool
	NoPackageMetadata bool
}

func (e gapEvidence) supportsE4() (bool, string) {
	switch {
	case e.StaticallyLinked && e.NoPackageMetadata:
		return true, "no process mapped any shared library, and the container carries no package database"
	case e.StaticallyLinked:
		return true, "no process mapped any shared library: there is no file for an ownership lookup to resolve"
	case e.NoPackageMetadata:
		return true, "the container carries no package database, so no file-to-package information exists to recover"
	default:
		return false, ""
	}
}

// computeGapEvidence derives the two observable grounds a case may claim
// for an unrecoverable gap. Both are read off the observation: a declared
// E4 that the observation does not bear out is not accepted, so a case
// cannot classify its own shortfall as unrecoverable by assertion.
func computeGapEvidence(rec *ContainerRecord, wv windowValidity) gapEvidence {
	ev := gapEvidence{NoPackageMetadata: !containerHasUsableDB(rec)}

	mapsRead, sawSharedLibrary := false, false
	for _, p := range rec.Processes {
		if !wv.ValidSampleIDs[p.SampleID] || p.Invalid || p.MapsError != "" {
			continue
		}
		mapsRead = true
		for _, m := range p.Maps {
			if m.Path != p.Exe {
				sawSharedLibrary = true
			}
		}
	}
	ev.StaticallyLinked = mapsRead && !sawSharedLibrary
	return ev
}

// classifyGap assigns the confirmation-gap class to one already-scored
// package, checked in the fixed order E3, E1, E2, E4, unclassified.
//
// Recoverability is recorded on the three-value scale (confirmed /
// candidate / unknown) only for the classes where recovery is an open
// question. E3 is not a gap and E4 is defined as not recovering, so the
// class itself carries the answer and the field is left empty rather than
// filled with a value from a scale that does not apply to them.
func classifyGap(pv PackageVerdict, e4Declared bool, evidence gapEvidence) (class, recoverability string) {
	switch {
	case pv.Verdict == VerdictConfirmed || pv.Verdict == VerdictNotDetermined:
		return "", ""
	case pv.GTBTruth == "not_used":
		return "E3", ""
	case pv.GTBTruth == "used" && pv.Verdict == VerdictUnobserved && isSamplingGapFactor(pv.Factor) && !hadMatchingFailure(pv):
		// Ground truth says it was used, the ownership machinery was able
		// to resolve this package's files (that is what rule 4's
		// file-list-present branch established), and the shortfall is one
		// of the purely temporal ones — the window's samples did not catch
		// it. A package whose paths *were* observed but failed to match on
		// version is not a sampling gap at all: more frequent sampling
		// would produce the same mismatch, so it is left unclassified
		// rather than credited to event evidence that would not fix it.
		return "E1", "candidate"
	case pv.Factor == factorLangPkg:
		return "E2", "candidate"
	case pv.Verdict == VerdictUnresolved && pv.Factor == factorNoFileList:
		// The database knows the package but not its files. Another way of
		// mapping files to packages could still reach it.
		return "E2", "candidate"
	default:
		if e4Declared {
			if ok, _ := evidence.supportsE4(); ok {
				return "E4", ""
			}
		}
		return "unclassified", "unknown"
	}
}

// isSamplingGapFactor reports whether a shortfall factor is one that more
// or better-timed sampling could close: the package's files are resolvable
// and the only question is whether a sample fell while they were loaded.
func isSamplingGapFactor(factor string) bool {
	switch factor {
	case factorShortLived, factorTransient, factorNoObserved:
		return true
	default:
		return false
	}
}

// hadMatchingFailure reports whether this package's paths were observed and
// owned but could not be matched to the Finding — a version disagreement or
// a database version that could not be read. That is a cross-referencing
// failure, not a sampling one.
func hadMatchingFailure(pv PackageVerdict) bool {
	return len(pv.VersionMismatchPaths) > 0 || len(pv.UnknownVersionPaths) > 0
}

func labelGTBTruth(pv *PackageVerdict, truth gtbTruth) {
	if !truth.Covered[pv.Package] {
		pv.GTBTruth = "undetermined"
		pv.GTBUndeterminedReason = truth.UndeterminedWhy[pv.Package]
		if pv.GTBUndeterminedReason == "" {
			pv.GTBUndeterminedReason = "outside the case's declared ground-truth scope"
		}
		return
	}
	if truth.Used[pv.Package] {
		pv.GTBTruth = "used"
	} else {
		pv.GTBTruth = "not_used"
	}
}

// aggregate computes the overall/by-class/by-priority Metrics rows, the
// factor breakdowns, and the confirmation-gap breakdown.
//
// A package contributes its Finding counts to every priority bucket those
// Findings fall in, but is counted as a package only in its own maximum
// priority bucket: the package-unit classification is the highest priority
// among its Findings, so counting it again under each lower one would make
// the package denominators sum to more than the package count.
func aggregate(packages []PackageVerdict) (overall Metrics, byClass, byPrio map[string]Metrics, unresolved, unobserved, notDetermined []FactorBreakdown, gaps []GapClassBreakdown) {
	byClass, byPrio = map[string]Metrics{}, map[string]Metrics{}
	unresolvedCounts, unobservedCounts, notDeterminedCounts := map[string]*FactorBreakdown{}, map[string]*FactorBreakdown{}, map[string]*FactorBreakdown{}
	gapCounts := map[string]*GapClassBreakdown{}

	addRaw := func(m *Metrics, pv PackageVerdict) {
		m.FindingDenominator += pv.FindingCount
		m.PkgDenominator++
		if pv.Verdict == VerdictNotDetermined {
			m.FindingObservationFailed += pv.FindingCount
		}
		if pv.Verdict == VerdictConfirmed {
			m.FindingConfirmed += pv.FindingCount
			m.PkgConfirmed++
		}
	}

	for _, pv := range packages {
		addRaw(&overall, pv)
		cm := byClass[pv.Class]
		addRaw(&cm, pv)
		byClass[pv.Class] = cm

		for prio, count := range pv.Priorities {
			if prio == "" {
				continue
			}
			pm := byPrio[prio]
			pm.FindingDenominator += count
			if pv.Verdict == VerdictNotDetermined {
				pm.FindingObservationFailed += count
			}
			if pv.Verdict == VerdictConfirmed {
				pm.FindingConfirmed += count
			}
			if prio == pv.MaxPriority {
				pm.PkgDenominator++
				if pv.Verdict == VerdictConfirmed {
					pm.PkgConfirmed++
				}
			}
			byPrio[prio] = pm
		}

		var bucket map[string]*FactorBreakdown
		switch pv.Verdict {
		case VerdictUnresolved:
			bucket = unresolvedCounts
		case VerdictUnobserved:
			bucket = unobservedCounts
		case VerdictNotDetermined:
			bucket = notDeterminedCounts
		}
		if bucket != nil {
			fb := bucket[pv.Factor]
			if fb == nil {
				fb = &FactorBreakdown{Verdict: string(pv.Verdict), Factor: pv.Factor}
				bucket[pv.Factor] = fb
			}
			fb.Packages++
			fb.Findings += pv.FindingCount
			fb.ActNow += pv.Priorities["act_now"]
			fb.Watch += pv.Priorities["watch"]
			fb.Low += pv.Priorities["low"]
		}

		if pv.GapClass != "" {
			gc := gapCounts[pv.GapClass]
			if gc == nil {
				gc = &GapClassBreakdown{Class: pv.GapClass, Recoverability: pv.GapRecoverability}
				gapCounts[pv.GapClass] = gc
			}
			gc.Packages++
			gc.Findings += pv.FindingCount
			gc.ActNow += pv.Priorities["act_now"]
			gc.Watch += pv.Priorities["watch"]
		}
	}

	finishRates := func(m Metrics) Metrics {
		m.UnconditionalRate = rateOrNA(m.FindingConfirmed, m.FindingDenominator)
		m.ConditionalRate = rateOrNA(m.FindingConfirmed, m.FindingDenominator-m.FindingObservationFailed)
		m.PkgRate = rateOrNA(m.PkgConfirmed, m.PkgDenominator)
		return m
	}
	overall = finishRates(overall)
	for k, v := range byClass {
		byClass[k] = finishRates(v)
	}
	for k, v := range byPrio {
		byPrio[k] = finishRates(v)
	}

	return overall, byClass, byPrio,
		sortedFactorBreakdowns(unresolvedCounts), sortedFactorBreakdowns(unobservedCounts), sortedFactorBreakdowns(notDeterminedCounts),
		sortedGapBreakdowns(gapCounts)
}

func rateOrNA(numerator, denominator int) float64 {
	if denominator <= 0 {
		return -1
	}
	return float64(numerator) / float64(denominator)
}

func sortedFactorBreakdowns(m map[string]*FactorBreakdown) []FactorBreakdown {
	out := make([]FactorBreakdown, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Factor < out[j].Factor })
	return out
}

func sortedGapBreakdowns(m map[string]*GapClassBreakdown) []GapClassBreakdown {
	out := make([]GapClassBreakdown, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	order := map[string]int{"E3": 0, "E1": 1, "E2": 2, "E4": 3, "unclassified": 4}
	sort.Slice(out, func(i, j int) bool { return order[out[i].Class] < order[out[j].Class] })
	return out
}

// --- Trivy cross-referencing (trivy_match; match-only, never collect) ---

// computeTrivyMatch cross-references one owned path against the Finding
// population. Candidates are restricted to the class the observed path's
// package actually belongs to, so an os-pkgs path is never matched against
// a lang-pkgs Finding that happens to share its package name.
func computeTrivyMatch(pr PathResolutionRecord, byPackage map[string][]pkgGroupKey) TrivyMatch {
	if pr.Ownership != OwnershipOwned {
		return TrivyMatchNotApplicable
	}
	class := pathRecordClass(pr)
	var candidates []pkgGroupKey
	for _, c := range byPackage[pr.Package] {
		if c.Class == class {
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		return TrivyMatchNoFinding
	}
	for _, c := range candidates {
		if ownedPathConfirms(pr, c) {
			return TrivyMatchMatched
		}
	}
	versions := map[string]bool{}
	for _, c := range candidates {
		versions[c.InstalledVer] = true
	}
	if len(versions) > 1 {
		return TrivyMatchMultipleCandidates
	}
	return TrivyMatchVersionMismatch
}

func buildPathMatches(rec *ContainerRecord, groups []pkgGroup) []PathMatchRecord {
	byPackage := map[string][]pkgGroupKey{}
	for _, g := range groups {
		byPackage[g.key.Package] = append(byPackage[g.key.Package], g.key)
	}
	out := make([]PathMatchRecord, 0, len(rec.PathResolution))
	for _, pr := range rec.PathResolution {
		out = append(out, PathMatchRecord{PathResolutionRecord: pr, TrivyMatch: computeTrivyMatch(pr, byPackage)})
	}
	return out
}

// pathIdentity is what makes two path observations the same path: the
// resolved path together with the device and inode the mapping recorded. A
// path alone is not an identity — the same name can be a different file in
// two samples (that is exactly what the replacement case creates), and
// merging those would hide the replacement the run exists to observe.
type pathIdentity struct {
	Path  string
	Dev   string
	Inode string
}

func identityOfPath(pr PathResolutionRecord) pathIdentity {
	path := pr.Resolved
	if path == "" {
		path = pr.Path
	}
	return pathIdentity{Path: path, Dev: pr.Dev, Inode: pr.Inode}
}

// aggregatePathTally counts distinct paths, not path observations: the same
// library seen in ten samples across four processes is one path, and
// counting each sighting would inflate every ownership bucket by whatever
// the sampling schedule and the process count happened to be. A path whose
// classification genuinely differed between samples is counted once in each
// bucket it fell into, which is a real disagreement rather than a
// duplicate.
func aggregatePathTally(matches []PathMatchRecord) []PathResolutionTally {
	ownershipPaths := map[Ownership]map[pathIdentity]bool{}
	trivyPaths := map[TrivyMatch]map[pathIdentity]bool{}
	for _, m := range matches {
		id := identityOfPath(m.PathResolutionRecord)
		if ownershipPaths[m.Ownership] == nil {
			ownershipPaths[m.Ownership] = map[pathIdentity]bool{}
		}
		ownershipPaths[m.Ownership][id] = true
		if trivyPaths[m.TrivyMatch] == nil {
			trivyPaths[m.TrivyMatch] = map[pathIdentity]bool{}
		}
		trivyPaths[m.TrivyMatch][id] = true
	}
	var out []PathResolutionTally
	for o, paths := range ownershipPaths {
		out = append(out, PathResolutionTally{Ownership: string(o), Paths: len(paths)})
	}
	for t, paths := range trivyPaths {
		out = append(out, PathResolutionTally{TrivyMatch: string(t), Paths: len(paths)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ownership != out[j].Ownership {
			return out[i].Ownership < out[j].Ownership
		}
		return out[i].TrivyMatch < out[j].TrivyMatch
	})
	return out
}

// --- GT-B counts with FPR/FNR bounds ---

func computeGTBCounts(packages []PackageVerdict) (GTBCounts, []Discrepancy) {
	var c GTBCounts
	var detail []Discrepancy
	undeterminedPositive, undeterminedNegative := 0, 0

	for _, pv := range packages {
		confirmed := pv.Verdict == VerdictConfirmed
		switch pv.GTBTruth {
		case "used":
			c.Population++
			if confirmed {
				c.TP++
				c.FindingTP += pv.FindingCount
			} else {
				c.FN++
				c.FindingFN += pv.FindingCount
				detail = append(detail, Discrepancy{Package: pv.Package, ExpectedVerdict: "used (GT-B)", ObservedVerdict: string(pv.Verdict), Findings: pv.FindingCount})
			}
		case "not_used":
			c.Population++
			if confirmed {
				c.FP++
				c.FindingFP += pv.FindingCount
				detail = append(detail, Discrepancy{Package: pv.Package, ExpectedVerdict: "not_used (GT-B)", ObservedVerdict: string(pv.Verdict), Findings: pv.FindingCount})
			} else {
				c.TN++
				c.FindingTN += pv.FindingCount
			}
		default:
			c.Undetermined++
			if confirmed {
				undeterminedPositive++
			} else {
				undeterminedNegative++
			}
		}
	}

	c.FPR = rateOrNA(c.FP, c.FP+c.TN)
	c.FNR = rateOrNA(c.FN, c.TP+c.FN)
	c.Coverage = rateOrNA(c.Population, c.Population+c.Undetermined)

	// FPR upper: undetermined-positive -> FP, undetermined-negative -> FN
	// (excluded from FP/TN, never TN — that would dilute the upper bound).
	fprUpperNum := c.FP + undeterminedPositive
	c.FPRUpperBound = rateOrNA(fprUpperNum, fprUpperNum+c.TN)
	// FPR lower: undetermined-positive -> TP (excluded), undetermined-negative -> TN.
	c.FPRLowerBound = rateOrNA(c.FP, c.FP+c.TN+undeterminedNegative)

	// FNR upper: undetermined-negative -> FN, undetermined-positive -> FP (excluded).
	fnrUpperNum := c.FN + undeterminedNegative
	c.FNRUpperBound = rateOrNA(fnrUpperNum, fnrUpperNum+c.TP)
	// FNR lower: undetermined-negative -> TN (excluded), undetermined-positive -> TP.
	c.FNRLowerBound = rateOrNA(c.FN, c.FN+c.TP+undeterminedPositive)

	sort.Slice(detail, func(i, j int) bool { return detail[i].Package < detail[j].Package })
	return c, detail
}

// gtaDiscrepancies reports where the case's pre-run declaration and the
// finished result disagree. Both halves of the declaration are checked
// separately: the expected verdict against the verdict actually reached,
// and the declared real-world usage against whether the run confirmed use.
// A package declared used whose expected verdict is "unobserved" — the
// language-package case — is not a discrepancy when it comes back
// unobserved, because that is exactly what was declared.
func gtaDiscrepancies(packages []PackageVerdict) []Discrepancy {
	var out []Discrepancy
	for _, pv := range packages {
		if pv.ExpectedVerdict == "" && pv.ExpectedUsage == "" && pv.ExpectedFactor == "" {
			continue
		}
		mismatch := false
		if pv.ExpectedVerdict != "" && pv.ExpectedVerdict != string(pv.Verdict) {
			mismatch = true
		}
		if pv.ExpectedFactor != "" && pv.ExpectedFactor != pv.Factor {
			// The verdict can be right for the wrong reason: an unobserved
			// language package that came out unobserved because nothing was
			// sampled is not the declared outcome.
			mismatch = true
		}
		if pv.ExpectedVerdict == "" && pv.ExpectedUsage != "" {
			expectUsed := pv.ExpectedUsage == "used"
			if expectUsed != (pv.Verdict == VerdictConfirmed) {
				mismatch = true
			}
		}
		if mismatch {
			out = append(out, Discrepancy{
				Package: pv.Package, ExpectedUsage: pv.ExpectedUsage, ExpectedVerdict: pv.ExpectedVerdict,
				ExpectedFactor: pv.ExpectedFactor, ObservedVerdict: string(pv.Verdict), ObservedFactor: pv.Factor,
				Findings: pv.FindingCount,
			})
		}
	}
	return out
}

// guessDependencyRate computes the guess-dependency rate: the union of
// (a) Findings confirmed via an unowned/multiple_owners path (always 0 in
// this harness — confirmation only ever comes from an owned+matched path)
// and (b) Findings belonging to a false-positive (container, package) pair.
// The bounds carry GT-B's undetermined pairs through: an undetermined pair
// the run predicted positive is a false positive in the upper bound and a
// true positive in the lower one.
func guessDependencyRate(packages []PackageVerdict, overall Metrics) GuessDependencyRate {
	fp, undeterminedPositive := 0, 0
	for _, pv := range packages {
		switch {
		case pv.GTBTruth == "not_used" && pv.Verdict == VerdictConfirmed:
			fp += pv.FindingCount
		case pv.GTBTruth == "undetermined" && pv.Verdict == VerdictConfirmed:
			undeterminedPositive += pv.FindingCount
		}
	}
	num := fp // unowned-confirmed contributes 0 by construction
	return GuessDependencyRate{
		Numerator: num, UnownedConfirmed: 0, FalsePositiveCount: fp,
		Denominator: overall.FindingConfirmed, Rate: rateOrNA(num, overall.FindingConfirmed),
		UndeterminedPositiveFindings: undeterminedPositive,
		UpperBound:                   rateOrNA(num+undeterminedPositive, overall.FindingConfirmed),
		LowerBound:                   rateOrNA(num, overall.FindingConfirmed),
	}
}

// --- Exposure (host/none network handled first, then bridge-style matching) ---

func computeExposure(rec *ContainerRecord, _ []PathMatchRecord) ExposureVerdict {
	return exposureFromListeners(rec, rec.Listeners)
}

// exposureFromListeners decides one exposure stage from a set of observed
// listeners and the container's Docker configuration.
//
// Every attributed listener is evaluated and the strongest stage wins.
// Returning on the first listener that matched anything would let whichever
// socket procfs happened to list first decide the answer — a service
// listening on both a loopback-published port and an all-interfaces
// published one would be reported as loopback-only half the time.
func exposureFromListeners(rec *ContainerRecord, listeners []Listener) ExposureVerdict {
	switch rec.Docker.NetworkMode {
	case "host":
		return ExposureVerdict{Verdict: "unknown", Reasons: []string{
			"host network: Docker port publishing is not meaningful in this mode, and a listener in the host network namespace cannot be distinguished from an unrelated host service",
		}}
	case "none":
		return ExposureVerdict{Verdict: "container_listening", Reasons: []string{"network_mode=none: no publishing is possible regardless of what is listening"}}
	}

	var attributed []Listener
	for _, l := range listeners {
		if len(listenerGenerations(l)) > 0 {
			attributed = append(attributed, l)
		}
	}
	if len(attributed) == 0 {
		return ExposureVerdict{Verdict: "unknown", Reasons: []string{"no listener could be attributed to any observed process"}}
	}

	best, bestReason := "unknown", ""
	var reasons []string
	seen := map[string]bool{}
	for _, l := range attributed {
		key := dockerPortKey(l)
		bindings, declared := rec.Docker.NetworkPorts[key]
		var stage, reason string
		switch {
		case !declared:
			stage = "unknown"
			reason = fmt.Sprintf("listener on %s port %d (%s) has no NetworkSettings.Ports key %q", l.LocalAddr, l.LocalPort, l.Family, key)
		case len(bindings) == 0:
			stage = "container_listening"
			reason = fmt.Sprintf("NetworkSettings.Ports[%q] is declared but not published (null)", key)
		case anyAllInterfaces(bindings):
			stage = "host_published_all"
			reason = fmt.Sprintf("listener on %s matches NetworkSettings.Ports[%q] published to 0.0.0.0/::", l.LocalAddr, key)
		case allLoopback(bindings):
			stage = "host_published_loopback"
			reason = fmt.Sprintf("listener on %s matches NetworkSettings.Ports[%q] published only to a loopback address", l.LocalAddr, key)
		default:
			stage = "unknown"
			reason = fmt.Sprintf("NetworkSettings.Ports[%q] is published to host addresses that are neither all-interfaces nor loopback", key)
		}
		if !seen[reason] {
			seen[reason] = true
			reasons = append(reasons, reason)
		}
		if exposureRank[stage] > exposureRank[best] {
			best, bestReason = stage, reason
		}
	}
	sort.Strings(reasons)
	out := []string{bestReason}
	for _, r := range reasons {
		if r != bestReason {
			out = append(out, r)
		}
	}
	return ExposureVerdict{Verdict: best, Reasons: out}
}

// dockerPortKey is the NetworkSettings.Ports key an observed listener
// corresponds to. Docker keys a mapping by transport protocol only —
// "8080/tcp" whether the socket is bound on an IPv4 or an IPv6 address — so
// the address family is not part of the key. A record written before the
// family was split out of the protocol field says "tcp6" there; it means
// the same TCP port.
func dockerPortKey(l Listener) string {
	proto := l.Protocol
	if proto == "tcp6" || proto == "" {
		proto = "tcp"
	}
	return fmt.Sprintf("%d/%s", l.LocalPort, proto)
}

func anyAllInterfaces(bindings []PortBinding) bool {
	for _, b := range bindings {
		if b.HostIP == "" || b.HostIP == "0.0.0.0" || b.HostIP == "::" {
			return true
		}
	}
	return false
}

func allLoopback(bindings []PortBinding) bool {
	if len(bindings) == 0 {
		return false
	}
	for _, b := range bindings {
		if !isLoopbackAddr(b.HostIP) {
			return false
		}
	}
	return true
}

func isLoopbackAddr(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || addr == "localhost"
}
