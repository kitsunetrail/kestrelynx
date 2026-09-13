package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/intel"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Default triage thresholds, mirroring the product defaults
// (internal/config/config.go's defaultActNowEPSS/defaultWatchEPSS).
const (
	defaultActNowEPSS = 0.10
	defaultWatchEPSS  = 0.01
)

func runMatch(args []string) error {
	fs := flag.NewFlagSet("match", flag.ExitOnError)
	obsPath := fs.String("observation", "", "path to the collect-produced container record JSON (required)")
	trivyPath := fs.String("trivy", "", "path to the Trivy JSON report for this case (required)")
	casePath := fs.String("case", "", "path to the case definition JSON, GT-A and gt_b_scope included (required)")
	gtbPath := fs.String("gtb", "", "path to the ground-truth-B JSON for this case (optional; omit to leave FP/FN undetermined)")
	intelCache := fs.String("intel-cache", "./out/intel-cache", "cache directory for the KEV/EPSS datasets, used only when -intel-snapshot is not given")
	intelSnapshot := fs.String("intel-snapshot", "", "path to a saved intel snapshot JSON (the \"intel\" object of an earlier match result). When given, no KEV/EPSS lookup is performed and the saved enrichment is used verbatim, which is what makes a re-run reproduce an earlier classification")
	outIntelSnapshot := fs.String("out-intel-snapshot", "", "path to write the intel snapshot this run used, for feeding back as -intel-snapshot later (optional)")
	actNowEPSS := fs.Float64("act-now-epss", defaultActNowEPSS, "EPSS threshold for act_now")
	watchEPSS := fs.Float64("watch-epss", defaultWatchEPSS, "EPSS threshold for watch")
	outJSON := fs.String("out-json", "./out/match-result.json", "output path for the match result JSON")
	outCSVDir := fs.String("out-csv-dir", "./out/match-csv", "output directory for the summary CSV tables")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: %s match [flags]\n\nMatches a collect container record against a Trivy scan, a case definition (GT-A + gt_b_scope), and optionally ground-truth-B, computing the observation-state/verdict decision table, confirmation rates, Exposure, G4 ranking, and false positive/negative counts.\n\nflags:\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *obsPath == "" || *trivyPath == "" || *casePath == "" {
		fs.Usage()
		return fmt.Errorf("-observation, -trivy, and -case are all required")
	}

	rec, err := readContainerRecord(*obsPath)
	if err != nil {
		return err
	}
	trivyData, err := os.ReadFile(*trivyPath)
	if err != nil {
		return fmt.Errorf("read trivy report: %w", err)
	}
	scan, err := scanner.ParseReport(trivyData)
	if err != nil {
		return fmt.Errorf("parse trivy report: %w", err)
	}
	def, err := readCase(*casePath)
	if err != nil {
		return err
	}
	var gtb *GroundTruthB
	if *gtbPath != "" {
		gtb, err = readGTB(*gtbPath)
		if err != nil {
			return err
		}
	}

	var snapshot *IntelSnapshot
	if *intelSnapshot != "" {
		snapshot, err = readIntelSnapshot(*intelSnapshot)
		if err != nil {
			return err
		}
	}

	result, err := runMatchPipeline(context.Background(), rec, scan, def, gtb, snapshot, *intelCache, *actNowEPSS, *watchEPSS)
	if err != nil {
		return err
	}

	if err := writeJSON(*outJSON, result); err != nil {
		return err
	}
	if *outIntelSnapshot != "" {
		if err := writeJSON(*outIntelSnapshot, result.Intel); err != nil {
			return err
		}
	}
	if err := writeMatchCSVs(*outCSVDir, result); err != nil {
		return err
	}
	return nil
}

// readIntelSnapshot loads a previously saved intel snapshot: the exact
// KEV/EPSS state an earlier run classified against.
func readIntelSnapshot(path string) (*IntelSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read intel snapshot: %w", err)
	}
	var snap IntelSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse intel snapshot: %w", err)
	}
	return &snap, nil
}

// runMatchPipeline is match's entire computation. It reads no rootfs and
// makes no call depending on any live container: everything it touches is
// either an argument or the intel cache on disk, so it is safe to call
// twice on the same saved inputs and expect the same result.
func runMatchPipeline(ctx context.Context, rec ContainerRecord, scan scanner.ImageScan, def Case, gtb *GroundTruthB, savedIntel *IntelSnapshot, intelCacheDir string, actNowEPSS, watchEPSS float64) (MatchResult, error) {
	result := MatchResult{CaseID: def.CaseID, Image: def.Image, GeneratedAt: time.Now().UTC(), Subject: rec.Subject, RunKey: rec.RunKey}
	result.ContainerID = rec.Subject.Docker.ContainerID
	result.ObservedImageID = rec.Subject.Docker.ImageID
	result.Failures = rec.Failures
	if rec.InspectError != "" {
		// The container could not be inspected at all, so it has no
		// samples. It stays in the population as a fully not_determined
		// result rather than disappearing from the denominator.
		result.Errors = append(result.Errors, "observation: container inspect failed: "+rec.InspectError)
	}

	verified, scanDigest, identityErr := verifyImageIdentity(rec, scan)
	result.ScanDigest = scanDigest
	result.ImageIdentityVerified = verified
	if identityErr != nil {
		return MatchResult{}, identityErr
	}

	var vulnIDs []string
	seen := map[string]bool{}
	for _, f := range scan.Findings {
		if !seen[f.VulnID] {
			seen[f.VulnID] = true
			vulnIDs = append(vulnIDs, f.VulnID)
		}
	}

	enrich, snapshot, source, lookupErr := resolveIntel(ctx, savedIntel, intelCacheDir, vulnIDs)
	if lookupErr != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("intel lookup: %v", lookupErr))
	}
	result.Intel, result.IntelSource = snapshot, source

	tr := analyze.Triage{
		Enabled: true, ActNowEPSS: actNowEPSS, WatchEPSS: watchEPSS,
		Enrich: convertEnrichment(enrich),
		Intel:  analyze.IntelStatus{KEVOK: snapshot.KEVOK, EPSSOK: snapshot.EPSSOK, StaleDays: snapshot.StaleDays},
	}
	priorityByIndex := computePriorities(scan.Findings, scan.Image, scan.OSFamily, tr, result.GeneratedAt)
	if byStatus := unclassifiedByStatus(scan.Findings, priorityByIndex); len(byStatus) > 0 {
		statuses := make([]string, 0, len(byStatus))
		for status := range byStatus {
			statuses = append(statuses, status)
		}
		sort.Strings(statuses)
		parts := make([]string, 0, len(statuses))
		total := 0
		for _, status := range statuses {
			parts = append(parts, fmt.Sprintf("%s=%d", status, byStatus[status]))
			total += byStatus[status]
		}
		result.Errors = append(result.Errors, fmt.Sprintf(
			"%d Finding(s) carry a vulnerability status the product's triage does not sort into a section, so no priority could be recovered for them and they are counted as %q (by status: %s)",
			total, priorityUnclassified, strings.Join(parts, ", ")))
	}

	wv := computeWindowValidity(&rec)
	obsState := observationState(&rec, wv)

	scope := scopeSet(def.GTBScope)
	truth := buildGTBTruth(gtb, scope, rec.Window.ScheduledStart, rec.Window.ScheduledEnd)
	result.GTBIncomplete = truth.IncompletenessLog

	gapEv := computeGapEvidence(&rec, wv)
	groups := groupFindings(scan.Findings)
	packages := make([]PackageVerdict, 0, len(groups))
	for _, g := range groups {
		pv := assignVerdict(g, &rec, def, obsState, wv)
		applyPriorities(&pv, g, priorityByIndex)
		labelGTBTruth(&pv, truth)
		pv.GapClass, pv.GapRecoverability = classifyGap(pv, declaresE4(def, g.key.Package), gapEv)
		packages = append(packages, pv)
	}
	result.Packages = packages

	result.Overall, result.ByClass, result.ByPrio,
		result.UnresolvedFactors, result.UnobservedFactors, result.NotDeterminedFactors,
		result.GapClasses = aggregate(packages)

	result.PathMatches = buildPathMatches(&rec, groups)
	result.PathResolutionTally = aggregatePathTally(result.PathMatches)
	result.GTB, result.FPFNDetail = computeGTBCounts(packages)
	result.GTADiscrepancies = gtaDiscrepancies(packages)
	result.GuessDependency = guessDependencyRate(packages, result.Overall)
	result.Exposure = computeExposure(&rec, result.PathMatches)

	evidence := joinPackageEvidence(&rec, groups, wv)
	for _, prio := range []string{"act_now", "watch"} {
		result.G4 = append(result.G4, computeG4(prio, groups, scan.Findings, priorityByIndex, evidence))
	}

	result.Evidence = buildEvidence(packages, result.Exposure, &rec, wv, rec.Window.ID)

	return result, nil
}

// resolveIntel supplies the KEV/EPSS enrichment the priority computation
// runs on, from a saved snapshot when one was given and from the product's
// own intel source otherwise. Only the snapshot path reproduces: a live
// lookup refreshes its feeds and re-classifies the same Findings
// differently as KEV and EPSS change, which is correct for the product and
// wrong for a measurement meant to be re-derivable from saved inputs.
func resolveIntel(ctx context.Context, saved *IntelSnapshot, cacheDir string, vulnIDs []string) (map[string]intel.Enrichment, IntelSnapshot, string, error) {
	if saved != nil {
		enrich := make(map[string]intel.Enrichment, len(saved.Enrichment))
		for id, e := range saved.Enrichment {
			enrich[id] = intel.Enrichment{KEV: e.KEV, EPSS: e.EPSS, EPSSKnown: e.EPSSKnown}
		}
		snapshot := *saved
		if snapshot.Enrichment == nil {
			snapshot.Enrichment = map[string]FindingIntel{}
		}
		if snapshot.Condition == "" {
			snapshot.Condition = conditionLabel(!snapshot.KEVOK && !snapshot.EPSSOK)
		}
		return enrich, snapshot, "snapshot", nil
	}

	src := &intel.Source{CacheDir: cacheDir}
	enrich, freshness, lookupErr := src.Lookup(ctx, vulnIDs)
	kevAt, epssAt := intelFetchTimes(cacheDir)
	snapshot := IntelSnapshot{
		KEVFetchedAt: kevAt, EPSSFetchedAt: epssAt,
		KEVOK: freshness.KEVOK, EPSSOK: freshness.EPSSOK, StaleDays: freshness.StaleDays,
		Condition:  conditionLabel(freshness.Degraded()),
		Enrichment: map[string]FindingIntel{},
	}
	for id, e := range enrich {
		snapshot.Enrichment[id] = FindingIntel{KEV: e.KEV, EPSS: e.EPSS, EPSSKnown: e.EPSSKnown}
	}
	return enrich, snapshot, "lookup", lookupErr
}

// intelFetchTimes reads when each dataset in the cache directory was last
// fetched, so a snapshot says which feed state it represents rather than
// only that the feeds were usable.
func intelFetchTimes(cacheDir string) (kevAt, epssAt time.Time) {
	data, err := os.ReadFile(filepath.Join(cacheDir, "meta.json"))
	if err != nil {
		return time.Time{}, time.Time{}
	}
	var meta struct {
		KEVFetchedAt  time.Time `json:"kev_fetched_at"`
		EPSSFetchedAt time.Time `json:"epss_fetched_at"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return time.Time{}, time.Time{}
	}
	return meta.KEVFetchedAt, meta.EPSSFetchedAt
}

func conditionLabel(degraded bool) string {
	if degraded {
		return "degraded"
	}
	return "normal"
}

// verifyImageIdentity checks that the container the observation describes
// is the same image Trivy actually scanned.
func verifyImageIdentity(rec ContainerRecord, scan scanner.ImageScan) (verified bool, scanDigest string, err error) {
	scanDigest = scan.ScannedKey.Digest.String()
	observedDigest, obsOK := inventory.ParseDigest(inventory.DigestConfig, rec.Subject.Docker.ImageID)
	scanOK := scan.ScannedKey.Digest.Kind == inventory.DigestConfig && scan.ScannedKey.Digest.Valid()
	if !obsOK || !scanOK {
		return false, scanDigest, nil
	}
	if observedDigest.Hex != scan.ScannedKey.Digest.Hex {
		return false, scanDigest, fmt.Errorf("image identity mismatch: container %q was observed running ImageID %s, but the Trivy report resolved %s",
			rec.Subject.Docker.ContainerID, observedDigest.String(), scan.ScannedKey.Digest.String())
	}
	return true, scanDigest, nil
}

func convertEnrichment(in map[string]intel.Enrichment) map[string]analyze.Enrichment {
	out := make(map[string]analyze.Enrichment, len(in))
	for id, e := range in {
		out[id] = analyze.Enrichment{KEV: e.KEV, Ransomware: e.Ransomware, EPSS: e.EPSS, EPSSKnown: e.EPSSKnown, KEVNoteURL: e.KEVNoteURL}
	}
	return out
}

func readContainerRecord(path string) (ContainerRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ContainerRecord{}, fmt.Errorf("read observation: %w", err)
	}
	var rec ContainerRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return ContainerRecord{}, fmt.Errorf("parse observation: %w", err)
	}
	// A record whose inspect failed is still matched. Refusing it would
	// remove the container's whole Finding set from the population, which
	// is exactly the bias the decision table's first rule exists to
	// prevent: those Findings are not_determined, not absent.
	return rec, nil
}

func readCase(path string) (Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Case{}, fmt.Errorf("read case definition: %w", err)
	}
	var def Case
	if err := json.Unmarshal(data, &def); err != nil {
		return Case{}, fmt.Errorf("parse case definition: %w", err)
	}
	if def.CaseID == "" {
		return Case{}, fmt.Errorf("case definition: case_id is required")
	}
	return def, nil
}

func readGTB(path string) (*GroundTruthB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ground truth B: %w", err)
	}
	var gtb GroundTruthB
	if err := json.Unmarshal(data, &gtb); err != nil {
		return nil, fmt.Errorf("parse ground truth B: %w", err)
	}
	if gtb.Kind != "usage_log" && gtb.Kind != "limited" {
		return nil, fmt.Errorf("ground truth B: kind must be \"usage_log\" or \"limited\", got %q", gtb.Kind)
	}
	return &gtb, nil
}
