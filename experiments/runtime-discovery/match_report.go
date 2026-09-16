package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// runKeyColumns returns the run_key dimensions as strings, in the fixed
// order every CSV table uses so columns line up across cases. The ordering
// condition and the event-collection configuration are part of the key:
// two runs that differ in either are not the same condition, and adding
// them together would combine measurements of different things.
func runKeyColumns(k RunKey) []string {
	return []string{k.CaseVariant, k.Permission, itoa(k.Interval), itoa(k.Window), itoa(k.Phase), itoa(k.Replicate), k.Sync, k.ConfigID}
}

var runKeyHeader = []string{"case_variant", "permission", "interval", "window", "phase", "replicate", "sync", "config_id"}

// writeMatchCSVs renders one MatchResult as the full set of summary tables:
// concatenating each table across every run's match invocation reproduces
// the corresponding cross-run aggregate. Runs are never merged by this
// tool — each CSV row carries its own run_key so the aggregation (or
// deliberate exclusion of non-standard conditions) happens downstream.
func writeMatchCSVs(dir string, r MatchResult) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	writers := []func(string, MatchResult) error{
		writeCaseSummaryCSV, writeClassificationCSV, writeFactorCSV,
		writeGapClassCSV, writePathResolutionCSV, writePermissionsCSV,
		writeGTBCSV, writeG4CSV,
		writeSeriesCSV, writeSourceInputCSV, writeMappingCSV,
		writeOccurrenceCSV, writeEventDropsCSV, writeAttributionCSV,
	}
	for _, w := range writers {
		if err := w(dir, r); err != nil {
			return err
		}
	}
	return nil
}

func rateStr(v float64) string {
	if v < 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.4f", v)
}

func create(dir, name string) (*csv.Writer, *os.File, error) {
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", name, err)
	}
	return csv.NewWriter(f), f, nil
}

func writeRows(w *csv.Writer, rows [][]string) error {
	if err := w.WriteAll(rows); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

// writeCaseSummaryCSV is the one per-run row of the all-case-variant
// summary table.
func writeCaseSummaryCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "case_summary.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "target_finding", "state_observation_failed", "confirmed",
		"unconditional_rate", "conditional_rate",
		"target_pkg", "confirmed_pkg", "pkg_rate",
		"fpr", "fnr", "gt_coverage",
		"guess_dependency_rate", "guess_dependency_lower", "guess_dependency_upper",
		"intel_condition", "intel_source", "image_identity_verified", "exposure_verdict",
	)
	row := append(append([]string{}, runKeyColumns(r.RunKey)...),
		r.CaseID, itoa(r.Overall.FindingDenominator), itoa(r.Overall.FindingObservationFailed), itoa(r.Overall.FindingConfirmed),
		rateStr(r.Overall.UnconditionalRate), rateStr(r.Overall.ConditionalRate),
		itoa(r.Overall.PkgDenominator), itoa(r.Overall.PkgConfirmed), rateStr(r.Overall.PkgRate),
		rateStr(r.GTB.FPR), rateStr(r.GTB.FNR), rateStr(r.GTB.Coverage),
		rateStr(r.GuessDependency.Rate), rateStr(r.GuessDependency.LowerBound), rateStr(r.GuessDependency.UpperBound),
		r.Intel.Condition, r.IntelSource, boolStr(r.ImageIdentityVerified), r.Exposure.Verdict,
	)
	if err := w.Write(header); err != nil {
		return err
	}
	return writeRows(w, [][]string{row})
}

// writeClassificationCSV is the per-classification summary table:
// overall, by triage priority, by package class, and the degraded-intel
// condition kept apart from the normal one.
func writeClassificationCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "classification.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...), "case_id", "classification", "target_finding", "state_observation_failed", "confirmed", "unconditional_rate", "conditional_rate")
	if err := w.Write(header); err != nil {
		return err
	}
	rows := [][]string{classificationRow(r, "overall", r.Overall)}
	for _, key := range []string{"act_now", "watch", "low", "unclassified"} {
		if m, ok := r.ByPrio[key]; ok {
			rows = append(rows, classificationRow(r, key, m))
		}
	}
	if r.Intel.Condition == "degraded" {
		rows = append(rows, classificationRow(r, "degraded_condition_overall", r.Overall))
	} else {
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...), r.CaseID, "degraded_condition_overall", "N/A", "N/A", "N/A", "N/A", "N/A"))
	}
	for _, key := range sortedClassKeys(r.ByClass) {
		rows = append(rows, classificationRow(r, "class:"+key, r.ByClass[key]))
	}
	return writeRows(w, rows)
}

func classificationRow(r MatchResult, label string, m Metrics) []string {
	return append(append([]string{}, runKeyColumns(r.RunKey)...),
		r.CaseID, label, itoa(m.FindingDenominator), itoa(m.FindingObservationFailed), itoa(m.FindingConfirmed), rateStr(m.UnconditionalRate), rateStr(m.ConditionalRate))
}

func sortedClassKeys(m map[string]Metrics) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeFactorCSV is the classification-by-shortfall-factor table.
func writeFactorCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "factors.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...), "case_id", "verdict", "factor", "packages", "findings_total", "findings_act_now", "findings_watch", "findings_low")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	for _, fb := range concatFactors(r.UnresolvedFactors, r.UnobservedFactors, r.NotDeterminedFactors) {
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...), r.CaseID, fb.Verdict, fb.Factor, itoa(fb.Packages), itoa(fb.Findings), itoa(fb.ActNow), itoa(fb.Watch), itoa(fb.Low)))
	}
	return writeRows(w, rows)
}

func concatFactors(groups ...[]FactorBreakdown) []FactorBreakdown {
	var out []FactorBreakdown
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// writeGapClassCSV is the confirmation-gap-class by classification table.
func writeGapClassCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "gap_classes.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...), "case_id", "class", "recoverability", "packages", "findings", "act_now_findings", "watch_findings")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	for _, gc := range r.GapClasses {
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...), r.CaseID, gc.Class, gc.Recoverability, itoa(gc.Packages), itoa(gc.Findings), itoa(gc.ActNow), itoa(gc.Watch)))
	}
	return writeRows(w, rows)
}

// writePathResolutionCSV is the per-path result table: both the ownership
// tally and the trivy_match tally, distinguished by which column is set,
// and counted in distinct paths rather than path sightings.
func writePathResolutionCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "path_resolution.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...), "case_id", "ownership", "trivy_match", "paths")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	for _, t := range r.PathResolutionTally {
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...), r.CaseID, t.Ownership, t.TrivyMatch, itoa(t.Paths)))
	}
	return writeRows(w, rows)
}

// writePermissionsCSV is the per-permission-condition table: one row per
// distinct failed operation under this run's declared permission
// condition, each carrying the run's own confirmation outcome so a
// condition's failures and what they cost can be read from one table.
func writePermissionsCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "permissions.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "operation", "result", "occurrences", "message",
		"target_finding", "confirmed", "unconditional_rate", "conditional_rate", "state_observation_failed")
	if err := w.Write(header); err != nil {
		return err
	}
	seen := map[string]string{}
	counts := map[string]int{}
	var order []string
	for _, fl := range r.Failures {
		if _, ok := seen[fl.Step]; !ok {
			order = append(order, fl.Step)
		}
		seen[fl.Step] = fl.Message
		counts[fl.Step]++
	}
	sort.Strings(order)
	// The run's own outcome columns repeat on every row so a permission
	// condition's failures can be read against what that condition
	// actually confirmed, rather than only against each other.
	outcome := []string{
		itoa(r.Overall.FindingDenominator), itoa(r.Overall.FindingConfirmed),
		rateStr(r.Overall.UnconditionalRate), rateStr(r.Overall.ConditionalRate),
		itoa(r.Overall.FindingObservationFailed),
	}
	var rows [][]string
	if len(order) == 0 {
		// A condition under which nothing failed is a result too, and an
		// empty table would be indistinguishable from a run that was never
		// made.
		rows = append(rows, append(append(append([]string{}, runKeyColumns(r.RunKey)...), r.CaseID, "none", "no_failure", "0", ""), outcome...))
	}
	for _, step := range order {
		rows = append(rows, append(append(append([]string{}, runKeyColumns(r.RunKey)...),
			r.CaseID, step, "failed", itoa(counts[step]), seen[step]), outcome...))
	}
	return writeRows(w, rows)
}

// writeGTBCSV is the FP/FN table with GT coverage and the four bound
// formulas.
func writeGTBCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "gt_b.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "population", "undetermined", "coverage", "tp", "fp", "tn", "fn",
		"fpr", "fnr", "fpr_upper", "fpr_lower", "fnr_upper", "fnr_lower")
	if err := w.Write(header); err != nil {
		return err
	}
	row := append(append([]string{}, runKeyColumns(r.RunKey)...),
		r.CaseID, itoa(r.GTB.Population), itoa(r.GTB.Undetermined), rateStr(r.GTB.Coverage),
		itoa(r.GTB.TP), itoa(r.GTB.FP), itoa(r.GTB.TN), itoa(r.GTB.FN),
		rateStr(r.GTB.FPR), rateStr(r.GTB.FNR), rateStr(r.GTB.FPRUpperBound), rateStr(r.GTB.FPRLowerBound), rateStr(r.GTB.FNRUpperBound), rateStr(r.GTB.FNRLowerBound),
	)
	return writeRows(w, [][]string{row})
}

// writeG4CSV is the G4 additional-judgement output, one row per priority
// bucket.
func writeG4CSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "g4.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...), "case_id", "series", "priority", "na", "total_findings", "rank_changed_top20", "labeled_count", "exposure_stages_in_top20", "example_labeled", "example_not_labeled")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	for _, g := range r.G4 {
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...), r.CaseID, g.Series, g.Priority, boolStr(g.NA), itoa(g.TotalFindings), itoa(g.RankChangedCount), itoa(g.LabeledCount), exposureStages(g.Top20), g.ExampleLabeled, g.ExampleNotLabeled))
	}
	return writeRows(w, rows)
}

// exposureStages summarizes the exposure stages present among the ranked
// rows, as "<stage>:<count>" pairs. Exposure is joined per Finding now, so
// one run can legitimately carry several stages and a single value would
// have to pick one arbitrarily.
func exposureStages(rows []RankedFinding) string {
	counts := map[string]int{}
	for _, r := range rows {
		stage := r.Exposure
		if stage == "" {
			stage = "unknown"
		}
		counts[stage]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf("%s:%d", k, counts[k])
	}
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// writeSeriesCSV is the series comparison: every classification's
// confirmation count under each of the three rule sets, the two increments
// kept apart, and the number of distinct files the positives rest on.
//
// The increments are separate columns because the combined figure does not
// say which layer produced it, and the two layers cost entirely different
// things to deploy. An increment that could not be computed is written as
// unavailable rather than as zero.
func writeSeriesCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "series.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "series", "classification", "target_finding", "state_observation_failed", "confirmed",
		"unconditional_rate", "conditional_rate", "target_pkg", "confirmed_pkg",
		"observed_binaries", "observed_files", "event_state", "collection_complete",
		"tp", "fp", "tn", "fn", "fpr", "fnr", "gt_coverage")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	row := func(sm SeriesMetrics, label string, m Metrics, binaries, files int, withGTB bool) []string {
		tp, fp, tn, fn, fpr, fnr, coverage := "", "", "", "", "", "", ""
		if withGTB {
			tp, fp = itoa(sm.GTB.TP), itoa(sm.GTB.FP)
			tn, fn = itoa(sm.GTB.TN), itoa(sm.GTB.FN)
			fpr, fnr = rateStr(sm.GTB.FPR), rateStr(sm.GTB.FNR)
			coverage = rateStr(sm.GTB.Coverage)
		}
		return append(append([]string{}, runKeyColumns(r.RunKey)...),
			r.CaseID, sm.Series, label,
			itoa(m.FindingDenominator), itoa(m.FindingObservationFailed), itoa(m.FindingConfirmed),
			rateStr(m.UnconditionalRate), rateStr(m.ConditionalRate),
			itoa(m.PkgDenominator), itoa(m.PkgConfirmed),
			itoa(binaries), itoa(files), r.EventState, boolStr(sm.CollectionComplete),
			tp, fp, tn, fn, fpr, fnr, coverage)
	}
	for _, sm := range r.Series {
		rows = append(rows, row(sm, "overall", sm.Overall, sm.ObservedBinaries, sm.ObservedFiles, true))
		for _, key := range []string{"act_now", "watch", "low", priorityUnclassified} {
			if m, ok := sm.ByPrio[key]; ok {
				rows = append(rows, row(sm, key, m, 0, 0, false))
			}
		}
		for _, key := range sortedClassKeys(sm.ByClass) {
			rows = append(rows, row(sm, "class:"+key, sm.ByClass[key], 0, 0, false))
		}
		for _, key := range sortedClassKeys(sm.ByEco) {
			rows = append(rows, row(sm, "ecosystem:"+key, sm.ByEco[key], 0, 0, false))
		}
		for _, key := range sortedClassKeys(sm.ByGrain) {
			rows = append(rows, row(sm, "grain:"+key, sm.ByGrain[key], 0, 0, false))
		}
	}
	for _, d := range r.SeriesDeltas {
		findings, packages := "N/A", "N/A"
		if d.Available {
			findings, packages = itoa(d.Findings), itoa(d.Packages)
		}
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...),
			r.CaseID, d.From+"->"+d.To, "delta", "", "", findings, "", "", "", packages, "", "", d.Reason, "",
			"", "", "", "", "", "", ""))
	}
	return writeRows(w, rows)
}

// writeSourceInputCSV is the per-evidence-source input availability table.
// It exists so a source that contributed nothing can be told apart from
// one that was never able to contribute.
func writeSourceInputCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "source_inputs.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...), "case_id", "source", "input_state", "positives", "reason")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	for _, st := range r.SourceInputStates {
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...),
			r.CaseID, st.Source, st.State, itoa(st.Positives), st.Reason))
	}
	return writeRows(w, rows)
}

// writeMappingCSV is the per-ecosystem file-to-package mapping outcome:
// how many files stage one identified, how many packages stage two spread
// the evidence over, and why the rest could not be reached.
func writeMappingCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "mapping.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "ecosystem", "scan_report_files", "stage1_files", "stage2_packages",
		"observed_binaries", "observed_files", "unmappable_reasons",
		"candidate_conflicts", "unresolved_paths", "unresolved_events",
		"unmappable_paths", "unmappable_events", "outside_scan_paths", "outside_scan_events")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	for _, row := range r.Mapping.Rows {
		reasons := make([]string, 0, len(row.UnmappableBy))
		for k := range row.UnmappableBy {
			reasons = append(reasons, k)
		}
		sort.Strings(reasons)
		text := ""
		for _, k := range reasons {
			if text != "" {
				text += " "
			}
			text += fmt.Sprintf("%s:%d", k, row.UnmappableBy[k])
		}
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...),
			r.CaseID, row.Ecosystem, itoa(row.ScanReportFiles), itoa(row.Stage1Files), itoa(row.Stage2Packages),
			itoa(row.ObservedBinary), itoa(row.ObservedFile), text,
			itoa(r.Mapping.CandidateConflicts), itoa(r.Mapping.UnresolvedPaths), itoa(r.Mapping.UnresolvedEvents),
			itoa(r.Mapping.UnmappablePaths), itoa(r.Mapping.UnmappableEvents),
			itoa(r.Mapping.OutsideScanPaths), itoa(r.Mapping.OutsideScanEvents)))
	}
	return writeRows(w, rows)
}

// writeOccurrenceCSV is the per-occurrence capture table: how many of the
// things the workload recorded itself doing were seen, at each of the
// three units those things are counted in, plus what was excluded from
// each denominator and why nothing was captured where nothing was.
func writeOccurrenceCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "occurrence_capture.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "available", "match_rule", "tolerance_ms", "clock_basis",
		"exec_eligible", "exec_decidable", "exec_one_to_one", "exec_rate", "exec_unmatchable", "exec_one_to_many", "exec_many_to_one", "exec_undecidable",
		"load_eligible", "load_decidable", "load_with_evidence", "load_rate", "load_attribution_conflicts", "load_undecidable",
		"real_open_occurrences", "real_open_decidable", "real_open_captured", "real_open_rate",
		"excluded_cache_hit", "excluded_failed", "excluded_outside_window",
		"uncaptured_outside_window", "uncaptured_in_window_missed", "uncaptured_reason_unknown")
	if err := w.Write(header); err != nil {
		return err
	}
	o := r.Occurrence
	realRate := rateStr(o.RealOpen.Rate)
	if o.RealOpen.NA {
		realRate = "N/A"
	}
	row := append(append([]string{}, runKeyColumns(r.RunKey)...),
		r.CaseID, boolStr(o.Available), o.MatchRule, fmt.Sprintf("%d", o.ToleranceMS), o.ClockBasis,
		itoa(o.Exec.Eligible), itoa(o.Exec.Decidable), itoa(o.Exec.OneToOne), rateStr(o.Exec.Rate), itoa(o.Exec.Unmatchable), itoa(o.Exec.OneToMany), itoa(o.Exec.ManyToOne), itoa(o.Exec.Undecidable),
		itoa(o.Load.Eligible), itoa(o.Load.Decidable), itoa(o.Load.WithEvidence), rateStr(o.Load.Rate), itoa(o.Load.AttributionConflicts), itoa(o.Load.Undecidable),
		itoa(o.RealOpen.Occurrences), itoa(o.RealOpen.Decidable), itoa(o.RealOpen.Captured), realRate,
		itoa(o.Excluded.CacheHit), itoa(o.Excluded.Failed), itoa(o.Excluded.OutsideWindow),
		itoa(o.Uncaptured.OutsideWindow), itoa(o.Uncaptured.InWindowMissed), itoa(o.Uncaptured.ReasonUnknown))
	return writeRows(w, [][]string{row})
}

// writeEventDropsCSV is the event-loss table. The number of overflow
// notifications and the number of events those notifications stand for are
// separate columns: one notification can represent many lost events, so
// the notification count is not a count of what was lost.
func writeEventDropsCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "event_drops.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "event_state", "method", "filter", "buffer_pages",
		"events_total", "events_attributed", "events_in_window",
		"events_before_filter", "events_after_filter",
		"lost_events", "lost_notifications", "enter_exit_unmatched", "enter_exit_unmatched_boundary", "unmatched_identity_unavailable",
		"identity_unavailable", "map_overflow",
		"path_read_failures", "path_truncations", "convert_failures", "partial_events",
		"stopped_early", "stopped_at", "gap_seconds", "stop_reason")
	if err := w.Write(header); err != nil {
		return err
	}
	d := r.EventDrops
	stoppedAt := ""
	if !d.StoppedAt.IsZero() {
		stoppedAt = d.StoppedAt.UTC().Format(time.RFC3339)
	}
	row := append(append([]string{}, runKeyColumns(r.RunKey)...),
		r.CaseID, r.EventState, r.EventHead.Method, r.EventHead.Filter, itoa(r.EventHead.BufferPages),
		itoa(r.EventsTotal), itoa(r.EventsAttributed), itoa(r.EventsInWindow),
		itoa(d.EventsBeforeFilter), itoa(d.EventsAfterFilter),
		itoa(d.LostEvents), itoa(d.LostNotifications), itoa(d.EnterExitUnmatched), itoa(d.EnterExitUnmatchedBoundary), itoa(d.UnmatchedIdentityUnavailable),
		itoa(d.IdentityUnavailable), itoa(d.MapOverflow),
		itoa(d.PathReadFailures), itoa(d.PathTruncations), itoa(d.ConvertFailures), itoa(d.PartialEvents),
		boolStr(d.StoppedEarly), stoppedAt, fmt.Sprintf("%.3f", d.GapSeconds), d.StopReason)
	return writeRows(w, [][]string{row})
}

// writeAttributionCSV is the container-attribution table. Both rates are
// always written: a collection that discarded every event would attribute
// nothing wrongly, so the wrong-attribution rate alone cannot show that
// attribution works.
func writeAttributionCSV(dir string, r MatchResult) error {
	w, f, err := create(dir, "attribution.csv")
	if err != nil {
		return err
	}
	defer f.Close()
	header := append(append([]string{}, runKeyHeader...),
		"case_id", "match_rule", "cross_container_evaluable",
		"attributed_events", "misattributed", "misattribution_rate",
		"logged_occurrences", "correctly_attributed", "correct_attribution_rate",
		"host_occurrences", "host_misattributed_occurrences", "host_left_unattributed", "host_unobserved", "host_correct_rate",
		"from_other_container", "from_host", "unattributed_events", "undecidable",
		"excluded_cache_hit", "excluded_failed", "excluded_outside_window")
	if err := w.Write(header); err != nil {
		return err
	}
	a := r.Attribution
	row := append(append([]string{}, runKeyColumns(r.RunKey)...),
		r.CaseID, a.MatchRule, boolStr(a.CrossContainerEvaluable),
		itoa(a.AttributedEvents), itoa(a.Misattributed), rateStr(a.MisattributionRate),
		itoa(a.LoggedOccurrences), itoa(a.CorrectlyAttributed), rateStr(a.CorrectAttributionRate),
		itoa(a.HostOccurrences), itoa(a.HostMisattributedOccurrences), itoa(a.HostLeftUnattributed), itoa(a.HostUnobserved), rateStr(a.HostCorrectRate),
		itoa(a.FromOtherContainer), itoa(a.FromHost), itoa(a.Unattributed), itoa(a.Undecidable),
		itoa(a.Excluded.CacheHit), itoa(a.Excluded.Failed), itoa(a.Excluded.OutsideWindow))
	return writeRows(w, [][]string{row})
}
