package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// runKeyColumns returns the six run_key dimensions as strings, in the fixed
// order every CSV table uses so columns line up across cases.
func runKeyColumns(k RunKey) []string {
	return []string{k.CaseVariant, k.Permission, itoa(k.Interval), itoa(k.Window), itoa(k.Phase), itoa(k.Replicate)}
}

var runKeyHeader = []string{"case_variant", "permission", "interval", "window", "phase", "replicate"}

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
	header := append(append([]string{}, runKeyHeader...), "case_id", "priority", "na", "total_findings", "rank_changed_top20", "labeled_count", "exposure_stages_in_top20", "example_labeled", "example_not_labeled")
	if err := w.Write(header); err != nil {
		return err
	}
	var rows [][]string
	for _, g := range r.G4 {
		rows = append(rows, append(append([]string{}, runKeyColumns(r.RunKey)...), r.CaseID, g.Priority, boolStr(g.NA), itoa(g.TotalFindings), itoa(g.RankChangedCount), itoa(g.LabeledCount), exposureStages(g.Top20), g.ExampleLabeled, g.ExampleNotLabeled))
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
