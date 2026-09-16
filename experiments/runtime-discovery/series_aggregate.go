package main

import (
	"fmt"
	"sort"
)

// seriesOf reads one package's verdict and factor for a given series off a
// finished PackageVerdict, so the aggregation does not have to know which
// fields each series lives in.
func seriesOf(pv PackageVerdict, series string) (Verdict, string) {
	switch series {
	case seriesS1:
		return pv.S1Verdict, pv.S1Factor
	case seriesS2:
		return pv.S2Verdict, pv.S2Factor
	default:
		return pv.Verdict, pv.Factor
	}
}

// aggregateSeries computes one series' rows. The population is the same in
// every series — every finding, whatever the observation managed — because
// a denominator that shrinks when the observation fails turns a failure to
// look into a better-looking result.
func aggregateSeries(series string, packages []PackageVerdict, collectionComplete bool) SeriesMetrics {
	sm := SeriesMetrics{
		Series: series, ByClass: map[string]Metrics{}, ByPrio: map[string]Metrics{},
		ByEco: map[string]Metrics{}, ByGrain: map[string]Metrics{},
	}
	unresolved, unobserved, notDetermined := map[string]*FactorBreakdown{}, map[string]*FactorBreakdown{}, map[string]*FactorBreakdown{}
	binaries, files := map[string]bool{}, map[string]bool{}

	add := func(m *Metrics, pv PackageVerdict, v Verdict) {
		m.FindingDenominator += pv.FindingCount
		m.PkgDenominator++
		if v == VerdictNotDetermined {
			m.FindingObservationFailed += pv.FindingCount
		}
		if v == VerdictConfirmed {
			m.FindingConfirmed += pv.FindingCount
			m.PkgConfirmed++
		}
	}

	for _, pv := range packages {
		v, factor := seriesOf(pv, series)
		add(&sm.Overall, pv, v)
		cm := sm.ByClass[pv.Class]
		add(&cm, pv, v)
		sm.ByClass[pv.Class] = cm

		eco := pv.Ecosystem
		if eco == "" {
			eco = ecoOS
		}
		em := sm.ByEco[eco]
		add(&em, pv, v)
		sm.ByEco[eco] = em

		if v == VerdictConfirmed {
			grain := pv.EvidenceGrain
			if grain == "" {
				grain = grainFile
			}
			gm := sm.ByGrain[grain]
			add(&gm, pv, v)
			sm.ByGrain[grain] = gm
			for _, f := range pv.EvidenceFiles {
				if grain == grainBinary {
					binaries[f] = true
				} else {
					files[f] = true
				}
			}
		}

		for prio, count := range pv.Priorities {
			if prio == "" {
				continue
			}
			pm := sm.ByPrio[prio]
			pm.FindingDenominator += count
			if v == VerdictNotDetermined {
				pm.FindingObservationFailed += count
			}
			if v == VerdictConfirmed {
				pm.FindingConfirmed += count
			}
			if prio == pv.MaxPriority {
				pm.PkgDenominator++
				if v == VerdictConfirmed {
					pm.PkgConfirmed++
				}
			}
			sm.ByPrio[prio] = pm
		}

		var bucket map[string]*FactorBreakdown
		switch v {
		case VerdictUnresolved:
			bucket = unresolved
		case VerdictUnobserved:
			bucket = unobserved
		case VerdictNotDetermined:
			bucket = notDetermined
		}
		if bucket != nil {
			fb := bucket[factor]
			if fb == nil {
				fb = &FactorBreakdown{Verdict: string(v), Factor: factor}
				bucket[factor] = fb
			}
			fb.Packages++
			fb.Findings += pv.FindingCount
			fb.ActNow += pv.Priorities["act_now"]
			fb.Watch += pv.Priorities["watch"]
			fb.Low += pv.Priorities["low"]
		}
	}

	// The conditional rate is over windows whose collection ran to
	// completion. Subtracting the undetermined findings is not the same
	// condition: a window that collected half of what it should have has
	// no undetermined findings and is still not a window the conditional
	// rate is about. Where the collection did not complete, the
	// conditional rate is unavailable rather than computed from a
	// denominator that does not mean what it says.
	finish := func(m Metrics) Metrics {
		m.UnconditionalRate = rateOrNA(m.FindingConfirmed, m.FindingDenominator)
		if collectionComplete {
			m.ConditionalRate = rateOrNA(m.FindingConfirmed, m.FindingDenominator-m.FindingObservationFailed)
		} else {
			m.ConditionalRate = -1
		}
		m.PkgRate = rateOrNA(m.PkgConfirmed, m.PkgDenominator)
		return m
	}
	sm.Overall = finish(sm.Overall)
	for k, v := range sm.ByClass {
		sm.ByClass[k] = finish(v)
	}
	for k, v := range sm.ByPrio {
		sm.ByPrio[k] = finish(v)
	}
	for k, v := range sm.ByEco {
		sm.ByEco[k] = finish(v)
	}
	for k, v := range sm.ByGrain {
		sm.ByGrain[k] = finish(v)
	}
	sm.ObservedBinaries, sm.ObservedFiles = len(binaries), len(files)
	sm.UnresolvedFactors = sortedFactorBreakdowns(unresolved)
	sm.UnobservedFactors = sortedFactorBreakdowns(unobserved)
	sm.NotDeterminedFactors = sortedFactorBreakdowns(notDetermined)
	return sm
}

// computeSeriesDeltas reports each layer's own increment.
//
// The event increment is only a number when the window collected usable
// events. Where it did not, it is reported as unavailable: saying zero
// would state that the events were collected and found nothing, when what
// happened is that the chance to find anything was never had.
func computeSeriesDeltas(packages []PackageVerdict, eventState string) []SeriesDelta {
	count := func(series string) (findings, pkgs int) {
		for _, pv := range packages {
			if v, _ := seriesOf(pv, series); v == VerdictConfirmed {
				findings += pv.FindingCount
				pkgs++
			}
		}
		return findings, pkgs
	}
	f0, p0 := count(seriesS0)
	f1, p1 := count(seriesS1)
	f2, p2 := count(seriesS2)

	out := []SeriesDelta{{From: seriesS0, To: seriesS1, Available: true, Findings: f1 - f0, Packages: p1 - p0}}
	switch eventState {
	case eventStateObserved, eventStateDegraded:
		out = append(out, SeriesDelta{From: seriesS1, To: seriesS2, Available: true, Findings: f2 - f1, Packages: p2 - p1})
	case eventStateFailed:
		out = append(out, SeriesDelta{From: seriesS1, To: seriesS2, Reason: "event collection produced nothing for this window, so what events would have added was never measured"})
	default:
		out = append(out, SeriesDelta{From: seriesS1, To: seriesS2, Reason: "this run collected no events, so what events would have added was never measured"})
	}
	return out
}

// buildMappingReport summarizes the two-stage mapping per ecosystem.
func buildMappingReport(idx *scanFileIndex, packages []PackageVerdict, ev *evidenceSet) MappingReport {
	rows := map[string]*MappingRow{}
	row := func(eco string) *MappingRow {
		r := rows[eco]
		if r == nil {
			r = &MappingRow{Ecosystem: eco, UnmappableBy: map[string]int{}}
			rows[eco] = r
		}
		return r
	}
	for _, f := range idx.files {
		row(f.Ecosystem).ScanReportFiles++
	}
	seenFiles := map[string]map[string]bool{}
	for _, pv := range packages {
		eco := pv.Ecosystem
		if eco == "" {
			eco = ecoOS
		}
		r := row(eco)
		switch {
		case pv.S2Verdict == VerdictConfirmed:
			r.Stage2Packages++
			if seenFiles[eco] == nil {
				seenFiles[eco] = map[string]bool{}
			}
			for _, f := range pv.EvidenceFiles {
				if !seenFiles[eco][f] {
					seenFiles[eco][f] = true
					r.Stage1Files++
					if pv.EvidenceGrain == grainBinary {
						r.ObservedBinary++
					} else {
						r.ObservedFile++
					}
				}
			}
		case pv.S2Factor == factorLangPkg:
			r.UnmappableBy["no_path_in_scan_report"]++
		case pv.S2Factor == factorMappingInputMissing:
			r.UnmappableBy["mapping_input_not_saved"]++
		case pv.S2Factor == factorEventPathUnresolved:
			r.UnmappableBy["event_path_unresolved"]++
		}
	}
	out := MappingReport{
		CandidateConflicts: ev.candidateConflict,
		UnresolvedPaths:    ev.unresolvedPaths,
		UnresolvedEvents:   ev.unresolvedEventPaths,
		UnmappablePaths:    ev.unmappablePaths,
		UnmappableEvents:   ev.unmappableEvents,
		OutsideScanPaths:   ev.outsideScanPaths,
		OutsideScanEvents:  ev.outsideScanEvents,
	}
	for _, r := range rows {
		out.Rows = append(out.Rows, *r)
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].Ecosystem < out.Rows[j].Ecosystem })
	return out
}

// computeSeriesGTB counts true and false positives and negatives for one
// series, so a confirmation the added evidence produced is checked against
// the ground truth the same way the first stage's own is.
//
// Without this, the added layers would be measured only by how much they
// raise the confirmation rate, and a layer that raises it by confirming
// packages the workload never used would look like the best one.
func computeSeriesGTB(series string, packages []PackageVerdict) GTBCounts {
	shadow := make([]PackageVerdict, 0, len(packages))
	for _, pv := range packages {
		v, _ := seriesOf(pv, series)
		pv.Verdict = v
		shadow = append(shadow, pv)
	}
	counts, _ := computeGTBCounts(shadow)
	return counts
}

// noteGapRecovery records, on a package whose first-stage shortfall was
// later closed, which evidence source closed it. The original shortfall
// class stays where it is: a shortfall that turns out to be recoverable is
// a fact about that class, and overwriting it would erase the finding.
func noteGapRecovery(pv *PackageVerdict, ev *evidenceSet) {
	if pv.Verdict == VerdictConfirmed || pv.S2Verdict != VerdictConfirmed {
		return
	}
	pv.GapRecoveredBy = ev.sourcesFor(pkgGroupKey{Class: classOf(pv.Class), Package: pv.Package, InstalledVer: pv.InstalledVer}, allowS2)
	if pv.GapClass != "" && pv.GapRecoverability == "candidate" {
		pv.GapRecoverability = "confirmed"
	}
	if pv.GapClass == "E4" {
		// A shortfall declared structurally unrecoverable that recovered
		// anyway is evidence the declaration was wrong, and is said so
		// rather than quietly reclassified.
		pv.EvidenceNotes = append(pv.EvidenceNotes,
			fmt.Sprintf("this package's shortfall was declared unrecoverable, and %v recovered it: the declaration was wrong", pv.GapRecoveredBy))
	}
}
