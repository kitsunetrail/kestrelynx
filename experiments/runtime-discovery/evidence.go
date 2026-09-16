package main

import "time"

// buildEvidence renders match's usage/exposure/privilege judgements as the
// common Evidence record shape, alongside (not instead of) the richer
// PackageVerdict/MatchResult fields those judgements are drawn from.
//
// ObservedAt is the time the evidence was captured, never the time the
// match ran: a record re-matched a week later describes the same window it
// always did, and stamping it with the recomputation time would make the
// evidence look freshly observed.
func buildEvidence(packages []PackageVerdict, exposure ExposureVerdict, rec *ContainerRecord, wv windowValidity, windowID string) []Evidence {
	var out []Evidence
	sampleTimes := sampleStartTimes(rec)
	fallback := rec.Window.ScheduledStart

	for _, pv := range packages {
		sampleID := ""
		gen := ProcessGeneration{}
		source := "proc_maps"
		observedAt := fallback
		if pv.Verdict == VerdictConfirmed {
			if s, g, ok := findConfirmingGeneration(rec, wv, pv); ok {
				sampleID, gen = s, g
				if t, known := sampleTimes[s]; known {
					observedAt = t
				}
			}
		} else {
			// Nothing was observed for this package, so no sample is its
			// source: the judgement is about the window as a whole.
			source = "docker_api"
		}
		out = append(out, Evidence{
			Type: "usage", Verdict: string(pv.Verdict), Factor: pv.Factor,
			Target:            EvidenceTarget{Kind: "package", Class: pv.Class, Name: pv.Package, Version: pv.InstalledVer},
			Source:            source,
			SampleID:          sampleID,
			ProcessGeneration: gen,
			ObservedAt:        observedAt,
			WindowID:          windowID,
		})
	}

	exposureAt := fallback
	for _, l := range rec.Listeners {
		if t, known := sampleTimes[l.SampleID]; known {
			exposureAt = t
		}
	}
	out = append(out, Evidence{
		Type:       "exposure",
		Verdict:    exposure.Verdict,
		Target:     EvidenceTarget{Kind: "port"},
		Value:      map[string]any{"reasons": exposure.Reasons},
		Source:     "docker_api",
		ObservedAt: exposureAt,
		WindowID:   windowID,
	})

	for _, p := range rec.Processes {
		// A privilege record is only "confirmed" when /proc/<pid>/status
		// was actually read. A failed read leaves the effective UID and
		// capability set unknown, and reporting that as a confirmed
		// observation of an empty capability set would turn a permission
		// failure into a finding of no privilege.
		verdict := "confirmed"
		value := map[string]any{"effective_uid": p.EffectiveUID, "cap_eff": p.CapEff}
		if p.StatusError != "" {
			verdict = "unknown"
			value = map[string]any{"error": p.StatusError}
		}
		if p.Invalid {
			verdict = "unknown"
			value["invalid_reason"] = p.InvalidReason
		}
		observedAt := fallback
		if t, known := sampleTimes[p.SampleID]; known {
			observedAt = t
		}
		out = append(out, Evidence{
			Type:              "privilege",
			Verdict:           verdict,
			Target:            EvidenceTarget{Kind: "process", Name: itoa(p.Generation.PID)},
			Value:             value,
			Source:            "proc_status",
			SampleID:          p.SampleID,
			ProcessGeneration: p.Generation,
			ObservedAt:        observedAt,
			WindowID:          windowID,
		})
	}

	return out
}

// sampleStartTimes maps each sample's id to when that sample actually
// started, which is the observation time of everything it read.
func sampleStartTimes(rec *ContainerRecord) map[string]time.Time {
	out := make(map[string]time.Time, len(rec.Window.Samples))
	for _, s := range rec.Window.Samples {
		out[s.SampleID] = s.ActualStart
	}
	return out
}

// findConfirmingGeneration returns the (sample, process generation) of the
// first path resolution that actually confirmed this package — the same
// evidence assignVerdict used to reach VerdictConfirmed, under the same
// predicate and the same restriction to valid samples, so the Evidence
// record never cites a path the verdict itself did not accept.
func findConfirmingGeneration(rec *ContainerRecord, wv windowValidity, pv PackageVerdict) (sampleID string, gen ProcessGeneration, ok bool) {
	key := pkgGroupKey{Class: classOf(pv.Class), Package: pv.Package, InstalledVer: pv.InstalledVer}
	for _, pr := range rec.PathResolution {
		if !wv.ValidSampleIDs[pr.SampleID] || !samplingReadKinds(pr) {
			continue
		}
		if ownedPathConfirms(pr, key) {
			return pr.SampleID, pr.Generation, true
		}
	}
	return "", ProcessGeneration{}, false
}
