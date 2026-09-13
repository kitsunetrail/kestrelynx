package main

import (
	"sort"
	"strconv"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// dangerousCapBits are the fixed 8 dangerous capabilities: CAP_SYS_ADMIN,
// CAP_SYS_PTRACE, CAP_SYS_MODULE, CAP_NET_ADMIN, CAP_DAC_READ_SEARCH,
// CAP_DAC_OVERRIDE, CAP_SETUID, CAP_SETGID (Linux capability bit numbers,
// man 7 capabilities).
var dangerousCapBits = []uint{21, 19, 16, 12, 2, 1, 7, 6}

func hasDangerousCapability(capEffHex string) bool {
	v, err := strconv.ParseUint(capEffHex, 16, 64)
	if err != nil {
		return false
	}
	for _, bit := range dangerousCapBits {
		if v&(1<<bit) != 0 {
			return true
		}
	}
	return false
}

// findingRow is one Finding as G4 ranks it. Its identity is the full
// Finding key — class, package, installed version, vulnerability ID — not
// the package name, so two Findings that merely share a name are ranked as
// the separate Findings they are.
type findingRow struct {
	Class     string
	Package   string
	Version   string
	VulnID    string
	Severity  string
	Priority  string
	Confirmed bool
	Exposure  string
	HighPriv  bool
}

func (r findingRow) key() string {
	return r.Class + "\x00" + r.Package + "\x00" + r.Version + "\x00" + r.VulnID
}

var priorityRank = map[string]int{"act_now": 3, "watch": 2, "low": 1, "": 0}
var severityRank = map[string]int{"CRITICAL": 2, "HIGH": 1}
var exposureRank = map[string]int{"host_published_all": 4, "host_published_loopback": 3, "container_listening": 2, "unknown": 1}

// buildFindingRows assembles the ranking input for one priority bucket,
// attaching each Finding's own joined evidence rather than evidence shared
// by package name.
func buildFindingRows(groups []pkgGroup, findings []scanner.Finding, priorityByIndex []string, evidence map[pkgGroupKey]packageEvidence, wantPriority string) []findingRow {
	var out []findingRow
	for _, g := range groups {
		ev := evidence[g.key]
		for _, v := range g.vulns {
			prio := ""
			if v.OriginalIndex < len(priorityByIndex) {
				prio = priorityByIndex[v.OriginalIndex]
			}
			if prio != wantPriority {
				continue
			}
			sev := ""
			if v.OriginalIndex < len(findings) {
				sev = string(findings[v.OriginalIndex].Severity)
			}
			out = append(out, findingRow{
				Class: string(g.key.Class), Package: g.key.Package, Version: g.key.InstalledVer,
				VulnID: v.VulnID, Severity: sev, Priority: prio,
				Confirmed: ev.Confirmed, Exposure: ev.Exposure, HighPriv: ev.HighPrivilege,
			})
		}
	}
	return out
}

// baselineLess is the experimental baseline order: priority desc (all rows
// here already share one priority, so this only matters if reused wider),
// severity desc, package asc, VulnID asc. Class and version break a tie
// between two rows the four declared keys cannot separate, so the order is
// total rather than dependent on input order.
func baselineLess(rows []findingRow) func(i, j int) bool {
	return func(i, j int) bool {
		a, b := rows[i], rows[j]
		if priorityRank[a.Priority] != priorityRank[b.Priority] {
			return priorityRank[a.Priority] > priorityRank[b.Priority]
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.VulnID != b.VulnID {
			return a.VulnID < b.VulnID
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Version < b.Version
	}
}

// adjustedLess is the additional-judgement order: confirmed desc, exposure
// stage desc, high-privilege desc, then the baseline keys. Each row now
// carries its own exposure — the stage observed on the same process
// generation and sample that confirmed that row's package — so the key
// genuinely discriminates instead of being a single container-wide value
// repeated on every row.
func adjustedLess(rows []findingRow) func(i, j int) bool {
	base := baselineLess(rows)
	return func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Confirmed != b.Confirmed {
			return a.Confirmed // true (confirmed) sorts first
		}
		if exposureRank[a.Exposure] != exposureRank[b.Exposure] {
			return exposureRank[a.Exposure] > exposureRank[b.Exposure]
		}
		if a.HighPriv != b.HighPriv {
			return a.HighPriv
		}
		return base(i, j)
	}
}

// computeG4 builds the baseline vs. adjusted ranking comparison for one
// priority bucket, over evidence that was already restricted to what a
// single process generation in a single sample established.
func computeG4(priority string, groups []pkgGroup, findings []scanner.Finding, priorityByIndex []string, evidence map[pkgGroupKey]packageEvidence) G4Result {
	rows := buildFindingRows(groups, findings, priorityByIndex, evidence, priority)
	res := G4Result{Priority: priority, TotalFindings: len(rows)}
	if len(rows) == 0 {
		res.NA = true
		return res
	}

	baseline := append([]findingRow(nil), rows...)
	sort.SliceStable(baseline, baselineLess(baseline))
	baselineRank := map[string]int{}
	for i, r := range baseline {
		baselineRank[r.key()] = i
	}

	adjusted := append([]findingRow(nil), rows...)
	sort.SliceStable(adjusted, adjustedLess(adjusted))

	limit := len(adjusted)
	if limit > 20 {
		limit = 20
	}
	rankChanged := 0
	labeled := 0
	var exampleLabeled, exampleNotLabeled string
	for i, r := range adjusted {
		bRank := baselineRank[r.key()]
		changed := i < limit && bRank != i
		if changed {
			rankChanged++
		}
		isLabeled := r.Confirmed && r.Exposure == "host_published_all" && r.HighPriv
		if isLabeled {
			labeled++
			if exampleLabeled == "" {
				exampleLabeled = describeFinding(r)
			}
		} else if exampleNotLabeled == "" {
			exampleNotLabeled = describeFinding(r)
		}
		if i < limit {
			res.Top20 = append(res.Top20, RankedFinding{
				Package: r.Package, Class: r.Class, Version: r.Version, VulnID: r.VulnID,
				BaselineRank: bRank, AdjustedRank: i,
				RankChanged: changed, Confirmed: r.Confirmed, Exposure: r.Exposure, HighPrivilege: r.HighPriv, Labeled: isLabeled,
			})
		}
	}
	res.RankChangedCount = rankChanged
	res.LabeledCount = labeled
	res.ExampleLabeled = exampleLabeled
	res.ExampleNotLabeled = exampleNotLabeled
	return res
}

func describeFinding(r findingRow) string {
	status := "not confirmed in use"
	if r.Confirmed {
		status = "confirmed in use"
	}
	priv := "no elevated privilege observed on a confirming process"
	if r.HighPriv {
		priv = "a dangerous capability or UID 0 was observed on the confirming process"
	}
	exposure := r.Exposure
	if exposure == "" {
		exposure = "unknown"
	}
	return r.Package + " " + r.Version + " (" + r.Class + ", " + r.VulnID + "): " + status + ", exposure=" + exposure + ", " + priv
}

// packageEvidence is the three G4 axes for one Finding group, each of them
// established by the same process generation in the same sample.
type packageEvidence struct {
	Confirmed     bool
	Exposure      string
	HighPrivilege bool
}

// joinPackageEvidence combines usage, exposure and privilege for each
// Finding group under the rule that evidence may only be combined when it
// was observed on the same process generation in the same sample. A
// package confirmed by a mapping in one worker process is not made
// "exposed and privileged" by a different process publishing a port or
// running as root: each axis is evaluated on the generations that actually
// confirmed the package, and an axis with no such observation stays
// unknown.
func joinPackageEvidence(rec *ContainerRecord, groups []pkgGroup, wv windowValidity) map[pkgGroupKey]packageEvidence {
	type sampleGen struct {
		sampleID  string
		pid       int
		starttime string
	}

	// Privilege, per (sample, process generation) that could actually be read.
	highProc := map[sampleGen]bool{}
	for _, p := range rec.Processes {
		if !wv.ValidSampleIDs[p.SampleID] || p.Invalid || p.StatusError != "" {
			continue
		}
		if p.EffectiveUID == "0" || hasDangerousCapability(p.CapEff) {
			highProc[sampleGen{p.SampleID, p.Generation.PID, p.Generation.Starttime}] = true
		}
	}

	// Exposure, per (sample, process generation) that owns a listener.
	listenersByGen := map[sampleGen][]Listener{}
	for _, l := range rec.Listeners {
		if !wv.ValidSampleIDs[l.SampleID] {
			continue
		}
		for _, g := range listenerGenerations(l) {
			key := sampleGen{l.SampleID, g.PID, g.Starttime}
			listenersByGen[key] = append(listenersByGen[key], l)
		}
	}

	out := map[pkgGroupKey]packageEvidence{}
	for _, g := range groups {
		ev := packageEvidence{Exposure: "unknown"}
		// The three axes are chosen together, as one confirming
		// observation's own exposure and privilege — never maximized one at
		// a time. A package confirmed in two processes, one of them
		// privileged and the other one published, must not come out
		// "published and privileged": no single process was both, and that
		// label is the whole point of the additional rule. Among the
		// observations that did confirm the package, the strongest single
		// one wins, ranked by exposure first and privilege second.
		bestRank := -1
		for _, pr := range rec.PathResolution {
			if !wv.ValidSampleIDs[pr.SampleID] || !ownedPathConfirms(pr, g.key) {
				continue
			}
			ev.Confirmed = true
			key := sampleGen{pr.SampleID, pr.Generation.PID, pr.Generation.Starttime}

			candidate := packageEvidence{Confirmed: true, Exposure: "unknown", HighPrivilege: highProc[key]}
			if ls := listenersByGen[key]; len(ls) > 0 {
				candidate.Exposure = exposureFromListeners(rec, ls).Verdict
			}
			rank := exposureRank[candidate.Exposure] * 2
			if candidate.HighPrivilege {
				rank++
			}
			if rank > bestRank {
				bestRank = rank
				ev = candidate
			}
		}
		out[g.key] = ev
	}
	return out
}

// listenerGenerations returns every process generation a listening socket
// was attributed to, falling back to the single primary attribution for a
// record written before multiple owners were retained.
func listenerGenerations(l Listener) []ProcessGeneration {
	if len(l.Generations) > 0 {
		return l.Generations
	}
	if l.Generation.PID != 0 {
		return []ProcessGeneration{l.Generation}
	}
	return nil
}
