// Package analyze turns raw scanner findings into a triaged, aggregated Report:
// it splits vulnerabilities by Trivy Status, groups them per image+package,
// judges update risk (semver for language packages only), and surfaces
// end-of-life base images. This is the differentiation core (docs/PROJECT_CONTEXT.md):
// the post-processing that makes raw scanner output actionable.
package analyze

import (
	"sort"
	"strconv"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/scanner"
)

// Risk is the update-risk hint attached to a fixable package.
type Risk string

const (
	RiskNone         Risk = ""              // not applicable (no fix available)
	RiskDistroUpdate Risk = "distro_update" // OS package: distro security revision, not semver
	RiskSafe         Risk = "safe"          // lang package: patch/minor bump
	RiskCaution      Risk = "caution"       // lang package: major bump (possible breaking change)
	RiskUnknown      Risk = "unknown"       // lang package: version not parseable
)

// PackageGroup aggregates all selected vulnerabilities of one package within
// one image (docs/TRIVY_OUTPUT.md §6: a single package often carries many CVEs).
type PackageGroup struct {
	Package      string
	Class        scanner.PkgClass
	InstalledVer string
	FixedVer     string
	Status       scanner.Status
	Risk         Risk
	Critical     int       // count of distinct CRITICAL CVEs
	High         int       // count of distinct HIGH CVEs
	Vulns        []VulnRef // deduplicated, strongest verdict first (sortVulns)
	Priority     Priority  // max of Vulns' priorities; PriorityNone when triage is off
	URL          string    // representative reference
}

// Total is the number of distinct vulnerabilities in the group.
func (g PackageGroup) Total() int { return g.Critical + g.High }

// VulnIDs returns the group's vulnerability IDs, sorted.
func (g PackageGroup) VulnIDs() []string {
	ids := make([]string, 0, len(g.Vulns))
	for _, v := range g.Vulns {
		ids = append(ids, v.ID)
	}
	sort.Strings(ids)
	return ids
}

// TopVuln is the vulnerability whose verdict headlines the group (the evidence
// shown for an act_now item). Zero value when the group is empty.
func (g PackageGroup) TopVuln() VulnRef {
	if len(g.Vulns) == 0 {
		return VulnRef{}
	}
	return g.Vulns[0]
}

// ImageFindings is one image's package groups within a single status section.
type ImageFindings struct {
	Image    string
	Packages []PackageGroup
}

// CriticalCount sums CRITICAL CVEs across the image's packages.
func (f ImageFindings) CriticalCount() int {
	n := 0
	for _, g := range f.Packages {
		n += g.Critical
	}
	return n
}

// TotalCount sums all CVEs across the image's packages.
func (f ImageFindings) TotalCount() int {
	n := 0
	for _, g := range f.Packages {
		n += g.Total()
	}
	return n
}

// ScanError records an image whose scan failed, so it is surfaced rather than
// silently dropped.
type ScanError struct {
	Image string
	Err   string
}

// Report is the triaged output, ready for the notify layer. Sections are
// ordered by priority via their position (docs/NOTIFICATION_SPEC.md §2):
// EOSL first, then actionable (fixed), watch (affected), wont-fix.
type Report struct {
	ImagesTotal int             // unique images scanned this run (incl. failures)
	EOSLImages  []string        // base OS end-of-life: highest priority
	Actionable  []ImageFindings // Status == fixed
	Watch       []ImageFindings // Status == affected (upstream not yet fixed)
	WontFix     []ImageFindings // Status == will_not_fix
	ScanErrors  []ScanError
	Triage      bool        // priorities were assigned (renderers use ByPriority)
	Intel       IntelStatus // freshness of the intel behind the priorities
	GeneratedAt time.Time
}

// AffectedImageCount is the number of distinct images with any issue (findings
// or EOLL). Scan failures are not counted as "affected".
func (r Report) AffectedImageCount() int {
	seen := map[string]bool{}
	for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix} {
		for _, img := range section {
			seen[img.Image] = true
		}
	}
	for _, im := range r.EOSLImages {
		seen[im] = true
	}
	return len(seen)
}

// HasFindings reports whether any vulnerability or EOSL image is present.
func (r Report) HasFindings() bool {
	return len(r.Actionable) > 0 || len(r.Watch) > 0 || len(r.WontFix) > 0 || len(r.EOSLImages) > 0
}

// HasIssues reports whether anything worth a notification exists, including
// scan failures.
func (r Report) HasIssues() bool {
	return r.HasFindings() || len(r.ScanErrors) > 0
}

// vulnInfo is the per-CVE data captured from the scanner during accumulation.
type vulnInfo struct {
	sev   scanner.Severity
	url   string
	title string
}

// pkgAcc accumulates a package group while deduplicating CVEs by ID.
type pkgAcc struct {
	group PackageGroup
	vulns map[string]vulnInfo
}

// Build triages and aggregates scan results into a Report. tr supplies the
// exploitation intel and thresholds for priority assignment (zero value =
// triage off, Phase 1 behavior). now is injected for deterministic output.
func Build(scans []scanner.ImageScan, tr Triage, now time.Time) Report {
	r := Report{GeneratedAt: now, ImagesTotal: len(scans), Triage: tr.Enabled, Intel: tr.Intel}

	// status -> image -> package -> accumulator
	byStatus := map[scanner.Status]map[string]map[string]*pkgAcc{}

	for _, s := range scans {
		if s.Err != nil {
			r.ScanErrors = append(r.ScanErrors, ScanError{Image: s.Image, Err: s.Err.Error()})
			continue
		}
		if s.OSEOSL {
			r.EOSLImages = append(r.EOSLImages, s.Image)
		}
		for _, find := range s.Findings {
			images := byStatus[find.Status]
			if images == nil {
				images = map[string]map[string]*pkgAcc{}
				byStatus[find.Status] = images
			}
			pkgs := images[s.Image]
			if pkgs == nil {
				pkgs = map[string]*pkgAcc{}
				images[s.Image] = pkgs
			}
			acc := pkgs[find.Package]
			if acc == nil {
				acc = &pkgAcc{
					group: PackageGroup{
						Package:      find.Package,
						Class:        find.Class,
						InstalledVer: find.InstalledVer,
						FixedVer:     find.FixedVer,
						Status:       find.Status,
						URL:          find.URL,
					},
					vulns: map[string]vulnInfo{},
				}
				pkgs[find.Package] = acc
			}
			// The same CVE ID can appear on more than one Trivy result line (e.g.
			// matched via more than one data source); prefer whichever line carries
			// a non-empty Title rather than letting a later, title-less line blank it.
			title := find.Title
			if title == "" {
				title = acc.vulns[find.VulnID].title
			}
			acc.vulns[find.VulnID] = vulnInfo{sev: find.Severity, url: find.URL, title: title}
		}
	}

	sort.Strings(r.EOSLImages)
	r.Actionable = buildSection(byStatus[scanner.StatusFixed], tr)
	r.Watch = buildSection(byStatus[scanner.StatusAffected], tr)
	r.WontFix = buildSection(byStatus[scanner.StatusWontFix], tr)
	return r
}

// buildSection finalizes one status bucket into sorted ImageFindings.
func buildSection(images map[string]map[string]*pkgAcc, tr Triage) []ImageFindings {
	if len(images) == 0 {
		return nil
	}
	out := make([]ImageFindings, 0, len(images))
	for image, pkgs := range images {
		groups := make([]PackageGroup, 0, len(pkgs))
		for _, acc := range pkgs {
			groups = append(groups, finalize(acc, tr))
		}
		sortPackages(groups)
		out = append(out, ImageFindings{Image: image, Packages: groups})
	}
	sortImages(out)
	return out
}

// finalize computes counts, per-vulnerability triage verdicts, the group's
// aggregate priority (max over its CVEs), and the risk label.
func finalize(acc *pkgAcc, tr Triage) PackageGroup {
	g := acc.group
	for id, info := range acc.vulns {
		if info.sev == scanner.SeverityCritical {
			g.Critical++
		} else {
			g.High++
		}
		e := tr.Enrich[id]
		v := VulnRef{
			ID:         id,
			Severity:   info.sev,
			URL:        info.url,
			Title:      info.title,
			KEV:        e.KEV,
			Ransomware: e.Ransomware,
			EPSS:       e.EPSS,
			EPSSKnown:  e.EPSSKnown,
			Priority:   tr.priorityOf(info.sev, e, g.Status),
			Refs:       buildRefs(e, tr.Refs[id]),
		}
		g.Vulns = append(g.Vulns, v)
		if v.Priority.Rank() > g.Priority.Rank() {
			g.Priority = v.Priority
		}
	}
	sortVulns(g.Vulns)
	g.Risk = riskOf(g)
	return g
}

// riskOf judges update risk. Semver is applied only to language packages;
// OS package versions are distro-format and not semver (docs/ARCHITECTURE.md ADR-005).
func riskOf(g PackageGroup) Risk {
	if g.Status != scanner.StatusFixed {
		return RiskNone
	}
	if g.Class == scanner.ClassOS {
		return RiskDistroUpdate
	}
	return langRisk(g.InstalledVer, g.FixedVer)
}

// langRisk compares major versions of a language package. A higher fixed major
// means a possible breaking change (caution); same-or-lower major is treated as
// safe (patch/minor). Unparseable versions yield unknown rather than a guess.
func langRisk(installed, fixed string) Risk {
	im, ok1 := majorVersion(installed)
	fm, ok2 := majorVersion(fixed)
	if !ok1 || !ok2 {
		return RiskUnknown
	}
	if fm > im {
		return RiskCaution
	}
	return RiskSafe
}

// majorVersion extracts the leading integer (the semver major) from a version
// string, tolerating an optional leading "v". Returns false if absent.
func majorVersion(v string) (int, bool) {
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(v[:i])
	if err != nil {
		return 0, false
	}
	return n, true
}

// sortPackages orders packages within an image: CRITICAL-bearing first, then by
// total count desc, then package name for stability.
func sortPackages(g []PackageGroup) {
	sort.Slice(g, func(i, j int) bool {
		ci, cj := g[i].Critical > 0, g[j].Critical > 0
		if ci != cj {
			return ci
		}
		if g[i].Total() != g[j].Total() {
			return g[i].Total() > g[j].Total()
		}
		return g[i].Package < g[j].Package
	})
}

// sortImages orders images within a section by worst-first severity, then total
// count, then image name for stability.
func sortImages(f []ImageFindings) {
	sort.Slice(f, func(i, j int) bool {
		ci, cj := f[i].CriticalCount(), f[j].CriticalCount()
		if ci != cj {
			return ci > cj
		}
		ti, tj := f[i].TotalCount(), f[j].TotalCount()
		if ti != tj {
			return ti > tj
		}
		return f[i].Image < f[j].Image
	})
}
