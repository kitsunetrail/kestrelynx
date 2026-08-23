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

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
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

// ImageFindings is one running entity's package groups within a single status
// section. The aggregation unit is (Image, ContentID) rather than Image alone:
// when the same reference runs more than one distinct, verified content at
// once, each content gets its own section entry instead of being merged
// silently. ContentID mirrors ExpectedContentID (the Docker-observed entity),
// so it is non-empty for the ordinary, single-resolved-entity case too —
// existing renderers only see it change shape when a reference is genuinely
// ambiguous. It is empty only when identity is unresolved (reference-fallback
// scans never had a Docker-observed ContentID to pin to).
type ImageFindings struct {
	Image     string
	ContentID string // ExpectedContentID (Docker-observed); empty only when unresolved
	Packages  []PackageGroup
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

// ImageObservation is the identity inventory for one scanned reference,
// covering every scan target this cycle — clean or not, resolved or not,
// failed or not. It is the single source state.Compute reads to update
// State.Images and to detect partial-failure references; unlike the status
// sections it does not depend on there being any findings.
//
// State persists a *sorted set* of content IDs per reference, not a single
// value, because an Ambiguous reference can run more than one verified
// entity at once. To give state.Compute that set without re-deriving it from
// the status sections, this inventory carries the set directly as
// ContentIDs; a single-entity reference simply has len(ContentIDs) <= 1.
type ImageObservation struct {
	Ref string

	// ContentIDs is the sorted set of boundary-validated ContentIDs (Docker's
	// ExpectedContentID) observed running under Ref this cycle. This is
	// Docker-observed data, independent of whether the Trivy scan itself
	// succeeded (chunk1, scanner/exec.go: ExpectedContentID/IdentityResolved
	// survive a scan failure) — a failed scan whose entity Docker still
	// resolved a ContentID for still contributes to this set. What never
	// contributes is a reference-fallback scan's ScannedContentID: that
	// describes whatever Trivy happened to resolve on its own, not a
	// specific running entity Docker told us about.
	ContentIDs []string
	// RegistryDigests is the sorted union of RegistryDigests across every
	// entity that both resolved a ContentID and scanned successfully under
	// Ref (Trivy's Metadata.RepoDigests isn't available otherwise).
	RegistryDigests []string
	// Ambiguous is true when more than one distinct verified ContentID is
	// running under Ref at once.
	Ambiguous bool
	// IdentityResolved is true when every entity running under Ref had a
	// Docker-observed ContentID this cycle (false if any entity used the
	// reference-fallback path). This is independent of scan success: it
	// reflects what Docker reported, not what Trivy managed to scan.
	IdentityResolved bool
	// ScanFailed is true when every entity running under Ref failed to scan
	// this cycle (the existing full-failure case: state carries findings over
	// untouched).
	ScanFailed bool
	// PartialFailure is true when some, but not all, entities running under
	// Ref failed to scan this cycle. This is a distinct case from ScanFailed —
	// state must not silently drop the failed entity's findings just because
	// a sibling entity under the same Ref succeeded.
	PartialFailure bool
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
	// Images is the per-reference identity inventory, covering every scanned
	// reference regardless of findings. Sorted by Ref.
	Images      []ImageObservation
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

// imgKey is the aggregation unit for findings: a running entity, identified
// by its display reference plus the ContentID the caller expected to be
// running there. ExpectedContentID is used rather than the scanned
// ContentID: for a reference-fallback scan ExpectedContentID is empty, which
// is exactly "unresolved" and must not be confused with a verified entity's
// content.
type imgKey struct {
	ref       string
	contentID string
}

// obsAcc accumulates one reference's identity inventory across every scan
// target observed under it this cycle: possibly several distinct entities
// when the reference is ambiguous, possibly a mix of successes and failures.
type obsAcc struct {
	total, failed   int
	contentIDs      map[string]bool
	registryDigests map[string]bool
	anyUnresolved   bool // some scan target under this ref had no ExpectedContentID (Docker-observed, tallied regardless of scan success/failure)
	seenEOSL        bool
}

// Build triages and aggregates scan results into a Report. tr supplies the
// exploitation intel and thresholds for priority assignment (zero value =
// triage off, Phase 1 behavior). now is injected for deterministic output.
func Build(scans []scanner.ImageScan, tr Triage, now time.Time) Report {
	r := Report{GeneratedAt: now, ImagesTotal: len(scans), Triage: tr.Enabled, Intel: tr.Intel}

	// status -> (ref, contentID) -> package -> accumulator
	byStatus := map[scanner.Status]map[imgKey]map[string]*pkgAcc{}
	obs := map[string]*obsAcc{} // by ref, the inventory backing Report.Images

	for _, s := range scans {
		a := obs[s.Image]
		if a == nil {
			a = &obsAcc{contentIDs: map[string]bool{}, registryDigests: map[string]bool{}}
			obs[s.Image] = a
		}
		a.total++

		// Identity (ExpectedContentID/IdentityResolved) is Docker-observed
		// data that survives a Trivy scan failure unchanged (chunk1,
		// scanner/exec.go): every error path still returns the
		// ExpectedContentID/IdentityResolved the caller asked Trivy to pin
		// to. So this must be recorded regardless of s.Err — only the
		// scan-derived RegistryDigests genuinely require a successful scan.
		if s.ExpectedContentID != "" {
			a.contentIDs[s.ExpectedContentID] = true
		} else {
			// Reference-fallback identity data describes whatever Trivy
			// happened to resolve, not a specific running entity, so it never
			// joins the verified set.
			a.anyUnresolved = true
		}

		if s.Err != nil {
			a.failed++
			r.ScanErrors = append(r.ScanErrors, ScanError{Image: s.Image, Err: s.Err.Error()})
			continue
		}
		if s.ExpectedContentID != "" {
			for _, d := range s.RegistryDigests {
				a.registryDigests[d] = true
			}
		}
		if s.OSEOSL && !a.seenEOSL {
			a.seenEOSL = true
			r.EOSLImages = append(r.EOSLImages, s.Image)
		}

		k := imgKey{ref: s.Image, contentID: s.ExpectedContentID}
		for _, find := range s.Findings {
			images := byStatus[find.Status]
			if images == nil {
				images = map[imgKey]map[string]*pkgAcc{}
				byStatus[find.Status] = images
			}
			pkgs := images[k]
			if pkgs == nil {
				pkgs = map[string]*pkgAcc{}
				images[k] = pkgs
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
	r.Images = buildInventory(obs)
	return r
}

// buildInventory finalizes the per-reference identity inventory that backs
// State.Images and the partial-failure rule: every scanned reference appears
// exactly once, independent of whether it produced any findings.
func buildInventory(obs map[string]*obsAcc) []ImageObservation {
	if len(obs) == 0 {
		return nil
	}
	out := make([]ImageObservation, 0, len(obs))
	for ref, a := range obs {
		var contentIDs []string
		for id := range a.contentIDs {
			contentIDs = append(contentIDs, id)
		}
		sort.Strings(contentIDs)
		var registryDigests []string
		for d := range a.registryDigests {
			registryDigests = append(registryDigests, d)
		}
		sort.Strings(registryDigests)

		out = append(out, ImageObservation{
			Ref:             ref,
			ContentIDs:      contentIDs,
			RegistryDigests: registryDigests,
			Ambiguous:       len(contentIDs) > 1,
			// Docker-observed, independent of scan success (see the
			// accumulation loop above) — a scan failure never demotes this.
			IdentityResolved: a.total > 0 && !a.anyUnresolved,
			ScanFailed:       a.total > 0 && a.failed == a.total,
			PartialFailure:   a.failed > 0 && a.failed < a.total,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// buildSection finalizes one status bucket into sorted ImageFindings.
func buildSection(images map[imgKey]map[string]*pkgAcc, tr Triage) []ImageFindings {
	if len(images) == 0 {
		return nil
	}
	out := make([]ImageFindings, 0, len(images))
	for k, pkgs := range images {
		groups := make([]PackageGroup, 0, len(pkgs))
		for _, acc := range pkgs {
			groups = append(groups, finalize(acc, tr))
		}
		sortPackages(groups)
		out = append(out, ImageFindings{Image: k.ref, ContentID: k.contentID, Packages: groups})
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

// sortImages orders images within a section by worst-first severity, then
// total count, then image name, then ContentID for stability (an Ambiguous
// reference can contribute more than one entry with the same Image).
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
		if f[i].Image != f[j].Image {
			return f[i].Image < f[j].Image
		}
		return f[i].ContentID < f[j].ContentID
	})
}
