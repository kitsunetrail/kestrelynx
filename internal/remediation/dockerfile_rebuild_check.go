package remediation

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// RebuildCheckStatus says how far comparing a running image with the current
// base got.
type RebuildCheckStatus string

const (
	// RebuildChecked: every finding of the running image was judged.
	RebuildChecked RebuildCheckStatus = "checked"
	// RebuildPartial: the images were compared, but some findings could not
	// be matched to a place in the base.
	RebuildPartial RebuildCheckStatus = "partial"
	// RebuildNotChecked: the images were not compared.
	RebuildNotChecked RebuildCheckStatus = "not_checked"
)

// RebuildCheck is what comparing a running image with the base its tag points
// at now shows. It reads the two scans; no image is built, so it says what the
// current base holds and not what the instructions after the FROM make of it.
type RebuildCheck struct {
	Status RebuildCheckStatus `json:"status"`
	// Reason and Detail say why the images were not compared.
	Reason Reason `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`

	// Gone are the running image's findings the current base does not have
	// although it has the package in the same place, and Remaining those it
	// still has. A package whose findings differ is in both.
	Gone      []RebuildPackage `json:"gone,omitempty"`
	Remaining []RebuildPackage `json:"remaining,omitempty"`
	// NotInBase are the OS packages and the packages of a global node_modules
	// the current base does not have in that place: the base dropped them or
	// the build added them, which the scans cannot tell apart.
	NotInBase []RebuildPackage `json:"not_in_base,omitempty"`
	// OtherNotInBase counts the other packages the current base does not
	// have, which are mostly the application's own dependencies.
	OtherNotInBase int `json:"other_not_in_base,omitempty"`
	// OnlyInBase are the fixed findings of the current base that the running
	// image does not have in that place.
	OnlyInBase []RebuildPackage `json:"only_in_base,omitempty"`
	// Undetermined counts the findings that could not be matched to a place
	// in the base.
	Undetermined int `json:"undetermined,omitempty"`

	// RunningScan and BaseScan are IDs into Plan.Scans.
	RunningScan string `json:"running_scan,omitempty"`
	BaseScan    string `json:"base_scan,omitempty"`

	// unsettled are the findings that are not listed because they are only
	// counted: other packages not in the base and undetermined ones. Taking
	// the running images together needs them to tell whether a finding is
	// gone from all of them.
	unsettled []RebuildPackage
}

// RebuildPackage is one package version in one place, with its findings of one
// outcome.
type RebuildPackage struct {
	Name    string             `json:"name"`
	Version string             `json:"version"`
	Class   inventory.PkgClass `json:"class"`
	Path    string             `json:"path,omitempty"`
	// Owner is the package of a global node_modules this one is found under:
	// npm for usr/local/lib/node_modules/npm/node_modules/undici/package.json.
	Owner string `json:"owner,omitempty"`
	// BaseVersion is the version in the current base, set on Gone packages.
	BaseVersion string   `json:"base_version,omitempty"`
	VulnIDs     []string `json:"vuln_ids"`
}

// HasGone reports whether the check names a finding the current base does not
// have.
func (c *RebuildCheck) HasGone() bool { return c != nil && len(c.Gone) > 0 }

// rebuildPlace identifies where a package is across two versions of a base.
type rebuildPlace struct {
	typ   string
	class inventory.PkgClass
	name  string
	place string
}

// versionedElement replaces the package's own version in one element of a
// path, when it follows "-" and ends there or continues with "." or "-". It is
// the last such part: the name before it may hold the same digits.
func versionedElement(elem, version string) string {
	needle := "-" + version
	for to := len(elem); ; {
		i := strings.LastIndex(elem[:to], needle)
		if i < 0 {
			return elem
		}
		end := i + len(needle)
		if end == len(elem) || elem[end] == '.' || elem[end] == '-' {
			return elem[:i] + "-*" + elem[end:]
		}
		to = end - 1
	}
}

// versionlessPath writes the path of a package without its own version, so the
// same place compares equal when the base moved to another version. Only the
// parts known to hold it change: a Python metadata directory and the file name
// of a Java archive. A version in a parent directory belongs to something else.
func versionlessPath(typ, version, path string) string {
	if version == "" {
		return path
	}
	elems := strings.Split(path, "/")
	switch typ {
	case typePythonPkg:
		for i, e := range elems {
			if strings.HasSuffix(e, ".dist-info") || strings.HasSuffix(e, ".egg-info") {
				elems[i] = versionedElement(e, version)
			}
		}
	case typeJar:
		last := len(elems) - 1
		if strings.HasSuffix(elems[last], "-"+version+".jar") {
			elems[last] = versionedElement(elems[last], version)
		}
	}
	return strings.Join(elems, "/")
}

// placeOf gives the place of a package. An OS package has one by its name
// alone. A language package needs a path: an empty one or a Target that is only
// a label ("Python", "Node.js") names no place, and two of them must not compare
// equal.
func placeOf(typ string, class inventory.PkgClass, name, version, pkgPath, target string) (rebuildPlace, bool) {
	p := rebuildPlace{typ: typ, class: class, name: name}
	if class == inventory.ClassOS {
		return p, true
	}
	switch {
	case pkgPath != "":
		p.place = versionlessPath(typ, version, pkgPath)
	case typ != typeNodePkg && typ != typePythonPkg && typ != typeJar && strings.Contains(target, "/"):
		p.place = target
	default:
		return p, false
	}
	return p, true
}

// pathsKnown reports whether the paths of a type are known well enough that a
// package missing from its place is not in the base. Of other types a package
// of the same name elsewhere may be the same one moved.
func pathsKnown(typ string, class inventory.PkgClass) bool {
	return class == inventory.ClassOS || typ == typeNodePkg || typ == typePythonPkg || typ == typeJar
}

type rebuildPackageKey struct {
	class         inventory.PkgClass
	name, version string
	path          string
	baseVersion   string
}

// rebuildBucket gathers findings by package version and place.
type rebuildBucket map[rebuildPackageKey]*RebuildPackage

func (b rebuildBucket) add(pkg RebuildPackage, vulns ...string) {
	k := rebuildPackageKey{pkg.Class, pkg.Name, pkg.Version, pkg.Path, pkg.BaseVersion}
	e := b[k]
	if e == nil {
		cp := pkg
		cp.VulnIDs = nil
		e = &cp
		b[k] = e
	}
	for _, v := range vulns {
		if !containsString(e.VulnIDs, v) {
			e.VulnIDs = append(e.VulnIDs, v)
		}
	}
}

func (b rebuildBucket) list() []RebuildPackage {
	if len(b) == 0 {
		return nil
	}
	out := make([]RebuildPackage, 0, len(b))
	for _, e := range b {
		sort.Strings(e.VulnIDs)
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, c := out[i], out[j]
		if a.Name != c.Name {
			return a.Name < c.Name
		}
		if a.Version != c.Version {
			return a.Version < c.Version
		}
		if a.Path != c.Path {
			return a.Path < c.Path
		}
		return a.BaseVersion < c.BaseVersion
	})
	return out
}

func rebuildPackageOf(f scanner.Finding) RebuildPackage {
	p := RebuildPackage{Name: f.Package, Version: f.InstalledVer, Class: f.Class}
	if f.Class == inventory.ClassOS {
		return p
	}
	p.Path = f.PkgPath
	if p.Path == "" {
		p.Path = f.Target
	}
	if f.Type == typeNodePkg {
		if owner, ok := GlobalNodeModule(f.PkgPath); ok {
			p.Owner = owner
		}
	}
	return p
}

// fixedFinding reports whether a finding names a version that fixes it, as the
// targets of a plan do.
func fixedFinding(f scanner.Finding) bool {
	return f.Status == scanner.StatusFixed && f.FixedVer != ""
}

// classifyRebuild compares the findings of the running image with those of the
// current base, place by place. The whole base counts when asking whether a
// finding remains, also what it reports without a fix; a finding of the running
// image counts only when it names a fix. Language runtimes are left to the
// runtimes given, which were checked from the base's configuration.
func classifyRebuild(running, base scanner.ImageScan, severities []string, runtimes []RuntimeRebuild) *RebuildCheck {
	rng := map[string]bool{}
	for _, s := range severities {
		rng[strings.ToUpper(s)] = true
	}
	inRange := func(f scanner.Finding) bool {
		return rng[strings.ToUpper(string(f.Severity))]
	}
	type vulnPlace struct {
		vuln  string
		place rebuildPlace
	}
	type nameKey struct {
		typ   string
		class inventory.PkgClass
		name  string
	}
	findingPlace := func(f scanner.Finding) (rebuildPlace, bool) {
		return placeOf(f.Type, f.Class, f.Package, f.InstalledVer, f.PkgPath, f.Target)
	}

	inBase := map[vulnPlace]bool{}
	for _, f := range base.Findings {
		if !inRange(f) || isRuntimeType(f.Type) {
			continue
		}
		if p, ok := findingPlace(f); ok {
			inBase[vulnPlace{f.VulnID, p}] = true
		}
	}
	baseVersions := map[rebuildPlace][]string{}
	baseNames := map[nameKey]bool{}
	for _, rp := range base.Packages {
		if isRuntimeType(rp.Type) {
			continue
		}
		for _, pk := range rp.Packages {
			baseNames[nameKey{rp.Type, rp.Class, pk.Name}] = true
			if p, ok := placeOf(rp.Type, rp.Class, pk.Name, pk.Version, pk.PkgPath, rp.Target); ok && !containsString(baseVersions[p], pk.Version) {
				baseVersions[p] = append(baseVersions[p], pk.Version)
			}
		}
	}

	// A runtime finding is judged when the runtime's own check names it, for
	// the version it was found at: a rescan may report what that check did not.
	judged := map[string]bool{}
	for _, rr := range runtimes {
		for _, vulns := range [][]string{rr.Disappearing, rr.Remaining} {
			for _, v := range vulns {
				judged[rr.Package+"\x00"+rr.Installed+"\x00"+v] = true
			}
		}
	}
	gone, remaining, notInBase, onlyInBase, unsettled := rebuildBucket{}, rebuildBucket{}, rebuildBucket{}, rebuildBucket{}, rebuildBucket{}
	other := map[rebuildPackageKey]bool{}
	undetermined := map[string]bool{}
	runningAt := map[vulnPlace]bool{}
	for _, f := range running.Findings {
		if !inRange(f) {
			continue
		}
		if isRuntimeType(f.Type) {
			if fixedFinding(f) && !judged[f.Package+"\x00"+f.InstalledVer+"\x00"+f.VulnID] {
				undetermined[f.VulnID+"\x00"+f.Package] = true
			}
			continue
		}
		place, ok := findingPlace(f)
		if ok {
			runningAt[vulnPlace{f.VulnID, place}] = true
		}
		if !fixedFinding(f) {
			continue
		}
		pkg := rebuildPackageOf(f)
		unjudged := func() {
			undetermined[f.VulnID+"\x00"+f.Package+"\x00"+f.InstalledVer+"\x00"+f.PkgPath] = true
			unsettled.add(pkg, f.VulnID)
		}
		versions := baseVersions[place]
		switch {
		case !ok, f.Class == inventory.ClassOS && base.OSFamily == "":
			unjudged()
		case len(versions) > 1:
			// The place does not name one package of the base.
			unjudged()
		case inBase[vulnPlace{f.VulnID, place}]:
			remaining.add(pkg, f.VulnID)
		case len(versions) == 1 && versions[0] == f.InstalledVer:
			// The same version without the finding says nothing about a fix.
			unjudged()
		case len(versions) == 1:
			pkg.BaseVersion = versions[0]
			gone.add(pkg, f.VulnID)
		case !pathsKnown(f.Type, f.Class) && baseNames[nameKey{f.Type, f.Class, f.Package}]:
			unjudged()
		case f.Class == inventory.ClassOS || pkg.Owner != "":
			notInBase.add(pkg, f.VulnID)
		default:
			other[rebuildPackageKey{pkg.Class, pkg.Name, pkg.Version, pkg.Path, ""}] = true
			unsettled.add(pkg, f.VulnID)
		}
	}
	for _, f := range base.Findings {
		if !inRange(f) || isRuntimeType(f.Type) || !fixedFinding(f) {
			continue
		}
		if p, ok := findingPlace(f); ok && !runningAt[vulnPlace{f.VulnID, p}] {
			onlyInBase.add(rebuildPackageOf(f), f.VulnID)
		}
	}

	c := &RebuildCheck{
		Status: RebuildChecked, Gone: gone.list(), Remaining: remaining.list(), NotInBase: notInBase.list(),
		OtherNotInBase: len(other), OnlyInBase: onlyInBase.list(), Undetermined: len(undetermined), unsettled: unsettled.list(),
	}
	if c.Undetermined > 0 {
		c.Status = RebuildPartial
	}
	return c
}

// mergeRebuildChecks gives the check of an item from those of its running
// images: an image not compared makes the item not compared, and a finding
// counts as gone only when every image that has it shows it gone. The versions
// the base moved to may differ between platforms, and each is kept.
func mergeRebuildChecks(ents []DockerfileEntity) *RebuildCheck {
	out := &RebuildCheck{Status: RebuildChecked}
	gone, remaining, notInBase, onlyInBase := rebuildBucket{}, rebuildBucket{}, rebuildBucket{}, rebuildBucket{}
	// held are the findings some image does not show gone.
	held := map[rebuildPackageKey]map[string]bool{}
	hold := func(ps []RebuildPackage) {
		for _, p := range ps {
			k := rebuildPackageKey{p.Class, p.Name, p.Version, p.Path, ""}
			if held[k] == nil {
				held[k] = map[string]bool{}
			}
			for _, v := range p.VulnIDs {
				held[k][v] = true
			}
		}
	}
	for _, e := range ents {
		c := e.RebuildCheck
		switch {
		case c == nil:
			return &RebuildCheck{Status: RebuildNotChecked}
		case c.Status == RebuildNotChecked:
			return &RebuildCheck{Status: RebuildNotChecked, Reason: c.Reason, Detail: c.Detail}
		case c.Status == RebuildPartial:
			out.Status = RebuildPartial
		}
		for _, p := range c.Gone {
			gone.add(p, p.VulnIDs...)
		}
		for _, p := range c.Remaining {
			remaining.add(p, p.VulnIDs...)
		}
		for _, p := range c.NotInBase {
			notInBase.add(p, p.VulnIDs...)
		}
		for _, p := range c.OnlyInBase {
			onlyInBase.add(p, p.VulnIDs...)
		}
		hold(c.Remaining)
		hold(c.NotInBase)
		hold(c.unsettled)
		out.Undetermined += c.Undetermined
		if c.OtherNotInBase > out.OtherNotInBase {
			out.OtherNotInBase = c.OtherNotInBase
		}
	}
	for k, g := range gone {
		h := held[rebuildPackageKey{k.class, k.name, k.version, k.path, ""}]
		var kept []string
		for _, v := range g.VulnIDs {
			if !h[v] {
				kept = append(kept, v)
			}
		}
		g.VulnIDs = kept
		if len(kept) == 0 {
			delete(gone, k)
		}
	}
	out.Gone, out.Remaining, out.NotInBase, out.OnlyInBase = gone.list(), remaining.list(), notInBase.list(), onlyInBase.list()
	return out
}

// RebuildCheckOptions are the limits of a check of the current bases.
type RebuildCheckOptions struct {
	// ReserveTime and ReserveRequests are the part of the cycle's time and
	// registry requests the check leaves to the work after it.
	ReserveTime     time.Duration
	ReserveRequests int
}

// RebuildCheckSummary is what a check of the current bases did.
type RebuildCheckSummary struct {
	Items            int // Dockerfile items checked
	Checked          int
	Partial          int
	NotChecked       int
	BaselineRescans  int
	RegistryRequests int
}

// allFloating reports whether every running image of an item has a base its
// floating tag no longer points at.
func allFloating(it DockerfileItem) bool {
	if len(it.Entities) == 0 {
		return false
	}
	for _, e := range it.Entities {
		if e.Reason != ReasonFloatingBaseUnconfirmed {
			return false
		}
	}
	return true
}

// CheckRebuildBases continues the pass of the last Plan call over plan, which
// is that call's plan with any later changes, and records on the running images
// whose floating tag moved how they compare with the base the tag points at
// now, and on the items all of whose images did. It shares the pass's caches and limits, comes
// after the comparisons that decide a proposal so it does not take their scans,
// writes nothing to an item but its RebuildCheck, and stops early to keep what
// opts says for the work after it. Without a Plan call it does nothing.
func (p *Planner) CheckRebuildBases(ctx context.Context, plan *Plan, opts RebuildCheckOptions) RebuildCheckSummary {
	r := p.last
	if r == nil {
		return RebuildCheckSummary{}
	}
	stage := ctx
	if dl, ok := ctx.Deadline(); ok && opts.ReserveTime > 0 {
		var cancel context.CancelFunc
		stage, cancel = context.WithDeadline(ctx, dl.Add(-opts.ReserveTime))
		defer cancel()
	}
	r.ctx, r.outer = stage, ctx
	r.plan = *plan
	r.initDF()
	before := r.plan.Usage
	startUsed := p.cfg.Budget.Used()
	p.cfg.Budget.Reserve(opts.ReserveRequests)
	defer p.cfg.Budget.Reserve(0)

	inputs := r.inputsByEntity()
	var sum RebuildCheckSummary
	for i := range r.plan.DockerfileItems {
		it := &r.plan.DockerfileItems[i]
		for j := range it.Entities {
			if e := &it.Entities[j]; e.Reason == ReasonFloatingBaseUnconfirmed {
				e.RebuildCheck = r.rebuildCheck(*e, it.BaseRef, inputs)
			}
		}
		if !allFloating(*it) {
			continue
		}
		it.RebuildCheck = mergeRebuildChecks(it.Entities)
		sum.Items++
		switch it.RebuildCheck.Status {
		case RebuildChecked:
			sum.Checked++
		case RebuildPartial:
			sum.Partial++
		default:
			sum.NotChecked++
		}
	}
	used := p.cfg.Budget.Used() - startUsed
	r.plan.Usage.RegistryRequests += used
	sum.BaselineRescans = r.plan.Usage.BaselineRescans - before.BaselineRescans
	sum.RegistryRequests = used
	*plan = r.plan
	return sum
}

// rebuildCheck compares one running image with the current base, scanning what
// the pass has not scanned under the prepared conditions yet.
func (r *run) rebuildCheck(e DockerfileEntity, baseRef string, inputs map[string]ImageInput) *RebuildCheck {
	fail := func(reason Reason, detail string) *RebuildCheck {
		return &RebuildCheck{Status: RebuildNotChecked, Reason: reason, Detail: detail}
	}
	if out := r.stopped(); out != nil {
		return fail(out.reason, out.detail)
	}
	in, ok := inputs[e.Running.Ref+"|"+e.Running.Entity]
	if !ok {
		return fail(ReasonEntityUnverified, "the scan of the running image is not at hand")
	}
	if e.CurrentBase == nil {
		return fail(ReasonRegistryError, "the current base was not resolved")
	}
	prep := r.p.cfg.Prepared
	if !prep.Known() {
		return fail(ReasonConditionsUnknown, "the cycle has no prepared scan conditions")
	}
	platform, ok := parsePlatform(e.CurrentBase.Platform)
	if !ok {
		return fail(ReasonPlatformUnknown, "the platform of the current base is not known")
	}
	ref := ParseImageRef(baseRef)
	// The current base was resolved by the plan; this is its cached resolution.
	curRes, out := r.resolveTag(ref.Repository, ref.Tag, platform)
	if out != nil {
		return fail(out.reason, out.detail)
	}
	digest, ok := inventory.ParseDigest(inventory.DigestRegistry, curRes.ManifestDigest)
	if !ok {
		return fail(ReasonRegistryError, "the registry resolution has no usable manifest digest")
	}

	repoKey, _ := inventory.RepositoryKey(ref.Repository)
	baseKey := baseScanKey(RoleBaseline, repoKey, digest, platform)
	base, baseCached := r.dfScans[baseKey]
	runKey := entityString(in.Scan.Subject.Key) + "|" + string(in.Target.Source)
	running, runCached := r.bases[runKey]
	rescan := !runCached && !(in.Conditions.Known() && in.Conditions.Equal(prep))
	need := 0
	if !baseCached {
		need++
	}
	if rescan {
		need++
	}
	// Both are checked before either is spent.
	if r.plan.Usage.BaselineRescans+need > r.p.cfg.Limits.MaxBaselineRescans {
		return fail(ReasonBaselineRescanLimit, "the baseline rescan limit was reached")
	}
	switch {
	case rescan:
		r.plan.Usage.BaselineRescans++
		running = r.scanUnder(RoleBaseline, in.Target)
		r.bases[runKey] = running
	case !runCached:
		rec := ScanRecord{Scan: in.Scan, Conditions: in.Conditions}
		running = scanned{rec: rec, id: r.addExecution(RoleBaseline, rec, entityString(in.Scan.Subject.Key), DBSupplied, nil, "", nil)}
		r.bases[runKey] = running
	}
	if !baseCached {
		r.plan.Usage.BaselineRescans++
		base = r.scanBaseTag(RoleBaseline, ref.Repository, ref.Tag, digest, platform)
		r.dfScans[baseKey] = base
	}
	if err := r.ctx.Err(); err != nil {
		return fail(r.deadlineReason(), err.Error())
	}

	vr := Compare(running.rec, base.rec)
	if !vr.Comparable {
		c := fail(vr.Reason, vr.Detail)
		c.RunningScan, c.BaseScan = running.id, base.id
		return c
	}
	c := classifyRebuild(running.rec.Scan, base.rec.Scan, vr.Severities, e.RebuildRuntimes)
	c.RunningScan, c.BaseScan = running.id, base.id
	return c
}
