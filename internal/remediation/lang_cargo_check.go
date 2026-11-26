package remediation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ReasonCargoRustVersionTooNew: the index gives a crate of the update a
// rust-version above the one the project declares.
const ReasonCargoRustVersionTooNew Reason = "cargo_rust_version_too_new"

// cargoChecker checks the Cargo.lock a worker container returned against the
// one it was given. The worker is not trusted: the file may have been made
// to look like the result of an update, so everything that is accepted is
// either something a Cargo update does (and the index of crates.io confirms)
// or is left as it was.
type cargoChecker struct {
	index CargoIndex
	// spend is called before each lookup in the index; it returns the failure
	// to give when the lookups of the update have used up what it may make.
	spend func() *updateFailure
	// bytes is what the update has read of the index, shared with the
	// choosing of the releases; nil gives the check a budget of its own.
	bytes *cargoIndexBudget
}

// cargoCheckTarget is a crate the update takes from one version to another.
type cargoCheckTarget struct {
	name, from, to string
}

// cargoCheckInput is what the check works from.
type cargoCheckInput struct {
	before, after []byte
	// members are the packages of the workspace as the plan read them, with
	// what they inherit from the workspace filled in.
	members []*cargoManifest
	targets []cargoCheckTarget
	record  CargoRecord
}

// CargoLockChange is what a checked update did to Cargo.lock.
type CargoLockChange struct {
	// Targets are the crates asked for, before and after.
	Targets []CargoCrateChange `json:"targets"`
	// Others are the crates other than the targets whose version changed
	// (both versions set), that were added (From empty) or that were removed
	// (To empty), by name and version.
	Others []CargoCrateChange `json:"others,omitempty"`
	// LockVersionFrom and LockVersionTo are the format versions of the file.
	LockVersionFrom int `json:"lock_version_from"`
	LockVersionTo   int `json:"lock_version_to"`
	// Moved are the crates of crates.io the file has after the update that
	// it did not have as they are: the targets, the crates they took along
	// and the others whose version changed.
	Moved []CargoCrateRef `json:"moved"`
	// MaxRustVersion is the highest rust-version the index declares for a
	// crate of Moved, "" when it declares none for any; NoRustVersion counts
	// the crates of Moved it declares none for.
	MaxRustVersion string `json:"max_rust_version,omitempty"`
	NoRustVersion  int    `json:"no_rust_version,omitempty"`
}

// CargoCrateChange is a crate whose version changed, appeared or went away.
type CargoCrateChange struct {
	Name string `json:"name"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// CargoCrateRef names a crate at a version.
type CargoCrateRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// cargoMinV4 is the Rust that reads the version 4 of Cargo.lock.
var cargoMinV4 = [3]int{1, 78, 0}

// check judges the file the worker returned. A nil failure means the update
// is what a Cargo update of the targets does, as far as the checks of
// cargoCheckRun go (see its methods); the change is then described.
func (c *cargoChecker) check(ctx context.Context, in cargoCheckInput) (*CargoLockChange, *updateFailure) {
	if c.index == nil || c.spend == nil {
		return nil, failedFailure(ReasonUpdateInputInvalid, "the Cargo.lock check has no crates.io index or lookup budget")
	}
	r := &cargoCheckRun{ctx: ctx, c: c, in: in, rels: map[string]map[string]CargoRelease{}, bytes: c.bytes}
	if r.bytes == nil {
		r.bytes = &cargoIndexBudget{}
	}
	return r.run()
}

// cargoCheckRun is one check.
type cargoCheckRun struct {
	ctx           context.Context
	c             *cargoChecker
	in            cargoCheckInput
	before, after *cargoLock
	rels          map[string]map[string]CargoRelease // index answers, by crate name and version
	bytes         *cargoIndexBudget
	manifests     map[string]*cargoManifest // the workspace's packages, by cargoMemberKey

	idxB, idxA map[string]int // crate keys of each file
	scope      map[string]bool
	// obligations are the edges whose requirement the parent's declaration
	// must allow, by the keys of the parent and the child.
	obligations [][2]int
	// lowers are the crates added in a series below one the file had.
	lowers []int
}

func cargoKey(c cargoCrate) string { return c.name + "\x00" + c.version + "\x00" + c.source }

// cargoSlot is the unit Cargo resolves one version in: the name, the source
// and the series of the version.
func cargoSlot(c cargoCrate) string {
	v, _ := parseCargoVersion(c.version)
	return c.name + "\x00" + c.source + "\x00" + cargoSeries(v)
}

// cargoDesc names a crate in a message.
func cargoDesc(c cargoCrate) string {
	if !c.registry() {
		return c.name + " " + c.version + " (workspace)"
	}
	return c.name + " " + c.version
}

// cargoNorm is a crate name as crates.io tells names apart: not by case,
// and with - and _ as one.
func cargoNorm(s string) string { return strings.ReplaceAll(strings.ToLower(s), "_", "-") }

func (r *cargoCheckRun) run() (*CargoLockChange, *updateFailure) {
	in := r.in
	var err error
	if r.before, err = parseCargoLock(in.before); err != nil {
		return nil, manualFailure(ReasonDependencyFileUnusable, "the Cargo.lock before the update cannot be read: %s", clip(err.Error(), 300))
	}
	if r.after, err = parseCargoLock(in.after); err != nil {
		var ue *UnsupportedError
		if errors.As(err, &ue) {
			return nil, manualFailure(ue.Reason, "the Cargo.lock the update returned: %s", clip(ue.Detail, 300))
		}
		return nil, manualFailure(ReasonOutputFilesInvalid, "the Cargo.lock the update returned cannot be read: %s", clip(err.Error(), 300))
	}
	r.manifests = map[string]*cargoManifest{}
	for _, m := range in.members {
		r.manifests[cargoMemberKey(m.name, m.version)] = m
	}
	r.idxB, r.idxA = map[string]int{}, map[string]int{}
	for i, c := range r.before.crates {
		r.idxB[cargoKey(c)] = i
	}
	for i, c := range r.after.crates {
		r.idxA[cargoKey(c)] = i
	}

	steps := []func() *updateFailure{
		r.checkInput,
		r.checkLockVersion,
		r.checkMembers,
		r.checkKept,
		r.checkTargets,
		r.computeScope,
		r.checkMoves,
		r.checkEdges,
		r.checkSeries,
		r.checkReachable,
	}
	for _, s := range steps {
		if f := s(); f != nil {
			return nil, f
		}
	}
	moved, f := r.checkDistribution()
	if f != nil {
		return nil, f
	}
	ch := &CargoLockChange{LockVersionFrom: r.before.version, LockVersionTo: r.after.version}
	if f := r.checkEdgeRequirements(); f != nil {
		return nil, f
	}
	if f := r.checkLowerSeries(); f != nil {
		return nil, f
	}
	if f := r.checkRustVersion(moved, ch); f != nil {
		return nil, f
	}
	r.describe(moved, ch)
	return ch, nil
}

// checkInput refuses what the caller should not have asked: no target, a
// target the lock does not have at its version, or one that is not a step
// up within a series.
func (r *cargoCheckRun) checkInput() *updateFailure {
	if len(r.in.targets) == 0 {
		return failedFailure(ReasonUpdateInputInvalid, "the Cargo.lock check has no target")
	}
	seen := map[string]bool{}
	for _, t := range r.in.targets {
		from, ok1 := parseCargoVersion(t.from)
		to, ok2 := parseCargoVersion(t.to)
		if t.name == "" || !ok1 || !ok2 || !cargoCompatible(from, to) || to.compare(from) <= 0 {
			return failedFailure(ReasonUpdateInputInvalid, "the target %s %s -> %s is not a step up within one series", t.name, t.from, t.to)
		}
		if seen[cargoNorm(t.name)] {
			return failedFailure(ReasonUpdateInputInvalid, "the target %s is given twice", t.name)
		}
		seen[cargoNorm(t.name)] = true
		if r.before.find(t.name, t.from, cratesIOSource) < 0 {
			return failedFailure(ReasonUpdateInputInvalid, "the Cargo.lock has no %s %s from crates.io", t.name, t.from)
		}
	}
	return nil
}

// checkLockVersion lets the format version stay, and lets 3 become 4 only
// where the Rust the project builds with reads version 4: the project's
// rust-version, when it declares one, and every rust-toolchain file name
// 1.78 or later (a toolchain file naming "stable" counts).
func (r *cargoCheckRun) checkLockVersion() *updateFailure {
	b, a := r.before.version, r.after.version
	if rec := r.in.record.LockVersion; rec != 0 && rec != b {
		return failedFailure(ReasonUpdateInputInvalid, "the plan recorded Cargo.lock of version %d, and the one given is of version %d", rec, b)
	}
	if a == b {
		return nil
	}
	if b != 3 || a != 4 {
		return manualFailure(ReasonLockfileFormatChanged, "the update changed the version of Cargo.lock from %d to %d", b, a)
	}
	if rv := r.in.record.RustVersion; rv != "" {
		p, ok := cargoVersionParts(rv)
		if !ok {
			return manualFailure(ReasonDependencyFileUnusable, "the rust-version %q of the project is not a version", rv)
		}
		if cargoVersionLess(p, cargoMinV4) {
			return manualFailure(ReasonLockfileFormatChanged, "the update changed the version of Cargo.lock from 3 to 4, which Rust %s, the rust-version of the project, does not read", rv)
		}
	}
	for _, tc := range r.in.record.Toolchains {
		if tc.Channel == "stable" {
			continue
		}
		p, ok := cargoVersionParts(tc.Version)
		if tc.Version == "" || !ok || cargoVersionLess(p, cargoMinV4) {
			return manualFailure(ReasonLockfileFormatChanged, "the update changed the version of Cargo.lock from 3 to 4, and %s names the toolchain %q, which is not stable or 1.78 or later", tc.Path, tc.Channel)
		}
	}
	return nil
}

// checkMembers requires the packages of the workspace to be the same, by
// name and version, before and after, to be those the plan read, and not to
// be listed again as crates of crates.io.
func (r *cargoCheckRun) checkMembers() *updateFailure {
	ws := &cargoWorkspaceInfo{members: r.in.members}
	if why := cargoLockMismatch(r.before, ws); why != "" {
		return manualFailure(ReasonDependencyFileUnusable, "%s", why)
	}
	if why := cargoLockMismatch(r.after, ws); why != "" {
		return manualFailure(ReasonUnexplainedDiff, "in the Cargo.lock the update returned, %s", why)
	}
	return nil
}

// checkKept requires a crate that is at the same version before and after to
// have the same checksum. (Its source cannot differ: the only sources the
// parser accepts are crates.io and none, and checkMembers has made the
// packages of the workspace the same.)
func (r *cargoCheckRun) checkKept() *updateFailure {
	for _, c := range r.after.crates {
		if bi, ok := r.idxB[cargoKey(c)]; ok && r.before.crates[bi].checksum != c.checksum {
			return manualFailure(ReasonDistributionMismatch, "the checksum of %s %s changed, though its version did not", c.name, c.version)
		}
	}
	return nil
}

// checkTargets requires each target to be in the file once, at its target
// version: its installed version is gone, and no other version of it (of
// another series, which a crate the update brought in could need) was added.
func (r *cargoCheckRun) checkTargets() *updateFailure {
	for _, t := range r.in.targets {
		if r.after.find(t.name, t.to, cratesIOSource) < 0 {
			return manualFailure(ReasonTargetNotUpdated, "the Cargo.lock the update returned does not have %s at %s", t.name, t.to)
		}
		if r.after.find(t.name, t.from, cratesIOSource) >= 0 {
			return manualFailure(ReasonTargetNotUpdated, "the Cargo.lock the update returned still has %s %s", t.name, t.from)
		}
		var others []string
		for _, i := range r.after.byName[t.name] {
			if c := r.after.crates[i]; c.registry() && c.version != t.to {
				others = append(others, c.version)
			}
		}
		if len(others) > 0 {
			sort.Strings(others)
			return pkgFailure(t.name, ReasonMultipleVersions, "the Cargo.lock the update returned has %s at %s besides %s", t.name, strings.Join(others, ", "), t.to)
		}
	}
	return nil
}

// reachRegistry returns the crates of crates.io reachable from the crate at
// index from, itself included.
func reachRegistry(l *cargoLock, from int) map[int]bool {
	seen := map[int]bool{from: true}
	stack := []int{from}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, d := range l.crates[i].deps {
			if !seen[d] && l.crates[d].registry() {
				seen[d] = true
				stack = append(stack, d)
			}
		}
	}
	return seen
}

// computeScope finds the crates the update may change: what the old
// version of a target reached before, and what its new version reaches
// after, the targets included. A package of the workspace is never in it.
func (r *cargoCheckRun) computeScope() *updateFailure {
	r.scope = map[string]bool{}
	for _, t := range r.in.targets {
		for i := range reachRegistry(r.before, r.before.find(t.name, t.from, cratesIOSource)) {
			r.scope[cargoKey(r.before.crates[i])] = true
		}
		for i := range reachRegistry(r.after, r.after.find(t.name, t.to, cratesIOSource)) {
			r.scope[cargoKey(r.after.crates[i])] = true
		}
	}
	return nil
}

// checkMoves requires every crate that appeared, went away or changed
// version to be in the scope, and a crate that took the place of one of its
// series to be a later version.
func (r *cargoCheckRun) checkMoves() *updateFailure {
	slotsB := map[string]cargoCrate{}
	for _, c := range r.before.crates {
		slotsB[cargoSlot(c)] = c
	}
	for _, c := range r.before.crates {
		if _, kept := r.idxA[cargoKey(c)]; !kept && !r.scope[cargoKey(c)] {
			return manualFailure(ReasonUnexplainedDiff, "the update removed %s, which is not among what the targets depend on", cargoDesc(c))
		}
	}
	for _, c := range r.after.crates {
		if _, kept := r.idxB[cargoKey(c)]; kept {
			continue
		}
		if !r.scope[cargoKey(c)] {
			return manualFailure(ReasonUnexplainedDiff, "the update added %s, which is not among what the targets depend on", cargoDesc(c))
		}
		if old, ok := slotsB[cargoSlot(c)]; ok {
			nv, _ := parseCargoVersion(c.version)
			ov, _ := parseCargoVersion(old.version)
			if nv.compare(ov) <= 0 {
				return manualFailure(ReasonUnexplainedDiff, "the update lowered %s from %s to %s", c.name, old.version, c.version)
			}
		}
	}
	return nil
}

// checkEdges looks at the dependencies of each crate of the file after the
// update against those before.
//
// A crate outside the scope keeps its dependencies except that one may move
// to the new version of a crate that changed within its series (the crate
// the dependency pointed at has gone, and the version that took its place is
// in the scope). A crate in the scope may change its dependencies freely,
// but each that is new or points elsewhere must be one its declaration
// allows (checked once the index has been read: see
// checkEdgeRequirements). A crate of crates.io never depends on a package of
// the workspace.
func (r *cargoCheckRun) checkEdges() *updateFailure {
	for i, p := range r.after.crates {
		pk := cargoKey(p)
		after := map[string]int{}
		for _, d := range p.deps {
			after[cargoKey(r.after.crates[d])] = d
			if p.registry() && !r.after.crates[d].registry() {
				return manualFailure(ReasonUnexplainedDiff, "%s depends on %s, a package of the workspace", cargoDesc(p), cargoDesc(r.after.crates[d]))
			}
		}
		before := map[string]int{}
		bi, inBefore := r.idxB[pk]
		if inBefore {
			for _, d := range r.before.crates[bi].deps {
				before[cargoKey(r.before.crates[d])] = d
			}
		}
		var added, removed []string
		for k := range after {
			if _, ok := before[k]; !ok {
				added = append(added, k)
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				removed = append(removed, k)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)

		if r.scope[pk] {
			for _, k := range added {
				r.obligations = append(r.obligations, [2]int{i, after[k]})
			}
			continue
		}
		// Outside the scope: every removed dependency must have been
		// replaced by the one that took its place in its series.
		replaced := map[string]bool{}
		for _, k := range added {
			ci := after[k]
			child := r.after.crates[ci]
			match := ""
			for _, rk := range removed {
				old := r.before.crates[before[rk]]
				if _, still := r.idxA[rk]; !still && cargoSlot(old) == cargoSlot(child) && r.scope[k] {
					match = rk
					break
				}
			}
			if match == "" {
				return manualFailure(ReasonUnexplainedDiff, "%s, which is outside what the targets depend on, now depends on %s", cargoDesc(p), cargoDesc(child))
			}
			replaced[match] = true
			r.obligations = append(r.obligations, [2]int{i, ci})
		}
		for _, rk := range removed {
			if !replaced[rk] {
				return manualFailure(ReasonUnexplainedDiff, "%s, which is outside what the targets depend on, no longer depends on %s", cargoDesc(p), cargoDesc(r.before.crates[before[rk]]))
			}
		}
	}
	return nil
}

// checkSeries looks at each crate that was added in a series of its own: one
// below a series the file had of the crate is accepted only when a crate in
// the scope depends on it, its declaration allows that version, and no
// version the file had already allows it (so that Cargo had to add this
// one); the versions the file had of the higher series stay as they were,
// with their dependencies. The requirement part is judged with the index
// (see checkLowerSeries).
func (r *cargoCheckRun) checkSeries() *updateFailure {
	byName := map[string][]int{}
	for i, c := range r.before.crates {
		if c.registry() {
			byName[c.name] = append(byName[c.name], i)
		}
	}
	slotsB := map[string]bool{}
	for _, c := range r.before.crates {
		slotsB[cargoSlot(c)] = true
	}
	for i, c := range r.after.crates {
		if _, kept := r.idxB[cargoKey(c)]; kept || !c.registry() || slotsB[cargoSlot(c)] {
			continue
		}
		nv, _ := parseCargoVersion(c.version)
		lower := false
		for _, bi := range byName[c.name] {
			ov, _ := parseCargoVersion(r.before.crates[bi].version)
			if ov.compare(nv) > 0 {
				lower = true
			}
		}
		if !lower {
			continue
		}
		r.lowers = append(r.lowers, i)
		for _, bi := range byName[c.name] {
			h := r.before.crates[bi]
			hv, _ := parseCargoVersion(h.version)
			if hv.compare(nv) < 0 {
				continue
			}
			ai, ok := r.idxA[cargoKey(h)]
			switch {
			case !ok:
				return manualFailure(ReasonUnexplainedDiff, "the update added %s below the series of %s, which it did not keep as it was", cargoDesc(c), cargoDesc(h))
			case !sameDepKeys(r.before, bi, r.after, ai):
				return manualFailure(ReasonUnexplainedDiff, "the update added %s below the series of %s and changed the dependencies of %s", cargoDesc(c), cargoDesc(h), cargoDesc(h))
			}
		}
	}
	return nil
}

// sameDepKeys reports whether the crate bi of the lock b and the crate ai of
// the lock a depend on the same crates, by name, version and source.
func sameDepKeys(b *cargoLock, bi int, a *cargoLock, ai int) bool {
	x, y := map[string]bool{}, map[string]bool{}
	for _, d := range b.crates[bi].deps {
		x[cargoKey(b.crates[d])] = true
	}
	for _, d := range a.crates[ai].deps {
		y[cargoKey(a.crates[d])] = true
	}
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if !y[k] {
			return false
		}
	}
	return true
}

// checkReachable requires every crate of the file to be reached from a
// package of the workspace.
func (r *cargoCheckRun) checkReachable() *updateFailure {
	seen := map[int]bool{}
	var stack []int
	for i, c := range r.after.crates {
		if !c.registry() {
			seen[i] = true
			stack = append(stack, i)
		}
	}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, d := range r.after.crates[i].deps {
			if !seen[d] {
				seen[d] = true
				stack = append(stack, d)
			}
		}
	}
	for i, c := range r.after.crates {
		if !seen[i] {
			return manualFailure(ReasonUnexplainedDiff, "the Cargo.lock the update returned has %s, which no package of the workspace depends on", cargoDesc(c))
		}
	}
	return nil
}

// release returns what the index lists for a version of a crate. A crate
// is asked for once.
func (r *cargoCheckRun) release(name, version string) (CargoRelease, *updateFailure) {
	vs, ok := r.rels[name]
	if !ok {
		if f := r.c.spend(); f != nil {
			return CargoRelease{}, f
		}
		list, err := r.bytes.versions(r.ctx, r.c.index, name)
		switch {
		case errors.Is(err, ErrReleaseNotFound):
			return CargoRelease{}, manualFailure(ReasonDistributionMismatch, "the crates.io index has no crate %s", name)
		case err != nil:
			return CargoRelease{}, lookupFailure(r.ctx, err, "the crates.io index entry of "+name)
		}
		vs = map[string]CargoRelease{}
		for _, rel := range list {
			vs[rel.Version] = rel
		}
		r.rels[name] = vs
	}
	rel, ok := vs[version]
	if !ok {
		return CargoRelease{}, manualFailure(ReasonDistributionMismatch, "the crates.io index lists no version %s of %s", version, name)
	}
	return rel, nil
}

// checkDistribution requires every crate of crates.io that is new in the
// file (a version it did not have) to be a version the index lists, not
// yanked, with the checksum the file gives. It returns those crates.
func (r *cargoCheckRun) checkDistribution() ([]cargoCrate, *updateFailure) {
	var moved []cargoCrate
	for _, c := range r.after.crates {
		if _, kept := r.idxB[cargoKey(c)]; !kept && c.registry() {
			moved = append(moved, c)
		}
	}
	sort.Slice(moved, func(i, j int) bool {
		if moved[i].name != moved[j].name {
			return moved[i].name < moved[j].name
		}
		return moved[i].version < moved[j].version
	})
	for _, c := range moved {
		rel, f := r.release(c.name, c.version)
		if f != nil {
			return nil, f
		}
		switch {
		case rel.Checksum != c.checksum:
			return nil, manualFailure(ReasonDistributionMismatch, "the checksum of %s %s in the Cargo.lock the update returned is not the one the crates.io index lists", c.name, c.version)
		case rel.Yanked:
			return nil, manualFailure(ReasonReleaseYanked, "%s %s was yanked", c.name, c.version)
		}
	}
	return moved, nil
}

// declared returns the requirements the crate p declares for its dependency
// on the crate named child. For a crate of crates.io these are the
// dependencies the index gives for its version other than dev ones, which a
// lock does not carry; for a package of the workspace, those of its
// Cargo.toml in every table.
func (r *cargoCheckRun) declared(p cargoCrate, child string) ([]string, *updateFailure) {
	var reqs []string
	if !p.registry() {
		m, ok := r.manifests[cargoMemberKey(p.name, p.version)]
		if !ok {
			return nil, manualFailure(ReasonDependencyFileUnusable, "the plan has no Cargo.toml of the package %s", cargoDesc(p))
		}
		for _, d := range m.deps {
			if cargoNorm(d.pkg) != cargoNorm(child) || d.path != "" {
				continue
			}
			if d.inherit {
				return nil, manualFailure(ReasonCargoManifestUnsupported, "%s: %s %s inherits from the workspace, which was not filled in", m.file, d.table, d.key)
			}
			if d.req != "" {
				reqs = append(reqs, d.req)
			}
		}
		return reqs, nil
	}
	rel, f := r.release(p.name, p.version)
	if f != nil {
		return nil, f
	}
	for _, d := range rel.Deps {
		pkg := d.Package
		if pkg == "" {
			pkg = d.Name
		}
		if d.Kind != "dev" && cargoNorm(pkg) == cargoNorm(child) {
			reqs = append(reqs, d.Req)
		}
	}
	return reqs, nil
}

// cargoAnyAllows reports whether the version satisfies one of the
// requirements; evaluable is false when none does and one cannot be
// evaluated.
func cargoAnyAllows(reqs []string, v semver) (ok, evaluable bool) {
	evaluable = true
	for _, q := range reqs {
		o, e := cargoReqAllows(q, v)
		if o {
			return true, true
		}
		if !e {
			evaluable = false
		}
	}
	return false, evaluable
}

// checkEdgeRequirements requires each new or moved dependency to be one the
// declaration of its crate allows, at the version it now points at.
func (r *cargoCheckRun) checkEdgeRequirements() *updateFailure {
	for _, o := range r.obligations {
		p, c := r.after.crates[o[0]], r.after.crates[o[1]]
		reqs, f := r.declared(p, c.name)
		if f != nil {
			return f
		}
		if len(reqs) == 0 {
			return manualFailure(ReasonLockfileInconsistent, "%s does not declare a dependency on %s, which the Cargo.lock the update returned has it depend on", cargoDesc(p), c.name)
		}
		v, _ := parseCargoVersion(c.version)
		ok, evaluable := cargoAnyAllows(reqs, v)
		switch {
		case ok:
		case !evaluable:
			return manualFailure(ReasonUnexplainedDiff, "the requirement of %s on %s (%s) cannot be evaluated against %s", cargoDesc(p), c.name, strings.Join(reqs, ", "), c.version)
		default:
			return manualFailure(ReasonLockfileInconsistent, "%s requires %s %s, and the Cargo.lock the update returned has it depend on %s", cargoDesc(p), c.name, strings.Join(reqs, ", "), c.version)
		}
	}
	return nil
}

// checkLowerSeries judges the crates checkSeries found: each needs a crate in
// the scope that depends on it and whose declaration allows its version but
// allows no version of the crate that the file had before.
func (r *cargoCheckRun) checkLowerSeries() *updateFailure {
	for _, ni := range r.lowers {
		n := r.after.crates[ni]
		nv, _ := parseCargoVersion(n.version)
		var had []semver
		for _, c := range r.before.crates {
			if c.registry() && c.name == n.name {
				v, _ := parseCargoVersion(c.version)
				had = append(had, v)
			}
		}
		var why string
		justified := false
		for _, p := range r.after.crates {
			if justified {
				break
			}
			if !r.scope[cargoKey(p)] {
				continue
			}
			depends := false
			for _, d := range p.deps {
				depends = depends || d == ni
			}
			if !depends {
				continue
			}
			reqs, f := r.declared(p, n.name)
			if f != nil {
				return f
			}
			var wanted []string
			for _, q := range reqs {
				ok, evaluable := cargoReqAllows(q, nv)
				if !evaluable {
					return manualFailure(ReasonUnexplainedDiff, "the requirement of %s on %s (%s) cannot be evaluated", cargoDesc(p), n.name, q)
				}
				if ok {
					wanted = append(wanted, q)
				}
			}
			if len(wanted) == 0 {
				why = fmt.Sprintf("%s does not require a version like %s", cargoDesc(p), n.version)
				continue
			}
			clash := ""
			for _, hv := range had {
				for _, q := range wanted {
					ok, evaluable := cargoReqAllows(q, hv)
					if !evaluable {
						return manualFailure(ReasonUnexplainedDiff, "the requirement of %s on %s (%s) cannot be evaluated", cargoDesc(p), n.name, q)
					}
					if ok {
						clash = fmt.Sprintf("a version of %s the file had satisfies %s of %s", n.name, q, cargoDesc(p))
					}
				}
			}
			if clash != "" {
				why = clash
				continue
			}
			justified = true
		}
		if !justified {
			if why == "" {
				why = "no crate depends on it that the targets lead to"
			}
			return manualFailure(ReasonUnexplainedDiff, "the update added %s in a series below one the file had: %s", cargoDesc(n), why)
		}
	}
	return nil
}

// checkRustVersion compares the rust-version the index declares for each new
// crate with the project's, and notes the highest and how many declare none.
func (r *cargoCheckRun) checkRustVersion(moved []cargoCrate, ch *CargoLockChange) *updateFailure {
	var limit [3]int
	hasLimit := false
	if rv := r.in.record.RustVersion; rv != "" {
		p, ok := cargoVersionParts(rv)
		if !ok {
			return manualFailure(ReasonDependencyFileUnusable, "the rust-version %q of the project is not a version", rv)
		}
		limit, hasLimit = p, true
	}
	var top [3]int
	for _, c := range moved {
		rel, f := r.release(c.name, c.version)
		if f != nil {
			return f
		}
		if rel.RustVersion == "" {
			ch.NoRustVersion++
			continue
		}
		p, ok := cargoVersionParts(rel.RustVersion)
		if !ok {
			if hasLimit {
				return manualFailure(ReasonDistributionMismatch, "the crates.io index gives %s %s the rust-version %q, which is not a version", c.name, c.version, clip(rel.RustVersion, 40))
			}
			ch.NoRustVersion++
			continue
		}
		if hasLimit && cargoVersionLess(limit, p) {
			return manualFailure(ReasonCargoRustVersionTooNew, "%s %s declares the rust-version %s, above the rust-version %s of the project", c.name, c.version, rel.RustVersion, r.in.record.RustVersion)
		}
		if ch.MaxRustVersion == "" || cargoVersionLess(top, p) {
			ch.MaxRustVersion, top = rel.RustVersion, p
		}
	}
	return nil
}

// describe fills in what the update changed.
func (r *cargoCheckRun) describe(moved []cargoCrate, ch *CargoLockChange) {
	for _, c := range moved {
		ch.Moved = append(ch.Moved, CargoCrateRef{c.name, c.version})
	}
	isTarget := map[CargoCrateChange]bool{}
	for _, t := range r.in.targets {
		tc := CargoCrateChange{Name: t.name, From: t.from, To: t.to}
		isTarget[tc] = true
		ch.Targets = append(ch.Targets, tc)
	}
	type pair struct{ from, to string }
	slots := map[string]*pair{}
	names := map[string]string{}
	for _, c := range r.before.crates {
		if _, kept := r.idxA[cargoKey(c)]; !kept && c.registry() {
			s := cargoSlot(c)
			names[s] = c.name
			slots[s] = &pair{from: c.version}
		}
	}
	for _, c := range r.after.crates {
		if _, kept := r.idxB[cargoKey(c)]; !kept && c.registry() {
			s := cargoSlot(c)
			names[s] = c.name
			if p, ok := slots[s]; ok {
				p.to = c.version
			} else {
				slots[s] = &pair{to: c.version}
			}
		}
	}
	for s, p := range slots {
		cc := CargoCrateChange{Name: names[s], From: p.from, To: p.to}
		if !isTarget[cc] {
			ch.Others = append(ch.Others, cc)
		}
	}
	sort.Slice(ch.Others, func(i, j int) bool {
		a, b := ch.Others[i], ch.Others[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
}
