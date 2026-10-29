package remediation

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// Reasons of the Go module update.
const (
	// ReasonGoRetracted: the module's author retracted the target version
	// (a retract directive in the go.mod of the module's latest version).
	ReasonGoRetracted Reason = "go_release_retracted"
	// ReasonGoLineRaised: the update raised the go or toolchain line above
	// the Go the running binaries were built with.
	ReasonGoLineRaised Reason = "go_line_raised_too_far"
	// ReasonGoRuntimeUnavailable: no supported Go of the runtime table is as
	// new as the go lines the update needs.
	ReasonGoRuntimeUnavailable Reason = "go_runtime_unavailable"
	// ReasonGoDependenciesUncheckable: the requirements of the versions the
	// update moved to cannot all be followed (too many module versions).
	ReasonGoDependenciesUncheckable Reason = "go_dependencies_uncheckable"
)

// RuntimeBasisGoLines is the runtime basis of a Go update: the lowest
// supported Go that is as new as the go lines of the module and of the
// targets' new versions.
const RuntimeBasisGoLines = "go_lines"

// GoUpdate is what a Go module update did besides moving its targets.
type GoUpdate struct {
	// Collateral are the requirements the update raised or added that are
	// not targets, by path.
	Collateral []GoModuleMove `json:"collateral,omitempty"`
	// GoBefore and GoAfter are the go line before and after the update,
	// ToolchainBefore and ToolchainAfter the toolchain line ("" for none).
	GoBefore        string `json:"go_before,omitempty"`
	GoAfter         string `json:"go_after,omitempty"`
	ToolchainBefore string `json:"toolchain_before,omitempty"`
	ToolchainAfter  string `json:"toolchain_after,omitempty"`
	// SumAdded are the go.sum lines this program added from the checksum
	// database.
	SumAdded []string `json:"sum_added,omitempty"`
}

// GoModuleMove is one requirement an update moved: From is "" for one it
// added.
type GoModuleMove struct {
	Path string `json:"path"`
	From string `json:"from,omitempty"`
	To   string `json:"to"`
}

// goLookupError is a failed request to the proxy or the checksum database,
// as opposed to an answer that is refused.
type goLookupError struct {
	what string
	err  error
}

func (e *goLookupError) Error() string { return e.what + ": " + e.err.Error() }
func (e *goLookupError) Unwrap() error { return e.err }

// spendGoLookup counts one request of the update to the proxy or the
// checksum database against the registry lookups an update may make. The
// go.mod files read to follow requirements have their own bound.
func (r *updateRun) spendGoLookup() error {
	if r.lookups >= maxRegistryChecks {
		return errRegistryBudget
	}
	r.lookups++
	return nil
}

// goFailure maps an error of the Go checks: a failed request as a lookup
// (lookupFailure), anything else as an answer that is refused.
func goFailure(ctx context.Context, err error, reason Reason) *updateFailure {
	var le *goLookupError
	switch {
	case errors.Is(err, errRegistryBudget), ctx.Err() != nil:
		return lookupFailure(ctx, err, "the Go module proxy")
	case errors.Is(err, errGoFetchLimit):
		return manualFailure(ReasonGoDependenciesUncheckable, "%v", err)
	case errors.As(err, &le):
		return lookupFailure(ctx, le.err, le.what)
	}
	return manualFailure(reason, "%s", clip(err.Error(), 300))
}

// runGo is the update of a Go module: one go get of every target at its
// canonical version, in a supported Go as new as the go lines need, and the
// checks of what came back (see checkGoResult).
func (r *updateRun) runGo(ctx context.Context) *updateFailure {
	reg := r.u.cfg.Go
	if reg == nil {
		return failedFailure(ReasonUpdateInputInvalid, "no Go module proxy client is configured")
	}
	before, err := parseGoMod(r.src.lock)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "go.mod cannot be read: %v", err)
	}
	if err := goModRefusal(before); err != nil {
		var ue *UnsupportedError
		if errors.As(err, &ue) {
			return manualFailure(ue.Reason, "%s", ue.Detail)
		}
		return manualFailure(ReasonDependencyFileUnusable, "%v", err)
	}
	if err := checkGoSum(r.src.manifest); err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "%v", err)
	}
	origLock, err := goLockfile(before)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "%v", err)
	}
	graph, err := newGoModGraph(ctx, reg, r.u.goCache, r.src.manifest)
	if err != nil {
		return manualFailure(ReasonDependencyFileUnusable, "%v", err)
	}

	// The targets at the versions the proxy names, neither retracted nor of
	// another major version than their path takes.
	var pkgs []worker.Package
	r.goTargets, r.goRetracts = map[string]string{}, map[string][]string{}
	need, _ := parseGoRelease(before.goVersion)
	if before.toolchain != "" {
		if tc, ok := parseGoRelease(before.toolchain); ok && tc.compare(need) > 0 {
			need = tc
		}
	}
	for _, n := range r.set.names {
		lp := origLock.lookup(n)
		if lp == nil {
			return pkgFailure(n, ReasonTargetNotInLockfile, "go.mod does not require %s", n)
		}
		installed := lp.occs[0].Version
		want := r.set.target[n]
		if !strings.HasPrefix(want, "v") {
			want = "v" + want
		}
		canonical, fail := r.goTargetVersion(ctx, reg, n, installed, want)
		if fail != nil {
			return fail
		}
		e, err := graph.entry(n, canonical)
		if err != nil {
			return goFailure(ctx, err, ReasonDistributionMismatch)
		}
		if e.goLine != "" {
			gl, ok := parseGoRelease(e.goLine)
			if !ok {
				return pkgFailure(n, ReasonGoRuntimeUnavailable, "the go.mod of %s@%s declares go %q, which is not a Go release", n, canonical, e.goLine)
			}
			if gl.compare(need) > 0 {
				need = gl
			}
		}
		pkgs = append(pkgs, worker.Package{Name: n, Version: canonical})
		r.goTargets[n] = canonical
	}
	spec, ok := goRuntimeFor(need, r.u.now())
	if !ok {
		return manualFailure(ReasonGoRuntimeUnavailable, "the update needs Go %s or later, and no supported Go of the runtime table is", need)
	}
	r.toolSpec = ToolSpec{Manager: ManagerGo, Runtime: spec.ID, RuntimeBasis: RuntimeBasisGoLines}

	steps := []worker.Step{{ID: stepUpdate, Op: worker.OpGoGet, Packages: pkgs}}
	out, fail := r.exec(ctx, worker.ManagerGo, map[string][]byte{"go.mod": r.src.lock, "go.sum": r.src.manifest}, steps, "update")
	if fail != nil {
		return fail
	}
	r.it.PostUpdateCheckExecuted = true
	newMod, ok1 := out.finalFile("go.mod")
	newSum, ok2 := out.finalFile("go.sum")
	if !ok1 || !ok2 {
		return manualFailure(ReasonOutputFilesInvalid, "the final tree lacks go.mod or go.sum")
	}
	return r.checkGoResult(ctx, reg, before, newMod, newSum)
}

// goTargetVersion settles the version a target is updated to: the
// canonical form the proxy gives for it (+incompatible where the module has
// no go.mod at that version), which must be of a major version the module
// path takes and must not be retracted. The retractions are those the go.mod
// of the module's latest version declares, as the go command reads them; a
// go.mod that cannot be read leaves the version unused.
func (r *updateRun) goTargetVersion(ctx context.Context, reg GoModuleRegistry, path, installed, want string) (string, *updateFailure) {
	at := path + "@" + want
	if err := r.spendGoLookup(); err != nil {
		return "", lookupFailure(ctx, err, at+" on the Go module proxy")
	}
	info, err := reg.Info(ctx, path, want)
	if errors.Is(err, ErrReleaseNotFound) && goPathMajor(path) == "" && !strings.HasSuffix(want, "+incompatible") {
		// From v2 on, a module without a major version suffix in its path is
		// published as +incompatible.
		if sv, ok := parseVersion(schemeGo, want); ok && sv.(semver).major != "0" && sv.(semver).major != "1" {
			if err := r.spendGoLookup(); err != nil {
				return "", lookupFailure(ctx, err, at+"+incompatible on the Go module proxy")
			}
			want += "+incompatible"
			at = path + "@" + want
			info, err = reg.Info(ctx, path, want)
		}
	}
	if err != nil {
		return "", lookupFailure(ctx, err, at+" on the Go module proxy")
	}
	if c, ok := compareVersions(schemeGo, info.Version, want); !ok || c != 0 {
		return "", pkgFailure(path, ReasonDistributionMismatch, "the Go module proxy answers %s for %s", info.Version, at)
	}
	if why := goMajorProblem(path, installed, info.Version); why != "" {
		return "", pkgFailure(path, ReasonFixInOtherMajor, "%s", why)
	}
	if err := r.spendGoLookup(); err != nil {
		return "", lookupFailure(ctx, err, path+"@latest on the Go module proxy")
	}
	latest, err := reg.Latest(ctx, path)
	if err != nil {
		return "", lookupFailure(ctx, err, path+"@latest on the Go module proxy")
	}
	if err := r.spendGoLookup(); err != nil {
		return "", lookupFailure(ctx, err, path+"@"+latest.Version+" on the Go module proxy")
	}
	data, err := reg.GoMod(ctx, path, latest.Version)
	if err != nil {
		return "", lookupFailure(ctx, err, "the go.mod of "+path+"@"+latest.Version)
	}
	gm, err := parseGoMod(data)
	if err != nil {
		return "", pkgFailure(path, ReasonDistributionMismatch, "the go.mod of %s@%s, the latest version, which declares its retractions, cannot be read: %v", path, latest.Version, err)
	}
	if gm.module != path {
		return "", pkgFailure(path, ReasonDistributionMismatch, "the go.mod of %s@%s declares the module %s", path, latest.Version, gm.module)
	}
	for _, d := range gm.others {
		if strings.HasPrefix(d, "retract ") {
			r.goRetracts[path] = append(r.goRetracts[path], d)
		}
	}
	if d := goRetraction(r.goRetracts[path], info.Version); d != "" {
		return "", pkgFailure(path, ReasonGoRetracted, "%s@%s is retracted by the go.mod of %s (%s)", path, info.Version, latest.Version, d)
	}
	return info.Version, nil
}

// goRetraction returns the retract directive that covers version, or "".
func goRetraction(retracts []string, version string) string {
	for _, d := range retracts {
		f := strings.Fields(strings.TrimPrefix(d, "retract "))
		lo, hi := f[0], f[0]
		if len(f) == 5 {
			lo, hi = f[1], f[3]
		}
		c1, ok1 := compareVersions(schemeGo, version, lo)
		c2, ok2 := compareVersions(schemeGo, version, hi)
		if ok1 && ok2 && c1 >= 0 && c2 <= 0 {
			return d
		}
	}
	return ""
}

// goRuntimeFor is the lowest supported Go of the runtime table that is at
// least need.
func goRuntimeFor(need goRelease, now time.Time) (worker.RuntimeSpec, bool) {
	var best worker.RuntimeSpec
	var bestV goRelease
	found := false
	for _, rt := range worker.Runtimes() {
		if rt.Kind != worker.KindGolang || !rt.HasImage() || rt.EndOfLife(now) {
			continue
		}
		v, ok := parseGoRelease(rt.Version)
		if !ok || v.compare(need) < 0 {
			continue
		}
		if !found || v.compare(bestV) < 0 {
			best, bestV, found = rt, v, true
		}
	}
	return best, found
}

// checkGoResult checks the go.mod and go.sum an update returned:
//
//   - go.mod changed only in its requirements and its go and toolchain
//     lines, nothing went down or away, and the go and toolchain lines are
//     at most the Go the running binaries were built with;
//   - every target is at or above its target and meets every fix;
//   - go.sum agrees with the checksum database on every line that is new
//     and on both hashes of every version that moved, and is completed with
//     those it lacks;
//   - every move is explained by the targets' requirements, and the written
//     versions meet the moved modules' requirements;
//   - the original and the updated go.mod, scanned under the cycle's
//     conditions, show the targets' vulnerabilities gone and no new one.
//
// Only the versions go.mod writes are scanned. A build with the go
// command's default -mod=readonly uses exactly those: one that needs a
// module go.mod does not write, or a higher version than it writes, stops
// with "updates to go.mod needed" instead of choosing one. The pull request
// says so, and asks for such a build.
func (r *updateRun) checkGoResult(ctx context.Context, reg GoModuleRegistry, before *goMod, newMod, newSum []byte) *updateFailure {
	if bytes.Equal(newMod, r.src.lock) {
		f := manualFailure(ReasonTargetNotUpdated, "the update left go.mod unchanged")
		f.lockUnchanged = true
		return f
	}
	after, err := parseGoMod(newMod)
	if err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "the updated go.mod cannot be read: %v", err)
	}
	if err := goModRefusal(after); err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "the updated go.mod: %v", err)
	}
	ch, err := diffGoMod(before, after)
	if err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "the updated go.mod: %v", err)
	}
	lf, err := goLockfile(after)
	if err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "the updated go.mod: %v", err)
	}
	if fail := r.checkVersions(lf); fail != nil {
		return fail
	}

	moved := ch.moved()
	sum, err := checkGoSumLines(ctx, reg, r.src.manifest, newSum, moved, r.spendGoLookup)
	if err != nil {
		return goFailure(ctx, err, ReasonDistributionMismatch)
	}
	graph, err := newGoModGraph(ctx, reg, r.u.goCache, sum.content)
	if err != nil {
		return manualFailure(ReasonOutputFilesInvalid, "%v", err)
	}
	why, err := explainGoMoves(graph, ch, r.goTargets)
	if err != nil {
		return goFailure(ctx, err, ReasonDistributionMismatch)
	}
	if why != "" {
		return manualFailure(ReasonUnexplainedDiff, "%s", why)
	}
	// A target that went past its version was raised by another one's
	// requirement; that version must not be retracted either.
	for _, p := range goSortedKeys(r.goTargets) {
		if v := moved[p]; v != "" && v != r.goTargets[p] {
			if d := goRetraction(r.goRetracts[p], v); d != "" {
				return pkgFailure(p, ReasonGoRetracted, "%s@%s, which the update moved to, is retracted (%s)", p, v, d)
			}
		}
	}
	need, err := goLineNeeded(graph, moved)
	if err != nil {
		return goFailure(ctx, err, ReasonOutputFilesInvalid)
	}
	if fail := r.checkGoLines(ch, need); fail != nil {
		return fail
	}

	r.newLock, r.manifest = newMod, sum.content
	rec := &GoUpdate{GoBefore: ch.goBefore, GoAfter: ch.goAfter, ToolchainBefore: ch.tcBefore, ToolchainAfter: ch.tcAfter, SumAdded: sum.added}
	for _, p := range goSortedKeys(moved) {
		if r.set.targets[p] {
			continue
		}
		m := GoModuleMove{Path: p, To: moved[p]}
		if v, ok := ch.raised[p]; ok {
			m.From = v[0]
		}
		rec.Collateral = append(rec.Collateral, m)
	}
	r.upd.Go = rec
	// go.sum is not scanned: a scanner takes its lines of versions no longer
	// required for dependencies.
	return r.sourceCheck(ctx, map[string][]byte{"go.mod": r.src.lock}, map[string][]byte{"go.mod": newMod})
}

// checkGoLines checks the go and toolchain lines of an update:
//
//   - the go line may go up only to the highest go line of the versions the
//     update moved to (need), exactly, which is what go get raises it to;
//   - the Go the lines ask for together (the higher of the go line and the
//     toolchain line) must not go down, a toolchain line taken away
//     included;
//   - a line that changed is at most the Go the running binaries were built
//     with (the lowest of them): raising the Go a project needs past the Go
//     it is built with is not this update's to decide.
func (r *updateRun) checkGoLines(ch *goModChange, need goRelease) *updateFailure {
	b, _ := parseGoRelease(ch.goBefore)
	a, ok := parseGoRelease(ch.goAfter)
	if !ok || a.compare(b) < 0 {
		return manualFailure(ReasonOutputFilesInvalid, "the update changed the go line from %s to %s", ch.goBefore, ch.goAfter)
	}
	if a.compare(b) > 0 && a.compare(need) != 0 {
		return manualFailure(ReasonUnexplainedDiff, "the update raised the go line to %s, not to go %s, the highest the versions it moved to declare", ch.goAfter, need)
	}
	effective := func(goLine goRelease, tc string) goRelease {
		if t, ok := parseGoRelease(tc); ok && t.compare(goLine) > 0 {
			return t
		}
		return goLine
	}
	if effective(a, ch.tcAfter).compare(effective(b, ch.tcBefore)) < 0 {
		return manualFailure(ReasonOutputFilesInvalid, "the update lowered the Go go.mod asks for (go %s, toolchain %q, now go %s, toolchain %q)", ch.goBefore, ch.tcBefore, ch.goAfter, ch.tcAfter)
	}
	if ch.goAfter == ch.goBefore && ch.tcAfter == ch.tcBefore {
		return nil
	}
	ceiling, known := parseGoRelease(r.it.GoBuiltWith)
	for _, line := range []struct{ name, before, after string }{{"go", ch.goBefore, ch.goAfter}, {"toolchain", ch.tcBefore, ch.tcAfter}} {
		if line.after == line.before || line.after == "" {
			continue
		}
		v, ok := parseGoRelease(line.after)
		switch {
		case !ok:
			return manualFailure(ReasonOutputFilesInvalid, "the update set the %s line to %q", line.name, line.after)
		case !known:
			return manualFailure(ReasonGoLineRaised, "the update changes the %s line from %q to %s, and the Go the running binaries were built with is not known", line.name, line.before, line.after)
		case v.compare(ceiling) > 0:
			return manualFailure(ReasonGoLineRaised, "the update raises the %s line to %s, above Go %s, which the running binaries were built with", line.name, line.after, ceiling)
		}
	}
	return nil
}
