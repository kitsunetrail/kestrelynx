package remediation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// runPip updates the pinned lines of a requirements.txt. The file is not a
// lockfile, so there is no tool to run for the update: this stage rewrites the
// lines of the packages in the set (the version, and the hashes of a line that
// has them, taken from the release's wheels on PyPI) and has the work image
// resolve the original and the rewritten file with pip for the environment the
// image runs in.
func (r *updateRun) runPip(ctx context.Context) *updateFailure {
	it := r.it
	orig := r.src.lock

	if len(r.set.names) > worker.MaxPackages {
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdatePackageLimit,
			detail: fmt.Sprintf("the update names %d packages, more than the %d one job takes", len(r.set.names), worker.MaxPackages)}
	}
	var pkgs []LanguagePackage
	for _, i := range r.set.idx {
		pkgs = append(pkgs, it.Packages[i])
	}
	target, undecided, mismatch, why := pipTargetOf(pkgs, r.u.cfg.Images)
	switch {
	case undecided:
		return manualFailure(ReasonPipTargetUndecidable, "the environment pip resolves for cannot be decided: %s", why)
	case mismatch:
		return manualFailure(ReasonPipTargetMismatch, "%s", why)
	}
	// pip runs in the default Python image whatever the target is, but an
	// update for a Python past the end of its support is not made.
	if spec, past := pythonPastSupport(target.PythonVersion, r.u.now()); past {
		return runtimeEOLFailure(spec)
	}

	edits, fail := r.pipEdits()
	if fail != nil {
		return fail
	}
	lines := splitReqLines(orig)
	// Hashes of the wheels of each release, for the lines that carry hashes.
	fetched := map[string][]string{}
	for i := range edits {
		if !requirementHasHashes(lines, edits[i].Line) {
			continue
		}
		key := edits[i].Name + "==" + edits[i].NewVersion
		hs, ok := fetched[key]
		if !ok {
			var f *updateFailure
			if hs, f = r.wheelHashesOf(ctx, edits[i].Name, edits[i].NewVersion); f != nil {
				return f
			}
			fetched[key] = hs
		}
		edits[i].Hashes = hs
	}
	requireHashes := requirementsHaveHashes(orig)

	newLock, err := rewriteLines(ctx, orig, lines, edits)
	if err == nil {
		err = verifyRewrite(orig, newLock, edits)
	}
	switch {
	case errors.Is(err, errRewriteLimit):
		return &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit, detail: err.Error()}
	case err != nil && ctx.Err() != nil:
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	case err != nil:
		return manualFailure(ReasonRequirementsRewrite, "%v", err)
	}
	if bytes.Equal(newLock, orig) {
		return manualFailure(ReasonTargetNotUpdated, "the rewrite left requirements.txt unchanged")
	}
	it.UpdateExecuted = true

	baseStep := worker.Step{ID: stepBaseline, Op: worker.OpPipDryRun, Scratch: true, RequireHashes: requireHashes, Target: target}
	baseOut, fail := r.exec(ctx, worker.ManagerPip, map[string][]byte{"requirements.txt": orig}, []worker.Step{baseStep}, "base")
	if fail != nil {
		if fail.reason == ReasonLockfileInconsistent {
			fail.detail = "the original requirements.txt does not resolve for the image's environment: " + fail.detail
		}
		return fail
	}
	reportBefore, ok := baseOut.stepFile(stepBaseline, worker.PipReportName)
	if !ok {
		return failedFailure(ReasonUpdateResultInvalid, "the baseline step returned no pip report")
	}

	checkStep := worker.Step{ID: stepCheck, Op: worker.OpPipDryRun, Scratch: true, RequireHashes: requireHashes, Target: target}
	out, fail := r.exec(ctx, worker.ManagerPip, map[string][]byte{"requirements.txt": newLock}, []worker.Step{checkStep}, "check")
	if fail != nil {
		if fail.reason == ReasonPostUpdateCheckFailed {
			if held := r.pipHeldBack(ctx, reportBefore, orig, target); held != nil {
				return held
			}
		}
		return fail
	}
	it.PostUpdateCheckExecuted = true
	if final, ok := out.finalFile("requirements.txt"); !ok || !bytes.Equal(final, newLock) {
		return manualFailure(ReasonOutputFilesInvalid, "the check changed requirements.txt")
	}
	reportAfter, ok := out.stepFile(stepCheck, worker.PipReportName)
	if !ok {
		return failedFailure(ReasonUpdateResultInvalid, "the check step returned no pip report")
	}

	chkBefore, fail := r.checkPipReport(ctx, reportBefore, orig, target)
	if fail != nil {
		return fail
	}
	chkAfter, fail := r.checkPipReport(ctx, reportAfter, newLock, target)
	if fail != nil {
		return fail
	}
	gb, err1 := pipGraph(ctx, reportBefore, chkBefore.requires, chkBefore.roots)
	ga, err2 := pipGraph(ctx, reportAfter, chkAfter.requires, chkAfter.roots)
	if err1 != nil || err2 != nil {
		if ctx.Err() != nil {
			return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
		}
		return manualFailure(ReasonOutputFilesInvalid, "the pip report cannot be read: %v", errors.Join(err1, err2))
	}
	diff, reason, detail := diffGraphs(ctx, gb, ga, r.targetSet())
	r.upd.Diff = &diff
	if ctx.Err() != nil {
		return &updateFailure{category: CategoryDeferred, reason: ReasonCycleDeadline, detail: ctx.Err().Error()}
	}
	if reason != "" {
		return manualFailure(reason, "%s", detail)
	}
	for _, n := range r.set.names {
		node := ga.nodes[n]
		if node == nil || !versionsEqual(schemePEP440, node.version, r.set.target[n]) {
			got := ""
			if node != nil {
				got = node.version
			}
			return manualFailure(ReasonTargetNotUpdated, "pip resolves %s to %q, not the pinned %s", n, got, r.set.target[n])
		}
	}
	return r.verifyAndScan(ctx, newLock)
}

// pipEdits lists the requirement lines to rewrite: every occurrence of an
// updated package at the version the image runs, with the name it must have.
func (r *updateRun) pipEdits() ([]reqEdit, *updateFailure) {
	var edits []reqEdit
	seen := map[int]bool{}
	for _, i := range r.set.idx {
		p := r.it.Packages[i]
		for _, o := range p.Occurrences {
			if !o.Matched {
				continue
			}
			line, err := occurrenceLine(o.Path)
			if err != nil {
				return nil, failedFailure(ReasonUpdateInputInvalid, "%s: %v", p.Name, err)
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			edits = append(edits, reqEdit{Name: p.matchName(), Line: line, OldVersion: o.Version, NewVersion: p.SelectionLowerBound})
		}
	}
	if len(edits) == 0 {
		return nil, failedFailure(ReasonUpdateInputInvalid, "no requirement line is to be updated")
	}
	return edits, nil
}

// occurrenceLine reads the line number of a "requirements.txt:N" occurrence.
func occurrenceLine(path string) (int, error) {
	i := strings.LastIndexByte(path, ':')
	if i < 0 {
		return 0, fmt.Errorf("the occurrence %q has no line number", path)
	}
	n, err := strconv.Atoi(path[i+1:])
	if err != nil || n < 1 {
		return 0, fmt.Errorf("the occurrence %q has no line number", path)
	}
	return n, nil
}

// requirementsHaveHashes reports whether any requirement of the file carries
// a --hash option; pip then requires a hash for every requirement.
func requirementsHaveHashes(data []byte) bool {
	for _, l := range splitReqLines(data) {
		if reqHashTokRE.MatchString(pipCommentRE.ReplaceAllString(l.text, "")) {
			return true
		}
	}
	return false
}

// wheelHashesOf returns the sha256 of every wheel of a release. A release the
// index does not know, one with no wheel or one with a yanked file is left to a
// person: the hashes would be of files that cannot be installed as pinned.
func (r *updateRun) wheelHashesOf(ctx context.Context, name, ver string) ([]string, *updateFailure) {
	rel, err := r.pyRelease(ctx, name, ver)
	pkg := func(reason Reason, format string, args ...any) *updateFailure {
		return pkgFailure(name, reason, format, args...)
	}
	switch {
	case errors.Is(err, ErrReleaseNotFound):
		return nil, pkg(ReasonNoWheelForVersion, "%s %s is not on PyPI", name, ver)
	case err != nil:
		return nil, lookupFailure(ctx, err, name+" "+ver+" on PyPI")
	}
	hs, yanked := wheelHashes(rel.Files)
	switch {
	case yanked:
		return nil, pkg(ReasonReleaseYanked, "%s %s has a yanked file on PyPI", name, ver)
	case len(hs) == 0:
		return nil, pkg(ReasonNoWheelForVersion, "%s %s has no wheel on PyPI, so no hash of an installable file can be pinned", name, ver)
	case len(hs) > maxWheelsPerEdit:
		return nil, &updateFailure{category: CategoryDeferred, reason: ReasonUpdateInputLimit,
			detail: fmt.Sprintf("%s %s has %d wheels, more than the %d hashes one requirement is given", name, ver, len(hs), maxWheelsPerEdit)}
	}
	return hs, nil
}

// pipHeldBack explains a check of the rewritten file that pip could not
// resolve, when the original file shows why: a package it pins asks, in the
// environment pip resolves for, for a package of the set at versions that
// leave out the version the set pins it to (a package of the set is not
// judged by what its current version asks for). Such a package is held back by
// the packages that depend on it, which this update does not move; it is left
// to a person with them recorded (see FixHint), and when other packages of the
// set are not held back the update is made again without it. nil when the
// original file shows no such requirement or cannot be read.
func (r *updateRun) pipHeldBack(ctx context.Context, reportBefore, orig []byte, target *worker.Target) *updateFailure {
	chk, fail := r.checkPipReport(ctx, reportBefore, orig, target)
	if fail != nil {
		return nil
	}
	// The requirements a package has in force for one package hold together,
	// so they are judged as one range.
	type edge struct{ parent, version, dep string }
	var order []edge
	ranges := map[edge][]string{}
	for _, e := range chk.edges {
		// What a package of the set asks for is that of the version it is
		// pinned to, which the original file does not show.
		if _, ok := r.set.target[e.dep]; !ok || r.set.targets[e.parent] {
			continue
		}
		k := edge{e.parent, e.version, e.dep}
		if _, seen := ranges[k]; !seen {
			order = append(order, k)
			ranges[k] = nil
		}
		if e.constraint != "" {
			ranges[k] = append(ranges[k], e.constraint)
		}
	}
	held := map[string][]FixHolder{}
	for _, k := range order {
		v, ok := parsePEP440(r.set.target[k.dep])
		if !ok {
			continue
		}
		rng := strings.Join(ranges[k], ",")
		if allowed, evaluable := pySatisfies(v, rng); allowed || !evaluable {
			continue
		}
		held[k.dep] = append(held[k.dep], FixHolder{Parent: k.parent, ParentVersion: k.version, Range: rng})
	}
	if len(held) == 0 {
		return nil
	}
	pkgs := map[string]updateFailureDetail{}
	var details []string
	for _, n := range r.set.names {
		hs, ok := held[n]
		if !ok {
			continue
		}
		detail := fmt.Sprintf("%s %s asks for %s %q, which leaves out %s", hs[0].Parent, hs[0].ParentVersion, n, hs[0].Range, r.set.target[n])
		if len(hs) > 1 {
			detail += fmt.Sprintf(", and %d more package(s) do so too", len(hs)-1)
		}
		pkgs[n] = updateFailureDetail{ReasonDependentsHoldBack, detail}
		details = append(details, detail)
		for _, k := range r.set.byName[n] {
			r.it.Packages[k].FixHint = &FixHint{HeldBy: append([]FixHolder(nil), hs...)}
		}
	}
	f := manualFailure(ReasonDependentsHoldBack, "pip cannot install the pinned versions next to the packages that depend on them: %s", strings.Join(details, "; "))
	if len(pkgs) < len(r.set.names) && r.attempt == 0 {
		f.retryWithout = pkgs
	} else {
		f.pkgs = pkgs
	}
	return f
}
