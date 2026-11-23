package notify

import (
	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// The base image of the Dockerfile that builds a running image is the second
// source of a card's action line. A finding is tied to it in one of three
// ways, each with its own evidence:
//   - it is a target of the Dockerfile item: a fixed finding in a layer of
//     the base the running image's layers start with (base);
//   - the floating tag of the base moved, and the plan compared the running
//     image with the tag's current content place by place (rebuilt);
//   - a merged pull request of this tool set the base, and the finding is
//     one that pull request was made to resolve (mergedWait).

// baseEntry is what a Dockerfile item says about one target of one of its
// running images: the target's outcome in the image's comparison, "" without
// one, and the base layers the target was reported in.
type baseEntry struct {
	item    *remediation.DockerfileItem
	ent     *remediation.DockerfileEntity
	outcome remediation.Outcome
	layers  []string
}

// buildEntry is a Dockerfile item and its part for one running image.
type buildEntry struct {
	item *remediation.DockerfileItem
	ent  *remediation.DockerfileEntity
}

// indexBases indexes the running images of the Dockerfile items and their
// targets.
func (x *cardActionIndex) indexBases() {
	for i := range x.plan.DockerfileItems {
		it := &x.plan.DockerfileItems[i]
		for j := range it.Entities {
			e := &it.Entities[j]
			if e.Running.Ref == "" || e.Running.Entity == "" || e.Running.Entity == remediation.Unconfirmed {
				continue
			}
			bk := [2]string{e.Running.Ref, e.Running.Entity}
			x.builds[bk] = append(x.builds[bk], buildEntry{item: it, ent: e})
			for _, t := range e.Targets {
				var outcome remediation.Outcome
				if e.Comparison != nil {
					for _, v := range e.Comparison.Verdicts {
						if v.VulnID == t.VulnID && v.Package == t.Package {
							outcome = v.Outcome
						}
					}
				}
				k := baseWaitKey{image: e.Running.Ref, entity: e.Running.Entity, vuln: t.VulnID, coord: t.Package}
				x.bases[k] = append(x.bases[k], baseEntry{item: it, ent: e, outcome: outcome, layers: t.Layers})
			}
		}
	}
}

// base is the action of a group from the base image of the Dockerfile that
// builds the running image, or nil when it has none: the Dockerfile part
// ties none of the group's fixed findings to the base, ties them only in
// part or to more than one base, or has nothing to say of them. The running
// image's own tag is asked then, which keeps its own rule for a finding the
// base holds.
func (x *cardActionIndex) base(img analyze.ImageFindings, entity string, g analyze.PackageGroup) *cardAction {
	coord := remediation.PackageCoord{Ecosystem: g.Ecosystem, Class: g.Class, Name: g.Package}
	vulns := fixedVulns(g)
	var hit *baseEntry
	layers := map[string]bool{}
	found, resolved, remaining, unlayered := 0, 0, 0, 0
	for _, id := range vulns {
		es := x.bases[baseWaitKey{image: img.Image, entity: entity, vuln: id, coord: coord}]
		if len(es) == 0 {
			continue
		}
		found++
		if len(es) != 1 || (hit != nil && (hit.item != es[0].item || hit.ent != es[0].ent)) {
			return nil
		}
		hit = &es[0]
		for _, l := range es[0].layers {
			layers[l] = true
		}
		if len(es[0].layers) == 0 {
			unlayered++
		}
		switch es[0].outcome {
		case remediation.OutcomeResolved:
			resolved++
		case remediation.OutcomeRemaining:
			remaining++
		}
	}
	if found == 0 {
		return x.rebuilt(img, entity, g, vulns)
	}
	if found != len(vulns) || x.inFiles(entity, g, vulns) {
		return nil
	}
	// Every layer the group's findings were attributed to is a base layer
	// the targets were reported in: a copy of the package in a later layer
	// is not the base's to fix. A language runtime has no layer; the plan
	// took it for the base's by the version both declare, and that holds
	// for a group all of whose targets came that way.
	if len(g.LayerDiffIDs) == 0 {
		return nil
	}
	runtime := inventory.RuntimeVersionEnv(g.Ecosystem) != "" && unlayered == found
	for _, l := range g.LayerDiffIDs {
		if (l == "" && !runtime) || (l != "" && !layers[l]) {
			return nil
		}
	}
	it, e := hit.item, hit.ent
	if e.CurrentBase == nil {
		return nil
	}
	name, tag := baseNameTag(*e.CurrentBase)
	if name == "" || tag == "" {
		return nil
	}
	a := &cardAction{Base: true, Name: name, Tag: tag, Resolved: resolved, Total: len(vulns)}
	if e.CandidateBase != nil {
		a.To = e.CandidateBase.Tag
	}
	// judged says the running image's comparison gives every finding of the
	// card an outcome the line can state.
	judged := e.Comparison != nil && a.To != "" && resolved+remaining == len(vulns)
	outcome := func() cardActionKind {
		switch {
		case resolved == 0:
			return actImageRemains
		case remaining == 0:
			return actImageResolved
		}
		return actImagePartial
	}
	pinned, floating := it.BaseKind == remediation.TagPinned, it.BaseKind == remediation.TagFloating
	// The item says whether the update is proposed: it is only when every
	// running image of the Dockerfile adopts the same candidate.
	switch it.Category {
	case remediation.CategoryPRCandidate:
		if a.To == "" {
			return nil
		}
		if !judged {
			a.Kind = actImageUnknown
			return a
		}
		if a.Kind = outcome(); a.Kind == actImageRemains {
			return a
		}
		pr, ok := prClauseOfItem(x.plan, remediation.PRItemKindDockerfile, it.Key)
		if !ok {
			return nil
		}
		a.PR = pr
		return a
	case remediation.CategoryManual:
		if it.Reason == "" {
			return nil
		}
		a.Why = it.Reason
		a.Kind = actBaseDecision
		if judged {
			a.Kind = outcome()
		}
		return a
	}
	// Any other item has one outcome for all its running images, which the
	// image's own part states with its own reason.
	switch e.Category {
	case remediation.CategoryNoCandidate:
		switch {
		case floating && e.Reason == remediation.ReasonBaseUnchanged && remediation.IsCommitTag(tag):
			a.Kind = actCommitTag
		case floating && e.Reason == remediation.ReasonBaseUnchanged:
			a.Kind = actBaseUnchanged
		case !pinned:
			return nil
		case it.NewerSeries != nil && e.NewerSeries != nil && it.NewerSeries.Status != remediation.NewerSeriesNone:
			// What the check of newer series found is the waits' to state.
			return nil
		case e.Reason == remediation.ReasonSameContent:
			a.Kind = actTagWaitSameContent
		case e.Reason == remediation.ReasonCandidateNotFixing && judged && resolved == 0:
			a.Kind = actTagWaitNotFixed
		default:
			return nil
		}
	case remediation.CategoryExcluded, remediation.CategoryNotComparable, remediation.CategoryFailed, remediation.CategoryDeferred:
		if e.Reason == "" {
			return nil
		}
		a.Why = e.Reason
		switch e.Category {
		case remediation.CategoryExcluded:
			a.Kind = actNotChecked
		case remediation.CategoryDeferred:
			a.Kind = actCheckLater
		default:
			a.Kind = actCheckFailed
		}
	default:
		return nil
	}
	return a
}

// rebuilt is the action of a group none of whose fixed findings is a target
// of the Dockerfile part, from what the part knows of the running image
// without them: the comparison with the current content of a floating base
// that moved, or the merged pull request that set the base.
func (x *cardActionIndex) rebuilt(img analyze.ImageFindings, entity string, g analyze.PackageGroup, vulns []string) *cardAction {
	bs := x.builds[[2]string{img.Image, entity}]
	if len(bs) != 1 || len(vulns) == 0 {
		return nil
	}
	it, e := bs[0].item, bs[0].ent
	var a *cardAction
	switch {
	case it.AwaitingDeploy != nil:
		a = mergedWait(it.AwaitingDeploy, img.Image+"|"+entity, g, vulns)
	case e.Reason == remediation.ReasonFloatingBaseUnconfirmed:
		a = rebuildAction(e, g, vulns)
	}
	if a != nil && x.inFiles(entity, g, vulns) {
		return nil
	}
	return a
}

// mergedWait is the action of a group all of whose fixed findings the merged
// pull request m was made to resolve for the running image id, in the layers
// the group's findings were attributed to.
func mergedWait(m *remediation.BaseUpdateMerged, id string, g analyze.PackageGroup, vulns []string) *cardAction {
	coord := remediation.PackageCoord{Ecosystem: g.Ecosystem, Class: g.Class, Name: g.Package}
	layers := map[string]bool{}
	found := 0
	for _, v := range vulns {
		hit := false
		for _, ft := range m.FixTargets {
			if ft.VulnID != v || ft.Package != coord {
				continue
			}
			for _, e := range ft.Entities {
				if e == id {
					hit = true
					for _, l := range ft.Layers {
						layers[l] = true
					}
				}
			}
		}
		if hit {
			found++
		}
	}
	if found != len(vulns) || len(g.LayerDiffIDs) == 0 {
		return nil
	}
	for _, l := range g.LayerDiffIDs {
		if l == "" || !layers[l] {
			return nil
		}
	}
	return &cardAction{Kind: actBaseMergedWait, Base: true,
		PR: prClause{Kind: prMergedRebuild, PRs: []prRef{{Number: m.Number, URL: m.URL}}}}
}

// rebuildVerdict is what the current content of a moved base shows for one
// finding in one place.
type rebuildVerdict int

const (
	rebuildUnknown rebuildVerdict = iota
	rebuildGone
	rebuildRemains
	rebuildNotInBase
)

// rebuildPlaceKey identifies a finding of a package version in one place, as
// the comparison with the current base records it.
type rebuildPlaceKey struct {
	typ, name, version, path, vuln string
	class                          inventory.PkgClass
}

// rebuildAction is the action of a group from the comparison of the running
// image e with the current content of its base. Every fixed finding of the
// group needs one verdict, the same in every place the group's package is
// in; findings that are gone and findings that remain make a part.
func rebuildAction(e *remediation.DockerfileEntity, g analyze.PackageGroup, vulns []string) *cardAction {
	if e.CurrentBase == nil {
		return nil
	}
	verdicts := map[string]rebuildVerdict{}
	if inventory.RuntimeVersionEnv(g.Ecosystem) != "" {
		// A language runtime is compared by the version the base declares.
		var rr *remediation.RuntimeRebuild
		for i := range e.RebuildRuntimes {
			if r := &e.RebuildRuntimes[i]; r.Package == g.Package && r.Installed == g.InstalledVer {
				if rr != nil {
					return nil
				}
				rr = r
			}
		}
		if rr == nil {
			return nil
		}
		for _, v := range rr.Disappearing {
			verdicts[v] = rebuildGone
		}
		for _, v := range rr.Remaining {
			verdicts[v] = rebuildRemains
		}
	} else {
		c := e.RebuildCheck
		if c == nil || c.Status == remediation.RebuildNotChecked {
			return nil
		}
		at := map[rebuildPlaceKey]rebuildVerdict{}
		clash := map[rebuildPlaceKey]bool{}
		add := func(ps []remediation.RebuildPackage, verdict rebuildVerdict) {
			for _, p := range ps {
				if p.Ecosystem != g.Ecosystem || p.Class != g.Class || p.Name != g.Package || p.Version != g.InstalledVer {
					continue
				}
				for _, v := range p.VulnIDs {
					k := rebuildPlaceKey{typ: p.Type, class: p.Class, name: p.Name, version: p.Version, path: p.Path, vuln: v}
					if have, ok := at[k]; ok && have != verdict {
						clash[k] = true
					}
					at[k] = verdict
				}
			}
		}
		add(c.Gone, rebuildGone)
		add(c.Remaining, rebuildRemains)
		add(c.NotInBase, rebuildNotInBase)
		if len(at) == 0 {
			return nil
		}
		// The places of the group's package: an OS package has one by its
		// name, a language package the file that reports it.
		type place struct{ typ, path string }
		var places []place
		for _, in := range g.Instances {
			p := place{typ: in.Type}
			if g.Class != inventory.ClassOS {
				if p.path = in.PkgPath; p.path == "" {
					p.path = in.Target
				}
			}
			dup := false
			for _, have := range places {
				dup = dup || have == p
			}
			if !dup {
				places = append(places, p)
			}
		}
		if len(places) == 0 {
			return nil
		}
		for _, v := range vulns {
			for i, p := range places {
				k := rebuildPlaceKey{typ: p.typ, class: g.Class, name: g.Package, version: g.InstalledVer, path: p.path, vuln: v}
				verdict, ok := at[k]
				if !ok || clash[k] || (i > 0 && verdicts[v] != verdict) {
					return nil
				}
				verdicts[v] = verdict
			}
		}
	}
	counts := map[rebuildVerdict]int{}
	for _, v := range vulns {
		verdict, ok := verdicts[v]
		if !ok {
			return nil
		}
		counts[verdict]++
	}
	name, tag := baseNameTag(*e.CurrentBase)
	if name == "" || tag == "" {
		return nil
	}
	a := &cardAction{Base: true, Name: name, Tag: tag, Resolved: counts[rebuildGone], Total: len(vulns)}
	switch total := len(vulns); {
	case counts[rebuildGone] == total:
		a.Kind = actRebuildResolved
	case counts[rebuildRemains] == total:
		a.Kind = actRebuildRemains
	case counts[rebuildNotInBase] == total:
		a.Kind = actRebuildNotInBase
	case counts[rebuildGone]+counts[rebuildRemains] == total:
		a.Kind = actRebuildPartial
	default:
		return nil
	}
	return a
}
