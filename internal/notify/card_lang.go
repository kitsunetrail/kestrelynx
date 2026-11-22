package notify

import (
	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// The dependency files that install a language package are the first source
// of a card's action line: when the plan matched the card's findings against
// them, what became of the package's update says most about how the findings
// get fixed. A package they cannot reach at all (langOutOfReach) is not
// theirs: the base image and the image's own tag are asked first, and what
// the files say of it comes last.

// langEntry is a language item and the package of it one finding came from.
type langEntry struct {
	item *remediation.LanguageItem
	pkg  *remediation.LanguagePackage
}

// langOutOfReach are the reasons of a package no change of the dependency
// files reaches: the files do not hold it at the version that runs, or what
// fixes it is elsewhere. Each is given to one package by what the files and
// the image show of that package; a reason that also stands for files that
// could not be compared with the image is not among them.
var langOutOfReach = map[remediation.Reason]bool{
	remediation.ReasonNotFoundInSource: true,
	remediation.ReasonJarBundled:       true,
	remediation.ReasonGoStdlib:         true,
}

// outOfReach reports whether no change of the dependency files reaches the
// package. A copy bundled in another archive is known to be one only where
// the finding names the archive it was reported in: a finding without a
// place is not shown to be out of reach.
func outOfReach(p *remediation.LanguagePackage) bool {
	if p.Action != remediation.ActionManual || p.LeftOut || !langOutOfReach[p.Reason] {
		return false
	}
	if p.Reason == remediation.ReasonJarBundled {
		for _, o := range p.Origins {
			if o.PkgPath == "" {
				return false
			}
		}
	}
	return true
}

// lang is the action of a group all of whose fixed findings came from one
// package of one language item; nil when they did not, or the item says
// nothing the line can state. last says the action is of a package the
// dependency files cannot reach, to be used when no other source has one.
func (x *cardActionIndex) lang(entity string, g analyze.PackageGroup) (a *cardAction, last bool) {
	vulns := fixedVulns(g)
	var hit *langEntry
	for _, id := range vulns {
		es := x.langs[actionKey{entity: entity, ecosystem: string(g.Ecosystem), class: string(g.Class), name: g.Package, version: g.InstalledVer, vuln: id}]
		if len(es) != 1 || (hit != nil && *hit != es[0]) {
			return nil, false
		}
		hit = &es[0]
	}
	if hit == nil {
		return nil, false
	}
	li, p := hit.item, hit.pkg
	a = &cardAction{File: li.Manager.LockfileName()}
	// The pull request of the item's update, when it has one, says what the
	// update does to the package.
	if u := languageUnitOf(*li, x.plan.PullRequests); u != nil && u.Number > 0 && pullRequestsOn(x.plan) {
		if done := langInPullRequest(a, u, p); done {
			return a, false
		}
	}
	switch p.Action {
	case remediation.ActionUpdate:
		switch li.Category {
		case remediation.CategoryPRCandidate:
			if p.AdoptedVersion == "" {
				return nil, false
			}
			pr, ok := prClauseOfItem(x.plan, remediation.PRItemKindLanguage, li.Key)
			// A pull request that exists is stated with what it holds, above:
			// here it could not be read for the package.
			if !ok || len(pr.PRs) > 0 {
				return nil, false
			}
			a.Kind, a.To, a.PR = actLangCandidate, p.AdoptedVersion, pr
		case remediation.CategoryDependencyUpdateCandidate:
			if p.SelectionLowerBound == "" {
				return nil, false
			}
			a.Kind, a.To = actLangCandidateAtLeast, p.SelectionLowerBound
			if pullRequestsOn(x.plan) {
				a.PR = prClause{Kind: prNotCreated, Reason: remediation.ReasonDependencyUpdateNotVerified}
			}
		case remediation.CategoryDeferred:
			if li.Reason == "" {
				return nil, false
			}
			a.Kind, a.Why = actLangItemLater, li.Reason
		case remediation.CategoryManual, remediation.CategoryNotComparable, remediation.CategoryFailed:
			if li.Reason == "" {
				return nil, false
			}
			a.Kind, a.Why = actLangItemFailed, li.Reason
		default:
			return nil, false
		}
	case remediation.ActionRebuildExpected:
		if p.SelectionLowerBound == "" {
			return nil, false
		}
		a.Kind, a.To = actLangRebuild, p.SelectionLowerBound
	case remediation.ActionManual:
		if p.Reason == "" {
			return nil, false
		}
		a.Why = p.Reason
		switch {
		case outOfReach(p):
			a.Kind = actLangOutOfReach
			return a, true
		case langOutOfReach[p.Reason] && !p.LeftOut:
			// The reason says the files cannot reach the package, and the
			// findings do not show it: nothing is stated.
			return nil, false
		case !p.LeftOut && p.Reason == li.Reason && itemStopped(li):
			// The package has the reason the whole item stopped for.
			a.Kind = actLangItemFailed
		default:
			a.Kind = actLangNotAutomatic
		}
	case "":
		// The files were not matched for the package: the item's outcome is
		// all there is.
		if li.Reason == "" {
			return nil, false
		}
		a.Why = li.Reason
		switch {
		case li.Category == remediation.CategoryDeferred:
			a.Kind = actLangItemLater
		case itemStopped(li):
			a.Kind = actLangItemFailed
		default:
			return nil, false
		}
	default:
		return nil, false
	}
	return a, false
}

// itemStopped reports whether the item as a whole could not be updated.
func itemStopped(li *remediation.LanguageItem) bool {
	switch li.Category {
	case remediation.CategoryManual, remediation.CategoryNotComparable, remediation.CategoryFailed:
		return true
	}
	return false
}

// pullRequestsOn reports whether this cycle's plan had pull requests on.
func pullRequestsOn(plan *remediation.Plan) bool {
	return plan.PullRequestsEnabled != nil && *plan.PullRequestsEnabled
}

// langInPullRequest fills a with what the pull request of unit u does to
// package p, and reports whether it says anything of it: the version it
// updates the package to, why it leaves the package out, or that what it
// holds is not known.
func langInPullRequest(a *cardAction, u *remediation.PRUnit, p *remediation.LanguagePackage) bool {
	pr := prClause{Kind: prExists, PRs: []prRef{{Number: u.Number, URL: u.URL}}}
	if u.Language == nil || u.UserModified {
		// What the pull request holds is not known: it has no record of its
		// packages, or a person changed it.
		if p.Action != remediation.ActionUpdate {
			return false
		}
		a.Kind, a.Why = actLangUnconfirmed, u.Reason
		if u.UserModified {
			a.Why = remediation.ReasonPullNotAsCreated
		}
		return true
	}
	for _, r := range u.Language.Remaining {
		if r.Name == p.Name && r.Ecosystem == p.Ecosystem && r.From == p.Installed {
			if r.Reason == "" {
				return false
			}
			a.Kind, a.Why = actLangNotAutomatic, r.Reason
			return true
		}
	}
	for _, up := range u.Language.Packages {
		if up.Name != p.Name || up.Ecosystem != p.Ecosystem || up.From != p.Installed {
			continue
		}
		if up.To == "" {
			return false
		}
		a.Kind, a.To, a.PR = actLangInPR, up.To, pr
		switch u.Status {
		case remediation.PRStatusMerged:
			a.PR.Kind = prMergedRunning
		case remediation.PRStatusSuppressed:
			a.PR.Kind = prClosed
			if u.ReplacedBy > 0 {
				a.PR.Kind, a.PR.Replaced = prReplaced, prRef{Number: u.ReplacedBy}
			}
		}
		return true
	}
	return false
}
