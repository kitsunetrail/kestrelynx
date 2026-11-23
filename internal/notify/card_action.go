package notify

import (
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// cardActionKind is what a card's action line says about its fixed findings,
// beyond the waits of card_basewait.go.
type cardActionKind int

const (
	// actImageResolved: the candidate tag of the running image's own series
	// resolves every fixed finding of the card.
	actImageResolved cardActionKind = iota
	// actImagePartial: it resolves some of them and the others remain.
	actImagePartial
	// actImageRemains: they all remain in the candidate tag.
	actImageRemains
	// actImageUnknown: the comparison could not judge one of them.
	actImageUnknown
	// actPullResolved: pulling the floating tag again, whose content is no
	// longer what runs, resolves every fixed finding of the card.
	actPullResolved
	// actPullPartial: it resolves some of them and the others remain.
	actPullPartial
	// actPullRemains: they all remain in the tag's content.
	actPullRemains
	// actPullUnknown: the comparison could not judge one of them.
	actPullUnknown
	// actImageDecision: a newer tag of the series is a person's to decide
	// on, and the plan does not say what it does to the card's findings.
	actImageDecision
	// actPullDecision: the same for pulling a floating tag again.
	actPullDecision
	// actContentSame: the floating tag still has the content that runs.
	actContentSame
	// actCommitTag: the tag names a commit and still has the content that
	// runs (or, for a base, the content the image was built from). No newer
	// content is to come under it, and no newer tag can be chosen by name.
	actCommitTag
	// actTagWaitNoNewer: the pinned tag's series has no newer tag, and newer
	// series were not looked at.
	actTagWaitNoNewer
	// actTagWaitSameContent: the newer tag of the series has the content
	// that runs.
	actTagWaitSameContent
	// actTagWaitNotFixed: the newer tag of the series resolves none of the
	// image's targets.
	actTagWaitNotFixed
	// actNotChecked: no newer version is looked up for the reference.
	actNotChecked
	// actCheckFailed: looking for one, or comparing it, did not work.
	actCheckFailed
	// actCheckLater: the look-up was left to a later run.
	actCheckLater
	// actGlobalBundled: the package is bundled with a package installed in a
	// global node_modules, which the dependency files do not install.
	actGlobalBundled
	// actGlobalSelf: the package is itself installed in a global
	// node_modules.
	actGlobalSelf
	// actBaseDecision: updating the base image of the Dockerfile is a
	// person's to decide on, and the plan does not say what it does to the
	// card's findings.
	actBaseDecision
	// actBaseUnchanged: the floating tag of the base still has the content
	// the image was built from.
	actBaseUnchanged
	// actRebuildResolved: the floating tag of the base moved, and its
	// current content has none of the card's fixed findings where the image
	// has them.
	actRebuildResolved
	// actRebuildPartial: it has some of them and not the others.
	actRebuildPartial
	// actRebuildRemains: it still has all of them.
	actRebuildRemains
	// actRebuildNotInBase: it has no package where the image has them.
	actRebuildNotInBase
	// actBaseMergedWait: a merged pull request set the base to one that
	// resolves the card's fixed findings, and the image was not rebuilt.
	actBaseMergedWait
	// actLangInPR: a pull request of the dependency files updates the
	// package; its state is in PR.
	actLangInPR
	// actLangCandidate: an update of the dependency files that was run and
	// checked takes the package to a version, and has no pull request.
	actLangCandidate
	// actLangCandidateAtLeast: the dependency files hold the package and a
	// version to update it to was chosen; no update was run.
	actLangCandidateAtLeast
	// actLangRebuild: the dependency files allow a fixed version, so a
	// rebuild is expected to install it.
	actLangRebuild
	// actLangOutOfReach: no change of the dependency files reaches the
	// package.
	actLangOutOfReach
	// actLangNotAutomatic: the package could not be updated automatically.
	actLangNotAutomatic
	// actLangItemFailed: the dependency files as a whole could not be
	// updated.
	actLangItemFailed
	// actLangItemLater: their update was left to a later run.
	actLangItemLater
	// actLangUnconfirmed: what the pull request of the dependency files
	// holds for the package is not known.
	actLangUnconfirmed
)

// prClauseKind is what a card's action line says about the pull request of
// the update it names.
type prClauseKind int

const (
	prNone prClauseKind = iota // nothing is said
	// prExists: the pull requests named are open, or exist in a state the
	// line does not put into words.
	prExists
	// prMergedRunning: merged, while the image the card is about still runs.
	prMergedRunning
	// prMergedRebuild: merged, while the image built from the Dockerfile it
	// changed was not rebuilt.
	prMergedRebuild
	prClosed   // closed without merging
	prReplaced // closed without merging in favour of another
	prModified // its content is not what was created
	// prNotCreated: an update unit exists and has no pull request, or the
	// stage did not get to it; Reason says why.
	prNotCreated
	// prWontCreate: no update unit is made for the item; Reason says why.
	prWontCreate
	// prUnconfirmed: a write was sent and its outcome is not known.
	prUnconfirmed
)

// prRef is one pull request a clause names.
type prRef struct {
	Number int
	URL    string
}

// prClause is the pull request part of an action line.
type prClause struct {
	Kind     prClauseKind
	PRs      []prRef // sorted by number
	Replaced prRef   // prReplaced: the pull request that replaced it
	Reason   remediation.Reason
	// Status stands for the reason of a unit that has none.
	Status string
}

// same reports whether two clauses say the same thing.
func (c prClause) same(o prClause) bool {
	if c.Kind != o.Kind || c.Replaced != o.Replaced || c.Reason != o.Reason || c.Status != o.Status || len(c.PRs) != len(o.PRs) {
		return false
	}
	for i := range c.PRs {
		if c.PRs[i] != o.PRs[i] {
			return false
		}
	}
	return true
}

// cardAction is the action line of a card that is not a wait: what a newer
// tag of the image's own series does to the card's findings and what became
// of its pull request, or why the dependency files cannot fix a package of a
// global node_modules.
type cardAction struct {
	Kind cardActionKind

	// Base says the line is about the base image of the Dockerfile that
	// builds the running image rather than about the running image's tag.
	Base bool
	// The image kinds: the short name and tag of the running image (or of
	// the base), the candidate tag, and how many of the card's fixed
	// findings it resolves.
	Name, Tag, To   string
	Resolved, Total int
	PR              prClause
	// Why is the reason a person decides on the update named, or the reason
	// of a line that says nothing else.
	Why remediation.Reason

	// The global kinds: the package installed in the global node_modules
	// (Owner; its version when the plan knows it), that directory, and the
	// dependency file of the item ("" when it names none).
	Owner, OwnerVersion string
	Dir, File           string
}

// actionKey identifies one fixed finding of a package version in one running
// entity.
type actionKey struct {
	entity    string
	ecosystem string
	class     string
	name      string
	version   string
	vuln      string
}

// globalEntry is one place a finding's package has in a global node_modules.
type globalEntry struct {
	item  string // the language item's key
	owner string
	self  bool
	dir   string
	file  string
}

// imageEntry is what the item of a running image says about one of its
// targets: the outcome is the target's in the item's comparison, "" without
// one.
type imageEntry struct {
	item    *remediation.Item
	outcome remediation.Outcome
}

// cardActionIndex finds the action line of a package group of a scanned
// image from this cycle's plan. Each finding is looked up in the sources of
// its fix in a fixed order, the most specific first: the dependency files
// that install the package, the base image of the Dockerfile, the running
// image's own tag. The nil index matches nothing.
type cardActionIndex struct {
	plan  *remediation.Plan
	waits *baseWaitIndex

	// globals are the findings of packages in a global node_modules; others
	// are those of every other package of a language item. langs gives the
	// item and package of each of the others, and owned are those among them
	// the dependency files can reach.
	globals map[actionKey][]globalEntry
	others  map[actionKey]bool
	langs   map[actionKey][]langEntry
	owned   map[actionKey]bool
	// ownerVersions are the versions of the packages installed in a global
	// node_modules, by language item, entity, directory and owner.
	ownerVersions map[[4]string][]string

	items map[baseWaitKey][]imageEntry
	// bases are the findings the Dockerfile part holds as targets of a base
	// image, with what it found for them.
	bases map[baseWaitKey][]baseEntry
	// builds are the running images a mapped Dockerfile builds, by reference
	// and entity, with the item and the running image's part of it.
	builds map[[2]string][]buildEntry
}

// newCardActionIndex indexes the plan of the cycle. It returns nil when there
// is no plan.
func newCardActionIndex(info *PlanInfo) *cardActionIndex {
	if info == nil || info.Plan == nil {
		return nil
	}
	x := &cardActionIndex{
		plan:          info.Plan,
		waits:         newBaseWaitIndex(info),
		globals:       map[actionKey][]globalEntry{},
		others:        map[actionKey]bool{},
		langs:         map[actionKey][]langEntry{},
		owned:         map[actionKey]bool{},
		ownerVersions: map[[4]string][]string{},
		items:         map[baseWaitKey][]imageEntry{},
		bases:         map[baseWaitKey][]baseEntry{},
		builds:        map[[2]string][]buildEntry{},
	}
	for i := range x.plan.LanguageItems {
		li := &x.plan.LanguageItems[i]
		file := li.Manager.LockfileName()
		for j := range li.Packages {
			p := &li.Packages[j]
			for _, o := range p.Origins {
				k := actionKey{entity: o.Entity, ecosystem: o.Ecosystem, class: o.Class, name: o.Name, version: o.Version, vuln: o.VulnID}
				owner, dir, self, ok := globalPlace(o.PkgPath)
				if p.Reason != remediation.ReasonGlobalNodeModules || !ok {
					x.others[k] = true
					if !outOfReach(p) {
						x.owned[k] = true
					}
					if e := (langEntry{item: li, pkg: p}); !containsLang(x.langs[k], e) {
						x.langs[k] = append(x.langs[k], e)
					}
					continue
				}
				e := globalEntry{item: li.Key, owner: owner, self: self, dir: dir, file: file}
				if !containsGlobal(x.globals[k], e) {
					x.globals[k] = append(x.globals[k], e)
				}
				if self {
					vk := [4]string{li.Key, o.Entity, dir, owner}
					x.ownerVersions[vk] = appendOnce(x.ownerVersions[vk], o.Version)
				}
			}
		}
	}
	x.indexBases()
	for i := range x.plan.Items {
		it := &x.plan.Items[i]
		if it.Current.Ref == "" || it.Current.Entity == "" || it.Current.Entity == remediation.Unconfirmed {
			continue
		}
		for _, t := range it.Targets {
			var outcome remediation.Outcome
			if it.Comparison != nil {
				for _, v := range it.Comparison.Verdicts {
					if v.VulnID == t.VulnID && v.Package == t.Package {
						outcome = v.Outcome
					}
				}
			}
			k := baseWaitKey{image: it.Current.Ref, entity: it.Current.Entity, vuln: t.VulnID, coord: t.Package}
			if e := (imageEntry{item: it, outcome: outcome}); !containsImage(x.items[k], e) {
				x.items[k] = append(x.items[k], e)
			}
		}
	}
	return x
}

func containsImage(list []imageEntry, e imageEntry) bool {
	for _, have := range list {
		if have == e {
			return true
		}
	}
	return false
}

func containsLang(list []langEntry, e langEntry) bool {
	for _, have := range list {
		if have == e {
			return true
		}
	}
	return false
}

func containsGlobal(list []globalEntry, e globalEntry) bool {
	for _, have := range list {
		if have == e {
			return true
		}
	}
	return false
}

// globalPlace reads the path of a node package in a global node_modules: the
// package installed there that it is part of, the directory as an absolute
// path, and whether the package is that installed package itself.
func globalPlace(pkgPath string) (owner, dir string, self, ok bool) {
	owner, ok = remediation.GlobalNodeModule(pkgPath)
	if !ok {
		return "", "", false, false
	}
	p := strings.Trim(pkgPath, "/")
	i := strings.Index("/"+p+"/", "/node_modules/")
	if i < 0 {
		return "", "", false, false
	}
	dir = "/" + p[:i] + "node_modules"
	rest := strings.TrimPrefix(p[i+len("node_modules"):], "/")
	self = strings.TrimSuffix(rest, "/package.json") == owner || rest == owner
	return owner, dir, self, true
}

// lookup returns the action of group g of the scanned entity img: a wait of
// card_basewait.go, an action of this file, of card_lang.go or of
// card_base.go, or neither. The sources are tried in order: the dependency
// files, the base image of the Dockerfile, the image's own tag. A global
// node_modules and the image's own tag end the search when they know the
// card's findings without being able to give one line for them. The
// dependency files and the base image pass a card they have no line for on;
// the sources after them leave out what the findings those hold make them
// unable to say.
func (x *cardActionIndex) lookup(img analyze.ImageFindings, g analyze.PackageGroup) (*baseWait, *cardAction) {
	if x == nil || img.Image == "" || !img.Subject.Resolved {
		return nil, nil
	}
	entity := remediation.EntityKeyString(img.Subject.Key)
	if entity == remediation.Unconfirmed {
		return nil, nil
	}
	if a, decided := x.global(entity, g); decided {
		return nil, a
	}
	files, last := x.lang(entity, g)
	if files != nil && !last {
		return nil, files
	}
	w, a := x.images(img, entity, g)
	if w == nil && a == nil {
		// What the dependency files say of a package they cannot reach.
		a = files
	}
	return w, a
}

// images is the action of group g from the images: the base image of the
// Dockerfile, then the running image's own tag.
func (x *cardActionIndex) images(img analyze.ImageFindings, entity string, g analyze.PackageGroup) (*baseWait, *cardAction) {
	if w, ok := x.waits.base(img, entity, g); ok {
		return &w, nil
	}
	if a := x.base(img, entity, g); a != nil {
		return nil, a
	}
	if a, decided := x.image(img, entity, g); decided {
		return nil, a
	}
	if w, ok := x.waits.own(img, entity, g); ok {
		return &w, nil
	}
	return nil, nil
}

// fixedVulns are the IDs of the fixed findings of a group.
func fixedVulns(g analyze.PackageGroup) []string {
	var out []string
	for _, v := range g.Vulns {
		if v.Status == scanner.StatusFixed {
			out = append(out, v.ID)
		}
	}
	return out
}

// global is the action of a group whose fixed findings are all of one place
// in a global node_modules. decided is false when none of them is of a
// global node_modules, so that the next source is asked; a group that mixes
// places, or whose package the dependency files hold as well, is decided
// without an action.
func (x *cardActionIndex) global(entity string, g analyze.PackageGroup) (a *cardAction, decided bool) {
	vulns := fixedVulns(g)
	var place *globalEntry
	found, mixed := 0, false
	for _, id := range vulns {
		k := actionKey{entity: entity, ecosystem: string(g.Ecosystem), class: string(g.Class), name: g.Package, version: g.InstalledVer, vuln: id}
		es := x.globals[k]
		if len(es) == 0 {
			continue
		}
		found++
		if len(es) != 1 || x.others[k] {
			mixed = true
			continue
		}
		if place == nil {
			place = &es[0]
		} else if *place != es[0] {
			mixed = true
		}
	}
	if found == 0 {
		return nil, false
	}
	if mixed || found != len(vulns) {
		return nil, true
	}
	a = &cardAction{Kind: actGlobalBundled, Owner: place.owner, Dir: place.dir, File: place.file}
	if place.self {
		a.Kind = actGlobalSelf
		return a, true
	}
	if vs := x.ownerVersions[[4]string{place.item, entity, place.dir, place.owner}]; len(vs) == 1 {
		a.OwnerVersion = vs[0]
	}
	return a, true
}

// image is the action of a group whose fixed findings are all targets of the
// item of the running image. decided is false when none of them is, or when
// the item's check of newer series is the waits' to state, so that the waits
// of the image's own tag are asked.
func (x *cardActionIndex) image(img analyze.ImageFindings, entity string, g analyze.PackageGroup) (a *cardAction, decided bool) {
	coord := remediation.PackageCoord{Ecosystem: g.Ecosystem, Class: g.Class, Name: g.Package}
	vulns := fixedVulns(g)
	var item *remediation.Item
	found, resolved, remaining := 0, 0, 0
	for _, id := range vulns {
		es := x.items[baseWaitKey{image: img.Image, entity: entity, vuln: id, coord: coord}]
		if len(es) == 0 {
			continue
		}
		found++
		if len(es) != 1 || (item != nil && item != es[0].item) {
			return nil, true
		}
		item = es[0].item
		switch es[0].outcome {
		case remediation.OutcomeResolved:
			resolved++
		case remediation.OutcomeRemaining:
			remaining++
		}
	}
	if found == 0 || waitsStateNewerSeries(item) {
		return nil, false
	}
	if found != len(vulns) {
		return nil, true
	}
	name, tag := baseNameTag(item.Current)
	a = &cardAction{Name: name, Tag: tag, Resolved: resolved, Total: len(vulns)}
	if item.Candidate != nil {
		a.To = item.Candidate.Tag
	}
	// judged says the item's comparison gives every finding of the card an
	// outcome the line can state.
	judged := item.Comparison != nil && resolved+remaining == len(vulns)
	if item.Category == remediation.CategoryPRCandidate {
		if name == "" || tag == "" || a.To == "" {
			return nil, true
		}
		switch {
		case !judged:
			a.Kind = actImageUnknown
			return a, true
		case resolved == 0:
			a.Kind = actImageRemains
			return a, true
		case remaining == 0:
			a.Kind = actImageResolved
		default:
			a.Kind = actImagePartial
		}
		pr, ok := prClauseOfItem(x.plan, remediation.PRItemKindImage, item.Key)
		if !ok {
			return nil, true
		}
		a.PR = pr
		return a, true
	}
	// What follows says less than a source that holds the finding itself
	// would: the dependency files that install the package, or the base
	// image of the Dockerfile. A card with such a finding gets no line from
	// the image's tag, whether or not that source has one for it.
	if x.inFiles(entity, g, vulns) {
		return nil, true
	}
	for _, id := range vulns {
		if len(x.bases[baseWaitKey{image: img.Image, entity: entity, vuln: id, coord: coord}]) > 0 {
			return nil, true
		}
	}
	// An image a mapped Dockerfile builds gets a newer version when its
	// owner builds one: there is none to wait for, and none to look up.
	if len(x.builds[[2]string{img.Image, entity}]) > 0 && (item.Category == remediation.CategoryNoCandidate || item.Category == remediation.CategoryExcluded) {
		return nil, true
	}
	floating := item.Kind == remediation.TagFloating
	if !floating && item.Kind != remediation.TagPinned {
		// A reference no newer version is looked up for has no tag to name.
		name, tag = "", ""
	}
	named := name != "" && tag != ""
	// outcome picks the kind for what the comparison says of the card.
	outcome := func(allResolved, partial, allRemain cardActionKind) cardActionKind {
		switch {
		case resolved == 0:
			return allRemain
		case remaining == 0:
			return allResolved
		}
		return partial
	}
	switch item.Category {
	case remediation.CategoryPullAgain:
		if !floating || !named {
			return nil, true
		}
		a.Kind = actPullUnknown
		if judged {
			a.Kind = outcome(actPullResolved, actPullPartial, actPullRemains)
		}
	case remediation.CategoryManual:
		if item.Reason == "" || !named {
			return nil, true
		}
		a.Why = item.Reason
		switch {
		case floating && judged:
			a.Kind = outcome(actPullResolved, actPullPartial, actPullRemains)
		case floating:
			a.Kind = actPullDecision
		case judged && a.To != "":
			a.Kind = outcome(actImageResolved, actImagePartial, actImageRemains)
		default:
			a.Kind = actImageDecision
		}
	case remediation.CategoryNoCandidate:
		if !named {
			return nil, true
		}
		// The item's candidate resolves none of its targets, yet one the
		// comparison did not judge is not known to remain: the card needs
		// the outcome of each of its findings.
		if item.Reason == remediation.ReasonCandidateNotFixing && (!judged || resolved != 0) {
			return nil, true
		}
		switch {
		case floating && item.Reason == remediation.ReasonSameContent && remediation.IsCommitTag(tag):
			a.Kind = actCommitTag
		case floating && item.Reason == remediation.ReasonSameContent:
			a.Kind = actContentSame
		case floating && item.Reason == remediation.ReasonCandidateNotFixing:
			a.Kind = actPullRemains
		case !floating && item.Reason == remediation.ReasonNoNewerTag:
			a.Kind = actTagWaitNoNewer
		case !floating && item.Reason == remediation.ReasonSameContent:
			a.Kind = actTagWaitSameContent
		case !floating && item.Reason == remediation.ReasonCandidateNotFixing:
			a.Kind = actTagWaitNotFixed
		default:
			return nil, true
		}
	case remediation.CategoryExcluded, remediation.CategoryNotComparable, remediation.CategoryFailed, remediation.CategoryDeferred:
		if item.Reason == "" {
			return nil, true
		}
		a.Why = item.Reason
		switch item.Category {
		case remediation.CategoryExcluded:
			a.Kind = actNotChecked
		case remediation.CategoryDeferred:
			a.Kind = actCheckLater
		default:
			a.Kind = actCheckFailed
		}
	default:
		return nil, true
	}
	return a, true
}

// waitsStateNewerSeries reports whether the waits of the image's own tag
// state what the item's check of newer series found. They state every result
// but one: no newer series after the own series had a newer tag, where what
// that tag showed is all there is to say.
func waitsStateNewerSeries(it *remediation.Item) bool {
	if it.NewerSeries == nil {
		return false
	}
	return it.NewerSeries.Status != remediation.NewerSeriesNone || it.Reason == remediation.ReasonNoNewerTag
}

// inFiles reports whether one of the fixed findings vulns of group g came
// from a package of the dependency files that a change of them can reach.
func (x *cardActionIndex) inFiles(entity string, g analyze.PackageGroup, vulns []string) bool {
	for _, id := range vulns {
		if x.owned[actionKey{entity: entity, ecosystem: string(g.Ecosystem), class: string(g.Class), name: g.Package, version: g.InstalledVer, vuln: id}] {
			return true
		}
	}
	return false
}

// prClauseOfItem is the pull request clause of a plan item of kind (an
// image item or a Dockerfile item): from the units the item is part of when
// it has any, else from why it has none. Nothing is said when pull requests
// are not enabled or the plan does not record what the stage did with the
// item. ok is false when the units, or the workloads without one, do not say
// the same thing.
func prClauseOfItem(plan *remediation.Plan, kind, itemKey string) (prClause, bool) {
	if plan.PullRequestsEnabled == nil || !*plan.PullRequestsEnabled {
		return prClause{}, true
	}
	var unitKeys []string
	var rest []remediation.PRItemResult
	for _, r := range plan.PRItems {
		if r.Kind != kind || r.ItemKey != itemKey {
			continue
		}
		if r.Status == remediation.PRItemAssigned {
			for _, k := range r.UnitKeys {
				unitKeys = appendOnce(unitKeys, k)
			}
			continue
		}
		rest = append(rest, r)
	}
	if len(unitKeys) > 0 {
		var clauses []prClause
		for _, k := range unitKeys {
			u := unitByKey(plan.PullRequests, k)
			if u == nil {
				return prClause{}, false
			}
			c := prClauseOfUnit(*u)
			if c.Kind == prMergedRunning && kind == remediation.PRItemKindDockerfile {
				c.Kind = prMergedRebuild
			}
			dup := false
			for _, have := range clauses {
				dup = dup || have.same(c)
			}
			if !dup {
				clauses = append(clauses, c)
			}
		}
		if len(clauses) == 1 {
			return clauses[0], true
		}
		merged := prClause{Kind: prExists}
		for _, c := range clauses {
			if c.Kind != prExists {
				return prClause{}, false
			}
			merged.PRs = append(merged.PRs, c.PRs...)
		}
		sort.Slice(merged.PRs, func(i, j int) bool {
			if merged.PRs[i].Number != merged.PRs[j].Number {
				return merged.PRs[i].Number < merged.PRs[j].Number
			}
			return merged.PRs[i].URL < merged.PRs[j].URL
		})
		return merged, true
	}
	if len(rest) == 0 {
		return prClause{}, true
	}
	for _, r := range rest[1:] {
		if r.Status != rest[0].Status || r.Reason != rest[0].Reason {
			return prClause{}, false
		}
	}
	c := prClause{Kind: prNotCreated, Reason: rest[0].Reason, Status: string(rest[0].Status)}
	if rest[0].Status == remediation.PRItemNotApplicable {
		c.Kind = prWontCreate
	}
	return c, true
}

func unitByKey(units []remediation.PRUnit, key string) *remediation.PRUnit {
	for i := range units {
		if units[i].Key == key {
			return &units[i]
		}
	}
	return nil
}

// prClauseOfUnit is the pull request clause of one update unit. A merged
// pull request is one whose image still runs: the card is about the image
// the unit updates from.
func prClauseOfUnit(u remediation.PRUnit) prClause {
	if u.Status == remediation.PRStatusWriteDisabled {
		return prClause{}
	}
	if u.Number == 0 {
		c := prClause{Kind: prNotCreated, Reason: u.Reason, Status: string(u.Status)}
		if u.Reason == remediation.ReasonWriteOutcomeUnknown || u.Reason == remediation.ReasonAttemptUnsettled {
			c.Kind = prUnconfirmed
		}
		return c
	}
	c := prClause{Kind: prExists, PRs: []prRef{{Number: u.Number, URL: u.URL}}}
	switch u.Status {
	case remediation.PRStatusMerged:
		c.Kind = prMergedRunning
	case remediation.PRStatusSuppressed:
		c.Kind = prClosed
		if u.ReplacedBy > 0 {
			c.Kind, c.Replaced = prReplaced, prRef{Number: u.ReplacedBy}
		}
		return c
	}
	// A pull request a person changed may no longer hold the update, merged
	// or not, so nothing is said about what it does.
	if u.UserModified {
		c.Kind = prModified
	}
	return c
}
