package remediation

import (
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// forEachPRCandidateWorkload calls fn for every pr_candidate item of the plan
// in plan order, and within an item for each distinct workload key of its
// services in ascending order; "" stands for the services that have none.
func forEachPRCandidateWorkload(plan Plan, fn func(it *Item, workload string)) {
	for i := range plan.Items {
		it := &plan.Items[i]
		if it.Category != CategoryPRCandidate {
			continue
		}
		seen := map[string]bool{}
		var keys []string
		for _, s := range it.Services {
			k := s.WorkloadKey()
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			fn(it, k)
		}
	}
}

// NotProcessedPRItems is the result for a stage that did not run: every
// pr_candidate item and workload, and every pr_candidate Dockerfile item, is
// not processed, for reason.
func NotProcessedPRItems(plan Plan, reason Reason) []PRItemResult {
	var out []PRItemResult
	forEachPRCandidateWorkload(plan, func(it *Item, workload string) {
		out = append(out, PRItemResult{Kind: PRItemKindImage, ItemKey: it.Key, Workload: workload, Status: PRItemNotProcessed, Reason: reason})
	})
	for _, it := range plan.DockerfileItems {
		if it.Category == CategoryPRCandidate {
			out = append(out, PRItemResult{Kind: PRItemKindDockerfile, ItemKey: it.Key, Status: PRItemNotProcessed, Reason: reason})
		}
	}
	return out
}

// buildPRItems relates the pr_candidate items of the plan to the units made
// for them: an image item to the units that edit the tag of each of its
// workloads, a Dockerfile item to the unit of its FROM. Language units take
// no part.
func buildPRItems(in PRStageInput, units []*composeUnit) []PRItemResult {
	type pair struct{ item, workload string }
	unitKeys := map[pair][]string{}
	for _, u := range units {
		if u.df != nil || u.lang != nil {
			continue
		}
		for _, it := range u.items {
			for _, w := range u.workloads {
				p := pair{it.Key, w}
				unitKeys[p] = append(unitKeys[p], u.key)
			}
		}
	}
	mapped := map[string]bool{}
	for _, m := range in.Mappings {
		mapped[m.Workload] = true
	}
	for _, m := range in.Kubernetes {
		mapped[m.Workload] = true
	}
	for _, m := range in.Kustomize {
		mapped[m.Workload] = true
		for _, w := range m.Affects {
			mapped[w] = true
		}
	}
	for _, m := range in.HelmValues {
		mapped[m.Workload] = true
		for _, w := range m.Affects {
			mapped[w] = true
		}
	}

	var out []PRItemResult
	forEachPRCandidateWorkload(in.Plan, func(it *Item, workload string) {
		res := PRItemResult{Kind: PRItemKindImage, ItemKey: it.Key, Workload: workload}
		switch keys := dedupeSorted(unitKeys[pair{it.Key, workload}]); {
		case len(keys) > 0:
			res.Status, res.UnitKeys = PRItemAssigned, keys
		case strings.HasPrefix(workload, inventory.ContainerKeyPrefix):
			res.Status, res.Reason = PRItemNotApplicable, ReasonContainerImageTagUnsupported
		case !mapped[workload]:
			res.Status, res.Reason = PRItemNotApplicable, ReasonSourceMappingMissing
		default:
			res.Status, res.Reason = PRItemNotProcessed, ReasonPRUnitUnavailable
		}
		out = append(out, res)
	})
	dfUnits := map[string]bool{}
	for _, u := range units {
		if u.df != nil {
			dfUnits[u.key] = true
		}
	}
	for _, it := range in.Plan.DockerfileItems {
		if it.Category != CategoryPRCandidate {
			continue
		}
		res := PRItemResult{Kind: PRItemKindDockerfile, ItemKey: it.Key, Status: PRItemNotProcessed, Reason: ReasonPRUnitUnavailable}
		if key, ok := DockerfileUnitKey(it); ok && dfUnits[key] {
			res.Status, res.Reason, res.UnitKeys = PRItemAssigned, "", []string{key}
		}
		out = append(out, res)
	}
	return out
}
