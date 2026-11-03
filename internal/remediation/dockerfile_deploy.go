package remediation

import (
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// ReasonBaseUpdateNotDeployed: the FROM names the base a merged pull request
// of this tool set, and the running images are still the ones that pull
// request was proposed for: the merge has not been built and deployed.
const ReasonBaseUpdateNotDeployed Reason = "base_update_not_deployed"

// BaseUpdateMerged is the merged pull request of a Dockerfile item whose
// running images were not rebuilt since.
type BaseUpdateMerged struct {
	Number int    `json:"number"`
	URL    string `json:"url,omitempty"`
	// From is the base the FROM named before the pull request, which the
	// running images were built from; To is the tag it set.
	From string `json:"from"`
	To   string `json:"to"`
}

// undeployedBaseUpdates finds, among the Dockerfile items whose running
// images do not start with the layers of the base the FROM names, those whose
// FROM was changed to that base by a merged pull request of this tool while
// every running image is one the pull request was proposed for. Only the
// records of a repository confirmed this cycle (repoIDs, by lower-case name)
// are used, and not those of a pull request someone changed, whose recorded
// base branch and edit may not be what was merged. The newest such pull
// request of an item is kept, by item key.
func undeployedBaseUpdates(plan Plan, recs []PRRecord, repoIDs map[string]int64) map[string]BaseUpdateMerged {
	out := map[string]BaseUpdateMerged{}
	for _, it := range plan.DockerfileItems {
		if it.Reason != ReasonBaseLayersMismatch || it.Source.Stage == nil || len(it.Entities) == 0 {
			continue
		}
		base := ParseImageRef(it.BaseRef)
		baseRepo, ok := inventory.RepositoryKey(it.BaseRef)
		if !ok || base.Tag == "" {
			continue
		}
		id, confirmed := repoIDs[strings.ToLower(it.Source.Repository)]
		if !confirmed {
			continue
		}
		loc := dockerfileStageLocation(*it.Source.Stage, it.Source.StageName)
		var best *PRRecord
		for i := range recs {
			rec := &recs[i]
			if rec.Kind != prKindDockerfile || rec.State != PRStateMerged || rec.Evidence == nil || rec.UserModified ||
				rec.RepoID != id || !strings.EqualFold(rec.Repo, it.Source.Repository) || rec.BaseBranch != it.Source.BaseBranch ||
				rec.Path != it.Source.Path || !containsString(rec.Locations, loc) || rec.CandidateTag != base.Tag {
				continue
			}
			if r, ok := inventory.RepositoryKey(rec.CurrentRef); !ok || r != baseRepo {
				continue
			}
			if !proposedFor(it.Entities, rec.Evidence.Items) {
				continue
			}
			if best == nil || rec.Number > best.Number {
				best = rec
			}
		}
		if best != nil {
			out[it.Key] = BaseUpdateMerged{Number: best.Number, URL: best.URL, From: best.CurrentRef, To: best.CandidateTag}
		}
	}
	return out
}

// proposedFor reports whether every running image is one the evidence of a
// pull request was made from.
func proposedFor(ents []DockerfileEntity, items []ItemEvidence) bool {
	for _, e := range ents {
		found := false
		for _, ev := range items {
			found = found || (e.Running.Entity != "" && ev.Current.Entity == e.Running.Entity)
		}
		if !found {
			return false
		}
	}
	return true
}

// markUndeployed gives the Dockerfile items found by undeployedBaseUpdates
// their reason; the running images keep the outcome of their own comparison.
func markUndeployed(p *Plan, found map[string]BaseUpdateMerged) {
	for i := range p.DockerfileItems {
		it := &p.DockerfileItems[i]
		m, ok := found[it.Key]
		if !ok || it.Reason != ReasonBaseLayersMismatch {
			continue
		}
		mm := m
		it.AwaitingDeploy = &mm
		it.Reason = ReasonBaseUpdateNotDeployed
		it.Detail = fmt.Sprintf("pull request #%d changed the FROM from %s to tag %s and was merged, but the running images are still the ones it was proposed for: the merge has not been built and deployed", m.Number, m.From, m.To)
	}
}
