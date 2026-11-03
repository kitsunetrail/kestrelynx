package remediation

import "testing"

const (
	esRepoID = 1141727046
	esImage  = "docker.elastic.co/elasticsearch/elasticsearch"
	esKey    = "dockerfile:yyac-project/regfis-infra@main:elasticsearch/Dockerfile#stages[0]"
)

// mismatchItem is the item of production: the FROM names 8.19.24, and the
// running image starts with the layers of 8.19.23.
func mismatchItem() DockerfileItem {
	stage := 0
	return DockerfileItem{
		Key: esKey, Category: CategoryNotComparable, Reason: ReasonBaseLayersMismatch, Detail: "layer 0 differs",
		Source:  DockerfileSource{Repository: "YYAC-project/regfis-infra", BaseBranch: "main", Path: "elasticsearch/Dockerfile", Stage: &stage},
		BaseRef: esImage + ":8.19.24", BaseKind: TagPinned,
		Entities: []DockerfileEntity{{
			Running:  ImageState{Ref: "regfis-infra-elasticsearch", Entity: "config:sha256:fd26"},
			Category: CategoryNotComparable, Reason: ReasonBaseLayersMismatch,
		}},
	}
}

// mergedBaseUpdate is the pull request that set the FROM to 8.19.24, proposed
// for the running image.
func mergedBaseUpdate(number int) PRRecord {
	return PRRecord{
		Repo: "YYAC-project/regfis-infra", RepoID: esRepoID, Kind: prKindDockerfile, Number: number, URL: "https://github.com/YYAC-project/regfis-infra/pull/2",
		BaseBranch: "main", Path: "elasticsearch/Dockerfile", Locations: []string{"stages[0]"}, State: PRStateMerged,
		CurrentRef: esImage + ":8.19.23", CandidateTag: "8.19.24",
		Evidence: &VerificationSummary{Items: []ItemEvidence{{Current: ImageState{Entity: "config:sha256:fd26"}}}},
	}
}

func TestUndeployedBaseUpdates(t *testing.T) {
	plan := Plan{DockerfileItems: []DockerfileItem{mismatchItem()}}
	confirmed := map[string]int64{"yyac-project/regfis-infra": esRepoID}
	got := undeployedBaseUpdates(plan, []PRRecord{mergedBaseUpdate(1), mergedBaseUpdate(2)}, confirmed)
	want := BaseUpdateMerged{Number: 2, URL: "https://github.com/YYAC-project/regfis-infra/pull/2", From: esImage + ":8.19.23", To: "8.19.24"}
	if len(got) != 1 || got[esKey] != want {
		t.Fatalf("found = %+v, want the newest merged pull request %+v", got, want)
	}

	for name, change := range map[string]func(*PRRecord, *DockerfileItem){
		"an open pull request":           func(r *PRRecord, _ *DockerfileItem) { r.State = PRStateOpen },
		"a closed pull request":          func(r *PRRecord, _ *DockerfileItem) { r.State = PRStateClosed },
		"another kind":                   func(r *PRRecord, _ *DockerfileItem) { r.Kind = prKindLanguage },
		"another repository":             func(r *PRRecord, _ *DockerfileItem) { r.Repo = "ex/other" },
		"another base branch":            func(r *PRRecord, _ *DockerfileItem) { r.BaseBranch = "dev" },
		"another file":                   func(r *PRRecord, _ *DockerfileItem) { r.Path = "Dockerfile" },
		"another stage":                  func(r *PRRecord, _ *DockerfileItem) { r.Locations = []string{"stages[1]"} },
		"another tag set":                func(r *PRRecord, _ *DockerfileItem) { r.CandidateTag = "8.19.25" },
		"another image":                  func(r *PRRecord, _ *DockerfileItem) { r.CurrentRef = "elasticsearch:8.19.23" },
		"a pull request someone changed": func(r *PRRecord, _ *DockerfileItem) { r.UserModified = true },
		"another repository ID":          func(r *PRRecord, _ *DockerfileItem) { r.RepoID = 7 },
		"no evidence":                    func(r *PRRecord, _ *DockerfileItem) { r.Evidence = nil },
		"a rebuilt image":                func(_ *PRRecord, it *DockerfileItem) { it.Entities[0].Running.Entity = "config:sha256:new" },
		"an image of no comparison":      func(_ *PRRecord, it *DockerfileItem) { it.Entities[0].Running.Entity = "" },
		"layers that match":              func(_ *PRRecord, it *DockerfileItem) { it.Reason = ReasonNoBaseFindings },
		"a floating base":                func(_ *PRRecord, it *DockerfileItem) { it.Reason = ReasonFloatingBaseUnconfirmed },
		"a second image not proposed for": func(_ *PRRecord, it *DockerfileItem) {
			it.Entities = append(it.Entities, DockerfileEntity{Running: ImageState{Entity: "config:sha256:other"}})
		},
	} {
		rec, it := mergedBaseUpdate(2), mismatchItem()
		change(&rec, &it)
		if got := undeployedBaseUpdates(Plan{DockerfileItems: []DockerfileItem{it}}, []PRRecord{rec}, confirmed); len(got) != 0 {
			t.Errorf("%s: found %+v", name, got)
		}
	}

	// A repository not confirmed this cycle gives nothing.
	if got := undeployedBaseUpdates(plan, []PRRecord{mergedBaseUpdate(2)}, nil); len(got) != 0 {
		t.Errorf("unconfirmed repository: found %+v", got)
	}
	// Two spellings of one image are the same image, and two running images
	// the pull request was proposed for are both its own.
	rec, it := mergedBaseUpdate(2), mismatchItem()
	rec.CurrentRef, it.BaseRef = "python:3.12.3-slim", "docker.io/library/python:3.12.5-slim"
	rec.CandidateTag = "3.12.5-slim"
	rec.Evidence.Items = append(rec.Evidence.Items, ItemEvidence{Current: ImageState{Entity: "config:sha256:second"}})
	it.Entities = append(it.Entities, DockerfileEntity{Running: ImageState{Entity: "config:sha256:second"}, Reason: ReasonBaseLayersMismatch})
	if got := undeployedBaseUpdates(Plan{DockerfileItems: []DockerfileItem{it}}, []PRRecord{rec}, confirmed); len(got) != 1 {
		t.Errorf("same image spelled differently, two images: found %+v", got)
	}
}

func TestAttachMarksUndeployedBaseUpdates(t *testing.T) {
	other := mismatchItem()
	other.Key = "dockerfile:ex/app@main:Dockerfile#stages[0]"
	plan := Plan{DockerfileItems: []DockerfileItem{mismatchItem(), other}}
	m := BaseUpdateMerged{Number: 2, From: esImage + ":8.19.23", To: "8.19.24"}
	PRStageResult{Undeployed: map[string]BaseUpdateMerged{esKey: m}}.Attach(&plan)

	it := plan.DockerfileItems[0]
	if it.Category != CategoryNotComparable || it.Reason != ReasonBaseUpdateNotDeployed || it.AwaitingDeploy == nil || *it.AwaitingDeploy != m {
		t.Errorf("item = %s %s %+v", it.Category, it.Reason, it.AwaitingDeploy)
	}
	if it.Entities[0].Reason != ReasonBaseLayersMismatch {
		t.Errorf("the running image lost its own outcome: %s", it.Entities[0].Reason)
	}
	if o := plan.DockerfileItems[1]; o.Reason != ReasonBaseLayersMismatch || o.AwaitingDeploy != nil {
		t.Errorf("another item was marked: %s %+v", o.Reason, o.AwaitingDeploy)
	}
}

// The merged pull request an item waits on is part of the plan's fingerprint;
// an item without one keeps the fingerprint it had.
func TestFingerprintAwaitingDeploy(t *testing.T) {
	plain := Plan{DockerfileItems: []DockerfileItem{mismatchItem()}}
	before := Fingerprint(plain)
	marked := func(n int) string {
		p := Plan{DockerfileItems: []DockerfileItem{mismatchItem()}}
		PRStageResult{Undeployed: map[string]BaseUpdateMerged{esKey: {Number: n, From: esImage + ":8.19.23", To: "8.19.24"}}}.Attach(&p)
		return Fingerprint(p)
	}
	if marked(2) == before || marked(2) == marked(3) {
		t.Error("the merged pull request is not in the fingerprint")
	}
	// The value the plan had before items could wait on a merge.
	if before != "7e55ec6398b7349371bdf5d78a18b8514a773d4dded4a758d9ec6a2169e75470" {
		t.Errorf("the fingerprint of an unmarked plan changed: %s", before)
	}
}
