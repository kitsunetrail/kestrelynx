package remediation

// PRItemStatus says what the pull request stage did with one plan item for one
// of its workloads.
type PRItemStatus string

const (
	// PRItemAssigned: the item is part of at least one update unit for the
	// workload; UnitKeys name them. The units say what became of the pull
	// request.
	PRItemAssigned PRItemStatus = "assigned"
	// PRItemNotApplicable: no update unit is made for the item and the
	// workload; Reason says why.
	PRItemNotApplicable PRItemStatus = "not_applicable"
	// PRItemNotProcessed: the stage did not get to decide: it did not run, or
	// the item could not be matched to a unit it should have been part of.
	PRItemNotProcessed PRItemStatus = "not_processed"
)

// PRItemKindImage is the kind of a result for an item of Plan.Items,
// PRItemKindDockerfile for one of Plan.DockerfileItems and PRItemKindLanguage
// for one of Plan.LanguageItems.
const (
	PRItemKindImage      = "image"
	PRItemKindDockerfile = "dockerfile"
	PRItemKindLanguage   = "language"
)

// Reasons of an item that has no update unit.
const (
	// ReasonSourceMappingMissing: no source mapping names the workload, so
	// there is no file to edit.
	ReasonSourceMappingMissing Reason = "source_mapping_missing"
	// ReasonContainerImageTagUnsupported: the workload is a container started
	// outside Compose, whose image tag no file of a repository sets.
	ReasonContainerImageTagUnsupported Reason = "container_image_tag_unsupported"
	// ReasonPRUnitUnavailable: a mapping names the workload, yet the item is in
	// none of the units built for it.
	ReasonPRUnitUnavailable Reason = "pr_unit_unavailable"
)

// PRItemResult ties one plan item, for one workload running its image, to the
// update units of the pull request stage, or says why it has none. A
// Dockerfile item and a language item have one result for all their
// workloads: their unit never covers part of them.
type PRItemResult struct {
	Kind    string `json:"kind"`
	ItemKey string `json:"item_key"`
	// Workload is the workload key the result is for; empty when the item
	// names a service that has none, and for a Dockerfile or language item.
	Workload string `json:"workload,omitempty"`
	// UnitKeys are the keys of the units (PRUnit.Key) the item is part of for
	// the workload, sorted; set with PRItemAssigned only.
	UnitKeys []string     `json:"unit_keys,omitempty"`
	Status   PRItemStatus `json:"status"`
	Reason   Reason       `json:"reason,omitempty"`
}
