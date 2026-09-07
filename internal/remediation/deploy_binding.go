package remediation

import "github.com/kitsunetrail/kestrelynx/internal/inventory"

// ImageIntent is the image reference a management chain declares, as
// opposed to what is actually running. Digest is the zero value when the
// declaration isn't digest-pinned.
type ImageIntent struct {
	Ref    string           // the reference written in the owner's definition (often a mutable tag).
	Digest inventory.Digest // set when the declaration pins a digest; zero value otherwise.
}

// OwnerChain is one management path, ordered from nearest to farthest: index
// 0 is the direct owner of the running entity, and the last element is the
// final management authority for this path. Intended is the image this
// chain's final owner declares — which can differ between chains when
// several tools independently manage the same running entity (a migration
// in progress, or intentional dual management).
type OwnerChain struct {
	Owners   []DeployOwner // near to far, 1..N.
	Intended ImageIntent
}

// Final returns the chain's final management authority (the last element of
// Owners), or the zero DeployOwner for an empty chain.
func (c OwnerChain) Final() DeployOwner {
	if len(c.Owners) == 0 {
		return DeployOwner{}
	}
	return c.Owners[len(c.Owners)-1]
}

// DeployBinding is the complete relation between one running entity and its
// candidate management chains. Several chains can coexist unreduced — this
// type never collapses them to a single "true" owner — because doing so
// would either point a fix at the wrong layer or lose track of the Git
// location a chain's final owner is defined at.
type DeployBinding struct {
	Workload  inventory.Workload // the higher-level grouping this entity runs under.
	Container string             // matches inventory.Container.Name.
	// Subject is the running entity (fact), independent of what any chain
	// declares (intent). Subject.Resolved == false means entity identity
	// itself is unresolved, not that the deployment owner is unknown.
	Subject     inventory.ImageSubject
	Chains      []OwnerChain // candidate management paths. 0..N.
	Conflicting bool         // true when len(Chains) > 1.
}
