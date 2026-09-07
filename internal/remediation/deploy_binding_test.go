package remediation

import "testing"

// TestOwnerChain_Final checks both the empty-chain zero-value case and the
// ordinary case where Final is the last (farthest) owner, not the first.
func TestOwnerChain_Final(t *testing.T) {
	t.Run("empty chain returns the zero DeployOwner", func(t *testing.T) {
		var c OwnerChain
		if got := c.Final(); got != (DeployOwner{}) {
			t.Errorf("Final() = %+v, want the zero value", got)
		}
	})

	t.Run("multi-owner chain returns the last element", func(t *testing.T) {
		near := DeployOwner{Kind: OwnerKubernetes, Resource: ResourceDeployment, Name: "web"}
		mid := DeployOwner{Kind: OwnerHelm, Name: "web-release"}
		far := DeployOwner{Kind: OwnerArgoCD, Name: "web-app"}
		c := OwnerChain{Owners: []DeployOwner{near, mid, far}}
		if got := c.Final(); got != far {
			t.Errorf("Final() = %+v, want %+v", got, far)
		}
	})
}
