package remediation

import "testing"

// TestDeployOwner_Valid exercises every branch of the Resource/ResourceID
// consistency rule: Resource is required exactly for OwnerKubernetes, and
// ResourceID is required exactly for OwnerKubernetes+ResourceOther and for
// OwnerFlux (restricted to the two Flux identifiers), and must be empty
// otherwise.
func TestDeployOwner_Valid(t *testing.T) {
	cases := []struct {
		name string
		o    DeployOwner
		want bool
	}{
		{
			name: "kubernetes deployment, no ResourceID: valid",
			o:    DeployOwner{Kind: OwnerKubernetes, Resource: ResourceDeployment},
			want: true,
		},
		{
			name: "kubernetes with ResourceNone: invalid (Resource required)",
			o:    DeployOwner{Kind: OwnerKubernetes, Resource: ResourceNone},
			want: false,
		},
		{
			name: "kubernetes deployment with a stray ResourceID: invalid",
			o:    DeployOwner{Kind: OwnerKubernetes, Resource: ResourceDeployment, ResourceID: "rollouts.argoproj.io"},
			want: false,
		},
		{
			name: "kubernetes ResourceOther with a validated ResourceID: valid",
			o:    DeployOwner{Kind: OwnerKubernetes, Resource: ResourceOther, ResourceID: "rollouts.argoproj.io"},
			want: true,
		},
		{
			name: "kubernetes ResourceOther with empty ResourceID: invalid",
			o:    DeployOwner{Kind: OwnerKubernetes, Resource: ResourceOther},
			want: false,
		},
		{
			name: "kubernetes ResourceOther with malformed ResourceID: invalid",
			o:    DeployOwner{Kind: OwnerKubernetes, Resource: ResourceOther, ResourceID: "Rollouts.argoproj.io"},
			want: false,
		},
		{
			name: "flux with the Kustomization ResourceID: valid",
			o:    DeployOwner{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization},
			want: true,
		},
		{
			name: "flux with the HelmRelease ResourceID: valid",
			o:    DeployOwner{Kind: OwnerFlux, ResourceID: ResourceIDFluxHelmRelease},
			want: true,
		},
		{
			name: "flux with empty ResourceID: invalid",
			o:    DeployOwner{Kind: OwnerFlux},
			want: false,
		},
		{
			name: "flux with an arbitrary validated-shape ResourceID: invalid (must be one of the two constants)",
			o:    DeployOwner{Kind: OwnerFlux, ResourceID: "somethingelse.fluxcd.io"},
			want: false,
		},
		{
			name: "flux with a non-empty Resource: invalid (Resource is kubernetes-only)",
			o:    DeployOwner{Kind: OwnerFlux, ResourceID: ResourceIDFluxKustomization, Resource: ResourceDeployment},
			want: false,
		},
		{
			name: "helm with no ResourceID and no Resource: valid",
			o:    DeployOwner{Kind: OwnerHelm, Name: "my-release"},
			want: true,
		},
		{
			name: "helm with a stray ResourceID: invalid",
			o:    DeployOwner{Kind: OwnerHelm, Name: "my-release", ResourceID: "kustomizations.kustomize.toolkit.fluxcd.io"},
			want: false,
		},
		{
			name: "argocd with no ResourceID and no Resource: valid",
			o:    DeployOwner{Kind: OwnerArgoCD, Name: "my-app"},
			want: true,
		},
		{
			name: "compose with no ResourceID and no Resource: valid",
			o:    DeployOwner{Kind: OwnerCompose, Name: "my-project"},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.o.Valid(); got != tc.want {
				t.Errorf("Valid() = %v, want %v (owner %+v)", got, tc.want, tc.o)
			}
		})
	}
}

// TestValidResourceID exercises the ResourceID shape rule directly: at least
// two "."-separated DNS-1123-label segments, and the whole string within
// maxResourceIDBytes.
func TestValidResourceID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want bool
	}{
		{name: "well-formed three segments", id: "rollouts.argoproj.io", want: true},
		{name: "well-formed multi-segment", id: "kustomizations.kustomize.toolkit.fluxcd.io", want: true},
		{name: "empty", id: "", want: false},
		{name: "single segment, no group", id: "rollouts", want: false},
		{name: "uppercase segment rejected", id: "Rollouts.argoproj.io", want: false},
		{name: "empty segment (leading dot)", id: ".argoproj.io", want: false},
		{name: "empty segment (trailing dot)", id: "rollouts.argoproj.", want: false},
		{name: "segment with underscore rejected", id: "roll_outs.argoproj.io", want: false},
		{name: "segment starting with hyphen rejected", id: "-rollouts.argoproj.io", want: false},
		{
			// Five 60-character labels (each within the 63-character
			// per-label limit) joined by dots: 5*60 + 4 = 304 bytes, over
			// maxResourceIDBytes even though every individual label is
			// well-formed on its own.
			name: "individually valid labels, over the overall byte limit",
			id:   repeatChar('a', 60) + "." + repeatChar('a', 60) + "." + repeatChar('a', 60) + "." + repeatChar('a', 60) + "." + repeatChar('a', 60),
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validResourceID(tc.id); got != tc.want {
				t.Errorf("validResourceID(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

// repeatChar builds a string of n copies of c, for constructing an
// over-the-limit test value without a magic literal of that length.
func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
