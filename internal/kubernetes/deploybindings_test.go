package kubernetes

import (
	"context"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// nativeDeploymentOwner is the native chain element every case in
// TestDeployBindings_MarkerDetection resolves to: pod_owned_by_deployment.json
// -> replicaset_for_deployment.json -> Deployment "web" in "default".
func nativeDeploymentOwner() remediation.DeployOwner {
	return remediation.DeployOwner{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourceDeployment, Name: "web", Scope: "default"}
}

// stripAttribution zeroes o.Attribution so two owners can be compared
// without the ObservedAt timestamp (captured fresh on every DeployBindings
// call) making every comparison spuriously fail.
func stripAttribution(o remediation.DeployOwner) remediation.DeployOwner {
	o.Attribution = remediation.Attribution{}
	return o
}

// chainsEqual compares two OwnerChain slices field by field, ignoring
// Attribution.ObservedAt (see stripAttribution) but comparing everything
// else, including Intended (which every case here expects at its zero
// value).
func chainsEqual(got, want []remediation.OwnerChain) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if len(got[i].Owners) != len(want[i].Owners) {
			return false
		}
		for j := range got[i].Owners {
			if stripAttribution(got[i].Owners[j]) != stripAttribution(want[i].Owners[j]) {
				return false
			}
		}
		if got[i].Intended != want[i].Intended {
			return false
		}
	}
	return true
}

// runDeployBindings drives DeployBindings against node_amd64.json plus the
// given pod/ReplicaSet/Deployment fixtures (each skipped when "") and
// returns the single resulting binding.
func runDeployBindings(t *testing.T, podFixture, rsFixture, deploymentFixture string) remediation.DeployBinding {
	t.Helper()
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, podFixture))))
	if rsFixture != "" {
		f.on("/apis/apps/v1/replicasets", ok(envelope("", loadFixture(t, rsFixture))))
	}
	if deploymentFixture != "" {
		f.on("/apis/apps/v1/deployments", ok(envelope("", loadFixture(t, deploymentFixture))))
	}
	srv := f.start()
	c := newTestClient(t, srv, nil)

	bindings, err := c.DeployBindings(context.Background())
	if err != nil {
		t.Fatalf("DeployBindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("got %d bindings, want 1: %+v", len(bindings), bindings)
	}
	return bindings[0]
}

// TestDeployBindings_MarkerDetection exercises every marker adoption/
// rejection rule against a single Pod -> ReplicaSet -> Deployment "web"
// chain, varying only the Deployment object's labels/annotations.
func TestDeployBindings_MarkerDetection(t *testing.T) {
	native := nativeDeploymentOwner()
	helm := remediation.DeployOwner{Kind: remediation.OwnerHelm, Name: "my-release", Scope: "default"}
	argo := remediation.DeployOwner{Kind: remediation.OwnerArgoCD, Name: "myapp"}
	argoViaAnnotation := remediation.DeployOwner{Kind: remediation.OwnerArgoCD, Name: "annotation-app"}
	fluxKustomization := remediation.DeployOwner{Kind: remediation.OwnerFlux, ResourceID: remediation.ResourceIDFluxKustomization, Name: "web-ks", Scope: "flux-system"}
	fluxHelmRelease := remediation.DeployOwner{Kind: remediation.OwnerFlux, ResourceID: remediation.ResourceIDFluxHelmRelease, Name: "web-hr", Scope: "flux-system"}

	nativeOnly := []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native}}}

	cases := []struct {
		name              string
		deploymentFixture string
		wantChains        []remediation.OwnerChain
		wantConflicting   bool
	}{
		// (i) Helm: all three conditions required.
		{
			name:              "Helm: all three conditions present -> adopted",
			deploymentFixture: "deployment_web_helm_full.json",
			wantChains:        []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native, helm}}},
		},
		{
			name:              "Helm: managed-by label missing -> not adopted",
			deploymentFixture: "deployment_web_helm_missing_label.json",
			wantChains:        nativeOnly,
		},
		{
			name:              "Helm: release-name annotation missing -> not adopted",
			deploymentFixture: "deployment_web_helm_missing_release_name.json",
			wantChains:        nativeOnly,
		},
		{
			name:              "Helm: release-namespace annotation missing -> not adopted",
			deploymentFixture: "deployment_web_helm_missing_release_namespace.json",
			wantChains:        nativeOnly,
		},

		// (ii) Argo CD: tracking-id self-reference.
		{
			name:              "Argo CD: tracking-id self-references the resource -> adopted",
			deploymentFixture: "deployment_web_argocd_selfref.json",
			wantChains:        []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native, argo}}},
		},
		{
			name:              "Argo CD: tracking-id group mismatch -> not adopted",
			deploymentFixture: "deployment_web_argocd_wrong_group.json",
			wantChains:        nativeOnly,
		},
		{
			name:              "Argo CD: tracking-id kind mismatch -> not adopted",
			deploymentFixture: "deployment_web_argocd_wrong_kind.json",
			wantChains:        nativeOnly,
		},
		{
			name:              "Argo CD: tracking-id namespace mismatch -> not adopted",
			deploymentFixture: "deployment_web_argocd_wrong_namespace.json",
			wantChains:        nativeOnly,
		},
		{
			name:              "Argo CD: tracking-id name mismatch -> not adopted",
			deploymentFixture: "deployment_web_argocd_wrong_name.json",
			wantChains:        nativeOnly,
		},
		{
			name:              "Argo CD: app.kubernetes.io/instance label alone -> not adopted",
			deploymentFixture: "deployment_web_argocd_label_only.json",
			wantChains:        nativeOnly,
		},
		{
			name:              "Argo CD: label disagrees with a self-referencing tracking-id -> annotation wins",
			deploymentFixture: "deployment_web_argocd_label_mismatch.json",
			wantChains:        []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native, argoViaAnnotation}}},
		},

		// (iii) Flux: Kustomization and HelmRelease are distinct owners.
		{
			name:              "Flux: Kustomization label pair only -> adopted",
			deploymentFixture: "deployment_web_flux_kustomization.json",
			wantChains:        []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native, fluxKustomization}}},
		},
		{
			name:              "Flux: HelmRelease label pair only -> adopted",
			deploymentFixture: "deployment_web_flux_helmrelease.json",
			wantChains:        []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native, fluxHelmRelease}}},
		},
		{
			name:              "Flux: both Kustomization and HelmRelease pairs present -> two chains",
			deploymentFixture: "deployment_web_flux_both.json",
			wantChains: []remediation.OwnerChain{
				{Owners: []remediation.DeployOwner{native, fluxKustomization}},
				{Owners: []remediation.DeployOwner{native, fluxHelmRelease}},
			},
			wantConflicting: true,
		},

		// (iv) Argo CD and Flux both claiming the same resource.
		{
			name:              "Argo CD and Flux Kustomization both present -> two chains, Conflicting",
			deploymentFixture: "deployment_web_argocd_and_flux.json",
			wantChains: []remediation.OwnerChain{
				{Owners: []remediation.DeployOwner{native, argo}},
				{Owners: []remediation.DeployOwner{native, fluxKustomization}},
			},
			wantConflicting: true,
		},

		// (v) Helm as the common intermediate layer under Argo CD.
		{
			name:              "Helm and Argo CD both present -> Helm is the intermediate layer in one chain",
			deploymentFixture: "deployment_web_helm_and_argocd.json",
			wantChains:        []remediation.OwnerChain{{Owners: []remediation.DeployOwner{native, helm, argo}}},
		},

		// (vi) UID mismatch: the Deployment found by name isn't the one the
		// Pod's owner-reference chain actually led to.
		{
			name:              "Deployment found by name has a different UID -> no tool layer",
			deploymentFixture: "deployment_web_uid_mismatch_helm.json",
			wantChains:        nativeOnly,
		},

		// No Deployment object listed at all.
		{
			name:              "no Deployment object listed -> no tool layer",
			deploymentFixture: "",
			wantChains:        nativeOnly,
		},

		// Flux: one side of the name/namespace label pair missing.
		{
			name:              "Flux: Kustomization namespace label missing -> not adopted",
			deploymentFixture: "deployment_web_flux_kustomization_missing_namespace.json",
			wantChains:        nativeOnly,
		},

		// Helm, Argo CD, and Flux Kustomization all present: Helm is the
		// common intermediate layer in both of the resulting chains, not
		// just the one that happens to come first.
		{
			name:              "Helm, Argo CD, and Flux Kustomization all present -> Helm is the intermediate layer in both chains",
			deploymentFixture: "deployment_web_helm_argocd_and_flux.json",
			wantChains: []remediation.OwnerChain{
				{Owners: []remediation.DeployOwner{native, helm, argo}},
				{Owners: []remediation.DeployOwner{native, helm, fluxKustomization}},
			},
			wantConflicting: true,
		},

		// A structurally invalid marker value (a release name containing a
		// newline) must sink the whole owner, not just the offending field.
		{
			name:              "Helm: release-name contains a newline -> not adopted",
			deploymentFixture: "deployment_web_helm_invalid_release_name.json",
			wantChains:        nativeOnly,
		},
		// C1 control characters (U+0080-U+009F) are control characters too:
		// a rejection that only covers C0 and DEL would let them ride into
		// the common model.
		{
			name:              "Helm: release-name contains a C1 control character -> not adopted",
			deploymentFixture: "deployment_web_helm_c1_release_name.json",
			wantChains:        nativeOnly,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := runDeployBindings(t, "pod_owned_by_deployment.json", "replicaset_for_deployment.json", tc.deploymentFixture)
			if !chainsEqual(b.Chains, tc.wantChains) {
				t.Errorf("Chains = %+v, want %+v", b.Chains, tc.wantChains)
			}
			if b.Conflicting != tc.wantConflicting {
				t.Errorf("Conflicting = %v, want %v", b.Conflicting, tc.wantConflicting)
			}
		})
	}
}

// TestDeployBindings_MarkerOwners_HaveRuntimeAttribution spot-checks that
// every marker kind's detected owner has its Attribution actually populated
// (OriginRuntime, ConfidenceClaimed, a non-zero ObservedAt) — Helm, Argo CD,
// and both Flux kinds each — rather than passing merely because
// stripAttribution hides a bug that leaves some of them at the zero value.
func TestDeployBindings_MarkerOwners_HaveRuntimeAttribution(t *testing.T) {
	cases := []struct {
		name              string
		deploymentFixture string
		ownerIndex        int // index into the single resulting chain's Owners, after the native layer.
	}{
		{name: "Helm", deploymentFixture: "deployment_web_helm_full.json", ownerIndex: 1},
		{name: "Argo CD", deploymentFixture: "deployment_web_argocd_selfref.json", ownerIndex: 1},
		{name: "Flux Kustomization", deploymentFixture: "deployment_web_flux_kustomization.json", ownerIndex: 1},
		{name: "Flux HelmRelease", deploymentFixture: "deployment_web_flux_helmrelease.json", ownerIndex: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := runDeployBindings(t, "pod_owned_by_deployment.json", "replicaset_for_deployment.json", tc.deploymentFixture)
			if len(b.Chains) != 1 || len(b.Chains[0].Owners) <= tc.ownerIndex {
				t.Fatalf("test setup broken: want one chain with an owner at index %d, got %+v", tc.ownerIndex, b.Chains)
			}
			owner := b.Chains[0].Owners[tc.ownerIndex]
			if owner.Attribution.Origin != remediation.OriginRuntime {
				t.Errorf("Attribution.Origin = %q, want %q", owner.Attribution.Origin, remediation.OriginRuntime)
			}
			if owner.Attribution.Confidence != remediation.ConfidenceClaimed {
				t.Errorf("Attribution.Confidence = %q, want %q (a marker is the tool's own claim, unverified)", owner.Attribution.Confidence, remediation.ConfidenceClaimed)
			}
			if owner.Attribution.ObservedAt.IsZero() {
				t.Error("Attribution.ObservedAt is zero, want the observation time")
			}
		})
	}
}

// TestDeployBindings_Subject_ResolvedWithDigestAndPlatform pins the exact
// Subject DeployBindings derives for pod_owned_by_deployment.json's
// container: the registry digest parsed from its imageID, the Platform
// resolved from node_amd64.json via the Pod's nodeName, and Resolved ==
// true. Every other test in this file only compares two bindings' Subjects
// to each other, so a regression that dropped DeployBindings' Node fetch
// (leaving Platform permanently unknown and Resolved permanently false)
// would pass all of them silently; this test would catch it.
func TestDeployBindings_Subject_ResolvedWithDigestAndPlatform(t *testing.T) {
	b := runDeployBindings(t, "pod_owned_by_deployment.json", "replicaset_for_deployment.json", "")

	wantDigest, ok := inventory.ParseDigest(inventory.DigestRegistry, "sha256:0000000000000000000000000000000000000000000000000000000000000030")
	if !ok {
		t.Fatalf("test setup broken: could not parse the expected digest out of pod_owned_by_deployment.json's imageID")
	}
	want := inventory.ImageSubject{
		Ref: "docker.io/library/nginx:1.25",
		Key: inventory.EntityKey{
			Digest:   wantDigest,
			Platform: inventory.Platform{OS: "linux", Architecture: "amd64"},
		},
		Resolved: true,
	}
	if b.Subject != want {
		t.Errorf("Subject = %+v, want %+v", b.Subject, want)
	}
}

// TestDeployBindings_BarePod_SingleNativeChain covers a Pod with no
// controller owner reference at all: its only chain must be the Pod itself,
// with no tool layer (Pod objects are never marker-checked).
func TestDeployBindings_BarePod_SingleNativeChain(t *testing.T) {
	b := runDeployBindings(t, "pod_standalone.json", "", "")
	want := []remediation.OwnerChain{{Owners: []remediation.DeployOwner{
		{Kind: remediation.OwnerKubernetes, Resource: remediation.ResourcePod, Name: "debug-shell", Scope: "default"},
	}}}
	if !chainsEqual(b.Chains, want) {
		t.Errorf("Chains = %+v, want %+v", b.Chains, want)
	}
	if b.Conflicting {
		t.Error("Conflicting = true, want false for a single chain")
	}
}

// TestDeployBindings_SortDeterministic proves the ordering tiers land in the
// order sortDeployBindings documents: both pods here share the same image
// identity, so only the Workload tier (derived from each pod's StatefulSet
// name, which sorts opposite to the pods' own names) can decide the order.
func TestDeployBindings_SortDeterministic(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	// Served b-first: a missing sort call would preserve this (wrong) order.
	f.on("/api/v1/pods", ok(envelope("",
		loadFixture(t, "pod_sort_b.json"), // pod "aaa-pod-b", StatefulSet "zzz-sts" -> must sort second
		loadFixture(t, "pod_sort_a.json"), // pod "zzz-pod-a", StatefulSet "aaa-sts" -> must sort first
	)))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	bindings, err := c.DeployBindings(context.Background())
	if err != nil {
		t.Fatalf("DeployBindings: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("got %d bindings, want 2", len(bindings))
	}
	if bindings[0].Subject.Ref != bindings[1].Subject.Ref || bindings[0].Subject.Key != bindings[1].Subject.Key {
		t.Fatalf("test setup broken: both pods must share the same image identity, got %+v and %+v", bindings[0].Subject, bindings[1].Subject)
	}
	if bindings[0].Workload.Group != bindings[1].Workload.Group {
		t.Fatalf("test setup broken: both pods must share the same namespace, got %+v and %+v", bindings[0].Workload, bindings[1].Workload)
	}
	if bindings[0].Workload.Name != "aaa-sts" || bindings[1].Workload.Name != "zzz-sts" {
		t.Errorf("Workload.Name order = [%q, %q], want [\"aaa-sts\", \"zzz-sts\"]", bindings[0].Workload.Name, bindings[1].Workload.Name)
	}
}

// TestDeployBindings_UnresolvedWorkload_NoChains covers a Pod owned by an
// out-of-allow-list controller (a CRD): the native owner itself can't be
// resolved, so Chains must be nil rather than a guess.
func TestDeployBindings_UnresolvedWorkload_NoChains(t *testing.T) {
	b := runDeployBindings(t, "pod_owned_by_crd.json", "", "")
	if b.Chains != nil {
		t.Errorf("Chains = %+v, want nil", b.Chains)
	}
	if b.Conflicting {
		t.Error("Conflicting = true, want false when there are no chains at all")
	}
}
