package remediation

import (
	"regexp"
	"strings"
)

// DeployOwnerKind identifies which tool or resource layer one DeployOwner
// represents within a management chain.
type DeployOwnerKind string

const (
	// OwnerUnknown is the zero value: no owner could be determined.
	OwnerUnknown DeployOwnerKind = ""
	// OwnerCompose means Name is a Docker Compose project.
	OwnerCompose DeployOwnerKind = "compose"
	// OwnerKubernetes means a native Kubernetes resource; Resource carries
	// which kind of resource.
	OwnerKubernetes DeployOwnerKind = "kubernetes"
	// OwnerHelm means Name is a Helm release.
	OwnerHelm DeployOwnerKind = "helm"
	// OwnerKustomize means a Kustomize overlay. Nothing in this slice
	// produces this value: a plain Kustomize apply leaves no marker on the
	// resulting objects to detect it by.
	OwnerKustomize DeployOwnerKind = "kustomize"
	// OwnerArgoCD means Name is an Argo CD Application.
	OwnerArgoCD DeployOwnerKind = "argocd"
	// OwnerFlux means a Flux Kustomization or HelmRelease; ResourceID
	// distinguishes which.
	OwnerFlux DeployOwnerKind = "flux"
)

// ResourceKind is the normalized Kubernetes resource type a
// Kind == OwnerKubernetes owner names. It is an allow-list, not a
// passthrough of the raw apiVersion/kind string: anything outside the
// allow-list becomes ResourceOther, with the raw value never crossing the
// package boundary — only a validated ResourceID does.
type ResourceKind string

const (
	// ResourceNone is the zero value, used for every owner whose Kind is
	// not OwnerKubernetes.
	ResourceNone        ResourceKind = ""
	ResourceDeployment  ResourceKind = "deployment"
	ResourceStatefulSet ResourceKind = "statefulset"
	ResourceDaemonSet   ResourceKind = "daemonset"
	ResourceCronJob     ResourceKind = "cronjob"
	ResourceJob         ResourceKind = "job"
	ResourceReplicaSet  ResourceKind = "replicaset"
	// ResourcePod means a bare Pod with no controller owner reference at
	// all — not a guess at some higher-level workload.
	ResourcePod ResourceKind = "pod"
	// ResourceOther means a Kubernetes resource kind outside the allow-list
	// (a CRD). ResourceID must carry a validated "<kind>.<group>"
	// identifier so that two different CRD kinds sharing a namespace and
	// name are never confused with each other.
	ResourceOther ResourceKind = "other"
)

// Flux ResourceID values. Unlike every other DeployOwnerKind, OwnerFlux
// alone does not determine the concrete underlying resource: a Flux
// Kustomization and a Flux HelmRelease can coexist under the same name and
// namespace as two distinct objects, so ResourceID always holds one of these
// two identifiers to tell them apart.
const (
	ResourceIDFluxKustomization = "kustomizations.kustomize.toolkit.fluxcd.io"
	ResourceIDFluxHelmRelease   = "helmreleases.helm.toolkit.fluxcd.io"
)

// DeployOwner is one layer in a management chain: a Kubernetes resource, a
// Helm release, an Argo CD Application, a Flux Kustomization/HelmRelease, or
// a Compose project.
//
// When several candidate owners disagree about the same layer, precedence
// among their Attribution.Origin values is: OriginConfig > OriginRuntime >
// OriginImageLabel. This is a norm for whatever resolves candidates down to
// one value, not something this package itself carries out: candidates at
// the same Origin that disagree are kept as separate conflicting values
// rather than merged, and only a strictly higher-Origin candidate overrides
// a lower one.
type DeployOwner struct {
	Kind DeployOwnerKind
	// Resource is non-ResourceNone exactly when Kind == OwnerKubernetes.
	Resource ResourceKind
	// ResourceID is a validated "<kind>.<group>" identifier, set exactly
	// when Kind alone does not determine the concrete resource type:
	// Kind == OwnerKubernetes with Resource == ResourceOther (an
	// unrecognized custom resource), or Kind == OwnerFlux (which must hold
	// one of the two ResourceIDFlux* constants above). It is "" for every
	// other combination, since the resource name and group Helm, Argo CD,
	// and Compose owners use are already unambiguous from Kind and Name
	// alone.
	ResourceID  string
	Name        string // helm release / argocd application / compose project / resource name.
	Scope       string // e.g. a Kubernetes namespace. "" when not applicable.
	Locator     RepoFileRef
	Attribution Attribution
}

// resourceIDLabelPattern matches one "."-separated segment of a ResourceID:
// a DNS-1123 label (lowercase alphanumerics, single hyphens between runs,
// 1-63 characters, never starting or ending with a hyphen).
var resourceIDLabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// maxResourceIDBytes mirrors the practical Kubernetes name length limit that
// applies to a ResourceID's underlying group.
const maxResourceIDBytes = 253

// validResourceID reports whether id has the shape a ResourceID requires: at
// least two "."-separated segments (a resource kind, then one or more group
// labels), every segment a DNS-1123 label, and the whole string within
// maxResourceIDBytes. id is never normalized — only accepted or rejected as
// given, with no fallback that lets a malformed value through in some
// truncated or lowercased form.
func validResourceID(id string) bool {
	if id == "" || len(id) > maxResourceIDBytes {
		return false
	}
	segments := strings.Split(id, ".")
	if len(segments) < 2 {
		return false
	}
	for _, s := range segments {
		if !resourceIDLabelPattern.MatchString(s) {
			return false
		}
	}
	return true
}

// Valid reports whether o's Resource and ResourceID fields are internally
// consistent: Resource must be ResourceNone unless Kind == OwnerKubernetes,
// and non-ResourceNone when it is; ResourceID must be "" unless Kind alone
// leaves the concrete resource type undetermined (OwnerKubernetes with
// Resource == ResourceOther, or OwnerFlux), in which case it must be a
// validResourceID "<kind>.<group>" string for the former, and specifically
// one of ResourceIDFluxKustomization or ResourceIDFluxHelmRelease for the
// latter. An owner that fails Valid must never be added to an OwnerChain —
// there is no fallback that carries an unvalidated identifier across the
// package boundary instead.
func (o DeployOwner) Valid() bool {
	if o.Kind == OwnerKubernetes {
		if o.Resource == ResourceNone {
			return false
		}
	} else if o.Resource != ResourceNone {
		return false
	}

	switch {
	case o.Kind == OwnerKubernetes && o.Resource == ResourceOther:
		return validResourceID(o.ResourceID)
	case o.Kind == OwnerFlux:
		return o.ResourceID == ResourceIDFluxKustomization || o.ResourceID == ResourceIDFluxHelmRelease
	default:
		return o.ResourceID == ""
	}
}
