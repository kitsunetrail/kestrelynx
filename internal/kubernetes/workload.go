package kubernetes

import "github.com/kitsunetrail/kestrelynx/internal/inventory"

// apiVersion strings every allow-listed owner Kind must match exactly. A
// same-named Kind under a different apiVersion — a CRD such as
// argoproj.io/v1alpha1 Rollout, or a same-named "Deployment" under some other
// group — is outside the allow-list, not guessed at.
const (
	appsV1  = "apps/v1"
	batchV1 = "batch/v1"
)

// ownerReference is the subset of a Kubernetes ownerReferences entry this
// package reads: enough to identify the controller owner (Controller ==
// true) and validate it against resolveWorkload's allow-list.
type ownerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller"`
}

// ownedMetadata is the subset of metadata this package reads from any
// namespaced object that participates in owner-reference resolution: Pod,
// ReplicaSet, and Job all share this shape.
type ownedMetadata struct {
	Namespace       string           `json:"namespace"`
	Name            string           `json:"name"`
	UID             string           `json:"uid"`
	OwnerReferences []ownerReference `json:"ownerReferences"`
}

// replicaSetRaw is the subset of a ReplicaSet object this package reads: just
// enough metadata to relay a Pod's owner reference on to a Deployment. Its
// actual Kind is never read back from the object itself — it's trusted
// because it came from the apps/v1 replicasets endpoint, the same way every
// other typed LIST in this package trusts the endpoint it was fetched from.
type replicaSetRaw struct {
	Metadata ownedMetadata `json:"metadata"`
}

// jobRaw is the subset of a Job object this package reads: just enough
// metadata to relay a Pod's owner reference on to a CronJob. Its Kind is
// trusted from the batch/v1 jobs endpoint for the same reason as
// replicaSetRaw.
type jobRaw struct {
	Metadata ownedMetadata `json:"metadata"`
}

// ownedKey builds the "<namespace>/<uid>" lookup key resolveWorkload uses to
// find a relay object (ReplicaSet, Job) by identity rather than by name: a
// deleted-and-recreated resource keeps its name but gets a new UID, and only
// the UID actually names one object across that history. Namespace names are
// DNS-1123 labels and UIDs are UUIDs, so neither ever contains "/" and the
// two can't collide across the separator.
func ownedKey(namespace, uid string) string {
	return namespace + "/" + uid
}

// indexReplicaSets builds the ns+uid -> ReplicaSet lookup resolveWorkload
// relays Pod -> Deployment chains through. Entries with an empty UID are
// skipped rather than indexed under a key that other empty-UID entries could
// collide on.
func indexReplicaSets(list []replicaSetRaw) map[string]replicaSetRaw {
	m := make(map[string]replicaSetRaw, len(list))
	for _, rs := range list {
		if rs.Metadata.UID == "" {
			continue
		}
		m[ownedKey(rs.Metadata.Namespace, rs.Metadata.UID)] = rs
	}
	return m
}

// indexJobs builds the ns+uid -> Job lookup resolveWorkload relays Pod ->
// CronJob chains through, with the same empty-UID exclusion as
// indexReplicaSets.
func indexJobs(list []jobRaw) map[string]jobRaw {
	m := make(map[string]jobRaw, len(list))
	for _, j := range list {
		if j.Metadata.UID == "" {
			continue
		}
		m[ownedKey(j.Metadata.Namespace, j.Metadata.UID)] = j
	}
	return m
}

// controllerOwner inspects refs for ownerReferences with Controller == true
// and reports which of three states hold:
//   - none found:      ok == false, ambiguous == false
//   - exactly one:     ok == true, ref is that one
//   - more than one:   ok == false, ambiguous == true
//
// Kubernetes guarantees at most one controller reference per object, but this
// package only reads objects it doesn't control the creation of — a
// malformed one is possible, and picking the first of several would make the
// resolved Workload depend on array order, which is not a documented
// contract. ambiguous is reported separately from "none found" specifically
// so a caller never mistakes "the object is malformed" for "the object has
// no controller" (the latter is a legitimate, meaningful state — it's what
// makes a bare Pod a WorkloadPod and a bare Job a WorkloadJob).
func controllerOwner(refs []ownerReference) (ref ownerReference, ok bool, ambiguous bool) {
	for _, r := range refs {
		if !r.Controller {
			continue
		}
		if ok {
			return ownerReference{}, false, true
		}
		ref, ok = r, true
	}
	return ref, ok, false
}

// resolveWorkload walks a Pod's controller owner-reference chain to the
// top-level workload that owns it, per the allow-list:
//
//	Pod -> StatefulSet (apps/v1)                        -> that StatefulSet
//	Pod -> DaemonSet (apps/v1)                          -> that DaemonSet
//	Pod -> ReplicaSet (apps/v1) -> Deployment (apps/v1)  -> that Deployment
//	Pod -> Job (batch/v1) -> CronJob (batch/v1)          -> that CronJob
//	Pod -> Job (batch/v1), no controller owner            -> that Job
//	Pod, no controller owner                              -> the Pod itself
//
// Anything outside this allow-list — an unrecognized Kind, a same-named Kind
// under a different apiVersion, a controller reference with an empty UID at
// any step, more than one controller reference on any object walked, a relay
// object (ReplicaSet/Job) missing from rsByKey/jobByKey, a ReplicaSet with no
// controller owner of its own (a bare ReplicaSet), or a relay whose
// controller owner fails these same checks — resolves to WorkloadUnknown
// (the zero Workload) rather than a guess. An empty UID is rejected even on
// a terminal reference (StatefulSet/DaemonSet/Deployment/CronJob) that never
// goes through an index lookup, since accepting it there would trust an
// incomplete ownerReference the relay paths would never accept.
func resolveWorkload(pod podRaw, rsByKey map[string]replicaSetRaw, jobByKey map[string]jobRaw) inventory.Workload {
	ns := pod.Metadata.Namespace
	ctrl, ok, ambiguous := controllerOwner(pod.Metadata.OwnerReferences)
	if ambiguous {
		return inventory.Workload{}
	}
	if !ok {
		return inventory.Workload{Kind: inventory.WorkloadPod, Group: ns, Name: pod.Metadata.Name}
	}

	switch {
	case ctrl.APIVersion == appsV1 && ctrl.Kind == "StatefulSet":
		if ctrl.UID == "" {
			return inventory.Workload{}
		}
		return inventory.Workload{Kind: inventory.WorkloadStatefulSet, Group: ns, Name: ctrl.Name}

	case ctrl.APIVersion == appsV1 && ctrl.Kind == "DaemonSet":
		if ctrl.UID == "" {
			return inventory.Workload{}
		}
		return inventory.Workload{Kind: inventory.WorkloadDaemonSet, Group: ns, Name: ctrl.Name}

	case ctrl.APIVersion == appsV1 && ctrl.Kind == "ReplicaSet":
		if ctrl.UID == "" {
			return inventory.Workload{}
		}
		rs, found := rsByKey[ownedKey(ns, ctrl.UID)]
		if !found {
			return inventory.Workload{}
		}
		rsCtrl, ok, ambiguous := controllerOwner(rs.Metadata.OwnerReferences)
		if ambiguous || !ok || rsCtrl.APIVersion != appsV1 || rsCtrl.Kind != "Deployment" || rsCtrl.UID == "" {
			return inventory.Workload{}
		}
		return inventory.Workload{Kind: inventory.WorkloadDeployment, Group: ns, Name: rsCtrl.Name}

	case ctrl.APIVersion == batchV1 && ctrl.Kind == "Job":
		if ctrl.UID == "" {
			return inventory.Workload{}
		}
		job, found := jobByKey[ownedKey(ns, ctrl.UID)]
		if !found {
			return inventory.Workload{}
		}
		jobCtrl, ok, ambiguous := controllerOwner(job.Metadata.OwnerReferences)
		if ambiguous {
			return inventory.Workload{}
		}
		if !ok {
			return inventory.Workload{Kind: inventory.WorkloadJob, Group: ns, Name: ctrl.Name}
		}
		if jobCtrl.APIVersion != batchV1 || jobCtrl.Kind != "CronJob" || jobCtrl.UID == "" {
			return inventory.Workload{}
		}
		return inventory.Workload{Kind: inventory.WorkloadCronJob, Group: ns, Name: jobCtrl.Name}

	default:
		return inventory.Workload{}
	}
}
