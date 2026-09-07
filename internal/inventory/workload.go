package inventory

// WorkloadKind identifies how a Container's Workload was determined.
// WorkloadUnknown is the zero value on purpose: a Workload that was never
// set (a bug, or an adapter that made no attempt) reads as "no association
// found" rather than silently claiming a known one.
type WorkloadKind string

const (
	// WorkloadUnknown means no association could be established. This is not
	// guessed at — a standalone container is unknown, not "the workload is
	// itself".
	WorkloadUnknown WorkloadKind = ""
	// WorkloadCompose means Group/Name came from a Docker Compose project and
	// service pair.
	WorkloadCompose WorkloadKind = "compose"
	// WorkloadDeployment means Group/Name came from a Kubernetes Deployment
	// (resolved through its ReplicaSet).
	WorkloadDeployment WorkloadKind = "deployment"
	// WorkloadStatefulSet means Group/Name came from a Kubernetes StatefulSet.
	WorkloadStatefulSet WorkloadKind = "statefulset"
	// WorkloadDaemonSet means Group/Name came from a Kubernetes DaemonSet.
	WorkloadDaemonSet WorkloadKind = "daemonset"
	// WorkloadJob means Group/Name came from a Kubernetes Job that is not
	// itself owned by a CronJob.
	WorkloadJob WorkloadKind = "job"
	// WorkloadCronJob means Group/Name came from a Kubernetes CronJob
	// (resolved through its Job).
	WorkloadCronJob WorkloadKind = "cronjob"
	// WorkloadPod means the container's Pod has no controller owner
	// reference at all; Group/Name name the Pod itself, not guessed at as
	// some higher-level workload.
	WorkloadPod WorkloadKind = "pod"
)

// Workload is the higher-level grouping a Container observably belongs to.
// Group and Name are only meaningful when Kind != WorkloadUnknown.
type Workload struct {
	Kind  WorkloadKind
	Group string // compose: project. kubernetes: namespace. "" when unknown.
	Name  string // compose: service. kubernetes: top-level owner's name (or the Pod's own name for WorkloadPod). "" when unknown.
}

// Known reports whether w carries an actual workload association.
func (w Workload) Known() bool { return w.Kind != WorkloadUnknown }

// Container is one running container as observed by a Runtime Adapter,
// stripped of anything specific to that runtime. Name is a human-assigned
// display name — the container equivalent of a Kubernetes pod/container
// name — and is never confused with an opaque runtime ID.
type Container struct {
	Name     string // adapter-normalized display name; "" when it couldn't be determined.
	Workload Workload
	Image    RunningImage
}
