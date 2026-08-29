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
)

// Workload is the higher-level grouping a Container observably belongs to.
// Group and Name are only meaningful when Kind != WorkloadUnknown.
type Workload struct {
	Kind  WorkloadKind
	Group string // compose: project. "" when unknown.
	Name  string // compose: service. "" when unknown.
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
