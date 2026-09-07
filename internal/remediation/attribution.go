// Package remediation holds the relation and judgment vocabulary built on
// top of internal/inventory's observation vocabulary: which build produced an
// image, which deployment tool owns a running entity, and (in later slices)
// how a fix is verified. Nothing here is itself observed; every value is a
// relation between observations, or a classification derived from one.
package remediation

import "time"

// OriginKind identifies which channel an attributed value came from. Origin
// is the axis candidate-resolution precedence is based on, decided per
// relation rather than by one global order: DeployOwner documents the order
// for deployment ownership, and SourceRef documents the order for
// build-origin attribution. Confidence (below) is a separate axis — how much
// a single value can be trusted — and does not by itself decide which of
// several same-relation candidates wins.
type OriginKind string

const (
	// OriginUnknown is the zero value: no origin could be determined.
	OriginUnknown OriginKind = ""
	// OriginConfig means the value came from explicit user configuration.
	OriginConfig OriginKind = "config"
	// OriginImageLabel means the value came from an OCI image label: the
	// image's own self-declared claim, unverified.
	OriginImageLabel OriginKind = "image_label"
	// OriginProvenance means the value came from a BuildKit/SLSA build
	// attestation.
	OriginProvenance OriginKind = "provenance"
	// OriginRuntime means the value came from a runtime API observation
	// (for example a Kubernetes annotation read directly off a live
	// resource), as opposed to anything declared ahead of time.
	OriginRuntime OriginKind = "runtime"
)

// Confidence ranks how much a single attributed value can be trusted, as an
// ordered enumeration rather than a numeric score: scores invite averaging
// or weighting two pieces of evidence into a third, which this product never
// does. Confidence is not the axis candidate-resolution precedence is based
// on — see OriginKind — so two candidates are never merged, or made to
// override one another, just because one has a higher Confidence than the
// other.
type Confidence string

const (
	// ConfidenceUnknown is the zero value: no confidence could be assigned.
	ConfidenceUnknown Confidence = ""
	// ConfidenceAsserted means a person stated the value explicitly; no tool
	// verified it.
	ConfidenceAsserted Confidence = "asserted"
	// ConfidenceAttested means the value came from a signed, verified
	// provenance record.
	ConfidenceAttested Confidence = "attested"
	// ConfidenceClaimed means the value is a self-declared claim (an image
	// label, a tracking annotation) that nothing has verified.
	ConfidenceClaimed Confidence = "claimed"
)

// Attribution records where a value came from, how much it can be trusted,
// and when it was observed. It is shared by every relation type in this
// package that needs to justify a value rather than just state it.
type Attribution struct {
	Origin     OriginKind
	Confidence Confidence
	ObservedAt time.Time
}
