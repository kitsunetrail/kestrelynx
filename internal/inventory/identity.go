package inventory

import "regexp"

// DigestKind distinguishes what a Digest actually identifies. The two kinds
// are never comparable to each other: a config digest and a registry digest
// are hashes of different objects, so an untyped string match between them
// would be meaningless rather than merely wrong.
type DigestKind string

const (
	// DigestUnknown is the zero value. It represents an unresolved or
	// boundary-rejected digest and never participates in any identity
	// decision.
	DigestUnknown DigestKind = ""
	// DigestConfig is the OCI image config digest (Docker's ImageID). This is
	// exactly the value the former ContentID field carried.
	DigestConfig DigestKind = "config"
	// DigestRegistry is a digest a registry can resolve a reference by
	// (`repo@sha256:...`). Whether it names a single-platform manifest or a
	// multi-platform index is not distinguished — this product never queries
	// a registry to tell them apart — so a DigestRegistry value may cover
	// more than one platform and must always be paired with Platform when
	// used as an identity key.
	DigestRegistry DigestKind = "registry"
)

// digestPattern is the sole boundary check for a wire-format digest: an
// exact "sha256:" prefix followed by 64 lowercase hex characters. Anything
// else (wrong length, uppercase, a different algorithm) is rejected outright
// — no normalization or guessing.
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Digest is a content-addressed identifier, tagged with what it identifies.
// Algorithm is kept separate from Hex so a future algorithm can be rejected
// explicitly at the boundary instead of silently falling through a
// sha256-shaped regexp; because equality is per-field, digests of different
// algorithms are never compared as if they were the same value.
type Digest struct {
	Kind      DigestKind
	Algorithm string // only "sha256" is currently accepted.
	Hex       string // lowercase, 64 characters for sha256.
}

// Valid reports whether d is a usable digest: Kind must be one of the
// enumerated kinds (never Kind != DigestUnknown, which would also accept an
// undefined DigestKind value), Algorithm must be "sha256", and Hex must be
// 64 lowercase hex characters.
func (d Digest) Valid() bool {
	if d.Kind != DigestConfig && d.Kind != DigestRegistry {
		return false
	}
	if d.Algorithm != "sha256" {
		return false
	}
	return digestPattern.MatchString(d.Algorithm + ":" + d.Hex)
}

// String renders d in wire format ("sha256:<hex>") when Valid, and ""
// otherwise — an invalid Digest never produces a value that looks usable.
func (d Digest) String() string {
	if !d.Valid() {
		return ""
	}
	return d.Algorithm + ":" + d.Hex
}

// ParseDigest is the only path that constructs a non-zero Digest. s must be
// exactly "sha256:<64 lowercase hex characters>"; anything else (wrong
// length, uppercase, a different algorithm, no prefix) returns the zero
// Digest and false rather than a partially-trusted value. The raw string
// never reaches the returned Digest on failure — callers that want it for
// diagnostics must keep it themselves.
func ParseDigest(kind DigestKind, s string) (Digest, bool) {
	if !digestPattern.MatchString(s) {
		return Digest{}, false
	}
	d := Digest{Kind: kind, Algorithm: "sha256", Hex: s[len("sha256:"):]}
	if !d.Valid() {
		return Digest{}, false
	}
	return d, true
}

// RegistryRef is where a registry digest can be fetched from, kept separate
// from what it identifies: Repository is location, not identity (the same
// manifest content can live under several repositories, e.g. mirrors).
type RegistryRef struct {
	Repository string // reference, parsed and normalized. "" means unknown location.
	Digest     Digest // Kind == DigestRegistry when set.
}

// Platform is the platform an image entity targets. The zero value means
// unknown, not "any platform" — Known distinguishes the two.
type Platform struct {
	OS           string // e.g. "linux".
	Architecture string // e.g. "amd64".
	Variant      string // e.g. "v8". "" when not applicable.
}

// Known reports whether p carries an actual platform, as opposed to being
// unset.
func (p Platform) Known() bool { return p.OS != "" && p.Architecture != "" }

// EntityKey is the sole unit of "is this the same image entity" comparison.
// Platform only contributes to the key for a registry-kind digest: a config
// digest already hashes one specific platform's config, so pairing it with a
// separately observed Platform would split identical config-digest
// observations into different entities depending on whether Platform
// happened to be known that cycle.
type EntityKey struct {
	Digest   Digest
	Platform Platform // zero value (ignored) when Digest.Kind == DigestConfig.
}

// EntityKeyOf derives the entity key an observation resolves to, or reports
// ok == false when none can be derived. Each branch checks the specific Kind
// it expects rather than relying on Valid() alone — Valid() only confirms
// Kind is one of the two enumerated values, not which one, so a Digest
// misassigned to the wrong field (a registry digest stored in Config, say)
// must not be mistaken for the kind that field is documented to hold.
//
// Derivation, in order:
//   - img.Config is a valid config digest: key is {Config, Platform{}}.
//   - otherwise, img.Registry.Digest is a valid registry digest and
//     img.Platform is known: key is {Registry.Digest, Platform}.
//   - otherwise (registry digest valid but Platform unknown, or neither
//     digest valid): no key can be derived, ok == false. A registry digest
//     without a known platform is never treated as identifying, even within
//     a single Environment, since an index digest does not pin a platform
//     (a mixed-architecture cluster can observe the same index digest under
//     two different running platforms).
func EntityKeyOf(img RunningImage) (EntityKey, bool) {
	if img.Config.Kind == DigestConfig && img.Config.Valid() {
		return EntityKey{Digest: img.Config}, true
	}
	if img.Registry.Digest.Kind == DigestRegistry && img.Registry.Digest.Valid() && img.Platform.Known() {
		return EntityKey{Digest: img.Registry.Digest, Platform: img.Platform}, true
	}
	return EntityKey{}, false
}

// ImageSubject is the subject scanning, analysis, and display work with: an
// observation that may or may not have resolved to an EntityKey. Ref always
// exists (it is the display and history-continuity axis); Key is only
// meaningful when Resolved is true. Two resolved subjects are the same
// subject iff their Key is equal; if either is unresolved, they are the same
// subject iff their Ref is equal — an EntityKey cannot be derived from a
// reference (a digest carries no name), and two unresolved observations
// under different references must never collide just because they share the
// same zero-value Key.
type ImageSubject struct {
	Ref      string
	Key      EntityKey
	Resolved bool
}
