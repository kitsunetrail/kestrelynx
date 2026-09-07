package inventory

import "sort"

// RunningImage is one running container's image identity as reported by a
// Runtime Adapter. Ref is the human-readable reference used for display and
// history continuity. Config, Registry, and Platform are the boundary-
// validated identity fields a Runtime Adapter may resolve; Docker only ever
// resolves Config (Registry and Platform stay their zero value). The raw
// value behind any of them (if any) never reaches this type — it is a
// runtime-specific diagnostic value, not part of the common vocabulary, and
// adapters keep it (or don't) entirely at their own discretion.
type RunningImage struct {
	Ref      string
	Config   Digest      // Kind == DigestConfig, or DigestUnknown when unresolved.
	Registry RegistryRef // runtime-resolved registry reference; zero value on Docker.
	Platform Platform
}

// ContentID is the derived accessor existing callers use: the OCI image
// config digest in wire format, or "" when Config isn't a config digest.
// This is a projection of Config, not a second source of truth — nothing
// else in this type stores identity redundantly.
func (r RunningImage) ContentID() string {
	if r.Config.Kind != DigestConfig {
		return ""
	}
	return r.Config.String()
}

// DistinctImages reduces a container observation list to the set of
// distinct running images: de-duplicated on (Ref, EntityKey) and sorted by
// Ref then EntityKey. The same image name running the same resolved entity
// yields one entry; the same name running a distinct entity is kept as a
// separate entry so scanning and identity never silently merge them
// (docs/REQUIREMENTS.md F-2). Two unresolved observations under the same Ref
// still collapse to one entry (an EntityKey cannot be derived from a
// reference, so they'd share the same zero-value key regardless); unresolved
// observations under different Refs never collide, since Ref is always part
// of the key. Containers with an empty Ref are excluded — there is nothing
// to scan.
func DistinctImages(containers []Container) []RunningImage {
	type dedupKey struct {
		ref string
		key EntityKey
	}
	seen := map[dedupKey]bool{}
	images := make([]RunningImage, 0, len(containers))
	for _, ct := range containers {
		img := ct.Image
		if img.Ref == "" {
			continue
		}
		key, _ := EntityKeyOf(img) // zero value when unresolved, same as every other unresolved image under this Ref
		k := dedupKey{img.Ref, key}
		if seen[k] {
			continue
		}
		seen[k] = true
		images = append(images, img)
	}
	sort.Slice(images, func(i, j int) bool {
		if images[i].Ref != images[j].Ref {
			return images[i].Ref < images[j].Ref
		}
		ki, _ := EntityKeyOf(images[i])
		kj, _ := EntityKeyOf(images[j])
		return lessEntityKey(ki, kj)
	})
	return images
}

// lessEntityKey orders two EntityKeys deterministically: Digest.Kind first
// (the zero value "" for an unresolved entity sorts before either resolved
// kind), then Hex, then Platform field by field. For Docker (Config-kind
// digests only, Platform always zero) this reduces to comparing Hex alone —
// the same order comparing the old ContentID() wire string produced, since
// both digests share the constant "sha256:" prefix.
func lessEntityKey(a, b EntityKey) bool {
	if a.Digest.Kind != b.Digest.Kind {
		return a.Digest.Kind < b.Digest.Kind
	}
	if a.Digest.Hex != b.Digest.Hex {
		return a.Digest.Hex < b.Digest.Hex
	}
	if a.Platform.OS != b.Platform.OS {
		return a.Platform.OS < b.Platform.OS
	}
	if a.Platform.Architecture != b.Platform.Architecture {
		return a.Platform.Architecture < b.Platform.Architecture
	}
	return a.Platform.Variant < b.Platform.Variant
}
