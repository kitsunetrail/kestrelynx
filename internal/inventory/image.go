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
// distinct running images: de-duplicated on (Ref, ContentID()) and sorted by
// Ref then ContentID(). The same image name running the same validated
// content yields one entry; the same name running distinct content is kept
// as separate entries so scanning and identity never silently merge them
// (docs/REQUIREMENTS.md F-2). Containers with an empty Ref are excluded —
// there is nothing to scan.
func DistinctImages(containers []Container) []RunningImage {
	type dedupKey struct{ ref, contentID string }
	seen := map[dedupKey]bool{}
	images := make([]RunningImage, 0, len(containers))
	for _, ct := range containers {
		img := ct.Image
		if img.Ref == "" {
			continue
		}
		k := dedupKey{img.Ref, img.ContentID()}
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
		return images[i].ContentID() < images[j].ContentID()
	})
	return images
}
