package inventory

import "testing"

// contentID1 / contentID2 are two distinct, well-formed OCI image config
// digests used across the DistinctImages tests below.
const (
	contentID1 = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	contentID2 = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
)

// TestDistinctImages_MatchesLegacyDockerRunningImages exercises the same
// branches internal/docker.RunningImages used to cover before it was
// replaced by RunningContainers + DistinctImages: same ref/same content ID
// dedupes to one entry, same ref/different content ID stays as two entries,
// a missing or malformed source ImageID both surface here as an empty
// ContentID (DistinctImages only ever sees the adapter's already-validated
// output — it can't tell "missing" from "malformed" and doesn't need to,
// since neither participates differently in the dedup key), and an empty Ref
// is excluded regardless of ContentID.
func TestDistinctImages_MatchesLegacyDockerRunningImages(t *testing.T) {
	containers := []Container{
		// same ref, same ContentID (e.g. two replicas of one Compose service) -> one entry
		{Name: "web1", Image: RunningImage{Ref: "nginx:1.25", ContentID: contentID1}},
		{Name: "web2", Image: RunningImage{Ref: "nginx:1.25", ContentID: contentID1}},
		// same ref, distinct ContentID -> both entries kept, never merged
		{Name: "a", Image: RunningImage{Ref: "shared:tag", ContentID: contentID1}},
		{Name: "b", Image: RunningImage{Ref: "shared:tag", ContentID: contentID2}},
		// ImageID missing at the source -> ContentID empty, still counted
		{Name: "c", Image: RunningImage{Ref: "alpine:3.20"}},
		// ImageID malformed at the source -> also ContentID empty (indistinguishable here)
		{Name: "d", Image: RunningImage{Ref: "busybox:1"}},
		// empty Ref (nothing to scan) is excluded regardless of ContentID
		{Name: "e", Image: RunningImage{Ref: "", ContentID: contentID1}},
	}

	got := DistinctImages(containers)
	want := []RunningImage{
		{Ref: "alpine:3.20"},
		{Ref: "busybox:1"},
		{Ref: "nginx:1.25", ContentID: contentID1},
		{Ref: "shared:tag", ContentID: contentID1},
		{Ref: "shared:tag", ContentID: contentID2},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDistinctImages_Empty(t *testing.T) {
	if got := DistinctImages(nil); len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestDistinctImages_AllBlankRefsExcluded(t *testing.T) {
	containers := []Container{
		{Name: "a", Image: RunningImage{Ref: ""}},
		{Name: "b", Image: RunningImage{Ref: "", ContentID: contentID1}},
	}
	if got := DistinctImages(containers); len(got) != 0 {
		t.Errorf("got %+v, want empty (all Refs blank)", got)
	}
}
