package inventory

import "testing"

// contentID1 / contentID2 are two distinct, well-formed OCI image config
// digests used across the DistinctImages tests below.
const (
	contentID1 = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	contentID2 = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
)

// configDigest1 / configDigest2 are contentID1 / contentID2 already parsed
// into the Config field DistinctImages actually keys on.
var (
	configDigest1 = mustParseDigest(DigestConfig, contentID1)
	configDigest2 = mustParseDigest(DigestConfig, contentID2)
)

// mustParseDigest parses s as kind or fails the test binary immediately —
// only ever used to build well-formed test fixtures, never production data.
func mustParseDigest(kind DigestKind, s string) Digest {
	d, ok := ParseDigest(kind, s)
	if !ok {
		panic("test fixture: invalid digest " + s)
	}
	return d
}

// TestDistinctImages_MatchesLegacyDockerRunningImages exercises the same
// branches internal/docker.RunningImages used to cover before it was
// replaced by RunningContainers + DistinctImages: same ref/same content ID
// dedupes to one entry, same ref/different content ID stays as two entries,
// a missing or malformed source ImageID both surface here as an empty
// ContentID() (DistinctImages only ever sees the adapter's already-validated
// output — it can't tell "missing" from "malformed" and doesn't need to,
// since neither participates differently in the dedup key), and an empty Ref
// is excluded regardless of ContentID().
func TestDistinctImages_MatchesLegacyDockerRunningImages(t *testing.T) {
	containers := []Container{
		// same ref, same ContentID (e.g. two replicas of one Compose service) -> one entry
		{Name: "web1", Image: RunningImage{Ref: "nginx:1.25", Config: configDigest1}},
		{Name: "web2", Image: RunningImage{Ref: "nginx:1.25", Config: configDigest1}},
		// same ref, distinct ContentID -> both entries kept, never merged
		{Name: "a", Image: RunningImage{Ref: "shared:tag", Config: configDigest1}},
		{Name: "b", Image: RunningImage{Ref: "shared:tag", Config: configDigest2}},
		// ImageID missing at the source -> ContentID empty, still counted
		{Name: "c", Image: RunningImage{Ref: "alpine:3.20"}},
		// ImageID malformed at the source -> also ContentID empty (indistinguishable here)
		{Name: "d", Image: RunningImage{Ref: "busybox:1"}},
		// empty Ref (nothing to scan) is excluded regardless of ContentID
		{Name: "e", Image: RunningImage{Ref: "", Config: configDigest1}},
	}

	got := DistinctImages(containers)
	want := []RunningImage{
		{Ref: "alpine:3.20"},
		{Ref: "busybox:1"},
		{Ref: "nginx:1.25", Config: configDigest1},
		{Ref: "shared:tag", Config: configDigest1},
		{Ref: "shared:tag", Config: configDigest2},
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
		{Name: "b", Image: RunningImage{Ref: "", Config: configDigest1}},
	}
	if got := DistinctImages(containers); len(got) != 0 {
		t.Errorf("got %+v, want empty (all Refs blank)", got)
	}
}
