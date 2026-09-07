package kubernetes

import (
	"math/rand"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// TestSortContainers_Deterministic exercises every tiebreak tier of
// sortContainers' key: (Image.Ref, Image.Config.Hex,
// Image.Registry.Digest.Hex, Image.Platform.OS, Image.Platform.Architecture,
// Image.Platform.Variant, Workload.Group, Workload.Name, Container.Name).
// Each entry below differs from the previous one in exactly the next tier,
// so a comparator that stopped checking early (or checked tiers out of
// order) would misplace at least one of them.
func TestSortContainers_Deterministic(t *testing.T) {
	want := []inventory.Container{
		{Name: "z", Image: inventory.RunningImage{Ref: "a"}},
		{Name: "z", Image: inventory.RunningImage{Ref: "b"}},
		{
			Name: "z",
			Image: inventory.RunningImage{
				Ref:    "b",
				Config: inventory.Digest{Hex: "config-hex-1"},
			},
		},
		{
			Name: "z",
			Image: inventory.RunningImage{
				Ref:      "b",
				Config:   inventory.Digest{Hex: "config-hex-1"},
				Registry: inventory.RegistryRef{Digest: inventory.Digest{Hex: "registry-hex-1"}},
			},
		},
		{
			Name: "z",
			Image: inventory.RunningImage{
				Ref:      "b",
				Config:   inventory.Digest{Hex: "config-hex-1"},
				Registry: inventory.RegistryRef{Digest: inventory.Digest{Hex: "registry-hex-1"}},
				Platform: inventory.Platform{OS: "linux"},
			},
		},
		{
			Name: "z",
			Image: inventory.RunningImage{
				Ref:      "b",
				Config:   inventory.Digest{Hex: "config-hex-1"},
				Registry: inventory.RegistryRef{Digest: inventory.Digest{Hex: "registry-hex-1"}},
				Platform: inventory.Platform{OS: "linux", Architecture: "amd64"},
			},
		},
		{
			Name: "z",
			Image: inventory.RunningImage{
				Ref:      "b",
				Config:   inventory.Digest{Hex: "config-hex-1"},
				Registry: inventory.RegistryRef{Digest: inventory.Digest{Hex: "registry-hex-1"}},
				Platform: inventory.Platform{OS: "linux", Architecture: "amd64", Variant: "v8"},
			},
		},
		{
			Name: "z",
			Image: inventory.RunningImage{
				Ref:      "b",
				Config:   inventory.Digest{Hex: "config-hex-1"},
				Registry: inventory.RegistryRef{Digest: inventory.Digest{Hex: "registry-hex-1"}},
				Platform: inventory.Platform{OS: "linux", Architecture: "amd64", Variant: "v8"},
			},
			Workload: inventory.Workload{Group: "group-1"},
		},
		{
			Name: "a",
			Image: inventory.RunningImage{
				Ref:      "b",
				Config:   inventory.Digest{Hex: "config-hex-1"},
				Registry: inventory.RegistryRef{Digest: inventory.Digest{Hex: "registry-hex-1"}},
				Platform: inventory.Platform{OS: "linux", Architecture: "amd64", Variant: "v8"},
			},
			Workload: inventory.Workload{Group: "group-1", Name: "workload-1"},
		},
		{
			Name: "z", // Container.Name, the last tiebreak: "z" sorts after "a" above with every other field equal.
			Image: inventory.RunningImage{
				Ref:      "b",
				Config:   inventory.Digest{Hex: "config-hex-1"},
				Registry: inventory.RegistryRef{Digest: inventory.Digest{Hex: "registry-hex-1"}},
				Platform: inventory.Platform{OS: "linux", Architecture: "amd64", Variant: "v8"},
			},
			Workload: inventory.Workload{Group: "group-1", Name: "workload-1"},
		},
	}

	for trial := 0; trial < 5; trial++ {
		got := append([]inventory.Container(nil), want...)
		rand.Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })

		sortContainers(got)

		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("trial %d: position %d = %+v, want %+v (full got: %+v)", trial, i, got[i], want[i], got)
			}
		}
	}
}
