package kubernetes

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestParseImageID(t *testing.T) {
	validHex := strings.Repeat("a", 64)
	cases := []struct {
		name     string
		raw      string
		wantOK   bool
		wantRepo string
		wantHex  string
	}{
		{
			name:     "repo at sha256 accepted",
			raw:      "docker.io/library/nginx@sha256:" + validHex,
			wantOK:   true,
			wantRepo: "docker.io/library/nginx",
			wantHex:  validHex,
		},
		{
			name:     "docker-pullable scheme accepted",
			raw:      "docker-pullable://docker.io/library/nginx@sha256:" + validHex,
			wantOK:   true,
			wantRepo: "docker.io/library/nginx",
			wantHex:  validHex,
		},
		{
			name:   "bare sha256 with no repository rejected",
			raw:    "sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "uppercase hex rejected",
			raw:    "docker.io/library/nginx@sha256:" + strings.Repeat("A", 64),
			wantOK: false,
		},
		{
			name:   "invalid repository rejected",
			raw:    "Docker.IO/Library/Nginx@sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "repository with invalid characters rejected",
			raw:    "docker.io/library/nginx!@sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "other scheme rejected",
			raw:    "containerd://docker.io/library/nginx@sha256:" + validHex,
			wantOK: false,
		},
		{
			name:   "empty string rejected",
			raw:    "",
			wantOK: false,
		},
		{
			name:     "host:port repository accepted",
			raw:      "registry.example.com:5000/team/app@sha256:" + validHex,
			wantOK:   true,
			wantRepo: "registry.example.com:5000/team/app",
			wantHex:  validHex,
		},
		{
			name:   "wrong digest algorithm rejected",
			raw:    "docker.io/library/nginx@sha512:" + validHex,
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseImageID(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("parseImageID(%q) ok = %v, want %v (got %+v)", tc.raw, ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				if got != (inventory.RegistryRef{}) {
					t.Errorf("parseImageID(%q) = %+v on rejection, want zero value", tc.raw, got)
				}
				return
			}
			if got.Repository != tc.wantRepo {
				t.Errorf("Repository = %q, want %q", got.Repository, tc.wantRepo)
			}
			if got.Digest.Kind != inventory.DigestRegistry {
				t.Errorf("Digest.Kind = %q, want %q", got.Digest.Kind, inventory.DigestRegistry)
			}
			if got.Digest.Hex != tc.wantHex {
				t.Errorf("Digest.Hex = %q, want %q", got.Digest.Hex, tc.wantHex)
			}
			if !got.Digest.Valid() {
				t.Errorf("Digest.Valid() = false for %+v", got.Digest)
			}
		})
	}
}
