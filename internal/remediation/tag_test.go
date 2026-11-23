package remediation

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

func TestParseImageRef(t *testing.T) {
	d := "sha256:" + hex64('a')
	cases := []struct {
		ref      string
		kind     TagKind
		exclude  ExcludeReason
		repo     string
		tag      string
		implicit bool
	}{
		{"nginx:1.25.3", TagPinned, "", "nginx", "1.25.3", false},
		{"nginx:1.25.3-alpine", TagPinned, "", "nginx", "1.25.3-alpine", false},
		{"ghcr.io/o/app:v2.4.1-bookworm", TagPinned, "", "ghcr.io/o/app", "v2.4.1-bookworm", false},
		{"localhost:5000/app:0.0.0", TagPinned, "", "localhost:5000/app", "0.0.0", false},
		{"postgres:16", TagFloating, "", "postgres", "16", false},
		{"nginx:1.25", TagFloating, "", "nginx", "1.25", false},
		{"nginx:latest", TagFloating, "", "nginx", "latest", false},
		{"debian:bookworm", TagFloating, "", "debian", "bookworm", false},
		{"postgres:16-alpine", TagFloating, "", "postgres", "16-alpine", false},
		{"ubuntu:22.04", TagFloating, "", "ubuntu", "22.04", false},
		{"app:v3", TagFloating, "", "app", "v3", false},
		{"app:v1.2-alpine", TagFloating, "", "app", "v1.2-alpine", false},
		{"app:bookworm-slim", TagFloating, "", "app", "bookworm-slim", false},
		{"app:1..2", TagExcluded, ExcludeUnsupportedTag, "app", "1..2", false},
		{"app:1.2.", TagExcluded, ExcludeUnsupportedTag, "app", "1.2.", false},
		{"app:1.", TagExcluded, ExcludeUnsupportedTag, "app", "1.", false},
		{"app:v1.2.x", TagExcluded, ExcludeUnsupportedTag, "app", "v1.2.x", false},
		{"app:1.2-alpine", TagFloating, "", "app", "1.2-alpine", false},
		{"app:0", TagFloating, "", "app", "0", false},
		{"nginx:1.25.3.4", TagExcluded, ExcludeUnsupportedTag, "nginx", "1.25.3.4", false},
		{"app:1.2.3.4-alpine", TagExcluded, ExcludeUnsupportedTag, "app", "1.2.3.4-alpine", false},
		{"app:1.2.3final", TagExcluded, ExcludeUnsupportedTag, "app", "1.2.3final", false},
		{"app:2024.01.15", TagExcluded, ExcludeUnsupportedTag, "app", "2024.01.15", false},
		{"nginx", TagFloating, "", "nginx", "latest", true},
		{"nginx@" + d, TagExcluded, ExcludeDigestOnly, "nginx", "", false},
		{"nginx:1.25.3@" + d, TagExcluded, ExcludeTagAndDigest, "nginx", "1.25.3", false},
		{"nginx:1.25.3-rc1", TagExcluded, ExcludePrerelease, "nginx", "1.25.3-rc1", false},
		{"app:2.0.0-beta.2", TagExcluded, ExcludePrerelease, "app", "2.0.0-beta.2", false},
		{"app:1.2.3rc1", TagExcluded, ExcludePrerelease, "app", "1.2.3rc1", false},
		{"app:1.2.3-rc.1", TagExcluded, ExcludePrerelease, "app", "1.2.3-rc.1", false},
		{"app:1.2.3a1", TagExcluded, ExcludePrerelease, "app", "1.2.3a1", false},
		{"app:2.0.0b2", TagExcluded, ExcludePrerelease, "app", "2.0.0b2", false},
		{"app:1.2.3-alpine3.19", TagPinned, "", "app", "1.2.3-alpine3.19", false},
		{"app:nightly", TagExcluded, ExcludePrerelease, "app", "nightly", false},
		{"app:dev", TagExcluded, ExcludePrerelease, "app", "dev", false},
		{"app:canary", TagExcluded, ExcludePrerelease, "app", "canary", false},
		{"app:1.2.3-alpine", TagPinned, "", "app", "1.2.3-alpine", false}, // "alpine" is not "alpha"
		{"app:sha-5cf2d7b", TagFloating, "", "app", "sha-5cf2d7b", false},
		{"app:sha-3a1b2c4", TagFloating, "", "app", "sha-3a1b2c4", false}, // "3a1" is not a prerelease marker in a commit id
		{"app:3a1b2c4", TagFloating, "", "app", "3a1b2c4", false},
		{"app:sha-3a1b2c", TagExcluded, ExcludePrerelease, "app", "sha-3a1b2c", false}, // six digits are not a commit id
		{d, TagExcluded, ExcludeBareDigest, "", "", false},
		{"", TagExcluded, ExcludeUnparsable, "", "", false},
		{"Not A Ref", TagExcluded, ExcludeUnparsable, "", "", false},
		{"app:1.02.3", TagExcluded, ExcludeUnsupportedTag, "app", "1.02.3", false},
		{"app:99999999999.1.1", TagExcluded, ExcludeUnsupportedTag, "app", "99999999999.1.1", false},
	}
	for _, c := range cases {
		t.Run(c.ref, func(t *testing.T) {
			got := ParseImageRef(c.ref)
			if got.Kind != c.kind || got.Exclude != c.exclude {
				t.Fatalf("kind/exclude = %q/%q, want %q/%q", got.Kind, got.Exclude, c.kind, c.exclude)
			}
			if got.Repository != c.repo || got.Tag != c.tag || got.ImplicitTag != c.implicit {
				t.Errorf("repo/tag/implicit = %q/%q/%v, want %q/%q/%v", got.Repository, got.Tag, got.ImplicitTag, c.repo, c.tag, c.implicit)
			}
			if got.Kind == TagPinned && got.Version.String() != got.Tag {
				t.Errorf("version %q does not render back to tag %q", got.Version.String(), got.Tag)
			}
		})
	}
}

func TestSelectPinned(t *testing.T) {
	cur := func(tag string) TagVersion {
		v, ok := ParseTagVersion(tag)
		if !ok {
			t.Fatalf("bad test tag %q", tag)
		}
		return v
	}
	cases := []struct {
		name    string
		current string
		list    registry.TagList
		outcome SelectionOutcome
		want    string
	}{
		{"highest patch wins", "1.25.3", registry.TagList{Tags: []string{"1.25.2", "1.25.4", "1.25.10", "1.25.9", "latest"}}, SelectionFound, "1.25.10"},
		{"numeric not lexical", "1.25.3", registry.TagList{Tags: []string{"1.25.9", "1.25.10"}}, SelectionFound, "1.25.10"},
		{"suffix kept", "1.25.3-alpine", registry.TagList{Tags: []string{"1.25.5", "1.25.4-alpine", "1.25.6-bookworm"}}, SelectionFound, "1.25.4-alpine"},
		{"prefix kept", "v2.4.1", registry.TagList{Tags: []string{"2.4.9", "v2.4.2", "w2.4.8"}}, SelectionFound, "v2.4.2"},
		{"same major.minor only", "1.25.3", registry.TagList{Tags: []string{"1.26.0", "1.24.9", "2.25.9"}}, SelectionNone, ""},
		{"lower or equal patch ignored", "1.25.3", registry.TagList{Tags: []string{"1.25.3", "1.25.1"}}, SelectionNone, ""},
		{"prerelease skipped", "1.25.3", registry.TagList{Tags: []string{"1.25.4-rc1", "1.25.5-beta", "1.25.4"}}, SelectionFound, "1.25.4"},
		{"only prerelease newer", "1.25.3", registry.TagList{Tags: []string{"1.25.4-rc1"}}, SelectionNone, ""},
		{"imprecise tags are not candidates", "1.25.3", registry.TagList{Tags: []string{"1.25", "1.25.4.1"}}, SelectionNone, ""},
		{"empty complete listing", "1.25.3", registry.TagList{}, SelectionNone, ""},
		{"truncated with candidate", "1.25.3", registry.TagList{Tags: []string{"1.25.4"}, Truncated: true}, SelectionIncomplete, ""},
		{"truncated without candidate", "1.25.3", registry.TagList{Truncated: true}, SelectionIncomplete, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SelectPinned(cur(c.current), c.list)
			if got.Outcome != c.outcome || got.Tag != c.want {
				t.Errorf("got %q %q, want %q %q", got.Outcome, got.Tag, c.outcome, c.want)
			}
		})
	}
}

func TestClassifyTagLeadingDot(t *testing.T) {
	// A leading dot cannot appear in a valid reference, but the classifier
	// must not call it floating if it is handed one.
	for _, tag := range []string{".1", ".", "..2"} {
		if kind, _, why := classifyTag(tag); kind != TagExcluded || why != ExcludeUnsupportedTag {
			t.Errorf("classifyTag(%q) = %q/%q", tag, kind, why)
		}
	}
}

func TestIsCommitTag(t *testing.T) {
	for tag, want := range map[string]bool{
		"sha-5cf2d7b":            true,
		"sha-1234567":            true,
		"5cf2d7b":                true,
		"abcdefa":                true,
		"sha-" + hex64('a')[:40]: true,
		hex64('a')[:40]:          true,
		"sha-5cf2d7":             false, // six digits
		"5cf2d7":                 false,
		"sha-" + hex64('a')[:41]: false, // longer than a commit id
		"1234567":                false, // a number
		"20260115":               false,
		"sha-5CF2D7B":            false,
		"sha-5cf2d7g":            false,
		"sha-5cf2d7b-alpine":     false,
		"main-5cf2d7b":           false,
		"latest":                 false,
		"1.25.3":                 false,
		"22-alpine":              false,
		"":                       false,
	} {
		if got := IsCommitTag(tag); got != want {
			t.Errorf("IsCommitTag(%q) = %v, want %v", tag, got, want)
		}
	}
}
