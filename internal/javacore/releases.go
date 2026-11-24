package javacore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

const (
	// releasePageSize is the page size requested from the Temurin release
	// list; a page with that many entries may be followed by another.
	releasePageSize = 50
	// maxReleasePages bounds how many pages of the release list are read.
	maxReleasePages = 20

	maxReleasePageBytes     = 1 << 20
	maxAvailableReleasesLen = 64 << 10
)

// releaseVersionRe reads the openjdk_version of a Temurin release:
// 21.0.13.1+2-LTS, 27.0.1.0, 27+35 or 1.8.0_514-b01. Any other form, such as
// a pre-release suffix, is not a published GA release.
var releaseVersionRe = regexp.MustCompile(`^(?:1\.8\.0_([1-9][0-9]*)-b[0-9]+|([0-9]+(?:\.[0-9]+)*)(?:\+[0-9]+(?:-LTS)?)?)$`)

// parseReleaseVersion turns the openjdk_version of a Temurin release into a
// version.
func parseReleaseVersion(s string) (version, bool) {
	m := releaseVersionRe.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	if m[1] != "" {
		return parseVersion("8u" + m[1])
	}
	return parseVersion(m[2])
}

// parseReleasePage reads one page of the Temurin release list. A body without
// content, or a list without entries, is an empty page: the list has ended.
// size is the number of entries the page held. A version that cannot be read
// is an error: matching a list that silently dropped it could name a fix
// that is not one.
func parseReleasePage(data []byte) (versions []version, size int, err error) {
	if len(data) > maxReleasePageBytes {
		return nil, 0, fmt.Errorf("release list page is larger than %d bytes", maxReleasePageBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, 0, nil
	}
	var raw struct {
		Versions *[]struct {
			OpenJDKVersion string `json:"openjdk_version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, 0, fmt.Errorf("not a release list: %w", err)
	}
	if raw.Versions == nil {
		return nil, 0, errors.New("release list has no versions field")
	}
	if len(*raw.Versions) > releasePageSize {
		return nil, 0, fmt.Errorf("release list page has more than %d entries", releasePageSize)
	}
	for _, r := range *raw.Versions {
		v, ok := parseReleaseVersion(r.OpenJDKVersion)
		if !ok {
			return nil, 0, fmt.Errorf("unreadable release version %q", clip(r.OpenJDKVersion))
		}
		versions = append(versions, v)
	}
	return versions, len(*raw.Versions), nil
}

// cachedReleases is the normalised release list kept in the cache.
type cachedReleases struct {
	Versions []string `json:"versions"`
}

// sortVersions orders versions of any series: by series, then ascending.
func sortVersions(vs []version) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].series() != vs[j].series() {
			return vs[i].series() < vs[j].series()
		}
		c, _ := vs[i].compare(vs[j])
		return c < 0
	})
}

// uniqueVersions sorts vs and drops repeated versions (the list repeats a
// version that was published again).
func uniqueVersions(vs []version) []version {
	sortVersions(vs)
	var out []version
	for _, v := range vs {
		if n := len(out); n > 0 {
			if c, ok := out[n-1].compare(v); ok && c == 0 && out[n-1].legacy == v.legacy {
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

func encodeReleases(vs []version) ([]byte, error) {
	c := cachedReleases{Versions: make([]string, len(vs))}
	for i, v := range vs {
		c.Versions[i] = v.String()
	}
	return json.Marshal(c)
}

func decodeReleases(data []byte) ([]version, error) {
	var c cachedReleases
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("not a release list: %w", err)
	}
	var vs []version
	for _, s := range c.Versions {
		v, ok := parseVersion(s)
		if !ok {
			return nil, fmt.Errorf("unreadable release version %q", clip(s))
		}
		vs = append(vs, v)
	}
	if len(vs) == 0 {
		return nil, errors.New("release list is empty")
	}
	return uniqueVersions(vs), nil
}

// availableReleases is what the Temurin list of release series says about
// which series are supported.
type availableReleases struct {
	lts    map[int]bool
	latest int // most_recent_feature_release
}

func parseAvailableReleases(data []byte) (availableReleases, error) {
	if len(data) > maxAvailableReleasesLen {
		return availableReleases{}, fmt.Errorf("release series list is larger than %d bytes", maxAvailableReleasesLen)
	}
	var raw struct {
		LTS     []int `json:"available_lts_releases"`
		MostLTS int   `json:"most_recent_lts"`
		Latest  int   `json:"most_recent_feature_release"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return availableReleases{}, fmt.Errorf("not a release series list: %w", err)
	}
	if len(raw.LTS) == 0 {
		return availableReleases{}, errors.New("release series list has no LTS releases")
	}
	a := availableReleases{lts: map[int]bool{}, latest: raw.Latest}
	for _, n := range raw.LTS {
		if n < 8 || n > 999 {
			return availableReleases{}, fmt.Errorf("unreadable LTS release %d", n)
		}
		a.lts[n] = true
	}
	top := 0
	for _, n := range raw.LTS {
		top = max(top, n)
	}
	if raw.MostLTS != top {
		return availableReleases{}, fmt.Errorf("most recent LTS release %d is not the highest of the LTS releases (%d)", raw.MostLTS, top)
	}
	if raw.Latest < 9 || raw.Latest > 999 {
		return availableReleases{}, fmt.Errorf("unreadable most recent feature release %d", raw.Latest)
	}
	return a, nil
}
