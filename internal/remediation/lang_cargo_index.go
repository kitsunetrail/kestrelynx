package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// CargoIndex is what the remediation reads from the crates.io sparse index.
type CargoIndex interface {
	// Versions returns every release the index lists for the crate, in file
	// order. ErrReleaseNotFound means the index has no such crate.
	Versions(ctx context.Context, name string) ([]CargoRelease, error)
}

// CargoRelease is one line of the index: a release of a crate.
type CargoRelease struct {
	Name     string // as the index writes it; the same as the name asked for
	Version  string
	Checksum string // the SHA-256 of the crate file, in lower-case hexadecimal
	Yanked   bool
	// RustVersion is the rust-version the release declares, "" when it
	// declares none.
	RustVersion string
	Deps        []CargoIndexDep
}

// CargoIndexDep is a dependency a release declares.
type CargoIndexDep struct {
	Name string // the name the dependency is written under
	// Package is the crate it names when that is not Name (a renamed
	// dependency), "" otherwise.
	Package  string
	Req      string
	Kind     string // "normal", "dev" or "build"
	Optional bool
	Target   string // the platform condition, "" for none
}

// CargoIndexClient reads the sparse index of crates.io.
type CargoIndexClient struct {
	BaseURL string       // default "https://index.crates.io"
	HTTP    *http.Client // default with a timeout
}

var _ CargoIndex = (*CargoIndexClient)(nil)

const cargoIndexURL = "https://index.crates.io"

// maxCargoIndexBytes bounds the index file of one crate. Among the crates with
// the most releases the largest file measured is web-sys's, of 4.5 MB (the
// cloud SDKs' are 1.5 MB at most); the bound leaves room well above them.
const maxCargoIndexBytes = 32 << 20

func (c *CargoIndexClient) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return cargoIndexURL
}

// cargoIndexNameRE is what a crate name asked for may be made of.
var cargoIndexNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// cargoIndexPath is the path of a crate's file in the sparse index, from the
// lower-cased name: 1/n, 2/nn, 3/a/nnn, and ab/cd/name for four letters or
// more. ok is false for a name that is not a crate name.
func cargoIndexPath(name string) (string, bool) {
	if !cargoIndexNameRE.MatchString(name) {
		return "", false
	}
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n, true
	case 2:
		return "2/" + n, true
	case 3:
		return "3/" + n[:1] + "/" + n, true
	}
	return n[:2] + "/" + n[2:4] + "/" + n, true
}

// Versions implements CargoIndex with GET <base>/<index path of the name>.
func (c *CargoIndexClient) Versions(ctx context.Context, name string) ([]CargoRelease, error) {
	p, ok := cargoIndexPath(name)
	if !ok {
		return nil, fmt.Errorf("%q is not a crate name this client looks up", name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+"/"+p, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kestrelynx")
	hc := *boundedClient(c.HTTP)
	hc.CheckRedirect = sameHostRedirect
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crates.io index request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, ErrReleaseNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCargoIndexBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", req.URL.Host, err)
	}
	if len(body) > maxCargoIndexBytes {
		return nil, fmt.Errorf("%s sent more than %d bytes", req.URL.Host, maxCargoIndexBytes)
	}
	return parseCargoIndex(body, name)
}

// maxCargoIndexLines bounds the lines of one index file.
const maxCargoIndexLines = 100000

// cargoVersionKey is a version without its build metadata, which does not
// make a release another one in the index.
func cargoVersionKey(v string) string {
	k, _, _ := strings.Cut(v, "+")
	return k
}

// parseCargoIndex reads an index file: one JSON object a line, each a release
// of the crate, processed in order. A line must have the name (the one asked
// for, to the case), vers (a version, once in the file when build metadata is
// left out), cksum (64 lower-case hexadecimal digits), yanked and deps, and a
// schema version v of 1 (also when it is left out) or 2; fields the plan does
// not use are ignored.
func parseCargoIndex(body []byte, name string) ([]CargoRelease, error) {
	type rawDep struct {
		Name     *string `json:"name"`
		Req      *string `json:"req"`
		Kind     *string `json:"kind"`
		Optional bool    `json:"optional"`
		Target   *string `json:"target"`
		Package  *string `json:"package"`
	}
	type rawRelease struct {
		Name        *string   `json:"name"`
		Vers        *string   `json:"vers"`
		Cksum       *string   `json:"cksum"`
		Yanked      *bool     `json:"yanked"`
		Deps        *[]rawDep `json:"deps"`
		RustVersion *string   `json:"rust_version"`
		V           *int      `json:"v"`
	}
	var out []CargoRelease
	seen := map[string]bool{}
	for n := 1; len(body) > 0; n++ {
		if n > maxCargoIndexLines {
			return nil, fmt.Errorf("the index file of %s has more than %d lines", name, maxCargoIndexLines)
		}
		line := body
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			body = nil
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if err := cargoIndexKeys(line, cargoIndexReleaseKeys); err != nil {
			return nil, fmt.Errorf("line %d of the index file of %s: %w", n, name, err)
		}
		var depObjs struct {
			Deps []json.RawMessage `json:"deps"`
		}
		if err := json.Unmarshal(line, &depObjs); err != nil {
			return nil, fmt.Errorf("line %d of the index file of %s is not JSON: %w", n, name, err)
		}
		for _, d := range depObjs.Deps {
			if err := cargoIndexKeys(d, cargoIndexDepKeys); err != nil {
				return nil, fmt.Errorf("a dependency on line %d of the index file of %s: %w", n, name, err)
			}
		}
		var raw rawRelease
		if err := json.Unmarshal(line, &raw); err != nil {
			return nil, fmt.Errorf("line %d of the index file of %s is not JSON: %w", n, name, err)
		}
		if raw.Name == nil || raw.Vers == nil || raw.Cksum == nil || raw.Yanked == nil || raw.Deps == nil {
			return nil, fmt.Errorf("line %d of the index file of %s lacks name, vers, cksum, yanked or deps", n, name)
		}
		if raw.V != nil && *raw.V != 1 && *raw.V != 2 {
			return nil, fmt.Errorf("line %d of the index file of %s has the schema version %d, which is not read", n, name, *raw.V)
		}
		if *raw.Name != name {
			return nil, fmt.Errorf("line %d of the index file of %s is of the crate %q", n, name, *raw.Name)
		}
		if _, ok := parseCargoVersion(*raw.Vers); !ok {
			return nil, fmt.Errorf("line %d of the index file of %s has the version %q, which is not a version", n, name, *raw.Vers)
		}
		if k := cargoVersionKey(*raw.Vers); seen[k] {
			return nil, fmt.Errorf("the index file of %s lists %s twice", name, k)
		} else {
			seen[k] = true
		}
		if !cargoChecksumRE.MatchString(*raw.Cksum) {
			return nil, fmt.Errorf("the index file of %s has no valid checksum for %s", name, *raw.Vers)
		}
		rel := CargoRelease{Name: *raw.Name, Version: *raw.Vers, Checksum: *raw.Cksum, Yanked: *raw.Yanked}
		if raw.RustVersion != nil {
			rel.RustVersion = *raw.RustVersion
		}
		for _, d := range *raw.Deps {
			if d.Name == nil || d.Req == nil {
				return nil, fmt.Errorf("a dependency of %s %s in the index lacks name or req", name, *raw.Vers)
			}
			dep := CargoIndexDep{Name: *d.Name, Req: *d.Req, Kind: "normal", Optional: d.Optional}
			if d.Kind != nil {
				dep.Kind = *d.Kind
			}
			if d.Target != nil {
				dep.Target = *d.Target
			}
			if d.Package != nil {
				dep.Package = *d.Package
			}
			rel.Deps = append(rel.Deps, dep)
		}
		out = append(out, rel)
	}
	if len(out) == 0 {
		return nil, errors.New("the index file of " + name + " lists no release")
	}
	return out, nil
}

// selectCargoRelease picks the release an update takes the crate to: the
// lowest at or above the lower bound that is in the series of the installed
// version (see cargoSeries), is not a pre-release and is not yanked. When
// there is none, the reason and its detail say so.
func selectCargoRelease(releases []CargoRelease, installed, lowerBound string) (CargoRelease, Reason, string) {
	inst, ok := parseCargoVersion(installed)
	if !ok {
		return CargoRelease{}, ReasonUnparsableVersion, fmt.Sprintf("the installed version %q is not a version", installed)
	}
	low, ok := parseCargoVersion(lowerBound)
	if !ok {
		return CargoRelease{}, ReasonUnparsableVersion, fmt.Sprintf("the target version %q is not a version", lowerBound)
	}
	var best CargoRelease
	var bestV semver
	found := false
	for _, r := range releases {
		v, ok := parseCargoVersion(r.Version)
		if !ok || r.Yanked || v.isPrerelease() || v.compare(low) < 0 || !cargoCompatible(inst, v) {
			continue
		}
		if !found || v.compare(bestV) < 0 {
			best, bestV, found = r, v, true
		}
	}
	if !found {
		return CargoRelease{}, ReasonCargoReleaseNotFound, fmt.Sprintf("crates.io lists no release at or above %s in the series of %s that is not yanked or a pre-release", lowerBound, installed)
	}
	return best, "", ""
}

// The keys the index writes for a release and for one of its dependencies.
var (
	cargoIndexReleaseKeys = []string{"name", "vers", "cksum", "yanked", "deps", "rust_version", "v", "features", "features2", "links", "pubtime"}
	cargoIndexDepKeys     = []string{"name", "req", "kind", "optional", "target", "package", "features", "default_features", "registry"}
)

// cargoIndexKeys checks the keys of one JSON object of the index before it is
// decoded: Go's decoder takes a key spelled in another case for a field and
// the last of two keys of one name, so a key that differs from a known one
// only in case, a key given twice, and a null schema version are refused.
func cargoIndexKeys(obj []byte, known []string) error {
	dec := json.NewDecoder(bytes.NewReader(obj))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("not JSON: %w", err)
		}
		k, ok := t.(string)
		if !ok {
			return fmt.Errorf("not a JSON object")
		}
		if seen[k] {
			return fmt.Errorf("the key %q is given twice", k)
		}
		seen[k] = true
		for _, w := range known {
			if k != w && strings.EqualFold(k, w) {
				return fmt.Errorf("the key %q is spelled differently from %q", k, w)
			}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("not JSON: %w", err)
		}
		if k == "v" && string(bytes.TrimSpace(v)) == "null" {
			return fmt.Errorf("the schema version is null")
		}
	}
	return nil
}
