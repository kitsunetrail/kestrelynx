package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// PyPIVersions tells which releases of a package the index publishes. An index
// client that has it lets the plan say what newer releases of a dependent
// declare (see ChainHint).
type PyPIVersions interface {
	// Versions returns the versions of name that have at least one file not
	// yanked, and how many bytes of the index's response were read to find out.
	// An error wrapping ErrReleaseNotFound says the index has no such package.
	Versions(ctx context.Context, name string) ([]string, int64, error)
}

var _ PyPIVersions = (*PyPIClient)(nil)

// maxPyPIProjectBytes bounds the project document Versions reads; a project
// with more files than that is not listed.
const maxPyPIProjectBytes = 32 << 20

// Versions implements PyPIVersions with GET <base>/pypi/<name>/json. Only the
// "releases" member is kept, and of each file only whether it is yanked; the
// rest is read past without being held, and reading stops at
// maxPyPIProjectBytes.
func (c *PyPIClient) Versions(ctx context.Context, name string) ([]string, int64, error) {
	if !worker.ValidPythonName(name) {
		return nil, 0, fmt.Errorf("%q is not a package name this client looks up", name)
	}
	base := c.BaseURL
	if base == "" {
		base = "https://pypi.org"
	}
	u := strings.TrimRight(base, "/") + "/pypi/" + url.PathEscape(normalizePyName(name)) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kestrelynx")
	resp, err := boundedClient(c.HTTP).Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("index request: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, 0, ErrReleaseNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, 0, fmt.Errorf("index answered %s", resp.Status)
	}
	cr := &countingReader{r: io.LimitReader(resp.Body, maxPyPIProjectBytes+1)}
	versions, err := readPyPIVersions(cr)
	if cr.n > maxPyPIProjectBytes {
		return nil, cr.n, fmt.Errorf("index response is over %d bytes", maxPyPIProjectBytes)
	}
	return versions, cr.n, err
}

// readPyPIVersions reads the "releases" member of a project document, which
// maps each version to its files, and returns the versions with a file that is
// not yanked. A version with no files at all cannot be installed and is left
// out too.
func readPyPIVersions(r io.Reader) ([]string, error) {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("index response is not a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("index response cannot be read: %w", err)
		}
		if key, _ := tok.(string); key != "releases" {
			if err := skipJSONValue(dec); err != nil {
				return nil, fmt.Errorf("index response cannot be read: %w", err)
			}
			continue
		}
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			return nil, errors.New("index response has a releases member that is not an object")
		}
		var out []string
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("index response cannot be read: %w", err)
			}
			version, _ := tok.(string)
			if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
				return nil, fmt.Errorf("index response lists the files of %q in something that is not an array", version)
			}
			installable := false
			for dec.More() {
				var f struct {
					Yanked bool `json:"yanked"`
				}
				if err := dec.Decode(&f); err != nil {
					return nil, fmt.Errorf("index response has a file of %q that cannot be read: %w", version, err)
				}
				if !f.Yanked {
					installable = true
				}
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("index response cannot be read: %w", err)
			}
			if installable {
				out = append(out, version)
			}
		}
		// A document cut short ends the loop as its end would; only the
		// closing brace says the list is whole.
		if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
			return nil, errors.New("index response ends before its releases member does")
		}
		// The rest of the document is not needed.
		return out, nil
	}
	return nil, errors.New("index response has no releases member")
}
