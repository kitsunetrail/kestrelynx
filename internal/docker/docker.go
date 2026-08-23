// Package docker lists running containers via the Docker Engine API over a
// docker.sock mount. It deliberately avoids the full Docker Go SDK to
// keep the binary small (single `docker run`, no heavy deps); only the
// /containers/json endpoint is needed (a single GET — nothing is controlled).
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"time"
)

// Client talks to the Docker Engine API. The socket is mounted read-only; this
// client only issues GET requests.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// New returns a Client that dials the Docker daemon over the given unix socket.
func New(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		httpClient: &http.Client{Transport: transport, Timeout: 15 * time.Second},
		// Host is ignored for unix sockets but required to form a valid URL.
		baseURL: "http://docker",
	}
}

// newClient is used by tests to point the client at an httptest server.
func newClient(baseURL string, hc *http.Client) *Client {
	return &Client{httpClient: hc, baseURL: baseURL}
}

// container is the subset of /containers/json we use.
type container struct {
	Image   string `json:"Image"`
	ImageID string `json:"ImageID"`
}

// contentIDPattern is the boundary check for the OCI image config digest: an
// exact "sha256:" followed by 64 lowercase hex characters. Anything else
// (wrong length, uppercase, a different algorithm) fails validation outright
// — no normalization or guessing.
var contentIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// RunningImage is one running container's image identity as reported by
// Docker. Ref is the human-readable reference used for display and history
// continuity. ContentID is the boundary-validated OCI image config digest
// that identifies the image's actual content; it is empty whenever Docker's
// ImageID is missing or does not validate, in which case the raw value (if
// any) is kept in RawImageID for diagnostics only — it never participates in
// identity comparisons or de-duplication.
type RunningImage struct {
	Ref        string
	ContentID  string
	RawImageID string
}

// RunningImages returns the sorted, de-duplicated running images of all
// containers. De-duplication is keyed on (Ref, ContentID): the same image
// name running the same validated content yields one entry, while the same
// name running distinct content is kept as separate entries so scanning and
// identity never silently merge them (docs/REQUIREMENTS.md F-2).
func (c *Client) RunningImages(ctx context.Context) ([]RunningImage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/containers/json", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("list containers: status %s: %s", resp.Status, body)
	}

	var containers []container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decode containers: %w", err)
	}

	type dedupKey struct{ ref, contentID string }
	seen := map[dedupKey]bool{}
	images := make([]RunningImage, 0, len(containers))
	for _, ct := range containers {
		if ct.Image == "" {
			continue
		}
		ri := RunningImage{Ref: ct.Image}
		switch {
		case contentIDPattern.MatchString(ct.ImageID):
			ri.ContentID = ct.ImageID
		case ct.ImageID != "":
			ri.RawImageID = ct.ImageID
		}
		k := dedupKey{ri.Ref, ri.ContentID}
		if seen[k] {
			continue
		}
		seen[k] = true
		images = append(images, ri)
	}
	sort.Slice(images, func(i, j int) bool {
		if images[i].Ref != images[j].Ref {
			return images[i].Ref < images[j].Ref
		}
		return images[i].ContentID < images[j].ContentID
	})
	return images, nil
}
