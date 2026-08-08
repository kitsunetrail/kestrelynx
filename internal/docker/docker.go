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
	Image string `json:"Image"`
}

// RunningImages returns the sorted, de-duplicated image references of all
// running containers. Multiple containers sharing an image yield one entry so
// each image is scanned once (docs/REQUIREMENTS.md F-2).
func (c *Client) RunningImages(ctx context.Context) ([]string, error) {
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

	seen := map[string]bool{}
	images := make([]string, 0, len(containers))
	for _, ct := range containers {
		if ct.Image == "" || seen[ct.Image] {
			continue
		}
		seen[ct.Image] = true
		images = append(images, ct.Image)
	}
	sort.Strings(images)
	return images, nil
}
