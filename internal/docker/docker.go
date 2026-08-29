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
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// Client talks to the Docker Engine API. The socket is mounted read-only; this
// client only issues GET requests. Log, when set, receives diagnostics (an
// ImageID that fails the ContentID boundary check); nil falls back to
// slog.Default.
type Client struct {
	httpClient *http.Client
	baseURL    string
	Log        *slog.Logger
}

func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
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

// container is the subset of /containers/json we use. Names/Labels are read
// from the same response as Image/ImageID — no extra request is made — and
// are consumed entirely within this file; nothing here reaches the common
// inventory.Container model except what workloadFromLabels and
// containerName distill out of it.
type container struct {
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Names   []string          `json:"Names"`
	Labels  map[string]string `json:"Labels"`
}

// contentIDPattern is the boundary check for the OCI image config digest: an
// exact "sha256:" followed by 64 lowercase hex characters. Anything else
// (wrong length, uppercase, a different algorithm) fails validation outright
// — no normalization or guessing.
var contentIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Docker Compose labels that, together, resolve a container's Workload.
const (
	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
)

// maxLabelValueBytes mirrors Docker Compose's own project/service name
// limit; a value over this is treated as unusable rather than truncated.
const maxLabelValueBytes = 253

// validLabelValue reports whether v is safe to trust for a Workload
// association: non-empty, free of control characters (C0 including TAB, US
// and newlines, DEL, and the C1 range), and no more than maxLabelValueBytes.
// Anything that fails is treated exactly like a missing label — no
// truncation, no partial acceptance, mirroring the image identity model's
// "an unresolved value is safer than a guessed one".
func validLabelValue(v string) bool {
	if v == "" || len(v) > maxLabelValueBytes {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// workloadFromLabels resolves a Workload from Docker Compose labels. Both
// the project and service labels must be present and valid or the container
// stays WorkloadUnknown — a Workload known from only one of the two would be
// a mapping that can't actually be used, not "partially known" (mirrors the
// image identity model's ban on canonical=false-with-nonempty-ContentID
// intermediate states).
func workloadFromLabels(labels map[string]string) inventory.Workload {
	project, service := labels[composeProjectLabel], labels[composeServiceLabel]
	if !validLabelValue(project) || !validLabelValue(service) {
		return inventory.Workload{}
	}
	return inventory.Workload{Kind: inventory.WorkloadCompose, Group: project, Name: service}
}

// containerName picks the display name for a container out of Docker's
// Names array. Each element carries exactly one leading "/", stripped here;
// Docker also lists legacy container-link aliases as "/parent/alias", which
// still contain a "/" after that strip and are excluded, since they name a
// link relationship rather than the container itself. Among what remains,
// the lexicographically smallest is chosen — a decisive, deterministic pick
// rather than trusting array order, which isn't a documented contract. No
// candidate at all yields "" (not guessed).
func containerName(names []string) string {
	best, found := "", false
	for _, n := range names {
		n = strings.TrimPrefix(n, "/")
		if strings.Contains(n, "/") {
			continue
		}
		if !found || n < best {
			best, found = n, true
		}
	}
	return best
}

// RunningContainers returns every running container as observed by Docker,
// stripped down to the runtime-agnostic inventory.Container vocabulary. It
// does not de-duplicate: two containers running the same image are two
// entries, since that multiplicity is itself an observation (needed
// downstream to associate a workload with each). Callers that want the
// distinct set of images to scan use inventory.DistinctImages on the result.
// The return order is deterministic: (Image.Ref, Image.ContentID,
// Workload.Group, Workload.Name, Container.Name), lexicographically.
func (c *Client) RunningContainers(ctx context.Context) ([]inventory.Container, error) {
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

	var raw []container
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode containers: %w", err)
	}

	containers := make([]inventory.Container, 0, len(raw))
	for _, ct := range raw {
		img := inventory.RunningImage{Ref: ct.Image}
		switch {
		case contentIDPattern.MatchString(ct.ImageID):
			img.ContentID = ct.ImageID
		case ct.ImageID != "":
			// A non-empty ImageID that fails the boundary check is never
			// normalized or guessed at — the common model has no place for
			// an unresolved raw value, so it stays a log-only diagnostic
			// (identity falls back to the reference downstream).
			c.log().Warn("image id failed content id validation",
				"ref", ct.Image, "raw_image_id", ct.ImageID)
		}
		containers = append(containers, inventory.Container{
			Name:     containerName(ct.Names),
			Workload: workloadFromLabels(ct.Labels),
			Image:    img,
		})
	}

	sort.Slice(containers, func(i, j int) bool {
		a, b := containers[i], containers[j]
		if a.Image.Ref != b.Image.Ref {
			return a.Image.Ref < b.Image.Ref
		}
		if a.Image.ContentID != b.Image.ContentID {
			return a.Image.ContentID < b.Image.ContentID
		}
		if a.Workload.Group != b.Workload.Group {
			return a.Workload.Group < b.Workload.Group
		}
		if a.Workload.Name != b.Workload.Name {
			return a.Workload.Name < b.Workload.Name
		}
		return a.Name < b.Name
	})
	return containers, nil
}
