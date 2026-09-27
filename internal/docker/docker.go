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
	"net/url"
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

// allowedPath is one Docker Engine API path this Client may GET. It is a
// distinct type, constructed only by containersJSONPath and inspectPath
// below, so that get (the only thing that can issue a request) cannot be
// handed an arbitrary caller-supplied path or method — a coding discipline
// that keeps this client's surface to "list" and "inspect" as the adapter
// grows, not a privilege boundary: the mounted socket itself grants the
// full Engine API regardless of what this type restricts.
type allowedPath string

// containersJSONPath is the fixed path RunningContainers lists from.
func containersJSONPath() allowedPath { return "/containers/json" }

// inspectPath is the per-container path Inspect reads from. id is
// URL-escaped, not merely trusted, since it can originate from data this
// package itself rejected as a malformed container ID upstream of a caller
// that used it anyway.
func inspectPath(id string) allowedPath {
	return allowedPath("/containers/" + url.PathEscape(id) + "/json")
}

// get issues the one HTTP method this Client ever uses (GET) against one of
// the allowed paths and returns the decoded JSON body. A non-200 response or
// a body that doesn't decode as out is an error; the caller never sees a
// half-decoded value.
func (c *Client) get(ctx context.Context, path allowedPath, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+string(path), nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: status %s: %s", path, resp.Status, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// container is the subset of /containers/json we use. Names/Labels are read
// from the same response as Image/ImageID — no extra request is made — and
// are consumed entirely within this file; nothing here reaches the common
// inventory.Container model except what workloadFromLabels and
// containerName distill out of it.
type container struct {
	ID      string            `json:"Id"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Names   []string          `json:"Names"`
	Labels  map[string]string `json:"Labels"`
}

// containerIDRE matches a well-formed 64-hex Docker container ID.
var containerIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validContainerID reports whether id is a well-formed 64-hex Docker
// container ID. A malformed value (short, mixed case, non-hex) is never
// truncated or lower-cased into shape — the common model has no place for a
// guessed identifier, matching the ImageID boundary check's philosophy.
func validContainerID(id string) bool {
	return containerIDRE.MatchString(id)
}

// Docker Compose labels that, together, resolve a container's Workload.
const (
	composeProjectLabel = "com.docker.compose.project"
	composeServiceLabel = "com.docker.compose.service"
)

// runtimeExcludeLabel opts a container out of the runtime-usage overlay
// entirely. Unlike the compose labels above it takes exactly one literal
// value ("true"); anything else (missing, empty, "1", "True") is not
// excluded — the label is a deliberate, explicit opt-out, not a general
// truthy flag, so a near-miss value is never guessed at as meaning yes.
const runtimeExcludeLabel = "io.kestrelynx.runtime.exclude"

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
// The return order is deterministic: (Image.Ref, Image.ContentID(),
// Workload.Group, Workload.Name, Container.Name), lexicographically.
func (c *Client) RunningContainers(ctx context.Context) ([]inventory.Container, error) {
	var raw []container
	if err := c.get(ctx, containersJSONPath(), &raw); err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	containers := make([]inventory.Container, 0, len(raw))
	for _, ct := range raw {
		img := inventory.RunningImage{Ref: ct.Image}
		if d, ok := inventory.ParseDigest(inventory.DigestConfig, ct.ImageID); ok {
			img.Config = d
		} else if ct.ImageID != "" {
			// A non-empty ImageID that fails the boundary check is never
			// normalized or guessed at — the common model has no place for
			// an unresolved raw value, so it stays a log-only diagnostic
			// (identity falls back to the reference downstream).
			c.log().Warn("image id failed content id validation",
				"ref", ct.Image, "raw_image_id", ct.ImageID)
		}
		id := ct.ID
		if id != "" && !validContainerID(id) {
			// A malformed Id is never truncated or guessed at — see
			// validContainerID — so it is dropped with a diagnostic, the
			// same treatment a malformed ImageID gets above.
			c.log().Warn("container id failed validation", "ref", ct.Image, "raw_id", ct.ID)
			id = ""
		}
		containers = append(containers, inventory.Container{
			ID:              id,
			Name:            containerName(ct.Names),
			Workload:        workloadFromLabels(ct.Labels),
			Image:           img,
			RuntimeExcluded: ct.Labels[runtimeExcludeLabel] == "true",
		})
	}

	sort.Slice(containers, func(i, j int) bool {
		a, b := containers[i], containers[j]
		if a.Image.Ref != b.Image.Ref {
			return a.Image.Ref < b.Image.Ref
		}
		if a.Image.ContentID() != b.Image.ContentID() {
			return a.Image.ContentID() < b.Image.ContentID()
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

// PortBinding is one host-side binding for a published container port,
// mirroring one entry of the Docker Engine API's NetworkSettings.Ports value
// arrays.
type PortBinding struct {
	HostIP   string
	HostPort string
}

// InspectResult is the subset of GET /containers/{id}/json the main body
// needs: enough to corroborate a Sensor evidence generation against this
// container's current identity (init PID and start time) and to describe
// its exposure (network mode, privileged, published ports) once a package
// running in it is judged in use.
type InspectResult struct {
	ID          string
	Image       inventory.Digest // Kind == DigestConfig, or DigestUnknown when the field failed the boundary check
	NetworkMode string
	Privileged  bool
	// Ports is NetworkSettings.Ports verbatim: a declared-but-unpublished
	// port (exposed with no host binding) is a present key with a nil
	// slice, not a dropped key.
	Ports     map[string][]PortBinding
	StartedAt time.Time
	Pid       int
}

// inspectResponse is the wire shape of /containers/{id}/json, trimmed to the
// fields InspectResult needs.
type inspectResponse struct {
	Id         string `json:"Id"`
	Image      string `json:"Image"` // resolved ImageID at inspect time
	HostConfig struct {
		Privileged  bool   `json:"Privileged"`
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	State struct {
		StartedAt string `json:"StartedAt"`
		Pid       int    `json:"Pid"`
	} `json:"State"`
}

// Inspect returns one container's current identity and exposure by ID. id
// must already be a well-formed 64-hex container ID (RunningContainers'
// own boundary check produces one); a caller that passes anything else gets
// an error before any request is made, since this is the one place a
// caller-influenced value reaches a request path this client builds.
func (c *Client) Inspect(ctx context.Context, id string) (InspectResult, error) {
	if !validContainerID(id) {
		return InspectResult{}, fmt.Errorf("inspect container: malformed container id %q", id)
	}

	var raw inspectResponse
	if err := c.get(ctx, inspectPath(id), &raw); err != nil {
		return InspectResult{}, fmt.Errorf("inspect container %s: %w", id, err)
	}

	result := InspectResult{
		ID:          raw.Id,
		NetworkMode: raw.HostConfig.NetworkMode,
		Privileged:  raw.HostConfig.Privileged,
		Pid:         raw.State.Pid,
	}
	if d, ok := inventory.ParseDigest(inventory.DigestConfig, raw.Image); ok {
		result.Image = d
	} else if raw.Image != "" {
		// Same treatment as RunningContainers' ImageID: never normalized or
		// guessed at, just logged and left at the zero value.
		c.log().Warn("inspect image id failed content id validation", "id", id, "raw_image_id", raw.Image)
	}
	if raw.State.StartedAt != "" {
		t, err := time.Parse(time.RFC3339Nano, raw.State.StartedAt)
		if err != nil {
			return InspectResult{}, fmt.Errorf("inspect container %s: parse StartedAt %q: %w", id, raw.State.StartedAt, err)
		}
		result.StartedAt = t
	}
	if raw.NetworkSettings.Ports != nil {
		result.Ports = make(map[string][]PortBinding, len(raw.NetworkSettings.Ports))
		for k, bindings := range raw.NetworkSettings.Ports {
			var converted []PortBinding
			for _, b := range bindings {
				converted = append(converted, PortBinding{HostIP: b.HostIP, HostPort: b.HostPort})
			}
			result.Ports[k] = converted
		}
	}
	return result, nil
}
