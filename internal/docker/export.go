package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// exportPlatformMinor is the first Engine API 1.x version whose image export
// accepts a platform.
const exportPlatformMinor = 48

// fetchIDRE matches what the export endpoint is given: an image ID or a
// manifest list digest, with or without the algorithm prefix.
var fetchIDRE = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)

// ErrExportInvalid means the image ID or platform given to ExportImage is
// unusable; nothing was sent.
var ErrExportInvalid = errors.New("docker: invalid image export request")

// ExportStatusError is a non-200 answer to an image export.
type ExportStatusError struct {
	Status int
	Body   string
}

func (e *ExportStatusError) Error() string {
	return fmt.Sprintf("docker: image export answered HTTP %d: %s", e.Status, e.Body)
}

// versionPath is the path the API version is read from.
func versionPath() allowedPath { return "/version" }

// exportPath is the per-image export path. id has been validated by the
// caller; it is escaped anyway.
func exportPath(id string) allowedPath {
	return allowedPath("/images/" + url.PathEscape(id) + "/get")
}

// maxVersionBytes bounds the answer to the version lookup that precedes an
// export, which is outside the export's own byte budget.
const maxVersionBytes = 64 << 10

// getLimited is get with a cap on the body: a longer answer is an error.
func (c *Client) getLimited(ctx context.Context, path allowedPath, limit int64, out any) error {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("GET %s: the answer is longer than %d bytes", path, limit)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// apiAtLeast reports whether the daemon's API version is at least 1.minor.
// A version that cannot be read counts as older.
func (c *Client) apiAtLeast(ctx context.Context, minor int) (bool, error) {
	var v struct {
		APIVersion string `json:"ApiVersion"`
	}
	if err := c.getLimited(ctx, versionPath(), maxVersionBytes, &v); err != nil {
		return false, err
	}
	maj, min, ok := parseAPIVersion(v.APIVersion)
	if !ok {
		return false, nil
	}
	return maj > 1 || maj == 1 && min >= minor, nil
}

// ExportImage streams the image tar of GET /images/{id}/get. id is the ID
// the image is fetched by: an image config digest or, with the containerd
// image store, a manifest list digest. When the daemon's API is 1.48 or later
// and the platform is known, the platform is passed so a multi-platform image
// is exported for that platform only; older daemons export whatever the ID
// names.
//
// The request is a read-only GET. It has no timeout of its own: the stream
// lives as long as ctx does, and the caller closes it. The 15 second timeout
// of the client's other requests applies only to the version lookup.
func (c *Client) ExportImage(ctx context.Context, id string, platform inventory.Platform) (io.ReadCloser, error) {
	if !fetchIDRE.MatchString(id) {
		return nil, fmt.Errorf("%w: image id %q", ErrExportInvalid, id)
	}
	if (platform.OS == "") != (platform.Architecture == "") {
		return nil, fmt.Errorf("%w: platform %+v", ErrExportInvalid, platform)
	}
	target := string(exportPath(id))
	if platform.Known() {
		newer, err := c.apiAtLeast(ctx, exportPlatformMinor)
		if err != nil {
			return nil, fmt.Errorf("read the Docker Engine API version: %w", err)
		}
		if newer {
			p := map[string]string{"os": platform.OS, "architecture": platform.Architecture}
			if platform.Variant != "" {
				p["variant"] = platform.Variant
			}
			b, _ := json.Marshal(p)
			target += "?platform=" + url.QueryEscape(string(b))
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+target, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	hc := *c.httpClient
	hc.Timeout = 0
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", exportPath(id), err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, &ExportStatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	return resp.Body, nil
}
