package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// dockerClient talks to the Docker Engine API over a UNIX socket, the same
// dial pattern internal/docker uses, but re-implemented here rather than
// imported: this harness needs /containers/{id}/json and
// /containers/{id}/top, which internal/docker.Client does not expose.
type dockerClient struct {
	httpClient *http.Client
	baseURL    string
}

func newDockerClient(socketPath string) *dockerClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &dockerClient{
		httpClient: &http.Client{Transport: transport, Timeout: 15 * time.Second},
		baseURL:    "http://docker",
	}
}

func (c *dockerClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
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
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// dockerContainerSummary is the subset of one /containers/json element used
// to enumerate running containers.
type dockerContainerSummary struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	Names []string
}

func (c *dockerClient) listContainers(ctx context.Context) ([]dockerContainerSummary, error) {
	var out []dockerContainerSummary
	if err := c.get(ctx, "/containers/json", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// dockerPortBinding mirrors one entry of HostConfig.PortBindings's value
// arrays and of NetworkSettings.Ports's value arrays.
type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// dockerInspect is the subset of /containers/{id}/json used by collect:
// identity, the declared run-as user, capability/privilege configuration,
// network mode, and both the requested and actual port bindings.
type dockerInspect struct {
	Id      string `json:"Id"`
	Image   string `json:"Image"` // resolved ImageID at inspect time
	Name    string `json:"Name"`
	Created string `json:"Created"`
	Config  struct {
		Image string `json:"Image"` // as-requested reference
		User  string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged   bool                           `json:"Privileged"`
		CapAdd       []string                       `json:"CapAdd"`
		CapDrop      []string                       `json:"CapDrop"`
		NetworkMode  string                         `json:"NetworkMode"`
		PortBindings map[string][]dockerPortBinding `json:"PortBindings"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports    map[string][]dockerPortBinding `json:"Ports"`
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	State struct {
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
}

func (c *dockerClient) inspectContainer(ctx context.Context, id string) (dockerInspect, error) {
	var out dockerInspect
	if err := c.get(ctx, "/containers/"+id+"/json", &out); err != nil {
		return dockerInspect{}, err
	}
	return out, nil
}

// dockerTop is the response shape of /containers/{id}/top: a header row
// (Titles) and one row per process (Processes), each row's columns
// positionally matching Titles, every column a string. The harness requests
// "-eo pid,ppid,user", so a row is expected to carry those three columns in
// that order; a response that doesn't match is recorded as a collection
// failure, not something to guess-parse.
type dockerTop struct {
	Titles    []string   `json:"Titles"`
	Processes [][]string `json:"Processes"`
}

func (c *dockerClient) top(ctx context.Context, id, psArgs string) (dockerTop, error) {
	var out dockerTop
	q := "/containers/" + id + "/top?ps_args=" + url.QueryEscape(psArgs)
	if err := c.get(ctx, q, &out); err != nil {
		return dockerTop{}, err
	}
	return out, nil
}
