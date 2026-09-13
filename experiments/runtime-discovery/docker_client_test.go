package main

import (
	"encoding/json"
	"testing"
)

// The three fixtures below are raw Docker Engine API response bodies,
// shaped as the published API specification describes them rather than as
// this harness's own structs would be most convenient. They exist to catch
// the failure mode a struct-level test cannot: a field decoded from the
// wrong name, the wrong nesting level, or the wrong JSON type would still
// round-trip through a hand-built Go value and only break against a real
// daemon.
//
// Details these fixtures deliberately carry: Id/Names/Image at the top
// level of a /containers/json element with Names slash-prefixed;
// HostConfig.PortBindings and NetworkSettings.Ports keyed "<port>/<proto>"
// with HostIp/HostPort as strings (not numbers), including a port declared
// with a JSON null value; an IPv6 host binding under the same "/tcp" key
// as its IPv4 sibling; and a /top response as the Titles + Processes pair
// of string arrays, not a table of objects.

const containersJSONFixture = `[
  {
    "Id": "8dfafdbc3a40e2c1a1d09c9a5e3f0b8e4a6c2d1f0e9b8a7c6d5e4f3a2b1c0d9e",
    "Names": ["/r1"],
    "Image": "nginx:1.27",
    "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732",
    "Command": "/docker-entrypoint.sh nginx -g 'daemon off;'",
    "Created": 1767139200,
    "State": "running",
    "Status": "Up 2 minutes",
    "Ports": [
      {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 18080, "Type": "tcp"}
    ],
    "Labels": {"maintainer": "NGINX Docker Maintainers"}
  }
]`

const containerInspectFixture = `{
  "Id": "8dfafdbc3a40e2c1a1d09c9a5e3f0b8e4a6c2d1f0e9b8a7c6d5e4f3a2b1c0d9e",
  "Created": "2026-01-01T00:00:00.000000000Z",
  "Name": "/r1",
  "Image": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732",
  "State": {
    "Status": "running",
    "Running": true,
    "Pid": 4242,
    "StartedAt": "2026-01-01T00:00:01.234567890Z",
    "FinishedAt": "0001-01-01T00:00:00Z"
  },
  "Config": {
    "Hostname": "8dfafdbc3a40",
    "User": "101:101",
    "Image": "nginx:1.27",
    "ExposedPorts": {"80/tcp": {}, "443/tcp": {}}
  },
  "HostConfig": {
    "NetworkMode": "bridge",
    "Privileged": false,
    "CapAdd": ["NET_ADMIN"],
    "CapDrop": ["NET_RAW"],
    "PortBindings": {
      "80/tcp": [
        {"HostIp": "0.0.0.0", "HostPort": "18080"},
        {"HostIp": "::", "HostPort": "18080"}
      ]
    }
  },
  "NetworkSettings": {
    "Ports": {
      "80/tcp": [
        {"HostIp": "0.0.0.0", "HostPort": "18080"},
        {"HostIp": "::", "HostPort": "18080"}
      ],
      "443/tcp": null
    },
    "Networks": {
      "bridge": {
        "NetworkID": "b7c0f1f9a0d1e2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f",
        "IPAddress": "172.17.0.2",
        "Gateway": "172.17.0.1",
        "IPPrefixLen": 16
      }
    }
  }
}`

const containerTopFixture = `{
  "Titles": ["PID", "PPID", "USER"],
  "Processes": [
    ["4242", "4200", "root"],
    ["4301", "4242", "101"]
  ]
}`

func TestDecodeContainersJSON(t *testing.T) {
	var out []dockerContainerSummary
	if err := json.Unmarshal([]byte(containersJSONFixture), &out); err != nil {
		t.Fatalf("decode /containers/json: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("decoded %d summaries, want 1", len(out))
	}
	s := out[0]
	if s.ID != "8dfafdbc3a40e2c1a1d09c9a5e3f0b8e4a6c2d1f0e9b8a7c6d5e4f3a2b1c0d9e" {
		t.Errorf("ID = %q: the element's identifier is the \"Id\" key, not \"ID\"", s.ID)
	}
	if s.Image != "nginx:1.27" {
		t.Errorf("Image = %q, want the requested reference nginx:1.27", s.Image)
	}
	if len(s.Names) != 1 || s.Names[0] != "/r1" {
		t.Fatalf("Names = %v, want [/r1] (the API's names are slash-prefixed)", s.Names)
	}
	if got := primaryName(s.Names); got != "r1" {
		t.Errorf("primaryName = %q, want r1", got)
	}
}

func TestDecodeContainerInspect(t *testing.T) {
	var insp dockerInspect
	if err := json.Unmarshal([]byte(containerInspectFixture), &insp); err != nil {
		t.Fatalf("decode /containers/{id}/json: %v", err)
	}
	if insp.Image != "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732" {
		t.Errorf("Image = %q, want the resolved ImageID from the top-level \"Image\" key", insp.Image)
	}
	if insp.Config.Image != "nginx:1.27" {
		t.Errorf("Config.Image = %q, want the as-requested reference", insp.Config.Image)
	}
	if insp.Config.User != "101:101" {
		t.Errorf("Config.User = %q, want 101:101", insp.Config.User)
	}
	if insp.State.StartedAt != "2026-01-01T00:00:01.234567890Z" {
		t.Errorf("State.StartedAt = %q", insp.State.StartedAt)
	}
	if insp.HostConfig.NetworkMode != "bridge" {
		t.Errorf("HostConfig.NetworkMode = %q, want bridge", insp.HostConfig.NetworkMode)
	}
	if len(insp.HostConfig.CapAdd) != 1 || insp.HostConfig.CapAdd[0] != "NET_ADMIN" {
		t.Errorf("HostConfig.CapAdd = %v, want [NET_ADMIN]", insp.HostConfig.CapAdd)
	}
	if len(insp.HostConfig.CapDrop) != 1 || insp.HostConfig.CapDrop[0] != "NET_RAW" {
		t.Errorf("HostConfig.CapDrop = %v, want [NET_RAW]", insp.HostConfig.CapDrop)
	}
	if insp.NetworkSettings.Networks["bridge"].IPAddress != "172.17.0.2" {
		t.Errorf("NetworkSettings.Networks[bridge].IPAddress = %q", insp.NetworkSettings.Networks["bridge"].IPAddress)
	}

	ports := convertPortBindings(insp.NetworkSettings.Ports)
	bindings, ok := ports["80/tcp"]
	if !ok {
		t.Fatalf("NetworkSettings.Ports keys = %v, want an 80/tcp key", ports)
	}
	if len(bindings) != 2 {
		t.Fatalf("80/tcp bindings = %v, want both the IPv4 and the IPv6 host binding", bindings)
	}
	var sawV4, sawV6 bool
	for _, b := range bindings {
		if b.HostPort != "18080" {
			t.Errorf("HostPort = %q, want the string \"18080\" (the API reports ports as strings)", b.HostPort)
		}
		switch b.HostIP {
		case "0.0.0.0":
			sawV4 = true
		case "::":
			sawV6 = true
		}
	}
	if !sawV4 || !sawV6 {
		t.Errorf("80/tcp bindings = %v, want both 0.0.0.0 and :: under the one /tcp key", bindings)
	}
	declared, present := ports["443/tcp"]
	if !present {
		t.Error("443/tcp: a declared-but-unpublished port's key must survive its null value")
	}
	if len(declared) != 0 {
		t.Errorf("443/tcp = %v, want an empty binding list for a JSON null", declared)
	}

	requested := convertPortBindings(insp.HostConfig.PortBindings)
	if len(requested["80/tcp"]) != 2 {
		t.Errorf("HostConfig.PortBindings[80/tcp] = %v, want the two requested bindings", requested["80/tcp"])
	}
}

func TestDecodeContainerTop(t *testing.T) {
	var top dockerTop
	if err := json.Unmarshal([]byte(containerTopFixture), &top); err != nil {
		t.Fatalf("decode /containers/{id}/top: %v", err)
	}
	if len(top.Titles) != 3 || top.Titles[0] != "PID" {
		t.Fatalf("Titles = %v, want the requested pid,ppid,user column names", top.Titles)
	}
	if len(top.Processes) != 2 {
		t.Fatalf("Processes = %v, want two rows", top.Processes)
	}
	// Every column is a string, including the numeric ones: the caller
	// parses them, and a decoder expecting numbers here would fail against
	// a real daemon.
	if top.Processes[0][0] != "4242" || top.Processes[1][2] != "101" {
		t.Errorf("Processes = %v, want positional string columns matching Titles", top.Processes)
	}
}
