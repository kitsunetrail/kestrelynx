package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// validContainerID1 is a well-formed 64-hex Docker container ID used across
// the tests below.
const validContainerID1 = "735accd562c50cc872e90aa71776f0ec855c480c6f1771619cc5e1dcec5e580d"

// --- inventory.Container.ID population (RunningContainers) ---

func TestRunningContainers_ValidID_Populated(t *testing.T) {
	srv := serveContainers(t, []rawContainer{{Id: validContainerID1, Image: "web:1"}})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].ID != validContainerID1 {
		t.Errorf("ID = %q, want %q", cs[0].ID, validContainerID1)
	}
}

func TestRunningContainers_MalformedID_Dropped(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"short", "735accd5"},
		{"uppercase", "735ACCD562C50CC872E90AA71776F0EC855C480C6F1771619CC5E1DCEC5E580"},
		{"non-hex", "zzzaccd562c50cc872e90aa71776f0ec855c480c6f1771619cc5e1dcec5e580"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveContainers(t, []rawContainer{{Id: tc.id, Image: "web:1"}})
			cs, err := newTestClient(srv).RunningContainers(context.Background())
			if err != nil {
				t.Fatalf("RunningContainers: %v", err)
			}
			if cs[0].ID != "" {
				t.Errorf("ID = %q, want empty (malformed id must not be normalized or guessed)", cs[0].ID)
			}
		})
	}
}

func TestRunningContainers_EmptyID_StaysEmpty(t *testing.T) {
	srv := serveContainers(t, []rawContainer{{Image: "web:1"}})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].ID != "" {
		t.Errorf("ID = %q, want empty (no Id in response)", cs[0].ID)
	}
}

// --- Inspect ---

// serveInspect starts an httptest server that serves body at
// /containers/<id>/json and fails the test on any other path.
func serveInspect(t *testing.T, id string, body []byte) *httptest.Server {
	t.Helper()
	wantPath := "/containers/" + id + "/json"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %q", r.Method)
		}
		if r.URL.Path != wantPath {
			t.Errorf("unexpected path %q, want %q", r.URL.Path, wantPath)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInspect_MalformedID_NoRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request should have been made for a malformed id, got %s", r.URL.Path)
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).Inspect(context.Background(), "not-a-valid-id"); err == nil {
		t.Fatal("expected error for malformed container id")
	}
}

func TestInspect_Fields(t *testing.T) {
	body := []byte(`{
		"Id": "` + validContainerID1 + `",
		"Image": "` + validID1 + `",
		"HostConfig": {"Privileged": true, "NetworkMode": "bridge"},
		"NetworkSettings": {"Ports": {
			"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
			"443/tcp": null
		}},
		"State": {"StartedAt": "2026-09-25T12:00:00.123456789Z", "Pid": 4242}
	}`)
	srv := serveInspect(t, validContainerID1, body)

	got, err := newTestClient(srv).Inspect(context.Background(), validContainerID1)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.ID != validContainerID1 {
		t.Errorf("ID = %q, want %q", got.ID, validContainerID1)
	}
	if got.Image.Kind != inventory.DigestConfig || got.Image.String() != validID1 {
		t.Errorf("Image = %+v, want a resolved config digest %q", got.Image, validID1)
	}
	if !got.Privileged {
		t.Error("Privileged = false, want true")
	}
	if got.NetworkMode != "bridge" {
		t.Errorf("NetworkMode = %q, want %q", got.NetworkMode, "bridge")
	}
	if got.Pid != 4242 {
		t.Errorf("Pid = %d, want 4242", got.Pid)
	}
	wantStarted := time.Date(2026, 9, 25, 12, 0, 0, 123456789, time.UTC)
	if !got.StartedAt.Equal(wantStarted) {
		t.Errorf("StartedAt = %v, want %v", got.StartedAt, wantStarted)
	}
	if bindings, ok := got.Ports["80/tcp"]; !ok || len(bindings) != 1 || bindings[0].HostIP != "0.0.0.0" || bindings[0].HostPort != "8080" {
		t.Errorf("Ports[80/tcp] = %+v, want one binding 0.0.0.0:8080", got.Ports["80/tcp"])
	}
	if bindings, ok := got.Ports["443/tcp"]; !ok || bindings != nil {
		t.Errorf("Ports[443/tcp] = %+v (present=%v), want a present key with a nil slice (exposed, not published)", bindings, ok)
	}
}

func TestInspect_MalformedImageID_ImageUnresolved(t *testing.T) {
	body := []byte(`{"Id": "` + validContainerID1 + `", "Image": "sha256:short"}`)
	srv := serveInspect(t, validContainerID1, body)

	got, err := newTestClient(srv).Inspect(context.Background(), validContainerID1)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got.Image.Kind == inventory.DigestConfig {
		t.Errorf("Image = %+v, want unresolved (malformed ImageID must not be normalized or guessed)", got.Image)
	}
}

func TestInspect_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("no such container"))
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).Inspect(context.Background(), validContainerID1); err == nil {
		t.Fatal("expected error on 404")
	}
}

func TestInspect_MalformedStartedAt(t *testing.T) {
	body := []byte(`{"Id": "` + validContainerID1 + `", "State": {"StartedAt": "not-a-time"}}`)
	srv := serveInspect(t, validContainerID1, body)

	if _, err := newTestClient(srv).Inspect(context.Background(), validContainerID1); err == nil {
		t.Fatal("expected error for malformed StartedAt")
	}
}

// ensure the test fixture type still round-trips through encoding/json the
// way the production decoder expects (guards the hand-written JSON bodies
// above against silently drifting from the real wire shape's field names).
func TestRawContainerFixtureShape(t *testing.T) {
	var raw rawContainer
	if err := json.Unmarshal([]byte(`{"Id":"x","Image":"y"}`), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if raw.Id != "x" || raw.Image != "y" {
		t.Errorf("raw = %+v", raw)
	}
}
