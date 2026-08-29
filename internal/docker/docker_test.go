package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func newTestClient(srv *httptest.Server) *Client {
	return newClient(srv.URL, srv.Client())
}

// validID1 / validID2 are two distinct, well-formed OCI image config digests
// used across the tests below.
const (
	validID1 = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	validID2 = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
)

// rawContainer mirrors the wire shape of one /containers/json entry, for
// building test fixtures.
type rawContainer struct {
	Id      string            `json:"Id"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	Names   []string          `json:"Names"`
	Labels  map[string]string `json:"Labels"`
}

func composeLabels(project, service string) map[string]string {
	return map[string]string{
		composeProjectLabel: project,
		composeServiceLabel: service,
	}
}

// serveContainers starts an httptest server that returns raw as the
// /containers/json response body, and fails the test if any other path is
// requested.
func serveContainers(t *testing.T, raw []rawContainer) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunningContainers_Empty(t *testing.T) {
	srv := serveContainers(t, nil)
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 0 {
		t.Errorf("got %v, want empty", cs)
	}
}

func TestRunningContainers_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).RunningContainers(context.Background()); err == nil {
		t.Fatal("expected error on 500")
	}
}

// --- ContentID boundary validation (unchanged behavior, ported from RunningImages) ---

func TestRunningContainers_MissingImageID_ContentIDEmpty(t *testing.T) {
	srv := serveContainers(t, []rawContainer{{Id: "a", Image: "alpine:3.20", Names: []string{"/app"}}})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %+v, want 1 entry", cs)
	}
	if cs[0].Image.ContentID != "" {
		t.Errorf("ContentID = %q, want empty (ImageID missing)", cs[0].Image.ContentID)
	}
}

func TestRunningContainers_MalformedImageID_ContentIDEmpty(t *testing.T) {
	cases := []struct {
		name    string
		imageID string
	}{
		{"short hex", "sha256:abc123"},
		{"uppercase hex", "sha256:" + "A" + validID1[len("sha256:")+1:]},
		{"wrong algorithm", "sha512:" + validID1[len("sha256:"):]},
		{"no prefix", validID1[len("sha256:"):]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveContainers(t, []rawContainer{{Id: "a", Image: "alpine:3.20", ImageID: tc.imageID}})
			cs, err := newTestClient(srv).RunningContainers(context.Background())
			if err != nil {
				t.Fatalf("RunningContainers: %v", err)
			}
			if len(cs) != 1 {
				t.Fatalf("got %+v, want 1 entry", cs)
			}
			if cs[0].Image.ContentID != "" {
				t.Errorf("ContentID = %q, want empty (malformed ImageID must not be normalized or guessed)", cs[0].Image.ContentID)
			}
		})
	}
}

// --- Compose workload resolution ---

func TestRunningContainers_ComposeBothLabels_WorkloadKnown(t *testing.T) {
	srv := serveContainers(t, []rawContainer{
		{Id: "a", Image: "web:1", ImageID: validID1, Names: []string{"/proj-web-1"}, Labels: composeLabels("proj", "web")},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %+v, want 1 entry", cs)
	}
	want := inventory.Workload{Kind: inventory.WorkloadCompose, Group: "proj", Name: "web"}
	if cs[0].Workload != want {
		t.Errorf("Workload = %+v, want %+v", cs[0].Workload, want)
	}
	if !cs[0].Workload.Known() {
		t.Error("Workload.Known() = false, want true")
	}
}

func TestRunningContainers_ComposeOneLabelMissing_WorkloadUnknown(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
	}{
		{"service missing", map[string]string{composeProjectLabel: "proj"}},
		{"project missing", map[string]string{composeServiceLabel: "web"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveContainers(t, []rawContainer{{Id: "a", Image: "web:1", Labels: tc.labels}})
			cs, err := newTestClient(srv).RunningContainers(context.Background())
			if err != nil {
				t.Fatalf("RunningContainers: %v", err)
			}
			if len(cs) != 1 {
				t.Fatalf("got %+v, want 1 entry", cs)
			}
			if cs[0].Workload.Known() {
				t.Errorf("Workload = %+v, want unknown (only one label present)", cs[0].Workload)
			}
		})
	}
}

func TestRunningContainers_ComposeLabelEmpty_WorkloadUnknown(t *testing.T) {
	srv := serveContainers(t, []rawContainer{
		{Id: "a", Image: "web:1", Labels: composeLabels("", "web")},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].Workload.Known() {
		t.Errorf("Workload = %+v, want unknown (empty project label)", cs[0].Workload)
	}
}

func TestRunningContainers_ComposeLabelControlChar_WorkloadUnknown(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"tab", "pr\toj"},
		{"unit separator", "pr\x1foj"},
		{"newline", "pr\noj"},
		{"delete", "pr\x7foj"},
		{"c1 next line", "pr\u0085oj"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serveContainers(t, []rawContainer{
				{Id: "a", Image: "web:1", Labels: composeLabels(tc.value, "web")},
			})
			cs, err := newTestClient(srv).RunningContainers(context.Background())
			if err != nil {
				t.Fatalf("RunningContainers: %v", err)
			}
			if cs[0].Workload.Known() {
				t.Errorf("Workload = %+v, want unknown (control character in project label)", cs[0].Workload)
			}
		})
	}
}

func TestRunningContainers_ComposeLabelOver253Bytes_WorkloadUnknown(t *testing.T) {
	srv := serveContainers(t, []rawContainer{
		{Id: "a", Image: "web:1", Labels: composeLabels(strings.Repeat("p", 254), "web")},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].Workload.Known() {
		t.Errorf("Workload = %+v, want unknown (project label over 253 bytes)", cs[0].Workload)
	}
}

func TestRunningContainers_NonCompose_WorkloadUnknown(t *testing.T) {
	srv := serveContainers(t, []rawContainer{{Id: "a", Image: "standalone:1"}})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].Workload.Known() {
		t.Errorf("Workload = %+v, want unknown (no compose labels)", cs[0].Workload)
	}
}

// --- container name normalization ---

func TestRunningContainers_NamesEmpty_NameBlank(t *testing.T) {
	srv := serveContainers(t, []rawContainer{{Id: "a", Image: "web:1"}})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].Name != "" {
		t.Errorf("Name = %q, want empty (no Names)", cs[0].Name)
	}
}

func TestRunningContainers_LinkAliasOnly_NameBlank(t *testing.T) {
	srv := serveContainers(t, []rawContainer{
		{Id: "a", Image: "web:1", Names: []string{"/parent/alias"}},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].Name != "" {
		t.Errorf("Name = %q, want empty (only a link alias present)", cs[0].Name)
	}
}

func TestRunningContainers_NameNormalization_PicksLexicographicallySmallest(t *testing.T) {
	srv := serveContainers(t, []rawContainer{
		{Id: "a", Image: "web:1", Names: []string{"/zebra", "/parent/alias", "/apple"}},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if cs[0].Name != "apple" {
		t.Errorf("Name = %q, want %q (link alias excluded, smallest of the rest picked)", cs[0].Name, "apple")
	}
}

// --- container-level observation, no image-level de-duplication ---

func TestRunningContainers_SameImageTwoContainers_TwoEntries(t *testing.T) {
	srv := serveContainers(t, []rawContainer{
		{Id: "a", Image: "nginx:1.25", ImageID: validID1, Names: []string{"/web1"}},
		{Id: "b", Image: "nginx:1.25", ImageID: validID1, Names: []string{"/web2"}},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("got %+v, want 2 entries (running the same image is not de-duplicated at container level)", cs)
	}
	if cs[0].Name != "web1" || cs[1].Name != "web2" {
		t.Errorf("Names = [%q %q], want [web1 web2] (sorted deterministically)", cs[0].Name, cs[1].Name)
	}
	for _, c := range cs {
		if c.Image.Ref != "nginx:1.25" || c.Image.ContentID != validID1 {
			t.Errorf("Image = %+v, want Ref=nginx:1.25 ContentID=%s", c.Image, validID1)
		}
	}
}

// --- deterministic ordering ---

func TestRunningContainers_DeterministicSortOrder(t *testing.T) {
	srv := serveContainers(t, []rawContainer{
		{Id: "a", Image: "redis:7.0", ImageID: validID2, Names: []string{"/cache"}},
		{Id: "b", Image: "nginx:1.25", ImageID: validID2, Names: []string{"/web-b"}},
		{Id: "c", Image: "nginx:1.25", ImageID: validID1, Names: []string{"/web-a"}},
		{Id: "d", Image: "nginx:1.25", ImageID: validID1, Names: []string{"/web-c"}, Labels: composeLabels("proj", "web")},
	})
	cs, err := newTestClient(srv).RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	// Order: (Image.Ref, Image.ContentID, Workload.Group, Workload.Name, Name).
	// Within Ref=nginx:1.25/ContentID=validID1, the unknown-workload entry
	// (Group="") sorts before the compose entry (Group="proj").
	wantNames := []string{"web-a", "web-c", "web-b", "cache"}
	if len(cs) != len(wantNames) {
		t.Fatalf("got %d entries, want %d: %+v", len(cs), len(wantNames), cs)
	}
	for i, want := range wantNames {
		if cs[i].Name != want {
			t.Errorf("cs[%d].Name = %q, want %q (full order: %+v)", i, cs[i].Name, want, cs)
		}
	}
}
