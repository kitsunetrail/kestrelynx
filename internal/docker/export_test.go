package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

var exportPlatform = inventory.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}

const exportID = "sha256:00000000000000000000000000000000000000000000000000000000000000aa"

type exportServer struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string // method + " " + request URI
}

func newExportServer(t *testing.T, version string, h http.HandlerFunc) *exportServer {
	t.Helper()
	s := &exportServer{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, r.Method+" "+r.URL.RequestURI())
		s.mu.Unlock()
		if r.URL.Path == "/version" {
			fmt.Fprintf(w, `{"ApiVersion":%q}`, version)
			return
		}
		h(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *exportServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reqs...)
}

func TestExportImage_PlatformOnlyFromAPI148(t *testing.T) {
	for version, wantPlatform := range map[string]bool{"1.47": false, "1.48": true, "1.50": true, "2.0": true, "1.9": false} {
		s := newExportServer(t, version, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "TAR") })
		c := newClient(s.srv.URL, s.srv.Client())
		rc, err := c.ExportImage(context.Background(), exportID, exportPlatform)
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != "TAR" {
			t.Errorf("%s: body %q", version, b)
		}
		reqs := s.requests()
		if len(reqs) != 2 || reqs[0] != "GET /version" {
			t.Fatalf("%s: requests %v", version, reqs)
		}
		u, _ := url.Parse("http://x" + reqs[1][len("GET "):])
		if u.Path != "/images/"+exportID+"/get" {
			t.Errorf("%s: path %q", version, u.Path)
		}
		p := u.Query().Get("platform")
		if !wantPlatform {
			if p != "" || u.RawQuery != "" {
				t.Errorf("%s: platform sent: %q", version, u.RawQuery)
			}
			continue
		}
		if p != `{"architecture":"arm64","os":"linux","variant":"v8"}` {
			t.Errorf("%s: platform %q", version, p)
		}
	}
}

func TestExportImage_NoPlatformMeansNoVersionLookup(t *testing.T) {
	s := newExportServer(t, "1.50", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "TAR") })
	rc, err := newClient(s.srv.URL, s.srv.Client()).ExportImage(context.Background(), exportID, inventory.Platform{})
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if reqs := s.requests(); len(reqs) != 1 || reqs[0] != "GET /images/"+exportID+"/get" {
		t.Errorf("requests %v", reqs)
	}
}

func TestExportImage_OnlyGETs(t *testing.T) {
	s := newExportServer(t, "1.50", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "TAR") })
	rc, err := newClient(s.srv.URL, s.srv.Client()).ExportImage(context.Background(), exportID, exportPlatform)
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	for _, r := range s.requests() {
		if r[:3] != "GET" {
			t.Errorf("request %q is not a GET", r)
		}
	}
}

func TestExportImage_RejectsUnusableIDs(t *testing.T) {
	s := newExportServer(t, "1.50", func(w http.ResponseWriter, r *http.Request) { t.Error("a request was sent") })
	c := newClient(s.srv.URL, s.srv.Client())
	for _, id := range []string{"", "latest", "../etc", "sha256:xyz", "alpine:3", exportID + "/../x", "SHA256:" + exportID[7:]} {
		if _, err := c.ExportImage(context.Background(), id, exportPlatform); !errors.Is(err, ErrExportInvalid) {
			t.Errorf("id %q: err = %v", id, err)
		}
	}
	// A bare hex ID is fine.
	s2 := newExportServer(t, "1.50", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "TAR") })
	rc, err := newClient(s2.srv.URL, s2.srv.Client()).ExportImage(context.Background(), exportID[7:], inventory.Platform{})
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if _, err := c.ExportImage(context.Background(), exportID, inventory.Platform{OS: "linux"}); !errors.Is(err, ErrExportInvalid) {
		t.Errorf("half a platform: %v", err)
	}
}

func TestExportImage_StatusErrors(t *testing.T) {
	s := newExportServer(t, "1.50", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no such image", http.StatusNotFound) })
	_, err := newClient(s.srv.URL, s.srv.Client()).ExportImage(context.Background(), exportID, exportPlatform)
	var se *ExportStatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Errorf("err = %v", err)
	}
}

// The 15 second timeout of the ordinary requests does not cut a long export:
// the stream lives as long as the caller's context.
func TestExportImage_NoClientTimeoutOnTheStream(t *testing.T) {
	s := newExportServer(t, "1.50", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "first|")
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "second")
	})
	hc := s.srv.Client()
	hc.Timeout = 100 * time.Millisecond
	c := newClient(s.srv.URL, hc)
	rc, err := c.ExportImage(context.Background(), exportID, exportPlatform)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil || string(b) != "first|second" {
		t.Errorf("%q %v", b, err)
	}
	if hc.Timeout != 100*time.Millisecond {
		t.Error("the client's own timeout was changed")
	}
	// The caller's context still ends it.
	s2 := newExportServer(t, "1.50", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := newClient(s2.srv.URL, s2.srv.Client()).ExportImage(ctx, exportID, inventory.Platform{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

func TestExportImage_VersionAnswerIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			t.Errorf("the export was requested after an oversized version answer: %s", r.URL.Path)
			return
		}
		io.WriteString(w, `{"ApiVersion":"1.50","Pad":"`)
		io.WriteString(w, strings.Repeat("a", 1<<20))
		io.WriteString(w, `"}`)
	}))
	defer srv.Close()
	_, err := newClient(srv.URL, srv.Client()).ExportImage(context.Background(), exportID, exportPlatform)
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("err = %v, want the answer to be refused for its length", err)
	}
}
