package remediation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type mavenTestServer struct {
	*httptest.Server
	mu    sync.Mutex
	paths []string
	uas   []string
}

func newMavenTestServer(t *testing.T, h http.HandlerFunc) *mavenTestServer {
	s := &mavenTestServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.paths = append(s.paths, r.URL.EscapedPath())
		s.uas = append(s.uas, r.Header.Get("User-Agent"))
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

const mavenMetadataXML = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <versioning>
    <latest>33.7.2-jre</latest>
    <versions>
      <version>31.1-jre</version>
      <version>32.0.0-android</version>
      <version> 33.7.2-jre </version>
      <version>bad/version</version>
    </versions>
  </versioning>
</metadata>`

func TestMavenClientVersions(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(mavenMetadataXML))
	})
	c := &MavenClient{BaseURL: srv.URL + "/maven2/"}
	got, err := c.Versions(context.Background(), "com.google.guava", "guava")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"31.1-jre", "32.0.0-android", "33.7.2-jre"}; !reflect.DeepEqual(got, want) {
		t.Errorf("versions = %q, want %q", got, want)
	}
	if want := []string{"/maven2/com/google/guava/guava/maven-metadata.xml"}; !reflect.DeepEqual(srv.paths, want) {
		t.Errorf("paths = %q, want %q", srv.paths, want)
	}
	if srv.uas[0] != "kestrelynx" {
		t.Errorf("User-Agent = %q", srv.uas[0])
	}
}

func TestMavenClientPOM(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<project/>"))
	})
	c := &MavenClient{BaseURL: srv.URL + "/maven2"}
	got, err := c.POM(context.Background(), "org.springframework", "spring-core", "5.2.24.RELEASE")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "<project/>" {
		t.Errorf("pom = %q", got)
	}
	if want := []string{"/maven2/org/springframework/spring-core/5.2.24.RELEASE/spring-core-5.2.24.RELEASE.pom"}; !reflect.DeepEqual(srv.paths, want) {
		t.Errorf("paths = %q, want %q", srv.paths, want)
	}
	if srv.uas[0] != "kestrelynx" {
		t.Errorf("User-Agent = %q", srv.uas[0])
	}
}

func TestMavenClientNotFound(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	c := &MavenClient{BaseURL: srv.URL}
	if _, err := c.Versions(context.Background(), "g", "a"); !errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("Versions err = %v", err)
	}
	if _, err := c.POM(context.Background(), "g", "a", "1"); !errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("POM err = %v", err)
	}
}

func TestMavenClientServerError(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) })
	c := &MavenClient{BaseURL: srv.URL}
	_, err := c.POM(context.Background(), "g", "a", "1")
	if err == nil || errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("err = %v, want a plain error", err)
	}
}

func TestMavenClientOversize(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := maxMavenPOMBytes + 1
		if strings.HasSuffix(r.URL.Path, "maven-metadata.xml") {
			n = maxMavenMetadataBytes + 1
		}
		w.Write([]byte(strings.Repeat("x", n)))
	})
	c := &MavenClient{BaseURL: srv.URL}
	if _, err := c.Versions(context.Background(), "g", "a"); err == nil {
		t.Error("oversize metadata accepted")
	}
	if _, err := c.POM(context.Background(), "g", "a", "1"); err == nil {
		t.Error("oversize pom accepted")
	}
}

func TestMavenClientAtLimit(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", maxMavenPOMBytes)))
	})
	c := &MavenClient{BaseURL: srv.URL}
	got, err := c.POM(context.Background(), "g", "a", "1")
	if err != nil || len(got) != maxMavenPOMBytes {
		t.Errorf("len = %d, err = %v", len(got), err)
	}
}

func TestMavenClientBadCoordinates(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<project/>")) })
	c := &MavenClient{BaseURL: srv.URL}
	ctx := context.Background()
	for _, g := range []string{"", "a..b", ".a", "a.", "..", "a/b", "a b", "a%2fb", "a\x00b", "g?x", strings.Repeat("a", 201)} {
		if _, err := c.Versions(ctx, g, "a"); err == nil {
			t.Errorf("groupId %q accepted", g)
		}
		if _, err := c.POM(ctx, g, "a", "1"); err == nil {
			t.Errorf("groupId %q accepted by POM", g)
		}
	}
	for _, a := range []string{"", ".", "..", "a/b", "a b", "a%2f", "a:b", "a?b"} {
		if _, err := c.Versions(ctx, "g", a); err == nil {
			t.Errorf("artifactId %q accepted", a)
		}
		if _, err := c.POM(ctx, "g", a, "1"); err == nil {
			t.Errorf("artifactId %q accepted by POM", a)
		}
	}
	for _, v := range []string{"", ".", "..", "1/2", `1\2`, "1 2", "1\n", "1\x00", "\xff", strings.Repeat("1", 129)} {
		if _, err := c.POM(ctx, "g", "a", v); err == nil {
			t.Errorf("version %q accepted", v)
		}
	}
	if len(srv.paths) != 0 {
		t.Errorf("requests were made for bad coordinates: %q", srv.paths)
	}
}

func TestMavenClientVersionEscaped(t *testing.T) {
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<project/>")) })
	c := &MavenClient{BaseURL: srv.URL}
	if _, err := c.POM(context.Background(), "g", "a", "1?x#y%z"); err != nil {
		t.Fatal(err)
	}
	if want := "/g/a/1%3Fx%23y%25z/a-1%3Fx%23y%25z.pom"; srv.paths[0] != want {
		t.Errorf("path = %q, want %q", srv.paths[0], want)
	}
}

func TestMavenClientRedirects(t *testing.T) {
	other := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<project/>")) })
	srv := newMavenTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/g/a/1/"):
			http.Redirect(w, r, other.URL+"/elsewhere", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/g/a/2/"):
			http.Redirect(w, r, "/moved.pom", http.StatusFound)
		default:
			w.Write([]byte("<project/>"))
		}
	})
	c := &MavenClient{BaseURL: srv.URL}
	if _, err := c.POM(context.Background(), "g", "a", "1"); err == nil {
		t.Error("a redirect to another host was followed")
	}
	for _, p := range other.paths {
		t.Errorf("other host was asked for %q", p)
	}
	if _, err := c.POM(context.Background(), "g", "a", "2"); err != nil {
		t.Errorf("same-host redirect: %v", err)
	}
}

func TestMavenRedirectKeepsScheme(t *testing.T) {
	from, _ := http.NewRequest(http.MethodGet, "https://repo.maven.apache.org/maven2/g/a/1/a-1.pom", nil)
	down, _ := http.NewRequest(http.MethodGet, "http://repo.maven.apache.org/maven2/g/a/1/a-1.pom", nil)
	same, _ := http.NewRequest(http.MethodGet, "https://repo.maven.apache.org/maven2/g/a/1/moved.pom", nil)
	if err := sameHostRedirect(down, []*http.Request{from}); err == nil {
		t.Error("a redirect from https to http on the same host was followed")
	}
	if err := sameHostRedirect(same, []*http.Request{from}); err != nil {
		t.Errorf("same scheme and host: %v", err)
	}
}

func TestParseMavenMetadataRefused(t *testing.T) {
	for name, body := range map[string]string{
		"doctype":    `<!DOCTYPE metadata><metadata/>`,
		"malformed":  `<metadata><versioning>`,
		"wrong root": `<project/>`,
		"empty":      ``,
	} {
		if _, err := parseMavenMetadata([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	got, err := parseMavenMetadata([]byte(`<metadata><versioning><versions/></versioning></metadata>`))
	if err != nil || len(got) != 0 {
		t.Errorf("no versions: %q, %v", got, err)
	}
}
