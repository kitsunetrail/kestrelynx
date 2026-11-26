package remediation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCargoIndexPath(t *testing.T) {
	for name, want := range map[string]string{
		"a":                "1/a",
		"ab":               "2/ab",
		"abc":              "3/a/abc",
		"tokio":            "to/ki/tokio",
		"Tokio":            "to/ki/tokio",
		"serde_json":       "se/rd/serde_json",
		"pin-project-lite": "pi/n-/pin-project-lite",
		"abcd":             "ab/cd/abcd",
		"A1":               "2/a1",
	} {
		got, ok := cargoIndexPath(name)
		if !ok || got != want {
			t.Errorf("cargoIndexPath(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "a b", "a/b", "../x", "a.b", "tokio\n", strings.Repeat("a", 65), "日本"} {
		if got, ok := cargoIndexPath(name); ok {
			t.Errorf("cargoIndexPath(%q) = %q", name, got)
		}
	}
}

func TestParseCargoIndex_Real(t *testing.T) {
	rs, err := parseCargoIndex([]byte(cargoFixture(t, "index_tokio.jsonl")), "tokio")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 10 {
		t.Fatalf("%d releases", len(rs))
	}
	got := map[string]CargoRelease{}
	for _, r := range rs {
		got[r.Version] = r
	}
	r := got["1.23.1"]
	if r.Name != "tokio" || r.Yanked || r.RustVersion != "1.49" || len(r.Checksum) != 64 || len(r.Deps) == 0 {
		t.Errorf("1.23.1 = %+v", r)
	}
	if !got["1.39.0"].Yanked || got["1.39.0"].RustVersion != "1.70" {
		t.Errorf("1.39.0 = %+v", got["1.39.0"])
	}
	var kinds = map[string]bool{}
	for _, d := range r.Deps {
		kinds[d.Kind] = true
		if d.Name == "" || d.Req == "" {
			t.Errorf("dep = %+v", d)
		}
	}
	if !kinds["normal"] || !kinds["dev"] {
		t.Errorf("kinds = %v", kinds)
	}
	if a := got["0.2.0-alpha.5"]; a.RustVersion != "" {
		t.Errorf("alpha = %+v", a)
	}
}

func indexLine(name, vers, extra string) string {
	return `{"name":"` + name + `","vers":"` + vers + `","cksum":"` + cksumA + `","yanked":false,"deps":[]` + extra + `}`
}

func TestParseCargoIndex_Validation(t *testing.T) {
	ok := indexLine("serde", "1.0.0", "")
	for name, c := range map[string]struct {
		body, name string
	}{
		"not JSON":                  {"{\n", "serde"},
		"other name":                {indexLine("Serde", "1.0.0", ""), "serde"},
		"other name by case":        {indexLine("serde", "1.0.0", ""), "Serde"},
		"duplicate version":         {ok + "\n" + ok, "serde"},
		"not a version":             {indexLine("serde", "1.0", ""), "serde"},
		"no checksum":               {`{"name":"serde","vers":"1.0.0","yanked":false,"deps":[]}`, "serde"},
		"capital checksum":          {strings.Replace(ok, cksumA, strings.Repeat("A", 64), 1), "serde"},
		"short checksum":            {strings.Replace(ok, cksumA, "abc", 1), "serde"},
		"no yanked":                 {`{"name":"serde","vers":"1.0.0","cksum":"` + cksumA + `","deps":[]}`, "serde"},
		"no deps":                   {`{"name":"serde","vers":"1.0.0","cksum":"` + cksumA + `","yanked":false}`, "serde"},
		"null deps":                 {`{"name":"serde","vers":"1.0.0","cksum":"` + cksumA + `","yanked":false,"deps":null}`, "serde"},
		"name is a number":          {`{"name":3,"vers":"1.0.0","cksum":"` + cksumA + `","yanked":false,"deps":[]}`, "serde"},
		"dependency without req":    {`{"name":"serde","vers":"1.0.0","cksum":"` + cksumA + `","yanked":false,"deps":[{"name":"x"}]}`, "serde"},
		"dependency without a name": {`{"name":"serde","vers":"1.0.0","cksum":"` + cksumA + `","yanked":false,"deps":[{"req":"1"}]}`, "serde"},
		"empty":                     {"\n\n", "serde"},
	} {
		if _, err := parseCargoIndex([]byte(c.body), c.name); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// Fields the plan does not use are ignored, and a blank line is skipped.
	body := indexLine("serde", "1.0.0", `,"features":{"a":[]},"features2":{"b":["dep:c"]},"v":2,"pubtime":"2024-01-01T00:00:00Z","links":null,"rust_version":null`) + "\n\n" +
		`{"name":"serde","vers":"1.0.1","cksum":"` + cksumB + `","yanked":true,"rust_version":"1.60","deps":[{"name":"x","req":"^1","kind":null,"target":null,"package":"y","optional":true,"features":[]}]}` + "\n"
	rs, err := parseCargoIndex([]byte(body), "serde")
	if err != nil || len(rs) != 2 {
		t.Fatalf("%v %+v", err, rs)
	}
	if !rs[1].Yanked || rs[1].RustVersion != "1.60" || len(rs[1].Deps) != 1 {
		t.Errorf("release = %+v", rs[1])
	}
	if d := rs[1].Deps[0]; d.Name != "x" || d.Package != "y" || d.Kind != "normal" || !d.Optional || d.Req != "^1" {
		t.Errorf("dep = %+v", d)
	}
}

func TestSelectCargoRelease(t *testing.T) {
	rs, err := parseCargoIndex([]byte(cargoFixture(t, "index_tokio.jsonl")), "tokio")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		installed, lower string
		want             string
		reason           Reason
	}{
		// The lowest that is at or above the bound, not the highest.
		{"1.18.0", "1.18.4", "1.18.4", ""},
		{"1.18.0", "1.18.1", "1.18.4", ""},
		{"1.18.0", "1.18.5", "1.18.5", ""},
		{"1.18.0", "1.18.6", "1.19.0", ""},
		{"1.18.0", "1.38.0", "1.38.2", ""},
		{"1.18.0", "1.38.2", "1.38.2", ""},
		// A yanked release is skipped: 1.39.0 is the only one above 1.38.2.
		{"1.18.0", "1.38.3", "", ReasonCargoReleaseNotFound},
		{"1.18.0", "1.99.0", "", ReasonCargoReleaseNotFound},
		// Another series is not taken.
		{"0.2.0", "0.2.0", "", ReasonCargoReleaseNotFound},
		{"1.18.0", "2.0.0", "", ReasonCargoReleaseNotFound},
		{"x", "1.0.0", "", ReasonUnparsableVersion},
		{"1.18.0", "x", "", ReasonUnparsableVersion},
	} {
		got, reason, detail := selectCargoRelease(rs, c.installed, c.lower)
		if got.Version != c.want || reason != c.reason {
			t.Errorf("select(%s, %s) = %q %q (%s); want %q %q", c.installed, c.lower, got.Version, reason, detail, c.want, c.reason)
		}
	}

	// A pre-release is not taken though it is the only one at the bound, and a
	// yanked release is not either.
	mk := func(vers string, yanked bool) CargoRelease {
		return CargoRelease{Name: "x", Version: vers, Yanked: yanked}
	}
	got, reason, _ := selectCargoRelease([]CargoRelease{mk("1.2.0-rc.1", false), mk("1.2.1", true), mk("1.3.0", false)}, "1.1.0", "1.2.0-rc.1")
	if got.Version != "1.3.0" || reason != "" {
		t.Errorf("pre-release and yanked: %q %q", got.Version, reason)
	}
	// The series of 0.x is the minor version.
	got, _, _ = selectCargoRelease([]CargoRelease{mk("0.3.0", false), mk("0.2.9", false), mk("0.2.7", false)}, "0.2.1", "0.2.5")
	if got.Version != "0.2.7" {
		t.Errorf("0.x: %q", got.Version)
	}
}

func TestCargoIndexClient(t *testing.T) {
	body := indexLine("tokio", "1.0.0", "") + "\n"
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("User-Agent") == "" {
			t.Error("no User-Agent")
		}
		switch r.URL.Path {
		case "/to/ki/tokio":
			_, _ = w.Write([]byte(body))
		case "/ot/he/other":
			_, _ = w.Write([]byte(body)) // an answer for another crate
		case "/gone":
			w.WriteHeader(http.StatusGone)
		case "/ab/cd/abcd":
			w.WriteHeader(http.StatusInternalServerError)
		case "/bi/g-/big-crate":
			_, _ = w.Write([]byte(strings.Repeat(" ", maxCargoIndexBytes+1)))
		case "/re/di/redirect":
			http.Redirect(w, r, "http://elsewhere.invalid/to/ki/tokio", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &CargoIndexClient{BaseURL: srv.URL + "/", HTTP: srv.Client()}
	ctx := context.Background()

	rs, err := c.Versions(ctx, "tokio")
	if err != nil || len(rs) != 1 || rs[0].Version != "1.0.0" {
		t.Fatalf("tokio: %v %+v", err, rs)
	}
	if _, err := c.Versions(ctx, "missing"); !errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("missing crate: %v", err)
	}
	if _, err := c.Versions(ctx, "abcd"); err == nil || errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("server error: %v", err)
	}
	if _, err := c.Versions(ctx, "other"); err == nil {
		t.Error("an answer for another crate was accepted")
	}
	if _, err := c.Versions(ctx, "big-crate"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("oversized answer: %v", err)
	}
	if _, err := c.Versions(ctx, "redirect"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("redirect to another host: %v", err)
	}
	before := len(paths)
	for _, bad := range []string{"", "../etc", "a/b", "a b"} {
		if _, err := c.Versions(ctx, bad); err == nil {
			t.Errorf("%q was looked up", bad)
		}
	}
	if len(paths) != before {
		t.Errorf("a name that is not a crate name reached the server: %v", paths[before:])
	}
}
