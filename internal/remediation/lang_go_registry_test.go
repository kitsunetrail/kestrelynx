package remediation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// goProxyServer serves handler as both the proxy and the checksum database
// and records the paths it was asked for.
func goProxyServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*GoClient, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return &GoClient{HTTP: srv.Client(), ProxyURL: srv.URL + "/", SumDBURL: srv.URL + "/"}, &seen
}

func TestGoEscape(t *testing.T) {
	for in, want := range map[string]string{
		"golang.org/x/net":             "golang.org/x/net",
		"github.com/Azure/go-autorest": "github.com/!azure/go-autorest",
		"github.com/BurntSushi/toml":   "github.com/!burnt!sushi/toml",
		"v1.0.0-RC1":                   "v1.0.0-!r!c1",
	} {
		if got := goEscape(in); got != want {
			t.Errorf("goEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoLookupArgsOK(t *testing.T) {
	good := [][2]string{
		{"golang.org/x/net", "v0.23.0"},
		{"golang.org/x/net", ""},
		{"gopkg.in/yaml.v3", "v3.0.1"},
		{"github.com/Azure/go-autorest/autorest/v2", "v2.1.0-RC1"},
		{"example.com/m", "v2.0.0+incompatible"},
		{"example.com/m", "v0.0.0-20240101000000-abcdef123456"},
		{"a~b.example/m_n", "v1.2.3"},
	}
	for _, c := range good {
		if !goLookupArgsOK(c[0], c[1]) {
			t.Errorf("refused %q %q", c[0], c[1])
		}
	}
	bad := [][2]string{
		{"", "v1.0.0"},
		{"-u", "v1.0.0"},
		{"x", "v1.0.0"},
		{"example.com/m/", "v1.0.0"},
		{"/example.com/m", "v1.0.0"},
		{"example.com//m", "v1.0.0"},
		{"example.com/../m", "v1.0.0"},
		{"example.com/m..n", "v1.0.0"},
		{"example.com/m n", "v1.0.0"},
		{"example.com/m?x=1", "v1.0.0"},
		{"example.com/m#x", "v1.0.0"},
		{"example.com/m\n", "v1.0.0"},
		{"example.com/m%2f", "v1.0.0"},
		{"example.com/m@v1", "v1.0.0"},
		{strings.Repeat("a", 501), "v1.0.0"},
		{"example.com/m", "1.0.0"},
		{"example.com/m", "latest"},
		{"example.com/m", "v1.0"},
		{"example.com/m", "v1.0.0/../x"},
		{"example.com/m", "v1.0.0?x"},
		{"example.com/m", "v1.0.0-" + strings.Repeat("a", 200)},
		{"example.com/m", "v1.0.0+build"},
	}
	for _, c := range bad {
		if goLookupArgsOK(c[0], c[1]) {
			t.Errorf("accepted %q %q", c[0], c[1])
		}
	}
}

func TestGoClientRefusesBadArgumentsWithoutAsking(t *testing.T) {
	c, seen := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })
	if _, err := c.Info(bg, "-u", "v1.0.0"); err == nil {
		t.Error("Info accepted a path starting with -")
	}
	if _, err := c.Info(bg, "example.com/m", ""); err == nil {
		t.Error("Info accepted an empty version")
	}
	if _, err := c.GoMod(bg, "example.com/m", "latest"); err == nil {
		t.Error("GoMod accepted latest")
	}
	if _, err := c.GoMod(bg, "example.com/m", ""); err == nil {
		t.Error("GoMod accepted an empty version")
	}
	if _, err := c.Latest(bg, "example.com/../m"); err == nil {
		t.Error("Latest accepted a path with ..")
	}
	if _, err := c.Sums(bg, "example.com/m", "v1.0"); err == nil {
		t.Error("Sums accepted a short version")
	}
	if _, err := c.Sums(bg, "example.com/m", ""); err == nil {
		t.Error("Sums accepted an empty version")
	}
	if len(*seen) != 0 {
		t.Errorf("requests were made for refused arguments: %v", *seen)
	}
}

func TestGoClientPaths(t *testing.T) {
	c, seen := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".info"), strings.HasSuffix(r.URL.Path, "/@latest"):
			w.Write([]byte(`{"Version":"v1.2.3-RC1","Time":"2024-03-04T05:06:07Z"}`))
		case strings.HasSuffix(r.URL.Path, ".mod"):
			w.Write([]byte("module github.com/Azure/go-autorest\n"))
		default:
			http.NotFound(w, r)
		}
	})
	info, err := c.Info(bg, "github.com/Azure/go-autorest", "v1.2.3-RC1")
	if err != nil || info.Version != "v1.2.3-RC1" || !info.Time.Equal(time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)) {
		t.Fatalf("info = %+v, %v", info, err)
	}
	if _, err := c.Latest(bg, "github.com/Azure/go-autorest"); err != nil {
		t.Fatal(err)
	}
	mod, err := c.GoMod(bg, "github.com/Azure/go-autorest", "v1.2.3-RC1")
	if err != nil || !strings.HasPrefix(string(mod), "module ") {
		t.Fatalf("go.mod = %q, %v", mod, err)
	}
	want := []string{
		"/github.com/!azure/go-autorest/@v/v1.2.3-!r!c1.info",
		"/github.com/!azure/go-autorest/@latest",
		"/github.com/!azure/go-autorest/@v/v1.2.3-!r!c1.mod",
	}
	if strings.Join(*seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("paths = %v, want %v", *seen, want)
	}
}

func TestGoClientNotFound(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusGone} {
		c, _ := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		if _, err := c.Info(bg, "example.com/m", "v1.0.0"); !errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("Info %d: %v", code, err)
		}
		if _, err := c.GoMod(bg, "example.com/m", "v1.0.0"); !errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("GoMod %d: %v", code, err)
		}
		if _, err := c.Latest(bg, "example.com/m"); !errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("Latest %d: %v", code, err)
		}
		if _, err := c.Sums(bg, "example.com/m", "v1.0.0"); !errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("Sums %d: %v", code, err)
		}
	}
	for _, code := range []int{http.StatusInternalServerError, http.StatusForbidden, http.StatusTooManyRequests, http.StatusFound} {
		c, _ := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		_, err := c.Info(bg, "example.com/m", "v1.0.0")
		if err == nil || errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("status %d: err = %v, want a failure that is not a missing release", code, err)
		}
	}
}

func TestGoClientResponseLimits(t *testing.T) {
	big := func(n int) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", n))) }
	}
	// One byte over the limit is refused; the limit itself is read (and then
	// fails on its content, not on its size).
	c, _ := goProxyServer(t, big(maxGoModBytes+1))
	if _, err := c.GoMod(bg, "example.com/m", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("a go.mod over the limit: %v", err)
	}
	c, _ = goProxyServer(t, big(maxGoModBytes))
	if body, err := c.GoMod(bg, "example.com/m", "v1.0.0"); err != nil || len(body) != maxGoModBytes {
		t.Errorf("a go.mod at the limit: %d bytes, %v", len(body), err)
	}
	c, _ = goProxyServer(t, big(maxGoInfoBytes+1))
	if _, err := c.Info(bg, "example.com/m", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("an info over the limit: %v", err)
	}
	if _, err := c.Latest(bg, "example.com/m"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("a latest over the limit: %v", err)
	}
	c, _ = goProxyServer(t, big(maxGoSumDBBytes+1))
	if _, err := c.Sums(bg, "example.com/m", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("a lookup over the limit: %v", err)
	}
}

func TestGoClientGoModMustBeUTF8(t *testing.T) {
	c, _ := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("module m\n\xff\xfe\n")) })
	if _, err := c.GoMod(bg, "example.com/m", "v1.0.0"); err == nil {
		t.Error("a go.mod that is not UTF-8 was returned")
	}
}

func TestGoClientInfoChecks(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":             "<html>",
		"no version":           `{"Time":"2024-03-04T05:06:07Z"}`,
		"version without v":    `{"Version":"1.2.3"}`,
		"version with a query": `{"Version":"v1.2.3?x=1"}`,
		"latest":               `{"Version":"latest"}`,
		"a path in version":    `{"Version":"v1.2.3/../x"}`,
		"bad time":             `{"Version":"v1.2.3","Time":"yesterday"}`,
	} {
		c, _ := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
		if got, err := c.Info(bg, "example.com/m", "v1.2.3"); err == nil {
			t.Errorf("Info %s: accepted %+v", name, got)
		}
		if got, err := c.Latest(bg, "example.com/m"); err == nil {
			t.Errorf("Latest %s: accepted %+v", name, got)
		}
	}
	c, _ := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v2.0.0+incompatible","Time":"2024-03-04T05:06:07Z","Origin":{"VCS":"git"}}`))
	})
	if got, err := c.Info(bg, "example.com/m", "v2.0.0+incompatible"); err != nil || got.Version != "v2.0.0+incompatible" {
		t.Errorf("info = %+v, %v", got, err)
	}
}

// testTreeHash is a root hash of the form the tree head carries.
const testTreeHash = "szntmUobRa8FxE+ioOiwOnvtisw0NkgrXz+98CGTND0="

// lookupBody is the checksum database's answer for path@version.
func lookupBody(path, version, zip, mod string) string {
	return "12345\n" + path + " " + version + " " + zip + "\n" + path + " " + version + "/go.mod " + mod + "\n\n" +
		"go.sum database tree\n27\n" + testTreeHash + "\n\n— sum.golang.org Az3grq1234\n"
}

func TestGoClientSums(t *testing.T) {
	zip, mod := fakeH1("zip"), fakeH1("mod")
	c, seen := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(lookupBody("github.com/Azure/go-autorest", "v1.2.3-RC1", zip, mod)))
	})
	got, err := c.Sums(bg, "github.com/Azure/go-autorest", "v1.2.3-RC1")
	if err != nil || got.Zip != zip || got.Mod != mod {
		t.Fatalf("sums = %+v, %v", got, err)
	}
	// The go.mod hash is asked for under the version itself.
	if len(*seen) != 1 || (*seen)[0] != "/lookup/github.com/!azure/go-autorest@v1.2.3-!r!c1" {
		t.Errorf("paths = %v", *seen)
	}
}

func TestParseSumDBLookup(t *testing.T) {
	const path, ver = "golang.org/x/net", "v0.23.0"
	zip, mod := fakeH1("zip"), fakeH1("mod")
	good := lookupBody(path, ver, zip, mod)
	if got, err := parseSumDBLookup([]byte(good), path, ver); err != nil || got.Zip != zip || got.Mod != mod {
		t.Fatalf("good answer: %+v, %v", got, err)
	}
	line := func(p, v, h string) string { return p + " " + v + " " + h }
	tail := "\n\ngo.sum database tree\n1\n" + testTreeHash + "\n\n— sum.golang.org Az3grq1234\n"
	cases := map[string]string{
		"empty":                          "",
		"no record number":               strings.TrimPrefix(good, "12345\n"),
		"record number not a number":     strings.Replace(good, "12345", "abc", 1),
		"record number negative-looking": strings.Replace(good, "12345", "12345x", 1),
		"too few lines":                  "1\n" + line(path, ver, zip) + "\n" + line(path, ver+"/go.mod", mod),
		"other path":                     "1\n" + line("golang.org/x/text", ver, zip) + "\n" + line("golang.org/x/text", ver+"/go.mod", mod) + tail,
		"other version":                  "1\n" + line(path, "v0.24.0", zip) + "\n" + line(path, "v0.24.0/go.mod", mod) + tail,
		"zip line for other path":        "1\n" + line("golang.org/x/text", ver, zip) + "\n" + line(path, ver+"/go.mod", mod) + tail,
		"go.mod line for other version":  "1\n" + line(path, ver, zip) + "\n" + line(path, "v0.24.0/go.mod", mod) + tail,
		"go.mod line without suffix":     "1\n" + line(path, ver, zip) + "\n" + line(path, ver, mod) + tail,
		"lines swapped":                  "1\n" + line(path, ver+"/go.mod", mod) + "\n" + line(path, ver, zip) + tail,
		"duplicate zip line":             "1\n" + line(path, ver, zip) + "\n" + line(path, ver, zip) + tail,
		"duplicate go.mod line":          "1\n" + line(path, ver+"/go.mod", mod) + "\n" + line(path, ver+"/go.mod", mod) + tail,
		"blank line missing":             "1\n" + line(path, ver, zip) + "\n" + line(path, ver+"/go.mod", mod) + "\nextra\ngo.sum database tree\n",
		"blank line first":               "1\n\n" + line(path, ver, zip) + "\n" + line(path, ver+"/go.mod", mod) + tail,
		"blank line between":             "1\n" + line(path, ver, zip) + "\n\n" + line(path, ver+"/go.mod", mod) + tail,
		"extra field":                    "1\n" + line(path, ver, zip) + " x\n" + line(path, ver+"/go.mod", mod) + tail,
		"missing field":                  "1\n" + path + " " + zip + "\n" + line(path, ver+"/go.mod", mod) + tail,
		"zip hash not h1":                "1\n" + line(path, ver, "h2:"+strings.TrimPrefix(zip, "h1:")) + "\n" + line(path, ver+"/go.mod", mod) + tail,
		"mod hash too short":             "1\n" + line(path, ver, zip) + "\n" + line(path, ver+"/go.mod", zip[:20]) + tail,
		"mod hash bad character":         "1\n" + line(path, ver, zip) + "\n" + line(path, ver+"/go.mod", strings.Replace(mod, mod[5:6], "!", 1)) + tail,
		"hash with no padding":           "1\n" + line(path, ver, zip) + "\n" + line(path, ver+"/go.mod", strings.TrimSuffix(mod, "=")+"A") + tail,
		"negative record number":         strings.Replace(good, "12345", "-1", 1),
		"tree head named otherwise":      strings.Replace(good, "go.sum database tree", "go.sum tree", 1),
		"tree size not a number":         strings.Replace(good, "\n27\n", "\nx\n", 1),
		"root hash of another form":      strings.Replace(good, testTreeHash, "abc=", 1),
		"no signature":                   strings.TrimSuffix(good, "— sum.golang.org Az3grq1234\n"),
		"signature without its dash":     strings.Replace(good, "— sum.golang.org", "sum.golang.org", 1),
		"no final newline":               strings.TrimSuffix(good, "\n"),
		"a line after the signature":     good + "extra\n",
		"no blank line before signature": strings.Replace(good, testTreeHash+"\n\n", testTreeHash+"\n", 1),
	}
	for name, body := range cases {
		if got, err := parseSumDBLookup([]byte(body), path, ver); err == nil {
			t.Errorf("%s: accepted %+v", name, got)
		}
	}
}

func TestGoClientCancelledRequest(t *testing.T) {
	c, _ := goProxyServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("module m\n")) })
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := c.GoMod(ctx, "example.com/m", "v1.0.0"); err == nil || errors.Is(err, ErrReleaseNotFound) {
		t.Errorf("err = %v", err)
	}
}
