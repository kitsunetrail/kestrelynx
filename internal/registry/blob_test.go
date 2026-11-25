package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const blobRepo = "team/app"

func serveBlob(f *fakeRegistry, content string) string {
	d := sha(content)
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, content) })
	return d
}

func TestOpenBlob_StreamsWithTokenAndVerifies(t *testing.T) {
	f := newFakeRegistry(t)
	content := strings.Repeat("layer bytes ", 5000)
	d := serveBlob(f, content)
	br, err := f.client(Options{}).OpenBlob(context.Background(), f.repo(blobRepo), d, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	got, err := io.ReadAll(br)
	if err != nil || string(got) != content {
		t.Fatalf("read %d bytes, err %v", len(got), err)
	}
	if err := br.Finish(); err != nil {
		t.Errorf("Finish after a full read: %v", err)
	}
	if f.tokenHits != 1 {
		t.Errorf("token endpoint hit %d times", f.tokenHits)
	}
}

func TestOpenBlob_FinishDrainsAndChecks(t *testing.T) {
	f := newFakeRegistry(t)
	content := strings.Repeat("x", 100000)
	d := serveBlob(f, content)
	br, err := f.client(Options{}).OpenBlob(context.Background(), f.repo(blobRepo), d, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	io.CopyN(io.Discard, br, 10) // a consumer that stops early
	if err := br.Finish(); err != nil {
		t.Errorf("Finish: %v", err)
	}
}

func TestOpenBlob_WrongContentIsADigestMismatchAtTheEnd(t *testing.T) {
	f := newFakeRegistry(t)
	want := strings.Repeat("a", 5000)
	d := sha(want)
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("b", 5000)) // same length, other bytes
	})
	br, err := f.client(Options{}).OpenBlob(context.Background(), f.repo(blobRepo), d, 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	if _, err := io.ReadAll(br); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("read: err = %v, want ErrDigestMismatch", err)
	}
	// The failure is sticky: no later call turns it into a success.
	if err := br.Finish(); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Finish: err = %v", err)
	}
	if _, err := br.Read(make([]byte, 8)); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Read again: err = %v", err)
	}
}

func TestOpenBlob_LengthMustMatchTheManifest(t *testing.T) {
	f := newFakeRegistry(t)
	content := strings.Repeat("a", 5000)
	d := serveBlob(f, content)
	c := f.client(Options{})
	// Shorter than the body: the body is cut off and refused, never read whole.
	br, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, 4000)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, br)
	br.Close()
	if !errors.Is(err, ErrBadResponse) || n > 4001 {
		t.Errorf("long body: read %d bytes, err %v", n, err)
	}
	// Longer than the body.
	br, err = c.OpenBlob(context.Background(), f.repo(blobRepo), d, 6000)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, br)
	br.Close()
	if !errors.Is(err, ErrBadResponse) {
		t.Errorf("short body: err = %v", err)
	}
}

func TestOpenBlob_NoPerRequestTimeoutAndCallerDeadline(t *testing.T) {
	f := newFakeRegistry(t)
	f.noAuth = true
	content := "first half|second half"
	d := sha(content)
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, content[:11])
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
		fmt.Fprint(w, content[11:])
	})
	// Ordinary requests give up after 100 ms; the body of a blob does not.
	c := f.client(Options{Timeout: 100 * time.Millisecond})
	br, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(br)
	br.Close()
	if err != nil || string(got) != content {
		t.Fatalf("slow body: %q, %v", got, err)
	}
	// The caller's deadline does end it.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	br, err = c.OpenBlob(ctx, f.repo(blobRepo), d, int64(len(content)))
	if err == nil {
		_, err = io.ReadAll(br)
		br.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the caller's deadline", err)
	}
}

func TestOpenBlob_ErrorsAndInput(t *testing.T) {
	f := newFakeRegistry(t)
	c := f.client(Options{})
	if _, err := c.OpenBlob(context.Background(), f.repo(blobRepo), sha("missing"), 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	for _, d := range []string{"latest", "sha256:../x", "sha256:" + strings.Repeat("A", 64)} {
		if _, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, 1); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("digest %q: %v", d, err)
		}
	}
	if _, err := c.OpenBlob(context.Background(), f.repo(blobRepo), sha("x"), -1); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("negative size: %v", err)
	}
	f.tokenStatus = http.StatusInternalServerError
	if _, err := c.OpenBlob(context.Background(), f.repo(blobRepo), sha("x"), 1); err == nil {
		t.Error("a token failure was ignored")
	}
}

func TestOpenBlob_CostsRequestsFromTheBudget(t *testing.T) {
	f := newFakeRegistry(t)
	content := "abc"
	d := serveBlob(f, content)
	b := NewBudget(2) // the blob, then the token, then the blob again would be 3
	c := f.client(Options{Budget: b})
	if _, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, 3); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("err = %v, want ErrBudgetExhausted", err)
	}
	b = NewBudget(3)
	br, err := f.client(Options{Budget: b}).OpenBlob(context.Background(), f.repo(blobRepo), d, 3)
	if err != nil {
		t.Fatal(err)
	}
	br.Close()
	if b.Used() != 3 {
		t.Errorf("used %d requests, want 3", b.Used())
	}
}

func TestOpenBlob_RedirectDropsAuthorizationAndAsksForIdentity(t *testing.T) {
	content := "layer served by a CDN"
	var mu sync.Mutex
	var cdnAuth, cdnEnc, regEnc, regAuth string
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cdnAuth, cdnEnc = r.Header.Get("Authorization"), r.Header.Get("Accept-Encoding")
		mu.Unlock()
		fmt.Fprint(w, content)
	}))
	defer cdn.Close()
	f := newFakeRegistry(t)
	d := sha(content)
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		regEnc = r.Header.Get("Accept-Encoding")
		if a := r.Header.Get("Authorization"); a != "" {
			regAuth = a
		}
		mu.Unlock()
		http.Redirect(w, r, cdn.URL+"/store/blob", http.StatusTemporaryRedirect)
	})
	f.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(cdn.Certificate())
	c := f.client(Options{AllowAddr: func(ip net.IP, _ string) bool { return ip.IsLoopback() }})
	br, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	got, err := io.ReadAll(br)
	if err != nil || string(got) != content {
		t.Fatalf("%q %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if regAuth == "" {
		t.Error("the source never received an Authorization header, so the test proves nothing")
	}
	if cdnAuth != "" {
		t.Errorf("Authorization %q reached the redirect target", cdnAuth)
	}
	if regEnc != "identity" || cdnEnc != "identity" {
		t.Errorf("Accept-Encoding %q / %q, want identity", regEnc, cdnEnc)
	}
}

func TestOpenBlob_RedirectToHTTPRefused(t *testing.T) {
	f := newFakeRegistry(t)
	d := sha("x")
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/plain", http.StatusFound)
	})
	if _, err := f.client(Options{}).OpenBlob(context.Background(), f.repo(blobRepo), d, 1); !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v, want ErrBadResponse", err)
	}
}

func TestOpenBlob_RedirectToInternalAddressRefused(t *testing.T) {
	target := newFakeRegistry(t)
	target.noAuth = true
	f := newFakeRegistry(t)
	d := sha("x")
	target.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "x") })
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+"/v2/"+blobRepo+"/blobs/"+d, http.StatusFound)
	})
	// Only the registry itself is allowed to be on loopback.
	_, err := f.client(Options{}).OpenBlob(context.Background(), f.repo(blobRepo), d, 1)
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("err = %v, want ErrForbiddenAddress", err)
	}
	if len(target.hits()) != 0 {
		t.Error("the redirect target must not be contacted")
	}
}

func TestOpenBlob_PublicAddressPolicyApplies(t *testing.T) {
	f := newFakeRegistry(t)
	d := serveBlob(f, "x")
	c := New(Options{HTTPClient: f.srv.Client()}) // no test allowance for loopback
	if _, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, 1); !errors.Is(err, ErrForbiddenAddress) {
		t.Errorf("err = %v, want ErrForbiddenAddress", err)
	}
}

// The login of a registry goes to its token service only when that is on the
// same host or named by the login; a blob request carries the token, not the
// login.
func TestOpenBlob_CredentialsKeepTheirRestrictions(t *testing.T) {
	content := "private layer"
	d := sha(content)
	var tokenSvc *recorder
	tokenSvc = newRecorder(t, func(w http.ResponseWriter, r *http.Request) { tokenOK(w, r) })
	reg := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token",service="reg"`, tokenSvc.host()))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, content)
	})
	// The token service is another host that the login does not name.
	c := authClient(reg, store(t, reg.host()), Options{})
	br, err := c.OpenBlob(context.Background(), reg.host()+"/"+blobRepo, d, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(br)
	br.Close()
	if err != nil || string(got) != content {
		t.Fatalf("%q %v", got, err)
	}
	if tr := tokenSvc.requests("/token"); len(tr) != 1 || tr[0].authz != "" {
		t.Errorf("token requests %+v, want one without the login", tr)
	}
	for _, s := range reg.requests("/v2/" + blobRepo + "/blobs/" + d) {
		if s.authz == authBasic {
			t.Errorf("the login itself was sent to the blob endpoint: %+v", s)
		}
	}
}

func TestOpenBlob_LoginNeverSurvivesAnErrorMessage(t *testing.T) {
	d := sha("x")
	reg := newRecorder(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	c := authClient(reg, store(t, reg.host()), Options{})
	_, err := c.OpenBlob(context.Background(), reg.host()+"/"+blobRepo, d, 1)
	if !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), authPass) {
		t.Errorf("the password is in the error: %v", err)
	}
}

func TestResolveAndImageLayers_ListTheManifestLayers(t *testing.T) {
	f := newFakeRegistry(t)
	cfg := `{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":["sha256:` + strings.Repeat("1", 64) + `","sha256:` + strings.Repeat("2", 64) + `"]}}`
	cd := sha(cfg)
	f.route("/v2/team/app/blobs/"+cd, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, cfg) })
	l1, l2 := sha("l1"), sha("l2")
	m := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"digest":%q,"size":%d},"layers":[`+
		`{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":11},`+
		`{"mediaType":"application/vnd.docker.image.rootfs.foreign.diff.tar.gzip","digest":%q,"size":22,"urls":["https://x.invalid/l2"]}]}`,
		mediaOCIManifest, cd, len(cfg), l1, l2)
	md := sha(m)
	f.serveManifest("team/app", mediaOCIManifest, m, md)
	ibody := fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[`+
		`{"digest":%q,"platform":{"os":"linux","architecture":"arm64"}},`+
		`{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}}]}`, mediaOCIIndex, sha("arm"), md)
	f.serveManifest("team/app", mediaOCIIndex, ibody, sha(ibody))

	got, err := f.client(Options{}).ImageLayers(context.Background(), f.repo("team/app"), sha(ibody), linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if got.ManifestDigest != md || got.ConfigDigest != cd || len(got.DiffIDs) != 2 || len(got.Layers) != 2 {
		t.Fatalf("%+v", got)
	}
	if got.Layers[0] != (Layer{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: l1, Size: 11}) {
		t.Errorf("layer 0 %+v", got.Layers[0])
	}
	if !got.Layers[1].HasURLs || got.Layers[1].Size != 22 {
		t.Errorf("layer 1 %+v", got.Layers[1])
	}
	// A tag is not a pin.
	if _, err := f.client(Options{}).ImageLayers(context.Background(), f.repo("team/app"), "latest", linuxAMD64); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("tag: %v", err)
	}
}

const signedSecret = "SIGNATURE-SECRET-123"

func TestOpenBlob_TwoHopRedirectKeepsSignatureOutOfHeaders(t *testing.T) {
	content := "layer behind two redirects"
	var mu sync.Mutex
	var hop2Referer, hop2Auth string
	hop2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hop2Referer, hop2Auth = r.Header.Get("Referer"), r.Header.Get("Authorization")
		mu.Unlock()
		fmt.Fprint(w, content)
	}))
	defer hop2.Close()
	hop1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop2.URL+"/final", http.StatusFound)
	}))
	defer hop1.Close()
	f := newFakeRegistry(t)
	d := sha(content)
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop1.URL+"/store?sig="+signedSecret, http.StatusTemporaryRedirect)
	})
	roots := f.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	roots.AddCert(hop1.Certificate())
	roots.AddCert(hop2.Certificate())
	c := f.client(Options{AllowAddr: func(ip net.IP, _ string) bool { return ip.IsLoopback() }})
	br, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	if got, err := io.ReadAll(br); err != nil || string(got) != content {
		t.Fatalf("%q %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(hop2Referer, signedSecret) || hop2Referer != "" {
		t.Errorf("Referer %q reached the second hop", hop2Referer)
	}
	if hop2Auth != "" {
		t.Errorf("Authorization %q reached the second hop", hop2Auth)
	}
}

func TestOpenBlob_ConnectionFailureAfterRedirectHidesSignature(t *testing.T) {
	dead := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // nothing listens there any more
	f := newFakeRegistry(t)
	d := sha("x")
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, deadURL+"/store?sig="+signedSecret, http.StatusTemporaryRedirect)
	})
	c := f.client(Options{AllowAddr: func(ip net.IP, _ string) bool { return ip.IsLoopback() }})
	_, err := c.OpenBlob(context.Background(), f.repo(blobRepo), d, 1)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), signedSecret) || strings.Contains(err.Error(), "sig=") {
		t.Errorf("the error shows the signed query: %v", err)
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Errorf("the cause is lost: %T %v", err, err)
	}
}

func TestRedactURLError(t *testing.T) {
	in := &url.Error{Op: "Get", URL: "https://user:pw@h.example/p?sig=" + signedSecret + "#f", Err: io.ErrUnexpectedEOF}
	out := redactURLError(fmt.Errorf("wrapped: %w", in))
	if strings.Contains(out.Error(), signedSecret) || strings.Contains(out.Error(), "pw") {
		t.Errorf("not redacted: %v", out)
	}
	if !errors.Is(out, io.ErrUnexpectedEOF) {
		t.Error("the cause is lost")
	}
}

// The standard library puts the whole Location into its error when it cannot
// parse it; a signed one must not reach the error text.
func TestOpenBlob_UnparsableSignedLocationIsHidden(t *testing.T) {
	f := newFakeRegistry(t)
	d := sha("x")
	f.route("/v2/"+blobRepo+"/blobs/"+d, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://cdn.example/store%zz?sig="+signedSecret)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	_, err := f.client(Options{}).OpenBlob(context.Background(), f.repo(blobRepo), d, 1)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), signedSecret) || strings.Contains(err.Error(), "sig=") {
		t.Errorf("the error shows the signed Location: %v", err)
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Errorf("the cause is lost: %T", err)
	}
	// The cause stays reachable through Unwrap: a deeper error still holds the
	// original text, which the shown message does not.
	found := false
	for e := errors.Unwrap(ue.Err); e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), signedSecret) {
			found = true
		}
	}
	if !found {
		t.Error("the original cause is not reachable through Unwrap")
	}
}

var errDistinct = errors.New("distinct cause")

func TestRedactURLErrorKeepsADistinctCause(t *testing.T) {
	cause := fmt.Errorf("%w: fetching https://h.example/p?sig=%s failed", errDistinct, signedSecret)
	out := redactURLError(&url.Error{Op: "Get", URL: "https://h.example/p?sig=" + signedSecret, Err: cause})
	if strings.Contains(out.Error(), signedSecret) {
		t.Errorf("the message holds the secret: %v", out)
	}
	if !errors.Is(out, errDistinct) {
		t.Error("errors.Is does not reach the cause")
	}
}
