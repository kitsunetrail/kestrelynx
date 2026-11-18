package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testArtifactType = "application/vnd.example.db.config.v1+json"
	testLayerType    = "application/vnd.example.db.layer.v1.tar+gzip"
	testArtifactRepo = "team/db"
)

var testSpec = ArtifactSpec{ArtifactType: testArtifactType, LayerMediaType: testLayerType, MaxLayerBytes: 1024}

// artifactManifestJSON is modelled on a manifest a registry served for an
// oras-style artifact: an empty config with inline data, one titled layer and
// a creation annotation.
func artifactManifestJSON(artifactType string, layers ...string) string {
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","artifactType":%q,"config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2,"data":"e30="},"layers":[%s],"annotations":{"org.opencontainers.image.created":"2026-11-17T19:14:40Z"}}`,
		artifactType, strings.Join(layers, ","))
}

func layerJSON(mediaType, digest string, size int, extra string) string {
	return fmt.Sprintf(`{"mediaType":%q,"digest":%q,"size":%d,%s"annotations":{"org.opencontainers.image.title":"db.tar.gz"}}`, mediaType, digest, size, extra)
}

// serveArtifact registers a manifest at tag "latest" and a layer blob.
func serveArtifact(f *fakeRegistry, manifest, layer string) {
	f.serveManifest(testArtifactRepo, mediaOCIManifest, manifest, "latest")
	f.route("/v2/"+testArtifactRepo+"/blobs/"+sha(layer), func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, layer)
	})
}

func TestArtifact_HappyPathWithTokenFlow(t *testing.T) {
	layer := `{"version":1,"entries":["a","b"]}`
	manifest := artifactManifestJSON(testArtifactType, layerJSON(testLayerType, sha(layer), len(layer), ""))
	f := newFakeRegistry(t)
	serveArtifact(f, manifest, layer)
	c := f.client(Options{})
	ctx := context.Background()

	m, err := c.ArtifactManifest(ctx, f.repo(testArtifactRepo), "latest", testSpec)
	if err != nil {
		t.Fatal(err)
	}
	if m.Digest != sha(manifest) || m.LayerDigest != sha(layer) || m.LayerSize != int64(len(layer)) {
		t.Fatalf("manifest = %+v", m)
	}
	got, err := c.ArtifactLayer(ctx, f.repo(testArtifactRepo), m, testSpec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != layer {
		t.Errorf("layer = %q", got)
	}
	// One anonymous token served both calls: 401, token, retry, then the blob.
	if f.tokenHits != 1 {
		t.Errorf("token endpoint hit %d times, want 1", f.tokenHits)
	}
	if q := f.tokenQuery[0]; !strings.Contains(q, "scope=repository%3Ateam%2Fdb%3Apull") {
		t.Errorf("token query = %q", q)
	}
}

func TestArtifact_SendsOCIManifestAccept(t *testing.T) {
	layer := "x"
	f := newFakeRegistry(t)
	f.noAuth = true
	manifest := artifactManifestJSON(testArtifactType, layerJSON(testLayerType, sha(layer), 1, ""))
	f.route("/v2/"+testArtifactRepo+"/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Accept"); a != mediaOCIManifest {
			t.Errorf("Accept = %q", a)
		}
		w.Header().Set("Content-Type", mediaOCIManifest)
		fmt.Fprint(w, manifest)
	})
	if _, err := f.client(Options{}).ArtifactManifest(context.Background(), f.repo(testArtifactRepo), "latest", testSpec); err != nil {
		t.Fatal(err)
	}
}

func TestArtifact_ManifestRefusals(t *testing.T) {
	layer := "payload"
	good := layerJSON(testLayerType, sha(layer), len(layer), "")
	tests := []struct {
		name        string
		contentType string
		body        string
		header      string // Docker-Content-Digest override, "" for the true one
		spec        ArtifactSpec
		tag         string
		want        error
	}{
		{name: "wrong schemaVersion", body: strings.Replace(artifactManifestJSON(testArtifactType, good), `"schemaVersion":2`, `"schemaVersion":1`, 1), want: ErrUnsupported},
		{name: "OCI index", contentType: mediaOCIIndex, body: `{"schemaVersion":2,"mediaType":"` + mediaOCIIndex + `","manifests":[]}`, want: ErrUnsupported},
		{name: "docker manifest", contentType: mediaDockerV2, body: artifactManifestJSON(testArtifactType, good), want: ErrUnsupported},
		{name: "wrong artifactType", body: artifactManifestJSON("application/vnd.other+json", good), want: ErrUnsupported},
		{name: "wrong layer media type", body: artifactManifestJSON(testArtifactType, layerJSON("application/vnd.other", sha(layer), len(layer), "")), want: ErrUnsupported},
		{name: "zero layers", body: artifactManifestJSON(testArtifactType), want: ErrUnsupported},
		{name: "two layers", body: artifactManifestJSON(testArtifactType, good, good), want: ErrUnsupported},
		{name: "layer size zero", body: artifactManifestJSON(testArtifactType, layerJSON(testLayerType, sha(layer), 0, "")), want: ErrBadResponse},
		{name: "layer size over the cap", body: artifactManifestJSON(testArtifactType, layerJSON(testLayerType, sha(layer), 1025, "")), want: ErrTooLarge},
		{name: "malformed layer digest", body: artifactManifestJSON(testArtifactType, layerJSON(testLayerType, "sha256:e187", len(layer), "")), want: ErrBadResponse},
		{name: "uppercase layer digest", body: artifactManifestJSON(testArtifactType, layerJSON(testLayerType, strings.ToUpper(sha(layer)), len(layer), "")), want: ErrBadResponse},
		{name: "not JSON", body: `<html>`, want: ErrBadResponse},
		{name: "body media type contradicts the header", body: strings.Replace(artifactManifestJSON(testArtifactType, good), "image.manifest.v1", "image.index.v1", 1), want: ErrBadResponse},
		{name: "body media type contradicts via fallback", contentType: "application/json", body: strings.Replace(artifactManifestJSON(testArtifactType, good), "image.manifest.v1", "image.index.v1", 1), want: ErrUnsupported},
		{name: "Docker-Content-Digest mismatch", body: artifactManifestJSON(testArtifactType, good), header: sha("something else"), want: ErrDigestMismatch},
		{name: "manifest over the cap", body: artifactManifestJSON(testArtifactType, good), spec: ArtifactSpec{MaxManifestBytes: 100}, want: ErrTooLarge},
		{name: "invalid tag", tag: "bad/tag", body: artifactManifestJSON(testArtifactType, good), want: ErrInvalidInput},
		{name: "digest as tag", tag: sha(layer), body: artifactManifestJSON(testArtifactType, good), want: ErrInvalidInput},
		{name: "layer cap missing", spec: ArtifactSpec{ArtifactType: testArtifactType, LayerMediaType: testLayerType}, body: artifactManifestJSON(testArtifactType, good), want: ErrInvalidInput},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			f.noAuth = true
			f.route("/v2/"+testArtifactRepo+"/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
				ct := tc.contentType
				if ct == "" {
					ct = mediaOCIManifest
				}
				w.Header().Set("Content-Type", ct)
				h := tc.header
				if h == "" {
					h = sha(tc.body)
				}
				w.Header().Set("Docker-Content-Digest", h)
				fmt.Fprint(w, tc.body)
			})
			spec := testSpec
			if tc.spec.MaxManifestBytes != 0 {
				spec.MaxManifestBytes = tc.spec.MaxManifestBytes
			}
			if tc.spec.ArtifactType != "" {
				spec = tc.spec
			}
			tag := tc.tag
			if tag == "" {
				tag = "latest"
			}
			_, err := f.client(Options{}).ArtifactManifest(context.Background(), f.repo(testArtifactRepo), tag, spec)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestArtifact_ManifestNotFound(t *testing.T) {
	f := newFakeRegistry(t)
	f.noAuth = true
	_, err := f.client(Options{}).ArtifactManifest(context.Background(), f.repo(testArtifactRepo), "latest", testSpec)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestArtifact_ManifestDefaultCapIs64KiB(t *testing.T) {
	f := newFakeRegistry(t)
	f.noAuth = true
	pad := strings.Repeat("x", 70<<10)
	body := fmt.Sprintf(`{"schemaVersion":2,"pad":%q}`, pad)
	f.serveManifest(testArtifactRepo, mediaOCIManifest, body, "latest")
	_, err := f.client(Options{}).ArtifactManifest(context.Background(), f.repo(testArtifactRepo), "latest", testSpec)
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestArtifactLayer_Refusals(t *testing.T) {
	layer := strings.Repeat("a", 100)
	tests := []struct {
		name  string
		serve func(w http.ResponseWriter)
		m     ArtifactManifest
		spec  ArtifactSpec
		want  error
	}{
		{name: "shorter than size", serve: func(w http.ResponseWriter) { fmt.Fprint(w, layer[:50]) },
			m: ArtifactManifest{LayerDigest: sha(layer), LayerSize: 100}, want: ErrBadResponse},
		{name: "longer than size, chunked", serve: func(w http.ResponseWriter) {
			w.Header().Set("Transfer-Encoding", "chunked")
			fmt.Fprint(w, layer+strings.Repeat("b", 5000))
		}, m: ArtifactManifest{LayerDigest: sha(layer), LayerSize: 100}, want: ErrTooLarge},
		{name: "longer than size, declared", serve: func(w http.ResponseWriter) { fmt.Fprint(w, layer+"b") },
			m: ArtifactManifest{LayerDigest: sha(layer), LayerSize: 100}, want: ErrTooLarge},
		{name: "size above the spec cap", serve: func(w http.ResponseWriter) { fmt.Fprint(w, layer) },
			m: ArtifactManifest{LayerDigest: sha(layer), LayerSize: 100}, spec: ArtifactSpec{MaxLayerBytes: 50}, want: ErrTooLarge},
		{name: "hash mismatch", serve: func(w http.ResponseWriter) { fmt.Fprint(w, strings.Repeat("c", 100)) },
			m: ArtifactManifest{LayerDigest: sha(layer), LayerSize: 100}, want: ErrDigestMismatch},
		{name: "malformed digest", serve: func(w http.ResponseWriter) { fmt.Fprint(w, layer) },
			m: ArtifactManifest{LayerDigest: "sha256:../x", LayerSize: 100}, want: ErrInvalidInput},
		{name: "cap missing", serve: func(w http.ResponseWriter) { fmt.Fprint(w, layer) },
			m: ArtifactManifest{LayerDigest: sha(layer), LayerSize: 100}, spec: ArtifactSpec{MaxLayerBytes: -1}, want: ErrInvalidInput},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			f.noAuth = true
			f.route("/v2/"+testArtifactRepo+"/blobs/"+sha(layer), func(w http.ResponseWriter, r *http.Request) { tc.serve(w) })
			spec := testSpec
			if tc.spec.MaxLayerBytes != 0 {
				spec = tc.spec
			}
			_, err := f.client(Options{}).ArtifactLayer(context.Background(), f.repo(testArtifactRepo), tc.m, spec)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if tc.want == ErrInvalidInput && len(f.hits()) != 0 {
				t.Errorf("requests sent for invalid input: %v", f.hits())
			}
		})
	}
}

func TestArtifactLayer_NotFound(t *testing.T) {
	f := newFakeRegistry(t)
	f.noAuth = true
	m := ArtifactManifest{LayerDigest: sha("x"), LayerSize: 1}
	_, err := f.client(Options{}).ArtifactLayer(context.Background(), f.repo(testArtifactRepo), m, testSpec)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestArtifactLayer_RedirectDropsAuthorization(t *testing.T) {
	layer := "layer bytes served by a CDN"
	var cdnAuth string
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, layer)
	}))
	defer cdn.Close()
	f := newFakeRegistry(t)
	f.route("/v2/"+testArtifactRepo+"/blobs/"+sha(layer), func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cdn.URL+"/store/blob", http.StatusTemporaryRedirect)
	})
	f.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(cdn.Certificate())
	c := f.client(Options{AllowAddr: func(ip net.IP, port string) bool { return ip.IsLoopback() }})
	// The registry's own request carries the token; the redirect target must not.
	m := ArtifactManifest{LayerDigest: sha(layer), LayerSize: int64(len(layer))}
	got, err := c.ArtifactLayer(context.Background(), f.repo(testArtifactRepo), m, testSpec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != layer {
		t.Errorf("layer = %q", got)
	}
	if cdnAuth != "" {
		t.Errorf("Authorization %q reached the redirect target", cdnAuth)
	}
	if f.tokenHits != 1 {
		t.Errorf("token endpoint hit %d times, want 1", f.tokenHits)
	}
}

// URLs a layer lists for fetching it elsewhere are not used: the layer comes
// from the repository, by its digest.
func TestArtifact_LayerURLsAreNotFollowed(t *testing.T) {
	layer := `{"version":1}`
	manifest := artifactManifestJSON(testArtifactType, layerJSON(testLayerType, sha(layer), len(layer), `"urls":["https://elsewhere.invalid/blob"],`))
	f := newFakeRegistry(t)
	serveArtifact(f, manifest, layer)
	c := f.client(Options{})
	m, err := c.ArtifactManifest(context.Background(), f.repo(testArtifactRepo), "latest", testSpec)
	if err != nil {
		t.Fatalf("a manifest whose layer lists URLs is refused: %v", err)
	}
	got, err := c.ArtifactLayer(context.Background(), f.repo(testArtifactRepo), m, testSpec)
	if err != nil || string(got) != layer {
		t.Fatalf("layer = %q, %v", got, err)
	}
}
