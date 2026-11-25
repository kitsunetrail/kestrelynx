package imagefs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

var amd64 = inventory.Platform{OS: "linux", Architecture: "amd64"}

const (
	mediaManifest = "application/vnd.oci.image.manifest.v1+json"
	mediaIndex    = "application/vnd.oci.image.index.v1+json"
	mediaLayerGz  = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// imageFixture is an image made of layers, with its config and manifest.
type imageFixture struct {
	raw            [][]byte // layer tars
	blobs          [][]byte // what the registry serves per layer
	blobTypes      []string
	diffIDs        []string
	config         []byte
	configDigest   string
	manifest       []byte
	manifestDigest string
}

func buildImage(t *testing.T, p inventory.Platform, layers ...[]fe) *imageFixture {
	t.Helper()
	f := &imageFixture{}
	for _, l := range layers {
		raw := tarOf(t, l...)
		f.raw = append(f.raw, raw)
		f.blobs = append(f.blobs, gzipOf(raw))
		f.blobTypes = append(f.blobTypes, mediaLayerGz)
		f.diffIDs = append(f.diffIDs, digestOf(raw))
	}
	f.finish(t, p)
	return f
}

// finish (re)builds the config and the manifest from the other fields.
func (f *imageFixture) finish(t *testing.T, p inventory.Platform) {
	t.Helper()
	cfg, _ := json.Marshal(map[string]any{
		"os": p.OS, "architecture": p.Architecture,
		"rootfs": map[string]any{"type": "layers", "diff_ids": f.diffIDs},
	})
	f.config, f.configDigest = cfg, digestOf(cfg)
	var layers []map[string]any
	for i, b := range f.blobs {
		layers = append(layers, map[string]any{"mediaType": f.blobTypes[i], "digest": digestOf(b), "size": len(b)})
	}
	m, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": f.configDigest, "size": len(cfg)},
		"layers": layers,
	})
	f.manifest, f.manifestDigest = m, digestOf(m)
}

// fakeRegistry serves images without authentication.
type fakeRegistry struct {
	srv *httptest.Server

	mu       sync.Mutex
	routes   map[string]http.HandlerFunc
	blobHits map[string]int
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{routes: map[string]http.HandlerFunc{}, blobHits: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		h := f.routes[r.URL.Path]
		if i := strings.Index(r.URL.Path, "/blobs/"); i >= 0 {
			f.blobHits[r.URL.Path[i+len("/blobs/"):]]++
		}
		f.mu.Unlock()
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) host() string { return f.srv.Listener.Addr().String() }
func (f *fakeRegistry) repo() string { return f.host() + "/team/app" }

func (f *fakeRegistry) route(path string, h http.HandlerFunc) {
	f.mu.Lock()
	f.routes["/v2/team/app/"+path] = h
	f.mu.Unlock()
}

func (f *fakeRegistry) hits(digest string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blobHits[digest]
}

func (f *fakeRegistry) totalBlobHits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.blobHits {
		n += v
	}
	return n
}

func body(media string, b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", media)
		w.Header().Set("Docker-Content-Digest", digestOf(b))
		w.Write(b)
	}
}

// add serves the image's blobs and config, and its manifest behind an index
// that also lists an arm64 entry that is never served. It returns the index
// digest.
func (f *fakeRegistry) add(img *imageFixture) string {
	for i, b := range img.blobs {
		f.route("blobs/"+digestOf(b), body("application/octet-stream", img.blobs[i]))
	}
	f.route("blobs/"+img.configDigest, body("application/vnd.oci.image.config.v1+json", img.config))
	f.route("manifests/"+img.manifestDigest, body(mediaManifest, img.manifest))
	idx, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": mediaIndex,
		"manifests": []map[string]any{
			{"mediaType": mediaManifest, "digest": digestOf([]byte("arm")), "size": 3, "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			{"mediaType": mediaManifest, "digest": img.manifestDigest, "size": len(img.manifest), "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	})
	f.route("manifests/"+digestOf(idx), body(mediaIndex, idx))
	return digestOf(idx)
}

func (f *fakeRegistry) client() *registry.Client {
	return registry.New(registry.Options{
		HTTPClient: f.srv.Client(),
		AllowAddr:  func(ip net.IP, _ string) bool { return ip.IsLoopback() },
	})
}

type env struct {
	reg    *fakeRegistry
	cache  *Cache
	limits Limits
	reader *Reader
}

func newEnv(t *testing.T, l Limits) *env {
	t.Helper()
	e := &env{reg: newFakeRegistry(t), cache: newCache(t), limits: l}
	e.reader = e.newReader(NewBudget(l))
	return e
}

func (e *env) newReader(b *Budget) *Reader {
	return &Reader{Registry: e.reg.client(), Cache: e.cache, Budget: b, Limits: e.limits, Version: "test-1"}
}

func (e *env) target(img *imageFixture, manifest string) Target {
	return RegistryTarget(e.reg.repo(), manifest, amd64, img.diffIDs)
}

func baseLayer() []fe { return []fe{file("etc/os-release", "ID=debian")} }

func temurinLayer() []fe {
	return append(jdkFiles("opt/java/openjdk", releaseTemurin21),
		sym("usr/bin/java", "/opt/java/openjdk/bin/java"))
}

func wantComplete(t *testing.T, out Outcome) {
	t.Helper()
	if out.Kind != Complete {
		t.Fatalf("outcome %v reason %q detail %q", out.Kind, out.Reason, out.Detail)
	}
	if len(out.JDKs) != 1 || out.JDKs[0].Dir != "opt/java/openjdk" || out.JDKs[0].Release != releaseTemurin21 {
		t.Fatalf("JDKs %+v", out.JDKs)
	}
}

func TestRegistryReadFindsTheJDKAndCaches(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)

	// Pinned by the digest of an index: the child of the platform is chosen.
	out := e.reader.Read(context.Background(), e.target(img, idx))
	wantComplete(t, out)
	if out.ConfigDigest != img.configDigest || out.Stats.LayersRead != 2 || out.Stats.RegistryBytes != int64(len(img.blobs[0])+len(img.blobs[1])) {
		t.Errorf("stats %+v config %s", out.Stats, out.ConfigDigest)
	}
	if got := e.reg.totalBlobHits(); got != 3 { // two layers and the config
		t.Errorf("blob requests %d, want 3", got)
	}
	// The JDK's layer is the second one.
	if out.JDKs[0].LayerDiffID != img.diffIDs[1] {
		t.Errorf("layer %q", out.JDKs[0].LayerDiffID)
	}

	// A second cycle does not read the layers again.
	before := e.reg.hits(digestOf(img.blobs[1]))
	out = e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(img, img.manifestDigest))
	wantComplete(t, out)
	if !out.Stats.ImageCached || e.reg.hits(digestOf(img.blobs[1])) != before {
		t.Errorf("second read: %+v", out.Stats)
	}

	// Without the image result, the verified layer summaries are enough.
	for _, d := range cacheDirsFiles(t, e.cache, "images") {
		removeFile(t, d)
	}
	out = e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(img, img.manifestDigest))
	wantComplete(t, out)
	if out.Stats.LayersCached != 2 || out.Stats.LayersRead != 0 || e.reg.hits(digestOf(img.blobs[1])) != before {
		t.Errorf("third read: %+v", out.Stats)
	}
}

func TestRegistryReadNoJDK(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), []fe{file("app/run.sh", "#!/bin/sh")})
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Complete || len(out.JDKs) != 0 {
		t.Errorf("%+v", out)
	}
}

func TestRegistryDiffIDsMustMatchTheScan(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	tg := e.target(img, idx)
	tg.DiffIDs = []string{img.diffIDs[0]}
	out := e.reader.Read(context.Background(), tg)
	if out.Kind != Permanent || out.Reason != ReasonDiffIDsDiffer || out.Recorded {
		t.Errorf("%+v", out)
	}
	if e.reg.totalBlobHits() > 1 { // only the config
		t.Error("layers were fetched for an image that is not the scanned one")
	}
}

// corruptBlob serves other bytes than the digest names, same length.
func corruptBlob(e *env, img *imageFixture, i int) {
	bad := append([]byte(nil), img.blobs[i]...)
	bad[len(bad)/2] ^= 0xff
	e.reg.route("blobs/"+digestOf(img.blobs[i]), body("application/octet-stream", bad))
}

func goodBlob(e *env, img *imageFixture, i int) {
	e.reg.route("blobs/"+digestOf(img.blobs[i]), body("application/octet-stream", img.blobs[i]))
}

// A blob that arrives with another digest is the source's failure: it is
// deferred twice, and the third time in a row it is permanent and recorded.
func TestRegistryBlobDigestMismatchIsPermanentOnTheThirdStrike(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	corruptBlob(e, img, 1)
	read := func() Outcome {
		return e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(img, idx))
	}
	for i := 1; i <= 2; i++ {
		out := read()
		if out.Kind != Deferred || out.Reason != ReasonBlobMismatch || out.Recorded {
			t.Fatalf("strike %d: %+v", i, out)
		}
	}
	out := read()
	if out.Kind != Permanent || out.Reason != ReasonBlobMismatch || !out.Recorded {
		t.Fatalf("third strike: %+v", out)
	}
	// Nothing is verified from it: the blob is not mapped under any diffID.
	if _, ok := e.cache.GetBlob(digestOf(img.blobs[1])); ok {
		t.Error("a blob that failed its digest was mapped")
	}
	// The record stops the next cycle from fetching again ...
	hits := e.reg.totalBlobHits()
	out = read()
	if out.Kind != Permanent || !out.Recorded || e.reg.totalBlobHits() != hits {
		t.Errorf("fourth read %+v, blob requests %d -> %d", out, hits, e.reg.totalBlobHits())
	}
	// ... until the limits or the program change.
	r := e.newReader(NewBudget(e.limits))
	r.Version = "test-2"
	r.Read(context.Background(), e.target(img, idx))
	if e.reg.totalBlobHits() == hits {
		t.Error("a new program version used the old record")
	}
}

// One bad answer does not condemn the image: a good one afterwards completes
// it and the strikes start again.
func TestRegistryBadBlobThenGoodRecovers(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	read := func() Outcome {
		return e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(img, idx))
	}
	corruptBlob(e, img, 1)
	for i := 0; i < 2; i++ {
		if out := read(); out.Kind != Deferred || out.Reason != ReasonBlobMismatch {
			t.Fatalf("%+v", out)
		}
	}
	goodBlob(e, img, 1)
	wantComplete(t, read())
	if n := e.cache.Timeouts(e.target(img, idx).key()); n != 0 {
		t.Errorf("the strike count is %d after a Complete", n)
	}
	// A new failure starts from one again, so two more are still deferred.
	for _, d := range cacheDirsFiles(t, e.cache, "images") {
		removeFile(t, d)
	}
	for _, d := range cacheDirsFiles(t, e.cache, "blobs") {
		removeFile(t, d)
	}
	corruptBlob(e, img, 1)
	for i := 0; i < 2; i++ {
		if out := read(); out.Kind != Deferred || out.Recorded {
			t.Fatalf("after recovery: %+v", out)
		}
	}
}

// A blob that arrives intact but is not a readable layer says something about
// the image itself: it is permanent at once.
func TestRegistryCorruptContentWithAVerifiedDigestIsPermanent(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	img.blobs[1] = append([]byte{0x1f, 0x8b, 0x08, 0x00}, []byte("not a deflate stream at all, just bytes")...)
	img.finish(t, amd64)
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonCorruptLayer || !out.Recorded {
		t.Errorf("%+v", out)
	}
}

// gzipVariant is raw compressed as another blob: same content, other bytes.
func gzipVariant(raw []byte) []byte {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Name = "variant"
	zw.Write(raw)
	zw.Close()
	return buf.Bytes()
}

// The image result of a config is not handed to a manifest whose blobs are
// not known to hold the config's layers.
func TestRegistryWarmCacheDoesNotVouchForAnotherManifest(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	wantComplete(t, e.reader.Read(context.Background(), e.target(img, e.reg.add(img))))

	t.Run("other blobs with the same content are read once and verified", func(t *testing.T) {
		other := *img
		other.blobs = [][]byte{gzipVariant(img.raw[0]), gzipVariant(img.raw[1])}
		other.finish(t, amd64)
		if other.configDigest != img.configDigest || other.manifestDigest == img.manifestDigest {
			t.Fatal("the fixture must share the config and differ in the manifest")
		}
		idx := e.reg.add(&other)
		out := e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(&other, idx))
		wantComplete(t, out)
		if out.Stats.ImageCached || e.reg.hits(digestOf(other.blobs[1])) != 1 {
			t.Errorf("stats %+v, hits %d", out.Stats, e.reg.hits(digestOf(other.blobs[1])))
		}
		// Now they are verified and the cached result serves.
		out = e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(&other, idx))
		wantComplete(t, out)
		if !out.Stats.ImageCached {
			t.Errorf("stats %+v", out.Stats)
		}
	})
	t.Run("a blob of other content is refused", func(t *testing.T) {
		other := *img
		// The second layer is another tar than the config's diffID says.
		fake := gzipOf(tarOf(t, file("etc/os-release", "ID=alpine")))
		other.blobs = [][]byte{img.blobs[0], fake}
		other.finish(t, amd64)
		if other.configDigest != img.configDigest {
			t.Fatal("the fixture must share the config")
		}
		idx := e.reg.add(&other)
		out := e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(&other, idx))
		if out.Kind != Permanent || out.Reason != ReasonDiffIDMismatch || out.Stats.ImageCached {
			t.Errorf("%+v", out)
		}
	})
}

func TestRegistryBlobWithTheWrongDiffID(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	// The config claims another diffID for the second layer than the blob has.
	img.diffIDs[1] = digestOf([]byte("something else"))
	img.finish(t, amd64)
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonDiffIDMismatch || !out.Recorded {
		t.Errorf("%+v", out)
	}
	if _, ok := e.cache.GetLayer(img.diffIDs[1]); ok {
		t.Error("a summary was stored under the claimed diffID")
	}
}

// A blob that claims a diffID the cache knows is read and verified: the
// cached summary alone does not vouch for it.
func TestRegistryUnverifiedBlobClaimingAKnownDiffID(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	// The cache holds an empty summary under the diffID of the JDK layer, as a
	// stale or planted entry would, and no blob mapping.
	if err := e.cache.PutLayer(img.diffIDs[1], LayerSummary{Version: SummaryVersion}); err != nil {
		t.Fatal(err)
	}
	out := e.reader.Read(context.Background(), e.target(img, idx))
	wantComplete(t, out)
	if e.reg.hits(digestOf(img.blobs[1])) != 1 {
		t.Errorf("the claiming blob was fetched %d times, want 1", e.reg.hits(digestOf(img.blobs[1])))
	}
	if got, ok := e.cache.GetBlob(digestOf(img.blobs[1])); !ok || got != img.diffIDs[1] {
		t.Errorf("mapping %q %v", got, ok)
	}
}

func TestRegistryUnsupportedLayers(t *testing.T) {
	cases := map[string]struct {
		mutate func(f *imageFixture)
		reason Reason
	}{
		"zstd media type": {func(f *imageFixture) { f.blobTypes[1] = "application/vnd.oci.image.layer.v1.tar+zstd" }, ReasonUnsupportedCompression},
		"foreign layer": {func(f *imageFixture) {
			f.blobTypes[1] = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
		}, ReasonForeignLayer},
		"nondistributable": {func(f *imageFixture) {
			f.blobTypes[1] = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
		}, ReasonForeignLayer},
		"other media type": {func(f *imageFixture) { f.blobTypes[1] = "application/x-something" }, ReasonUnsupportedMediaType},
		"zstd content under a gzip media type": {func(f *imageFixture) {
			f.blobs[1] = append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 40)...)
		}, ReasonUnsupportedCompression},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, Limits{})
			img := buildImage(t, amd64, baseLayer(), temurinLayer())
			tc.mutate(img)
			img.finish(t, amd64)
			idx := e.reg.add(img)
			out := e.reader.Read(context.Background(), e.target(img, idx))
			if out.Kind != Permanent || out.Reason != tc.reason || !out.Recorded {
				t.Errorf("%+v", out)
			}
		})
	}
}

func TestRegistryForeignLayerWithURLs(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	external := 0
	ext := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		external++
		w.Write(img.blobs[1])
	}))
	defer ext.Close()
	// A manifest with a urls entry on the second layer, under its own digest.
	var m map[string]any
	json.Unmarshal(img.manifest, &m)
	m["layers"].([]any)[1].(map[string]any)["urls"] = []string{ext.URL + "/blob"}
	b, _ := json.Marshal(m)
	img.manifest, img.manifestDigest = b, digestOf(b)
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonForeignLayer || !out.Recorded {
		t.Fatalf("%+v", out)
	}
	for i, blob := range img.blobs {
		if n := e.reg.hits(digestOf(blob)); n != 0 {
			t.Errorf("layer %d was fetched %d times", i, n)
		}
	}
	if external != 0 {
		t.Errorf("the external URL was fetched %d times", external)
	}
}

func TestRegistryBudget(t *testing.T) {
	big := []fe{file("opt/pad", strings.Repeat("0123456789abcdef", 8192))}
	img := buildImage(t, amd64, baseLayer(), append(temurinLayer(), big...))
	small0, big1 := int64(len(img.blobs[0])), int64(len(img.blobs[1]))

	t.Run("deferred then resumed", func(t *testing.T) {
		// The budget covers the first layer and not the second.
		l := Limits{RegistryBytesPerCycle: big1 + small0 - 1}
		e := newEnv(t, l)
		idx := e.reg.add(img)
		out := e.reader.Read(context.Background(), e.target(img, idx))
		if out.Kind != Deferred || out.Reason != ReasonBudget {
			t.Fatalf("%+v", out)
		}
		if e.reg.hits(digestOf(img.blobs[1])) != 0 {
			t.Error("the layer that does not fit was fetched")
		}
		// The next cycle has a new budget and continues from the cached layer.
		out = e.newReader(NewBudget(l)).Read(context.Background(), e.target(img, idx))
		wantComplete(t, out)
		if out.Stats.LayersCached != 1 || out.Stats.LayersRead != 1 || e.reg.hits(digestOf(img.blobs[0])) != 1 {
			t.Errorf("%+v", out.Stats)
		}
	})
	t.Run("one blob over the whole budget is permanent", func(t *testing.T) {
		l := Limits{RegistryBytesPerCycle: big1 - 1}
		e := newEnv(t, l)
		idx := e.reg.add(img)
		out := e.reader.Read(context.Background(), e.target(img, idx))
		if out.Kind != Permanent || out.Reason != ReasonBlobOverBudget || !out.Recorded {
			t.Errorf("%+v", out)
		}
	})
}

func TestRegistryLayerSizeLimit(t *testing.T) {
	e := newEnv(t, Limits{MaxLayerBytes: 2048})
	img := buildImage(t, amd64, baseLayer(), append(temurinLayer(), file("opt/pad", strings.Repeat("x", 4096))))
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonLayerTooLarge || !out.Recorded {
		t.Errorf("%+v", out)
	}
}

func TestRegistrySummaryLimit(t *testing.T) {
	e := newEnv(t, Limits{MaxEntries: 3})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonSummaryLimit {
		t.Errorf("%+v", out)
	}
}

// stall holds a response until the request is cancelled.
func stall(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
}

func TestRegistryTimeoutResumesWhenLayersWereVerified(t *testing.T) {
	l := Limits{ImageTimeout: 400 * time.Millisecond}
	e := newEnv(t, l)
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	e.reg.route("blobs/"+digestOf(img.blobs[1]), stall)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Deferred || out.Reason != ReasonTimeout || out.Recorded {
		t.Fatalf("%+v", out)
	}
	// The first layer was verified and kept: the next cycle only needs the rest.
	e.reg.route("blobs/"+digestOf(img.blobs[1]), body("application/octet-stream", img.blobs[1]))
	out = e.newReader(NewBudget(l)).Read(context.Background(), e.target(img, idx))
	wantComplete(t, out)
	if out.Stats.LayersCached != 1 || out.Stats.LayersRead != 1 {
		t.Errorf("%+v", out.Stats)
	}
}

func TestRegistryTimeoutWithoutProgressIsPermanent(t *testing.T) {
	l := Limits{ImageTimeout: 300 * time.Millisecond}
	e := newEnv(t, l)
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	e.reg.route("blobs/"+digestOf(img.blobs[0]), stall)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonTimeoutNoProgress || !out.Recorded {
		t.Errorf("%+v", out)
	}
}

func TestRegistryCancelledByTheCaller(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	e.reg.route("blobs/"+digestOf(img.blobs[0]), stall)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	out := e.reader.Read(ctx, e.target(img, idx))
	if out.Kind != Deferred || out.Reason != ReasonCancelled {
		t.Errorf("%+v", out)
	}
}

func TestRegistryTransientFailureIsDeferred(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	e.reg.route("blobs/"+digestOf(img.blobs[1]), func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Deferred || out.Reason != ReasonTransient || out.Recorded {
		t.Errorf("%+v", out)
	}
}

func TestRegistryTruncatedBlobIsNotCachedAsVerified(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	e.reg.route("blobs/"+digestOf(img.blobs[1]), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(img.blobs[1])))
		w.Write(img.blobs[1][:len(img.blobs[1])/2])
		// The connection is cut by the handler returning with a short body.
	})
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind == Complete {
		t.Fatalf("a truncated blob completed: %+v", out)
	}
	if _, ok := e.cache.GetBlob(digestOf(img.blobs[1])); ok {
		t.Error("a truncated blob was mapped")
	}
}

func TestInvalidTargets(t *testing.T) {
	e := newEnv(t, Limits{})
	good := []string{digestOf([]byte("a"))}
	for name, tg := range map[string]Target{
		"unknown platform": RegistryTarget("r/x", digestOf([]byte("m")), inventory.Platform{}, good),
		"tag not digest":   RegistryTarget("r/x", "latest", amd64, good),
		"no diffIDs":       RegistryTarget("r/x", digestOf([]byte("m")), amd64, nil),
		"bad diffID":       RegistryTarget("r/x", digestOf([]byte("m")), amd64, []string{"sha256:zz"}),
		"bad docker id":    DockerTarget("nope", amd64, good),
		"no route":         {Platform: amd64, DiffIDs: good},
	} {
		out := e.reader.Read(context.Background(), tg)
		if out.Kind != Permanent || out.Reason != ReasonInvalidTarget || out.Recorded {
			t.Errorf("%s: %+v", name, out)
		}
	}
}

func TestReadPrunesTheCacheAfterWriting(t *testing.T) {
	e := newEnv(t, Limits{})
	e.cache.MaxFiles = 2
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	wantComplete(t, e.reader.Read(context.Background(), e.target(img, idx)))
	if n := countFiles(t, e.cache); n != 2 {
		t.Errorf("%d cache files, want 2", n)
	}
}

func TestRegistryJavaHomeIsResolvedInTheImage(t *testing.T) {
	e := newEnv(t, Limits{})
	layer := append(temurinLayer(), dir("opt/java"), sym("opt/java/current", "/opt/java/openjdk"))
	img := buildImage(t, amd64, baseLayer(), layer)
	idx := e.reg.add(img)
	tg := e.target(img, idx)
	tg.JavaHome = "/opt/java/current"
	out := e.reader.Read(context.Background(), tg)
	wantComplete(t, out)
	if out.JavaHome != "opt/java/openjdk" {
		t.Errorf("JavaHome %q, want the JDK's real directory", out.JavaHome)
	}
	// The result comes back with the cached image result.
	out = e.newReader(NewBudget(e.limits)).Read(context.Background(), tg)
	if !out.Stats.ImageCached || out.JavaHome != "opt/java/openjdk" {
		t.Errorf("cached: %+v home %q", out.Stats, out.JavaHome)
	}
	// Another JAVA_HOME is not answered from a result made for this one.
	other := tg
	other.JavaHome = "/opt/java/openjdk"
	out = e.newReader(NewBudget(e.limits)).Read(context.Background(), other)
	if out.JavaHome != "opt/java/openjdk" || out.Stats.ImageCached {
		t.Errorf("other: %+v home %q", out.Stats, out.JavaHome)
	}
	// A JAVA_HOME that names nothing resolves to nothing.
	other.JavaHome = "/nowhere"
	if out := e.newReader(NewBudget(e.limits)).Read(context.Background(), other); out.Kind != Complete || out.JavaHome != "" {
		t.Errorf("nowhere: %+v", out)
	}
}

func TestRegistryOverlayLimitIsPermanent(t *testing.T) {
	e := newEnv(t, Limits{})
	deep := strings.TrimSuffix(strings.Repeat("d/", 300), "/")
	img := buildImage(t, amd64, baseLayer(), []fe{file(deep+"/f", "x")})
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonOverlayLimit || !out.Recorded {
		t.Errorf("%+v", out)
	}
}

func TestRegistryTooManyJDKsIsPermanent(t *testing.T) {
	defer func(n int) { maxJDKs = n }(maxJDKs)
	maxJDKs = 2
	e := newEnv(t, Limits{})
	layer := append(jdkFiles("opt/a", releaseTemurin21), jdkFiles("opt/b", releaseTemurin21)...)
	layer = append(layer, jdkFiles("opt/c", releaseTemurin21)...)
	img := buildImage(t, amd64, baseLayer(), layer)
	idx := e.reg.add(img)
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonTooManyJDKs || !out.Recorded || len(out.JDKs) != 0 {
		t.Errorf("%+v", out)
	}
	// Within the bound it completes.
	maxJDKs = 3
	e2 := newEnv(t, Limits{})
	idx = e2.reg.add(img)
	if out := e2.reader.Read(context.Background(), e2.target(img, idx)); out.Kind != Complete || len(out.JDKs) != 3 {
		t.Errorf("at the bound: %+v", out)
	}
}

// Many layers that overwrite one path leave a small tree but hold a summary
// each: what is held at once is bounded, and a layer that repeats is held once.
func TestRegistryHeldSummariesAreBounded(t *testing.T) {
	defer func(n int64) { maxHeldSummaryBytes = n }(maxHeldSummaryBytes)
	var layers [][]fe
	for i := 0; i < 12; i++ {
		layers = append(layers, []fe{file("etc/conf", strings.Repeat("v", 10+i))})
	}
	img := buildImage(t, amd64, layers...)
	one := summaryCost(summarize(t, img.raw[0]).Summary)
	t.Run("distinct layers over the bound", func(t *testing.T) {
		maxHeldSummaryBytes = one * 5
		e := newEnv(t, Limits{})
		idx := e.reg.add(img)
		out := e.reader.Read(context.Background(), e.target(img, idx))
		if out.Kind != Permanent || out.Reason != ReasonSummaryLimit || !out.Recorded {
			t.Errorf("%+v", out)
		}
	})
	t.Run("fresh and cached reads draw the same boundary", func(t *testing.T) {
		var total int64
		for _, raw := range img.raw {
			total += summaryCost(summarize(t, raw).Summary)
		}
		for _, tc := range []struct {
			limit int64
			want  Kind
		}{{total - 1, Permanent}, {total, Complete}} {
			maxHeldSummaryBytes = tc.limit
			fresh := newEnv(t, Limits{})
			idx := fresh.reg.add(img)
			out := fresh.reader.Read(context.Background(), fresh.target(img, idx))
			if out.Kind != tc.want || (tc.want == Permanent && out.Reason != ReasonSummaryLimit) {
				t.Errorf("limit %d fresh: %+v", tc.limit, out)
			}
			// The layers cached by an earlier read (with room), then the limit.
			maxHeldSummaryBytes = 1 << 30
			warm := newEnv(t, Limits{})
			idx = warm.reg.add(img)
			wantComplete2(t, warm.reader.Read(context.Background(), warm.target(img, idx)))
			for _, d := range cacheDirsFiles(t, warm.cache, "images") {
				removeFile(t, d)
			}
			maxHeldSummaryBytes = tc.limit
			out = warm.newReader(NewBudget(warm.limits)).Read(context.Background(), warm.target(img, idx))
			if out.Kind != tc.want || (tc.want == Permanent && out.Reason != ReasonSummaryLimit) {
				t.Errorf("limit %d cached: %+v", tc.limit, out)
			}
		}
	})
	t.Run("one layer repeated is held once", func(t *testing.T) {
		same := make([][]fe, 12)
		for i := range same {
			same[i] = []fe{file("etc/conf", "same")}
		}
		img := buildImage(t, amd64, same...)
		maxHeldSummaryBytes = one * 3
		e := newEnv(t, Limits{})
		idx := e.reg.add(img)
		if out := e.reader.Read(context.Background(), e.target(img, idx)); out.Kind != Complete {
			t.Errorf("%+v", out)
		}
		// Again from the cache: still one decoded summary.
		for _, d := range cacheDirsFiles(t, e.cache, "images") {
			removeFile(t, d)
		}
		if out := e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(img, idx)); out.Kind != Complete {
			t.Errorf("from cache: %+v", out)
		}
	})
}

func wantComplete2(t *testing.T, out Outcome) {
	t.Helper()
	if out.Kind != Complete {
		t.Fatalf("outcome %v reason %q detail %q", out.Kind, out.Reason, out.Detail)
	}
}

// Three bad answers with another kind of end between them are not three in a
// row.
func TestRegistryBlobStrikesMustBeConsecutive(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	read := func() Outcome {
		return e.newReader(NewBudget(e.limits)).Read(context.Background(), e.target(img, idx))
	}
	corruptBlob(e, img, 1)
	for i := 0; i < 2; i++ {
		if out := read(); out.Kind != Deferred || out.Reason != ReasonBlobMismatch {
			t.Fatalf("%+v", out)
		}
	}
	e.reg.route("blobs/"+digestOf(img.blobs[1]), func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if out := read(); out.Kind != Deferred || out.Reason != ReasonTransient {
		t.Fatalf("502: %+v", out)
	}
	corruptBlob(e, img, 1)
	for i := 0; i < 2; i++ {
		if out := read(); out.Kind != Deferred || out.Recorded {
			t.Fatalf("after the 502, bad answer %d: %+v", i+1, out)
		}
	}
	if out := read(); out.Kind != Permanent || !out.Recorded {
		t.Errorf("the third in a row: %+v", out)
	}
}

// Different compressed blobs of one layer are verified one by one, and the
// read holds a single summary for the diffID.
func TestRegistryBlobsOfOneDiffIDShareOneSummary(t *testing.T) {
	same := []fe{file("etc/conf", "same")}
	img := buildImage(t, amd64, same, same, same)
	img.blobs = [][]byte{gzipOf(img.raw[0]), gzipVariant(img.raw[1]), nil}
	// A third spelling: another header name.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Name = "third"
	zw.Write(img.raw[2])
	zw.Close()
	img.blobs[2] = buf.Bytes()
	img.finish(t, amd64)
	if digestOf(img.blobs[0]) == digestOf(img.blobs[1]) || digestOf(img.blobs[1]) == digestOf(img.blobs[2]) || digestOf(img.blobs[0]) == digestOf(img.blobs[2]) {
		t.Fatal("the fixture needs three different blobs")
	}
	e := newEnv(t, Limits{})
	idx := e.reg.add(img)
	ctx := context.Background()
	st := &runState{r: e.reader, t: e.target(img, idx), limits: e.limits.withDefaults(), ctx: ctx, parent: ctx}
	var stacked []LayerRef
	st.stacked = func(refs []LayerRef) { stacked = refs }
	if out := st.readRegistry(); out.Kind != Complete {
		t.Fatalf("%+v", out)
	}
	if len(stacked) != 3 {
		t.Fatalf("%d layers reached the overlay", len(stacked))
	}
	for i := 1; i < len(stacked); i++ {
		if len(stacked[i].Summary.Entries) == 0 || &stacked[i].Summary.Entries[0] != &stacked[0].Summary.Entries[0] {
			t.Errorf("layer %d holds its own copy of the summary", i)
		}
	}
	if len(st.sums) != 1 || st.held != summaryCost(summarize(t, img.raw[0]).Summary) {
		t.Errorf("held %d summaries, %d bytes", len(st.sums), st.held)
	}
	if st.stats.LayersRead != 3 {
		t.Errorf("each blob must be verified: %+v", st.stats)
	}
}

// Without a cache on disk the layers read in one cycle are lost, so an image
// that needs more than a whole cycle's budget is refused rather than put off
// for ever.
func TestRegistryOverBudgetWithoutACache(t *testing.T) {
	img := buildImage(t, amd64, []fe{file("a/pad", strings.Repeat("0123456789abcdef", 4096))}, append(temurinLayer(), file("b/pad", strings.Repeat("fedcba9876543210", 4096))))
	a, b := int64(len(img.blobs[0])), int64(len(img.blobs[1]))
	if a < 2 || b < 2 {
		t.Fatalf("the fixture is too small: %d %d", a, b)
	}
	l := Limits{RegistryBytesPerCycle: max(a, b) + 1} // each layer fits, both do not
	e := newEnv(t, l)
	idx := e.reg.add(img)
	e.reader.Cache = NewMemoryCache()
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonOverBudgetNoCache || out.Recorded {
		t.Errorf("%+v", out)
	}
	if got := e.reg.hits(digestOf(img.blobs[0])) + e.reg.hits(digestOf(img.blobs[1])); got != 0 {
		t.Errorf("%d layer requests were made for an image that cannot fit", got)
	}
	// With a cache on disk the same image is read over two cycles.
	e2 := newEnv(t, l)
	idx = e2.reg.add(img)
	if out := e2.reader.Read(context.Background(), e2.target(img, idx)); out.Kind != Deferred || out.Reason != ReasonBudget {
		t.Errorf("with a cache: %+v", out)
	}
}

// The bytes read to verify a failed blob are in the statistics: they were
// taken from the budget. The blob has a header the gzip reader refuses at the
// first bytes and a long body that is only read to check the digest.
func TestRegistryStatsCountTheBytesReadAfterAFailure(t *testing.T) {
	e := newEnv(t, Limits{})
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	body := make([]byte, 300<<10)
	rand.New(rand.NewSource(2)).Read(body)
	img.blobs[1] = append([]byte{0x1f, 0x8b, 0x07, 0x00}, body...) // method 7 is no deflate
	img.finish(t, amd64)
	idx := e.reg.add(img)
	b := NewBudget(e.limits)
	before := b.RegistryLeft()
	out := e.newReader(b).Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonCorruptLayer {
		t.Fatalf("%+v", out)
	}
	spent := before - b.RegistryLeft()
	want := int64(len(img.blobs[0]) + len(img.blobs[1]))
	if spent != want || out.Stats.RegistryBytes != spent {
		t.Errorf("budget lost %d, Stats.RegistryBytes = %d, the two blobs are %d bytes", spent, out.Stats.RegistryBytes, want)
	}
}

// Without a cache on disk a layer read before the timeout is lost, so it is no
// progress: the image is not put off for ever at the same layer.
func TestRegistryTimeoutWithoutACacheIsNoProgress(t *testing.T) {
	l := Limits{ImageTimeout: 400 * time.Millisecond}
	e := newEnv(t, l)
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	idx := e.reg.add(img)
	e.reg.route("blobs/"+digestOf(img.blobs[1]), stall)
	e.reader.Cache = NewMemoryCache()
	out := e.reader.Read(context.Background(), e.target(img, idx))
	if out.Kind != Permanent || out.Reason != ReasonTimeoutNoProgress || !out.Recorded {
		t.Errorf("%+v", out)
	}
	if out.Stats.LayersRead != 1 || out.Stats.LayersKept != 0 {
		t.Errorf("stats %+v", out.Stats)
	}
}

func TestLayersExceedDoesNotOverflow(t *testing.T) {
	huge := registry.Layer{Size: math.MaxInt64}
	if _, over := layersExceed([]registry.Layer{huge, huge}, 1<<30); !over {
		t.Error("overflow-sized layers fit")
	}
	if _, over := layersExceed([]registry.Layer{{Size: 600}, {Size: 400}}, 1000); over {
		t.Error("exactly the limit does not fit")
	}
	if _, over := layersExceed([]registry.Layer{{Size: 600}, {Size: 401}}, 1000); !over {
		t.Error("one byte over fits")
	}
}

// With no cycle budget the contract is no limit: the layers of an image that
// would pass a budget are read all the same.
func TestRegistryNoBudgetNoTotalCheck(t *testing.T) {
	img := buildImage(t, amd64, baseLayer(), temurinLayer())
	a, b := int64(len(img.blobs[0])), int64(len(img.blobs[1]))
	e := newEnv(t, Limits{RegistryBytesPerCycle: max(a, b) + 1})
	idx := e.reg.add(img)
	r := e.newReader(nil)
	r.Cache = NewMemoryCache()
	if out := r.Read(context.Background(), e.target(img, idx)); out.Kind != Complete {
		t.Errorf("no budget must read the whole image: %+v", out)
	}
}
