package imagefs

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/docker"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// fakeDocker is a Docker Engine on a unix socket that answers the version
// request and exports one prepared tar.
type fakeDocker struct {
	sock string

	mu      sync.Mutex
	exports int
	queries []string
	version string
	handler func(w http.ResponseWriter, r *http.Request) // replaces the export when set
	export  []byte
}

func newFakeDocker(t *testing.T, export []byte) *fakeDocker {
	t.Helper()
	dir, err := os.MkdirTemp("", "fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeDocker{sock: filepath.Join(dir, "s"), version: "1.50", export: export}
	l, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			f.mu.Lock()
			v := f.version
			f.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"ApiVersion": v})
		case strings.HasPrefix(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/get"):
			f.mu.Lock()
			f.exports++
			f.queries = append(f.queries, r.URL.RawQuery)
			h, b := f.handler, f.export
			f.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return f
}

func (f *fakeDocker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exports
}

// exportImage describes an image to put into an export tar.
type exportImage struct {
	p       inventory.Platform
	layers  [][]fe
	tars    [][]byte
	diffIDs []string
	config  []byte
	cfgID   string // sha256:<hex> of the config
}

func newExportImage(t *testing.T, p inventory.Platform, extra string, layers ...[]fe) *exportImage {
	t.Helper()
	x := &exportImage{p: p, layers: layers}
	for _, l := range layers {
		raw := tarOf(t, l...)
		x.tars = append(x.tars, raw)
		x.diffIDs = append(x.diffIDs, digestOf(raw))
	}
	x.rebuildConfig(extra)
	return x
}

func (x *exportImage) rebuildConfig(extra string) {
	x.config, _ = json.Marshal(map[string]any{
		"os": x.p.OS, "architecture": x.p.Architecture, "created": extra,
		"rootfs": map[string]any{"type": "layers", "diff_ids": x.diffIDs},
	})
	x.cfgID = digestOf(x.config)
}

func hexOfDigest(d string) string { return strings.TrimPrefix(d, "sha256:") }

// ociExport builds the tar of an export in the OCI layout for a manifest
// list: the config and the layers of every image (gzip), the other
// platform's layer in zstd, an attestation, and the index files. configFirst
// puts the configs before the layers.
func ociExport(t *testing.T, configFirst bool, imgs ...*exportImage) []byte {
	t.Helper()
	var layers, configs []fe
	for _, x := range imgs {
		configs = append(configs, file("blobs/sha256/"+hexOfDigest(x.cfgID), string(x.config)))
		for _, raw := range x.tars {
			gz := gzipOf(raw)
			layers = append(layers, file("blobs/sha256/"+hexOfDigest(digestOf(gz)), string(gz)))
		}
	}
	zst := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 64)...)
	att := `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[]}`
	var all []fe
	all = append(all, file("oci-layout", `{"imageLayoutVersion":"1.0.0"}`), dir("blobs"), dir("blobs/sha256"))
	if configFirst {
		all = append(all, configs...)
		all = append(all, layers...)
	} else {
		all = append(all, layers...)
		all = append(all, configs...)
	}
	all = append(all,
		file("blobs/sha256/"+hexOfDigest(digestOf(zst)), string(zst)), // a layer this reader cannot read, of no image of ours
		file("blobs/sha256/"+hexOfDigest(digestOf([]byte(att))), att),
		file("index.json", `{"schemaVersion":2,"manifests":[]}`),
		file("manifest.json", `[{"Config":"blobs/sha256/x","Layers":[]}]`),
	)
	return tarOf(t, all...)
}

// legacyExport builds the tar of an export in the legacy layout. The layer
// ids are made up; a layer whose content is the same as an earlier one is a
// symbolic link to it.
func legacyExport(t *testing.T, x *exportImage) []byte {
	t.Helper()
	var all []fe
	seen := map[string]string{}
	var names []string
	for i, raw := range x.tars {
		id := hex.EncodeToString([]byte{byte(i + 1), 0xaa}) + strings.Repeat("0", 60)
		name := id + "/layer.tar"
		if first, ok := seen[x.diffIDs[i]]; ok {
			all = append(all, dir(id), sym(name, "../"+first))
		} else {
			seen[x.diffIDs[i]] = name
			all = append(all, dir(id), file(name, string(raw)), file(id+"/json", `{"id":"`+id+`"}`), file(id+"/VERSION", "1.0"))
		}
		names = append(names, name)
	}
	m, _ := json.Marshal([]map[string]any{{"Config": hexOfDigest(x.cfgID) + ".json", "RepoTags": nil, "Layers": names}})
	all = append(all, file(hexOfDigest(x.cfgID)+".json", string(x.config)), file("manifest.json", string(m)), file("repositories", "{}"))
	return tarOf(t, all...)
}

func dockerEnv(t *testing.T, export []byte, l Limits) (*fakeDocker, *Reader, *Cache) {
	t.Helper()
	f := newFakeDocker(t, export)
	c := newCache(t)
	r := &Reader{Docker: docker.New(f.sock), Cache: c, Budget: NewBudget(l), Limits: l, Version: "test-1"}
	return f, r, c
}

var arm64 = inventory.Platform{OS: "linux", Architecture: "arm64"}

func TestDockerOCIExportOfAManifestList(t *testing.T) {
	for _, configFirst := range []bool{false, true} {
		target := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
		other := newExportImage(t, arm64, "", baseLayer(), []fe{file("opt/other", "arm")})
		f, r, c := dockerEnv(t, ociExport(t, configFirst, other, target), Limits{})
		listID := digestOf([]byte("manifest list"))
		tg := DockerTarget(listID, amd64, target.diffIDs)

		out := r.Read(context.Background(), tg)
		wantComplete(t, out)
		if out.ConfigDigest != target.cfgID || out.Stats.LayersRead != 2 || !out.Stats.ExportCalled {
			t.Errorf("configFirst=%v: %+v config %s", configFirst, out.Stats, out.ConfigDigest)
		}
		if f.count() != 1 || len(f.queries) != 1 || !strings.Contains(f.queries[0], "platform=") ||
			!strings.Contains(f.queries[0], "%22architecture%22%3A%22amd64%22") {
			t.Errorf("export requests %d %v", f.count(), f.queries)
		}
		// The cache has the result under the config; the layers make the export
		// unnecessary even when the image is known by a manifest list digest.
		if _, ok := c.GetImage(target.cfgID, target.diffIDs); !ok {
			t.Error("no image result stored")
		}
		out = r.Read(context.Background(), tg)
		wantComplete(t, out)
		if f.count() != 1 || out.Stats.ExportCalled || out.Stats.LayersCached != 2 {
			t.Errorf("second read: exports %d, %+v", f.count(), out.Stats)
		}
		// Known by its config digest, the image result answers at once.
		out = r.Read(context.Background(), DockerTarget(target.cfgID, amd64, target.diffIDs))
		if !out.Stats.ImageCached || f.count() != 1 {
			t.Errorf("by config: %+v", out.Stats)
		}
	}
}

func TestDockerLegacyExportWithRepeatedLayer(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer(), baseLayer())
	if x.diffIDs[0] != x.diffIDs[2] {
		t.Fatal("fixture: the first and third layer should be the same")
	}
	_, r, _ := dockerEnv(t, legacyExport(t, x), Limits{})
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	wantComplete(t, out)
	if out.ConfigDigest != x.cfgID {
		t.Errorf("config %s", out.ConfigDigest)
	}
}

func TestDockerOlderEngineSendsNoPlatform(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	f, r, _ := dockerEnv(t, ociExport(t, false, x), Limits{})
	f.version = "1.47"
	wantComplete(t, r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs)))
	if len(f.queries) != 1 || f.queries[0] != "" {
		t.Errorf("queries %v", f.queries)
	}
}

func TestDockerNoUniqueMatchingConfig(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	twin := newExportImage(t, amd64, "other build", baseLayer(), temurinLayer()) // same layers, another config
	for name, tc := range map[string]struct {
		export []byte
		target Target
	}{
		"diffIDs differ":   {ociExport(t, false, x), DockerTarget(x.cfgID, amd64, x.diffIDs[:1])},
		"platform differs": {ociExport(t, false, x), DockerTarget(x.cfgID, arm64, x.diffIDs)},
		"two configs":      {ociExport(t, false, x, twin), DockerTarget(x.cfgID, amd64, x.diffIDs)},
		"no config":        {tarOf(t, file("index.json", "{}")), DockerTarget(x.cfgID, amd64, x.diffIDs)},
	} {
		_, r, c := dockerEnv(t, tc.export, Limits{})
		for i := 0; i < 2; i++ { // the first two are strikes, deferred
			// Layers cached by an earlier try would make the export unnecessary.
			for _, p := range cacheDirsFiles(t, c, "layers") {
				removeFile(t, p)
			}
			if out := r.Read(context.Background(), tc.target); out.Kind != Deferred || out.Reason != ReasonNoMatchingConfig {
				t.Errorf("%s: strike %d: %+v", name, i+1, out)
			}
		}
		for _, p := range cacheDirsFiles(t, c, "layers") {
			removeFile(t, p)
		}
		out := r.Read(context.Background(), tc.target)
		if out.Kind != Permanent || out.Reason != ReasonNoMatchingConfig || !out.Recorded {
			t.Errorf("%s: %+v", name, out)
		}
	}
}

func TestDockerLayerMissingFromExport(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	// Export only the config and the first layer.
	gz := gzipOf(x.tars[0])
	export := tarOf(t, file("blobs/sha256/"+hexOfDigest(x.cfgID), string(x.config)), file("blobs/sha256/"+hexOfDigest(digestOf(gz)), string(gz)))
	_, r, _ := dockerEnv(t, export, Limits{})
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Permanent || out.Reason != ReasonLayerMissing {
		t.Errorf("%+v", out)
	}
}

func TestDockerUnreadableLayerOfTheImageIsPermanent(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	zst := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 64)...)
	gz := gzipOf(x.tars[0])
	export := tarOf(t,
		file("blobs/sha256/"+hexOfDigest(x.cfgID), string(x.config)),
		file("blobs/sha256/"+hexOfDigest(digestOf(gz)), string(gz)),
		file("blobs/sha256/"+hexOfDigest(digestOf(zst)), string(zst)),
	)
	_, r, _ := dockerEnv(t, export, Limits{})
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Permanent || out.Reason != ReasonUnsupportedCompression || !out.Recorded {
		t.Errorf("%+v", out)
	}
}

func TestDockerBlobNamedByAnotherDigestIsPermanentOnTheThirdStrike(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	bad := tarOf(t,
		file("blobs/sha256/"+hexOfDigest(x.cfgID), string(x.config)),
		file("blobs/sha256/"+hexOfDigest(digestOf(gzipOf(x.tars[0]))), string(gzipOf(x.tars[0]))),
		file("blobs/sha256/"+strings.Repeat("ab", 32), string(gzipOf(x.tars[1]))), // named by a digest it does not have
	)
	f, _, c := dockerEnv(t, bad, Limits{})
	tg := DockerTarget(x.cfgID, amd64, x.diffIDs)
	read := func() Outcome {
		r := &Reader{Docker: docker.New(f.sock), Cache: c, Budget: NewBudget(Limits{}), Version: "test-1"}
		return r.Read(context.Background(), tg)
	}
	for i := 1; i <= 2; i++ {
		if out := read(); out.Kind != Deferred || out.Reason != ReasonExportInconsistent || out.Recorded {
			t.Fatalf("strike %d: %+v", i, out)
		}
	}
	if _, ok := c.GetBlob("sha256:" + strings.Repeat("ab", 32)); ok {
		t.Error("a mismatched blob was mapped")
	}
	// A good export in between completes and resets the count.
	f.mu.Lock()
	f.export = ociExport(t, false, x)
	f.mu.Unlock()
	wantComplete(t, read())
	if n := c.Timeouts(tg.key()); n != 0 {
		t.Fatalf("count %d after a complete read", n)
	}
	for _, p := range cacheDirsFiles(t, c, "images") {
		removeFile(t, p)
	}
	for _, p := range cacheDirsFiles(t, c, "layers") {
		removeFile(t, p)
	}
	f.mu.Lock()
	f.export = bad
	f.mu.Unlock()
	for i := 1; i <= 2; i++ {
		if out := read(); out.Kind != Deferred || out.Recorded {
			t.Fatalf("strike %d after the reset: %+v", i, out)
		}
	}
	out := read()
	if out.Kind != Permanent || out.Reason != ReasonExportInconsistent || !out.Recorded {
		t.Fatalf("third strike: %+v", out)
	}
	n := f.count()
	if out := read(); out.Kind != Permanent || !out.Recorded || f.count() != n {
		t.Errorf("after the record: %+v, exports %d -> %d", out, n, f.count())
	}
}

func TestDockerKnownBlobsAreReadThroughNotSummarized(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	f, r, c := dockerEnv(t, ociExport(t, false, x), Limits{})
	tg := DockerTarget(digestOf([]byte("list")), amd64, x.diffIDs)
	wantComplete(t, r.Read(context.Background(), tg))
	// Lose the summary of the second layer and the image result only.
	h, _ := hexOf(x.diffIDs[1])
	removeFile(t, filepath.Join(c.dir, "layers", h+".json"))
	for _, p := range cacheDirsFiles(t, c, "images") {
		removeFile(t, p)
	}
	out := r.Read(context.Background(), tg)
	wantComplete(t, out)
	if f.count() != 2 || out.Stats.LayersCached != 1 || out.Stats.LayersRead != 1 {
		t.Errorf("exports %d, %+v", f.count(), out.Stats)
	}
}

func TestDockerBudget(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	export := ociExport(t, false, x)

	t.Run("an export larger than a whole cycle is permanent", func(t *testing.T) {
		l := Limits{DockerBytesPerCycle: int64(len(export) / 2)}
		_, r, _ := dockerEnv(t, export, l)
		out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
		if out.Kind != Permanent || out.Reason != ReasonExportOverBudget || !out.Recorded {
			t.Errorf("%+v", out)
		}
	})
	t.Run("what the cycle has left is not enough: deferred", func(t *testing.T) {
		l := Limits{}
		f, r, _ := dockerEnv(t, export, l)
		r.Budget.take(&r.Budget.dockerLeft, DefaultDockerBytesPerCycle-100)
		out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
		if out.Kind != Deferred || out.Reason != ReasonBudget || out.Recorded {
			t.Errorf("%+v", out)
		}
		// A new cycle starts again.
		r.Budget = NewBudget(l)
		wantComplete(t, r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs)))
		if f.count() != 2 {
			t.Errorf("exports %d", f.count())
		}
	})
	t.Run("an empty budget does not even ask", func(t *testing.T) {
		f, r, _ := dockerEnv(t, export, Limits{})
		r.Budget.take(&r.Budget.dockerLeft, DefaultDockerBytesPerCycle)
		out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
		if out.Kind != Deferred || out.Reason != ReasonBudget || f.count() != 0 {
			t.Errorf("%+v exports %d", out, f.count())
		}
	})
}

func TestDockerThreeTimeoutsInARowArePermanent(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	l := Limits{ImageTimeout: 150 * time.Millisecond}
	f, _, c := dockerEnv(t, nil, l)
	f.handler = stall
	tg := DockerTarget(x.cfgID, amd64, x.diffIDs)
	read := func() Outcome {
		// Every cycle has a reader of its own; the counter lives in the cache.
		r := &Reader{Docker: docker.New(f.sock), Cache: c, Budget: NewBudget(l), Limits: l, Version: "test-1"}
		return r.Read(context.Background(), tg)
	}
	for i := 1; i <= 2; i++ {
		if out := read(); out.Kind != Deferred || out.Reason != ReasonTimeout {
			t.Fatalf("read %d: %+v", i, out)
		}
	}
	out := read()
	if out.Kind != Permanent || out.Reason != ReasonTimeoutRepeated || !out.Recorded {
		t.Fatalf("third read: %+v", out)
	}
	n := f.count()
	if out := read(); out.Kind != Permanent || !out.Recorded || f.count() != n {
		t.Errorf("after the record: %+v, exports %d -> %d", out, n, f.count())
	}
}

func TestDockerTimeoutCountIsConsecutive(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	l := Limits{ImageTimeout: 150 * time.Millisecond}
	f, _, c := dockerEnv(t, ociExport(t, false, x), l)
	good := f.export
	tg := DockerTarget(x.cfgID, amd64, x.diffIDs)
	read := func() Outcome {
		r := &Reader{Docker: docker.New(f.sock), Cache: c, Budget: NewBudget(l), Limits: l, Version: "test-1"}
		return r.Read(context.Background(), tg)
	}
	f.mu.Lock()
	f.handler = stall
	f.mu.Unlock()
	read()
	read()
	if got := c.Timeouts(tg.key()); got != 2 {
		t.Fatalf("count %d", got)
	}
	// A read that does not time out resets the count.
	f.mu.Lock()
	f.handler = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "gone", http.StatusNotFound) }
	f.mu.Unlock()
	if out := read(); out.Kind != Permanent || out.Reason != ReasonImageNotFound {
		t.Fatalf("%+v", out)
	}
	if got := c.Timeouts(tg.key()); got != 0 {
		t.Errorf("count %d after a read that did not time out", got)
	}
	_ = good
}

func TestDockerImageNotFound(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	f, r, _ := dockerEnv(t, nil, Limits{})
	f.handler = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no such image", http.StatusNotFound) }
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Permanent || out.Reason != ReasonImageNotFound || out.Recorded {
		t.Errorf("%+v", out)
	}
}

func TestDockerServerErrorIsDeferred(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	f, r, _ := dockerEnv(t, nil, Limits{})
	f.handler = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) }
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Deferred || out.Reason != ReasonTransient {
		t.Errorf("%+v", out)
	}
}

func TestDockerExportCutByTheConnectionIsDeferred(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	full := ociExport(t, false, x)
	f, r, _ := dockerEnv(t, nil, Limits{})
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Write(full[:len(full)/2])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // the daemon dies mid-stream
	}
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Deferred || out.Reason != ReasonTransient || out.Recorded {
		t.Errorf("%+v", out)
	}
}

func TestDockerNoMatchingConfigIsPermanentOnTheThirdStrike(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	f, _, c := dockerEnv(t, tarOf(t, file("index.json", "{}")), Limits{})
	tg := DockerTarget(x.cfgID, amd64, x.diffIDs)
	read := func() Outcome {
		r := &Reader{Docker: docker.New(f.sock), Cache: c, Budget: NewBudget(Limits{}), Version: "test-1"}
		return r.Read(context.Background(), tg)
	}
	for i := 1; i <= 2; i++ {
		if out := read(); out.Kind != Deferred || out.Reason != ReasonNoMatchingConfig || out.Recorded {
			t.Fatalf("strike %d: %+v", i, out)
		}
	}
	out := read()
	if out.Kind != Permanent || out.Reason != ReasonNoMatchingConfig || !out.Recorded {
		t.Fatalf("third strike: %+v", out)
	}
	n := f.count()
	if out := read(); out.Kind != Permanent || !out.Recorded || f.count() != n {
		t.Errorf("after the record: %+v, exports %d -> %d", out, n, f.count())
	}
}

func TestDockerCompleteResetsTheStrikes(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	f, _, c := dockerEnv(t, tarOf(t, file("index.json", "{}")), Limits{})
	tg := DockerTarget(x.cfgID, amd64, x.diffIDs)
	read := func() Outcome {
		r := &Reader{Docker: docker.New(f.sock), Cache: c, Budget: NewBudget(Limits{}), Version: "test-1"}
		return r.Read(context.Background(), tg)
	}
	read()
	read()
	if c.Timeouts(tg.key()) != 2 {
		t.Fatalf("count %d", c.Timeouts(tg.key()))
	}
	f.mu.Lock()
	f.export = ociExport(t, false, x)
	f.mu.Unlock()
	wantComplete(t, read())
	if c.Timeouts(tg.key()) != 0 {
		t.Errorf("count %d after a complete read", c.Timeouts(tg.key()))
	}
	// Two more failures are strikes 1 and 2 again.
	f.mu.Lock()
	f.export = tarOf(t, file("index.json", "{}"))
	f.mu.Unlock()
	h, _ := hexOf(x.diffIDs[0])
	for _, p := range []string{"layers/" + h + ".json"} {
		os.Remove(filepath.Join(c.dir, p))
	}
	for _, p := range cacheDirsFiles(t, c, "images") {
		removeFile(t, p)
	}
	if out := read(); out.Kind != Deferred {
		t.Errorf("first strike after a reset: %+v", out)
	}
}

// A layer blob that arrives damaged under the name of its digest is a bad
// transfer: the damage is not held against the image, and the next good
// export completes.
func TestDockerDamagedBlobUnderItsDigestIsATransferFailure(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	good := gzipOf(x.tars[1])
	damaged := append([]byte(nil), good...)
	damaged[len(damaged)-6] ^= 0xff // the checksum at the end of the gzip stream
	build := func(second []byte) []byte {
		return tarOf(t,
			file("blobs/sha256/"+hexOfDigest(x.cfgID), string(x.config)),
			file("blobs/sha256/"+hexOfDigest(digestOf(gzipOf(x.tars[0]))), string(gzipOf(x.tars[0]))),
			file("blobs/sha256/"+hexOfDigest(digestOf(good)), string(second)),
		)
	}
	f, _, c := dockerEnv(t, build(damaged), Limits{})
	tg := DockerTarget(x.cfgID, amd64, x.diffIDs)
	read := func() Outcome {
		r := &Reader{Docker: docker.New(f.sock), Cache: c, Budget: NewBudget(Limits{}), Version: "test-1"}
		return r.Read(context.Background(), tg)
	}
	if out := read(); out.Kind != Deferred || out.Reason != ReasonExportInconsistent || out.Recorded {
		t.Fatalf("damaged transfer: %+v", out)
	}
	f.mu.Lock()
	f.export = build(good)
	f.mu.Unlock()
	wantComplete(t, read())
}

// The same damage in a blob whose digest verifies is the layer's own: it is
// permanent at once.
func TestDockerCorruptBlobWithAVerifiedDigestIsPermanent(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	corrupt := gzipOf(x.tars[1])
	corrupt[len(corrupt)-6] ^= 0xff
	export := tarOf(t,
		file("blobs/sha256/"+hexOfDigest(x.cfgID), string(x.config)),
		file("blobs/sha256/"+hexOfDigest(digestOf(gzipOf(x.tars[0]))), string(gzipOf(x.tars[0]))),
		file("blobs/sha256/"+hexOfDigest(digestOf(corrupt)), string(corrupt)),
	)
	_, r, _ := dockerEnv(t, export, Limits{})
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Permanent || out.Reason != ReasonCorruptLayer || !out.Recorded {
		t.Errorf("%+v", out)
	}
}

// Without a directory the strike counts live in memory: the third strike in
// a row is still permanent.
func TestDockerStrikesWorkWithAMemoryCache(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	f := newFakeDocker(t, tarOf(t, file("index.json", "{}")))
	cache := NewMemoryCache()
	tg := DockerTarget(x.cfgID, amd64, x.diffIDs)
	read := func() Outcome {
		r := &Reader{Docker: docker.New(f.sock), Cache: cache, Budget: NewBudget(Limits{}), Version: "test-1"}
		return r.Read(context.Background(), tg)
	}
	for i := 1; i <= 2; i++ {
		if out := read(); out.Kind != Deferred || out.Recorded != false {
			t.Fatalf("strike %d: %+v", i, out)
		}
	}
	if out := read(); out.Kind != Permanent || out.Reason != ReasonNoMatchingConfig || !out.Recorded {
		t.Fatalf("third strike: %+v", out)
	}
	n := f.count()
	if out := read(); out.Kind != Permanent || f.count() != n {
		t.Errorf("after the record: %+v", out)
	}
	// Nothing was written anywhere: the memory cache has no layers or images.
	if _, ok := cache.GetLayer(x.diffIDs[0]); ok {
		t.Error("a memory cache holds a layer")
	}
}

// sparseExport is an export whose first entry is a PAX sparse file with a
// huge logical size and a few bytes of data.
func sparseExport(t *testing.T) []byte {
	t.Helper()
	rec := func(k, v string) string {
		n := len(k) + len(v) + 3 // " ", "=", "\n"
		for {
			s := fmt.Sprintf("%d %s=%s\n", n, k, v)
			if len(s) == n {
				return s
			}
			n = len(s)
		}
	}
	pax := rec("GNU.sparse.major", "1") + rec("GNU.sparse.minor", "0") +
		rec("GNU.sparse.realsize", "100000000000") + rec("GNU.sparse.name", "blobs/sha256/"+strings.Repeat("ab", 32))
	m := "1\n0\n10\n"
	data := m + string(make([]byte, 512-len(m))) + "0123456789"
	// The extended header block is made by hand: the writer refuses to.
	blk := make([]byte, 512)
	copy(blk, "PaxHeaders.0/blob")
	copy(blk[100:], "0000644\x00")
	copy(blk[124:], fmt.Sprintf("%011o\x00", len(pax)))
	blk[156] = tar.TypeXHeader
	copy(blk[257:], "ustar\x0000")
	copy(blk[148:], "        ")
	sum := 0
	for _, b := range blk {
		sum += int(b)
	}
	copy(blk[148:], fmt.Sprintf("%06o\x00 ", sum))
	var buf bytes.Buffer
	buf.Write(blk)
	buf.WriteString(pax + string(make([]byte, (512-len(pax)%512)%512)))
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "GNUSparseFile.0/blob", Typeflag: tar.TypeReg, Size: int64(len(data)), Format: tar.FormatPAX}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(data))
	tw.Close()
	// What the reader makes of it must really be a sparse entry.
	h, err := tar.NewReader(bytes.NewReader(buf.Bytes())).Next()
	if err != nil || !isSparse(h) {
		t.Fatalf("the fixture is not a sparse entry: %+v %v", h, err)
	}
	return buf.Bytes()
}

func TestDockerSparseEntryIsRefusedBeforeItIsRead(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	_, r, _ := dockerEnv(t, sparseExport(t), Limits{})
	start := time.Now()
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Deferred || out.Reason != ReasonExportInconsistent {
		t.Errorf("%+v", out)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the logical size of the sparse entry was read")
	}
}

// An entry longer than a layer can be stops the hashing, and so does the
// context.
func TestDockerOverlongEntryStopsTheRead(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	// Incompressible content, well over the cap of a 1 KiB layer limit.
	noise := make([]byte, 3<<20)
	rand.New(rand.NewSource(1)).Read(noise)
	big := tarOf(t, file("big", string(noise)))
	gz := gzipOf(big)
	export := tarOf(t,
		file("blobs/sha256/"+hexOfDigest(x.cfgID), string(x.config)),
		file("blobs/sha256/"+hexOfDigest(digestOf(gz)), string(gz)),
	)
	l := Limits{MaxLayerBytes: 1024}
	_, r, _ := dockerEnv(t, export, l)
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	if out.Kind != Deferred || out.Reason != ReasonExportInconsistent || !strings.Contains(out.Detail, "longer than a layer") {
		t.Errorf("%+v", out)
	}
}

func TestEntryReaderStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	er := &entryReader{ctx: ctx, r: strings.NewReader(strings.Repeat("x", 100)), left: 1000}
	buf := make([]byte, 10)
	if _, err := er.Read(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := er.Read(buf); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	er = &entryReader{ctx: context.Background(), r: strings.NewReader(strings.Repeat("x", 100)), left: 25}
	n, _ := io.Copy(io.Discard, er)
	if n != 25 {
		t.Errorf("read %d bytes, want the 25 allowed", n)
	}
}

func TestEntryReaderBoundary(t *testing.T) {
	read := func(size, limit int) (int64, error) {
		er := &entryReader{ctx: context.Background(), r: strings.NewReader(strings.Repeat("x", size)), left: int64(limit)}
		return io.Copy(io.Discard, er)
	}
	if n, err := read(25, 25); err != nil || n != 25 {
		t.Errorf("exactly the cap: %d %v", n, err)
	}
	if _, err := read(26, 25); !errors.Is(err, errEntryTooLarge) {
		t.Errorf("cap+1: %v", err)
	}
	if n, err := read(24, 25); err != nil || n != 24 {
		t.Errorf("below the cap: %d %v", n, err)
	}
}

func TestDockerLayersKeptCountsEachLayerOnce(t *testing.T) {
	x := newExportImage(t, amd64, "", baseLayer(), temurinLayer())
	_, r, _ := dockerEnv(t, ociExport(t, false, x), Limits{})
	out := r.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	wantComplete(t, out)
	if out.Stats.LayersRead != 2 || out.Stats.LayersKept != 2 {
		t.Errorf("stats %+v", out.Stats)
	}
	// No cache on disk: nothing is kept.
	f := newFakeDocker(t, ociExport(t, false, x))
	r2 := &Reader{Docker: docker.New(f.sock), Cache: NewMemoryCache(), Budget: NewBudget(Limits{}), Version: "t"}
	out = r2.Read(context.Background(), DockerTarget(x.cfgID, amd64, x.diffIDs))
	wantComplete(t, out)
	if out.Stats.LayersKept != 0 {
		t.Errorf("kept %d without a cache on disk", out.Stats.LayersKept)
	}
}
