package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

func digestOf(c string) string { return "sha256:" + strings.Repeat(c, 64) }

type fakeImages struct {
	mu       sync.Mutex
	status   map[string][]int  // "METHOD path" -> statuses served in order; the last repeats
	inspect  map[string]string // path -> JSON body of a 200 inspect; default has no tags or digests
	requests []string          // "METHOD path?query"
}

func (f *fakeImages) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	key := r.Method + " " + r.URL.Path
	st := f.status[key]
	code := 200
	if len(st) > 0 {
		code = st[0]
		if len(st) > 1 {
			f.status[key] = st[1:]
		}
	}
	w.WriteHeader(code)
	if r.Method == "GET" && code == 200 {
		body, ok := f.inspect[strings.TrimSuffix(r.URL.Path, "/json")]
		if !ok {
			body = `{"RepoTags":[],"RepoDigests":[]}`
		}
		io.WriteString(w, body)
		return
	}
	io.WriteString(w, `{"message":"x"}`)
}

// deletes returns the DELETE requests received.
func (f *fakeImages) deletes() []string {
	var out []string
	for _, r := range f.requests {
		if strings.HasPrefix(r, "DELETE ") {
			out = append(out, r)
		}
	}
	return out
}

func newTestPruner(t *testing.T, f *fakeImages) (*ImagePruner, string) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	rec := filepath.Join(t.TempDir(), "sub", "work-images.json")
	p, err := newImagePruner(srv.URL, srv.Client(), rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return p, rec
}

// pulled records ref as a pull that finished: reserved, then confirmed. It
// returns what the reservation said.
func pulled(p *ImagePruner, ref string) error {
	if err := p.Reserve(ref); err != nil {
		return err
	}
	p.Confirm(ref)
	return nil
}

// pendingImages returns the references the record holds as reserved only.
func pendingImages(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec imageRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	return rec.Pending
}

func recordedImages(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec imageRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Schema != 1 {
		t.Errorf("schema = %d", rec.Schema)
	}
	return rec.Images
}

// ensureCase is one run of EnsureImage against a fake daemon.
type ensureCase struct {
	present     bool  // the daemon holds the image for the platform
	otherArch   bool  // the daemon holds the reference for another platform only
	pullFails   bool  // the pull reports an error in its stream
	verifyFails bool  // what was pulled is not the pinned image
	beforePull  error // what BeforePull returns
}

// runEnsure returns what BeforePull was called with, the requests the daemon
// got in order, and the error of EnsureImage.
func runEnsure(t *testing.T, c ensureCase) (calls []string, requests []string, err error) {
	t.Helper()
	var pulled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/version":
			json.NewEncoder(w).Encode(map[string]any{"ApiVersion": "1.52"})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/images/"):
			forPlatform := r.URL.Query().Get("platform") != ""
			if forPlatform {
				requests = append(requests, "inspect for the platform")
			} else {
				requests = append(requests, "inspect the reference")
			}
			held := c.present || pulled || (c.otherArch && !forPlatform)
			if !held {
				w.WriteHeader(404)
				return
			}
			digs := []string{testImage}
			if c.verifyFails {
				digs = []string{"registry.example/kestrelynx-worker@" + digestOf("b")}
			}
			arch := "amd64"
			if c.otherArch && !pulled {
				arch = "arm64"
			}
			json.NewEncoder(w).Encode(map[string]any{"RepoDigests": digs, "Os": "linux", "Architecture": arch})
		case r.Method == "POST" && r.URL.Path == "/images/create":
			requests = append(requests, "pull")
			pulled = true
			if c.pullFails {
				w.Write([]byte("{\"error\":\"denied\"}\n"))
				return
			}
			w.Write([]byte("{\"status\":\"ok\"}\n"))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()
	wc, cerr := newWorkClient(srv.URL, srv.Client(), WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"},
		AllowedEnvKeys: []string{"HOME"}, InstanceID: testInstance, Limits: testLimits(),
		BeforePull: func(ref string) error {
			calls = append(calls, ref)
			requests = append(requests, "before pull")
			return c.beforePull
		},
		AfterPull: func(ref string) {
			if ref != testImage {
				t.Errorf("AfterPull(%q)", ref)
			}
			requests = append(requests, "after pull")
		}})
	if cerr != nil {
		t.Fatal(cerr)
	}
	err = wc.EnsureImage(context.Background())
	return calls, requests, err
}

func TestEnsureImageBeforePull(t *testing.T) {
	once := []string{testImage}
	t.Run("pulled", func(t *testing.T) {
		calls, reqs, err := runEnsure(t, ensureCase{})
		if err != nil || !reflect.DeepEqual(calls, once) {
			t.Fatalf("calls = %v, err = %v", calls, err)
		}
		// The reference is recorded before the daemon is asked to pull.
		want := []string{"inspect for the platform", "inspect the reference", "before pull", "pull", "after pull", "inspect for the platform"}
		if !reflect.DeepEqual(reqs, want) {
			t.Fatalf("requests = %v, want %v", reqs, want)
		}
	})
	t.Run("present", func(t *testing.T) {
		calls, reqs, err := runEnsure(t, ensureCase{present: true})
		if err != nil || len(calls) != 0 || slices.Contains(reqs, "pull") {
			t.Fatalf("calls = %v, requests = %v, err = %v", calls, reqs, err)
		}
	})
	// A pull that fails was announced and is not confirmed.
	t.Run("pull fails", func(t *testing.T) {
		calls, reqs, err := runEnsure(t, ensureCase{pullFails: true})
		if err == nil || !reflect.DeepEqual(calls, once) || slices.Contains(reqs, "after pull") {
			t.Fatalf("calls = %v, requests = %v, err = %v", calls, reqs, err)
		}
	})
	// An image that was pulled and is not the pinned one is on the host all
	// the same: the pull is confirmed before the image is checked.
	t.Run("verification fails", func(t *testing.T) {
		calls, reqs, err := runEnsure(t, ensureCase{verifyFails: true})
		if err == nil || !reflect.DeepEqual(calls, once) || !slices.Contains(reqs, "after pull") {
			t.Fatalf("calls = %v, requests = %v, err = %v", calls, reqs, err)
		}
	})
	// What cannot be recorded is not pulled.
	t.Run("cannot be recorded", func(t *testing.T) {
		calls, reqs, err := runEnsure(t, ensureCase{beforePull: errors.New("the record is full")})
		if err == nil || !strings.Contains(err.Error(), "the record is full") || !reflect.DeepEqual(calls, once) || slices.Contains(reqs, "pull") || slices.Contains(reqs, "after pull") {
			t.Fatalf("calls = %v, requests = %v, err = %v", calls, reqs, err)
		}
	})
	// A reference the daemon already holds for another platform was somebody
	// else's first: the platform is pulled, and the reference is not recorded
	// as this installation's.
	t.Run("held for another platform", func(t *testing.T) {
		calls, reqs, err := runEnsure(t, ensureCase{otherArch: true})
		if err != nil || len(calls) != 0 || !slices.Contains(reqs, "pull") || slices.Contains(reqs, "after pull") {
			t.Fatalf("calls = %v, requests = %v, err = %v", calls, reqs, err)
		}
	})
}

func TestRecordNormalizesAndIsIdempotent(t *testing.T) {
	p, rec := newTestPruner(t, &fakeImages{})
	d := "@" + digestOf("a")
	pulled(p, "node"+d)
	pulled(p, "node"+d)
	pulled(p, "docker.io/library/node"+d)
	got := recordedImages(t, rec)
	if len(got) != 1 || got[0] != "docker.io/library/node"+d {
		t.Fatalf("record = %v", got)
	}
	pulled(p, "registry.example.com/dockerhub/library/node"+d)
	if got := recordedImages(t, rec); len(got) != 2 || got[0] > got[1] {
		t.Fatalf("record = %v", got)
	}
}

func TestRecordRefusesOtherReferences(t *testing.T) {
	p, rec := newTestPruner(t, &fakeImages{})
	for _, r := range []string{"node:22", "node", "node@sha256:abc", "node@" + digestOf("A"), "a//b@" + digestOf("a"), "a/../b@" + digestOf("a"), "", "Node@" + digestOf("a")} {
		pulled(p, r)
	}
	if _, err := os.Stat(rec); err == nil {
		t.Fatalf("record written for refused references: %v", recordedImages(t, rec))
	}
}

func TestRecordPersistsAcrossPruners(t *testing.T) {
	p, rec := newTestPruner(t, &fakeImages{})
	pulled(p, "node@"+digestOf("a"))
	f := &fakeImages{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	p2, _ := newImagePruner(srv.URL, srv.Client(), rec, nil)
	pulled(p2, "python@"+digestOf("b"))
	if got := recordedImages(t, rec); len(got) != 2 {
		t.Fatalf("record = %v", got)
	}
	if res := p2.Prune(context.Background(), nil); res.Removed != 2 {
		t.Fatalf("res = %+v", res)
	}
}

// A full record refuses a new reference, so that the image is not pulled: an
// image on the host that is not in the record would never be removed.
func TestRecordCap(t *testing.T) {
	p, rec := newTestPruner(t, &fakeImages{})
	var imgs []string
	for i := 0; i < maxImageRecordEntries; i++ {
		imgs = append(imgs, fmt.Sprintf("docker.io/library/n%d@%s", i, digestOf("a")))
	}
	if err := p.save(imageState{pulled: imgs}); err != nil {
		t.Fatal(err)
	}
	if err := pulled(p, "node@"+digestOf("b")); err == nil {
		t.Fatal("a reference was accepted by a full record")
	}
	if got := recordedImages(t, rec); len(got) != maxImageRecordEntries {
		t.Fatalf("len = %d", len(got))
	}
	// An entry that is already there is still fine.
	if err := pulled(p, "n0@"+digestOf("a")); err != nil {
		t.Fatalf("a recorded reference is refused: %v", err)
	}
	if got := recordedImages(t, rec); len(got) != maxImageRecordEntries {
		t.Fatalf("len = %d", len(got))
	}
}

// What is not a pinned reference, or cannot be written, is an error: the
// caller does not pull.
func TestRecordReportsWhatItCannotRecord(t *testing.T) {
	p, _ := newTestPruner(t, &fakeImages{})
	if err := pulled(p, "node:24"); err == nil {
		t.Error("a tag reference was recorded")
	}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p2, err := newImagePruner("http://127.0.0.1:1", http.DefaultClient, filepath.Join(blocked, "work-images.json"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := pulled(p2, "node@"+digestOf("a")); err == nil {
		t.Error("a record that cannot be written reported no error")
	}
}

func TestPruneRemovesOnlyRecordedAndNotKept(t *testing.T) {
	f := &fakeImages{}
	p, rec := newTestPruner(t, f)
	a, b, c := "node@"+digestOf("a"), "python@"+digestOf("b"), "registry.example.com/dockerhub/library/node@"+digestOf("a")
	pulled(p, a)
	pulled(p, b)
	pulled(p, c)
	// The Docker Hub node reference is kept in another spelling; its mirror
	// twin is a different reference and goes.
	res := p.Prune(context.Background(), []string{"docker.io/library/node@" + digestOf("a")})
	if res.Removed != 2 || res.Kept != 1 {
		t.Fatalf("res = %+v", res)
	}
	want := map[string]bool{
		"DELETE /images/docker.io/library/python@" + digestOf("b") + "?":                    true,
		"DELETE /images/registry.example.com/dockerhub/library/node@" + digestOf("a") + "?": true,
	}
	if len(f.deletes()) != 2 {
		t.Fatalf("requests = %v", f.requests)
	}
	for _, r := range f.deletes() {
		if !want[r] {
			t.Errorf("unexpected request %q (the DELETE must carry no query)", r)
		}
	}
	if got := recordedImages(t, rec); len(got) != 1 || got[0] != "docker.io/library/node@"+digestOf("a") {
		t.Fatalf("record = %v", got)
	}
}

func TestPruneStatuses(t *testing.T) {
	d := digestOf("a")
	path := "DELETE /images/docker.io/library/node@" + d
	cases := []struct {
		name      string
		statuses  []int
		removed   int
		kept      int
		remaining int
	}{
		{"not found", []int{404}, 1, 0, 0},
		{"conflict", []int{409}, 0, 1, 1},
		{"server error", []int{500}, 0, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeImages{status: map[string][]int{path: tc.statuses}}
			p, rec := newTestPruner(t, f)
			pulled(p, "node@"+d)
			res := p.Prune(context.Background(), nil)
			if res.Removed != tc.removed || res.Kept != tc.kept {
				t.Fatalf("res = %+v", res)
			}
			if got := recordedImages(t, rec); len(got) != tc.remaining {
				t.Fatalf("record = %v", got)
			}
		})
	}
}

func TestPruneRetriesAfterConflict(t *testing.T) {
	d := digestOf("a")
	f := &fakeImages{status: map[string][]int{"DELETE /images/docker.io/library/node@" + d: {409, 200}}}
	p, rec := newTestPruner(t, f)
	pulled(p, "node@"+d)
	if res := p.Prune(context.Background(), nil); res.Removed != 0 || res.Kept != 1 {
		t.Fatalf("first: %+v", res)
	}
	if res := p.Prune(context.Background(), nil); res.Removed != 1 || res.Kept != 0 {
		t.Fatalf("second: %+v", res)
	}
	if got := recordedImages(t, rec); len(got) != 0 {
		t.Fatalf("record = %v", got)
	}
	if len(f.deletes()) != 2 {
		t.Fatalf("requests = %v", f.requests)
	}
}

func TestPruneCancelledContextDoesNothing(t *testing.T) {
	f := &fakeImages{}
	p, rec := newTestPruner(t, f)
	pulled(p, "node@"+digestOf("a"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res := p.Prune(ctx, nil); res.Removed != 0 || res.Kept != 0 {
		t.Fatalf("res = %+v", res)
	}
	if len(f.requests) != 0 || len(recordedImages(t, rec)) != 1 {
		t.Fatalf("requests = %v", f.requests)
	}
}

func TestPruneMalformedRecordRemovesNothing(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":      "not json",
		"wrong schema": `{"schema":2,"images":["docker.io/library/node@` + digestOf("a") + `"]}`,
		"too large":    `{"schema":1,"images":[],"pad":"` + strings.Repeat("x", maxImageRecordBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeImages{}
			p, rec := newTestPruner(t, f)
			if err := os.MkdirAll(filepath.Dir(rec), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(rec, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := p.Prune(context.Background(), nil); res.Removed != 0 {
				t.Fatalf("res = %+v", res)
			}
			if len(f.requests) != 0 {
				t.Fatalf("requests = %v", f.requests)
			}
			// A later Record rewrites the file.
			pulled(p, "node@"+digestOf("b"))
			if got := recordedImages(t, rec); len(got) != 1 {
				t.Fatalf("record = %v", got)
			}
		})
	}
}

func TestPruneMissingRecordIsEmpty(t *testing.T) {
	f := &fakeImages{}
	p, _ := newTestPruner(t, f)
	if res := p.Prune(context.Background(), nil); res != (PruneResult{}) || len(f.requests) != 0 {
		t.Fatalf("res = %+v, requests = %v", res, f.requests)
	}
}

func TestRecordFilePermissions(t *testing.T) {
	p, rec := newTestPruner(t, &fakeImages{})
	pulled(p, "node@"+digestOf("a"))
	fi, err := os.Stat(rec)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(rec))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v", di.Mode().Perm())
	}
	ents, _ := os.ReadDir(filepath.Dir(rec))
	if len(ents) != 1 {
		t.Errorf("leftover files: %v", ents)
	}
}

func TestPruneInspectGuards(t *testing.T) {
	d := digestOf("a")
	ref := "docker.io/library/node@" + d
	other := "mirror.example.com/node@" + d
	cases := []struct {
		name    string
		status  map[string][]int
		inspect string
		keep    []string
		want    PruneResult
		deleted bool
		recLen  int
	}{
		{"untagged", nil, "", nil, PruneResult{Removed: 1}, true, 0},
		{"digest listed among RepoTags only", nil, `{"RepoTags":["node@` + d + `"],"RepoDigests":["node@` + d + `"]}`, nil, PruneResult{Removed: 1}, true, 0},
		{"tagged", nil, `{"RepoTags":["node@` + d + `","node:latest"],"RepoDigests":["node@` + d + `"]}`, nil, PruneResult{Released: 1}, false, 0},
		{"inspect not found", map[string][]int{"GET /images/" + ref + "/json": {404}}, "", nil, PruneResult{Removed: 1}, false, 0},
		{"inspect error", map[string][]int{"GET /images/" + ref + "/json": {500}}, "", nil, PruneResult{Kept: 1}, false, 1},
		{"other digest reference kept", nil, `{"RepoTags":[],"RepoDigests":["node@` + d + `","` + other + `"]}`, []string{other}, PruneResult{Kept: 1}, false, 1},
		{"other digest reference not kept", nil, `{"RepoTags":[],"RepoDigests":["node@` + d + `","` + other + `"]}`, nil, PruneResult{Removed: 1}, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeImages{status: tc.status}
			if tc.inspect != "" {
				f.inspect = map[string]string{"/images/" + ref: tc.inspect}
			}
			p, rec := newTestPruner(t, f)
			pulled(p, "node@"+d)
			if res := p.Prune(context.Background(), tc.keep); res != tc.want {
				t.Fatalf("res = %+v, want %+v", res, tc.want)
			}
			dl := f.deletes()
			if tc.deleted != (len(dl) == 1) {
				t.Fatalf("deletes = %v", dl)
			}
			if tc.deleted && !strings.HasSuffix(dl[0], "@"+d+"?") {
				t.Errorf("DELETE has a query string: %v", dl)
			}
			for _, r := range f.requests {
				if !strings.HasPrefix(r, "DELETE ") && !(strings.HasPrefix(r, "GET ") && strings.Contains(r, "/json?")) {
					t.Errorf("unexpected request %q", r)
				}
			}
			if got := recordedImages(t, rec); len(got) != tc.recLen {
				t.Fatalf("record = %v", got)
			}
		})
	}
}

// A reservation whose pull never finished says nothing about an image that is
// found under the reference later: somebody else may have pulled it. Such a
// reference is dropped from the record and the daemon is not asked to remove
// anything.
func TestPruneDoesNotRemoveWhatWasOnlyReserved(t *testing.T) {
	f := &fakeImages{} // the daemon holds an image under every reference
	p, rec := newTestPruner(t, f)
	ref := "node@" + digestOf("a")
	if err := p.Reserve(ref); err != nil {
		t.Fatal(err)
	}
	// The pull failed; the reservation stays while the table still names it.
	if res := p.Prune(context.Background(), []string{ref}); res != (PruneResult{}) {
		t.Fatalf("res = %+v", res)
	}
	if got := pendingImages(t, rec); len(got) != 1 {
		t.Fatalf("pending = %v", got)
	}
	// Somebody else pulls the same reference; the table moves on.
	res := p.Prune(context.Background(), nil)
	if res.Unfinished != 1 || res.Removed != 0 || len(f.requests) != 0 {
		t.Fatalf("res = %+v, requests = %v", res, f.requests)
	}
	if len(recordedImages(t, rec)) != 0 || len(pendingImages(t, rec)) != 0 {
		t.Fatalf("the reservation is still recorded")
	}

	// A later pull of this installation that finishes is its own image.
	if err := p.Reserve(ref); err != nil {
		t.Fatal(err)
	}
	p.Confirm(ref)
	if len(pendingImages(t, rec)) != 0 || len(recordedImages(t, rec)) != 1 {
		t.Fatalf("after the pull: pulled %v, pending %v", recordedImages(t, rec), pendingImages(t, rec))
	}
	if res := p.Prune(context.Background(), nil); res.Removed != 1 {
		t.Fatalf("res = %+v", res)
	}
}

// A reservation counts against the size of the record, and a confirmation of
// something that was not reserved tracks nothing.
func TestReserveAndConfirm(t *testing.T) {
	p, rec := newTestPruner(t, &fakeImages{})
	var pending []string
	for i := 0; i < maxImageRecordEntries; i++ {
		pending = append(pending, fmt.Sprintf("docker.io/library/n%d@%s", i, digestOf("a")))
	}
	if err := p.save(imageState{pending: pending}); err != nil {
		t.Fatal(err)
	}
	if err := p.Reserve("node@" + digestOf("b")); err == nil {
		t.Fatal("a record full of reservations took another one")
	}

	p2, rec2 := newTestPruner(t, &fakeImages{})
	p2.Confirm("node@" + digestOf("c"))
	if _, err := os.Stat(rec2); err == nil && (len(recordedImages(t, rec2)) != 0 || len(pendingImages(t, rec2)) != 0) {
		t.Fatal("a reference that was not reserved is tracked")
	}
	_ = rec
}
