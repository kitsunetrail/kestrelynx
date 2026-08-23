package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(srv *httptest.Server) *Client {
	return newClient(srv.URL, srv.Client())
}

// validID1 / validID2 are two distinct, well-formed OCI image config digests
// used across the identity tests below.
const (
	validID1 = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	validID2 = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
)

func TestRunningImages_DedupesAndSorts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/json" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[
			{"Id":"a","Image":"nginx:1.25","ImageID":"` + validID1 + `","Names":["/web1"]},
			{"Id":"b","Image":"nginx:1.25","ImageID":"` + validID1 + `","Names":["/web2"]},
			{"Id":"c","Image":"redis:7.0","ImageID":"` + validID2 + `","Names":["/cache"]},
			{"Id":"d","Image":"postgres:16","ImageID":"` + validID2 + `","Names":["/db"]}
		]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	want := []RunningImage{
		{Ref: "nginx:1.25", ContentID: validID1},
		{Ref: "postgres:16", ContentID: validID2},
		{Ref: "redis:7.0", ContentID: validID2},
	}
	if len(imgs) != len(want) {
		t.Fatalf("got %+v, want %+v", imgs, want)
	}
	for i := range want {
		if imgs[i] != want[i] {
			t.Errorf("imgs[%d] = %+v, want %+v (sorted unique by Ref then ContentID)", i, imgs[i], want[i])
		}
	}
}

func TestRunningImages_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	if len(imgs) != 0 {
		t.Errorf("got %v, want empty", imgs)
	}
}

func TestRunningImages_SkipsBlankImage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Id":"a","Image":""},{"Id":"b","Image":"alpine:3.20","ImageID":"` + validID1 + `"}]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	want := RunningImage{Ref: "alpine:3.20", ContentID: validID1}
	if len(imgs) != 1 || imgs[0] != want {
		t.Errorf("got %+v, want [%+v]", imgs, want)
	}
}

func TestRunningImages_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	if _, err := newTestClient(srv).RunningImages(context.Background()); err == nil {
		t.Fatal("expected error on 500")
	}
}

// --- identity boundary validation ---

func TestRunningImages_SameRefSameContentID_OneEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"Id":"a","Image":"nginx:1.25","ImageID":"` + validID1 + `"},
			{"Id":"b","Image":"nginx:1.25","ImageID":"` + validID1 + `"}
		]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("got %+v, want 1 entry (same ref, same content)", imgs)
	}
	if imgs[0].ContentID != validID1 {
		t.Errorf("ContentID = %q, want %q", imgs[0].ContentID, validID1)
	}
}

func TestRunningImages_SameRefDifferentContentID_TwoEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"Id":"a","Image":"nginx:1.25","ImageID":"` + validID1 + `"},
			{"Id":"b","Image":"nginx:1.25","ImageID":"` + validID2 + `"}
		]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	if len(imgs) != 2 {
		t.Fatalf("got %+v, want 2 entries (same ref, distinct content, not merged)", imgs)
	}
	if imgs[0].Ref != "nginx:1.25" || imgs[1].Ref != "nginx:1.25" {
		t.Errorf("both entries should keep Ref %q, got %+v", "nginx:1.25", imgs)
	}
	if imgs[0].ContentID == imgs[1].ContentID {
		t.Errorf("ContentIDs must differ, got %+v", imgs)
	}
}

func TestRunningImages_MissingImageID_Unresolved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Id":"a","Image":"alpine:3.20"}]`))
	}))
	defer srv.Close()

	imgs, err := newTestClient(srv).RunningImages(context.Background())
	if err != nil {
		t.Fatalf("RunningImages: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("got %+v, want 1 entry", imgs)
	}
	if imgs[0].ContentID != "" {
		t.Errorf("ContentID = %q, want empty (ImageID missing)", imgs[0].ContentID)
	}
	if imgs[0].RawImageID != "" {
		t.Errorf("RawImageID = %q, want empty (nothing to hold when ImageID is empty)", imgs[0].RawImageID)
	}
}

func TestRunningImages_MalformedImageID_UnresolvedButRawKept(t *testing.T) {
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
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`[{"Id":"a","Image":"alpine:3.20","ImageID":"` + tc.imageID + `"}]`))
			}))
			defer srv.Close()

			imgs, err := newTestClient(srv).RunningImages(context.Background())
			if err != nil {
				t.Fatalf("RunningImages: %v", err)
			}
			if len(imgs) != 1 {
				t.Fatalf("got %+v, want 1 entry", imgs)
			}
			if imgs[0].ContentID != "" {
				t.Errorf("ContentID = %q, want empty (malformed ImageID must not be normalized or guessed)", imgs[0].ContentID)
			}
			if imgs[0].RawImageID != tc.imageID {
				t.Errorf("RawImageID = %q, want raw value %q kept for diagnostics", imgs[0].RawImageID, tc.imageID)
			}
		})
	}
}
