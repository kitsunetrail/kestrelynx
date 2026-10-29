package registry

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// askedSmallPages reports whether any tag listing request asked for 1000 tags.
func askedSmallPages(hits []string) bool {
	for _, h := range hits {
		u, err := url.Parse(h)
		if err == nil && strings.HasSuffix(u.Path, "/tags/list") && u.Query().Get("n") == "1000" {
			return true
		}
	}
	return false
}

// A whole listing asks for large pages, and a registry that refuses that size
// is asked again with pages of 1000.
func TestListTagsPageSizeAndFallback(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("n") {
		case "1000":
			if r.URL.Query().Get("last") == "" {
				tagPage([]string{"1.0.0"}, "/v2/team/app/tags/list?n=1000&last=1.0.0", w)
				return
			}
			tagPage([]string{"2.0.0"}, "", w)
		default:
			http.Error(w, `{"errors":[{"code":"PAGINATION_NUMBER_INVALID"}]}`, http.StatusBadRequest)
		}
	})
	l, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	if err != nil || !reflect.DeepEqual(l.Tags, []string{"1.0.0", "2.0.0"}) || l.Truncated || l.Pages != 3 {
		t.Fatalf("list = %+v, %v; want both pages after the refused one, 3 requests", l, err)
	}
	if hits := f.hits(); len(hits) == 0 || !strings.Contains(hits[0], "n=10000") || !askedSmallPages(hits) {
		t.Errorf("requests = %v; want the large page size first, then 1000", hits)
	}

	// Only the first page falls back, and only from a 400.
	g := newFakeRegistry(t)
	g.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	if _, err := g.client(Options{}).ListTags(context.Background(), g.repo("team/app")); err == nil || askedSmallPages(g.hits()) {
		t.Errorf("err = %v, hits %v; a 503 is not a refused page size", err, g.hits())
	}
}

// A 400 from the token service, or on a later page, is not a refused page
// size: the listing is not asked again.
func TestListTagsFallbackOnlyForTheFirstListingPage(t *testing.T) {
	f := newFakeRegistry(t)
	f.tokenStatus = http.StatusBadRequest
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) { tagPage([]string{"1.0.0"}, "", w) })
	_, err := f.client(Options{}).ListTags(context.Background(), f.repo("team/app"))
	var status *StatusError
	if !errors.As(err, &status) || status.Status != http.StatusBadRequest || askedSmallPages(f.hits()) {
		t.Errorf("err = %v, hits %v; want the token service's 400 and no second listing", err, f.hits())
	}

	g := newFakeRegistry(t)
	g.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("last") == "" {
			tagPage([]string{"1.0.0"}, "/v2/team/app/tags/list?n=10000&last=1.0.0", w)
			return
		}
		http.Error(w, "bad", http.StatusBadRequest)
	})
	if l, err := g.client(Options{}).ListTags(context.Background(), g.repo("team/app")); !errors.As(err, &status) || l.Pages != 2 {
		t.Errorf("list = %+v, err = %v; a 400 on the second page is an error", l, err)
	}

	// With one page allowed, the refused request uses it up and the listing is
	// cut short rather than failed.
	h := newFakeRegistry(t)
	h.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("n") != "1000" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		tagPage([]string{"1.0.0"}, "", w)
	})
	if l, err := h.client(Options{}).ListTagsUpTo(context.Background(), h.repo("team/app"), 1); err != nil || !l.Truncated || l.Pages != 1 {
		t.Errorf("list = %+v, err = %v", l, err)
	}
}

// Tag listings wait longer than other requests: one listing of a repository
// with tens of thousands of tags can take most of a minute.
func TestTagListingsHaveTheirOwnTimeout(t *testing.T) {
	f := newFakeRegistry(t)
	f.route("/v2/team/app/tags/list", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		tagPage([]string{"1.0.0"}, "", w)
	})
	c := f.client(Options{Timeout: 50 * time.Millisecond, TagTimeout: 5 * time.Second})
	if _, err := c.ListTags(context.Background(), f.repo("team/app")); err != nil {
		t.Errorf("whole listing: %v", err)
	}
	if _, err := c.ListTagsAfter(context.Background(), f.repo("team/app"), "", 10); err != nil {
		t.Errorf("listing from a position: %v", err)
	}
	if New(Options{}).opts.TagTimeout != defaultTagTimeout || defaultTagTimeout < time.Minute {
		t.Errorf("default tag timeout = %v", New(Options{}).opts.TagTimeout)
	}
	// Other requests keep the ordinary timeout.
	f.serveManifest("team/app", mediaOCIManifest, `{}`, "slow")
	f.route("/v2/team/app/manifests/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	})
	if _, err := c.Resolve(context.Background(), f.repo("team/app"), "slow", linuxAMD64); !errors.Is(err, ErrTimeout) {
		t.Errorf("manifest request: %v; want the ordinary timeout", err)
	}
}
