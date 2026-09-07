package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunningContainers_Pagination_TwoPages(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods",
		ok(envelope("page-2-token", loadFixture(t, "pod_running.json"))),
		ok(envelope("", loadFixture(t, "pod_no_node.json"))),
	)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("got %d containers, want 2 (one per page); requests: %v", len(cs), f.requests)
	}
	if !f.requestedPathPrefix("/api/v1/pods?limit=500&continue=page-2-token") {
		t.Errorf("second page request did not carry continue=page-2-token; requests: %v", f.requests)
	}
}

// TestRunningContainers_410_RestartsListFromScratch drives a 410 mid-list
// (after one page already succeeded) and checks that the restart truly
// starts over rather than resuming: the pre-410 page's container must be
// absent from the result, the post-restart pages' containers must both be
// present, and the restart's first request must carry no continue token
// (proving it re-listed from page 1, not from the stale one).
func TestRunningContainers_410_RestartsListFromScratch(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("",
		loadFixture(t, "node_amd64.json"),
		loadFixture(t, "node_arm64.json"),
	)))
	f.on("/api/v1/pods",
		// Attempt 1: page 1 succeeds with old data and a continue token
		// implying a page 2, but page 2 comes back 410.
		ok(envelope("stale-continue-token", loadFixture(t, "pod_running.json"))),
		scriptedResponse{status: http.StatusGone, body: []byte(`{}`)},
		// Restart: two fresh pages of different data, ending cleanly.
		ok(envelope("fresh-continue-token", loadFixture(t, "pod_mixed_arch_amd64.json"))),
		ok(envelope("", loadFixture(t, "pod_mixed_arch_arm64.json"))),
	)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}

	names := map[string]bool{}
	for _, ct := range cs {
		names[ct.Name] = true
	}
	if names["default/web-7f8c9d-abcde/web"] {
		t.Errorf("result must not contain the pre-410 page's container; got %v", cs)
	}
	for _, want := range []string{"default/multiarch-amd64-1/app", "default/multiarch-arm64-1/app"} {
		if !names[want] {
			t.Errorf("missing container %q from the post-restart pages; got %v", want, cs)
		}
	}
	if len(cs) != 2 {
		t.Errorf("got %d containers, want exactly 2 (no duplicate or stale entries); got %v", len(cs), cs)
	}
	if !f.requestedPathPrefix("/api/v1/pods?limit=500&continue=stale-continue-token") {
		t.Fatalf("test setup broken: expected the pre-410 continuation request to have been made")
	}
	// The restart's first request is the bare "/api/v1/pods?limit=500" with
	// no continue parameter — but that exact string is also a prefix of the
	// continuation request above, so distinguish by counting how many
	// requests to /api/v1/pods carried no "&continue=" at all.
	fresh := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, "/api/v1/pods") && !strings.Contains(r, "continue=") {
			fresh++
		}
	}
	if fresh != 2 {
		t.Errorf("got %d continue-less /api/v1/pods requests, want 2 (attempt 1 page 1, and the restart's page 1); requests: %v", fresh, f.requests)
	}
}

func TestRunningContainers_410_ExhaustsRestarts(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	// maxGoneRestarts allows 2 restarts (3 attempts total); a 4th 410 must
	// surface as an error rather than restarting forever.
	f.on("/api/v1/pods",
		scriptedResponse{status: http.StatusGone, body: []byte(`{}`)},
		scriptedResponse{status: http.StatusGone, body: []byte(`{}`)},
		scriptedResponse{status: http.StatusGone, body: []byte(`{}`)},
	)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error after exhausting 410 restarts, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

func TestRunningContainers_MidListFailure_NoPartialResult(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	// One page succeeds, then the resource fails permanently (enough 500s
	// to exhaust both the per-page retry budget and every 410-style
	// restart attempt, though this is a 500 not a 410).
	f.on("/api/v1/pods", append(
		[]scriptedResponse{ok(envelope("page-2-token", loadFixture(t, "pod_running.json")))},
		repeatedServerErrors(12)...,
	)...)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error when a later page fails permanently, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure (no partial listing), got %v", cs)
	}
}

func TestRunningContainers_NodeListFailure_NoPartialResult(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", repeatedServerErrors(12)...)
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_running.json"))))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error when the Node list fails, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

func TestRunningContainers_MidNamespaceFailure_NoPartialResult(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/namespaces/team-a/pods", ok(envelope("", loadFixture(t, "pod_running.json"))))
	f.on("/api/v1/namespaces/team-b/pods", repeatedServerErrors(12)...)
	srv := f.start()
	c := newTestClient(t, srv, []string{"team-a", "team-b"})

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error when one namespace's Pod list fails, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure (team-a's results must not leak through), got %v", cs)
	}
	if !f.requestedPathPrefix("/api/v1/namespaces/team-a/pods") {
		t.Fatalf("test setup broken: expected team-a to have been listed before the failure")
	}
}

func TestRunningContainers_ReplicaSetsListFailure_NoPartialResult(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_running.json"))))
	f.on("/apis/apps/v1/replicasets", repeatedServerErrors(12)...)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error when the ReplicaSet list fails, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

func TestRunningContainers_JobsListFailure_NoPartialResult(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_running.json"))))
	f.on("/apis/batch/v1/jobs", repeatedServerErrors(12)...)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error when the Job list fails, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

func TestRunningContainers_RetryableFailure_ExhaustsRetries(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", repeatedServerErrors(12)...)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

func TestRunningContainers_401_TokenRereadAndRetryOnce(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))

	tokenPath, err := writeTempToken(t, "old-token")
	if err != nil {
		t.Fatalf("write token: %v", err)
	}

	calls := 0
	f.onFunc("/api/v1/pods", func(w http.ResponseWriter, r *http.Request) {
		calls++
		auth := r.Header.Get("Authorization")
		switch calls {
		case 1:
			if auth != "Bearer old-token" {
				t.Errorf("first request Authorization = %q, want %q", auth, "Bearer old-token")
			}
			if err := os.WriteFile(tokenPath, []byte("new-token"), 0o600); err != nil {
				t.Fatalf("rotate token file: %v", err)
			}
			w.WriteHeader(http.StatusUnauthorized)
		case 2:
			if auth != "Bearer new-token" {
				t.Errorf("retry request Authorization = %q, want %q", auth, "Bearer new-token")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(envelope("", loadFixture(t, "pod_running.json")))
		default:
			t.Fatalf("unexpected %d-th request to /api/v1/pods; a single 401 must yield exactly one retry", calls)
		}
	})

	srv := f.start()
	c := newClient(srv.URL, srv.Client(), tokenPath, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 1 {
		t.Errorf("got %d containers, want 1", len(cs))
	}
	if calls != 2 {
		t.Errorf("pods endpoint called %d times, want 2 (initial 401 + one retry)", calls)
	}
}

func TestRunningContainers_401Twice_Errors(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods",
		scriptedResponse{status: http.StatusUnauthorized},
		scriptedResponse{status: http.StatusUnauthorized},
	)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error after a second 401, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

func TestRunningContainers_Namespaces_ScopedPaths(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	srv := f.start()
	c := newTestClient(t, srv, []string{"team-a", "team-b"})

	if _, err := c.RunningContainers(context.Background()); err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}

	wantPrefixes := []string{
		"/api/v1/namespaces/team-a/pods",
		"/api/v1/namespaces/team-b/pods",
		"/apis/apps/v1/namespaces/team-a/replicasets",
		"/apis/apps/v1/namespaces/team-b/replicasets",
		"/apis/batch/v1/namespaces/team-a/jobs",
		"/apis/batch/v1/namespaces/team-b/jobs",
	}
	for _, want := range wantPrefixes {
		if !f.requestedPathPrefix(want) {
			t.Errorf("missing request to %s; got requests %v", want, f.requests)
		}
	}
	if f.requestedPathPrefix("/api/v1/pods?") {
		t.Errorf("cluster-scoped /api/v1/pods must not be requested when namespaces is set; got requests %v", f.requests)
	}
	if !f.requestedPathPrefix("/api/v1/nodes") {
		t.Errorf("nodes must always be listed cluster-scoped; got requests %v", f.requests)
	}
}

func writeTempToken(t *testing.T, content string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	return path, os.WriteFile(path, []byte(content), 0o600)
}

// TestRunningContainers_RetryAfter_Respected proves the Retry-After header
// is actually read and honored end to end, not just that the retryable
// branch is taken: the test client's backoffBase is 1ms (transport_test's
// other retry tests rely on that to stay fast), so a delay near the
// requested 1s before the retry can only be explained by the header being
// used, not the exponential fallback.
func TestRunningContainers_RetryAfter_Respected(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))

	var firstAttempt time.Time
	calls := 0
	f.onFunc("/api/v1/pods", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			firstAttempt = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if elapsed := time.Since(firstAttempt); elapsed < 900*time.Millisecond {
			t.Errorf("retry happened after %v, want >= ~1s (Retry-After must be honored over the tiny test backoffBase)", elapsed)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(envelope("", loadFixture(t, "pod_running.json")))
	})

	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 1 {
		t.Errorf("got %d containers, want 1", len(cs))
	}
	if calls != 2 {
		t.Errorf("pods endpoint called %d times, want 2", calls)
	}
}

// TestBackoffDuration_RetryAfter unit-tests the Retry-After parsing rules in
// isolation (seconds form, HTTP-date form, and the exponential fallback for
// an absent or unparseable header) without paying for a real sleep.
func TestBackoffDuration_RetryAfter(t *testing.T) {
	const base = 500 * time.Millisecond

	if got := backoffDuration(base, 1, "2"); got != 2*time.Second {
		t.Errorf("seconds form: got %v, want 2s", got)
	}
	if got := backoffDuration(base, 1, "0"); got != 0 {
		t.Errorf("zero seconds: got %v, want 0", got)
	}
	if got := backoffDuration(base, 1, "not-a-number-or-date"); got != base {
		t.Errorf("unparseable Retry-After falls back to exponential: got %v, want %v", got, base)
	}
	if got := backoffDuration(base, 1, ""); got != base {
		t.Errorf("no Retry-After, attempt 1: got %v, want %v", got, base)
	}
	if got := backoffDuration(base, 2, ""); got != 2*base {
		t.Errorf("no Retry-After, attempt 2: got %v, want %v", got, 2*base)
	}

	future := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	if got := backoffDuration(base, 1, future); got < 2*time.Second || got > 4*time.Second {
		t.Errorf("HTTP-date form: got %v, want ~3s", got)
	}
}

// TestRunningContainers_ContextCanceled_StopsPromptly checks that an
// already-canceled context aborts the very first request without exhausting
// the transient-failure retry budget (which would otherwise treat a
// canceled context's Do() error like any other transport hiccup).
func TestRunningContainers_ContextCanceled_StopsPromptly(t *testing.T) {
	f := newFakeServer(t)
	srv := f.start()
	c := newTestClient(t, srv, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	cs, err := c.RunningContainers(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected an error for an already-canceled context, got containers %v", cs)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, does not wrap context.Canceled", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("RunningContainers took %v to stop after a canceled context, want a prompt return", elapsed)
	}
}

// TestRunningContainers_MalformedListResponse_Null_Errors and its {}
// counterpart pin the fix for a 200 response whose body doesn't have the
// shape of a Kubernetes List at all: json.Unmarshal happily decodes both
// `null` and `{}` into a zero-value envelope (empty Continue, empty Items),
// which the pre-fix code read as "an empty, complete page" — silently
// ending the list with whatever had already been collected treated as the
// full result.
func TestRunningContainers_MalformedListResponse_Null_Errors(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok([]byte(`null`)))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error for a `null` LIST body, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

func TestRunningContainers_MalformedListResponse_EmptyObject_Errors(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok([]byte(`{}`)))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("expected error for a `{}` LIST body, got containers %v", cs)
	}
	if cs != nil {
		t.Errorf("expected nil containers on failure, got %v", cs)
	}
}

// TestRunningContainers_EmptyListResponse_Succeeds is the positive control
// for the two tests above: a genuinely empty List (a real kind/apiVersion,
// items: []) must still succeed with zero containers, not be mistaken for a
// malformed response.
func TestRunningContainers_EmptyListResponse_Succeeds(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("")))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 0 {
		t.Errorf("got %d containers, want 0 for a genuinely empty list", len(cs))
	}
}

// readBodyLimited is the only guard between an oversized page body and
// unbounded memory use, so its boundary must hold exactly: a body at the
// limit is returned whole, one byte past it is rejected with
// errBodyTooLarge, and nothing about the reader's content changes either
// verdict.
func TestReadBodyLimited_Boundary(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		limit   int64
		wantErr bool
	}{
		{name: "under limit", body: "abc", limit: 4},
		{name: "exactly at limit", body: "abcd", limit: 4},
		{name: "one byte over limit", body: "abcde", limit: 4, wantErr: true},
		{name: "empty body", body: "", limit: 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readBodyLimited(strings.NewReader(c.body), c.limit)
			if c.wantErr {
				if !errors.Is(err, errBodyTooLarge) {
					t.Fatalf("err = %v, want errBodyTooLarge", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if string(got) != c.body {
				t.Errorf("body = %q, want %q", got, c.body)
			}
		})
	}
}

// roundTripperFunc adapts a function to http.RoundTripper so a test can
// serve responses without a network listener.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// truncatedBody yields a JSON prefix and then fails mid-read, the shape a
// connection dropped after headers produces on the client side.
type truncatedBody struct {
	data []byte
	read int
}

func (b *truncatedBody) Read(p []byte) (int, error) {
	if b.read < len(b.data) {
		n := copy(p, b.data[b.read:])
		b.read += n
		return n, nil
	}
	return 0, errors.New("unexpected connection reset mid-body")
}

func (b *truncatedBody) Close() error { return nil }

func newTokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A body that dies mid-read is a transient failure: the partial bytes are
// discarded and the same page is fetched again within the existing retry
// budget, succeeding once a complete body arrives.
func TestFetchList_BodyTruncatedMidRead_RetriedThenSucceeds(t *testing.T) {
	valid := string(envelope("", json.RawMessage(`{"metadata":{"name":"x"}}`)))
	attempts := 0
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    r,
		}
		if attempts == 1 {
			resp.Body = &truncatedBody{data: []byte(valid[:len(valid)/2])}
		} else {
			resp.Body = io.NopCloser(strings.NewReader(valid))
		}
		return resp, nil
	})
	c := newClient("https://unit.invalid", &http.Client{Transport: rt}, newTokenFile(t), nil)
	token := "test-token"

	items, err := fetchList[struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}](context.Background(), c, c.httpClient, &token, "/api/v1/things")
	if err != nil {
		t.Fatalf("fetchList: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2 (one truncated, one retried)", attempts)
	}
	if len(items) != 1 || items[0].Metadata.Name != "x" {
		t.Errorf("items = %+v, want the single item from the complete retry", items)
	}
}

// When every attempt dies mid-body, the retry budget is exhausted and the
// caller gets an error — never a partial list.
func TestFetchList_BodyTruncatedEveryRead_ExhaustsRetries(t *testing.T) {
	valid := string(envelope("", json.RawMessage(`{"metadata":{"name":"x"}}`)))
	attempts := 0
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       &truncatedBody{data: []byte(valid[:len(valid)/2])},
			Request:    r,
		}, nil
	})
	c := newClient("https://unit.invalid", &http.Client{Transport: rt}, newTokenFile(t), nil)
	token := "test-token"

	items, err := fetchList[struct{}](context.Background(), c, c.httpClient, &token, "/api/v1/things")
	if err == nil {
		t.Fatal("expected error once the retry budget is exhausted")
	}
	if items != nil {
		t.Errorf("items = %+v, want nil (no partial result)", items)
	}
	if want := maxRetries + 1; attempts != want {
		t.Errorf("attempts = %d, want %d (initial try plus full retry budget)", attempts, want)
	}
}
