package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// slackFake is a minimal Slack Web API double for chat.postMessage and
// chat.getPermalink.
type slackFake struct {
	mu        sync.Mutex
	posts     []map[string]any // decoded chat.postMessage bodies, in order
	permCalls int
	failPosts int  // fail this many chat.postMessage calls with ok:false
	failPerm  bool // always fail chat.getPermalink
	srv       *httptest.Server
}

func newSlackFake(t *testing.T) *slackFake {
	t.Helper()
	f := &slackFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/chat.postMessage", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if f.failPosts > 0 {
			f.failPosts--
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "fatal_error"})
			return
		}
		f.posts = append(f.posts, body)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": tsFor(len(f.posts))})
	})
	mux.HandleFunc("/chat.getPermalink", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.permCalls++
		if f.failPerm {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "message_not_found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"permalink": "https://example.slack.com/archives/C1/p" + r.URL.Query().Get("message_ts"),
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func tsFor(n int) string {
	return "1000." + strings.Repeat("0", 5) + string(rune('0'+n))
}

func (f *slackFake) notifier() SlackAPINotifier {
	return SlackAPINotifier{
		Token:   "xoxb-test",
		Channel: "C1",
		BaseURL: f.srv.URL,
		Sleep:   func(time.Duration) {},
	}
}

func (f *slackFake) text(i int) string {
	s, _ := f.posts[i]["text"].(string)
	return s
}

func TestSlackAPINotifier_PostsThreadAndReportsRef(t *testing.T) {
	f := newSlackFake(t)
	res := &ThreadResult{}
	m := Message{Report: triageReport(), Thread: true, Result: res}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) < 2 {
		t.Fatalf("expected summary + thread reply, got %d post(s)", len(f.posts))
	}
	if !strings.Contains(f.text(0), "Full report in this message's thread") {
		t.Errorf("summary missing thread pointer:\n%s", f.text(0))
	}
	summaryTS := tsFor(1)
	for i, p := range f.posts[1:] {
		if p["thread_ts"] != summaryTS {
			t.Errorf("reply %d thread_ts = %v, want %s", i, p["thread_ts"], summaryTS)
		}
	}
	if !strings.Contains(f.text(1), "Full report —") {
		t.Errorf("thread reply missing report header:\n%s", f.text(1))
	}
	want := state.ReportRef{Channel: "C1", TS: summaryTS, Permalink: "https://example.slack.com/archives/C1/p" + summaryTS}
	if res.Ref != want {
		t.Errorf("Result.Ref = %+v, want %+v", res.Ref, want)
	}
}

func TestSlackAPINotifier_QuietDayLinksLastReport(t *testing.T) {
	f := newSlackFake(t)
	res := &ThreadResult{}
	ref := &state.ReportRef{Channel: "C1", TS: "999.1", Permalink: "https://example.slack.com/archives/C1/p9991"}
	m := Message{Report: triageReport(), Diff: &state.Diff{}, LastReport: ref, Result: res}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) != 1 {
		t.Fatalf("quiet day must not post a thread, got %d post(s)", len(f.posts))
	}
	if !strings.Contains(f.text(0), "Last full report → <"+ref.Permalink) {
		t.Errorf("summary missing last-report link:\n%s", f.text(0))
	}
	if res.Ref.TS != "" {
		t.Errorf("no thread posted, Result must stay zero: %+v", res.Ref)
	}
}

func TestSlackAPINotifier_MissingRefForcesThread(t *testing.T) {
	// First run in diff mode (no stored ref): even a no-changes day posts the
	// full thread so a link exists afterwards (spec edge case 1).
	f := newSlackFake(t)
	m := Message{Report: triageReport(), Diff: &state.Diff{}, Result: &ThreadResult{}}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) < 2 {
		t.Fatalf("missing ref must force a thread post, got %d post(s)", len(f.posts))
	}
}

func TestSlackAPINotifier_ChannelChangeInvalidatesRef(t *testing.T) {
	// Stored ref points at another channel (spec edge case 2): ignore the
	// link and post a fresh thread.
	f := newSlackFake(t)
	ref := &state.ReportRef{Channel: "C-OLD", TS: "999.1", Permalink: "https://example.slack.com/archives/C-OLD/p9991"}
	m := Message{Report: triageReport(), Diff: &state.Diff{}, LastReport: ref, Result: &ThreadResult{}}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) < 2 {
		t.Fatalf("stale-channel ref must force a thread post, got %d post(s)", len(f.posts))
	}
	if strings.Contains(f.text(0), "Last full report") {
		t.Errorf("summary must not link a report in another channel:\n%s", f.text(0))
	}
}

func TestSlackAPINotifier_RetriesTransientFailure(t *testing.T) {
	f := newSlackFake(t)
	f.failPosts = 1 // first attempt of the summary fails, retry succeeds
	m := Message{Report: triageReport(), Thread: true, Result: &ThreadResult{}}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send should recover from a transient failure: %v", err)
	}
}

func TestSlackAPINotifier_PermalinkFailureIsAnError(t *testing.T) {
	f := newSlackFake(t)
	f.failPerm = true
	res := &ThreadResult{}
	m := Message{Report: triageReport(), Thread: true, Result: res}
	if err := f.notifier().Send(context.Background(), m); err == nil {
		t.Fatal("expected an error when the permalink lookup fails")
	}
	if res.Ref.TS != "" {
		t.Errorf("failed thread flow must not report a ref: %+v", res.Ref)
	}
	if f.permCalls != apiAttempts {
		t.Errorf("permalink lookup attempts = %d, want %d", f.permCalls, apiAttempts)
	}
}

func TestSlackAPINotifier_ThreadFailureLeavesRefUnset(t *testing.T) {
	f := newSlackFake(t)
	res := &ThreadResult{}
	m := Message{Report: triageReport(), Thread: true, Result: res}
	n := f.notifier()
	// Let the summary through, then fail every reply attempt. The first Sleep
	// call happens after the summary post and before the first thread reply.
	n.Sleep = func(time.Duration) {
		f.mu.Lock()
		f.failPosts = 100
		f.mu.Unlock()
	}
	if err := n.Send(context.Background(), m); err == nil {
		t.Fatal("expected an error when thread replies keep failing")
	}
	if res.Ref.TS != "" {
		t.Errorf("failed thread post must not report a ref: %+v", res.Ref)
	}
}
