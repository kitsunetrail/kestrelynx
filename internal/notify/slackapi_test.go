package notify

import (
	"context"
	"encoding/json"
	"fmt"
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
	mu          sync.Mutex
	posts       []map[string]any // decoded chat.postMessage bodies, in order
	permCalls   int
	failPosts   int  // fail this many chat.postMessage calls with ok:false
	failAfter   int  // when > 0, fail every post once this many succeeded
	failPerm    bool // always fail chat.getPermalink
	rate429     int  // answer this many chat.postMessage calls with 429
	retryAfter  string
	postAttempt int
	srv         *httptest.Server
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
		f.postAttempt++
		if f.rate429 > 0 {
			f.rate429--
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if f.failPosts > 0 || (f.failAfter > 0 && len(f.posts) >= f.failAfter) {
			if f.failPosts > 0 {
				f.failPosts--
			}
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
	return fmt.Sprintf("1000.%06d", n)
}

func (f *slackFake) notifier() SlackAPINotifier {
	return SlackAPINotifier{
		Token:   "xoxb-test",
		Channel: "C1",
		BaseURL: f.srv.URL,
		Sleep:   func(time.Duration) {},
	}
}

// text is post i's fallback text.
func (f *slackFake) text(i int) string {
	s, _ := f.posts[i]["text"].(string)
	return s
}

// blocks are post i's decoded blocks.
func (f *slackFake) blocks(i int) []map[string]any {
	raw, _ := f.posts[i]["blocks"].([]any)
	out := make([]map[string]any, len(raw))
	for j, b := range raw {
		out[j], _ = b.(map[string]any)
	}
	return out
}

// blockText is the text of every block of post i, newline-joined.
func (f *slackFake) blockText(i int) string {
	var parts []string
	for _, b := range f.blocks(i) {
		if t, ok := b["text"].(map[string]any); ok {
			parts = append(parts, t["text"].(string))
		}
		if els, ok := b["elements"].([]any); ok {
			for _, e := range els {
				parts = append(parts, e.(map[string]any)["text"].(string))
			}
		}
	}
	return strings.Join(parts, "\n")
}

// footer is the text of post i's last block when it is a context, else "".
func (f *slackFake) footer(i int) string {
	bs := f.blocks(i)
	if len(bs) == 0 || bs[len(bs)-1]["type"] != "context" {
		return ""
	}
	return bs[len(bs)-1]["elements"].([]any)[0].(map[string]any)["text"].(string)
}

// recordingNotifier returns a notifier whose pauses are recorded.
func (f *slackFake) recordingNotifier(sleeps *[]time.Duration) SlackAPINotifier {
	n := f.notifier()
	n.Sleep = func(d time.Duration) { *sleeps = append(*sleeps, d) }
	return n
}

func TestSlackAPINotifier_PostsThreadAndReportsRef(t *testing.T) {
	f := newSlackFake(t)
	res := &ThreadResult{}
	m := Message{Report: triageReport(), Thread: true, Result: res}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) < 2 {
		t.Fatalf("expected channel message + thread reply, got %d post(s)", len(f.posts))
	}
	for i, p := range f.posts {
		if p["channel"] != "C1" || p["unfurl_links"] != false {
			t.Errorf("post %d channel/unfurl_links = %v/%v", i, p["channel"], p["unfurl_links"])
		}
		if f.text(i) == "" || len(f.blocks(i)) == 0 {
			t.Errorf("post %d must carry both text and blocks: %v", i, p)
		}
	}
	if got := f.footer(0); !strings.Contains(got, "Everything open now is in this message's thread") {
		t.Errorf("channel message missing the thread notice, footer = %q", got)
	}
	summaryTS := tsFor(1)
	if _, has := f.posts[0]["thread_ts"]; has {
		t.Errorf("the channel message must be top-level, got thread_ts %v", f.posts[0]["thread_ts"])
	}
	for i, p := range f.posts[1:] {
		if p["thread_ts"] != summaryTS {
			t.Errorf("reply %d thread_ts = %v, want %s", i, p["thread_ts"], summaryTS)
		}
	}
	if !strings.Contains(f.blockText(1), "Everything open now —") {
		t.Errorf("thread reply missing report header:\n%s", f.blockText(1))
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
	if got := f.footer(0); !strings.Contains(got, "Everything open as of the last report → <"+ref.Permalink) {
		t.Errorf("channel message missing the last-report link, footer = %q", got)
	}
	if res.Ref.TS != "" {
		t.Errorf("no thread posted, Result must stay zero: %+v", res.Ref)
	}
}

// TestSlackAPINotifier_PostsThreadAndReportsRef_Japanese is the ja
// counterpart of the thread-posted-day scenario: the footer closing the first
// channel message must come from the Japanese dictionary too.
func TestSlackAPINotifier_PostsThreadAndReportsRef_Japanese(t *testing.T) {
	f := newSlackFake(t)
	res := &ThreadResult{}
	m := Message{Report: triageReport(), Thread: true, Result: res}
	n := f.notifier()
	n.Language = LanguageJA
	if err := n.Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) < 2 {
		t.Fatalf("expected channel message + thread reply, got %d post(s)", len(f.posts))
	}
	wantFooter := strings.Trim(strings.TrimSpace(jaMessages.ThreadPostedNotice), "_")
	if got := f.footer(0); got != wantFooter {
		t.Errorf("footer = %q, want the Japanese thread pointer %q", got, wantFooter)
	}
	for _, english := range []string{
		"Everything open now is in this message's thread",
		"Everything currently open",
		"images scanned",
		"scan results for",
	} {
		if strings.Contains(f.blockText(0), english) || strings.Contains(f.text(0), english) {
			t.Errorf("channel message leaked English text %q:\n%s", english, f.blockText(0))
		}
	}
	if strings.Contains(f.blockText(1), "Everything open now —") {
		t.Errorf("thread reply leaked the English report header:\n%s", f.blockText(1))
	}
}

// TestSlackAPINotifier_QuietDayLinksLastReport_Japanese is the ja counterpart
// of the last-report-link day, including the link label ("thread" /
// "スレッド") itself.
func TestSlackAPINotifier_QuietDayLinksLastReport_Japanese(t *testing.T) {
	f := newSlackFake(t)
	res := &ThreadResult{}
	ref := &state.ReportRef{Channel: "C1", TS: "999.1", Permalink: "https://example.slack.com/archives/C1/p9991"}
	m := Message{Report: triageReport(), Diff: &state.Diff{}, LastReport: ref, Result: res}
	n := f.notifier()
	n.Language = LanguageJA
	if err := n.Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) != 1 {
		t.Fatalf("quiet day must not post a thread, got %d post(s)", len(f.posts))
	}
	if got := f.footer(0); !strings.Contains(got, "→ <"+ref.Permalink+"|スレッド>") {
		t.Errorf("channel message missing the Japanese last-report link, footer = %q", got)
	}
	for _, english := range []string{
		"Everything open as of the last report",
		"|thread>",
		"Everything currently open",
		"scan results for",
	} {
		if strings.Contains(f.blockText(0), english) || strings.Contains(f.text(0), english) {
			t.Errorf("channel message leaked English text %q:\n%s", english, f.blockText(0))
		}
	}
}

// With neither a thread nor a valid last report, the channel message has no
// footer at all.
func TestSlackAPINotifier_NoFooterWithoutThreadOrLink(t *testing.T) {
	f := newSlackFake(t)
	m := Message{Report: triageReport(), Result: &ThreadResult{}} // full mode, Thread false, no LastReport
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) != 1 {
		t.Fatalf("no thread expected, got %d post(s)", len(f.posts))
	}
	if got := f.footer(0); strings.Contains(got, "thread") || strings.Contains(got, "last report") {
		t.Errorf("unexpected footer %q", got)
	}
}

func TestSlackAPINotifier_MissingRefForcesThread(t *testing.T) {
	// First run in diff mode (no stored ref): even a no-changes day posts the
	// full thread so a link exists afterwards.
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
	// Stored ref points at another channel: ignore the link and post a fresh
	// thread.
	f := newSlackFake(t)
	ref := &state.ReportRef{Channel: "C-OLD", TS: "999.1", Permalink: "https://example.slack.com/archives/C-OLD/p9991"}
	m := Message{Report: triageReport(), Diff: &state.Diff{}, LastReport: ref, Result: &ThreadResult{}}
	if err := f.notifier().Send(context.Background(), m); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.posts) < 2 {
		t.Fatalf("stale-channel ref must force a thread post, got %d post(s)", len(f.posts))
	}
	if strings.Contains(f.blockText(0), "Everything open as of the last report") {
		t.Errorf("channel message must not link a report in another channel:\n%s", f.blockText(0))
	}
}

func TestSlackAPINotifier_RetriesTransientFailure(t *testing.T) {
	f := newSlackFake(t)
	f.failPosts = 1 // first attempt of the channel message fails, retry succeeds
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
	// Let the channel message through, then fail every reply attempt. The
	// first pause happens after the channel message and before the first
	// thread reply.
	n.Sleep = func(time.Duration) {
		f.mu.Lock()
		f.failPosts = 100
		f.mu.Unlock()
	}
	err := n.Send(context.Background(), m)
	if err == nil {
		t.Fatal("expected an error when thread replies keep failing")
	}
	if !strings.Contains(err.Error(), "post thread reply 1/") {
		t.Errorf("error should name the failing reply: %v", err)
	}
	if res.Ref.TS != "" {
		t.Errorf("failed thread post must not report a ref: %+v", res.Ref)
	}
}

// A long full view spans several channel messages: they are posted in order,
// the first is the only one with the footer, the later ones are top-level and
// numbered, and the thread replies go under the FIRST channel message.
func TestSlackAPINotifier_MultiMessageChannelAndThreadUnderFirst(t *testing.T) {
	f := newSlackFake(t)
	res := &ThreadResult{}
	var sleeps []time.Duration
	n := f.recordingNotifier(&sleeps)
	r := bigReport(60, "")
	if err := n.Send(context.Background(), Message{Report: r, Thread: true, Result: res}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	channel := buildChannelMessages(Message{Report: r, Thread: true}, ChannelFooter{Kind: FooterThreadNotice}, enMessages, defaultRenderLimits)
	thread := buildThreadBlockMessages(r, Ages{}, enMessages, defaultRenderLimits)
	if len(channel) < 2 || len(thread) < 2 {
		t.Fatalf("fixture must span several messages: channel %d, thread %d", len(channel), len(thread))
	}
	if len(f.posts) != len(channel)+len(thread) {
		t.Fatalf("posts = %d, want %d channel + %d thread", len(f.posts), len(channel), len(thread))
	}
	first := tsFor(1)
	for i := range channel {
		if f.text(i) != channel[i].Text {
			t.Errorf("channel post %d text = %q, want %q", i, f.text(i), channel[i].Text)
		}
		if _, has := f.posts[i]["thread_ts"]; has {
			t.Errorf("channel post %d must be top-level", i)
		}
		if (f.footer(i) != "") != (i == 0) {
			t.Errorf("channel post %d footer = %q: only the first carries one", i, f.footer(i))
		}
	}
	for i := range thread {
		p := f.posts[len(channel)+i]
		if p["thread_ts"] != first {
			t.Errorf("thread reply %d thread_ts = %v, want the first channel message %s", i, p["thread_ts"], first)
		}
		if f.text(len(channel)+i) != thread[i].Text {
			t.Errorf("thread reply %d text mismatch", i)
		}
	}
	if len(sleeps) != len(f.posts)-1 {
		t.Errorf("pauses = %d, want one before every post but the first (%d)", len(sleeps), len(f.posts)-1)
	}
	for _, d := range sleeps {
		if d != threadPostGap {
			t.Errorf("pause = %v, want %v", d, threadPostGap)
		}
	}
	if res.Ref.TS != first || !strings.HasSuffix(res.Ref.Permalink, first) {
		t.Errorf("Result.Ref = %+v, want the first channel message %s", res.Ref, first)
	}
}

func TestSlackAPINotifier_Honors429RetryAfter(t *testing.T) {
	for _, c := range []struct {
		name, header string
		want         time.Duration
	}{
		{"seconds", "7", 7 * time.Second},
		{"capped", "100", maxRetryAfter},
		{"absent", "", time.Second},
		{"unreadable", "soon", time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSlackFake(t)
			f.rate429, f.retryAfter = 1, c.header
			var sleeps []time.Duration
			err := f.recordingNotifier(&sleeps).Send(context.Background(), Message{Report: triageReport(), Result: &ThreadResult{}})
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if len(f.posts) != 1 || len(sleeps) != 1 || sleeps[0] != c.want {
				t.Errorf("posts = %d, pauses = %v, want one post after a pause of %v", len(f.posts), sleeps, c.want)
			}
		})
	}
}

func TestSlackAPINotifier_MidwayFailureNamesTheMessageAndKeepsRefZero(t *testing.T) {
	f := newSlackFake(t)
	f.failAfter = 1 // the first channel message succeeds, the second never does
	res := &ThreadResult{}
	n := f.notifier()
	err := n.Send(context.Background(), Message{Report: bigReport(60, ""), Thread: true, Result: res})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "post summary 2/") {
		t.Errorf("error should name the failing channel message: %v", err)
	}
	if res.Ref != (state.ReportRef{}) {
		t.Errorf("Result.Ref must stay zero after a partial post: %+v", res.Ref)
	}
	if len(f.posts) != 1 {
		t.Errorf("nothing may be posted after the failure, got %d post(s)", len(f.posts))
	}
	if strings.Contains(err.Error(), "xoxb-test") {
		t.Errorf("the token leaked into the error: %v", err)
	}
}

func TestSlackAPINotifier_ErrorsNeverContainTheToken(t *testing.T) {
	const token = "xoxb-test-super-secret"
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead.Close()
	n := SlackAPINotifier{Token: token, Channel: "C1", BaseURL: dead.URL, Sleep: func(time.Duration) {}}
	err := n.Send(context.Background(), Message{Report: triageReport(), Result: &ThreadResult{}})
	if err == nil {
		t.Fatal("expected an error against a dead server")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("the token leaked into the error: %v", err)
	}

	f := newSlackFake(t)
	f.failPosts = 100
	n = f.notifier()
	n.Token = token
	if err := n.Send(context.Background(), Message{Report: triageReport(), Result: &ThreadResult{}}); err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("error = %v, want one without the token", err)
	}
}
