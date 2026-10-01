package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSlackNotifier_Send(t *testing.T) {
	var gotBody string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := SlackNotifier{WebhookURL: srv.URL}
	if err := n.Send(context.Background(), Message{Report: sampleReport()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	// Slack expects a JSON object with the fallback "text" and the "blocks".
	var payload struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body not JSON: %v\n%s", err, gotBody)
	}
	if !strings.Contains(payload.Text, "KestreLynx") {
		t.Errorf("text missing header: %q", payload.Text)
	}
	if len(payload.Blocks) == 0 || payload.Blocks[0]["type"] != "section" {
		t.Errorf("body must carry blocks starting with a section: %s", gotBody)
	}
}

// TestSlackNotifier_Send_Japanese confirms SlackNotifier (the Incoming
// Webhook path, which can never thread or link a last report — see
// slackapi.go's own doc comment) forwards Language all the way into the
// body it posts.
func TestSlackNotifier_Send_Japanese(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := SlackNotifier{WebhookURL: srv.URL, Language: LanguageJA}
	if err := n.Send(context.Background(), Message{Report: sampleReport()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var payload struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body not JSON: %v\n%s", err, gotBody)
	}
	if !strings.Contains(payload.Text, "KestreLynx") {
		t.Errorf("text missing header: %q", payload.Text)
	}
	body := payload.Text + gotBody
	// "affected" is deliberately excluded: it's the scanner's own status
	// vocabulary (scanner.StatusAffected), shown verbatim like "will_not_fix"
	// — see messages.go's own doc comment on what stays untranslated.
	for _, english := range []string{"scan results for", "images scanned", "All clear"} {
		if strings.Contains(body, english) {
			t.Errorf("message leaked English wording %q: %s", english, body)
		}
	}
}

func TestSlackNotifier_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := SlackNotifier{WebhookURL: srv.URL}
	if err := n.Send(context.Background(), Message{Report: sampleReport()}); err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Webhook URLs are secrets (the Slack path is the credential), so errors must
// never contain them: not on a non-2xx response, not on transport failure, and
// not via url.Error text that net/http nests into its errors.
func TestSendErrors_DoNotLeakURL(t *testing.T) {
	const secret = "/services/T000/B000/supersecrettoken"

	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer status.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close() // connection refused from here on

	// Redirect whose Location cannot be parsed: the parse error quotes the
	// raw Location, so a Location echoing the secret must still be scrubbed.
	badRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "%zz"+secret)
		w.WriteHeader(http.StatusFound)
	}))
	defer badRedirect.Close()

	// Server that echoes the secret in the HTTP reason phrase.
	badReason := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, bufrw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		bufrw.WriteString("HTTP/1.1 500 oops" + secret + "\r\nContent-Length: 0\r\n\r\n")
		bufrw.Flush()
	}))
	defer badReason.Close()

	// Redirect that reflects the request's query string (where a generic
	// webhook may carry a signing secret) into an unparsable Location: a
	// substring-scrub of the URL would miss this partial reflection.
	reflectQuery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "%zz?"+r.URL.RawQuery)
		w.WriteHeader(http.StatusFound)
	}))
	defer reflectQuery.Close()

	// Transport returning a *url.Error, which Client.Do nests inside its own
	// *url.Error — the redaction must unwrap all levels.
	nested := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "post", URL: r.URL.String(), Err: errors.New("inner boom")}
	})}

	cases := []struct {
		name string
		n    Notifier
	}{
		{"slack status error", SlackNotifier{WebhookURL: status.URL + secret}},
		{"slack transport error", SlackNotifier{WebhookURL: dead.URL + secret}},
		{"webhook status error", WebhookNotifier{URL: status.URL + secret}},
		{"webhook transport error", WebhookNotifier{URL: dead.URL + secret}},
		{"malformed redirect location", SlackNotifier{WebhookURL: badRedirect.URL + secret}},
		{"query secret reflected in redirect", WebhookNotifier{URL: reflectQuery.URL + "/hook?sig=" + strings.TrimPrefix(secret, "/")}},
		{"secret in reason phrase", SlackNotifier{WebhookURL: badReason.URL + secret}},
		{"nested url.Error", SlackNotifier{WebhookURL: status.URL + secret, Client: nested}},
		{"request build error", SlackNotifier{WebhookURL: status.URL + secret + "\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.n.Send(context.Background(), Message{Report: sampleReport()})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if strings.Contains(err.Error(), "supersecrettoken") {
				t.Errorf("error leaks webhook URL: %v", err)
			}
		})
	}
}

// Redaction must not break error inspection: the original chain stays
// reachable through Unwrap.
func TestSendErrors_PreserveErrorsIs(t *testing.T) {
	const secret = "/services/T000/B000/supersecrettoken"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body: with unread body data the server never notices the
		// client going away, and this handler (and srv.Close) would hang.
		io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := SlackNotifier{WebhookURL: srv.URL + secret}.Send(ctx, Message{Report: sampleReport()})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks webhook URL: %v", err)
	}
}

func TestWebhookNotifier_Send(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := WebhookNotifier{URL: srv.URL}
	if err := n.Send(context.Background(), Message{Report: sampleReport()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if _, ok := got["summary"]; !ok {
		t.Errorf("posted body missing summary: %v", got)
	}
}

func TestMultiNotifier_SendsToAll(t *testing.T) {
	var hits int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})
	s1 := httptest.NewServer(handler)
	defer s1.Close()
	s2 := httptest.NewServer(handler)
	defer s2.Close()

	m := Multi(SlackNotifier{WebhookURL: s1.URL}, WebhookNotifier{URL: s2.URL})
	if err := m.Send(context.Background(), Message{Report: sampleReport()}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
}

// webhookRecorder is an Incoming Webhook double that records each posted body
// and can answer chosen calls with a status.
type webhookRecorder struct {
	mu     sync.Mutex
	bodies []map[string]any
	calls  int
	status map[int]int    // call number (1-based) -> status to answer
	after  map[int]string // call number -> Retry-After header
	srv    *httptest.Server
}

func newWebhookRecorder(t *testing.T) *webhookRecorder {
	t.Helper()
	w := &webhookRecorder{status: map[int]int{}, after: map[int]string{}}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.calls++
		if h := w.after[w.calls]; h != "" {
			rw.Header().Set("Retry-After", h)
		}
		if st := w.status[w.calls]; st != 0 {
			rw.WriteHeader(st)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.bodies = append(w.bodies, body)
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *webhookRecorder) notifier(sleeps *[]time.Duration) SlackNotifier {
	return SlackNotifier{WebhookURL: w.srv.URL, Sleep: func(d time.Duration) { *sleeps = append(*sleeps, d) }}
}

// A long full view is posted as several messages in order, one second apart,
// with no thread notice or last-report link (a webhook cannot thread).
func TestSlackNotifier_PostsEveryMessageInOrder(t *testing.T) {
	w := newWebhookRecorder(t)
	var sleeps []time.Duration
	r := bigReport(60, "")
	if err := w.notifier(&sleeps).Send(context.Background(), Message{Report: r, Thread: true}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	want := buildChannelMessages(Message{Report: r}, ChannelFooter{}, enMessages, defaultRenderLimits)
	if len(want) < 2 || len(w.bodies) != len(want) {
		t.Fatalf("posted %d message(s), want %d (more than one)", len(w.bodies), len(want))
	}
	for i, b := range w.bodies {
		if b["text"] != want[i].Text {
			t.Errorf("message %d fallback = %v, want %q", i+1, b["text"], want[i].Text)
		}
		blocks, _ := b["blocks"].([]any)
		if len(blocks) != len(want[i].Blocks) {
			t.Errorf("message %d has %d blocks, want %d", i+1, len(blocks), len(want[i].Blocks))
		}
		if strings.Contains(fmt.Sprint(b["blocks"]), "thread ↓") {
			t.Errorf("message %d carries a thread notice a webhook cannot honor", i+1)
		}
	}
	if len(sleeps) != len(want)-1 {
		t.Errorf("pauses = %d, want %d", len(sleeps), len(want)-1)
	}
	for _, d := range sleeps {
		if d != threadPostGap {
			t.Errorf("pause = %v, want %v", d, threadPostGap)
		}
	}
}

func TestSlackNotifier_Honors429RetryAfter(t *testing.T) {
	for _, c := range []struct {
		name, header string
		want         time.Duration
	}{
		{"seconds", "5", 5 * time.Second},
		{"capped", "999", maxRetryAfter},
		{"absent", "", time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWebhookRecorder(t)
			w.status[1], w.after[1] = http.StatusTooManyRequests, c.header
			var sleeps []time.Duration
			if err := w.notifier(&sleeps).Send(context.Background(), Message{Report: sampleReport()}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if len(w.bodies) != 1 || len(sleeps) != 1 || sleeps[0] != c.want {
				t.Errorf("bodies = %d, pauses = %v, want one message after a pause of %v", len(w.bodies), sleeps, c.want)
			}
		})
	}
}

func TestSlackNotifier_GivesUpAfterThreeAttemptsOn429(t *testing.T) {
	w := newWebhookRecorder(t)
	for i := 1; i <= 5; i++ {
		w.status[i] = http.StatusTooManyRequests
	}
	var sleeps []time.Duration
	err := w.notifier(&sleeps).Send(context.Background(), Message{Report: sampleReport()})
	if err == nil || !strings.Contains(err.Error(), "post message 1/1") {
		t.Fatalf("error = %v, want one naming message 1/1", err)
	}
	if w.calls != apiAttempts {
		t.Errorf("attempts = %d, want %d", w.calls, apiAttempts)
	}
}

// A message that ultimately fails stops the run and is named; later messages
// are not posted.
func TestSlackNotifier_StopsAtTheFirstFailureAndNamesIt(t *testing.T) {
	w := newWebhookRecorder(t)
	w.status[2] = http.StatusInternalServerError
	var sleeps []time.Duration
	err := w.notifier(&sleeps).Send(context.Background(), Message{Report: bigReport(60, "")})
	if err == nil || !strings.Contains(err.Error(), "post message 2/") {
		t.Fatalf("error = %v, want one naming message 2", err)
	}
	if len(w.bodies) != 1 || w.calls != 2 {
		t.Errorf("bodies = %d, calls = %d: nothing may be posted after the failure", len(w.bodies), w.calls)
	}
	if strings.Contains(err.Error(), w.srv.URL) {
		t.Errorf("the webhook URL leaked into the error: %v", err)
	}
}
