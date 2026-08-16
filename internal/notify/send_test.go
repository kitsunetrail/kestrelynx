package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	// Slack expects a JSON object with a "text" field.
	var payload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body not JSON: %v\n%s", err, gotBody)
	}
	if !strings.Contains(payload.Text, "KestreLynx") {
		t.Errorf("text missing header: %q", payload.Text)
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
