package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	if !strings.Contains(payload.Text, "StackWatch") {
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
