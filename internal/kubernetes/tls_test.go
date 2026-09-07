package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCAFile PEM-encodes srv's own certificate and writes it as a CA file —
// the standard way to make a client trust an httptest.NewTLSServer's
// self-signed certificate: the leaf, added to a RootCAs pool, is its own
// trust anchor.
func writeCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

// writeUnrelatedCAFile generates a throwaway self-signed certificate that
// belongs to no server anywhere and writes it as a CA file. This is
// deliberately not "some other httptest server's certificate": Go's
// httptest package hands out the same fixed built-in certificate to every
// NewTLSServer call in a process, so two different httptest servers are not
// a valid stand-in for "a CA that doesn't match" — they'd trivially match.
func writeUnrelatedCAFile(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func TestNew_RejectsHTTPAPIServer(t *testing.T) {
	if _, err := New(Options{APIServer: "http://10.0.0.1:8080"}); err == nil {
		t.Fatal("expected error for a non-https api_server, got nil")
	}
}

func TestNew_AcceptsHTTPSAPIServer(t *testing.T) {
	c, err := New(Options{APIServer: "https://10.0.0.1:6443"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil {
		t.Fatal("New returned a nil Client with a nil error")
	}
}

// TestRunningContainers_RealTLS_Succeeds exercises the production TLS path
// end to end (buildHTTPClient, not the newClient test hook that bypasses
// it): a real TLS handshake against an httptest.NewTLSServer, verified
// against a CA file holding that server's own certificate.
func TestRunningContainers_RealTLS_Succeeds(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_running.json"))))
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)

	c, err := New(Options{
		APIServer: srv.URL,
		CAFile:    writeCAFile(t, srv),
		TokenFile: writeTokenFile(t, "test-token"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers over real TLS: %v", err)
	}
	if len(cs) != 1 {
		t.Errorf("got %d containers, want 1", len(cs))
	}
}

// TestRunningContainers_RealTLS_UntrustedCARejected checks the negative
// space of the same path: a CA file that does not correspond to the
// server's certificate must fail the handshake, not be silently accepted.
func TestRunningContainers_RealTLS_UntrustedCARejected(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)

	c, err := New(Options{
		APIServer: srv.URL,
		CAFile:    writeUnrelatedCAFile(t),
		TokenFile: writeTokenFile(t, "test-token"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.RunningContainers(context.Background()); err == nil {
		t.Fatal("expected a TLS verification error against an unrelated CA, got nil")
	}
}

// TestRunningContainers_RealTLS_CARereadEachCycle proves the CA file is read
// fresh on every cycle rather than cached on the Client: the same server's
// certificate validates on the first cycle, then the CA file is rotated to
// garbage and a second cycle against the same Client must now fail.
func TestRunningContainers_RealTLS_CARereadEachCycle(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_running.json"))))
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)

	caFile := writeCAFile(t, srv)
	c, err := New(Options{
		APIServer: srv.URL,
		CAFile:    caFile,
		TokenFile: writeTokenFile(t, "test-token"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.RunningContainers(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}

	if err := os.WriteFile(caFile, []byte("not a valid certificate"), 0o600); err != nil {
		t.Fatalf("rotate ca file: %v", err)
	}

	if _, err := c.RunningContainers(context.Background()); err == nil {
		t.Fatal("second cycle: expected an error after the CA file was rotated to invalid content, got nil (CA must be re-read every cycle, not cached)")
	}
}

// TestRunningContainers_RealTLS_RedirectRejected checks that a 3xx response
// from the apiserver is treated as an error rather than followed: following
// it would replay the Authorization header (the SA token) at whatever the
// redirect names.
func TestRunningContainers_RealTLS_RedirectRejected(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(envelope("", loadFixture(t, "node_amd64.json")))
	})
	mux.HandleFunc("/api/v1/pods", func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect target must never be requested")
		w.Header().Set("Content-Type", "application/json")
		w.Write(envelope(""))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	c, err := New(Options{
		APIServer: srv.URL,
		CAFile:    writeCAFile(t, srv),
		TokenFile: writeTokenFile(t, "test-token"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.RunningContainers(context.Background()); err == nil {
		t.Fatal("expected an error for a redirected LIST response, got nil")
	}
	if calls != 1 {
		t.Errorf("pods endpoint called %d times, want exactly 1 (no retry/follow of the redirect)", calls)
	}
}
