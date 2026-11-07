//go:build live

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// These tests run the scanners as main assembles them, with the real Trivy,
// against a registry that asks for a login: the registry image with htpasswd
// authentication, served over TLS with a certificate of its own, holding
// kx/app. Give it a private address, the case of a registry on the user's own
// network. scripts/live_auth_test.sh sets all of this up and runs them; by hand
// they need the environment below:
//
//	KX_LIVE_AUTH_ADDR   host:port of the registry, e.g. 172.20.0.2:5443
//	KX_LIVE_AUTH_USER   the login's user name
//	KX_LIVE_AUTH_PWFILE a file holding the login's password
//	KX_LIVE_AUTH_CA     the registry certificate, PEM
//	KX_LIVE_AUTH_DIGEST the digest of kx/app, sha256:...
//
//	go test -tags live -run TestLiveAuth -v ./cmd/kestrelynx
type liveAuth struct {
	addr, user, password string
	target               scanner.ScanTarget
}

func liveAuthEnv(t *testing.T) liveAuth {
	t.Helper()
	l := liveAuth{addr: os.Getenv("KX_LIVE_AUTH_ADDR"), user: os.Getenv("KX_LIVE_AUTH_USER")}
	pwfile, ca, sum := os.Getenv("KX_LIVE_AUTH_PWFILE"), os.Getenv("KX_LIVE_AUTH_CA"), os.Getenv("KX_LIVE_AUTH_DIGEST")
	if l.addr == "" || l.user == "" || pwfile == "" || ca == "" || sum == "" {
		t.Skip("KX_LIVE_AUTH_* is not set")
	}
	pw, err := os.ReadFile(pwfile)
	if err != nil {
		t.Fatal(err)
	}
	if l.password = strings.TrimSpace(string(pw)); l.password == "" {
		t.Fatal("KX_LIVE_AUTH_PWFILE is empty")
	}
	t.Setenv("SSL_CERT_FILE", ca) // both Trivy and the registry client trust the test registry
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	d, ok := inventory.ParseDigest(inventory.DigestRegistry, sum)
	if !ok {
		t.Fatalf("KX_LIVE_AUTH_DIGEST %q is not a digest", sum)
	}
	repo := l.addr + "/kx/app"
	l.target = scanner.ScanTarget{
		Subject: inventory.ImageSubject{
			Ref:      repo + ":1.2.3",
			Key:      inventory.EntityKey{Digest: d, Platform: inventory.Platform{OS: "linux", Architecture: "amd64"}},
			Resolved: true,
		},
		Registry: inventory.RegistryRef{Repository: repo, Digest: d},
		Source:   scanner.SourceRemote,
	}
	return l
}

func (l liveAuth) config(password string, plan bool) config.Config {
	return config.Config{
		Scan: config.ScanConfig{Severity: []string{"HIGH", "CRITICAL"}},
		Remediation: config.RemediationConfig{
			Enabled: plan, StorageDir: "/data/remediation",
			Limits: config.RemediationLimits{TagPagesPerRepository: 5},
		},
		Registries: []config.RegistryLogin{{Host: l.addr, Username: l.user, Password: config.Secret(password)}},
	}
}

func TestLiveAuthPlanOff(t *testing.T) {
	l := liveAuthEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scan := buildScanner(l.config(l.password, false)).Scan(ctx, l.target)
	if scan.Err != nil {
		t.Fatalf("with the login: %v", scan.Err)
	}
	if !scan.Pinned {
		t.Errorf("with the login: scan is not pinned: %+v", scan)
	}

	none := buildScanner(config.Config{Scan: config.ScanConfig{Severity: []string{"HIGH", "CRITICAL"}}}).Scan(ctx, l.target)
	if none.Err == nil {
		t.Fatal("without a login: the registry let the scan through, so this setup shows nothing")
	}
	t.Logf("without a login: %v", none.Err)

	const wrong = "not-the-password"
	bad := buildScanner(l.config(wrong, false)).Scan(ctx, l.target)
	if bad.Err == nil {
		t.Fatal("with a wrong password: the scan passed")
	}
	if strings.Contains(bad.Err.Error(), wrong) {
		t.Errorf("the error carries the password: %v", bad.Err)
	}
}

// The plan's budget is spent before the running images are scanned, which is
// what a large cycle comes to; they must still get their login.
func TestLiveAuthPlanOnWithTheBudgetSpent(t *testing.T) {
	l := liveAuthEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pc := buildPlanConfig(l.config(l.password, true))
	if _, err := pc.Scanner.PrepareDB(ctx); err != nil {
		t.Fatalf("prepare databases: %v", err)
	}
	pc.NewRegistry(registry.NewBudget(0))
	if scan := pc.RunningScanner.Scan(ctx, l.target); scan.Err != nil {
		t.Fatalf("running image: %v", scan.Err)
	}
	if scan := pc.Scanner.Scan(ctx, l.target); scan.Err == nil {
		t.Error("the plan's scanner fetched past its spent budget")
	}
}
