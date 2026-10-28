package github

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const ownerToken = "github_pat_ownersecret0123"

func TestOwnerTokenGoesToThatOwnersRepositoriesOnly(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[strings.Split(r.URL.EscapedPath(), "/")[2]] = r.Header.Get("Authorization")
		mu.Unlock()
		jsonResp(w, 200, `{"ref":"refs/heads/main","object":{"type":"commit","sha":"`+sha40+`"}}`)
	})
	c, _ := newTest(t, h, Options{Token: Token(token), OwnerTokens: []OwnerToken{{Owner: "Kitsune-Trail", Token: Token(ownerToken)}}})
	for _, repo := range []string{"example/app", "kitsune-trail/app"} {
		if _, err := c.ResolveBranch(context.Background(), repo, "main"); err != nil {
			t.Fatalf("%s: %v", repo, err)
		}
	}
	if got["kitsune-trail"] != "Bearer "+ownerToken {
		t.Errorf("owner with its own token: Authorization = %q, want the owner's token (owners compare case-insensitively)", got["kitsune-trail"])
	}
	if got["example"] != "Bearer "+token {
		t.Errorf("other owner: Authorization = %q, want the default token", got["example"])
	}
}

func TestOwnerTokenWithoutDefault(t *testing.T) {
	var auth []string
	w := newWriterTest(t, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		jsonResp(rw, 201, `{"id":1}`)
	}), Options{OwnerTokens: []OwnerToken{{Owner: "kitsunetrail", Token: Token(ownerToken)}}})
	_ = w.CreateIssueComment(context.Background(), "kitsunetrail/app", 1, "x")
	_ = w.CreateIssueComment(context.Background(), "example/app", 1, "x")
	if len(auth) != 2 || auth[0] != "Bearer "+ownerToken || auth[1] != "" {
		t.Errorf("Authorization = %q, want the owner's token, then none for an owner without a token", auth)
	}
}

func TestEveryTokenIsMasked(t *testing.T) {
	c := New(Options{Token: Token(token), OwnerTokens: []OwnerToken{{Owner: "kitsunetrail", Token: Token(ownerToken)}}})
	err := c.redact(fmt.Errorf("%w: %s and %s", ErrBadResponse, token, ownerToken))
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), ownerToken) {
		t.Errorf("err = %v, want both tokens masked", err)
	}
}

func TestOwnerTokenIsNeverPrinted(t *testing.T) {
	o := Options{OwnerTokens: []OwnerToken{{Owner: "kitsunetrail", Token: Token(ownerToken)}}}
	c := New(o)
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "client", c, "opts", o)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "client", c, "opts", o)
	outs := []string{buf.String()}
	for _, v := range []any{c, o, &o, o.OwnerTokens, o.OwnerTokens[0]} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
	}
	if j, err := json.Marshal(o); err == nil {
		outs = append(outs, string(j))
	}
	for _, out := range outs {
		if strings.Contains(out, ownerToken) || strings.Contains(out, hex.EncodeToString([]byte(ownerToken))) {
			t.Errorf("token printed: %.200s", out)
		}
	}
}

// redirectingServer redirects every request for /repos/<from>/ to target
// (a path) and answers every other request with a branch, recording the
// Authorization each path was asked with.
func redirectingServer(from, target string, got map[string]string, mu *sync.Mutex) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/repos/"+from+"/") {
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		jsonResp(w, 200, `{"ref":"refs/heads/main","object":{"type":"commit","sha":"`+sha40+`"}}`)
	})
}

func TestRedirectToAnotherOwnerChoosesThatOwnersToken(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	c, _ := newTest(t, redirectingServer("old", "/repos/kitsunetrail/app/git/ref/heads/main", got, &mu),
		Options{Token: Token(token), OwnerTokens: []OwnerToken{{Owner: "kitsunetrail", Token: Token(ownerToken)}}})
	if _, err := c.ResolveBranch(context.Background(), "old/app", "main"); err != nil {
		t.Fatal(err)
	}
	if got["/repos/old/app/git/ref/heads/main"] != "Bearer "+token || got["/repos/kitsunetrail/app/git/ref/heads/main"] != "Bearer "+ownerToken {
		t.Errorf("Authorization by path = %q, want the default token, then the new owner's", got)
	}

	// The other way round, the default token replaces the owner's token.
	got = map[string]string{}
	c, _ = newTest(t, redirectingServer("kitsunetrail", "/repos/example/app/git/ref/heads/main", got, &mu),
		Options{Token: Token(token), OwnerTokens: []OwnerToken{{Owner: "kitsunetrail", Token: Token(ownerToken)}}})
	if _, err := c.ResolveBranch(context.Background(), "kitsunetrail/app", "main"); err != nil {
		t.Fatal(err)
	}
	if got["/repos/example/app/git/ref/heads/main"] != "Bearer "+token {
		t.Errorf("redirect to an owner without its own token: Authorization = %q, want the default token", got["/repos/example/app/git/ref/heads/main"])
	}

	// And an owner with no token at all gets none.
	got = map[string]string{}
	c, _ = newTest(t, redirectingServer("kitsunetrail", "/repos/example/app/git/ref/heads/main", got, &mu),
		Options{OwnerTokens: []OwnerToken{{Owner: "kitsunetrail", Token: Token(ownerToken)}}})
	if _, err := c.ResolveBranch(context.Background(), "kitsunetrail/app", "main"); err != nil {
		t.Fatal(err)
	}
	if got["/repos/example/app/git/ref/heads/main"] != "" {
		t.Errorf("an owner without a token got Authorization %q", got["/repos/example/app/git/ref/heads/main"])
	}
}

func TestRedirectToAnUnownedURL(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	c, _ := newTest(t, redirectingServer("example", "/repositories/42/git/ref/heads/main", got, &mu),
		Options{Token: Token(token), OwnerTokens: []OwnerToken{{Owner: "kitsunetrail", Token: Token(ownerToken)}}})
	_, err := c.ResolveBranch(context.Background(), "example/app", "main")
	if err == nil || !strings.Contains(err.Error(), "names no repository owner") {
		t.Errorf("with owner tokens: err = %v, want the redirect refused", err)
	}
	if _, reached := got["/repositories/42/git/ref/heads/main"]; reached {
		t.Error("the redirect was followed")
	}

	// With one token for every owner the redirect is followed as before.
	got = map[string]string{}
	c, _ = newTest(t, redirectingServer("example", "/repositories/42/git/ref/heads/main", got, &mu), Options{Token: Token(token)})
	if _, err := c.ResolveBranch(context.Background(), "example/app", "main"); err != nil {
		t.Fatal(err)
	}
	if got["/repositories/42/git/ref/heads/main"] != "Bearer "+token {
		t.Errorf("single token: Authorization = %q, want the token kept", got["/repositories/42/git/ref/heads/main"])
	}
}

func TestReadErrorsMaskEveryToken(t *testing.T) {
	for name, o := range map[string]Options{
		"default token": {Token: Token(token)},
		"owner token":   {OwnerTokens: []OwnerToken{{Owner: "example", Token: Token(ownerToken)}}},
	} {
		secret := token
		if o.Token == "" {
			secret = ownerToken
		}
		c, _ := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://[::1 "+secret)
			w.WriteHeader(http.StatusFound)
		}), o)
		_, err := c.ResolveBranch(context.Background(), "example/app", "main")
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("%s: err = %v, want an error with the token masked", name, err)
		}
	}
}
