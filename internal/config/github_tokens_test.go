package config

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const ownerTok = "github_pat_ownersecretvalue"

// githubSection is a remediation section with pull requests on, the given
// github keys and one mapping per repository.
func githubSection(github string, repos ...string) []byte {
	var ms []string
	for i, r := range repos {
		ms = append(ms, mapping(fmt.Sprintf("compose/p/web%d", i), r, "main", "      dependencies:\n        directory: "+strings.ReplaceAll(r, "/", "-")+"\n"))
	}
	return []byte(minimal + "\nremediation:\n  enabled: true\n  pull_requests:\n    enabled: true\n  github:\n" + github +
		"  mappings:\n" + strings.Join(ms, ""))
}

func TestParse_GitHubOwnerTokens(t *testing.T) {
	c, err := Parse(githubSection("    token: ghp_default\n    tokens:\n      - owner: KitsuneTrail\n        token: "+ownerTok+"\n", "example/app", "kitsunetrail/kestrelynx"))
	if err != nil {
		t.Fatal(err)
	}
	g := c.Remediation.GitHub
	if len(g.Tokens) != 1 || g.Tokens[0].Owner != "KitsuneTrail" || g.Tokens[0].Token.Value() != ownerTok {
		t.Fatalf("tokens = %d entries", len(g.Tokens))
	}
	if g.TokenFor("kitsunetrail/kestrelynx").Value() != ownerTok {
		t.Error("the owner's token is not chosen for its repository (owners compare case-insensitively)")
	}
	if g.TokenFor("example/app").Value() != "ghp_default" {
		t.Error("the default token is not chosen for another owner")
	}
}

func TestParse_GitHubOwnerTokensWithoutDefault(t *testing.T) {
	if _, err := Parse(githubSection("    tokens:\n      - owner: example\n        token: "+ownerTok+"\n", "example/app", "Example/api")); err != nil {
		t.Errorf("every mapped owner has a token: %v", err)
	}
	_, err := Parse(githubSection("    tokens:\n      - owner: example\n        token: "+ownerTok+"\n", "example/app", "kitsunetrail/kestrelynx"))
	if err == nil || !strings.Contains(err.Error(), "remediation.mappings[1]") || !strings.Contains(err.Error(), `owner "kitsunetrail"`) {
		t.Errorf("a mapped owner without a token: err = %v, want it to name the mapping and the owner", err)
	}
	if _, err := Parse([]byte(minimal + "\nremediation:\n  enabled: true\n  github:\n    tokens:\n      - owner: example\n        token: " + ownerTok + "\n" +
		"  mappings:\n" + mapping("compose/p/web", "kitsunetrail/kestrelynx", "main", depsRoute))); err != nil {
		t.Errorf("without pull requests a mapped owner may be read anonymously: %v", err)
	}
}

func TestParse_GitHubOwnerTokensRejected(t *testing.T) {
	for name, tc := range map[string]struct{ github, want string }{
		"invalid owner":    {"    tokens:\n      - owner: -bad\n        token: " + ownerTok + "\n", "tokens[0].owner"},
		"owner with slash": {"    tokens:\n      - owner: a/b\n        token: " + ownerTok + "\n", "tokens[0].owner"},
		"no owner":         {"    tokens:\n      - token: " + ownerTok + "\n", "tokens[0].owner"},
		"repeated owner": {"    tokens:\n      - owner: example\n        token: " + ownerTok + "\n      - owner: EXAMPLE\n        token: " + ownerTok + "x\n",
			"repeats remediation.github.tokens[0]"},
		"no token":        {"    tokens:\n      - owner: example\n", "tokens[0].token is required"},
		"blank token":     {"    tokens:\n      - owner: example\n        token: \"\"\n", "tokens[0].token is required"},
		"spaced token":    {"    tokens:\n      - owner: example\n        token: \"a " + ownerTok + "\"\n", "tokens[0].token must not contain"},
		"numeric token":   {"    tokens:\n      - owner: example\n        token: 12345678\n", "tokens[0].token"},
		"unknown key":     {"    tokens:\n      - owner: example\n        token: " + ownerTok + "\n        repository: x\n", "repository"},
		"no token at all": {"    {}\n", "requires remediation.github.token or remediation.github.tokens"},
	} {
		_, err := Parse(githubSection(tc.github, "example/app"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
			continue
		}
		if strings.Contains(err.Error(), ownerTok) || strings.Contains(err.Error(), "12345678") {
			t.Errorf("%s: error echoes the token: %v", name, err)
		}
	}
}

func TestParse_GitHubOwnerTokenIsRedacted(t *testing.T) {
	c, err := Parse([]byte(minimal + "\nremediation:\n  github:\n    tokens:\n      - owner: example\n        token: " + ownerTok + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cfg", "github", c.Remediation.GitHub, "remediation", c.Remediation)
	for _, out := range []string{
		fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c.Remediation), fmt.Sprintf("%#v", c.Remediation.GitHub.Tokens), buf.String(),
	} {
		if strings.Contains(out, ownerTok) {
			t.Errorf("token leaked in %.200s", out)
		}
	}
}
