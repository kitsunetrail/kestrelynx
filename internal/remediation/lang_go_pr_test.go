package remediation

import (
	"strings"
	"testing"
)

// A Go pull request names the module proxy, says what moved besides the
// targets and how go.sum was checked, and asks for a build with go.mod as it
// is, in both languages.
func TestLanguagePRBody_Go(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		in := languageBodyFixture(lang, "<!-- marker -->", true)
		in.Item.Manager = ManagerGo
		in.Item.GoBuiltWith = "1.26.10"
		in.LockPath = "svc/go.mod"
		in.Files = []FileChange{{Path: "svc/go.mod"}, {Path: "svc/go.sum"}}
		in.Record.Manager = "go"
		in.Record.Chain, in.Record.ManifestEdits, in.Record.Tool = nil, nil, nil
		in.Record.Runtime = &RuntimeRecord{ID: "golang1.26", Version: "1.26.10", Image: "golang@sha256:" + strings.Repeat("c", 64), Basis: RuntimeBasisGoLines}
		in.Item.Update.Diff, in.Item.Update.Notes = nil, nil
		in.Item.Update.Steps = []UpdateStep{{Op: "go get golang.org/x/net@v0.53.0", ExitCode: 0}}
		in.Record.DeprecatedNotes, in.Record.DeprecatedChanged, in.Record.Followed = nil, 0, nil
		in.Item.SourceCheck.Before = []HashedFile{{Path: "go.mod", SHA256: strings.Repeat("a", 64)}}
		in.Item.SourceCheck.After = []HashedFile{{Path: "go.mod", SHA256: strings.Repeat("b", 64)}}
		in.Item.Update.Go = &GoUpdate{
			GoBefore: "1.22", GoAfter: "1.25.0", ToolchainAfter: "go1.25.3",
			Collateral: []GoModuleMove{{Path: "golang.org/x/text", From: "v0.14.0", To: "v0.36.0"}, {Path: "golang.org/x/sys", To: "v0.40.0"}},
			SumAdded:   []string{"golang.org/x/text v0.36.0/go.mod h1:" + strings.Repeat("A", 43) + "="},
		}
		body, err := buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"`go build -mod=readonly ./... && go test -mod=readonly ./...`",
			"`1.22`", "`1.25.0`", "`1.26.10`", "`go1.25.3`",
			"`golang.org/x/text`", "`v0.36.0`", "`golang.org/x/sys`", "`v0.40.0`",
			"sum.golang.org", "proxy.golang.org", "-mod=mod",
			"golang.org/x/text v0.36.0/go.mod h1:",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the body lacks %q:\n%s", lang, want, body)
			}
		}
		for _, not := range []string{"npm", "lockfile からのインストール", "installs from the lockfile"} {
			if strings.Contains(body, not) {
				t.Errorf("%s: the body says %q:\n%s", lang, not, body)
			}
		}
	}
	// The same release written in another form is not said to be raised.
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		in := languageBodyFixture(lang, "<!-- marker -->", true)
		in.Item.Manager = ManagerGo
		in.Item.Update.Go = &GoUpdate{GoBefore: "1.22", GoAfter: "1.22.0"}
		body, err := buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body, "GODEBUG") || !strings.Contains(body, "`1.22.0`") {
			t.Errorf("%s: a go line in another form:\n%s", lang, body)
		}
	}
	for m, want := range map[DependencyManager]string{ManagerGo: "go.mod", ManagerPip: "requirements.txt", "unknown": ""} {
		if got := manifestFileName(m); got != want {
			t.Errorf("manifestFileName(%s) = %q", m, got)
		}
	}
	if installCheck("unknown") != "" || registryName(textFor(BodyEN), "unknown") != "unknown" {
		t.Error("an unknown manager falls back to another manager's text")
	}
}
