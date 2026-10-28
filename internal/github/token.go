package github

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

const redacted = "[redacted]"

// Token is a GitHub credential that prints as a placeholder under every fmt
// verb, in slog and when marshalled, so a struct holding one cannot leak it by
// being printed. Use Value to read it.
type Token string

// Value returns the credential itself.
func (t Token) Value() string { return string(t) }

func (t Token) text() string {
	if t == "" {
		return ""
	}
	return redacted
}

func (t Token) String() string   { return t.text() }
func (t Token) GoString() string { return `"` + t.text() + `"` }

// Format implements fmt.Formatter, covering every verb.
func (t Token) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.text()) }

func (t Token) LogValue() slog.Value         { return slog.StringValue(t.text()) }
func (t Token) MarshalText() ([]byte, error) { return []byte(t.text()), nil }
func (t Token) MarshalJSON() ([]byte, error) { return []byte(`"` + t.text() + `"`), nil }

// OwnerToken is the token for the repositories of one owner (a user or an
// organization). A fine-grained token reaches the repositories of a single
// owner, so repositories of several owners need one token each.
type OwnerToken struct {
	Owner string
	Token Token
}

// bearers returns the Authorization header value for a request to a
// repository of owner, or "" for none: the owner's own token when one is
// listed (owners compare case-insensitively, as GitHub names do), otherwise
// def. secrets returns every token value, for masking. The client keeps both
// as funcs: fmt prints unexported fields without calling their methods (a bad
// verb even prints a pointer's target), but it prints a func only as an
// address, so the values stay out of any printed Client.
func bearers(def Token, owners []OwnerToken) (auth func(owner string) string, secrets func() []string) {
	byOwner := map[string]string{}
	var all []string
	if def != "" {
		all = append(all, def.Value())
	}
	for _, o := range owners {
		if o.Token == "" {
			continue
		}
		byOwner[strings.ToLower(o.Owner)] = "Bearer " + o.Token.Value()
		all = append(all, o.Token.Value())
	}
	fallback := ""
	if def != "" {
		fallback = "Bearer " + def.Value()
	}
	auth = func(owner string) string {
		if v, ok := byOwner[strings.ToLower(owner)]; ok && owner != "" {
			return v
		}
		return fallback
	}
	secrets = func() []string { return all }
	return auth, secrets
}
