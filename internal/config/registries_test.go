package config

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const regPW = "ghp_registrysecretvalue"

func registriesYAML(entries ...string) []byte {
	return []byte(minimal + "\nregistries:\n" + strings.Join(entries, ""))
}

func registryEntry(host, user, password string, extra ...string) string {
	s := "    - host: " + host + "\n      username: " + user + "\n"
	if password != "" {
		s += "      password: " + password + "\n"
	}
	return s + strings.Join(extra, "")
}

func TestParse_Registries(t *testing.T) {
	c, err := Parse(registriesYAML(
		registryEntry("ghcr.io", "me", regPW),
		registryEntry("registry.example.com:5000", "bot", `"`+regPW+`2"`, "      token_hosts:\n        - auth.example.com\n"),
	))
	if err != nil {
		t.Fatal(err)
	}
	rs := c.Registries
	if len(rs) != 2 || rs[0].Host != "ghcr.io" || rs[0].Username != "me" || rs[0].Password.Value() != regPW {
		t.Fatalf("registries = %+v", rs)
	}
	if rs[1].Password.Value() != regPW+"2" || len(rs[1].TokenHosts) != 1 || rs[1].TokenHosts[0] != "auth.example.com" {
		t.Errorf("second = %+v", rs[1])
	}
	store, err := c.RegistryCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if cr, ok := store.For("registry.example.com:5000"); !ok || cr.Password() != regPW+"2" || !cr.AllowsTokenHost("auth.example.com") {
		t.Errorf("credential = %v, %v", cr, ok)
	}
	// None configured: no store content, no error.
	c, err = Parse([]byte(minimal))
	if err != nil || len(c.Registries) != 0 {
		t.Fatalf("default = %+v, %v", c.Registries, err)
	}
	if s, err := c.RegistryCredentials(); err != nil || len(s.Hosts()) != 0 {
		t.Errorf("empty store = %v, %v", s, err)
	}
}

func TestParse_RegistriesRejected(t *testing.T) {
	for name, tc := range map[string]struct {
		body []byte
		want string
	}{
		"scheme":         {registriesYAML(registryEntry("https://ghcr.io", "u", regPW)), "registries[0].host"},
		"path":           {registriesYAML(registryEntry("ghcr.io/org", "u", regPW)), "registries[0].host"},
		"user info":      {registriesYAML(registryEntry("u@ghcr.io", "u", regPW)), "registries[0].host"},
		"empty host":     {registriesYAML(registryEntry(`""`, "u", regPW)), "registries[0].host"},
		"bad port":       {registriesYAML(registryEntry("ghcr.io:99999", "u", regPW)), "registries[0].host"},
		"duplicate":      {registriesYAML(registryEntry("ghcr.io", "u", regPW), registryEntry("GHCR.io", "v", regPW)), "registries[1].host: ghcr.io is configured twice"},
		"docker aliases": {registriesYAML(registryEntry("docker.io", "u", regPW), registryEntry("registry-1.docker.io", "v", regPW)), "configured twice"},
		"colon in user":  {registriesYAML(registryEntry("ghcr.io", `"a:b"`, regPW)), "registries[0].username"},
		"no username":    {registriesYAML(registryEntry("ghcr.io", `""`, regPW)), "registries[0].username"},
		"no password":    {registriesYAML(registryEntry("ghcr.io", "u", "")), "registries[0].password"},
		"blank password": {registriesYAML(registryEntry("ghcr.io", "u", `""`)), "registries[0].password"},
		"space password": {registriesYAML(registryEntry("ghcr.io", "u", `"a b"`)), "registries[0].password"},
		"bad token host": {registriesYAML(registryEntry("ghcr.io", "u", regPW, "      token_hosts: [\"https://a.example.com\"]\n")), "token_hosts[0]"},
		"unknown key":    {registriesYAML(registryEntry("ghcr.io", "u", regPW, "      token: x\n")), "token"},
	} {
		_, err := Parse(tc.body)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
			continue
		}
		if strings.Contains(err.Error(), regPW) || strings.Contains(err.Error(), "a b") {
			t.Errorf("%s: error shows the password: %v", name, err)
		}
	}
}

func TestParse_RegistryPasswordIsRedacted(t *testing.T) {
	c, err := Parse(registriesYAML(registryEntry("ghcr.io", "me", regPW)))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("cfg", "cfg", c, "registries", c.Registries)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "registry", c.Registries[0])
	store, _ := c.RegistryCredentials()
	cred, _ := store.For("ghcr.io")
	for i, out := range []string{
		fmt.Sprint(c), fmt.Sprintf("%v", c.Remediation), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c.Remediation),
		fmt.Sprintf("%+v", c.Registries), fmt.Sprintf("%#v", c.Registries[0]), buf.String(),
		fmt.Sprint(store), fmt.Sprintf("%+v", cred),
	} {
		if strings.Contains(out, regPW) {
			t.Errorf("output %d shows the password: %q", i, out)
		}
	}
}

func TestParse_RegistryPasswordDecodeErrorsDoNotEchoIt(t *testing.T) {
	for name, val := range map[string]string{
		"tagged int":  "!!int " + regPW,
		"tagged null": "!!null " + regPW,
		"tagged seq":  "!!seq " + regPW,
		"custom tag":  "!custom " + regPW,
		"list":        "[" + regPW + "]",
		"map":         "{k: " + regPW + "}",
		"number":      "12345678",
		"bool":        "true",
	} {
		_, err := Parse(registriesYAML(registryEntry("ghcr.io", "me", val)))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), regPW) || strings.Contains(err.Error(), "12345678") {
			t.Errorf("%s: error echoes the value: %v", name, err)
		}
	}
	// A null password is the same as none, and is refused for that.
	for _, val := range []string{"~", "null", "!!null"} {
		if _, err := Parse(registriesYAML(registryEntry("ghcr.io", "me", val))); err == nil || !strings.Contains(err.Error(), "registries[0].password") {
			t.Errorf("%q: err = %v", val, err)
		}
	}
	for _, val := range []string{"!!str " + regPW, `"` + regPW + `"`, "'" + regPW + "'", regPW} {
		c, err := Parse(registriesYAML(registryEntry("ghcr.io", "me", val)))
		if err != nil || c.Registries[0].Password.Value() != regPW {
			t.Errorf("%s: err = %v", val, err)
		}
	}
}

func TestParse_RegistryPasswordMayHoldAColon(t *testing.T) {
	c, err := Parse(registriesYAML(registryEntry("ghcr.io", "me", `"pa:ss:word"`)))
	if err != nil || c.Registries[0].Password.Value() != "pa:ss:word" {
		t.Errorf("err = %v", err)
	}
}

// Logins have one place. The key they had under remediation is an unknown key
// like any other, so a login there cannot be silently ignored.
func TestParse_RegistriesUnderRemediationAreRejected(t *testing.T) {
	yml := []byte(minimal + "\nremediation:\n  registries:\n" + registryEntry("ghcr.io", "me", regPW))
	_, err := Parse(yml)
	if err == nil || !strings.Contains(err.Error(), "registries") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), regPW) {
		t.Errorf("the error carries the password: %v", err)
	}
}

// Every line of a config copied with the indentation it has in a ConfigMap,
// then a key added at the left margin. The added key ends the first document, so
// it is never read: a login would be lost without a word unless this is refused.
func TestParse_ContentAfterTheFirstDocumentIsRejected(t *testing.T) {
	indented := "    " + strings.ReplaceAll(strings.TrimSuffix(minimal, "\n"), "\n", "\n    ") + "\n"
	for name, data := range map[string]string{
		"key at the margin after indented keys": indented + "\nregistries:\n  - host: ghcr.io\n    username: me\n    password: " + regPW + "\n",
		"second document":                       minimal + "\n---\nregistries: []\n",
		"second document without keys":          minimal + "\n---\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(data))
			if err == nil {
				t.Fatal("Parse accepted content it would not read")
			}
			if strings.Contains(err.Error(), regPW) {
				t.Errorf("the error shows the password: %v", err)
			}
		})
	}
	for name, data := range map[string]string{
		"indented keys alone":     indented,
		"trailing comment":        minimal + "\n# the end\n",
		"trailing blank lines":    minimal + "\n\n\n",
		"explicit document end":   minimal + "\n...\n",
		"explicit document start": "---\n" + minimal,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
