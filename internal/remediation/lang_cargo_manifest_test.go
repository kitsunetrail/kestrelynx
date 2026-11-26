package remediation

import (
	"errors"
	"strings"
	"testing"
)

func TestParseCargoManifest_Real(t *testing.T) {
	m, err := parseCargoManifest("svc/Cargo.toml", []byte(cargoFixture(t, "exp1.Cargo.toml")))
	if err != nil {
		t.Fatal(err)
	}
	if !m.hasPackage || m.name != "exp1" || m.version != "0.1.0" || m.ws != nil || m.dir != "svc" {
		t.Errorf("manifest = %+v", m)
	}
	if len(m.deps) != 1 || m.deps[0].pkg != "tokio" || m.deps[0].req != "1" || m.deps[0].table != "dependencies" {
		t.Errorf("deps = %+v", m.deps)
	}

	m, err = parseCargoManifest("Cargo.toml", []byte(cargoFixture(t, "exp3.Cargo.toml")))
	if err != nil || m.hasPackage || m.ws == nil || strings.Join(m.ws.members, ",") != "a,b" {
		t.Fatalf("workspace manifest = %+v %v", m, err)
	}

	m, err = parseCargoManifest("a/Cargo.toml", []byte(cargoFixture(t, "exp3.a.Cargo.toml")))
	if err != nil || len(m.deps) != 2 {
		t.Fatalf("member = %+v %v", m, err)
	}
	if b := m.deps[0]; b.key != "b" || b.path != "b" || b.req != "" {
		t.Errorf("path dependency = %+v", b)
	}

	m, err = parseCargoManifest("Cargo.toml", []byte(cargoFixture(t, "exp4.Cargo.toml")))
	if err != nil || m.rustVersion != "1.60" {
		t.Fatalf("exp4 = %+v %v", m, err)
	}
	var syns []string
	for _, d := range m.deps {
		if d.pkg == "syn" {
			syns = append(syns, d.key+"="+d.req)
		}
	}
	if strings.Join(syns, ",") != "syn1=1,syn2=2" {
		t.Errorf("renamed dependencies = %v", syns)
	}
}

func TestParseCargoManifest_Forms(t *testing.T) {
	const pkg = "[package]\nname = \"app\"\nversion = \"0.2.0\"\nedition = \"2021\"\n"
	m, err := parseCargoManifest("Cargo.toml", []byte(pkg+`
[dependencies]
a = "1.2"
b = { version = "0.3", features = ["x"], optional = true, default-features = false }
c = { version = "1", default_features = false }
d = { package = "real-d", version = "2" }
e = { path = "../e" }
f = { workspace = true, features = ["y"] }

[dev-dependencies]
g = "1"

[build-dependencies.h]
version = "1"

[target.'cfg(unix)'.dependencies]
i = "1"

[target.x86_64-pc-windows-msvc.build-dependencies]
j = "1"

[features]
default = ["a"]

[profile.release]
lto = true

[lints]
workspace = true

[[bin]]
name = "app"
`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]cargoDep{}
	for _, d := range m.deps {
		got[d.key] = d
	}
	if len(got) != 10 {
		t.Fatalf("deps = %+v", m.deps)
	}
	if d := got["d"]; d.pkg != "real-d" || d.req != "2" || !d.pkgKey {
		t.Errorf("d = %+v", d)
	}
	if d := got["e"]; d.path != "../e" || d.req != "" {
		t.Errorf("e = %+v", d)
	}
	if d := got["f"]; !d.inherit {
		t.Errorf("f = %+v", d)
	}
	if d := got["h"]; d.table != "build-dependencies" || d.req != "1" {
		t.Errorf("h = %+v", d)
	}
	if d := got["i"]; d.table != "target.cfg(unix).dependencies" {
		t.Errorf("i = %+v", d)
	}
	if d := got["j"]; d.table != "target.x86_64-pc-windows-msvc.build-dependencies" {
		t.Errorf("j = %+v", d)
	}

	// A package without a version is 0.0.0; one that takes it from the
	// workspace is filled in later.
	m, err = parseCargoManifest("Cargo.toml", []byte("[package]\nname = \"app\"\n"))
	if err != nil || m.version != "0.0.0" || m.versionInherited {
		t.Errorf("no version: %+v %v", m, err)
	}
	m, err = parseCargoManifest("Cargo.toml", []byte("[package]\nname = \"app\"\nversion.workspace = true\nrust-version.workspace = true\n"))
	if err != nil || !m.versionInherited || !m.rustVersionInherited || m.version != "" {
		t.Errorf("inherited: %+v %v", m, err)
	}
	m, err = parseCargoManifest("Cargo.toml", []byte("[package]\nname = \"app\"\nrust-version = \"1.70\"\n"))
	if err != nil || m.rustVersion != "1.70" {
		t.Errorf("rust-version: %+v %v", m, err)
	}

	m, err = parseCargoManifest("Cargo.toml", []byte(`
[workspace]
members = ["crates/*", "tools/x"]
exclude = ["crates/old"]
default-members = ["tools/x"]
resolver = "2"
[workspace.package]
version = "1.4.0"
rust-version = "1.75"
edition = "2021"
[workspace.dependencies]
tokio = "=1.18.0"
log = { version = "0.4", features = ["std"] }
[workspace.metadata.docs]
x = 1
[workspace.lints.rust]
unsafe_code = "forbid"
`))
	if err != nil || m.ws == nil || m.hasPackage {
		t.Fatalf("workspace: %+v %v", m, err)
	}
	ws := m.ws
	if strings.Join(ws.members, ",") != "crates/*,tools/x" || strings.Join(ws.exclude, ",") != "crates/old" ||
		ws.version != "1.4.0" || ws.rustVersion != "1.75" || len(ws.deps) != 2 {
		t.Errorf("workspace = %+v", ws)
	}
	d, ok := ws.inherited(cargoDep{key: "tokio", inherit: true, table: "dependencies"})
	if !ok || d.req != "=1.18.0" || d.pkg != "tokio" || d.inherit {
		t.Errorf("inherited = %+v %v", d, ok)
	}
	if _, ok := ws.inherited(cargoDep{key: "absent", inherit: true}); ok {
		t.Error("an entry the workspace lacks was inherited")
	}
}

func TestParseCargoManifest_Refusals(t *testing.T) {
	const pkg = "[package]\nname = \"app\"\nversion = \"0.2.0\"\n"
	for name, c := range map[string]struct {
		text   string
		reason Reason // "" for an error without one
	}{
		"patch":                       {pkg + "[patch.crates-io]\ntokio = { path = \"../tokio\" }\n", ReasonUnsupportedSource},
		"replace":                     {pkg + "[replace]\n\"tokio:1.0.0\" = { path = \"../tokio\" }\n", ReasonUnsupportedSource},
		"cargo-features":              {"cargo-features = [\"edition2024\"]\n" + pkg, ReasonUnsupportedSource},
		"underscore dev table":        {pkg + "[dev_dependencies]\na = \"1\"\n", ReasonCargoManifestUnsupported},
		"underscore build table":      {pkg + "[build_dependencies]\na = \"1\"\n", ReasonCargoManifestUnsupported},
		"underscore under target":     {pkg + "[target.'cfg(unix)'.dev_dependencies]\na = \"1\"\n", ReasonCargoManifestUnsupported},
		"unknown key under target":    {pkg + "[target.'cfg(unix)'.frobnicate]\na = \"1\"\n", ReasonCargoManifestUnsupported},
		"unknown top-level key":       {pkg + "[frobnicate]\nx = 1\n", ReasonCargoManifestUnsupported},
		"project table":               {"[project]\nname = \"app\"\nversion = \"1.0.0\"\n", ReasonCargoManifestUnsupported},
		"git dependency":              {pkg + "[dependencies]\na = { git = \"https://github.com/x/a\" }\n", ReasonUnsupportedSource},
		"git with a version":          {pkg + "[dependencies]\na = { git = \"https://github.com/x/a\", version = \"1\" }\n", ReasonUnsupportedSource},
		"branch":                      {pkg + "[dependencies]\na = { version = \"1\", branch = \"main\" }\n", ReasonUnsupportedSource},
		"tag":                         {pkg + "[dependencies]\na = { version = \"1\", tag = \"v1\" }\n", ReasonUnsupportedSource},
		"rev":                         {pkg + "[dependencies]\na = { version = \"1\", rev = \"abc\" }\n", ReasonUnsupportedSource},
		"registry":                    {pkg + "[dependencies]\na = { version = \"1\", registry = \"corp\" }\n", ReasonUnsupportedSource},
		"registry-index":              {pkg + "[dependencies]\na = { version = \"1\", registry-index = \"https://x/index\" }\n", ReasonUnsupportedSource},
		"git in a dev table":          {pkg + "[dev-dependencies]\na = { git = \"https://github.com/x/a\" }\n", ReasonUnsupportedSource},
		"git under target":            {pkg + "[target.'cfg(unix)'.dependencies]\na = { git = \"https://github.com/x/a\" }\n", ReasonUnsupportedSource},
		"git in the workspace table":  {"[workspace]\nmembers = []\n[workspace.dependencies]\na = { git = \"https://github.com/x/a\" }\n", ReasonUnsupportedSource},
		"unknown dependency key":      {pkg + "[dependencies]\na = { version = \"1\", artifact = \"bin\" }\n", ReasonCargoManifestUnsupported},
		"dependency without a source": {pkg + "[dependencies]\na = { features = [\"x\"] }\n", ReasonCargoManifestUnsupported},
		"workspace with a version":    {pkg + "[dependencies]\na = { workspace = true, version = \"1\" }\n", ReasonCargoManifestUnsupported},
		"workspace = false":           {pkg + "[dependencies]\na = { workspace = false, version = \"1\" }\n", ReasonCargoManifestUnsupported},
		"workspace in the table":      {"[workspace]\n[workspace.dependencies]\na = { workspace = true }\n", ReasonCargoManifestUnsupported},
		"package.workspace":           {"[package]\nname = \"app\"\nworkspace = \"..\"\n", ReasonWorkspaceUnsupported},
		"unknown workspace key":       {"[workspace]\nmembers = []\nfrobnicate = 1\n", ReasonCargoManifestUnsupported},
		"odd rust-version":            {"[package]\nname = \"app\"\nrust-version = \"1.70.0-beta\"\n", ReasonCargoManifestUnsupported},
		"absolute path dependency":    {pkg + "[dependencies]\na = { path = \"/abs\" }\n", ReasonCargoManifestUnsupported},
		"no package and no workspace": {"[dependencies]\na = \"1\"\n", Reason("")},
		"bad name":                    {"[package]\nname = \"a b\"\n", Reason("")},
		"bad version":                 {"[package]\nname = \"a\"\nversion = \"1.0\"\n", Reason("")},
		"dependency is a number":      {pkg + "[dependencies]\na = 3\n", Reason("")},
		"empty requirement":           {pkg + "[dependencies]\na = \"\"\n", Reason("")},
		"not TOML":                    {"[package\n", Reason("")},
		"members is not a list":       {"[workspace]\nmembers = \"a\"\n", Reason("")},
	} {
		_, err := parseCargoManifest("Cargo.toml", []byte(c.text))
		var ue *UnsupportedError
		switch {
		case err == nil:
			t.Errorf("%s: parsed", name)
		case c.reason == "" && errors.As(err, &ue):
			t.Errorf("%s: refused with %s, want no reason", name, ue.Reason)
		case c.reason != "" && (!errors.As(err, &ue) || ue.Reason != c.reason):
			t.Errorf("%s: err = %v, want %s", name, err, c.reason)
		}
	}
}

func TestCargoMemberPath(t *testing.T) {
	for _, c := range []struct {
		root, entry string
		glob        bool
		want        string
		bad         bool
	}{
		{".", "crates/app", true, "crates/app", false},
		{"svc", "crates/app", true, "svc/crates/app", false},
		{"svc", "./crates/app", true, "svc/crates/app", false},
		{"svc", "crates/*", true, "svc/crates/*", false},
		{"svc", "*", true, "svc/*", false},
		{"svc", "crates/*", false, "", true},
		{"svc", "crates/a*", true, "", true},
		{"svc", "*/app", true, "", true},
		{"svc", "crates/**", true, "", true},
		{"svc", "crates/[ab]", true, "", true},
		{"svc", "../other", true, "", true},
		{"svc", "crates/../../other", true, "", true},
		{"svc", "/abs", true, "", true},
		{"svc", "a\\b", true, "", true},
		{".", "..", true, "", true},
		{"svc", ".", true, "svc", false},
	} {
		got, err := cargoMemberPath(c.root, c.entry, c.glob)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("cargoMemberPath(%q, %q, %v) = %q, %v", c.root, c.entry, c.glob, got, err)
		}
	}
}

func TestParseRustToolchain(t *testing.T) {
	for _, c := range []struct {
		file, text string
		want       CargoToolchain
		bad        bool
	}{
		{"rust-toolchain.toml", "[toolchain]\nchannel = \"1.75.0\"\ncomponents = [\"clippy\"]\n", CargoToolchain{Path: "rust-toolchain.toml", Channel: "1.75.0", Version: "1.75.0"}, false},
		{"rust-toolchain.toml", "[toolchain]\nchannel = \"1.75\"\n", CargoToolchain{Path: "rust-toolchain.toml", Channel: "1.75", Version: "1.75"}, false},
		{"rust-toolchain.toml", "[toolchain]\nchannel = \"stable\"\n", CargoToolchain{Path: "rust-toolchain.toml", Channel: "stable"}, false},
		{"rust-toolchain.toml", "[toolchain]\nchannel = \"nightly-2025-01-01\"\n", CargoToolchain{Path: "rust-toolchain.toml", Channel: "nightly-2025-01-01"}, false},
		{"rust-toolchain.toml", "[toolchain]\ncomponents = [\"rustfmt\"]\n", CargoToolchain{Path: "rust-toolchain.toml"}, false},
		{"rust-toolchain", "1.70.0\n", CargoToolchain{Path: "rust-toolchain", Channel: "1.70.0", Version: "1.70.0"}, false},
		{"rust-toolchain", "nightly\n", CargoToolchain{Path: "rust-toolchain", Channel: "nightly"}, false},
		{"rust-toolchain", "[toolchain]\nchannel = \"1.80.1\"\n", CargoToolchain{Path: "rust-toolchain", Channel: "1.80.1", Version: "1.80.1"}, false},
		{"rust-toolchain", "", CargoToolchain{Path: "rust-toolchain"}, false},
		{"rust-toolchain", "2.0.0\n", CargoToolchain{Path: "rust-toolchain", Channel: "2.0.0"}, false},
		{"rust-toolchain.toml", "[toolchain\n", CargoToolchain{}, true},
		{"rust-toolchain.toml", "[toolchain]\nchannel = 1\n", CargoToolchain{}, true},
	} {
		got, err := parseRustToolchain(c.file, []byte(c.text))
		if (err != nil) != c.bad || (!c.bad && got != c.want) {
			t.Errorf("parseRustToolchain(%q, %q) = %+v, %v; want %+v", c.file, c.text, got, err, c.want)
		}
	}
}
