package evidence

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestNormalizeContainerPath(t *testing.T) {
	cases := map[string]string{
		"usr/local/bin/trivy":  "usr/local/bin/trivy",
		"/usr/local/bin/trivy": "usr/local/bin/trivy",
		"":                     "",
		"/":                    "",
		"//usr/bin/x":          "/usr/bin/x", // only one leading slash is stripped
	}
	for in, want := range cases {
		if got := normalizeContainerPath(in); got != want {
			t.Errorf("normalizeContainerPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEcosystemMapped(t *testing.T) {
	mapped := []inventory.Ecosystem{
		inventory.EcosystemGoBinary, inventory.EcosystemRustBinary,
		inventory.EcosystemPythonPkg, inventory.EcosystemCondaPkg,
		inventory.EcosystemNodePkg, inventory.EcosystemJar,
		inventory.EcosystemGemSpec, inventory.EcosystemComposer,
		inventory.EcosystemComposerVendor, inventory.EcosystemDotNetCore,
	}
	for _, e := range mapped {
		if !EcosystemMapped(e) {
			t.Errorf("EcosystemMapped(%q) = false, want true", e)
		}
	}

	unmapped := []inventory.Ecosystem{
		inventory.EcosystemBundler, inventory.EcosystemCargo,
		inventory.EcosystemNpm, inventory.EcosystemUnknown,
	}
	for _, e := range unmapped {
		if EcosystemMapped(e) {
			t.Errorf("EcosystemMapped(%q) = true, want false", e)
		}
	}
}

// TestRuntimeNameMatches pins the runtimeRules table against the executable
// names each ecosystem is expected to run under. ASSUMED: none of these
// exact names (python/python3/python3.<n>, nodejs, java, ruby, php-fpm and
// its versioned form, dotnet) have been confirmed against a real running
// container's recorded executable path — they come from each ecosystem's
// well-known interpreter/runtime binary name, not from a captured fixture.
// "node" is the one exception: it was seen as a production container's
// recorded exe. Recording real containers for each of these and updating
// this table accordingly is follow-up work, not part of this test.
func TestRuntimeNameMatches(t *testing.T) {
	cases := []struct {
		eco     inventory.Ecosystem
		path    string
		matches bool
	}{
		{inventory.EcosystemPythonPkg, "/usr/local/bin/python3", true},
		{inventory.EcosystemPythonPkg, "/usr/local/bin/python3.11", true}, // versioned name
		{inventory.EcosystemPythonPkg, "/usr/local/bin/python3.9", true},
		{inventory.EcosystemPythonPkg, "/usr/local/bin/python3-config", false},
		{inventory.EcosystemCondaPkg, "/opt/conda/bin/python3.12", true},
		{inventory.EcosystemNodePkg, "/usr/local/bin/node", true}, // VERIFIED: seen as a production container's exe
		{inventory.EcosystemNodePkg, "/usr/bin/nodejs", true},
		{inventory.EcosystemNodePkg, "/usr/bin/npm", false},
		{inventory.EcosystemJar, "/usr/lib/jvm/java-17/bin/java", true}, // resolved final element
		{inventory.EcosystemJar, "/usr/bin/javac", false},
		{inventory.EcosystemGemSpec, "/usr/local/bin/ruby", true},
		{inventory.EcosystemComposer, "/usr/local/sbin/php-fpm", true},
		{inventory.EcosystemComposer, "/usr/local/sbin/php-fpm8.2", true}, // versioned name
		{inventory.EcosystemComposer, "/usr/local/sbin/php-fpm82", true},
		{inventory.EcosystemComposerVendor, "/usr/local/bin/php", true},
		{inventory.EcosystemDotNetCore, "/usr/bin/dotnet", true},
		{inventory.EcosystemDotNetCore, "/usr/bin/dotnet-something", false},
		{inventory.EcosystemBundler, "/usr/local/bin/ruby", false}, // unmapped ecosystem never matches
	}
	for _, c := range cases {
		if got := RuntimeNameMatches(c.eco, c.path); got != c.matches {
			t.Errorf("RuntimeNameMatches(%q, %q) = %v, want %v", c.eco, c.path, got, c.matches)
		}
	}
}

// TestRuntimeNameMatches_SymlinkResolvedName documents the contract that the
// name compared is the resolved final path element, never a symlink's own
// name: a Sensor recording "ruby" as the resolved path of a "ruby3.2" binary
// (or vice versa) is a Sensor/executable-recording concern, not something
// this matcher re-resolves. This test only pins that RuntimeNameMatches
// itself does no further resolution — it trusts execPath's last element as
// given.
func TestRuntimeNameMatches_TrustsGivenPathVerbatim(t *testing.T) {
	if !RuntimeNameMatches(inventory.EcosystemGemSpec, "/usr/local/bin/ruby") {
		t.Error("expected exact final-element match for a plain path")
	}
	if RuntimeNameMatches(inventory.EcosystemGemSpec, "/usr/local/bin/ruby3.2") {
		t.Error("ruby3.2 is not one of gemspec's exact runtime names and must not match by prefix")
	}
}
