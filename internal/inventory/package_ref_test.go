package inventory

import "testing"

func TestRuntimeVersionEnv(t *testing.T) {
	for eco, want := range map[Ecosystem]string{
		EcosystemNodeRuntime: "NODE_VERSION", EcosystemPythonRuntime: "PYTHON_VERSION", EcosystemJavaRuntime: "JAVA_VERSION", EcosystemNpm: "", EcosystemPip: "", "": "",
	} {
		if got := RuntimeVersionEnv(eco); got != want {
			t.Errorf("RuntimeVersionEnv(%q) = %q, want %q", eco, got, want)
		}
	}
}

func TestRuntimeLocationEnv(t *testing.T) {
	for eco, want := range map[Ecosystem]string{
		EcosystemJavaRuntime: "JAVA_HOME", EcosystemNodeRuntime: "", EcosystemPythonRuntime: "", EcosystemJar: "", "": "",
	} {
		if got := RuntimeLocationEnv(eco); got != want {
			t.Errorf("RuntimeLocationEnv(%q) = %q, want %q", eco, got, want)
		}
	}
}

func TestParseEcosystem_JavaRuntime(t *testing.T) {
	if got := ParseEcosystem("java-runtime"); got != EcosystemJavaRuntime {
		t.Errorf("ParseEcosystem(java-runtime) = %q", got)
	}
}
