package worker

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

func cargoInput(path, role string) Input {
	in := Input{Path: path, Size: 10, SHA256: strings.Repeat("a", 64), Role: role}
	if role == RoleEmpty {
		in.Size, in.SHA256 = 0, EmptySHA256
	}
	return in
}

func goodCargoJob() *Job {
	return &Job{
		Protocol: ProtocolVersion, Manager: ManagerCargo, Runtime: testRuntime(ManagerCargo),
		Inputs: []Input{
			cargoInput("Cargo.lock", RoleLockfile), cargoInput("Cargo.toml", RoleManifest), cargoInput("src/main.rs", RoleEmpty),
			cargoInput("crates/app/Cargo.toml", RoleManifest), cargoInput("crates/app/src/lib.rs", RoleEmpty),
		},
		Steps:   []Step{{ID: "update", Op: OpCargoUpdate, Packages: []Package{{Name: "tokio", From: "1.18.0", Version: "1.18.4"}}}},
		Outputs: []string{"Cargo.lock", "Cargo.toml", "src/main.rs", "crates/app/Cargo.toml", "crates/app/src/lib.rs"},

		DeadlineSeconds: 300, StepTimeoutSeconds: 280,
	}
}

func TestCargoJobValidate(t *testing.T) {
	if err := goodCargoJob().Validate(); err != nil {
		t.Fatalf("good cargo job: %v", err)
	}
	if !RunsFromImage(ManagerCargo) || !ManagerCargo.Known() || KindFor(ManagerCargo) != KindRust {
		t.Error("cargo is not a manager that runs from the image of its Rust runtime")
	}
	many := func(j *Job, n int) {
		j.Inputs = j.Inputs[:2]
		for i := 0; len(j.Inputs) < n; i++ {
			j.Inputs = append(j.Inputs, cargoInput("src/bin/b"+strings.Repeat("x", 3)+string(rune('a'+i%26))+strings.Repeat("y", i/26)+".rs", RoleEmpty))
		}
	}
	// 512 inputs are within the limit of a Cargo job, and the other managers
	// keep theirs.
	j := goodCargoJob()
	many(j, MaxCargoInputs)
	j.Outputs = []string{"Cargo.lock"}
	if err := j.Validate(); err != nil {
		t.Errorf("%d inputs: %v", MaxCargoInputs, err)
	}
	many(j, MaxCargoInputs+1)
	if err := j.Validate(); err == nil {
		t.Errorf("%d inputs accepted", MaxCargoInputs+1)
	}
	if MaxInputs != 8 {
		t.Errorf("MaxInputs is %d", MaxInputs)
	}

	h := strings.Repeat("a", 64)
	mutations := map[string]func(*Job){
		"protocol":                   func(j *Job) { j.Protocol = 4 },
		"no lockfile":                func(j *Job) { j.Inputs = j.Inputs[1:] },
		"two lockfiles":              func(j *Job) { j.Inputs = append(j.Inputs, cargoInput("other/Cargo.lock", RoleLockfile)) },
		"a nested lockfile":          func(j *Job) { j.Inputs[0].Path = "crates/Cargo.lock" },
		"no root manifest":           func(j *Job) { j.Inputs = append(j.Inputs[:1], j.Inputs[2:]...) },
		"a manifest of another name": func(j *Job) { j.Inputs[3].Path = "crates/app/Cargo.toml.bak" },
		"a manifest as empty":        func(j *Job) { j.Inputs[3].Role = RoleEmpty; j.Inputs[3].Size = 0; j.Inputs[3].SHA256 = EmptySHA256 },
		"no role":                    func(j *Job) { j.Inputs[2].Role = "" },
		"an unknown role":            func(j *Job) { j.Inputs[2].Role = "source" },
		"empty with content":         func(j *Job) { j.Inputs[2].Size = 1 },
		"empty with another hash":    func(j *Job) { j.Inputs[2].SHA256 = h },
		"a duplicate path":           func(j *Job) { j.Inputs = append(j.Inputs, j.Inputs[2]) },
		"a file as a directory":      func(j *Job) { j.Inputs = append(j.Inputs, cargoInput("src/main.rs/x.rs", RoleEmpty)) },
		"a directory as a file":      func(j *Job) { j.Inputs = append(j.Inputs, cargoInput("crates/app", RoleEmpty)) },
		"a toolchain file":           func(j *Job) { j.Inputs = append(j.Inputs, cargoInput("rust-toolchain.toml", RoleEmpty)) },
		"a cargo directory":          func(j *Job) { j.Inputs = append(j.Inputs, cargoInput(".cargo/config.toml", RoleEmpty)) },
		"target":                     func(j *Job) { j.Inputs = append(j.Inputs, cargoInput("target/x.rs", RoleEmpty)) },
		"a foreign output":           func(j *Job) { j.Outputs = []string{"build.rs"} },
		"a duplicate output":         func(j *Job) { j.Outputs = []string{"Cargo.lock", "Cargo.lock"} },
		"no outputs":                 func(j *Job) { j.Outputs = nil },
		"a tool":                     func(j *Job) { j.Tool = testTool(ManagerNpm, "11.19.0") },
		"a replacement":              func(j *Job) { j.Replacements = []Input{{Path: "Cargo.lock", SHA256: h}} },
		"node runtime":               func(j *Job) { j.Runtime = testRuntime(ManagerNpm) },
		"a version off":              func(j *Job) { j.Runtime.Version = "1.99.0" },
		"a series off":               func(j *Job) { j.Runtime.Version = "1.101.0" },
		"pip":                        func(j *Job) { j.Runtime.Pip = "26.2.1" },
		"a scratch step":             func(j *Job) { j.Steps[0].Scratch = true },
		"no packages":                func(j *Job) { j.Steps[0].Packages = nil },
		"two packages": func(j *Job) {
			j.Steps[0].Packages = append(j.Steps[0].Packages, Package{Name: "syn", From: "2.0.0", Version: "2.0.1"})
		},
		"another op":              func(j *Job) { j.Steps[0].Op = OpGoGet },
		"a path over the archive": func(j *Job) { j.Inputs[2].Path = strings.Repeat("a", 253) },
		"a result path over 255": func(j *Job) {
			j.Steps[0].ID = strings.Repeat("s", 32)
			j.Inputs[4].Path = "crates/app/" + strings.Repeat("a", 220) + ".rs"
			j.Outputs[4] = j.Inputs[4].Path
		},
	}
	for name, mut := range mutations {
		j := goodCargoJob()
		mut(j)
		if err := j.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCargoRoleOnlyForCargo(t *testing.T) {
	j := goodGradleJob()
	j.Inputs[1].Role = RoleManifest
	if err := j.Validate(); err == nil {
		t.Error("a role on a Gradle input accepted")
	}
	g := &Job{Protocol: ProtocolVersion, Manager: ManagerGo, Runtime: testRuntime(ManagerGo),
		Inputs: []Input{{Path: "go.mod", SHA256: strings.Repeat("a", 64), Role: RoleLockfile}, {Path: "go.sum", SHA256: strings.Repeat("a", 64)}},
		Steps:  []Step{{ID: "get", Op: OpGoGet, Packages: []Package{{Name: "golang.org/x/net", Version: "v0.23.0"}}}}, Outputs: []string{"go.mod"}, DeadlineSeconds: 60}
	if err := g.Validate(); err == nil {
		t.Error("a role on a Go input accepted")
	}
	g.Inputs[0].Role = ""
	if err := g.Validate(); err != nil {
		t.Errorf("the same Go job without a role: %v", err)
	}
}

func TestCargoInputPaths(t *testing.T) {
	long := strings.Repeat("a", 255)
	for p, want := range map[string]bool{
		"Cargo.toml": true, "src/main.rs": true, "crates/app/Cargo.toml": true, "_x/y.rs": true, "a-b/c_d/e.f.rs": true,
		"a/b/c/d/e/f/g/h": true, long: true, "7zip/x.rs": true,
		"": false, "/Cargo.toml": false, "../Cargo.toml": false, "a/../b": false, "a//b": false, "./a": false, "a/./b": false,
		".cargo/config.toml": false, "a/.cargo/config": false, ".hidden": false, "-x": false, "a/-b": false,
		"rust-toolchain": false, "rust-toolchain.toml": false, "a/rust-toolchain": false, "a/b/rust-toolchain.toml": false,
		"target": false, "target/debug/x": false, "a/target/x": true, "targets/x": true,
		"a/b/c/d/e/f/g/h/i": false, long + "a": false, "a b": false, "a\\b": false, "a\nb": false, "é.rs": false, "a:b": false,
		"a/b\x00": false, "a*b": false,
	} {
		if err := ValidCargoInputPath(p); (err == nil) != want {
			t.Errorf("ValidCargoInputPath(%q) = %v, want ok=%v", p, err, want)
		}
	}
	if err := CheckCargoInputPaths([]string{"a/b", "a/c", "d"}); err != nil {
		t.Error(err)
	}
	for name, paths := range map[string][]string{
		"repeat":            {"a", "a"},
		"file then dir":     {"a", "a/b"},
		"dir then file":     {"a/b/c", "a/b"},
		"deep file and dir": {"x/y", "x/y/z/w"},
		"an invalid path":   {"a", "../b"},
	} {
		if err := CheckCargoInputPaths(paths); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCargoPackages(t *testing.T) {
	ok := func(p Package) error {
		j := goodCargoJob()
		j.Steps[0].Packages = []Package{p}
		return j.Validate()
	}
	for _, p := range []Package{
		{Name: "tokio", From: "1.18.0", Version: "1.18.4"},
		{Name: "syn", From: "2.0.9", Version: "2.0.119"},
		{Name: "a_b-c", From: "0.1.0", Version: "0.2.0-rc.1"},
		{Name: "tokio", From: "1.0.0-alpha.1", Version: "1.0.0"},
		{Name: strings.Repeat("a", 64), From: "1.0.0", Version: "1.0.1"},
	} {
		if err := ok(p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	for name, p := range map[string]Package{
		"no name":            {From: "1.0.0", Version: "1.0.1"},
		"a dash first":       {Name: "-p", From: "1.0.0", Version: "1.0.1"},
		"a long name":        {Name: strings.Repeat("a", 65), From: "1.0.0", Version: "1.0.1"},
		"a space":            {Name: "to kio", From: "1.0.0", Version: "1.0.1"},
		"an at sign":         {Name: "tokio@1", From: "1.0.0", Version: "1.0.1"},
		"a dot":              {Name: "to.kio", From: "1.0.0", Version: "1.0.1"},
		"no from":            {Name: "tokio", Version: "1.0.1"},
		"no version":         {Name: "tokio", From: "1.0.0"},
		"same version":       {Name: "tokio", From: "1.0.0", Version: "1.0.0"},
		"from with build":    {Name: "tokio", From: "1.0.0+b", Version: "1.0.1"},
		"version with build": {Name: "tokio", From: "1.0.0", Version: "1.0.1+b"},
		"a dash version":     {Name: "tokio", From: "1.0.0", Version: "-1.0.1"},
		"a dash from":        {Name: "tokio", From: "-1.0.0", Version: "1.0.1"},
		"a range":            {Name: "tokio", From: "1.0.0", Version: "^1.0.1"},
		"two numbers":        {Name: "tokio", From: "1.0", Version: "1.1"},
		"a v":                {Name: "tokio", From: "v1.0.0", Version: "v1.0.1"},
		"at least":           {Name: "tokio", From: "1.0.0", Version: "1.0.1", AtLeast: "1.0.0"},
	} {
		if err := ok(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A current version belongs to cargo.update alone.
	g := goodGradleJob()
	g.Steps[0].Packages[0].From = "1.0.0"
	if err := g.Validate(); err == nil {
		t.Error("from on a gradle package accepted")
	}
	u := &Job{Protocol: ProtocolVersion, Manager: ManagerGo, Runtime: testRuntime(ManagerGo),
		Inputs: []Input{{Path: "go.mod", SHA256: strings.Repeat("a", 64)}, {Path: "go.sum", SHA256: strings.Repeat("a", 64)}},
		Steps:  []Step{{ID: "get", Op: OpGoGet, Packages: []Package{{Name: "golang.org/x/net", Version: "v0.23.0", From: "v0.22.0"}}}}, Outputs: []string{"go.mod"}, DeadlineSeconds: 60}
	if err := u.Validate(); err == nil {
		t.Error("from on a go package accepted")
	}
}

func TestCargoResultFits(t *testing.T) {
	// Many outputs times many steps would not fit the entries of a result; the
	// job is refused before anything runs.
	j := goodCargoJob()
	j.Inputs = j.Inputs[:2]
	for i := 0; i < 80; i++ {
		j.Inputs = append(j.Inputs, cargoInput("src/bin/b"+strings.Repeat("x", i%7)+string(rune('a'+i/7))+".rs", RoleEmpty))
	}
	j.Outputs = nil
	for _, in := range j.Inputs {
		j.Outputs = append(j.Outputs, in.Path)
	}
	j.Steps = nil
	for i := 0; i < 12; i++ {
		j.Steps = append(j.Steps, Step{ID: "s" + string(rune('a'+i)), Op: OpCargoUpdate, Packages: []Package{{Name: "tokio", From: "1.18.0", Version: "1.18.4"}}})
	}
	if err := j.Validate(); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Errorf("a result of over %d entries: %v", MaxResultEntries, err)
	}
	j.Outputs = []string{"Cargo.lock"}
	if err := j.Validate(); err != nil {
		t.Errorf("the lockfile alone: %v", err)
	}
	// The size of the copies counts too.
	j.Inputs[0].Size = MaxOutTotalBytes / 6
	if err := j.Validate(); err == nil {
		t.Error("copies over the total size accepted")
	}
}

func TestCargoToolchainBin(t *testing.T) {
	for goarch, want := range map[string]string{
		"amd64": "/usr/local/rustup/toolchains/1.100.0-x86_64-unknown-linux-gnu/bin",
		"arm64": "/usr/local/rustup/toolchains/1.100.0-aarch64-unknown-linux-gnu/bin",
	} {
		got, err := CargoToolchainBin("1.100.0", goarch)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", goarch, got, err)
		}
	}
	for _, c := range [][2]string{{"1.100.0", "386"}, {"1.100.0", "riscv64"}, {"1.100.0", ""}, {"../x", "amd64"}, {"", "amd64"}, {"1.100", "amd64"}, {"1.100.0/../x", "arm64"}} {
		if got, err := CargoToolchainBin(c[0], c[1]); err == nil {
			t.Errorf("CargoToolchainBin(%q, %q) = %q", c[0], c[1], got)
		}
	}
}

func TestArgvCargo(t *testing.T) {
	j := goodCargoJob()
	a, err := Argv(*j, j.Steps[0])
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		if err == nil {
			t.Errorf("an architecture without a toolchain: %q", a)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	bin, _ := CargoToolchainBin("1.100.0", runtime.GOARCH)
	want := []string{bin + "/cargo", "update", "--manifest-path", "Cargo.toml", "-p", "tokio@1.18.0", "--precise", "1.18.4"}
	if !slices.Equal(a, want) {
		t.Errorf("argv %q", a)
	}
	// Another kind of runtime does not run it, and a name that starts with '-'
	// is refused before it becomes an argument.
	k := goodCargoJob()
	k.Runtime = testRuntime(ManagerGo)
	if _, err := Argv(*k, k.Steps[0]); err == nil {
		t.Error("cargo in a Go runtime accepted")
	}
	k = goodCargoJob()
	k.Steps[0].Packages[0].Name = "-Zunstable"
	if _, err := Argv(*k, k.Steps[0]); err == nil {
		t.Error("a name that starts with '-' accepted")
	}
}

func TestRustRuntimeID(t *testing.T) {
	for id, want := range map[string]bool{"rust1.100": true, "rust1.9": true, "rust1.0": true, "rust2.0": false, "rust1.": false, "rust1": false, "rust": false, "rust1.100.0": false, "Rust1.100": false, "rust1.0100": false} {
		spec, ok := RuntimeFromID(id)
		if ok != want || (ok && (spec.Kind != KindRust || spec.Series != id[len("rust"):])) {
			t.Errorf("RuntimeFromID(%q) = %+v, %v", id, spec, ok)
		}
	}
}
