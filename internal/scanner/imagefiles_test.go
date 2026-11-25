package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

type fakeImageReader struct {
	mu      sync.Mutex
	targets []imagefs.Target
	out     imagefs.Outcome
}

func (f *fakeImageReader) Read(_ context.Context, t imagefs.Target) imagefs.Outcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets = append(f.targets, t)
	return f.out
}

func (f *fakeImageReader) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.targets)
}

// outcomeAdvisor records the outcome it was handed and answers like the Java
// advisor does for it.
type outcomeAdvisor struct {
	seen *imagefs.Outcome
	scan ImageScan
}

func (a *outcomeAdvisor) Augment(scan ImageScan, _ []string) RuntimeAugment {
	a.seen, a.scan = scan.ImageFiles, scan
	return RuntimeAugment{
		Retired:         []string{"Java runtime"},
		Unchecked:       []string{"Node.js", "Java runtime"},
		UncheckedReason: map[string]string{"Java runtime": ReasonDeferred},
		JavaImage:       &JavaImageState{Kind: JavaImageDeferred, Reason: "budget"},
	}
}

var diffIDs = []string{"sha256:" + strings.Repeat("1", 64), "sha256:" + strings.Repeat("2", 64)}

// reportJSON is a Trivy report with the image config fields the hook reads.
func reportJSON(t *testing.T, imageID, arch string, env []string, repoDigests []string, results string) string {
	t.Helper()
	m := map[string]any{
		"ArtifactName": "whatever",
		"Metadata": map[string]any{
			"OS":          map[string]any{"Family": "debian"},
			"ImageID":     imageID,
			"DiffIDs":     diffIDs,
			"RepoDigests": repoDigests,
			"ImageConfig": map[string]any{"os": "linux", "architecture": arch, "config": map[string]any{"Env": env}},
		},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if results != "" {
		s = strings.TrimSuffix(s, "}") + `,"Results":` + results + "}"
	}
	return s
}

func TestHasJavaHints(t *testing.T) {
	tests := []struct {
		name string
		scan ImageScan
		want bool
	}{
		{"nothing", ImageScan{ConfigEnv: []string{"PATH=/usr/bin:/bin", "HOME=/root"}}, false},
		{"JAVA_HOME", ImageScan{ConfigEnv: []string{"JAVA_HOME=/opt/x"}}, true},
		{"JAVA_VERSION", ImageScan{ConfigEnv: []string{"JAVA_VERSION=21"}}, true},
		{"PATH with java", ImageScan{ConfigEnv: []string{"PATH=/usr/bin:/opt/java/openjdk/bin"}}, true},
		{"PATH with jre", ImageScan{ConfigEnv: []string{"PATH=/opt/jre/bin"}}, true},
		{"PATH with jvm", ImageScan{ConfigEnv: []string{"PATH=/usr/lib/jvm/x/bin"}}, true},
		{"PATH with JDK upper case", ImageScan{ConfigEnv: []string{"PATH=/opt/JDK/bin"}}, true},
		{"a variable that only mentions java", ImageScan{ConfigEnv: []string{"FOO=/opt/java", "MY_JAVA_HOME=/x"}}, false},
		{"jar package", ImageScan{Packages: []ResultPackages{{Type: "jar"}}}, true},
		{"jar finding", ImageScan{Findings: []Finding{{Type: "jar"}}}, true},
		{"jar result", ImageScan{HasJarResult: true}, true},
		{"other package", ImageScan{Packages: []ResultPackages{{Type: "pip"}}}, false},
		{"packages truncated", ImageScan{PackagesTruncated: true}, true},
		{"env truncated", ImageScan{ConfigEnvTruncated: true}, true},
	}
	for _, tt := range tests {
		if got := hasJavaHints(tt.scan); got != tt.want {
			t.Errorf("%s: hasJavaHints = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParseReport_JavaHints(t *testing.T) {
	scan, err := ParseReport([]byte(`{"Metadata":{"ImageConfig":{"config":{"Env":["A=1"]}}},"Results":[{"Class":"lang-pkgs","Type":"jar","Target":"Java","Packages":[{"Name":"a:b","Version":"1"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !scan.HasJarResult || scan.ConfigEnvTruncated {
		t.Errorf("HasJarResult %v ConfigEnvTruncated %v", scan.HasJarResult, scan.ConfigEnvTruncated)
	}
	if scan, _ = ParseReport([]byte(`{"Results":[{"Class":"lang-pkgs","Type":"pip","Target":"Python"}]}`)); scan.HasJarResult {
		t.Error("HasJarResult for a pip Result")
	}

	// A jar Result with no package is no hint of Java.
	if scan, _ = ParseReport([]byte(`{"Results":[{"Class":"lang-pkgs","Type":"jar","Target":"Java","Packages":[]}]}`)); scan.HasJarResult {
		t.Error("HasJarResult for a jar Result without packages")
	}
	if scan, _ = ParseReport([]byte(`{"Results":[{"Class":"lang-pkgs","Type":"jar","Target":"Java","Packages":[{"Name":"a:b","Version":"1"}]}]}`)); !scan.HasJarResult {
		t.Error("no HasJarResult for a jar Result with a package")
	}

	long := strings.Repeat("x", maxConfigEnvLen+1)
	scan, _ = ParseReport([]byte(fmt.Sprintf(`{"Metadata":{"ImageConfig":{"config":{"Env":["A=1",%q]}}}}`, long)))
	if !scan.ConfigEnvTruncated || len(scan.ConfigEnv) != 1 {
		t.Errorf("a long entry: truncated %v, env %d", scan.ConfigEnvTruncated, len(scan.ConfigEnv))
	}
	var env []string
	for i := 0; i < maxConfigEnv+1; i++ {
		env = append(env, fmt.Sprintf("V%d=1", i))
	}
	b, _ := json.Marshal(map[string]any{"Metadata": map[string]any{"ImageConfig": map[string]any{"config": map[string]any{"Env": env}}}})
	scan, _ = ParseReport(b)
	if !scan.ConfigEnvTruncated || len(scan.ConfigEnv) != maxConfigEnv {
		t.Errorf("too many entries: truncated %v, env %d", scan.ConfigEnvTruncated, len(scan.ConfigEnv))
	}
	b, _ = json.Marshal(map[string]any{"Metadata": map[string]any{"ImageConfig": map[string]any{"config": map[string]any{"Env": env[:maxConfigEnv]}}}})
	if scan, _ = ParseReport(b); scan.ConfigEnvTruncated {
		t.Error("exactly the maximum count is not a truncation")
	}
}

func TestScan_ImageFiles_DockerTarget(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "app:1", id)
	rd := &fakeImageReader{out: imagefs.Outcome{Kind: imagefs.Complete}}
	adv := &outcomeAdvisor{}
	bin := writeFakeTrivy(t, filepath.Join(t.TempDir(), "args"), reportJSON(t, id, "amd64", []string{"JAVA_HOME=/opt/java/openjdk"}, nil, ""), false)

	scan := Trivy{BinPath: bin, ImageFiles: rd, Runtimes: []RuntimeAdvisor{adv}}.Scan(context.Background(), target)
	if scan.Err != nil || !scan.Pinned {
		t.Fatalf("scan: err %v pinned %v", scan.Err, scan.Pinned)
	}
	want := imagefs.DockerTarget(id, inventory.Platform{OS: "linux", Architecture: "amd64"}, diffIDs)
	want.JavaHome = "/opt/java/openjdk" // the image's own JAVA_HOME, resolved later in the image
	if len(rd.targets) != 1 || !reflect.DeepEqual(rd.targets[0], want) {
		t.Fatalf("targets = %+v, want %+v", rd.targets, want)
	}
	if adv.seen == nil || adv.seen.Kind != imagefs.Complete || scan.ImageFiles == nil {
		t.Errorf("the advisor did not get the outcome: %+v", adv.seen)
	}
}

func TestScan_ImageFiles_RegistryTarget(t *testing.T) {
	digest := "sha256:" + strings.Repeat("f", 64)
	target := registryTarget(t, "app:1", "ghcr.io/o/app", digest, "linux", "arm64")
	rd := &fakeImageReader{out: imagefs.Outcome{Kind: imagefs.Complete}}
	bin := writeFakeTrivy(t, filepath.Join(t.TempDir(), "args"),
		reportJSON(t, "", "arm64", []string{"JAVA_VERSION=21"}, []string{"ghcr.io/o/app@" + digest}, ""), false)

	scan := Trivy{BinPath: bin, ImageFiles: rd}.Scan(context.Background(), target)
	if scan.Err != nil || !scan.Pinned {
		t.Fatalf("scan: err %v pinned %v", scan.Err, scan.Pinned)
	}
	want := imagefs.RegistryTarget("ghcr.io/o/app", digest, inventory.Platform{OS: "linux", Architecture: "arm64"}, diffIDs)
	if len(rd.targets) != 1 || !reflect.DeepEqual(rd.targets[0], want) {
		t.Fatalf("targets = %+v, want %+v", rd.targets, want)
	}
}

func TestScan_ImageFiles_RefOnlyIsPermanent(t *testing.T) {
	// An image that was not resolved is scanned by reference alone.
	target := ScanTarget{Subject: inventory.ImageSubject{Ref: "app:1"}, Source: SourceLocal}
	rd := &fakeImageReader{}
	adv := &outcomeAdvisor{}
	bin := writeFakeTrivy(t, filepath.Join(t.TempDir(), "args"), reportJSON(t, "sha256:"+strings.Repeat("c", 64), "amd64", []string{"JAVA_HOME=/x"}, nil, ""), false)

	Trivy{BinPath: bin, ImageFiles: rd, Runtimes: []RuntimeAdvisor{adv}}.Scan(context.Background(), target)
	if rd.calls() != 0 {
		t.Errorf("the reader was called %d times for a ref-only scan", rd.calls())
	}
	if adv.seen == nil || adv.seen.Kind != imagefs.Permanent || adv.seen.Reason != ReasonRefOnly {
		t.Errorf("outcome = %+v", adv.seen)
	}
}

func TestScan_ImageFiles_NotCalledWithoutHints(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "app:1", id)
	rd := &fakeImageReader{out: imagefs.Outcome{Kind: imagefs.Complete}}
	adv := &outcomeAdvisor{}
	bin := writeFakeTrivy(t, filepath.Join(t.TempDir(), "args"), reportJSON(t, id, "amd64", []string{"PATH=/usr/bin", "LANG=C"}, nil, ""), false)

	scan := Trivy{BinPath: bin, ImageFiles: rd, Runtimes: []RuntimeAdvisor{adv}}.Scan(context.Background(), target)
	if rd.calls() != 0 || scan.ImageFiles != nil || adv.seen != nil {
		t.Errorf("read without a hint: calls %d, outcome %+v", rd.calls(), scan.ImageFiles)
	}
}

func TestScan_ImageFiles_NotCalledWithoutReaderOrOnFailure(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "app:1", id)
	adv := &outcomeAdvisor{}
	bin := writeFakeTrivy(t, filepath.Join(t.TempDir(), "args"), reportJSON(t, id, "amd64", []string{"JAVA_HOME=/x"}, nil, ""), false)
	if scan := (Trivy{BinPath: bin, Runtimes: []RuntimeAdvisor{adv}}).Scan(context.Background(), target); scan.ImageFiles != nil || adv.seen != nil {
		t.Error("an outcome without a reader")
	}

	// A scan of another entity than the one asked for fails and reads nothing.
	rd := &fakeImageReader{}
	other := "sha256:" + strings.Repeat("d", 64)
	bin = writeFakeTrivy(t, filepath.Join(t.TempDir(), "args"), reportJSON(t, other, "amd64", []string{"JAVA_HOME=/x"}, nil, ""), false)
	if scan := (Trivy{BinPath: bin, ImageFiles: rd}).Scan(context.Background(), target); scan.Err == nil || rd.calls() != 0 {
		t.Errorf("err %v, reads %d", scan.Err, rd.calls())
	}
}

func TestScan_ImageFiles_JarResultIsAHint(t *testing.T) {
	id := "sha256:" + strings.Repeat("c", 64)
	target := pinnedTarget(t, "app:1", id)
	rd := &fakeImageReader{out: imagefs.Outcome{Kind: imagefs.Complete}}
	results := `[{"Class":"lang-pkgs","Type":"jar","Target":"Java","Packages":[{"Name":"a:b","Version":"1"}]}]`
	bin := writeFakeTrivy(t, filepath.Join(t.TempDir(), "args"), reportJSON(t, id, "amd64", []string{"PATH=/usr/bin"}, nil, results), false)
	Trivy{BinPath: bin, ImageFiles: rd}.Scan(context.Background(), target)
	if rd.calls() != 1 {
		t.Errorf("reads = %d, want 1", rd.calls())
	}
}

func TestAugment_CollectsReasonsAndRetired(t *testing.T) {
	adv := &outcomeAdvisor{}
	scan := Trivy{Runtimes: []RuntimeAdvisor{adv}}.augment(ImageScan{Image: "app:1"})
	if !reflect.DeepEqual(scan.RuntimeUnchecked, []string{"Java runtime", "Node.js"}) {
		t.Errorf("RuntimeUnchecked = %v", scan.RuntimeUnchecked)
	}
	// A reason the advisor leaves out is "advisories".
	wantReason := map[string]string{"Java runtime": "deferred", "Node.js": "advisories"}
	if !reflect.DeepEqual(scan.RuntimeUncheckedReason, wantReason) {
		t.Errorf("RuntimeUncheckedReason = %v", scan.RuntimeUncheckedReason)
	}
	if !reflect.DeepEqual(scan.RuntimeRetired, []string{"Java runtime"}) {
		t.Errorf("RuntimeRetired = %v", scan.RuntimeRetired)
	}
	if scan.JavaImage != (JavaImageState{Kind: "deferred", Reason: "budget"}) {
		t.Errorf("JavaImage = %+v", scan.JavaImage)
	}
}

type emptyAdvisor struct{}

func (emptyAdvisor) Augment(ImageScan, []string) RuntimeAugment { return RuntimeAugment{} }

func TestAugment_NothingUncheckedLeavesFieldsNil(t *testing.T) {
	scan := Trivy{Runtimes: []RuntimeAdvisor{emptyAdvisor{}}}.augment(ImageScan{Image: "app:1"})
	if scan.RuntimeUnchecked != nil || scan.RuntimeUncheckedReason != nil || scan.RuntimeRetired != nil || scan.JavaImage != (JavaImageState{}) {
		t.Errorf("scan = %+v", scan)
	}
}
