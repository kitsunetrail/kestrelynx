package main

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/kubework"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/runner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

func kubeWorkConfig(t *testing.T, apiURL string, ca []byte) config.Config {
	t.Helper()
	cfg := workTestConfig(t)
	dir := t.TempDir()
	tok, cafile := filepath.Join(dir, "token"), filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(tok, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cafile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Kubernetes = config.KubernetesConfig{Enabled: true, APIServer: apiURL, TokenFile: tok, CAFile: cafile}
	cfg.Remediation.Worker.Kubernetes = config.RemediationWorkerKubernetes{
		Namespace: "kestrelynx-work", ServiceAccount: "kestrelynx-work", PriorityClass: "kestrelynx-work", MaxConcurrentPods: 2,
		ReceiverImage: "docker.io/library/kestrelynx@sha256:" + strings.Repeat("a", 64),
	}
	withProgramDir(t, &cfg, "program")
	return cfg
}

func TestKubernetesLanguageConfigWithoutANamespaceIsManual(t *testing.T) {
	lc := kubernetesLanguageConfig(config.Config{}, quietLog())
	if lc.NewUpdater != nil || lc.Unavailable == nil || !lc.Unavailable.Manual || lc.Unavailable.Reason != remediation.ReasonWorkNamespaceNotConfigured {
		t.Errorf("config = %+v", lc)
	}
}

func TestKubernetesLanguageConfigProblems(t *testing.T) {
	withToolSupply(t, okToolSupply)
	t.Run("program missing", func(t *testing.T) {
		cfg := workTestConfig(t)
		cfg.Remediation.Worker.Kubernetes.Namespace = "kestrelynx-work"
		cfg.Remediation.Worker.ProgramDir = t.TempDir()
		lc := kubernetesLanguageConfig(cfg, quietLog())
		if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageUnavailable || lc.NewUpdater != nil {
			t.Errorf("config = %+v", lc)
		}
	})
	t.Run("not in a cluster", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		cfg := workTestConfig(t)
		cfg.Remediation.Worker.Kubernetes = config.RemediationWorkerKubernetes{Namespace: "kestrelynx-work", ServiceAccount: "a", PriorityClass: "b", MaxConcurrentPods: 1}
		withProgramDir(t, &cfg, "program")
		lc := kubernetesLanguageConfig(cfg, quietLog())
		if lc.Unavailable == nil || lc.Unavailable.Reason != remediation.ReasonWorkImageUnavailable || lc.NewUpdater != nil {
			t.Errorf("config = %+v", lc)
		}
	})
}

// With everything set the stage is built on work Pods, the collector runs, and
// the policy is checked when a cycle begins: an old cluster stops the cycle's
// updates with the executor's own reason.
func TestKubernetesLanguageConfigChecksTheClusterEachCycle(t *testing.T) {
	withToolSupply(t, okToolSupply)
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/version":
			w.Write([]byte(`{"major":"1","minor":"29"}`))
		default:
			w.Write([]byte(`{"items":[]}`))
		}
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cfg := kubeWorkConfig(t, srv.URL, ca)
	lc := kubernetesLanguageConfig(cfg, quietLog())
	if lc.Unavailable != nil || lc.NewUpdater == nil {
		t.Fatalf("config = %+v", lc)
	}
	for i := 0; i < 2; i++ {
		_, err := lc.NewUpdater(context.Background(), runner.LanguageUpdateInput{})
		var un *workexec.Unavailable
		if !errors.As(err, &un) || un.Reason != "work_cluster_too_old" || !un.Manual {
			t.Fatalf("cycle %d: error = %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	versions := 0
	for _, p := range paths {
		if p == "GET /version" {
			versions++
		}
		if !strings.HasPrefix(p, "GET ") {
			t.Errorf("a request that is not a read: %s", p)
		}
	}
	if versions != 2 {
		t.Errorf("the cluster was checked %d times in 2 cycles (%v)", versions, paths)
	}
}

func TestKubernetesWorkImageRefNamesTheRegistry(t *testing.T) {
	spec, ok := worker.LookupRuntime(remediation.DefaultRuntimeIDs()[0])
	if !ok {
		t.Fatal("no runtime")
	}
	if got, want := kubernetesWorkImageRef(spec, ""), "docker.io/library/"+spec.ImageRef(); got != want {
		t.Errorf("without a mirror = %q, want %q", got, want)
	}
	if got, want := kubernetesWorkImageRef(spec, "registry.example.com/dockerhub"), "registry.example.com/dockerhub/library/"+spec.ImageRef(); got != want {
		t.Errorf("with a mirror = %q, want %q", got, want)
	}
}

func TestKubernetesLanguageConfigRefusesARuntimeClass(t *testing.T) {
	withToolSupply(t, okToolSupply)
	cfg := workTestConfig(t)
	withProgramDir(t, &cfg, "program")
	cfg.Remediation.Worker.Kubernetes = config.RemediationWorkerKubernetes{
		Namespace: "kestrelynx-work", ServiceAccount: "a", PriorityClass: "b", MaxConcurrentPods: 1, RuntimeClass: "gvisor",
	}
	lc := kubernetesLanguageConfig(cfg, quietLog())
	if lc.NewUpdater != nil || lc.Unavailable == nil || !lc.Unavailable.Manual || lc.Unavailable.Reason != remediation.ReasonWorkRuntimeClassUnsupported {
		t.Errorf("config = %+v", lc)
	}
}

// Every volume an image of the table declares is one a work Pod covers, so a
// row whose image declares another is noticed when the table is updated.
func TestKubernetesCoversEveryDeclaredVolume(t *testing.T) {
	covered := 0
	for _, spec := range worker.Runtimes() {
		cover, ok := kubernetesCover(spec)
		if !ok {
			t.Errorf("%s: the volumes %v cannot be covered in a work Pod", spec.ID, spec.Volumes)
		}
		if cover != "" {
			covered++
		}
	}
	if covered == 0 {
		t.Error("no row declares a volume; the Gradle rows do")
	}
	if _, ok := kubernetesCover(worker.RuntimeSpec{Volumes: []string{"/data"}}); ok {
		t.Error("a volume outside the list was accepted")
	}
	if _, ok := kubernetesCover(worker.RuntimeSpec{Volumes: []string{"/home/gradle/.gradle", "/data"}}); ok {
		t.Error("two volumes were accepted")
	}
}

// The image of this process's container is read again while the Pod's status
// does not report it, as right after the container started. Any other error
// ends the reading at the read that gave it, and a status that never reports
// the image gives an error once the time is up.
func TestReadOwnImageWaitsForTheStatus(t *testing.T) {
	const id = "ghcr.io/kitsunetrail/kestrelynx@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	type answer struct {
		id  string
		err error
	}
	// reader gives the answers in turn, the last one repeating, and counts the
	// reads.
	reader := func(answers ...answer) (func(context.Context) (string, error), *int) {
		reads := 0
		return func(context.Context) (string, error) {
			reads++
			a := answers[min(reads, len(answers))-1]
			return a.id, a.err
		}, &reads
	}
	notYet := answer{"", kubework.ErrImageNotReported}

	read, reads := reader(notYet, notYet, answer{id, nil})
	if got, err := readOwnImage(context.Background(), read, time.Millisecond, nil); err != nil || got != id || *reads != 3 {
		t.Fatalf("got %q, %v after %d reads", got, err, *reads)
	}

	forbidden := errors.New("forbidden")
	read, reads = reader(notYet, answer{"", forbidden})
	if _, err := readOwnImage(context.Background(), read, time.Millisecond, nil); !errors.Is(err, forbidden) || *reads != 2 {
		t.Fatalf("err = %v after %d reads, want the error of the second read", err, *reads)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	read, _ = reader(notYet)
	if got, err := readOwnImage(ctx, read, time.Millisecond, nil); !errors.Is(err, kubework.ErrImageNotReported) || got != "" {
		t.Fatalf("got %q, %v for a status that never reports the image", got, err)
	}
}
