package kubework

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/workexec"
)

const (
	testGoImg      = "docker.io/library/golang@sha256:" + "3333333333333333333333333333333333333333333333333333333333333333"
	testGradleImg  = "docker.io/library/gradle@sha256:" + "4444444444444444444444444444444444444444444444444444444444444444"
	testNode22Img  = "docker.io/library/node@sha256:" + "5555555555555555555555555555555555555555555555555555555555555555"
	testPythonImg  = "docker.io/library/python@sha256:" + "6666666666666666666666666666666666666666666666666666666666666666"
	testGradle2Img = "docker.io/library/gradle@sha256:" + "7777777777777777777777777777777777777777777777777777777777777777"
)

// manyImagesRunner is a runner whose work images come from four repositories,
// one of them (Gradle's) known only through ProbeImages.
func manyImagesRunner(t *testing.T, f *fakeAPI) *Runner {
	t.Helper()
	r, err := NewRunner(Config{
		API: f, Namespace: "kestrelynx-work", ServiceAccount: "kestrelynx-work", PriorityClass: "kestrelynx-work", Arch: "amd64",
		ReceiverImage: testRecvImg,
		Images:        map[string]string{"node24": testNodeImg, "node22": testNode22Img, "python313": testPythonImg, "go126": testGoImg},
		ProbeImages:   []string{testGradleImg, testGradle2Img},
		Entrypoint:    []string{"/work/bin/kestrelynx-worker", "run-kubernetes", "/work/job.json"},
		Env:           []string{"PATH=/usr/bin", "HOME=/home/worker"},
		InstanceID:    testInstance, SessionID: testSession, MaxConcurrent: 1,
		Limits:            workexec.TransferLimits{MaxInputBytes: 1 << 20, MaxInputTarBytes: 4 << 20, MaxInputFiles: 12, MaxInputPathBytes: 256, MaxToolBytes: 1 << 20, MaxProgramBytes: 1 << 20},
		MaxResultTarBytes: 1 << 20, Poll: time.Millisecond,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func imageRuleRefusal() *APIError {
	return &APIError{Code: 422, Message: refusalPrefix() + RuleMessage("images")}
}

// The check tries one image of each repository, in the same order every time.
func TestProbeImages(t *testing.T) {
	r := manyImagesRunner(t, newFake())
	want := []string{testGoImg, testGradleImg, testNodeImg, testPythonImg}
	for i := 0; i < 20; i++ {
		if got := r.probeImages(); !reflect.DeepEqual(got, want) {
			t.Fatalf("probe images %v, want %v", got, want)
		}
	}
}

// A policy that allows the repositories of some languages only is still
// verified: the right Pod is the one with an image the policy accepts.
func TestVerifyAdmissionWithSomeRepositories(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed string
		tries   int
	}{
		{"first", testGoImg, 1},
		{"probe image only", testGradleImg, 2},
		{"third", testNodeImg, 3},
		{"last", testPythonImg, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			r := manyImagesRunner(t, f)
			// The cluster refuses the right Pod of every image before the
			// allowed one, as the policy's image rule would.
			f.createErr = func(dry bool, n int) error {
				if dry && n < tc.tries {
					return imageRuleRefusal()
				}
				return nil
			}
			if p := r.VerifyAdmission(context.Background()); p != nil {
				t.Fatal(p)
			}
			if got := workOf(f.good)["image"]; got != tc.allowed {
				t.Errorf("the check went on with %v, want %v", got, tc.allowed)
			}
			if len(f.probes) != len(probes()) {
				t.Errorf("%d probes made, want %d", len(f.probes), len(probes()))
			}
		})
	}
}

// When the image rule refuses the right Pod of every repository, the check
// fails and says which parameters to look at.
func TestVerifyAdmissionNoRepositoryAllowed(t *testing.T) {
	f := newFake()
	r := manyImagesRunner(t, f)
	f.createErr = func(bool, int) error { return imageRuleRefusal() }
	p := r.VerifyAdmission(context.Background())
	if p == nil || !p.Manual || p.Reason != ReasonAdmissionUnverified {
		t.Fatalf("got %v, want a manual %s", p, ReasonAdmissionUnverified)
	}
	for _, want := range []string{"receiverRepository", "docker.io/library/kestrelynx", "workRepositories",
		"docker.io/library/golang", "docker.io/library/gradle", "docker.io/library/node", "docker.io/library/python"} {
		if !strings.Contains(p.Detail, want) {
			t.Errorf("the detail %q does not name %s", p.Detail, want)
		}
	}
	if f.creates != 4 {
		t.Errorf("%d dry runs, want one for each of 4 repositories", f.creates)
	}
}

// Another refusal of the right Pod is not retried with the next image.
func TestVerifyAdmissionOtherRefusalStops(t *testing.T) {
	f := newFake()
	r := manyImagesRunner(t, f)
	f.createErr = func(bool, int) error {
		return &APIError{Code: 422, Message: refusalPrefix() + RuleMessage("resources")}
	}
	p := r.VerifyAdmission(context.Background())
	if p == nil || p.Reason != ReasonAdmissionUnverified || !strings.Contains(p.Detail, "the right Pod was not accepted") {
		t.Fatalf("got %v", p)
	}
	if f.creates != 1 {
		t.Errorf("%d dry runs, want 1", f.creates)
	}
}

// A job whose image the policy does not allow fails with a message that names
// the repository to add.
func TestRunJobImageNotAllowed(t *testing.T) {
	f := newFake()
	r := manyImagesRunner(t, f)
	verified(t, r)
	f.createErr = func(dry bool, _ int) error {
		if dry {
			return nil
		}
		return imageRuleRefusal()
	}
	spec := testSpec("job-1")
	spec.Runtime = "python313"
	_, err := r.RunJob(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "workRepositories") || !strings.Contains(err.Error(), "docker.io/library/python") {
		t.Fatalf("got %v", err)
	}
	var un *workexec.Unavailable
	if errors.As(err, &un) {
		t.Errorf("the failure is reported as unavailable: %v", un)
	}
}

// After the image rule refuses one repository, another refusal of the next
// one ends the check there.
func TestVerifyAdmissionOtherRefusalAfterImageRule(t *testing.T) {
	f := newFake()
	r := manyImagesRunner(t, f)
	f.createErr = func(_ bool, n int) error {
		if n == 1 {
			return imageRuleRefusal()
		}
		return &APIError{Code: 422, Message: refusalPrefix() + RuleMessage("resources")}
	}
	p := r.VerifyAdmission(context.Background())
	if p == nil || p.Reason != ReasonAdmissionUnverified || !strings.Contains(p.Detail, "the right Pod was not accepted") {
		t.Fatalf("got %v", p)
	}
	if f.creates != 2 {
		t.Errorf("%d dry runs, want 2", f.creates)
	}
}

func TestRefusedByImageRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the image rule", imageRuleRefusal(), true},
		{"wrapped", fmt.Errorf("create the Pod: %w", imageRuleRefusal()), true},
		{"another rule", &APIError{Code: 422, Message: refusalPrefix() + RuleMessage("resources")}, false},
		{"another policy", &APIError{Code: 422, Message: "ValidatingAdmissionPolicy 'other' with binding 'other' denied request: " + RuleMessage("images")}, false},
		{"not an API error", errors.New(refusalPrefix() + RuleMessage("images")), false},
		{"no error", nil, false},
	} {
		if got := refusedByImageRule(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A runtime table that is replaced while the process runs is served without a
// list made at the start: the image of a runtime is looked up when a job asks
// for it, and the images of the admission check when the check runs.
func TestRunnerLooksImagesUpOnDemand(t *testing.T) {
	base := Config{
		API: newFake(), Namespace: "kestrelynx-work", ServiceAccount: "kestrelynx-work", PriorityClass: "kestrelynx-work", Arch: "amd64",
		ReceiverImage: testRecvImg,
		Entrypoint:    []string{"/work/bin/kestrelynx-worker", "run-kubernetes", "/work/job.json"},
		Env:           []string{"PATH=/usr/bin", "HOME=/home/worker"},
		InstanceID:    testInstance, SessionID: testSession, MaxConcurrent: 1,
		Limits:            workexec.TransferLimits{MaxInputBytes: 1 << 20, MaxInputTarBytes: 4 << 20, MaxInputFiles: 12, MaxInputPathBytes: 256, MaxToolBytes: 1 << 20, MaxProgramBytes: 1 << 20},
		MaxResultTarBytes: 1 << 20, Poll: time.Millisecond,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if _, err := NewRunner(base); err == nil {
		t.Fatal("a runner without any way to find a work image was made")
	}

	table := map[string]string{"gradle9": testGradleImg}
	cfg := base
	cfg.ImageFor = func(key string) (string, bool) { img, ok := table[key]; return img, ok }
	cfg.ProbeImagesFor = func() []string {
		var out []string
		for _, img := range table {
			out = append(out, img)
		}
		return out
	}
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatalf("a runner that looks its images up on demand is refused: %v", err)
	}
	if got := r.probeImages(); !reflect.DeepEqual(got, []string{testGradleImg}) {
		t.Fatalf("probe images %v", got)
	}
	// The table changes; the next check and the next job see it.
	table = map[string]string{"node24": testNodeImg, "go126": testGoImg}
	if got := r.probeImages(); !reflect.DeepEqual(got, []string{testGoImg, testNodeImg}) {
		t.Fatalf("probe images after the change %v", got)
	}
	if _, err := r.RunJob(context.Background(), workexec.JobSpec{Runtime: "gradle9", JobID: "j", Timeout: time.Second}); err == nil || !strings.Contains(err.Error(), "no work image") {
		t.Fatalf("a job for a runtime the table no longer has: %v", err)
	}
}
