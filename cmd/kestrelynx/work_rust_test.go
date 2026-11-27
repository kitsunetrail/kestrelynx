package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// The Rust row is one row of the table like the Node.js, Python and Go ones:
// it has a client made when the work containers are set up, whether or not an
// integration test has recorded it, and the official image names it.
func TestRustRowIsRunInLikeTheOtherLanguages(t *testing.T) {
	spec, ok := rustRow()
	if !ok || !spec.HasImage() {
		t.Fatal("no Rust runtime with an image")
	}
	if !slices.Contains(remediation.DefaultRuntimeIDs(), spec.ID) {
		t.Errorf("runtime ids %v", remediation.DefaultRuntimeIDs())
	}
	if got, ok := workRuntime(spec.ID, "linux/amd64"); !ok || got.ID != spec.ID {
		t.Errorf("workRuntime = %q, %v", got.ID, ok)
	}
	if _, err := onDemandRuntime(spec.ID, "linux/amd64"); err == nil {
		t.Error("a Rust row is an on-demand runtime")
	}
	if got := dockerCoverPaths(spec); len(got) != 0 {
		t.Errorf("cover paths %v", got)
	}
	if got := workImageRef(spec, ""); got != "rust@"+spec.IndexDigest {
		t.Errorf("docker: %s", got)
	}
	if got := kubernetesWorkImageRef(spec, ""); got != "docker.io/library/rust@"+spec.IndexDigest {
		t.Errorf("kubernetes: %s", got)
	}
	cfg := workTestConfig(t)
	if c, err := newDockerWorkClient(cfg, spec, "linux/amd64", "0123456789abcdef0123456789abcdef", nil, quietLog()); err != nil || c == nil {
		t.Errorf("client %v, %v", c, err)
	}
}

func TestKubernetesFindsTheImageOfTheRustRow(t *testing.T) {
	spec, _ := rustRow()
	imageFor := kubernetesImageFor("", "linux/amd64")
	if got, ok := imageFor(spec.ID); !ok || got != "docker.io/library/rust@"+spec.IndexDigest {
		t.Errorf("image of %s = %q, %v", spec.ID, got, ok)
	}
	var probed bool
	for _, img := range kubernetesProbeImages(imageFor) {
		probed = probed || strings.HasPrefix(img, "docker.io/library/rust@")
	}
	if !probed {
		t.Error("the admission check does not try the Rust image")
	}
	if cover, ok := kubernetesCover(spec); !ok || cover != "" {
		t.Errorf("cover %q, %v", cover, ok)
	}
}

// The files of a Cargo job are many, so the limits of the transfer take them.
func TestWorkTransferLimitsTakeTheFilesOfACargoJob(t *testing.T) {
	l := workTransferLimits()
	if l.MaxInputFiles < worker.MaxCargoInputs || l.MaxInputPathBytes != worker.MaxInputPathBytes {
		t.Errorf("limits %+v", l)
	}
}

// rustRow is the Rust row of the table: there is one, of the newest stable
// release, which the weekly update replaces.
func rustRow() (worker.RuntimeSpec, bool) {
	for _, r := range worker.Runtimes() {
		if r.Kind == worker.KindRust && r.HasImage() {
			return r, true
		}
	}
	return worker.RuntimeSpec{}, false
}
