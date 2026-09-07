package kubernetes

import (
	"context"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func TestRunningContainers_NodeMissing_PlatformZero_EntityUnresolved(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_no_node.json"))))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 1 {
		t.Fatalf("got %d containers, want 1", len(cs))
	}

	if cs[0].Image.Platform.Known() {
		t.Errorf("Platform = %+v, want zero value (pod's nodeName has no matching Node)", cs[0].Image.Platform)
	}
	if _, ok := inventory.EntityKeyOf(cs[0].Image); ok {
		t.Error("EntityKeyOf ok = true, want false: a registry digest with unknown Platform must not resolve to an entity")
	}
}

func TestRunningContainers_MixedArchitecture_DistinctEntities(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("",
		loadFixture(t, "node_amd64.json"),
		loadFixture(t, "node_arm64.json"),
	)))
	f.on("/api/v1/pods", ok(envelope("",
		loadFixture(t, "pod_mixed_arch_amd64.json"),
		loadFixture(t, "pod_mixed_arch_arm64.json"),
	)))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("got %d containers, want 2", len(cs))
	}
	if cs[0].Image.Registry.Digest.Hex == "" || cs[0].Image.Registry.Digest.Hex != cs[1].Image.Registry.Digest.Hex {
		t.Fatalf("test setup broken: both pods must share the same index digest, got %+v and %+v", cs[0].Image, cs[1].Image)
	}
	if cs[0].Image.Platform == cs[1].Image.Platform {
		t.Fatalf("test setup broken: the two pods must resolve to different Platforms, both got %+v", cs[0].Image.Platform)
	}

	images := inventory.DistinctImages(cs)
	if len(images) != 2 {
		t.Errorf("DistinctImages len = %d, want 2: the same index digest under two different running platforms is two entities, not one", len(images))
	}
}

func TestRunningContainers_NativeSidecarIncluded_OrdinaryInitExcluded(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/pods", ok(envelope("", loadFixture(t, "pod_native_sidecar.json"))))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}

	names := map[string]bool{}
	for _, ct := range cs {
		names[ct.Name] = true
	}
	const (
		mainName          = "default/app-with-sidecar-1/app"
		nativeSidecarName = "default/app-with-sidecar-1/envoy-proxy"
		ordinaryInitName  = "default/app-with-sidecar-1/wait-for-db"
	)
	if !names[mainName] {
		t.Errorf("missing main container %q; got %v", mainName, cs)
	}
	if !names[nativeSidecarName] {
		t.Errorf("missing native sidecar %q (restartPolicy Always, running); got %v", nativeSidecarName, cs)
	}
	if names[ordinaryInitName] {
		t.Errorf("ordinary init container %q must be excluded even though its status reports running; got %v", ordinaryInitName, cs)
	}
	if len(cs) != 2 {
		t.Errorf("got %d containers, want 2 (main + native sidecar); got %v", len(cs), cs)
	}
}
