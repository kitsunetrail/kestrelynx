package docker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func coverConfig(paths ...string) WorkConfig {
	return WorkConfig{Image: testImage, Platform: "linux/amd64", Entrypoint: []string{"/w"}, AllowedEnvKeys: []string{"HOME"},
		InstanceID: testInstance, Limits: testLimits(), CoverPaths: paths}
}

func TestCoverPathsAreValidated(t *testing.T) {
	if _, err := newWorkClient("x", nil, coverConfig("/home/gradle", "/home/gradle/.gradle", "/var/lib/pebble/default")); err != nil {
		t.Fatal(err)
	}
	for name, paths := range map[string][]string{
		"relative":         {"home/gradle"},
		"empty":            {""},
		"root":             {"/"},
		"not clean":        {"/home/../etc"},
		"trailing slash":   {"/home/gradle/"},
		"repeated":         {"/home/gradle", "/home/gradle"},
		"a fixed mount":    {"/tmp"},
		"the tools":        {"/opt/kestrelynx-tools"},
		"the go path":      {"/go"},
		"a comma":          {"/a,b"},
		"a colon":          {"/a:b"},
		"a nul":            {"/a\x00b"},
		"a backslash":      {"/a\\b"},
		"the home of jobs": {"/home/worker"},
	} {
		if _, err := newWorkClient("x", nil, coverConfig(paths...)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCreateBodyCoversTheConfiguredPaths(t *testing.T) {
	c, err := newWorkClient("x", nil, coverConfig("/home/gradle", "/home/gradle/.gradle"))
	if err != nil {
		t.Fatal(err)
	}
	body := c.buildCreateBody("job1", testRes())
	for _, p := range []string{"/home/gradle", "/home/gradle/.gradle"} {
		opts, ok := body.Host.Tmpfs[p]
		if !ok || !strings.Contains(opts, "size=1048576") || !strings.Contains(opts, "mode=0755") || strings.Contains(opts, "uid=") || strings.Contains(opts, "exec") {
			t.Errorf("%s: %q (covered %v)", p, opts, ok)
		}
	}
	if len(body.Host.Tmpfs) != 8 {
		t.Errorf("tmpfs %v", body.Host.Tmpfs)
	}
	// A client without them mounts the same six as before.
	plain, _ := newWorkClient("x", nil, coverConfig())
	if n := len(plain.buildCreateBody("job1", testRes()).Host.Tmpfs); n != 6 {
		t.Errorf("%d mounts without cover paths", n)
	}
}

func TestDeclaredVolumesAreAcceptedOnlyWhereATmpfsTakesTheirPlace(t *testing.T) {
	c, _ := newWorkClient("x", nil, coverConfig("/home/gradle", "/home/gradle/.gradle"))
	plain, _ := newWorkClient("x", nil, coverConfig())
	img := imageInspect{Os: "linux", Architecture: "amd64", RepoDigests: []string{testImage}}
	img.Config.Volumes = map[string]json.RawMessage{"/home/gradle/.gradle": nil}
	if err := c.verifyImage(img); err != nil {
		t.Errorf("a covered volume: %v", err)
	}
	if err := plain.verifyImage(img); err == nil || !strings.Contains(err.Error(), "volume") {
		t.Errorf("an uncovered volume: %v", err)
	}
	img.Config.Volumes = map[string]json.RawMessage{"/home/gradle/.gradle": nil, "/data": nil}
	if err := c.verifyImage(img); err == nil {
		t.Error("a volume nothing covers accepted")
	}

	// The container the daemon made: the declared volume is in its config, and
	// there must be no mount for it.
	body := c.buildCreateBody("job1", testRes())
	got := inspectOf(body)
	got.Config.Volumes = map[string]any{"/home/gradle/.gradle": map[string]any{}}
	if bad := verifyInspect(body, got); len(bad) != 0 {
		t.Errorf("a covered volume: %v", bad)
	}
	got.Mounts = []any{map[string]any{"Type": "volume", "Destination": "/home/gradle/.gradle"}}
	if bad := verifyInspect(body, got); len(bad) == 0 {
		t.Error("an anonymous volume accepted")
	}
	got.Mounts = nil
	got.Config.Volumes = map[string]any{"/data": map[string]any{}}
	if bad := verifyInspect(body, got); len(bad) == 0 {
		t.Error("a volume nothing covers accepted")
	}
}

func TestWorkSetMakesTheClientOfARuntimeWhenAJobAsksForIt(t *testing.T) {
	f, c := newFake(t)
	f.logsBody = frames(1, "ok")
	set := NewWorkSet()
	var asked []string
	set.SetFactory(func(key string) (*WorkClient, error) {
		asked = append(asked, key)
		switch key {
		case "made":
			return c, nil
		case "refused":
			return nil, errors.New("not a runtime of this kind")
		}
		return nil, nil
	})
	if len(set.Keys()) != 0 || len(asked) != 0 {
		t.Fatal("a client was made before a job asked")
	}
	s := spec()
	s.Runtime = "made"
	for i := 0; i < 2; i++ {
		if res, err := set.RunJob(context.Background(), s); err != nil || string(res.Stdout) != "ok" {
			t.Fatalf("%v %v", res, err)
		}
	}
	if len(asked) != 1 || asked[0] != "made" || len(set.Keys()) != 1 {
		t.Errorf("asked %v, keys %v", asked, set.Keys())
	}
	for _, key := range []string{"refused", "nil"} {
		s.Runtime = key
		if _, err := set.RunJob(context.Background(), s); err == nil || !strings.Contains(err.Error(), "no work client") {
			t.Errorf("%s: %v", key, err)
		}
	}
	if len(set.Keys()) != 1 {
		t.Errorf("keys %v", set.Keys())
	}
	// Without a factory an unknown runtime has no client.
	plain := NewWorkSet()
	s.Runtime = "made"
	if _, err := plain.RunJob(context.Background(), s); err == nil {
		t.Error("ran without a client")
	}
}

func TestWorkSetFactoryClientsShareTheInstance(t *testing.T) {
	_, c := newFake(t)
	other, _ := newWorkClient("x", nil, coverConfig())
	other.cfg.InstanceID = strings.Repeat("a", 32)
	set := NewWorkSet()
	if err := set.Add("a", c); err != nil {
		t.Fatal(err)
	}
	set.SetFactory(func(string) (*WorkClient, error) { return other, nil })
	s := spec()
	s.Runtime = "b"
	if _, err := set.RunJob(context.Background(), s); err == nil {
		t.Error("a client of another installation was made")
	}
	if len(set.Keys()) != 1 {
		t.Errorf("keys %v", set.Keys())
	}
}

// inspectOf is what the daemon reports for a container made from body when it
// applied everything as asked.
func inspectOf(body createBody) workInspect {
	var got workInspect
	got.Config.User, got.Config.WorkingDir, got.Config.Entrypoint, got.Config.Labels = body.User, body.WorkingDir, body.Entrypoint, body.Labels
	got.Config.Healthcheck = &struct {
		Test []string `json:"Test"`
	}{Test: body.Healthcheck.Test}
	h, w := &got.HostConfig, body.Host
	h.ReadonlyRootfs, h.Tmpfs, h.CapDrop, h.SecurityOpt = w.ReadonlyRootfs, w.Tmpfs, w.CapDrop, w.SecurityOpt
	h.NetworkMode, h.Memory, h.MemorySwap, h.NanoCpus, h.PidsLimit = w.NetworkMode, w.Memory, w.MemorySwap, w.NanoCpus, &w.PidsLimit
	h.Ulimits, h.RestartPolicy, h.LogConfig, h.ShmSize = w.Ulimits, w.RestartPolicy, w.LogConfig, w.ShmSize
	return got
}
