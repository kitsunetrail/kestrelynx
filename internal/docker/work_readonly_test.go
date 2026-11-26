package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func readOnlyConfig(ro bool) WorkConfig {
	c := coverConfig()
	c.ReadOnlyRoot = ro
	return c
}

// Only a client made with ReadOnlyRoot differs: the root is read only and
// /work is an anonymous volume. The rest of the body is the same.
func TestReadOnlyRootChangesOnlyTheRootAndTheWorkVolume(t *testing.T) {
	plain, _ := newWorkClient("x", nil, readOnlyConfig(false))
	ro, _ := newWorkClient("x", nil, readOnlyConfig(true))
	a, b := plain.buildCreateBody("job1", testRes()), ro.buildCreateBody("job1", testRes())
	if a.Host.ReadonlyRootfs || len(a.Volumes) != 0 {
		t.Errorf("plain body: %+v %v", a.Host.ReadonlyRootfs, a.Volumes)
	}
	if !b.Host.ReadonlyRootfs || !reflect.DeepEqual(b.Volumes, map[string]struct{}{"/work": {}}) {
		t.Errorf("read-only body: %+v %v", b.Host.ReadonlyRootfs, b.Volumes)
	}
	b.Host.ReadonlyRootfs, b.Volumes = false, nil
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the bodies differ in more than the root and the volume:\n%+v\n%+v", a, b)
	}
}

func TestInspectOfAReadOnlyRootExpectsTheWorkVolume(t *testing.T) {
	ro, _ := newWorkClient("x", nil, readOnlyConfig(true))
	plain, _ := newWorkClient("x", nil, readOnlyConfig(false))
	body := ro.buildCreateBody("job1", testRes())
	vol := map[string]any{"Type": "volume", "Name": "abc", "Destination": "/work", "RW": true}
	good := func() workInspect {
		g := inspectOf(body)
		g.Config.Volumes = map[string]any{"/work": map[string]any{}}
		g.Mounts = []any{vol}
		return g
	}
	if bad := verifyInspect(body, good()); len(bad) != 0 {
		t.Errorf("the expected container: %v", bad)
	}
	for name, mut := range map[string]func(*workInspect){
		"no volume": func(g *workInspect) { g.Mounts = nil },
		"two volumes": func(g *workInspect) {
			g.Mounts = []any{vol, map[string]any{"Type": "volume", "Name": "d", "Destination": "/data", "RW": true}}
		},
		"a bind": func(g *workInspect) {
			g.Mounts = []any{map[string]any{"Type": "bind", "Destination": "/work", "RW": true}}
		},
		"another path": func(g *workInspect) {
			g.Mounts = []any{map[string]any{"Type": "volume", "Name": "a", "Destination": "/data", "RW": true}}
		},
		"read only": func(g *workInspect) {
			g.Mounts = []any{map[string]any{"Type": "volume", "Name": "a", "Destination": "/work", "RW": false}}
		},
		"writable root": func(g *workInspect) { g.HostConfig.ReadonlyRootfs = false },
		"no config vol": func(g *workInspect) { g.Config.Volumes = nil },
		"an image vol":  func(g *workInspect) { g.Config.Volumes["/data"] = map[string]any{} },
	} {
		g := good()
		mut(&g)
		if bad := verifyInspect(body, g); len(bad) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	// Any other client still refuses a mount, and a volume at /work too.
	pb := plain.buildCreateBody("job1", testRes())
	g := inspectOf(pb)
	g.Mounts = []any{vol}
	if bad := verifyInspect(pb, g); len(bad) == 0 {
		t.Error("a volume accepted for a client with a writable root")
	}
	g = inspectOf(pb)
	g.Config.Volumes = map[string]any{"/work": map[string]any{}}
	if bad := verifyInspect(pb, g); len(bad) == 0 {
		t.Error("a volume in the config accepted for a client with a writable root")
	}
}

func TestWorkVolumeMustStartEmpty(t *testing.T) {
	for name, c := range map[string]struct {
		names []string
		ok    bool
		code  int
	}{
		"empty":     {[]string{"work/"}, true, 200},
		"with file": {[]string{"work/", "work/x"}, false, 200},
		"gone":      {nil, false, 404},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/archive") || r.URL.Query().Get("path") != "/work" {
				t.Errorf("%s: request %s %s", name, r.Method, r.URL)
			}
			if c.code != 200 {
				w.WriteHeader(c.code)
				return
			}
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			for _, n := range c.names {
				h := &tar.Header{Name: n, Mode: 0o755}
				if strings.HasSuffix(n, "/") {
					h.Typeflag = tar.TypeDir
				}
				_ = tw.WriteHeader(h)
			}
			tw.Close()
			w.Write(buf.Bytes())
		}))
		cl, err := newWorkClient(srv.URL, srv.Client(), readOnlyConfig(true))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = cl.checkWorkEmpty(ctx, testCID)
		cancel()
		srv.Close()
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The delete asks for the volumes of the container to go with it.
func TestDeleteTakesTheVolumesWithTheContainer(t *testing.T) {
	op := deleteOp(testCID)
	if op.query.Get("v") != "true" || op.query.Get("force") != "true" {
		t.Errorf("delete query %v", op.query)
	}
}
