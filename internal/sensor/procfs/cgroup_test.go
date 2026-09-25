package procfs

import (
	"os"
	"testing"
)

// capturedSystemdCgroupPath is a raw, unedited /proc/<pid>/cgroup capture
// from a real running container on a systemd-cgroup-driver, cgroup v2 host.
// See testdata/cgroup/README.md for how it was taken and how to reproduce
// it against any publicly available image.
const capturedSystemdCgroupPath = "testdata/cgroup/systemd_docker.cgroup"

// capturedSystemdContainerID is the container ID capturedSystemdCgroupPath
// names, read from the same `docker inspect` call the capture procedure
// used (testdata/cgroup/README.md) rather than re-derived from the file
// under test.
const capturedSystemdContainerID = "7b33f1d83ca7c4851e419dcf75275ef39258b880073684b4c32df7372d93d599"

func TestContainerIDFromCgroup_Systemd_RealCapture(t *testing.T) {
	data, err := os.ReadFile(capturedSystemdCgroupPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	id, ok := ContainerIDFromCgroup(data)
	if !ok || id != capturedSystemdContainerID {
		t.Errorf("ContainerIDFromCgroup(%q) = (%q, %v), want (%q, true)", data, id, ok, capturedSystemdContainerID)
	}
}

// full is a well-formed 64-hex ID used to build the constructed (not
// captured) test cases below: this host's Docker daemon only offers the
// systemd cgroup driver (see testdata/cgroup/README.md), so the cgroupfs
// driver's line shape is exercised here from the driver's well-known naming
// convention rather than from a raw capture (ASSUMED).
const full = "735accd562c50cc872e90aa71776f0ec855c480c6f1771619cc5e1dcec5e580d"

func TestContainerIDFromCgroup_Cgroupfs(t *testing.T) {
	data := []byte("0::/docker/" + full + "\n")
	id, ok := ContainerIDFromCgroup(data)
	if !ok || id != full {
		t.Errorf("ContainerIDFromCgroup = (%q, %v), want (%q, true)", id, ok, full)
	}
}

func TestContainerIDFromCgroup_CgroupfsNestedChild(t *testing.T) {
	// A process in a child cgroup created inside the container's own
	// (e.g. a nested cgroup namespace) still names the container directory
	// as a path component, not just a suffix.
	data := []byte("0::/docker/" + full + "/init.scope\n")
	id, ok := ContainerIDFromCgroup(data)
	if !ok || id != full {
		t.Errorf("ContainerIDFromCgroup = (%q, %v), want (%q, true)", id, ok, full)
	}
}

func TestContainerIDFromCgroup_NoMatch(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"no docker segment", "0::/user.slice/user-1000.slice/session-1.scope\n"},
		{"short id", "0::/docker/735accd5\n"},
		{"uppercase id", "0::/docker/" + "735ACCD562C50CC872E90AA71776F0EC855C480C6F1771619CC5E1DCEC5E580D" + "\n"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if id, ok := ContainerIDFromCgroup([]byte(tc.data)); ok {
				t.Errorf("ContainerIDFromCgroup(%q) = (%q, true), want no match", tc.data, id)
			}
		})
	}
}
