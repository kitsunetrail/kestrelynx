package sensor

import (
	"errors"
	"testing"
)

func TestHostCgroupNamespaceError(t *testing.T) {
	cases := []struct {
		name    string
		info    CgroupInfo
		wantErr bool
	}{
		{"private namespace root", CgroupInfo{CgroupV2: true, Path: "/"}, true},
		{"empty path", CgroupInfo{CgroupV2: true, Path: ""}, true},
		{"systemd scope", CgroupInfo{CgroupV2: true, Path: "/system.slice/docker-" + strings64('a') + ".scope"}, false},
		{"cgroupfs", CgroupInfo{CgroupV2: true, Path: "/docker/" + strings64('b')}, false},
		{"cgroup v1 reported elsewhere", CgroupInfo{CgroupV2: false, Err: errors.New("cgroup_v1: x")}, false},
	}
	for _, c := range cases {
		if err := hostCgroupNamespaceError(c.info); (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}
