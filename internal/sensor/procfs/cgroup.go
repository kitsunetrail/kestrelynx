package procfs

import (
	"regexp"
	"strings"
)

// dockerScopeRE matches a systemd cgroup driver's unit name for a container,
// e.g. ".../docker-<64hex>.scope".
var dockerScopeRE = regexp.MustCompile(`docker-([0-9a-f]{64})\.scope$`)

// dockerCgroupfsRE matches a cgroupfs driver's container directory, e.g.
// "/docker/<64hex>" (optionally followed by a nested path for a process in a
// child cgroup of the container's own).
var dockerCgroupfsRE = regexp.MustCompile(`/docker/([0-9a-f]{64})(?:/|$)`)

// ContainerIDFromCgroup extracts a Docker container ID from the contents of
// /proc/<pid>/cgroup, world-readable and unfaked by anything short of the
// container's own runtime. It assumes cgroup v2 (a single "0::<path>" line,
// per Documentation/admin-guide/cgroup-v2.rst); a v1/hybrid host's
// multi-line, per-controller output is out of scope here (the Sensor
// requires cgroup v2 for eBPF and refuses to run event collection without
// it — this function is only ever asked to look at content already known to
// come from one). Both cgroup drivers Docker ships are recognized: systemd's
// "docker-<id>.scope" unit name and cgroupfs's "/docker/<id>" directory.
func ContainerIDFromCgroup(data []byte) (id string, ok bool) {
	// Trimmed so Go regexp's "$" (end of text, not "before a trailing
	// newline" the way Perl's default is) anchors correctly against a file
	// that — like every proc(5) text file — ends in "\n".
	text := strings.TrimRight(string(data), "\n")
	if m := dockerScopeRE.FindStringSubmatch(text); m != nil {
		return m[1], true
	}
	if m := dockerCgroupfsRE.FindStringSubmatch(text); m != nil {
		return m[1], true
	}
	return "", false
}
