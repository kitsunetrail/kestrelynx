package procfs

import (
	"regexp"
	"strings"
)

// dockerScopeRE matches a systemd cgroup driver's unit name for a container,
// e.g. ".../docker-<64hex>.scope" (optionally followed by a nested path for a
// process in a child cgroup of the container's own — the same allowance
// dockerCgroupfsRE already makes for the other driver).
var dockerScopeRE = regexp.MustCompile(`docker-([0-9a-f]{64})\.scope(?:/|$)`)

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

// CgroupPathFromCgroup extracts the raw cgroup v2 path from the contents of
// /proc/<pid>/cgroup (the single "0::<path>" line — see ContainerIDFromCgroup's
// own doc comment on why only cgroup v2 is handled at all), normalized to
// match scanCgroupTree's own path convention (internal/sensor/cgroupmap.go):
// the cgroup root is "" (never "/"), every other path keeps its own leading
// "/" and never carries a trailing one. ok is false if data is not
// recognizable single-line cgroup v2 output at all — never guessed at as
// the root in that case, since a caller seeding a cgroup-route table from
// this must be able to tell "this really is the root" from "this could not
// be read at all" apart.
//
// Also ok=false if the path starts with "/.." — the kernel's own
// cgroup_path_ns_locked prefixes a target task's own cgroup path with one
// "/.." per level once that task's own cgroup is not a descendant of the
// *reading* task's own cgroup namespace root (man 7 cgroup_namespaces),
// dropping every real path segment above that point entirely (confirmed
// directly: reading another container's own /proc/<pid>/cgroup without
// --cgroupns=host reports "0::/../docker-<id>.scope", never the real
// "0::/system.slice/docker-<id>.scope" a matching namespace would). Every
// caller of this function needs the Sensor's own cgroup namespace to be the
// host's own for the very same reason scanCgroupTree's own startup walk
// already needs cgroup: host in docker-compose.sensor.yml — treating a
// "/.."-prefixed path as unusable here, rather than blindly prepending
// cgroupHostRoot and stat()ing whatever that produces, turns a silent,
// always-failing lookup into an explicit "not usable" the caller can tell
// apart from "genuinely does not exist".
func CgroupPathFromCgroup(data []byte) (path string, ok bool) {
	text := strings.TrimRight(string(data), "\n")
	const prefix = "0::"
	if !strings.HasPrefix(text, prefix) {
		return "", false
	}
	p := strings.TrimPrefix(text, prefix)
	if strings.HasPrefix(p, "/..") {
		return "", false
	}
	if p == "/" {
		return "", true
	}
	return strings.TrimSuffix(p, "/"), true
}

// ContainerScopePath returns the shortest prefix of path (already extracted
// via CgroupPathFromCgroup) that itself names a container's own top-level
// cgroup scope — the same match ContainerIDFromCgroup makes, but reporting
// where that match ends rather than just the ID it captured: path itself if
// it already is the container's own scope, or a shorter prefix if path
// names something nested under it (a child cgroup, or one of the
// container's own processes placed directly in a descendant of its own
// scope). Used to root a bounded walk over a container's own cgroup subtree
// from any one live process's own cgroup path, without needing to already
// know the container's own scope path some other way.
func ContainerScopePath(path string) (scopePath string, ok bool) {
	if loc := dockerScopeRE.FindStringIndex(path); loc != nil {
		return trimMatchedScope(path, loc), true
	}
	if loc := dockerCgroupfsRE.FindStringIndex(path); loc != nil {
		return trimMatchedScope(path, loc), true
	}
	return "", false
}

// trimMatchedScope returns path's own prefix ending at loc's own match, minus
// a trailing "/" the match's own optional (?:/|$) alternative may have
// consumed (dockerScopeRE/dockerCgroupfsRE both end this way, to also match
// a nested child path without capturing that child into the scope itself).
func trimMatchedScope(path string, loc []int) string {
	end := loc[1]
	if end > 0 && path[end-1] == '/' {
		end--
	}
	return path[:end]
}
