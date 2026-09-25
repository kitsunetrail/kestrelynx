# cgroup fixtures

`systemd_docker.cgroup` is a raw, unedited capture of one running
container's `/proc/<host PID>/cgroup`, taken against the systemd cgroup
driver on a cgroup v2 host. It is not hand-written: `/proc/<pid>/cgroup` is
world-readable, so capturing it needs no root or extra capability, only a
running container and its host PID.

## How it was captured

```sh
docker run -d --rm --name cgroup-fixture alpine:3.20 sleep 300
PID=$(docker inspect --format '{{.State.Pid}}' cgroup-fixture)
cat /proc/$PID/cgroup > systemd_docker.cgroup
docker inspect --format '{{.Id}}' cgroup-fixture   # confirms the container ID embedded in the line above
docker stop cgroup-fixture
```

The container ID this line names is
`7b33f1d83ca7c4851e419dcf75275ef39258b880073684b4c32df7372d93d599`, taken
from the same `docker inspect` call, and is what `TestContainerIDFromCgroup_Systemd_RealCapture`
asserts `ContainerIDFromCgroup` extracts from this file.

Any publicly available image works for this capture — the container's own
image is irrelevant to what ends up in `/proc/<pid>/cgroup`, which is
entirely a function of the cgroup driver and hierarchy the host's Docker
daemon uses.

## What isn't captured here

This host's Docker daemon uses the systemd cgroup driver
(`docker info --format '{{.CgroupDriver}}'`); reproducing the cgroupfs
driver's own line shape (`/docker/<id>` instead of a `docker-<id>.scope`
unit name) needs a host configured to use it, which this one is not. The
cgroupfs-shaped test cases in `cgroup_test.go` remain constructed rather
than captured (ASSUMED, following the cgroupfs driver's well-known naming
convention), not verified against a raw capture the way the systemd case
above is.
