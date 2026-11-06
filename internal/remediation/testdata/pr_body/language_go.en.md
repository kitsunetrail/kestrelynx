## What

KestreLynx proposes updating 2 package entries in `svc/go.mod` of `example/app` with `go`.

- Dependency directory: `svc`
- Package manager: `go`
- Workloads running these packages: `compose/app/web`
- Files changed: `svc/go.mod`, `svc/go.sum`

**1 package(s) move to another major version (for 0.x, another minor version). Review these first: the application may need changes.**

## Change

Running version to version after the update, with how the project requires the package:

- `lodash`: `4.17.20` to `4.17.21` (direct dependency)
- `minimist`: `0.2.1` to `1.2.8` (transitive dependency) — **major version change**
- `odd`: `2.0.0` to `2.0.1` (relation not known)

### Vulnerabilities this update targets

- `CVE-2026-1111` in `lodash`, severity `CRITICAL`, in the CISA KEV catalog, priority `act_now`
- `CVE-2026-2222` in `minimist`, severity `HIGH`

## Verification

- Runtime: `golang1.26` `1.26.10`
  - Official image: `golang@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
  - Version chosen: the lowest supported Go that is at least the go and toolchain lines of go.mod and the go lines of the targets' new versions

**Operations run**

- `go get golang.org/x/net@v0.53.0`
  - Exit code: 0

**Go module update**

- The go line of go.mod goes from `1.22` to `1.25.0`
  - It is the highest go line the versions the update moved to declare
  - It stays at or below Go `1.26.10`, which the running binaries were built with
  - A higher go line can change language features and default behaviour (the GODEBUG defaults)
  - That the build still succeeds was not checked
- The toolchain line of go.mod goes from none to `go1.25.3`
- Each target version was confirmed on the Go module proxy (proxy.golang.org)
  - Published
  - In its canonical form
  - Not retracted
- The go.mod of every version the update moved to was read from it
  - Every module that moved besides the targets is required at that version by those go.mod files
- go.sum was checked against the Go checksum database (sum.golang.org)
  - Every line the update added or changed
  - Both hashes (of the module and of its go.mod) of every version the update moved to
- The scans below cover the versions go.mod writes
  - A build with the go command's default -mod=readonly uses exactly those
  - It stops when go.mod lacks a module it needs or writes a lower version than one it needs

**Modules the update also moved, which the targets' new versions require (2)**

- `golang.org/x/text`: `v0.14.0` to `v0.36.0`
- `golang.org/x/sys`: added at `v0.40.0`

**go.sum lines of the versions the update moved to, added from the checksum database (1)**

- `golang.org/x/text v0.36.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`

**Scan of the dependency files before and after (Trivy, filesystem mode)**

- Before: `svc/go.mod sha256:aaaaaaaaaaaa`
- After: `svc/go.mod sha256:bbbbbbbbbbbb`
- Findings over every package of the files, not only the updated ones
  - Resolved: 2
  - Remaining: 1
  - Introduced: 0
- The lists below are cut

**Resolved (2)**

- `CVE-2026-1111` in `lodash` `4.17.20`, severity `CRITICAL`, in the CISA KEV catalog, fixed in `4.17.21`
- `CVE-2026-2222` in `minimist` `0.2.1`

**Remaining (1)**

- `CVE-2026-3333` in `semver` `7.5.4`, severity `HIGH`

**Introduced (0)**

- none

Both scans ran under these conditions:

- Trivy: `0.71.2`
- Vulnerability database built at: 2026-10-09T01:02:03Z
- Severity range: `CRITICAL`, `HIGH`
- Settings: the same in both scans

The repository's own Trivy configuration, ignore files and VEX documents were not read.

- Before merging, run a CI job that builds and tests with go.mod as it is
  - For example: `go build -mod=readonly ./... && go test -mod=readonly ./...`
  - Do not run go get, go mod tidy or a build with -mod=mod before it
  - The checks above assume a build that stops when go.mod lacks a module it needs, which is what the go command does by default

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->