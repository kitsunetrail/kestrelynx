## What

KestreLynx proposes updating 2 package entries in `svc/Cargo.lock` of `example/app` with `cargo`.

- Dependency directory: `svc`
- Package manager: `cargo`
- Workloads running these packages: `compose/app/web`
- Files changed: `svc/Cargo.lock`

## Change

Running version to version after the update, with how the project requires the package:

- `mio`: `0.8.0` to `0.8.11` (transitive dependency)
- `tokio`: `1.18.0` to `1.18.4` (direct dependency)

### Vulnerabilities this update targets

- `CVE-2026-2222` in `mio`, severity `HIGH`
- `CVE-2026-1111` in `tokio`, severity `CRITICAL`, in the CISA KEV catalog, priority `act_now`

## Verification

- Runtime: `rust1.100` `1.100.0`
  - Official image: `rust@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`

**Operations run**

- `cargo.update`
  - Exit code: 0
- `cargo.update`
  - Exit code: 0

**Cargo update**

- Only cargo update was run, in a work container
  - Nothing was built
  - The source files were not sent
  - The build targets were sent as empty files
- KestreLynx checked what came back
  - Only Cargo.lock changed
  - The Cargo.toml files are as they were sent
  - The packages of the workspace are the same
  - Every target is at its release
  - Every crate at a version Cargo.lock did not have before is a release the crates.io index lists, not yanked, with the checksum Cargo.lock gives
- The version of the Cargo.lock format goes from `3` to `4`
- Of the crates at a version Cargo.lock did not have before, the highest rust-version the crates.io index declares is `1.70.0`
- Of the 4 crates at a version Cargo.lock did not have before, 1 have no rust-version in the crates.io index that could be read

**Crates the update was asked to move (2)**

- `mio`: `0.8.0` to `0.8.11`
- `tokio`: `1.18.0` to `1.18.4`

**Other crates whose version changed, or that were added or removed (3)**

- `bytes`: `1.5.0` to `1.6.1`
- `once_cell`: `1.21.4` removed
- `windows-sys`: added at `0.48.0`

**Scan of the dependency files before and after (Trivy, filesystem mode)**

- Before: `svc/Cargo.lock sha256:aaaaaaaaaaaa`
- After: `svc/Cargo.lock sha256:bbbbbbbbbbbb`
- Findings over every package of the files, not only the updated ones
  - Resolved: 2
  - Remaining: 1
  - Introduced: 0
- The lists below are cut

**Resolved (2)**

- `CVE-2026-1111` in `tokio` `1.18.0`, severity `CRITICAL`, in the CISA KEV catalog, fixed in `1.18.4`
- `CVE-2026-2222` in `mio` `0.8.0`

**Remaining (1)**

- `CVE-2026-3333` in `time` `0.1.45`, severity `HIGH`

**Introduced (0)**

- none

Both scans ran under these conditions:

- Trivy: `0.71.2`
- Vulnerability database built at: 2026-10-09T01:02:03Z
- Severity range: `CRITICAL`, `HIGH`
- Settings: the same in both scans

The repository's own Trivy configuration, ignore files and VEX documents were not read.

- Before merging, run a CI job that builds and tests with Cargo.lock as it is
  - For example: `cargo build --locked && cargo test --locked`
  - --locked makes cargo stop when Cargo.lock would have to change

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->