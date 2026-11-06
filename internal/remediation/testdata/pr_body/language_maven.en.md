## What

KestreLynx proposes updating 2 package entries in `svc/pom.xml` of `example/app` with `maven`.

- Dependency directory: `svc`
- Package manager: `maven`
- Workloads running these packages: `compose/app/web`
- Files changed: `svc/pom.xml`

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

- No package manager was run: KestreLynx edited the pom files itself, as described below

**Maven update**

- `svc/pom.xml`: the property `snakeyaml.version` of a parent pom is set to `2.7` in place of `2.6` (it sets the version of `org.yaml:snakeyaml`)
- The releases were confirmed on Maven Central
- The pom files before and after were scanned with Trivy resolving them through Maven Central
  - Forms whose resolution Trivy does not reproduce (profiles, other repositories, version ranges, relocations and the like) would have stopped the update
- An override of a parent's property or a pin in dependencyManagement stays until it is removed
  - Take it out when the parent (Spring Boot, say) is upgraded to a release that brings the fix
  - Otherwise it keeps this version

**Packages whose resolved version also changed (1)**

- `org.example:up`: `1` to `2`

**Scan of the dependency files before and after (Trivy, filesystem mode)**

- Before: `svc/pom.xml sha256:aaaaaaaaaaaa`
- After: `svc/pom.xml sha256:bbbbbbbbbbbb`
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

- Before merging, check what Maven resolves and run the build
  - For example: `mvn -B dependency:tree && mvn -B verify`
  - The check above used Trivy's resolution of the pom files, not Maven's

<!-- kestrelynx:{"v":1,"repo_id":7,"base_branch":"main","path":"compose.yml","locations":["services.web.image"],"current_ref":"nginx:1.25.3","candidate_tag":"1.25.4","candidate_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","base_sha":"1111111111111111111111111111111111111111","head_sha":"2222222222222222222222222222222222222222","input_blob_sha":"3333333333333333333333333333333333333333","changes":[{"path":"compose.yml","mode":"100644","blob_sha":"4444444444444444444444444444444444444444"}],"target_key":"d596a66a37dc307e942721c34ab9e199f77f040025dd35c89eca19f67f63a6ca","update_key":"e513bca69279da9566db0a06ac85a0a173b88d9bf1a0a76acc455a31016fe979","attempt_key":"e17763c925cde9702bea370d076aec40d211b1d0658f6a78f56fbf450df9d39d","fix_targets":[{"location":"services.web.image","vuln_id":"CVE-1","package":{"ecosystem":"debian","class":"os","name":"libc"}}]} -->