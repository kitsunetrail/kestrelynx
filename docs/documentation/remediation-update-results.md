---
title: Reading update results and re-pull and rebuild guidance
---

# Reading update results and re-pull and rebuild guidance

This page explains target and adopted versions, partial PRs, and results of re-resolution through dependent packages.
It also explains what re-pull and rebuild guidance establishes and what remains unverified.

See [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks) for the meaning of each notification line.
See [Terms](remediation.md#terms) for the terminology used on this page.

## Interpreting update results {#interpreting-updates}

Read update results by distinguishing proposed versions, versions actually found in dependency files, and targets left out of a PR.

### Target and adopted versions {#target-and-adopted-version}

For package updates in Slack, the version to the right of `→` depends on the processing stage.

| Display and processing stage | Version to the right of `→` |
| --- | --- |
| Update candidate: a plan before dependency updates run | Update target |
| Update candidate: a candidate that passed dependency update checks | Adopted version |
| Update: a change proposed by a PR | Adopted version recorded for the PR |

The “Update candidate” label alone does not distinguish an update target from an adopted version.
Check `category` and `packages[]` for the relevant `language_items[]` entry in the webhook or `plan.json`.

| `category` | Field identifying the version to the right of the arrow |
| --- | --- |
| `dependency_update_candidate` | `packages[].selection_lower_bound` |
| `pr_candidate` | `packages[].adopted_version` |

See [Finding detailed results](remediation-results.md#detailed-results) for where to find the data, and [Language package fields](webhook-remediation-language-reference.md#remediation-language-fields) for field specifications.

The update target is not necessarily the version the package manager actually selects.
Planning alone does not run dependency updates, so do not read an update target as a verified adopted version.

If the updated dependency files contain multiple versions of the same package, the lowest version is displayed as the adopted version.
The lowest adopted version alone does not describe all checks, so also review the [Resolved findings in comparisons](remediation-pr-results.md#verification-results).

See [Fixed-version lower bounds](remediation-package-logic.md#fix-lower-bound) for how the lower bound is derived and [Plan and PR execution scope](remediation-logic.md#plan-and-pr-execution) for execution scope.

### Partial pull requests {#partial-pull-requests}

A partial PR contains only the planned package updates that passed the checks.
npm, pnpm, uv, pip, Maven, and Gradle updates can produce partial PRs.

Distinguish updates included in the PR from remaining work as follows.

| Result | Interpretation |
| --- | --- |
| A package listed under the PR's “Update” | A change included in the displayed PR |
| A package shown under “Needs a decision” or as left out because of a reason | A target excluded from the PR's updates that needs separate attention |
| A package reported as unable to reach the target and still at its original version | A target that did not reach a fixed version |
| An open PR with exclusion information | A state in which packages still need attention alongside the update proposed by an existing PR |

Failure to reach a fixed version does not necessarily mean that the cause was identified.
“Left out” does not mean that the package was removed from the image.

Also, an item being a PR candidate does not mean that every package was updated.
Go updates are not split into partial PRs.

For pip fixed-version updates, packages blocked by their dependents (`dependents_hold_back`) may be excluded and the remaining updates retried.
If the remaining updates pass the checks, a PR is created for only those updates.

See [Conditions for partial PRs](remediation-package-logic.md#partial-pr-selection), [Conditions for excluding Maven targets and updating the rest](remediation-maven-logic.md#maven-update-exclusions), and [Conditions for excluding Gradle targets and updating the rest](remediation-gradle-logic.md#gradle-update-exclusions) for the conditions.
See [Fix pull request contents and pre-merge checks](remediation-pr-results.md) for PR review and [Checking update failures](remediation-troubleshooting.md#check-update-failure) for investigating remaining targets.

### Results of re-resolution through dependent packages {#dependent-reresolution-results}

Re-resolution through dependent packages updates the packages holding a target at an old version so that the target can reach a fixed version.
Dependent packages are updated within the ranges specified by the project.

The following shows dependencies before and after an update when `package.json` specifies `mkdirp ^0.5.1`.
The `minimist` brought in through `mkdirp` needs its dependent updated, while the one brought in through `rc` can reach a fixed version through a normal update.

Dependencies before the update are as follows.

```text
project
|-- mkdirp 0.5.1                 # Requires exactly minimist 0.0.8
|   `-- minimist 0.0.8           # The dependent's requirement blocks an update
`-- rc 1.2.8                     # Requires minimist ^1.2.0
    `-- minimist 1.2.0           # A normal update can select a fixed version
```

A normal update alone cannot bring the `minimist` required by `mkdirp` to a fixed version.
Dependencies after the update are as follows.

```text
project
|-- mkdirp 0.5.6                 # Requires minimist ^1.2.6
|   `-- minimist 1.2.x           # A fixed version is adopted
`-- rc 1.2.8                     # The dependent's version stays unchanged
    `-- minimist 1.2.x           # A fixed version is adopted
```

Raising `mkdirp` to `0.5.6` allows `minimist` to reach a fixed version.
The project's `mkdirp ^0.5.1` requirement stays unchanged.

When `minimist 1.2.8` is adopted, Slack displays the following.

```text
minimist 0.0.8 → 1.2.8 (with mkdirp 0.5.1 → 0.5.6)
```

Read re-resolution results using the following displays.

| Display | Meaning |
| --- | --- |
| `with mkdirp 0.5.1 → 0.5.6` | The dependent package `mkdirp` was also updated to fix `minimist` |
| `starlette 0.32.0.post1 cannot be raised to the fixed 1.3.1 (the dependent fastapi 0.108.0 limits the version of starlette)` | The dependent's requirement prevents updating to the fixed version |
| `did not reach the fixed version this time` | Selecting dependent packages again did not reach a fixed version in the re-resolution performed for the plan |
| `needs … updated as well, and that update was not adopted because …` | The update was not adopted because of failed checks or another reason |
| `updating … was not tried` | The update was skipped because of unsupported inputs, processing limits, or similar conditions |
| `a version it brings in is less than 72 hours old, so it is tried again after …` | The update was deferred before the displayed date and time |

The line describing dependent constraints appears when updating dependents within the project's ranges did not reach a fixed version (`not_fixed`).
Multiple dependents are listed by name and version; if no dependent requirement for the target package was recorded, the display says “did not reach the fixed version this time.”

For uv, the dependent-constraint line also appears when re-resolution specifying the fixed version found no solution (`no_resolution`).
After a release-age wait, KestreLynx makes the update eligible for retry in a cycle at or after the displayed time.

A PR may include normal updates that pass the checks even when re-resolution is not adopted.
“Did not reach the fixed version this time” does not mean that other methods cannot fix the vulnerability.

The PR body's “Packages updated along with the fix” section lists direct dependencies whose versions changed.
In this example, it shows the versions before and after the update and the requirement that blocked the update:

> - `mkdirp`: `0.5.1` to `0.5.6` (it required `minimist` `0.0.8`)

Re-resolution can change another package's version while leaving the same vulnerability at the same position in the dependency structure.
When the conditions are met, the vulnerability is treated as carried and is not fixed by this update.

The following fictional example leaves the same `CVE-2` in `Y`, which `A` uses, even though its version changes.

| Stage | Dependencies | Remaining vulnerability |
| --- | --- | --- |
| Before the update | `project → A 1.0 → Y 1.0` | `CVE-2` in `Y` |
| After the update | `project → A 2.0 → Y 1.1` | `CVE-2` in `Y` |

The same vulnerability remains in `Y` at the position used by `A`; this does not mean that a new vulnerability appeared in another package.
The PR body displays the carried vulnerability count and an example with the CVE ID, package name, and versions before and after the update.

See [Carried vulnerabilities](remediation-reresolution-logic.md#dependent-reresolution-carried-findings) for the conditions that allow carry-over.

If you receive webhooks, the following fields provide details.

| Information needed | Location relative to `language_items[]` |
| --- | --- |
| Dependent packages updated along with the target | `packages[].through` |
| Outcomes such as adoption or skipped attempts, and their reasons | `update.chain.outcome`, `update.chain.reason`, and `update.chain.detail` |
| Carried vulnerabilities | `source_check.chain_carried` |
| Earliest retry date and time | `retry_after` |

See [Re-resolution through dependent packages](remediation-reresolution-logic.md#dependent-reresolution) for processing in npm, pnpm, and uv.
See [Results of re-resolution through dependent packages](webhook-remediation-update-reference.md#language-chain-fields) and [Re-resolution scan comparisons](webhook-remediation-check-reference.md#language-chain-scan-fields) for other fields.

### Re-pull guidance {#repull-guidance}

Re-pull guidance means that an improvement was confirmed by comparing the running image with the content currently referenced by the same tag in the registry.
Slack labels this “Re-pull.”

Because the tag string does not change, this guidance alone does not create a PR to update a Compose, Kubernetes manifest, Kustomize, or Helm values tag.
`resolves 3 of 4 findings` means that three of the four findings being compared were no longer detected in the candidate.

It does not mean that running containers have been replaced with the candidate's content.
For Kubernetes retrieval guidance, see the notification's “Pull policy” and [Kubernetes image references and pulling images again](remediation-kubernetes-logic.md#kubernetes-image-references).

### Rebuild guidance {#rebuild-guidance}

Rebuild guidance shows expected changes from rebuilding and the steps to take when a rebuild is recommended.
The reasons for the guidance are as follows.

| Reason | When it applies |
| --- | --- |
| pip dependency range | The current dependency range permits a fixed version |
| Go standard library | The application needs to be rebuilt with a newer Go |
| A merged base update is not deployed | The running image is unchanged since the PR was created |
| A floating-tag base has changed | The current base layers do not match the start of the running image |

For pip, `a rebuild is expected to pick up … or later` is an estimate based on the dependency range allowing a fixed version.
Go `stdlib` findings do not produce a PR; a separate plan item recommends rebuilding with at least the Go version that fixes all CVEs.

When a merged base update is not deployed, the following guidance appears.

```text
Rebuild: PR #… (base image … … → …) is merged, but the running image is still built from …
```

Deploying an image built from the merged Dockerfile puts the base update in place.

In floating-tag guidance, `the first layers of the running image do not match the current …` indicates a mismatch between the current base and the running image.
KestreLynx scans the current base from the registry and matches findings with the running image by package location and CVE.

It does not build an image.
Slack and email display the following guidance according to the matching result.

```text
Check against the current base
├─ Every finding could be assessed (checked)
│  ├─ Findings are expected to disappear
│  │  └─ Rebuild: show steps and count in the rebuild summary
│  └─ No findings are expected to disappear
│     └─ Show nothing
├─ Compared, but some findings could not be assessed (partial)
│  └─ Rebuild: show steps and count in the rebuild summary
│     Append " (some findings could not be confirmed)"
└─ The images could not be compared (not_checked)
   └─ Rebuild: show steps and count in the rebuild summary
      Append " (which findings disappear could not be confirmed)"
```

“Findings are expected to disappear” means that package or runtime estimates include disappearing findings.
A hidden line is not counted in the rebuild summary, but the result remains available in the webhook's `rebuild_check`.

See [Base image fields](webhook-remediation-dockerfile-reference.md#remediation-dockerfile-fields) for the field specification.

When rebuild steps are shown, the command depends on how the Dockerfile was found.

| How the Dockerfile was found | Suggested operation |
| --- | --- |
| Compose `build` | Pull the current base and rebuild with `docker compose build --pull` |
| Configured mapping only | Pull the current base, rebuild, and deploy again using `docker build --pull` or a similar command |

Guidance based on a configured mapping also applies to images built in CI.
`docker build --pull` identifies the option for retrieving the base again; it is not a complete command ready to run.

The guidance alone does not determine which Dockerfile, build context, or output image name to use.
The following fictional display uses illustrative package names and versions.

```text
Rebuild: the first layers of the running image do not match the current node:24-alpine; pull the base again, rebuild the image (for example with `docker build --pull`) and deploy it again
  • gone if the current base's version carries over: package-a 1.0.0 → 1.0.1
  • also in the current base: package-b 2.0.0
  • new in the current base: package-c 3.0.0
```

The display lines relate to webhook fields as follows.
Package details appear below the “Rebuild” line.

| Display or estimate | Field | Meaning |
| --- | --- | --- |
| gone if the current base's version carries over | `rebuild_check.gone` | A different version exists at the same location in the base without the target CVE |
| also in the current base | `rebuild_check.remaining` | The target CVE also exists at the same location in the base |
| not in the current base | `rebuild_check.not_in_base` | The target OS package or global `node_modules` package is absent from the same location in the base |
| new in the current base | `rebuild_check.only_in_base` | The corresponding finding exists only in the current base |
| Estimate for inheriting the runtime version | `rebuild_runtimes` | Expected CVE results when inheriting the Node.js or Python version |

For runtimes, the estimate for inheriting the current base's version is displayed as follows.

```text
Node.js in the current … is …; if the rebuild takes over this version, … of the … findings of the detected Node.js … are expected to disappear (the rebuilt image is not checked)
```

The count covers currently detected runtime CVEs and excludes CVEs introduced by the new version.
Python is displayed as `Python runtime`, and estimates are also shown when they contain only remaining findings.

The following display rules apply to Slack package lists.

- Package names and versions are shown without CVE IDs
- Global `node_modules` packages under “not in the current base” are grouped by the outer package that contains them in its nested `node_modules`
- Each line shows at most 10 entries, with additional entries represented by a count

The following example places `undici` inside a globally installed `npm`.

```text
/usr/local/lib/node_modules/
`-- npm/                         # The outer package
    `-- node_modules/
        `-- undici/package.json  # A package included in npm
```

When this `undici` appears under “not in the current base,” it is counted among the packages included in `npm` instead of being named separately.
Rebuild estimates have the following limitations.

- Dockerfile `RUN` effects are not evaluated, so an instruction such as `apk upgrade` may remove findings listed as remaining
- Reinstalling an older version at the same location in the Dockerfile may leave findings that were expected to disappear
- “Not in the current base” cannot distinguish packages removed from the base from packages added by the Dockerfile
- “New in the current base” also includes findings that Dockerfile instructions remove from the completed image
- The webhook result field `dockerfile_items[].final_image_verified` is `false`, indicating that the completed image after rebuilding has not been verified

These results do not confirm the versions actually installed after rebuilding or resolution in the running image after deployment.
For details, see [Direct dependency version declarations](remediation-node-python-logic.md#direct-dependencies), [Matching base layers](remediation-base-image-logic.md#base-layer-matching), and [Standard library rebuild guidance](remediation-go-logic.md#go-stdlib-rebuild).
