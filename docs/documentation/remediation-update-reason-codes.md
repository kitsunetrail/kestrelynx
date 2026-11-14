---
title: Update and PR processing reason codes
---

# Update and PR processing reason codes

Look up reason codes for dependency update runtimes, tool retrieval, validation, PR processing, and storage.
See [Result values](remediation-reason-codes.md#result-values) and [Reason codes](remediation-reason-codes.md#reason-codes) for result values and reason categories.

KEV is CISA's Known Exploited Vulnerabilities catalog of vulnerabilities confirmed to have been exploited.

Choose a subsection for the target or processing stage you want to check.

| Reference |
| --- |
| [Runtime reasons](#runtime-reasons) |
| [Tool retrieval reasons](#tool-reasons) |
| [Candidate selection](#update-selection-reasons) |
| [Go](#update-go-reasons) |
| [Maven and Gradle](#update-java-reasons) |
| [Update execution](#update-execution-reasons) |
| [Post-update validation](#update-validation-reasons) |
| [Scan comparison](#update-scan-reasons) |
| [Re-resolution through dependents](#update-reresolution-reasons) |
| [PR processing reasons](#pr-reasons) |
| [Storage reasons](#storage-reasons) |

See [Terms](remediation.md#terms) for the terminology used on this page.

## Runtime reasons {#runtime-reasons}

Runtime reasons describe whether a language runtime and work container can be selected and used for the update.

The following codes distinguish version-declaration and execution-environment results.

| Code | Meaning | Details |
| --- | --- | --- |
| `node_spec_invalid` | The declared Node.js version cannot be parsed | [Node.js selection](remediation-node-python-logic.md#node-selection) |
| `python_spec_invalid` | The declared Python version cannot be parsed | [Python selection for uv](remediation-node-python-logic.md#uv-python-selection) |
| `manager_spec_invalid` | The declared package manager version cannot be parsed | [Tool version selection](remediation-node-python-logic.md#tool-version-selection) |
| `node_spec_conflict` | No Node.js version satisfies the declarations in `.node-version`, `.nvmrc`, and `package.json` fields `engines.node`, `devEngines.runtime`, and `engines.runtime` together | [Node.js selection](remediation-node-python-logic.md#node-selection) |
| `python_spec_conflict` | No Python version satisfies both `.python-version` and `requires-python` in `pyproject.toml` | [Python selection for uv](remediation-node-python-logic.md#uv-python-selection) |
| `manager_spec_conflict` | A package manager name or version declared in `package.json` conflicts with the lockfile's manager or another declaration | [Tool version selection](remediation-node-python-logic.md#tool-version-selection) |
| `node_spec_unsupported` | The declared Node.js version is unsupported | [Node.js selection](remediation-node-python-logic.md#node-selection) |
| `python_spec_unsupported` | The declared Python version is unsupported | [Python selection for uv](remediation-node-python-logic.md#uv-python-selection) |
| `manager_spec_unsupported` | The declared package manager version is unsupported | [Tool version selection](remediation-node-python-logic.md#tool-version-selection) |
| `work_program_mismatch` | The program in the work container differs from the one shipped with the running KestreLynx | [Update failures](remediation-troubleshooting.md#check-update-failure) |
| `work_environment_rejected` | The work container does not meet the program's execution requirements | [Execution restrictions](remediation-worker-logic.md#worker-restrictions) |
| `go_version_too_old` | `go.mod` has no `go` version declaration, or it is older than 1.21 | [Go dependency files](remediation-dependency-formats.md#go-inputs) |
| `go_toolchain_unsupported` | The `toolchain` line in `go.mod` is not a released Go version | [Go dependency files](remediation-dependency-formats.md#go-inputs) |
| `go_runtime_unavailable` | No supported Go release is new enough for the update | [Go runtime selection](remediation-go-logic.md#go-runtime-selection) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `gradle_version_unsupported` | The build uses an unsupported Gradle version | [Gradle dependency files](remediation-dependency-formats.md#gradle-inputs) |
| `gradle_toolchain_unsupported` | The build requests an unsupported Java toolchain | [Gradle worker settings](remediation-gradle-logic.md#gradle-worker-settings) |
| `runtime_eol` | The runtime selected for updates from project declarations or other inputs, or the running image's Python checked by pip, is past end of support | [Runtime selection](remediation-package-logic.md#runtime-and-tool-versions) |
| `runtime_engines_mismatch` | An updated dependency does not support the minimum Node.js version declared by the project | [Node.js compatibility](remediation-node-python-logic.md#node-compatibility) |
| `requires_python_unsupported` | Required Python version conditions cannot be met, are missing, or cannot be parsed | [Python selection for uv](remediation-node-python-logic.md#uv-python-selection) |
| `pip_target_undecidable` | Running-image scan information and package discovery paths do not establish a validation target with a known Python version and OS/CPU platform | [pip target environment](remediation-node-python-logic.md#pip-target-environment) |
| `pip_target_mismatch` | Validation environments derived from package origins disagree on the Python version, implementation, platform tags, or ABI | [pip target environment](remediation-node-python-logic.md#pip-target-environment) |
| `work_image_not_configured` | No work environment is prepared for updates | [Update failures](remediation-troubleshooting.md#check-update-failure) |
| `work_namespace_not_configured` | The work namespace required for non-Maven language-package updates on Kubernetes is unset, requiring manual handling | [Kubernetes work Pod configuration](configuration.md#remediation-worker-kubernetes) |
| `work_runtime_class_unsupported` | An unsupported RuntimeClass is configured for work Pods, requiring manual handling | [Kubernetes work Pod configuration](configuration.md#remediation-worker-kubernetes) |
| `work_cluster_too_old` | The cluster is older than Kubernetes 1.30 required by the work Pod policy, requiring manual handling | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_pod_limit` | The work Pod count or namespace quota is at its limit, so the update is deferred to the next cycle | [Kubernetes work Pod configuration](configuration.md#remediation-worker-kubernetes) |
| `work_admission_unverified` | The work namespace's Pod creation policy cannot be confirmed as enforced, so no work Pod is started | [Work Pod execution](remediation-worker-logic.md#kubernetes-work-pods) |
| `work_priority_class_missing` | The PriorityClass configured for work Pods is absent or does not match required settings, requiring manual handling | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_pod_not_started` | The work Pod did not start in time, so the update is deferred to the next cycle | [Checking update failures](remediation-troubleshooting.md#check-update-failure) |
| `work_image_unavailable` | The work image could not be prepared | [Pinned official images](remediation-worker-logic.md#worker-images) |

The following examples show conflicting version declarations.
For package managers, declarations in `packageManager`, `devEngines.packageManager`, and `engines` are checked against each other.

| Target | Example of conflicting declarations |
| --- | --- |
| Node.js | `.nvmrc` containing `22` and `package.json` declaring `engines.node: ">=24"` cannot both be satisfied |
| Python | `.python-version` containing `3.11` and `pyproject.toml` declaring `requires-python = ">=3.12"` cannot both be satisfied |
| Package manager | `packageManager: "pnpm@10.34.4"` and `devEngines.packageManager` declaring `name: "pnpm"` with `version: "^11"` cannot both be satisfied |

## Tool retrieval reasons {#tool-reasons}

Tool retrieval reasons describe whether a package manager distribution can be retrieved, verified, and used.
The following codes cover retrieval settings, artifact verification, waiting periods, and caching.

| Code | Meaning | Details |
| --- | --- | --- |
| `tool_fetch_config_unsupported` | Settings require the manager to fetch tools itself or use unsupported dependency-resolution settings | [Update failures](remediation-troubleshooting.md#check-update-failure) |
| `tool_version_unsupported` | The package manager version is unsupported | [Tool version selection](remediation-node-python-logic.md#tool-version-selection) |
| `tool_version_not_found` | The specified package manager version was not found | [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) |
| `tool_hash_mismatch` | The tool artifact does not match its checksum | [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) |
| `tool_hash_unsupported` | The tool artifact's checksum cannot be verified | [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) |
| `tool_artifact_invalid` | The tool artifact is invalid | [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) |
| `tool_metadata_invalid` | The tool release metadata is invalid | [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) |
| `tool_too_new` | The tool was published less than 72 hours ago, or an unknown publication time prevents confirming that 72 hours have elapsed | [Tool release waiting period](remediation-node-python-logic.md#tool-release-age) |
| `tool_fetch_failed` | Tool retrieval failed | [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) |
| `tool_fetch_budget` | The tool retrieval limit was reached | [Update failures](remediation-troubleshooting.md#check-update-failure) |
| `tool_cache_full` | Space cannot be made available in the tool cache | [Tool cache reuse](remediation-node-python-logic.md#tool-cache) |
| `tool_file_mismatch` | A cached tool artifact differs from its record | [Tool cache reuse](remediation-node-python-logic.md#tool-cache) |

The following examples show unsupported retrieval settings.

| File | Example setting |
| --- | --- |
| `package.json` | Specifies `pnpm.configDependencies`, `pnpm.executionEnv`, or `resolutions` |
| `package.json` | Specifies `onFail: "download"` in `devEngines.runtime` or `engines.runtime` |
| `pnpm-lock.yaml` | Contains a runtime download specification using `runtime:` |
| `uv.toml` | Makes uv read source or runtime settings from a separate file |
| `pyproject.toml` | Contains unsupported retrieval or dependency-resolution settings in `[tool.uv]` |

## Update result reasons {#update-reasons}

Update result reasons describe decisions from package candidate selection, update execution, and post-update validation.

### Candidate selection {#update-selection-reasons}

These codes describe whether a fixed version can be selected and whether dependency constraints allow it.

| Code | Meaning | Details |
| --- | --- | --- |
| `update_candidate_in_source` | A fixed-version update candidate exists for a package in the source | [Fixed-version lower bound](remediation-package-logic.md#fix-lower-bound) |
| `range_allows_fix` | The dependency range allows a fixed version expected to be installed on rebuild | [Direct dependency declarations](remediation-node-python-logic.md#direct-dependencies) |
| `no_fixed_version_above_installed` | No fixed version is newer than the installed version, or there is nothing to fix | [Fixed-version lower bound](remediation-package-logic.md#fix-lower-bound) |
| `constraint_excludes_fix` | The candidate or updated version does not satisfy dependency constraints | [Direct dependency declarations](remediation-node-python-logic.md#direct-dependencies) · [Transitive dependency scope](remediation-node-python-logic.md#transitive-dependencies) |
| `constraint_not_evaluable` | The version constraint cannot be evaluated, or the fixed version is a prerelease that pip does not select | [Direct dependency declarations](remediation-node-python-logic.md#direct-dependencies) |
| `packages_need_manual_update` | No packages can be updated automatically | [Update failures](remediation-troubleshooting.md#check-update-failure) |

### Go {#update-go-reasons}

These codes describe Go module updates and checks on the Go version required after updating.

| Code | Meaning | Details |
| --- | --- | --- |
| `go_stdlib_needs_newer_go` | The Go standard-library vulnerability is fixed by rebuilding with a newer Go, not by updating `go.mod` | [Go package selection](remediation-go-logic.md#go-package-selection) |
| `fix_in_other_major_version` | The fix is in another major version, which Go identifies by a different module path | [Go package selection](remediation-go-logic.md#go-package-selection) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `go_release_retracted` | The target version is retracted with no alternative fixed version available, or dependency requirements selected a retracted target-package version above the target | [Go package selection](remediation-go-logic.md#go-package-selection) · [Go update validation](remediation-go-logic.md#go-update-validation) |
| `go_line_raised_too_far` | Changes to the `go` or `toolchain` lines in `go.mod` violate the limit imposed by the Go versions used to build the target module's running binaries | [Go update validation](remediation-go-logic.md#go-update-validation) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `go_dependencies_uncheckable` | Too many module versions must be traversed to verify updated dependency requirements | [Go update validation](remediation-go-logic.md#go-update-validation) |

The line-change check uses running binaries built from the target `go.mod` module, whether or not they have findings.
The rejection condition depends on whether their build Go versions are known.

| Build-version result | Condition that rejects a line change |
| --- | --- |
| Known for all target binaries | The updated `go` or `toolchain` version exceeds the lowest build Go version |
| Unknown for any target binary | The `go` or `toolchain` version changes while the build Go version is unknown |

### Maven and Gradle {#update-java-reasons}

These codes describe Maven and Gradle version sources, update targets, and lockfile validation.

| Code | Meaning | Details |
| --- | --- | --- |
| `maven_fix_in_other_major` | The fix is available only in another major version | [Maven package selection](remediation-maven-logic.md#maven-package-selection) · [Gradle target versions](remediation-gradle-logic.md#gradle-target-versions) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `maven_version_source_unsupported` | The version is determined in a way that edits to the project's pom files cannot change | [Version sources and edits](remediation-maven-logic.md#maven-version-sources) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `maven_release_not_found` | Maven Central has no release usable for the update | [Target versions and Maven Central releases](remediation-maven-logic.md#maven-target-versions) · [Gradle target versions](remediation-gradle-logic.md#gradle-target-versions) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `maven_bom_series_unreached` | No qualifying version is found after checking up to 20 newer stable releases within the imported BOM's current major and minor version | [Version sources and edits](remediation-maven-logic.md#maven-version-sources) · [Gradle version declarations and edits](remediation-gradle-logic.md#gradle-version-sources) |
| `maven_dependency_held_back` | After updating, a dependency required by the new release remains below its declared version | [Maven update validation](remediation-maven-logic.md#maven-update-validation) |
| `gradle_version_source_unsupported` | The version is determined in a way that edits to the project's files cannot change | [Version declarations and edits](remediation-gradle-logic.md#gradle-version-sources) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `gradle_lock_entry_removed` | The update removed an entry from `gradle.lockfile` | [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation) |
| `gradle_lock_configurations_changed` | The update changed the configurations locked by `gradle.lockfile` | [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation) |
| `gradle_lock_version_unsupported` | The updated `gradle.lockfile` contains a snapshot version | [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation) |

### Update execution {#update-execution-reasons}

These codes describe starting and running dependency-file updates and collecting their results.

| Code | Meaning | Details |
| --- | --- | --- |
| `update_job_limit` | The limit on dependency-file updates in one cycle was reached | [Update failures](remediation-troubleshooting.md#check-update-failure) |
| `update_input_limit` | Update input files exceed the size limit | [Container inputs](remediation-worker-logic.md#worker-inputs) |
| `update_job_failed` | Update execution failed | [Update failures](remediation-troubleshooting.md#check-update-failure) |
| `update_result_invalid` | The update result is invalid | [Result collection](remediation-worker-logic.md#worker-results) |
| `update_job_timed_out` | Update execution timed out | [Execution restrictions](remediation-worker-logic.md#worker-restrictions) |
| `distribution_lookup_failed` | Reading package information from a registry such as npm or PyPI failed | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `update_input_invalid` | KestreLynx detected invalid target versions, file records, runtime configuration, or execution data for the work container while preparing or validating the update | [Container inputs](remediation-worker-logic.md#worker-inputs) |
| `update_job_input_rejected` | The program inside the work container rejected update input while checking execution instructions, input files, or other inputs | [Container inputs](remediation-worker-logic.md#worker-inputs) |
| `manifest_edit_required` | Dependency declarations in `package.json` or `pyproject.toml` require changes, such as version specifications that cannot be edited automatically | [Direct dependency declarations](remediation-node-python-logic.md#direct-dependencies) |
| `input_modified` | A settings file that should only be read was modified | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `lockfile_inconsistent` | The lockfile is inconsistent with the project | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `no_wheel_for_version` | The target version has no wheel for the required platform | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `release_yanked` | The target release was yanked | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `requirements_rewrite_unsupported` | The remediation update method cannot rewrite the requirements | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `update_set_not_applied` | Another package being updated together with the target could not be updated | [Partial PR conditions](remediation-package-logic.md#partial-pr-selection) |
| `target_not_in_lockfile` | The target package is missing from the lockfile | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `no_reresolve_trigger` | No direct dependency can be temporarily removed from `importers['.']` in `pnpm-lock.yaml` to make pnpm resolve dependency versions again | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `pnpm12_removal_unsupported` | pnpm 12 releases before 12.10.0 cannot use the current update method | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `update_step_failed` | A step during the update failed | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `registry_check_limit` | The update reached its limit on registry lookups such as npm or PyPI requests | [Update failures](remediation-troubleshooting.md#check-update-failure) |
| `update_package_limit` | The number of packages to update exceeds the limit | [Update failures](remediation-troubleshooting.md#check-update-failure) |

### Post-update validation {#update-validation-reasons}

These codes describe whether output files and dependency changes stay within the permitted scope.

| Code | Meaning | Details |
| --- | --- | --- |
| `post_update_check_failed` | Post-update validation failed | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `unexpected_files` | The update modified unexpected files | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `release_age_violation` | A dependency release does not meet the project's minimum release age | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `manifest_changed` | The update made unauthorized changes to a dependency declaration file such as `package.json` | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `output_files_invalid` | Output files are invalid or unreadable | [Result collection](remediation-worker-logic.md#worker-results) |
| `lockfile_format_changed` | The update changed the lockfile format | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `target_not_updated` | The updated version does not reach the version required by validation, such as the Maven Central release selected for Maven or Gradle | [Partial PR conditions](remediation-package-logic.md#partial-pr-selection) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `target_removed` | The target package disappeared after updating or became unreachable through dependencies | [Partial PR conditions](remediation-package-logic.md#partial-pr-selection) |
| `fix_condition_not_met` | The updated version does not satisfy the vulnerability's fix conditions | [Partial PR conditions](remediation-package-logic.md#partial-pr-selection) |
| `unexplained_dependency_diff` | A dependency change cannot be explained by the update, or a raised Go `go` line does not match updated module requirements | [Collateral change validation](remediation-node-python-logic.md#change-validation) · [Go update validation](remediation-go-logic.md#go-update-validation) |
| `distribution_mismatch` | A package differs from registry contents or pip resolution results | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `resolved_source_changed` | A package's source changed | [Collateral change validation](remediation-node-python-logic.md#change-validation) |
| `post_update_lockfile_unstable` | Regenerating the lockfile changes its contents again | [Manager update methods](remediation-package-logic.md#manager-update-methods) |
| `drop_side_effect` | A dependency temporarily removed for re-resolution did not return to its original state | [Manager update methods](remediation-package-logic.md#manager-update-methods) |

When a Go update raises the `go` line, it must exactly match the highest Go version required by modules whose versions increased or that were added.
For example, if the highest requirement is Go `1.25.0`, an updated `go 1.23.0` does not match.

### Scan comparison {#update-scan-reasons}

These codes describe comparing dependency files before and after updating to check whether target findings were resolved.

| Code | Meaning | Details |
| --- | --- | --- |
| `source_scan_failed` | Scanning dependency files failed | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_target_not_detected_before` | The target vulnerability was not detected in dependency files before updating | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_target_not_analysed_after` | The target could not be analysed in dependency files after updating | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_target_still_detected` | The target vulnerability is still detected after updating | [Verification scope](remediation-logic.md#verification-scope) |
| `source_introduced_findings` | The dependency-file update was rejected for new findings, more records of vulnerable packages or more dependents using them, or disallowed dependency-path splits, merges, or similar changes | [Comparison conditions](remediation-logic.md#comparison-conditions) · [Rejected changes](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `source_introduced_kev` | The update was rejected because KEV-listed vulnerabilities were involved in new findings, more records of vulnerable packages or more dependents using them, or disallowed dependency-path splits, merges, or similar changes | [Comparison conditions](remediation-logic.md#comparison-conditions) · [Rejected changes](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `source_scan_incomplete` | The dependency-file scan was incomplete | [Comparison conditions](remediation-logic.md#comparison-conditions) |
| `update_verified` | Update-result checks and before-and-after dependency-file scans passed, confirming resolution of the adopted update targets' findings | [Verification scope](remediation-logic.md#verification-scope) |

Vulnerable-package record counts refer to records in the lockfile; growth in dependents refers to the number of dependency requirements on vulnerable versions.
For one old version splitting into multiple vulnerable new versions, or merged paths that prevent choosing one old version for comparison, see the diagrams in [Rejected changes](remediation-reresolution-logic.md#dependent-reresolution-rules).

Completed dependency-file verification does not confirm an application build or vulnerability resolution in an updated running image.

### Re-resolution through dependents {#update-reresolution-reasons}

These codes describe re-resolving dependencies while also updating packages that depend on the target.
In webhooks, check the per-package `language_items[].packages[].reason` together with the overall re-resolution reason in `language_items[].update.chain.reason`.

| Code | Meaning | Details |
| --- | --- | --- |
| `dependents_update_not_fixed` | Re-resolving dependent packages did not reach the fixed version this time | [Re-resolution through dependents](remediation-reresolution-logic.md#dependent-reresolution) |
| `no_resolution` | Re-resolution requesting the fixed version found no solution | [Re-resolution through dependents](remediation-reresolution-logic.md#dependent-reresolution) |
| `dependents_update_rejected` | The dependent update failed validation, or re-resolution stopped after three consecutive release-age waits | [Rejected changes](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `dependents_update_unsupported` | Dependent packages cannot be updated with the tool in use | [Re-resolution scope and limits](remediation-reresolution-logic.md#dependent-reresolution-limits) |
| `dependents_update_limit` | The dependent update stopped because of a limit, repeated deferral for the same limit, or failure to save a waiting record | [Re-resolution scope and limits](remediation-reresolution-logic.md#dependent-reresolution-limits) |
| `dependents_hold_back` | A dependent package constrains the target package's version | [Manager update methods](remediation-package-logic.md#manager-update-methods) · [Overview of the hints](remediation-fix-hints.md#fix-hints) |
| `release_too_new` | A version introduced by the update was published less than 72 hours ago | [Release-age waits and retries](remediation-reresolution-logic.md#dependent-reresolution-waits) |
| `chain_downgrade` | The update lowers a package version, or packages and versions before and after the update cannot be matched along dependency paths | [Rejected changes](remediation-reresolution-logic.md#dependent-reresolution-rules) |
| `chain_move_limit` | The number of packages changed by the update exceeds the limit | [Re-resolution scope and limits](remediation-reresolution-logic.md#dependent-reresolution-limits) |
| `chain_item_budget` | The update requires more work than one plan item is allowed | [Release-age waits and retries](remediation-reresolution-logic.md#dependent-reresolution-waits) |

The following conditions distinguish limits from failures to save waiting records for dependent updates.

| Cause | Trigger |
| --- | --- |
| Re-resolution limit | The number of dependent packages, required lookups, or other work exceeds a limit |
| Repeated deferral for the same limit | The same inputs are deferred for the same kind of processing limit in three consecutive cycles |
| Failure to save a waiting record | A waiting record required to defer processing to a later cycle cannot be saved |

Check `language_items[].update.chain.reason` and `language_items[].update.chain.detail` for the specific limit or stop reason, and `language_items[].packages[].detail` for a failure to save a waiting record.

Failures during re-resolution execution or retrieval can also use failure codes shared with ordinary updates.

## PR processing reasons {#pr-reasons}

PR processing reasons describe whether PRs can be created, reconciled, or replaced and why GitHub writes stopped.
The following codes distinguish processing limits, candidate or file changes, and relationships to existing PRs.

| Code | Meaning | Details |
| --- | --- | --- |
| `pr_limit` | The limit on PRs created per cycle, `new_prs_per_cycle`, was reached | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `open_pr_limit` | The limit on open KestreLynx PRs across configured repositories, `open_prs`, was reached | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_changed` | The same candidate tag pointed to different content during a pre-PR recheck or a Dockerfile newer-series check | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) · [Newer series check](remediation-image-logic.md#newer-series-check) |
| `base_moved` | The base branch advanced during PR preparation | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `github_rate_limited` | The GitHub rate limit was reached | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `write_outcome_unknown` | The result of a GitHub write cannot be confirmed | [Write stops](remediation-pr-logic.md#write-stops) |
| `reconciliation_failed` | Reconciling existing PRs failed | [Existing PR matching](remediation-pr-logic.md#existing-pr-matching) |
| `repository_mismatch` | The repository differs from the PR processing record | [Write stops](remediation-pr-logic.md#write-stops) |
| `attempt_unsettled` | A previous PR creation result is not yet settled | [Existing PR matching](remediation-pr-logic.md#existing-pr-matching) |
| `branch_not_ours` | A branch with the same name exists and was not created by KestreLynx | [Write stops](remediation-pr-logic.md#write-stops) |
| `pull_request_not_as_created` | A defined code for a PR differing from its creation state, which current PR processing does not set | [Write stops](remediation-pr-logic.md#write-stops) |
| `github_refused` | GitHub refused the write | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `github_error` | GitHub returned an error | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `candidate_recheck_failed` | The candidate could not be rechecked before PR creation | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `source_changed` | A file used to create the plan changed | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `artifact_content_missing` | Updated file contents are no longer retained | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `artifacts_unusable` | Updated files cannot be written to a PR as they are | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `open_pr_not_inherited` | The new update proposal does not fix some findings fixed by an existing PR for the same file | [Replacing older PRs](remediation-pr-logic.md#pr-replacement) |
| `language_set_too_large` | Too many packages are updated to fit in the PR record | [Missing PRs](remediation-troubleshooting.md#check-missing-pr) |
| `update_already_proposed` | A PR already proposes the target update | [Existing PR matching](remediation-pr-logic.md#existing-pr-matching) |

The content compared when checking a candidate tag for changes depends on the processing stage.

| Processing stage | Content compared |
| --- | --- |
| PR preparation | Compares the candidate digest verified by the plan with the candidate digest retrieved again before PR creation |
| Dockerfile newer-series check | Compares content retrieved for the same candidate tag across running images, using the top-level digest and manifest digests for matching platforms |

## Storage reasons {#storage-reasons}

Storage reasons describe whether PR processing records in `prs.json` can be read and whether new records can be saved.
The following codes distinguish locks, write failures, record limits, and records that cannot be verified.

| Code | Meaning | Details |
| --- | --- | --- |
| `store_locked` | Another process has locked the PR processing records | [Record verification failures](remediation-troubleshooting.md#check-record-failure) |
| `storage_failed` | PR processing records could not be saved | [Record ordering](remediation-pr-logic.md#record-order) |
| `storage_full` | Space for new events cannot be made within the operation-event count limit in `prs.json` | [Write stops](remediation-pr-logic.md#write-stops) |
| `records_unverified` | Existing PR records could not be verified | [Record recovery](remediation-pr-logic.md#record-recovery) |
| `proposal_not_found` | The record of the PR proposing the target update could not be found | [Existing PR matching](remediation-pr-logic.md#existing-pr-matching) |
