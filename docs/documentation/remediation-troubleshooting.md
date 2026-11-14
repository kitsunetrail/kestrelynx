# When no candidate or pull request appears

Use notification text and reason codes to identify why a candidate or PR does not appear.
Choose the section matching your situation, then compare your diagnostics with its checks.

For language packages, “Update candidate” alone does not distinguish an update execution problem from a PR creation problem.
If you cannot tell, start with [Checking update failures](#check-update-failure).

For terms used on this page, see [Terms](remediation.md#terms).

| Situation | Section |
| --- | --- |
| No remediation plan notification arrives, or an expected item is missing | [Checking for a missing plan](#check-missing-plan) |
| A language item's `category` is `dependency_update_candidate`, or an update failure reason appears | [Checking update failures](#check-update-failure) |
| An image update candidate exists, or a language item's `category` is `pr_candidate`, but no PR appears | [Checking for a missing PR](#check-missing-pr) |
| “Pull request writes are stopped” appears, or records produce an error | [Checking record reconciliation failures](#check-record-failure) |

## Collecting diagnostics {#collect-diagnostics}

Diagnostics use plans, notifications, and logs for the same target and run time.
Check them in the following order.

1. Note the target workload, image, and scan time
2. Check the category, reason, and details in the item's Slack line or its webhook `category`, `reason`, and `detail` fields
3. For PR processing problems, check the notified PR status and operation results alongside the KestreLynx logs from the same run

For the location of `plan.json`, which you can read without a notification, and `prs.json`, which records PR processing, see [Stored files](remediation-pr-logic.md#stored-records).
See [Reason codes](remediation-reason-codes.md#reason-codes) for definitions and [Finding detailed results](remediation-results.md#detailed-results) for information omitted from notifications.

This Docker example retrieves files and logs using the distributed configuration's container name and default storage location.
Substitute the actual values if you changed the container name or `remediation.storage_dir`.

```sh
docker cp kestrelynx:/var/lib/kestrelynx/remediation/plan.json ./plan.json
docker cp kestrelynx:/var/lib/kestrelynx/remediation/prs.json ./prs.json
docker logs kestrelynx > kestrelynx.log 2>&1
```

This Kubernetes example uses the distributed configuration's namespace and Deployment names and the default storage location.
Substitute the actual values if you changed the names or storage location.

```sh
kubectl -n kestrelynx exec deployment/kestrelynx -c kestrelynx -- cat /var/lib/kestrelynx/remediation/plan.json > plan.json
kubectl -n kestrelynx exec deployment/kestrelynx -c kestrelynx -- cat /var/lib/kestrelynx/remediation/prs.json > prs.json
kubectl -n kestrelynx logs deployment/kestrelynx -c kestrelynx > kestrelynx.log 2>&1
```

## Checking for a missing plan {#check-missing-plan}

Planning selects update targets from findings in running images.
Findings qualify when their severity is selected by `scan.severity`, their status is `fixed`, and fixed-version information is available.

Check the status in `Results[].Vulnerabilities[].Status` in Trivy's scan results; `fixed` means vulnerability information reports that a fix exists.
Check `FixedVersion` in the same finding for fixed-version information; it does not mean the fix has been applied to the running environment.

Use the following table when notifications do not arrive or a plan lacks an item or image candidate.

| Symptom | What to check | Reference |
| --- | --- | --- |
| Startup stops while loading configuration | Compare the logged error message with the relevant settings | [Remediation plans and pull requests](configuration.md#remediation) |
| The plan has no item for the target | Check whether the running-image scan results meet the target selection conditions | [Image candidate selection](remediation-image-logic.md#image-selection), [Language package selection](remediation-package-logic.md#package-selection) |
| No item appears for `container/<name>` | Check that the mapping's name matches `NAMES` in `docker ps` | [docker run containers](remediation-reference.md#docker-run-containers) |
| `container/<name>` refers to a Compose container | Change the mapping to the `compose/<project>/<service>` shown in the warning | [Identifying the workload key](remediation-setup-docker.md#identify-workload) |
| No item appears for an older container after rebuilding with the same tag | Check whether the old image has disappeared from the containerd image store | [docker run containers](remediation-reference.md#docker-run-containers) |
| The scanned image's digest differs from the running image's digest | Check scan failures in the logs and the target image ID | [Source verification](remediation-logic.md#source-verification) |
| `plan.json` contains a plan, but no notification arrives | Check notification destinations and delivery conditions | [Scan notification conditions](notification-conditions.md#notification-conditions), [Remediation plan redelivery](notification-conditions.md#remediation-redelivery) |
| Source files cannot be retrieved, or a target file is missing | Check the mapping in the order given after the table | [Source mappings](configuration.md#remediation-mappings), [GitHub access](configuration.md#remediation-github) |
| Owner-specific tokens cannot read a renamed or transferred repository | Update the mapping's `repository` to the current `owner/name` | [GitHub access](configuration.md#remediation-github) |
| A private image cannot be accessed | Check the registry host and credentials | [Image registry authentication](configuration.md#registries) |
| `no_newer_tag`: “no newer tag exists” | Check for a newer version among tags with the same major, minor, prefix, and suffix | [Image candidate reasons](remediation-image-reason-codes.md#image-reasons) |
| `same_content`: “the newer tag has the same content” | Check whether the candidate and running image have the same digest | [Published image tags](remediation-image-logic.md#published-image-tags) |
| `candidate_does_not_resolve_targets`: “the candidate does not resolve the target findings” | Check whether comparing the running image and candidate shows resolved target findings | [Verification scope by target](remediation-logic.md#verification-scope) |
| `declared_ref_mismatch`: “the image the spec of the workload names is not the one the container runs” | Compare the Pod spec's `image` with the running image name for every container sharing that running image name | [Kubernetes image references and pulling images again](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `declared_ref_unavailable`: “the image the spec of the workload names could not be read” | Check whether `image` can be read from each container's Pod spec for containers sharing the running image name | [Kubernetes image references and pulling images again](remediation-kubernetes-logic.md#kubernetes-image-references) |
| `tag_listing_incomplete`: “the tag list could not be read to the end” | Check retrieval failure logs and the limit shown in the notification | [Tag discovery](remediation-image-logic.md#tag-discovery), [Processing limits](configuration.md#remediation-limits) |
| An image is treated as locally built | Compare Compose's `build` setting with the Dockerfile and dependency-file mappings | [Excluding local builds](remediation-image-logic.md#local-builds) |
| The base image cannot be confirmed | Check the image named by `FROM` in the target Dockerfile stage and its matching results against the running image | [Matching base layers](remediation-base-image-logic.md#base-layer-matching), [Image candidate reasons](remediation-image-reason-codes.md#image-reasons) |

The following additional checks apply to specific symptoms.

- `container/<name>` targets containers running when the list was retrieved, so check the next cycle's results after renaming or recreating a container
- Check earlier logs for the Compose warning because it appears only once while the same condition persists
- Recreate the container with the new image if the old image has disappeared from containerd
- Check delivery failure logs when no notification arrives
- Also check pull permissions and token service permissions for private images
- For tag listing, check limits on tag requests, registry requests, and processing time

If source files cannot be retrieved, check the following in order.

1. Compare Compose labels, the docker run container name, or the Kubernetes workload key with `workload`
2. Check that `repository` identifies the intended repository
3. Check that `base_branch` identifies the intended branch
4. Check that the target file exists at the configured path
5. Check GitHub access and read permissions

With owner-specific tokens, redirects to repository-ID URLs without an owner are rejected because a token cannot be selected.

## Checking update failures {#check-update-failure}

Language-package updating applies candidate updates and checks the resulting dependency files.

KestreLynx retrieves and verifies npm, pnpm, and uv before passing them to a work container.

When candidates are not updated, use the following table to match notification reasons with checks.

| Symptom | What to check | Reference |
| --- | --- | --- |
| Language packages remain candidates | Check whether PR creation is enabled and the reason attached to the item | [Basic settings](configuration.md#remediation-basics), [Plan and PR execution scope](remediation-logic.md#plan-and-pr-execution) |
| An input format or package source is reported as unsupported | Check the dependency files or settings identified by the reason | [Supported input formats](remediation-reference.md#supported-inputs), [Source reasons](remediation-image-reason-codes.md#source-reasons) |
| A runtime cannot be selected, or compatibility requirements are not met | Compare the project's version declarations with dependency requirements | [Runtime selection](remediation-package-logic.md#runtime-and-tool-versions), [Runtime reasons](remediation-update-reason-codes.md#runtime-reasons) |
| `pip_target_undecidable`: “the environment the packages run in cannot be decided” | Check whether the verification environment can be determined from the running image | [Target environment for pip validation](remediation-node-python-logic.md#pip-target-environment) |
| `pip_target_mismatch`: “the environment pip resolves for differs from the one the packages run in” | Check that verification environments derived from each target package's origins agree on Python version, implementation, platform tags, and ABI | [Target environment for pip validation](remediation-node-python-logic.md#pip-target-environment) |
| `tool_too_new`: “the package manager release is too new to use” | Check the availability time shown in the details | [Work containers](configuration.md#remediation-worker), [Tool retrieval reasons](remediation-update-reason-codes.md#tool-reasons) |
| `tool_fetch_failed`: “fetching the package manager failed” | Check connectivity to the download destination and notification details | [Tool downloads](outbound-communication.md#tool-downloads) |
| `tool_fetch_budget`: “the limit on fetching package managers was reached” | Check the retrieval limit shown in the notification details | [Tool retrieval reasons](remediation-update-reason-codes.md#tool-reasons) |
| `tool_hash_mismatch`: “the package manager archive does not match its checksum” | Check notification details to distinguish a mismatch with the registry's hash from a mismatch with the hash declared in npm or pnpm's `packageManager` | [Tool version declarations](remediation-dependency-formats.md#tool-declarations), [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) |
| The tool cache cannot be used | Check storage write permissions and free space | [Work containers](configuration.md#remediation-worker), [Tool retrieval reasons](remediation-update-reason-codes.md#tool-reasons) |
| A Docker work container cannot run | Check the Docker API and work environment validation logs | [Enabling remediation pull requests](remediation-setup.md#enable-pull-requests), [Work container execution](remediation-worker-logic.md#worker-execution) |
| `work_program_mismatch`: “the program in the work container is not the one this build came with” | Check the distribution in use and the logs | [Work containers](configuration.md#remediation-worker) |
| Processing stops at a limit or deadline | Compare the limit shown in the notification with the configured value | [Processing limits](configuration.md#remediation-limits), [Update result reasons](remediation-update-reason-codes.md#update-reasons) |
| An update does not reach a fixed version, or only part appears in the PR | Check excluded packages and remaining versions | [Partial pull requests](remediation-update-results.md#partial-pull-requests), [Update result reasons](remediation-update-reason-codes.md#update-reasons) |
| Checks of updated files or accompanying changes fail | Check notification details for the changes that failed validation | [Collateral change validation](remediation-node-python-logic.md#change-validation), [Update result reasons](remediation-update-reason-codes.md#update-reasons) |
| Results before and after the update cannot be compared | Check scan logs and the comparison conditions before and after the update | [Scan comparison conditions](remediation-logic.md#comparison-conditions) |
| `source_target_still_detected`: “the target vulnerability is still detected in the updated files” | Check the comparison results for target findings remaining after the update | [Resolved findings in comparisons](remediation-pr-results.md#verification-results) |
| `source_introduced_findings`: “the update brings new findings into the dependency files” | Check the comparison results for findings absent before the update | [Resolved findings in comparisons](remediation-pr-results.md#verification-results) |

For runtimes and inputs, also check the following information.

- For unsupported inputs, check dependency files, workspaces, additional configuration, and package sources
- For Node.js version declarations, check files such as `.nvmrc` and `.node-version`, and `engines.node` in the dependency declaration file `package.json`
- For Python version declarations, check files such as `.python-version`, and `requires-python` in the dependency declaration file `pyproject.toml`
- Check whether runtimes such as Node.js 22 or Python 3.13 are still supported under [Supported runtimes](remediation-reference.md#supported-runtimes)
- For pip's verification environment, check the running image's Python version, OS, and platform

For retrieval, execution, and validation, also check the following information.

- For tool waiting periods, check publication times and `remediation.worker.tool_versions.min_release_age`, and for caching check `remediation.worker.tool_versions.cache_max_size`
- For Docker, also check the work image download source
- For custom builds, also check the location of the supplied program that executes updates inside the container (`remediation.worker.program_dir`)
- If processing stops at a limit or deadline, also check the next scheduled run
- If an update cannot reach a fixed version, also check the parent package's dependency range
- For post-update checks, check changed files, lockfile formats, dependency ranges, and verification results against package distributions

When Kubernetes language-package updates require manual action or are deferred, check the following items by reason.

| Symptom | What to check | Reference |
| --- | --- | --- |
| `work_namespace_not_configured`: “updates on Kubernetes need work Pods, and no work namespace is configured” | Check that `remediation.worker.kubernetes.namespace` is configured | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_cluster_too_old`: “the cluster is older than the lowest Kubernetes version the work Pod policy needs” | Check that Kubernetes is version 1.30 or newer | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_runtime_class_unsupported`: “a RuntimeClass is configured for work Pods, which is not supported yet” | Check that `remediation.worker.kubernetes.runtime_class` is empty | [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) |
| `work_admission_unverified`: “the admission policy of the work namespace could not be confirmed to be in force, so no work Pod was started” | Check the admission validation failure identified in the details | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_priority_class_missing`: “the PriorityClass configured for work Pods does not exist” | Check that the configured PriorityClass exists and has `preemptionPolicy: Never` | [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) |
| `work_pod_limit`: “the work namespace is at its Pod or quota limit, so the update waits for the next cycle” | Check the work namespace's Pod count and available quota | [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) |
| `work_pod_not_started`: “the work Pod did not start in time” | Check Pod events for the reason startup was blocked | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `update_result_invalid`: Details indicate missing result logs | Check that the execution node's `containerLogMaxSize` is at least `144Mi` | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |

For `work_admission_unverified`, follow the details to check RBAC, Pod admission rules and parameters, and the result of retrieving the cluster version.
For `update_result_invalid`, also check whether result logs were truncated or rotated.

For `work_pod_not_started`, find Pods labeled `io.kestrelynx.work=v1` in the work namespace and compare their creation times with the failed update's time.
Check during update execution because work Pods are deleted when processing ends.

In this example, replace `WORK_NAMESPACE` with `remediation.worker.kubernetes.namespace` and `POD_NAME` with the Pod name to check.

```sh
kubectl -n WORK_NAMESPACE get pods -l io.kestrelynx.work=v1 -o custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp
kubectl -n WORK_NAMESPACE get events --field-selector involvedObject.name=POD_NAME
```

If the Pod is gone, check KestreLynx logs and the notification's `reason` and `detail` from the same run.

## Checking for a missing PR {#check-missing-pr}

PR processing checks whether updates can be adopted and source files can be edited, then checks for existing PRs to prevent duplicates.
Use the following table when an update candidate exists but no PR appears.

| Symptom | What to check | Reference |
| --- | --- | --- |
| A candidate exists, but no PR appears | Check whether PR creation is enabled and the target file is editable | [Basic settings](configuration.md#remediation-basics), [Supported input formats](remediation-reference.md#supported-inputs) |
| `undeclared_affected_workload`: “a container that is not listed declares the image of the images entry and may be changed by it” | Check whether changing the tag affects the container identified in the details | [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs), [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs) |
| `init_container_unverified`: “a listed init container could not be shown to have run the image of the running containers” | Check the comparison conditions for containers in the same Pod described after the table | [Kustomize PRs](remediation-kubernetes-logic.md#kustomize-prs), [Helm values PRs](remediation-kubernetes-logic.md#helm-values-prs) |
| Kustomize requires manual action with a `kustomize_*` reason | Check the target `images[].name` and a string `newTag` | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| `kustomize_image_automation`: “the newTag line carries a Flux image automation marker” | Check whether the `newTag` line has a comment containing `$imagepolicy` | [Kustomize formats](remediation-source-formats.md#kustomize-formats) |
| Helm values require manual action with a `helm_*` reason | Check whether the image at the selected key has an explicit string tag | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| `helm_image_automation`: “a line of the image carries a Flux image automation marker” | Check whether an image declaration line has a comment containing `$imagepolicy` | [Helm values formats](remediation-source-formats.md#helm-values-formats) |
| A Helm values PR asks you to confirm the final value | Check whether any settings override the value at the selected key | [Configure Helm values PRs](remediation-setup-kubernetes.md#helm-values-pull-requests) |
| `github_refused`: “GitHub refused the write” | Check the token's target repositories and write permissions | [GitHub access](configuration.md#remediation-github), [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) |
| `pr_limit`: “the limit on pull requests of a run was reached” | Compare the number of new PRs this cycle with `remediation.limits.new_prs_per_cycle` | [Processing limits](configuration.md#remediation-limits) |
| `open_pr_limit`: “the limit on open pull requests of KestreLynx was reached” | Compare the current PR count with `remediation.limits.open_prs` | [Processing limits](configuration.md#remediation-limits) |
| An update is matched to an existing PR | Check whether the existing PR shown in the notification proposes the same update | [Matching existing PRs](remediation-pr-logic.md#existing-pr-matching) |
| No PR appears after the same update was closed without merging | Check the history that prevents duplicate creation | [Closed PRs](remediation-pr-logic.md#closed-prs) |
| Source files change during PR preparation | Compare notification details with the current files or base branch | [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) |
| `candidate_changed`: “the candidate changed while the pull request was prepared” | Compare notification details with the current candidate | [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) |
| A GitHub operation fails | Check operation details for access or connectivity problems | [PR operation event fields](webhook-remediation-pr-reference.md#remediation-operation-fields), [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) |
| `write_outcome_unknown`: “the result of a write to GitHub is unknown” | Check the operation result reconciled in the next cycle | [Stopping writes](remediation-pr-logic.md#write-stops), [PR operation event fields](webhook-remediation-pr-reference.md#remediation-operation-fields) |

The following additional checks apply to specific symptoms.

- If a candidate exists without a PR, also check source mappings in the order given under [Checking for a missing plan](#check-missing-plan)
- For Kustomize, also check unsupported syntax or features and interference from other `images` entries
- For Helm, also check the image representation and YAML keys and syntax according to the reason code
- For the final Helm value, check overrides from Flux HelmRelease `spec.values`, Argo CD `parameters`, `valuesObject`, and `valuesFrom`, CI `--set`, and other values files, along with the containers affected by changing the tag
- If GitHub refuses a write, also check repository rules
- If source files or candidates change during PR preparation, check the next cycle's results

For `undeclared_affected_workload`, add the container to `affects` if the tag change affects it.
Check mappings that target the same Kustomize entry or Helm key in the same repository, branch, and file.

Each mapping must declare the same combined list of containers from `workload` and `affects`.
The `workload` values themselves do not need to be identical.

If the container should not be included in the update, change the scope affected by the Kustomize entry or Helm key.
See the examples under [Configure Kustomize PRs](remediation-setup-kubernetes.md#kustomize-pull-requests) and [Configure Helm values PRs](remediation-setup-kubernetes.md#helm-values-pull-requests).

For `init_container_unverified`, check each observed Pod belonging to workloads listed in `workload` and `affects`.
Compare the ordinary init container with a running container listed in `workload` or `affects` in the same Pod using these conditions.

| Comparison | Fields to check | Required match |
| --- | --- | --- |
| The init container's declared and executed image names | `spec.initContainers[].image` and `status.initContainerStatuses[].image` | The declared and executed references for the same container name match |
| The init container's and running container's image names | Each container's `image` in Pod status | The references read from status match |
| The init container's and running container's image content | Each container's `imageID` in Pod status and the node's platform | The parsed digests and platforms match |

If `image` in status contains only an image ID, the image reference read from `imageID` is used for comparison.
In addition to these comparisons, the matched running container's scan results must be included in the plan.

An example Flux comment is `# {"$imagepolicy": "flux:nginx:tag"}`, which prevents automatic editing when present on a checked line.
For Helm, checked lines contain `repository`, `registry`, `tag`, or a string image declaration.

KestreLynx reconciles GitHub operations with unknown outcomes through reads in the next cycle.
Find events with the same `id` as the operation with an unknown outcome in `operations[]` in the webhook or `prs.json`.

Use the following fields to distinguish completed reconciliation from the operation's outcome.

| Field and value | Meaning |
| --- | --- |
| `phase: settled` | Handling after reconciliation has been settled |
| `result: ok` | The operation was confirmed successful |
| `result: failed` | The operation failed or the intended change was confirmed absent |
| `result: unknown` | The operation's outcome could not be determined |
| `error` | An explanation of the error or what reconciliation confirmed |

When retrying without reusing Git blobs, trees, or commits whose creation is uncertain, `result: unknown` remains even with `phase: settled`.
If writes remain stopped, continue to [Checking record reconciliation failures](#check-record-failure).

## Checking record reconciliation failures {#check-record-failure}

Record reconciliation checks `prs.json` against PRs and operation results on GitHub to decide whether GitHub writes may proceed.
Use the following table when “Pull request writes are stopped” or a record error appears.

| Symptom | What to check | Reference |
| --- | --- | --- |
| Plan or PR processing records cannot be saved | Check the storage location identified in the logs and its persistent volume mount | [Basic settings](configuration.md#remediation-basics), [Storage reasons](remediation-update-reason-codes.md#storage-reasons) |
| `store_locked`: “the pull request records are locked by another process” | Check whether another KestreLynx instance is running with the same storage location | [Storage reasons](remediation-update-reason-codes.md#storage-reasons) |
| `records_unverified`: “the records of existing pull requests could not be verified” | Check whether the identification marker remains in an HTML comment at the end of the PR body | [Record recovery](remediation-pr-logic.md#record-recovery) |
| `reconciliation_failed`: “existing pull requests could not be reconciled” | Check GitHub access and notification details | [Record recovery](remediation-pr-logic.md#record-recovery), [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) |
| Reading records reports `parse plan` or `parse pull request records` | Compare the JSON syntax or type error at the end of the log message with the relevant part of the file | [Stopping writes](remediation-pr-logic.md#write-stops) |
| `unsupported plan version` or `unsupported pull request record version` appears | Check that the file version shown by `has version` matches the supported version shown by `this build reads` | [Stopping writes](remediation-pr-logic.md#write-stops) |
| `operation events are out of sequence` appears | Check `operations[]` in `prs.json` against the conditions below the table | [Stopping writes](remediation-pr-logic.md#write-stops) |
| `storage_full`: “the pull request records are full” | Check operation history retained because it is undelivered or unsettled | [Stopping writes](remediation-pr-logic.md#write-stops), [Storage reasons](remediation-update-reason-codes.md#storage-reasons) |

For `operation events are out of sequence`, check these conditions in `prs.json`.

- Each `seq` in `operations[]` is positive and increases in array order
- Every `seq` is less than `next_seq`
- Every event has a nonempty `id`

For save failures, also check storage permissions and free space.
If existing PRs cannot be reconciled, also check the change history of PR bodies and repositories.

The identification marker is an HTML comment beginning with `<!-- kestrelynx:` and ending with ` -->`, visible when editing the PR body.
See [Record recovery](remediation-pr-logic.md#record-recovery) for the checks relevant to missing or modified markers.

If you cannot identify the cause, retain the original `plan.json` and `prs.json`, the full error, and notifications and logs from the same run.
Gather the information under [Collecting diagnostics](#collect-diagnostics) and compare it with the conditions under [Stopping writes](remediation-pr-logic.md#write-stops).

!!! warning "Preserve records"

    Do not delete PR processing records to force a retry.
    They are needed to prevent closed updates from being recreated and to reconcile previous operations.
