# When no candidate or pull request appears

Use notification text and reason codes to identify why a candidate or PR does not appear.
Choose the section matching your situation and follow the action in the row that matches the text in your notification or logs.

For the meaning of reason codes not listed in the tables, see [Reason codes](remediation-reason-codes.md#reason-codes).

For language packages, Slack displays “Update candidate” in either of the following cases.

- The dependency update has not yet run (the webhook `category` is `dependency_update_candidate`)
- The dependency update passed its checks, but no PR exists yet (the webhook `category` is `pr_candidate`)

The “Update candidate” label alone does not distinguish a problem at the dependency update stage from a problem at the PR creation stage.
If you cannot distinguish the stages, start with [Checking update failures](#check-update-failure).

For terms used on this page, see [Terms](index.md#terms).

Choose a section from the following table for your situation.

| Situation | Section |
| --- | --- |
| No remediation plan notification arrives, or an expected item is missing | [Checking for a missing plan](#check-missing-plan) |
| A language item's `category` is `dependency_update_candidate`, or an update failure reason appears | [Checking update failures](#check-update-failure) |
| An image update candidate exists, or a language item's `category` is `pr_candidate`, but no PR appears | [Checking for a missing PR](#check-missing-pr) |
| “Pull request writes are stopped” appears, or records produce an error | [Checking record reconciliation failures](#check-record-failure) |

## Collecting diagnostics {#collect-diagnostics}

For diagnostics, gather and use the plans, notifications, and logs produced in one cycle for the workload and image you are investigating.
Check them in the following order.

1. Note the workload and image you are investigating and the notification's date and time
2. Check the category, reason, and details in the item's Slack line or its webhook `category`, `reason`, and `detail` fields
3. For PR processing problems, check the notified PR status and operation results alongside the KestreLynx logs from the cycle that produced that notification

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
Check `FixedVersion` in the same finding for fixed-version information.

Use the following table when notifications do not arrive or a plan lacks an item or image candidate.

| What you see | What to do | Reference |
| --- | --- | --- |
| A `container/<name>` item is missing | Set the mapping's `workload` to `container/` followed by the `NAMES` value from `docker ps` | [Containers started with docker run](remediation-reference.md#docker-run-containers) |
| A log warning contains `use the Compose key instead` (shown only once while the condition causing the warning persists) | Change the mapping's `workload` to the `compose/<project>/<service>` shown in the warning's `use` field | [Identifying workload keys](remediation-setup-docker.md#identify-workload) |
| No item appears for an older container after rebuilding with the same tag | Recreate the container with the new image | [docker run containers](remediation-reference.md#docker-run-containers) |
| `plan.json` contains a plan, but no notification arrives | Check KestreLynx logs for delivery failures and check notification delivery conditions | [Scan notification conditions](notification-conditions.md#notification-conditions), [Remediation plan redelivery](notification-conditions.md#remediation-redelivery) |
| `source_not_found`: “the source repository or branch was not found” | Correct the mapping's `repository`, `base_branch`, and `dependencies.directory` to existing values | [Source mappings](configuration.md#remediation-mappings) |
| `source_access_denied`: “access to the source repository was denied” | Use a GitHub token that can read Contents in the target repository | [GitHub access](configuration.md#remediation-github) |
| `source_error` with `names no repository owner to choose a token for` in the details | Change the mapping's `repository` to its current `owner/name` | [GitHub access](configuration.md#remediation-github) |
| `dockerfile_file_not_found`: “the Dockerfile is not at the configured path” (when the mapping specifies `dockerfile`) | Correct the mapping's `dockerfile.path` to the actual Dockerfile path | [Source mappings](configuration.md#remediation-mappings) |
| `dockerfile_file_not_found` when the mapping omits `dockerfile` and derives the Dockerfile from Compose's `build` | Correct the mapping's `compose.path` and the selected Compose file's `build` to match the actual build | [Source mappings](configuration.md#remediation-mappings) |
| `compose_file_not_found`: “the Compose file is not at the configured path” | Correct the mapping's `compose.path` to the actual Compose file path | [Source mappings](configuration.md#remediation-mappings) |
| `manifest_file_not_found`: “the manifest is not at the configured path” | Correct whichever path the mapping sets: `manifest.path`, `kustomize.path`, or `helm_values.path` | [Source mappings](configuration.md#remediation-mappings) |
| `dependency_files_not_found`: “no dependency files were found” | Correct `dependencies.directory` or add the missing dependency files identified in the details on the target branch | [Source mappings](configuration.md#remediation-mappings) |
| No dependency findings for an image containing only a Rust binary | Rebuild with cargo-auditable and redeploy the image | [Rust candidate selection](remediation-cargo-logic.md#cargo-package-selection) |
| `ambiguous_dependency_files`: “more than one set of dependency files matches” | Remove unused lockfiles from the directory named by `dependencies.directory` on the target branch | [Source mappings](configuration.md#remediation-mappings) |
| `auth_required`: “the registry requires a login” | Correct `host`, `username`, `password`, and `token_hosts` under top-level `registries` for the registry being accessed | [Image registry authentication](configuration.md#registries) |
| The webhook `reason` is `locally_built` and no image update candidate appears (this reason is not shown in Slack) | Set `dockerfile.path` or `dependencies.directory` in the mapping | [Source mappings](configuration.md#remediation-mappings) |
| `base_update_not_deployed`: “PR &lt;PR&gt; (base image &lt;image&gt; &lt;old-tag&gt; → &lt;new-tag&gt;) is merged, but the running image is still built from &lt;old-tag&gt;” | Deploy an image rebuilt from the Dockerfile after the merge | [Base layer matching](remediation-base-image-logic.md#base-layer-matching) |
| `base_layers_mismatch`: “the running image was not built from &lt;base-image&gt;, which the FROM names (the image was not rebuilt after the Dockerfile changed, or the tag was moved after the build)” | Match the mapping's `dockerfile.path` and `dockerfile.target` to the actual build, or deploy a rebuilt image if the settings already match | [Source mappings](configuration.md#remediation-mappings) |

Work stopped by a limit is deferred to later cycles; if a limit is reached every cycle, increase the following setting as described under [Processing limits](configuration.md#remediation-limits).

| What you see | Setting to increase |
| --- | --- |
| `candidate_scan_limit`: “the limit on candidate scans of a run was reached” | `remediation.limits.candidate_scans_per_cycle` |
| `baseline_rescan_limit`: “the limit on rescans of running images was reached” | `remediation.limits.baseline_rescans_per_cycle` |
| `registry_budget_exhausted`: “the registry request budget of a run is used up” | `remediation.limits.registry_requests_per_cycle` |
| `tag_page_limit`: “the limit on tag list requests was reached” | `remediation.limits.tag_pages_per_repository` |
| `cycle_deadline`: “the time limit of the run was reached” | `remediation.limits.cycle_timeout` |

## Checking update failures {#check-update-failure}

Language-package updating applies candidate updates and checks the resulting dependency files.

When candidates are not updated, follow the action in the row that matches the notification reason in the following table.

| What you see | What to do | Reference |
| --- | --- | --- |
| A language package remains an “Update candidate” with webhook `category: dependency_update_candidate` | Set `remediation.pull_requests.enabled` to `true` | [Basic settings](configuration.md#remediation-basics) |
| `tool_too_new` with `it can be used from` in the details | Wait until the time following `it can be used from` in the details | [Work containers](configuration.md#remediation-worker) |
| `tool_fetch_failed` with `downloading` or `reading the registry's document` in the details, but no `answered` | Enable HTTPS connections to `registry.npmjs.org`, `pypi.org`, and `files.pythonhosted.org` | [Tool downloads](outbound-communication.md#tool-downloads) |
| `tool_fetch_failed` with `the tool cache could not be written` in the details | Ensure `remediation.storage_dir` is writable and has free space | [Basic settings](configuration.md#remediation-basics) |
| `tool_hash_mismatch` with `declared hash` in the details | Correct the hash in `packageManager` in the target branch's `package.json` | [Tool version declarations](remediation-dependency-formats.md#tool-declarations) |
| `tool_cache_full`: “the cache of package managers is full” | Increase `remediation.worker.tool_versions.cache_max_size` | [Work containers](configuration.md#remediation-worker) |
| `work_image_unavailable` with `the work image could not be made ready` or `work image unavailable` in the details | Enable work image retrieval from Docker Hub or the mirror set in `remediation.worker.registry` | [Work image downloads](outbound-communication.md#worker-image-downloads) |
| `work_image_unavailable` with `the work program is missing or is not the one this build was released with` in the details | Use the program that runs updates from the running KestreLynx build in `remediation.worker.program_dir` | [Work containers](configuration.md#remediation-worker) |
| `work_image_unavailable` with `the instance id of the work containers could not be read or created` in the details | Set `remediation.storage_dir` to a writable location | [Basic settings](configuration.md#remediation-basics) |
| `work_image_not_configured`: “no work image is configured for updates” | For a custom build without the program that runs updates, set `remediation.worker.program_dir` to the directory containing the program | [Work containers](configuration.md#remediation-worker) |
| `work_program_mismatch`: “the program in the work container is not the one this build came with” | Restart KestreLynx after replacing the program that runs updates in `remediation.worker.program_dir` | [Work containers](configuration.md#remediation-worker) |
| `update_job_limit`: “the limit on update jobs of a run was reached” | Increase `remediation.limits.dependency_jobs_per_cycle` | [Processing limits](configuration.md#remediation-limits) |
| `update_job_timed_out`: “the update job timed out” | Increase `remediation.limits.job_timeout` | [Processing limits](configuration.md#remediation-limits) |

When Kubernetes language-package updates require manual action or are deferred, check the following items by reason.

| What you see | What to do | Reference |
| --- | --- | --- |
| `work_namespace_not_configured`: “updates on Kubernetes need work Pods, and no work namespace is configured” | Set `remediation.worker.kubernetes.namespace` to the work namespace | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_cluster_too_old`: “the cluster is older than the lowest Kubernetes version the work Pod policy needs” | Upgrade Kubernetes to version 1.30 or newer | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_runtime_class_unsupported`: “a RuntimeClass is configured for work Pods, which is not supported yet” | Clear `remediation.worker.kubernetes.runtime_class` | [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) |
| `work_admission_unverified` with `the policy allows none of the work images` in the details | Set `data.receiverRepository` and `data.workRepositories` in `52-policy-params.yaml` to the actual repositories | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_admission_unverified` with `the policy is not in force` in the details | Reapply `50-validatingadmissionpolicy.yaml` and `51-validatingadmissionpolicybinding.yaml` | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `work_priority_class_missing` with `does not exist` in the details | Create a PriorityClass with the name set in `remediation.worker.kubernetes.priority_class` | [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) |
| `work_priority_class_missing` with `is not one that never preempts, or is not the one the policy expects` in the details | Set the PriorityClass's `preemptionPolicy` to `Never` and match `data.priorityClass` in `52-policy-params.yaml` to the configured name | [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) |
| `work_pod_limit`: “the work namespace is at its Pod or quota limit, so the update waits for the next cycle” | Free capacity under the work namespace's Pod and quota limits | [Kubernetes work container settings](configuration.md#remediation-worker-kubernetes) |
| `work_pod_not_started`: “the work Pod did not start in time” | Resolve the startup blocker identified in Pod events | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `update_result_invalid` with details indicating missing result logs | Set the execution node's `containerLogMaxSize` to at least `144Mi` | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |
| `update_job_failed` with `workRepositories of its parameters must list` in the details | Add the repository named in the details to `data.workRepositories` in `52-policy-params.yaml` | [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates) |

The files in the table are under `deploy/kubernetes/work/`; after editing `52-policy-params.yaml`, reapply it as described under [Preparing work Pods](remediation-setup-work-pods.md#kubernetes-language-updates).

Check the cause of `work_pod_not_started` during update execution using the following steps, because work Pods are deleted when processing ends.

1. List Pods labeled `io.kestrelynx.work=v1` in the work namespace and select the Pod whose creation time matches the failed update's time

    ```sh
    kubectl -n WORK_NAMESPACE get pods -l io.kestrelynx.work=v1 -o custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp
    ```

2. Display events for the selected Pod

    ```sh
    kubectl -n WORK_NAMESPACE get events --field-selector involvedObject.name=POD_NAME
    ```

In the commands, replace `WORK_NAMESPACE` with the value of `remediation.worker.kubernetes.namespace` and `POD_NAME` with the selected Pod's name.

## Checking for a missing PR {#check-missing-pr}

PR processing checks whether updates can be adopted and source files can be edited, then checks for existing PRs to prevent duplicates.

You can check why there is no PR despite an available fix on the card's [`Action:` line](slack-package-display.md#base-image-wait) in the vulnerability notification.

Use the following table when an update candidate exists but no PR appears.

| What you see | What to do | Reference |
| --- | --- | --- |
| An image “Update candidate” in the remediation plan has no PR or reason, and `remediation.pull_requests.enabled` is `false` | Set `remediation.pull_requests.enabled` to `true` | [Basic settings](configuration.md#remediation-basics) |
| An image “Update candidate” in the remediation plan has no PR or reason, and the Compose service's mapping has no `compose` | Configure `compose` in the mapping | [Source mappings](configuration.md#remediation-mappings) |
| An image “Update candidate” in the remediation plan has no PR or reason, and the Kubernetes workload's mapping has none of `manifest`, `kustomize`, or `helm_values` | Configure `manifest`, `kustomize`, or `helm_values` in the mapping | [Source mappings](configuration.md#remediation-mappings) |
| An image “Update candidate” in the remediation plan has no PR or reason, and the target is a container started with `docker run` (`container/<name>`) | KestreLynx does not create PRs that change image tags for containers started with `docker run` | [docker run containers](remediation-reference.md#docker-run-containers) |
| `undeclared_affected_workload`: “a container that is not listed declares the image of the images entry and may be changed by it” (when the tag change should also include the container identified in the details) | Add the container identified in the details to the mapping's `affects` | [Configure Kustomize PRs](remediation-setup-kubernetes.md#kustomize-pull-requests), [Configure Helm values PRs](remediation-setup-kubernetes.md#helm-values-pull-requests) |
| `undeclared_affected_workload` when the tag change should not include the container identified in the details | Change and deploy the manifests so that the container identified in the details no longer declares the same image reference as the mapped entry's value | [Kustomize and Helm values PRs](remediation-kubernetes-logic.md#kustomize-and-helm-prs) |
| `init_container_unverified`: “a listed init container could not be shown to have run the image of the running containers” (the details contain `no running container of the set runs in the same Pod`) | Add the running container that uses the target image in the init container's Pod to the mapping's `affects` | [Source mappings](configuration.md#remediation-mappings) |
| `init_container_unverified` with `it ran the same image entity as` in the details | Change the image reference in the init container's manifest to the running container's reference identified in the details and recreate the Pod | [Kustomize and Helm values PRs](remediation-kubernetes-logic.md#kustomize-and-helm-prs) |
| `kustomize_image_missing`: “the kustomization has no images entry of the mapped name” | Set the mapping's `kustomize.path` and `kustomize.image` to the `images` entry to update | [Source mappings](configuration.md#remediation-mappings) |
| `helm_key_missing`: “the values file has no value at the mapped key” | Set the mapping's `helm_values.path` and `helm_values.key` to the key that specifies the image | [Source mappings](configuration.md#remediation-mappings) |
| `github_refused`: “GitHub refused the write” | Grant the token Read and write access to Contents and Pull requests | [GitHub access](configuration.md#remediation-github) |
| `github_refused` with details indicating rejection by branch protection or a ruleset | Correct the repository rules | [GitHub access](configuration.md#remediation-github) |
| `pr_limit`: “the limit on pull requests of a run was reached” | Increase `remediation.limits.new_prs_per_cycle` | [Processing limits](configuration.md#remediation-limits) |
| `open_pr_limit`: “the limit on open pull requests of KestreLynx was reached” | Merge or close open KestreLynx PRs, or increase `remediation.limits.open_prs` | [Processing limits](configuration.md#remediation-limits) |
| Slack shows “closed without merging” and the closed PR's update is not proposed again (webhook `status: pr_suppressed`) | Reopen the closed PR on GitHub to propose the update again | [Closed PRs](remediation-pr-logic.md#closed-prs) |
| `write_outcome_unknown`: “the result of a write to GitHub is unknown” | Wait for the next cycle | [Stopping writes](remediation-pr-logic.md#write-stops), [PR operation event fields](webhook-remediation-pr-reference.md#remediation-operation-fields) |

For `undeclared_affected_workload`, update `affects` across mappings as follows.

- Include all mappings that target the same Kustomize entry or Helm key in the same repository, branch, and file
- Each mapping must declare the same combined list of containers from `workload` and `affects`
- The `workload` values may differ between mappings

## Checking record reconciliation failures {#check-record-failure}

Record reconciliation checks `prs.json` against PRs and operation results on GitHub to decide whether GitHub writes may proceed.
Use the following table when “Pull request writes are stopped” or a record error appears.

| What you see | What to do | Reference |
| --- | --- | --- |
| `storage_failed`: “the pull request records could not be saved”, or Slack shows “The fix plan could not be saved.” | Place `remediation.storage_dir` on a writable persistent volume with free space | [Basic settings](configuration.md#remediation-basics) |
| `store_locked`: “the pull request records are locked by another process” | Stop any other KestreLynx instance using the same storage location | [Storage reasons](remediation-update-reason-codes.md#storage-reasons) |
| `records_unverified`: “the records of existing pull requests could not be verified” with `kestrelynx marker`, `the marker is malformed`, or `the marker's keys do not recompute` in the details | If you edited the PR body, restore the HTML comment beginning with `<!-- kestrelynx:` to its content before the edit | [Record recovery](remediation-pr-logic.md#record-recovery) |
| `records_unverified` with `github: authentication required` or `github: access forbidden` in the details | Use a valid token with Read and write access to Contents and Pull requests in the target repository | [GitHub access](configuration.md#remediation-github) |
| `records_unverified` with `github: not found` in the details | Correct the mapping's `repository` to an existing `owner/name`, or grant the token access to the target repository if it already exists | [GitHub access](configuration.md#remediation-github) |
| `records_unverified` with `github: rate limited` in the details | Wait for a cycle after GitHub's rate limit is lifted | [GitHub access](configuration.md#remediation-github) |
| `records_unverified` with `GitHub names the repository` in the details | Change the mapping's `repository` to the name shown in the details | [Source mappings](configuration.md#remediation-mappings) |
| The logs contain `parse plan`, `parse pull request records`, or `operation events are out of sequence` | If you manually edited `plan.json` or `prs.json`, undo the edit | [Stopping writes](remediation-pr-logic.md#write-stops) |
| `unsupported plan version` or `unsupported pull request record version` appears, or the details contain `the marker has version` | Switch KestreLynx back to the version that created the file or PR | [Stopping writes](remediation-pr-logic.md#write-stops) |
| `storage_full`: “the pull request records are full” | Wait for the next cycle | [Stopping writes](remediation-pr-logic.md#write-stops), [Storage reasons](remediation-update-reason-codes.md#storage-reasons) |
| `storage_full` persists with a `send notification` error in the logs | Correct the failed destination's URL, credentials, or connection in the `notify` settings and wait for the next cycle | [Notification destinations](configuration.md#notify-destinations) |
| `storage_full` persists even though notifications are being delivered | Follow the remedies for other reasons stopping PR creation or replacement in the notification that shows `storage_full` | [PR processing reasons](remediation-update-reason-codes.md#pr-reasons) |

!!! warning "Preserve records"

    Do not delete PR processing records to force a retry.
    They are needed to prevent closed updates from being recreated and to reconcile previous operations.
