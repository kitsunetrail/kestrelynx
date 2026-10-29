# Newer series check development

- **Status:** Implemented (local verification only).
- **Started:** October 29, 2026
- **Last updated:** October 29, 2026

## Purpose

Remediation candidates for pinned tags are selected only from the latest patch in the same series (the same major and minor).
When a series had ended or a newer patch did not resolve the findings, notifications continued to say that a newer version was needed, leaving users to investigate whether a newer minor version would resolve them.

To reduce that effort, KestreLynx checks up to two versions—the latest versions with a newer minor or major—and reports candidates that resolve findings in remediation plans and cards.
Since compatibility cannot be verified, it does not create PRs to update to a newer series.

## Approach

- Keep the rule of selecting remediation candidates from the latest patch in the same series
- Compare newer-series candidates using the same method as same-series candidates

## Decisions

### Eligible items and versions checked

The check covers pinned tags of published images and pinned-tag `FROM` references in mapped Dockerfiles.
It runs when there is no newer patch in the same series, when the newer patch has the same content as the current image, or when the newer patch does not resolve the target findings.

| Order | Version checked |
| --- | --- |
| First | The latest version with the same major and a newer minor |
| Second | The latest version with a newer major |

Intermediate minor versions are not checked, so findings remaining in the checked versions do not establish that no fixed version exists.
Remaining findings in an item that became a PR candidate after a same-series candidate resolved some findings are excluded.

- If there is no same-major candidate, checking starts with the newer-major candidate
- If the first candidate resolves all findings without adding new findings, the second is not checked
- If the first candidate resolves only some findings, adds new findings, or leaves all findings unresolved, the second is also checked
- If the first candidate cannot be checked, checking does not proceed to the second

### Comparison and candidate selection for display

The result is derived from individual target results, rather than the comparison's decision category.
Resolved findings and newly added findings are considered separately; if even one target is indeterminate or was not detected in the baseline, the candidate is not described as resolving the findings.

| Comparison result | Treatment |
| --- | --- |
| All findings resolved without adding new findings | All resolved |
| Some findings resolved without adding new findings | Partly resolved |
| At least one finding resolved, with new findings or KEV-listed findings added | Report both the resolutions and additions as needing a decision |
| No target findings resolved | Not resolved |
| Any target indeterminate or not detected in the baseline | Treat the result as unverified and exclude the candidate from selection for display |

Selection for display prioritizes a version that resolves all findings without adding any.
Otherwise, the version resolving the most findings is selected; ties favor the version without added findings, then the version checked first.

For Dockerfiles, the current and candidate base images are compared for each running image, and results for the same candidate are aggregated.
This is a comparison between base images; the rebuilt image and application compatibility remain unchecked.

### Guidance in remediation plans and cards

The remediation plan is the “🔧 Fix plan” message that lists update suggestions for each image or file, and it shows a “Newer series” line only when a version in a newer series resolves findings.
A card is the part of a vulnerability notification thread that shows findings for each package, and it shows newer-series results on the `Action:` line.

The remediation plan lines include “compatibility not checked”.

| Situation | Example |
| --- | --- |
| All findings resolved in the remediation plan | `Newer series: nginx 1.24.1 → 1.27.3 (minor update, resolves 1 finding(s), compatibility not checked)` |
| Some findings resolved in the remediation plan | `Newer series: nginx 1.24.1 → 1.27.3 (minor update, resolves 1 of 2 findings, compatibility not checked)` |
| Dockerfile base comparison in the remediation plan | `Newer series: base image python 3.11.9-slim → 3.13.1-slim (minor update, resolves 2 finding(s), base images compared, the rebuilt image not checked, compatibility not checked)` |
| New findings added in the remediation plan | `Needs a decision: nginx 1.24.1 → 2.0.1 in a newer series resolves 1 finding(s) and adds 2 (major update, compatibility not checked)` |

Cards show the results for the findings on that card on the `Action:` line after `Findings:`.

| Situation | Example |
| --- | --- |
| Card findings resolved in a base image | `Action: base image python 3.11.9 → 3.13.1 resolves it (minor update, no newer tag in the same series, base images compared)` |
| Card findings partly resolved in a published image | `Action: image nginx 1.24.1 → 1.27.3 resolves part of it (1 of 2, minor update, no newer tag in the same series)` |
| Card findings still unresolved in the checked versions | `Action: waiting for a newer image of nginx 1.24.1 (not resolved in the checked tag(s) 1.27.3 and 2.0.1 either)` |
| No newer tag in the same series or a matching newer series | `Action: waiting for a newer base image of python 3.11.9 (no newer tag in the same series or in a newer series of the same form)` |

If findings remain unresolved even in a newer series, only the card's `Action:` line changes to “not resolved in the checked versions either”, and this is not included in the remediation plan message.
A change to this line alone does not cause the detailed thread report to be sent again; the information is delivered the next time findings change or in the weekly full report.

## Verification method

### Unit tests

- Verified version selection, conditions for checking the next candidate, and candidate selection priorities for display
- Verified classification based on individual target results and added findings
- Verified aggregation of Dockerfile comparison results across running images
- Verified remediation plan notification lines, cards, Webhook output, and notification send decisions

### Integration test environment

The following two targets were checked locally using Docker, Trivy, and Docker Hub.

| Target | Configuration |
| --- | --- |
| Published image | A container running `aquasec/trivy:0.71.2` directly |
| Dockerfile base | A container built from a Dockerfile with `FROM aquasec/trivy:0.71.2` |

### Integration test scope

The tests checked the availability of same-series candidates, newer-series candidate selection, scan comparisons, and registry request counts.
Slack remediation plan lines and card lines were verified by rendering them from the plans and findings obtained in the integration tests.

## Verification results

The following results are from local verification on October 29, 2026.

### Candidates and resolution results

| Check | Result | Significance for the implementation |
| --- | --- | --- |
| Candidate selection | No newer patch existed in the `0.71.2` series; the only newer-series candidate was the minor update `0.76.1`, with no newer major version | Checking can proceed to a newer series even without a same-series candidate |
| Published image and Dockerfile base | Both resolved 53 of 56 target findings without adding new findings | Partial resolution can be identified for both target types |
| Remaining findings | `CVE-2026-111497` in `brotli-libs` remained unresolved in `0.76.1` | The overall resolution count does not imply that each individual finding is resolved |

### Remediation plan and card display

| Display location | Verified text |
| --- | --- |
| Published-image remediation plan | `Newer series: aquasec/trivy 0.71.2 → 0.76.1 (minor update, resolves 53 of 56 findings, compatibility not checked)` |
| Card for `brotli-libs` remaining in the Dockerfile base | `Action: waiting for a newer base image of trivy 0.71.2 (not resolved in the checked tag(s) 0.76.1 either, base images compared)` |
| Card for findings resolved in the published image | `Action: image trivy 0.71.2 → 0.76.1 resolves it (minor update, no newer tag in the same series)` |

The remediation plan identified a version that resolves some findings, while cards distinguished remaining findings from resolved findings.
This allows users to see which findings an update would resolve and which still require waiting for a newer version.

## Unverified areas and next steps

- Verification with a real example of `resolves`, where all findings are resolved
- Verification that retrieving the full tag list stays within limits for repositories with many tags
- Verification in the production environment and on a validation host

## Update history

### October 29, 2026

- Implemented comparisons of up to two newer-series versions and reporting of resolution results in remediation plans and cards.
- Documented decisions based on individual target results and notification delivery.
- Recorded integration test results for published images and Dockerfile bases, along with the unverified scope.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
