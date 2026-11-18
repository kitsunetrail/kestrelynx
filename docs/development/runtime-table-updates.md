# Development to separate the runtime table from the KestreLynx image

- **Status:** Implemented (table publication and fetching, dependency updates, unused work image removal, and startup in deployed environments verified)
- **Started:** November 18, 2026
- **Last updated:** November 18, 2026

## Purpose

Separate the runtime table from the KestreLynx image so that new execution versions and series can be used without fetching a new KestreLynx image.

The runtime table, which specifies the execution versions and official images used for language package updates, is supplied in the KestreLynx image.
To receive each weekly table update, users therefore need to fetch a new KestreLynx image.

The following table shows the effects on language package updates when users do not fetch a new KestreLynx image and the runtime table stays old.
The first two rows show limitations caused by an old runtime table; the last shows that end-of-support status still changes even when the table is old.

| When the table stays old | Effect on users |
|---|---|
| Work images stay old | Fixes to Node.js, Python, Go, and OS libraries are not included |
| The Go execution version is old | A `go.mod` requiring a newer patch version than the table provides cannot be updated |
| An end-of-support date in the table is reached | The series becomes unsupported based on the current time, even if the table is old |

The behavior during use is described in [Updating the runtime table](../documentation/remediation-worker-logic.md#runtime-table-updates).

## Approach

- Publish the runtime table separately from the KestreLynx image
- Fetch the published table at startup and at the start of each cycle
- Replace the current table if the fetched table passes the checks and is newer
- Remove unused work images only if KestreLynx fetched them itself

## Decisions

### Publishing and fetching the table

<h4>Decision</h4>

Publish the table as a single file on GHCR, separately from the KestreLynx image.
KestreLynx fetches it at startup and at the start of each cycle, without changing the table during a cycle.

<h4>Details</h4>

The publication destination is `ghcr.io/kitsunetrail/kestrelynx-runtimes`.
Publish the table when the weekly table update PR is merged.

Settings are described in [Work containers](../documentation/configuration.md#remediation-worker), and destinations in [Runtime table downloads](../documentation/outbound-communication.md#runtime-table-download).

### Conditions for replacing the table with a fetched table

<h4>Decision</h4>

Replace the whole table when the fetched table passes the checks and is newer than the current one.

<h4>Details</h4>

The table to use is selected as follows.

| Situation | Table used |
|---|---|
| Before the first fetch completes | Supplied table |
| Fetched table passes the checks and is newer than the current table | Replace the entire table with the fetched table |
| Fetched table is not newer than the current table | Table currently in use |
| Fetched table fails the checks | Table currently in use |
| Fetching is disabled | Supplied table |

The fetched table is checked against the following conditions.

- Size and counts are within the limits
- Images are the official Docker Hub `node`, `python`, `golang`, and `gradle` images
- Digests and versions are correctly formatted
- Series and versions are consistent
- The update time is not 24 hours or more in the future

Rows unsupported by the KestreLynx in use are skipped individually.

### Changes that take effect without updating KestreLynx

<h4>Decision</h4>

Allow table updates alone to make new series available, as well as updates to execution versions and official images.

<h4>Details</h4>

The following table shows whether each change requires a KestreLynx update.

| Change | KestreLynx update |
|---|---|
| Execution versions and official images for existing series | Not required |
| pip versions | Not required |
| End-of-support dates | Not required |
| New series (Node.js, Python, and Go) | Not required |
| New Gradle versions and JDK combinations | Not required |
| Support for Gradle plugins, such as Spring Boot | Required |
| Interpretation of `lts/<new-name>` in `.nvmrc` | Required |
| New languages | Required |

### Changes to use new series in work containers

<h4>Decision</h4>

The work program carries no runtime table and reads the language and series from the runtime name.

<h4>Details</h4>

The work program is the KestreLynx program that runs the package manager inside a work container.

Previously, the work program also carried a runtime table and checked that the requested runtime was listed.
That table came from when the KestreLynx image was built, so series added later could not be used.

In runtime names, `node24` means Node.js 24, and `gradle9.8.2-jdk21` means Gradle 9.8.2 with JDK 21.
The program still checks that the version actually run matches the instructed version.

### Signatures

<h4>Decision</h4>

The table is left unsigned.
Fetched tables are checked to ensure that images are official Docker Hub images, so changing the table cannot cause unofficial images to run.

### Removing unused work images

<h4>Decision</h4>

On Docker, remove work images that are no longer used after the table is replaced.
Only images that KestreLynx fetched itself are removed.

<h4>Details</h4>

Images are not removed in the following cases.

| Case | Handling |
|---|---|
| The user has tagged the same image | Do not remove it |
| The user had already fetched the same image | Do not remove it |
| A container uses the image | Keep it and retry in the next cycle |

Removal is not forced.
On Kubernetes, image removal is left to the node.

The conditions during use are described in [Removing unused work images](../documentation/remediation-worker-logic.md#worker-image-cleanup).

## Verification methods

- Run work containers on local Docker to check that dependency updates with npm, pnpm, uv, pip, Go, and Gradle still work after removing the table from the work program
- Publish the table to GHCR and check that KestreLynx can fetch it without authentication
- With both Docker image store types, check locally that unused work images are removed and users' images are retained
- Update KestreLynx in the production environment (Docker) and on the validation host (Kubernetes), and check the startup logs for the table in use

## Verification results

### Dependency updates

Dependency updates were checked on Docker 29.1.3.

| Target | Series included | Result |
|---|---|---|
| npm, pnpm, uv, pip, and Go updates | Node.js 22, 24, and 26; Python 3.11–3.15; Go 1.26 and 1.27 | All 61 cases passed |
| Gradle updates | Gradle 8.14.6 and 9.8.2 | All 3 cases passed |

### Publishing and fetching the table

The table was published to GHCR and could be fetched without authentication immediately after publication.
All 106 rows in the fetched table passed the checks.

### Removing unused work images

Removal was checked on Docker 29.1.3 (containerd image store) and Docker 29.10.0 (classic image store), with the same results.

| Case | Result |
|---|---|
| Image fetched by KestreLynx itself | Removed |
| Image tagged by the user after fetching | Retained |
| Image used by a stopped container | Retained, then removed in the cycle after the container was removed |

Removing an image by digest with the containerd image store also removed its tags, so KestreLynx does not remove tagged images.

### Startup in deployed environments

KestreLynx was updated on Docker in the production environment and on Kubernetes on the validation host, and the startup logs were checked.

| Recorded item | Value |
|---|---|
| Table source | Supplied |
| Update time | `2026-11-16T11:58:54Z` |
| Row count | 106 rows |

The published table has the same contents as the supplied table, so no replacement occurred.

| Environment | First cycle |
|---|---|
| Production environment (Docker) | Completed with 0 warning or error log entries |
| Validation host (Kubernetes) | Completed with 0 warning or error log entries |

## Known limitations

- Tests before publishing the table use the latest KestreLynx, so correct operation of older KestreLynx versions with new series has not been checked
    - If it does not work, the update fails and no PR is created

## Unverified areas and next steps

Verify that deployed environments replace the table with the next weekly table without updating the KestreLynx image.

## Update history

### November 18, 2026

- Implementation and verification of table publication and fetching, and unused work image removal

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
