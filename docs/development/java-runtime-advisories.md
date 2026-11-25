# Development of Java runtime vulnerability matching

- **Status:** Implemented (verified in the production environment and on a validation host).
- **Started:** November 24, 2026
- **Last updated:** November 25, 2026

## Purpose

Include vulnerabilities in the JDK itself that Trivy does not detect in notifications and remediation plans.
The scope covers Temurin-based images, including the official `maven` and `gradle` images, and images that bundle a JDK, such as Elasticsearch.

## Background

Among the images examined, Trivy 0.76.2 reports no JDK vulnerabilities in either the images that use major JDK distributions such as Temurin, Corretto, and Zulu or the Elasticsearch image that bundles a JDK.
Temurin is installed by unpacking a tarball, so it is neither an OS package nor a language package.
The November 17, 2026 OpenJDK advisory listed the Oracle OpenJDK build 27.0.1.0.3 bundled with Elasticsearch in the production environment as affected, but the vulnerabilities did not appear in notifications.

## Approach

- **Reading the JDK version and matching it against OpenJDK advisories**
    - Read the `JAVA_VERSION` environment variable when its value uses the Temurin format.
    - Read the version from the JDK's `release` file in the image layers.
- **Public data retrieval and local assessment**
    - Download public data and perform matching within KestreLynx without sending information about scanned images externally.
- **Selecting distributions by version numbering scheme**
    - Check only distributions that use the same version numbering scheme as upstream OpenJDK.

## Data sources

The table shows the public data used for JDK matching and how each source is used.

| Data source | Use |
| --- | --- |
| OpenJDK advisories | Read the last affected version for each release line, along with CVE IDs and CVSS scores. |
| Adoptium's Temurin release list | Determine the fixed version. |
| Adoptium's release-line list | Determine which lines are LTS and which have reached end of life. |

## Decisions

- **JDK distributions checked**
    - Check Temurin, Oracle OpenJDK builds, and JDKs with no listed vendor, such as runtimes built with `jlink`.
    - Skip Corretto, Zulu, SapMachine, Microsoft, Liberica, Semeru, and commercial Oracle JDK builds.
    - Limiting the distributions checked avoids false positives and missed findings caused by Zulu's own version numbers or differences between Oracle JDK 11 and upstream version numbers.
    - Trivy reports vulnerabilities in JDK packages from OS distributions.
- **Selecting images and reading their layers**
    - Read the layers of an image if it sets `JAVA_HOME` or `JAVA_VERSION`, has a `PATH` entry containing `java`, `jdk`, `jre`, or `jvm`, or contains a `jar` package reported by Trivy.
    - Fetch layers from Docker Engine for Docker images. For Kubernetes images and candidate images in remediation plans, fetch layers from the registry.
    - Cache each layer's read results to avoid reading the same layer again.
- **Read limits and deferral to the next scan**
    - Each scan reads up to 2 GiB from the registry and 8 GiB from Docker.
    - Defer reading images that would exceed the limit until the next scan.
    - Retain previous findings for deferred images without treating them as resolved.
- **Remediation plans**
    - Determine layer by layer whether the JDK comes from the base image.
    - For an image that bundles a JDK, read the new image tag and create a remediation PR only if the new image resolves the vulnerabilities.

## Verification methods

- Run unit tests with downloaded real data and actual `release` files.
- Use local Docker to check JDKs in images pinned by digest.
- In the production environment running Docker, verify the Elasticsearch findings and the remediation PR.
- On a Kubernetes validation host, verify that KestreLynx reads layers from the registry and checks the JDK.

## Verification results

### Local Docker

The table shows the JDK checked in each image with local Docker and the number of Java findings across all severities.

| Image | JDK checked | Java findings |
| --- | --- | --- |
| Distroless Java 21 | Temurin 21.0.10 (version unavailable from the environment variables) | 69 |
| `maven` (Java 21) | Temurin 21.0.12.1 | 49 (the same count as when reading the version from the environment variable) |
| JRE built from the `maven` JDK with `jlink`, keeping only `java.base` | 21.0.12.1 (no listed vendor) | 33 (excluding 16 findings for absent modules) |
| Corretto 21 | Distribution skipped | 0 (KestreLynx logs the distribution and location) |
| Elasticsearch 9.5.7 | Oracle OpenJDK build 27.0.1.1 | 0 (unaffected version) |

The first scan took about four and a half minutes. The second took 22 seconds because it did not need to read the layers again.

### Elasticsearch 8.19.25 in the production environment

KestreLynx detected vulnerabilities that Trivy had not reported in the JDK bundled with Elasticsearch and automatically created a remediation PR.
Five vulnerabilities in the bundled Oracle OpenJDK build 27.0.1.0.3 matched the default severity selection (`HIGH` and `CRITICAL`), from CVE-2026-114938 through CVE-2026-114942, all with severity `HIGH` and a fixed version of 27.0.1.1.
After the PR updated the Dockerfile base image to Elasticsearch 8.19.26, which bundles JDK 27.0.1.1, a scan confirmed that all five JDK findings had been resolved and that only one guava finding remained from the base image.

### Kubernetes validation host

In a Kubernetes environment without Docker Engine, KestreLynx detected the JDK by reading image layers from the registry.
For a Pod running a `maven` image (Java 21) pinned by digest, KestreLynx detected Temurin 21.0.12.1 and reported eight Java findings under the default severity selection.
All reads succeeded, and no images were deferred to the next scan.

### Temurin image with a floating tag

Although the floating tag in the Dockerfile's `FROM eclipse-temurin:21-jre` prevented KestreLynx from creating a remediation PR, the remediation plan showed that a rebuild was expected to resolve the vulnerabilities.
The image built from `eclipse-temurin:21.0.10_7-jre` and run on local Docker used Temurin 21.0.10 and had 69 Java findings across all severities.
The first and second scans produced the same row in the remediation plan, showing that a rebuild was expected to update the JDK to 21.0.13.1, the version currently in `eclipse-temurin:21-jre`, and resolve all 69 findings.

## Known limitations

- **Matching scope**
    - KestreLynx skips JDKs from distributions outside the matching scope.
    - KestreLynx skips images with no signs of Java.
        - This includes images that leave a JRE built with `jlink` outside `PATH` and run it directly from a startup script.
- **Fixed versions shown for Oracle OpenJDK builds**
    - Because KestreLynx determines the fixed version from the Temurin release list, the displayed version can be later than the first upstream release with the fix.
- **Affected ranges in advisories**
    - Advisories do not identify the first affected version, so older versions in the same release line can also be reported as affected.
- **Layer compression formats**
    - KestreLynx skips layers compressed with zstd.

## Unverified areas and next steps

- **Default read limits**
    - Reassess the limits using the time spent reading layers and the amount of data read.

## Update history

### November 25, 2026

- Implemented and verified Java runtime vulnerability matching.
- Verified the remediation plan for a Temurin image with a floating tag.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
