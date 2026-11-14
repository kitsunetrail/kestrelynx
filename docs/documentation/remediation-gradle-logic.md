---
title: Gradle updates
---

# Gradle updates

For Gradle, KestreLynx edits version declarations and updates the lockfile in a work container or Pod.
Trivy examines the files before and after the update and compares findings.

Gradle updates follow these steps.

1. Use [Gradle package selection](#gradle-package-selection) to choose dependencies and version declarations to update
2. Edit the declarations and run `dependencies --update-locks` in a work container or Pod according to [Gradle worker settings](#gradle-worker-settings)
3. Check returned files, the lockfile, and findings through [Gradle update validation](#gradle-update-validation)
4. If a target cannot be updated, use [Conditions for excluding targets and updating the rest](#gradle-update-exclusions) to decide whether to continue

See [Terms](remediation.md#terms) for the terminology used on this page.

## Gradle package selection {#gradle-package-selection}

Gradle package selection matches `jar` findings from the running image against the `group:artifact` names and versions in `gradle.lockfile`.
It reads files in the dependency directory specified by the mapping.

Dependencies are candidates when the running version appears in `compileClasspath`, `runtimeClasspath`, or `productionRuntimeClasspath`.
If the detection path does not end in the target's own `artifactId-version.jar`, the target is treated as a copy inside another archive and requires manual handling with `jar_bundled_copy`.

A package running at multiple versions also requires manual handling.

Direct dependencies are identified from dependency declarations in the build script and catalog references.
KestreLynx checks whether Gradle's standard configuration inheritance carries a dependency from its declared configuration into the configuration that locks the running version.

The following table contrasts a relationship determined by standard inheritance with one that cannot be determined.

| Declared configuration | Relationship to the configuration locking the running version | Result |
| --- | --- | --- |
| `implementation` | The declared dependency enters `runtimeClasspath` | Direct dependency |
| `developmentOnly` or similar configurations | Standard inheritance alone does not determine the relationship | Manual handling with `gradle_build_unsupported` |

`constraints` do not count as direct dependency declarations.
The check also accounts for `compileOnly` extending `annotationProcessor` using a supported declaration.

### Target versions {#gradle-target-versions}

Gradle's update target lower bound, published release from Maven Central, and guidance about fixed versions in another major version follow the Maven rules in [Target versions and Maven Central releases](remediation-maven-logic.md#maven-target-versions).

### Version declarations and edits {#gradle-version-sources}

Version declaration checks locate the declaration that determines the target's version and decide where to edit.
Methods are examined in the following order; if the applicable method cannot make the change, manual handling is required.

1. If a dependency declaration specifies the target's version, change that declaration
2. If no dependency declaration specifies a version, check whether the Spring Boot BOM determines the target's version
3. If the target has no dependency declaration and the Spring Boot BOM does not determine its version, check whether a `constraints` entry can be added for the transitive dependency

An uneditable dependency declaration or BOM property does not cause KestreLynx to switch to the next method.
Mixed versioned and unversioned dependency declarations for the same target require manual handling.

An unversioned direct dependency requires manual handling unless the Spring Boot BOM specifies its version.
Adding `constraints` is considered for a transitive dependency with no dependency declaration for the target and no version specified by the Spring Boot BOM.

Declarations are edited as follows.

| Declaration location | Edit |
| --- | --- |
| Catalog `[versions]` | Change the version value |
| Catalog library `version` or `"g:a:v"` | Change the library version |
| Build script `"g:a:v"` | Change the version within the string |
| Spring Boot BOM property | Change the existing value |
| Unset Spring Boot BOM property | Append it to `gradle.properties` |
| Transitive dependency with no target dependency declaration and no version specified by the Spring Boot BOM | Append `constraints` to the end of the build script |

Edit conditions are checked according to the selected edit method.
A target whose edit method cannot be determined requires manual handling with `gradle_version_source_unsupported`.

Each condition in the following table applies only when that edit method is used.

| Edit method | Condition |
| --- | --- |
| Change a catalog version | The declared version matches the running version and is not shared with `[plugins]` |
| Change a build script version | The declared version matches the running version and the `"g:a:v"` string being changed appears exactly once in the entire file |
| Change or add a BOM property | It is set exactly once in `gradle.properties` or the build script's `extra` or `ext`, or is unset |
| Add `constraints` | Every configuration locking the target is one of `compileClasspath`, `runtimeClasspath`, `productionRuntimeClasspath`, `testCompileClasspath`, or `testRuntimeClasspath` |

Catalog editing supports `key = "value"` in `[versions]`, a library's single-line `"g:a:v"`, and `version = "..."` in an inline table.
Constraints are added using `dependencies { constraints { implementation("g:a:v") } }`, with the corresponding syntax for Groovy.

Updating through a Spring Boot BOM property requires both the Spring Boot and dependency-management plugins.
KestreLynx reads `org.springframework.boot:spring-boot-dependencies` at the Spring Boot plugin's version and its parents from Maven Central to find the property determining the target's version.

Declarations within the BOM are handled as follows.

| Declaration within the BOM | Handling |
| --- | --- |
| The target version is `${p}` | Change `p` |
| The BOM imported by the Spring Boot BOM (first level) has version `${p}` and directly specifies the target's version | Change `p` to update the BOM's dependencies together |
| A literal version or an expression using a property as part of a version | Require manual handling because the property to change cannot be determined |
| Multiple BOMs specify the target's version, or the first-level BOM specifies it through further BOM imports (second level or deeper) | Require manual handling because the property to change cannot be determined |

If the target version or imported BOM version is not a property the project can set, KestreLynx records the BOM at the Spring Boot plugin's version as the source determining the version.
It makes the same record for versions specified through multiple BOMs or another BOM import and uses it for [Guidance when a fixed version cannot be reached](remediation-fix-hints.md#fix-hints).

The BOM whose version is raised is the BOM imported through a property by the Spring Boot BOM.
KestreLynx examines up to 20 newer stable releases within that imported BOM's current major and minor version in ascending order.

It selects the lowest BOM version that brings the target to the published release selected from Maven Central or above.
If none of the examined BOM versions meets the condition, manual handling is required with `maven_bom_series_unreached`.

For the rules used to search for guidance about a later minor version of the imported BOM, see Maven's [Version sources and edits](remediation-maven-logic.md#maven-version-sources).

The following checks apply to every edit method.

- When multiple targets change the same property or catalog value, use the highest required version
- Verify that other packages whose versions use the same value also exist on Maven Central at that version
- Preserve formatting and comments, then reread the edits using the same reading rules
- Verify that changes to dependency declarations, the catalog, properties, and `constraints` match the intended edits
- Reread and compare declarations that the update does not change, including the Gradle version, toolchain, and plugins

See [Gradle dependency files](remediation-dependency-formats.md#gradle-inputs) for required files and inputs that require manual handling.

## Gradle worker settings {#gradle-worker-settings}

Gradle worker settings determine the Gradle and JDK used to update the lockfile and the environment passed to the work container or Pod.

Gradle and JDK versions are selected from the project's declarations.

| Item | Selection source |
| --- | --- |
| Gradle version | `distributionUrl` in `gradle/wrapper/gradle-wrapper.properties` |
| JDK version | `languageVersion` in `java.toolchain` |
| JDK when no toolchain is declared | 21 |

The Gradle version, JDK, and platform are selected from KestreLynx's built-in list of supported versions described in [Supported runtimes](remediation-reference.md#supported-runtimes).
An unavailable Gradle version requires manual handling with `gradle_version_unsupported`; an unavailable requested JDK requires manual handling with `gradle_toolchain_unsupported`.

Execution uses `/opt/gradle/bin/gradle` from the official image, not `gradlew` or `gradle-wrapper.jar`.
At startup, KestreLynx verifies the Gradle and executing JDK versions and disables automatic JDK downloads.

Target `group:artifact` names are separated by commas in the following command.

```sh
gradle --no-daemon --no-build-cache -q -Porg.gradle.java.installations.auto-download=false dependencies --update-locks g1:a1,g2:a2
```

Environment variables and cache locations use the following values.

| Environment variable | Value |
| --- | --- |
| `JAVA_HOME` | `/opt/java/openjdk` |
| `GRADLE_USER_HOME` | `/tmp/kestrelynx-cache/gradle` |
| `HOME` | `/home/worker` |

The child process environment is built from a fixed list and does not inherit `GRADLE_OPTS`, `JAVA_OPTS`, or proxy settings.
`GRADLE_USER_HOME` and `HOME` use temporary storage so that init scripts and settings belonging to the image's user are not loaded.

The image's declared `VOLUME` at `/home/gradle/.gradle` is handled according to the execution environment.

| Execution environment | Volume configuration |
| --- | --- |
| Docker | Cover `/home/gradle/.gradle` with tmpfs |
| Kubernetes | Cover `/home/gradle/.gradle` with an empty, read-only memory volume limited to 1 MiB |

On Docker, KestreLynx verifies that no anonymous volume was created.
The Kubernetes configuration prevents a volume from being created on the node's disk.

On Kubernetes, an admission policy restricts the volume type, mount destination, and read-only setting.
Startup checks also verify that the mount is a read-only memory volume with a capacity limit.

Input files are passed using paths relative to the dependency directory.
The following files are returned.

- The updated `gradle.lockfile`
- The supplied build script, settings, properties, catalog, wrapper configuration, and auxiliary lockfiles
- `gradle-dependencies.txt`, containing dependency trees for each configuration

`gradle-dependencies.txt` contains up to the first 8 MiB of standard output from `dependencies --update-locks`, with control characters removed.
The `.gradle/` and `build/` directories created by Gradle are excluded from the result.

See [Work container execution restrictions](remediation-worker-logic.md#worker-restrictions) for common restrictions and [Dependency package downloads](outbound-communication.md#dependency-downloads) for network destinations.

## Gradle update validation {#gradle-update-validation}

Gradle update validation uses files returned by the work container or Pod and scan results to decide whether the update can be accepted.
KestreLynx supplies the files it edited and checks the returned results against the following conditions.

| Check | Acceptance condition |
| --- | --- |
| Returned files | All supplied files and `gradle-dependencies.txt` are present |
| Changes made by the work container or Pod | Of the input files, only `gradle.lockfile` has changed |
| Build definitions and auxiliary lockfiles | The edited files, `settings-gradle.lockfile`, and `buildscript-gradle.lockfile` match the supplied contents |
| Configurations recorded in the lockfile | The same configurations are recorded before and after the update |
| Configurations listed in `empty=` | The same configurations are listed before and after the update |
| Entry removal | Every package present in each configuration before the update remains present |
| Target version | The target reaches the selected Maven Central release or above in every configuration where it was present |
| Added or changed coordinates | Maven Central has a `.pom` for the requested coordinates and version |
| Added or changed versions | They do not contain `SNAPSHOT`, ignoring case |
| New comments | They use a format generated by Gradle |
| The same package within one configuration | Multiple versions are not recorded |

The following changes require manual handling.

| Change | Reason code |
| --- | --- |
| A lockfile entry was removed | `gradle_lock_entry_removed` |
| Configurations recorded in the lockfile or in `empty=` changed | `gradle_lock_configurations_changed` |
| An added or changed version contains `SNAPSHOT` | `gradle_lock_version_unsupported` |

Removing an entry requires manual handling even if the dependency is no longer needed by the new version.

Scanning examines only `gradle.lockfile` before and after the update, using the same Trivy, vulnerability database, and severity settings.
KestreLynx verifies that every parsed entry's name and version appear in the respective Trivy `gradle` package list.

Missing packages prevent comparison, producing “Not comparable” with `source_scan_incomplete`, and the update is not accepted.
KestreLynx verifies that target findings are confirmed before the update, disappear from every occurrence afterward, and that no new findings appear, including in non-target packages.

If the target remains below the published release selected from Maven Central in any configuration after the update, it receives `target_not_updated`.

Dependency parents in that configuration are recorded for guidance.
From that configuration's dependency tree, KestreLynx records up to five parent packages depending on that target version in `packages[].fix_hint.held_by`.

The configuration name is recorded in `fix_hint.configuration`.
If there is no dependency parent and the configuration declares the target directly, `fix_hint.direct` is set to `true`.

Dependency tree reading is limited to 8 MiB, 100,000 lines, and 1,024 bytes per line, and stops reading a tree at an unreadable line.
The tree is used only for [Guidance when a fixed version cannot be reached](remediation-fix-hints.md#fix-hints), not for PR or update decisions.

Lockfile reading has the following restrictions.

- Read comments, `group:artifact:version=configurations`, and at most one `empty=` line
- Reject lone CR characters and lines longer than 8,192 bytes
- Count line length without LF but including the CR in CRLF

See [Gradle PRs and CI checks](remediation-pr-results.md#gradle-pull-requests) for PR body contents and checks before merging.

### Conditions for excluding targets and updating the rest {#gradle-update-exclusions}

For Gradle, checks on individual targets before editing determine whether the remaining targets can be updated.
While examining published releases and version declarations, KestreLynx excludes only the following targets and continues updating the rest.

- Targets with no usable published release
- Targets whose version declarations cannot be changed
- Targets that cannot reach the selected published release after examining up to 20 newer stable BOM releases within its current major and minor version

After exclusions for individual targets are complete, KestreLynx checks shared values, rereads the edits, validates work container or Pod output, and checks the scans.
If any of these checks fails, the entire update result, including the remaining targets, is rejected.

If a target fails to reach the selected published release after the lockfile update, KestreLynx does not create a partial PR by excluding it and rerunning the update.

The resolution through dependency parents used for npm, pnpm, and uv is not applied.
See [Conditions for partial PRs](remediation-package-logic.md#partial-pr-selection) for the conditions for each package manager.
