---
title: Supported dependency files and version declarations
---

# Supported dependency files and version declarations

Use this page to check whether your dependency files and version declarations can be updated automatically.
See [Language package selection](remediation-package-logic.md#package-selection) for choosing update versions and [Runtime selection](remediation-package-logic.md#runtime-and-tool-versions) for choosing execution versions.

Find the section for the files your project uses.

| Package manager or purpose | Main files or declarations | Section |
| --- | --- | --- |
| npm | `package.json` and `package-lock.json` | [npm dependency files](#npm-inputs) |
| pnpm | `package.json` and `pnpm-lock.yaml` | [pnpm dependency files](#pnpm-inputs) |
| pip | `requirements.txt` | [pip dependency files](#pip-inputs) |
| uv | `pyproject.toml` and `uv.lock` | [uv dependency files](#uv-inputs) |
| Go | `go.mod` and `go.sum` | [Go dependency files](#go-inputs) |
| Maven | `pom.xml` | [Maven dependency files](#maven-inputs) |
| Gradle | `gradle.lockfile` and build scripts | [Gradle dependency files](#gradle-inputs) |
| Gradle build settings | `build.gradle`, `build.gradle.kts`, settings, and catalogs | [Build script syntax](#gradle-build-forms) |
| Gradle plugins | Plugin declarations in build and settings scripts | [Plugin allowlist](#gradle-plugins) |
| Node.js | `.nvmrc`, `.node-version`, and `package.json` | [Node.js version declarations](#node-declarations) |
| Python | `.python-version` and `requires-python` | [Python version declarations](#python-declarations) |
| Package manager versions | `packageManager` and `tool.uv.required-version` | [Tool version declarations](#tool-declarations) |

Unsupported means a declaration or setting that automatic updates cannot handle.

“All dependency files” in a table means that dependency files in the directory specified by the mapping are not updated automatically.
Mappings that specify the same repository, base branch, and dependency directory are assessed together.

For Maven, the scope also includes child modules reached through `modules` from the root `pom.xml`.
Different dependency directories in the same repository are assessed separately.

“Affected package” means that the package is excluded from automatic updates.

See [Conditions for partial PRs](remediation-package-logic.md#partial-pr-selection) for when a PR can update other packages.
Reason codes are explained in [Source reasons](remediation-image-reason-codes.md#source-reasons) and [Runtime reasons](remediation-update-reason-codes.md#runtime-reasons).

See [Terms](remediation.md#terms) for terminology used on this page.

## npm dependency files {#npm-inputs}

KestreLynx reads `package.json` and `package-lock.json`, then updates dependency package versions recorded in the lockfile and any dependency declarations that need changing.
The required files and supported contents are listed below.

| Item | Supported scope |
| --- | --- |
| Required files | `package.json` and `package-lock.json` for a single project |
| Lockfile | `lockfileVersion` 2 or 3, with a root entry in `packages` |
| Source | Distributions from the public npm registry |
| Re-resolution through dependents | Updating packages that require the target package and resolving dependencies again (see [Re-resolution eligibility](remediation-reresolution-logic.md#dependent-reresolution-eligibility), including direct dependencies) |

The following declarations require manual handling.

| Condition | Scope not updated | Reason code |
| --- | --- | --- |
| The project uses workspaces | All dependency files | `workspace_unsupported` |
| A package is installed from Git, a URL, or under an alias | Affected package | `non_registry_source` |
| A local reference is used and all non-root `packages` entries are inside `node_modules/` | Affected package | `non_registry_source` |
| A local reference or another declaration creates a non-root `packages` entry outside `node_modules/` | All dependency files | `workspace_unsupported` |
| A package bundles dependencies in its distribution, is nested below such a package, or is bundled in a distribution | Affected package | `non_registry_source` |
| A package carries its own `npm-shrinkwrap.json` or is nested below such a package | Affected package | `non_registry_source` |
| `overrides` in `package.json` fixes the version | Affected package | `forced_by_override` |
| `.npmrc` specifies a private registry | All dependency files | `unsupported_source_settings` |

Bundled dependencies are declared with `bundleDependencies` or `bundledDependencies`, and KestreLynx also checks `inBundle` in the lockfile.
KestreLynx checks `hasShrinkwrap` in the lockfile to identify packages carrying their own `npm-shrinkwrap.json`.

## pnpm dependency files {#pnpm-inputs}

KestreLynx reads `package.json` and `pnpm-lock.yaml`, then updates dependency package versions recorded in the lockfile and any dependency declarations that need changing.
The required files and supported contents are listed below.

| Item | Supported scope |
| --- | --- |
| Required files | `package.json` and `pnpm-lock.yaml` |
| Lockfile | `lockfileVersion: '9.0'`, with `.` as the only entry in `importers` |
| Consistency with `package.json` | Direct dependency names and version specifiers matching the names and `specifier` values in the dependency entries of `importers['.']` |
| Source | Distributions from the public npm registry |
| pnpm 12 | `12.10.0` or later |
| Re-resolution through dependents | Updating packages that require the target package and resolving dependencies again (see [Re-resolution eligibility](remediation-reresolution-logic.md#dependent-reresolution-eligibility), including direct dependencies) |

The consistency check uses `dependencies`, `devDependencies`, and `optionalDependencies`.
Dependencies in `package.json`'s `peerDependencies` may also appear in the lockfile's importer.

The allowed keys in `package.json`'s `pnpm` field are `allowBuilds`, `onlyBuiltDependencies`, `ignoredBuiltDependencies`, `neverBuiltDependencies`, and `supportedArchitectures`.
Other keys, including `pnpm.configDependencies` and `pnpm.executionEnv`, are unsupported.

The following declarations or versions require manual handling.

| Condition | Scope not updated | Reason code |
| --- | --- | --- |
| The project uses workspaces | All dependency files | `workspace_unsupported` |
| The lockfile uses catalogs or patched dependencies | All dependency files | `unsupported_lockfile` |
| A package comes from outside the public npm registry | Affected package | `non_registry_source` |
| The lockfile records automatic runtime downloads | All dependency files | `tool_fetch_config_unsupported` |
| `package.json` contains `resolutions` | All dependency files | `tool_fetch_config_unsupported` |
| `pnpm` in `package.json` contains a key that is not allowed | All dependency files | `tool_fetch_config_unsupported` |
| The pnpm 12 version is earlier than `12.10.0` | All dependency files | `pnpm12_removal_unsupported` |

A `pnpm-workspace.yaml` in the same directory may contain only the following build permission and architecture settings.
The file's presence alone does not make the project a workspace.

| Key or location | Accepted content or handling |
| --- | --- |
| `allowBuilds` | A mapping from package selectors to booleans or strings |
| `onlyBuiltDependencies`, `ignoredBuiltDependencies`, and `neverBuiltDependencies` | Lists of package name strings |
| `supportedArchitectures` | Lists of strings for `os`, `cpu`, and `libc` |
| `packages` | A workspace declaration requiring manual handling for all dependency files |
| Keys outside the allowed list | Manual handling for all dependency files with `workspace_settings_unsupported` |
| `pnpm-workspace.yaml` above the dependency directory | Manual handling for all dependency files if found when checking up to the repository root |

Scripts remain disabled during updates even when accepted build permission settings are present.

## pip dependency files {#pip-inputs}

KestreLynx reads `requirements.txt` and updates exact dependency pins and existing hashes.
The supported declarations and update behavior are listed below.

| Item | Supported scope or update |
| --- | --- |
| Required file | UTF-8 `requirements.txt` |
| Exact pins | Version updates for `name==1.2.3` |
| Ranges or no version specifier | “Rebuild” (`rebuild_expected`) in the fix plan when the declaration allows the fixed version |
| Extras | Reading `name[extra]` |
| Comments and continuation lines | Reading |
| Existing `--hash` values | Updates from PyPI wheel information when an exact pin changes |

Dependencies declared with a range or without a version are not rewritten as exact pins, and no PR is created to update those dependencies.

The following declarations or distributions cannot be updated automatically.

| Condition | Scope not updated | Reason code |
| --- | --- | --- |
| An environment marker is present | Affected package, left for manual handling without evaluating the marker | `marker_not_evaluated`, `invalid_marker` |
| Another file is referenced with `-r`, `-c`, or a similar option | All dependency files | `unsupported_requirements` |
| An option changes the package source | All dependency files | `unsupported_requirements` |
| A named reference such as `name @ URL` specifies Git, a URL, or a local source | Affected package | `non_registry_source` |
| A line contains only a URL or path, or uses `-e` | All dependency files | `unsupported_requirements` |
| The update version has no wheel and only a source distribution | The entire pip update for the affected dependency directory is rejected | — |

See [Target environment for pip validation](remediation-node-python-logic.md#pip-target-environment) for validation conditions based on the running image.

## uv dependency files {#uv-inputs}

KestreLynx reads `pyproject.toml` and `uv.lock`, then updates dependency package versions recorded in the lockfile and any dependency declarations that need changing.
The required files and supported contents are listed below.

| Item | Supported scope |
| --- | --- |
| Required files | Static `pyproject.toml` and `uv.lock` for a single project |
| Lockfile | `version = 1` and `revision = 5` |
| Project | A `[project]` table without requests for dynamic metadata |
| Python requirements | `requires-python` in `[project]` |
| Source | Public PyPI |
| `[tool.uv]` in `pyproject.toml` | `required-version`, `dev-dependencies`, `sources`, and `package` |
| Re-resolution through dependents | Updating packages that require the target package and resolving dependencies again (see [Re-resolution eligibility](remediation-reresolution-logic.md#dependent-reresolution-eligibility), including direct dependencies) |

Accepted `[tool.uv]` keys still require supported dependency sources and project structure.
The following declarations or dependencies require manual handling.

| Condition | Scope not updated | Reason code |
| --- | --- | --- |
| The project uses workspaces | All dependency files | `workspace_unsupported` |
| A dependency uses Git, a URL, or a local reference | Affected package | `non_registry_source` |
| A dependency requires a source build | Affected package | `sdist_only` |
| `[tool.uv]` contains a key that is not allowed | All dependency files | `tool_fetch_config_unsupported` |
| `uv.toml` exists anywhere from the dependency directory up to the repository root | All dependency files | `tool_fetch_config_unsupported` |

## Go dependency files {#go-inputs}

KestreLynx reads `go.mod` and `go.sum` in the configured dependency directory and updates module requirements and checksums.

The input files and conditions for matching findings are listed below.

| Item | Supported scope |
| --- | --- |
| Required files | `go.mod` and `go.sum` |
| Findings | Findings from Go binaries in the running image that Trivy detects as `gobinary` |
| Binary matching | Binaries whose main module path matches `module` in `go.mod` |
| Source | Public `proxy.golang.org` and `sum.golang.org` |
| `go` directive | 1.21 or later |
| `toolchain` directive | `go1.N.M` naming a released Go version |

Findings from binaries with a different main module are omitted from the plan.
The same rule applies to tools included in a base image.

The following conditions prevent automatic updates.

| Condition | Scope not updated | Reason code |
| --- | --- | --- |
| A module version in the binary does not match `require` in `go.mod` | All dependency files | `go_binary_not_from_source` |
| The scan result's package list is truncated | All dependency files | `go_binary_not_from_source` |
| A module needed for the update, such as a private module, cannot be fetched from the public proxy | The entire Go update for the affected dependency directory is rejected | — |
| At least one `replace` directive is present | All dependency files | `go_replace_unsupported` |
| At least one `exclude` directive is present | All dependency files | `go_exclude_unsupported` |
| The `go` directive is missing or earlier than 1.21 | All dependency files | `go_version_too_old` |
| `toolchain` specifies `default`, a custom suffix, or an RC | All dependency files | `go_toolchain_unsupported` |
| `go.work` exists anywhere from the dependency directory up to the repository root | All dependency files | `workspace_unsupported` |
| `vendor` exists in the dependency directory | All dependency files | `workspace_unsupported` |
| Fixes exist only at the module path of another major version | Affected package | `fix_in_other_major_version` |

For fixes in another major version, [Overview of the hints](remediation-fix-hints.md#fix-hints) shows the lowest confirmed fixed version and whether the requirement is direct or comes from a dependent.
For the standard library's `stdlib`, KestreLynx creates no PR and instead shows guidance in the fix plan to raise the Go version used for the build.

See [Go candidate selection](remediation-go-logic.md#go-package-selection) for candidates and standard library handling, and [Go update validation](remediation-go-logic.md#go-update-validation) for acceptance conditions.

## Maven dependency files {#maven-inputs}

KestreLynx reads the root and module `pom.xml` files and rewrites the declarations that determine dependency versions.
Maven updates do not use work containers or Pods.

The required files and update eligibility conditions are listed below.

| Item | Supported scope |
| --- | --- |
| Required files | `pom.xml` in the configured dependency directory and each module's `pom.xml` reached through `modules` |
| Findings | Findings from Java archives in the running image that Trivy detects as `jar` |
| Dependencies updated | Dependencies with `compile` or `runtime` scope |
| Dependencies excluded | Dependencies with `test`, `provided`, or `system` scope |
| Source | Maven Central only |
| Module paths | Relative paths to directories below the configured dependency directory |
| Module count | At most 100 modules, including the root |
| Module depth | At most 8 levels of `modules` references, counting the root as level 0 |
| Root inheritance | Every module inheriting from the root `pom.xml` at update time |
| Version sources | Literals, properties, overrides of parent properties, properties for BOM versions, and pins in `dependencyManagement` |

The following module structures require manual handling for all dependency files.

| Condition | Reason code |
| --- | --- |
| A module path is absolute, contains `..`, names a hidden directory, or specifies a POM filename | `maven_reactor_unsupported` |
| A module has no `pom.xml` | `maven_reactor_unsupported` |
| Multiple modules declare the same `groupId:artifactId` | `maven_reactor_unsupported` |
| Parent references form a cycle | `maven_reactor_unsupported` |
| There are at least 101 modules, including the root | `maven_reactor_unsupported` |
| A module is at depth 9 or greater from the root | `maven_reactor_unsupported` |
| A module does not inherit from the root `pom.xml` | `maven_reactor_unsupported` |

For each POM, KestreLynx checks the parent location specified by `parent.relativePath` and `../pom.xml`.
Even if one location contains the correct parent POM, a manual-handling condition in the following table at the other location stops updates to all dependency files.

| Declaration or result at a location | Decision |
| --- | --- |
| A POM has the parent's `artifactId` | Matching `groupId` and `version`, and membership in the modules already read, are required |
| The `artifactId` matches but `groupId` or `version` differs | Manual handling for all dependency files with `maven_parent_mismatch` |
| The `artifactId` matches but the POM is outside the modules already read | Manual handling for all dependency files with `maven_parent_mismatch` |
| `relativePath` points outside the repository | Manual handling for all dependency files with `maven_parent_mismatch` |
| There is no POM, or its `artifactId` differs | Continue checking without confirming a matching parent at that location |

For example, even if the POM at `relativePath` is correct, a POM at `../pom.xml` with the parent's `artifactId` but a different `version` requires manual handling for all dependency files.

A direct dependency's `optional` may be omitted or set to `false`.
Check declaration restrictions by their location and the scope they affect.

| Declaration location or target | Condition requiring manual handling | Scope not updated | Reason code |
| --- | --- | --- | --- |
| `project/profiles/profile` | Changes dependencies, `dependencyManagement`, properties, parents, modules, or repositories | All dependency files | `maven_model_unsupported` |
| `project/repositories` or `project/pluginRepositories` | Declares download repositories | All dependency files | `unsupported_source_settings` |
| The root `.mvn` directory | Contains `maven.config` or `extensions.xml` | All dependency files | `unsupported_source_settings` |
| `project/dependencies/dependency` | Has `optional` set to `true` or an unreadable boolean value, a version range, or duplicate dependency declarations | All dependency files | `maven_model_unsupported` |
| `project/dependencyManagement/dependencies/dependency` | Uses `optional`, `exclusions`, version ranges, or duplicate managed dependencies | All dependency files | `maven_model_unsupported` |
| `project/distributionManagement` | Contains `relocation` | All dependency files | `maven_model_unsupported` |
| Installed version or targeted direct dependency | Uses a SNAPSHOT | Affected package | `maven_model_unsupported` |
| Targeted direct dependency's artifact type | Has a classifier or a type other than jar | Affected package | `maven_model_unsupported` |
| Installed versions of one package | Contains multiple versions | Affected package | `multiple_versions` |
| Version source | The location to change cannot be determined | Affected package | — |

See [Maven package selection](remediation-maven-logic.md#maven-package-selection) for candidates and editing methods, and [Maven update validation](remediation-maven-logic.md#maven-update-validation) for acceptance conditions.

## Gradle dependency files {#gradle-inputs}

KestreLynx reads `gradle.lockfile` and build settings, then updates the declarations that determine dependency versions and the lockfile.
Files read from the configured dependency directory are grouped by when they are required.

| File | Requirement |
| --- | --- |
| `gradle.lockfile` | Always required |
| `build.gradle` or `build.gradle.kts` | Exactly one required |
| `settings.gradle` or `settings.gradle.kts` | Exactly one required |
| `gradle/wrapper/gradle-wrapper.properties` | Always required |
| `gradle/libs.versions.toml` | Required when referenced as a catalog; otherwise read when present |
| `settings-gradle.lockfile` | Required when a catalog is present; otherwise read when present |
| `gradle.properties` | Read when present |
| `buildscript-gradle.lockfile` | Read when present |

Update targets and execution requirements are listed below.

| Item | Supported scope |
| --- | --- |
| Findings | Findings from Java archives in the running image that Trivy detects as `jar` |
| Dependencies updated | Dependencies in `gradle.lockfile`'s `compileClasspath`, `runtimeClasspath`, or `productionRuntimeClasspath` matching a finding's name and installed version |
| Dependency source | Maven Central only |
| Plugin sources | Gradle Plugin Portal and Maven Central |
| Gradle version | The same version as the wrapper's `distributionUrl` |
| `distributionUrl` | `https://services.gradle.org/distributions/gradle-<version>-bin.zip` or `-all.zip` |
| JDK | The version specified by `languageVersion` in `java.toolchain`, or 21 when absent |
| Execution environment | A Gradle version, JDK, and platform combination in [Supported runtimes](remediation-reference.md#supported-runtimes) |

Check the settings that enable locking separately from the records required in the lockfile.
Failure to meet these conditions requires manual handling for all dependency files with `gradle_locking_unenforced`.

| Location to check | Required content |
| --- | --- |
| Build script | Exactly one `dependencyLocking` block in the file |
| Inside `dependencyLocking` | Exactly one `lockAllConfigurations()` and one `lockMode = LockMode.STRICT` |
| `gradle.lockfile` | Both `compileClasspath` and `runtimeClasspath` present in dependency entries or `empty=` |

Only single projects are supported.
The following structures require manual handling.

| Condition | Scope not updated | Reason code |
| --- | --- | --- |
| `include`, `includeBuild`, `allprojects`, `subprojects`, `buildSrc`, or `gradle/dependency-locks` is present | All dependency files | `gradle_build_unsupported` |
| Both Groovy and Kotlin build scripts are in the directory | All dependency files | `ambiguous_dependency_files` |
| Both Groovy and Kotlin settings scripts are in the directory | All dependency files | `ambiguous_dependency_files` |
| The same package runs at multiple versions | Affected package | `multiple_versions` |

### Build script syntax {#gradle-build-forms}

KestreLynx reads dependency declarations and settings that can be executed during updates from `build.gradle` or `build.gradle.kts`.
Build scripts, settings scripts, `gradle.properties`, and `gradle/libs.versions.toml` accept only the syntax listed in this section.

Statements, arguments, or settings outside the listed scope require manual handling for all dependency files.
The accepted build script statements and arguments are listed below, where `<configuration>` denotes a configuration name.

| Statement | Accepted syntax |
| --- | --- |
| `plugins { }` | `java`, `java-library`, and `application` without versions, or literal external plugin IDs and versions from the [Plugin allowlist](#gradle-plugins) |
| `group`, `version`, and `description` | String literals |
| `java { }` | `toolchain { languageVersion = JavaLanguageVersion.of(N) }`, and assignments of strings, numbers, or `JavaVersion.VERSION_n` to `sourceCompatibility` and `targetCompatibility` |
| `repositories { }` | Only `mavenCentral()` |
| `configurations { }` | `compileOnly { extendsFrom(configurations.annotationProcessor.get()) }`, also `compileOnly { extendsFrom annotationProcessor }` in Groovy |
| `dependencies { }` | `<configuration>("g:a:v")`, `<configuration>("g:a")`, `<configuration>(libs.x)`, `<configuration>(libs.bundles.x)`, and the same syntax inside `constraints { }` |
| `dependencyLocking { }` | Only `lockAllConfigurations()` and `lockMode = LockMode.STRICT` |
| `extra` and `ext` | Literal names and values in Kotlin's `extra["p"] = "v"` or Groovy's `ext["p"] = "v"` and `ext.p = "v"` |
| `application { }` | `mainClass = "..."`, also `mainClass.set("...")` in Kotlin |

Test task blocks can be written as follows in Groovy and Kotlin.
The only operation accepted inside these blocks is `useJUnitPlatform()`.

| Language | Test task blocks |
| --- | --- |
| Groovy | `test { }`, `tasks.withType(Test) { }`, and `tasks.named("test") { }` |
| Kotlin | `test { }`, `tasks.withType<Test> { }`, `tasks.named<Test>("test") { }`, and `tasks.named("test") { }` |

Groovy also accepts the following syntax.

| Declaration | Accepted syntax |
| --- | --- |
| Dependencies | Omitted parentheses, as in `implementation 'g:a:v'` |
| `sourceCompatibility` and `targetCompatibility` | Literal declarations at the top level |

Dependency declarations and `constraints` accept the following configuration names.

| Purpose | Configuration names |
| --- | --- |
| Application dependencies | `implementation`, `api`, `compileOnly`, and `runtimeOnly` |
| Test dependencies | `testImplementation`, `testCompileOnly`, and `testRuntimeOnly` |
| Annotation processing | `annotationProcessor` and `testAnnotationProcessor` |
| Additional declaration with the Spring Boot plugin | `developmentOnly` |

To determine whether a package is a direct dependency, KestreLynx uses Gradle's standard configuration inheritance to relate its build script declaration to the configuration holding its installed version in `gradle.lockfile`.
A `developmentOnly` declaration can be read, but a package declared there requires manual handling because standard inheritance cannot establish that relationship.

For example, even if the installed version of a package declared in `developmentOnly` appears in `runtimeClasspath`, that package requires manual handling with `gradle_build_unsupported`.
See [Gradle package selection](remediation-gradle-logic.md#gradle-package-selection) for the decision rules.

The following settings can be read from `settings.gradle` or `settings.gradle.kts`.

| Declaration | Accepted syntax or handling |
| --- | --- |
| Project name | `rootProject.name = "..."` |
| Plugin repositories | `gradlePluginPortal()` and `mavenCentral()` inside `pluginManagement { repositories { } }` |
| Settings plugins | Checked against the [Plugin allowlist](#gradle-plugins), with no allowed plugin and version combinations |

The following keys and values can be read from `gradle.properties`.

| Key | Accepted values |
| --- | --- |
| `org.gradle.parallel`, `org.gradle.caching`, `org.gradle.daemon`, and `org.gradle.configuration-cache` | `true` or `false` |
| `org.gradle.jvmargs` | Space-separated memory settings using `-Xmx`, `-Xms`, or `-XX:MaxMetaspaceSize=`, and `-Dfile.encoding=UTF-8` |
| Keys ending in `.version` | Literal versions for properties defined by the Spring Boot BOM in use |

For `extra` and `ext` in build scripts, the update also reads the Spring Boot BOM and its parents to confirm that the property names are defined.
Other `gradle.properties` keys, Java agents, JVM arguments outside the allowed list, continuation lines, escapes, and duplicate keys require manual handling for all dependency files.

The version catalog is read from `gradle/libs.versions.toml`.
Accepted contents and editing restrictions are listed below.

| Item | Accepted syntax or handling |
| --- | --- |
| Sections | Only `[versions]`, `[libraries]`, `[bundles]`, and `[plugins]` |
| Libraries | `"g:a:v"`, or a table containing `module` or `group` and `name` |
| Library versions | String literals, `version.ref`, or omitted versions |
| Bundles | Lists of library aliases |
| Alias collisions | Manual handling for all dependency files when aliases produce the same accessor |
| `[versions]` values referenced by `[plugins]` | Excluded from editing |
| Applying a plugin with `alias(libs.plugins.x)` | Manual handling for all dependency files |

Common unsupported syntax is listed below.

| Target | Unsupported syntax |
| --- | --- |
| Statements and blocks | `apply from`, `buildscript { }`, `dependencyManagement { }`, `dependencyResolutionManagement { }`, `resolutionStrategy`, and `configurations.all` |
| Arguments | String interpolation or construction, dynamic versions, version ranges, and `platform(...)` in dependency declarations |

### Plugin allowlist {#gradle-plugins}

KestreLynx reads plugin declarations in build and settings scripts to determine which plugins and versions may run during updates.
The allowed combinations are listed below.

| Plugin | Allowed version | Gradle version |
| --- | --- | --- |
| `java`, `java-library`, and `application` | No version specified | Gradle in [Supported runtimes](remediation-reference.md#supported-runtimes) |
| `org.springframework.boot` | `4.1.2` | `9.8.2` |
| `io.spring.dependency-management` | `1.1.7` | `9.8.2` |
| `org.gradle.toolchains.foojay-resolver-convention` (settings) | No allowed version | No allowed combination |

External plugins are allowed only in plugin, plugin version, and Gradle version combinations whose behavior has been checked.
A version string that does not match exactly, or a combination outside the table, requires manual handling for all dependency files with `gradle_plugin_unsupported`.

Gradle updates use work containers or Pods, where the build script and allowed plugin code execute.
See [Gradle package selection](remediation-gradle-logic.md#gradle-package-selection) for candidates and editing methods, and [Gradle update validation](remediation-gradle-logic.md#gradle-update-validation) for acceptance conditions.

## Node.js version declarations {#node-declarations}

KestreLynx reads version files and declarations in `package.json` to choose Node.js for npm and pnpm updates.
Version files select only a major version series such as Node.js 22.

The actual minor and patch version comes from the list built into KestreLynx in [Supported runtimes](remediation-reference.md#supported-runtimes).
For example, `22.14.0` in a version file selects Node.js 22; it does not pin execution to `22.14.0`.

Accepted declarations and unsupported values are listed below.

| Declaration | Accepted syntax or handling |
| --- | --- |
| `.nvmrc` and `.node-version` | Numeric values such as `22`, `22.14`, or `22.14.0` on the first nonempty line, optionally prefixed with `v` |
| LTS declarations in `.nvmrc` | `lts/*` and the series names prefixed with `lts/` listed below |
| `engines.node` in `package.json` | Interpretable ranges including exact versions, comparison operators, `^`, `~`, and wildcards |
| `devEngines.runtime` and `engines.runtime` in `package.json` | An object or array specifying Node.js and its version range |
| Values such as `system` or `current` | Manual handling for all dependency files because the execution series cannot be determined |
| Ranges with prerelease boundaries | Unsupported, requiring manual handling for all dependency files |
| `onFail: download` in a runtime declaration | Unsupported, requiring manual handling for all dependency files |

The LTS series names read from `.nvmrc` and their major versions are listed below.
A recognized name is usable for updates only if its series is still supported in [Supported runtimes](remediation-reference.md#supported-runtimes).

| LTS series name | Major version |
| --- | --- |
| `lts/argon` | 4 |
| `lts/boron` | 6 |
| `lts/carbon` | 8 |
| `lts/dubnium` | 10 |
| `lts/erbium` | 12 |
| `lts/fermium` | 14 |
| `lts/gallium` | 16 |
| `lts/hydrogen` | 18 |
| `lts/iron` | 20 |
| `lts/jod` | 22 |
| `lts/krypton` | 24 |

See [Node.js selection](remediation-node-python-logic.md#node-selection) for how declarations are combined.

## Python version declarations {#python-declarations}

KestreLynx reads `pyproject.toml` and Python version files to choose Python for generating uv lockfiles.
`.python-version` selects only an X.Y series such as Python 3.13.

The actual patch version comes from [Supported runtimes](remediation-reference.md#supported-runtimes), so it may be newer or older than the patch version written in the file.
Accepted declarations and unsupported values are listed below.

| Declaration | Accepted syntax or handling |
| --- | --- |
| `[project].requires-python` in `pyproject.toml` | Interpretable Python version conditions such as `>=3.12,<3.15` |
| `.python-version` | Values such as `3.13` or `3.13.5` on the first nonempty line |
| CPython prefixes | Values such as `cpython-3.13` or `cpython@3.13` |
| `.python-versions` | Multiple-version declarations are unsupported, requiring manual handling for all dependency files |
| PyPy, GraalPy, Pyodide, and `system` | Unsupported, requiring manual handling for all dependency files |
| Free-threaded builds | Unsupported, requiring manual handling for all dependency files |

`.python-version` and `requires-python` must be consistent, and the Python version actually used must also satisfy `requires-python`.
See [Python selection for uv](remediation-node-python-logic.md#uv-python-selection) for the conditions, including selection without a version file.

## Tool version declarations {#tool-declarations}

KestreLynx reads declarations in `package.json` and `pyproject.toml` to choose the package manager version used for updates.
Accepted declarations are listed below.

| Declaration | Accepted syntax |
| --- | --- |
| `packageManager` in `package.json` | A manager name and exact version, such as `npm@11.21.0` or `pnpm@11.28.5` |
| Hash in `packageManager` | `name@version+<algorithm>.<hex>` |
| Hash algorithms | `sha1`, `sha224`, `sha256`, `sha384`, and `sha512` |
| `devEngines.packageManager` in `package.json` | A manager name and an exact version or interpretable range |
| `engines.npm` and `engines.pnpm` in `package.json` | An exact version or interpretable range |
| `tool.uv.required-version` in `pyproject.toml` | An exact version such as `==0.13.0`, or an interpretable range |
| Tool versions with prereleases or build metadata | Unsupported |

The default version is used when the project has no version declaration.
See [Tool version selection](remediation-node-python-logic.md#tool-version-selection) for declarations that specify only a range.

| Tool | Accepted versions | Default version |
| --- | --- | --- |
| npm | Major versions 9–12 compatible with the selected Node.js | `11.21.0` |
| pnpm | Major versions 9–12 compatible with the selected Node.js (12 requires `12.10.0` or later) | `11.28.5` |
| uv | Stable `X.Y.Z` releases at or above `0.12.22`, without prereleases, build metadata, or prefixes, and with no upper version bound | `0.13.0` |
| pip | The version in the official Python work image | `26.2.2` in the Python 3.13 work image |

Meeting the version number requirements also requires satisfying [Tool retrieval and verification](remediation-node-python-logic.md#tool-verification) and [Waiting after tool publication](remediation-node-python-logic.md#tool-release-age).
See [Tool version selection](remediation-node-python-logic.md#tool-version-selection) for how declared and default versions are chosen.
