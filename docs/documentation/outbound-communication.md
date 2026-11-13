# Outbound communication

This page explains KestreLynx's destinations, information sent outside your environment, credential destinations, and work container networking.

The programs that communicate, their roles, and their locations are listed below.

| Program making the connection | Role | Location |
| --- | --- | --- |
| KestreLynx | Manage scans, retrieve public data, create [remediation plans](remediation.md#overview), and send notifications | Main KestreLynx container |
| Trivy | Check images and dependency files for vulnerabilities | Same container as the main KestreLynx program |
| Work container | Update dependency files using package managers | Monitored Docker host or a Kubernetes work Pod |
| Container runtime (Docker Engine, or containerd on a Kubernetes node, for example) | Download the images that work containers need | Docker host or Kubernetes node |

The default URLs for public data sources and the GitHub and Slack APIs use HTTPS (TCP port 443).
Destinations and ports for mirrors, webhooks, registries, and email depend on configuration.

## Communication destinations {#outbound-communication}

KEV is CISA's catalog of vulnerabilities with confirmed exploitation.
EPSS estimates the probability that exploitation activity for a vulnerability will be observed in the next 30 days.

The table lists communication conditions based on enabled features and work needed in each cycle, along with information sent about your environment.

| Communication | When communication occurs | Information sent about your environment |
| --- | --- | --- |
| [KEV downloads](#kev-download) | [`triage.enabled`](configuration.md#triage) is enabled (default: enabled) | None |
| [EPSS downloads](#epss-download) | [`triage.enabled`](configuration.md#triage) is enabled (default: enabled) | None |
| [Node.js advisories](#node-runtime-download) | [`scan.node_runtime.enabled`](configuration.md#scan) is enabled (default: enabled) | None |
| [Python advisories](#python-runtime-download) | [`scan.python_runtime.enabled`](configuration.md#scan) is enabled (default: enabled) | None |
| [Hacker News searches](#hacker-news-search) | [`triage.enabled` and `triage.discussion_links`](configuration.md#triage) are enabled (each enabled by default) | CVE IDs being searched |
| [Trivy downloads](#trivy-downloads) | [Every time a scan runs](configuration.md#schedule) | Names, tags, and digests of requested images |
| [GitHub communication](#github-communication) | Reads require [remediation planning](configuration.md#remediation-basics); writes require both planning and PRs (each disabled by default) | Repository and source identifiers, PR contents |
| [Image candidate downloads](#candidate-registry-communication) | [Remediation planning](configuration.md#remediation-basics) is enabled (default: disabled) | Image names, tags, and digests |
| [Work image downloads](#worker-image-downloads) | Dependency updates run with [both remediation planning and PRs](configuration.md#remediation-basics) enabled (each disabled by default) | Work image names and digests |
| [Tool downloads](#tool-downloads) | Dependency updates run with [both remediation planning and PRs](configuration.md#remediation-basics) enabled (each disabled by default) | Tool names and versions |
| [Dependency downloads](#dependency-downloads) | Dependency updates run with [both remediation planning and PRs](configuration.md#remediation-basics) enabled (each disabled by default) | Package names and versions |
| [Notification delivery](#notification-delivery) | [Destinations are configured](configuration.md#notify-destinations) and delivery conditions are met (no default destinations) | Vulnerability findings, remediation plans, and PR information |

### KEV downloads {#kev-download}

Triage uses exploitation intelligence and severity to assign response priorities.

When triage is enabled and the feed needs downloading or refreshing, KestreLynx downloads the KEV feed in bulk.
The default source is `www.cisa.gov`.

Detected CVEs are matched locally, and the list of detected CVEs is not sent to the source.
See [Triage settings](configuration.md#triage) for the source, and [Threat intelligence updates](scan-logic.md#intel-cache) and [Unavailable threat intelligence](scan-logic.md#degraded-triage) for updates and failure handling.

### EPSS downloads {#epss-download}

When triage is enabled and the feed needs downloading or refreshing, KestreLynx downloads the EPSS feed in bulk.
The default source is `epss.empiricalsecurity.com`.

Detected CVEs are matched locally, and the list of detected CVEs is not sent to the source.
See [Triage settings](configuration.md#triage) for the source, and [Threat intelligence updates](scan-logic.md#intel-cache) and [Unavailable threat intelligence](scan-logic.md#degraded-triage) for updates and failure handling.

### Node.js advisory downloads {#node-runtime-download}

When Node.js runtime checks are enabled and data needs downloading or refreshing, KestreLynx retrieves the following public data.
A release line in the table means versions sharing a major version, such as `22.x`.

| Program making the connection | Destination | Information retrieved |
| --- | --- | --- |
| KestreLynx | `raw.githubusercontent.com` | Complete `nodejs/security-wg` Node.js runtime vulnerability index, including CVEs, severities, affected ranges, and fixed ranges |
| KestreLynx | `nodejs.org` | RSS listing of security blog posts |
| KestreLynx | `raw.githubusercontent.com` | Post bodies as Markdown from `nodejs/nodejs.org` |
| KestreLynx | `nodejs.org` | Complete `dist/index.json`, including release dates |
| KestreLynx | `raw.githubusercontent.com` | Complete `nodejs/Release` `schedule.json`, including end-of-support dates for each release line |

Index updates can lag releases by several weeks or longer, so security blog posts supplement the index under the conditions in [Node.js runtime findings](scan-logic.md#node-runtime).

Public data is matched locally, and image information and detected CVEs are not sent to the sources.
See [Scanning settings](configuration.md#scan) to enable or disable checks, [Threat intelligence updates](scan-logic.md#intel-cache) for refresh rules, and [Unavailable language runtime advisory data](scan-logic.md#node-runtime-unavailable) for failure handling.

### Python advisory downloads {#python-runtime-download}

When Python runtime checks are enabled, KestreLynx retrieves public data from the Python Software Foundation (PSF) and other sources listed below.

| Program making the connection | Destination | Information retrieved |
| --- | --- | --- |
| KestreLynx | `codeload.github.com` | Complete `tar.gz` archive of the PSF `advisory-database`, including its advisory list |
| KestreLynx | `raw.githubusercontent.com` | Official records for every CVE in the PSF list, from `CVEProject/cvelistV5` |
| KestreLynx | `www.python.org` | Complete release list from the API, including final versions in each release line |
| KestreLynx | `peps.python.org` | Complete release-cycle data, including each release line's end-of-support status |

Connections occur when data needs downloading or refreshing, or when CVE records need downloading or revalidation.
Official records provide PSF-authored CPython version ranges and target OS information, severity, and `REJECTED` status.

Public datasets are retrieved in full and matched locally, and image information and detected CVEs are not sent to the sources.
CVE IDs in record requests come from the PSF list, rather than being selected from image findings.

See [Scanning settings](configuration.md#scan) to enable or disable checks, [Threat intelligence updates](scan-logic.md#intel-cache) for refresh rules, and [Unavailable language runtime advisory data](scan-logic.md#node-runtime-unavailable) for failure handling.

### Hacker News searches {#hacker-news-search}

For Hacker News searches, KestreLynx sends detected CVE IDs as search queries to `hn.algolia.com` and retrieves discussion links.
Unlike bulk KEV and EPSS downloads, search queries contain part of the scan findings.

Only IDs of CVEs with the highest response priority are sent.
These are CVEs with confirmed exploitation listed in KEV or a high estimated probability of exploitation based on EPSS.

After a successful search for a CVE, it is not searched again for 24 hours.
Setting either `triage.discussion_links` or `triage.enabled` to `false` in [Triage settings](configuration.md#triage) disables searches.

### Trivy downloads {#trivy-downloads}

Trivy retrieves the following data for ordinary scans and scans that compare states before and after updates in remediation plans.
Comparison scans recheck updated images or dependency files.

| Information retrieved | Destination | When communication occurs |
| --- | --- | --- |
| Vulnerability databases and related data | Trivy's database download sources | Scan databases need preparing |
| Images for scanning or comparison | Registry determined by the image name and destinations serving layers and other image content | Required images must be downloaded from a registry |

Trivy's `db.repository` and `db.java-repository` settings determine the database sources.
The defaults are `mirror.gcr.io` and `ghcr.io`; see [Trivy database configuration](https://trivy.dev/docs/latest/guide/configuration/db/) to change them.

Image download requests include repository names, tags, and digests.
Registry responses determine where layers and other content are downloaded, and Trivy's registry mirror settings also apply when using mirrors.

See [Scan comparison conditions](remediation-logic.md#comparison-conditions) for comparisons and [Environment variables used by Trivy](#trivy-environment-credentials) for credentials.

### GitHub communication {#github-communication}

A remediation plan proposes updates to resolve vulnerabilities.
[Source mappings](configuration.md#remediation-mappings) associate running containers with GitHub repositories and files.

KestreLynx specifies repository names, branches, file paths, and similar identifiers in the following reads and writes to `api.github.com`.

| Operation | Information retrieved or sent | When communication occurs |
| --- | --- | --- |
| Read | Configured repositories, branches, and source files | Remediation planning checks sources |
| Read | Information used to match existing PRs and past operation results | PR processing is enabled |
| Write | Create commits, branches, and PRs, and replace older PRs | PR processing is enabled and write conditions are met |

Replacing an older PR creates a comment explaining the replacement and closes the older PR when the conditions are met.
PR contents may include the following information.

- Image names and digests, and workload names
- Repository names, source paths, and changes
- Package names and versions, vulnerability IDs, comparison results, and processing reasons

Re-resolution updates dependent packages that require an old version so that the target package can reach a fixed version.
To explain why those dependents need updates, re-resolution PRs also send their names, versions before and after the update, and the blocking version requirements.

If a package between the dependent and the package held at an old version requires an older version, its name is also included.

See [PR management](remediation-logic.md#pr-management) for management conditions and [Enabling PR creation](remediation-setup.md#enable-pr-creation) for workflows triggered by PRs.

### Image candidate downloads {#candidate-registry-communication}

Remediation planning looks for updates to ready-to-run images published in registries and base images used as the foundation of builds.
KestreLynx specifies image names, tags, and digests in requests and retrieves tag lists, manifests, configs, and other information used to verify digests.

The destination is the public registry or registry with configured authentication specified by the image name.
For Docker Hub, KestreLynx connects to `registry-1.docker.io`.

See [Image registry authentication](configuration.md#registries) for authentication and [Image candidate selection](remediation-logic.md#image-selection) for discovery.

### Work image downloads {#worker-image-downloads}

A work Pod uses a container for dependency updates and a container based on the KestreLynx image to receive input files.

When an image needed for a language-package update is unavailable locally, the container runtime downloads it from the sources below.
Requests include work image names and digests.

| Program making the connection | Destination | Image retrieved |
| --- | --- | --- |
| Docker or the Kubernetes node's container runtime | Docker Hub or the configured mirror | Official Node.js, Python, Go (`golang`), and Gradle (`gradle`) images |
| Kubernetes node's container runtime | Registry specified by the KestreLynx image name | Image for the container receiving input files in the work Pod |

See [Pinning official images](remediation-logic.md#worker-images) for pinning and handling unavailable images.

The official-image mirror is set through [`remediation.worker.registry`](configuration.md#remediation-worker), and container runtime mirror settings also affect actual destinations.
The input container image is set through [`remediation.worker.kubernetes.receiver_image`](configuration.md#remediation-worker-kubernetes), or taken from KestreLynx's own Pod when unset.

### Tool downloads {#tool-downloads}

KestreLynx specifies tool names or versions in requests and makes the following connections when it needs to check version information or download distributions.

| Program making the connection | Destination | Information retrieved |
| --- | --- | --- |
| KestreLynx | `registry.npmjs.org` | npm and pnpm version information and distributions |
| KestreLynx | `pypi.org` and `files.pythonhosted.org` | uv version information and distributions |

Tool download requests and redirects are restricted to HTTPS (TCP port 443) on the hosts in the table.
See [Tool downloads and verification](remediation-logic.md#tool-verification) for retrieval and verification, and [Tool cache reuse](remediation-logic.md#tool-cache) for reuse.

### Dependency downloads {#dependency-downloads}

Dependency download requests include package names and versions.
Names are module paths for Go, and the package identifiers `groupId` and `artifactId` for Maven and Gradle.

Dependency files are read locally, and their contents are not uploaded as part of download requests.

#### Downloads by KestreLynx {#dependency-kestrelynx}

KestreLynx retrieves the following information to check versions and dependencies needed for updates, and to verify update results.

| Target | Destination | Information retrieved | Purpose |
| --- | --- | --- | --- |
| npm and pnpm | `registry.npmjs.org` | Versions, dependencies, dependency version requirements, and publication timestamps | Check Node.js compatibility, update results, and re-resolution conditions |
| pip and uv | `pypi.org` | Package metadata, distribution metadata such as URLs and hashes, dependency version requirements, and upload timestamps | Check Python update results and uv re-resolution conditions |
| Go | `proxy.golang.org` | Version information, `go.mod`, latest versions, and version lists | Check target versions, retractions, required Go versions, and dependency requirements |
| Go | `sum.golang.org` | Hashes of module zip files and `go.mod` | Verify update results and complete `go.sum` |
| Maven | `repo.maven.apache.org` | Published version lists and parent, BOM, and dependency POMs | Check version sources, dependency requirements, and resolution results before and after updates |
| Gradle | `repo.maven.apache.org` | Published version lists and POMs | Check published versions, BOM properties, and identifiers of added or changed packages |

The following details explain retrieval conditions and how the information is used.

- npm, pnpm, and uv re-resolution check blocking version requirements and the [72-hour wait after publication](remediation-reference.md#dependent-reresolution-waits) for newly introduced versions
- Go also retrieves version information when finding alternatives to versions the publisher has retracted from use
- Go retrieves version information from `.info`, `go.mod` from `.mod`, the latest version from `@latest`, version lists from `@v/list`, and hashes from `lookup`
- Maven and Gradle read published versions from `maven-metadata.xml` and dependency and version requirements from `.pom` files
- When checking Maven or Gradle versions and POMs, KestreLynx includes `kestrelynx` in the `User-Agent` of requests to Maven Central

npm re-resolution may retrieve information about dependent packages in addition to the target package.
For example, if updating `minimist` requires updating `mkdirp`, KestreLynx also retrieves information about `mkdirp` and newly introduced versions.

A BOM manages versions for multiple dependency packages.
For Gradle, the retrieved POMs include the Spring Boot BOM, its parent POMs, other BOMs imported by the Spring Boot BOM, and dependency POMs.

When a package cannot reach a fixed version, KestreLynx performs additional checks to suggest updates.
It checks target package versions specified by published Maven parent or BOM releases, or Spring Boot BOM releases.

See [Update processing by package manager](remediation-logic.md#manager-update-methods) for update methods and [Re-resolution support and limits](remediation-reference.md#dependent-reresolution-limits) for transfer and other limits.

#### Downloads by work containers {#dependency-workers}

Work containers make the following connections to resolve dependencies, generate or update lockfiles, and perform checks.

| Target | Destination | Information retrieved | When communication occurs |
| --- | --- | --- | --- |
| npm, pnpm, pip, and uv | `registry.npmjs.org`, `pypi.org`, and `files.pythonhosted.org` | Metadata and distributions needed for dependency resolution, lockfile generation, and checks | Dependency updates run |
| Go | `proxy.golang.org` and `sum.golang.org` | Module metadata, distributions, and information needed to verify hashes | Go dependency updates run |
| Go | `storage.googleapis.com` | Module zip files | The Go proxy redirects a distribution download |
| Gradle | Maven Central (`repo.maven.apache.org`) | Metadata and distributions needed for dependency resolution and lockfile updates | Gradle dependency updates run |
| Gradle plugins | `plugins.gradle.org`, `plugins-artifacts.gradle.org`, and `repo.maven.apache.org` | Metadata and distributions for allowed plugins and their dependencies | Build scripts apply plugins |

Gradle connects to the [download destination for `mavenCentral()`](https://docs.gradle.org/current/dsl/org.gradle.api.artifacts.dsl.RepositoryHandler.html).
Gradle Plugin Portal distributions are retrieved through [redirects to `plugins-artifacts.gradle.org`](https://plugins.gradle.org/docs/mirroring).

Only plugin types and versions listed under KestreLynx's [Plugin allowlist](remediation-reference.md#gradle-plugins) can be used.

#### Downloads by Trivy {#dependency-trivy}

In KestreLynx's dependency file scans, Trivy makes network requests to retrieve dependency information only for Maven.
Maven requires additional `.pom` files to inspect parent POMs and packages used by dependencies.

Files such as `package-lock.json` and `gradle.lockfile` record package names and versions, so no network requests are needed to retrieve dependency information.

When Trivy checks Maven dependency files before and after updates, KestreLynx provides a relay to Maven Central inside the main KestreLynx container.
Trivy connects over HTTP to an available port on `127.0.0.1` and requests `.pom` files using `groupId`, `artifactId`, and version.

For Maven dependency resolution, Trivy connects only to the local relay, without connecting directly to Maven Central.
KestreLynx relays requests to `repo.maven.apache.org` and includes `kestrelynx` in the `User-Agent`.

Requests for `.pom` files of modules read from the project are not forwarded to Maven Central.

### Notification delivery {#notification-delivery}

When delivery conditions are met, KestreLynx sends vulnerability findings, remediation plans, decision reasons, PR links, and operation results.
Destinations depend on the notification method as follows.

| Notification method | Destination |
| --- | --- |
| Slack Incoming Webhook | URL configured in `notify.slack_webhook_url` |
| Slack Bot | API on `slack.com` |
| Generic webhook | URL configured in `notify.generic_webhook_url` |
| Email | SMTP server configured in `notify.email.host` and `notify.email.port` |

Email uses SMTP with required TLS (`starttls` or implicit `tls`).
Each send has a total limit of 30 seconds from connection through `QUIT`, and communication is cut off when the deadline is reached.

Notifications may contain the following information.
Re-resolution notifications include the re-resolution outcomes.

| Destination | Content type | Information included |
| --- | --- | --- |
| All notification methods | Environment and source | Image names and digests, workload names, repository names, and source paths |
| All notification methods | Vulnerabilities and update comparisons | Package names and versions, vulnerability IDs, and comparison results |
| All notification methods | Re-resolution outcomes | Dependents updated with the target, update adoption, skipped updates, waiting periods, and reasons |
| Generic webhook | Re-resolution details | Version requirements, change lists, processing usage, and the earliest retry timestamp |
| Generic webhook | Remaining vulnerabilities and reasons for rejecting updates | Package names, versions, dependents, vulnerability IDs, occurrence counts, and KEV listing information |

Configure notification destinations according to the information you can share.
See [Notification destinations](configuration.md#notify-destinations) for settings, [Notification conditions](notification-conditions.md#notification-conditions) for delivery rules, and [Webhook field reference](webhook-reference.md#generic-webhook) for JSON contents.

## Credential destinations {#credential-destinations}

This section explains credential destinations and the restrictions applied by each program.

### GitHub tokens {#github-token-destinations}

KestreLynx selects tokens from [GitHub access settings](configuration.md#remediation-github) using the following rules.
The owner is the `owner` part of the repository name `owner/name`.

- Use the token in `remediation.github.tokens` matching the target repository owner
- If no owner entry matches, use the default `remediation.github.token`
- If neither an owner token nor a default token is available, send no token

The following rules govern token destinations and redirects.
Redirects within `api.github.com` are handled differently for reads and writes.

- Send tokens only to `api.github.com` over HTTPS and reject redirects to other hosts
- For read requests redirected to another owner, select the token again for the destination owner
- For read requests, reject redirects to URLs without an owner when owner-specific tokens are configured and the redirected request carries a token
- For read requests with only the default token configured, follow redirects to URLs without an owner as well
- Never follow redirects for write requests, regardless of token configuration

### Image registry credentials {#registry-credential-destinations}

This section covers the usernames and passwords specified in `registries` under [Image registry authentication settings](configuration.md#registries).
It explains when KestreLynx itself and Trivy use them and how their destinations are restricted.

The programs that use the credentials and their purposes are listed below.

| Program using credentials | When they are used | How destinations are restricted |
| --- | --- | --- |
| KestreLynx | Reading update candidate tags and image information for remediation plans | Sends requests itself and restricts destinations |
| Trivy | Downloading images to scan | KestreLynx checks destinations before passing credentials to Trivy |

#### Credential destinations {#registry-credential-targets}

`host` specifies the registry host that uses the credentials.
A token service issues temporary tokens for accessing the registry.

A token service may be on a different host from the registry.
For example, Docker Hub uses `host: docker.io` with `token_hosts: [auth.docker.io]`.

Allowed token services are on the registry's host or hosts listed in `token_hosts`.
KestreLynx uses the same destination rules for its own requests and for checks before passing credentials to Trivy.

Credentials are sent over HTTPS.
Credentials may be used even for public images if a configured registry requires a login.

#### When KestreLynx reads registries {#registry-credential-kestrelynx}

KestreLynx handles credentials as follows when reading registries itself.

| Registry state | Credential handling |
| --- | --- |
| Not configured in `registries` | Not used (anonymous access) |
| Configured, and the registry does not require a login | Not used |
| Configured and requires a login at the registry itself | Sent to the registry |
| Configured and requires authentication at an allowed token service | Sent to the specified token service |
| Configured and requires authentication at a token service that is not allowed | Not sent |

Once the registry itself requests a login, KestreLynx includes credentials from the start in subsequent requests to that registry.

KestreLynx does not forward credentials to redirect destinations.

Allowed addresses depend on the host configuration.

| Destination host | Allowed addresses |
| --- | --- |
| Listed in `host` or `token_hosts` | Public, private, loopback, and shared carrier addresses (CGNAT, `100.64.0.0/10`) |
| Listed in neither `host` nor `token_hosts` | Public addresses only |

KestreLynx does not connect to link-local addresses.

#### When Trivy scans images {#registry-credential-trivy}

Trivy downloads images using configured credentials through the following steps.

1. Before scanning, KestreLynx sends requests without credentials to the registry to check where authentication is required
2. Only after confirming that every authentication destination is allowed, KestreLynx passes the credentials for that registry to Trivy
3. Trivy downloads the image and sends the necessary credentials itself

Credentials passed to Trivy are determined by the checks before scanning.

| Registry state | Credential handling |
| --- | --- |
| Not configured in `registries` | Not passed |
| Every checked authentication requirement specifies an allowed destination | Only the credentials for the target registry are passed |
| A response requires no login | Not passed |
| A response specifies a disallowed destination | Not passed |
| The authentication requirement cannot be checked | Not passed |

The preliminary checks and Trivy's image downloads are separate requests, and Trivy chooses where credentials are actually sent.
As a result, the following limitations apply.

- KestreLynx cannot detect changes in the registry's responses after the checks
- Trivy may include credentials in redirects within the same registry host, but does not forward them to other hosts
- The address restrictions for KestreLynx's own registry reads do not apply to Trivy's connections

Credentials may be sent to destinations that differ from those checked.
KestreLynx does not control where Trivy actually sends credentials.

The `TRIVY_USERNAME`, `TRIVY_PASSWORD`, and `GITHUB_TOKEN` variables read by Trivy are outside the credential destination restrictions for `registries` and are explained in [Environment variables used by Trivy](#trivy-environment-credentials).

### Environment variables used by Trivy {#trivy-environment-credentials}

Trivy may use the following environment variables set in the main KestreLynx container.

| Environment variables | When Trivy uses them and where they may be sent |
| --- | --- |
| `TRIVY_USERNAME` and `TRIVY_PASSWORD` | Registries and authentication endpoints contacted when downloading images or databases |
| `GITHUB_TOKEN` | Authentication endpoints used when downloading images or databases from `ghcr.io` |

[Destinations for `TRIVY_USERNAME` and `TRIVY_PASSWORD` are not limited to a specific registry](https://trivy.dev/docs/latest/guide/advanced/private-registries/#passing-credentials).
`GITHUB_TOKEN` is also used for authentication when downloading databases from `ghcr.io`; see [Trivy's explanation of database authentication errors](https://trivy.dev/docs/latest/references/troubleshooting/#denied).

When remediation planning is enabled, Trivy's vulnerability and Java databases are prepared before scanning.
Database preparation does not remove `TRIVY_*` variables from the environment.

After successful preparation, the ordinary scans of running images that follow and the subsequent comparison scans for the remediation plan use the same databases.
Environment variable handling for ordinary and comparison scans depends on the state before scanning.

| State before scanning | `TRIVY_*` in ordinary scans | `TRIVY_*` in comparison scans |
| --- | --- | --- |
| Database preparation succeeds | Removed | Removed |
| Database preparation fails | Retained | No comparison scans run |
| Remediation planning is disabled | Retained | No comparison scans run |

`GITHUB_TOKEN` remains in the environment under all these conditions.

### Work containers {#worker-credentials}

GitHub tokens and image registry credentials are not passed to work containers.

## Work container network {#worker-network}

Docker work containers use bridge networking.
Destinations are not restricted by a network allowlist.

For Kubernetes work Pods, the user applies a NetworkPolicy.
The example in `deploy/kubernetes/work/40-networkpolicy.yaml` denies ingress and limits egress to DNS (UDP and TCP port 53) and TCP port 443 to IPv4 addresses outside specified ranges.

The TCP port 443 rule excludes private addresses (`10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`), link-local addresses (`169.254.0.0/16`), and CGNAT (`100.64.0.0/10`).
The example permits public HTTPS sites generally, rather than only npm and PyPI.

A networking implementation (CNI) that enforces NetworkPolicy is required, and standard NetworkPolicy does not block communication between a Pod and its execution node.
Until the CNI finishes applying restrictions to a new Pod, egress may be unrestricted for a few seconds (observed with the default K3s CNI).

See [Kubernetes language-package updates](remediation-setup.md#kubernetes-language-updates) for installation adjustments and [Runtime restrictions](remediation-logic.md#worker-restrictions) for restrictions other than networking.
