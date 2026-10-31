# Comparison with other tools {#comparison}

- This page compares updates for fixing vulnerabilities: what each tool can fix, how it updates, and what it checks before and after
- Based on each tool's official documentation as of October 31, 2026

## Tools compared {#tools}

- This comparison covers open source tools that can change files or images to fix vulnerabilities in container images or their dependencies
- Commercial services are introduced only and excluded from the comparison because the author cannot verify their features firsthand

| Tool | What it does | License |
| --- | --- | --- |
| [KestreLynx](remediation.md) | Proposes updates through remediation plans and update pull requests for vulnerabilities detected in running container images | [AGPL-3.0](https://github.com/kitsunetrail/kestrelynx/blob/main/LICENSE) |
| [Dependabot](https://github.com/dependabot/dependabot-core) | A GitHub feature that creates pull requests to update dependencies recorded in repository files | MIT for [dependabot-core](https://github.com/dependabot/dependabot-core) |
| [Renovate](https://github.com/renovatebot/renovate) | Creates pull requests to update dependencies recorded in repository files | [AGPL-3.0](https://github.com/renovatebot/renovate) |
| [Copacetic](https://github.com/project-copacetic/copacetic) | Patches packages inside a container image and produces a patched image | [Apache-2.0](https://github.com/project-copacetic/copacetic) |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Detects known vulnerabilities using OSV data and updates dependency files with its fix command (`osv-scanner fix`) | [Apache-2.0](https://github.com/google/osv-scanner/blob/main/LICENSE) |

- Commercial options excluded from the comparison tables
    - [Snyk Container](https://snyk.io/product/container-vulnerability-management/) scans container images for vulnerabilities and recommends updates to base images
    - [Docker Scout](https://docs.docker.com/scout/) analyzes image components and matches them against vulnerability data
    - [Socket](https://socket.dev/) analyzes open source dependencies and their updates for malicious behavior and other risks in the software supply chain

## Fix targets {#fix-targets}

| Tool | Distributed image tags | Dockerfile base images (`FROM`) | Direct patches to OS packages inside images | Language packages |
| --- | --- | --- | --- | --- |
| [KestreLynx](remediation-reference.md#supported-targets) | Same major/minor only: Compose, Kubernetes, Kustomize, Helm values | Same major/minor only | No: updates images or base images | npm, pnpm, pip, uv, Go only |
| [Dependabot](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories) | Yes: Compose, Kubernetes, Helm | Yes | No | npm, pnpm, pip, uv, Go, and others; see the [supported list](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories) |
| [Renovate](https://docs.renovatebot.com/modules/manager/) | Yes: Compose, Kubernetes, Kustomize, Helm values | Yes | No | npm, pnpm, pip, uv, Go, and others; see the [supported list](https://docs.renovatebot.com/modules/manager/) |
| [Copacetic](https://project-copacetic.github.io/copacetic/website/faq) | No | No | Yes: DPKG, RPM, APK | npm, pip, Go, .NET (experimental) |
| [OSV-Scanner](https://google.github.io/osv-scanner/experimental/guided-remediation/) | No | No | No | npm and Maven only (experimental): npm `package-lock.json` / `package.json`, Maven `pom.xml` |

- Dependabot and Renovate update packages recorded in repository files without checking their presence in running images
- KestreLynx updates GitHub dependency files for packages with vulnerabilities detected in running images
- KestreLynx handles floating tags such as `latest` for distributed images through [re-pull guidance (no update pull requests)](remediation-logic.md#published-image-tags)

## Update methods {#update-methods}

The last column covers checking the image running after an update.
The table describes each tool's own checks; separate scanners and automation can add checks.

| Tool | Trigger | Changes | Vulnerability checks before creating an update pull request | Output | Vulnerability checks after updates |
| --- | --- | --- | --- | --- | --- |
| [KestreLynx](remediation.md) | Vulnerabilities detected in images used by running containers | Image references and language dependency files in repositories | Compares scans before and after the proposed update | Remediation plans, update pull requests, notifications | Checks through subsequent periodic scans |
| [Dependabot](https://github.com/dependabot/dependabot-core) | New versions or GitHub vulnerability alerts | Image references and language dependency files in repositories | Does not compare image scans | Update pull requests | Does not check deployed images |
| [Renovate](https://github.com/renovatebot/renovate) | New versions or package vulnerability information | Image references and language dependency files in repositories | Does not compare image scans | Update pull requests | Does not check deployed images |
| [Copacetic](https://github.com/project-copacetic/copacetic) | An image and scanner report, or available package updates | Packages inside an image | Not applicable (does not create update pull requests) | A patched image | Does not check deployed images |
| [OSV-Scanner](https://google.github.io/osv-scanner/experimental/guided-remediation/) | Known vulnerabilities (OSV database) | npm `package-lock.json` / `package.json`, Maven `pom.xml` | Not applicable (does not create update pull requests) | Updated dependency files; a report of fixed vulnerabilities and the remaining count | Does not check deployed images |

- For image updates, KestreLynx [compares scans of the current and proposed images](remediation-logic.md#verification-scope)
- For language package updates, KestreLynx compares scans of dependency files before and after the proposed change
- Dependabot and Renovate can use published vulnerability information for supported package updates, but do not compare scans of the current and proposed images

## Example: each tool's workflow for fixing nginx vulnerabilities {#example}

A container running `nginx:1.27.0`, specified in `compose.yml`, has vulnerabilities with fixes available.

The examples assume the required features are enabled.
KestreLynx creates update pull requests only when enabled in settings; this is disabled by default.

- KestreLynx
    - Before creating [demo update pull request #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1), KestreLynx performed these checks
        - Scanned the running `nginx:1.27.0` image and the proposed `nginx:1.27.5` image for HIGH and CRITICAL vulnerabilities
        - Compared the results and found that 17 vulnerabilities targeted by the update were no longer detected, while 86 remained
        - Confirmed that the proposed image introduced no new vulnerabilities within the checked severity range
    - Created an update pull request containing the comparison results and changing `services.proxy.image` in `compose.yml` to `nginx:1.27.5`
    - The user then merged the update pull request and replaced the running `proxy` container with nginx 1.27.5
    - The next KestreLynx scan reported vulnerability resolutions for four packages
    - The KestreLynx author published those results in the [demo results](../index.md)
- Dependabot
    - When configured to [update image versions in Compose files](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories), Dependabot checks for newer nginx versions and creates an update pull request changing `image:` in `compose.yml`
- Renovate
    - Renovate checks `image:` in `compose.yml` for [newer nginx versions](https://docs.renovatebot.com/docker/) allowed by its settings and creates an update pull request
- Copacetic
    - Given the nginx image and a scanner report identifying vulnerabilities in its OS packages, Copacetic [patches those packages and produces an image](https://project-copacetic.github.io/copacetic/website/quick-start)
    - You scan and test the resulting image, change `image:` in `compose.yml` to use it, and replace the running container
- OSV-Scanner
    - [`osv-scanner fix`](https://google.github.io/osv-scanner/experimental/guided-remediation/) does not change the nginx image tag in `compose.yml`
    - If the repository contains npm or Maven dependency files, `osv-scanner fix` updates those files to fix dependency vulnerabilities

## KestreLynx scope and limits {#scope-and-limits}

- Monitoring covers only Docker or Kubernetes containers running when they are discovered, as described in the [scan scope](scan-logic.md#scan-targets)
- This monitoring does not replace scans in CI
- Remediation plans and update pull requests are experimental and disabled by default, with enablement described in [setup](remediation-setup.md)
- Editing files requires a mapping between a running container and files in a GitHub repository, with supported formats and conditions described in the [reference](remediation-reference.md)
- Language package sources are limited to public npm, public PyPI, and the public Go module proxy with `sum.golang.org`
- Comparisons before an update do not check the complete rebuilt application image or application behavior, as explained in the [verification scope](remediation-logic.md#verification-scope)

## Notes on other tools {#tool-notes}

- Dependabot
    - [Version updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-version-updates) periodically check repository files for newer versions and create update pull requests
    - [Security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates) respond to Dependabot alerts, GitHub warnings about known vulnerabilities in repository packages
    - Docker images in Dockerfiles and Compose files support version updates but [not security updates](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories)
- Renovate
    - [`vulnerabilityAlerts`](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts) uses GitHub's Dependabot alerts
    - [`osvVulnerabilityAlerts`](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts) is an experimental feature using OSV vulnerability data and excludes Docker images
    - Supported formats and configuration are described in the [official documentation](https://docs.renovatebot.com/modules/manager/)
- Copacetic
    - OS package patching supports [DPKG, RPM, and APK](https://project-copacetic.github.io/copacetic/website/faq)
    - [Application dependency patching](https://project-copacetic.github.io/copacetic/website/app-level-patching) is experimental and supports npm, pip, Go, and .NET
    - Updating Go dependency files alone does not fix vulnerabilities in existing compiled binaries
    - [Experimental Go binary rebuilding](https://project-copacetic.github.io/copacetic/website/app-level-patching#experimental-go-binary-rebuilding) requires accessible public source code
    - pnpm and uv are not supported
- OSV-Scanner
    - [Guided remediation (`osv-scanner fix`)](https://google.github.io/osv-scanner/experimental/guided-remediation/) is experimental
    - For npm, [`in-place`](https://google.github.io/osv-scanner/experimental/guided-remediation/#in-place-lockfile-changes) updates the lockfile within existing version constraints
    - For npm, [`relock`](https://google.github.io/osv-scanner/experimental/guided-remediation/#relock-and-relax-direct-dependencies) recomputes the entire dependency graph from `package.json`
    - Maven's [`override`](https://google.github.io/osv-scanner/experimental/guided-remediation/#override-dependency-versions) updates direct dependency versions or overrides dependency versions through `<dependencyManagement>` in `pom.xml`
    - [`node_modules` is not reinstalled, so users run `npm ci` separately](https://google.github.io/osv-scanner/experimental/guided-remediation/#basic-usage)

## Official references {#references}

Checked on 2026-10-31

- KestreLynx
    - [Overview](remediation.md), [Setup](remediation-setup.md), [Update checks and update pull request handling](remediation-logic.md)
    - [Reading results](remediation-results.md), [Supported inputs](remediation-reference.md), [Scan scope](scan-logic.md), [History and resolution](diff-logic.md)
    - [Demo update pull request #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1), [Demo results after container replacement](../index.md)
    - [Supported targets](remediation-reference.md#supported-targets), [Scope and requirements](remediation-reference.md#scope-and-requirements), [Supported file formats](remediation-reference.md#supported-inputs)
    - [docker run containers](remediation-reference.md#docker-run-containers), [Node.js version files](remediation-reference.md#node-declarations), [Base image attribution](remediation-logic.md#base-layer-matching), [Kubernetes work Pods](remediation-setup.md#kubernetes-language-updates)
- Trivy
    - [Container image scanning](https://trivy.dev/docs/latest/guide/target/container_image/)
- Dependabot
    - [Repository and license](https://github.com/dependabot/dependabot-core), [Version updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-version-updates), [Security updates](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates)
    - [Supported ecosystems](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories), [Managing update pull requests](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/manage-dependabot-prs), [Pull request comment commands](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-pull-request-comment-commands)
    - [Docker and Kubernetes](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories#docker), [Docker Compose](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories#docker-compose), [Helm charts and images](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories#helm-charts)
- Renovate
    - [Repository and license](https://github.com/renovatebot/renovate), [Docker updates](https://docs.renovatebot.com/docker/)
    - [GitHub vulnerability alerts](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts), [OSV vulnerability alerts](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts), [Matching and recreating update pull requests](https://docs.renovatebot.com/key-concepts/pull-requests/)
    - [Full manager list](https://docs.renovatebot.com/modules/manager/), [Docker Compose](https://docs.renovatebot.com/modules/manager/docker-compose/), [Dockerfile](https://docs.renovatebot.com/modules/manager/dockerfile/)
    - [Kubernetes](https://docs.renovatebot.com/modules/manager/kubernetes/), [Kustomize](https://docs.renovatebot.com/modules/manager/kustomize/), [Helm values](https://docs.renovatebot.com/modules/manager/helm-values/)
    - [npm and pnpm](https://docs.renovatebot.com/modules/manager/npm/), [pip](https://docs.renovatebot.com/modules/manager/pip_requirements/), [uv and PEP 621](https://docs.renovatebot.com/modules/manager/pep621/), [Go modules](https://docs.renovatebot.com/modules/manager/gomod/)
- Copacetic
    - [Repository and license](https://github.com/project-copacetic/copacetic), [Patching and verification](https://project-copacetic.github.io/copacetic/website/quick-start), [Application dependency patching](https://project-copacetic.github.io/copacetic/website/app-level-patching)
    - [Supported OS package systems](https://project-copacetic.github.io/copacetic/website/faq), [Go binary rebuilding](https://project-copacetic.github.io/copacetic/website/app-level-patching#experimental-go-binary-rebuilding), [.NET patching](https://project-copacetic.github.io/copacetic/website/app-level-patching#net)
- OSV-Scanner
    - [Repository](https://github.com/google/osv-scanner), [License](https://github.com/google/osv-scanner/blob/main/LICENSE), [Guided remediation](https://google.github.io/osv-scanner/experimental/guided-remediation/)
- Commercial services
    - [Snyk Container](https://snyk.io/product/container-vulnerability-management/), [Docker Scout](https://docs.docker.com/scout/), [Socket](https://socket.dev/)
