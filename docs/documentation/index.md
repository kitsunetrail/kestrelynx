# Documentation

This section covers installing, configuring, and operating KestreLynx.

## Page guide {#contents}

This guide lists pages on KestreLynx comparisons, setup, configuration, how it works, remediation plans, and runtime usage.

| What you want to know | Page |
| --- | --- |
| Differences between update PRs and image patching, and vulnerability checks before and after updates | [Comparison with other tools](comparison.md) |
| Installation with Docker Compose, `docker run`, or Kubernetes | [Setup](getting-started.md) |
| Settings for schedules, notification destinations, Kubernetes, environment names, state management, and vulnerability prioritization | [Configuration](configuration.md) |
| Feature overview, decision logic, reading Slack notifications, webhook field specifications, and outbound communication | [How it works](how-it-works.md) |
| Setup, reading results, decision logic, and supported files and version specifications for remediation plans and pull requests | [Remediation plans and pull requests (experimental)](remediation.md#contents) |
| Marking packages in use with the optional Docker Sensor without changing priority | [Runtime usage (experimental)](runtime-usage.md) |

## Terms {#terms}

The following tables define terms used in the documentation.

### Terms used throughout the documentation {#common-terms}

The following terms are shared across multiple chapters.

| Term | Meaning |
| --- | --- |
| Finding | A vulnerability detected by scanning, including EOL (end-of-life) vulnerabilities that the distributor treats as outside the target release’s support scope |
| Running image | An image used by a running container |
| Base image | An image specified by `FROM` in a Dockerfile |
| Fixed version | A version reported by vulnerability information to fix the vulnerability |
| Series | A group of versions (image tags sharing the same major, minor, prefix, and suffix, or language runtime release lines such as Node.js 22 or Python 3.13) |
| Cycle | One regularly scheduled run from scanning through notification |

### Terms used for remediation plans and pull requests {#remediation-terms}

The following terms help you read the configuration, processing, and results of remediation plans and pull requests.

| Term | Meaning |
| --- | --- |
| Published image | A ready-made image pulled from a registry and run as provided |
| Pinned tag | A tag specifying a complete version, such as `1.27.0` |
| Floating tag | A tag whose content can change, such as `latest` or `22-alpine` |
| Commit tag | A tag named after a commit hash, such as `sha-5cf2d7b` |
| Mapping | An entry in `remediation.mappings` that links running containers to files in a GitHub repository |
| Workload key | The value in a mapping’s `workload` that identifies a Compose service, Docker container, or Kubernetes container |
| Running version | The version detected in the running image |
| Update target | The minimum version used when selecting an update |
| Adopted version | The version confirmed in the dependency files after an update |
| Manual handling | An update left to your judgment without automatic changes by KestreLynx (value: `manual`; Slack: “Needs a decision”) |
| Deferred | Processing postponed to a later cycle because of limits, waiting periods, or similar conditions (value: `deferred`; Slack: “Deferred”) |
| Work container (work Pod) | A disposable container created by KestreLynx to run a package manager (a work Pod on Kubernetes) |
| Runtime table | Execution versions, official images pinned by digest, and end-of-support dates for each Node.js, Python, Go, and Gradle series used for language package updates |

KestreLynx is under active development.
Unless otherwise noted, this documentation describes the latest container image and the current `main` branch.

For bugs, feature requests, and documentation corrections, open an issue in the [GitHub repository](https://github.com/kitsunetrail/kestrelynx/issues).
