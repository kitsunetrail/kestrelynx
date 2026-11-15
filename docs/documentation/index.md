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

KestreLynx is under active development.
Unless otherwise noted, this documentation describes the latest container image and the current `main` branch.

For bugs, feature requests, and documentation corrections, open an issue in the [GitHub repository](https://github.com/kitsunetrail/kestrelynx/issues).
