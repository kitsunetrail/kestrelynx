---
template: home.html
hide:
  - navigation
  - toc
  - footer
---

<div class="kl-hero" markdown>
<div class="kl-hero__text" markdown>

Docker · Compose · Kubernetes · GitHub pull requests
{ .kl-eyebrow }

# Remediation plans, pull requests, and resolution checks after deployment

KestreLynx is open-source software that rescans update candidates under the same conditions for comparison and creates remediation pull requests on GitHub to update the Compose files, Kubernetes manifests, Kustomize configuration files, Helm values files, Dockerfiles, and dependency files you already use. After you merge and deploy the changes, the next scan carries history forward to check for resolved findings.
Scanning running images with [Trivy](https://trivy.dev/), prioritizing findings with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [EPSS](https://www.first.org/epss/), and notifying Slack, email, or webhooks provide the starting point for remediation and a way to check the results.

[Setup](documentation/getting-started.md){ .md-button .md-button--primary }
[GitHub](https://github.com/kitsunetrail/kestrelynx){ .md-button }
{ .kl-actions }

Open source · AGPL-3.0
{ .kl-license }

</div>
<figure class="kl-notification">
<div class="kl-slack">
<div class="kl-slack__channel"># security-alerts</div>
<div class="kl-slack__message">
<div class="kl-slack__avatar" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/></svg></div>
<div class="kl-slack__body">
<p class="kl-slack__meta"><strong>KestreLynx</strong> <span class="kl-slack__badge">APP</span> <span class="kl-slack__time">9:00 AM</span></p>
<p>🔧 <strong>Fix plan</strong><br><strong>Pull requests:</strong> 3 created</p>
<hr>
<p><strong>Image: nginx:1.27.0</strong><br><strong>File to change:</strong> compose.yml in kitsunetrail/kestrelynx-demo<br><strong>Pull request:</strong> <span class="kl-slack__link">#1</span> (opened now)<br><strong>Update:</strong> nginx 1.27.0 → 1.27.5</p>
<hr>
<p><strong>Image: kestrelynx-demo-api</strong><br><strong>File to change:</strong> api/requirements.txt in kitsunetrail/kestrelynx-demo<br><strong>Pull request:</strong> <span class="kl-slack__link">#2</span> (opened now)<br><strong>Update:</strong> Werkzeug 3.0.1 → 3.0.3, urllib3 2.2.2 → 2.8.0<br><strong>File to change:</strong> api/Dockerfile in kitsunetrail/kestrelynx-demo<br><strong>Update candidate:</strong> base image python 3.12.3-slim → 3.12.15-slim<br><strong>Needs a decision:</strong> the candidate brings new findings</p>
<hr>
<p><strong>Image: kestrelynx-demo-web</strong><br><strong>File to change:</strong> web/package-lock.json in kitsunetrail/kestrelynx-demo<br><strong>Pull request:</strong> <span class="kl-slack__link">#3</span> (opened now)<br><strong>Update:</strong> body-parser 1.20.1 → 1.20.8 (with express 4.18.2 → 4.22.3), path-to-regexp 0.1.7 → 0.1.13 (with express 4.18.2 → 4.22.3)</p>
<hr>
<p><em>Details in the generic webhook payload.</em></p>
</div>
</div>
</div>
<figcaption>The fix plan actually produced by the demo repository.</figcaption>
</figure>
</div>

<div class="kl-callouts" markdown>

- **Created PRs** “Pull request” #1, #2, and #3 and “File to change” identify where the changes go.
- **A base image update without a PR** The python 3.12.15-slim candidate brings new findings, so no PR is created; “Needs a decision” means you choose whether to update or wait for another tag.
- **Updates including dependent packages** Updating body-parser and path-to-regexp also updates express, which depends on them, from 4.18.2 to 4.22.3.

</div>

<div class="kl-section kl-features" markdown>
<div markdown>

:material-magnify-scan:

## Update candidate comparison

Rescans before and after an update use the same conditions to compare resolved, remaining, and newly introduced findings.

- Published images: compare the current and candidate images
- Dockerfiles: compare the current and candidate base images
- Language packages: compare dependency files before and after the update

</div>
<div markdown>

:material-source-pull:

## Pull requests to update image tags and dependency files

KestreLynx creates PRs that update the following parts of files already used in mapped GitHub repositories. There is no need to move version specifications to new configuration files or a different management method.

- Published image tags in Compose files
- Image tags in plain Kubernetes manifests
- Kustomize `images[].newTag`
- Image tags in Helm values
- Base image tags in Dockerfiles
- Dependency files for npm, pnpm, pip, uv, and Go

</div>
<div markdown>

:material-history:

## Resolution checks after merge and deployment

After you merge a PR and deploy the new image, the next scan carries history forward to check for resolved findings.

- Use history from before the update to identify findings no longer detected in the running image
- Check notifications for resolutions since the last scan and findings that remain open

</div>
</div>

<div class="kl-section" markdown>

## Remediation examples from the demo repository (experimental)

These screenshots show actual output from the [demo repository](https://github.com/kitsunetrail/kestrelynx-demo), which intentionally pins older images and dependencies, with the [generated PRs available on GitHub](https://github.com/kitsunetrail/kestrelynx-demo/pulls).

The Slack fix plan lists three created PRs and a Dockerfile base image update candidate marked “Needs a decision” because the candidate introduces new findings.

![Slack fix plan showing Compose, pip, and npm update PRs and a Dockerfile base image update candidate requiring a decision](assets/screenshots/slack-fix-plan.png)

[PR #1](https://github.com/kitsunetrail/kestrelynx-demo/pull/1) proposes updating nginx from 1.27.0 to 1.27.5 and records the candidate scan comparison: 17 targeted findings resolved, 86 remaining.

![GitHub PR body with What, Change, and Verification sections, including 94 other findings remaining and no introduced findings](assets/screenshots/pr-compose-body.png)

After PR #1 was merged and the running `proxy` container was replaced with nginx 1.27.5, the next scan reported resolutions for four packages with history carried over.

![Slack scan notification showing the nginx image update and resolutions for libabsl20220623, libavif15, libfreetype6, and liblzma5](assets/screenshots/slack-resolved.png)

A candidate or pull request does not mean the running image has been fixed.
Review the comparison scope and run your CI before merging; rebuilding and
deploying remain separate steps.

Supported language-package sources and source hosts are limited to the following.

- Language packages are retrieved only from the public npm registry, public PyPI, and the public Go module proxy
- Private language-package registries are not supported
- GitHub is the only supported source host

See [Remediation plans and pull requests (experimental)](documentation/remediation.md)
for setup, notifications, and permissions.

</div>

<div class="kl-section" markdown>

## Scanning and notifications

Regular scans and notifications provide the starting point for remediation and a way to check results after deployment.

<div class="kl-features" markdown>
<div markdown>

:material-history:

## Changes since the last scan

Diff notifications show which findings have changed since the previous scan.

- Notifications cover new findings, added CVEs, newly available fixes, priority escalations, and findings that leave the monitored scope
- Open findings trigger a short notification even on days without changes
- Monday notifications include a full report by default

</div>
<div markdown>

:material-sort-variant:

## Priorities based on KEV and EPSS

Severity, CISA KEV, and EPSS provide context for deciding which findings to review first.

- Findings are grouped into Act now, Watch, and Low
- These priorities do not establish whether your environment can be exploited

</div>
<div markdown>

:material-magnify-scan:

## Trivy results and runtime checks

Trivy scans report HIGH and CRITICAL vulnerabilities by default, including findings without available fixes.

- Package summaries show fixed versions when available and upgrade-risk guidance, without guaranteeing compatibility
- Checks against each project's security information add findings for the runtimes in official `node` and `python` images that Trivy does not report

</div>
</div>

<figure class="kl-notification">
<div class="kl-slack">
<div class="kl-slack__channel"># security-alerts</div>
<div class="kl-slack__message">
<div class="kl-slack__avatar" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/></svg></div>
<div class="kl-slack__body">
<p class="kl-slack__meta"><strong>KestreLynx</strong> <span class="kl-slack__badge">APP</span> <span class="kl-slack__time">9:00 AM</span></p>
<p>🛡️ <strong>KestreLynx</strong> [prod-vps] — scan results for 2026-06-28 09:00<br>12 images scanned, 1 affected<br><em>Changes since the last scan.</em></p>
<hr>
<p><strong>🆕 New since last scan (1)</strong><br>Image: <code>nginx:1.25.3</code></p>
<p><strong>◆ libnghttp2-14</strong><br><strong>Installed:</strong> 1.52.0-1<br><strong>Fixed in:</strong> 1.52.0-1+deb12u1<br><strong>Upgrade risk:</strong> 🟢 distro security patch<br><strong>Findings:</strong> CRITICAL 0 / HIGH 2</p>
<p><strong>Top CVE:</strong> <span class="kl-slack__link">CVE-2023-44487</span> · HIGH · EPSS &gt;99% (+1 more CVE(s) in this package)<br><strong>Exploitation:</strong> CISA KEV (exploited in the wild)<br><strong>References:</strong> <span class="kl-slack__link">advisory</span> · <span class="kl-slack__link">vendor advisory</span> · 💬 <span class="kl-slack__link">HN (166 pts)</span></p>
<hr>
<p>📌 <strong>Open now:</strong> 🚨 1 act-now</p>
</div>
</div>
</div>
<figcaption>Sample notification in the default <code>diff</code> mode. Values are illustrative, not from a live scan.</figcaption>
</figure>

</div>

<div class="kl-section" markdown>

## Scope and access

KestreLynx is suited to continuously checking vulnerabilities in images used by running containers, creating remediation pull requests,
and checking for resolved findings after you merge and deploy the changes.

See [Comparison with other tools](documentation/comparison.md) for a running nginx example covering update pull requests and vulnerability checks before and after updates.

<dl class="kl-scope" markdown>
<dt>Docker</dt>
<dd markdown="span">One instance per host covers running containers across Compose projects and standalone deployments.</dd>
<dt>Kubernetes</dt>
<dd markdown="span">An in-cluster Deployment discovers running containers across all or selected namespaces through read-only API operations, with additional permissions limited to a work namespace only when language-package updates are configured.</dd>
<dt>Verified scope</dt>
<dd markdown="span">Single-node K3s with containerd on linux/amd64. Multi-node clusters, arm64, managed Kubernetes, and authenticated private registries remain unverified. [Verification record](development/kubernetes-support.md)</dd>
<dt>Discovery</dt>
<dd markdown="span">Containers must be running when discovered. Kubernetes native sidecars are included; ordinary init containers and ephemeral containers are excluded.</dd>
<dt>Docker socket access</dt>
<dd markdown="span">KestreLynx reads container information and Trivy reads images through the Docker API; with remediation pull requests enabled, KestreLynx also creates, starts, and removes work containers for language-package updates. Mounting the socket with `:ro` does not restrict API permissions and does not need to change to `:rw`, so the mounted image must be trusted.</dd>
</dl>

</div>

<div class="kl-section kl-steps" markdown>

## Setup

These steps use Docker Compose. You need a Docker host with Docker Compose and
at least one notification destination: a Slack Incoming Webhook, a Slack bot
with a destination channel, email, or a generic webhook. For Kubernetes, see
[Setup instructions](documentation/getting-started.md#run-on-kubernetes).

1. Clone the repository and enter its directory

    ```sh
    git clone https://github.com/kitsunetrail/kestrelynx.git
    cd kestrelynx
    ```

2. Create the configuration file

    Copy the example to `config.yml` and set a notification destination.
    { .kl-step-note }

    ```sh
    cp config.example.yml config.yml
    ${EDITOR:-vi} config.yml
    ```

3. Start KestreLynx

    ```sh
    docker compose up -d
    ```

4. Check startup and scans in the logs

    The example configuration runs one scan at startup, then scans daily at
    09:00.
    { .kl-step-note }

    ```sh
    docker compose logs -f
    ```

5. Enable remediation plans

    Remediation plans and pull requests are both disabled by default.
    { .kl-step-note }

    - Follow [Enabling remediation](documentation/remediation-setup.md) to first [enable remediation plans](documentation/remediation-setup.md#enable-fix-plans), which do not write to GitHub
    - After reviewing the plan, [enable fix pull requests separately](documentation/remediation-setup.md#enable-pull-requests)

:material-information-outline: Trial reports are welcome in [Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx).
{ .kl-note }

</div>

<div class="kl-section" markdown>

## Documentation, development logs, and articles

<div class="kl-links" markdown>
<div markdown>

### Documentation

- [Comparison with other tools](documentation/comparison.md)
- [Setup](documentation/getting-started.md)
- [Configuration](documentation/configuration.md)
- [How it works](documentation/how-it-works.md)
- [Remediation plans and pull requests (experimental)](documentation/remediation.md)
- [Runtime usage (experimental)](documentation/runtime-usage.md)

</div>
<div markdown>

### Development logs

- [Go modules remediation pull request development](development/go-modules-remediation.md)
- [Kubernetes remediation pull request development](development/kubernetes-remediation.md)
- [All development logs →](development/index.md){ .kl-more }

</div>
<div markdown>

### Technical articles

- [Trivy Basics and How to Read Scan Results](articles/trivy-basics-scan-results.md)
- [EPSS Basics and How to Check Scores](articles/epss-exploit-prediction-scoring-system.md)
- [How to Check Runtime Usage of Packages Reported by Container Vulnerability Scans](articles/which-container-scan-findings-are-actually-running.md)
- [All articles →](articles/index.md){ .kl-more }

</div>
</div>

Report a bug or suggest an improvement on
[GitHub Issues](https://github.com/kitsunetrail/kestrelynx/issues).
{ .kl-issues }

</div>
