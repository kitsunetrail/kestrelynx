---
template: home.html
hide:
  - navigation
  - toc
  - footer
---

<div class="kl-hero" markdown>

Docker · Compose · Kubernetes · GitHub pull requests
{ .kl-eyebrow }

# Vulnerability notifications and remediation PRs, <span>resolution checks after deployment</span>

KestreLynx is open-source software that reports vulnerabilities in images used by running containers, compares update candidates, and creates remediation PRs on GitHub. After you merge and deploy, the next scan carries history forward to check for resolution.
{ .kl-lede }

[Setup](documentation/getting-started.md){ .md-button .md-button--primary }
[GitHub](https://github.com/kitsunetrail/kestrelynx){ .md-button }
{ .kl-actions }

Open source · AGPL-3.0 · Scans with [Trivy](https://trivy.dev/) · Prioritizes with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [EPSS](https://www.first.org/epss/)
{ .kl-license }

</div>

<div class="kl-section kl-demo" markdown>

## Fix plan notification from the demo { .kl-eyebrow }

<div class="kl-demo__body" markdown>
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

<div class="kl-callouts" markdown>

- **Created PRs** “Pull request” #1, #2, and #3 and “File to change” identify where the changes go.
- **A candidate without a PR** The python 3.12.15-slim candidate introduces vulnerabilities and is marked “Needs a decision”; you decide whether to update or wait for another tag.
- **Updates to dependent packages** Updating body-parser and path-to-regexp also updates express, which depends on them, from 4.18.2 to 4.22.3.

</div>
</div>
</div>

<div class="kl-section" markdown>

How it works
{ .kl-eyebrow }

## Remediation PRs and resolution checks

<div class="kl-stages" markdown>
<div markdown>

### Comparing update candidates

Rescans before and after an update use the same conditions to compare resolved, remaining, and newly introduced findings.

</div>
<div markdown>

### Creating remediation PRs

KestreLynx creates PRs in GitHub repositories mapped to running containers, updating existing files. Version specifications can stay where they are.

</div>
<div markdown>

### Checking resolution

After you merge a PR and deploy the new image, the next scan carries history forward to check for resolution.

</div>
</div>

<dl class="kl-rows" markdown>
<dt>Published image tags</dt>
<dd markdown="span">Compose files · plain Kubernetes manifests · Kustomize `images[].newTag` · Helm values</dd>
<dt>Base image tags</dt>
<dd markdown="span">Dockerfile</dd>
<dt>Dependency files</dt>
<dd markdown="span">npm · pnpm · pip · uv · Go · Maven (`pom.xml`) · Gradle (`gradle.lockfile`)</dd>
</dl>

</div>

<div class="kl-section" markdown>

Demo remediation example (experimental)
{ .kl-eyebrow }

## One PR, from proposal to resolution check

Actual output in English from the [demo repository](https://github.com/kitsunetrail/kestrelynx-demo), which pins older images and dependencies. The [generated PRs](https://github.com/kitsunetrail/kestrelynx-demo/pulls) are also public.
{ .kl-section__lede }

<div class="kl-example" markdown>
<figure class="kl-shot kl-shot--crop" markdown="span">
![GitHub PR body showing 94 out-of-scope vulnerabilities remaining and none newly introduced](assets/screenshots/pr-compose-body.png)
</figure>
<div markdown>

Remediation pull request
{ .kl-label }

### nginx 1.27.0 → 1.27.5

The candidate scan comparison records 17 targeted vulnerabilities resolved and 86 remaining.

[Open PR #1 on GitHub →](https://github.com/kitsunetrail/kestrelynx-demo/pull/1)

</div>
</div>

<figure class="kl-shot kl-shot--padded" markdown="span">
![Slack notification showing the nginx update and resolved vulnerabilities in libabsl20220623, libavif15, libfreetype6, and liblzma5](assets/screenshots/slack-resolved.png)
<figcaption><strong>After merge and deployment</strong> After PR #1 was merged and the running <code>proxy</code> container was replaced with nginx 1.27.5, the next scan reported resolutions for four packages with history carried over.</figcaption>
</figure>

<div class="kl-caveat" markdown>

Creating a candidate or PR does not fix the running image. Checking the comparison scope and running CI are required before merging. You rebuild and deploy the image.

GitHub is the only supported source host, and language packages are retrieved only from public registries. [Remediation plans and pull requests (experimental) →](documentation/remediation.md)

</div>

</div>

<div class="kl-section" markdown>

Scanning and notifications
{ .kl-eyebrow }

## Vulnerability changes and priorities

<div class="kl-cards" markdown>
<div markdown>

<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v4h4"/><path d="M12 7v5l3 2"/></svg>

### Changes since the last scan

Notifications show changes in findings since the previous scan.

</div>
<div markdown>

<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16"/><path d="M4 12h11"/><path d="M4 18h6"/></svg>

### Remediation priorities

Priorities combine severity, known exploitation (KEV), and predicted exploitation probability (EPSS).

</div>
<div markdown>

<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/><path d="M3 7V3h4"/><path d="M21 7V3h-4"/></svg>

### Scanning with Trivy

Trivy scans report HIGH and CRITICAL vulnerabilities by default, including findings without available fixes.

</div>
</div>

</div>

<div class="kl-section kl-setup" markdown>

Setup
{ .kl-eyebrow }

## Steps with Docker Compose

Setup requires a Docker host with Docker Compose and at least one notification destination: Slack Incoming Webhook, a Slack bot and channel, email, or a generic webhook.
{ .kl-section__lede }

```sh
# 1. Clone the repository and enter its directory
git clone https://github.com/kitsunetrail/kestrelynx.git
cd kestrelynx

# 2. Copy the example; set a notification destination
cp config.example.yml config.yml
${EDITOR:-vi} config.yml

# 3. Start KestreLynx and check startup and scans in the logs
docker compose up -d
docker compose logs -f
```

The example configuration runs one scan at startup, then scans daily at 09:00. Remediation planning and PR creation are disabled by default.

[Setup instructions →](documentation/getting-started.md)
[Run on Kubernetes →](documentation/getting-started.md#run-on-kubernetes)
[Enable remediation plans →](documentation/remediation-setup.md)
{ .kl-more-links }

</div>

<div class="kl-section" markdown>

## Documentation, development logs, and articles { .kl-eyebrow }

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

Bug reports and suggestions go to [GitHub Issues](https://github.com/kitsunetrail/kestrelynx/issues); trial reports go to [Discussions](https://github.com/kitsunetrail/kestrelynx/discussions/categories/trying-kestrelynx).
{ .kl-feedback }

</div>
