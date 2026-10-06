# Short-lived container scanning development

- **Status:** Design (implementation not started).
- **Started:** October 3, 2026
- **Last updated:** October 6, 2026

## Purpose

Include images used by containers that run briefly and disappear, such as scheduled batch jobs, in vulnerability scanning and notifications.

The scope is Docker environments where the main application runs continuously, using execution history for containers that have already ended by scan time. This is designed separately from usage assessment by the Sensor, the component that observes runtime information.

## Approach

- **Do not assess usage in short-lived containers**
    - A few seconds of observation provides little basis for assessing usage, and completing observation setup before execution ends is technically difficult
    - Notify users of vulnerabilities found in the image even without a usage assessment
- **Target the last version that ran under each image name**
    - A name such as `:latest` can point to different content under the same name when an image is rebuilt, so record and scan the content that actually ran rather than relying on the name
    - Treat different image names separately without retaining every past version as a scan target
- **Expect missed executions and show when they may have occurred**
    - Record periods when executions may have been missed and show them in notifications
    - Distinguish events confirmed to be outside observation scope from actual observation losses
- **Keep leaving the monitoring window distinct from fixing vulnerabilities**
    - Separate an image leaving scan scope from a finding disappearing after a successful rescan
    - Do not mark previous findings as resolved because verification is unavailable

## The investigation that started this work

- The Sensor's records showed an increase every morning in the number of events that could not be used for usage assessment
- A scheduled batch job created containers every morning that ran for only a few seconds, exited, and were then deleted, leaving the Sensor unable to discover the containers or prepare the mapping from events to packages in time
    - Events from containers that were discovered but ended before preparation completed were counted as lost
    - Events from containers that ended before discovery were counted as unclassified because they could not be associated with a container
    - Mixing events outside observation scope into these counts made it impossible to distinguish them from actual observation problems using the counts alone
- Because the containers ended so quickly, the batch image was also absent from the main application's daily scans, which only target containers running at scan time, and its findings did not appear in notifications
- During the checked period, no events were lost through an overflow of the temporary event buffer in the kernel, the core of the operating system
    - To keep kernel event losses distinguishable, a field recording the number of kernel event losses has been added to the evidence emitted by the Sensor and is already implemented

## Decisions

### Usage assessment and notifications

Usage will not be assessed for short-lived containers, and images added through execution history will carry a note about that execution.

| Target | Handling |
| --- | --- |
| An image included solely through a short-lived container's execution history | Omit usage markers from findings and annotate the image heading with “Short-lived container” and the last execution time |
| The same image also runs in a long-running container | Continue assessing usage in the long-running container without presenting that result as evidence of usage in the short-lived execution |

### Capturing executions and selecting targets

- The main application will continuously receive Docker events, which report container starts, exits, and deletions, and save execution history
    - Confirm the content that actually ran before the container disappears and associate it with the image name and last execution time
    - If the content cannot be confirmed, retain that uncertainty instead of substituting another version currently referenced by the name
- In addition to images of currently running containers, select images that are no longer running from execution history
    - For each image name, keep only the last version that ran as a scan target for 14 days after its last execution
    - Treat different image names separately
    - Update the expiry when a new execution under the same name is confirmed, without extending it merely because a scan ran

If several versions run under the same name before the next scan, only the last one is selected from history, so intermediate versions may never be scanned.

### Retaining findings and leaving monitoring scope

| State | Handling of findings and notifications |
| --- | --- |
| A rescan succeeds and a previous finding is no longer present | Treat the finding as resolved |
| 14 days have elapsed since the last execution | Report that the image has left monitoring scope, separately from resolution |
| The executed content cannot be confirmed or scanning fails | Retain previous findings and show that verification is unavailable |
| A period of potentially missed executions prevents confirmation of changes to the targets | Retain previous findings without treating an uncertain disappearance as resolution |

When findings from a previous scan are displayed because scanning could not be completed, they will be labeled as results from the previous scan. A “collection gap” is a period when Docker events, which report container starts and exits, could not be received, for example because the main application was stopped. Periods when events could not be received will not extend the 14-day window. Images that reach expiry will leave monitoring scope, with a note that they may have run again during those periods.

### Recording gaps and losses

- Docker events cannot be captured completely during periods such as main application downtime, so collection gaps will be recorded and shown in notifications with their periods and a short notice
    - Recovering some events after reconnection will not be treated as recovering every execution during that period
- The Sensor will count events from short-lived containers confirmed to be outside observation scope separately from lost or unclassified events
    - Events that cannot be associated with a container will remain unclassified
    - Separating out-of-scope events will not hide actual observation losses for long-running containers or losses in the kernel

## Unverified areas and next steps

Short-lived container scanning and Sensor counting changes are not yet implemented. Implementation will proceed through Sensor counting changes, execution capture and storage in the main application, and then scan target selection and notifications.

- **Verify execution conditions in the operational environment**
    - Check whether the batch image is rebuilt for every run
    - Check the Docker Engine and Compose versions and how containers are started and deleted
- **Validate the Sensor's classification criteria**
    - Examine execution duration, evidence of termination, and observation readiness to determine concrete criteria for classifying a container as short-lived
    - Check the types of recorded events and the conditions under which they are counted as lost or unclassified
- **Measure capture and storage overhead**
    - Measure the overhead of receiving events, retrieving container information, and saving history to set processing and storage limits
    - Verify that unconfirmed periods remain visible in records and notifications when application restarts, disconnections, and container deletions overlap

## Update history

### October 6, 2026

- Recorded investigation results and design

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
