# Notification conditions

## Scan notification conditions {#notification-conditions}

Scan notifications are sent according to the notification mode and the findings and changes in the current cycle.
When a notification is due for a cycle, it is sent to all configured destinations (Slack, generic webhooks, and email).
See [Notification mode](configuration.md#notify-mode) for notification mode settings.

### Delivery in diff mode {#diff-delivery}

`diff` mode reports changes since the previous scan and the current unresolved state.
In the following table, “findings” includes ordinary packages, EOL packages, and EOL base operating systems.

In Kubernetes, when a node does not report a digest, the scanned contents cannot be verified, so previous records may be retained (see [Image digest verification](scan-logic.md#identity-verification)).

| State | Scan notification |
| --- | --- |
| Changes detected | Reports changes such as new and resolved findings |
| No changes | Reports that nothing changed and shows the current unresolved state if findings remain |
| No findings or changes | Sends only when `notify.notify_on_clean` is `true` |
| Last finding resolved | Reports the resolution even when no current findings remain |
| Scan failure | Sends even without findings or changes |
| Findings retained | Sends even without changes if previous package findings (ordinary and EOL) are retained because Kubernetes digests are unconfirmed |
| Image digest changed or image name updated | Sends even without package changes |

If only base-OS EOL records are retained, retention alone does not trigger a notification.

See [Change and history decisions](diff-logic.md#comparison-baseline) for what constitutes a change and [Failed scans](scan-logic.md#scan-failures) for when results are retained.

### Delivery in full mode {#full-delivery}

`full` mode sends the current report without using diff history.

| Current state | Scan notification |
| --- | --- |
| Package findings or an EOL base OS | Sends every cycle |
| Scan failures | Sends every cycle |
| No findings or scan failures | Sends only when `notify.notify_on_clean` is `true` |

Even when a cycle does not meet the scan notification conditions, a remediation plan is sent if it meets the [remediation delivery conditions](#remediation-delivery).

### Weekly report delivery {#weekly-report}

In `diff` mode, a full Slack report is added to scan notifications that qualify for delivery on the configured weekly report day.

Even on the weekly report day, no full report is sent in the following cases:

- Cycles that do not meet the scan notification conditions (for example, cycles with no findings or changes and `notify.notify_on_clean` set to `false`)
- Cycles that send only a remediation plan

See [Configuration](configuration.md) for the weekday and disabling options, and [Channel reports](slack-display.md#channel-display) for what the full report includes.

## Slack thread delivery conditions {#slack-thread-delivery}

For scan notifications sent through a Slack Bot in `diff` mode, a message is posted to the channel. On cycles that meet the conditions, all unresolved findings are posted as a reply to the first channel message.
This keeps the channel messages limited to a summary and lets you open the reply to review each finding.

The following diagram shows example posts for scans on two consecutive days.

```text
November 8 (changes since the previous scan)
Channel: 🛡️ KestreLynx — scan results for 2026-11-08 09:00
  Changes since the last scan. …
  📌 Open now: 🚨 1 act-now / 👀 3 watch / 🔕 25 low
  📊 Everything open now is in this message's thread ↓
  └ Reply: 📊 Everything open now — 2026-11-08 09:00
      🚨 ACT NOW (1) — exploited or likely to be
      Image: example/app:1.0
      ◆ openssl
        Installed: 3.0.13-r0
        Fixed in: 3.0.15-r0
      …

November 9 (no changes since the previous scan, not the weekly report day)
Channel: 🛡️ KestreLynx — scan results for 2026-11-09 09:00
  No changes since last scan.
  📌 Open now: 🚨 1 act-now / 👀 3 watch / 🔕 25 low
  🔗 Everything open as of the last report → thread
    → Link destination: November 8 reply (no new reply)
```

The reply is posted when the report from the latest scan contains findings and any of the following applies.

- There are changes since the previous scan
- The weekly report is due
- No valid previous report link exists, such as on the first notification
- The destination channel changed and the previous report link cannot be carried over

On cycles that do not meet the conditions for posting a reply, no new reply is added. Instead, a link to the previous reply appears at the end of the first channel message.
The link footer is omitted when no valid link exists or the link cannot be displayed.

If the report from the latest scan contains no findings, no reply is posted, even when scans failed or history is retained.
No reply is posted for a cycle that sends only a remediation plan.

In `full` mode, unresolved findings are listed directly in the channel messages, without replies or links to previous replies.
Slack Incoming Webhooks do not support replies.

See [Thread reports](slack-display.md#thread-display) for reply placement and links to previous replies, and [Configuration](configuration.md) for connection settings.

## Scan notification redelivery {#scan-redelivery}

In `diff` mode, history for the next comparison is saved only after all required notifications are sent successfully.

| Delivery result | History and next cycle |
| --- | --- |
| Delivery succeeds to all destinations | Saves the state after the latest scan for the next comparison |
| Delivery fails to some or all destinations | Leaves comparison history unchanged and compares against the previous history next time |
| No notification needed | Saves the state after the latest scan |
| History cannot be saved after delivery | May report the same changes again because the next cycle still compares against the previous history |

Delivery to other destinations is attempted even if one destination fails.
As a result, destinations where delivery succeeded may receive the same changes again next time.

If a split Slack message or thread fails partway through, messages already posted remain.
The saved report link is not updated, and the next notification may post duplicate messages.

## Remediation plan delivery conditions {#remediation-delivery}

Remediation plan delivery is decided independently of scan notification delivery.
See [Remediation processing flow](remediation-logic.md#processing-flow) for plan generation and PR operation decisions.

### Delivery conditions by destination {#remediation-destination-conditions}

For each destination, remediation plans are sent when any of the following conditions applies.
Conditions marked “—” are not used to decide delivery to that destination.

| Condition | Slack | Email | Webhook |
| --- | --- | --- | --- |
| Content changed since the last delivery | Send | Send | Send |
| Weekly report day in `diff` mode with content to display | Send | Send | — |
| PR operations have not yet been reported | — | — | Send |
| Problems blocking PR writes persist | — | — | Send |

Problems blocking PR writes are reported through the webhook every cycle while they persist.

Slack and email compare the remediation plan and PR information shown in the notification (display content) with the content last sent to each destination.
The webhook compares the plan content, plan availability, and plan save-failure status with the last delivery.
The plan generation time is excluded from the comparison for every destination.
See [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks) for how to read the display.

### Content sent on the weekly report day {#remediation-weekly-content}

For Slack and email, the PRs included on the weekly report day depend on whether the display content has changed.
If the display content is unchanged, merged PRs and PRs closed without merging are excluded, and nothing is sent if no content remains to display.
If the display content has changed, completed PRs are included, whether or not it is the weekly report day.

### Slack and email delivery records {#remediation-email-delivery}

Slack and email keep separate delivery records that track what was last sent to each destination.
Email remediation plans use the same display content as Slack.
A successful Slack delivery does not mark the email plan as delivered.

### When the webhook includes a plan {#remediation-webhook-delivery}

The webhook also includes the current remediation plan when a scan notification or a Slack remediation plan is sent.
In these cases, the plan is included even if it has not changed.
See [Common remediation plan fields](webhook-remediation-reference.md#remediation-fields) for the data format.

### Remediation plan redelivery {#remediation-redelivery}

Sent remediation plans are recorded separately for each destination, and the next cycle compares against these records to decide whether to send.
Content that was not recorded is sent again in the next cycle.

Delivery is recorded for each destination at the following times.

| Record | When it is recorded |
| --- | --- |
| Webhook plan and PR operations | When delivery to all destinations succeeds |
| Slack remediation plan display content | When all Slack remediation plan messages are posted successfully |
| Email remediation plan display content | When the email containing the remediation plan is sent successfully |

Slack and email deliveries are each recorded when their condition above is met, even if delivery to other destinations fails.
If saving a record fails, content already sent may be sent again.
Resending a notification does not recreate existing PRs.
See [Stored files](remediation-reference.md#stored-records) for saved contents and [Matching existing PRs](remediation-logic.md#existing-pr-matching) for PR checks.
