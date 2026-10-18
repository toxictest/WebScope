# Webhook integrations

No webhook traffic occurs unless a destination is explicitly configured. Secrets live in protected environment variables; the alert file references **variable names**, not literal webhook URLs. The alert configuration must be owned by the invoking UID, have no group/other permissions, and declare the same organization as the scope.

```text
organization=customer-a
approved_host=hooks.slack.com
slack_env=SURFACEINTEL_SLACK_WEBHOOK
minimum_severity=HIGH
cooldown_seconds=86400
retries=2
```

Set the corresponding environment securely through your service secret-management mechanism. Avoid command-line literals, shell history, `set -x`, world-readable environment files and logging full environments. For a systemd deployment, a root-protected `EnvironmentFile` can pass only that customer's variables to its service. The engine does not print URL/token values or curl errors containing them. Secret URLs go into temporary mode-0600 curl configuration files, not curl's argument list.

## Slack

Create an authorized incoming webhook and approve its **exact hostname** (normally `hooks.slack.com`). `integrations/slack.sh` emits a text payload with link/media unfurling disabled. No API token or Slack account is required by the core audit engine; the customer configures the webhook separately.

## Discord

Configure an authorized webhook and its exact hostname (normally `discord.com`). `integrations/discord.sh` emits `content`, disables mentions and suppresses embeds. The engine does not manage Discord identities or channels.

## Microsoft Teams: use Workflows

Use a customer-managed workflow with **When a Teams webhook request is received**, followed by an action that posts the supplied Adaptive Card to the approved chat/channel. `integrations/teams.sh` emits a message envelope with an Adaptive Card. Configure `teams_env=...` and the **exact callback hostname**, which depends on the customer environment. Do not assume legacy Office 365 connector URLs are the supported setup.

The configured workflow must accept the customer-selected callback mechanism. This release supports a protected webhook/callback URL (including a workflow's secret query parameters); it does not implement OAuth token acquisition for tenant-authenticated-only triggers. If your policy requires OAuth, use a separately authenticated relay/transport rather than weakening tenant controls.

Microsoft's guidance, checked 2026-10-17, recommends Workflows and notes that flows are owned by users; assign co-owners and a lifecycle owner so departure of one user does not orphan delivery:
https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook

Hosted Slack/Discord/Teams delivery was not tested with a real customer account. Payload serialization, destination controls, retry/failure, redaction and delivery records were tested with an owned local receiver. Validate your exact workflow/card contract in staging before relying on it.

## Filters, deduplication and delivery

- `minimum_severity`: CRITICAL/HIGH/MEDIUM/LOW/INFO; default HIGH.
- Optional repeatable `category=...`: exact finding or drift event category.
- `cooldown_seconds`: 0–604800; default 86400.
- `retries`: 0–3 extra attempts; default 2; exponential delays of 1, 2, 4 seconds where applicable.
- Only transient network/429/5xx errors are retried. Redirects are never followed. Provider responses are discarded under bounds.
- Deduplication binds organization, provider, a non-exported digest of the destination, stable record ID and evidence fingerprint. Successful deliveries only are cached; failures can be retried on later runs. A changed destination does not silently inherit another destination's delivery acknowledgement.
- Persistent cache is bounded to 10,000 recent entries and seven days. A malformed cache disables delivery for that run rather than executing anything; the local audit continues.

Open security findings can be repeated after cooldown. Drift notices are sent only when the corresponding change exists relative to the selected baseline. NEW_ASSET and NEW_WEB_SERVICE default to INFO; DNS_RECORD_CHANGE and COVERAGE_CHANGED default to LOW; RESOLVED defaults to INFO. Initial observations are not proof that an asset was just created. Set filters deliberately—default HIGH will not notify on ordinary DNS churn.

Payloads contain organization, severity/category, affected asset, first-seen epoch, bounded whitelisted evidence/remediation and a local report-directory reference. Full reports, bodies, cookies, raw TXT values, private keys and webhook destinations are not sent. The messaging provider still processes the explicitly approved summary data; this is an external disclosure chosen by the operator.

`alert-delivery.tsv` records provider, DELIVERED/FAILED/DEDUPLICATED/CACHE_INVALID and a stable event/finding identifier, without URLs/tokens. Delivery failure does not invalidate otherwise complete local evidence or prevent an explicitly requested successful baseline update. Monitor delivery status independently.

HTTPS is required for normal webhook delivery. Plain HTTP is accepted **only for explicitly authorized loopback addresses with nonpublic access enabled**, supporting controlled integration tests—not Internet webhook deployment.
