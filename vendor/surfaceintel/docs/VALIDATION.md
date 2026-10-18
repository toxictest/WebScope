# Validation record — 1.0.0-rc1

Development/validation date: **2026-10-17**.

## Actual executed results

- **206 assertions passed, 0 failed**. Full transcript: `tests/test-results.txt`.
- Bash syntax checks passed for the entry point, libraries, modules, provider adapters, installer and test launcher.
- ShellCheck at warning severity passed without diagnostics. SC2034 is explicitly suppressed for shared cross-module globals and unused positional schema fields; dynamic source paths are restricted to shipped module names.
- Public inventory/findings JSON validated against the shipped Draft 2020-12 schemas in the test environment using `jsonschema`.
- **No tests were skipped in the recorded final run.** Native IPv6 loopback and optional schema validation were available and exercised.
- Core Bash operation was also exercised with **Python and jq absent from PATH**; emitted JSON was independently parsed by the development harness.

Environment inspected before implementation: Debian 13 sandbox, Bash 5.2.37, curl 8.14.1 with OpenSSL 3.5.7, dig/host, GNU core utilities, timeout, jq, ShellCheck and development Python 3.13.16. No package installation or host security configuration changes were made.

## What the suite actually did

### Scope, SSRF and parsing

Exact domain/tree boundaries; excluded subtrees; IPv4/IPv6 prefix matching; authorized loopback; private/link-local/multicast/reserved/translation addresses; well-known cloud metadata endpoints even under broad explicit CIDRs; alternate integer/octal/hex IPv4 and malformed IPv6; canonical network CIDRs; URL credentials/query/traversal/encoded ambiguity; unapproved CNAMEs; mixed allowed/disallowed answers; exact cloud resource authorization; separate provider/alert roles; malformed configuration and historical state; command-injection-shaped state as inert data.

### Controlled active services

Owned local IPv4 HTTP, HTTPS and IPv6 HTTP listeners; actual curl connection pinning under deliberately hostile proxy environment variables; no following of external redirects; exact-approved redirect following; HTTP request timeout and oversized response handling; HEAD default behavior; opt-in bounded title extraction without storing full bodies; hostile metadata HTML escaping and JSON serialization; genuine OpenSSL certificate expiry inspection, hostname mismatch and successful renewal; known-risk and evidence-backed resolved-lifecycle behavior.

### DNS and passive fixtures

A/AAAA/CNAME/TXT response fixtures, DNS address changes, NXDOMAIN versus temporary failure, guarded destination resolution, candidate retention, passive/active separation, CT JSON names filtered to scope, wildcard/third-party candidate rejection and source provenance. DNS responses came from an owned executable mock, not a public resolver or third-party production zone.

### Cloud fixtures

S3, Azure Blob and GCS provider-specific HEAD metadata interpretation; 200 alone remains indeterminate; denied/auth-required/not-found cases; default object requests are HEAD, never GET; opt-in S3 zero-object result recognition; unexpected object entries, XML attribute variants and comment spoofing fail closed. **These are synthetic provider-response tests, not live cloud tenant tests.**

### State, reports, alerts and operations

Private permissions; stable IDs and known findings; partial DNS failures and interrupted explicit updates preserve the reference baseline; malformed/duplicate/foreign state rejection; source separation; cloud namespace restrictions; severity policy overrides and no critical novelty-only scoring; real local webhook JSON delivery, transient retry, permanent outage, cooldown, category-filtered INFO change notices and destination-aware deduplication; secret omission; cache/organization-marker symlink protection; actual overlapping-run rejection; SIGTERM/SIGINT exits and lock cleanup; report and baseline retention; opt-in installer plan/confirmation/overwrite refusal and installed dry-run; repeated scheduled-equivalent commands plus an external wall-clock supervisor.

## Example artifacts

`examples/controlled-local/` contains three generated runs:

1. Complete local-fixture audit with a valid but soon-expiring test certificate and conservative management heuristics.
2. Repeat scan showing known findings and stable identities.
3. DNS-failure partial scan showing unavailable evidence without fictitious asset removal or successful-baseline overwrite.

They use reserved synthetic domains and ephemeral local ports. They do **not** describe the user's infrastructure, a public company or a cloud customer. No fixture private keys, webhook tokens, page bodies, cookies or raw TXT values are packaged.

## Not executed / not claimed

- Real AWS/Azure/GCS access classification against customer-owned resources; actual S3 `max-keys=0` response behavior in each region; specialized cloud endpoints or private connectivity.
- Hosted Slack, Discord or Teams Workflows delivery with a real customer account; tenant-specific authentication/card/ownership lifecycle.
- Live public CT availability, rate-limit policy, provider outages or third-party tool execution. Only the bounded CT parser/adapter contract and local import workflow were tested.
- Installed cron/systemd timer activation, service-account provisioning or production scheduler sandbox integration. Templates remain opt-in and uninstalled.
- Other native distributions/Bash/curl/OpenSSL combinations, large-fleet performance, uninterruptible filesystem/network faults, power-loss durability, adversarial same-UID/root attacks or independent penetration/security review.
- Automatic proof of arbitrary unauthenticated administrative privileges; complete cloud-organization discovery; ownership/authorization certification; distributed/parallel workers or a hosted MSP platform.

## Deployment qualification gates

Before calling a deployment production-qualified: review and sign authorization/scope; validate representative native runtime/tool versions; test exact approved cloud/provider endpoints and webhooks in staging without customer-object downloads; verify scheduler identities, overall deadlines, secret handling and retention; review configured severity and alert noise; benchmark the declared serial workload; establish trusted baseline/report backups and incident ownership.

The artifact is a runnable, tested local pipeline, not merely a specification. The release-candidate designation and these unrun integrations prevent local fixture success from being misrepresented as universal commercial qualification.
