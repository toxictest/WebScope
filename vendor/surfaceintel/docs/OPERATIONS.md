# Scheduling, retention and operational runbook

## First deployment

1. Obtain written scope and define ownership/expiry of that authorization.
2. Use a dedicated local execution identity and trusted immutable code directory.
3. Review exact endpoints, ports, cloud candidates, CNAME approvals, CIDRs and exclusions. Do not use guessed brand-related resources.
4. Run `--dry-run`, then a controlled scan without baseline promotion.
5. Review coverage/errors and findings. Test the exact approved webhook destination separately in staging.
6. Only then run with `--update-baseline` and deploy a schedule.

A complete run may contain high/critical findings; baseline promotion does not approve or suppress those findings. Ongoing findings remain eligible for notification after cooldown. An unsuccessful alert does not discard otherwise successful local evidence.

## Daily / weekly jobs

Examples are in `packaging/cron.example`, `surfaceintel@.service`, `surfaceintel-daily@.timer` and `surfaceintel-weekly@.timer`. The installer never activates them. Choose daily or weekly explicitly; both produce daily-baseline delta and seven-day management reports on each run. The interval is determined by the schedule, not a daemon hidden in the auditor.

For a systemd deployment, an administrator must separately create the service account, protected customer config directories and `/var/lib/surfaceintel`, copy/review units, reload the service manager and enable only the intended customer timer. Instance names should match approved simple customer identifiers. The sample service uses root-protected code and an unprivileged `surfaceintel` account, an optional customer-specific environment file, NoNewPrivileges, private temporary storage, read-only system paths and a 20-minute overall deadline. Customer policies/output paths must be readable/writable under that sandbox; adapt the timeout if increasing the collection budget.

The examples include explicit HTTP/cloud flags as a reviewed monitoring workflow. Remove them if only DNS/TLS authorization exists. Schedule templates are not evidence that production systemd/cron integration was exercised in this development environment.

Cron examples use an outer `timeout` for a wall-clock limit. Configure a trusted PATH and private umask; do not place webhook secrets inline in cron. A customer-specific trusted wrapper or service secret mechanism may populate environment variables. Never source a **SurfaceIntel data configuration** as a shell script.

## Locks and overlapping runs

Each organization has an atomic `state/run.lock`; each selected baseline also has a lock. Concurrent use exits 75 without deleting another invocation's lock. The default output layout is:

```text
<output>/<organization>/
  state/organization
  state/baseline.tsv
  state/baseline-prev-<timestamp>-<random>.tsv
  state/delivered.tsv
  run-<UTC timestamp>-<PID>/
    state.tsv
    inventory.json / findings.json          # when JSON selected
    summary.txt / summary.html              # HTML when selected
    daily-delta.txt / delta.tsv
    weekly-management.txt
    errors.tsv / provenance.tsv
    rejected-candidates.tsv / alert-delivery.tsv
```

After a crash, inspect job/service status, process ownership and the recorded PID before manually removing a stale lock. Do not automatically kill a PID from an untrusted lock file or assume PID reuse proves ownership. Never delete another customer's lock to force overlap.

## Baseline promotion

No `--update-baseline` means no modification of the reference state. With the flag, complete collection first produces validated reports/state, then atomically publishes a new baseline and retains the previous one. Partial/interrupted scans keep their reports but cannot replace the successful baseline. Organization/schema mismatch is fatal. A different coverage mode requires a new baseline path, rather than silently replacing a fuller scan with a smaller one.

Scope changes are reported. Missing candidates from a passive source are retained from history while still authorized. Scope exclusion is recorded as SCOPE_REMOVED; DNS failure/NXDOMAIN is not proof of infrastructure deletion. Confirmed resolutions require a current compatible successful observation, such as provider-denied anonymous cloud access or a renewed valid certificate. An absent management fingerprint alone is merely not observed, not proof that a dashboard was secured.

## Retention and weekly interpretation

`retention_runs` limits tool-created report directories, identified by organization marker and controlled filename pattern. `retention_baselines` limits previous state copies separately. Current baseline and delivery state are not removed as ordinary report directories. Do not place unrelated data in tool-managed run directories. Offload long-term archives through a separately approved process before pruning.

Weekly reporting uses retained runs within the last seven days (bounded history traversal), counts complete/partial/interrupted runs, shows current posture and counts distinct event IDs by kind. It does not fill missing days, claim fleet-wide completeness or treat runs with differing scopes/policies/modes as equivalent. If retention is smaller than seven days of scheduled runs, the weekly view is necessarily incomplete.

Application report retention is implemented. Scheduler stdout/stderr logs are separate: rotate them with your existing logrotate/journald policy, mode 0600/0700 storage and an approved retention schedule. No logrotate/system configuration is changed by the tool.

## Troubleshooting

| Symptom | Action |
|---|---|
| Exit 2 before requests | Check data syntax, exact scope, allowed URL format, private ownership/modes, available core utilities, baseline organization/version and mode compatibility. Do not add broad scope just to suppress errors. |
| Exit 3 / partial | Inspect `errors.tsv` and per-record status. Restore capabilities/authorized access or accept a consciously reduced **separate** monitoring mode. Do not promote the partial snapshot manually as a complete baseline. |
| DNS fallback incomplete | Install/admin-provide dig through normal change control, or use the reduced evidence knowingly. TXT content is intentionally not printed. |
| DESTINATION_NOT_AUTHORIZED | Review resolved A/AAAA addresses and explicit CIDRs. Private addresses require both policy consent and CIDR. Metadata/ambiguous forms remain blocked. |
| UNAPPROVED_CNAME | Confirm the exact tenant/alias and authorization before adding `allow_cname`; never authorize an entire provider just because a name appears related. |
| Out-of-scope redirect | Check intended SSO/CDN routing. Add only the exact authorized endpoint if following it is permitted; queries containing secrets are not followed or reported. |
| Cloud INDETERMINATE | HEAD did not prove permissions. Review provider identity, region, resource type and approved verification method. Never infer listing/object exposure from 200 alone. |
| TLS CONNECT_FAILED | Inspect connectivity/port/timeout separately from validity. Do not interpret it as expiry or bypass verification. |
| TLS_VALIDATION_FAILURE | Verify hostname/SAN, CA chain, validity and clock. Provide an explicitly trusted CA bundle if appropriate; there is no insecure-TLS switch. |
| Alert FAILED | Check secret variable existence, matching organization, exact approved host, current Workflows/provider contract, egress and response/rate limits. Logs deliberately omit URL/token and raw provider body. |
| Alert DEDUPLICATED | Expected cooldown behavior. Changed evidence/destination creates a new delivery key; do not delete state as a first troubleshooting step. |
| Exit 75 | Investigate overlap/stale locks; never blindly delete or kill. |

## Future MSP / centralized interface

The versioned JSON schemas are the read-only integration boundary. A separate authenticated orchestration/transport layer should bind organization identity, authorization version, scope/policy digests, completion, timestamps and report signatures; maintain separate secrets/state; and preserve unknown/partial evidence. It must not turn candidate discovery into scanning permission, merge different customer baselines, or upload raw bodies. Centralized uploads, tenant authentication, a hosted UI, billing and distributed workers are deliberately outside this local engine.
