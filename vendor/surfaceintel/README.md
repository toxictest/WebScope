# SurfaceIntel

**Authorized external asset inventory, DNS drift, cloud metadata exposure and TLS lifecycle monitoring — v1.0.0-rc1**

A working, modular **Bash** pipeline. Core operation needs no paid API, Python runtime, account, or cloud service. It collects scoped observations, compares a validated historical baseline, generates private reports, and optionally sends deduplicated webhook alerts.

**Release status:** controlled-deployment candidate. Owned local HTTP/HTTPS/IPv6/webhook services and deterministic DNS/cloud fixtures are tested. Real cloud tenants, hosted webhook providers, public CT availability and installed production schedulers have **not** been exercised. This is not an assertion that arbitrary Internet resources are secure, exposed, or authorized.

## Start safely

```bash
./surfaceintel.sh --help
./surfaceintel.sh --scope config/scope.example.conf --config config/policy.example.conf --dry-run
# Replace example.invalid with assets you are explicitly authorized to monitor.
./surfaceintel.sh --scope /private/customer.scope --config /private/customer.policy --output ./reports
# Explicit active web/cloud checks and explicit successful-baseline promotion:
./surfaceintel.sh --scope /private/customer.scope --config /private/customer.policy \
  --output ./reports --http-checks --cloud-checks --update-baseline
```

The example uses reserved `.invalid` names, not a real organization's infrastructure. No scope file means no scan. Domain authorization is an operator assertion; the tool does not establish legal ownership or permission.

Default normal mode discovers configured/imported candidates, inventories DNS, and inspects TLS **only for explicitly configured HTTPS endpoints**. HTTP and cloud checks require their flags. No CIDR sweep, guessed subdomains, port scan, route brute force, password test, exploit, upload, object-content download or automatic permission change exists.

## Runtime requirements

- Linux, Bash **4.4+**, GNU-style core utilities including `date`, `sha256sum`, `stat`, `sort`, `awk`, `sed`, `grep`, `cut`, `diff`, `cmp`, `tr`, `mktemp`, `find`, `head`, `tail`, `wc` and normal file utilities.
- `curl` for bounded, pinned HTTP requests. Proxy inheritance and `.curlrc` are disabled.
- `dig` recommended. `host` fallback supports A/AAAA with reduced record/TTL coverage; unavailable capabilities make the scan partial. `getent` is deliberately not used as an unbounded NSS fallback.
- Optional `openssl` **and** `timeout` for bounded certificate inspection. Without either, required TLS observations are unavailable, not valid.
- Optional `jq`: generated JSON syntax validation and the opt-in CT adapter. Baseline/state validation and JSON serialization are implemented in Bash and do not depend on jq or Python.
- Python 3.9+ is used by the **development test harness only**, to run isolated local test services. Optional `jsonschema` strengthens test-time schema validation.

No dependencies are installed by the auditor or installer.

## Modules

| Module | Implemented behavior |
|---|---|
| Scope and transport | Exact domains, explicit domain trees, CIDRs, host/tree/CIDR exclusions, approved CNAMEs, explicit endpoint paths/ports and cloud resources; IPv4/IPv6 validation; DNS/IP pinning; per-hop redirect approval |
| Passive discovery | Configured roots/hosts/assets, imported tool-output files, opt-in `crt.sh` CT adapter; source/timestamp provenance and historical candidate retention |
| DNS | A/AAAA/CNAME/MX/NS/TXT, response status, available TTLs, collection source; TXT **hashes only**; normalized drift without TTL/timestamp noise |
| HTTP | HEAD by default; bounded opt-in landing-page GET; status, server/content-type/auth-scheme/HSTS indicators, safe redirect origin and optional sanitized title fingerprint; conservative management/staging heuristics |
| Cloud | Explicit S3 virtual-hosted resources, Azure Blob containers/objects, GCS XML endpoints; provider-specific anonymous HEAD evidence; opt-in S3 zero-object listing verification |
| TLS | Pinned connection with SNI/hostname or IP validation; public certificate metadata, SANs, validity dates, SHA-256, chain/mismatch results, 30/15/7/1-day/expired categories |
| History | Validated non-executable TSV state, stable record/asset/finding IDs, first/last seen, drift, scope changes, unavailable observations, evidence-backed resolutions |
| Alerts | Slack, Discord, Teams **Workflows** Adaptive Card payloads; exact approved destination hosts, protected environment references, category/severity filtering, cooldown, destination-aware deduplication and bounded retry |
| Reports | Text summary, JSON inventory/findings, daily delta, seven-day management/run-health summary, optional self-contained escaped HTML; errors, provenance and delivery TSVs |
| Operations | One-shot command, daily/weekly cron/systemd templates, customer and baseline locks, explicit baseline updates, private artifacts and bounded retention |

## CLI

| Option | Meaning |
|---|---|
| `--help`, `--version` | Help/version |
| `--scope FILE` | Required authorization data |
| `--config FILE` | Optional policy data |
| `--output DIR` | Private output root; default `./surfaceintel-reports`; each organization gets a separate subtree |
| `--baseline FILE` | Explicit same-organization state; default `<output>/<organization>/state/baseline.tsv` |
| `--update-baseline` | Promote only a complete successful run, atomically, preserving the previous snapshot |
| `--passive-only` | Candidates only; external CT requests occur **only if separately enabled** |
| `--dns-only` | Candidates plus DNS; no endpoint HTTP/TLS/cloud validation |
| `--tls-only` | Candidates plus TLS; scoped DNS lookups still occur to pin connections |
| `--http-checks` | Opt-in HTTP exposure checks on exact configured endpoints |
| `--cloud-checks` | Opt-in checks on exact configured cloud resources |
| `--report text\|json\|html\|all` | Additional report formats; operational text/delta/weekly/state artifacts are always retained |
| `--rate-limit VALUE` | Integer 1–20 requests/sec for both DNS and HTTP/TLS; separate policy rates also available |
| `--concurrency COUNT` | Maximum allowed workers, 1–8. **This release intentionally executes serially (actual concurrency 1)**, satisfying that ceiling; it does not promise parallel throughput |
| `--timeout SECONDS` | Per-request bound, 1–60 seconds |
| `--exclude FILE` | Additional exclusion-only key=value file |
| `--dry-run` | Validate plan; no network or output/state creation |
| `--no-color` | Accepted; all output is ANSI-free |
| `--quiet` | Suppress successful progress; errors remain on stderr |

The three `*-only` modes are mutually exclusive and cannot be combined with HTTP/cloud flags. Different coverage modes must use separate baseline paths when promoting state.

Exit codes: **0** collection complete (findings may exist); **2** configuration/dependency/state/output error; **3** partial collection; **75** overlap/stale lock; **130** SIGINT; **143** SIGTERM. Hosted webhook delivery failure does not turn a successfully collected local audit into a failed scan; delivery status is reported separately.

## Scope and privacy model

`domain_tree=example.org` authorizes that exact name and its subdomains—not `badexample.org` or `example.org.attacker.net`. `host=` is exact. IP literals require an explicit `cidr=`. Nonpublic destinations additionally require `allow_nonpublic=true`; default is false. Metadata-service destinations and several ambiguous/transition-address classes remain forbidden even under broad CIDRs.

Every active endpoint is configured, not guessed. Each connection resolves again, checks **all returned addresses**, then connects to one approved address using curl `--resolve` or a validated literal IP. HTTP remote IP is checked against the pin. OpenSSL connects directly to the approved address. Curl never performs automatic redirects; opt-in redirects are followed only when the new exact URL is in the endpoint list and is revalidated. Unapproved external CNAMEs block asset connections until explicitly approved. Passive-provider and webhook destinations have separate, explicit transport roles; they never become asset-scope permissions.

Public addresses resolved from an authorized hostname are allowed by default (`allow_public_dns=true`). This authorizes that configured hostname/service, **not arbitrary ports or other tenants on that address**. Set false and provide precise CIDRs for destination-change approval workflows. Authoritative DNS ownership, routing, anycast and upstream NAT are not cryptographically established by this tool.

HTTP defaults to HEAD. Optional page previews are limited to operator-approved non-sensitive routes; only an ASCII-sanitized title/fingerprint is reported, not page bodies. Raw headers and bounded preview/CT/zero-object-list responses exist briefly in private temporary files and are removed. Cookies, raw TXT values, URL queries and webhook URLs are not exported. Do not put credentials in hostnames, object names, policy metadata or approved URL paths.

## Evidence, not assumptions

- A newly discovered subdomain is a **candidate**, not a vulnerability or proof of ownership.
- A changed DNS record may be a planned deployment, CDN rotation or transient infrastructure change.
- A login page, management-looking path or HTTP 200 **never confirms unauthenticated administration**. Generic dashboard findings remain potential exposures requiring manual validation; no automatic authentication-bypass verifier is included.
- Cloud object-read confirmation means an **unsigned provider-identified HEAD request demonstrated the provider's object-read permission/metadata access**. Object bytes were not fetched. It is not a classification of object sensitivity or proof that all objects are readable.
- Bucket/container HTTP 200 alone remains `INDETERMINATE`. Default HEAD requests do not enumerate objects. Only explicit S3 listing verification requests `max-keys=0`; unexpected object entries invalidate the confirmation. Azure/GCS container listing is not attempted.
- Certificate connection failure is not silently labeled certificate expiry. Validation errors and expiration evidence are separate. Default lifecycle priority is CRITICAL within 15 days and after expiry, configurable by policy.
- Assets missing from a source are retained from the baseline while still in scope. NXDOMAIN becomes unresolved—not automatically removed. Explicit exclusions/scope contraction produce `SCOPE_REMOVED`, not a claim that infrastructure was destroyed.
- Successful collection is not the same as secure configuration. Cloud indeterminacy and unavailable required capabilities preserve the previous successful baseline.

## State and reports

State is a bounded, schema-validated **TSV format**, intentionally avoiding a mandatory JSON parser. The public inventory/findings API is JSON with schemas under `schemas/`. State files are never sourced. Atomic promotion is opt-in; previous snapshots are archived. Partial/interrupted scans remain separate reports and cannot overwrite the last successful baseline. A mismatched organization is rejected; different scan modes require a new baseline path.

Reports are mode 0600 inside owned mode-0700 directories. Stable fingerprints exclude volatile timestamps, TTLs and remaining-day counters. Daily reports mean **delta from the selected successful baseline**; that is a daily interval only when your schedule updates daily. Weekly reports summarize retained runs in the last seven days, latest posture and distinct recorded event IDs; they do not invent observations for missing days.

Default limits: 128 candidates/endpoints/resources per configured class, 8-second native request deadlines, DNS 2 requests/sec, HTTP/TLS/alerts 1 request/sec, 900-second collection budget, bounded responses, 30 retained report runs and 8 prior baseline copies. Final validation/reporting/retention adds bounded-data processing time beyond the collection budget. Use the provided systemd overall timeout or cron `timeout` wrapper for a hard operational wall-clock deadline. Serial collection and explicit coverage errors favor safe evidence over throughput.

## Documentation and tests

- [Installation and upgrade](INSTALL.md)
- [Configuration and policy](docs/CONFIGURATION.md)
- [Webhook setup](docs/WEBHOOKS.md)
- [Scheduling, retention and troubleshooting](docs/OPERATIONS.md)
- [Safety and privacy boundaries](SECURITY.md)
- [Validation results and unrun integrations](docs/VALIDATION.md)
- [State schema](schemas/STATE-FORMAT.md)
- [Changelog](CHANGELOG.md)

```bash
./tests/run_tests.sh
SURFACEINTEL_WRITE_SAMPLES=1 ./tests/run_tests.sh
```

The suite never scans public production targets. It uses deterministic DNS mocks, fake provider metadata, and owned local HTTP/HTTPS/IPv6/webhook servers. See the shipped transcript for actual executed assertions, rather than assuming every optional integration has been tested live.
