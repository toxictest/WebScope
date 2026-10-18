# Configuration and policy

All configuration is bounded UTF-8/ASCII text with **unquoted `key=value` lines**. Full-line `#` comments and empty lines are allowed; shell syntax, interpolation, inline comments and arbitrary directives are not. No file is sourced or evaluated. Scalar policy keys cannot repeat; scope list keys deliberately repeat. Paths are interpreted relative to the invoking working directory unless absolute; use absolute paths in schedulers.

## Scope example

```text
organization=customer-a
domain_tree=example.org
host=separate-owned.example.net
asset=staging.example.org
asset_file=/private/customer-a/subfinder-approved.txt
endpoint=https://www.example.org/
endpoint=https://ci.example.org/jenkins
endpoint=https://api.example.org:8443/swagger
critical_endpoint=https://www.example.org/
exclude_host=legacy.example.org
exclude_tree=vendor.example.org
exclude_cidr=198.51.100.0/24
allow_cname=customer-specific.vendor.example.net
```

Replace all names only after obtaining explicit authorization. Root/tree authorization includes the root and exact dotted subdomains. Excluded trees include their apex. `allow_cname` approves a specific resolution-chain name, **not** permission to scan that provider hostname itself. `critical_endpoint` must also be an endpoint; it raises certificate trust-failure priority for that explicitly critical service.

`cidr=` permits destination addresses/IP literal assets; it does not trigger a range sweep. `host=192.0.2.10` needs an appropriate authorized CIDR. Reserved/example/private addresses need the separate nonpublic policy flag. Link-local zone identifiers, alternate integer/octal/hex IPv4 spellings, IPv4-mapped IPv6, URL credentials, fragments, arbitrary query strings, encoded path ambiguity and traversal segments are rejected. Use ASCII/punycode DNS names, canonical decimal IPv4 and network-aligned CIDRs (host bits must be zero). URLs may contain common ASCII path characters only; unsupported encodings fail closed.

`asset_file` is one hostname or literal IP per line, with optional full-line comments. Imported names are candidates and must pass the same scope checks. Rejected candidates are recorded, never probed. No `www`, bucket names or administrative paths are generated from naming guesses.

### Explicit cloud resources

```text
cloud=s3|bucket|https://approved-bucket.s3.us-east-1.amazonaws.com/
cloud=s3|object|https://approved-bucket.s3.us-east-1.amazonaws.com/non-sensitive-canary.txt
cloud=azure|bucket|https://approvedaccount.blob.core.windows.net/container
cloud=azure|object|https://approvedaccount.blob.core.windows.net/container/non-sensitive-canary.txt
cloud=gcs|bucket|https://storage.googleapis.com/approved-bucket/
cloud=gcs|object|https://storage.googleapis.com/approved-bucket/non-sensitive-canary.txt
```

These exact resources are separately authorized. They do not authorize other buckets/containers/objects or arbitrary URLs on a shared provider endpoint. No signed URL, SAS token, access key or object credential is accepted in a resource URL. Prefer owner-selected non-sensitive canary objects for HEAD verification. Cloud domains remain TLS-verified and their destination addresses are checked before connecting.

Supported endpoint subset: standard S3 virtual-hosted global/regional `amazonaws.com` endpoints; standard Azure public-cloud Blob endpoints; GCS XML API at `storage.googleapis.com`. China/government/private endpoints, S3 path-style/website/access-point/MRAP endpoints, Azure special container names, and complex encoded object keys are not guessed or silently mapped to another provider. Extend and test the provider validator before using those formats.

## Policy keys

See the complete commented `config/policy.example.conf`. Defaults/ranges:

| Key | Default | Range/meaning |
|---|---|---|
| `config_version` | 1 | Explicit operator-controlled policy revision |
| `dns_rate` | 2 | Integer 1–50 requests/sec |
| `http_rate` | 1 | Integer 1–20 HTTP/TLS/alert requests/sec |
| `concurrency` | 1 | Ceiling 1–8; actual release engine is serial |
| `timeout` | 8 | Per-request seconds, 1–60 |
| `max_duration` | 900 | Collection budget, 10–3600 seconds; use scheduler wall-clock enforcement too |
| `max_assets` | 128 | 1–1000, bounded candidate/endpoint/resource counts |
| `retention_runs` | 30 | 1–365 report runs, not guaranteed days |
| `retention_baselines` | 8 | 1–100 previous baseline snapshots |
| `tls_critical_days` | 15 | 1–30 days |
| `allow_nonpublic` | false | Requires explicit CIDR as well; metadata services remain blocked |
| `allow_public_dns` | true | Allow public destinations resolved for an authorized name; false requires CIDRs |
| `ct_enabled` | false | Explicitly enable the public CT transport adapter; jq required |
| `http_body_preview` | false | Opt-in GET of exact approved non-sensitive landing pages; otherwise HEAD |
| `follow_redirects` | false | At most three manually revalidated hops, only to exact approved endpoints |
| `cloud_listing_verification` | false | S3 ListObjectsV2 `max-keys=0` only; no object listing on Azure/GCS |
| `resolver` | system | System resolver or an explicitly selected literal DNS resolver IP |
| `ca_file` | system trust | Optional trusted CA bundle; use a protected absolute path |
| `alert_config` | none | Protected, matching-organization alert configuration |
| `baseline` | customer state path | Default may be overridden with CLI |
| `output` | ./surfaceintel-reports | Default may be overridden with CLI |

CLI rate/concurrency/timeout/output/baseline overrides take precedence. No HTTP/cloud flag is inferred from a config file or hostname.

### Severity overrides

Known categories can be configured as lowercase policy keys, for example:

```text
severity_public_cloud_access=HIGH
severity_certificate_lifecycle=CRITICAL
severity_management_interface_potential=HIGH
severity_dns_record_change=LOW
severity_new_asset=INFO
```

Levels are CRITICAL, HIGH, MEDIUM, LOW, INFO. Unknown categories/levels are rejected. CRITICAL is forbidden for novelty-only NEW_ASSET/NEW_WEB_SERVICE/DNS_RECORD_CHANGE and unconfirmed `*_POTENTIAL` heuristics. Setting public cloud access CRITICAL should reflect a reviewed sensitivity policy for the explicitly approved resources, not a claim that their contents were inspected. Policy digests include overrides and critical-endpoint declarations.

Finding categories also include ADMIN_ROUTE_POTENTIAL, NONPRODUCTION_INTERFACE, OUT_OF_SCOPE_REDIRECT, POSSIBLE_DANGLING_DNS, TLS_VALIDATION_FAILURE and TLS_NOT_YET_VALID. Alert-only drift categories include NEW_ASSET, NEW_WEB_SERVICE, DNS_RECORD_CHANGE, COVERAGE_CHANGED and RESOLVED. Observational notices are distinct from security findings in JSON.

## Passive provider and tool adapters

The core works from configured/imported candidates without any external discovery API. The opt-in CT adapter queries only the fixed `crt.sh` provider role, under rate, DNS destination and response-size limits. Provider errors, invalid JSON, restricted access or size truncation are visible and make discovery incomplete; configured and historical candidates still proceed. Do not evade provider access restrictions. Respect provider terms and disable the adapter if not authorized to use it.

Outputs from tools such as Subfinder or Amass can be supplied through separate approved `asset_file` lists. SurfaceIntel does **not** execute third-party discovery binaries or inherit their network permissions. Run those tools only under their own reviewed provider/scope configuration; import only hostname lists, not executable adapters. Provenance identifies the import filename and persists observed source tags in the asset baseline. The current release has a CT adapter plus safe file-import integration, not a live runner for every external discovery tool.

### Configuration digest boundary

The policy digest identifies selected semantic settings, severity overrides, critical endpoints, the configured CA **path**, and `config_version`; it is not a hash of every input file or the operating system trust store. Replacing a CA bundle in place does not by itself change that digest. Protect trust/configuration files, increment `config_version` for reviewed trust-policy changes, and retain their approved content hashes in deployment change records. Report `tool_version` identifies the collecting release; release manifests cover shipped source, not customer configuration.
