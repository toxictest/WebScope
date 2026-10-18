# Security, privacy and authorization

## Authorization boundary

Use only assets for which the operator has explicit monitoring authorization. Scope data is an assertion, not proof of ownership, a legal permission check or a license to access unrelated tenants. CIDRs constrain destinations; they are never swept. A brand match, CNAME, certificate SAN, public CT entry or cloud name does not create permission.

The request layer validates the authorized role (asset, explicit cloud resource, opt-in CT provider, or approved webhook host), hostname/URL, all returned A/AAAA addresses, and the actual pinned connection address. Asset CNAMEs outside scope require an exact allow entry. Curl uses no inherited proxy or user curl configuration, no automatic redirects, no cookies and no credentials. Redirects require exact configured endpoint approval and new resolution/validation at every followed hop. OpenSSL uses a literal approved destination with hostname/IP verification and SNI where applicable.

URL support is intentionally strict: no userinfo, arbitrary asset query strings, fragments, ambiguous percent encoding, path traversal, IPv6 zones or alternate integer/octal/hex IPv4 interpretation. Nonpublic destinations require both a matching CIDR and an explicit policy flag. Well-known metadata-service endpoints, multicast/reserved classes and selected transition/translation address forms remain denied under broad scopes. Scope is rechecked before network operations, not merely at discovery time.

DNS queries necessarily go to the configured resolver infrastructure; `resolver=system` explicitly chooses system recursive DNS. A recursive resolver may follow CNAMEs or contact authoritative servers outside the asset's zone. Those are resolver operations, not permission for SurfaceIntel to probe those third-party services. Enforce resolver/network policies externally if the organization's definition of offline/egress control requires stricter mediation.

## Read-only observations

No exploitation, default-password testing, authentication bypass, account modification, bucket-policy edit, upload, deletion or destructive request is implemented. Cloud object bodies are never requested. Default web checks use HEAD. Opt-in landing-page previews are GET requests only to exact approved non-sensitive routes; public servers can still put sensitive content in unexpected responses, so do not enable preview indiscriminately.

Cloud HEAD confirmations reflect documented provider read-permission semantics and recognizable provider response metadata on TLS-verified endpoints. They do not classify content, prove all objects readable, or establish customer ownership. Bucket HTTP 200 without stronger evidence is indeterminate. Zero-object S3 listing verification is opt-in and rejects a response containing object entries. Azure/GCS list enumeration is not implemented.

No general safe observation proves arbitrary admin privileges without an application-specific contract. Therefore management interfaces remain potential findings in this release; login pages and HTTP 200 never become confirmed unauthenticated administration.

## Data handling

- Reports, temporary evidence and state are private; final artifacts are 0600 under caller-owned 0700 directories.
- Only TXT hashes, bounded whitelisted HTTP metadata, optional sanitized titles, public certificate fields and access classifications are exported. Cookies, raw TXT values, full bodies, raw provider errors and secret webhook URLs are not.
- Raw bounded headers and optional preview/provider responses can exist briefly in private temporary files. Cleanup runs on ordinary exit and handled signals. SIGKILL, power loss, filesystem faults or a hostile privileged user can prevent cleanup; inspect abandoned private temporary directories under your retention procedure.
- Webhook URLs are supplied through named environment variables and written only to private temporary curl config files. They are not in curl's argument list, reports or diagnostics. Same-UID/root observers can still read process environments or private files: protect the execution identity.
- Redaction is defense in depth, not a universal secret detector. Do not embed credentials in domain names, URL paths, cloud object names, configuration descriptions, server headers or titles. Disable preview when unknown responses could contain confidential material.

## State and local trust

Configuration and historical state are untrusted **data**, never shell code. Strict parsers reject unknown directives, malformed fields, unsupported schema versions, duplicate record IDs, control bytes, invalid hashes/identities and cross-organization baselines. No eval, sourced user file or downloaded executable adapter is supported.

Trust the shipped code, Bash/native tools, PATH, OS, resolver, CA configuration and the authorized local account. A malicious root user, compromised tool/CA, hostile resolver plus permissive public-destination policy, upstream routing/NAT changes or same-UID attacker can falsify observations or interfere with artifacts. Pinning reduces DNS rebinding/SSRF but does not cryptographically prove organizational ownership of an address. HTTP lacks TLS identity; report it accordingly. Only one approved address is sampled per endpoint; alternate-address behavior may differ.

Baselines and delivery caches are unsigned. Schema validation prevents execution and structural ambiguity, not authorized-file tampering or forged historical claims. For stronger assurance, separately sign/archive release, policy, scope, reports and baselines in trusted storage. Future centralized systems must preserve those trust boundaries.

Logical customer separation uses organization-specific directories, baseline organization validation, per-customer locks and matching alert configuration. It is **not adversarial tenant isolation** when multiple customers share one Unix account. Use separate accounts/containers, secret stores and storage permissions for mutually untrusted customers; do not expose the local engine as an unrestricted multi-tenant API.

## Bounds and failure modes

Native request deadlines, rates, global collection budget, candidate/config/state/response bounds, redirect count, alert retries, serial execution and bounded retention constrain work. The default `concurrency` setting is a ceiling; actual release execution is serial. The global budget stops new collection, while finalization operates on bounded data. Use a supervisor wall-clock timeout for strict operational deadlines. Uninterruptible kernel I/O and OS failure cannot be solved by a shell timeout.

SIGINT/SIGTERM may wait for an already running bounded native request to finish before the shell trap writes an interrupted report. They never intentionally promote interrupted state. Locks are acquired atomically and not automatically broken by guessing whether a PID is alive; review stale locks manually. Renames provide atomic baseline publication on a normal local filesystem; power-loss durability, NFS semantics and adversarial ancestor-directory races are not guaranteed. Use a local trusted filesystem and external backups.

Never interpret a partial scan, failed request, absent tool, login page, source outage, blocked destination or indeterminate cloud response as proof of security or exposure.
