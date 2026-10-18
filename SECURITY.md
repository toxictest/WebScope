# Security, authorization and privacy

## Required authorization

A root domain is not evidence of ownership. `--authorized` records an operator assertion, not legal verification. Obtain written scope, excluded third-party services, approved schemes/ports/routes, traffic limits and an incident contact before running. Tree authorization must be explicit; CNAME approval does not create asset scope for a vendor. Avoid broad hosting/public-suffix roots; the small built-in public-suffix rejection list is not a complete ownership registry.

This release performs anonymous HEAD and bounded GET of public web discovery documents only. Never use it to bypass login, find usable credentials on unowned systems, test leaked keys, exploit management interfaces or access customer objects. It has no POST, upload, credential validation or permission-changing path.

## Network boundary

SurfaceIntel validates all A/AAAA answers and approved CNAMEs; every active request resolves again and pins one approved address. Curl remote-IP evidence must match. Proxy inheritance, `.curlrc`, automatic redirects and TLS-insecure retries are disabled. Literal/ambiguous special addresses and metadata endpoints are governed by the included transport's strict address rules. Operator-approved private networks require explicit CIDRs plus a nonpublic flag.

DNS uses configured system resolvers through `dig` and is a separate infrastructure role, not arbitrary web access. `--ct` grants only the fixed `crt.sh` provider query for the configured root. No CT discovery was performed against public targets during validation.

Name authorization cannot prove CDN tenancy, DNS ownership, routing/NAT behavior or legal permission. Exact external CNAME approval is intentionally required even when a CDN would be convenient. Trusted OS routing, CA roots, executable dependencies and same-account filesystem integrity remain assumptions.

## Content safety

- Sensitive-path detection uses conservative name/extension heuristics. A HEAD 200 can be a login page, catch-all route or soft 404; it stays review-required, never confirmed secret access.
- Discovered config/backup/database/source-map paths are HEAD-only. Robot-disallowed paths are not requested at all. Nested XML sitemap candidates are metadata-only; root `/sitemap.xml` is the explicit discovery-document exception.
- HTML/JS GET is allowed only after HEAD advertises a permitted MIME type, under the fixed body cap. HEAD is not a server-side contract: GET may still return different or unexpectedly sensitive content. A changed type is marked incomplete and discarded after the bounded response has arrived. Approve genuinely public routes and exclude sensitive applications; this tool cannot establish that every anonymous page is harmless.
- Known state-changing URL names are not requested; forms and APIs are not executed. However, a poorly designed server can mutate state on any GET/HEAD. Read-only HTTP methods are not a universal guarantee of zero server side effects.
- All query-bearing references are observed without their query values and are not fetched as query URLs. A separately observed query-free URL may be requested. Credential-shaped path values are rejected; arbitrary opaque path segments cannot always be recognized as secrets. Do not encode secrets in URLs.
- Public JavaScript is parsed as text, never executed. Potential credential assignments are low-confidence hints; only labels and `[REDACTED]` appear in reports. No password/key/token validation takes place and no low-entropy secret-value hashes are exported.
- No raw pages, JS, cookies, authorization headers or raw DNS TXT contents are persisted in final reports. Reported body hashes describe public document observations, not verified secret exposure.

## Local files and processes

Reports and work directories use restrictive permissions. Existing shared/wrong-owner output directories and symlinks are refused; advisory locking prevents overlap in one output root. Use separate Unix identities/containers for mutually untrusted customers. These protections are not a defense against a hostile process with the same UID, root, unsafe ancestor replacement races or modified shipped code.

Transient response files are bounded and pruned between transport operations, then removed on normal finalization and handled SIGINT/SIGTERM. SIGKILL, power loss or filesystem failure can leave a private `.work-*` directory. A remaining `INCOMPLETE` marker means report finalization did not complete. Inspect ownership and ensure no process is running before manually removing stale work; never publish raw abandoned work directories.

The collection deadline bounds outstanding transport processes. Local helper calls have separate deadlines; report finalization can exceed the collection budget. Output retention is manual in this release; no old report is automatically deleted or promoted as a baseline. Set storage quotas and a reviewed cleanup policy for repeated use.

## Publication and disclosure

There is no automatic GitHub push, telemetry or webhook. Treat real report URLs, DNS topology, application paths and certificate identities as private customer information. Only synthetic/local examples belong in source repositories. Internal/external SHA-256 manifests detect corruption, not publisher authenticity; review/sign releases before fleet deployment.

Report suspected implementation vulnerabilities privately to the repository maintainer. Include a minimized owned fixture, version and reproduction steps, not live credentials, private keys, customer page bodies or a public-target exploit demonstration.
