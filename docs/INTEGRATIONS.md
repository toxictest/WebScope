# Integration contract

This is **component-level integration**, not a launcher claiming that six complete independent scanners ran. Network-capable standalone legacy entry points are never invoked by WebScope. There are no optional external GitHub tool runners, cloned-at-runtime code, package installs or arbitrary plugin command fields.

| Existing tool | Executed/reused component | Deliberately not enabled |
|---|---|---|
| ReconScope | Original `normalise_list` helper, with shell globbing disabled, for imported hostname lists. Imported names are validated independently. Root/linked/CT discovery is coordinated by WebScope/SurfaceIntel. | subfinder/assetfinder/amass/httpx/naabu execution, broad automatic probing, a claim of full ReconScope discovery |
| URLMiner | Original noise/sensitive extension/path classification data, copied into a non-executable JSON adapter; WebScope extracts bounded HTML/JS references. | Archive crawlers, raw JS downloads to reports, unrestricted original crawler, sensitive-URL exposure assertions |
| HeaderGuard | Original POSIX AWK final-response header normalizer; WebScope records header presence and cookie flags without values. | Original request routine, automatic redirects, insecure retry, live arbitrary-origin CORS probes or a security grade |
| DNSShield | Original `CLOUD_PATTERNS` and `cloud_provider` helper on observed CNAME answers; DNS records collected via SurfaceIntel. | AXFR, wildcard DNS experiments, guessed DKIM selectors, registrar/WHOIS calls, takeover confirmation |
| TLSWatch | Original `audit_certificate` and `add` helpers against an already-collected public certificate, no network. | Separate direct connections, protocol/cipher sweeps, an independent chain-verification verdict |
| SurfaceIntel | Original scope/config validation, destination checking, rate limiting, DNS queries, pinned curl transport, fixed CT transport and TLS lifecycle inspection. | Cloud object/listing checks, webhooks, baseline promotion, scheduler activation in this orchestrator |

## Adapter implementation

`adapters/transport.sh` loads only fixed, shipped SurfaceIntel modules, never scope/config text as shell. A private line-oriented subprocess interface accepts HEAD/GET, specific DNS record types, one configured CT root, and TLS inspection. The Python coordinator enforces authorization, URL/path/scheme/port rules and limits; SurfaceIntel revalidates names and all destination addresses before active connections. The transport is an internal component, **not a public standalone API**: invoking it separately bypasses coordinator-level URL-policy checks.

`adapters/headerguard.awk`, `dnsshield-local.sh`, `tlswatch-local.sh` and `reconscope-local.sh` contain extracted local-only helpers. The original entry points are preserved under `vendor/` for source provenance but never sourced wholesale. Untrusted response text is not evaluated as shell, Python or JavaScript. Extraction avoids the legacy scripts' automatic `main` calls and network defaults.

`adapters/urlminer-patterns.json` holds original URLMiner classification constants. These are heuristics, not a file-format or sensitivity oracle. Query values and credential-shaped URL values are discarded before exports. JS literal detection produces only a label, redacted placeholder and low-confidence review status—not a credential dump or validity claim.

## Source provenance and versioning

`vendor/SOURCES.json` records the original workspace entry-point hashes. Original scripts and README/license notices remain with their tool. `MANIFEST.sha256` covers the complete shipped bundle, including the modified/extracted adapters, orchestration code, schemas and reports. No external source changes are silently fetched on startup.

The original tool directories outside this new project were not modified. Their historical versioned archives are independent deliverables. WebScope is versioned separately because its safe coverage profile intentionally differs from the full standalone tools.

## Extending safely

A future plugin must consume sanitized observations or route requests through the centralized authorization/transport layer. Do not simply shell out to a crawler and assume a root-domain parameter controls redirects, DNS rebinding, private IPs, inherited proxies, cloud tenancy or authentication. API tokens, authenticated crawling, write operations and distributed jobs require a separately reviewed interface; none are present here.
