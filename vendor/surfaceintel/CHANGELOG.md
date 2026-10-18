# Changelog and version policy

## 1.0.0-rc1 — 2026-10-17

Initial runnable controlled-deployment candidate:

- Modular Bash scope, discovery, DNS, HTTP, cloud metadata, TLS, drift, alerts and reports.
- Non-executable validated configuration/state; explicit endpoint/resource authorization, IPv4/IPv6 and metadata/redirect/rebinding guards, pinned curl/OpenSSL connections.
- Local/imported candidates plus opt-in bounded CT adapter; persistent provenance, no naming guesses or range sweeps.
- Conservative management heuristics; provider-specific anonymous HEAD classification and opt-in S3 zero-object listing checks.
- Versioned baseline schema, atomic explicit promotion, archive retention, partial/interrupted preservation, customer/baseline locks and stable fingerprints.
- Slack/Discord/Teams Workflows payload adapters, redaction, filters, destination-aware cooldown/deduplication and bounded retries.
- JSON schemas, text/daily/weekly/HTML reports, installation and opt-in scheduling templates, security/operational guidance and isolated regression suite.

Limitations: serial execution (concurrency is an upper bound), strict URL/provider subsets, no automatic unauthenticated-admin confirmation, no live third-party tool runner, no real cloud/provider/timer deployment qualification. See validation documentation for actual results rather than treating the feature list as native-platform certification.

## Versioning

Semantic versioning applies to the tool. State and public JSON schemas have independent explicit versions. Incompatible state/schema changes require a new major schema version and reviewed migration; unsupported versions fail closed. Update `config_version` when approved expectations change. Review scope/policy digests before comparing unlike runs. Release artifacts include internal and external SHA-256 manifests; checksums detect corruption, not publisher authenticity. Signing and fleet rollout approval remain deployment responsibilities.
