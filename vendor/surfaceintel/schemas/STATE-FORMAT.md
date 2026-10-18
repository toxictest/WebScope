# SurfaceIntel state schema v1

The baseline is **TSV, not executable shell and not JSON**. This deliberate format permits mandatory structural validation without jq/Python. Public reports use the accompanying JSON Schemas. `lib/state_store.sh::validate_state` is the authoritative baseline validator.

UTF-8 text, LF line endings; no NUL, CR or other control bytes except TAB/LF. Maximum 8 MiB, 12,000 records, 8,192 bytes per row. Exactly nine nonempty fields per line. File must be readable, regular and not a symlink.

Header columns:

1. Literal `SURFACEINTEL_STATE`
2. Schema version `1`
3. Organization identifier, matching the current explicit scope
4. Scope digest: 64 lowercase hexadecimal characters
5. Policy digest: 64 lowercase hexadecimal characters
6. Completion: `complete`, `partial` or `interrupted`
7. Collection epoch, 10–12 decimal digits
8. Mode: `normal|passive|dns|tls`, followed by `-<HTTP flag>-<cloud flag>` (0/1)
9. Literal `END`

Data columns:

1. Kind: `asset`, `dns`, `http`, `tls`, `cloud`, `finding`
2. Stable record ID: SHA-256 of `kind|asset-key`
3. Asset key: hostname/literal IP/URL; findings use `CATEGORY|asset`
4. Uppercase status (letters, digits, underscore)
5. Normalized nonvolatile observation fingerprint: 64 lowercase hex characters
6. Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
7. First-seen epoch for the current historical record
8. Last-seen epoch
9. Nonempty bounded ASCII-sanitized evidence/metadata description

IDs must be unique and match their kind/asset key. Digests must be syntactically valid; they are **not signatures** or proof that an untrusted historical observation was truthful. Only a complete snapshot may be used as a baseline. Unknown schema versions are rejected; no automatic migration or file execution occurs.

Public JSON records add a kind-independent `asset_id`. Findings expose category, confidence, first/last seen, verification method, scope status, baseline change, remediation and policy reference as explicit properties. Time values are UTC Unix seconds. TTLs and days-remaining appear in evidence but are excluded from the relevant semantic fingerprints.

Provenance, rejection, delta, errors and delivery files are separate small TSV reports, not executable state. `delta.tsv` columns are event, record ID, kind, asset key, severity. Scope removals and unavailable records are not equivalent to confirmed resolved exposure.
