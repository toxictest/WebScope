# WebScope

**One authorized domain → scoped subdomains, linked paths, JavaScript references and sensitive-path metadata.**

Version **1.0.0-rc2** · local CLI · Bash launcher + Python 3 standard-library orchestrator · existing tool components · no paid API or required account.

This integrates safe components from **ReconScope, URLMiner, HeaderGuard, DNSShield, TLSWatch and SurfaceIntel**. It does **not** blindly execute their standalone scanners. Only the vendored SurfaceIntel transport performs active DNS/HTTP/TLS operations. Host auditors such as KernelGuard, ProcSentry and AuditSync cannot meaningfully audit a remote host from its domain and are deliberately not launched.

## Quick start

```bash
chmod +x webscope.sh
./webscope.sh example.invalid --dry-run

# ONLY after replacing the example with assets you own or are authorized to test:
./webscope.sh example.org --authorized --include-subdomains --ct
```

`example.org` above is a documentation example, not permission to scan it. One domain is the target input; authorization/provider flags are explicit. `--ct` queries the fixed `crt.sh` provider. Without it, discovery uses the configured root, in-scope linked hosts and optional imported lists, **not an invented list of subdomain guesses**.

```bash
# Import an existing ReconScope/plain-hostname export; do not execute external tools:
./webscope.sh your-domain.example --authorized --include-subdomains \
  --import-hosts /private/subdomains.txt \
  --exclude vendor.your-domain.example --exclude-path /customer-data/ \
  --output /private/webscope-reports
```

The default initial service is HTTPS/443. `--allow-http` permits in-scope HTTP links; for an HTTP-only initial service use `--allow-http --port 80`. For a custom service use `--port N`; with `--allow-http` and no authorized port 443 the initial service is HTTP, otherwise HTTPS. Additional `--port` values allow linked services; **there is no port sweep**. One initial service per host is selected, favoring HTTPS/443, otherwise the lowest configured port.

## Dependency setup

```bash
git clone https://github.com/toxictest/WebScope.git
cd WebScope
bash install_deps.sh --check        # no changes
bash install_deps.sh --plan         # review OS package list
sudo bash install_deps.sh --install # explicitly install runtime + TLS dependencies
bash webscope.sh example.invalid --dry-run
```

Debian/Ubuntu and Fedora/RHEL-family package-manager recipes are included; only Debian planning/checking was exercised here. Other distributions require manual setup. `requirements.txt` intentionally contains no pip runtime dependencies: **pip alone cannot install curl, dig or the other OS tools**. See [DEPENDENCIES.md](DEPENDENCIES.md) for optional tests, development venv setup and troubleshooting. The helper never runs a scan or configures a service; package-manager hooks can still run during explicit installation.

## What you get

- Root/imported/CT/linked subdomains, exact domain-tree filtering and provenance.
- `robots.txt` and root `sitemap.xml` discovery; conservative robots exclusions.
- HTML navigation, script tags, module-preload/script-preload links, bounded JS import/string references and source-map **URLs**.
- Inferred URL directory prefixes, **not proof of server filesystem directories**.
- Sensitive-path candidates from observed links, using URLMiner-derived patterns. HEAD/status only: HTTP 200 is **not confirmed secret exposure**.
- Low-confidence potential credential literals in already-fetched public JS/inline scripts, with values **redacted**, never tested for validity.
- DNS A/AAAA/CNAME/MX/NS/TXT observations (TXT hashes only), offline provider hints, TLS lifecycle/local certificate checks, header presence and cookie-flag observations.
- JSON, self-contained escaped HTML, summary text and separate URL/subdomain/JS/route/candidate lists.

**No exhaustive discovery guarantee.** Authenticated content, unlinked files, complex dynamic imports, JS runtime-generated URLs, disallowed/query-bearing URLs, large bundles and other ports can be missed. JavaScript is never executed. Raw page/JS bodies are **not** saved or offered as downloads; discovered JS URLs, body hashes and route hints are exported instead.

## Safe defaults

- No scan without `--authorized`; `--dry-run` makes no network requests or report directories.
- Root-only authorization unless `--include-subdomains` is explicit. Excluded trees and path prefixes are rechecked before requests.
- Public resolved destinations by default; loopback/private destinations require **both** `--allow-nonpublic` and precise `--cidr` entries. Well-known metadata endpoints remain blocked.
- All returned addresses checked; one address pinned for the connection. External CNAMEs require exact `--allow-cname NAME` approval; this does not authorize scanning that provider name.
- No inherited curl proxy or `.curlrc`, no automatic curl redirects, no TLS-verification bypass, no credentials/cookies sent.
- Redirects are separately queued and revalidated for domain, scheme, port and path. No token-bearing query URLs are fetched; query values are omitted from exports.
- No wordlists, directory brute force, exploit templates, AXFR, selector guessing, form submission, authentication testing, uploads or permission changes.
- Sensitive filenames, backups, config/JSON/XML data and source maps get metadata-only treatment. Only the fixed root `/sitemap.xml` is eligible for XML-body discovery; nested XML sitemap candidates remain metadata-only.
- Public page/JS GETs require an approved HEAD MIME type first; every GET is re-resolved and pinned. A server can still return unexpected content despite HEAD; such bounded responses are discarded, not saved. This is not proof that every public page is non-sensitive.
- Fixed **64 KiB response-body cap**, serial processing, bounded requests/depth/hosts/URLs/timeouts, partial reporting when collection limits or errors are encountered.
- Private reports, a per-output lock and transient-body cleanup. No telemetry, automatic upload, scheduled job, GitHub publication or system dependency installation.

## Requirements

Linux; Bash 4.4+; Python **3.9+**; curl; **dig**; GNU-style utilities (`awk`, `sha256sum`, `date`, `stat`, `sort`, `sed`, `grep`, `cut`, `diff`, `cmp`, `tr`, `mktemp`, `find`, `head`, `tail`, `wc`). Python uses only its standard library at runtime. OpenSSL + GNU `timeout` enable certificate inspection; absence produces incomplete TLS coverage, not a valid-certificate conclusion.

Development tests additionally use OpenSSL, Python `jsonschema`, and preferably ShellCheck. Nothing is automatically installed.

## Options

Run `./webscope.sh --help` for the complete CLI.

| Option | Default / purpose |
|---|---|
| `--authorized` | Operator acknowledgement of ownership/written authorization |
| `--dry-run` | Validate inputs; no network/output creation |
| `--include-subdomains` | Authorize the exact root and its subdomain tree |
| `--ct` | Explicit bounded `crt.sh` query; requires tree authorization |
| `--import-hosts FILE` | Repeatable bounded plain-hostname imports |
| `--exclude DOMAIN` | Repeatable excluded domain/subdomain tree |
| `--exclude-path /prefix/` | Repeatable excluded path prefix across authorized hosts |
| `--allow-cname NAME` | Explicit resolution-chain approval, not new asset scope |
| `--allow-http`, `--port N` | Permit schemes/ports; defaults HTTPS/443 |
| `--allow-nonpublic`, `--cidr NETWORK` | Joint explicit nonpublic destination authorization |
| `--ca-file FILE` | Protected public CA bundle; no private keys or insecure mode |
| `--output DIR` | `./webscope-reports`; existing root must be owned and mode 0700 |
| `--max-hosts N` | 32; maximum 128 |
| `--max-urls N` | 200; maximum 2000 |
| `--max-requests N` | 400; maximum 4000 HTTP/TLS/provider operations; DNS lookups additional |
| `--depth N` | 3; maximum 8 |
| `--budget SECONDS` | 600; 10–3600 collection deadline |
| `--timeout SECONDS` | 6; 1–30 per transport request |
| `--rate N` | 2; 1–10/sec **per DNS and HTTP/TLS channel**, serial engine |

Exit codes: **0** complete within declared policy/limits, not exhaustive; **2** configuration/dependency/output error; **3** partial collection; **75** overlap lock; **130** SIGINT; **143** SIGTERM. Intentional policy exclusions are recorded and do not automatically imply a failed audit.

## Reports

Each run gets a new private `run-...` directory. Nothing overwrites a prior report or promotes a historical baseline.

| File | Contents |
|---|---|
| `report.json` | Unified evidence, scope digest, integration roles, limits and incomplete coverage |
| `report.html` | Self-contained escaped summary and URL evidence table |
| `summary.txt` | Counts, completion and caveats |
| `subdomains.txt` | In-scope candidate names, not necessarily live |
| `all_urls.txt` | Canonical observed URLs; query values removed, not all fetched |
| `directories.txt` | Inferred URL prefixes only |
| `js_files.txt` | Observed JS URLs; consult JSON for fetch status/query omission |
| `route_hints.txt` | JS-derived hints; HEAD-only, no API execution |
| `sensitive_candidates.txt` | Candidate paths, **not a confirmed-secrets list** |

`INCOMPLETE` means report finalization did not finish. Even without that marker, consult `report.json` completion/errors. A partial report is still useful but is not evidence of absence or asset removal. Scope hashes include exclusions, CNAME/CIDR settings, ports and the initial custom-CA content hash; the system trust store is not hashed.

## Validation and documentation

- [Integration boundaries and source provenance](docs/INTEGRATIONS.md)
- [Security and operational guide](SECURITY.md)
- [Installation and operation](INSTALL.md)
- [Actual validation results and limitations](docs/VALIDATION.md)
- [Report schema](schemas/report.schema.json)
- [Controlled local example](examples/controlled-local/report.html)
- [Changelog](CHANGELOG.md)

```bash
./tests/run_tests.sh
bash vendor/surfaceintel/tests/run_tests.sh
```

Release status: **controlled-deployment candidate**, not independently security-reviewed or universally production-qualified. Original tools remain independently usable under their own requirements, but their standalone profiles do not inherit WebScope's transport protections.
