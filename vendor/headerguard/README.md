# HeaderGuard v1.0.0

**Automated Security Headers & CORS Policy Auditor** — a single-file Bash tool
that inspects HTTP response headers and reports missing or weak security
headers, banner leakage, CORS misconfiguration and unsafe cookie attributes.

It takes Day 1's `live_hosts.txt` (or a single URL) and produces a
per-target compliance score with a plain-text or CSV report.

```
  Day 1 (ReconScope)                 Day 2 (HeaderGuard)
  results/<domain>/live/       -->   headerguard_report.txt
    live_hosts.txt                    target,grade,score,headers_passed,...
```

---

## Why it exists

A port scan tells you a host is open. It does not tell you that the host
sends `Access-Control-Allow-Origin: *` together with
`Access-Control-Allow-Credentials: true`, that its CSP still allows
`unsafe-inline`, or that it hands out session cookies with neither `Secure`
nor `HttpOnly` set.

HeaderGuard asks the server those questions directly and answers with a score
you can track over time or gate a pipeline on.

**100% free and standalone. No API keys. No paid services. No Go, Python or
npm dependency.**

---

## Requirements

| Tool | Used for | Required? |
|---|---|---|
| `bash` | the script itself (4.4+) | **yes** |
| `curl` | HTTP requests and header capture | **yes** |
| `awk` | header normalisation | **yes** |
| `grep`, `sed`, `tr`, `sort` | text processing | **yes** |

That is the complete dependency list — all of them ship with every mainstream
Linux distribution. Nothing needs to be compiled, downloaded or paid for.

If a required tool is missing, HeaderGuard prints the exact install command
for your distribution and exits cleanly.

---

## Installation

```bash
chmod +x headerguard.sh
```

One file. No build step, no package manager, no configuration.

---

## Usage

```bash
# Single target
./headerguard.sh -u https://example.com

# Batch: consume Day 1's live_hosts.txt
./headerguard.sh -l results/example.com/live/live_hosts.txt -o report.txt

# CSV output for spreadsheets / CI
./headerguard.sh -l live_hosts.txt -o report.csv

# Fail the pipeline when anything is wrong
./headerguard.sh -l live_hosts.txt --strict -o report.txt
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-u, --url <url>` | — | Single target URL. |
| `-l, --list <file>` | — | Batch input, one URL or host per line. Entries without a scheme are audited over `https://`. |
| `-o, --output <file>` | `headerguard_report.txt` | Report file. |
| `--format <fmt>` | auto | `text`, `csv` or `auto` (by file extension). |
| `-t, --threads <n>` | `10` | Parallel audits. |
| `--timeout <sec>` | `10` | Per-request HTTP timeout. |
| `--connect-timeout <sec>` | `5` | Connect timeout. |
| `--origin <url>` | `https://headerguard-probe.invalid` | Origin sent by the CORS probe. |
| `--outdir <dir>` | — | Also write one detail file per target. |
| `--insecure` | off | Skip TLS certificate verification. |
| `--strict` | off | Exit `1` when any FAIL finding is recorded. |
| `-v, --verbose` | off | Verbose per-target logging. |
| `--no-color` | off | Disable ANSI colours. |
| `-h, --help` | — | Help banner and exit. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Audit completed (no failing checks in `--strict` mode). |
| `1` | `--strict` mode and at least one FAIL finding. |
| `2` | Usage error, missing dependency, or unreadable input. |

---

## The four modules

### Module 1 — Security headers

| Header | Passes when | Notes |
|---|---|---|
| `Strict-Transport-Security` | present with `max-age >= 15552000` (180 days) | Over plain HTTP it is ignored — flagged as ineffective. `includeSubDomains` noted. |
| `Content-Security-Policy` | present and enforcing | `report-only` does **not** count. `unsafe-inline` / `unsafe-eval` are flagged as weak. |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | A CSP containing `frame-ancestors` counts as covering clickjacking. `ALLOW-FROM` is deprecated. |
| `X-Content-Type-Options` | `nosniff` | |
| `Referrer-Policy` | a recognised value | Comma-separated lists are accepted if any value is valid. |
| `Permissions-Policy` | present | A policy permitting everything (`=*`) is flagged. |

### Module 2 — Information disclosure

Flags `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNet-Mvc-Version`,
`X-Generator`, `X-Runtime`, `X-Shopify-Stage`, `X-Drupal-Cache`,
`X-Debug-Token` and `X-AspNet-Duration`, noting when a version number is
leaked.

### Module 3 — CORS policy

A second request is sent with `Origin: https://headerguard-probe.invalid`
(a reserved TLD that can never be a real caller) and the response is checked:

| Response | Verdict |
|---|---|
| no `Access-Control-Allow-Origin` | **PASS** — cross-origin access is blocked |
| a fixed, specific origin | **PASS** — proper allowlist |
| `*` | **FAIL** — any origin allowed |
| `*` + `Access-Control-Allow-Credentials: true` | **FAIL, critical** |
| echoes the probe origin | **FAIL** — arbitrary origin reflection |
| echoes the probe origin + credentials | **FAIL, critical** |
| reflects without `Vary: Origin` | **WARN** — shared cache poisoning risk |
| `Access-Control-Allow-Methods: *` / `-Headers: *` | **WARN** |

### Module 4 — Cookie flags

Every `Set-Cookie` header is checked for:

* `Secure` — **FAIL** over HTTPS, **WARN** over plain HTTP
* `HttpOnly` — **WARN**
* `SameSite` — **WARN**
* `SameSite=None` without `Secure` — **FAIL**

---

## Scoring

```
  6 security headers passed      × 10  =  60 points
  no information disclosure              =  15 points
  CORS policy safe                       =  15 points
  all cookie attributes correct           =  10 points
                                        ----------
                                          100 points
```

Deductions: a missing or weak header scores 0 for that header; each
disclosure banner costs 5 points (capped at 15); a wildcard CORS policy costs
7, an origin-reflecting one costs 12; each missing cookie attribute costs 2
points.

| Grade | Score |
|---|---|
| A+ | ≥ 95 |
| A | ≥ 90 |
| B | ≥ 80 |
| C | ≥ 70 |
| D | ≥ 60 |
| F | < 60 |

The report also states the raw `X/6` header count, so you can see *why* a
target scored what it did.

---

## Output

### Console

Each target gets a colour-coded breakdown, followed by a summary table:

```
TARGET: https://github.com
  Final URL  : https://github.com/
  Status     : 200   TLS: yes   Redirects: 0   0.115278s
  Module 1 - Security headers
    [ OK ] Strict-Transport-Security    present (max-age=31536000, includeSubDomains)
    [WARN] Content-Security-Policy      weak directives: unsafe-inline
    [ OK ] X-Frame-Options              present (deny)
    [ OK ] X-Content-Type-Options       present (nosniff)
    [ OK ] Referrer-Policy              present (origin-when-cross-origin, strict-origin-when-cross-origin)
    [FAIL] Permissions-Policy           MISSING - powerful features not restricted
  Module 2 - Information disclosure
    [WARN] server                       github.com
  Module 3 - CORS policy
    [ OK ] Access-Control-Allow-Origin  not set - cross-origin access blocked
  Module 4 - Cookie flags
    [WARN] Cookie: _octo                missing HttpOnly attribute
  Score: 73/100   Headers: 4/6   Grade: C
```

| Colour | Meaning |
|---|---|
| **Green** | header present / secure / pass |
| **Red** | header missing / insecure / critical |
| **Yellow** | information disclosure / review needed |
| **Cyan** | informational note |

### Text report (`-o report.txt`)

A plain-text document with a header block, one section per target listing
every finding, and the score and grade. No ANSI escapes — it is safe to
`grep`, `diff` and attach to a ticket.

### CSV report (`-o report.csv`)

One row per target, for spreadsheets and CI dashboards:

```csv
target,final_url,status,tls_verified,redirects,reachable,grade,score,headers_passed,headers_total,disclosure_findings,cookies,cookie_issues,fail_count,warn_count
https://example.com,https://example.com/,200,yes,0,yes,F,35,0,6,1,0,0,6,1
https://github.com,https://github.com/,200,yes,0,yes,C,73,4,6,1,3,1,1,3
```

### Per-target detail files (`--outdir <dir>`)

One TSV per target, holding the score line and every finding:

```
https://example.com	200	35	F	headers=0/6
FAIL|M1|Strict-Transport-Security|MISSING - no HTTPS enforcement
WARN|M2|server|cloudflare
PASS|M3|Access-Control-Allow-Origin|not set - cross-origin access blocked
```

---

## Pipeline integration

```bash
# Day 1 - ReconScope
./reconscope.sh -d example.com
#  -> results/example.com/live/live_hosts.txt

# Day 2 - HeaderGuard
./headerguard.sh -l results/example.com/live/live_hosts.txt -o report.txt
```

Entries in the list may be bare hosts (`example.com`) — they are audited over
`https://` automatically.

---

## Testing

```bash
./tests/run_tests.sh
```

The suite starts a **real HTTPS server** (with a generated self-signed
certificate) that serves deliberately broken and deliberately hardened header
profiles, and asserts every module classifies them correctly.

| Run | What it covers |
|---|---|
| 1 | A fully hardened target — 6/6 headers, no disclosure, clean cookies, grade A+ |
| 2 | A bare target — every header missing, `Server` and `X-Powered-By` leaked |
| 3 | Four CORS profiles — wildcard, wildcard+credentials, origin reflection, wildcard methods |
| 4 | Cookie attributes — which flags are missing on which cookie |
| 5 | Edge cases — report-only CSP, weak CSP, short HSTS, plain HTTP, multi-value Referrer-Policy |
| 6 | CLI, text + CSV reports, unreachable targets, `--strict` exit codes |

Latest run: **64 assertions, 64 passing, 0 failing.**

---

## Code quality

```bash
bash -n headerguard.sh                 # syntax
shellcheck -S warning headerguard.sh   # static analysis — clean
```

---

## Design notes

* `set -euo pipefail` throughout, with every failure-prone pipeline written so
  a non-zero status cannot abort the run mid-audit.
* **Reachability is decided by the headers received, not by curl's exit
  code.** A server that closes TLS without a `close_notify` makes curl exit
  `56` even though a complete response arrived — treating that as
  "unreachable" would be wrong.
* **The embedded awk normaliser is compile-checked at startup.** If it ever
  fails to compile, the tool aborts with a clear error instead of silently
  reporting that every target has no headers at all.
* Header values are stripped of the trailing CR that CRLF responses leave
  behind, and duplicate headers are merged without introducing stray spaces.
* POSIX-portable `awk` (mawk compatible) — no `IGNORECASE`, no gawk-only
  extensions. Note that POSIX bracket expressions do not treat `\` as an
  escape, and awk's `print` inserts `OFS` between every expression — both
  bite hard when parsing tab-separated data.
* TLS certificates are verified by default. A verification failure is
  reported as a finding and the request is retried without verification so
  the headers can still be audited.
* HTTP/2 lowercases header names by specification, so findings echo exactly
  what the server sent.
* No writes outside the output path, no `sudo`, no destructive operations.

---

## Legal

Only sends ordinary `GET` requests to the targets you specify. The CORS probe
uses a reserved `.invalid` origin that can never resolve. Use it on systems
you are authorised to test.

---

## License

MIT
