# URLMiner v1.0.0

**Passive Endpoint & Parameter Harvester** — a single-file Bash tool that mines web
archives and live sites for hidden endpoints, API routes, query parameters and
exposed configuration files.

Part of the *Recon & Asset Discovery Pipeline* (Day 2). Takes the live targets
produced on Day 1 and turns them into a clean, filtered endpoint list.

```
  Day 1 (ReconScope)                 Day 2 (URLMiner)
  results/<domain>/live/       -->   results/<target>/urls/
    live_hosts.txt                     all_urls.txt
                                       params.txt
                                       sensitive_files.txt
                                       api_endpoints.txt
                                       js_files.txt
                                       js_routes.txt
```

---

## Why it exists

Scanning a domain tells you what is *open*. It does not tell you what the
application *exposes*. A forgotten `backup.sql`, an API route that was never
documented, a `?redirect=` that accepts a full URL, or a `/api/v1/` prefix
buried in a minified bundle — none of that shows up in a port scan.

URLMiner harvests URLs from places that already have them (the Wayback Machine,
Common Crawl, AlienVault OTX) and from the target itself, then sorts what it
finds into actionable buckets.

**100% free and open source. No API keys. No paid services. No account.**

---

## Requirements

| Tool | Used for | Required? |
|---|---|---|
| `bash` | the script itself (4.4+) | **yes** |
| `curl` | archive queries + local crawl | **yes** |
| `sed`, `awk`, `grep`, `sort`, `tr` | normalisation & filtering | **yes** |
| `gau` | passive URL scraping (preferred) | optional |
| `waybackurls` | Wayback Machine scraping | optional |
| `uro` | URL de-duplication | optional |

The three Go tools are **optional accelerators**. If they are missing, URLMiner
prints the exact `go install` command and falls back to its built-in tier:

```bash
go install -v github.com/lc/gau/v2/cmd/gau@latest          # gau
go install -v github.com/tomnomnom/waybackurls@latest       # waybackurls
go install -v github.com/s0md3v/uro@latest                  # uro
```

Use `--strict` if you want the tool to abort instead of falling back.

### Built-in archive tier

When `gau` / `waybackurls` are absent, URLMiner queries the archives directly
with `curl`:

| Archive | Endpoint | Notes |
|---|---|---|
| Wayback Machine | `web.archive.org/cdx/search/cdx` | `fl=original&collapse=urlkey` |
| Common Crawl | `index.commoncrawl.org/<index>-index` | needs a `User-Agent` header + retries |
| AlienVault OTX | `otx.alienvault.com/api/v1/indicators/domain/<host>/url_list` | no key required |

All three are verified working. Select a subset with
`--providers wayback,commoncrawl,alienvault`.

---

## Installation

```bash
git clone <this-repo> && cd urlminer
chmod +x urlminer.sh
```

That is the whole installation — it is one Bash file with no runtime
dependencies beyond core Linux utilities.

---

## Usage

```bash
# Single domain, everything enabled
./urlminer.sh -d example.com

# Batch: consume Day 1's live_hosts.txt
./urlminer.sh -d example.com -l results/example.com/live/live_hosts.txt

# Custom output directory
./urlminer.sh -d example.com -o ./scans

# Archive query only, no active crawling
./urlminer.sh -d example.com --no-crawl --no-js

# Re-categorise a previous harvest without touching the network
./urlminer.sh -d example.com --seed results/example.com/urls/raw_urls.txt
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-d, --domain <domain>` | — | Target domain. Also the output directory label. |
| `-l, --list <file>` | auto | Batch input list. When omitted, URLMiner auto-detects `results/<domain>/live/live_hosts.txt`. |
| `-o, --output <dir>` | `./results` | Output base directory. |
| `-t, --threads <n>` | `20` | Archive query concurrency. |
| `--limit <n>` | `2000` | Max URLs per host per archive. |
| `--timeout <sec>` | `12` | HTTP timeout for the local crawl. |
| `--providers <list>` | `all` | `wayback,commoncrawl,alienvault`. |
| `--seed <file>` | — | Re-use a saved harvest instead of querying archives. |
| `--no-crawl` | off | Skip the local crawl stage. |
| `--no-js` | off | Skip downloading JavaScript for route extraction. |
| `--js-max <n>` | `60` | Max JS files to download. |
| `--noise-ext <list>` | — | Extra extensions to treat as noise. |
| `--strict` | off | Abort when the optional Go tools are missing. |
| `-v, --verbose` | off | Verbose per-host logging. |
| `--no-color` | off | Disable ANSI colours. |
| `-h, --help` | — | Help banner and exit. |

---

## Output

Everything lands in `results/<target>/urls/`:

| File | Contents |
|---|---|
| **`all_urls.txt`** | ★ cleaned, de-duplicated, noise-filtered URL set |
| **`raw_urls.txt`** | every URL exactly as harvested |
| **`params.txt`** | ★ URLs carrying query parameters |
| `param_names.txt` | distinct parameter names |
| `sensitive_params.txt` | high-value parameter names (`id`, `redirect`, `file`, `token` …) |
| **`sensitive_files.txt`** | ★ backups, configs, credentials |
| `sensitive_details.tsv` | what makes each one interesting |
| **`api_endpoints.txt`** | ★ `/api/`, `/graphql`, `/rest/`, `/v1/` … |
| **`js_files.txt`** | ★ every JavaScript file |
| `js_routes.txt` | API routes extracted from those JavaScript files |
| `js_routes_other.txt` | non-API routes found in the same bundles |
| `interesting_paths.txt` | non-parameter paths worth a look |
| `unique_hosts.txt` | distinct hosts seen |
| `endpoints_by_host.txt` | breakdown per host |
| `local_urls.txt` | results of the local crawl |
| `urlminer.log` | timestamped run log (ANSI-free) |
| `urlminer_summary.txt` | machine-readable counts |

★ = the four modules named in the pipeline spec.

---

## The four modules

### Module 1 — Parameter mining → `params.txt`

Every URL with a query string, plus `param_names.txt` and
`sensitive_params.txt` (names worth fuzzing: `id`, `uid`, `user`, `email`,
`password`, `token`, `api_key`, `redirect`, `next`, `file`, `path`, `cmd`,
`callback`, `jsonp`, `session`, `csrf_token`, `otp`, …).

Array-style names are normalised (`filter[]=x` → `filter`).

### Module 2 — Sensitive extensions → `sensitive_files.txt`

`.sql`, `.env`, `.bak`, `.old`, `.orig`, `.json`, `.log`, `.yaml`, `.yml`,
`.config`, `.conf`, `.ini`, `.pem`, `.key`, `.p12`, `.pfx`, `.keystore`,
`.jks`, `.zip`, `.tar.gz`, `.dump`, `.swp`, `.git`, `.htpasswd`, `.DS_Store`,
`/.aws/credentials`, `/.ssh/id_rsa` and friends — matched either as a file
extension or as a sensitive path fragment.

`sensitive_details.tsv` records *why* each URL was flagged.

### Module 3 — API & endpoint sorting → `api_endpoints.txt`

URLs matching `/api/`, `/apis/`, `/rest/`, `/graphql`, `/gql`, `/rpc`, `/ws`,
`/webhook`, `/oauth`, `/v1/`…`/v9/`, `/swagger`, `/openapi`, and
`.json` / `.xml` API responses.

### Module 4 — JavaScript → `js_files.txt` + `js_routes.txt`

Every `.js` / `.mjs` / `.cjs` URL is recorded, then the files are downloaded
and scanned for quoted route-like strings. Routes that look like API
endpoints land in `js_routes.txt`; everything else in `js_routes_other.txt`.
Single-segment routes such as `/graphql` are deliberately kept.

---

## Noise filtering

Automatically dropped, by default:

```
.png .jpg .jpeg .gif .svg .ico .webp .bmp .tiff
.woff .woff2 .ttf .eot .otf
.css .map
.mp3 .mp4 .avi .mov .webm .flv .m4a
.pdf .doc .docx .xls .xlsx .ppt .pptx .zip .rar .7z .gz
```

Add your own with `--noise-ext exe,bin,iso`.

---

## Terminal UI

| Colour | Meaning |
|---|---|
| **Blue / Cyan** | stage headers, extraction progress bars |
| **Green** | counts and successful results |
| **Red** | errors, invalid input, missing dependencies |
| **Yellow** | warnings, fallbacks, skipped work |

The run ends with a boxed summary table:

```
╔════════════════════════════════════════════════╗
║  URLMiner - Execution Summary                  ║
╠════════════════════════════════════════════════╣
║  Target                              example.com║
║  Hosts processed                              1║
║  Duration                              00:00:24║
╠────────────────────────────────────────────────╣
║  Total URLs (raw)                          2300║
║  Total URLs (kept)                         2185║
║  Noise filtered                              95║
║  Unique hosts                               104║
║  Local crawl URLs                             1║
╠────────────────────────────────────────────────╣
║  Parameters found                            29║
║  Sensitive paths found                       32║
║  API endpoints found                         26║
║  JavaScript files                             6║
║  JS API routes                                0║
║  Exposed sensitive files                      0║
╠────────────────────────────────────────────────╣
║  Output: results/example.com/urls             ║
║  Summary: urlminer_summary.txt                ║
╚════════════════════════════════════════════════╝
```

(The same counts are written to `urlminer_summary.txt` for machine consumption.)

---

## Pipeline integration

URLMiner is Day 2 of the recon pipeline. It consumes Day 1's output directly:

```bash
# Day 1 — ReconScope
./reconscope.sh -d example.com
#  -> results/example.com/live/live_hosts.txt

# Day 2 — URLMiner
./urlminer.sh -d example.com -l results/example.com/live/live_hosts.txt
#  -> results/example.com/urls/
```

If `-l` is omitted, URLMiner looks for `results/<domain>/live/live_hosts.txt`
on its own.

---

## Testing

```bash
./tests/run_tests.sh
```

The suite is self-contained — it builds fixtures in a temp directory, starts
real local HTTP servers, and cleans up after itself:

| Run | What it covers |
|---|---|
| 1 | Every module classifies a planted 30-URL corpus correctly, and noise is dropped |
| 2 | The local crawl really fetches pages, follows links, finds form actions and detects an exposed `/.env` |
| 3 | CLI behaviour: help, invalid flags, missing inputs, output structure, ANSI-free logs |
| 4 | JavaScript route extraction from a real served bundle |

Latest run: **57 assertions, 57 passing, 0 failing.**

---

## Code quality

```bash
bash -n urlminer.sh          # syntax
shellcheck -S warning urlminer.sh   # static analysis — clean
```

---

## Design notes

* `set -euo pipefail` throughout, with every failure-prone pipeline written so
  a non-zero status cannot abort the run mid-harvest.
* **No `head` inside a command substitution** — `head` closes the pipe early,
  `pipefail` sees SIGPIPE (141) and `set -e` kills the script. `awk` is used
  for truncation instead.
* **The EXIT trap preserves the real exit code** instead of masking it with
  `exit 0`.
* POSIX-portable `awk` (`mawk` compatible) — no `IGNORECASE`, no gawk-only
  extensions.
* A backslash does **not** escape `]` inside a POSIX bracket expression, so
  character classes are kept unambiguous and array suffixes are matched as a
  separate optional group.
* One `awk` pass per module instead of a `grep` fork per URL — the difference
  between seconds and minutes on a 100k-URL harvest.
* No writes outside the output directory, no `sudo`, no destructive operations.

---

## Legal

Only requests public archives and URLs belonging to the targets you specify.
Use it on systems you are authorised to test. The archives queried are public
and read-only.

---

## License

MIT
