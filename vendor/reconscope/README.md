# ReconScope

**Automated Subdomain & Live Host Discovery Pipeline** — a single, dependency-light Bash script that passively enumerates subdomains for a target domain, filters down to live web assets, categorises them by HTTP status, and produces human-readable + machine-readable reports.

> 100% free & open-source. **No paid APIs. No API keys. No subscriptions.**

---

## Features

| Stage | What happens |
|---|---|
| **0 — Verify** | Checks `subfinder`, `assetfinder`, `httpx` (ProjectDiscovery), `jq`, `curl`. Prints the exact `go install` / `apt` command for anything missing and exits cleanly — nothing is half-scanned. |
| **1 — Prepare** | Validates & normalises the domain (`https://Example.com/path` → `example.com`), builds `results/<domain>/` with `subdomains/ live/ categories/ reports/ logs/`. |
| **2 — Discover** | Runs **subfinder** (`-all`, free sources) and **assetfinder** (`--subs-only`), plus **crt.sh** CT logs and the **Wayback CDX** index. Everything is normalised to bare hostnames (wildcards, schemes, userinfo, ports and paths stripped) and de-duplicated into `all_subdomains.txt`. |
| **3 — Probe** | Runs **httpx** over the merged list to extract status code, page title, content length, web server, technologies, IP and CNAME. Uses native JSON output when available and falls back to legacy text mode automatically. |
| **4 — Categorise** | Buckets hosts into `status_200 / 301 / 302 / 403 / other`, and flags **high-value targets** (dev, staging, admin, api, vpn, portal…) using both host-name and page-title heuristics. |
| **5 — Report** | Writes `summary.txt`, `summary.md`, `summary.json` and a self-contained `report.html`. |

---

## Install

```bash
chmod +x reconscope.sh install_deps.sh
./install_deps.sh          # installs everything that is missing
```

Or install the tools yourself:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/anew@latest          # optional
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest   # optional
sudo apt-get install -y jq curl                          # or: brew install jq curl
```

### ⚠️ The `httpx` name collision

The PyPI package `httpx` (a Python HTTP client) and ProjectDiscovery's `httpx` are **different projects with the same binary name**. Installing the Python one breaks most recon tooling.

ReconScope detects this automatically: it runs `httpx -version` and only accepts a binary that identifies itself as ProjectDiscovery. If the wrong one is on your `PATH` you get a clear error instead of a confusing crash.

**Fix:** install the Go version and make sure `$HOME/go/bin` comes first in `PATH`.

---

## Usage

```
./reconscope.sh -d <domain> [options]
```

| Flag | Description | Default |
|---|---|---|
| `-d, --domain <domain>` | Target domain (**required**) | — |
| `-o, --output <dir>` | Output root directory | `./results` |
| `-t, --threads <n>` | Concurrent probe threads | `50` |
| `--timeout <sec>` | Per-request HTTP timeout | `10` |
| `--rps <n>` | Max requests/second handed to httpx | `150` |
| `--status <codes>` | Status codes treated as live | `200,301,302,403` |
| `--no-web` | Skip crt.sh + Wayback collectors | off |
| `--deep` | Extra ports (8080,8443,8000,3000,5000) + DNS resolution via `dnsx` | off |
| `--only <tools>` | Restrict the recon tool set, e.g. `subfinder,httpx` | all |
| `-v, --verbose` | Debug logging | off |
| `--no-color` | Disable ANSI colours | auto (off when piped) |
| `-h, --help` | Help menu | — |

### Examples

```bash
# standard run
./reconscope.sh -d example.com

# custom output folder + higher concurrency
./reconscope.sh -d example.com -o ./scans -t 100

# deep scan: extra ports + DNS resolution
./reconscope.sh -d example.com --deep

# fully offline-safe: only the Go tools, no web APIs
./reconscope.sh -d example.com --only subfinder,httpx --no-web

# treat 500s as interesting too
./reconscope.sh -d example.com --status 200,301,302,403,500
```

---

## Output layout

```
results/<domain>/
├── subdomains/
│   ├── subfinder.txt          raw subfinder results
│   ├── assetfinder.txt        raw assetfinder results
│   ├── crt_sh.txt             raw certificate-transparency results
│   ├── wayback.txt            raw Wayback CDX results
│   ├── resolved_ips.txt       DNS resolutions (--deep)
│   └── all_subdomains.txt     ★ merged + de-duplicated
├── live/
│   ├── live_hosts.txt         ★ live asset URLs, one per line
│   ├── live_hosts_details.tsv url | status | title | size | tech | server | ip | cname
│   ├── live_hosts.json        raw httpx JSON
│   ├── hosts_probed.txt       every host that responded
│   └── httpx_raw.jsonl        unmodified probe output
├── categories/
│   ├── status_200.txt         ★ category buckets
│   ├── status_301.txt
│   ├── status_302.txt
│   ├── status_403.txt
│   ├── status_301_302.txt
│   ├── status_other.txt
│   ├── high_value.txt         ★ dev/staging/admin/api/vpn/portal … for manual review
│   ├── tech_breakdown.txt
│   └── webserver_breakdown.txt
├── reports/
│   ├── report.html            ★ self-contained visual report
│   ├── summary.md
│   ├── summary.json
│   └── summary.txt
└── logs/reconscope.log
```

### Chaining with other tools

```bash
# nmap the live hosts
nmap -p 80,443 -iL results/example.com/live/live_hosts.txt

# feed httpx results into nuclei
cat results/example.com/live/live_hosts.txt | nuclei -silent

# only the interesting hosts
cat results/example.com/categories/high_value.txt
```

---

## Code quality

* `set -euo pipefail` with `pipefail` guarded pipelines.
* Modular functions: `check_deps`, `preflight`, `gather_subs`, `collect_crt_sh`, `collect_wayback`, `resolve_dns`, `probe_hosts`, `parse_json_results`, `parse_text_results`, `categorize`, `generate_summary`, `render_html_report`, `print_console_summary`.
* Every variable expansion is quoted; no `eval`; no word-splitting on untrusted input.
* External tools are always invoked with a wall-clock `timeout` so one hung source can never stall the pipeline.
* Domain input is validated against a strict hostname regex before anything is executed.
* Colour output auto-disables when stdout is not a TTY, and honours the `NO_COLOR` standard.
* Temporary files live in a `mktemp -d` scratch directory and are removed by an `EXIT`/`INT`/`TERM` trap.

---

## Legal & scope

Use ReconScope only against assets you own or have explicit written authorisation to assess. The discovery stage is purely passive (public certificate-transparency logs, the Wayback Machine, and the tools' own free passive source lists); the probing stage sends HTTP requests to hosts that resolve under the target domain. Keep `--rps` and `--timeout` conservative when scanning third-party infrastructure.

## License

MIT.
