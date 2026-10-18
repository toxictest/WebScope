#!/usr/bin/env bash
# ==============================================================================
#  ReconScope — Automated Subdomain & Live Host Discovery Pipeline
# ------------------------------------------------------------------------------
#  Version  : 1.0.0
#  License  : MIT
#  Category : Defensive Recon / Security Auditing Automation
#  Cost     : 100% free & open-source. No paid APIs. No API keys required.
#
#  Pipeline : Passive subdomains -> de-duplication -> HTTP probing
#             -> status categorisation -> reporting
#
#  Required : subfinder, assetfinder, httpx (ProjectDiscovery), jq, curl
#  Optional : anewer, dnsx, amass, naabu (used automatically when present)
#
#  Legal    : Use only against assets you own or are explicitly authorised to
#             test. Passive sources are queried; the HTTP probe touches only
#             the discovered hosts of the target domain.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Metadata
# ------------------------------------------------------------------------------
readonly SCRIPT_NAME="ReconScope"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_AUTHOR="ReconScope Contributors"

# ------------------------------------------------------------------------------
# Global configuration (defaults — overridden by CLI flags)
# ------------------------------------------------------------------------------
DOMAIN=""                       # target domain
OUTPUT_ROOT="results"           # root output directory
THREADS="50"                    # concurrency for probing
HTTP_TIMEOUT="10"               # per-request timeout in seconds
RPS="150"                       # max requests per second handed to httpx
LIVE_STATUS="200,301,302,403"   # status codes treated as "live"
USE_WEB="yes"                   # use web/API passive sources (crt.sh, wayback)
USE_DEEP="no"                   # extra ports + DNS resolution
VERBOSE="no"                    # verbose logging
COLOR="auto"                    # auto | always | never
TOOL_SET="all"                  # all | comma separated list of tool names

# Runtime state
OUT_DIR=""                      # results/<domain>
SUBDOMAIN_DIR=""                # results/<domain>/subdomains
LIVE_DIR=""                     # results/<domain>/live
CATEGORY_DIR=""                 # results/<domain>/categories
REPORT_DIR=""                   # results/<domain>/reports
LOG_DIR=""                      # results/<domain>/logs
TMP_DIR=""                      # scratch space
LOG_FILE=""                     # path to logfile
START_TS=0
SPIN_PID=""
HTTPX_BIN=""                    # resolved ProjectDiscovery httpx binary
HTTPX_MODE=""                   # json | text
HTTPX_JSON_FLAG=""              # -json or -jsonl, depending on httpx version

# ------------------------------------------------------------------------------
# Colour handling
# ------------------------------------------------------------------------------
C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_DIM=""; C_BOLD=""

init_colors() {
    local use=0
    case "$COLOR" in
        always) use=1 ;;
        never)  use=0 ;;
        auto)
            if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then use=1; fi
            ;;
    esac

    if [[ $use -eq 1 ]]; then
        C_RESET=$'\033[0m'
        C_BOLD=$'\033[1m'
        C_DIM=$'\033[2m'
        C_RED=$'\033[1;31m'
        C_GREEN=$'\033[1;32m'
        C_YELLOW=$'\033[1;33m'
        C_BLUE=$'\033[1;34m'
        C_CYAN=$'\033[1;36m'
    fi
}

# ------------------------------------------------------------------------------
# Logging helpers
# ------------------------------------------------------------------------------
_now() { date '+%H:%M:%S'; }
_stamp() { date '+%Y-%m-%d %H:%M:%S'; }

log_line() {
    local level="$1" color="$2" msg="$3"
    printf '%s[%s]%s %s%-7s%s %s\n' \
        "$color" "$(_now)" "$C_RESET" "$color" "$level" "$C_RESET" "$msg"
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s [%s] %s\n' "$(_stamp)" "$level" "$msg" >>"$LOG_FILE"
    fi
}

log_info() { log_line "INFO"  "$C_BLUE"   "$*"; }
log_ok()   { log_line "OK"    "$C_GREEN"  "$*"; }
log_warn() { log_line "WARN"  "$C_YELLOW" "$*"; }
log_err()  { log_line "ERROR" "$C_RED"    "$*" >&2; }
log_debug() {
    [[ "$VERBOSE" == "yes" ]] || return 0
    log_line "DEBUG" "$C_DIM" "$*"
}
log_step() {
    printf '\n%s%s%s\n' "$C_CYAN$C_BOLD" "━━━ $*" "$C_RESET"
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s [STEP] %s\n' "$(_stamp)" "$*" >>"$LOG_FILE"
    fi
}

# --- Lightweight spinner (TTY only, silent otherwise) ------------------------
spin_start() {
    [[ -t 1 ]] || return 0
    local msg="$1"
    (
        trap 'exit 0' INT TERM
        local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        local i=0
        while :; do
            printf '\r\033[K  %s%s%s %s' "$C_CYAN" "${frames:i++%10:1}" "$C_RESET" "$msg"
            sleep 0.12
        done
    ) &
    SPIN_PID=$!
    disown 2>/dev/null || true
}

spin_stop() {
    [[ -n "$SPIN_PID" ]] || return 0
    kill "$SPIN_PID" 2>/dev/null || true
    wait "$SPIN_PID" 2>/dev/null || true
    SPIN_PID=""
    [[ -t 1 ]] && printf '\r\033[K'
    return 0
}

# ------------------------------------------------------------------------------
# Usage / help
# ------------------------------------------------------------------------------
usage() {
    cat <<EOF
${C_BOLD}${C_CYAN}  ReconScope v${SCRIPT_VERSION}${C_RESET}
${C_DIM}  Automated Subdomain & Live Host Discovery — 100% free, no API keys${C_RESET}

${C_BOLD}USAGE${C_RESET}
  ./reconscope.sh -d <domain> [options]

${C_BOLD}REQUIRED${C_RESET}
  -d, --domain <domain>    Target domain to enumerate (e.g. example.com)

${C_BOLD}OPTIONS${C_RESET}
  -o, --output <dir>       Output root directory            (default: ./results)
  -t, --threads <n>        Concurrent probe threads         (default: 50)
      --timeout <sec>      Per-request HTTP timeout         (default: 10)
      --rps <n>            Max requests/second for httpx    (default: 150)
      --status <codes>     Live status codes                (default: 200,301,302,403)
      --no-web             Skip web-based passive sources (crt.sh, wayback)
      --deep               Extra ports (8080,8443,8000,3000,5000) + DNS resolution
      --only <tools>       Comma separated recon-tool subset (e.g. subfinder,httpx)
  -v, --verbose            Verbose debug output
      --no-color           Disable ANSI colours
  -h, --help               Show this help and exit

${C_BOLD}TOOLS${C_RESET}
  Required : subfinder, assetfinder, httpx (ProjectDiscovery), jq, curl
  Optional : anewer (faster de-duplication), dnsx (DNS resolution), amass

${C_BOLD}EXAMPLES${C_RESET}
  ./reconscope.sh -d example.com
  ./reconscope.sh -d example.com -o ./scans -t 100 --deep
  ./reconscope.sh -d example.com --only subfinder,httpx --no-web

${C_BOLD}OUTPUT${C_RESET}
  results/<domain>/
    ├── subdomains/     raw + merged subdomain lists
    ├── live/           live hosts, details, raw probe output
    ├── categories/     status-coded buckets + high-value targets
    ├── reports/        summary.txt / summary.md / summary.json / report.html
    └── logs/           reconscope.log
EOF
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                [[ -n "${2:-}" ]] || { log_err "Option $1 requires a domain value."; exit 2; }
                DOMAIN="$2"; shift 2 ;;
            -d=*|--domain=*)
                DOMAIN="${1#*=}"; shift ;;
            -o|--output)
                [[ -n "${2:-}" ]] || { log_err "Option $1 requires a directory value."; exit 2; }
                OUTPUT_ROOT="$2"; shift 2 ;;
            -o=*|--output=*)
                OUTPUT_ROOT="${1#*=}"; shift ;;
            -t|--threads)
                [[ -n "${2:-}" ]] || { log_err "Option $1 requires a numeric value."; exit 2; }
                THREADS="$2"; shift 2 ;;
            -t=*|--threads=*)
                THREADS="${1#*=}"; shift ;;
            --timeout)
                HTTP_TIMEOUT="${2:-}"; shift 2 ;;
            --timeout=*)
                HTTP_TIMEOUT="${1#*=}"; shift ;;
            --rps)
                RPS="${2:-}"; shift 2 ;;
            --rps=*)
                RPS="${1#*=}"; shift ;;
            --status)
                LIVE_STATUS="${2:-}"; shift 2 ;;
            --status=*)
                LIVE_STATUS="${1#*=}"; shift ;;
            --only)
                TOOL_SET="${2:-}"; shift 2 ;;
            --only=*)
                TOOL_SET="${1#*=}"; shift ;;
            --no-web)      USE_WEB="no"; shift ;;
            --deep)        USE_DEEP="yes"; shift ;;
            --no-color)    COLOR="never"; shift ;;
            -v|--verbose)  VERBOSE="yes"; shift ;;
            -h|--help)
                init_colors; usage; exit 0 ;;
            --version)
                printf '%s v%s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
            *)
                init_colors
                log_err "Unknown or invalid argument: '$1'"
                printf '\n'
                usage
                exit 2 ;;
        esac
    done

    if [[ -z "$DOMAIN" ]]; then
        init_colors
        log_err "No target domain supplied."
        printf '\n'
        usage
        exit 2
    fi
}

# Normalise a comma separated list into lowercase trimmed values
normalise_list() {
    local raw="$1" out="" item
    raw="${raw//,/ }"
    for item in $raw; do
        item="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')"
        [[ -n "$item" ]] && out="${out}${out:+,}${item}"
    done
    printf '%s' "$out"
}

# Should a given tool be used? (honours --only)
tool_enabled() {
    local name="$1"
    [[ "$TOOL_SET" == "all" ]] && return 0
    local enabled
    enabled="$(normalise_list "$TOOL_SET")"
    [[ ",${enabled}," == *",${name},"* ]]
}

# ------------------------------------------------------------------------------
# Dependency verification
# ------------------------------------------------------------------------------
install_hint() {
    case "$1" in
        subfinder)  printf 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' ;;
        assetfinder) printf 'go install -v github.com/tomnomnom/assetfinder@latest' ;;
        httpx)      printf 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest' ;;
        anewer)     printf 'go install -v github.com/tomnomnom/anew@latest' ;;
        dnsx)       printf 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest' ;;
        amass)      printf 'go install -v github.com/owasp-amass/amass/v4/...@master' ;;
        jq)         printf 'sudo apt-get install -y jq   # or: brew install jq' ;;
        curl)       printf 'sudo apt-get install -y curl  # or: brew install curl' ;;
        *)          printf 'see the project README for manual installation' ;;
    esac
}

# Resolve a genuine ProjectDiscovery httpx binary (the PyPI "httpx" package is a
# different project entirely and must never be mistaken for it).
resolve_httpx() {
    local candidates=()
    local c
    for c in httpx httpx-pd pd-httpx httpx1; do
        if command -v "$c" >/dev/null 2>&1; then
            candidates+=("$(command -v "$c")")
        fi
    done
    for c in "$HOME/go/bin/httpx" /usr/local/go/bin/httpx /opt/go/bin/httpx; do
        [[ -x "$c" ]] && candidates+=("$c")
    done

    local bin
    for bin in "${candidates[@]:-}"; do
        [[ -x "$bin" ]] || continue
        if "$bin" -version 2>&1 | grep -qi 'projectdiscovery'; then
            HTTPX_BIN="$bin"
            return 0
        fi
    done
    return 1
}

# Detect the richest output mode supported by the installed httpx
detect_httpx_mode() {
    local help_txt
    help_txt="$("$HTTPX_BIN" -h 2>&1 || true)"
    if printf '%s' "$help_txt" | grep -qE '(^|[ ,])-json([ ,]|$)'; then
        HTTPX_MODE="json"; HTTPX_JSON_FLAG="-json"
    elif printf '%s' "$help_txt" | grep -qE '(^|[ ,])-jsonl([ ,]|$)'; then
        HTTPX_MODE="json"; HTTPX_JSON_FLAG="-jsonl"
    else
        HTTPX_MODE="text"; HTTPX_JSON_FLAG=""
    fi
}

check_deps() {
    log_step "Step 0/6 — Dependency verification"

    # Utility dependencies — always required, the pipeline itself relies on them
    local util_tools=("jq" "curl")
    # Recon tools — the user may restrict this set with --only
    local recon_tools=("subfinder" "assetfinder" "httpx")
    local optional_tools=("anewer" "dnsx" "amass")

    local -a missing=()
    local tool

    for tool in "${util_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            log_ok "Found '$tool' -> $(command -v "$tool")"
        else
            missing+=("$tool")
        fi
    done

    for tool in "${recon_tools[@]}"; do
        if ! tool_enabled "$tool"; then
            log_info "Skipping '$tool' (excluded via --only)"
            continue
        fi
        if [[ "$tool" == "httpx" ]]; then
            continue    # handled by resolve_httpx below
        fi
        if command -v "$tool" >/dev/null 2>&1; then
            log_ok "Found '$tool' -> $(command -v "$tool")"
        else
            missing+=("$tool")
        fi
    done

    # --- httpx (ProjectDiscovery) special handling -------------------------
    if tool_enabled "httpx"; then
        if resolve_httpx; then
            log_ok "Found 'httpx' (ProjectDiscovery) -> $HTTPX_BIN"
            detect_httpx_mode
            log_debug "httpx output mode: $HTTPX_MODE"
        else
            log_err "Could not find the ProjectDiscovery 'httpx' binary."
            if command -v httpx >/dev/null 2>&1; then
                log_warn "A 'httpx' binary exists at $(command -v httpx) but it is the Python client, not ProjectDiscovery's."
                log_warn "Install the correct one:  $(install_hint httpx)"
                log_warn "If both are needed, install PD's httpx into a separate PATH entry (e.g. ~/go/bin) and re-run."
            fi
            missing+=("httpx")
        fi
    fi

    # --- optional tools -----------------------------------------------------
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            log_ok "Found optional '$tool' -> $(command -v "$tool")"
        else
            log_debug "Optional tool '$tool' not installed — continuing without it"
        fi
    done

    # --- graceful exit on missing required tools ----------------------------
    if [[ ${#missing[@]} -gt 0 ]]; then
        printf '\n'
        log_err "Missing required tool(s): ${missing[*]}"
        printf '\n'
        printf '%s  Suggested installation commands:%s\n' "$C_BOLD" "$C_RESET"
        for tool in "${missing[@]}"; do
            printf '  %-12s %s%s%s\n' "$tool" "$C_CYAN" "$(install_hint "$tool")" "$C_RESET"
        done
        printf '\n'
        log_info "Debian/Ubuntu : sudo apt-get install -y jq curl"
        log_info "macOS         : brew install jq curl"
        log_info "Docker        : docker pull projectdiscovery/subfinder:latest"
        log_info "Full helper   : ./install_deps.sh"
        printf '\n'
        log_err "Aborting — nothing was scanned."
        exit 1
    fi

    log_ok "All required dependencies satisfied."
}

# ------------------------------------------------------------------------------
# Preflight: validate input and build the directory tree
# ------------------------------------------------------------------------------
preflight() {
    log_step "Step 1/6 — Target preparation & workspace setup"

    # Strip scheme, path, trailing dot, lower-case
    DOMAIN="${DOMAIN,,}"
    DOMAIN="${DOMAIN#*://}"
    DOMAIN="${DOMAIN%%/*}"
    DOMAIN="${DOMAIN%.}"

    if [[ ! "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]; then
        log_err "Invalid domain format: '$DOMAIN'"
        log_info "Expected something like 'example.com' (no scheme, no path)."
        exit 2
    fi

    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
        log_err "Invalid thread count: '$THREADS'"
        exit 2
    fi
    if ! [[ "$HTTP_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$HTTP_TIMEOUT" -lt 1 ]]; then
        log_err "Invalid timeout: '$HTTP_TIMEOUT'"
        exit 2
    fi
    if ! [[ "$RPS" =~ ^[0-9]+$ ]] || [[ "$RPS" -lt 1 ]]; then
        log_err "Invalid rps value: '$RPS'"
        exit 2
    fi

    OUT_DIR="${OUTPUT_ROOT%/}/${DOMAIN}"
    SUBDOMAIN_DIR="$OUT_DIR/subdomains"
    LIVE_DIR="$OUT_DIR/live"
    CATEGORY_DIR="$OUT_DIR/categories"
    REPORT_DIR="$OUT_DIR/reports"
    LOG_DIR="$OUT_DIR/logs"

    mkdir -p "$SUBDOMAIN_DIR" "$LIVE_DIR" "$CATEGORY_DIR" "$REPORT_DIR" "$LOG_DIR"

    TMP_DIR="$(mktemp -d "${OUT_DIR}/.tmp.XXXXXX")"
    LOG_FILE="$LOG_DIR/reconscope.log"
    : >"$LOG_FILE"

    log_ok "Target      : $C_BOLD$DOMAIN$C_RESET"
    log_ok "Output dir  : $(cd "$OUT_DIR" && pwd)"
    log_ok "Threads     : $THREADS   Timeout: ${HTTP_TIMEOUT}s   RPS: $RPS"
    log_ok "Live codes  : $LIVE_STATUS"
    log_ok "Workspace ready."

    if [[ -f "$REPORT_DIR/report.html" ]]; then
        cp -f "$REPORT_DIR/report.html" "$REPORT_DIR/report.prev.html" 2>/dev/null || true
    fi
}

cleanup() {
    local rc=$?
    spin_stop
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    return $rc
}

# Run a command with a wall-clock limit when 'timeout' is available
run_limited() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@" || true
    else
        "$@" || true
    fi
}

# ------------------------------------------------------------------------------
# Step 2 — Passive subdomain gathering
# ------------------------------------------------------------------------------
gather_subs() {
    log_step "Step 2/6 — Passive subdomain gathering (free sources only)"

    local combined="$TMP_DIR/merged_raw.txt"
    : >"$combined"

    # --- subfinder ----------------------------------------------------------
    if tool_enabled "subfinder"; then
        spin_start "Querying subfinder passive sources..."
        run_limited 900 subfinder -d "$DOMAIN" -all -silent -t "$THREADS" \
            -o "$SUBDOMAIN_DIR/subfinder.txt" >/dev/null 2>"$LOG_DIR/subfinder_stderr.log" || true
        spin_stop
        local n=0
        [[ -f "$SUBDOMAIN_DIR/subfinder.txt" ]] && n="$(count_lines "$SUBDOMAIN_DIR/subfinder.txt")"
        log_ok "subfinder   : ${n} subdomains -> subdomains/subfinder.txt"
        [[ -f "$SUBDOMAIN_DIR/subfinder.txt" ]] && cat "$SUBDOMAIN_DIR/subfinder.txt" >>"$combined"
    else
        log_warn "subfinder skipped by --only"
    fi

    # --- assetfinder --------------------------------------------------------
    if tool_enabled "assetfinder"; then
        spin_start "Querying assetfinder passive sources..."
        run_limited 600 assetfinder --subs-only "$DOMAIN" \
            >"$SUBDOMAIN_DIR/assetfinder.txt" 2>"$LOG_DIR/assetfinder_stderr.log" || true
        spin_stop
        local n=0
        [[ -f "$SUBDOMAIN_DIR/assetfinder.txt" ]] && n="$(count_lines "$SUBDOMAIN_DIR/assetfinder.txt")"
        log_ok "assetfinder : ${n} subdomains -> subdomains/assetfinder.txt"
        [[ -f "$SUBDOMAIN_DIR/assetfinder.txt" ]] && cat "$SUBDOMAIN_DIR/assetfinder.txt" >>"$combined"
    else
        log_warn "assetfinder skipped by --only"
    fi

    # --- amass (optional) ---------------------------------------------------
    if tool_enabled "amass" && command -v amass >/dev/null 2>&1; then
        spin_start "Enumerating with amass (passive)..."
        run_limited 600 amass enum -passive -d "$DOMAIN" -silent \
            -o "$SUBDOMAIN_DIR/amass.txt" >/dev/null 2>&1 || true
        spin_stop
        local n=0
        [[ -f "$SUBDOMAIN_DIR/amass.txt" ]] && n="$(count_lines "$SUBDOMAIN_DIR/amass.txt")"
        log_ok "amass       : ${n} subdomains -> subdomains/amass.txt"
        [[ -f "$SUBDOMAIN_DIR/amass.txt" ]] && cat "$SUBDOMAIN_DIR/amass.txt" >>"$combined"
    fi

    # --- web based sources (crt.sh + wayback) --------------------------------
    if [[ "$USE_WEB" == "yes" ]]; then
        collect_crt_sh "$combined"
        collect_wayback "$combined"
    else
        log_warn "Web-based passive sources disabled (--no-web)"
    fi

    # --- de-duplicate -------------------------------------------------------
    local all="$SUBDOMAIN_DIR/all_subdomains.txt"
    : >"$all"

    # Normalise every raw entry into a bare hostname:
    #   strip scheme -> strip userinfo -> strip path -> strip port
    #   -> strip wildcard/leading dot -> trim -> validate hostname syntax
    if [[ -s "$combined" ]]; then
        tr '[:upper:]' '[:lower:]' <"$combined" \
            | sed -e 's#^[a-z][a-z0-9+.-]*://##' \
                  -e 's#^[a-z0-9._%+-]*:[^@/]*@##' \
                  -e 's#/.*$##' \
                  -e 's#:[0-9]*$##' \
                  -e 's/^\*\.//' \
                  -e 's/^\.//' \
                  -e 's/[[:space:]]*$//' \
                  -e 's/\.$//' \
            | grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$' \
            | grep -E "\.${DOMAIN}$|^${DOMAIN}$" || true
    fi >"$TMP_DIR/cleaned.txt"

    if command -v anewer >/dev/null 2>&1 && [[ -s "$TMP_DIR/cleaned.txt" ]]; then
        anewer -q <"$TMP_DIR/cleaned.txt" >"$all" || sort -u "$TMP_DIR/cleaned.txt" >"$all"
        log_info "De-duplicated with 'anewer'"
    else
        sort -u "$TMP_DIR/cleaned.txt" >"$all" 2>/dev/null || : >"$all"
        log_info "De-duplicated with 'sort -u'"
    fi

    local total
    total="$(count_lines "$all")"
    log_ok "Total unique subdomains: ${C_BOLD}${total}${C_RESET} -> subdomains/all_subdomains.txt"

    if [[ "$total" -eq 0 ]]; then
        log_warn "No subdomains were discovered. Reporting will be empty — check connectivity or try --no-web off."
    fi
}

count_lines() {
    local f="$1" n=0
    if [[ -f "$f" ]]; then
        # grep exits non-zero when there are no matches — capture stdout only.
        n="$(grep -c . "$f" 2>/dev/null | head -n 1 || true)"
    fi
    sanitize_int "$n"
}

# Coerce any value into a safe non-negative integer (0 on failure)
sanitize_int() {
    local v="${1:-0}"
    v="${v//[[:space:]]/}"
    [[ "$v" =~ ^[0-9]+$ ]] || v=0
    printf '%s' "$v"
}

# crt.sh certificate transparency (free, no key)
collect_crt_sh() {
    local combined="${1:-}"
    local out="$SUBDOMAIN_DIR/crt_sh.txt"
    : >"$out"
    if ! command -v curl >/dev/null 2>&1; then
        log_warn "curl unavailable — skipping crt.sh"
        return 0
    fi
    spin_start "Querying crt.sh certificate transparency..."
    local body="$TMP_DIR/crt.json"
    run_limited 120 curl -sS --max-time 100 --retry 1 \
        -H 'User-Agent: ReconScope/1.0' \
        "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$body" >/dev/null 2>&1 || true
    spin_stop

    if [[ -s "$body" ]] && jq -e 'type == "array"' "$body" >/dev/null 2>&1; then
        jq -r '.[].name_value? // empty' "$body" 2>/dev/null \
            | tr '\r' '\n' \
            | grep -v '^\*' \
            | sed 's/^\.//' \
            | grep -iE "\.${DOMAIN}$|^${DOMAIN}$" >>"$out" || true
        local n; n="$(count_lines "$out")"
        log_ok "crt.sh      : ${n} subdomains -> subdomains/crt_sh.txt"
        [[ -n "$combined" && -s "$out" ]] && cat "$out" >>"$combined"
    else
        log_warn "crt.sh returned no usable data (rate limit or connectivity) — continuing"
    fi
}

# Internet Archive Wayback CDX (free, no key)
collect_wayback() {
    local combined="${1:-}"
    local out="$SUBDOMAIN_DIR/wayback.txt"
    : >"$out"
    if ! command -v curl >/dev/null 2>&1; then
        log_warn "curl unavailable — skipping wayback"
        return 0
    fi
    spin_start "Querying Wayback Machine CDX index..."
    local body="$TMP_DIR/wayback.txt.raw"
    run_limited 120 curl -sS --max-time 60 \
        -H 'User-Agent: ReconScope/1.0' \
        "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=txt&fl=original&collapse=urlkey&limit=10000" \
        -o "$body" >/dev/null 2>&1 || true
    spin_stop

    if [[ -s "$body" ]]; then
        sed -E 's#^[a-zA-Z]+://##; s#/.*$##' "$body" 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | grep -E "\.${DOMAIN}$|^${DOMAIN}$" >>"$out" || true
        local n; n="$(count_lines "$out")"
        log_ok "wayback     : ${n} subdomains -> subdomains/wayback.txt"
        [[ -n "$combined" && -s "$out" ]] && cat "$out" >>"$combined"
    else
        log_warn "Wayback CDX returned no data — continuing"
    fi
}

# Optional DNS resolution pass (dnsx) to enrich the data set
resolve_dns() {
    [[ "$USE_DEEP" == "yes" ]] || return 0
    command -v dnsx >/dev/null 2>&1 || { log_warn "dnsx not installed — skipping DNS resolution"; return 0; }
    local subs="$SUBDOMAIN_DIR/all_subdomains.txt"
    [[ -s "$subs" ]] || return 0

    spin_start "Resolving DNS records with dnsx..."
    run_limited 600 dnsx -l "$subs" -silent -a -resp -cname \
        -o "$SUBDOMAIN_DIR/resolved_ips.txt" >/dev/null 2>&1 || true
    spin_stop

    if [[ -f "$SUBDOMAIN_DIR/resolved_ips.txt" ]]; then
        local n; n="$(count_lines "$SUBDOMAIN_DIR/resolved_ips.txt")"
        log_ok "dnsx        : ${n} resolved hosts -> subdomains/resolved_ips.txt"
    fi
}

# ------------------------------------------------------------------------------
# Step 3 — HTTP probing with httpx
# ------------------------------------------------------------------------------
probe_hosts() {
    log_step "Step 3/6 — HTTP probing live assets (httpx)"

    local subs="$SUBDOMAIN_DIR/all_subdomains.txt"
    local raw_json="$LIVE_DIR/httpx_raw.jsonl"
    local raw_text="$LIVE_DIR/httpx_raw.txt"
    local details="$LIVE_DIR/live_hosts_details.tsv"
    local live="$LIVE_DIR/live_hosts.txt"
    local probed="$LIVE_DIR/hosts_probed.txt"
    local json_out="$LIVE_DIR/live_hosts.json"

    if ! tool_enabled "httpx"; then
        log_warn "httpx excluded via --only — skipping the HTTP probing stage."
        : >"$live"; : >"$probed"; : >"$details"; : >"$json_out"
        return 0
    fi

    if [[ ! -s "$subs" ]]; then
        log_warn "No subdomains to probe — skipping HTTP stage."
        : >"$live"; : >"$probed"; : >"$details"; : >"$json_out"
        return 0
    fi

    local -a extra_args=()
    if [[ "$USE_DEEP" == "yes" ]]; then
        local extra_ports="80,443,8080,8443,8000,3000,5000"
        extra_args+=(-ports "$extra_ports")
    fi

    local -a cmd=(
        "$HTTPX_BIN" -l "$subs"
        -silent -no-color
        -threads "$THREADS"
        -timeout "$HTTP_TIMEOUT"
        -rate-limit "$RPS"
        -follow-redirects
        -status-code
        -title
        -content-length
        -web-server
        -tech-detect
        -ip
        -cname
    )
    # Guarded expansion: safe on bash < 4.4 where an empty array trips `set -u`
    if [[ ${#extra_args[@]} -gt 0 ]]; then
        cmd+=("${extra_args[@]}")
    fi

    spin_start "Probing $(count_lines "$subs") hosts over HTTP..."

    local stderr_log="$LOG_DIR/httpx_stderr.log"
    if [[ "$HTTPX_MODE" == "json" ]]; then
        cmd+=("$HTTPX_JSON_FLAG" -o "$raw_json")
        run_limited 1800 "${cmd[@]}" >/dev/null 2>"$stderr_log" || true
    else
        cmd+=(-o "$raw_text")
        run_limited 1800 "${cmd[@]}" >/dev/null 2>"$stderr_log" || true
    fi
    spin_stop

    if [[ -s "$stderr_log" ]]; then
        log_debug "httpx stderr captured -> $stderr_log"
    fi

    # --- parse the probe results -------------------------------------------
    : >"$details"
    if [[ "$HTTPX_MODE" == "json" && -s "$raw_json" ]]; then
        jq -s '.' "$raw_json" >"$json_out" 2>/dev/null || cp -f "$raw_json" "$json_out"
        parse_json_results "$raw_json" "$details"
    elif [[ -s "$raw_text" ]]; then
        cp -f "$raw_text" "$json_out" 2>/dev/null || true
        parse_text_results "$raw_text" "$details"
        log_warn "Legacy httpx detected — titles/sizes may be incomplete."
    else
        log_warn "httpx produced no output."
    fi

    # --- filter by the requested status codes --------------------------------
    local filter="" code_csv
    local IFS=','
    for code_csv in $LIVE_STATUS; do
        code_csv="${code_csv// /}"
        [[ -n "$code_csv" ]] && filter="${filter:+$filter|}$code_csv"
    done
    unset IFS
    [[ -z "$filter" ]] && filter="200|301|302|403"

    awk -F'\t' -v re="^(${filter})$" 'BEGIN{OFS="\t"} $2 ~ re {print $1}' "$details" >"$live" 2>/dev/null || : >"$live"
    cut -f1 "$details" 2>/dev/null | sort -u >"$probed" || : >"$probed"

    local n; n="$(count_lines "$live")"
    log_ok "Live hosts  : ${C_BOLD}${n}${C_RESET} -> live/live_hosts.txt"
    log_ok "Hosts probed: $(count_lines "$probed")  |  details: live/live_hosts_details.tsv  |  raw: live/live_hosts.json"
}

# JSON mode parser: url, status, title, size, tech, webserver, host, ip, cname
parse_json_results() {
    local src="$1" dst="$2"
    jq -r '
        def s: if type == "array" then join(",")
               elif . == null then ""
               else tostring end;
        select(.status_code != null)
        | [
            (.url // .input // ""),
            (.status_code | tostring),
            ((.title // "") | gsub("[\t\r\n]"; " ") | s),
            ((.content_length // 0) | tostring),
            ((.tech // []) | s),
            ((.webserver // "") | s),
            ((.host // .input // "") | s),
            ((.a // []) | s),
            ((.cname // []) | s)
          ] | @tsv
    ' "$src" 2>/dev/null | sort -u >"$dst" || : >"$dst"
}

# Text-mode parser (older httpx): "<url> [code] [title] ..."
parse_text_results() {
    local src="$1" dst="$2"
    awk '
        {
            url = $1
            if (url == "") next
            code = ""
            title = ""
            if (match($0, /\[[0-9]{3}\]/)) {
                code = substr($0, RSTART + 1, 3)
                rest = substr($0, RSTART + 5)
                if (match(rest, /\[[^]]*\]/)) {
                    title = substr(rest, RSTART + 1, RLENGTH - 2)
                }
            }
            gsub(/\t/, " ", title)
            printf "%s\t%s\t%s\t0\t\t\t%s\t\t\n", url, code, title, url
        }
    ' "$src" 2>/dev/null | sort -u >"$dst" || : >"$dst"
}

# ------------------------------------------------------------------------------
# Step 4 — Categorisation of alive assets
# ------------------------------------------------------------------------------
categorize() {
    log_step "Step 4/6 — Categorising alive assets"

    local details="$LIVE_DIR/live_hosts_details.tsv"

    if [[ ! -s "$details" ]]; then
        log_warn "No probe details available — categories will be empty."
        : >"$CATEGORY_DIR/status_200.txt"
        : >"$CATEGORY_DIR/status_301_302.txt"
        : >"$CATEGORY_DIR/status_403.txt"
        : >"$CATEGORY_DIR/status_other.txt"
        : >"$CATEGORY_DIR/high_value.txt"
        return 0
    fi

    local buckets=("200" "301" "302" "403" "other")
    local bucket code
    for bucket in "${buckets[@]}"; do
        : >"$CATEGORY_DIR/status_${bucket}.txt"
    done

    # Bucket the probed hosts by status code. Paths are passed with -v so that
    # an output directory containing spaces or quotes cannot break the program.
    awk -F'\t' \
        -v d200="$CATEGORY_DIR/status_200.txt" \
        -v d301="$CATEGORY_DIR/status_301.txt" \
        -v d302="$CATEGORY_DIR/status_302.txt" \
        -v d403="$CATEGORY_DIR/status_403.txt" \
        -v dother="$CATEGORY_DIR/status_other.txt" '
        {
            code = $2
            if      (code == "200") { print $1 > d200 }
            else if (code == "301") { print $1 > d301 }
            else if (code == "302") { print $1 > d302 }
            else if (code == "403") { print $1 > d403 }
            else                    { print $1 > dother }
        }
    ' "$details" 2>/dev/null || true

    cat "$CATEGORY_DIR"/status_301.txt "$CATEGORY_DIR"/status_302.txt 2>/dev/null \
        | sort -u >"$CATEGORY_DIR/status_301_302.txt" || : >"$CATEGORY_DIR/status_301_302.txt"

    # High-value targets for deeper manual review.
    # Two signals are combined:
    #   1. host-name patterns  (admin, dev, staging, vpn, api ...)
    #   2. page-title patterns (Admin Login, Jenkins, GitLab ...)
    local hv_host_pattern='(^|[.-])(admin|administrator|jenkins|gitlab|gira|jira|bitbucket|grafana|kibana|sonar|confluence|dev|devops|develop|development|test|testing|qa|uat|stage|staging|preprod|pre-prod|prod|production|sandbox|demo|lab|vpn|remote|portal|intranet|internal|corp|api|apis|apigee|gateway|graphql|swagger|api-docs|docs|doc|backup|backups|bak|old|legacy|archive|db|database|mysql|postgres|redis|mongo|elastic|logs|log|monitor|monitoring|metrics|proxy|artifactory|nexus|registry|docker|k8s|kube|kubernetes|ci|cd|build|mail|smtp|webmail|cpanel|whm|ftp|ssh|phpmyadmin|adminer|erp|crm|intranet)([.-]|$)'
    local hv_title_pattern='(admin|login|sign ?in|dashboard|jenkins|gitlab|grafana|kibana|sonar|confluence|phpMyAdmin|Adminer|internal|restricted|forbidden|unauthori[sz]ed|debug|swagger|api ?doc|graphql|playground|console|phpmyadmin|vpn|firewall|private|secret|token|credential)'

    # 1) host-name based
    { cat "$CATEGORY_DIR"/status_*.txt 2>/dev/null || true; } \
        | sed -e 's#^[A-Za-z]*://##' -e 's#/.*$##' -e 's#:[0-9]*$##' \
        | grep -iE "$hv_host_pattern" >"$TMP_DIR/hv_hosts.txt" 2>/dev/null || : >"$TMP_DIR/hv_hosts.txt"

    # 2) title based (pull the host out of the details table)
    awk -F'\t' -v pat="$hv_title_pattern" '
        $3 != "" && tolower($3) ~ tolower(pat) {
            h=$1; sub(/^[A-Za-z]*:\/\//,"",h); sub(/\/.*$/,"",h); sub(/:[0-9]*$/,"",h);
            if (h != "") print h
        }
    ' "$details" 2>/dev/null | sort -u >"$TMP_DIR/hv_titles.txt" || : >"$TMP_DIR/hv_titles.txt"

    cat "$TMP_DIR/hv_hosts.txt" "$TMP_DIR/hv_titles.txt" 2>/dev/null \
        | sed -e 's/[[:space:]]*$//' | grep -v '^$' | sort -u >"$CATEGORY_DIR/high_value.txt" \
        || : >"$CATEGORY_DIR/high_value.txt"

    # Technology & web server breakdowns
    awk -F'\t' '$5 != "" {print $5}' "$details" 2>/dev/null \
        | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -v '^$' | sort | uniq -c | sort -rn \
        >"$CATEGORY_DIR/tech_breakdown.txt" 2>/dev/null || : >"$CATEGORY_DIR/tech_breakdown.txt"

    awk -F'\t' '$6 != "" {print $6}' "$details" 2>/dev/null \
        | sort | uniq -c | sort -rn >"$CATEGORY_DIR/webserver_breakdown.txt" 2>/dev/null \
        || : >"$CATEGORY_DIR/webserver_breakdown.txt"

    local b
    for b in 200 301 302 403 other; do
        log_ok "Status ${b} : $(count_lines "$CATEGORY_DIR/status_${b}.txt") host(s)"
    done
    log_ok "High-value targets flagged: $(count_lines "$CATEGORY_DIR/high_value.txt")"
}

# ------------------------------------------------------------------------------
# Step 5 & 6 — Summary and reporting
# ------------------------------------------------------------------------------
generate_summary() {
    log_step "Step 5/6 — Generating summary & reports"

    local details="$LIVE_DIR/live_hosts_details.tsv"
    local total_subs live_total probed_total
    total_subs="$(count_lines "$SUBDOMAIN_DIR/all_subdomains.txt")"
    live_total="$(count_lines "$LIVE_DIR/live_hosts.txt")"
    probed_total="$(count_lines "$LIVE_DIR/hosts_probed.txt")"

    local s200 s301 s302 s403 sother
    s200="$(count_lines "$CATEGORY_DIR/status_200.txt")"
    s301="$(count_lines "$CATEGORY_DIR/status_301.txt")"
    s302="$(count_lines "$CATEGORY_DIR/status_302.txt")"
    s403="$(count_lines "$CATEGORY_DIR/status_403.txt")"
    sother="$(count_lines "$CATEGORY_DIR/status_other.txt")"

    local elapsed=$(( $(date +%s) - START_TS ))
    local hh=$(( elapsed / 3600 )); local mm=$(( (elapsed % 3600) / 60 )); local ss=$(( elapsed % 60 ))

    # --- plain text summary -------------------------------------------------
    {
        printf '===============================================================\n'
        printf ' %s v%s — Scan Summary\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '===============================================================\n\n'
        printf 'Target          : %s\n' "$DOMAIN"
        printf 'Date            : %s\n' "$(_stamp)"
        printf 'Duration        : %02d:%02d:%02d\n' "$hh" "$mm" "$ss"
        printf 'Output          : %s\n' "$(cd "$OUT_DIR" && pwd)"
        printf 'Tools           : subfinder, assetfinder, httpx (ProjectDiscovery)\n'
        printf 'Threads / RPS   : %s / %s\n\n' "$THREADS" "$RPS"
        printf -- '--- SUBDOMAIN DISCOVERY -------------------------------------\n'
        printf 'Unique subdomains : %s\n\n' "$total_subs"
        printf -- '--- LIVE HOSTS -----------------------------------------------\n'
        printf 'Hosts probed      : %s\n' "$probed_total"
        printf 'Live hosts        : %s   (status filter: %s)\n' "$live_total" "$LIVE_STATUS"
        printf '  HTTP 200         : %s\n' "$s200"
        printf '  HTTP 301         : %s\n' "$s301"
        printf '  HTTP 302         : %s\n' "$s302"
        printf '  HTTP 403         : %s\n' "$s403"
        printf '  Other (2xx/3xx/4xx/5xx): %s\n\n' "$sother"
        printf -- '--- TOP TECHNOLOGIES -----------------------------------------\n'
        if [[ -s "$CATEGORY_DIR/tech_breakdown.txt" ]]; then
            head -15 "$CATEGORY_DIR/tech_breakdown.txt"
        else
            printf '(none detected)\n'
        fi
        printf -- '\n--- TOP WEB SERVERS ------------------------------------------\n'
        if [[ -s "$CATEGORY_DIR/webserver_breakdown.txt" ]]; then
            head -10 "$CATEGORY_DIR/webserver_breakdown.txt"
        else
            printf '(none detected)\n'
        fi
        printf -- '\n--- HIGH VALUE TARGETS (manual review) ----------------------\n'
        if [[ -s "$CATEGORY_DIR/high_value.txt" ]]; then
            head -40 "$CATEGORY_DIR/high_value.txt"
        else
            printf '(none flagged)\n'
        fi
        printf -- '\n--- ARTIFACTS -------------------------------------------------\n'
        printf 'subdomains/all_subdomains.txt\n'
        printf 'live/live_hosts.txt | live/live_hosts_details.tsv | live/live_hosts.json\n'
        printf 'categories/status_*.txt | categories/high_value.txt\n'
        printf 'reports/summary.txt | reports/summary.md | reports/summary.json | reports/report.html\n'
    } >"$REPORT_DIR/summary.txt"

    # --- JSON summary -------------------------------------------------------
    jq -n \
        --arg tool "$SCRIPT_NAME" \
        --arg version "$SCRIPT_VERSION" \
        --arg domain "$DOMAIN" \
        --arg date "$(_stamp)" \
        --argjson duration_sec "$elapsed" \
        --argjson subdomains "$total_subs" \
        --argjson probed "$probed_total" \
        --argjson live_hosts "$live_total" \
        --argjson s200 "$s200" \
        --argjson s301 "$s301" \
        --argjson s302 "$s302" \
        --argjson s403 "$s403" \
        --argjson other "$sother" \
        --argjson high_value "$(count_lines "$CATEGORY_DIR/high_value.txt")" \
        '{tool:$tool, version:$version, target:$domain, date:$date,
          duration_seconds:$duration_sec,
          discovery:{unique_subdomains:$subdomains},
          live_hosts:{probed:$probed, total:$live_hosts,
            status_200:$s200, status_301:$s301, status_302:$s302,
            status_403:$s403, other:$other, high_value:$high_value}}' \
        >"$REPORT_DIR/summary.json" 2>/dev/null || echo '{}' >"$REPORT_DIR/summary.json"

    # --- Markdown summary ---------------------------------------------------
    {
        # shellcheck disable=SC2016  # markdown backticks are intentional
        printf '# ReconScope Report — `%s`\n\n' "$DOMAIN"
        printf '**Generated:** %s  |  **Duration:** %02d:%02d:%02d  |  **Tool:** %s v%s\n\n' \
            "$(_stamp)" "$hh" "$mm" "$ss" "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '## Overview\n\n'
        printf '| Metric | Value |\n|---|---:|\n'
        printf '| Unique subdomains | %s |\n' "$total_subs"
        printf '| Hosts probed | %s |\n' "$probed_total"
        # shellcheck disable=SC2016  # markdown backticks are intentional
        printf '| Live hosts (filter `%s`) | %s |\n' "$LIVE_STATUS" "$live_total"
        printf '| High-value targets | %s |\n\n' "$(count_lines "$CATEGORY_DIR/high_value.txt")"
        printf '## Status breakdown\n\n'
        printf '| Status | Count |\n|---|---:|\n'
        printf '| 200 | %s |\n' "$s200"
        printf '| 301 | %s |\n' "$s301"
        printf '| 302 | %s |\n' "$s302"
        printf '| 403 | %s |\n' "$s403"
        printf '| Other | %s |\n\n' "$sother"
        printf '## High-value targets\n\n'
        if [[ -s "$CATEGORY_DIR/high_value.txt" ]]; then
            # shellcheck disable=SC2016  # markdown backticks are intentional
        printf -- '- `%s`\n' "$(head -60 "$CATEGORY_DIR/high_value.txt" | tr '\n' ' ' | sed 's/ $//' | sed 's/ /`\n- `/g')"
        else
            printf '_None flagged._\n'
        fi
        printf '\n## Top technologies\n\n'
        if [[ -s "$CATEGORY_DIR/tech_breakdown.txt" ]]; then
            printf '| Technology | Hosts |\n|---|---:|\n'
            while read -r cnt tech || [[ -n "${tech:-}" ]]; do
                [[ -n "${tech:-}" ]] && printf '| %s | %s |\n' "$tech" "$cnt"
            done < <(head -15 "$CATEGORY_DIR/tech_breakdown.txt")
        else
            printf '_None detected._\n'
        fi
        printf '\n## Live hosts\n\n'
        printf '```\n'
        head -200 "$LIVE_DIR/live_hosts_details.tsv" 2>/dev/null || printf '(none)\n'
        printf '```\n'
    } >"$REPORT_DIR/summary.md"

    # --- self-contained HTML report -----------------------------------------
    render_html_report "$REPORT_DIR/report.html" "$total_subs" "$live_total" \
        "$probed_total" "$s200" "$s301" "$s302" "$s403" "$sother" "$elapsed"

    log_ok "Summary written : reports/summary.txt"
    log_ok "Markdown report : reports/summary.md"
    log_ok "JSON summary    : reports/summary.json"
    log_ok "HTML report     : reports/report.html"
}

# HTML escaping helper (pure bash — no subprocess per value)
html_escape() {
    local s="$1"
    s="${s//&/\&amp;}"
    s="${s//</\&lt;}"
    s="${s//>/\&gt;}"
    s="${s//\"/\&quot;}"
    s="${s//\'/\&#39;}"
    printf '%s' "$s"
}

render_html_report() {
    local out="$1" total_subs="$2" live_total="$3" probed_total="$4"
    local s200="$5" s301="$6" s302="$7" s403="$8" sother="$9" elapsed="${10}"

    {
        printf '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        printf '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        printf '<title>ReconScope Report — %s</title>\n' "$(html_escape "$DOMAIN")"
        printf '<style>\n'
        printf ':root{--bg:#0d1117;--panel:#161b22;--line:#21262d;--fg:#e6edf3;--mut:#8b949e;--acc:#2f81f7;--ok:#3fb950;--warn:#d29922;--bad:#f85149}\n'
        printf '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}\n'
        printf '.wrap{max-width:1120px;margin:0 auto;padding:32px 20px 64px}\n'
        printf 'h1{margin:0 0 4px;font-size:24px;letter-spacing:-.3px}h2{font-size:16px;margin:32px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line);color:var(--mut);text-transform:uppercase;letter-spacing:.08em}\n'
        printf '.sub{color:var(--mut);font-size:13px;margin-bottom:24px}\n'
        printf '.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}\n'
        printf '.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}\n'
        printf '.card .n{font-size:28px;font-weight:600;letter-spacing:-.5px}\n'
        printf '.card .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.1em;margin-top:4px}\n'
        printf 'table{width:100%%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}\n'
        printf 'th{background:#1c2128;color:var(--mut);text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding:10px 12px;border-bottom:1px solid var(--line)}\n'
        printf 'td{padding:9px 12px;border-bottom:1px solid #1b2027;font-size:13px;vertical-align:top}\n'
        printf 'tr:last-child td{border-bottom:none}tr:hover td{background:#1a2028}\n'
        printf 'code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}\n'
        printf '.s200{color:var(--ok)}.s301{color:var(--acc)}.s302{color:var(--acc)}.s403{color:var(--warn)}.sother{color:var(--bad)}\n'
        printf '.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:600;background:#1f2630;color:var(--mut)}\n'
        printf '.tl{color:var(--mut);font-size:12px}\n'
        printf 'code.sh{background:#1f2630;padding:10px 12px;border-radius:8px;display:block;overflow-x:auto;white-space:pre;color:#a5d6ff}\n'
        printf '</style>\n</head>\n<body>\n<div class="wrap">\n'
        printf '<h1>ReconScope Report</h1>\n'
        printf '<div class="sub">Target <code>%s</code> &nbsp;·&nbsp; %s &nbsp;·&nbsp; duration %ss &nbsp;·&nbsp; %s v%s</div>\n' \
            "$(html_escape "$DOMAIN")" "$(_stamp)" "$elapsed" "$SCRIPT_NAME" "$SCRIPT_VERSION"

        printf '<div class="cards">\n'
        printf '<div class="card"><div class="n">%s</div><div class="l">Subdomains</div></div>\n' "$total_subs"
        printf '<div class="card"><div class="n">%s</div><div class="l">Live hosts</div></div>\n' "$live_total"
        printf '<div class="card"><div class="n">%s</div><div class="l">Hosts probed</div></div>\n' "$probed_total"
        printf '<div class="card"><div class="n s200">%s</div><div class="l">Status 200</div></div>\n' "$s200"
        printf '<div class="card"><div class="n s301">%s</div><div class="l">Redirects 301/302</div></div>\n' "$(( s301 + s302 ))"
        printf '<div class="card"><div class="n s403">%s</div><div class="l">Forbidden 403</div></div>\n' "$s403"
        printf '<div class="card"><div class="n sother">%s</div><div class="l">Other</div></div>\n' "$sother"
        printf '</div>\n'

        printf '<h2>Status breakdown</h2>\n<table><tr><th>Status</th><th>Count</th><th>Share of live</th></tr>\n'
        local st cnt share
        for st in 200 301 302 403; do
            case "$st" in
                200) cnt="$s200" ;; 301) cnt="$s301" ;; 302) cnt="$s302" ;; 403) cnt="$s403" ;;
            esac
            if [[ "$live_total" -gt 0 ]]; then
                share="$(awk -v c="$cnt" -v t="$live_total" 'BEGIN{printf "%.1f%%", (c*100)/t}')"
            else
                share="0.0%"
            fi
            printf '<tr><td><span class="pill s%s">%s</span></td><td>%s</td><td>%s</td></tr>\n' "$st" "$st" "$cnt" "$share"
        done
        printf '</table>\n'

        printf '<h2>High-value targets</h2>\n'
        if [[ -s "$CATEGORY_DIR/high_value.txt" ]]; then
            printf '<table><tr><th>Host</th><th>Status</th><th>Title</th></tr>\n'
            # Single pass: join the high-value host list with the probe details
            awk -F'\t' '
                NR==FNR { hv[$0]=1; next }
                {
                    h=$1; sub(/^[A-Za-z]*:\/\//,"",h); sub(/\/.*$/,"",h); sub(/:[0-9]*$/,"",h);
                    if (h in hv) print h "\t" $2 "\t" $3
                }
            ' "$CATEGORY_DIR/high_value.txt" "$LIVE_DIR/live_hosts_details.tsv" 2>/dev/null \
            | head -25 | while IFS=$'\t' read -r hv hst htitle || [[ -n "${hv:-}" ]]; do
                [[ -z "${hv:-}" ]] && continue
                printf '<tr><td><code>%s</code></td><td>%s</td><td class="tl">%s</td></tr>\n' \
                    "$(html_escape "$hv")" "$(html_escape "${hst:-?}")" "$(html_escape "${htitle:-}")"
            done
            printf '</table>\n'
        else
            printf '<p class="tl">No high-value targets were flagged.</p>\n'
        fi

        printf '<h2>Top technologies</h2>\n'
        if [[ -s "$CATEGORY_DIR/tech_breakdown.txt" ]]; then
            printf '<table><tr><th>Technology</th><th>Hosts</th></tr>\n'
            while read -r cnt tech || [[ -n "${tech:-}" ]]; do
                [[ -n "${tech:-}" ]] && printf '<tr><td>%s</td><td>%s</td></tr>\n' "$(html_escape "$tech")" "$cnt"
            done < <(head -15 "$CATEGORY_DIR/tech_breakdown.txt")
            printf '</table>\n'
        else
            printf '<p class="tl">No technologies detected.</p>\n'
        fi

        printf '<h2>Live hosts (first 200)</h2>\n'
        printf '<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Size</th><th>Server</th><th>IP</th></tr>\n'
        if [[ -s "$LIVE_DIR/live_hosts_details.tsv" ]]; then
            # shellcheck disable=SC2034  # host/cname are consumed as placeholders
            while IFS=$'\t' read -r u code title size tech ws host ip cname || [[ -n "${u:-}" ]]; do
                [[ -z "${u:-}" ]] && continue
                printf '<tr><td><code>%s</code></td><td class="s%s">%s</td><td class="tl">%s</td><td>%s</td><td class="tl">%s</td><td><code>%s</code></td></tr>\n' \
                    "$(html_escape "$u")" "${code:-000}" "${code:-}" "$(html_escape "${title:-}")" "${size:-0}" "$(html_escape "${ws:-}")" "$(html_escape "${ip:-}")"
            done < <(head -200 "$LIVE_DIR/live_hosts_details.tsv")
        fi
        printf '</table>\n'

        printf '<h2>Reuse</h2>\n'
        printf '<code class="sh"># live hosts, one per line\ncat %s/live/live_hosts.txt\n\n# 200-only hosts\ncat %s/categories/status_200.txt\n\n# high-value targets\ncat %s/categories/high_value.txt</code>\n' \
            "$(html_escape "$OUT_DIR")" "$(html_escape "$OUT_DIR")" "$(html_escape "$OUT_DIR")"
        printf '<p class="tl" style="margin-top:32px">Generated by %s v%s — %s. Passive reconnaissance tool; use only on authorised assets.</p>\n' \
            "$SCRIPT_NAME" "$SCRIPT_VERSION" "$SCRIPT_AUTHOR"
        printf '</div>\n</body>\n</html>\n'
    } >"$out"
}

# ------------------------------------------------------------------------------
# Final console summary
# ------------------------------------------------------------------------------
print_console_summary() {
    local total_subs live_total probed_total
    total_subs="$(count_lines "$SUBDOMAIN_DIR/all_subdomains.txt")"
    live_total="$(count_lines "$LIVE_DIR/live_hosts.txt")"
    probed_total="$(count_lines "$LIVE_DIR/hosts_probed.txt")"
    local elapsed=$(( $(date +%s) - START_TS ))

    printf '\n'
    printf '%s%s  %s v%s — scan complete%s\n' "$C_BOLD" "$C_GREEN" "$SCRIPT_NAME" "$SCRIPT_VERSION" "$C_RESET"
    printf '%s  ───────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"
    printf '  Target            : %s%s%s\n' "$C_BOLD" "$DOMAIN" "$C_RESET"
    printf '  Subdomains found  : %s%s%s\n' "$C_BOLD" "$total_subs" "$C_RESET"
    printf '  Live hosts        : %s%s%s\n' "$C_GREEN" "$live_total" "$C_RESET"
    printf '  Hosts probed      : %s\n' "$probed_total"
    printf '    200 / 301 / 302 / 403 / other : %s / %s / %s / %s / %s\n' \
        "$(count_lines "$CATEGORY_DIR/status_200.txt")" \
        "$(count_lines "$CATEGORY_DIR/status_301.txt")" \
        "$(count_lines "$CATEGORY_DIR/status_302.txt")" \
        "$(count_lines "$CATEGORY_DIR/status_403.txt")" \
        "$(count_lines "$CATEGORY_DIR/status_other.txt")"
    printf '  High-value hosts  : %s%s%s\n' "$C_YELLOW" "$(count_lines "$CATEGORY_DIR/high_value.txt")" "$C_RESET"
    printf '  Duration          : %ss\n' "$elapsed"
    printf '%s  ───────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"
    printf '  %sReports%s : %s/reports/report.html\n' "$C_CYAN" "$C_RESET" "$OUT_DIR"
    printf '  %sLog%s     : %s\n' "$C_CYAN" "$C_RESET" "$LOG_FILE"
    printf '\n'
}

banner() {
    printf '%s%s\n' "$C_CYAN$C_BOLD" "  ┌──────────────────────────────────────────────────┐"
    printf "  │  %-44s  │\n" "ReconScope v${SCRIPT_VERSION}"
    printf "  │  %-44s  │\n" "Passive Subdomain & Live Host Discovery"
    printf '  └──────────────────────────────────────────────────┘%s\n' "$C_RESET"
    printf '%s  Free & open-source. No API keys. Passive only.%s\n\n' "$C_DIM" "$C_RESET"
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
    START_TS="$(date +%s)"
    parse_args "$@"
    init_colors
    trap cleanup EXIT INT TERM

    banner
    check_deps
    preflight
    gather_subs
    resolve_dns
    probe_hosts
    categorize
    generate_summary
    print_console_summary
}

main "$@"
