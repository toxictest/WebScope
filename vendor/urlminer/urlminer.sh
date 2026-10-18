#!/usr/bin/env bash
# ==============================================================================
#  URLMiner — Passive Endpoint & Parameter Harvester
# ------------------------------------------------------------------------------
#  Version  : 1.0.0
#  License  : MIT
#  Category : Recon & Asset Discovery Pipeline
#  Cost     : 100% free & open-source. No paid APIs. No API keys.
#
#  Pipeline : passive archive harvest (Wayback / Common Crawl / AlienVault)
#             + local crawl  ->  de-duplication  ->  noise filtering
#             ->  categorisation (params / sensitive / api / js)
#
#  Sibling  : URLMiner consumes the output of ReconScope (Day 1):
#             ./urlminer.sh -d example.com -l results/example.com/live/live_hosts.txt
#
#  Legal    : Passive archive queries plus a light crawl of the target's own
#             live hosts. Use only against assets you are authorised to test.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Metadata
# ------------------------------------------------------------------------------
readonly SCRIPT_NAME="URLMiner"
readonly SCRIPT_VERSION="1.0.0"

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
DOMAIN=""                       # -d : target domain
LIST_FILE=""                    # -l : batch input (Day 1 live_hosts.txt)
OUTPUT_ROOT="results"           # -o : output base directory
THREADS="20"                    # archive query concurrency
ARCHIVE_LIMIT="2000"            # max URLs per host per archive
CURL_TIMEOUT="12"               # per-request timeout (seconds)
CRAWL_TIMEOUT="8"               # per-request timeout while crawling
CRAWL="yes"                     # local crawl enabled
JS_FETCH="yes"                  # download JS to extract routes
JS_MAX="60"                     # max JS files to download
STRICT_DEPS="no"                # --strict : abort when optional tools are missing
SEED_FILE=""                     # --seed : reuse a saved harvest instead of querying archives
PROVIDERS="all"                 # all | wayback | commoncrawl | alienvault
NOISE_EXT="png jpg jpeg gif svg ico webp bmp tif tiff css woff woff2 ttf eot otf mp4 webm avi mov mp3 m4a wav flv swf psd"
SENSITIVE_EXT="sql bak old orig save swp swo env ini conf config yaml yml json log csv xml pem key crt p12 pfx jks keystore ppk rdp ovpn kdbx zip tar gz tgz 7z rar dump htpasswd htaccess git svn lock"
# Plain substrings (comma separated) that mark a URL as sensitive.
SENSITIVE_PATH_TOKENS=".git/,.env,.svn/,backup,backups,config,/conf/,phpmyadmin,adminer,wp-config,web.config,id_rsa,id_dsa,credentials,secret,api_key,apikey,private_key,.aws/,.ssh/,.npmrc,.docker,phpinfo,error_log,access_log,dump,.ds_store,.htpasswd,.htaccess,vendor/,.well-known/,password,passwd,.key"

# Runtime state
TARGET=""                      # label used for the output directory
OUT_DIR=""                     # results/<target>/urls
TMP_DIR=""
LOG_FILE=""
SUMMARY_FILE=""
START_TS=0
HOSTS_FILE=""                  # unique hostnames to harvest

# Counters
CNT_RAW=0; CNT_UNIQUE=0; CNT_NOISE=0; CNT_PARAMS=0; CNT_SENSITIVE=0
CNT_API=0; CNT_JS=0; CNT_JSROUTES=0; CNT_HOSTS=0; CNT_LOCAL=0; CNT_EXPOSED=0

# Colours
C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_DIM=""; C_BOLD=""
NO_COLOR_SET="no"                # --no-color

# Tool discovery
GAU_BIN=""; WAYBACKURLS_BIN=""; URO_BIN=""; CURL_BIN=""

# ------------------------------------------------------------------------------
# Colour
# ------------------------------------------------------------------------------
init_colors() {
    local use=0
    if [[ -t 1 && -z "${NO_COLOR:-}" && "$NO_COLOR_SET" != "yes" ]]; then use=1; fi
    if [[ $use -eq 1 ]]; then
        C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
        C_RED=$'\033[1;31m'; C_GREEN=$'\033[1;32m'
        C_YELLOW=$'\033[1;33m'; C_BLUE=$'\033[1;34m'; C_CYAN=$'\033[1;36m'
    fi
}

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
_now() { date '+%H:%M:%S'; }

log_line() {
    local level="$1" color="$2" msg="$3"
    printf '%s[%s]%s %s%-6s%s %s\n' "$color" "$(_now)" "$C_RESET" "$color" "$level" "$C_RESET" "$msg"
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg" >>"$LOG_FILE"
    fi
}

log_info()  { log_line "INFO"  "$C_BLUE"   "$*"; }
log_ok()    { log_line "OK"    "$C_GREEN"  "$*"; }
log_warn()  { log_line "WARN"  "$C_YELLOW" "$*"; }
log_err()   { log_line "ERROR" "$C_RED"    "$*" >&2; }
log_step()  {
    printf '\n%s%s━━━ %s%s\n' "$C_CYAN$C_BOLD" "" "$*" "$C_RESET"
    if [[ -n "$LOG_FILE" ]]; then
        printf '\n--- %s ---\n' "$*" >>"$LOG_FILE"
    fi
}
note() {
    printf '       %s%s%s\n' "$C_DIM" "$*" "$C_RESET"
    if [[ -n "$LOG_FILE" ]]; then printf '       %s\n' "$*" >>"$LOG_FILE"; fi
}
log_debug() {
    [[ "${VERBOSE:-no}" == "yes" ]] || return 0
    log_line "DEBUG" "$C_DIM" "$*"
}

# In-place progress bar
progress() {
    local cur="$1" total="$2" label="$3" width=28 pct=0 filled=0
    [[ "$total" -gt 0 ]] && pct=$(( cur * 100 / total ))
    filled=$(( pct * width / 100 ))
    local bar="" empty=""
    printf -v bar '%*s' "$filled" ''
    printf -v empty '%*s' $(( width - filled )) ''
    bar="${bar// /█}"
    empty="${empty// /░}"
    printf '\r\033[K  %s%s%s %3d%% (%d/%d) %s' "$C_BLUE" "$bar" "$C_RESET" "$pct" "$cur" "$total" "$label"
}
progress_done() { [[ -t 1 ]] && printf '\r\033[K'; return 0; }

# Run a command under a wall-clock limit
run_limited() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@" || true
    else
        "$@" || true
    fi
}

# ------------------------------------------------------------------------------
# Usage
# ------------------------------------------------------------------------------
usage() {
    cat <<EOF
${C_BOLD}${C_CYAN}  URLMiner v${SCRIPT_VERSION}${C_RESET}
${C_DIM}  Passive endpoint & parameter harvester — archives + local crawl${C_RESET}

${C_BOLD}USAGE${C_RESET}
  ./urlminer.sh -d <domain> [-l alive_hosts.txt] [-o output_dir]

${C_BOLD}REQUIRED${C_RESET}
  -d, --domain <domain>    Target domain (or the label for the output directory)

${C_BOLD}OPTIONS${C_RESET}
  -l, --list <file>        Batch input: a list of hosts/URLs (e.g. Day 1's
                           live_hosts.txt). When omitted, URLMiner auto-detects
                           results/<domain>/live/live_hosts.txt.
  -o, --output <dir>       Output base directory              (default: ./results)
  -t, --threads <n>        Archive query concurrency           (default: 20)
      --limit <n>          Max URLs per host per archive      (default: 2000)
      --timeout <sec>      HTTP timeout for the local crawl    (default: 12)
      --providers <list>   all | wayback,commoncrawl,alienvault
      --seed <file>        Re-use a saved raw_urls.txt instead of querying the
                           archives (re-runs categorisation for free)
      --no-crawl           Skip the local crawl stage
      --no-js              Skip downloading JS files for route extraction
      --js-max <n>         Max JS files to download            (default: 60)
      --noise-ext <list>   Extra extensions to treat as noise
      --strict             Abort when the optional Go tools are missing
  -v, --verbose            Verbose logging
      --no-color           Disable ANSI colours
  -h, --help               Show this help and exit

${C_BOLD}SOURCES${C_RESET}
  1. gau          (all providers)          preferred
  2. waybackurls  (Wayback Machine)
  3. built-in     Wayback CDX + Common Crawl + AlienVault OTX via curl
     — the built-in tier keeps URLMiner working when the Go tools are absent.

${C_BOLD}OUTPUT${C_RESET}
  results/<target>/urls/
    ├── all_urls.txt          ★ cleaned, de-duplicated, noise-filtered
    ├── raw_urls.txt          every URL as harvested
    ├── params.txt            ★ URLs carrying query parameters
    ├── param_names.txt       distinct parameter names
    ├── sensitive_params.txt  ★ high-value parameter names
    ├── sensitive_files.txt   ★ backups, configs, credentials
    ├── sensitive_details.tsv what makes each one interesting
    ├── api_endpoints.txt     ★ /api/, /graphql, /rest/, /v1/ ...
    ├── js_files.txt          ★ every JavaScript file
    ├── js_routes.txt         routes extracted from the JavaScript
    ├── js_routes_other.txt   non-API routes found in the same bundles
    ├── interesting_paths.txt non-parameter paths worth a look
    ├── unique_hosts.txt      distinct hosts seen
    ├── endpoints_by_host.txt breakdown per host
    └── local_urls.txt        results of the local crawl

${C_BOLD}EXAMPLES${C_RESET}
  ./urlminer.sh -d example.com
  ./urlminer.sh -d example.com -l results/example.com/live/live_hosts.txt
  ./urlminer.sh -d example.com -o ./scans -t 50
  ./urlminer.sh -d example.com --providers wayback --no-crawl
EOF
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)     [[ -n "${2:-}" ]] || { log_err "Option $1 needs a value."; exit 2; }
                            DOMAIN="$2"; shift 2 ;;
            -d=*|--domain=*) DOMAIN="${1#*=}"; shift ;;
            -l|--list)       [[ -n "${2:-}" ]] || { log_err "Option $1 needs a value."; exit 2; }
                            LIST_FILE="$2"; shift 2 ;;
            -l=*|--list=*)   LIST_FILE="${1#*=}"; shift ;;
            -o|--output)     [[ -n "${2:-}" ]] || { log_err "Option $1 needs a value."; exit 2; }
                            OUTPUT_ROOT="$2"; shift 2 ;;
            -o=*|--output=*) OUTPUT_ROOT="${1#*=}"; shift ;;
            -t|--threads)    THREADS="$2"; shift 2 ;;
            -t=*|--threads=*) THREADS="${1#*=}"; shift ;;
            --limit)         ARCHIVE_LIMIT="$2"; shift 2 ;;
            --limit=*)       ARCHIVE_LIMIT="${1#*=}"; shift ;;
            --timeout)       CURL_TIMEOUT="$2"; CRAWL_TIMEOUT="$2"; shift 2 ;;
            --timeout=*)     CURL_TIMEOUT="${1#*=}"; CRAWL_TIMEOUT="${1#*=}"; shift ;;
            --providers)     PROVIDERS="$2"; shift 2 ;;
            --providers=*)   PROVIDERS="${1#*=}"; shift ;;
            --js-max)        JS_MAX="$2"; shift 2 ;;
            --js-max=*)      JS_MAX="${1#*=}"; shift ;;
            --noise-ext)     NOISE_EXT="$NOISE_EXT $2"; shift 2 ;;
            --seed)          SEED_FILE="$2"; shift 2 ;;
            --seed=*)        SEED_FILE="${1#*=}"; shift ;;
            --no-crawl)      CRAWL="no"; shift ;;
            --no-js)         JS_FETCH="no"; shift ;;
            --strict)        STRICT_DEPS="yes"; shift ;;
            -v|--verbose)    VERBOSE="yes"; shift ;;
            --no-color)      NO_COLOR_SET="yes"; shift ;;
            -h|--help)       init_colors; usage; exit 0 ;;
            --version)       printf '%s v%s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
            *)
                init_colors
                log_err "Unknown argument: '$1'"
                printf '\n'
                usage
                exit 2 ;;
        esac
    done

    if [[ -z "$DOMAIN" && -z "$LIST_FILE" ]]; then
        init_colors
        log_err "Nothing to do — pass -d <domain> and/or -l <file>."
        printf '\n'
        usage
        exit 2
    fi
}

# ------------------------------------------------------------------------------
# Dependency verification
# ------------------------------------------------------------------------------
install_hint() {
    case "$1" in
        gau)         printf 'go install -v github.com/lc/gau/v2/cmd/gau@latest' ;;
        waybackurls) printf 'go install -v github.com/tomnomnom/waybackurls@latest' ;;
        uro)         printf 'go install -v github.com/s0md3v/uro@latest' ;;
        curl)        printf 'sudo apt-get install -y curl   # or: brew install curl' ;;
        *)           printf 'see the README for manual installation' ;;
    esac
}

check_deps() {
    log_step "Stage 0/6 — Dependency verification"

    local -a missing=()
    local -a optional_missing=()

    command -v curl >/dev/null 2>&1 && CURL_BIN="$(command -v curl)" \
        || missing+=("curl")
    command -v gau >/dev/null 2>&1 && GAU_BIN="$(command -v gau)" \
        || optional_missing+=("gau")
    command -v waybackurls >/dev/null 2>&1 && WAYBACKURLS_BIN="$(command -v waybackurls)" \
        || optional_missing+=("waybackurls")
    command -v uro >/dev/null 2>&1 && URO_BIN="$(command -v uro)" \
        || optional_missing+=("uro")

    local t
    for t in sed awk sort grep cut tr; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        printf '\n'
        log_err "Missing required tool(s): ${missing[*]}"
        printf '\n  %sSuggested installation:%s\n' "$C_BOLD" "$C_RESET"
        for t in "${missing[@]}"; do
            printf '    %-12s %s%s%s\n' "$t" "$C_CYAN" "$(install_hint "$t")" "$C_RESET"
        done
        printf '\n'
        log_err "Aborting — nothing was harvested."
        exit 1
    fi

    log_ok "curl        : $CURL_BIN"

    # --- optional Go tools --------------------------------------------------
    if [[ -n "$GAU_BIN" ]]; then
        log_ok "gau         : $GAU_BIN"
    else
        log_warn "gau not installed — falling back to the built-in archive tier."
        note "install with: $(install_hint gau)"
    fi
    if [[ -n "$WAYBACKURLS_BIN" ]]; then
        log_ok "waybackurls : $WAYBACKURLS_BIN"
    else
        log_warn "waybackurls not installed — falling back to the built-in archive tier."
        note "install with: $(install_hint waybackurls)"
    fi
    if [[ -n "$URO_BIN" ]]; then
        log_ok "uro         : $URO_BIN"
    else
        log_info "uro not installed — using sort -u plus the built-in noise filter."
        note "install with: $(install_hint uro)"
    fi

    if [[ ${#optional_missing[@]} -gt 0 && "$STRICT_DEPS" == "yes" ]]; then
        printf '\n'
        log_err "Strict mode: required tool(s) missing: ${optional_missing[*]}"
        printf '\n  %sSuggested installation:%s\n' "$C_BOLD" "$C_RESET"
        for t in "${optional_missing[@]}"; do
            printf '    %-12s %s%s%s\n' "$t" "$C_CYAN" "$(install_hint "$t")" "$C_RESET"
        done
        printf '\n'
        log_err "Aborting in strict mode."
        exit 1
    fi

    # --- which source tier will be used ------------------------------------
    if [[ -n "$GAU_BIN" ]]; then
        log_ok "Archive tier: gau (all providers)"
    elif [[ -n "$WAYBACKURLS_BIN" ]]; then
        log_ok "Archive tier: waybackurls"
    else
        log_ok "Archive tier: built-in (Wayback CDX + Common Crawl + AlienVault OTX)"
    fi
}

# ------------------------------------------------------------------------------
# Stage 1 — target preparation
# ------------------------------------------------------------------------------
preflight() {
    log_step "Stage 1/6 — Target preparation"

    # The scratch directory must exist before anything writes into it.
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/urlminer.XXXXXX")"

    if [[ -n "$DOMAIN" ]]; then
        DOMAIN="${DOMAIN,,}"
        DOMAIN="${DOMAIN#*://}"
        DOMAIN="${DOMAIN%%/*}"
        DOMAIN="${DOMAIN%.}"
        if [[ ! "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]]; then
            log_err "Invalid domain: '$DOMAIN'"
            exit 2
        fi
        TARGET="$DOMAIN"
    fi

    # --- resolve the batch input -------------------------------------------
    if [[ -z "$LIST_FILE" && -n "$DOMAIN" ]]; then
        local cand
        for cand in "${OUTPUT_ROOT%/}/${DOMAIN}/live/live_hosts.txt" \
                    "results/${DOMAIN}/live/live_hosts.txt" \
                    "${OUTPUT_ROOT%/}/${DOMAIN}/live/hosts_probed.txt" \
                    "results/${DOMAIN}/live/hosts_probed.txt"; do
            if [[ -f "$cand" ]]; then
                LIST_FILE="$cand"
                log_ok "Auto-detected Day 1 artifact: $cand"
                break
            fi
        done
    fi

    if [[ -n "$LIST_FILE" ]]; then
        if [[ ! -f "$LIST_FILE" ]]; then
            log_err "Input list not found: $LIST_FILE"
            exit 2
        fi
        log_ok "Batch input : $LIST_FILE"
    fi

    # --- build the host list ------------------------------------------------
    HOSTS_FILE="$TMP_DIR/hosts.txt"
    : >"$HOSTS_FILE"

    if [[ -n "$LIST_FILE" ]]; then
        # Accept a mix of bare hosts and full URLs (Day 1 emits full URLs).
        sed -e 's#^[A-Za-z][A-Za-z0-9+.-]*://##' \
            -e 's#/.*$##' \
            -e 's#:[0-9][0-9]*$##' \
            -e 's/[[:space:]]//g' \
            "$LIST_FILE" 2>/dev/null | grep -v '^$' | sort -u >"$HOSTS_FILE" || true

        # Base URLs for the local crawl, taken straight from the list.
        grep -E '^https?://' "$LIST_FILE" 2>/dev/null | sed 's#[[:space:]]##g' | sort -u \
            >"$TMP_DIR/crawl_bases.txt" || true
    fi

    if [[ -n "$DOMAIN" ]]; then
        printf '%s\n' "$DOMAIN" >>"$HOSTS_FILE"
    fi

    sort -u -o "$HOSTS_FILE" "$HOSTS_FILE"
    CNT_HOSTS=$(wc -l <"$HOSTS_FILE" 2>/dev/null || printf '0'); CNT_HOSTS="${CNT_HOSTS//[[:space:]]/}"

    if [[ "$CNT_HOSTS" -eq 0 ]]; then
        log_err "No hosts to work with."
        exit 2
    fi

    if [[ -z "$TARGET" ]]; then
        TARGET="$(head -n 1 "$HOSTS_FILE")"
    fi

    OUT_DIR="${OUTPUT_ROOT%/}/${TARGET}/urls"
    mkdir -p "$OUT_DIR"
    LOG_FILE="$OUT_DIR/urlminer.log"
    SUMMARY_FILE="$OUT_DIR/urlminer_summary.txt"
    : >"$LOG_FILE"

    log_ok "Target      : $C_BOLD$TARGET$C_RESET"
    log_ok "Output dir  : $(cd "$OUT_DIR" && pwd)"
    log_ok "Hosts       : $CNT_HOSTS"
    log_ok "Workspace ready."
}

# ------------------------------------------------------------------------------
# Stage 2 — passive archive harvest
# ------------------------------------------------------------------------------
# Built-in tier: query the three public archives with curl.
builtin_harvest() {
    local host="$1" out="$2"
    local ua="Mozilla/5.0 (compatible; URLMiner/${SCRIPT_VERSION}; +authorized-security-audit)"
    # The archive APIs are slow; give them a generous multiple of the base
    # timeout, but never less than a minute.
    local atime=$(( CURL_TIMEOUT * 8 ))
    [[ "$atime" -lt 60 ]] && atime=60

    # --- Wayback Machine CDX ---------------------------------------------
    if [[ "$PROVIDERS" == "all" || "$PROVIDERS" == *wayback* ]]; then
        run_limited "$(( atime + 30 ))" "$CURL_BIN" -sS --max-time "$atime" --retry 1 -A "$ua" \
            "https://web.archive.org/cdx/search/cdx?url=*.${host}&output=txt&fl=original&collapse=urlkey&limit=${ARCHIVE_LIMIT}" \
            2>/dev/null >>"$out" || true
    fi

    # --- Common Crawl -----------------------------------------------------
    if [[ "$PROVIDERS" == "all" || "$PROVIDERS" == *commoncrawl* ]]; then
        local cc_api=""
        if [[ -s "$TMP_DIR/cc_api.txt" ]]; then
            cc_api="$(cat "$TMP_DIR/cc_api.txt")"
        else
            cc_api=$(run_limited "$(( atime + 30 ))" "$CURL_BIN" -sS --max-time "$atime" -A "$ua" \
                "https://index.commoncrawl.org/collinfo.json" 2>/dev/null \
                | jq -r '.[0]."cdx-api"' 2>/dev/null || true)
            [[ -n "$cc_api" && "$cc_api" != "null" ]] && printf '%s' "$cc_api" >"$TMP_DIR/cc_api.txt"
        fi
        if [[ -n "$cc_api" && "$cc_api" != "null" ]]; then
            run_limited "$(( atime + 30 ))" "$CURL_BIN" -sS --max-time "$atime" --retry 2 -A "$ua" \
                "${cc_api}?url=*.${host}&output=json&limit=${ARCHIVE_LIMIT}" 2>/dev/null \
                | jq -r '.url // empty' 2>/dev/null >>"$out" || true
        fi
    fi

    # --- AlienVault OTX ----------------------------------------------------
    if [[ "$PROVIDERS" == "all" || "$PROVIDERS" == *alienvault* ]]; then
        local page=1
        while [[ "$page" -le 3 ]]; do
            run_limited "$(( atime + 30 ))" "$CURL_BIN" -sS --max-time "$atime" -A "$ua" \
                "https://otx.alienvault.com/api/v1/indicators/domain/${host}/url_list?limit=100&page=${page}" \
                2>/dev/null | jq -r '.url_list[]?.url // empty' 2>/dev/null >>"$out" || true
            page=$((page + 1))
        done
    fi
}

harvest() {
    log_step "Stage 2/6 — Passive archive harvest"

    local raw="$OUT_DIR/raw_urls.txt"
    local per="$TMP_DIR/host_urls.txt"
    : >"$raw"

    # A seed file short-circuits the archive queries: handy for re-running
    # the categorisation stage over a harvest you already paid for.
    if [[ -n "$SEED_FILE" ]]; then
        if [[ ! -f "$SEED_FILE" ]]; then
            log_err "Seed file not found: $SEED_FILE"
            exit 2
        fi
        cp "$SEED_FILE" "$raw"
        CNT_RAW=$(grep -c . "$raw" 2>/dev/null || true); CNT_RAW="${CNT_RAW//[[:space:]]/}"
        log_ok "Using seeded URLs from $SEED_FILE (${CNT_RAW} URLs) — archive queries skipped"
        progress_done
        return 0
    fi

    local total=$CNT_HOSTS cur=0 host count
    local started=$SECONDS

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        cur=$((cur + 1))
        progress "$cur" "$total" "$host"

        : >"$per"
        if [[ -n "$GAU_BIN" ]]; then
            run_limited 300 "$GAU_BIN" --threads "$THREADS" "$host" 2>/dev/null >>"$per" || true
        elif [[ -n "$WAYBACKURLS_BIN" ]]; then
            printf '%s\n' "$host" | run_limited 300 "$WAYBACKURLS_BIN" 2>/dev/null >>"$per" || true
        else
            builtin_harvest "$host" "$per"
        fi

        count=$(grep -c . "$per" 2>/dev/null || true); count="${count//[[:space:]]/}"
        log_debug "host=$host urls=$count"
        cat "$per" >>"$raw"
    done <"$HOSTS_FILE"
    progress_done

    CNT_RAW=$(grep -c . "$raw" 2>/dev/null || true); CNT_RAW="${CNT_RAW//[[:space:]]/}"
    local dur=$(( SECONDS - started ))

    if [[ "$CNT_RAW" -eq 0 ]]; then
        log_warn "No URLs were harvested from the archives."
        note "This is normal for a brand-new domain. Try --providers all or widen --limit."
    else
        log_ok "Harvested ${C_BOLD}${CNT_RAW}${C_RESET} raw URLs from $CNT_HOSTS host(s) in ${dur}s"
    fi
}

# ------------------------------------------------------------------------------
# Stage 3 — local crawl of the live hosts
# ------------------------------------------------------------------------------
CRAWL_PATHS=(
    "/"
    "/robots.txt"
    "/sitemap.xml"
    "/sitemap_index.xml"
    "/.well-known/security.txt"
    "/api"
    "/api/v1"
    "/graphql"
    "/swagger.json"
    "/openapi.json"
    "/config.json"
    "/manifest.json"
    "/.env"
    "/.git/HEAD"
)

crawl() {
    log_step "Stage 3/6 — Local crawl of live hosts"

    if [[ "$CRAWL" != "yes" ]]; then
        log_warn "Local crawl disabled (--no-crawl)"
        : >"$OUT_DIR/local_urls.txt"
        return 0
    fi

    local bases="$TMP_DIR/crawl_bases.txt"
    if [[ ! -s "$bases" ]]; then
        # No Day 1 list supplied — crawl the target domain itself.
        printf 'https://%s\n' "$DOMAIN" >"$bases" 2>/dev/null || true
    fi

    local out="$OUT_DIR/local_urls.txt"
    local details="$TMP_DIR/crawl_details.tsv"
    : >"$out"; : >"$details"

    local total; total=$(grep -c . "$bases" 2>/dev/null || true); total="${total//[[:space:]]/}"
    if [[ "$total" -eq 0 ]]; then
        log_warn "No live hosts available to crawl."
        return 0
    fi

    local cur=0 base path full body status content
    local ua="Mozilla/5.0 (compatible; URLMiner/${SCRIPT_VERSION}; +authorized-security-audit)"

    while IFS= read -r base; do
        [[ -z "$base" ]] && continue
        cur=$((cur + 1))
        progress "$cur" "$total" "${base}"

        for path in "${CRAWL_PATHS[@]}"; do
            full="${base%/}${path}"
            body=$(run_limited 20 "$CURL_BIN" -sS -k -L --max-time "$CRAWL_TIMEOUT" \
                --connect-timeout 5 -A "$ua" -w $'\n%{http_code}' "$full" 2>/dev/null || true)
            status="${body##*$'\n'}"
            content="${body%$'\n'*}"
            [[ -z "$status" ]] && continue
            [[ "$status" == "000" ]] && continue

            printf '%s\t%s\n' "$full" "$status" >>"$details"

            # A 200 on a sensitive path is a genuine finding.
            if [[ "$path" == "/.env" || "$path" == "/.git/HEAD" ]]; then
                if [[ "$status" == "200" ]]; then
                    CNT_EXPOSED=$((CNT_EXPOSED + 1))
                    log_err "EXPOSED ${full} (HTTP $status)"
                fi
            fi

            # Only 2xx/3xx bodies are worth parsing for links.
            [[ "$status" =~ ^(200|301|302)$ ]] || continue
            printf '%s\n' "$full" >>"$out"

            [[ -z "$content" ]] && continue
            # Extract href/src/action targets and resolve them against the base.
            grep -oE '(href|src|action)=["'"'"'][^"'"'"']+["'"'"']' <<<"$content" 2>/dev/null \
                | sed -E "s/^(href|src|action)=[\"']//; s/[\"']$//" \
                | grep -vE '^(#|javascript:|mailto:|data:|tel:)' \
                | while IFS= read -r link; do
                    case "$link" in
                        http://*|https://*) printf '%s\n' "$link" ;;
                        /*)               printf '%s%s\n' "${base%/}" "$link" ;;
                    esac
                done >>"$out" 2>/dev/null || true
        done
    done <"$bases"
    progress_done

    sort -u -o "$out" "$out"
    CNT_LOCAL=$(grep -c . "$out" 2>/dev/null || true); CNT_LOCAL="${CNT_LOCAL//[[:space:]]/}"

    if [[ "$CNT_LOCAL" -gt 0 ]]; then
        log_ok "Crawl collected ${C_BOLD}${CNT_LOCAL}${C_RESET} local URLs"
    else
        log_warn "The local crawl returned nothing."
    fi
    if [[ "$CNT_EXPOSED" -gt 0 ]]; then
        log_err "$CNT_EXPOSED sensitive file(s) are directly reachable — treat as a finding."
    fi
}

# ------------------------------------------------------------------------------
# Stage 4 — normalise, de-duplicate, filter noise
# ------------------------------------------------------------------------------
clean_urls() {
    log_step "Stage 4/6 — Normalisation, de-duplication & noise filtering"

    local raw="$OUT_DIR/raw_urls.txt"
    local merged="$TMP_DIR/merged.txt"
    local all="$OUT_DIR/all_urls.txt"

    # Merge the archive harvest with the local crawl.
    { cat "$raw" 2>/dev/null || true; cat "$OUT_DIR/local_urls.txt" 2>/dev/null || true; } >"$merged"

    # Normalise: strip fragments, whitespace, trailing punctuation.
    tr -d '\r' <"$merged" \
        | sed -e 's/[[:space:]]//g' \
              -e 's/#.*$//' \
              -e "s/['\"\`<>\\{}|].*\$//" \
              -e 's/[,;]$//' \
        | grep -E '^(https?://|www\.)' \
        | grep -Ev '^(https?://)?[^/]*[ ]' \
        | sort -u >"$TMP_DIR/normalised.txt" || true

    local before; before=$(grep -c . "$TMP_DIR/normalised.txt" 2>/dev/null || true); before="${before//[[:space:]]/}"

    # --- optional uro pass -------------------------------------------------
    local after_uro="$before"
    if [[ -n "$URO_BIN" ]]; then
        run_limited 300 "$URO_BIN" -i "$TMP_DIR/normalised.txt" >"$TMP_DIR/uro.txt" 2>/dev/null || true
        if [[ -s "$TMP_DIR/uro.txt" ]]; then
            after_uro=$(grep -c . "$TMP_DIR/uro.txt" 2>/dev/null || true); after_uro="${after_uro//[[:space:]]/}"
            cp "$TMP_DIR/uro.txt" "$TMP_DIR/normalised.txt"
            log_ok "uro removed $(( before - after_uro )) low-value URLs"
        fi
    fi

    # --- noise filter -------------------------------------------------------
    local ext_re
    ext_re="\\.($(printf '%s' "$NOISE_EXT" | tr ' ' '|' | sed 's/[^a-zA-Z0-9|]//g'))([?#]|$)"
    grep -Eiv "$ext_re" "$TMP_DIR/normalised.txt" 2>/dev/null \
        | grep -Eiv '/(favicon\.ico|apple-touch-icon[^/]*|android-chrome[^/]*|safari-pinned-tab|site\.webmanifest|browserconfig\.xml|manifest\.json)([?#]|$)' \
        >"$all" 2>/dev/null || : >"$all"

    local kept; kept=$(grep -c . "$all" 2>/dev/null || true); kept="${kept//[[:space:]]/}"
    CNT_UNIQUE=$kept
    CNT_NOISE=$(( after_uro - kept ))
    [[ "$CNT_NOISE" -lt 0 ]] && CNT_NOISE=0

    log_ok "Unique URLs : ${C_BOLD}${CNT_UNIQUE}${C_RESET} -> urls/all_urls.txt"
    log_ok "Noise dropped : $CNT_NOISE (images, fonts, stylesheets, icon paths)"

    # Distinct hosts
    sed -e 's#^[A-Za-z][A-Za-z0-9+.-]*://##' -e 's#/.*$##' -e 's#:[0-9][0-9]*$##' "$all" 2>/dev/null \
        | grep -v '^$' | sort -u >"$OUT_DIR/unique_hosts.txt" || true
    local uh; uh=$(grep -c . "$OUT_DIR/unique_hosts.txt" 2>/dev/null || true); uh="${uh//[[:space:]]/}"
    log_ok "Unique hosts : $uh"

    # Per-host breakdown
    awk -F/ '{ host=$3; if (host != "") print host }' "$all" 2>/dev/null \
        | sort | uniq -c | sort -rn >"$OUT_DIR/endpoints_by_host.txt" 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# Stage 5 — categorisation modules
# ------------------------------------------------------------------------------
categorize() {
    log_step "Stage 5/6 — Endpoint categorisation"

    local all="$OUT_DIR/all_urls.txt"

    # ---------------------------------------------------------------------
    # Module 1 — parameter mining
    # ---------------------------------------------------------------------
    grep -E '\?[^=&[:space:]]+=' "$all" 2>/dev/null | sort -u >"$OUT_DIR/params.txt" || : >"$OUT_DIR/params.txt"
    CNT_PARAMS=$(grep -c . "$OUT_DIR/params.txt" 2>/dev/null || true); CNT_PARAMS="${CNT_PARAMS//[[:space:]]/}"

    # Distinct parameter names.
    # NOTE: a backslash does NOT escape ']' inside a POSIX bracket expression —
    # the first ']' terminates the class early and the pattern silently matches
    # nothing. The character class is therefore kept to unambiguous members and
    # the array suffix is matched as a separate optional group, e.g.
    # "filter[]=x" is captured as "filter[]" and then normalised to "filter".
    grep -oE '[?&][A-Za-z0-9_.-]{1,60}(\[\])?=' "$OUT_DIR/params.txt" 2>/dev/null \
        | sed -e 's/^[?&]//' -e 's/=$//' -e 's/\[\]//g' \
        | sort -u >"$OUT_DIR/param_names.txt" || : >"$OUT_DIR/param_names.txt"

    # High-value parameter names worth fuzzing.
    grep -iE '^(id|uid|gid|user|username|uname|login|email|password|passwd|pwd|pass|secret|token|api_?key|apikey|access_?key|auth|authorization|redirect|redirect_?url|return_?url|next|dest|destination|url|uri|path|file|filename|dir|folder|include|template|cmd|command|exec|exec_?url|shell|query|q|search|view|action|module|load|page_?id|callback|jsonp|src|target|host|domain|server|proxy|port|ip|data|xml|html|content|doc|download|upload|lang|locale|config|debug|test|version|offset|limit|view_?state|csrf_?token|state|session|sid|code|otp|mfa|2fa|pin|hash|salt|key)$' \
        "$OUT_DIR/param_names.txt" 2>/dev/null | sort -u >"$OUT_DIR/sensitive_params.txt" || : >"$OUT_DIR/sensitive_params.txt"

    local sp; sp=$(grep -c . "$OUT_DIR/sensitive_params.txt" 2>/dev/null || true); sp="${sp//[[:space:]]/}"
    log_ok "Module 1 — parameters: ${C_BOLD}${CNT_PARAMS}${C_RESET} URLs, $sp distinct high-value parameter names"

    # ---------------------------------------------------------------------
    # Module 2 — sensitive extensions & paths
    # ---------------------------------------------------------------------
    # Extension match: the last path segment ends with a sensitive extension.
    # Path match: a plain substring from the sensitive-path list.
    local sens_re
    sens_re="\\.($(printf '%s' "$SENSITIVE_EXT" | tr ' ' '|' | sed 's/[^a-zA-Z0-9|]//g'))([?#]|$)"

    printf '%s' "$SENSITIVE_PATH_TOKENS" | tr ',' '\n' | sed '/^$/d' >"$TMP_DIR/sens_tokens.txt"

    # Union of both signals, in one pass.
    {
        grep -Ei "$sens_re" "$all" 2>/dev/null || true
        grep -F -f "$TMP_DIR/sens_tokens.txt" "$all" 2>/dev/null || true
    } | sort -u >"$OUT_DIR/sensitive_files.txt" || : >"$OUT_DIR/sensitive_files.txt"

    CNT_SENSITIVE=$(grep -c . "$OUT_DIR/sensitive_files.txt" 2>/dev/null || true); CNT_SENSITIVE="${CNT_SENSITIVE//[[:space:]]/}"

    # Explain *why* each one is interesting — a single awk pass, no forks.
    awk -v exts="$(printf '%s' "$SENSITIVE_EXT" | tr ' ' ',')" \
        -v paths="$SENSITIVE_PATH_TOKENS" '
        BEGIN {
            n = split(exts, e, ","); for (i = 1; i <= n; i++) ext[e[i]] = 1
            m = split(paths, p, ","); for (i = 1; i <= m; i++) ptok[p[i]] = 1
        }
        {
            url = $0
            low = tolower(url)
            why = ""
            # last path segment (ignoring any query string)
            seg = url
            q = index(seg, "?"); if (q > 0) seg = substr(seg, 1, q - 1)
            s2 = split(seg, sl, "/"); last = tolower(sl[s2])
            d = index(last, ".")
            if (d > 0) {
                ext = substr(last, d + 1)
                if (ext in ext) why = "sensitive extension: ." ext
            }
            if (why == "") {
                for (i = 1; i <= m; i++) {
                    if (length(ptok[i]) > 0 && index(low, tolower(ptok[i])) > 0) {
                        why = "sensitive path: " ptok[i]
                        break
                    }
                }
            }
            if (why == "") why = "sensitive"
            print url "\t" why
        }
    ' "$OUT_DIR/sensitive_files.txt" >"$OUT_DIR/sensitive_details.tsv" 2>/dev/null \
        || : >"$OUT_DIR/sensitive_details.tsv"

    log_ok "Module 2 — sensitive files: ${C_BOLD}${CNT_SENSITIVE}${C_RESET} candidate paths"

    # ---------------------------------------------------------------------
    # Module 3 — API & endpoint sorting
    # ---------------------------------------------------------------------
    grep -Ei '/(api|apis|rest|graphql|gql|rpc|ws|websocket|webhook|webhooks|oauth|oauth2|token|auth|service|services|backend|internal|admin/api|_api|openapi|swagger|api-docs|apispec|graphql-playground)(/|$|[?#])|/v[0-9]+(/|$|\?)|\\.(json|xml)(\?|$)|/(rest|json|rpc|api)/' \
        "$all" 2>/dev/null | sort -u >"$OUT_DIR/api_endpoints.txt" || : >"$OUT_DIR/api_endpoints.txt"
    CNT_API=$(grep -c . "$OUT_DIR/api_endpoints.txt" 2>/dev/null || true); CNT_API="${CNT_API//[[:space:]]/}"
    log_ok "Module 3 — API endpoints: ${C_BOLD}${CNT_API}${C_RESET} routes"

    # ---------------------------------------------------------------------
    # Module 4 — JavaScript files
    # ---------------------------------------------------------------------
    grep -Ei '\.(js|mjs|cjs)(\?|$)' "$all" 2>/dev/null | sort -u >"$OUT_DIR/js_files.txt" || : >"$OUT_DIR/js_files.txt"
    CNT_JS=$(grep -c . "$OUT_DIR/js_files.txt" 2>/dev/null || true); CNT_JS="${CNT_JS//[[:space:]]/}"
    log_ok "Module 4 — JavaScript files: ${C_BOLD}${CNT_JS}${C_RESET} -> urls/js_files.txt"

    # --- route extraction from the JavaScript --------------------------------
    : >"$OUT_DIR/js_routes.txt"
    if [[ "$JS_FETCH" == "yes" && "$CNT_JS" -gt 0 ]]; then
        extract_js_routes
    fi

    # ---------------------------------------------------------------------
    # Extra — interesting non-parameter paths
    # ---------------------------------------------------------------------
    grep -vE '\?' "$all" 2>/dev/null \
        | grep -Eiv '\.(html?|php|aspx?|jsp|css|js|mjs|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|mp[34]|pdf)(\?|$)' \
        | sort -u >"$OUT_DIR/interesting_paths.txt" || : >"$OUT_DIR/interesting_paths.txt"
}

extract_js_routes() {
    local jslist="$OUT_DIR/js_files.txt"
    local out="$OUT_DIR/js_routes.txt"
    local tmpjs="$TMP_DIR/js_cache"
    mkdir -p "$tmpjs"

    local total; total=$(grep -c . "$jslist" 2>/dev/null || true); total="${total//[[:space:]]/}"
    [[ "$total" -eq 0 ]] && return 0

    local limit=$JS_MAX
    [[ "$total" -lt "$limit" ]] && limit=$total

    local ua="Mozilla/5.0 (compatible; URLMiner/${SCRIPT_VERSION}; +authorized-security-audit)"
    local cur=0 url body

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        cur=$((cur + 1))
        [[ "$cur" -gt "$limit" ]] && break
        progress "$cur" "$limit" "downloading JS"

        body=$(run_limited 20 "$CURL_BIN" -sS -k -L --max-time 10 --connect-timeout 5 \
            -A "$ua" "$url" 2>/dev/null || true)
        [[ -z "$body" ]] && continue
        printf '%s' "$body" >>"$tmpjs/all.js"
        printf '\n' >>"$tmpjs/all.js"
    done <"$jslist"
    progress_done

    if [[ -s "$tmpjs/all.js" ]]; then
        # Quoted path-like strings that look like routes.
        grep -oE '["'"'"'`]/[A-Za-z0-9._~!$&()*+,;=:@%/-]{2,120}["'"'"'`]' "$tmpjs/all.js" 2>/dev/null \
            | tr -d '"'"'"'`' \
            | grep -E '^/[A-Za-z0-9._~!$&()*+,;=:@%/-]+$' \
            | sort -u >"$TMP_DIR/js_routes_raw.txt" 2>/dev/null || : >"$TMP_DIR/js_routes_raw.txt"

        # Keep the ones that actually look like API routes.
        # Single-segment routes such as "/graphql" are deliberately kept —
        # requiring a second slash would throw away the most interesting
        # endpoints. The prefix list below does the actual filtering.
        grep -Ei '^/(api|apis|rest|graphql|gql|rpc|ws|websocket|webhook|webhooks|oauth|oauth2|auth|token|service|services|backend|internal|admin|user|users|account|accounts|profile|settings|config|data|download|upload|search|login|logout|register|order|orders|product|products|cart|checkout|payment|panel|dashboard|metrics|status|health|version|v[0-9]+)(/|$|\?)' \
            "$TMP_DIR/js_routes_raw.txt" 2>/dev/null | sort -u | awk 'NR<=5000' >"$out" || : >"$out"
        CNT_JSROUTES=$(grep -c . "$out" 2>/dev/null || true); CNT_JSROUTES="${CNT_JSROUTES//[[:space:]]/}"

        # Any remaining routes are still worth keeping in a secondary file.
        grep -FvxFf "$out" "$TMP_DIR/js_routes_raw.txt" 2>/dev/null | sort -u | awk 'NR<=5000' \
            >"$OUT_DIR/js_routes_other.txt" || : >"$OUT_DIR/js_routes_other.txt"

        log_ok "JS route extraction: ${C_BOLD}${CNT_JSROUTES}${C_RESET} API routes from $limit file(s)"
    else
        log_warn "No JavaScript could be downloaded — route extraction skipped."
    fi
}

# ------------------------------------------------------------------------------
# Stage 6 — execution summary
# ------------------------------------------------------------------------------
generate_summary() {
    log_step "Stage 6/6 — Execution summary"

    local elapsed=$(( $(date +%s) - START_TS ))

    # ---- text summary ------------------------------------------------------
    {
        printf '===============================================================\n'
        printf ' %s v%s — Harvest Summary\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '===============================================================\n\n'
        printf 'Target           : %s\n' "$TARGET"
        printf 'Date             : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'Duration         : %02d:%02d:%02d\n' \
            "$(( elapsed / 3600 ))" "$(( (elapsed % 3600) / 60 ))" "$(( elapsed % 60 ))"
        printf 'Hosts            : %s\n' "$CNT_HOSTS"
        printf 'Input list       : %s\n' "${LIST_FILE:-(none)}"
        printf 'Output           : %s\n' "$(cd "$OUT_DIR" && pwd)"
        printf '\n--- COUNTS ----------------------------------------------------\n'
        printf 'Total URLs (raw) : %s\n' "$CNT_RAW"
        printf 'Total URLs (kept): %s\n' "$CNT_UNIQUE"
        printf 'Noise filtered   : %s\n' "$CNT_NOISE"
        printf 'Unique hosts     : %s\n' "$(grep -c . "$OUT_DIR/unique_hosts.txt" 2>/dev/null || printf 0)"
        printf 'Local crawl URLs : %s\n' "$CNT_LOCAL"
        printf '\n--- MODULES ---------------------------------------------------\n'
        printf 'Parameters found : %s\n' "$CNT_PARAMS"
        printf 'Sensitive paths  : %s\n' "$CNT_SENSITIVE"
        printf 'API endpoints    : %s\n' "$CNT_API"
        printf 'JS files         : %s\n' "$CNT_JS"
        printf 'JS API routes    : %s\n' "$CNT_JSROUTES"
        printf 'Exposed secrets  : %s\n' "$CNT_EXPOSED"
        printf '\n--- TOP HIGH-VALUE PARAMETERS ----------------------------------\n'
        head -25 "$OUT_DIR/sensitive_params.txt" 2>/dev/null | tr '\n' ' '
        printf '\n\n--- ARTIFACTS -------------------------------------------------\n'
        printf 'all_urls.txt params.txt param_names.txt sensitive_params.txt\n'
        printf 'sensitive_files.txt sensitive_details.tsv api_endpoints.txt\n'
        printf 'js_files.txt js_routes.txt interesting_paths.txt unique_hosts.txt\n'
        printf 'endpoints_by_host.txt local_urls.txt raw_urls.txt\n'
    } >"$SUMMARY_FILE"

    # ---- console table -----------------------------------------------------
    # Inner width is fixed so every row's right border lines up.
    local inner=48
    local bar; bar="$(printf '═%.0s' $(seq 1 "$inner"))"
    local thin; thin="$(printf '─%.0s' $(seq 1 "$inner"))"

    # NOTE: printf's %-Ns pads by BYTES, so a multi-byte character (an em
    # dash, for example) would shorten the visible row and break the border
    # alignment. Labels are therefore kept ASCII.
    trow() {   # trow <label> <value> [bold]
        local lbl="${1:-}" val="${2:-}" bold="${3:-}" style="$C_CYAN"
        [[ "$bold" == "bold" ]] && style="$C_CYAN$C_BOLD"
        printf '%s║%s  %-35s %10s%s║%s\n' "$style" "" "$lbl" "$val" "$style" "$C_RESET"
    }
    twide() {  # twide <text> [bold]
        local txt="${1:-}" bold="${2:-}" style="$C_CYAN"
        [[ "$bold" == "bold" ]] && style="$C_CYAN$C_BOLD"
        printf '%s║%s  %-46s%s║%s\n' "$style" "" "$txt" "$style" "$C_RESET"
    }

    printf '\n'
    printf '%s╔%s╗%s\n' "$C_CYAN$C_BOLD" "$bar" "$C_RESET"
    twide "URLMiner - Execution Summary" "bold"
    printf '%s╠%s╣%s\n' "$C_CYAN$C_BOLD" "$bar" "$C_RESET"

    trow "Target" "$TARGET"
    trow "Hosts processed" "$CNT_HOSTS"
    trow "Duration" "$(printf '%02d:%02d:%02d' $(( elapsed / 3600 )) $(( (elapsed % 3600) / 60 )) $(( elapsed % 60 )))"
    printf '%s╠%s╣%s\n' "$C_CYAN$C_BOLD" "$thin" "$C_RESET"

    trow "Total URLs (raw)" "$CNT_RAW" "bold"
    trow "Total URLs (kept)" "$CNT_UNIQUE" "bold"
    trow "Noise filtered" "$CNT_NOISE"
    trow "Unique hosts" "$(grep -c . "$OUT_DIR/unique_hosts.txt" 2>/dev/null || printf 0)"
    trow "Local crawl URLs" "$CNT_LOCAL"
    printf '%s╠%s╣%s\n' "$C_CYAN$C_BOLD" "$thin" "$C_RESET"

    trow "Parameters found" "$CNT_PARAMS" "bold"
    trow "Sensitive paths found" "$CNT_SENSITIVE" "bold"
    trow "API endpoints found" "$CNT_API" "bold"
    trow "JavaScript files" "$CNT_JS" "bold"
    trow "JS API routes" "$CNT_JSROUTES"
    trow "Exposed sensitive files" "$CNT_EXPOSED"
    printf '%s╠%s╣%s\n' "$C_CYAN$C_BOLD" "$thin" "$C_RESET"

    twide "Output: $(cd "$OUT_DIR" && pwd)"
    twide "Summary: urlminer_summary.txt"
    printf '%s╚%s╝%s\n' "$C_CYAN$C_BOLD" "$bar" "$C_RESET"
    printf '\n'
}

# Cleanup — preserves the caller's exit status (a bare `exit 0` in an EXIT
# trap would mask genuine failures).
urlminer_cleanup() {
    local rc=$?
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    return $rc
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
main() {
    START_TS="$(date +%s)"
    parse_args "$@"
    init_colors
    trap 'urlminer_cleanup' EXIT
    trap 'urlminer_cleanup; exit 130' INT TERM

    printf '%s%s\n' "$C_CYAN$C_BOLD" "  ┌──────────────────────────────────────────────────────┐"
    printf "  │  %-50s  │\n" "URLMiner v${SCRIPT_VERSION}"
    printf "  │  %-50s  │\n" "Passive Endpoint & Parameter Harvester"
    printf '  └──────────────────────────────────────────────────────┘%s\n' "$C_RESET"
    printf '%s  Free & open-source. No API keys. Archive data + local crawl.%s\n\n' "$C_DIM" "$C_RESET"

    check_deps
    preflight
    harvest
    crawl
    clean_urls
    categorize
    generate_summary
}

main "$@"
