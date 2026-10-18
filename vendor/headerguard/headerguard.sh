#!/usr/bin/env bash
# ==============================================================================
#  HeaderGuard v1.0.0
#  Automated Security Headers & CORS Policy Auditor
#  ---------------------------------------------------------------------------
#  Takes Day 1's live_hosts.txt (or a single URL) and inspects the HTTP
#  response headers for:
#     Module 1 - missing / weak OWASP security headers
#     Module 2 - information disclosure (banner leakage)
#     Module 3 - CORS policy verification (wildcard / origin reflection)
#     Module 4 - cookie attribute hygiene (Secure / HttpOnly / SameSite)
#
#  100% free and standalone: curl + grep/awk/sed/tr only.
#  No API keys, no paid services, no Go or Python runtime dependency.
# ==============================================================================

set -euo pipefail

SCRIPT_NAME="HeaderGuard"
SCRIPT_VERSION="1.0.0"

# ------------------------------------------------------------------ defaults --
TARGET_URL=""
LIST_FILE=""
REPORT_FILE="headerguard_report.txt"
REPORT_FORMAT="auto"          # auto | text | csv
THREADS=10
TIMEOUT=10
CONNECT_TIMEOUT=5
PROBE_ORIGIN="https://headerguard-probe.invalid"
OUT_DIR=""
INSECURE=0
NO_COLOR=0
VERBOSE=0
STRICT=0

# Required header set (Module 1).
H_HSTS="strict-transport-security"
H_CSP="content-security-policy"
H_XFO="x-frame-options"
H_XCTO="x-content-type-options"
H_RP="referrer-policy"
H_PP="permissions-policy"
H_CSP_RO="content-security-policy-report-only"

HSTS_MIN_MAXAGE=15552000      # 180 days - anything shorter counts as weak

# Valid Referrer-Policy values.
VALID_RP=" no-referrer no-referrer-when-downgrade origin origin-when-cross-origin same-origin strict-origin strict-origin-when-cross-origin unsafe-url "

# Header names that leak implementation details (Module 2).
DISCLOSURE_HEADERS=(server x-powered-by x-aspnet-version x-aspnet-mvc-version
                    x-generator x-runtime x-shopify-stage x-drupal-cache
                    x-debug-token x-aspnet-duration)

TMP_DIR=""
START_TS=$(date +%s)
TARGET_COUNT=0
REACHABLE=0
UNREACHABLE=0
TOTAL_SCORE=0
TOTAL_HEADERS_PASSED=0
TOTAL_HEADERS_TOTAL=0
GRADE_AP=0
GRADE_A=0
GRADE_B=0
GRADE_C=0
GRADE_D=0
GRADE_F=0
TOTAL_FAILS=0
CURL_VERSION="unknown"
PROGRESS_DRAWN=0

declare -a TARGETS=()
declare -a FINDINGS=()
declare -a RF=()
declare -A R=()

# ------------------------------------------------------------------ colours --
C_RESET=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_DIM=""; C_BOLD=""
init_colors() {
    if [[ "$NO_COLOR" -eq 0 && -t 1 ]]; then
        C_RESET=$'\033[0m'
        C_RED=$'\033[1;31m'
        C_GRN=$'\033[1;32m'
        C_YEL=$'\033[1;33m'
        C_BLU=$'\033[1;34m'
        C_CYN=$'\033[1;36m'
        C_DIM=$'\033[2m'
        C_BOLD=$'\033[1m'
    fi
}

# ------------------------------------------------------------------ logging --
_ts() { date '+%H:%M:%S'; }

log_info() { printf '[%s] %sINFO%s   %s\n' "$(_ts)" "$C_BLU" "$C_RESET" "$*"; }
log_ok()   { printf '[%s] %sOK%s     %s\n' "$(_ts)" "$C_GRN" "$C_RESET" "$*"; }
log_warn() { printf '[%s] %sWARN%s   %s\n' "$(_ts)" "$C_YEL" "$C_RESET" "$*"; }
log_err()  { printf '[%s] %sERROR%s  %s\n' "$(_ts)" "$C_RED" "$C_RESET" "$*"; }
log_step() { printf '\n%s%s%s\n' "$C_BLU" "$*" "$C_RESET"; }

die() {
    log_err "$*"
    exit 2
}

PROGRESS_DRAWN=0
progress() {
    local cur="$1" total="$2" label="${3:-working}"
    [[ "$total" -le 0 ]] && return 0
    local pct=$(( cur * 100 / total ))
    local width=30
    local filled=$(( pct * width / 100 ))
    local bar="" i
    for (( i = 0; i < filled; i++ )); do bar+="#"; done
    for (( i = filled; i < width; i++ )); do bar+="-"; done
    printf '\r%s[%s]%s %3d%% (%d/%d) %s' "$C_CYN" "$bar" "$C_RESET" "$pct" "$cur" "$total" "$label"
    PROGRESS_DRAWN=1
}

progress_done() {
    [[ "$PROGRESS_DRAWN" -eq 1 ]] || return 0
    printf '\r%-90s\r' ""
    PROGRESS_DRAWN=0
}

banner() {
    local w=54
    local bar="" i
    for (( i = 0; i < w; i++ )); do bar+="─"; done
    printf '%s\n' "$C_CYN"
    printf '  ┌%s┐\n' "$bar"
    printf '  │  %s%-52s│\n' "$C_BOLD" "$SCRIPT_NAME v$SCRIPT_VERSION"
    printf '  │  %s%-52s│\n' "" "Automated Security Headers & CORS Auditor"
    printf '  └%s┘\n' "$bar"
    printf '%s\n' "$C_RESET"
    printf '  Free & standalone. No API keys. curl + grep/awk/sed/tr only.\n\n'
}

# ------------------------------------------------------------------ cleanup --
cleanup() {
    local rc=$?
    [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR" 2>/dev/null || true
    return $rc
}
trap 'rc=$?; cleanup; exit $rc' EXIT

# ------------------------------------------------------------------ usage ---
usage() {
    cat <<EOF
${C_BOLD}${C_CYN}  $SCRIPT_NAME v$SCRIPT_VERSION${C_RESET}
${C_DIM}  Automated security headers & CORS policy auditor${C_RESET}

${C_BOLD}USAGE${C_RESET}
  ./headerguard.sh -u https://example.com [-l alive_hosts.txt] [-o report.txt]
  ./headerguard.sh -l results/example.com/live/live_hosts.txt -o report.csv

${C_BOLD}REQUIRED (one of)${C_RESET}
  -u, --url <url>        Single target URL to audit
  -l, --list <file>      Batch input: one URL or host per line (e.g. Day 1's
                         live_hosts.txt). Entries without a scheme are audited
                         over https://.

${C_BOLD}OPTIONS${C_RESET}
  -o, --output <file>    Report file                     (default: $REPORT_FILE)
      --format <fmt>     text | csv | auto (auto = by file extension)
  -t, --threads <n>      Parallel audits                 (default: $THREADS)
      --timeout <sec>    Per-request HTTP timeout        (default: $TIMEOUT)
      --connect-timeout  Connect timeout                 (default: $CONNECT_TIMEOUT)
      --origin <url>     Origin used by the CORS probe   (default: $PROBE_ORIGIN)
      --outdir <dir>     Also write one detail file per target
      --insecure         Skip TLS certificate verification
      --strict           Exit 1 when any FAIL finding is recorded
  -v, --verbose          Verbose logging
      --no-color         Disable ANSI colours
  -h, --help             Show this help and exit

${C_BOLD}MODULES${C_RESET}
  1  Security headers        Strict-Transport-Security, Content-Security-Policy,
                             X-Frame-Options, X-Content-Type-Options,
                             Referrer-Policy, Permissions-Policy
  2  Information disclosure  Server / X-Powered-By / CMS banners
  3  CORS policy             wildcard (*) and arbitrary-origin reflection
  4  Cookie flags            Secure, HttpOnly, SameSite

${C_BOLD}SCORING${C_RESET}
  6 headers x 10 = 60 | no disclosure = 15 | CORS safe = 15 | cookies safe = 10
  Grade: A+ >=95, A >=90, B >=80, C >=70, D >=60, F <60

${C_BOLD}COLOURS${C_RESET}
  ${C_GRN}Green${C_RESET}  present / secure      ${C_RED}Red${C_RESET}    missing / insecure
  ${C_YEL}Yellow${C_RESET}  info disclosure / review needed

${C_BOLD}EXAMPLES${C_RESET}
  ./headerguard.sh -u https://example.com
  ./headerguard.sh -l live_hosts.txt -o report.txt
  ./headerguard.sh -l live_hosts.txt -o report.csv --format csv
EOF
}

# ------------------------------------------------------------- dependencies --
check_deps() {
    log_step "Stage 0/6 - Dependency verification"

    local missing=0 tool path
    for tool in curl awk grep sed tr sort; do
        path=$(command -v "$tool" 2>/dev/null || true)
        if [[ -n "$path" ]]; then
            log_ok "$(printf '%-12s %s' "$tool" "$path")"
        else
            log_err "missing required tool: $tool"
            missing=1
        fi
    done

    if [[ "$missing" -ne 0 ]]; then
        printf '\n'
        log_err "HeaderGuard needs only core Linux utilities. Install them with:"
        printf '  Debian/Ubuntu : sudo apt-get install -y curl gawk grep sed coreutils\n'
        printf '  RHEL/Fedora   : sudo dnf install -y curl gawk grep sed coreutils\n'
        printf '  Alpine        : sudo apk add curl gawk grep sed coreutils\n'
        printf '\n'
        die "Dependency check failed."
    fi

    CURL_VERSION=$(curl --version 2>/dev/null | awk 'NR==1{print $2}' || true)
    log_ok "All dependencies present - no paid tools required."

    # Self-check: the embedded awk normaliser must compile.  If it does not,
    # every target would be reported as having no headers at all, which is
    # exactly the kind of silent failure this tool must never have.
    local awk_err
    awk_err=$(awk "$NORMALISE_AWK" /dev/null 2>&1 >/dev/null || true)
    if [[ -n "$awk_err" ]]; then
        log_err "internal error: the header normaliser does not compile"
        printf '  %s\n' "$awk_err"
        die "Aborting - the audit would report false results."
    fi
    log_ok "Header normaliser compiled successfully."
}

# ------------------------------------------------------------ target loading --
load_targets() {
    local -a raw=()
    local line

    if [[ -n "$LIST_FILE" ]]; then
        [[ -f "$LIST_FILE" ]] || die "List file not found: $LIST_FILE"
        while IFS= read -r line || [[ -n "$line" ]]; do
            local stripped="${line%%#*}"
            stripped="${stripped//[[:space:]]/}"
            [[ -z "$stripped" ]] && continue
            raw+=("$stripped")
        done <"$LIST_FILE"
    fi

    if [[ -n "$TARGET_URL" ]]; then
        raw+=("$TARGET_URL")
    fi

    [[ ${#raw[@]} -eq 0 ]] && die "No targets. Use -u <url> or -l <file>."

    local -a norm=()
    for line in "${raw[@]}"; do
        if [[ "$line" != *"://"* ]]; then
            line="https://$line"
        fi
        line="${line%/}"
        [[ -z "$line" ]] && continue
        norm+=("$line")
    done

    local -a uniq=()
    local seen="|"
    for line in "${norm[@]}"; do
        if [[ "$seen" != *"|$line|"* ]]; then
            uniq+=("$line")
            seen="$seen$line|"
        fi
    done

    TARGETS=("${uniq[@]}")
    TARGET_COUNT=${#TARGETS[@]}
    log_ok "$TARGET_COUNT unique target(s) queued."
}

# --------------------------------------------------------- header normaliser -
# Turns a curl -D dump into "KIND<TAB>KEY<TAB>VALUE" lines, keeping only the
# FINAL response of a redirect chain.  POSIX awk (mawk safe): no IGNORECASE,
# no gensub, no nested arrays.
NORMALISE_AWK='
{ line[++n] = $0 }
END {
    blk = 0; inblk = 0
    for (i = 1; i <= n; i++) {
        L = line[i]
        if (L ~ /^[ \t\r]*$/) {
            inblk = 0
        } else if (L ~ /^HTTP\//) {
            blk++; inblk = 1
            stat[blk] = L
        } else if (inblk == 1) {
            p = index(L, ":")
            if (p > 0) {
                k = substr(L, 1, p - 1)
                v = substr(L, p + 1)
                gsub(/^[ \t]+/, "", k); gsub(/[ \t\r]+$/, "", k)
                gsub(/^[ \t]+/, "", v); gsub(/[ \t\r]+$/, "", v)
                gsub(/\r/, " ", v)
                gsub(/\t/, " ", v)
                lk = tolower(k)
                if (lk == "set-cookie") {
                    sc[blk, ++nsc[blk]] = v
                } else {
                    bk = blk SUBSEP k
                    if (!(bk in seen)) { seen[bk] = 1; ord[blk, ++kc[blk]] = k }
                    # NB: do NOT write this as
                    #     val[bk] = (bk in val) ? val[bk] " " v : v
                    # referencing val[bk] on the left-hand side CREATES the
                    # element, so the "in" test then always succeeds and every
                    # value is prefixed with a stray space.
                    if (bk in val) {
                        val[bk] = (val[bk] == "") ? v : val[bk] " " v
                    } else {
                        val[bk] = v
                    }
                }
            }
        }
    }
    if (blk == 0) exit 0
    last = blk
    code = stat[last]
    sub(/^HTTP\/[^ ]+[ ]+/, "", code)
    sub(/[ ].*$/, "", code)
    # printf, not print: print inserts OFS between every expression, which
    # would put a stray space around each field and break the tab split.
    printf "STATUS\t%s\n", code
    for (j = 1; j <= kc[last]; j++) {
        k = ord[last, j]
        printf "HDR\t%s\t%s\n", k, val[last SUBSEP k]
    }
    for (j = 1; j <= nsc[last]; j++) printf "COOKIE\t%s\n", sc[last, j]
}
'

# ------------------------------------------------------------------- helpers --
add_finding() {
    # severity|module|label|detail   severity: PASS | FAIL | WARN | INFO
    FINDINGS+=("$1|$2|$3|$4")
}

sev_colour() {
    case "$1" in
        PASS) printf '%s' "$C_GRN" ;;
        FAIL) printf '%s' "$C_RED" ;;
        WARN) printf '%s' "$C_YEL" ;;
        *)    printf '%s' "$C_CYN" ;;
    esac
}

# ============================================================== target audit ==
audit_target() {
    local idx="$1" url="$2"
    local dir="$TMP_DIR/targets/$idx"
    mkdir -p "$dir"

    local hdr="$dir/headers.txt"
    local chdr="$dir/cors_headers.txt"
    local res="$dir/result.txt"

    FINDINGS=()
    local -A H=()
    local -A ORIG=()
    local -A CH=()
    local -a COOKIES=()
    local status="000" final_url="$url" redirects="0" rtime="0"
    local tls_ok="yes" reach="no" err=""

    local -a ssl_opt=()
    [[ "$INSECURE" -eq 1 ]] && ssl_opt=(-k)

    local ua="Mozilla/5.0 (compatible; $SCRIPT_NAME/$SCRIPT_VERSION; +security-audit)"
    local rc=0
    local wfmt='%{http_code}\t%{url_effective}\t%{num_redirects}\t%{time_total}'
    local out=""

    # --- baseline request ---------------------------------------------------
    out=$(curl -sS "${ssl_opt[@]+"${ssl_opt[@]}"}" -D "$hdr" -o /dev/null \
        --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT" \
        -A "$ua" -L -w "$wfmt" "$url" 2>"$dir/err.txt") || rc=$?

    if [[ "$rc" -eq 60 ]]; then
        # Certificate could not be verified.  That is itself a finding, but we
        # still want to audit the headers, so retry without verification.
        tls_ok="no"
        rc=0
        out=$(curl -sS -k -D "$hdr" -o /dev/null \
            --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT" \
            -A "$ua" -L -w "$wfmt" "$url" 2>"$dir/err.txt") || rc=$?
    fi

    # Reachability is decided by the headers we actually received, not by
    # curl's exit code.  A server that closes the TLS connection without a
    # close_notify makes curl exit 56 even though a complete set of response
    # headers arrived - treating that as "unreachable" would be wrong.
    local -A N=()
    local -a NCOOK=()
    if [[ -s "$hdr" ]]; then
        while IFS=$'\t' read -r kind k v; do
            case "$kind" in
                STATUS) N[status]="$k" ;;
                HDR)    N["h:${k,,}"]="$v"; N["o:${k,,}"]="$k" ;;
                COOKIE) NCOOK+=("$k") ;;
            esac
        done < <(awk "$NORMALISE_AWK" "$hdr" 2>/dev/null || true)
    fi

    if [[ -n "${N[status]:-}" && "${N[status]}" != "000" ]]; then
        reach="yes"
        status="${N[status]}"
        IFS=$'\t' read -r _wstatus final_url redirects rtime <<<"$out"
        [[ -z "$final_url" ]] && final_url="$url"
        [[ -z "$rtime" ]] && rtime="0"
        [[ -z "$redirects" ]] && redirects="0"
    else
        reach="no"
        status="000"
        err=$(tr '\n' ' ' <"$dir/err.txt" 2>/dev/null || true)
        err="${err:0:160}"
    fi
    if [[ "$rc" -ne 0 && "$reach" == "yes" ]]; then
        local cerr
        cerr=$(tr '\n' ' ' <"$dir/err.txt" 2>/dev/null || true)
        cerr="${cerr:0:120}"
        err="${err:+$err | }transfer ended early (curl rc=$rc) ${cerr}"
    fi

    # --- CORS probe ---------------------------------------------------------
    if [[ "$reach" == "yes" ]]; then
        local cout="" crc=0
        cout=$(curl -sS "${ssl_opt[@]+"${ssl_opt[@]}"}" -D "$chdr" -o /dev/null \
            --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT" \
            -A "$ua" -L -H "Origin: $PROBE_ORIGIN" \
            -w '%{http_code}\t%{url_effective}' "$url" 2>/dev/null) || crc=$?
        if [[ "$crc" -eq 60 ]]; then
            # same certificate problem as the baseline request: retry without
            # verification so the CORS headers can still be inspected
            crc=0
            cout=$(curl -sS -k -D "$chdr" -o /dev/null \
                --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT" \
                -A "$ua" -L -H "Origin: $PROBE_ORIGIN" \
                -w '%{http_code}\t%{url_effective}' "$url" 2>/dev/null) || crc=$?
        fi
        if [[ "$crc" -eq 0 && -n "$cout" ]]; then
            IFS=$'\t' read -r _cors_status _cors_url <<<"$cout"
        fi
    fi

    # --- parse the CORS probe ----------------------------------------------
    local -A CN=()
    if [[ -s "$chdr" ]]; then
        while IFS=$'\t' read -r kind k v; do
            case "$kind" in
                HDR)    CN["h:${k,,}"]="$v" ;;
            esac
        done < <(awk "$NORMALISE_AWK" "$chdr" 2>/dev/null || true)
    fi

    local hk
    if [[ ${#N[@]} -gt 0 ]]; then
        for hk in "${!N[@]}"; do
            case "$hk" in
                h:*) H["${hk#h:}"]="${N[$hk]}" ;;
                o:*) ORIG["${hk#o:}"]="${N[$hk]}" ;;
            esac
        done
    fi
    COOKIES=("${NCOOK[@]+"${NCOOK[@]}"}")
    if [[ ${#CN[@]} -gt 0 ]]; then
        for hk in "${!CN[@]}"; do
            [[ "$hk" == h:* ]] && CH["${hk#h:}"]="${CN[$hk]}"
        done
    fi

    # --- Module 1 : security headers ----------------------------------------
    local passed=0
    local is_https="no"
    [[ "$final_url" == https://* ]] && is_https="yes"

    if [[ "$reach" != "yes" ]]; then
        add_finding "FAIL" "M1" "Target" "unreachable - no response to audit"
    elif [[ "$is_https" == "no" ]]; then
        add_finding "WARN" "M1" "Transport" "served over plain HTTP - no HTTPS"
    fi

    # 1a Strict-Transport-Security
    local hsts="${H[$H_HSTS]:-}"
    if [[ "$reach" != "yes" ]]; then
        :
    elif [[ -n "$hsts" ]]; then
        local ma=""
        if [[ "$hsts" =~ [Mm]ax-age[[:space:]]*=[[:space:]]*([0-9]+) ]]; then ma="${BASH_REMATCH[1]}"; fi
        if [[ "$is_https" == "no" ]]; then
            add_finding "WARN" "M1" "Strict-Transport-Security" "present but ignored over plain HTTP"
        elif [[ -z "$ma" ]]; then
            add_finding "WARN" "M1" "Strict-Transport-Security" "present but no max-age directive"
        elif [[ "$ma" -lt "$HSTS_MIN_MAXAGE" ]]; then
            add_finding "WARN" "M1" "Strict-Transport-Security" "weak: max-age=$ma (below 180 days)"
        else
            local extra=""
            [[ "$hsts" == *[Ii]nclude[Ss]ub[Dd]omains* ]] && extra=", includeSubDomains"
            add_finding "PASS" "M1" "Strict-Transport-Security" "present (max-age=$ma$extra)"
            passed=$((passed + 1))
        fi
    else
        add_finding "FAIL" "M1" "Strict-Transport-Security" "MISSING - no HTTPS enforcement"
    fi

    # 1b Content-Security-Policy
    local csp="${H[$H_CSP]:-}"
    local csp_ro="${H[$H_CSP_RO]:-}"
    local csp_lower="${csp,,}"
    if [[ "$reach" != "yes" ]]; then
        :
    elif [[ -n "$csp" ]]; then
        local weak=""
        [[ "$csp_lower" == *"unsafe-inline"* ]] && weak="unsafe-inline"
        [[ "$csp_lower" == *"unsafe-eval"* ]] && weak="${weak:+$weak, }unsafe-eval"
        if [[ -n "$weak" ]]; then
            add_finding "WARN" "M1" "Content-Security-Policy" "weak directives: $weak"
        else
            add_finding "PASS" "M1" "Content-Security-Policy" "present (enforcing)"
            passed=$((passed + 1))
        fi
    elif [[ -n "$csp_ro" ]]; then
        add_finding "WARN" "M1" "Content-Security-Policy" "report-only - NOT enforced"
    else
        add_finding "FAIL" "M1" "Content-Security-Policy" "MISSING - no XSS mitigation"
    fi

    # 1c X-Frame-Options (or CSP frame-ancestors)
    local xfo="${H[$H_XFO]:-}"
    local xfo_lower="${xfo,,}"
    local frame_ancestors="no"
    [[ "$csp_lower" == *"frame-ancestors"* ]] && frame_ancestors="yes"
    if [[ "$reach" != "yes" ]]; then
        :
    elif [[ -n "$xfo_lower" ]]; then
        if [[ "$xfo_lower" == "deny" || "$xfo_lower" == "sameorigin" ]]; then
            add_finding "PASS" "M1" "X-Frame-Options" "present ($xfo_lower)"
            passed=$((passed + 1))
        elif [[ "$xfo_lower" == allow-from* ]]; then
            add_finding "WARN" "M1" "X-Frame-Options" "deprecated value ($xfo_lower)"
        else
            add_finding "WARN" "M1" "X-Frame-Options" "unrecognised value ($xfo_lower)"
        fi
    elif [[ "$frame_ancestors" == "yes" ]]; then
        add_finding "PASS" "M1" "X-Frame-Options" "covered by CSP frame-ancestors"
        passed=$((passed + 1))
    else
        add_finding "FAIL" "M1" "X-Frame-Options" "MISSING - clickjacking possible"
    fi

    # 1d X-Content-Type-Options
    local xcto="${H[$H_XCTO]:-}"
    if [[ "$reach" != "yes" ]]; then
        :
    elif [[ -n "$xcto" ]]; then
        if [[ "${xcto,,}" == "nosniff" ]]; then
            add_finding "PASS" "M1" "X-Content-Type-Options" "present (nosniff)"
            passed=$((passed + 1))
        else
            add_finding "WARN" "M1" "X-Content-Type-Options" "unexpected value ($xcto)"
        fi
    else
        add_finding "FAIL" "M1" "X-Content-Type-Options" "MISSING - MIME sniffing possible"
    fi

    # 1e Referrer-Policy
    local rp="${H[$H_RP]:-}"
    if [[ "$reach" != "yes" ]]; then
        :
    elif [[ -n "$rp" ]]; then
        # A comma-separated list is legal (the browser picks the strictest
        # one), so accept the header when ANY of its values is recognised.
        local rp_lower="${rp,,}"
        local rp_ok=0 rp_part rp_clean=""
        local -a rp_parts=()
        IFS=',' read -r -a rp_parts <<<"$rp_lower"
        for rp_part in "${rp_parts[@]}"; do
            rp_part="${rp_part//[[:space:]]/}"
            [[ -z "$rp_part" ]] && continue
            rp_clean="${rp_clean:+$rp_clean, }$rp_part"
            if [[ "$VALID_RP" == *" $rp_part "* ]]; then rp_ok=1; fi
        done
        if [[ "$rp_ok" -eq 1 ]]; then
            add_finding "PASS" "M1" "Referrer-Policy" "present ($rp_clean)"
            passed=$((passed + 1))
        else
            add_finding "WARN" "M1" "Referrer-Policy" "unrecognised value ($rp)"
        fi
    else
        add_finding "FAIL" "M1" "Referrer-Policy" "MISSING - referrer may leak"
    fi

    # 1f Permissions-Policy
    local pp="${H[$H_PP]:-}"
    if [[ "$reach" != "yes" ]]; then
        :
    elif [[ -n "$pp" ]]; then
        if [[ "${pp,,}" == *"=*"* ]]; then
            add_finding "WARN" "M1" "Permissions-Policy" "present but permits everything (*)"
        else
            add_finding "PASS" "M1" "Permissions-Policy" "present"
            passed=$((passed + 1))
        fi
    else
        add_finding "FAIL" "M1" "Permissions-Policy" "MISSING - powerful features not restricted"
    fi

    # --- Module 2 : information disclosure ----------------------------------
    local disclosure=0
    if [[ "$reach" == "yes" ]]; then
        for hk in "${DISCLOSURE_HEADERS[@]}"; do
            local hv="${H[$hk]:-}"
            [[ -z "$hv" ]] && continue
            disclosure=$((disclosure + 1))
            local extra=""
            if [[ "$hv" =~ [0-9] ]]; then
                extra=" - version disclosed"
            fi
            add_finding "WARN" "M2" "${ORIG[$hk]:-$hk}" "$hv$extra"
        done
        if [[ "$disclosure" -eq 0 ]]; then
            add_finding "PASS" "M2" "Banner leakage" "no implementation details disclosed"
        fi
        if [[ "$tls_ok" == "no" ]]; then
            add_finding "WARN" "M2" "TLS certificate" "could not be verified"
        fi
        if [[ "$reach" == "yes" && "$rc" -ne 0 ]]; then
            add_finding "WARN" "M2" "Transfer" "response truncated (curl rc=$rc)"
        fi
    fi

    # --- Module 3 : CORS policy ---------------------------------------------
    local acao="${CH[access-control-allow-origin]:-}"
    local acac="${CH[access-control-allow-credentials]:-}"
    local acam="${CH[access-control-allow-methods]:-}"
    local acah="${CH[access-control-allow-headers]:-}"
    local vary="${CH[vary]:-}"
    local base_acao="${H[access-control-allow-origin]:-}"
    local cors_pts=15
    local acao_lower="${acao,,}"

    if [[ "$reach" == "yes" ]]; then
        if [[ -n "$base_acao" ]]; then
            add_finding "INFO" "M3" "Access-Control-Allow-Origin" "sent even without an Origin request ($base_acao)"
        fi

        if [[ -z "$acao" ]]; then
            add_finding "PASS" "M3" "Access-Control-Allow-Origin" "not set - cross-origin access blocked"
        elif [[ "$acao_lower" == "*" ]]; then
            if [[ "${acac,,}" == "true" ]]; then
                add_finding "FAIL" "M3" "Access-Control-Allow-Origin" "wildcard (*) WITH credentials - critical"
                cors_pts=0
            else
                add_finding "FAIL" "M3" "Access-Control-Allow-Origin" "wildcard (*) - any origin allowed"
                cors_pts=8
            fi
        elif [[ "$acao_lower" == "${PROBE_ORIGIN,,}" ]]; then
            if [[ "${acac,,}" == "true" ]]; then
                add_finding "FAIL" "M3" "Access-Control-Allow-Origin" "reflects arbitrary origin WITH credentials - critical"
                cors_pts=0
            else
                add_finding "FAIL" "M3" "Access-Control-Allow-Origin" "reflects arbitrary origin ($acao)"
                cors_pts=3
            fi
            if [[ "${vary,,}" != *"origin"* ]]; then
                add_finding "WARN" "M3" "Vary" "Origin not declared - shared cache poisoning risk"
            fi
        else
            add_finding "PASS" "M3" "Access-Control-Allow-Origin" "fixed allowlist ($acao)"
        fi

        if [[ "${acac,,}" == "true" && -z "$acao" ]]; then
            add_finding "INFO" "M3" "Access-Control-Allow-Credentials" "true but no origin allowed - inert"
        fi
        if [[ "${acam,,}" == "*" ]]; then
            add_finding "WARN" "M3" "Access-Control-Allow-Methods" "wildcard (*) method list"
        fi
        if [[ "${acah,,}" == "*" ]]; then
            add_finding "WARN" "M3" "Access-Control-Allow-Headers" "wildcard (*) header list"
        fi
    fi

    # --- Module 4 : cookie attributes ---------------------------------------
    local cookie_count=0
    local cookie_issues=0
    local ck_name ck_attr ck_lc ck_trim
    local -a ck_attrs=()
    for ck_name in "${COOKIES[@]}"; do
        cookie_count=$((cookie_count + 1))
        local has_secure=0 has_http=0 samesite_val=""
        IFS=';' read -r -a ck_attrs <<<"$ck_name"
        for ck_attr in "${ck_attrs[@]}"; do
            ck_trim="${ck_attr#"${ck_attr%%[![:space:]]*}"}"
            ck_lc="${ck_trim,,}"
            case "$ck_lc" in
                secure)     has_secure=1 ;;
                httponly)   has_http=1 ;;
                samesite=*) samesite_val="${ck_lc#samesite=}" ;;
            esac
        done
        local ck_display="${ck_name%%;*}"
        [[ "$ck_display" == *=* ]] && ck_display="${ck_display%%=*}"
        if [[ "$has_secure" -eq 0 ]]; then
            if [[ "$is_https" == "yes" ]]; then
                add_finding "FAIL" "M4" "Cookie: $ck_display" "missing Secure attribute"
            else
                add_finding "WARN" "M4" "Cookie: $ck_display" "missing Secure attribute"
            fi
            cookie_issues=$((cookie_issues + 1))
        fi
        if [[ "$has_http" -eq 0 ]]; then
            add_finding "WARN" "M4" "Cookie: $ck_display" "missing HttpOnly attribute"
            cookie_issues=$((cookie_issues + 1))
        fi
        if [[ -z "$samesite_val" ]]; then
            add_finding "WARN" "M4" "Cookie: $ck_display" "missing SameSite attribute"
            cookie_issues=$((cookie_issues + 1))
        elif [[ "$samesite_val" == "none" && "$has_secure" -eq 0 ]]; then
            add_finding "FAIL" "M4" "Cookie: $ck_display" "SameSite=None without Secure"
            cookie_issues=$((cookie_issues + 1))
        fi
    done
    if [[ "$reach" == "yes" ]]; then
        if [[ "$cookie_count" -eq 0 ]]; then
            add_finding "INFO" "M4" "Cookies" "no Set-Cookie header issued"
        else
            add_finding "PASS" "M4" "Cookie attributes" "$cookie_count cookie(s), $cookie_issues attribute issue(s)"
        fi
    fi

    # --- scoring ------------------------------------------------------------
    local header_pts=$(( passed * 10 ))
    local disc_pts=15
    case "$disclosure" in
        0) disc_pts=15 ;;
        1) disc_pts=10 ;;
        2) disc_pts=5 ;;
        *) disc_pts=0 ;;
    esac
    local cookie_pts=10
    if [[ "$cookie_issues" -gt 0 ]]; then
        cookie_pts=$(( 10 - cookie_issues * 2 ))
        [[ "$cookie_pts" -lt 0 ]] && cookie_pts=0
    fi

    local score=0
    if [[ "$reach" == "yes" ]]; then
        score=$(( header_pts + disc_pts + cors_pts + cookie_pts ))
    fi
    [[ "$score" -gt 100 ]] && score=100
    [[ "$score" -lt 0 ]] && score=0

    local grade="F"
    if   [[ "$score" -ge 95 ]]; then grade="A+"
    elif [[ "$score" -ge 90 ]]; then grade="A"
    elif [[ "$score" -ge 80 ]]; then grade="B"
    elif [[ "$score" -ge 70 ]]; then grade="C"
    elif [[ "$score" -ge 60 ]]; then grade="D"
    fi

    # --- write the result file ---------------------------------------------
    {
        printf 'target\t%s\n'    "$url"
        printf 'final_url\t%s\n' "$final_url"
        printf 'status\t%s\n'    "$status"
        printf 'tls_ok\t%s\n'    "$tls_ok"
        printf 'redirected\t%s\n' "$redirects"
        printf 'rtime\t%s\n'     "$rtime"
        printf 'reachable\t%s\n' "$reach"
        printf 'error\t%s\n'    "$err"
        printf 'headers_passed\t%s\n' "$passed"
        printf 'headers_total\t6\n'
        printf 'disclosure\t%s\n' "$disclosure"
        printf 'cookies\t%s\n'  "$cookie_count"
        printf 'cookie_issues\t%s\n' "$cookie_issues"
        printf 'score\t%s\n'    "$score"
        printf 'grade\t%s\n'    "$grade"
        local f
        for f in "${FINDINGS[@]}"; do
            printf 'finding\t%s\n' "$f"
        done
    } >"$res"

    if [[ -n "$OUT_DIR" ]]; then
        mkdir -p "$OUT_DIR" 2>/dev/null || true
        {
            printf '%s\t%s\t%s\t%s\theaders=%s/6\n' "$url" "$status" "$score" "$grade" "$passed"
            local f
            for f in "${FINDINGS[@]}"; do
                printf '%s\n' "$f"
            done
        } >"$OUT_DIR/${idx}_${url//[^A-Za-z0-9._-]/_}.tsv" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------- reporting --
read_result() {
    # Populates the global R (assoc) and RF (findings) from a result file.
    R=()
    RF=()
    local kind k v
    while IFS=$'\t' read -r kind k v; do
        case "$kind" in
            finding) RF+=("$k") ;;
            *)       R["$kind"]="$k" ;;
        esac
    done <"$1"
}

build_text_report() {
    local out="$1"; shift
    local -a res_files=("$@")

    {
        printf '================================================================================\n'
        printf ' %s v%s - Security Headers & CORS Audit Report\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
        printf '================================================================================\n'
        printf ' Generated  : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf ' Duration   : %02d:%02d:%02d\n' \
            "$(( ($(date +%s) - START_TS) / 3600 ))" \
            "$(( (($(date +%s) - START_TS) % 3600) / 60 ))" \
            "$(( ($(date +%s) - START_TS) % 60 ))"
        printf ' Targets    : %s queued, %s reachable, %s unreachable\n' \
            "$TARGET_COUNT" "$REACHABLE" "$UNREACHABLE"
        printf ' CORS probe : Origin: %s\n' "$PROBE_ORIGIN"
        printf ' curl       : %s\n' "$CURL_VERSION"
        printf '================================================================================\n\n'

        local n=0 f
        local finding sev mod lbl det
        local m2 m3 m4
        for f in "${res_files[@]}"; do
            n=$((n + 1))
            read_result "$f"
            printf -- '--------------------------------------------------------------------------------\n'
            printf ' TARGET %d - %s\n' "$n" "${R[target]:-unknown}"
            printf -- '--------------------------------------------------------------------------------\n'
            printf ' Final URL      : %s\n' "${R[final_url]:-}"
            printf ' HTTP status    : %s\n' "${R[status]:-000}"
            printf ' Reachable      : %s\n' "${R[reachable]:-no}"
            printf ' TLS verified   : %s\n' "${R[tls_ok]:-unknown}"
            printf ' Redirects      : %s\n' "${R[redirected]:-0}"
            printf ' Response time  : %ss\n' "${R[rtime]:-0}"
            if [[ "${R[error]:-}" != "" ]]; then
                printf ' Error          : %s\n' "${R[error]}"
            fi

            # count only actionable findings (PASS lines are not issues)
            m2=0; m3=0; m4=0
            for finding in "${RF[@]}"; do
                IFS='|' read -r sev mod lbl det <<<"$finding"
                [[ "$sev" == "PASS" ]] && continue
                case "$mod" in
                    M2) m2=$((m2 + 1)) ;;
                    M3) m3=$((m3 + 1)) ;;
                    M4) m4=$((m4 + 1)) ;;
                esac
            done

            printf '\n MODULE 1 - Security headers              %s/6 headers passed\n' "${R[headers_passed]:-0}"
            printf ' MODULE 2 - Information disclosure        %s issue(s)\n' "$m2"
            printf ' MODULE 3 - CORS policy                   %s issue(s)\n' "$m3"
            printf ' MODULE 4 - Cookie flags                  %s cookie(s), %s attribute issue(s)\n' \
                "${R[cookies]:-0}" "${R[cookie_issues]:-0}"

            printf '\n'
            for finding in "${RF[@]}"; do
                IFS='|' read -r sev mod lbl det <<<"$finding"
                printf '   [%-4s] %-30s %s\n' "$sev" "$lbl" "$det"
            done

            printf '\n SCORE : %s/100\n' "${R[score]:-0}"
            printf ' GRADE : %s\n' "${R[grade]:-F}"
            printf '\n'
        done

        printf '================================================================================\n'
        printf ' END OF REPORT\n'
        printf '================================================================================\n'
    } >"$out"
}

build_csv_report() {
    local out="$1"; shift
    local -a res_files=("$@")

    {
        printf 'target,final_url,status,tls_verified,redirects,reachable,grade,score,'
        printf 'headers_passed,headers_total,disclosure_findings,cookies,cookie_issues,fail_count,warn_count\n'
        local f
        local finding sev mod lbl det
        for f in "${res_files[@]}"; do
            read_result "$f"
            local fails=0 warns=0
            for finding in "${RF[@]}"; do
                IFS='|' read -r sev mod lbl det <<<"$finding"
                case "$sev" in
                    FAIL) fails=$((fails + 1)) ;;
                    WARN) warns=$((warns + 1)) ;;
                esac
            done
            printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "${R[target]:-}" "${R[final_url]:-}" "${R[status]:-000}" \
                "${R[tls_ok]:-unknown}" "${R[redirected]:-0}" "${R[reachable]:-no}" \
                "${R[grade]:-F}" "${R[score]:-0}" "${R[headers_passed]:-0}" "6" \
                "${R[disclosure]:-0}" "${R[cookies]:-0}" "${R[cookie_issues]:-0}" \
                "$fails" "$warns"
        done
    } >"$out"
}

# ------------------------------------------------------------------- console --
grade_colour() {
    case "$1" in
        A+|A) printf '%s' "$C_GRN" ;;
        B)    printf '%s' "$C_CYN" ;;
        C)    printf '%s' "$C_YEL" ;;
        *)    printf '%s' "$C_RED" ;;
    esac
}

print_target_detail() {
    local idx="$1"
    read_result "$TMP_DIR/targets/$idx/result.txt"

    printf '%sTARGET: %s%s\n' "$C_BOLD" "${R[target]:-unknown}" "$C_RESET"
    printf '  %sFinal URL%s  : %s\n' "$C_DIM" "$C_RESET" "${R[final_url]:-}"
    printf '  %sStatus%s     : %s   %sTLS%s: %s   %sRedirects%s: %s   %s%s\n' \
        "$C_DIM" "$C_RESET" "${R[status]:-000}" "$C_DIM" "$C_RESET" "${R[tls_ok]:-}" \
        "$C_DIM" "$C_RESET" "${R[redirected]:-0}" "${R[rtime]:-0}s" "$C_RESET"

    local cur_mod=""
    local finding sev mod lbl det
    for finding in "${RF[@]}"; do
        IFS='|' read -r sev mod lbl det <<<"$finding"
        if [[ "$mod" != "$cur_mod" ]]; then
            cur_mod="$mod"
            case "$mod" in
                M1) printf '  %sModule 1 - Security headers%s\n' "$C_BLU" "$C_RESET" ;;
                M2) printf '  %sModule 2 - Information disclosure%s\n' "$C_BLU" "$C_RESET" ;;
                M3) printf '  %sModule 3 - CORS policy%s\n' "$C_BLU" "$C_RESET" ;;
                M4) printf '  %sModule 4 - Cookie flags%s\n' "$C_BLU" "$C_RESET" ;;
            esac
        fi
        local col tag
        col=$(sev_colour "$sev")
        case "$sev" in
            PASS) tag=" OK " ;;
            FAIL) tag="FAIL" ;;
            WARN) tag="WARN" ;;
            *)    tag="INFO" ;;
        esac
        printf '    %s[%s]%s %-28s %s\n' "$col" "$tag" "$C_RESET" "$lbl" "$det"
    done

    local g="${R[grade]:-F}" gcol
    gcol=$(grade_colour "$g")
    printf '  %sScore%s: %s/100   %sHeaders%s: %s   %sGrade%s: %s%s%s\n\n' \
        "$C_DIM" "$C_RESET" "${R[score]:-0}" "$C_DIM" "$C_RESET" "${R[headers_passed]:-0}/6" \
        "$C_DIM" "$C_RESET" "$gcol" "$g" "$C_RESET"
}

print_summary_table() {
    printf '\n%s%s%s\n' "$C_BOLD" "Execution summary" "$C_RESET"
    printf '  %s%-38s %9s %7s %7s%s\n' "$C_DIM" "TARGET" "HEADERS" "SCORE" "GRADE" "$C_RESET"
    printf '  %s%s %s %s %s%s\n' "$C_DIM" \
        "--------------------------------------" "---------" "-------" "-------" "$C_RESET"

    local idx
    local t g gcol
    for idx in "$@"; do
        read_result "$TMP_DIR/targets/$idx/result.txt"
        g="${R[grade]:-F}"
        gcol=$(grade_colour "$g")
        t="${R[target]:-}"
        [[ ${#t} -gt 38 ]] && t="${t:0:35}..."
        printf '  %-38s %9s %7s %7s%s%s%s\n' "$t" \
            "${R[headers_passed]:-0}/6" "${R[score]:-0}" "$gcol" "$g" "$C_RESET" ""
    done

    printf '  %s%s %s %s %s%s\n' "$C_DIM" \
        "--------------------------------------" "---------" "-------" "-------" "$C_RESET"

    local avg=0
    [[ "$REACHABLE" -gt 0 ]] && avg=$(( TOTAL_SCORE / REACHABLE ))
    printf '  %s%-38s %9s %7s%s\n' "$C_DIM" "TOTALS (avg score over reachable)" \
        "$TOTAL_HEADERS_PASSED/$TOTAL_HEADERS_TOTAL" "$avg" "$C_RESET"
    printf '\n'
    printf '  %sGrades%s   %sA+:%d%s %sA:%d%s %sB:%d%s %sC:%d%s %sD:%d%s %sF:%d%s\n' \
        "$C_DIM" "$C_RESET" \
        "$C_GRN" "$GRADE_AP" "$C_RESET" "$C_GRN" "$GRADE_A" "$C_RESET" \
        "$C_CYN" "$GRADE_B" "$C_RESET" "$C_YEL" "$GRADE_C" "$C_RESET" \
        "$C_YEL" "$GRADE_D" "$C_RESET" "$C_RED" "$GRADE_F" "$C_RESET"
    printf '  %sReachable%s: %s      %sUnreachable%s: %s      %sFAIL findings%s: %s\n' \
        "$C_DIM" "$C_RESET" "$REACHABLE" "$C_DIM" "$C_RESET" "$UNREACHABLE" \
        "$C_DIM" "$C_RESET" "$TOTAL_FAILS"
    printf '\n'
}

# ---------------------------------------------------------------------- main --
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--url)              TARGET_URL="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -l|--list)             LIST_FILE="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -o|--output)           REPORT_FILE="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --format)              REPORT_FORMAT="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -t|--threads)          THREADS="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --timeout)             TIMEOUT="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --connect-timeout)     CONNECT_TIMEOUT="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --origin)              PROBE_ORIGIN="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --outdir)              OUT_DIR="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --insecure)            INSECURE=1; shift ;;
            --strict)              STRICT=1; shift ;;
            -v|--verbose)          VERBOSE=1; shift ;;
            --no-color)            NO_COLOR=1; shift ;;
            -h|--help)             usage; exit 0 ;;
            *)                     usage; die "Unknown argument: $1" ;;
        esac
    done
}

main() {
    init_colors
    banner
    parse_args "$@"

    if [[ -z "$TARGET_URL" && -z "$LIST_FILE" ]]; then
        usage
        die "No target given. Use -u <url> or -l <file>."
    fi

    case "$REPORT_FORMAT" in
        auto|text|csv) ;;
        *) die "Invalid --format '$REPORT_FORMAT' (use text, csv or auto)" ;;
    esac

    [[ "$THREADS" =~ ^[0-9]+$ ]] && [[ "$THREADS" -ge 1 ]] || die "--threads must be a positive integer"
    [[ "$TIMEOUT" =~ ^[0-9]+$ ]] && [[ "$TIMEOUT" -ge 1 ]] || die "--timeout must be a positive integer"
    [[ "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] && [[ "$CONNECT_TIMEOUT" -ge 1 ]] || die "--connect-timeout must be a positive integer"

    check_deps

    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/headerguard.XXXXXX")
    mkdir -p "$TMP_DIR/targets"

    log_step "Stage 1/6 - Target preparation"
    load_targets

    log_step "Stage 2/6 - Auditing response headers"
    local -a idxs=()
    local i=0 t
    for t in "${TARGETS[@]}"; do
        i=$((i + 1))
        idxs+=("$i")
    done

    local running=0 done_n=0
    for i in "${!TARGETS[@]}"; do
        audit_target "$((i + 1))" "${TARGETS[$i]}" &
        running=$((running + 1))
        if [[ "$running" -ge "$THREADS" ]]; then
            wait -n || true
            running=$((running - 1))
            done_n=$((done_n + 1))
            progress "$done_n" "$TARGET_COUNT" "auditing headers"
        fi
    done
    wait || true
    progress_done

    local missing=0
    for i in "${idxs[@]}"; do
        [[ -f "$TMP_DIR/targets/$i/result.txt" ]] || missing=$((missing + 1))
    done
    if [[ "$missing" -gt 0 ]]; then
        log_err "$missing audit(s) produced no result - check for errors above."
    fi
    log_ok "Audited $TARGET_COUNT target(s)."

    log_step "Stage 3/6 - Scoring and aggregation"
    local idx
    local finding sev mod lbl det
    for idx in "${idxs[@]}"; do
        read_result "$TMP_DIR/targets/$idx/result.txt"
        if [[ "${R[reachable]:-no}" == "yes" ]]; then
            REACHABLE=$((REACHABLE + 1))
            TOTAL_HEADERS_PASSED=$((TOTAL_HEADERS_PASSED + ${R[headers_passed]:-0}))
            TOTAL_HEADERS_TOTAL=$((TOTAL_HEADERS_TOTAL + 6))
            TOTAL_SCORE=$((TOTAL_SCORE + ${R[score]:-0}))
        else
            UNREACHABLE=$((UNREACHABLE + 1))
        fi
        for finding in "${RF[@]}"; do
            IFS='|' read -r sev mod lbl det <<<"$finding"
            [[ "$sev" == "FAIL" ]] && TOTAL_FAILS=$((TOTAL_FAILS + 1))
        done
        case "${R[grade]:-F}" in
            A+)   GRADE_AP=$((GRADE_AP + 1)) ;;
            A)    GRADE_A=$((GRADE_A + 1)) ;;
            B)    GRADE_B=$((GRADE_B + 1)) ;;
            C)    GRADE_C=$((GRADE_C + 1)) ;;
            D)    GRADE_D=$((GRADE_D + 1)) ;;
            *)    GRADE_F=$((GRADE_F + 1)) ;;
        esac
        if [[ "$VERBOSE" -eq 1 ]]; then
            log_info "$(printf '%-46s status=%-4s headers=%s/6 score=%-4s grade=%s' \
                "${R[target]:-}" "${R[status]:-000}" "${R[headers_passed]:-0}" \
                "${R[score]:-0}" "${R[grade]:-F}")"
        fi
    done
    log_ok "Scoring complete."

    log_step "Stage 4/6 - Per-target results"
    for idx in "${idxs[@]}"; do
        print_target_detail "$idx"
    done

    log_step "Stage 5/6 - Writing report"
    local fmt="$REPORT_FORMAT"
    if [[ "$fmt" == "auto" ]]; then
        case "$REPORT_FILE" in
            *.csv|*.CSV) fmt="csv" ;;
            *)           fmt="text" ;;
        esac
    fi
    local report_dir
    report_dir=$(dirname "$REPORT_FILE")
    [[ -d "$report_dir" ]] || mkdir -p "$report_dir"

    local -a files=()
    for idx in "${idxs[@]}"; do files+=("$TMP_DIR/targets/$idx/result.txt"); done

    if [[ "$fmt" == "csv" ]]; then
        build_csv_report "$REPORT_FILE" "${files[@]}"
    else
        build_text_report "$REPORT_FILE" "${files[@]}"
    fi
    log_ok "Report written: $REPORT_FILE"

    log_step "Stage 6/6 - Execution summary"
    print_summary_table "${idxs[@]}"

    log_ok "Audit complete. $REACHABLE reachable, $UNREACHABLE unreachable."

    if [[ "$STRICT" -eq 1 && "$TOTAL_FAILS" -gt 0 ]]; then
        log_err "Strict mode: $TOTAL_FAILS failing check(s) recorded."
        exit 1
    fi
    exit 0
}

main "$@"
