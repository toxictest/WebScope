#!/usr/bin/env bash
# ==============================================================================
#  TLSWatch v1.0.0
#  Automated SSL/TLS Configuration & Certificate Lifecycle Auditor
#
#  Defensive Infrastructure & Transport Layer Compliance
#  100% free & standalone - no API keys, no paid services, no external
#  runtimes. Built on openssl + coreutils + awk/sed/grep.
#
#  Modules
#    1  Certificate lifecycle & expiry tracker
#    2  Protocol support verification (SSLv2 -> TLSv1.3)
#    3  Weak cipher & key exchange flags
#    4  Certificate chain & CA validation (OCSP / CRL)
# ==============================================================================

set -euo pipefail

VERSION="1.0.0"
SCRIPT_NAME="tlswatch.sh"

# ------------------------------------------------------------------ config ---
DOMAIN=""
HOSTLIST=""
OUTPUT_DIR="results"
WARN_DAYS=30
THREADS=10
TIMEOUT=10
NO_COLOR=0
VERBOSE=0
NO_HISTORY=0
CA_FILE=""

C_RESET=""; C_GREEN=""; C_RED=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_DIM=""; C_BOLD=""

TMP_DIR=""
WORK_DIR=""
TARGET=""
REPORT_DIR=""
CSV_FILE=""
TXT_FILE=""
TS_FILE=""
START_TS=""

# ==============================================================================
#  helpers
# ==============================================================================

now_ts() { date +%H:%M:%S; }
utc_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log_step() { printf '\n%s%s%s\n' "$C_BLUE" "$*" "$C_RESET"; }
log_info() { printf '[%s] %sINFO%s %s\n' "$(now_ts)" "$C_BLUE" "$C_RESET" "$*"; }
log_ok()   { printf '[%s] %sOK%s   %s\n' "$(now_ts)" "$C_GREEN" "$C_RESET" "$*"; }
log_warn() { printf '[%s] %sWARN%s %s\n' "$(now_ts)" "$C_YELLOW" "$C_RESET" "$*"; }
log_err()  { printf '[%s] %sERR%s  %s\n' "$(now_ts)" "$C_RED" "$C_RESET" "$*" >&2; }
die()      { log_err "$*"; exit 2; }

sev_colour() {
    case "$1" in
        PASS|PROTECTED) printf '%s' "$C_GREEN" ;;
        FAIL|VULNERABLE) printf '%s' "$C_RED" ;;
        WARN|WARNING) printf '%s' "$C_YELLOW" ;;
        INFO) printf '%s' "$C_CYAN" ;;
        *)    printf '%s' "$C_RESET" ;;
    esac
}

# Safe string for use as a file name.
safe_name() { printf '%s' "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }

# Echo the first line of a file, or nothing. Never aborts under set -e.
first_line() { sed -n '1p' "$1" 2>/dev/null || true; }

count_lines() {
    local n
    n=$(wc -l < "$1" 2>/dev/null | tr -d '[:space:]' || true)
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    printf '%s' "$n"
}

# ------------------------------------------------------------------ colours ---
init_colors() {
    if [[ "$NO_COLOR" -eq 1 || ! -t 1 ]]; then
        C_RESET=""; C_GREEN=""; C_RED=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
        C_DIM=""; C_BOLD=""; return
    fi
    C_RESET=$'\033[0m';  C_GREEN=$'\033[1;32m'; C_RED=$'\033[1;31m'
    C_YELLOW=$'\033[1;33m'; C_BLUE=$'\033[1;34m'; C_CYAN=$'\033[1;36m'
    C_DIM=$'\033[2m';    C_BOLD=$'\033[1m'
}

# ==============================================================================
#  banner / usage
# ==============================================================================
banner() {
    printf '\n'
    printf '  %s┌──────────────────────────────────────────────────────┐%s\n' "$C_BLUE" "$C_RESET"
    printf '  %s│%s  %sTLSWatch v%s%s                                      %s│%s\n' \
        "$C_BLUE" "$C_RESET" "$C_BOLD" "$VERSION" "$C_RESET" "$C_BLUE" "$C_RESET"
    printf '  %s│%s  %sSSL/TLS Configuration & Certificate Lifecycle%s  %s│%s\n' \
        "$C_BLUE" "$C_RESET" "$C_BOLD" "$C_RESET" "$C_BLUE" "$C_RESET"
    printf '  %s└──────────────────────────────────────────────────────┘%s\n' "$C_BLUE" "$C_RESET"
    printf '  %sFree & standalone. openssl + coreutils. No API keys.%s\n\n' "$C_DIM" "$C_RESET"
}

usage() {
    cat <<EOF

  TLSWatch v$VERSION - SSL/TLS Configuration & Certificate Lifecycle Auditor

USAGE
  ./$SCRIPT_NAME -d target.com:443 [-l live_hosts.txt] [-w alert_days] [-o report_dir]

REQUIRED (one of)
  -d, --domain <host[:port]>   Target endpoint to audit (e.g. target.com:443)
  -l, --list <file>            Host list, one per line. host:port or host

OPTIONS
  -w, --warn-days <days>       Expiry alert threshold        (default: $WARN_DAYS)
  -o, --output <dir>           Report directory               (default: $OUTPUT_DIR)
  -t, --threads <n>            Parallel endpoint audits       (default: $THREADS)
      --ca-file <file>         Custom trusted CA bundle (optional)
      --timeout <sec>          Per-handshake timeout          (default: $TIMEOUT)
      --no-history             Do not keep a timestamped copy
  -v, --verbose                Verbose logging
      --no-color               Disable ANSI colours
  -h, --help                   Show this help and exit

MODULES
  1  Certificate lifecycle & expiry    expiry countdown, self-signed, CN/SAN mismatch
  2  Protocol support                 SSLv2, SSLv3, TLSv1.0-1.3 negotiation
  3  Weak ciphers & key exchange      NULL/RC4/3DES/DES/EXPORT, RSA key size
  4  Chain & CA validation            intermediates, OCSP stapling, CRL

OUTPUT
  <output_dir>/<target>/tls_audit_summary.csv
  <output_dir>/<target>/tls_full_report.txt
  <output_dir>/<target>/tls_full_report_<YYYYmmdd_HHMMSS>.txt

EXIT CODES
  0  audit completed          2  usage error / missing dependency

EOF
}

# ==============================================================================
#  stage 0 - dependency check
# ==============================================================================
check_deps() {
    log_step "Stage 0/5 - Dependency verification"

    local missing=0 tool
    for tool in openssl timeout awk sed date sort grep tr cut head tail cat wc find paste mktemp mkdir chmod cp mv rm; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '  %s✔%s %-12s %spresent%s\n' "$C_GREEN" "$C_RESET" "$tool" "$C_GREEN" "$C_RESET"
        else
            printf '  %s✘%s %-12s %sMISSING%s\n' "$C_RED" "$C_RESET" "$tool" "$C_RED" "$C_RESET"
            missing=$((missing + 1))
        fi
    done

    if command -v nc >/dev/null 2>&1; then
        printf '  %s✔%s %-12s %spresent (optional; TLS handshake handles reachability)%s\n' \
            "$C_GREEN" "$C_RESET" "nc" "$C_GREEN" "$C_RESET"
    else
        printf '  %s✔%s %-12s %sabsent (optional - reachability inferred from the TLS handshake)%s\n' \
            "$C_CYAN" "$C_RESET" "nc" "$C_CYAN" "$C_RESET"
    fi

    if [[ "$missing" -gt 0 ]]; then
        log_err "$missing required tool(s) missing."
        printf '\n  Install with:\n    %ssudo apt-get install -y openssl coreutils gawk%s\n\n' "$C_BOLD" "$C_RESET" >&2
        exit 2
    fi

    OPENSSL_VER=$(openssl version 2>/dev/null || echo "unknown")
    printf '  %sopenssl: %s%s\n' "$C_DIM" "$OPENSSL_VER" "$C_RESET"

    # Which legacy protocols can this client even offer? OpenSSL 3.x removed
    # SSLv2/SSLv3 outright, so we must not report "server refused" for them.
    SSL2_CLIENT=0; SSL3_CLIENT=0
    if openssl s_client -ssl2 -help >/dev/null 2>&1; then SSL2_CLIENT=1; fi
    if openssl s_client -ssl3 -help >/dev/null 2>&1; then SSL3_CLIENT=1; fi
    if [[ "$SSL2_CLIENT" -eq 0 ]]; then
        printf '  %snote: this OpenSSL cannot test SSLv2 (option removed) - reported as untestable%s\n' "$C_DIM" "$C_RESET"
    fi
    if [[ "$SSL3_CLIENT" -eq 0 ]]; then
        printf '  %snote: this OpenSSL cannot test SSLv3 (option removed) - reported as untestable%s\n' "$C_DIM" "$C_RESET"
    fi

    # Which weak cipher families does the client still carry?
    log_ok "Dependencies satisfied"
}

# ==============================================================================
#  stage 1 - target preparation
# ==============================================================================

# Normalise one input line into "host:port". Accepts bare hosts, host:port,
# URLs and host:port/path.
normalise_endpoint() {
    local line="$1" host port=443
    line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [[ -z "$line" || "$line" == \#* ]] && return 0
    if [[ "$line" == http://* ]]; then
        log_warn "Skipping plaintext HTTP URL: $line (use host:443 to audit TLS explicitly)" >&2
        return 0
    fi
    line="${line#https://}"
    line="${line%%[/?#]*}"
    [[ "$line" != *@* ]] || { log_err "Credentials are not permitted in endpoints"; return 2; }
    if [[ "$line" == \[* ]]; then
        [[ "$line" =~ ^\[([0-9a-fA-F:]+)\](:([0-9]+))?$ ]] || return 2
        host="[${BASH_REMATCH[1]}]"; port="${BASH_REMATCH[3]:-443}"
    else
        [[ "$line" =~ ^([A-Za-z0-9][A-Za-z0-9._-]*)(:([0-9]+))?$ ]] || return 2
        host="${BASH_REMATCH[1],,}"; port="${BASH_REMATCH[3]:-443}"
        host="${host%.}"
        [[ "$host" != *..* && ${#host} -le 253 ]] || return 2
    fi
    [[ ${#port} -le 5 ]] || return 2
    port=$((10#$port))
    [[ "$port" -ge 1 && "$port" -le 65535 ]] || return 2
    printf '%s:%s' "$host" "$port"
}

load_targets() {
    log_step "Stage 1/5 - Target preparation"

    ENDPOINT_FILE="$TMP_DIR/endpoints.txt"
    : >"$ENDPOINT_FILE"

    if [[ -n "$DOMAIN" ]]; then
        local ep
        ep=$(normalise_endpoint "$DOMAIN") || die "Invalid endpoint: $DOMAIN"
        [[ -z "$ep" ]] && die "Invalid -d value: $DOMAIN"
        printf '%s\n' "$ep" >>"$ENDPOINT_FILE"
        TARGET=$(safe_name "${ep%:*}")
    fi

    if [[ -n "$HOSTLIST" ]]; then
        [[ -f "$HOSTLIST" ]] || die "Host list not found: $HOSTLIST"
        [[ -r "$HOSTLIST" ]] || die "Host list not readable: $HOSTLIST"
        local line ep
        while IFS= read -r line || [[ -n "$line" ]]; do
            ep=$(normalise_endpoint "$line") || die "Invalid list endpoint: $line"
            [[ -z "$ep" ]] && continue
            printf '%s\n' "$ep" >>"$ENDPOINT_FILE"
        done <"$HOSTLIST"
        if [[ -z "$TARGET" ]]; then
            local first
            first=$(first_line "$ENDPOINT_FILE")
            TARGET=$(safe_name "${first%:*}")
        fi
    fi

    [[ -s "$ENDPOINT_FILE" ]] || die "No targets to audit. Use -d and/or -l."

    # De-duplicate, keep a stable order.
    sort -u "$ENDPOINT_FILE" >"$TMP_DIR/endpoints.sorted" 2>/dev/null || cp "$ENDPOINT_FILE" "$TMP_DIR/endpoints.sorted"
    mv "$TMP_DIR/endpoints.sorted" "$ENDPOINT_FILE"

    local n
    n=$(count_lines "$ENDPOINT_FILE")
    log_ok "$n endpoint(s) queued - target: $TARGET"

    REPORT_DIR="$OUTPUT_DIR/$TARGET"
    mkdir -p "$REPORT_DIR" || die "Cannot create report directory: $REPORT_DIR"
    CSV_FILE="$REPORT_DIR/tls_audit_summary.csv"
    TXT_FILE="$REPORT_DIR/tls_full_report.txt"
    TS_FILE="$REPORT_DIR/tls_full_report_$(date +%Y%m%d_%H%M%S).txt"
}

# ==============================================================================
#  openssl helpers
# ==============================================================================

# Run an s_client handshake and return its raw output.
sclient() {
    # $1 host  $2 port  $3.. extra openssl args
    local host="$1" port="$2"; shift 2
    timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" "$@" </dev/null 2>&1 || true
}

# Split a PEM bundle into leaf.pem and chain.pem (the intermediates).
split_chain() {
    local bundle="$1" outdir="$2"
    awk -v d="$outdir" '
        /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/cert%02d.pem", d, n); active = 1 }
        active { print > f }
        /-----END CERTIFICATE-----/   { active = 0 }
    ' "$bundle" 2>/dev/null || true
}

# ==============================================================================
#  module 1 - certificate lifecycle
# ==============================================================================
audit_certificate() {
    local host="$1" port="$2" leaf="$3"
    local f="$WORK_DIR/$4.find"

    local subject issuer not_before not_after nb_epoch na_epoch now_epoch days
    local cn sans san_list key_algo key_bits curve

    subject=$(openssl x509 -in "$leaf" -noout -subject 2>/dev/null | sed 's/^subject=//' || true)
    issuer=$(openssl x509 -in "$leaf" -noout -issuer 2>/dev/null | sed 's/^issuer=//' || true)
    not_before=$(openssl x509 -in "$leaf" -noout -startdate 2>/dev/null | cut -d= -f2- || true)
    not_after=$(openssl x509 -in "$leaf" -noout -enddate 2>/dev/null | cut -d= -f2- || true)

    nb_epoch=$(date -u -d "$not_before" +%s 2>/dev/null || echo 0)
    na_epoch=$(date -u -d "$not_after" +%s 2>/dev/null || echo 0)
    now_epoch=$(date -u +%s)
    if [[ "$na_epoch" -gt 0 ]]; then
        days=$(( (na_epoch - now_epoch) / 86400 ))
    else
        days=-1
    fi

    # Common Name
    cn=$(openssl x509 -in "$leaf" -noout -subject -nameopt multiline 2>/dev/null \
         | awk -F'=' '/commonName/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' || true)
    [[ -z "$cn" ]] && cn=$(printf '%s' "$subject" | sed -n 's/.*CN=\([^,]*\).*/\1/p' || true)

    # Subject Alternative Names
    san_list=$(openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null \
        | tail -n +2 | tr ',' '\n' | sed 's/^[[:space:]]*//' \
        | grep -E '^(DNS|IP Address|IP):' | sed -E 's/^(DNS|IP Address|IP)://' || true)
    if [[ -z "$san_list" ]]; then
        san_list=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
            | grep -A1 "Subject Alternative Name" | tail -1 \
            | sed 's/^[[:space:]]*//' | tr ',' '\n' | sed 's/^[[:space:]]*//' \
            | grep -E '^(DNS|IP Address|IP):' | sed -E 's/^(DNS|IP Address|IP)://' || true)
    fi
    sans=$(printf '%s' "$san_list" | tr '\n' ',' | sed 's/,$//' || true)
    [[ -z "$sans" ]] && sans="(none)"

    # Key algorithm and size
    key_algo=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
        | awk -F: '/Public Key Algorithm/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' || true)
    key_bits=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
        | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -1 || true)
    curve=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
        | sed -n 's/.*NIST CURVE: \(.*\)/\1/p' | head -1 || true)
    [[ -z "$key_bits" ]] && key_bits=0

    local key_summary
    if [[ "$key_algo" == *rsa* ]]; then
        key_summary="RSA ${key_bits}-bit"
    elif [[ "$key_algo" == *ecPublicKey* || "$key_algo" == *id-ec* ]]; then
        key_summary="EC ${key_bits}-bit${curve:+ ($curve)}"
    else
        key_summary="${key_algo:-unknown}${key_bits:+ ${key_bits}-bit}"
    fi

    # --- expiry ---
    if [[ "$na_epoch" -le 0 ]]; then
        add "$f" "WARN" "M1" "Certificate expiry" "UNTESTED - expiration could not be parsed"
    elif [[ "$na_epoch" -le "$now_epoch" ]]; then
        add "$f" "FAIL" "M1" "Certificate expiry" "EXPIRED (remaining days: ${days}) on ${not_after}"
    elif [[ "$days" -le "$WARN_DAYS" ]]; then
        add "$f" "WARN" "M1" "Certificate expiry" "EXPIRING SOON - ${days} day(s) left (threshold ${WARN_DAYS}), expires ${not_after}"
    else
        add "$f" "PASS" "M1" "Certificate expiry" "valid - ${days} day(s) remaining, expires ${not_after}"
    fi

    if [[ "$nb_epoch" -gt 0 && "$now_epoch" -lt "$nb_epoch" ]]; then
        add "$f" "FAIL" "M1" "Certificate validity window" "NOT YET VALID - becomes valid ${not_before}"
    else
        add "$f" "PASS" "M1" "Certificate validity window" "valid from ${not_before}"
    fi

    # --- self signed ---
    local subject_cn
    subject_cn=$(printf '%s' "$subject" | sed -n 's/.*CN=\([^,]*\).*/\1/p' || true)
    if [[ -n "$subject" && "$subject" == "$issuer" ]] && openssl verify -check_ss_sig -no_check_time -CAfile "$leaf" "$leaf" >/dev/null 2>&1; then
        add "$f" "FAIL" "M1" "Self-signed certificate" "SELF-SIGNED - subject and issuer are identical (${subject_cn})"
    else
        add "$f" "PASS" "M1" "Self-signed certificate" "not self-signed - issued by ${issuer:-unknown}"
    fi

    # OpenSSL checks wildcard depth, SAN precedence, and IP SANs.
    local checkhost="${host#[}" checkflag=-checkhost
    checkhost="${checkhost%]}"
    if [[ "$checkhost" == *:* || "$checkhost" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then checkflag=-checkip; fi
    if openssl x509 -in "$leaf" -noout "$checkflag" "$checkhost" >/dev/null 2>&1; then
        if [[ -n "$san_list" ]]; then
            add "$f" PASS M1 "Hostname match" "CN/SAN MATCH - '$host' is covered by the certificate"
        else
            add "$f" WARN M1 "Hostname match" "CN MATCH but no SAN extension - modern clients require SAN"
        fi
    else
        add "$f" FAIL M1 "Hostname match" "CN/SAN MISMATCH - '$host' is not covered by the certificate"
    fi

    # --- key strength (module 3 content, reported in module 3 as well) ---
    if [[ "$key_bits" -eq 0 ]]; then
        add "$f" WARN M3 "Public key strength" "UNTESTED - key size could not be parsed"
    elif [[ "$key_algo" == *rsa* ]]; then
        if [[ "$key_bits" -gt 0 && "$key_bits" -lt 2048 ]]; then
            add "$f" "FAIL" "M3" "Public key strength" "WEAK KEY - RSA ${key_bits}-bit is below the 2048-bit minimum"
        else
            add "$f" "PASS" "M3" "Public key strength" "RSA ${key_bits}-bit meets the 2048-bit minimum"
        fi
    elif [[ "$key_algo" == *ecPublicKey* || "$key_algo" == *id-ec* ]]; then
        if [[ "$key_bits" -gt 0 && "$key_bits" -lt 256 ]]; then
            add "$f" "WARN" "M3" "Public key strength" "WEAK KEY - EC ${key_bits}-bit${curve:+ ($curve)} is below P-256"
        else
            add "$f" "PASS" "M3" "Public key strength" "EC ${key_bits}-bit${curve:+ ($curve)} is a strong curve"
        fi
    else
        add "$f" "WARN" "M3" "Public key strength" "key algorithm '${key_algo:-unknown}' could not be evaluated"
    fi

    printf 'subject=%s\nissuer=%s\ncn=%s\nsan=%s\nnot_before=%s\nnot_after=%s\ndays_remaining=%s\nkey_algo=%s\nkey_bits=%s\nkey_summary=%s\n' \
        "$subject" "$issuer" "$cn" "$sans" "$not_before" "$not_after" "$days" \
        "$key_algo" "$key_bits" "$key_summary" >"$WORK_DIR/$4.m1.detail"
}

# ==============================================================================
#  module 2 - protocol support
# ==============================================================================

# Probe a single protocol. Echoes SUPPORTED / REFUSED / UNTESTABLE.
probe_protocol() {
    local host="$1" port="$2" flag="$3" extra_cipher="$4"
    local out rc=0 expected args=()
    case "$flag" in ssl2) expected=SSLv2;; ssl3) expected=SSLv3;; tls1) expected=TLSv1;; tls1_1) expected=TLSv1.1;; tls1_2) expected=TLSv1.2;; tls1_3) expected=TLSv1.3;; esac
    [[ -n "$extra_cipher" ]] && args+=(-cipher "$extra_cipher")
    out=$(timeout "$TIMEOUT" openssl s_client -"$flag" "${args[@]}" \
          -connect "$host:$port" -servername "$host" </dev/null 2>&1) || rc=$?
    printf '%s\n' "$out" >"$WORK_DIR/$(safe_name "$host:$port").$flag.raw"
    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
        printf 'UNTESTABLE'
    elif grep -F "New, $expected, Cipher is " <<<"$out" | grep -Eq 'Cipher is [A-Za-z0-9_-]+'; then
        printf 'SUPPORTED'
    elif grep -qiE 'alert protocol version|alert handshake failure|no shared cipher' <<<"$out"; then
        printf 'REFUSED'
    else
        printf 'UNTESTABLE'
    fi
}

audit_protocols() {
    local host="$1" port="$2"
    local f="$WORK_DIR/$3.find"
    local detail="$WORK_DIR/$3.m2.detail"

    local legacy_ok=0 modern_ok=0 unknown=0 line

    # --- legacy protocols ---
    # SSLv2 / SSLv3
    if [[ "$SSL2_CLIENT" -eq 1 ]]; then
        line=$(probe_protocol "$host" "$port" "ssl2" "")
        if [[ "$line" == "SUPPORTED" ]]; then
            add "$f" "FAIL" "M2" "SSLv2 support" "DEPRECATED - SSLv2 handshake succeeded (POODLE / DROWN class attacks)"
            legacy_ok=1
        elif [[ "$line" == "UNTESTABLE" ]]; then
            unknown=1; add "$f" "WARN" "M2" "SSLv2 support" "not testable - the client refused to offer SSLv2"
        else
            add "$f" "PASS" "M2" "SSLv2 support" "not accepted - SSLv2 is disabled"
        fi
    else
        unknown=1; add "$f" "WARN" "M2" "SSLv2 support" "not testable - SSLv2 was removed from this OpenSSL client"
    fi

    if [[ "$SSL3_CLIENT" -eq 1 ]]; then
        line=$(probe_protocol "$host" "$port" "ssl3" "")
        if [[ "$line" == "SUPPORTED" ]]; then
            add "$f" "FAIL" "M2" "SSLv3 support" "DEPRECATED - SSLv3 handshake succeeded (POODLE vulnerable)"
            legacy_ok=1
        elif [[ "$line" == "UNTESTABLE" ]]; then
            unknown=1; add "$f" "WARN" "M2" "SSLv3 support" "not testable - the client refused to offer SSLv3"
        else
            add "$f" "PASS" "M2" "SSLv3 support" "not accepted - SSLv3 is disabled"
        fi
    else
        unknown=1; add "$f" "WARN" "M2" "SSLv3 support" "not testable - SSLv3 was removed from this OpenSSL client"
    fi

    # TLS 1.0 / 1.1 - the security level is lowered so the probe is genuine
    # rather than blocked by the client's own minimum.
    local p
    for p in "tls1:TLSv1.0" "tls1_1:TLSv1.1"; do
        local flag="${p%%:*}" label="${p#*:}"
        line=$(probe_protocol "$host" "$port" "$flag" "ALL:@SECLEVEL=0")
        case "$line" in
            SUPPORTED)
                add "$f" "FAIL" "M2" "$label support" "DEPRECATED - $label handshake succeeded (legacy protocol accepted)"
                legacy_ok=1
                ;;
            UNTESTABLE)
                unknown=1; add "$f" "WARN" "M2" "$label support" "UNTESTED - client limitation, network failure or inconclusive handshake for $label"
                ;;
            *)
                add "$f" "PASS" "M2" "$label support" "not accepted - $label is disabled"
                ;;
        esac
    done

    # --- modern protocols ---
    for p in "tls1_2:TLSv1.2" "tls1_3:TLSv1.3"; do
        local flag="${p%%:*}" label="${p#*:}"
        line=$(probe_protocol "$host" "$port" "$flag" "")
        case "$line" in
            SUPPORTED)
                add "$f" "PASS" "M2" "$label support" "supported - $label handshake succeeded"
                modern_ok=1
                ;;
            UNTESTABLE)
                unknown=1; add "$f" "WARN" "M2" "$label support" "UNTESTED - client limitation, network failure or inconclusive handshake for $label"
                ;;
            *)
                add "$f" "WARN" "M2" "$label support" "not negotiated - $label handshake rejected"
                ;;
        esac
    done

    if [[ "$legacy_ok" -eq 0 && "$unknown" -eq 1 ]]; then
        add "$f" "WARN" "M2" "Protocol policy" "INCOMPLETE COVERAGE - no tested legacy protocol accepted; some probes inconclusive"
    elif [[ "$legacy_ok" -eq 0 && "$modern_ok" -eq 1 ]]; then
        add "$f" "PASS" "M2" "Protocol policy" "no tested legacy protocol accepted; at least one modern version negotiated"
    elif [[ "$legacy_ok" -eq 1 ]]; then
        add "$f" "FAIL" "M2" "Protocol policy" "LEGACY PROTOCOL ACCEPTED - downgrade to TLSv1.0/1.1 or worse is possible"
    else
        add "$f" "FAIL" "M2" "Protocol policy" "no usable modern protocol - the endpoint offers neither TLSv1.2 nor TLSv1.3"
    fi

    printf 'legacy_accepted=%s\nmodern_accepted=%s\n' "$legacy_ok" "$modern_ok" >"$detail"
}

# ==============================================================================
#  module 3 - weak ciphers
# ==============================================================================

# Probe one weak cipher family. Echoes ACCEPTED:<cipher> / REJECTED / UNTESTABLE.
probe_cipher_family() {
    local host="$1" port="$2" pattern="$3" ciphers out proto rc unknown=0
    ciphers=$(openssl ciphers "$pattern:@SECLEVEL=0" 2>/dev/null | tr ':' '\n' |
        grep -vE '^TLS_|PSK|^$' | paste -sd: - || true)
    [[ -n "$ciphers" ]] || { printf UNTESTABLE; return; }
    for proto in tls1_2 tls1_1 tls1; do
        rc=0
        out=$(timeout "$TIMEOUT" openssl s_client -"$proto" -cipher "$ciphers:@SECLEVEL=0" \
            -connect "$host:$port" -servername "$host" </dev/null 2>&1) || rc=$?
        printf '%s\n' "$out" >"$WORK_DIR/$(safe_name "$host:$port").$pattern.$proto.raw"
        if [[ "$rc" -ne 124 && "$rc" -ne 137 ]] && grep -Eq '^New, (TLS|SSL)v[0-9].*Cipher is [A-Za-z0-9_-]+' <<<"$out"; then
            printf 'ACCEPTED:%s' "$(sed -n 's/.*Cipher is //p' <<<"$out" | sed -n '1p')"; return
        fi
        if [[ "$rc" -eq 124 ]] || ! grep -qiE 'alert protocol version|alert handshake failure|no shared cipher' <<<"$out"; then unknown=1; fi
    done
    if [[ "$unknown" -eq 1 ]]; then printf UNTESTABLE; else printf REJECTED; fi
}

audit_ciphers() {
    local host="$1" port="$2"
    local f="$WORK_DIR/$3.find"
    local detail="$WORK_DIR/$3.m3.detail"

    local weak_found=0 unknown=0 summary=""
    local p label pattern result

    # label : pattern used to select the family's ciphers from the client
    while IFS='|' read -r label pattern; do
        [[ -z "$label" ]] && continue
        result=$(probe_cipher_family "$host" "$port" "$pattern")
        case "$result" in
            ACCEPTED:*)
                add "$f" "FAIL" "M3" "Weak cipher: $label" "WEAK CIPHER ACCEPTED - the server negotiated ${result#ACCEPTED:}"
                weak_found=1
                summary="$summary$label(accepted) "
                ;;
            UNTESTABLE)
                unknown=1; add "$f" "WARN" "M3" "Weak cipher: $label" "UNTESTED - $label unavailable locally or handshake inconclusive"
                summary="$summary$label(untestable) "
                ;;
            *)
                add "$f" "PASS" "M3" "Weak cipher: $label" "not accepted - no offered $label negotiated on TLS 1.0-1.2 (not an exhaustive server cipher inventory)"
                summary="$summary$label(rejected) "
                ;;
        esac
    done <<'EOF'
NULL cipher|NULL
RC4 cipher|RC4
3DES cipher|3DES
DES cipher|DES
EXPORT cipher|EXPORT
EOF

    if [[ "$weak_found" -eq 0 && "$unknown" -eq 1 ]]; then
        add "$f" "WARN" "M3" "Cipher policy" "INCOMPLETE COVERAGE - no tested weak cipher accepted; unavailable families remain unknown"
    elif [[ "$weak_found" -eq 0 ]]; then
        add "$f" "PASS" "M3" "Cipher policy" "no weak cipher family accepted by the server"
    else
        add "$f" "FAIL" "M3" "Cipher policy" "WEAK CIPHERS ACCEPTED - at least one legacy cipher family negotiated"
    fi

    # The negotiated cipher of the default handshake.
    local neg
    neg=$(timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" </dev/null 2>&1 \
        | sed -n -e 's/.*Cipher is //p' -e 's/^ *Cipher *: *//p' | head -1 || true)
    [[ -z "$neg" ]] && neg="(unknown)"

    printf 'weak_ciphers=%s\nnegotiated_cipher=%s\n' "$summary" "$neg" >"$detail"
}

# ==============================================================================
#  module 4 - chain, OCSP, CRL
# ==============================================================================
audit_chain() {
    local host="$1" port="$2" bundle="$3"
    local f="$WORK_DIR/$4.find"
    local detail="$WORK_DIR/$4.m4.detail"
    local work="$WORK_DIR/$4.chain"

    mkdir -p "$work"
    split_chain "$bundle" "$work"

    local leaf="$work/cert01.pem"
    local depth=0
    if [[ -d "$work" ]]; then
        depth=$(find "$work" -name 'cert*.pem' -type f 2>/dev/null | wc -l | tr -d '[:space:]' || true)
    fi
    [[ "$depth" =~ ^[0-9]+$ ]] || depth=0

    # --- chain completeness ---
    if [[ "$depth" -le 1 ]]; then
        add "$f" "INFO" "M4" "Certificate chain" "${depth} certificate sent; leaf-only does not itself prove a missing intermediate"
    else
        add "$f" "INFO" "M4" "Certificate chain" "chain presented - ${depth} certificate(s) sent by the server"
    fi

    # --- trust validation ---
    local ca_bundle="" verify_out=""
    local c
    for c in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
             /etc/ssl/cert.pem /etc/ssl/certs/ca-bundle.crt; do
        if [[ -f "$c" ]]; then ca_bundle="$c"; break; fi
    done

    if [[ -n "$CA_FILE" ]]; then ca_bundle="$CA_FILE"; fi
    if [[ -z "$ca_bundle" ]]; then
        add "$f" "WARN" "M4" "CA trust validation" "not testable - no system CA bundle was found"
    else
        local args=(-CAfile "$ca_bundle")
        if [[ "$depth" -gt 1 ]]; then
            local cert
            : >"$work/intermediates.pem"
            for cert in "$work"/cert*.pem; do
                [[ "$cert" == "$leaf" ]] || cat "$cert" >>"$work/intermediates.pem"
            done
            args+=(-untrusted "$work/intermediates.pem")
        fi
        args+=(-purpose sslserver)
        verify_out=$(openssl verify "${args[@]}" "$leaf" 2>&1 || true)
        case "$verify_out" in
            *": OK"*)
                add "$f" "PASS" "M4" "CA trust validation" "TRUSTED - the chain validates against the system CA store"
                ;;
            *"unable to get local issuer certificate"*)
                add "$f" "FAIL" "M4" "CA trust validation" "UNTRUSTED / POSSIBLE MISSING INTERMEDIATE CHAIN - issuer cannot be resolved with the supplied chain and local trust store"
                ;;
            *"self-signed certificate"*)
                add "$f" "FAIL" "M4" "CA trust validation" "SELF-SIGNED CHAIN - the certificate does not chain to a trusted root"
                ;;
            *"certificate has expired"*)
                add "$f" "FAIL" "M4" "CA trust validation" "EXPIRED - the certificate is outside its validity window"
                ;;
            *"certificate is not yet valid"*)
                add "$f" "FAIL" "M4" "CA trust validation" "NOT YET VALID - the certificate is outside its validity window"
                ;;
            *"certificate revoked"*)
                add "$f" "FAIL" "M4" "CA trust validation" "REVOKED - the certificate is on a CRL"
                ;;
            *)
                add "$f" "FAIL" "M4" "CA trust validation" "UNTRUSTED / verification failed - ${verify_out%%$'\n'*}"
                ;;
        esac
    fi

    # --- OCSP stapling ---
    local ocsp_out ocsp_state="no"
    ocsp_out=$(timeout "$TIMEOUT" openssl s_client -status -connect "$host:$port" -servername "$host" </dev/null 2>&1 || true)
    if printf '%s' "$ocsp_out" | grep -qi "Cert Status: revoked"; then
        ocsp_state="revoked"
        add "$f" "FAIL" "M4" "OCSP stapling" "REVOKED - stapled response reports revoked (not independently validated)"
    elif printf '%s' "$ocsp_out" | grep -qi "Cert Status: good"; then
        ocsp_state="stapled"
        add "$f" "PASS" "M4" "OCSP stapling" "OCSP STAPLED - response says good; signature, freshness and certificate binding not independently verified"
    elif printf '%s' "$ocsp_out" | grep -qi "OCSP Response Status: revoked"; then
        ocsp_state="revoked"
        add "$f" "FAIL" "M4" "OCSP stapling" "REVOKED - the stapled OCSP response reports a revoked certificate"
    elif printf '%s' "$ocsp_out" | grep -qi "OCSP Response Status"; then
        ocsp_state="error"
        add "$f" "WARN" "M4" "OCSP stapling" "the stapled OCSP response is not valid"
    else
        add "$f" "WARN" "M4" "OCSP stapling" "MISSING OCSP - the server does not staple a revocation response"
    fi

    # --- CRL distribution points ---
    local crl_uri
    crl_uri=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
        | grep -A4 "CRL Distribution Points" | grep -oE "URI:https?://[^ ]+" | head -1 | sed 's/^URI://' || true)
    if [[ -n "$crl_uri" ]]; then
        add "$f" "PASS" "M4" "CRL distribution point" "present - ${crl_uri}"
    else
        add "$f" "WARN" "M4" "CRL distribution point" "MISSING - the certificate carries no CRL distribution point"
    fi

    # --- OCSP responder URI in the certificate ---
    local ocsp_uri
    ocsp_uri=$(openssl x509 -in "$leaf" -noout -ocsp_uri 2>/dev/null || true)
    if [[ -z "$ocsp_uri" ]]; then
        ocsp_uri="(none)"
        add "$f" "INFO" "M4" "OCSP responder URI" "absent; CRL may be used instead"
    else
        add "$f" "INFO" "M4" "OCSP responder URI" "$ocsp_uri (presence only; not fetched)"
    fi

    printf 'chain_depth=%s\nocsp_stapled=%s\nocsp_uri=%s\ncrl_uri=%s\nverify=%s\n' \
        "$depth" "$ocsp_state" "$ocsp_uri" "${crl_uri:-(none)}" \
        "$(printf '%s' "$verify_out" | head -1 | sed 's/^/ /;s/ *$//')" >"$detail"
}

# ==============================================================================
#  worker - one endpoint
# ==============================================================================
# add <file> <severity> <module> <label> <detail>
add() {
    printf '%s|%s|%s|%s\n' "$2" "$3" "$4" "$5" >>"$1" 2>/dev/null || true
}

audit_host() {
    local ep="$1"
    local host="${ep%:*}" port="${ep##*:}"
    local tag; tag=$(safe_name "$ep")
    local f="$WORK_DIR/$tag.find"
    : >"$f"

    # 1. handshake and certificate
    local bundle="$WORK_DIR/$tag.bundle"
    sclient "$host" "$port" -showcerts -status >"$bundle"

    if ! grep -q "BEGIN CERTIFICATE" "$bundle"; then
        add "$f" "FAIL" "M1" "Endpoint reachability" "NO TLS HANDSHAKE - ${host}:${port} did not return a certificate (port closed, filtered, or not a TLS service)"
        printf 'handshake=failed\n' >"$WORK_DIR/$tag.detail"
        printf 'host=%s\nport=%s\n' "$host" "$port" >>"$WORK_DIR/$tag.detail"
        return 0
    fi

    local leaf="$WORK_DIR/$tag.leaf.pem"
    awk '/-----BEGIN CERTIFICATE-----/ {f=1} f {print} /-----END CERTIFICATE-----/ {exit}' "$bundle" >"$leaf"

    add "$f" "PASS" "M1" "Endpoint reachability" "TLS handshake succeeded on ${host}:${port}"

    audit_certificate "$host" "$port" "$leaf" "$tag"
    audit_protocols "$host" "$port" "$tag"
    audit_ciphers "$host" "$port" "$tag"
    audit_chain "$host" "$port" "$bundle" "$tag"
    local exchange
    exchange=$(grep -E 'Server Temp Key:|Peer Temp Key:|Negotiated TLS1.3 group:' "$bundle" || true)
    if [[ -n "$exchange" ]]; then
        add "$f" INFO M3 "Negotiated key exchange" "$(tr '\n' ';' <<<"$exchange")"
        local dhbits
        dhbits=$(sed -n 's/.*Temp Key: DH, \([0-9]*\) bits.*/\1/p' <<<"$exchange")
        if [[ -n "$dhbits" && "$dhbits" -lt 2048 ]]; then add "$f" FAIL M3 "DH parameters" "WEAK DH - $dhbits bits (minimum 2048)"; fi
    fi


    # merge the per-module detail fragments into one detail file
    {
        printf 'host=%s\nport=%s\n' "$host" "$port"
        local frag
        for frag in "$WORK_DIR/$tag.m1.detail" "$WORK_DIR/$tag.m2.detail" \
                    "$WORK_DIR/$tag.m3.detail" "$WORK_DIR/$tag.m4.detail"; do
            [[ -f "$frag" ]] && cat "$frag" 2>/dev/null || true
        done
    } >"$WORK_DIR/$tag.detail"
}

# ==============================================================================
#  parallel driver
# ==============================================================================
run_audits() {
    log_step "Stage 2/5 - Parallel TLS audit"

    WORK_DIR="$TMP_DIR/work"
    mkdir -p "$WORK_DIR"

    local pids=() ep running=0 p
    while IFS= read -r ep; do
        [[ -z "$ep" ]] && continue
        if [[ "$running" -ge "$THREADS" ]]; then
            wait -n 2>/dev/null || true
            running=$((running - 1))
        fi
        ( audit_host "$ep" ) &
        pids+=("$!")
        running=$((running + 1))
    done <"$ENDPOINT_FILE"

    for p in "${pids[@]:-}"; do
        if [[ -n "$p" ]]; then wait "$p" 2>/dev/null || true; fi
    done

    local n
    n=$(count_lines "$ENDPOINT_FILE")
    while IFS= read -r ep; do
        local tag; tag=$(safe_name "$ep")
        if [[ ! -f "$WORK_DIR/$tag.detail" ]]; then
            add "$WORK_DIR/$tag.find" WARN M1 "Worker status" "INCOMPLETE AUDIT - worker failed"
        fi
    done <"$ENDPOINT_FILE"
    log_ok "$n endpoint(s) audited"
}

# ==============================================================================
#  stage 3 - aggregation
# ==============================================================================
read_findings() {
    local ep="$1"
    local tag; tag=$(safe_name "$ep")
    local f="$WORK_DIR/$tag.find"
    [[ -f "$f" ]] || return 0
    sort -s -t'|' -k2,2 "$f" 2>/dev/null || true
}

read_detail() {
    local ep="$1"
    local tag; tag=$(safe_name "$ep")
    local f="$WORK_DIR/$tag.detail"
    [[ -f "$f" ]] || return 0
    cat "$f" 2>/dev/null || true
}

count_sev() {
    local sev="$1"
    local n=0 ep line s
    while IFS= read -r ep; do
        [[ -z "$ep" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            s="${line%%|*}"
            [[ "$s" == "$sev" ]] && n=$((n + 1))
        done < <(read_findings "$ep")
    done <"$ENDPOINT_FILE"
    printf '%s' "$n"
}

host_verdict() {
    local ep="$1"
    local line s v=PROTECTED
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        s="${line%%|*}"
        case "$s" in
            FAIL) v=VULNERABLE; break ;;
            WARN) v=WARNING ;;
        esac
    done < <(read_findings "$ep")
    printf '%s' "$v"
}

host_sev_count() {
    local ep="$1" sev="$2"
    local n=0 line s
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        s="${line%%|*}"
        [[ "$s" == "$sev" ]] && n=$((n + 1))
    done < <(read_findings "$ep")
    printf '%s' "$n"
}

detail_get() {
    local ep="$1" key="$2"
    local v
    v=$(read_detail "$ep" | sed -n "s/^${key}=//p" | head -1 || true)
    printf '%s' "$v"
}

# ==============================================================================
#  stage 3 - the terminal table
# ==============================================================================
print_table() {
    log_step "Stage 3/5 - TLS posture table"

    local ep host port verdict days nc
    printf '\n'
    printf '  %s%-34s %-6s %-11s %-7s %-9s %-4s %s%s\n' \
        "$C_BOLD" "ENDPOINT" "PORT" "VERDICT" "DAYS" "PROTOCOL" "CHAIN" "NOTES" "$C_RESET"
    printf '  %s%s%s\n' "$C_DIM" "----------------------------------------------------------------------------------------------" "$C_RESET"

    while IFS= read -r ep; do
        [[ -z "$ep" ]] && continue
        host="${ep%:*}"; port="${ep##*:}"
        verdict=$(host_verdict "$ep")
        days=$(detail_get "$ep" "days_remaining")
        [[ -z "$days" ]] && days="-"
        nc=$(detail_get "$ep" "negotiated_cipher")
        [[ -z "$nc" ]] && nc="-"

        local chain depth
        chain=$(detail_get "$ep" "chain_depth")
        [[ -z "$chain" ]] && chain="-"

        local legacy modern proto_note notes
        legacy=$(detail_get "$ep" "legacy_accepted")
        modern=$(detail_get "$ep" "modern_accepted")
        proto_note=""
        [[ "$legacy" == "1" ]] && proto_note="legacy!"
        [[ -z "$proto_note" && "$modern" == "1" ]] && proto_note="modern"

        notes=""
        local weak
        weak=$(detail_get "$ep" "weak_ciphers")
        if [[ "$weak" == *"(accepted)"* ]]; then
            notes="weak cipher"
        fi
        if [[ -n "$days" && "$days" =~ ^-?[0-9]+$ && "$days" -lt 0 ]]; then
            notes="expired"
        fi
        [[ -z "$notes" ]] && notes="-"

        local vc
        case "$verdict" in
            PROTECTED)  vc="$C_GREEN" ;;
            WARNING)    vc="$C_YELLOW" ;;
            VULNERABLE) vc="$C_RED" ;;
            *)          vc="$C_RESET" ;;
        esac

        printf '  %-34s %-6s %s%-11s%s %-7s %-9s %-4s %s\n' \
            "$host" "$port" "$vc" "$verdict" "$C_RESET" "$days" "$proto_note" "$chain" "$notes"
    done <"$ENDPOINT_FILE"

    printf '  %s%s%s\n' "$C_DIM" "----------------------------------------------------------------------------------------------" "$C_RESET"
}

# ==============================================================================
#  stage 4 - reports
# ==============================================================================
csv_escape() {
    local v="$1"
    v="${v//\"/\"\"}"
    printf '"%s"' "$v"
}

build_reports() {
    log_step "Stage 4/5 - Report generation"

    local ep host port verdict days subject issuer nb na cn ka kb chain ocsp crl modern legacy weak ncipher
    local p w f i

    # ---------------------------------------------------------------- CSV ---
    {
        printf 'endpoint,port,verdict,subject_cn,issuer,not_before,not_after,days_remaining,key_algorithm,key_bits,chain_depth,legacy_protocol_accepted,modern_protocol_accepted,weak_ciphers,negotiated_cipher,ocsp_stapled,crl_uri,pass,warning,fail,info\n'
        while IFS= read -r ep; do
            [[ -z "$ep" ]] && continue
            host="${ep%:*}"; port="${ep##*:}"
            verdict=$(host_verdict "$ep")
            days=$(detail_get "$ep" "days_remaining");      [[ -z "$days" ]] && days=""
            subject=$(detail_get "$ep" "cn");               [[ -z "$subject" ]] && subject=$(detail_get "$ep" "subject")
            issuer=$(detail_get "$ep" "issuer")
            nb=$(detail_get "$ep" "not_before")
            na=$(detail_get "$ep" "not_after")
            ka=$(detail_get "$ep" "key_summary")
            kb=$(detail_get "$ep" "key_bits")
            chain=$(detail_get "$ep" "chain_depth")
            ocsp=$(detail_get "$ep" "ocsp_stapled")
            crl=$(detail_get "$ep" "crl_uri")
            legacy=$(detail_get "$ep" "legacy_accepted")
            modern=$(detail_get "$ep" "modern_accepted")
            weak=$(detail_get "$ep" "weak_ciphers")
            ncipher=$(detail_get "$ep" "negotiated_cipher")
            p=$(host_sev_count "$ep" PASS)
            w=$(host_sev_count "$ep" WARN)
            f=$(host_sev_count "$ep" FAIL)
            i=$(host_sev_count "$ep" INFO)

            printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "$(csv_escape "$host")" "$port" "$verdict" \
                "$(csv_escape "$subject")" "$(csv_escape "$issuer")" \
                "$(csv_escape "$nb")" "$(csv_escape "$na")" "$days" \
                "$(csv_escape "$ka")" "$kb" "$chain" \
                "$legacy" "$modern" "$(csv_escape "$weak")" "$(csv_escape "$ncipher")" \
                "$ocsp" "$(csv_escape "$crl")" "$p" "$w" "$f" "$i"
        done <"$ENDPOINT_FILE"
    } >"$CSV_FILE"

    # ---------------------------------------------------------------- TXT ---
    {
        printf '================================================================================\n'
        printf ' TLSWatch v%s - SSL/TLS Configuration & Certificate Lifecycle Audit\n' "$VERSION"
        printf '================================================================================\n'
        printf ' Generated    : %s\n' "$(utc_now)"
        printf ' Target       : %s\n' "$TARGET"
        printf ' Endpoints    : %s\n' "$(count_lines "$ENDPOINT_FILE")"
        printf ' Alert window : %s day(s) before expiry\n' "$WARN_DAYS"
        printf ' Duration     : %s\n' "$(elapsed)"
        printf ' Verdict      : %s\n' "$(overall_verdict)"
        printf ' Checks       : %s pass, %s warning, %s vulnerable, %s info\n' \
            "$(count_sev PASS)" "$(count_sev WARN)" "$(count_sev FAIL)" "$(count_sev INFO)"
        printf '================================================================================\n'

        while IFS= read -r ep; do
            [[ -z "$ep" ]] && continue
            host="${ep%:*}"; port="${ep##*:}"
            printf '\n\n--------------------------------------------------------------------------------\n'
            printf ' ENDPOINT : %s:%s\n' "$host" "$port"
            printf ' VERDICT  : %s\n' "$(host_verdict "$ep")"
            printf '%s\n' '--------------------------------------------------------------------------------'

            printf '\n  Technical detail\n'
            local k v
            while IFS= read -r k; do
                [[ -z "$k" ]] && continue
                v="${k#*=}"
                printf '    %-22s %s\n' "${k%%=*}" "$v"
            done < <(read_detail "$ep")

            local last_mod=""
            printf '\n  Findings\n'
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local sev lm ll ld
                sev="${line%%|*}"; ll="${line#*|}"
                lm="${ll%%|*}"; ll="${ll#*|}"
                ld="${ll#*|}"; ll="${ll%%|*}"
                if [[ "$lm" != "$last_mod" ]]; then
                    printf '\n'
                    case "$lm" in
                        M1) printf '    %sModule 1 - Certificate lifecycle & expiry%s\n' "$C_BLUE" "$C_RESET" ;;
                        M2) printf '    %sModule 2 - Protocol support verification%s\n' "$C_BLUE" "$C_RESET" ;;
                        M3) printf '    %sModule 3 - Weak ciphers & key exchange%s\n' "$C_BLUE" "$C_RESET" ;;
                        M4) printf '    %sModule 4 - Certificate chain & CA validation%s\n' "$C_BLUE" "$C_RESET" ;;
                    esac
                    last_mod="$lm"
                fi
                printf '    %s[%s]%s %-26s %s\n' "$(sev_colour "$sev")" "$sev" "$C_RESET" "$ll" "$ld"
            done < <(read_findings "$ep")
            if [[ "$VERBOSE" -eq 1 ]]; then
                printf '\n  Raw handshake evidence\n'
                local raw tag
                tag=$(safe_name "$ep")
                for raw in "$WORK_DIR/$tag.bundle" "$WORK_DIR/$tag".*.raw; do
                    [[ -f "$raw" ]] || continue
                    printf '\n--- %s ---\n' "${raw##*/}"
                    cat "$raw"
                done
            fi
        done <"$ENDPOINT_FILE"

        printf '\n\n================================================================================\n'
        printf ' END OF REPORT\n'
        printf '================================================================================\n'
    } >"$TXT_FILE"

    # strip the colours out of the report file
    sed -i 's/\x1b\[[0-9;]*m//g' "$TXT_FILE" 2>/dev/null || true

    if [[ "$NO_HISTORY" -eq 0 ]]; then
        cp "$TXT_FILE" "$TS_FILE" 2>/dev/null || true
    fi

    log_ok "CSV summary : $CSV_FILE"
    log_ok "Full report : $TXT_FILE"
    if [[ "$NO_HISTORY" -eq 0 ]]; then log_ok "Timestamped  : $TS_FILE"; fi
}

elapsed() {
    local now
    now=$(date +%s)
    local d=$((now - START_TS))
    printf '%02d:%02d:%02d' $((d/3600)) $((d%3600/60)) $((d%60))
}

overall_verdict() {
    local ep v
    local worst=PROTECTED
    while IFS= read -r ep; do
        [[ -z "$ep" ]] && continue
        v=$(host_verdict "$ep")
        case "$v" in
            VULNERABLE) printf 'VULNERABLE'; return 0 ;;
            WARNING)    worst=WARNING ;;
        esac
    done <"$ENDPOINT_FILE"
    printf '%s' "$worst"
}

# ==============================================================================
#  stage 5 - summary
# ==============================================================================
print_summary() {
    log_step "Stage 5/5 - Summary"

    local p w f i
    p=$(count_sev PASS); w=$(count_sev WARN); f=$(count_sev FAIL); i=$(count_sev INFO)
    local verdict; verdict=$(overall_verdict)

    printf '\n'
    printf '  %sAudit summary%s\n' "$C_BOLD" "$C_RESET"
    printf '    %-22s %s\n' "Target" "$TARGET"
    printf '    %-22s %s%s%s\n' "Verdict" "$(sev_colour "$verdict")" "$verdict" "$C_RESET"
    printf '    %-22s %s\n' "Endpoints" "$(count_lines "$ENDPOINT_FILE")"
    printf '    %-22s %s%s%s  %s%s%s  %s%s%s  %s%s%s\n' "Checks" \
        "$C_GREEN" "$p pass" "$C_RESET" \
        "$C_YELLOW" "$w warning" "$C_RESET" \
        "$C_RED" "$f vulnerable" "$C_RESET" \
        "$C_CYAN" "$i info" "$C_RESET"
    printf '    %-22s %s\n' "Duration" "$(elapsed)"
    printf '    %-22s %s\n' "CSV" "$CSV_FILE"
    printf '    %-22s %s\n\n' "Report" "$TXT_FILE"
}

# ==============================================================================
#  argument parsing
# ==============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)    DOMAIN="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -l|--list)      HOSTLIST="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -o|--output)    OUTPUT_DIR="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -w|--warn-days) WARN_DAYS="${2:-}"; shift 2 || die "Missing value for $1" ;;
            -t|--threads)   THREADS="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --ca-file) CA_FILE="${2:-}"; shift 2 || die "Missing CA file" ;;
            --timeout)      TIMEOUT="${2:-}"; shift 2 || die "Missing value for $1" ;;
            --no-history)   NO_HISTORY=1; shift ;;
            -v|--verbose)   VERBOSE=1; shift ;;
            --no-color)     NO_COLOR=1; shift ;;
            -h|--help)      init_colors; banner; usage; exit 0 ;;
            *)              printf '\n  Unknown option: %s\n\n' "$1" >&2; init_colors; usage >&2; exit 2 ;;
        esac
    done

    if [[ -z "$DOMAIN" && -z "$HOSTLIST" ]]; then
        printf '\n  Error: -d and/or -l are required.\n\n' >&2
        init_colors; usage >&2
        exit 2
    fi
    if ! [[ "$WARN_DAYS" =~ ^[0-9]+$ ]]; then
        die "--warn-days must be a non-negative integer"
    fi
    if ! [[ "$THREADS" =~ ^[0-9]+$ ]]; then
        die "--threads must be a positive integer"
    fi
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]]; then
        die "--timeout must be a positive integer"
    fi
    [[ ${#WARN_DAYS} -le 6 && ${#THREADS} -le 3 && ${#TIMEOUT} -le 4 ]] || die "Numeric option too large"
    WARN_DAYS=$((10#$WARN_DAYS)); THREADS=$((10#$THREADS)); TIMEOUT=$((10#$TIMEOUT))
    [[ "$THREADS" -ge 1 && "$THREADS" -le 128 && "$TIMEOUT" -ge 1 && "$TIMEOUT" -le 600 ]] || die "Maximum threads=128, timeout=600"
    if [[ -z "$OUTPUT_DIR" || "$OUTPUT_DIR" == "/" || "$OUTPUT_DIR" == "." ]]; then
        die "Invalid output directory"
    fi
}

# ==============================================================================
#  main
# ==============================================================================
main() {
    START_TS=$(date +%s)
    parse_args "$@"
    init_colors
    banner

    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tlswatch.XXXXXX")"
    chmod 700 "$TMP_DIR" 2>/dev/null || true

    [[ -z "$CA_FILE" || -r "$CA_FILE" ]] || die "CA file is not readable"
    check_deps
    load_targets
    run_audits
    print_table
    build_reports
    print_summary

    return 0
}

cleanup() {
    local rc=$?
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
        rm -rf "$TMP_DIR" 2>/dev/null || true
    fi
    return "$rc"
}
# shellcheck disable=SC2317  # invoked indirectly by the EXIT trap
trap 'rc=$?; cleanup; exit $rc' EXIT

main "$@"
