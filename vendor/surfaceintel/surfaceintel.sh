#!/usr/bin/env bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
# SurfaceIntel: trusted code only; configuration/state is never sourced.
set +x
set -uo pipefail
unset SSLKEYLOGFILE OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
umask 077
export LC_ALL=C
HOME_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib/common.sh
source "$HOME_DIR/lib/common.sh"
for library in validation state_store network; do
    # shellcheck disable=SC1090
    source "$HOME_DIR/lib/$library.sh"
done
for module in scope dns_resolution passive_discovery http_exposure cloud_storage tls_monitor drift_detection alerting reporting; do
    # shellcheck disable=SC1090
    source "$HOME_DIR/modules/$module.sh"
done
for provider in slack discord teams; do
    # shellcheck disable=SC1090
    source "$HOME_DIR/integrations/$provider.sh"
done
usage() {
    cat <<'HELP'
SurfaceIntel — authorized external inventory and change monitoring
Usage: surfaceintel.sh --scope FILE [--config FILE] [OPTIONS]
  --help --version
  --scope FILE             Required explicit authorization scope, data only
  --config FILE            Optional policy configuration, data only
  --output DIR             Private report root, separated by organization
  --baseline FILE          Same-organization validated TSV state
  --update-baseline        Explicit atomic update only after a complete scan
  --passive-only           Configured/imported/optional CT candidates only
  --dns-only               Candidates plus DNS, no HTTP/TLS/cloud validation
  --tls-only               Candidates plus TLS for explicit HTTPS endpoints
  --http-checks            Opt-in HTTP exposure checks on approved endpoints
  --cloud-checks           Opt-in metadata checks for explicit cloud resources
  --report text|json|html|all  Default all; daily/weekly text and state always saved
  --rate-limit VALUE       Integer requests/second, 1..20, both DNS and HTTP
  --concurrency COUNT      Maximum permitted workers, 1..8; engine currently serial
  --timeout SECONDS        Request timeout, 1..60
  --exclude FILE           Extra exclude_host/exclude_tree/exclude_cidr key=value data
  --dry-run                Validate and show plan; no network or output creation
  --no-color               Output is always ANSI-free
  --quiet                  Suppress successful console progress
Safe defaults: no HTTP/cloud checks without flags, no redirects, no page bodies,
no cloud object downloads, no exploit/authentication testing, no telemetry.
Exit: 0 complete, 2 configuration/output/dependency error, 3 partial scan,
75 overlap/lock, 130 SIGINT, 143 SIGTERM. Findings do not imply an error exit.
HELP
}
SCOPE_FILE=''; CONFIG_FILE=''; EXCLUDE_FILE=''; CLI_OUTPUT=''; CLI_BASELINE=''; CLI_RATE=''; CLI_CONCURRENCY=''; CLI_TIMEOUT=''; MODE_SET=0
while (($#)); do
    case $1 in
        --help) usage; exit 0;; --version) printf 'SurfaceIntel %s\n' "$VERSION"; exit 0;;
        --scope|--config|--output|--baseline|--report|--rate-limit|--concurrency|--timeout|--exclude)
            (($#>=2)) || fatal 'Missing option value.'
            [[ -n $2 && $2 != *[$'\n\r\t']* ]] || fatal 'Invalid option value.'
            case $1 in --scope) SCOPE_FILE=$2;; --config) CONFIG_FILE=$2;; --output) CLI_OUTPUT=$2;; --baseline) CLI_BASELINE=$2;; --report) REPORT=$2;; --rate-limit) CLI_RATE=$2;; --concurrency) CLI_CONCURRENCY=$2;; --timeout) CLI_TIMEOUT=$2;; --exclude) EXCLUDE_FILE=$2;; esac
            shift 2;;
        --passive-only|--dns-only|--tls-only)
            ((MODE_SET==0)) || fatal 'Scan-only modes are mutually exclusive.'
            MODE_SET=1; case $1 in --passive-only) MODE=passive;; --dns-only) MODE=dns;; --tls-only) MODE=tls;; esac; shift;;
        --http-checks) HTTP_CHECKS=1; shift;; --cloud-checks) CLOUD_CHECKS=1; shift;;
        --update-baseline) UPDATE=1; shift;; --dry-run) DRY=1; shift;; --quiet) QUIET=1; shift;; --no-color) shift;;
        *) fatal 'Unknown command-line option.';;
    esac
done
[[ -n $SCOPE_FILE ]] || fatal '--scope is required; no implicit scan targets.'
[[ $REPORT =~ ^(text|json|html|all)$ ]] || fatal 'Invalid report format.'
if [[ $MODE != normal ]] && ((HTTP_CHECKS || CLOUD_CHECKS)); then fatal 'Only modes cannot be combined with HTTP/cloud flags.'; fi
for dependency in curl sha256sum date sort awk sed grep cut diff cmp tr stat mktemp find head tail wc; do command -v "$dependency" >/dev/null 2>&1 || fatal "Required local utility missing: $dependency (nothing installed)."; done
[[ -z $CONFIG_FILE ]] || read_pairs "$CONFIG_FILE" policy_pair
read_pairs "$SCOPE_FILE" scope_pair
exclusion_pair() { case $1 in exclude_host|exclude_tree|exclude_cidr) scope_pair "$1" "$2";; *) fatal 'Only exclusion keys allowed in exclusion file.';; esac; }
[[ -z $EXCLUDE_FILE ]] || read_pairs "$EXCLUDE_FILE" exclusion_pair
[[ -z $CLI_OUTPUT ]] || OUTPUT=$CLI_OUTPUT
[[ -z $CLI_BASELINE ]] || BASELINE=$CLI_BASELINE
if [[ -n $CLI_RATE ]]; then number "$CLI_RATE" 1 20 || fatal 'Rate must be 1..20.'; DNS_RATE=$((10#$CLI_RATE)); HTTP_RATE=$DNS_RATE; fi
if [[ -n $CLI_CONCURRENCY ]]; then number "$CLI_CONCURRENCY" 1 8 || fatal 'Concurrency must be 1..8.'; CONCURRENCY=$((10#$CLI_CONCURRENCY)); fi
if [[ -n $CLI_TIMEOUT ]]; then number "$CLI_TIMEOUT" 1 60 || fatal 'Timeout must be 1..60.'; REQ_TIMEOUT=$((10#$CLI_TIMEOUT)); fi
validate_scope
validate_alerts
if ((DRY)); then
    [[ -n $BASELINE ]] || BASELINE="$OUTPUT/$ORG/state/baseline.tsv"
    load_baseline
    printf 'VALIDATED PLAN | organization=%s | mode=%s | endpoint_count=%s | cloud_count=%s | DNS_rate=%s | HTTP_rate=%s | concurrency_ceiling=%s | actual_concurrency=1\nNo network requests or output/state writes performed.\n' "$ORG" "$MODE" "${#ENDPOINTS[@]}" "${#CLOUDS[@]}" "$DNS_RATE" "$HTTP_RATE" "$CONCURRENCY"
    exit 0
fi
cleanup() {
    [[ -z $WORK || ! -d $WORK ]] || rm -rf -- "$WORK"
    [[ -z $BASELOCK || ! -d $BASELOCK ]] || rmdir -- "$BASELOCK" 2>/dev/null || :
    if [[ -n $LOCK && -d $LOCK ]]; then rm -f -- "$LOCK/pid"; rmdir -- "$LOCK" 2>/dev/null || :; fi
}
interrupt() {
    trap '' INT TERM
    PARTIAL=1; COMPLETION=interrupted
    if [[ -n $WORK && -n $RUN && -f $WORK/records.tsv ]]; then
        issue interruption scope 'Scan interrupted; last successful baseline is unchanged.'
        write_state interrupted; drift_detection; reporting
    fi
    exit "$1"
}
trap cleanup EXIT
trap 'interrupt 130' INT
trap 'interrupt 143' TERM
initialize_store
log "SurfaceIntel $VERSION | $ORG | authorized scope only; serial collection"
passive_discovery
if [[ $MODE == normal || $MODE == dns ]]; then dns_inventory; fi
if [[ $MODE == normal || $MODE == tls ]]; then tls_monitor; fi
((HTTP_CHECKS==0)) || http_exposure
((CLOUD_CHECKS==0)) || cloud_storage
COMPLETION=complete; ((PARTIAL==0)) || COMPLETION=partial
write_state "$COMPLETION"
drift_detection
alerting
reporting
update_baseline
retention
log "Completed: $COMPLETION | reports: $RUN | baseline updated only if explicitly requested and complete"
((PARTIAL==0)) || exit 3
exit 0
