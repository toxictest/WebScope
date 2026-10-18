# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
VERSION=1.0.0-rc1
NOW=$(date -u +%s)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
PARTIAL=0
QUIET=0
WORK=''
RUN=''
LOCK=''
BASELOCK=''
ORG=''
BASELINE=''
OUTPUT=./surfaceintel-reports
REPORT=all
UPDATE=0
DRY=0
MODE=normal
HTTP_CHECKS=0
CLOUD_CHECKS=0
DNS_RATE=2
HTTP_RATE=1
CONCURRENCY=1
REQ_TIMEOUT=8
RUN_TIMEOUT=900
MAX_ASSETS=128
RETENTION_RUNS=30
RETENTION_BASELINES=8
TLS_CRITICAL_DAYS=15
ALLOW_NONPUBLIC=false
ALLOW_PUBLIC_DNS=true
CT_ENABLED=false
BODY_PREVIEW=false
FOLLOW_REDIRECTS=false
CLOUD_LISTING=false
RESOLVER=system
CA_FILE=''
ALERT_CONFIG=''
COOLDOWN=86400
ALERT_MIN=HIGH
ALERT_RETRIES=2
CONFIG_VERSION=1
REQUEST_SEQ=0
NEXT_DNS=0
NEXT_HTTP=0
START_TIME=$NOW
declare -a ROOTS=() HOSTS=() CIDRS=() EXCLUDES=() EXCLUDE_TREES=() EXCLUDE_CIDRS=() ALIASES=() ENDPOINTS=() CLOUDS=() SEEDS=() ASSET_FILES=() CRITICAL_ENDPOINTS=() ALERT_HOSTS=() ALERT_CATEGORIES=()
declare -A SEVERITY_OVERRIDES=()
declare -A OLD_ROWS=() CURRENT_IDS=() ALERT_ENV=() DELIVERED=()
log() { (( QUIET )) || printf '%s\n' "$*" >&2; }
fatal() { printf 'SurfaceIntel: %s\n' "$1" >&2; exit "${2:-2}"; }
hash() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
clean() { printf '%s' "$1" | LC_ALL=C tr '\000-\037\177' ' ' | LC_ALL=C tr -cd '\040-\176' | sed -E 's/([Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd])=[^ ;,]+/\1=[REDACTED]/g;s/[Bb]earer [A-Za-z0-9._~-]+/Bearer [REDACTED]/g' | cut -c1-1200; }
json_string() {
    local x=$1
    x=${x//\\/\\\\}; x=${x//\"/\\\"}; x=${x//$'\n'/\\n}; x=${x//$'\r'/\\r}; x=${x//$'\t'/\\t}
    printf '"%s"' "$x"
}
html_escape() { printf '%s' "$1" | sed 's/\&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g;s/"/\&quot;/g;s/'"'"'/\&#39;/g'; }
number() { [[ $1 =~ ^[0-9]{1,6}$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }
contains() { local wanted=$1; shift; local value; for value; do [[ $value == "$wanted" ]] && return 0; done; return 1; }
private_dir() {
    local path=$1 mode owner
    [[ ! -L $path ]] || return 1
    mkdir -p -- "$path" || return 1
    mode=$(stat -c '%a' -- "$path") || return 1
    owner=$(stat -c '%u' -- "$path") || return 1
    [[ $owner == "$(id -u)" ]] && (( (8#$mode & 077) == 0 ))
}
text_file() {
    [[ -f $1 && ! -L $1 && -r $1 ]] || return 1
    (( $(stat -c '%s' -- "$1") <= ${2:-1048576} )) || return 1
    cmp -s -- "$1" <(LC_ALL=C tr -d '\000' < "$1") || return 1
    cmp -s -- "$1" <(LC_ALL=C tr -d '\001-\010\013-\037\177' < "$1")
}
read_pairs() {
    local file=$1 callback=$2 line key value count=0
    text_file "$file" || fatal 'Configuration must be a bounded, readable, non-symlink text file.'
    while IFS= read -r line || [[ -n $line ]]; do
        ((count+=1)); (( count <= 4096 )) || fatal 'Too many configuration lines.'
        [[ -z $line || $line == \#* ]] && continue
        [[ $line == *=* && ${#line} -le 4096 && $line != *$'\t'* ]] || fatal 'Invalid configuration line; use unquoted key=value.'
        key=${line%%=*}; value=${line#*=}
        [[ $key =~ ^[a-z_]+$ && -n $value ]] || fatal 'Invalid configuration key/value.'
        "$callback" "$key" "$value"
    done < "$file"
}
issue() {
    local category=$1 asset=$2 detail=$3
    PARTIAL=1
    printf '%s\t%s\t%s\n' "$category" "$(clean "$asset")" "$(clean "$detail")" >> "$WORK/errors.tsv"
}
rate_wait() {
    local channel=$1 rate now next delay
    if [[ $channel == dns ]]; then rate=$DNS_RATE; next=$NEXT_DNS; else rate=$HTTP_RATE; next=$NEXT_HTTP; fi
    now=$(date +%s%N)
    delay=$((next-now))
    if ((delay>0)); then sleep "$(awk -v d="$delay" 'BEGIN{printf "%.6f",d/1000000000}')"; fi
    now=$(date +%s%N)
    if [[ $channel == dns ]]; then NEXT_DNS=$((now+1000000000/rate)); else NEXT_HTTP=$((now+1000000000/rate)); fi
}
budget() { (( $(date +%s)-START_TIME < RUN_TIMEOUT )); }
severity_rank() { case $1 in CRITICAL) REPLY=5;; HIGH) REPLY=4;; MEDIUM) REPLY=3;; LOW) REPLY=2;; INFO) REPLY=1;; *) REPLY=0;; esac; }
record() {
    local kind=$1 asset=$2 status=$3 severity=$4 semantic=$5 detail=$6 id fingerprint first previous
    id=$(hash "$kind|$asset"); fingerprint=$(hash "$kind|$asset|$status|$severity|$semantic")
    first=$NOW; previous=${OLD_ROWS[$id]-}
    if [[ -n $previous ]]; then first=$(printf '%s\n' "$previous" | cut -f7); fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$kind" "$id" "$asset" "$status" "$fingerprint" "$severity" "$first" "$NOW" "$(clean "$detail")" >> "$WORK/records.tsv"
    CURRENT_IDS[$id]=1
}
finding() {
    local category=$1 asset=$2 severity=$3 confidence=$4 evidence=$5 remedy=$6
    severity=${SEVERITY_OVERRIDES[$category]:-$severity}
    record finding "$category|$asset" OPEN "$severity" "$evidence" "confidence=$confidence;scope=VALIDATED;method=$category;evidence=$evidence;remediation=$remedy;policy=$CONFIG_VERSION"
}
