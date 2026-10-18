# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
ALERT_ORG=''
declare -A ALERT_SEEN=()
alert_pair() {
    local key=$1 value=$2 provider
    case $key in
        organization) [[ -z $ALERT_ORG ]] || fatal 'Duplicate alert organization.'; ALERT_ORG=$value;;
        approved_host) host_valid "$value" || ip_expand "$value" || fatal 'Invalid alert host.'; ALERT_HOSTS+=("$value");;
        category) [[ $value =~ ^[A-Z_]+$ ]] || fatal 'Invalid alert category.'; ALERT_CATEGORIES+=("$value");;
        slack_env|discord_env|teams_env)
            [[ $value =~ ^[A-Z_][A-Z0-9_]*$ && -z ${ALERT_SEEN[$key]-} ]] || fatal 'Invalid/duplicate webhook environment reference.'
            ALERT_SEEN[$key]=1; provider=${key%_env}; ALERT_ENV[$provider]=$value;;
        minimum_severity) severity_rank "$value"; ((REPLY>0)) || fatal 'Invalid alert severity.'; ALERT_MIN=$value;;
        cooldown_seconds) number "$value" 0 604800 || fatal 'Invalid cooldown.'; COOLDOWN=$((10#$value));;
        retries) number "$value" 0 3 || fatal 'Alert retries must be 0..3.'; ALERT_RETRIES=$((10#$value));;
        *) fatal 'Unknown alert configuration key.';;
    esac
}
validate_alerts() {
    local perms provider name secret base
    [[ -n $ALERT_CONFIG ]] || return 0
    text_file "$ALERT_CONFIG" || fatal 'Alert configuration unavailable.'
    perms=$(stat -c '%a' "$ALERT_CONFIG"); (( (8#$perms & 077) == 0 )) || fatal 'Alert configuration must be private (0600).'
    [[ $(stat -c '%u' "$ALERT_CONFIG") == "$(id -u)" ]] || fatal 'Alert configuration must be owned by caller.'
    read_pairs "$ALERT_CONFIG" alert_pair
    [[ $ALERT_ORG == "$ORG" ]] || fatal 'Alert configuration organization mismatch.'
    for provider in "${!ALERT_ENV[@]}"; do
        name=${ALERT_ENV[$provider]}; secret=${!name-}
        [[ -n $secret ]] || fatal 'Configured webhook environment variable is missing (value not logged).'
        [[ ${#secret} -le 4096 && $secret != *[$'\n\r\t'\"\\\#]* ]] || fatal 'Invalid webhook URL (value not logged).'
        base=${secret%%\?*}; parse_url "$base" || fatal 'Unsupported webhook URL syntax (value not logged).'
        contains "$URL_HOST" "${ALERT_HOSTS[@]}" || fatal 'Webhook host not explicitly authorized.'
    done
}
alert_send() {
    local provider=$1 payload=$2 name secret base host port scheme address attempt rc code config
    name=${ALERT_ENV[$provider]}; secret=${!name-}; base=${secret%%\?*}
    parse_url "$base" || return 1; host=$URL_HOST; port=$URL_PORT; scheme=$URL_SCHEME
    for ((attempt=0;attempt<=ALERT_RETRIES;attempt++)); do
        budget || return 1
        role_scope "$host" alert || return 1
        resolve_destination "$host" alert || return 1
        if [[ $scheme != https ]]; then
            [[ $ALLOW_NONPUBLIC == true ]] && { in_cidr "$PINNED_IP" 127.0.0.0/8 || in_cidr "$PINNED_IP" ::1/128; } || return 1
        fi
        address=$PINNED_IP; [[ $address != *:* ]] || address="[$address]"
        ((REQUEST_SEQ+=1)); config="$WORK/webhook-$REQUEST_SEQ.conf"
        printf 'url = "%s"\n' "$secret" > "$config"
        local -a args=(-q --config "$config" --silent --noproxy '*' --proxy '' --proto '=http,https' --max-redirs 0 --connect-timeout "$REQ_TIMEOUT" --max-time "$REQ_TIMEOUT" --header 'Content-Type: application/json' --data-binary "@$payload" --max-filesize 65536 --output "$WORK/webhook-response-$REQUEST_SEQ" --write-out '%{http_code}')
        if ! ip_expand "$host"; then args+=(--resolve "$host:$port:$address"); fi
        [[ -z $CA_FILE || $scheme != https ]] || args+=(--cacert "$CA_FILE")
        rate_wait http; rc=0
        code=$(unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR; ulimit -f 64; curl "${args[@]}" 2>/dev/null) || rc=$?
        [[ $code =~ ^[0-9]{3}$ ]] || code=000
        rm -f -- "$config" "$WORK/webhook-response-$REQUEST_SEQ"
        if ((rc==0)) && [[ $code =~ ^2[0-9][0-9]$ ]]; then return 0; fi
        # Never follow webhook redirects or retry non-transient HTTP 4xx.
        if ((rc==0)) && [[ $code != 429 && ! $code =~ ^5[0-9][0-9]$ ]]; then return 1; fi
        ((attempt>=ALERT_RETRIES)) || sleep "$((1<<attempt))"
    done
    return 1
}
prepare_alert_rows() {
    local event event_id kind asset sev line id status fp first last detail category
    cp -- "$WORK/records.tsv" "$WORK/alert-rows.tsv"
    while IFS=$'\t' read -r event event_id kind asset sev; do
        category=''
        case "$event|$kind" in
            NEW_ASSET\|asset) category=NEW_ASSET; sev=INFO;;
            EVIDENCE_CHANGED\|dns|NEWLY_RESOLVING\|dns|NEWLY_UNRESOLVED\|dns) category=DNS_RECORD_CHANGE; sev=LOW;;
            NEW_OBSERVATION\|http) category=NEW_WEB_SERVICE; sev=INFO;;
            NEWLY_UNAVAILABLE\|*) category=COVERAGE_CHANGED; sev=LOW;;
            RESOLVED\|finding) category=RESOLVED; sev=INFO;;
        esac
        [[ -n $category ]] || continue
        line=$(awk -F '\t' -v id="$event_id" '$2==id{print;exit}' "$WORK/records.tsv")
        [[ -n $line ]] || line=${OLD_ROWS[$event_id]-}
        [[ -n $line ]] || continue
        IFS=$'\t' read -r kind id asset status fp _ first last detail <<< "$line"
        if [[ $category == NEW_WEB_SERVICE && $status != REACHABLE && $status != AUTH_REQUIRED_OR_DENIED ]]; then continue; fi
        [[ $kind != finding ]] || asset=${asset#*|}
        sev=${SEVERITY_OVERRIDES[$category]:-$sev}
        id=$(hash "event|$category|$asset")
        printf 'event\t%s\t%s|%s\tOBSERVED\t%s\t%s\t%s\t%s\t%s\n' "$id" "$category" "$asset" "$fp" "$sev" "$first" "$NOW" "confidence=HIGH;scope=AUTHORIZED_SUBJECT;method=baseline-difference;event=$event;remediation=Review approved change records and actual collected evidence;policy=$CONFIG_VERSION" >> "$WORK/alert-rows.tsv"
    done < "$WORK/events.tsv"
}
alerting() {
    local key timestamp extra line kind id asset status fp sev first last detail provider min rank category payload summary delivery now cached destination_name destination_value
    (( ${#ALERT_ENV[@]} )) || return 0
    if [[ -e $STATE/delivered.tsv || -L $STATE/delivered.tsv ]]; then
        text_file "$STATE/delivered.tsv" 2097152 || { printf 'all\tCACHE_INVALID\n' >> "$WORK/delivery.tsv"; return; }
        while IFS=$'\t' read -r key timestamp extra; do
            [[ $key =~ ^[a-f0-9]{64}$ && $timestamp =~ ^[0-9]{10,12}$ && -z $extra ]] || { printf 'all\tCACHE_INVALID\n' >> "$WORK/delivery.tsv"; return; }
            DELIVERED[$key]=$timestamp
        done < "$STATE/delivered.tsv"
    fi
    prepare_alert_rows
    severity_rank "$ALERT_MIN"; min=$REPLY
    while IFS=$'\t' read -r kind id asset status fp sev first last detail; do
        [[ $kind == finding || $kind == event ]] || continue
        severity_rank "$sev"; rank=$REPLY; ((rank>=min)) || continue
        category=${asset%%|*}
        if (( ${#ALERT_CATEGORIES[@]} )); then contains "$category" "${ALERT_CATEGORIES[@]}" || continue; fi
        for provider in "${!ALERT_ENV[@]}"; do
            destination_name=${ALERT_ENV[$provider]}; destination_value=${!destination_name-}
            key=$(hash "$ORG|$provider|$(hash "$destination_value")|$id|$fp")
            cached=${DELIVERED[$key]:-0}
            if ((NOW-cached<COOLDOWN)); then printf '%s\tDEDUPLICATED\t%s\n' "$provider" "$id" >> "$WORK/delivery.tsv"; continue; fi
            # Concise whitelisted evidence, not raw responses or secret destination URLs.
            summary="SurfaceIntel $ORG | $sev | $category | ${asset#*|} | first_seen_epoch=$first | $detail | report=$(basename "$RUN")"
            summary=$(clean "$summary"); payload="$WORK/payload-$provider.json"; "payload_$provider" "$summary" > "$payload"
            if alert_send "$provider" "$payload"; then DELIVERED[$key]=$NOW; delivery=DELIVERED; else delivery=FAILED; fi
            printf '%s\t%s\t%s\n' "$provider" "$delivery" "$id" >> "$WORK/delivery.tsv"
        done
    done < "$WORK/alert-rows.tsv"
    : > "$WORK/delivered-new.tsv"
    for key in "${!DELIVERED[@]}"; do
        timestamp=${DELIVERED[$key]}; ((NOW-timestamp<=604800)) || continue
        printf '%s\t%s\n' "$key" "$timestamp" >> "$WORK/delivered-new.tsv"
    done
    local next_cache
    next_cache=$(mktemp "$STATE/.delivered.XXXXXXXX") || return 1
    sort -k2,2nr "$WORK/delivered-new.tsv" | head -n 10000 > "$next_cache"
    mv -f -- "$next_cache" "$STATE/delivered.tsv"
}
