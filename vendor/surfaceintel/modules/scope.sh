# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
declare -A POLICY_SEEN=()
scope_pair() {
    local key=$1 value=$2
    case $key in
        organization) [[ -z $ORG && $value =~ ^[a-z][a-z0-9_-]{0,47}$ ]] || fatal 'Invalid/duplicate organization.'; ORG=$value;;
        domain_tree) host_valid "$value" || fatal 'Invalid domain tree.'; ROOTS+=("$value"); SEEDS+=("$value");;
        host) host_valid "$value" || ip_expand "$value" || fatal 'Invalid explicit host.'; HOSTS+=("$value"); SEEDS+=("$value");;
        cidr) cidr_valid "$value" || fatal 'Invalid authorized CIDR.'; CIDRS+=("$value");;
        exclude_cidr) cidr_valid "$value" || fatal 'Invalid exclusion CIDR.'; EXCLUDE_CIDRS+=("$value");;
        exclude_host) host_valid "$value" || ip_expand "$value" || fatal 'Invalid excluded host.'; EXCLUDES+=("$value");;
        exclude_tree) host_valid "$value" || fatal 'Invalid excluded tree.'; EXCLUDE_TREES+=("$value");;
        allow_cname) host_valid "$value" || fatal 'Invalid approved CNAME.'; ALIASES+=("$value");;
        asset) host_valid "$value" || ip_expand "$value" || fatal 'Invalid asset.'; SEEDS+=("$value");;
        asset_file) ASSET_FILES+=("$value");;
        endpoint) parse_url "$value" || fatal 'Invalid endpoint URL.'; ENDPOINTS+=("$value");;
        critical_endpoint) parse_url "$value" || fatal 'Invalid critical endpoint URL.'; CRITICAL_ENDPOINTS+=("$value");;
        cloud) CLOUDS+=("$value");;
        *) fatal 'Unknown scope key.';;
    esac
}
policy_pair() {
    local key=$1 value=$2
    [[ -z ${POLICY_SEEN[$key]-} ]] || fatal 'Duplicate policy key.'; POLICY_SEEN[$key]=1
    case $key in
        config_version) [[ $value =~ ^[a-zA-Z0-9._-]{1,32}$ ]] || fatal 'Invalid configuration version.'; CONFIG_VERSION=$value;;
        dns_rate) number "$value" 1 50 || fatal 'DNS rate must be 1..50.'; DNS_RATE=$((10#$value));;
        http_rate) number "$value" 1 20 || fatal 'HTTP rate must be 1..20.'; HTTP_RATE=$((10#$value));;
        concurrency) number "$value" 1 8 || fatal 'Concurrency must be 1..8.'; CONCURRENCY=$((10#$value));;
        timeout) number "$value" 1 60 || fatal 'Timeout must be 1..60.'; REQ_TIMEOUT=$((10#$value));;
        max_duration) number "$value" 10 3600 || fatal 'Duration must be 10..3600.'; RUN_TIMEOUT=$((10#$value));;
        max_assets) number "$value" 1 1000 || fatal 'Asset bound must be 1..1000.'; MAX_ASSETS=$((10#$value));;
        retention_runs) number "$value" 1 365 || fatal 'Retention must be 1..365.'; RETENTION_RUNS=$((10#$value));;
        retention_baselines) number "$value" 1 100 || fatal 'Baseline retention must be 1..100.'; RETENTION_BASELINES=$((10#$value));;
        tls_critical_days) number "$value" 1 30 || fatal 'TLS critical threshold must be 1..30.'; TLS_CRITICAL_DAYS=$((10#$value));;
        allow_nonpublic|allow_public_dns|ct_enabled|http_body_preview|follow_redirects|cloud_listing_verification)
            [[ $value == true || $value == false ]] || fatal 'Boolean must be true or false.'
            case $key in allow_nonpublic) ALLOW_NONPUBLIC=$value;; allow_public_dns) ALLOW_PUBLIC_DNS=$value;; ct_enabled) CT_ENABLED=$value;; http_body_preview) BODY_PREVIEW=$value;; follow_redirects) FOLLOW_REDIRECTS=$value;; cloud_listing_verification) CLOUD_LISTING=$value;; esac;;
        resolver) [[ $value == system ]] || ip_expand "$value" || fatal 'Resolver must be system or a literal IP.'; RESOLVER=$value;;
        ca_file) text_file "$value" || fatal 'CA file unavailable.'; CA_FILE=$value;;
        alert_config) ALERT_CONFIG=$value;;
        baseline) BASELINE=$value;;
        output) OUTPUT=$value;;
        severity_*)
            local category=${key#severity_}; category=${category^^}
            case $category in MANAGEMENT_INTERFACE_POTENTIAL|ADMIN_ROUTE_POTENTIAL|NONPRODUCTION_INTERFACE|OUT_OF_SCOPE_REDIRECT|POSSIBLE_DANGLING_DNS|PUBLIC_CLOUD_ACCESS|TLS_VALIDATION_FAILURE|TLS_NOT_YET_VALID|CERTIFICATE_LIFECYCLE|NEW_ASSET|DNS_RECORD_CHANGE|NEW_WEB_SERVICE|COVERAGE_CHANGED|RESOLVED) :;; *) fatal 'Unknown severity category.';; esac
            severity_rank "$value"; ((REPLY>0)) || fatal 'Unknown severity level.'
            if [[ $category == NEW_ASSET || $category == NEW_WEB_SERVICE || $category == DNS_RECORD_CHANGE || $category == *POTENTIAL ]] && [[ $value == CRITICAL ]]; then fatal 'Critical severity cannot be assigned solely to novelty or an unconfirmed interface heuristic.'; fi
            SEVERITY_OVERRIDES[$category]=$value;;
        *) fatal 'Unknown policy key.';;
    esac
}
validate_cloud() {
    local entry=$1 provider kind url tail bucket
    [[ $(printf '%s' "$entry" | tr -cd '|' | wc -c) == 2 ]] || return 1
    IFS='|' read -r provider kind url <<< "$entry"
    [[ $kind == bucket || $kind == object ]] && parse_url "$url" && [[ $URL_SCHEME == https && $URL_PORT == 443 ]] || return 1
    case $provider in
        s3)
            [[ $URL_HOST =~ ^([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3(\.[a-z0-9-]+)?\.amazonaws\.com$ ]] || return 1
            bucket=${BASH_REMATCH[1]}; [[ ${#bucket} -ge 3 && ${#bucket} -le 63 ]] || return 1
            if [[ $kind == bucket ]]; then [[ $URL_PATH == / ]]; else [[ $URL_PATH != / ]]; fi;;
        azure)
            [[ $URL_HOST =~ ^[a-z0-9]{3,24}\.blob\.core\.windows\.net$ ]] || return 1
            tail=${URL_PATH#/}; bucket=${tail%%/*}; [[ $bucket =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ ]] || return 1
            if [[ $kind == bucket ]]; then [[ $tail == "$bucket" || $tail == "$bucket/" ]]; else [[ $tail == "$bucket/"* && $tail != "$bucket/" ]]; fi;;
        gcs)
            [[ $URL_HOST == storage.googleapis.com ]] || return 1
            tail=${URL_PATH#/}; bucket=${tail%%/*}; [[ $bucket =~ ^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$ ]] || return 1
            if [[ $kind == bucket ]]; then [[ $tail == "$bucket" || $tail == "$bucket/" ]]; else [[ $tail == "$bucket/"* && $tail != "$bucket/" ]]; fi;;
        *) return 1;;
    esac
}
validate_scope() {
    local value provider kind url asset_file line
    for asset_file in "${ASSET_FILES[@]}"; do
        text_file "$asset_file" || fatal "Asset list unavailable or invalid."
        while IFS= read -r line || [[ -n $line ]]; do
            [[ -z $line || $line == \#* ]] && continue
            host_valid "$line" || ip_expand "$line" || fatal "Malformed asset list entry."
        done < "$asset_file"
    done
    [[ -n $ORG ]] || fatal 'Scope needs organization.'
    (( ${#ROOTS[@]}+${#HOSTS[@]}+${#CIDRS[@]}+${#CLOUDS[@]} > 0 )) || fatal 'Empty authorization scope.'
    for value in "${HOSTS[@]}"; do
        if ip_expand "$value"; then ip_allowed "$value" true || fatal "Explicit IP host requires an authorized CIDR and applicable nonpublic policy."; fi
    done
    for value in "${ENDPOINTS[@]}" "${CRITICAL_ENDPOINTS[@]}"; do url_scope "$value" || fatal 'Endpoint is outside authorized domain/IP scope.'; done
    for value in "${CRITICAL_ENDPOINTS[@]}"; do contains "$value" "${ENDPOINTS[@]}" || fatal 'Critical endpoint must also be explicitly listed.'; done
    for value in "${CLOUDS[@]}"; do validate_cloud "$value" || fatal 'Invalid or unsupported explicit cloud resource.'; done
    for value in "${ENDPOINTS[@]}"; do parse_url "$value"; SEEDS+=("$URL_HOST"); done
    (( ${#ENDPOINTS[@]} <= MAX_ASSETS && ${#CLOUDS[@]} <= MAX_ASSETS )) || fatal 'Too many explicitly configured endpoints/resources.'
    SCOPE_HASH=$(hash "$(printf '%s\n' "org=$ORG" "${ROOTS[@]/#/tree=}" "${HOSTS[@]/#/host=}" "${CIDRS[@]/#/cidr=}" "${EXCLUDES[@]/#/exclude=}" "${EXCLUDE_TREES[@]/#/exclude_tree=}" "${EXCLUDE_CIDRS[@]/#/exclude_cidr=}" "${ALIASES[@]/#/alias=}" "${ENDPOINTS[@]/#/endpoint=}" "${CLOUDS[@]/#/cloud=}" | sort)")
    local severity_policy
    severity_policy=$(for value in "${!SEVERITY_OVERRIDES[@]}"; do printf '%s=%s\n' "$value" "${SEVERITY_OVERRIDES[$value]}"; done | sort)
    POLICY_HASH=$(hash "$severity_policy|${CRITICAL_ENDPOINTS[*]}|$CONFIG_VERSION|$ALLOW_NONPUBLIC|$ALLOW_PUBLIC_DNS|$MODE|$HTTP_CHECKS|$CLOUD_CHECKS|$TLS_CRITICAL_DAYS|$BODY_PREVIEW|$FOLLOW_REDIRECTS|$CLOUD_LISTING|$CA_FILE")
}
