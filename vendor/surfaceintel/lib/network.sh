# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
# The only HTTP transport. No proxy, .curlrc, redirects, retries or cookies are inherited.
request() {
    local url=$1 role=$2 method=${3:-HEAD} query=${4:-} host port scheme ip address config rc=0
    local resource=$url
    HTTP_CODE=000; HTTP_RC=0; HTTP_LOCATION=''; HTTP_REASON=''; HTTP_HEADERS=''; HTTP_BODY=''
    parse_url "$url" || { HTTP_REASON=INVALID_URL; return 1; }
    host=$URL_HOST; port=$URL_PORT; scheme=$URL_SCHEME
    role_scope "$host" "$role" "$resource" || { HTTP_REASON=OUT_OF_SCOPE; return 1; }
    resolve_destination "$host" "$role" "$resource" || { HTTP_REASON=$DEST_REASON; return 1; }
    ip=$PINNED_IP; address=$ip; [[ $ip != *:* ]] || address="[$ip]"
    budget || { HTTP_REASON=BUDGET_EXCEEDED; return 1; }
    ((REQUEST_SEQ+=1)); config="$WORK/curl-$REQUEST_SEQ.conf"
    HTTP_HEADERS="$WORK/headers-$REQUEST_SEQ"; HTTP_BODY="$WORK/body-$REQUEST_SEQ"
    # query is constructed internally, never taken from an arbitrary asset URL.
    printf 'url = "%s%s"\n' "$url" "$query" > "$config"
    local -a args=(-q --globoff --config "$config" --silent --show-error --noproxy '*' --proxy '' --proto '=http,https' --proto-redir '=http,https' --connect-timeout "$REQ_TIMEOUT" --max-time "$REQ_TIMEOUT" --max-filesize 65536 --max-redirs 0 --dump-header "$HTTP_HEADERS" --output "$HTTP_BODY" --write-out $'%{http_code}\n%{remote_ip}' --user-agent 'SurfaceIntel/1.0 authorized-metadata-audit')
    if ! ip_expand "$host"; then args+=(--resolve "$host:$port:$address"); fi
    [[ $method != HEAD ]] || args+=(--head)
    [[ -z $CA_FILE || $scheme != https ]] || args+=(--cacert "$CA_FILE")
    rate_wait http
    (unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR; ulimit -f 64; curl "${args[@]}" > "$WORK/code-$REQUEST_SEQ" 2>/dev/null) || rc=$?
    HTTP_CODE=$(head -n 1 "$WORK/code-$REQUEST_SEQ" 2>/dev/null); [[ $HTTP_CODE =~ ^[0-9]{3}$ ]] || HTTP_CODE=000
    HTTP_RC=$rc
    if ((rc!=0)); then HTTP_REASON=REQUEST_FAILED; [[ $rc != 60 ]] || HTTP_REASON=TLS_VALIDATION_FAILED; return 1; fi
    HTTP_REMOTE_IP=$(tail -n 1 "$WORK/code-$REQUEST_SEQ")
    ip_expand "$ip" || return 1; local expected_bits=$IP_BITS
    ip_expand "$HTTP_REMOTE_IP" && [[ $IP_BITS == "$expected_bits" ]] || { HTTP_REASON=PIN_MISMATCH; return 1; }
    HTTP_LOCATION=$(header location)
    HTTP_REASON=RESPONSE_RECEIVED
}
header() {
    local name=$1
    [[ -n $HTTP_HEADERS && -f $HTTP_HEADERS ]] || return 0
    awk -v wanted="$name" 'BEGIN{IGNORECASE=0} {gsub(/\r/,"");p=index($0,":");if(p>0 && tolower(substr($0,1,p-1))==wanted){v=substr($0,p+1);sub(/^[ \t]+/,"",v);result=v}} END{print result}' "$HTTP_HEADERS" | LC_ALL=C tr -cd '\040-\176\n' | head -c 1200
}
redirect_target() {
    local base=$1 location=$2
    REDIRECT_URL=''; REDIRECT_STATUS=UNSUPPORTED_OR_REDACTED
    # Queries/fragments/userinfo may contain tokens: do not log them or follow them.
    [[ $location != *[?#@\\]* ]] || return 1
    if [[ $location == /* && $location != //* ]]; then
        parse_url "$base" || return 1; REDIRECT_URL="$URL_ORIGIN$location"
    else REDIRECT_URL=$location; fi
    parse_url "$REDIRECT_URL" || { REDIRECT_URL=''; return 1; }
    if ! url_scope "$REDIRECT_URL"; then REDIRECT_STATUS=OUT_OF_SCOPE; return 1; fi
    if ! contains "$REDIRECT_URL" "${ENDPOINTS[@]}"; then REDIRECT_STATUS=PATH_NOT_APPROVED; return 1; fi
    REDIRECT_STATUS=APPROVED_NOT_FOLLOWED
}
