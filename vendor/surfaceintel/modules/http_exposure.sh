# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
http_one() {
    local original=$1 url=$1 hops=0 method=HEAD status server jenkins grafana title='' bodyhash='' redirect='' redirect_url='' location code tls detail content_type auth_scheme hsts
    [[ $BODY_PREVIEW != true ]] || method=GET
    while :; do
        url_scope "$url" || { issue http "$original" 'Scope validation rejected endpoint.'; record http "$original" OUT_OF_SCOPE INFO blocked 'Request not sent.'; return; }
        if ! request "$url" asset "$method"; then
            issue http "$original" "$HTTP_REASON"
            record http "$original" "$HTTP_REASON" INFO "$HTTP_REASON" "No HTTP conclusion;reason=$HTTP_REASON;curl_exit=$HTTP_RC"
            return
        fi
        code=$HTTP_CODE; location=$HTTP_LOCATION; status=REACHABLE
        server=$(header server | cut -c1-120); jenkins=$(header x-jenkins); grafana=$(header x-grafana-version)
        content_type=$(clean "$(header content-type)" | cut -c1-120); auth_scheme=$(header www-authenticate | awk '{print $1}'); case $auth_scheme in Basic|Bearer|Digest|Negotiate|NTLM|'') :;; *) auth_scheme=OTHER;; esac; hsts=false; [[ -z $(header strict-transport-security) ]] || hsts=true
        tls=NOT_APPLICABLE; [[ $url != https:* ]] || tls=VALIDATED
        if [[ $code == 401 || $code == 403 ]]; then status=AUTH_REQUIRED_OR_DENIED; fi
        if [[ -n $location ]]; then
            redirect_target "$url" "$location" || :
            redirect=$REDIRECT_STATUS
            if [[ -n $REDIRECT_URL ]] && parse_url "$REDIRECT_URL"; then redirect_url=$URL_ORIGIN; fi
            if [[ $FOLLOW_REDIRECTS == true && $REDIRECT_STATUS == APPROVED_NOT_FOLLOWED && $hops -lt 3 ]]; then
                redirect=FOLLOWED_APPROVED; url=$REDIRECT_URL; ((hops+=1)); continue
            fi
            [[ $REDIRECT_STATUS != OUT_OF_SCOPE ]] || finding OUT_OF_SCOPE_REDIRECT "$original" LOW HIGH 'Redirect observed but not followed; destination is not approved.' 'Review expected SSO/CDN routing and approve only intended destinations.'
        fi
        if [[ $method == GET && -s $HTTP_BODY ]]; then
            title=$(LC_ALL=C tr '\n\r' '  ' < "$HTTP_BODY" | sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\([^<]*\)<\/[Tt][Ii][Tt][Ll][Ee]>.*/\1/p' | head -c 120)
            title=$(printf '%s' "$title" | LC_ALL=C tr -cd '\040-\176')
            # Fingerprint only the sanitized title, not arbitrary customer content.
            bodyhash=$(hash "$title")
        fi
        detail="code=$code;server=$(clean "$server");content_type=$content_type;auth_scheme=${auth_scheme:-none};hsts_present=$hsts;tls=$tls;redirect=${redirect:-none};redirect_destination_origin=${redirect_url:-omitted};title=$(clean "$title");title_fingerprint=${bodyhash:-none};address=$PINNED_IP;method=$method;hops=$hops;auth_bypass_attempted=false"
        record http "$original" "$status" INFO "$code|$server|$content_type|$auth_scheme|$hsts|$jenkins|$grafana|$bodyhash|$redirect|$redirect_url" "$detail"
        parse_url "$original"
        if [[ $code =~ ^2[0-9][0-9]$ ]]; then
            if [[ -n $jenkins || -n $grafana ]]; then
                finding MANAGEMENT_INTERFACE_POTENTIAL "$original" HIGH MEDIUM 'Management-product header on a reachable endpoint; authentication/privileges NOT verified.' 'Restrict exposure and manually validate authentication using approved non-sensitive methods.'
            elif [[ $URL_PATH =~ /(admin|jenkins|grafana|phpmyadmin|swagger|api-docs|debug|actuator|manage)(/|\.|$) ]]; then
                finding ADMIN_ROUTE_POTENTIAL "$original" MEDIUM LOW 'Approved management-like path returned success; route name/HTTP 200 alone does not prove a dashboard or unauthenticated access.' 'Validate purpose, access controls and intended publication.'
            fi
            if [[ $URL_HOST =~ ^(dev|staging|uat|qa|test)([.-]|$) ]]; then finding NONPRODUCTION_INTERFACE "$original" MEDIUM MEDIUM 'Explicitly configured development/staging-style hostname is reachable.' 'Confirm whether public access is approved and protect nonproduction interfaces.'; fi
        fi
        return
    done
}
http_exposure() { local url; for url in "${ENDPOINTS[@]}"; do http_one "$url"; done; }
