# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
tls_bucket() {
    local seconds=$1
    TLS_BUCKET=VALID
    if ((seconds<0)); then TLS_BUCKET=EXPIRED
    elif ((seconds<=86400)); then TLS_BUCKET=WITHIN_1_DAY
    elif ((seconds<=604800)); then TLS_BUCKET=WITHIN_7_DAYS
    elif ((seconds<=1296000)); then TLS_BUCKET=WITHIN_15_DAYS
    elif ((seconds<=2592000)); then TLS_BUCKET=WITHIN_30_DAYS; fi
}
tls_one() {
    local url=$1 host port address raw pem rc=0 cert_hash notbefore notafter start end remaining days subject issuer sans verify mismatch severity status
    url_scope "$url" || { issue tls "$url" 'Endpoint rejected by scope.'; return; }
    host=$URL_HOST; port=$URL_PORT
    if ! command -v openssl >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then
        issue tls "$url" 'Bounded TLS inspection requires optional openssl and timeout.'
        record tls "$url" UNAVAILABLE INFO unavailable 'Optional inspection dependency unavailable; no validity conclusion.'; return
    fi
    if ! resolve_destination "$host" asset "$url"; then
        issue tls "$url" "$DEST_REASON"; record tls "$url" COLLECTION_FAILED INFO "$DEST_REASON" 'No TLS conclusion; destination validation/resolution failed.'; return
    fi
    budget || { issue tls "$url" 'Global budget exceeded.'; return; }
    address=$PINNED_IP; [[ $address != *:* ]] || address="[$address]"
    ((REQUEST_SEQ+=1)); raw="$WORK/tls-$REQUEST_SEQ"; pem="$WORK/cert-$REQUEST_SEQ.pem"
    local -a args=(s_client -connect "$address:$port" -showcerts)
    if ip_expand "$host"; then args+=(-verify_ip "$host"); else args+=(-servername "$host" -verify_hostname "$host"); fi
    [[ -z $CA_FILE ]] || args+=(-CAfile "$CA_FILE")
    rate_wait http
    (unset SSL_CERT_FILE SSL_CERT_DIR; ulimit -f 128; timeout --kill-after=1 "$REQ_TIMEOUT" openssl "${args[@]}" < /dev/null > "$raw" 2>&1) || rc=$?
    awk '/-----BEGIN CERTIFICATE-----/{printing=1} printing{print} /-----END CERTIFICATE-----/{exit}' "$raw" > "$pem"
    if [[ ! -s $pem ]] || ! openssl x509 -in "$pem" -noout >/dev/null 2>&1; then
        issue tls "$url" 'TLS connection/certificate collection failed.'
        record tls "$url" CONNECT_FAILED INFO "$rc" "certificate_unavailable=true;process_exit=$rc;not_a_certificate_validation_verdict=true"; return
    fi
    if ((rc==124 || rc==137)); then issue tls "$url" 'TLS handshake deadline exceeded; collected certificate is partial evidence.'; fi
    cert_hash=$(openssl x509 -in "$pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d :)
    notbefore=$(openssl x509 -in "$pem" -noout -startdate 2>/dev/null); notbefore=${notbefore#*=}
    notafter=$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null); notafter=${notafter#*=}
    if ! start=$(date -u -d "$notbefore" +%s 2>/dev/null) || ! end=$(date -u -d "$notafter" +%s 2>/dev/null); then
        issue tls "$url" 'Certificate dates could not be parsed.'; record tls "$url" COLLECTION_FAILED INFO dates 'Certificate date parsing unavailable.'; return
    fi
    remaining=$((end-NOW)); days=$((remaining/86400)); if ((remaining<0)); then days=$((-((-remaining+86399)/86400))); fi; tls_bucket "$remaining"
    verify=$(sed -n 's/.*Verify return code: \([0-9][0-9]*\).*/\1/p' "$raw" | tail -n 1)
    mismatch=false; [[ $verify != 62 && $verify != 64 ]] || mismatch=true
    subject=$(openssl x509 -in "$pem" -noout -subject -nameopt RFC2253 2>/dev/null)
    issuer=$(openssl x509 -in "$pem" -noout -issuer -nameopt RFC2253 2>/dev/null)
    sans=$(openssl x509 -in "$pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr '\n' ' ' | head -c 800)
    status=$TLS_BUCKET; severity=INFO
    local trust_severity=HIGH
    contains "$url" "${CRITICAL_ENDPOINTS[@]}" && trust_severity=CRITICAL
    if [[ -z $verify ]]; then status=VERIFICATION_UNAVAILABLE; issue tls "$url" "Chain validation result unavailable."
    elif [[ $verify != 0 ]]; then status=VALIDATION_FAILED; finding TLS_VALIDATION_FAILURE "$url" "$trust_severity" HIGH "verify_code=${verify:-unknown};hostname_mismatch=$mismatch;cert=$cert_hash" 'Review hostname coverage, trust chain and certificate validity; do not disable verification.'; fi
    if ((start>NOW)); then status=NOT_YET_VALID; finding TLS_NOT_YET_VALID "$url" HIGH HIGH "cert=$cert_hash;not_before=$notbefore" 'Review deployment timing, clock synchronization and certificate issuance.'; fi
    if ((remaining<=TLS_CRITICAL_DAYS*86400)); then severity=CRITICAL
    elif ((remaining<=2592000)); then severity=MEDIUM; fi
    record tls "$url" "$status" "$severity" "$cert_hash|$TLS_BUCKET|$verify|$mismatch|$start" "not_before=$notbefore;not_after=$notafter;remaining_days=$days;expiry_category=$TLS_BUCKET;chain_verify_code=${verify:-unknown};hostname_mismatch=$mismatch;certificate_sha256=$cert_hash;subject=$(clean "$subject" | cut -c1-180);issuer=$(clean "$issuer" | cut -c1-180);SAN_preview=$(clean "$sans" | cut -c1-350)"
    if [[ $severity != INFO ]]; then finding CERTIFICATE_LIFECYCLE "$url" "$severity" HIGH "certificate=$cert_hash;expiry_category=$TLS_BUCKET;not_after=$notafter" 'Renew and deploy the complete validated certificate chain before expiry; confirm service ownership.'; fi
}
tls_monitor() { local url; for url in "${ENDPOINTS[@]}"; do [[ $url != https:* ]] || tls_one "$url"; done; }
