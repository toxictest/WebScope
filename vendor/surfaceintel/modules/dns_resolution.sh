# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
dns_query() {
    local host=$1 type=$2 role=${3:-asset} resource=${4:-} rc=0 line name ttl cls rr value
    DNS_STATUS=UNAVAILABLE; DNS_VALUES=''; DNS_TTLS=''; DNS_ALIASES=''; DNS_SOURCE=none
    role_scope "$host" "$role" "$resource" || { DNS_STATUS=OUT_OF_SCOPE; return 1; }
    budget || { DNS_STATUS=BUDGET_EXCEEDED; return 1; }
    rate_wait dns
    ((REQUEST_SEQ+=1)); local raw="$WORK/dns-$REQUEST_SEQ"
    local -a server=(); [[ $RESOLVER == system ]] || server=("@$RESOLVER")
    if command -v dig >/dev/null 2>&1; then
        DNS_SOURCE=dig
        (ulimit -f 128; dig -r +nosearch "${server[@]}" "+time=$REQ_TIMEOUT" +tries=1 +noall +answer +comments "$host" "$type" > "$raw" 2>/dev/null) || rc=$?
        ((rc==0)) || { DNS_STATUS=TEMPORARY_FAILURE; return 1; }
        if grep -q 'status: NXDOMAIN' "$raw"; then DNS_STATUS=NXDOMAIN; return 0; fi
        grep -q 'status: NOERROR' "$raw" || { DNS_STATUS=TEMPORARY_FAILURE; return 1; }
        while IFS= read -r line; do
            [[ -n $line && $line != \;* ]] || continue
            read -r name ttl cls rr value <<< "$line"
            [[ $cls == IN && $ttl =~ ^[0-9]+$ ]] || continue
            case $rr in CNAME|NS|MX|AAAA) value=${value,,};; esac
            if [[ $rr == CNAME ]]; then DNS_ALIASES+="${value%.}"$'\n'; fi
            [[ $rr == "$type" ]] || continue
            if [[ $type == TXT ]]; then value="sha256:$(hash "$value")"; else value=${value%.}; fi
            DNS_VALUES+="$value"$'\n'; DNS_TTLS+="$type:$ttl"$'\n'
        done < "$raw"
        DNS_STATUS=NODATA; [[ -z $DNS_VALUES ]] || DNS_STATUS=ANSWER
    elif command -v host >/dev/null 2>&1 && [[ $type == A || $type == AAAA ]] && [[ $RESOLVER == system ]]; then
        DNS_SOURCE=host
        (ulimit -f 128; host -W "$REQ_TIMEOUT" -R 1 -t "$type" "$host." > "$raw" 2>/dev/null) || rc=$?
        if grep -q NXDOMAIN "$raw"; then DNS_STATUS=NXDOMAIN; return 0; fi
        ((rc==0)) || { DNS_STATUS=TEMPORARY_FAILURE; return 1; }
        DNS_VALUES=$(awk '/ has address /{print $NF}/ has IPv6 address /{print $NF}' "$raw")
        DNS_ALIASES=$(awk '/ is an alias for /{sub(/\.$/,"",$NF);print $NF}' "$raw")
        DNS_STATUS=NODATA; [[ -z $DNS_VALUES ]] || DNS_STATUS=ANSWER
    else return 1; fi
    DNS_VALUES=$(printf '%s\n' "$DNS_VALUES" | sed '/^$/d' | sort -u)
    DNS_TTLS=$(printf '%s\n' "$DNS_TTLS" | sed '/^$/d' | sort -u)
    DNS_ALIASES=$(printf '%s\n' "$DNS_ALIASES" | sed '/^$/d' | sort -u)
}
resolve_destination() {
    local host=$1 role=$2 resource=${3:-} type ip alias all='' failed=false literal=false
    PINNED_IP=''; DEST_REASON=''
    role_scope "$host" "$role" "$resource" || { DEST_REASON=OUT_OF_SCOPE; return 1; }
    if ip_expand "$host"; then all=$host; literal=true
    else
        for type in A AAAA; do
            if ! dns_query "$host" "$type" "$role" "$resource"; then failed=true; fi
            [[ $DNS_STATUS != NXDOMAIN ]] || failed=true
            if [[ -n $DNS_VALUES ]]; then all+="$DNS_VALUES"$'\n'; fi
            if [[ $role == asset ]]; then
                while IFS= read -r alias; do
                    [[ -n $alias ]] || continue
                    host_scope "$alias" || contains "$alias" "${ALIASES[@]}" || { DEST_REASON=UNAPPROVED_CNAME; return 1; }
                done <<< "$DNS_ALIASES"
            fi
        done
    fi
    [[ $failed == false ]] || { DEST_REASON=DNS_INCOMPLETE; return 1; }
    while IFS= read -r ip; do
        [[ -n $ip ]] || continue
        ip_allowed "$ip" "$literal" || { DEST_REASON=DESTINATION_NOT_AUTHORIZED; return 1; }
        [[ -n $PINNED_IP ]] || PINNED_IP=$ip
    done < <(printf '%s\n' "$all" | sed '/^$/d' | awk '!seen[$0]++')
    [[ -n $PINNED_IP ]] || { DEST_REASON=UNRESOLVED; return 1; }
}
dns_inventory() {
    local host type normalized detail addresses cnames status failed qstatus ttl source
    while IFS= read -r host; do
        host_scope "$host" || continue
        if ip_expand "$host"; then record dns "$host" RESOLVED INFO "$host" 'source=explicit-IP;TTL=not-applicable'; continue; fi
        normalized=''; detail=''; addresses=''; cnames=''; failed=false; status=NODATA
        for type in A AAAA CNAME MX NS TXT; do
            if ! dns_query "$host" "$type"; then failed=true; fi
            qstatus=$DNS_STATUS; ttl=$(printf '%s' "$DNS_TTLS" | tr '\n' ','); source=$DNS_SOURCE
            normalized+="$type:$qstatus:$DNS_VALUES;"
            detail+="$type=$DNS_VALUES;status=$qstatus;ttl=$ttl;source=$source;"
            if [[ $type == A || $type == AAAA ]]; then addresses+=$DNS_VALUES; fi
            [[ $type != CNAME ]] || cnames=$DNS_VALUES
            [[ $qstatus != NXDOMAIN ]] || status=NXDOMAIN
        done
        if [[ $failed == true ]]; then status=COLLECTION_FAILED; issue dns "$host" 'One or more DNS record types could not be collected.'
        elif [[ -n $addresses ]]; then status=RESOLVED; fi
        if (( ${#detail}>1100 )); then issue dns "$host" "DNS evidence display bound exceeded; complete record set not exported."; status=EVIDENCE_TRUNCATED; detail="truncated=true;$detail"; fi
        record dns "$host" "$status" INFO "$normalized" "$detail"
        if [[ -n $cnames && -z $addresses && $failed == false ]]; then finding POSSIBLE_DANGLING_DNS "$host" MEDIUM LOW 'CNAME observed without A/AAAA answers; target not probed or claimed takeable.' 'Review authoritative DNS, provider ownership and intended service lifecycle.'; fi
    done < "$WORK/assets.txt"
}
