# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
drift_detection() {
    local line kind id asset status fp sev first last detail old oldfp oldsev oldstatus event oldkind oldasset oldid current related found
    : > "$WORK/events.tsv"
    while IFS= read -r line; do
        IFS=$'\t' read -r kind id asset status fp sev first last detail <<< "$line"
        old=${OLD_ROWS[$id]-}; event=UNCHANGED
        if [[ -z $old ]]; then
            if [[ $kind == finding ]]; then event=NEW_FINDING; elif [[ $kind == asset ]]; then event=NEW_ASSET; else event=NEW_OBSERVATION; fi
        else
            oldfp=$(printf '%s' "$old" | cut -f5); oldsev=$(printf '%s' "$old" | cut -f6); oldstatus=$(printf '%s' "$old" | cut -f4)
            if [[ $oldfp != "$fp" ]]; then
                event=EVIDENCE_CHANGED
                [[ $oldsev == "$sev" ]] || event=SEVERITY_CHANGED
                case $status in COLLECTION_FAILED|CONNECT_FAILED|REQUEST_FAILED|UNAVAILABLE|DNS_INCOMPLETE|BUDGET_EXCEEDED) event=NEWLY_UNAVAILABLE;; esac
                if [[ $kind == dns && $oldstatus == RESOLVED && $status == NXDOMAIN ]]; then event=NEWLY_UNRESOLVED; fi
                if [[ $kind == dns && $oldstatus != RESOLVED && $status == RESOLVED ]]; then event=NEWLY_RESOLVING; fi
            elif [[ $kind == finding ]]; then event=KNOWN_FINDING; fi
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$event" "$id" "$kind" "$asset" "$sev" >> "$WORK/events.tsv"
    done < "$WORK/records.tsv"
    for oldid in "${!OLD_ROWS[@]}"; do
        [[ -z ${CURRENT_IDS[$oldid]-} ]] || continue
        old=${OLD_ROWS[$oldid]}; IFS=$'\t' read -r oldkind id oldasset oldstatus oldfp oldsev _ <<< "$old"
        event=NOT_OBSERVED
        if [[ $oldkind == asset ]] && ! host_scope "$oldasset"; then event=SCOPE_REMOVED; fi
        if [[ $oldkind == finding && $PARTIAL == 0 && $OLD_SCOPE == "$SCOPE_HASH" && $OLD_MODE == "$MODE-$HTTP_CHECKS-$CLOUD_CHECKS" ]]; then
            related=${oldasset#*|}; found=false
            while IFS=$'\t' read -r kind id asset status _; do
                [[ $asset == "$related" ]] || continue
                case "$oldasset|$kind|$status" in
                    PUBLIC_CLOUD_ACCESS\|*\|cloud\|ACCESS_DENIED|PUBLIC_CLOUD_ACCESS\|*\|cloud\|AUTH_REQUIRED|PUBLIC_CLOUD_ACCESS\|*\|cloud\|NOT_FOUND) found=true;;
                    CERTIFICATE_LIFECYCLE\|*\|tls\|VALID|TLS_VALIDATION_FAILURE\|*\|tls\|VALID|TLS_NOT_YET_VALID\|*\|tls\|VALID) found=true;;
                    POSSIBLE_DANGLING_DNS\|*\|dns\|RESOLVED) found=true;;
                esac
            done < "$WORK/records.tsv"
            [[ $found != true ]] || event=RESOLVED
        fi
        printf '%s\t%s\t%s\t%s\t%s\n' "$event" "$oldid" "$oldkind" "$oldasset" "$oldsev" >> "$WORK/events.tsv"
    done
}
