# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
records_json() {
    local selection=$1 kind id asset status fp severity first last detail scope_status output_asset category confidence remediation event asset_id comma=''
    printf '['
    while IFS=$'\t' read -r kind id asset status fp severity first last detail; do
        if [[ $selection == findings ]]; then [[ $kind == finding ]] || continue; else [[ $kind != finding ]] || continue; fi
        output_asset=$asset; category=''
        if [[ $kind == finding ]]; then output_asset=${asset#*|}; category=${asset%%|*}; fi
        asset_id=$(hash "$output_asset")
        printf '%s{' "$comma"; comma=','
        printf '"kind":'; json_string "$kind"; printf ',"id":'; json_string "$id"
        printf ',"asset":'; json_string "$output_asset"; printf ',"asset_id":'; json_string "$asset_id"; printf ',"status":'; json_string "$status"
        printf ',"fingerprint":'; json_string "$fp"; printf ',"severity":'; json_string "$severity"
        scope_status=VALIDATED
        if [[ $kind == asset || $kind == dns ]]; then scope_status=AUTHORIZED_NAME; fi
        case $status in OUT_OF_SCOPE|DESTINATION_NOT_AUTHORIZED|UNAPPROVED_CNAME|PIN_MISMATCH) scope_status=BLOCKED;; COLLECTION_FAILED|DNS_INCOMPLETE|UNAVAILABLE) scope_status=INCOMPLETE;; esac
        printf ',"first_seen":%s,"last_seen":%s,"scope_validation":' "$first" "$last"; json_string "$scope_status"; printf ',"evidence":'; json_string "$detail"
        if [[ $kind == finding ]]; then
            confidence=${detail#confidence=}; confidence=${confidence%%;*}
            remediation=${detail#*;remediation=}; remediation=${remediation%;policy=*}
            event=$(awk -F '\t' -v id="$id" '$2==id{print $1;exit}' "$WORK/events.tsv")
            printf ',"category":'; json_string "$category"; printf ',"confidence":'; json_string "$confidence"
            printf ',"verification_method":'; json_string "$category"; printf ',"baseline_change":'; json_string "${event:-UNASSESSED}"
            printf ',"remediation":'; json_string "$remediation"; printf ',"policy_reference":'; json_string "$CONFIG_VERSION"
        fi
        printf '}'
    done < "$WORK/records.tsv"
    printf ']'
}
reporting() {
    local assets findings errors added removed changed resolved severity count path header marker version org scope policy completion stamp mode end scans=0 completed=0 partial=0 cutoff=$((NOW-604800))
    assets=$(awk -F '\t' '$1!="finding" && !seen[$3]++{n++}END{print n+0}' "$WORK/records.tsv")
    findings=$(awk -F '\t' '$1=="finding"{n++}END{print n+0}' "$WORK/records.tsv")
    errors=$(wc -l < "$WORK/errors.tsv")
    added=$(awk -F '\t' '$1=="NEW_ASSET"{n++}END{print n+0}' "$WORK/events.tsv")
    removed=$(awk -F '\t' '$1=="SCOPE_REMOVED"{n++}END{print n+0}' "$WORK/events.tsv")
    changed=$(awk -F '\t' '$3=="dns" && $1!="UNCHANGED" && $1!="NEW_OBSERVATION"{n++}END{print n+0}' "$WORK/events.tsv")
    resolved=$(awk -F '\t' '$1=="RESOLVED"{n++}END{print n+0}' "$WORK/events.tsv")
    cp -- "$WORK/rejected.tsv" "$RUN/rejected-candidates.tsv"
    cp -- "$WORK/events.tsv" "$RUN/delta.tsv"; cp -- "$WORK/provenance.tsv" "$RUN/provenance.tsv"; cp -- "$WORK/errors.tsv" "$RUN/errors.tsv"; cp -- "$WORK/delivery.tsv" "$RUN/alert-delivery.tsv"
    {
        printf 'SurfaceIntel %s — %s\nRun: %s | Completion: %s | Mode: %s\n' "$VERSION" "$ORG" "$STAMP" "$COMPLETION" "$MODE-$HTTP_CHECKS-$CLOUD_CHECKS"
        printf 'Assets: %s | Findings: %s | Coverage errors/skips: %s\nAdded candidates: %s | Removed from scope: %s | DNS deltas: %s | Resolved observations: %s\n' "$assets" "$findings" "$errors" "$added" "$removed" "$changed" "$resolved"
        printf 'Policy version: %s\n' "$CONFIG_VERSION"
        printf 'Scope hash: %s\nPolicy hash: %s\nPrevious baseline scope: %s\nConcurrency ceiling: %s; actual engine concurrency: 1 (serial safety mode)\n' "$SCOPE_HASH" "$POLICY_HASH" "${OLD_SCOPE:-none}" "$CONCURRENCY"
        for severity in CRITICAL HIGH MEDIUM LOW INFO; do count=$(awk -F '\t' -v s="$severity" '$1=="finding"&&$6==s{n++}END{print n+0}' "$WORK/records.tsv"); printf '%s findings: %s\n' "$severity" "$count"; done
        printf '\nTLS EXPIRY CATEGORIES\n'; awk -F '\t' '$1=="tls" {n=split($9,a,";");for(i=1;i<=n;i++)if(a[i]~/^expiry_category=/)c[a[i]]++}END{for(k in c)print k,c[k]}' "$WORK/records.tsv" | sort
        printf '\nCLOUD ACCESS CATEGORIES\n'; awk -F '\t' '$1=="cloud"{c[$4]++}END{for(k in c)print k,c[k]}' "$WORK/records.tsv" | sort
        printf '\nREJECTED CANDIDATES (NOT PROBED)\n'; cat "$WORK/rejected.tsv"
        printf '\nOBSERVATIONS\n'; cat "$WORK/records.tsv"
        printf '\nDELTA\n'; cat "$WORK/events.tsv"
        printf '\nCOVERAGE ERRORS / SKIPS\n'; cat "$WORK/errors.tsv"
        printf '\nALERT DELIVERY\n'; cat "$WORK/delivery.tsv"
        printf '\nLIMITATIONS\nNo exploitation, credential guessing or authentication bypass. HTTP success/login pages are not unauthenticated-admin proof. Cloud object bytes are never fetched; object-read findings are provider HEAD-permission evidence. Names absent from discovery are not automatically removed. DNS/anycast/CDN changes are not intrinsically malicious. Only one validated address per endpoint is connected; all returned addresses must pass policy. Reports are scoped observations, not a guarantee of security.\n'
    } > "$RUN/summary.txt"
    {
        printf 'SurfaceIntel daily delta — %s — %s\nCompletion: %s\n' "$ORG" "$STAMP" "$COMPLETION"
        printf 'Added candidates=%s, scope removals=%s, DNS changes=%s, confirmed observation resolutions=%s\n' "$added" "$removed" "$changed" "$resolved"
        cat "$WORK/events.tsv"
    } > "$RUN/daily-delta.txt"
    : > "$WORK/weekly-events.tsv"
    while IFS= read -r path; do
        text_file "$path" 8388608 || continue
        IFS= read -r header < "$path"; IFS=$'\t' read -r marker version org scope policy completion stamp mode end <<< "$header"
        [[ $marker == SURFACEINTEL_STATE && $version == 1 && $org == "$ORG" && $completion =~ ^(complete|partial|interrupted)$ && $stamp =~ ^[0-9]{10,12}$ && $end == END ]] || continue
        ((stamp>=cutoff)) || continue
        local eventfile
        eventfile="$(dirname "$path")/delta.tsv"
        if text_file "$eventfile"; then awk -F '\t' 'NF==5 && $1~/^(NEW_ASSET|NEW_FINDING|EVIDENCE_CHANGED|RESOLVED|SCOPE_REMOVED|NEWLY_UNRESOLVED)$/ {print $1 "\t" $2 "\t" $3}' "$eventfile" >> "$WORK/weekly-events.tsv"; fi
        ((scans+=1)); if [[ $completion == complete ]]; then ((completed+=1)); else ((partial+=1)); fi
    done < <(find "$CUSTOMER" -mindepth 2 -maxdepth 2 -name state.tsv -type f | sort | tail -n 366)
    {
        printf 'SurfaceIntel weekly management report — %s\nWindow: last 7 days through %s\nRuns: %s | Complete: %s | Partial/interrupted: %s\n' "$ORG" "$STAMP" "$scans" "$completed" "$partial"
        printf 'Latest snapshot: %s assets, %s open findings, %s coverage errors.\nLatest-run delta: %s new candidates, %s scope removals, %s DNS changes, %s resolved observations.\n' "$assets" "$findings" "$errors" "$added" "$removed" "$changed" "$resolved"
        printf '\nDistinct event IDs observed in the 7-day retained history (by event kind):\n'; sort -u "$WORK/weekly-events.tsv" | awk -F '\t' '{c[$1]++}END{for(k in c)print k,c[k]}' | sort
        printf 'Management priorities: review high/critical evidence, certificate renewals, authorized publication, DNS changes and unavailable coverage. Historical runs with different scope/policy/modes are not assumed comparable. This is a latest-snapshot + run-health summary, not a claim that all assets were observed every day.\n'
    } > "$RUN/weekly-management.txt"
    if [[ $REPORT == json || $REPORT == all ]]; then
        { printf '{"schema_version":"1","tool":"SurfaceIntel","tool_version":'; json_string "$VERSION"; printf ',"organization":'; json_string "$ORG"; printf ',"config_version":'; json_string "$CONFIG_VERSION"; printf ',"completion":'; json_string "$COMPLETION"; printf ',"scope_hash":'; json_string "$SCOPE_HASH"; printf ',"policy_hash":'; json_string "$POLICY_HASH"; printf ',"collected_at":%s,"assets":' "$NOW"; records_json inventory; printf '}\n'; } > "$RUN/inventory.json"
        { printf '{"schema_version":"1","tool":"SurfaceIntel","tool_version":'; json_string "$VERSION"; printf ',"organization":'; json_string "$ORG"; printf ',"findings":'; records_json findings; printf '}\n'; } > "$RUN/findings.json"
        if command -v jq >/dev/null 2>&1; then jq -e . "$RUN/inventory.json" "$RUN/findings.json" >/dev/null || fatal 'Generated JSON validation failed.'; fi
    fi
    if [[ $REPORT == html || $REPORT == all ]]; then
        {
            printf '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SurfaceIntel report</title><style>body{font:15px system-ui;background:#eef3f9;color:#17283d;margin:32px auto;padding:0 24px;max-width:1200px}header{background:#122a46;color:white;padding:28px;border-radius:12px}pre{background:white;padding:24px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.55;border-radius:10px}</style><header><h1>SurfaceIntel</h1><p>Authorized external surface · evidence and change monitoring</p></header><pre>'
            html_escape "$(cat "$RUN/summary.txt")"; printf '</pre><h2>Weekly management</h2><pre>'; html_escape "$(cat "$RUN/weekly-management.txt")"; printf '</pre></html>\n'
        } > "$RUN/summary.html"
    fi
}
