# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
candidate() {
    local name=$1 source=$2
    if host_scope "$name"; then
        printf '%s\n' "$name" >> "$WORK/candidates.txt"
        printf '%s\t%s\t%s\n' "$name" "$source" "$NOW" >> "$WORK/provenance.tsv"
    else
        printf '%s\t%s\tOUT_OF_SCOPE\n' "$(clean "$name")" "$source" >> "$WORK/rejected.tsv"
    fi
}
passive_discovery() {
    local value file line row kind id asset root name
    : > "$WORK/candidates.txt"
    for value in "${SEEDS[@]}"; do candidate "$value" configured; done
    for file in "${ASSET_FILES[@]}"; do
        text_file "$file" || fatal 'Asset list unavailable or invalid.'
        while IFS= read -r line || [[ -n $line ]]; do
            [[ -z $line || $line == \#* ]] && continue
            host_valid "$line" || ip_expand "$line" || fatal 'Malformed asset list entry.'
            candidate "$line" "imported:$(basename "$file")"
        done < "$file"
    done
    # Historical candidates remain monitored; source outages cannot silently delete assets.
    for row in "${OLD_ROWS[@]}"; do
        IFS=$'\t' read -r kind id asset _ <<< "$row"
        [[ $kind != asset ]] || candidate "$asset" baseline
    done
    if [[ $CT_ENABLED == true ]]; then
        if ! command -v jq >/dev/null 2>&1; then issue discovery crt.sh 'Optional CT adapter unavailable: jq is required for safe provider JSON parsing.'
        else
            for root in "${ROOTS[@]}"; do
                if request 'https://crt.sh/' discovery GET "?q=%25.$root&output=json" && [[ $HTTP_CODE == 200 ]] && jq -e 'type=="array" and all(.[]; type=="object" and (.name_value|type=="string"))' "$HTTP_BODY" >/dev/null 2>&1; then
                    jq -r '.[].name_value' "$HTTP_BODY" > "$WORK/ct-names.txt" 2>/dev/null
                    if (( $(wc -l < "$WORK/ct-names.txt") > 10000 )); then issue discovery crt.sh "Provider candidate line limit exceeded."; fi
                    while IFS= read -r name; do
                        name=${name,,}; [[ $name != \*.* ]] || continue
                        candidate "$name" certificate-transparency
                    done < <(head -n 10000 "$WORK/ct-names.txt")
                else issue discovery crt.sh 'CT unavailable, non-JSON, rate-limited or bounded response exceeded; configured and historical candidates retained.'; fi
            done
        fi
    fi
    sort -u "$WORK/candidates.txt" > "$WORK/all-assets.txt"
    if (( $(wc -l < "$WORK/all-assets.txt") > MAX_ASSETS )); then issue discovery scope 'Asset limit reached; scan is incomplete.'; fi
    head -n "$MAX_ASSETS" "$WORK/all-assets.txt" > "$WORK/assets.txt"
    while IFS= read -r value; do
        local source_list prior_id prior_sources
        source_list=$(awk -F '\t' -v h="$value" '$1==h{print $2}' "$WORK/provenance.tsv" | sort -u | tr '\n' ',')
        prior_id=$(hash "asset|$value"); prior_sources=${OLD_ROWS[$prior_id]-}
        prior_sources=$(printf '%s' "$prior_sources" | sed -n 's/.*sources=\([^;]*\);.*/\1/p')
        source_list=$(printf '%s,%s' "$source_list" "$prior_sources" | tr ',' '\n' | sed '/^$/d' | sort -u | tr '\n' ',')
        record asset "$value" CANDIDATE INFO "$value" "sources=$source_list;In explicit scope; discovery is not proof of resolution, ownership or exposure."
    done < "$WORK/assets.txt"
}
