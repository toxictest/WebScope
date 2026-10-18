# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
validate_state() {
    local file=$1 header marker version org scope policy completion stamp mode end line kind id asset status fp severity first last detail count=0
    text_file "$file" 8388608 || return 1
    IFS= read -r header < "$file" || return 1
    [[ $(printf '%s' "$header" | awk -F '\t' '{print NF}') == 9 ]] || return 1
    IFS=$'\t' read -r marker version org scope policy completion stamp mode end <<< "$header"
    # The last column is a fixed sentinel, preventing empty-field ambiguity.
    [[ $marker == SURFACEINTEL_STATE && $version == 1 && $org == "$ORG" && $scope =~ ^[a-f0-9]{64}$ && $policy =~ ^[a-f0-9]{64}$ && $completion =~ ^(complete|partial|interrupted)$ && $stamp =~ ^[0-9]{10,12}$ && $mode =~ ^(normal|passive|dns|tls)-[01]-[01]$ && $end == END ]] || return 1
    local -A seen=()
    while IFS= read -r line; do
        ((count+=1)); ((count<=12000)) || return 1
        [[ ${#line} -le 8192 && $(printf '%s' "$line" | awk -F '\t' '{print NF}') == 9 ]] || return 1
        IFS=$'\t' read -r kind id asset status fp severity first last detail <<< "$line"
        [[ $kind =~ ^(asset|dns|http|tls|cloud|finding)$ && $id =~ ^[a-f0-9]{64}$ && $fp =~ ^[a-f0-9]{64}$ && $status =~ ^[A-Z][A-Z0-9_]*$ && $severity =~ ^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$ && $first =~ ^[0-9]{10,12}$ && $last =~ ^[0-9]{10,12}$ && -n $asset && -n $detail && -z ${seen[$id]-} ]] || return 1
        [[ $id == "$(hash "$kind|$asset")" ]] || return 1
        seen[$id]=1
    done < <(tail -n +2 -- "$file")
}
load_baseline() {
    local line id header marker version org completion stamp mode end
    OLD_SCOPE=''; OLD_POLICY=''; OLD_MODE=''
    [[ -e $BASELINE || -L $BASELINE ]] || return 0
    validate_state "$BASELINE" || fatal 'Baseline schema/organization validation failed.'
    IFS= read -r header < "$BASELINE"
    IFS=$'\t' read -r marker version org OLD_SCOPE OLD_POLICY completion stamp mode end <<< "$header"
    [[ $completion == complete ]] || fatal 'Only a complete successful state can be a baseline.'
    OLD_MODE=$mode
    if ((UPDATE)) && [[ $OLD_MODE != "$MODE-$HTTP_CHECKS-$CLOUD_CHECKS" ]]; then fatal "Baseline mode differs; select a new baseline path before requesting replacement."; fi
    while IFS= read -r line; do id=$(printf '%s' "$line" | cut -f2); OLD_ROWS[$id]=$line; done < <(tail -n +2 -- "$BASELINE")
}
initialize_store() {
    local marker
    private_dir "$OUTPUT" || fatal 'Output must be owned, private and non-symlink.'
    CUSTOMER="$OUTPUT/$ORG"; private_dir "$CUSTOMER" || fatal 'Customer directory is not private.'
    STATE="$CUSTOMER/state"; private_dir "$STATE" || fatal 'State directory is not private.'
    if [[ -e $STATE/organization || -L $STATE/organization ]]; then
        text_file "$STATE/organization" 256 || fatal 'Invalid organization marker.'
        IFS= read -r marker < "$STATE/organization"; [[ $marker == "$ORG" ]] || fatal 'Customer state mismatch.'
    else printf '%s\n' "$ORG" > "$STATE/organization"; fi
    LOCK="$STATE/run.lock"
    if ! mkdir -m0700 -- "$LOCK" 2>/dev/null; then LOCK=''; fatal 'Another run or stale lock exists; review the lock before retrying.' 75; fi
    printf '%s\n' "$$" > "$LOCK/pid"
    [[ -n $BASELINE ]] || BASELINE="$STATE/baseline.tsv"
    [[ ! -L $BASELINE ]] || fatal 'Symlink baseline refused.'
    private_dir "$(dirname -- "$BASELINE")" || fatal 'Baseline parent must be private and owned.'
    BASELOCK="$BASELINE.lock"
    if ! mkdir -m0700 -- "$BASELOCK" 2>/dev/null; then BASELOCK=''; fatal 'Baseline already locked; overlapping runs refused.' 75; fi
    load_baseline
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/surfaceintel.XXXXXXXX") || fatal 'Cannot create private workspace.'
    : > "$WORK/errors.tsv"; : > "$WORK/records.tsv"; : > "$WORK/provenance.tsv"; : > "$WORK/events.tsv"; : > "$WORK/delivery.tsv"; : > "$WORK/rejected.tsv"
    RUN="$CUSTOMER/run-$STAMP-$$"; mkdir -m0700 -- "$RUN" || fatal 'Cannot create unique report directory.'
    printf '%s\n' "$ORG" > "$RUN/.surfaceintel-run"
}
write_state() {
    local completion=$1
    printf 'SURFACEINTEL_STATE\t1\t%s\t%s\t%s\t%s\t%s\t%s\tEND\n' "$ORG" "$SCOPE_HASH" "$POLICY_HASH" "$completion" "$NOW" "$MODE-$HTTP_CHECKS-$CLOUD_CHECKS" > "$RUN/state.tsv"
    sort -t $'\t' -k1,1 -k3,3 "$WORK/records.tsv" >> "$RUN/state.tsv"
    validate_state "$RUN/state.tsv" || fatal 'Internal state validation failed.'
}
update_baseline() {
    local temp archive
    ((UPDATE)) || return 0
    if ((PARTIAL)) || [[ $COMPLETION != complete ]]; then log 'Baseline preserved: scan is incomplete.'; return 0; fi
    if [[ -n $OLD_MODE && $OLD_MODE != "$MODE-$HTTP_CHECKS-$CLOUD_CHECKS" ]]; then
        log 'Baseline preserved: scan modes differ; use a new baseline path for a different coverage mode.'; return 0
    fi
    if [[ -e $BASELINE ]]; then
        archive=$(mktemp "$STATE/baseline-prev-$STAMP-XXXXXXXX.tsv") || fatal "Cannot allocate baseline archive."; cp -- "$BASELINE" "$archive" || fatal 'Could not preserve prior baseline.'
    fi
    temp=$(mktemp "$(dirname -- "$BASELINE")/.surfaceintel-baseline.XXXXXXXX") || fatal 'Could not stage baseline.'
    cp -- "$RUN/state.tsv" "$temp" && mv -f -- "$temp" "$BASELINE" || fatal 'Atomic baseline replacement failed.'
}
retention() {
    local path marker n=0
    while IFS= read -r path; do
        [[ -d $path && ! -L $path && -f $path/.surfaceintel-run && ! -L $path/.surfaceintel-run ]] || continue
        IFS= read -r marker < "$path/.surfaceintel-run"; [[ $marker == "$ORG" ]] || continue
        ((n+=1)); if ((n>RETENTION_RUNS)); then rm -rf -- "$path"; fi
    done < <(find "$CUSTOMER" -mindepth 1 -maxdepth 1 -type d -name 'run-20??????T??????Z-[0-9]*' -print | sort -r)
    n=0
    while IFS= read -r path; do
        [[ -f $path && ! -L $path ]] || continue
        ((n+=1)); if ((n>RETENTION_BASELINES)); then rm -f -- "$path"; fi
    done < <(find "$STATE" -mindepth 1 -maxdepth 1 -type f -name 'baseline-prev-20??????T??????Z-????????.tsv' -print | sort -r)
}
