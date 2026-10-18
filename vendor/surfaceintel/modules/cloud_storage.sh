# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
cloud_classify() {
    local provider=$1 kind=$2 code=$3 listing=$4 identified=false err marker
    CLOUD_STATUS=INDETERMINATE; CLOUD_EVIDENCE='Provider/object access could not be established; status alone is insufficient.'
    case $provider in
        s3) marker=$(header x-amz-request-id); err=$(header x-amz-error-code);;
        azure) marker=$(header x-ms-request-id); err=$(header x-ms-error-code);;
        gcs) marker=$(header x-guploader-uploadid); [[ -n $marker ]] || marker=$(header x-goog-generation); err=$(header x-goog-error-code);;
    esac
    [[ -z $marker ]] || identified=true
    [[ $identified == true ]] || return 0
    if [[ $code == 401 ]]; then CLOUD_STATUS=AUTH_REQUIRED; CLOUD_EVIDENCE='Provider-identified request requires authentication; no anonymous data read attempted.'
    elif [[ $code == 403 ]]; then CLOUD_STATUS=ACCESS_DENIED; CLOUD_EVIDENCE='Provider-identified anonymous request denied; resource existence and other permissions remain unknown.'
    elif [[ $code == 404 ]]; then CLOUD_STATUS=NOT_FOUND; CLOUD_EVIDENCE='Provider returned not-found for this request; permission masking and region differences remain possible.'
    elif [[ $code == 200 && $kind == object ]]; then
        case $provider in
            s3) marker=$(header etag);;
            azure) marker=$(header x-ms-blob-type);;
            gcs) marker=$(header x-goog-generation);;
        esac
        if [[ -n $marker ]]; then CLOUD_STATUS=PUBLIC_OBJECT_READ_CONFIRMED; CLOUD_EVIDENCE='Unsigned HEAD succeeded with provider-specific object metadata; provider object-read permission evidenced, object bytes NOT fetched.'; fi
    elif [[ $code == 200 && $listing == true && $provider == s3 && -f $HTTP_BODY ]]; then
        if grep -Eq '<ListBucketResult([ >])' "$HTTP_BODY" && grep -Eq '<MaxKeys>0</MaxKeys>' "$HTTP_BODY" && ! grep -Eq '<(Contents|Key)([[:space:]>])|<[^>]*:(Contents|Key)([[:space:]>])|<!DOCTYPE|<!ENTITY|<!--' "$HTTP_BODY"; then
            CLOUD_STATUS=PUBLIC_LISTING_CONFIRMED; CLOUD_EVIDENCE='Opt-in unsigned S3 ListObjectsV2 max-keys=0 returned provider list-result XML without object entries; no names or bytes requested.'
        fi
    fi
    # Error text is not exported; it could contain tenant/resource details or secrets.
    : "$err"
}
cloud_storage() {
    local entry provider kind url query method listing severity
    for entry in "${CLOUDS[@]}"; do
        IFS='|' read -r provider kind url <<< "$entry"
        validate_cloud "$entry" || { issue cloud resource 'Scope/provider validation rejected candidate.'; continue; }
        query=''; method=HEAD; listing=false
        if [[ $provider == azure && $kind == bucket ]]; then query='?restype=container'; fi
        if [[ $provider == s3 && $kind == bucket && $CLOUD_LISTING == true ]]; then query='?list-type=2&max-keys=0'; method=GET; listing=true; fi
        if ! request "$url" cloud "$method" "$query"; then
            issue cloud "$url" "$HTTP_REASON"
            record cloud "$url" REQUEST_FAILED INFO "$HTTP_REASON" "provider=$provider;reason=$HTTP_REASON;no_exposure_conclusion=true"
            continue
        fi
        cloud_classify "$provider" "$kind" "$HTTP_CODE" "$listing"
        if [[ $CLOUD_STATUS == INDETERMINATE ]]; then issue cloud "$url" "Provider access classification remains indeterminate; successful baseline preserved."; fi
        severity=INFO
        case $CLOUD_STATUS in PUBLIC_LISTING_CONFIRMED|PUBLIC_OBJECT_READ_CONFIRMED) severity=HIGH;; esac
        record cloud "$url" "$CLOUD_STATUS" "$severity" "$CLOUD_STATUS" "provider=$provider;kind=$kind;code=$HTTP_CODE;method=$method;$CLOUD_EVIDENCE"
        if [[ $severity == HIGH ]]; then finding PUBLIC_CLOUD_ACCESS "$url" HIGH HIGH "$CLOUD_STATUS; $CLOUD_EVIDENCE" 'Confirm intentional publication; restrict anonymous permissions through approved change control if inappropriate.'; fi
    done
}
