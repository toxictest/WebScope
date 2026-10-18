#!/usr/bin/env bash
set -uo pipefail
umask 077
WARN_DAYS=30
WORK_DIR=$4
add() {
    printf '%s|%s|%s|%s\n' "$2" "$3" "$4" "$5" >>"$1" 2>/dev/null || true
}
audit_certificate() {
    # shellcheck disable=SC2034 # Retain the original upstream call signature.
    local host="$1" port="$2" leaf="$3"
    local f="$WORK_DIR/$4.find"

    local subject issuer not_before not_after nb_epoch na_epoch now_epoch days
    local cn sans san_list key_algo key_bits curve

    subject=$(openssl x509 -in "$leaf" -noout -subject 2>/dev/null | sed 's/^subject=//' || true)
    issuer=$(openssl x509 -in "$leaf" -noout -issuer 2>/dev/null | sed 's/^issuer=//' || true)
    not_before=$(openssl x509 -in "$leaf" -noout -startdate 2>/dev/null | cut -d= -f2- || true)
    not_after=$(openssl x509 -in "$leaf" -noout -enddate 2>/dev/null | cut -d= -f2- || true)

    nb_epoch=$(date -u -d "$not_before" +%s 2>/dev/null || echo 0)
    na_epoch=$(date -u -d "$not_after" +%s 2>/dev/null || echo 0)
    now_epoch=$(date -u +%s)
    if [[ "$na_epoch" -gt 0 ]]; then
        days=$(( (na_epoch - now_epoch) / 86400 ))
    else
        days=-1
    fi

    # Common Name
    cn=$(openssl x509 -in "$leaf" -noout -subject -nameopt multiline 2>/dev/null \
         | awk -F'=' '/commonName/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' || true)
    [[ -z "$cn" ]] && cn=$(printf '%s' "$subject" | sed -n 's/.*CN=\([^,]*\).*/\1/p' || true)

    # Subject Alternative Names
    san_list=$(openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null \
        | tail -n +2 | tr ',' '\n' | sed 's/^[[:space:]]*//' \
        | grep -E '^(DNS|IP Address|IP):' | sed -E 's/^(DNS|IP Address|IP)://' || true)
    if [[ -z "$san_list" ]]; then
        san_list=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
            | grep -A1 "Subject Alternative Name" | tail -1 \
            | sed 's/^[[:space:]]*//' | tr ',' '\n' | sed 's/^[[:space:]]*//' \
            | grep -E '^(DNS|IP Address|IP):' | sed -E 's/^(DNS|IP Address|IP)://' || true)
    fi
    sans=$(printf '%s' "$san_list" | tr '\n' ',' | sed 's/,$//' || true)
    [[ -z "$sans" ]] && sans="(none)"

    # Key algorithm and size
    key_algo=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
        | awk -F: '/Public Key Algorithm/ { gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit }' || true)
    key_bits=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
        | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -1 || true)
    curve=$(openssl x509 -in "$leaf" -noout -text 2>/dev/null \
        | sed -n 's/.*NIST CURVE: \(.*\)/\1/p' | head -1 || true)
    [[ -z "$key_bits" ]] && key_bits=0

    local key_summary
    if [[ "$key_algo" == *rsa* ]]; then
        key_summary="RSA ${key_bits}-bit"
    elif [[ "$key_algo" == *ecPublicKey* || "$key_algo" == *id-ec* ]]; then
        key_summary="EC ${key_bits}-bit${curve:+ ($curve)}"
    else
        key_summary="${key_algo:-unknown}${key_bits:+ ${key_bits}-bit}"
    fi

    # --- expiry ---
    if [[ "$na_epoch" -le 0 ]]; then
        add "$f" "WARN" "M1" "Certificate expiry" "UNTESTED - expiration could not be parsed"
    elif [[ "$na_epoch" -le "$now_epoch" ]]; then
        add "$f" "FAIL" "M1" "Certificate expiry" "EXPIRED (remaining days: ${days}) on ${not_after}"
    elif [[ "$days" -le "$WARN_DAYS" ]]; then
        add "$f" "WARN" "M1" "Certificate expiry" "EXPIRING SOON - ${days} day(s) left (threshold ${WARN_DAYS}), expires ${not_after}"
    else
        add "$f" "PASS" "M1" "Certificate expiry" "valid - ${days} day(s) remaining, expires ${not_after}"
    fi

    if [[ "$nb_epoch" -gt 0 && "$now_epoch" -lt "$nb_epoch" ]]; then
        add "$f" "FAIL" "M1" "Certificate validity window" "NOT YET VALID - becomes valid ${not_before}"
    else
        add "$f" "PASS" "M1" "Certificate validity window" "valid from ${not_before}"
    fi

    # --- self signed ---
    local subject_cn
    subject_cn=$(printf '%s' "$subject" | sed -n 's/.*CN=\([^,]*\).*/\1/p' || true)
    if [[ -n "$subject" && "$subject" == "$issuer" ]] && openssl verify -check_ss_sig -no_check_time -CAfile "$leaf" "$leaf" >/dev/null 2>&1; then
        add "$f" "FAIL" "M1" "Self-signed certificate" "SELF-SIGNED - subject and issuer are identical (${subject_cn})"
    else
        add "$f" "PASS" "M1" "Self-signed certificate" "not self-signed - issued by ${issuer:-unknown}"
    fi

    # OpenSSL checks wildcard depth, SAN precedence, and IP SANs.
    local checkhost="${host#[}" checkflag=-checkhost
    checkhost="${checkhost%]}"
    if [[ "$checkhost" == *:* || "$checkhost" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then checkflag=-checkip; fi
    if openssl x509 -in "$leaf" -noout "$checkflag" "$checkhost" >/dev/null 2>&1; then
        if [[ -n "$san_list" ]]; then
            add "$f" PASS M1 "Hostname match" "CN/SAN MATCH - '$host' is covered by the certificate"
        else
            add "$f" WARN M1 "Hostname match" "CN MATCH but no SAN extension - modern clients require SAN"
        fi
    else
        add "$f" FAIL M1 "Hostname match" "CN/SAN MISMATCH - '$host' is not covered by the certificate"
    fi

    # --- key strength (module 3 content, reported in module 3 as well) ---
    if [[ "$key_bits" -eq 0 ]]; then
        add "$f" WARN M3 "Public key strength" "UNTESTED - key size could not be parsed"
    elif [[ "$key_algo" == *rsa* ]]; then
        if [[ "$key_bits" -gt 0 && "$key_bits" -lt 2048 ]]; then
            add "$f" "FAIL" "M3" "Public key strength" "WEAK KEY - RSA ${key_bits}-bit is below the 2048-bit minimum"
        else
            add "$f" "PASS" "M3" "Public key strength" "RSA ${key_bits}-bit meets the 2048-bit minimum"
        fi
    elif [[ "$key_algo" == *ecPublicKey* || "$key_algo" == *id-ec* ]]; then
        if [[ "$key_bits" -gt 0 && "$key_bits" -lt 256 ]]; then
            add "$f" "WARN" "M3" "Public key strength" "WEAK KEY - EC ${key_bits}-bit${curve:+ ($curve)} is below P-256"
        else
            add "$f" "PASS" "M3" "Public key strength" "EC ${key_bits}-bit${curve:+ ($curve)} is a strong curve"
        fi
    else
        add "$f" "WARN" "M3" "Public key strength" "key algorithm '${key_algo:-unknown}' could not be evaluated"
    fi

    printf 'subject=%s\nissuer=%s\ncn=%s\nsan=%s\nnot_before=%s\nnot_after=%s\ndays_remaining=%s\nkey_algo=%s\nkey_bits=%s\nkey_summary=%s\n' \
        "$subject" "$issuer" "$cn" "$sans" "$not_before" "$not_after" "$days" \
        "$key_algo" "$key_bits" "$key_summary" >"$WORK_DIR/$4.m1.detail"
}
audit_certificate "$1" "$2" "$3" local
