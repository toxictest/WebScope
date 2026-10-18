#!/usr/bin/env bash
# SurfaceIntel is the only active DNS/HTTP/TLS transport used by WebScope.
# shellcheck disable=SC2034
set +x
set -uo pipefail
unset SSLKEYLOGFILE OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
umask 077
export LC_ALL=C
ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
SI="$ROOT/vendor/surfaceintel"
# shellcheck source=../vendor/surfaceintel/lib/common.sh
source "$SI/lib/common.sh"
for lib in validation state_store network; do
    # shellcheck disable=SC1090
    source "$SI/lib/$lib.sh"
done
for mod in scope dns_resolution tls_monitor; do
    # shellcheck disable=SC1090
    source "$SI/modules/$mod.sh"
done
read_pairs "$1" scope_pair
read_pairs "$2" policy_pair
validate_scope
WORK=$3
private_dir "$WORK" || fatal 'Unsafe work directory.'
: > "$WORK/errors.tsv"
: > "$WORK/records.tsv"
while IFS=$'\t' read -r action value extra; do
    NOW=$(date -u +%s)
    case $action in
        HEAD|GET)
            request "$value" asset "$action" || :
            printf '{"status":'; json_string "$HTTP_CODE"
            printf ',"reason":'; json_string "$HTTP_REASON"
            printf ',"headers":'; json_string "$HTTP_HEADERS"
            printf ',"body":'; json_string "$HTTP_BODY"
            printf '}\n';;
        CT)
            if [[ $CT_ENABLED == true ]] && contains "$value" "${ROOTS[@]}"; then
                request 'https://crt.sh/' discovery GET "?q=%25.$value&output=json" || :
                printf '{"status":'; json_string "$HTTP_CODE"
                printf ',"reason":'; json_string "$HTTP_REASON"
                printf ',"body":'; json_string "$HTTP_BODY"
                printf '}\n'
            else printf '{"status":"000","reason":"CT_NOT_AUTHORIZED"}\n'; fi;;
        DNS)
            case $extra in A|AAAA|CNAME|MX|NS|TXT) ;; *) printf '{"reason":"INVALID_TYPE"}\n'; continue;; esac
            dns_query "$value" "$extra" || :
            printf '{"status":'; json_string "$DNS_STATUS"
            printf ',"values":'; json_string "$DNS_VALUES"
            printf ',"ttls":'; json_string "$DNS_TTLS"
            printf ',"source":'; json_string "$DNS_SOURCE"
            printf '}\n';;
        TLS)
            : > "$WORK/records.tsv"
            : > "$WORK/errors.tsv"
            tls_one "$value"
            printf '{"records":'; json_string "$WORK/records.tsv"
            printf ',"certificate":'; json_string "$WORK/cert-$REQUEST_SEQ.pem"
            printf ',"errors":'; json_string "$WORK/errors.tsv"
            printf '}\n';;
        *) printf '{"reason":"INVALID_COMMAND"}\n';;
    esac
done
