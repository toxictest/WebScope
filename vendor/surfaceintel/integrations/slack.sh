# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
payload_slack() { printf '{"text":'; json_string "$1"; printf ',"unfurl_links":false,"unfurl_media":false}\n'; }
