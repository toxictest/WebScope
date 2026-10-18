# shellcheck shell=bash
# shellcheck disable=SC2034 # Shared module globals and positional schema fields form the library interface.
payload_discord() { printf '{"content":'; json_string "$1"; printf ',"flags":4,"allowed_mentions":{"parse":[]}}\n'; }
