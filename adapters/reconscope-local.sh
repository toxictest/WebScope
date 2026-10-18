#!/usr/bin/env bash
set -uo pipefail
set -f
normalise_list() {
    local raw="$1" out="" item
    raw="${raw//,/ }"
    for item in $raw; do
        item="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')"
        [[ -n "$item" ]] && out="${out}${out:+,}${item}"
    done
    printf '%s' "$out"
}
raw=$(head -c 262144)
normalise_list "$raw"
