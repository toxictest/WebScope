#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for cmd in python3 bash; do
    command -v "$cmd" >/dev/null 2>&1 || { printf 'Missing dependency: %s (nothing installed)\n' "$cmd" >&2; exit 2; }
done
unset BASH_ENV ENV SSLKEYLOGFILE OPENSSL_CONF OPENSSL_MODULES OPENSSL_ENGINES
exec python3 -I -B "$ROOT/lib/engine.py" "$@"
