#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
for script in webscope.sh install_deps.sh adapters/*.sh tests/run_tests.sh; do bash -n "$script"; done
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -S warning webscope.sh install_deps.sh adapters/*.sh tests/run_tests.sh
else
    echo 'ShellCheck unavailable: static analysis NOT RUN.' >&2
fi
python3 -I -B tests/run_tests.py
