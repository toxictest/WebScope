#!/usr/bin/env bash
set -euo pipefail
umask 022
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
prefix=/opt/surfaceintel/1.0.0-rc1
confirm=0
while (($#)); do
    case $1 in
        --prefix) (($#>=2)) || exit 2; prefix=$2; shift 2;;
        --confirm-install) confirm=1; shift;;
        --help) echo 'install.sh [--prefix /absolute/NEW/directory] --confirm-install'; exit 0;;
        *) echo 'Invalid installer option.' >&2; exit 2;;
    esac
done
[[ $prefix == /* && $prefix != / && $prefix != *'/../'* && $prefix != *'/..' && $prefix != *[$'\n\r\t']* ]] || { echo 'Unsafe prefix.' >&2; exit 2; }
printf 'Plan: copy SurfaceIntel into new directory %s. No scheduling or package/security changes.\n' "$prefix"
((confirm)) || { echo 'No changes made. Explicit --confirm-install required.'; exit 0; }
[[ ! -e $prefix && ! -L $prefix ]] || { echo 'Destination already exists; use a new version directory.' >&2; exit 2; }
mkdir -p -- "$(dirname -- "$prefix")"
mkdir -m0755 -- "$prefix"
for file in surfaceintel.sh README.md INSTALL.md SECURITY.md CHANGELOG.md LICENSE; do cp -- "$root/$file" "$prefix/"; done
for dir in lib modules integrations schemas config docs packaging; do cp -R -- "$root/$dir" "$prefix/"; done
find "$prefix" -type d -exec chmod 0755 {} +
find "$prefix" -type f -exec chmod 0644 {} +
chmod 0755 "$prefix/surfaceintel.sh"
chmod 0600 "$prefix/config/alerting.example.conf"
printf '%s\n' 'SurfaceIntel 1.0.0-rc1' > "$prefix/.surfaceintel-install"
printf 'Installed: %s/surfaceintel.sh\nNo job or service was enabled.\n' "$prefix"
