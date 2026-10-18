#!/usr/bin/env bash
# Dependency setup only; never starts a scan or activates a job.
set +x
set -euo pipefail
ROOT=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
action=check
dev=0
modes=0
for arg in "$@"; do
    case "$arg" in
        --check|--plan|--install) ((modes+=1)); action=${arg#--};;
        --dev) dev=1;;
        --help|-h) printf '%s\n' 'Usage: bash install_deps.sh [--check|--plan|--install] [--dev]' 'Default --check makes no changes. --install explicitly installs OS packages.' '--dev installs optional OS test tools and prints normal-user venv setup commands.'; exit 0;;
        *) printf 'Unknown option. Use --help.\n' >&2; exit 2;;
    esac
done
((modes<=1)) || { echo "Choose only one action: --check, --plan or --install." >&2; exit 2; }
check_dependencies() {
    local cmd missing=0 py=python3
    local -a required=(bash python3 curl dig awk sha256sum date stat sort sed grep cut diff cmp tr mktemp find head tail wc dirname mkdir rm sleep openssl timeout)
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then printf 'MISSING: %s\n' "$cmd"; missing=1; fi
    done
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
        printf 'MISSING: Bash >= 4.4\n'; missing=1
    fi
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 -I -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
            printf 'MISSING: Python >= 3.9\n'; missing=1
        fi
    fi
    if ((dev)); then
        if ! command -v shellcheck >/dev/null 2>&1; then printf 'MISSING: ShellCheck (development)\n'; missing=1; fi
        if [[ -x $ROOT/.venv/bin/python ]]; then py="$ROOT/.venv/bin/python"; fi
        if ! "$py" -I -c 'import jsonschema' >/dev/null 2>&1; then printf 'MISSING: jsonschema (development interpreter)\n'; missing=1; fi
    fi
    if ((missing)); then
        printf '%s\n' 'Dependencies incomplete. Review --plan, then explicitly use --install (optionally --dev).' >&2
        return 1
    fi
    printf '%s\n' 'Dependency check passed. This does not test target authorization, DNS connectivity or provider availability.'
}
if [[ $action == check ]]; then check_dependencies; exit $?; fi
[[ $(uname -s) == Linux ]] || { echo 'Only supported Linux package managers are automated.' >&2; exit 2; }
# Read OS data without sourcing it as shell code.
os_id=$(awk -F= '$1=="ID" {gsub(/"/,"",$2);print $2}' /etc/os-release)
case "$os_id" in
    debian|ubuntu|linuxmint|pop)
        manager=apt-get
        packages=(bash python3 curl bind9-dnsutils coreutils gawk grep sed diffutils findutils ca-certificates openssl)
        ((dev==0)) || packages+=(python3-venv python3-pip shellcheck)
        ;;
    fedora|rhel|centos|rocky|almalinux)
        manager=dnf
        packages=(bash python3 curl bind-utils coreutils gawk grep sed diffutils findutils ca-certificates openssl)
        ((dev==0)) || packages+=(python3-pip ShellCheck)
        ;;
    *) echo 'Unsupported distribution for automatic install. See DEPENDENCIES.md; no changes made.' >&2; exit 2;;
esac
printf 'Plan: %s install' "$manager"; printf ' %s' "${packages[@]}"; printf '\n'
if ((dev)); then printf '%s\n' 'Development plan: install OS test packages; print commands for a separate normal-user venv setup.'; fi
if [[ $action == plan ]]; then echo 'Plan only; no changes made.'; exit 0; fi
command -v "$manager" >/dev/null 2>&1 || { echo 'Package manager unavailable.' >&2; exit 2; }
# Explicit package installation requires privileges; do not invoke sudo implicitly.
((EUID==0)) || { echo 'OS installation requires root. Review the plan, then use sudo bash install_deps.sh --install; use --dev separately as your normal user as documented.' >&2; exit 2; }
if [[ $manager == apt-get ]]; then apt-get update; fi
"$manager" install -y "${packages[@]}"
if ((dev)); then
    # Root should not install Python packages into an operator-owned checkout.
    printf '%s\n' 'Development OS packages installed. As your normal user, run:' 'python3 -m venv .venv' '.venv/bin/python -m pip install -r requirements-dev.txt' 'Then: bash install_deps.sh --check --dev'
fi
# Runtime readiness is checked now; development readiness requires the printed venv steps.
dev=0
check_dependencies
