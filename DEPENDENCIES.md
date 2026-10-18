# Dependency setup and troubleshooting

## Runtime: no pip packages required

WebScope requires Linux, **Bash 4.4+**, **Python 3.9+**, curl, dig and GNU-style core/text utilities. OpenSSL and timeout provide the full TLS inspection profile. The supplied installer includes these TLS dependencies. `requirements.txt` documents that runtime Python is standard-library-only; running `pip install -r requirements.txt` does **not** install OS tools.

```bash
bash install_deps.sh --check
bash install_deps.sh --plan
sudo bash install_deps.sh --install
bash install_deps.sh --check
bash webscope.sh example.invalid --dry-run
```

Default/check/plan modes make no package changes or target requests. Installation requires explicit `--install` and root; sudo is never invoked implicitly. Apt installation first refreshes package indexes. This changes the OS package set and uses configured package repositories, but the helper never starts a scan or configures firewall rules/scheduled jobs. Package-manager maintainer scripts and administrator-configured hooks may still run, including CA trust-store updates. Review repository trust and the plan first.

`packaging/dependencies.json` lists the package recipes. Debian/Ubuntu-family uses `apt-get`; Fedora/RHEL/Rocky/Alma/CentOS uses `dnf`. Unsupported systems fail closed for automatic installation. DNF recipes are **not native-tested**. On enterprise releases, ShellCheck may require an administrator-approved repository; the script does not enable EPEL or substitute third-party downloads automatically. Older RHEL/Python packages may be below Python 3.9: select an administrator-provisioned newer `python3` on PATH, then rerun the check. This helper cannot guarantee every distribution/repository combination.

## Optional development tests

Development tests need OpenSSL, ShellCheck and `jsonschema`. Install OS test packages explicitly, then create the Python environment **as your normal user**, not through sudo:

```bash
sudo bash install_deps.sh --install --dev
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
. .venv/bin/activate
bash install_deps.sh --check --dev
bash tests/run_tests.sh
bash vendor/surfaceintel/tests/run_tests.sh
python3 -I -B tests/test_dependencies.py
```

`--install --dev` installs OS test packages and prints venv instructions; it does not run pip or create a root-owned environment. `--check --dev` checks `.venv/bin/python` if available; **activate that venv before running tests** so their `python3` selects the same interpreter. Never use `sudo pip` or `--break-system-packages`.

## Common errors

- **Missing dig:** install `bind9-dnsutils` on Debian/Ubuntu, or `bind-utils` on DNF systems. There is no silent unbounded resolver fallback.
- **Missing jsonschema:** it is a development dependency, not needed for scanning. Activate the development venv after installing `requirements-dev.txt`.
- **Permission denied:** invoke entry points with `bash`, or `chmod +x webscope.sh tests/run_tests.sh`. Vendored SurfaceIntel tests also expect executable `vendor/surfaceintel/surfaceintel.sh` and `vendor/surfaceintel/packaging/install.sh`; Git and the release ZIP retain these bits.
- **Existing report directory rejected:** create an operator-owned private directory with mode 0700; do not use a shared or symlinked output directory.
- **DNS/CNAME/private-address failure:** dependencies may be correct. Review actual authorization and exclusions; use precise `--allow-cname` or joint `--cidr`/`--allow-nonpublic` only when explicitly legitimate. Never disable TLS or broaden scope just to suppress errors.
- **CT unavailable / partial:** external availability, response limits and authorization are independent of dependency installation. Local imports remain usable.

Successful dependency checks mean required commands/interpreter versions were found, not that a target is authorized, DNS/network/provider access works, or every installed utility version has been qualified. No system packages were installed while developing/testing this setup helper.
