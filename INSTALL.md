# Installation and operation

## Install without system changes

1. Verify the supplied ZIP SHA-256 against a trusted copy of the checksum.
2. Extract into a new versioned directory owned by the operator.
3. Review dependencies, authorization and [integration boundaries](docs/INTEGRATIONS.md).

```bash
unzip WebScope-v1.0.0-rc2.zip
cd webscope
sha256sum -c MANIFEST.sha256
chmod +x webscope.sh tests/run_tests.sh
./webscope.sh example.invalid --dry-run
```

Runtime: Linux, Python 3.9+, Bash 4.4+, curl, dig and the GNU-style utilities listed in README. OpenSSL plus timeout provide optional certificate inspection. Missing required dependencies produce an error before network collection. Scanning needs no root privilege. The separate opt-in dependency helper uses the OS package manager only when explicitly invoked with --install; it creates no service account, cron entry or systemd job. See [DEPENDENCIES.md](DEPENDENCIES.md).

## Real authorized use

Start with one approved host and small limits. Then separately approve the subdomain tree, CT provider, CNAMEs, HTTP/custom ports and any legitimate nonpublic CIDRs. Keep reports outside the source tree.

```bash
mkdir -m 700 "$HOME/private-webscope-reports"
./webscope.sh YOUR_AUTHORIZED_DOMAIN --authorized \
  --max-hosts 8 --max-urls 80 --max-requests 160 \
  --output "$HOME/private-webscope-reports"
```

Use ASCII/punycode domain names, not a URL. Imports are bounded hostname-only files, one entry per line; lines beginning `#` are comments. Invalid imported candidates are counted and not requested. Malformed/binary/symlink inputs are refused. Scope/configuration is not shell code.

`--ca-file` accepts a protected public PEM CA bundle, never a private key. Do not replace trust files while a run is in progress; the scope record hashes the initial custom bundle, not every later filesystem read or the OS trust store.

## Output lifecycle

Every run creates a fresh mode-0700 directory with mode-0600 reports. A lock covers one output root. Check the exit code and JSON completion/errors rather than using file existence as success. Results are not baseline updates and findings are not proof of exploitation.

Inspect the report, retain it according to the customer's policy, and remove obsolete run directories manually only when no scan is active. Do not delete another process's lock file: the advisory lock is released automatically when its file descriptor closes. An `INCOMPLETE` marker indicates failed/interrupted finalization, including possible leftover private work.

## Upgrade / rollback

Install a new bundle beside the old version, verify its manifest, run fixture tests, compare configuration/report schemas, and perform a small authorized staging run. Change your invoking path only after review. Rollback means selecting the prior version; do not overwrite unrelated tool source directories or reports.

## Scheduling

No schedule is installed or bundled as an enabled service. If an operator later adds a job, use absolute paths, a private dedicated output root, explicit reviewed authorization flags and a separate wall-clock supervisor. Do not hide exit 3/75 or repeatedly retry an overloaded provider. CT provider availability/rate policy and customer traffic windows require operational review.

## Developer tests

```bash
./tests/run_tests.sh
bash vendor/surfaceintel/tests/run_tests.sh
```

Tests require development Python `jsonschema` and OpenSSL. ShellCheck is used when available; absence is explicitly reported. Tests create only temporary local servers, synthetic DNS responses and ephemeral fixture certificates. Do not run the example documentation domains as targets merely because they appear in usage examples.
