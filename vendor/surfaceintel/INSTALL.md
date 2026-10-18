# Installation, upgrade and removal

## Verify and run from the release directory

1. Verify the external archive SHA-256 and extract it into a trusted directory.
2. Verify `SHA256SUMS` from the extracted `surfaceintel/` directory with `sha256sum -c SHA256SUMS`.
3. Review source, authorization scope and policy. Never run an unreviewed example against an organization merely because its name appears related.
4. Run `./surfaceintel.sh --version`, `--help`, and a scope/config `--dry-run`.
5. Test your approved deployment with private output storage before scheduling.

No root privilege is needed for normal DNS/HTTP/TLS monitoring. Python and paid services are not runtime requirements. Runtime dependencies and optional degraded behavior are listed in README. The installer never invokes a package manager.

## Explicit-confirmation installer

```bash
./packaging/install.sh --prefix /opt/surfaceintel/1.0.0-rc1
# Inspect the printed plan; no changes were made.
sudo ./packaging/install.sh --prefix /opt/surfaceintel/1.0.0-rc1 --confirm-install
```

Use a new directory under your home without sudo for a user installation. The destination must be new; existing directories are refused. Installation copies code, schemas, examples and documentation only. It does not change PATH, install packages, create users, alter DNS/TLS trust, create persistent jobs, enable services, configure webhooks or edit host security settings.

Root-run or scheduled code should be owned by a trusted administrator and not writable by the service account or unrelated users. Store actual customer scope/policy, alert config and secrets outside the shipped examples. Use mode 0600 for customer secret material and alert config; the alert config must be owned by the account that invokes the auditor. Protect state and report directories with mode 0700.

## Opt-in scheduling

See `docs/OPERATIONS.md` and `packaging/`. The service and daily/weekly timer templates are examples, **not installed or enabled by the installer**. Creating a dedicated service user, deploying unit files, enabling timers or adding cron entries are separate, explicitly authorized administrative changes. Review the example active-check flags before using them.

## Upgrade

- Keep versioned code directories; do not overwrite the running release in place.
- Verify the new archive/manifests and review CHANGELOG/schema/transport changes.
- Run the tests and stage a representative customer with native DNS/TLS/firewall conditions and approved webhook destinations.
- Pin the new absolute executable/config paths in your job only after approval.
- Retain the old release, scope, policy and baseline for rollback. Policy changes should increment `config_version`.
- Baseline organization/schema validation is mandatory. Different coverage modes need separate baseline paths. Partial scans never perform automatic migration or promotion.

The `--update-baseline` flag is explicit permission to atomically replace the current successful baseline after a complete run; it first archives the prior copy under the customer's private state directory. Without that flag, the baseline is read-only. Retention of prior copies is configurable.

## Uninstall

If you manually scheduled jobs, disable/remove **only those SurfaceIntel jobs** through your normal change-control process. Review the exact versioned prefix and `.surfaceintel-install` marker, then remove that code directory. Do not recursively delete generic `/opt`, `/etc`, `/var/lib`, or other customers' trees. Retain or securely delete reports, scope, policies, secret files and state according to your authorization/retention agreement. Revoke webhooks independently if appropriate. No uninstall step changes target infrastructure.
