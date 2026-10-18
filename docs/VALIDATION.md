# Executed validation — WebScope 1.0.0-rc2

Validation date: **2026-10-18**. This report describes actual executed tests, not prospective test cases.

## Results

| Suite | Actual result | Transcript |
|---|---:|---|
| Dependency setup safety suite | **10 passed, 0 failed** | `tests/dependencies-results.txt` |
| WebScope integration/regression suite | **113 passed, 0 failed** | `tests/test-results.txt` |
| Included SurfaceIntel backend full regression suite | **206 passed, 0 failed** | `tests/surfaceintel-results.txt` |
| Bash syntax / warning-level ShellCheck | Passed | Executed by the launchers; no warnings in final run |
| Report schema validation | Passed | Complete, partial, HTTPS, IPv6 and interrupted run reports tested |

All three recorded stderr files are empty. **No tests were skipped in these final runs.** The WebScope suite requires development `jsonschema`; it does not silently omit validation. Local IPv6 was available and tested.

Environment: Debian 13, Bash 5.2.37, Python 3.13.16, curl 8.14.1/OpenSSL 3.5.7. ShellCheck 0.10.0 was downloaded as a Debian package and extracted into a workspace-only development directory; no system package installation or security configuration change was made. The base environment did not provide `dig`; hermetic tests supplied an owned deterministic `dig` executable. A real deployment must provide `dig` or fails preflight. No claim of native public DNS resolver qualification is made.

## WebScope tests exercised

- Exact root/tree/exclusion boundaries, canonical host case/trailing dots, forbidden userinfo, scheme/port/path ambiguity, credential-shaped path rejection and omission of URL query values.
- Sensitive filename/extension classification from original URLMiner constants; normal public JS eligibility; no automatic guessed directory/file requests.
- No-side-effect dry-run, explicit authorization acknowledgement, CT/tree role requirements, bounded option lists, invalid CIDRs/ports/rates, malformed imports and private-key rejection as a CA bundle.
- Actual owned local HTTP listeners using curl through the pinned SurfaceIntel transport under deliberately hostile proxy variables; local HTML/scripts, JS imports, route hints, robots/sitemap, same-scope redirect handling and external redirect rejection.
- Actual oversized HTTP response rejection, native request timeout, request caps, private/metadata/mixed-address/CNAME/temporary-DNS-failure blocks, and explicit CNAME approval of the original scoped host.
- Sensitive candidates returning HTTP 200 stay **review-required**, with **no GET** of `.env`, backups, databases or source maps. API hints do not cause API GETs. Query/script URLs, mutating-name paths and robot-disallowed paths are not fetched.
- Deliberate secret markers in inline JS, public JS, query strings, cookies, raw TXT, redirect queries and sensitive/API bodies are absent from final reports. JS literal values are redacted. Transient work is removed and permissions checked.
- Actual original HeaderGuard AWK parsing, DNSShield local provider mapping, ReconScope import normalization including an input larger than a typical per-argument OS limit, and TLSWatch local certificate checks.
- Actual local HTTPS and public certificate collection using an explicit fixture CA; hostname validation, critical imminent-expiry evidence, no insecure HTTP retry. Actual pinned IPv6 loopback HTTP.
- Output symlink/permission/overlap protections, SIGTERM partial report and exit status, work cleanup, finalized-marker removal, and a complete end-to-end native local run exiting zero.
- Synthetic CT JSON candidate parsing, wildcard/third-party filtering and provider failure classification. **No live CT provider query was executed.**

## Underlying backend tests

The dependency suite checks no-write plans/default checks, missing commands, invalid/ambiguous options, development planning, the nonroot install refusal and machine-readable recipes. Actual package installation and DNF deployment were not executed.

The complete vendored SurfaceIntel suite was rerun against the copied backend, not merely quoted from an earlier delivery. Its 206 passing assertions cover the transport/scope, DNS, TLS, schemas, state, alerts and operational behavior described in its own validation guide. WebScope does not enable all those standalone features: in particular it does not run cloud checks, webhooks, historical baseline promotion or scheduling. Backend test success is not a claim that those features were integrated into this CLI.

## Shipped examples

- `examples/complete-local/`: an owned fixture run completed within declared policy/limits, including public JS parsing and metadata-only candidates.
- `examples/controlled-local/`: a deliberately oversized JS fixture makes coverage partial while other evidence is retained; external/query/action/robots restrictions and redacted hints are demonstrated.

Both use reserved `.test` names and ephemeral loopback ports. They do not describe the user's infrastructure. Fixture private keys and response bodies are not shipped. Additional historical SurfaceIntel examples remain within its vendor directory and are labeled independently.

## Unrun qualification / limitations

No public/customer target scan, real CT availability/rate-policy test, cross-distribution matrix, external GitHub tool runner, browser execution, authenticated crawl, raw JS archive, wordlist brute force, live cloud tenant, hosted webhook, production scheduler activation, stress/load campaign, independent security review or adversarial same-UID/root assessment was performed.

A single domain cannot reveal every subdomain, directory, JS file or secret. Discovery is bounded, policy-filtered and incomplete by nature. Filesystem directories are not inferred as confirmed from URL prefixes. HEAD success is not sensitive-content exposure, and possible JS literals are not validated credentials.

Qualify a deployment with reviewed scope/exclusions, dependencies and versions; a small owner-controlled staging site; exact provider/CNAME/port approvals; traffic and storage budgets; privacy review; and an operator response plan. Treat the release as a controlled-deployment candidate rather than a universal production certification.
