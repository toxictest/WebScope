# TLSWatch v1.0.0

**Automated SSL/TLS Configuration & Certificate Lifecycle Auditor**  
Defensive Infrastructure & Transport Layer Compliance — free, standalone Bash.

No paid API, SaaS scanner, Python runtime, Go tool, or external scanning framework is required to run the auditor. Audit only endpoints you own or are authorized to assess.

## Quick start

```bash
chmod +x tlswatch.sh
./tlswatch.sh -d target.com:443
./tlswatch.sh -d target.com:443 -l live_hosts.txt -w 14 -o reports
./tlswatch.sh -l live_hosts.txt -t 10 --timeout 5
./tlswatch.sh -d internal.example:8443 --ca-file company-root.pem -v
```

A single endpoint or list alone is supported. With both `-d` and `-l`, the root endpoint is included along with the list.

### Requirements

- Bash 4.4+ on Linux.
- OpenSSL 1.1.1+ (validated with OpenSSL 3.5.7); supported probes depend on the installed build and policy.
- GNU `timeout`, `date`, and standard utilities: awk, sed, sort, grep, tr, cut, head, tail, cat, wc, find, paste, mktemp, mkdir, chmod, cp, mv, rm.
- A system CA trust store, or `--ca-file` for a custom CA bundle.
- `nc` is optional, not required; TLS handshakes provide reachability evidence.

Debian/Ubuntu setup, if these utilities are absent:

```bash
sudo apt-get install openssl ca-certificates coreutils findutils grep sed gawk
```

The script never installs anything itself, does not need root, and makes no configuration changes on targets.

## Input formats

One entry per line, for example:

```text
# HTTPS endpoints
example.com
example.com:443
https://www.example.com/login
https://api.example.com:8443/health
127.0.0.1:9443
[2001:db8::1]:443
```

Names without a port use **443**. HTTPS paths and queries are removed, duplicates are removed, and blank/comment lines are ignored. Bracketed IPv6 is accepted. Credentials in URLs and invalid ports are rejected. **Explicit `http://` URLs are skipped** rather than assuming that the plaintext port offers TLS. To audit such a hostname's HTTPS service, supply `hostname:443` separately.

Direct TLS only: this is not a STARTTLS tester for SMTP, IMAP, LDAP, or other protocol upgrades. No proxy support is implemented.

Day 1 integration:

```bash
./tlswatch.sh -l results/target.com/live/live_hosts.txt -o results/tls -w 30
```

## Options

| Option | Purpose |
|---|---|
| `-d`, `--domain` | Single hostname, hostname:port, or HTTPS URL |
| `-l`, `--list` | File of endpoints; may be used without `-d` |
| `-w`, `--warn-days` | Expiry warning threshold, default 30; warning at or below threshold |
| `-o`, `--output` | Output base directory, default `results` |
| `-t`, `--threads` | Parallel endpoint workers, default 10, maximum 128 |
| `--timeout` | Timeout per handshake, default 10 seconds, maximum 600 |
| `--ca-file` | Custom trusted CA bundle |
| `--no-history` | Disable timestamped text-report copy |
| `-v`, `--verbose` | Include raw protocol/cipher handshakes and initial certificate bundle in technical report |
| `--no-color` | Disable ANSI terminal colours |
| `-h`, `--help` | Usage |

Exit **0** means the audit/report generation completed, even if findings are FAIL. Exit **2** denotes usage/dependency errors. Unexpected execution/I/O errors may return another nonzero status. Use CSV findings for compliance gates, not exit 0 alone.

## Auditing modules

### 1. Certificate lifecycle

- Parses `notBefore` and `notAfter`, compares to the current **system clock**, and exports whole days remaining.
- Expired or not-yet-valid certificates → FAIL. Near-expiry certificates → WARN / **EXPIRING SOON**.
- Expiration is checked using seconds, avoiding a false valid result for certificates expired less than 24 hours ago.
- Self-signed detection compares subject/issuer and verifies the self-signature.
- OpenSSL hostname/IP matching handles SANs and wildcard depth. SANs take precedence over CN. A valid CN without SAN generates a warning.
- A different CN and SAN is not inherently an error: what matters is whether the requested hostname is covered.

### 2. Protocol negotiation

Individually probes SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, and 1.3. Successful negotiation of a legacy protocol is **FAIL / DEPRECATED**. Modern protocol acceptance is PASS.

Legacy TLS probes lower the *probe client's* security level (`ALL:@SECLEVEL=0`), not the server's configuration. Only a negotiated protocol with a nonempty, non-`(NONE)` cipher counts as acceptance. Explicit peer rejection is distinct from an unavailable client feature, timeout, or inconclusive result.

**OpenSSL 3.x cannot test SSLv2/SSLv3.** These are WARN / not testable, never falsely reported as disabled. Incomplete coverage prevents a clean “modern only” conclusion. A missing modern version is a warning; no negotiated modern version produces a policy failure.

### 3. Weak ciphers and keys

- Offers available non-PSK suites from each family: NULL, RC4, 3DES, DES, EXPORT.
- Tests family offerings on TLS 1.0, 1.1 and 1.2; any accepted weak family is FAIL.
- TLS 1.3 is excluded from these probes because it ignores the legacy `-cipher` list.
- Removed/unavailable cipher families are WARN / **UNTESTED**.
- RSA <2048 bits is FAIL; EC <256 bits is WARN. Unknown algorithms/key sizes are not marked secure.
- Records the default negotiated key exchange; flags reported finite-field DH parameters <2048 bits.

This is **not an exhaustive cipher enumeration**, PSK audit, or a proof of cryptographic compliance. Removed algorithms cannot be tested by enabling a command-line flag alone. It does not install obsolete crypto libraries to bypass that limitation.

### 4. Chain, CA and revocation metadata

- Extracts the server's leaf and remaining certificates.
- Concatenates supplied intermediates into a PEM bundle and runs `openssl verify -purpose sslserver` against the trust store.
- A root certificate does **not** have to be sent by the server. Certificate count alone does not establish chain completeness.
- An unresolved issuer is labelled **UNTRUSTED / POSSIBLE MISSING INTERMEDIATE CHAIN**: a missing intermediate and an unavailable trust anchor may yield the same error.
- Reports stapled OCSP status, OCSP responder URI, and CRL distribution point presence.
- A stapled `Cert Status: revoked` is a FAIL, even when the OCSP response envelope itself says `successful`.

**Revocation limitation:** no CRL download or active OCSP query is performed. Staple signature, freshness and certificate binding are not independently verified. A “good” staple is reported as an observed response, not conclusive proof that the certificate is unrevoked. Missing stapling/CRL metadata is a review warning, not proof of a vulnerability.

## Reporting

```text
results/<first-target-host>/
├── tls_audit_summary.csv
├── tls_full_report.txt
└── tls_full_report_YYYYmmdd_HHMMSS.txt
```

CSV has 21 columns including host, port, verdict, CN, issuer, validity dates, days remaining, key size, certificate count, legacy/modern flags, weak-cipher results, negotiated cipher, OCSP/CRL metadata, and severity counts. Text reports contain separate module sections per endpoint. `-v` includes raw evidence. Reports are ANSI-free; colours are terminal-only.

- Green **PASS**: tested property satisfied.
- Yellow **WARN**: soft policy, expiry alert, or incomplete test coverage.
- Red **FAIL**: insecure observation, invalid certificate, failed trust validation, or unreachable TLS service.
- Cyan **INFO**: evidence/metadata.

Endpoint verdicts are `VULNERABLE` (any FAIL), `WARNING` (any WARN), or `PROTECTED` (no FAIL/WARN). These are tool labels, not exploitability claims. In particular, an unreachable endpoint is a failed audit, not evidence of a remotely exploitable flaw. With modern OpenSSL, unsupported legacy probes normally keep the overall verdict at least WARNING.

Parallelism is across endpoints. Each handshake is bounded by `timeout`; there is no single global scan deadline. Multiple handshakes may observe different load-balancer backends. Rerun unexpected results and validate against authoritative configuration.

## Validation

```bash
bash -n tlswatch.sh
shellcheck -S warning tlswatch.sh   # optional developer utility
./tests/run_tests.sh
```

Latest regression run: **59 PASS / 0 FAIL**. Development tests use Python 3's standard library and real OpenSSL-generated certificates with simulated network transcripts. Python is **not** needed to run TLSWatch. Tests cover certificate parsing and real CA verification, expiry, mismatches, wildcard depth, weak RSA, legacy protocol acceptance, NULL cipher detection, revocation flags, untestable/timeouts, input validation, list deduplication, and CSV/history output.

A separate integration run used a real local OpenSSL server restricted to TLS 1.2+ with a one-day self-signed certificate. Both modern handshakes succeeded; legacy versions were rejected; expiry/self-signed alerts fired.

`sample-output/` includes the live example.com snapshot and local test-server reports. These are time-specific observations, not enduring statements about domain security. The local private key is not included.
