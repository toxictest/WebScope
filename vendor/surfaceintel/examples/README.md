# Example reports

`controlled-local/` contains generated complete, repeat and DNS-failure/partial scans from the automated test harness. DNS names under `.example.test` were mocked; HTTP/HTTPS/IPv6 and webhook services were owned local test services. Cloud provider classifications were tested separately using synthetic metadata, not real customer resources.

Ephemeral ports, certificate dates, scope/policy digests and timestamps are genuine test-run values. They do not describe the user's infrastructure, a public organization or a live cloud tenant. Raw page content, cookies, TXT values, webhook tokens and private keys are absent. No fixture certificate private key is packaged.

The partial sample demonstrates that unavailable DNS does not establish asset removal and does not replace the successful baseline. JSON samples follow `schemas/`; TSV state uses the documented state format.
