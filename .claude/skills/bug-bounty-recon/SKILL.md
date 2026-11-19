---
name: bug-bounty-recon
description: Authorized bug-bounty workflow — run ReconRaptor on a domain, triage and manually verify its output with curl or Burp, audit login pages and JavaScript for crypto/secrets, test the standard vulnerability classes, and produce a severity-sorted report. Use when asked to recon or pentest a domain, run ReconRaptor, check scan output for vulnerabilities, analyze login-page JavaScript, or write up findings.
---

# Bug-bounty recon and verification

End-to-end workflow: ReconRaptor scan → manual triage and verification → login/JS crypto
review → vulnerability-class checklist → severity-sorted report.

## Authorization gate (check first)

- Only operate on domains the user is explicitly authorized to test (programme scope,
  engagement letter, or their own asset).
- Read the programme's exclusions before scanning and apply them with
  `--exclude-file` so out-of-scope subdomains are never touched.
- Never test third-party SaaS/CDN hosts that appear in the scan.
- Refuse or stop if scope is unclear. Confirm before any write action or account flow.

---

## Step 1 — Run the scan

```bash
cd <repo>/ReconRaptor
./reconraptor.sh -d example.com
```

Useful flags: `--exclude-file <file>` (out-of-scope subdomains), `--keep-evidence` (retain
raw validator responses), `--ai` + `--ai-provider` (triage aid only, never proof).

Output lands in `recon_<domain>/`. When it finishes, read `START_HERE.md` first — it lists
the report files and counts. Do not treat any scanner output as a finding yet.

## Step 2 — Triage the output, then verify by hand

Read, in this order:

1. `recon_<domain>/START_HERE.md` — inventory and counts.
2. `reports/findings/confirmed_findings.json` — validator "confirmed" items. **These are
   candidates, not findings.**
3. `reports/urls/` — `smart_sensitive_files.json`, `smart_secret_urls.json`,
   `url_info_disclosure.txt`.
4. `reports/js/` — `js_secret_summary.txt`, `genuine_leaks.json`, `generic_api_keys.json`,
   `js_vulnerability_findings.json`.
5. `reports/pd/` — nuclei and TLS output.
6. `reports/candidates/` — open redirect, sensitive file, CORS, GraphQL, bucket lists.
7. `raw/` — `subdomains.txt`, `resolved_subdomains.txt`, `urls.txt`, `js_files.txt`.

Then reproduce every candidate manually with `curl` or the Burp MCP tools (see
`references/verification.md`). Rules:

- **Default every scanner item to false positive until you reproduce it.**
- Record the reason each item was rejected; a rejected lead is still useful output.
- Check the usual false-positive families before spending time: third-party CORS/CDN hosts,
  WAF "Request Rejected" pages served with HTTP 200, PWA manifests, subdomain-takeover
  flags with no dangling CNAME, base64-image strings matched as "AWS keys", UI labels
  matched as "passwords", expired certificates (hygiene, not a finding).

## Step 3 — Login pages and JavaScript

Find the authentication surface: `/login`, `/signin`, `/user/login`, `/oauth`, `*token*`,
`sso?`, `*.ajax`, and every JS bundle those pages load.

For each login bundle and auth helper:

1. Download it and map which URL it came from.
2. Search for crypto and secrets: `CryptoJS`, `PBKDF2`, `AES.encrypt|decrypt`, `JSEncrypt`,
   `RSA`, `forge`, `btoa(`, `secret`, `passphrase`, `apiKey`, `api_key`, `sk_`, `Bearer`,
   `token`, `sourceMappingURL`.
3. Reconstruct any client-side encryption: cipher, mode, padding, iteration count, salt/IV
   format, and **where the passphrase comes from**.
4. Classify what you find:
   - hardcoded key/passphrase in a public bundle → working-credential candidate;
   - passphrase transmitted alongside the ciphertext → defeats the encryption;
   - fallback default key when the expected field is missing/misspelled → same;
   - public source maps with `sourcesContent` → full source and endpoint disclosure;
   - token endpoints whose parameter doubles as the encryption passphrase.
5. Test only with dummy credentials/values and one request. See
   `references/js-crypto-analysis.md` for the procedure and the evidence to capture.

## Step 4 — Vulnerability review checklist

Work through the programme's classes against the collected URLs. For each: try the smallest
safe test, then prove it with a control. Full techniques in `references/vuln-checklist.md`.
For lab-proven payloads, bypasses and exploitation chains per class, use the
`web-pentest-skills` skill — it is nested by category and vulnerability and covers all 273
PortSwigger Academy labs. The checklist here is the triage order; that skill is the
exploitation detail.

- Remote code execution (RCE)
- Server-side injection: SSTI, SQLi, command/NoSQL, PHP object injection
- File access/manipulation: LFI, RFI, XXE, SSRF, XSPA
- Cross-site scripting (reflected, stored, DOM)
- CSRF with real security impact
- IDOR / BOLA
- CORS with real security impact (credentials, data-bearing origin reflection)
- Horizontal and vertical privilege escalation
- Business-logic errors
- Exposed secrets, credentials, sensitive information
- Authentication bypass and broken access control
- Cache poisoning, race conditions, algorithmic-complexity issues (no volumetric DoS)
- User enumeration (only if unintended or not public by design)
- Open redirection

Not in scope by default: DoS/DDoS, brute force, credential stuffing, social engineering,
third-party platform vulnerabilities, clickjacking without sensitive action.

## Step 5 — Report, most critical first

Produce a prioritized list, then a full report per finding. Order by severity, and within a
severity by exploitability (confirmed > unconfirmed, no-account > needs-account).

For each finding record: title, target, vuln class + CWE, CVSS 3.1 vector, what was
confirmed vs not, reproduction steps, evidence, impact, remediation.

Report format, severity guidance and wording: `references/report-format.md`.

Rules that make a report credible:

- Separate **demonstrated** from **suspected**; never claim impact you did not observe.
- Include **controls** — the same request with the credential removed or replaced by a
  bogus value. A `200` alone proves nothing; a `200` for the real credential and a rejection
  for the bogus one proves the credential is validated.
- One benign request per test; no enumeration, no sustained querying.
- Redact tokens, cookies, PII and account numbers. Never use another person's data.

## Cross-cutting rules

- Secrets and live values go in `private/` (gitignored). Never commit a live key; never write
  it into a published docs folder.
- Keep raw evidence (encrypted + decrypted request/response) under `private/evidence/`.
- Stop when the surface is exhausted; a clean "nothing else" is a valid result.
- If triage denies accounts, remain blackbox: use only the user's own data, and drop leads
  that need a valid account rather than guessing.

## Burp MCP quick reference

If Burp's MCP server is configured (`http://127.0.0.1:9876/mcp`), reconnect with `/mcp`.
Useful tools: `send_http1_request`, `create_repeater_tab`, `create_repeater_tab_http2`,
`get_proxy_http_history`, `get_proxy_http_history_regex`, `send_to_intruder`,
`url_encode`/`url_decode`, `base64_encode`/`base64_decode`.

If it failed at session start with `ECONNREFUSED`, the server was not up when the session
began — start Burp with the MCP extension, then `/mcp` → reconnect (tools load mid-session).
