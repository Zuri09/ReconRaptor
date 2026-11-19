# Verification playbook

How to turn a scanner candidate into a confirmed (or rejected) finding.

## Rule zero

ReconRaptor output is **triage**, not proof. Every item gets reproduced by hand before it
enters a report. Record both outcomes: a rejected candidate with its reason is useful.

## Reproduce with curl

Always capture status, size and a short body in one line:

```bash
curl -s -i 'https://target.example/path' \
  -H 'User-Agent: Mozilla/5.0' \
  --max-time 20 | sed -n '1,20p'
```

For POST bodies keep them in a file and use `--data-binary @file` so encoding survives.
Record the exact command in the report.

## Reproduce with Burp MCP

```
send_http1_request      -> run a raw request, returns request+response
create_repeater_tab     -> leave a ready-to-send tab for the user
get_proxy_http_history  -> inspect traffic already captured
send_to_intruder        -> only for non-brute-force payload sets
```

Raw requests need CRLF line endings and a correct `Content-Length`. If a request that works
in curl fails in Repeater, re-check the header block and the token for transcription errors.

## Always include a control

A finding is only credible when you show what changes when the key element is removed.

| Variant | Purpose |
|---|---|
| Full request | the exploit |
| Same request without the credential/header | proves the gate exists |
| Same request with a bogus credential | proves the credential is validated |
| Same request with the parameter removed | proves the parameter is required |

Example of a strong result pair:

- genuine key → `200`, success payload with data;
- bogus key → `200` envelope, `statusCode 999` failure; and
- no token → `401`.

That triple separates "public string that looks like a key" from "working credential".

## Evidence to save

Under `private/evidence/` (gitignored):

- raw request and raw response (encrypted, as sent),
- decrypted success output,
- decrypted control output,
- the exact command line used.

Do not save third-party personal data, tokens in plaintext reports, or account numbers.

## False-positive families (check before spending time)

- **CORS**: `Access-Control-Allow-Origin: *` on a static CDN file, or reflection on a host
  that is a CNAME to a third party (Branch, BillDesk, CDNJS) with no
  `Access-Control-Allow-Credentials` and no data-bearing response.
- **Exposed file**: F5/BIG-IP or Varnish "Request Rejected"/"Access Denied" page returned
  with HTTP 200 for any path. Compare against a deliberately nonexistent control path — if
  the body is identical besides the support ID, it is a WAF page, not a file.
- **Subdomain takeover**: `subzy`/`subjack` flags without a dangling CNAME or a claimable
  third-party service. Check DNS: an A record to a provider-owned IP is not claimable.
- **JS secrets**: `lblPassword: "Password"` labels, base64 inside `data:image/png`,
  JSEncrypt's own PEM header strings, bare `amazonaws.com`/`firebaseio` strings with no
  bucket name or config.
- **TLS**: expired certificates on dead/UAT hosts are hygiene, not a vulnerability.
- **Open redirect**: parameter names in third-party mail-protection or SSO URLs
  (`safelinks.protection.outlook.com`) are not the target's redirect.

## When verification is impossible

If the test needs a valid account, token, or another person's data, stop. Write it as a lead
with the exact reason it is unconfirmed. Do not guess, enumerate, or simulate data you do
not own.
