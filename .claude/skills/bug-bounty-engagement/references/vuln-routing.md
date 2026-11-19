# Vulnerability routing — web-pentest-skills

Base path for the technique library:

```
.claude/skills/web-pentest-skills/references/
```

Use this file as the bridge between an observed signal and the exact technique file. The
engagement skill handles scope, state, evidence, triage, and reporting; this library
handles payloads, bypasses, and exploit shape.

## Field guides (2026 writeups)

Use these before or alongside the class files:

- `../../web-pentest-skills/references/field-techniques-2026.md` — SSRF, exposed Google/API
  keys, IIS shortname, SQLmap/Ghauri WAF bypass, auth/session, mass assignment,
  registration bugs, Spring Boot Actuator, blind/clipboard XSS, WordPress/XML-RPC, cache
  deception, Swagger UI, SQLi recon, CRLF, host header, email input, 403 bypass,
  Cloudflare/WAF bypass, S3 recon, ffuf, Nuclei, Wayback, origin IP, fast XSS.
- `field-methodology-2026.md` — chaos/httpx/naabu/nmap, ffuf, Nuclei, Wayback CDX,
  origin-IP discovery, S3 recon, fast-XSS and SQLi pipelines.

## Route by signal

| What you see / control | Start here |
|---|---|
| Quote makes the app error; numeric parameter changes results | `injection/sql-injection.md` |
| JSON accepts objects; `$ne`, `$regex`, `$where` appear | `injection/nosql-injection.md` |
| Stock checker, feedback form, or filename reaches a shell | `injection/os-command-injection.md` |
| Input rendered by a template engine; `7*7` returns `49` | `injection/server-side-template-injection.md` |
| XML body, SOAP, SAML, SVG upload, "check stock" XML | `injection/xxe.md` |
| Input appears in HTML, an attribute, JS string, or DOM sink | `client-side/xss.md` |
| State-changing request has no unpredictable token | `client-side/csrf.md` |
| Sensitive action is one click away and framing is allowed | `client-side/clickjacking.md` |
| `postMessage`, `location.hash`, `document.write`, DOM clobbering | `client-side/dom-based-vulnerabilities.md` |
| `Access-Control-Allow-Origin` reflects your origin / `null` | `client-side/cors.md` |
| Live chat over `ws://`; handshake has no CSRF token | `client-side/websockets.md` |
| JSON merge/query parser accepts `__proto__` or `constructor` | `client-side/prototype-pollution.md` |
| Object IDs, GUIDs, `/admin`, role parameters, cookie role flags | `server-side/access-control.md` |
| Login, 2FA, password reset, remember-me, rate limits | `server-side/authentication.md` |
| Cart, coupons, checkout, registration, role selection, price fields | `server-side/business-logic.md` |
| Stack traces, debug pages, `.git`, backups, `robots.txt` | `server-side/information-disclosure.md` |
| `filename=`, image/file path, download endpoint | `server-side/path-traversal.md` |
| Avatar/file upload with type or extension checks | `server-side/file-upload.md` |
| URL/fetch parameter, stock API, image import, webhook | `server-side/ssrf.md` |
| Front-end/back-end disagreement, `CL`/`TE`, HTTP/2 downgrade | `server-side/request-smuggling.md` |
| Cache `X-Cache`, unkeyed headers/cookies/params, `X-Forwarded-Host` | `server-side/web-cache-poisoning.md` |
| Cache stores private pages by extension/delimiter confusion | `server-side/web-cache-deception.md` |
| `Host` header, password-reset links, routing, absolute URLs | `server-side/host-header-attacks.md` |
| Serialized cookie, `O:`, `rO0`, `BAh`, Marshal, PHAR | `server-side/deserialization.md` |
| `/api`, docs, hidden endpoints, mass assignment, `OPTIONS` | `api/api-testing.md` |
| `/graphql`, introspection, aliases, mutations | `api/graphql.md` |
| `eyJ...` JWT, `alg`, `kid`, `jwk`, `jku` | `api/jwt.md` |
| `client_id`, `redirect_uri`, `response_type`, OAuth callback | `api/oauth.md` |
| Duplicate/replayed requests change outcome; single-packet timing | `other/race-conditions.md` |
| Chatbot, AI scanner, tool-calling agent, review ingestion | `other/llm-attacks.md` |
| Need to find the class fast, or a non-standard input location | `other/essential-skills.md` |

## Class → reference file

| Class | File | Minimum proof |
|---|---|---|
| SQLi | `injection/sql-injection.md` | differential query, not just an error |
| NoSQLi | `injection/nosql-injection.md` | object/operator accepted |
| OS command | `injection/os-command-injection.md` | `whoami`/DNS interaction |
| SSTI | `injection/server-side-template-injection.md` | `49` from `7*7` |
| XXE | `injection/xxe.md` | one file read or OAST |
| XSS | `client-side/xss.md` | `alert(1)` in a victim context |
| CSRF | `client-side/csrf.md` | state change without a token |
| Clickjacking | `client-side/clickjacking.md` | framed sensitive action |
| DOM | `client-side/dom-based-vulnerabilities.md` | sink reached from source |
| CORS | `client-side/cors.md` | reflected origin + credentials |
| WebSockets | `client-side/websockets.md` | cross-origin message effect |
| Prototype pollution | `client-side/prototype-pollution.md` | polluted property/gadget |
| Access control | `server-side/access-control.md` | another user's object/action |
| Authentication | `server-side/authentication.md` | bypass or takeover |
| Business logic | `server-side/business-logic.md` | real financial/state impact |
| Information disclosure | `server-side/information-disclosure.md` | sensitive data, not just a banner |
| Path traversal | `server-side/path-traversal.md` | file read/write |
| File upload | `server-side/file-upload.md` | executable/active file |
| SSRF | `server-side/ssrf.md` | internal fetch or OAST |
| Request smuggling | `server-side/request-smuggling.md` | queue effect |
| Cache poisoning | `server-side/web-cache-poisoning.md` | poisoned cache effect |
| Cache deception | `server-side/web-cache-deception.md` | private page cached |
| Host header | `server-side/host-header-attacks.md` | reset link/route effect |
| Deserialization | `server-side/deserialization.md` | gadget/RCE proof |
| API testing | `api/api-testing.md` | hidden endpoint/field |
| GraphQL | `api/graphql.md` | schema/auth field bypass |
| JWT | `api/jwt.md` | forged token accepted |
| OAuth | `api/oauth.md` | code/token theft or redirect abuse |
| Race conditions | `other/race-conditions.md` | duplicated effect |
| LLM attacks | `other/llm-attacks.md` | cross-user action/disclosure |
| Essential skills | `other/essential-skills.md` | non-standard input reached |

## Universal testing loop (use for every class)

1. **Map the surface.** Every parameter, header, cookie, JSON key, path segment, file input.
2. **Fingerprint.** Provoke an error or harmless arithmetic to learn the stack.
3. **Smallest probe.** One quote, one `{{7*7}}`, one `<b>`, one OAST host.
4. **Control.** Re-send with a benign value; compare status, length, timing, body, cache.
5. **Escalate one step.** Detection → read → write → execution → persistence.
6. **Adapt to defenses.** Encoding, context, protocol, transport before declaring "safe".
7. **Record evidence.** Request/response pair, control, timestamp, payload, what it proves.

## Rules

- Open the reference file **before** sending payloads for that class.
- Use the smallest proof; stop at the first level that proves impact.
- Do not run lab destructive commands (`rm`, account deletion, mass exfiltration) on a live
  target. Replace them with `whoami`, a marker, or a DNS interaction.
- OAST payloads only to a domain you control; never a third party.
- Keep live secrets in `private/`; redact them in reports.
- If a class is not applicable, record why in `notes/class-coverage.md`.
