# Class coverage — <asset>

Update this after every class. `N/A` is only valid with a reason (e.g. no XML parser, no
file upload surface). No class may be skipped silently.

| Class | Reference | Applicable | Tests run | Result | Evidence ID | Notes |
|---|---|---|---|---|---|---|
| SQLi | `injection/sql-injection.md` | | | | | |
| NoSQLi | `injection/nosql-injection.md` | | | | | |
| OS command | `injection/os-command-injection.md` | | | | | |
| SSTI | `injection/server-side-template-injection.md` | | | | | |
| XXE | `injection/xxe.md` | | | | | |
| XSS (reflected/stored/DOM) | `client-side/xss.md` | | | | | |
| CSRF | `client-side/csrf.md` | | | | | |
| Clickjacking | `client-side/clickjacking.md` | | | | | |
| DOM | `client-side/dom-based-vulnerabilities.md` | | | | | |
| CORS | `client-side/cors.md` | | | | | |
| WebSockets | `client-side/websockets.md` | | | | | |
| Prototype pollution | `client-side/prototype-pollution.md` | | | | | |
| Access control / IDOR / BOLA | `server-side/access-control.md` | | | | | |
| Authentication | `server-side/authentication.md` | | | | | |
| Business logic | `server-side/business-logic.md` | | | | | |
| Information disclosure | `server-side/information-disclosure.md` | | | | | |
| Path traversal / LFI | `server-side/path-traversal.md` | | | | | |
| File upload / RFI | `server-side/file-upload.md` | | | | | |
| SSRF / XSPA | `server-side/ssrf.md` | | | | | |
| Request smuggling | `server-side/request-smuggling.md` | | | | | |
| Web cache poisoning | `server-side/web-cache-poisoning.md` | | | | | |
| Web cache deception | `server-side/web-cache-deception.md` | | | | | |
| Host header | `server-side/host-header-attacks.md` | | | | | |
| Deserialization | `server-side/deserialization.md` | | | | | |
| API testing | `api/api-testing.md` | | | | | |
| GraphQL | `api/graphql.md` | | | | | |
| JWT | `api/jwt.md` | | | | | |
| OAuth | `api/oauth.md` | | | | | |
| Race conditions | `other/race-conditions.md` | | | | | |
| LLM / AI | `other/llm-attacks.md` | | | | | |
| Essential skills | `other/essential-skills.md` | | | | | |

## Status key

- `tested-clean` — probes sent, control matched, no signal.
- `tested-signal` — a difference was found; see evidence ID.
- `N/A` — surface absent; write the reason.
- `blocked` — WAF/auth/scope prevented testing; write why.
