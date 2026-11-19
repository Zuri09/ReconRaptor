# Vulnerability checklist

Smallest safe test per class, what actually proves it, and the usual false positive.
Apply only within the programme's scope and exclusions.

## Remote code execution (RCE)
- **Test:** look for file-write + execute chains already exposed (upload endpoints, deserialization, template engines, command parameters). Prefer a harmless proof (`id`, `whoami`, DNS callback to your own collaborator).
- **Proves it:** command output or an out-of-band interaction you can attribute to your payload.
- **FP:** reflected input that merely appears in an error page.

## Server-side injection (SSTI, SQLi, command, NoSQL, PHP object injection)
- **Test:** arithmetic/boolean/time probes with a control value; single quote vs doubled quote; `{{7*7}}` vs literal; JSON operator injection (`$ne`, `$gt`) in login/filter bodies.
- **Proves it:** differential response between true/false or matched/unmatched pairs, reproduced twice.
- **FP:** generic 500s, WAF blocks, or cached responses that do not change with the control.

## File access / manipulation (LFI, RFI, XXE, SSRF, XSPA)
- **Test:** path parameters with `../`, absolute paths, `file://`; XML endpoints with an external entity pointing at *your own* collaborator; URL parameters with `http://<your-host>`.
- **Proves it:** file contents, a callback from the target's egress, or a response that contains your fetched resource.
- **FP:** error pages that echo the parameter; redirects that never leave the app.

## Cross-site scripting (XSS)
- **Test:** reflection probes with characters that need encoding (`<>"'`); DOM sinks (`innerHTML`, `document.write`, `eval`) fed by `location.*`/`referrer`/`postMessage`.
- **Proves it:** execution in a browser (screenshot/video), not just reflection.
- **FP:** input reflected inside a JSON body with `Content-Type: application/json`, or escaped output.

## CSRF with real impact
- **Test:** state-changing request without anti-CSRF token, with `SameSite=None` cookies or cookie-based auth.
- **Proves it:** a cross-origin page that completes a sensitive change.
- **FP:** actions with no security impact, or endpoints that also require a non-cookie header.

## IDOR / BOLA
- **Test:** change an object identifier you own to one you do not (use two of your own test objects where possible).
- **Proves it:** access to the other object's data with a differential response.
- **FP:** endpoints returning the same generic shell for every id (check the body, not the status).

## CORS with real impact
- **Test:** send `Origin: https://evil.example` and `Origin: null`; check for reflection plus `Access-Control-Allow-Credentials: true` on a data-bearing endpoint.
- **Proves it:** a browser-readable authenticated response for a foreign origin.
- **FP:** wildcard CORS on static assets, third-party CDN files, or reflection without credentials.

## Horizontal / vertical privilege escalation
- **Test:** perform a low-privilege action with a higher-privilege object, or access admin routes with a normal session.
- **Proves it:** the privileged action succeeds.
- **FP:** client-side hiding of a link while the API correctly rejects.

## Business logic
- **Test:** negative quantities, zero-value orders, currency/rounding changes, coupon stacking, step-skipping in multi-step flows.
- **Proves it:** a state change that benefits the attacker (price, balance, entitlement).
- **FP:** validation happening on the next step.

## Exposed secrets / credentials / sensitive information
- **Test:** JS bundles, source maps, config files, `.well-known`, error payloads, internal hostnames/IPs, verbose stack traces.
- **Proves it:** the secret is live and usable for something (validate with a control where safe).
- **FP:** placeholder strings, UI labels, base64 images, library constants.

## Authentication bypass / broken access control
- **Test:** missing-auth on a parallel route, method swap (GET vs POST), path casing/encoding, header trust (`X-Forwarded-*`, `X-Original-URL`), token/parameter confusion.
- **Proves it:** a protected response without the credential, or a credential for a different principal.
- **FP:** a public endpoint that simply looks protected.

## Cache poisoning / race conditions / algorithmic complexity
- **Test:** unkeyed headers reflected into cacheable responses; concurrent requests on single-use logic; inputs with pathological parsing cost.
- **Proves it:** a poisoned cache entry served to a second client, or a duplicated effect from concurrency.
- **FP:** "no rate limit" alone — only report when it produces a concrete abuse (cost, SMS, state).
- **Never** run volumetric or sustained load.

## User enumeration
- **Test:** differential responses on login/forgot-password/registration for existent vs nonexistent identifiers.
- **Only report** if it is unintended and not clearly public; a "registered email" check in a forgot-password form is often by design.
- **FP:** timing noise; re-test several times before concluding.

## Open redirect
- **Test:** `next`, `return`, `url`, `redirect`, `continue` parameters with an external host; try scheme-relative `//evil.example` and encoded variants.
- **Proves it:** the response redirects to a host you control.
- **FP:** third-party mail-protection URLs; redirects restricted to the same registrable domain.
