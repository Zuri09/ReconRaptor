# Login-page and JavaScript crypto analysis

What to extract from first-party JavaScript, and how to decide whether it is a finding.

## 1. Build the JS inventory

For each authentication or sensitive page (`/login`, `/signin`, `/user/login`, `/oauth`,
`/sprint/`, apply/rewards flows), list the scripts it loads, then download each one and keep
the source URL next to the local copy. Record `sourceMappingURL` comments separately.

```bash
curl -s 'https://target.example/login' | grep -oE 'src="[^"]+\.js[^"]*"' | sort -u
curl -s 'https://target.example/static/js/main.<hash>.chunk.js' -o app.js
```

Check for public source maps — they often contain the full unminified source:

```bash
curl -s 'https://target.example/static/js/main.<hash>.chunk.js.map' -o app.map
python3 - <<'PY'
import json
m=json.load(open('app.map'))
print(len(m.get('sources',[])),'sources')
for s,c in zip(m.get('sources',[]),m.get('sourcesContent',[])):
    if c and 'encrypt' in c.lower(): print('HIT',s)
PY
```

## 2. Search for crypto and credential material

Patterns worth grepping in downloaded bundles:

```
CryptoJS  PBKDF2  AES.encrypt  AES.decrypt  mode.CBC  pad.Pkcs7  iterations
JSEncrypt  RSA  forge  sjcl  btoa(  atob(
passphrase  secret  apiKey  api_key  x-api-key  sk_  Bearer  Authorization
tokenGen  oauth  /token  client_id  client_secret
```

## 3. Reconstruct the scheme

For every encrypt/decrypt helper, answer:

- cipher, mode, padding;
- key derivation (algorithm, iteration count, key size);
- salt and IV generation and **wire format** (e.g. `salt hex + iv hex + base64`);
- **where the passphrase comes from** — hardcoded constant, hidden form field, server
  response, URL/path segment, partner code, or `process.env` inlined at build time;
- whether the server response is encrypted with the same scheme.

Reimplement it in a small script (Python + the `openssl` CLI is enough) so requests can be
built and responses decrypted without a browser.

## 4. Classify the result

| Pattern | Assessment |
|---|---|
| Passphrase hardcoded in a public bundle | Application-layer encryption is reversible by anyone; it protects nothing beyond TLS. Report as a hardcoded-key/information-disclosure issue, with the key's use sites. |
| Passphrase transmitted with the ciphertext (hidden field, header, body) | Same effect plus a logging problem: a body-only log is decryptable. |
| Fallback default key when the expected field is missing or misspelled | The fallback becomes the de-facto key; check for `#passphase` vs `#passphrase` style mismatches. |
| Token endpoint whose `cname`/param doubles as the AES passphrase | Anonymous token issuance is reproducible from public values; test whether the token unlocks other resources. |
| Public source maps with `sourcesContent` | Full front-end source and API surface disclosed; also gives you exact request contracts for later testing. |
| Key validated by the backend | This is the strong case: prove it with a bogus-credential control, then state impact as working-credential, not "public string". |

## 5. Extract API contracts from source maps

Source maps are the cheapest way to get exact request shapes for blackbox testing. Look for
service modules and endpoint constants:

```
services/*.Service.js        request bodies, headers, header identifiers
shared/ServiceCommonEndpoints.js   complete endpoint list
shared/axios.js              interceptors (which requests get encrypted)
```

Use the recovered contract to send one minimal request per endpoint, never to enumerate.

## 6. Test safely

- Dummy credentials, dummy identifiers, one request per variant.
- Never use a real customer/account number unless it is yours; never test another person's
  data even if triage "allows real data".
- Do not submit applications, upload files, or create records unless the programme has
  explicitly approved that write and you can do it with your own data.
- Capture encrypted request/response and the decrypted output as evidence.
