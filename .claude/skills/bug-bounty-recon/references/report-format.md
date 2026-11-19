# Report format and severity

Most programmes use a form with fixed fields. Fill every field; put detail inside the field,
not in extra sections. Typical field order (Bugbase-style):

1. **Title** — one sentence: asset + flaw + consequence.
2. **Select a target** — programme name (e.g. "Main Wildcard").
3. **Specific target URL** — one URL on the in-scope domain.
4. **Vulnerability Type** — the dropdown class, plus CWE if "Other".
5. **Select Severity Method** — CVSS 3.1.
6. **Tools used** — curl, Python, OpenSSL, Burp Suite.
7. **Description** — what the asset is, where it lives (file + line), how it is used, why it
   matters, and what was demonstrated. Include the exact mechanism, not just the outcome.
8. **Steps to Reproduce** — numbered, with exact requests/responses, a control table, then
   **Expected Result** and **Actual Result**.
9. **Potential Impact** — demonstrated impact first, then plausible impact clearly labelled,
   then an explicit "not claimed" paragraph.
10. **Recommendation** — immediate containment, short-term fix, long-term structural fix.
11. **Upload Proof Of Concept** — short screen recording (MP4/WebM): public source → request
    → decrypted result → controls. Redact tokens/cookies; the public key needs no redaction.
12. **Additional Information** — scope and conduct, scope of testing, artefacts available,
    related reports, credential status, date.
13. **PII disclosure** — No unless you actually accessed it; leave unchecked.

## Severity

Use CVSS 3.1 and map to the programme's bands (P1–P5). Be precise about the vector:

- `AC:L` only if no special condition is needed; `AC:H` when a captured request or log access
  is required.
- `PR:N` only if no account exists anywhere in the chain.
- `C:L` when the data returned is public/non-sensitive; do not inflate to `C:H`.
- Business impact (quota, cost, SMS abuse) belongs in the Impact section, not silently in
  the CVSS vector.
- Requested band may be lower than the CVSS score if the programme's policy treats a class
  as informational — say so explicitly.

## Writing rules

- **Demonstrated vs suspected** must be visibly separate. Never write "can" for something
  you did not do.
- Include the **control** results in Steps to Reproduce — they are what make a credential
  finding credible.
- One finding per report. Related findings get their own report and a cross-reference line.
- Redact secrets, tokens, cookies, IPs and PII. Put live values in a gitignored `private/`
  file and paste them only into the submission form.
- Keep a local status line per report: prepared → submitted → triage response, with date and
  report ID when known.

## Triage bookkeeping

Keep a short table in the project docs:

| # | Finding | Severity | State | Report ID |
|---|---|---|---|---|

Update it as responses arrive. A duplicate-class report filed after an earlier one is more
likely to be closed as informative — check what is already submitted before writing.
