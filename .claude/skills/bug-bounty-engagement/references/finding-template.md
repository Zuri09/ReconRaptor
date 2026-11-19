# <Finding title — specific, not "IDOR on API">

## Metadata

- Asset / endpoint:
- Vulnerability class / CWE:
- CVSS 3.1 vector:
- Requested severity:
- Status: draft / submitted / accepted / rejected / duplicate
- Report ID:

## Summary

One paragraph: what is broken, where, and who can exploit it.

## Attack scenario

Attacker → prerequisite → action → victim/business impact. Be concrete:

> An unauthenticated attacker who knows a customer email sends one request to
> `POST /gateway` and overwrites that customer's marketing consent, clearing an explicit
> opt-out. No login, token, or interaction from the customer is required.

## Why this is not informational

State the concrete security consequence. If this line is weak, the finding is a DROP.

## Root cause

The missing check, trust boundary, or design flaw.

## Prerequisites

Authentication, knowledge of an identifier, user interaction, timing, rate limits.

## Reproduction

### Control

```http
<benign request>
```

### Payload

```http
<exploit request>
```

Observed difference: `<status/body/state change>`

## Impact

- Confidentiality:
- Integrity:
- Availability:
- Users affected:
- Business effect:

## Evidence

- `evidence/<ID>/control.request` / `.response`
- `evidence/<ID>/payload.request` / `.response`
- `evidence/<ID>/repro.sh`
- Screenshots / video:
- Redactions applied:

## Remediation

Specific, actionable fixes. Not "sanitize input".

## Clean-up

What was created or changed, and how it was restored.

## Triage review

- Saved to `triage/<finding-id>.md` with `reviewer: bounty-triage` and `verdict: SUBMIT`
  (the pre-submit hook requires this before `private/submissions/<finding-id>.md` can be
  written).
- Verdict: SUBMIT / NEEDS_EVIDENCE / DROP
- Confidence:
- Expected triage / bounty:
- Strongest counterargument:
- Reviewer notes:
