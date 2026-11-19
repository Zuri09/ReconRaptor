#!/usr/bin/env python3
"""PreToolUse guard: block new submission writes without a SUBMIT triage verdict.

Gated paths:
  - <repo>/private/submissions/*.md
  - <repo>/private/*submission*.md
  - <repo>/private/*report-final*.md

A gated write is allowed only if a triage file for the same finding id exists and
contains both:
  reviewer: bounty-triage
  verdict: SUBMIT

Triage file lookup (first match wins):
  <repo>/triage/<id>.md
  <repo>/private/triage/<id>.md
  <submission-dir>/<id>.triage.md
  <submission>.triage.md
  <repo>/recon_*/triage/<id>.md
  <cwd>/triage/<id>.md

All other writes are untouched (exit 0, no output).
"""
import glob
import json
import os
import re
import sys


def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return  # malformed input: do not interfere

    if payload.get("tool_name") != "Write":
        return

    file_path = (payload.get("tool_input") or {}).get("file_path") or ""
    if not file_path:
        return

    cwd = payload.get("cwd") or os.getcwd()
    path = os.path.abspath(os.path.join(cwd, file_path)) if not os.path.isabs(file_path) else os.path.abspath(file_path)
    norm = path.replace("\\", "/")
    base = os.path.basename(norm)
    lower_base = base.lower()

    gated = (
        "/private/submissions/" in norm
        or (
            "/private/" in norm
            and lower_base.endswith(".md")
            and (
                "submission" in lower_base
                or "report-final" in lower_base
                or "final-report" in lower_base
            )
        )
    )
    if not gated:
        return

    stem = os.path.splitext(base)[0]
    sub_dir = os.path.dirname(norm)
    private_dir = os.path.dirname(sub_dir)
    repo_dir = os.path.dirname(private_dir)

    candidates = [
        os.path.join(repo_dir, "triage", stem + ".md"),
        os.path.join(private_dir, "triage", stem + ".md"),
        os.path.join(sub_dir, stem + ".triage.md"),
        norm + ".triage.md",
        os.path.join(cwd, "triage", stem + ".md"),
    ]
    candidates += glob.glob(os.path.join(repo_dir, "recon_*", "triage", stem + ".md"))
    candidates += glob.glob(os.path.join(cwd, "recon_*", "triage", stem + ".md"))

    triage_path = next((p for p in candidates if os.path.isfile(p)), None)
    if not triage_path:
        deny(
            "Blocked: no triage review for '{0}'. Save the bounty-triage reviewer output to "
            "triage/{0}.md with 'reviewer: bounty-triage' and 'verdict: SUBMIT' before "
            "writing a submission.".format(stem),
        )

    try:
        content = open(triage_path, encoding="utf-8", errors="ignore").read()
    except Exception as exc:
        deny( "Blocked: triage file {0} could not be read: {1}".format(triage_path, exc))

    normalized = content.lower().replace("*", "").replace("`", "").replace("_", " ")
    has_reviewer = re.search(r"reviewer\s*:\s*bounty-triage\b", normalized) is not None
    has_submit = re.search(r"verdict\s*:\s*submit\b", normalized, re.MULTILINE) is not None

    if not (has_reviewer and has_submit):
        missing = []
        if not has_reviewer:
            missing.append("reviewer: bounty-triage")
        if not has_submit:
            missing.append("verdict: SUBMIT")
        deny(
            "Blocked: triage file {0} is missing {1}. A submission needs the "
            "bounty-triage reviewer's SUBMIT verdict.".format(triage_path, " and ".join(missing)),
        )

    # Deny-only guard: a valid SUBMIT verdict lets the normal permission flow continue.
    # The hook never grants permission itself.
    return


if __name__ == "__main__":
    main()
