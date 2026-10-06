"""Two stages: Auditor (risk assessment) and Remediation (what to do)."""
import json
import os
import re

MODEL = os.environ.get("PURRGUARD_MODEL", "claude-sonnet-4-6")  # check the current name in Anthropic's documentation

AUDITOR = ("You are a security Auditor agent. You receive results from a steganography scanner. "
           "For each finding: briefly explain what it means, assess false-positive likelihood, "
           "and give overall risk (Critical/High/Medium/Low). Do not invent facts outside the data. "
           "A finding with analyzer `honeytoken` is certain evidence of exfiltration (no false positive). Format: markdown.")
REMEDIATOR = ("You are a Remediation agent. Based on the report, give a concrete checklist: "
              "how to sanitize the file, which keys to rotate (for GCP service account: "
              "`gcloud iam service-accounts keys disable/delete`), who to notify. Short, numbered.")


def redact(text: str) -> str:
    """Never sends real secrets to external APIs."""
    return re.sub(r"(AKIA|AIza|glpat-|sk-ant-)[\w\-]+", r"\1***", text)


def _fallback(results):  # without API: just a list of findings
    lines = [f"- **{f['file']}** — {f['severity']}: {f['detail']}" for f in results["findings"]]
    return "\n".join(lines) or "No findings."


def _ask(system, user):
    import anthropic
    client = anthropic.Anthropic()
    msg = client.messages.create(model=MODEL, max_tokens=1000, system=system,
                                 messages=[{"role": "user", "content": user}])
    return "".join(b.text for b in msg.content if b.type == "text")


def analyze(results, playbook=""):
    payload = redact(json.dumps(results["findings"], ensure_ascii=False, indent=2))
    base_plan = "1. Sanitized files are prepared in an automatic fix MR.\n2. Rotate all keys that were accessible.\n3. Notify the security team."
    if os.environ.get("PURRGUARD_MOCK") == "1" or not os.environ.get("ANTHROPIC_API_KEY"):
        return _fallback(results), base_plan + ("\n\n" + playbook if playbook else "")
    audit = _ask(AUDITOR, payload)
    plan = _ask(REMEDIATOR, audit + "\n\nReady rotation plan (include it without changing the commands):\n" + playbook)
    return audit, plan
