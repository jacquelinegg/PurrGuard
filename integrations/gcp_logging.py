"""Sends findings as structured logs to Google Cloud Logging (for alerts and monitoring)."""
import json
import os

SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "ERROR", "MEDIUM": "WARNING", "LOW": "NOTICE"}
LOG_NAME = "purrguard"


def _client():
    project = os.environ.get("GCP_PROJECT_ID")
    if not project:
        return None
    try:
        from google.cloud import logging as gcl
    except ImportError:
        print("[gcp] missing google-cloud-logging; skipped")
        return None
    key = os.environ.get("GCP_SA_KEY_JSON")  # CI променлива със съдържанието на ключа (masked)
    if key:
        return gcl.Client.from_service_account_info(json.loads(key), project=project)
    return gcl.Client(project=project)  # иначе стандартните credentials


def log_findings(findings, context=None, client=None):
    """Returns count of sent records. Never sends the secrets themselves - only finding metadata."""
    client = client or _client()
    if client is None or not findings:
        return 0
    logger = client.logger(LOG_NAME)
    ctx = context or {
        "project": os.environ.get("CI_PROJECT_PATH", "local"),
        "mr": os.environ.get("CI_MERGE_REQUEST_IID", "-"),
        "commit": os.environ.get("CI_COMMIT_SHA", "-"),
        "pipeline": os.environ.get("CI_PIPELINE_URL", "-"),
    }
    n = 0
    try:
        for f in findings:
            logger.log_struct({
                "message": f"PurrGuard: {f['analyzer']} in {f['file']}",
                "file": f["file"], "analyzer": f["analyzer"], "detail": f["detail"],
                "severity_label": f["severity"], "honeytoken": f.get("honeytoken"), "secret_types": [s["type"] for s in f.get("secrets", [])],
                **ctx}, severity=SEVERITY.get(f["severity"], "DEFAULT"))
            n += 1
    except Exception as e:  # monitoring must not break the pipeline
            print("[gcp] send failed:", e)
    return n
