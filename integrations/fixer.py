"""Automatic fix MR: cleaned files are submitted as a new merge request."""
import base64
import os
from pathlib import Path

import requests

from core.sanitize import sanitize


def build_fixes(findings, outdir="purrguard_fixed"):
    fixed = {}
    for path in sorted({f["file"] for f in findings if f["analyzer"] != "error" and not f["analyzer"].startswith("carrier")}):
        data = sanitize(path)
        if data is not None and data != Path(path).read_bytes():
            fixed[path] = data
            os.makedirs(os.path.join(outdir, os.path.dirname(path)), exist_ok=True)
            Path(os.path.join(outdir, path)).write_bytes(data)
    return fixed


def open_fix_mr(fixed, description):
    api, pid, token = os.environ.get("CI_API_V4_URL"), os.environ.get("CI_PROJECT_ID"), os.environ.get("GITLAB_API_TOKEN")
    src, iid = os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"), os.environ.get("CI_MERGE_REQUEST_IID")
    if not (api and pid and token and src and fixed):
        print("[fixer] fix MR skipped; cleaned files are in purrguard_fixed/")
        return None
    h = {"PRIVATE-TOKEN": token}
    branch = f"purrguard/fix-mr{iid}"
    actions = [{"action": "update", "file_path": p, "encoding": "base64",
                "content": base64.b64encode(d).decode()} for p, d in fixed.items()]
    r = requests.post(f"{api}/projects/{pid}/repository/commits", headers=h, timeout=60,
                      json={"branch": branch, "start_branch": src, "commit_message": "PurrGuard: sanitize hidden content",
                            "actions": actions})
    r.raise_for_status()
    r = requests.post(f"{api}/projects/{pid}/merge_requests", headers=h, timeout=30,
                      json={"source_branch": branch, "target_branch": src, "title": f"[PurrGuard] Automatic fix for MR !{iid}",
                            "description": description, "labels": "security"})
    r.raise_for_status()
    print("[fixer] fix MR:", r.json().get("web_url"))
    return r.json().get("web_url")
