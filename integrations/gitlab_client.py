import os

import requests


def _cfg():
    api, pid, token = os.environ.get("CI_API_V4_URL"), os.environ.get("CI_PROJECT_ID"), os.environ.get("GITLAB_API_TOKEN")
    return (api, pid, {"PRIVATE-TOKEN": token}) if api and pid and token else None


def post_mr_comment(body):
    c, iid = _cfg(), os.environ.get("CI_MERGE_REQUEST_IID")
    if not c or not iid:
        print("[gitlab] MR comment skipped (no context/token)")
        return
    r = requests.post(f"{c[0]}/projects/{c[1]}/merge_requests/{iid}/notes", headers=c[2], data={"body": body}, timeout=30)
    r.raise_for_status()


def create_security_issue(title, description):
    c = _cfg()
    if not c:
        print("[gitlab] issue skipped (no token)")
        return
    r = requests.post(f"{c[0]}/projects/{c[1]}/issues", headers=c[2],
                      data={"title": title, "description": description, "labels": "security,critical"}, timeout=30)
    r.raise_for_status()
    print("[gitlab] issue created:", r.json().get("web_url"))
