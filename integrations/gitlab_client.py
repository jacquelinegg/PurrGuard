import os
import re

import requests

_QUICK_ACTION = re.compile(r"(?m)^/")


def neutralize_quick_actions(text):
    """GitLab executes quick actions (/merge, /approve, ...) when a comment
    line starts with '/'. A scanned file name or finding detail must never be
    able to trigger them with the project token, so a line-leading '/' is
    prefixed with an invisible character."""
    return _QUICK_ACTION.sub("​/", text)


def post_mr_comment(body):
    c, iid = _cfg(), os.environ.get("CI_MERGE_REQUEST_IID")
    if not c or not iid:
        print("[gitlab] MR comment skipped (no context/token)")
        return
    r = requests.post(f"{c[0]}/projects/{c[1]}/merge_requests/{iid}/notes", headers=c[2],
                      data={"body": neutralize_quick_actions(body)}, timeout=30)
    r.raise_for_status()


def create_security_issue(title, description):
    c = _cfg()
    if not c:
        print("[gitlab] issue skipped (no token)")
        return
    r = requests.post(f"{c[0]}/projects/{c[1]}/issues", headers=c[2],
                      data={"title": neutralize_quick_actions(title),
                            "description": neutralize_quick_actions(description),
                            "labels": "security,critical"}, timeout=30)
    r.raise_for_status()
    print("[gitlab] issue created:", r.json().get("web_url"))
