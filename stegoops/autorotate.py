"""Hands-off rotation: nearing expiry -> issue -> rotation (only here holds the key) -> MR -> auto-merge on green pipeline.
Agents (Duo flows) do NOT perform privileged steps: they only verify and report."""
import base64
import datetime as dt
import os
import subprocess
import time

import requests

from . import vault

LABEL = "stegoops::rotation"
BRANCH_PREFIX = "stegoops/rotate-"


def expiring(manifest_path=vault.MANIFEST, within_days=7, now=None):
    """Carriers expiring within <= within_days days (or already expired). No key, no secrets."""
    now = now or vault._now()
    out = []
    for e in vault.load_manifest(manifest_path)["carriers"]:
        left = (dt.datetime.fromisoformat(e["expires_at"]) - now).total_seconds() / 86400
        if left <= within_days:
            out.append({"path": e["path"], "env": e["env"], "names": e["names"],
                        "expires_at": e["expires_at"], "days_left": round(left, 1)})
    return out


def changed_files(base):
    r = subprocess.run(["git", "diff", "--name-only", base, "HEAD"], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise vault.VaultError("git diff failed: " + r.stderr.strip())
    return [f for f in r.stdout.split("\n") if f]


def guard_rotation(base, manifest_path=vault.MANIFEST):
    """A rotation MR can change ONLY carriers and manifest. Returns violations (empty list = OK)."""
    allowed = {os.path.normpath(e["path"]) for e in vault.load_manifest(manifest_path)["carriers"]}
    allowed.add(os.path.normpath(manifest_path))
    return [f for f in changed_files(base) if os.path.normpath(f) not in allowed]


class GitLab:
    def __init__(self, api=None, project=None, token=None, session=None):
        self.api = (api or os.environ["CI_API_V4_URL"]).rstrip("/")
        self.pid = project or os.environ["CI_PROJECT_ID"]
        self.token = token or os.environ.get("GITLAB_API_TOKEN")
        if not self.token:
            raise vault.VaultError("Missing GITLAB_API_TOKEN (project access token, scope api, role Developer)")
        self.s = session or requests.Session()

    def _req(self, method, path, ok=(200, 201), **kw):
        r = self.s.request(method, f"{self.api}/projects/{self.pid}{path}", headers={"PRIVATE-TOKEN": self.token}, timeout=30, **kw)
        if r.status_code not in ok:
            raise vault.VaultError(f"GitLab API {method} {path}: HTTP {r.status_code}")
        return r.json()

    def default_branch(self):
        return os.environ.get("CI_DEFAULT_BRANCH") or self._req("GET", "")["default_branch"]

    def find_open_issue(self, label=LABEL):
        found = self._req("GET", "/issues", params={"labels": label, "state": "opened"})
        return found[0] if found else None

    def open_issue(self, title, description, label=LABEL):
        return self._req("POST", "/issues", json={"title": title, "description": description, "labels": label})

    def create_branch(self, name, ref):
        return self._req("POST", "/repository/branches", params={"branch": name, "ref": ref})

    def commit(self, branch, message, files):
        actions = [{"action": "update", "file_path": p, "encoding": "base64", "content": base64.b64encode(b).decode()}
                   for p, b in files.items()]
        return self._req("POST", "/repository/commits", json={"branch": branch, "commit_message": message, "actions": actions})

    def create_mr(self, source, target, title, description, label=LABEL):
        return self._req("POST", "/merge_requests", json={"source_branch": source, "target_branch": target, "title": title,
                                                          "description": description, "labels": label, "remove_source_branch": True})

    def automerge(self, iid, retries=12, delay=5, sleep=time.sleep):
        """Merges when the pipeline passes. The new MR's pipeline may not exist yet - retries."""
        for i in range(retries):
            r = self.s.request("PUT", f"{self.api}/projects/{self.pid}/merge_requests/{iid}/merge",
                               headers={"PRIVATE-TOKEN": self.token}, timeout=30,
                               json={"auto_merge": True, "merge_when_pipeline_succeeds": True})
            if r.status_code == 200:
                return True
            if r.status_code not in (405, 406, 422):
                raise vault.VaultError(f"auto-merge: HTTP {r.status_code}")
            sleep(delay)
        return False


def watch(within_days=7, gl=None, manifest_path=vault.MANIFEST):
    """Opens (once) a rotation issue if there is an approaching expiry. Returns (issue, items) or (None, [])."""
    items = expiring(manifest_path, within_days)
    if not items:
        return None, []
    gl = gl or GitLab()
    issue = gl.find_open_issue()
    if not issue:
        lines = [f"- `{i['path']}` ({i['env']}): valid until {i['expires_at']} ({i['days_left']} days); secrets (names only): {', '.join(i['names'])}"
                 for i in items]
        issue = gl.open_issue("[Stego-Ops] Secret package expiry approaching - automatic rotation pending",
                              "Detected without key, from manifest:\n\n" + "\n".join(lines) +
                              "\n\nNext: the `rotate-secrets` CI job (the only one with the key) will perform rotation and open an MR with auto-merge. "
                              "The Deploy Sentinel agent checks the result after deploy. Secret values are never shown.")
    return issue, items


def rotate_and_open_mr(within_days, provider_factory, ttl_days=30, gl=None, manifest_path=vault.MANIFEST, sleep=time.sleep):
    """The only privileged action. provider_factory(name) -> provider with the key (KEK/KMS)."""
    gl = gl or GitLab()
    issue, items = watch(within_days, gl, manifest_path)
    if not items:
        return None
    files = {}
    for it in items:
        e = vault.find_entry(vault.load_manifest(manifest_path), path=it["path"])
        vault.rotate(it["path"], provider_factory(e["provider"]), ttl_days, manifest_path)
        files[it["path"]] = open(it["path"], "rb").read()
    files[manifest_path] = open(manifest_path, "rb").read()
    branch = BRANCH_PREFIX + vault._now().strftime("%Y%m%d%H%M%S")
    gl.create_branch(branch, gl.default_branch())
    gl.commit(branch, "stegoops: automatic secret package rotation", files)
    mr = gl.create_mr(branch, gl.default_branch(), "[Stego-Ops] Automatic secret rotation",
                      f"Closes #{issue['iid']}\n\nOnly carriers and manifest have changed (verified by `rotation-guard`). "
                      "Merges automatically when the pipeline passes (PurrGuard + verify + tests).")
    merged_when_green = gl.automerge(mr["iid"], sleep=sleep)
    return {"issue": issue["web_url"], "mr": mr["web_url"], "iid": mr["iid"], "auto_merge": merged_when_green,
            "carriers": [i["path"] for i in items]}
