"""Авторизирани носители на Stego-Ops. PurrGuard НЕ бива заслепен от собствения си продукт:
файл от манифеста е легитимен само ако SHA-256 съвпада с манифеста от ДОВЕРЕНА версия
(при MR - тази от базовия комит, която MR не може да промени)."""
import hashlib
import json
import os
import subprocess

from .analyzers import finding

DEFAULT_MANIFEST = ".stegoops/manifest.json"
EMPTY = {"carriers": []}


def _sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def _git_show(rev, path):
    r = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True)
    return r.stdout.decode() if r.returncode == 0 else None


def _norm(p):
    return os.path.normpath(p)


class Carriers:
    def __init__(self, manifest_path=DEFAULT_MANIFEST):
        self.path = manifest_path
        try:
            self.local = json.load(open(manifest_path)) if os.path.exists(manifest_path) else EMPTY
        except json.JSONDecodeError:
            self.local = EMPTY
        base = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
        self.in_mr = bool(base)
        if base:
            txt = _git_show(base, manifest_path)
            self.trusted = json.loads(txt) if txt else EMPTY
        else:
            self.trusted = self.local
        idx = lambda m: {_norm(e["path"]): e["sha256"] for e in m["carriers"]}
        self._trusted, self._local = idx(self.trusted), idx(self.local)

    def status(self, path):
        """none | ok | resealed (съвпада само с манифеста от MR - иска преглед) | tampered"""
        p = _norm(path)
        if p not in self._trusted and p not in self._local:
            return "none"
        h = _sha(path)
        if self._trusted.get(p) == h:
            return "ok"
        if self._local.get(p) == h:
            return "resealed"
        return "tampered"

    def file_finding(self, path, status):
        if status == "resealed":
            return finding("carrier_resealed", "MEDIUM",
                           "Носител на Stego-Ops е презапечатан/добавен в този MR - изисква преглед от CODEOWNERS (манифестът е променен)")
        if status == "tampered":
            return finding("carrier_tampered", "HIGH" if self.in_mr else "CRITICAL",
                           "Носител на Stego-Ops не съвпада с НИТО един манифест (SHA-256) - подменен или модифициран файл")
        return None

    def manifest_finding(self):
        if self.in_mr and self._local != self._trusted:
            return finding("carrier_manifest", "MEDIUM",
                           "Манифестът на Stego-Ops е променен в този MR (нови/сменени носители) - изисква преглед от CODEOWNERS")
        return None


def historical_hashes(manifest_path=DEFAULT_MANIFEST):
    """Всички SHA-256 от всички версии на манифеста - за да не се маркират стари законни носители в историята."""
    out = set()
    revs = subprocess.run(["git", "log", "--all", "--format=%H", "--", manifest_path], capture_output=True).stdout.decode().split()
    for r in revs:
        txt = _git_show(r, manifest_path)
        try:
            out |= {e["sha256"] for e in json.loads(txt or "{}").get("carriers", [])}
        except json.JSONDecodeError:
            pass
    return out
