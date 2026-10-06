"""Honeytokens: fake secret baits. If they appear elsewhere, that is certain evidence of exfiltration."""
import hashlib
import json
import os
import re
import secrets
import string
import wave
from pathlib import Path

import numpy as np
from PIL import Image

from .analyzers import PNG_SIG, ZW_CHARS, finding

DEFAULT_FILE = ".purrguard_honey.json"
CANDIDATES = [re.compile(p) for p in (rb"AKIA[0-9A-Z]{16,}", rb"AIza[0-9A-Za-z_\-]{35}", rb"\b[0-9a-f]{40}\b", rb"glpat-[0-9A-Za-z_\-]{20}")]
UP, DIG, ALNUM = string.ascii_uppercase, string.digits, string.ascii_letters + string.digits
_cache = {}


def _rand(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


GEN = {
    "aws_access_key": lambda: "AKIA" + _rand(UP + DIG, 16),
    "gcp_api_key": lambda: "AIza" + _rand(ALNUM + "_-", 35),
    "gcp_sa_key_id": lambda: _rand("0123456789abcdef", 40),
    "gitlab_token": lambda: "glpat-" + _rand(ALNUM, 20),
}
sha = lambda s: hashlib.sha256(s if isinstance(s, bytes) else s.encode()).hexdigest()


def load(path=DEFAULT_FILE):
    if not os.path.exists(path):
        return {"tokens": []}
    key = (path, os.path.getmtime(path))
    if key not in _cache:
        _cache[key] = json.load(open(path))
    return _cache[key]


def _save(reg, path):
    json.dump(reg, open(path, "w"), indent=2, ensure_ascii=False)


def add(kind, value, decoy, path=DEFAULT_FILE):
    """Registers an existing bait (e.g., a real service account key without permissions). Only the hash is stored."""
    reg = load(path) if os.path.exists(path) else {"tokens": []}
    reg = {"tokens": list(reg["tokens"])}
    tid = f"ht-{len(reg['tokens']) + 1}"
    reg["tokens"].append({"id": tid, "kind": kind, "sha256": sha(value), "decoy": decoy})
    _save(reg, path)
    return tid


def init(root=".", project="demo-project", path=DEFAULT_FILE):
    """Creates baits in the repository. Does not overwrite existing files."""
    t = {k: g() for k, g in GEN.items()}
    pem = "\n".join(_rand(ALNUM + "+/", 64) for _ in range(5))
    files = {
        "config/legacy-credentials.json": (json.dumps({
            "type": "service_account", "project_id": project, "private_key_id": t["gcp_sa_key_id"],
            "private_key": f"-----BEGIN PRIVATE KEY-----\n{pem}\n-----END PRIVATE KEY-----\n",
            "client_email": f"legacy-backup@{project}.iam.gserviceaccount.com"}, indent=2), "gcp_sa_key_id"),
        ".env.backup": (f"AWS_ACCESS_KEY_ID={t['aws_access_key']}\nAWS_SECRET_ACCESS_KEY={_rand(ALNUM + '+/', 40)}\n", "aws_access_key"),
        "config/maps_api.txt": (f"MAPS_API_KEY={t['gcp_api_key']}\n", "gcp_api_key"),
        "scripts/.deploy-token": (f"{t['gitlab_token']}\n", "gitlab_token"),
    }
    made = []
    for rel, (content, kind) in files.items():
        p = os.path.join(root, rel)
        if os.path.exists(p):
            continue
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        open(p, "w").write(content)
        add(kind, t[kind], rel, path)
        made.append(rel)
    return made


def _zw_decode(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return b""
    bits = "".join("1" if c == "\u200c" else "0" for c in text if c in "\u200b\u200c")
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8)) if len(bits) >= 8 else b""


def _streams(path, data):
    yield "в чист вид", data
    zw = _zw_decode(data)
    if zw:
        yield "скрито в невидими Unicode символи", zw
    try:
        if data.startswith(PNG_SIG):
            arr = np.array(Image.open(path).convert("RGB"), dtype=np.uint8)
            if arr.size < 60_000_000:
                for c, n in enumerate("RGB"):
                    yield f"скрито в LSB на PNG канал {n}", np.packbits(arr[:, :, c].ravel() & 1).tobytes()
                yield "скрито в LSB на PNG (RGB последователно)", np.packbits(arr.ravel() & 1).tobytes()
        elif data[:4] == b"RIFF":
            with wave.open(path, "rb") as w:
                if w.getsampwidth() == 2:
                    s = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2")
                    yield "скрито в LSB на WAV семпли", np.packbits((s & 1).astype(np.uint8)).tobytes()
    except Exception:
        pass


def scan(path, registry, repo_path=None):
    tokens = {t["sha256"]: t for t in registry.get("tokens", [])}
    if not tokens:
        return []
    rp = (repo_path or path).lstrip("./") if (repo_path or path).startswith("./") else (repo_path or path)
    if any(t["decoy"] == rp for t in tokens.values()):
        return []  # самата примамка си стои на мястото
    if os.path.getsize(path) > 50_000_000:
        return []
    data = open(path, "rb").read()
    out, seen = [], set()
    for where, blob in _streams(path, data):
        for rx in CANDIDATES:
            for m in rx.finditer(blob):
                t = tokens.get(sha(m.group()))
                if t and (t["id"], where) not in seen:
                    seen.add((t["id"], where))
                    f = finding("honeytoken", "CRITICAL",
                                f"ПРИМАМКА {t['id']} ({t['kind']}, от {t['decoy']}) е открита {where} - сигурно доказателство за опит за изнасяне")
                    f["honeytoken"] = t["id"]
                    out.append(f)
    return out
