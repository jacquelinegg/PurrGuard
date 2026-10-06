"""Scanning the entire git history (for already committed files)."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from . import carriers
from .engine import load_config, scan_file


def _git(*args):
    return subprocess.run(["git", *args], capture_output=True)


def scan_history(cfg=None, max_commits=None):
    cfg = cfg or load_config()
    max_commits = max_commits or cfg.get("history_max_commits", 500)
    log = _git("log", "--all", f"-n{max_commits}", "--format=COMMIT:%H", "--name-only", "--diff-filter=AM").stdout.decode()
    seen, results, commit, scanned = set(), [], None, 0
    known = carriers.historical_hashes(cfg.get("carrier_manifest", carriers.DEFAULT_MANIFEST))
    for line in log.splitlines():
        if line.startswith("COMMIT:"):
            commit = line[7:]
        elif line.strip() and commit:
            blob = _git("rev-parse", f"{commit}:{line}").stdout.decode().strip()
            if not blob or blob in seen:
                continue
            seen.add(blob)
            data = _git("show", f"{commit}:{line}").stdout
            if hashlib.sha256(data).hexdigest() in known:
                continue  # legitimate Stego-Ops carrier from some manifest version
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "f" + Path(line).suffix)
                open(p, "wb").write(data)
                try:
                    found = scan_file(p, cfg, line)
                except Exception:
                    found = []
            scanned += 1
            for fd in found:
                results.append({"file": line, "commit": commit[:10], **fd})
    out = {"blobs_scanned": scanned, "findings": results}
    json.dump(out, open("history_results.json", "w"), ensure_ascii=False, indent=2)
    return out
