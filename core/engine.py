import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path

import yaml

from . import analyzers as A
from . import baseline, carriers, honeytokens, trusted

RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
TEXT_EXT = {".sql", ".py", ".js", ".ts", ".md", ".txt", ".yml", ".yaml", ".json", ".sh", ".java", ".go", ".html", ".css", ".env", ".cfg", ".ini"}


def load_config(path=".purrguard.yml"):
    cfg = {"fail_on": "HIGH", "ignore_paths": [".git"], "chi_square_threshold": 0.05, "min_zero_width_chars": 1,
           "allowlist_sha256": [], "honeytokens_file": ".purrguard_honey.json", "carrier_manifest": carriers.DEFAULT_MANIFEST, "auto_fix": True, "history_max_commits": 500}
    data = trusted.read_trusted(path)  # in an MR the config comes from the base commit: the MR cannot weaken its own scan
    if data is not None:
        cfg.update(yaml.safe_load(data.decode("utf-8")) or {})
    return cfg


def changed_files():
    """Files changed in MR; if no context - all tracked files. Fails loudly: a git
    error must never look like "0 files, all clean". -z disables name quoting (names
    with special characters survive), AMR includes renamed files."""
    base = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    if base:
        cmd = ["git", "-c", "core.quotePath=false", "diff", "--name-only", "-z", "--diff-filter=AMR", base, "HEAD"]
    else:
        cmd = ["git", "-c", "core.quotePath=false", "ls-files", "-z"]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError("git failed (the scanner refuses to report a silent clean): " + r.stderr.strip())
    return [f for f in r.stdout.split("\0") if f]


def _is_ignored(path, ignore_paths):
    """True if any ignore_paths entry is a whole path component (e.g. '.git', 'node_modules')
    or a path prefix. Component matching avoids substring false positives: '.gitignore' is NOT ignored."""
    norm = os.path.normpath(path)
    parts = Path(norm).parts
    for p in ignore_paths:
        p = os.path.normpath(p)
        if p in parts or norm == p or norm.startswith(p + os.sep):
            return True
    return False


def scan_file(path, cfg, repo_path=None):
    """Runs each analyzer in isolation: a crash in one (e.g. a broken PNG in the
    chi-square test) must not wipe the findings of the others, and the crash itself
    is a HIGH finding (a file that crashes a parser is corrupt or crafted to evade)."""
    ext = Path(path).suffix.lower()
    jobs = []
    if ext == ".png":
        jobs += [("trailing_bytes", lambda: A.trailing_bytes(path)),
                 ("png_chunks", lambda: A.png_chunks(path)),
                 ("chi_square_lsb", lambda: A.chi_square_png(path, cfg["chi_square_threshold"]))]
    elif ext in (".jpg", ".jpeg"):
        jobs += [("trailing_bytes", lambda: A.trailing_bytes(path))]
    elif ext == ".wav":
        jobs += [("wav_structure", lambda: A.wav_structure(path))]
    elif ext == ".pdf":
        jobs += [("pdf_structure", lambda: A.pdf_structure(path))]
    elif ext == ".mp3":
        jobs += [("trailing_bytes", lambda: A.mp3_trailing(path))]
    elif ext in TEXT_EXT:
        jobs += [("zero_width", lambda: A.zero_width(path, cfg["min_zero_width_chars"])),
                 ("invisible_unicode", lambda: A.invisible_unicode(path, cfg["min_zero_width_chars"]))]
    out = []
    for name, fn in jobs:
        try:
            out += fn()
        except Exception as e:
            out.append(A.finding(name, "HIGH", f"Analyzer crashed (corrupt or crafted file): {type(e).__name__}: {e}"))
    reg = honeytokens.load(cfg.get("honeytokens_file", honeytokens.DEFAULT_FILE))
    try:
        out += honeytokens.scan(path, reg, repo_path or path)
    except Exception as e:
        out.append(A.finding("honeytoken", "HIGH", f"Honeytoken scan crashed: {type(e).__name__}: {e}"))
    return out  # honeytokens are searched in ALL files


def run(files=None, cfg=None):
    cfg = cfg or load_config()
    files = files if files is not None else changed_files()
    results, authorized = [], []
    car = carriers.Carriers(cfg["carrier_manifest"])
    mf = car.manifest_finding()
    if mf:
        results.append({"file": cfg["carrier_manifest"], **mf})
    for f in files:
        if _is_ignored(f, cfg["ignore_paths"]) or not os.path.isfile(f):
            continue
        if hashlib.sha256(open(f, "rb").read()).hexdigest() in cfg["allowlist_sha256"]:
            continue  # approved false positive
        st = car.status(f)
        if st in ("ok", "resealed"):  # Stego-Ops carrier: LSB statistics are expected, so we trust the hash
            authorized.append(f)
            if st == "resealed":
                results.append({"file": f, **car.file_finding(f, st)})
            continue
        if st == "tampered":
            results.append({"file": f, **car.file_finding(f, st)})
        try:
            for fd in scan_file(f, cfg):
                results.append({"file": f, **fd})
        except Exception as e:  # last-resort safety net: must not stop the pipeline, but must not look clean either
            results.append({"file": f, "analyzer": "error", "severity": "HIGH", "detail": f"Analysis error: {e}", "score": None})
    try:
        results += baseline.compare([f for f in files if os.path.isfile(f) and f not in authorized])
    except Exception as e:
        print("[baseline] skipped:", e)
    top = max((RANK[r["severity"]] for r in results), default=0)
    out = {"files_scanned": len(files), "authorized_carriers": authorized, "findings": results,
           "max_severity": next((k for k, v in RANK.items() if v == top), "NONE"),
           "threat_detected": top >= RANK[cfg["fail_on"]]}
    with open("scan_results.json", "w", encoding="utf-8") as fp:
        json.dump(out, fp, ensure_ascii=False, indent=2)
    os.makedirs(".purrguard_log", exist_ok=True)
    counts = {k: sum(r["severity"] == k for r in results) for k in RANK}
    with open(".purrguard_log/log.jsonl", "a") as lg:
        lg.write(json.dumps({"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                             "mr": os.environ.get("CI_MERGE_REQUEST_IID", "-"), "scanned": len(files),
                             "findings": len(results), "max": out["max_severity"], "counts": counts}) + "\n")
    return out
