"""Comparison with default branch: change is a stronger signal than absolute value."""
import io
import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image

from . import analyzers as A


def _old_version(base, path):
    r = subprocess.run(["git", "show", f"{base}:{path}"], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def compare(files, base=None):
    base = base or os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
    if not base:
        return []
    out = []
    for f in files:
        if Path(f).suffix.lower() != ".png" or not os.path.isfile(f):
            continue
        old = _old_version(base, f)
        if not old:
            continue  # нов файл: няма с какво да се сравни
        new = open(f, "rb").read()
        try:
            io_old, io_new = Image.open(io.BytesIO(old)), Image.open(f)
            if io_old.size != io_new.size:
                continue  # легитимна смяна на изображението
            ratio = len(new) / max(len(old), 1)
            with tempfile.NamedTemporaryFile(suffix=".png") as t:
                t.write(old); t.flush()
                old_p, new_p = A.lsb_score_png(t.name), A.lsb_score_png(f)
        except Exception:
            continue
        if ratio > 1.3:
            out.append({"file": f, **A.finding("baseline_size", "MEDIUM",
                        f"Същите размери, но файлът е нараснал {int((ratio - 1) * 100)}% спрямо основния клон "
                        "(шум в пикселите се компресира лошо)", ratio)})
        if new_p - old_p > 0.3 and new_p > 0.3:
            out.append({"file": f, **A.finding("baseline_lsb_shift", "HIGH",
                        f"LSB статистиката се е променила рязко спрямо основния клон ({old_p:.2f} → {new_p:.2f})", new_p)})
    return out
