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
            continue  # new file: nothing to compare
        new = open(f, "rb").read()
        try:
            io_old, io_new = Image.open(io.BytesIO(old)), Image.open(f)
            if io_old.size != io_new.size:
                continue  # legitimate image change
            ratio = len(new) / max(len(old), 1)
            fd, tmp = tempfile.mkstemp(suffix=".png")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(old)
                old_p, new_p = A.lsb_score_png(tmp), A.lsb_score_png(f)
            finally:
                os.unlink(tmp)
        except Exception:
            continue
        if ratio > 1.3:
            out.append({"file": f, **A.finding("baseline_size", "MEDIUM",
                        "Same dimensions, but file grew {}% vs base (pixel noise compresses poorly)".format(int((ratio - 1) * 100)),
                        ratio)})
        if new_p - old_p > 0.3 and new_p > 0.3:
            out.append({"file": f, **A.finding("baseline_lsb_shift", "HIGH",
                        "LSB distribution changed sharply vs base ({} → {})".format(old_p, new_p), new_p)})
    return out
