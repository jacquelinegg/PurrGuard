"""Trusted reads inside a merge request: the MR head cannot change the base commit."""
import os
import subprocess


def base_rev():
    """The MR diff base commit, or None outside an MR."""
    return os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")


def read_trusted(path):
    """Bytes of `path` from the base commit in an MR (the MR cannot change it),
    otherwise from the working tree. None if the file does not exist."""
    base = base_rev()
    if base:
        r = subprocess.run(["git", "show", f"{base}:{path}"], capture_output=True)
        return r.stdout if r.returncode == 0 else None
    return open(path, "rb").read() if os.path.exists(path) else None
