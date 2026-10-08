"""Tests for the security hardening fixes: base-commit trust (config, manifest,
honeytoken registry), structural end-of-file, invisible Unicode (TAG + Trojan Source),
GitLab quick-action injection, analyzer crash isolation, renamed/special-character
files, loud git failures, exec environment hardening, and atomic rotation.
Only FAKE secrets."""
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
for v in ("CI_MERGE_REQUEST_DIFF_BASE_SHA", "STEGOOPS_KEK", "STEGOOPS_KMS_KEY",
          "GITLAB_API_TOKEN", "ANTHROPIC_API_KEY", "STEGOOPS_MANIFEST",
          "CI_JOB_TOKEN", "CI_REPOSITORY_URL"):
    os.environ.pop(v, None)
os.environ["PURRGUARD_MOCK"] = "1"
work = tempfile.mkdtemp()
os.chdir(work)

import numpy as np
from PIL import Image

from core import engine, honeytokens as H
from core.analyzers import trailing_bytes, invisible_unicode
from integrations.gitlab_client import neutralize_quick_actions
from stegoops import crypto, lsb, vault
from stegoops import autorotate

ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def git(*a):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                          capture_output=True, text=True, check=True).stdout.strip()


def make_png(path, size=128):
    y, x = np.mgrid[0:size, 0:size]
    img = (60 + 0.2 * x + 0.1 * y + 20 * np.sin(x / 13) * np.cos(y / 17))[..., None] * np.array([1, 0.9, 0.7])
    Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save(path)


FAKE = b"api_key=AKIAFAKEFAKEFAKE1234 FAKE-DEMO-ONLY"
PNG_END = b"IEND\xaeB`\x82"

# --- structural end of file: a payload followed by a fake end marker cannot hide ---
make_png("png_fake_end.png")
data = open("png_fake_end.png", "rb").read()
open("png_fake_end.png", "wb").write(data + FAKE + PNG_END)  # fake IEND at the very end
res = trailing_bytes("png_fake_end.png")
check("eof: payload before a fake IEND is still found", len(res) == 1 and res[0]["analyzer"] == "trailing_bytes")

make_png("tmp_for_jpg.png")
Image.open("tmp_for_jpg.png").convert("RGB").save("jpg_fake_end.jpg", quality=90)
jdata = open("jpg_fake_end.jpg", "rb").read()
open("jpg_fake_end.jpg", "wb").write(jdata + FAKE + b"\xff\xd9")  # fake EOI at the very end
res = trailing_bytes("jpg_fake_end.jpg")
check("eof: payload before a fake EOI is still found", len(res) == 1 and res[0]["analyzer"] == "trailing_bytes")

# an EXIF thumbnail is a full JPEG inside a length-prefixed APP segment: its EOI must not end the file
mini = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
app1 = b"\xff\xe1" + struct.pack(">H", len(mini) + 8) + b"Exif\x00\x00" + mini
open("exif_thumb.jpg", "wb").write(b"\xff\xd8" + app1 + b"\xff\xd9")
check("eof: an EOI inside an EXIF thumbnail does not end the file", trailing_bytes("exif_thumb.jpg") == [])

# --- invisible Unicode: TAG characters and bidi controls (Trojan Source) ---
tag_secret = "".join(chr(0xE0000 + b) for b in b"AKIAFAKEFAKEFAKE1234")
open("tag_token.sql", "w", encoding="utf-8").write("-- ok" + tag_secret)
res = invisible_unicode("tag_token.sql")
check("invisible: TAG characters encoding a secret are CRITICAL",
      len(res) == 1 and res[0]["analyzer"] == "invisible_tag" and res[0]["severity"] == "CRITICAL")
open("bidi.sql", "w", encoding="utf-8").write("-- x‮y\nSELECT 1;")
res = invisible_unicode("bidi.sql")
check("invisible: bidi controls (Trojan Source) are detected",
      len(res) == 1 and res[0]["analyzer"] == "invisible_bidi")
open("clean_unicode.sql", "w", encoding="utf-8").write("-- plain\nSELECT 1;\n")
check("invisible: ordinary text is clean", invisible_unicode("clean_unicode.sql") == [])

cfg = engine.load_config()
res = engine.run(["tag_token.sql", "bidi.sql", "clean_unicode.sql"], cfg)
an = {(f["analyzer"], f["severity"]) for f in res["findings"]}
check("invisible: end-to-end scan catches TAG secret and bidi controls",
      ("invisible_tag", "CRITICAL") in an and ("invisible_bidi", "MEDIUM") in an)

# --- analyzer crash isolation: a broken PNG keeps its other findings ---
make_png("broken.png")
raw = bytearray(open("broken.png", "rb").read())
i = raw.find(b"IDAT")
raw[i + 4] ^= 0xFF  # corrupt the first IDAT data byte: PIL can no longer decode the pixels
open("broken.png", "wb").write(bytes(raw) + FAKE + PNG_END)
res = engine.scan_file("broken.png", cfg)
an = {f["analyzer"] for f in res}
check("crash: a crashing analyzer does not wipe the other findings",
      "trailing_bytes" in an and "chi_square_lsb" in an)
check("crash: the crash itself is a HIGH finding",
      any(f["analyzer"] == "chi_square_lsb" and f["severity"] == "HIGH" for f in res))

# --- GitLab quick actions: a file name must not be able to run /merge ---
check("quick-actions: a line-leading / is neutralized",
      neutralize_quick_actions("found:\n/merge\nmore") == "found:\n​/merge\nmore")
check("quick-actions: normal text is unchanged", neutralize_quick_actions("all good") == "all good")
body = "- **x\n/approve** — HIGH: detail"
check("quick-actions: a file name cannot inject a command", not re.search(r"(?m)^/", neutralize_quick_actions(body)))

# --- git repo: base-commit trust ---
git("init", "-q", ".")
kek = crypto.generate_kek()
os.environ["STEGOOPS_KEK"] = kek
prov = crypto.EnvProvider(kek)
make_png("carrier.png")
vault.seal("carrier.png", {"DB_PASSWORD": "FAKE-db-pass-1234567890"}, prov, env="staging")
git("add", "-A")
git("commit", "-qm", "base")
base = git("rev-parse", "HEAD")

# rotation guard: the allowed list comes from the base manifest, not the MR's
m = json.load(open(vault.MANIFEST))
m["carriers"].append({"id": "staging:.gitlab-ci.yml", "path": ".gitlab-ci.yml", "sha256": "0" * 64,
                      "env": "staging", "names": [], "created": "x", "expires_at": "x",
                      "provider": "env", "locator": "eA=="})
json.dump(m, open(vault.MANIFEST, "w"))
open(".gitlab-ci.yml", "w").write("stages: [build]\n")
git("add", "-A")
git("commit", "-qm", "mr: carrier added in the MR")
check("guard: a file added as a carrier inside the MR is still a violation",
      ".gitlab-ci.yml" in autorotate.guard_rotation(base))

# configuration: the MR cannot weaken its own scan
open(".purrguard.yml", "w").write('fail_on: CRITICAL\nignore_paths: ["/"]\n')
git("add", "-A")
git("commit", "-qm", "mr: weaken config")
os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"] = base
cfg2 = engine.load_config()
check("config: fail_on comes from the base commit", cfg2["fail_on"] == "HIGH")
check("config: ignore_paths comes from the base commit", cfg2["ignore_paths"] == [".git"])
res = engine.run(["broken.png"], cfg2)
check("config: the MR cannot switch off the block on HIGH findings", res["threat_detected"])

# honeytoken registry: the MR cannot empty it
H.init(".", "demo-proj")
git("add", "-A")
git("commit", "-qm", "honey base")
hbase = git("rev-parse", "HEAD")
n_base = len(json.load(open(H.DEFAULT_FILE))["tokens"])
open(H.DEFAULT_FILE, "w").write(json.dumps({"tokens": []}))
git("add", "-A")
git("commit", "-qm", "mr: empty the registry")
os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"] = hbase
check("honeytokens: the registry comes from the base commit in an MR",
      len(H.load()["tokens"]) == n_base == 4)

# --- changed_files: special characters, renames, and loud failures ---
open("old_name.sql", "w", encoding="utf-8").write("SELECT 2;\n")
git("add", "-A")
git("commit", "-qm", "add files")
pre = git("rev-parse", "HEAD")
open("héllo wörld.sql", "w", encoding="utf-8").write("SELECT 1;\n")
git("mv", "old_name.sql", "renamed file.sql")
git("add", "-A")
git("commit", "-qm", "special chars and rename")
files = engine.changed_files()
check("changed_files: names with special characters are not quoted", "héllo wörld.sql" in files)
check("changed_files: renamed files are included", "renamed file.sql" in files)
os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"] = "deadbeef"
try:
    engine.changed_files()
    check("changed_files: a git failure raises instead of reporting a silent clean", False)
except RuntimeError:
    check("changed_files: a git failure raises instead of reporting a silent clean", True)
os.environ.pop("CI_MERGE_REQUEST_DIFF_BASE_SHA")

# --- exec: the child process must not receive the CI job token ---
os.environ["CI_JOB_TOKEN"] = "FAKE-job-token"
os.environ["CI_REPOSITORY_URL"] = "https://gitlab-ci-token:FAKE@gitlab.com/g/p.git"
code = ("import os;"
        "print('JOB', os.environ.get('CI_JOB_TOKEN'));"
        "print('REPO', os.environ.get('CI_REPOSITORY_URL'));"
        "print('DB', os.environ.get('DB_PASSWORD'))")
r = subprocess.run([sys.executable, "-m", "stegoops", "exec", "--carrier", "carrier.png", "--",
                    sys.executable, "-c", code], capture_output=True, text=True,
                   env={**os.environ, "PYTHONPATH": ROOT})
check("exec: CI_JOB_TOKEN is not passed to the child", "JOB None" in r.stdout)
check("exec: CI_REPOSITORY_URL is not passed to the child", "REPO None" in r.stdout)
check("exec: the sealed secret still reaches the child (scrubbed in the log)", "DB ***" in r.stdout)

# --- rotation is atomic: a failure must not destroy the carrier ---
before = open("carrier.png", "rb").read()
entry = vault.find_entry(vault.load_manifest(), path="carrier.png")
orig_embed = lsb.embed


def boom(*a, **k):
    raise lsb.StegoError("injected failure")


lsb.embed = boom
try:
    try:
        vault.rotate("carrier.png", prov)
        check("rotation: a failed re-seal leaves the original carrier intact", False)
    except lsb.StegoError:
        still_ok = (open("carrier.png", "rb").read() == before
                    and vault.open_bytes(before, entry, prov) == {"DB_PASSWORD": "FAKE-db-pass-1234567890"})
        check("rotation: a failed re-seal leaves the original carrier intact", still_ok)
finally:
    lsb.embed = orig_embed

print("\nALL PASS" if ok else "\nFAILURES")
sys.exit(0 if ok else 1)
