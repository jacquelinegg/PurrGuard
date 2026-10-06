"""Test of Stego-Ops and its integration with PurrGuard: python tests/test_stegoops.py  (only FAKE secrets)"""
import base64
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
for v in ("CI_MERGE_REQUEST_DIFF_BASE_SHA", "STEGOOPS_KMS_KEY", "GITLAB_API_TOKEN", "ANTHROPIC_API_KEY"):
    os.environ.pop(v, None)
os.environ["PURRGUARD_MOCK"] = "1"
work = tempfile.mkdtemp()
os.chdir(work)

import numpy as np
from PIL import Image

from core import engine, honeytokens as H
from stegoops import crypto, lsb, registry, vault
from stegoops.__main__ import make_logo
from stegoops.scrub import Scrubber

ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


SECRETS = {"DB_PASSWORD": "FAKE-db-pass-123456", "API_TOKEN": "FAKE-token-abcdef987654", "PEM": "line-one-FAKE-key\nline-two-FAKE-key"}
kek = crypto.generate_kek()
prov = crypto.EnvProvider(kek)
make_logo("logo.png")
clean = open("logo.png", "rb").read()

# --- cryptography + steganography ---
e = vault.seal("logo.png", SECRETS, prov, env="staging")
sealed = open("logo.png", "rb").read()
check("round-trip: secrets are returned unchanged", vault.open_bytes(sealed, e, prov) == SECRETS)
a, b = np.array(Image.open(io.BytesIO(clean))).astype(int), np.array(Image.open(io.BytesIO(sealed))).astype(int)
check("the image changes by at most 1 out of 255 per pixel", np.abs(a - b).max() <= 1)
check("the file does not contain secrets in plaintext", all(v.encode() not in sealed for v in SECRETS.values()))
check("wrong KEK does not decrypt", raises(lambda: vault.open_bytes(sealed, e, crypto.EnvProvider(crypto.generate_kek())), crypto.CryptoError))
check("tampered carrier is rejected (SHA-256)", raises(lambda: vault.open_bytes(sealed + b"x", e, prov), vault.VaultError))
e2 = dict(e, id="prod:logo.png")
check("carrier cannot be used under a different identifier (AAD)", raises(lambda: vault.open_bytes(sealed, e2, prov), crypto.CryptoError))
arr = np.array(Image.open(io.BytesIO(sealed)))
arr.reshape(-1)[:200000:7] ^= 1  # pixel corruption
buf = io.BytesIO(); Image.fromarray(arr).save(buf, "PNG")
bad = dict(e, sha256=vault._sha(buf.getvalue()))
check("corrupted payload bits are detected (GCM tag)", raises(lambda: vault.open_bytes(buf.getvalue(), bad, prov), (crypto.CryptoError, vault.VaultError, lsb.StegoError, json.JSONDecodeError)))
check("sequential LSB reader (like zsteg) finds nothing readable",
      b"FAKE" not in np.packbits(np.array(Image.open(io.BytesIO(sealed)).convert("RGB")).reshape(-1) & 1).tobytes())

# --- expiry + rotation ---
Image.open(io.BytesIO(clean)).save("old.png")
ee = vault.seal("old.png", {"X_TOKEN": "FAKE-expired-token"}, prov, env="old", ttl_days=-1)
check("expired package is rejected", raises(lambda: vault.open_bytes(open("old.png", "rb").read(), ee, prov), vault.VaultError))
check("verify detects expired package", any("expired" in p for p in vault.verify()))
old_loc = e["locator"]
ne = vault.rotate("logo.png", prov, ttl_days=30)
rotated = open("logo.png", "rb").read()
check("rotation: new seed/locator and new hash", ne["locator"] != old_loc and ne["sha256"] != e["sha256"])
check("rotation: secrets are the same", vault.open_bytes(rotated, ne, prov) == SECRETS)
old_seed = prov.unwrap(base64.b64decode(old_loc), vault._aad(e["id"]))
try:
    stale = lsb.extract(rotated, old_seed)
    check("rotation: old ciphertext is destroyed", not stale.startswith(crypto.MAGIC))
except lsb.StegoError:
    check("rotation: old ciphertext is destroyed", True)

# --- scrubber + execution ---
sc = Scrubber(SECRETS.values())
leak = ("pw=" + SECRETS["DB_PASSWORD"] + " b64=" + base64.b64encode(SECRETS["API_TOKEN"].encode()).decode() + " " + "line-two-FAKE-key").encode()
out = sc.scrub(leak)
check("the scrubber masks raw, base64, and multiline forms", not any(x in out for x in (b"FAKE-db-pass", b"RkFLRS10b2tlbi", b"line-two-FAKE")))
os.environ["STEGOOPS_KEK"] = kek
r = subprocess.run([sys.executable, "-m", "stegoops", "exec", "--carrier", "logo.png", "--", sys.executable, "-c",
                    "import os;print(os.environ['DB_PASSWORD']);print('KEK' , os.environ.get('STEGOOPS_KEK'))"],
                   capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ROOT})
check("exec: secret is available to the process, but the log is scrubbed", "***" in r.stdout and "FAKE-db-pass" not in r.stdout + r.stderr)
check("exec: KEK is not passed to the child process", "KEK None" in r.stdout)
leftovers = [f for f in os.listdir(".") if f.endswith((".env", ".json")) and f != "x"]
check("no temporary files with secrets on disk", not any("FAKE" in open(f, errors="ignore").read() for f in leftovers if os.path.isfile(f)))

# --- Container Registry (fake registry) ---
def layer(files):
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as t:
        for n, d in files.items():
            ti = tarfile.TarInfo(n); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
    return bio.getvalue()


L1, L2 = layer({"./app/assets/logo.png": clean, "./etc/x": b"1"}), layer({"./app/assets/logo.png": rotated})


class Resp:
    def __init__(self, code=200, js=None, raw=b"", headers=None):
        self.status_code, self._js, self.raw, self.headers = code, js, io.BytesIO(raw), headers or {}
    def json(self): return self._js


class FakeSession:
    def __init__(self): self.calls = []
    def get(self, url, headers=None, params=None, auth=None, timeout=None, stream=False):
        self.calls.append(url)
        if url.endswith("/token"):
            return Resp(js={"token": "T"}) if auth else Resp(401)
        if not (headers or {}).get("Authorization"):
            return Resp(401, headers={"WWW-Authenticate": 'Bearer realm="https://reg.test/token",service="registry"'})
        if "/manifests/" in url:
            return Resp(js={"layers": [{"digest": "sha256:l1"}, {"digest": "sha256:l2"}]})
        return Resp(raw={"sha256:l1": L1, "sha256:l2": L2}[url.rsplit("/", 1)[1]])


got = registry.fetch_file("reg.test/group/proj/app:abc", "app/assets/logo.png", session=FakeSession(), password="jobtoken")
check("registry: gets the file from the top layer (streaming, no disk)", got == rotated)
check("registry: extracted carrier decrypts", vault.open_bytes(got, ne, prov) == SECRETS)
check("registry: missing file -> error", raises(lambda: registry.fetch_file("reg.test/g/p:t", "nope.png", session=FakeSession(), password="x"), registry.RegistryError))

# --- integration with PurrGuard ---
subprocess.run("git init -q . && git config user.email a@b && git config user.name t", shell=True)
os.makedirs("tests/samples", exist_ok=True)
cfg = engine.load_config()
res = engine.run(["logo.png"], cfg)
check("PurrGuard: authorized carrier is recognized and does not alert", "logo.png" in res["authorized_carriers"] and not res["threat_detected"])
evil = np.array(Image.open("logo.png")).copy(); evil.reshape(-1)[:60000] = (evil.reshape(-1)[:60000] & 0xFE) | np.random.default_rng(1).integers(0, 2, 60000, dtype=np.uint8)
Image.fromarray(evil).save("logo.png")
res = engine.run(["logo.png"], cfg)
check("PurrGuard: tampered carrier (hash mismatch) is CRITICAL", any(f["analyzer"] == "carrier_tampered" and f["severity"] == "CRITICAL" for f in res["findings"]) and res["threat_detected"])
open("logo.png", "wb").write(rotated)
# MR: carrier + manifest change together -> review only (MEDIUM), does not block
subprocess.run("git add -A && git commit -qm base", shell=True)
base = subprocess.run("git rev-parse HEAD", shell=True, capture_output=True, text=True).stdout.strip()
ne2 = vault.rotate("logo.png", prov)
os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"] = base
res = engine.run(["logo.png", ".stegoops/manifest.json"], cfg)
an = {f["analyzer"] for f in res["findings"]}
check("MR with agreed resealing -> carrier_resealed + carrier_manifest (review)", {"carrier_resealed", "carrier_manifest"} <= an)
check("...but does not block the merge", not res["threat_detected"])
# attacker adds THEIR image to the manifest in MR: the base manifest is trusted
os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"] = base
m = json.load(open(".stegoops/manifest.json")); [e.__setitem__("sha256", "0" * 64) for e in m["carriers"] if e["path"] == "logo.png"]
json.dump(m, open(".stegoops/manifest.json", "w"))
res = engine.run(["logo.png", ".stegoops/manifest.json"], cfg)
check("MR with tampered manifest (hash mismatch) -> tampered/HIGH", any(f["analyzer"] == "carrier_tampered" and f["severity"] == "HIGH" for f in res["findings"]))
subprocess.run("git checkout -q -- .stegoops/manifest.json logo.png", shell=True)
os.environ.pop("CI_MERGE_REQUEST_DIFF_BASE_SHA")

# --- decoy + honeytoken ---
clean2 = "decoy.png"; Image.open(io.BytesIO(clean)).save(clean2)
r = subprocess.run([sys.executable, "-m", "stegoops", "decoy", "--carrier", clean2], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ROOT})
check("decoy: created and registered", "Decoy carrier" in r.stdout and os.path.exists(".purrguard_honey.json"))
tok = None
a = np.packbits(np.array(Image.open(clean2).convert("RGB")).reshape(-1)[:160] & 1).tobytes()
import re
m = re.search(rb"AKIA[0-9A-Z]{16,}", a); tok = m.group() if m else None
check("decoy: ordinary LSB reader finds the decoy (the trap is attractive)", tok is not None)
open("exfil.txt", "wb").write(b"copied: " + tok)
res = engine.run(["decoy.png", "exfil.txt"], engine.load_config())
hit = {f["file"] for f in res["findings"] if f["analyzer"] == "honeytoken"}
check("decoy: same value elsewhere -> CRITICAL honeytoken, the decoy itself does not alert", "exfil.txt" in hit and "decoy.png" not in hit)
check("PurrGuard: logs/findings do not contain secret values", not any(v in json.dumps(res) for v in SECRETS.values()))

print("\nALL PASS" if ok else "\nFAILURES")
sys.exit(0 if ok else 1)
