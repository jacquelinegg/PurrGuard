"""Тест на Stego-Ops и интеграцията му с PurrGuard: python tests/test_stegoops.py  (само ФАЛШИВИ тайни)"""
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

# --- криптография + стеганография ---
e = vault.seal("logo.png", SECRETS, prov, env="staging")
sealed = open("logo.png", "rb").read()
check("round-trip: тайните се връщат непроменени", vault.open_bytes(sealed, e, prov) == SECRETS)
a, b = np.array(Image.open(io.BytesIO(clean))).astype(int), np.array(Image.open(io.BytesIO(sealed))).astype(int)
check("картинката се променя най-много с 1 от 255 на пиксел", np.abs(a - b).max() <= 1)
check("файлът не съдържа тайните в чист вид", all(v.encode() not in sealed for v in SECRETS.values()))
check("грешен KEK не отключва", raises(lambda: vault.open_bytes(sealed, e, crypto.EnvProvider(crypto.generate_kek())), crypto.CryptoError))
check("подменен носител се отхвърля (SHA-256)", raises(lambda: vault.open_bytes(sealed + b"x", e, prov), vault.VaultError))
e2 = dict(e, id="prod:logo.png")
check("носител не може да се използва под друг идентификатор (AAD)", raises(lambda: vault.open_bytes(sealed, e2, prov), crypto.CryptoError))
arr = np.array(Image.open(io.BytesIO(sealed)))
arr.reshape(-1)[:200000:7] ^= 1  # повреждане на пиксели
buf = io.BytesIO(); Image.fromarray(arr).save(buf, "PNG")
bad = dict(e, sha256=vault._sha(buf.getvalue()))
check("повредени payload битове се засичат (GCM таг)", raises(lambda: vault.open_bytes(buf.getvalue(), bad, prov), (crypto.CryptoError, vault.VaultError, lsb.StegoError, json.JSONDecodeError)))
check("sequential LSB четец (като zsteg) не намира нищо четимо",
      b"FAKE" not in np.packbits(np.array(Image.open(io.BytesIO(sealed)).convert("RGB")).reshape(-1) & 1).tobytes())

# --- срок на валидност + ротация ---
Image.open(io.BytesIO(clean)).save("old.png")
ee = vault.seal("old.png", {"X_TOKEN": "FAKE-expired-token"}, prov, env="old", ttl_days=-1)
check("изтекъл пакет се отказва", raises(lambda: vault.open_bytes(open("old.png", "rb").read(), ee, prov), vault.VaultError))
check("verify detects expired package", any("expired" in p for p in vault.verify()))
old_loc = e["locator"]
ne = vault.rotate("logo.png", prov, ttl_days=30)
rotated = open("logo.png", "rb").read()
check("ротация: нов seed/локатор и нов хеш", ne["locator"] != old_loc and ne["sha256"] != e["sha256"])
check("ротация: тайните са същите", vault.open_bytes(rotated, ne, prov) == SECRETS)
old_seed = prov.unwrap(base64.b64decode(old_loc), vault._aad(e["id"]))
try:
    stale = lsb.extract(rotated, old_seed)
    check("ротация: старото шифротекст е унищожено", not stale.startswith(crypto.MAGIC))
except lsb.StegoError:
    check("ротация: старото шифротекст е унищожено", True)

# --- скрубер + изпълнение ---
sc = Scrubber(SECRETS.values())
leak = ("pw=" + SECRETS["DB_PASSWORD"] + " b64=" + base64.b64encode(SECRETS["API_TOKEN"].encode()).decode() + " " + "line-two-FAKE-key").encode()
out = sc.scrub(leak)
check("скруберът маскира суров, base64 и многоредов вид", not any(x in out for x in (b"FAKE-db-pass", b"RkFLRS10b2tlbi", b"line-two-FAKE")))
os.environ["STEGOOPS_KEK"] = kek
r = subprocess.run([sys.executable, "-m", "stegoops", "exec", "--carrier", "logo.png", "--", sys.executable, "-c",
                    "import os;print(os.environ['DB_PASSWORD']);print('KEK' , os.environ.get('STEGOOPS_KEK'))"],
                   capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ROOT})
check("exec: тайната е достъпна за процеса, но логът е скрубнат", "***" in r.stdout and "FAKE-db-pass" not in r.stdout + r.stderr)
check("exec: KEK не се предава на дъщерния процес", "KEK None" in r.stdout)
leftovers = [f for f in os.listdir(".") if f.endswith((".env", ".json")) and f != "x"]
check("няма временни файлове с тайни на диска", not any("FAKE" in open(f, errors="ignore").read() for f in leftovers if os.path.isfile(f)))

# --- Container Registry (фалшив регистър) ---
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
check("registry: взима файла от най-горния слой (стрийминг, без диск)", got == rotated)
check("registry: извлеченият носител се отключва", vault.open_bytes(got, ne, prov) == SECRETS)
check("registry: липсващ файл -> грешка", raises(lambda: registry.fetch_file("reg.test/g/p:t", "nope.png", session=FakeSession(), password="x"), registry.RegistryError))

# --- интеграция с PurrGuard ---
subprocess.run("git init -q . && git config user.email a@b && git config user.name t", shell=True)
os.makedirs("tests/samples", exist_ok=True)
cfg = engine.load_config()
res = engine.run(["logo.png"], cfg)
check("PurrGuard: авторизираният носител е разпознат и не алармира", "logo.png" in res["authorized_carriers"] and not res["threat_detected"])
evil = np.array(Image.open("logo.png")).copy(); evil.reshape(-1)[:60000] = (evil.reshape(-1)[:60000] & 0xFE) | np.random.default_rng(1).integers(0, 2, 60000, dtype=np.uint8)
Image.fromarray(evil).save("logo.png")
res = engine.run(["logo.png"], cfg)
check("PurrGuard: подменен носител (хешът не съвпада) е CRITICAL", any(f["analyzer"] == "carrier_tampered" and f["severity"] == "CRITICAL" for f in res["findings"]) and res["threat_detected"])
open("logo.png", "wb").write(rotated)
# MR: носител + манифест се променят заедно -> само преглед (MEDIUM), не блокира
subprocess.run("git add -A && git commit -qm base", shell=True)
base = subprocess.run("git rev-parse HEAD", shell=True, capture_output=True, text=True).stdout.strip()
ne2 = vault.rotate("logo.png", prov)
os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"] = base
res = engine.run(["logo.png", ".stegoops/manifest.json"], cfg)
an = {f["analyzer"] for f in res["findings"]}
check("MR със съгласувано презапечатване -> carrier_resealed + carrier_manifest (преглед)", {"carrier_resealed", "carrier_manifest"} <= an)
check("...но не блокира merge-а", not res["threat_detected"])
# атакуващ добавя СВОЯ картинка в манифеста в MR: манифестът от базата е доверен
os.environ["CI_MERGE_REQUEST_DIFF_BASE_SHA"] = base
m = json.load(open(".stegoops/manifest.json")); [e.__setitem__("sha256", "0" * 64) for e in m["carriers"] if e["path"] == "logo.png"]
json.dump(m, open(".stegoops/manifest.json", "w"))
res = engine.run(["logo.png", ".stegoops/manifest.json"], cfg)
check("MR с подправен манифест (хеш, който не съвпада) -> tampered/HIGH", any(f["analyzer"] == "carrier_tampered" and f["severity"] == "HIGH" for f in res["findings"]))
subprocess.run("git checkout -q -- .stegoops/manifest.json logo.png", shell=True)
os.environ.pop("CI_MERGE_REQUEST_DIFF_BASE_SHA")

# --- decoy + honeytoken ---
clean2 = "decoy.png"; Image.open(io.BytesIO(clean)).save(clean2)
r = subprocess.run([sys.executable, "-m", "stegoops", "decoy", "--carrier", clean2], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ROOT})
check("decoy: създаден и регистриран", "Decoy носител" in r.stdout and os.path.exists(".purrguard_honey.json"))
tok = None
a = np.packbits(np.array(Image.open(clean2).convert("RGB")).reshape(-1)[:160] & 1).tobytes()
import re
m = re.search(rb"AKIA[0-9A-Z]{16}", a); tok = m.group() if m else None
check("decoy: обикновен LSB четец намира примамката (капанът е примамлив)", tok is not None)
open("exfil.txt", "wb").write(b"copied: " + tok)
res = engine.run(["decoy.png", "exfil.txt"], engine.load_config())
hit = {f["file"] for f in res["findings"] if f["analyzer"] == "honeytoken"}
check("decoy: същата стойност другаде -> CRITICAL honeytoken, самият decoy не алармира", "exfil.txt" in hit and "decoy.png" not in hit)
check("PurrGuard: логовете/находките не съдържат стойностите на тайните", not any(v in json.dumps(res) for v in SECRETS.values()))

print("\nВСИЧКО МИНАВА" if ok else "\nИМА ГРЕШКИ")
sys.exit(0 if ok else 1)
