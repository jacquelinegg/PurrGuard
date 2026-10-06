"""Пълен тест: python tests/test_purrguard.py"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["PURRGUARD_MOCK"] = "1"
for v in ("CI_MERGE_REQUEST_DIFF_BASE_SHA", "GITLAB_API_TOKEN", "ANTHROPIC_API_KEY"):
    os.environ.pop(v, None)

work = tempfile.mkdtemp()
os.chdir(work)
subprocess.run([sys.executable, os.path.join(ROOT, "tests", "make_samples.py")], check=True, capture_output=True)

from core import analyzers as A, baseline, engine, history, sanitize
from dashboard.generate_report import generate
from integrations import fixer, rotation

ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


S = "tests/samples/"
cfg = engine.load_config()
bad = ["chunk.png", "migration.sql", "stego.wav", "stego_lsb.png", "trailing.png"]
good = ["clean.png", "clean.sql", "clean.wav"]
res = engine.run([S + f for f in bad + good], cfg)
flagged = {r["file"] for r in res["findings"]}
check("all 5 infected files are caught", all(S + f in flagged for f in bad))
check("0 false positives on 3 clean files", not any(S + f in flagged for f in good))

# обезвреждане: изчистеният файл вече не дава находки
fixed = fixer.build_fixes(res["findings"], outdir="fixed_out")
check("all infected files are sanitized", len(fixed) == len(bad))
res2 = engine.run(["fixed_out/" + S + f for f in bad], cfg)
check("no findings after sanitization", not res2["findings"])

# ротация
pb = rotation.playbook(res["findings"])
check("AWS key rotation playbook", "update-access-key" in pb)
sa = b'{"type": "service_account", "private_key_id": "' + b"a" * 40 + b'", "client_email": "x@p.iam.gserviceaccount.com", "k": "api_key=ABCDEFGH12345"}'
pb2 = rotation.playbook([{"secrets": A.classify_secret(sa)}])
check("GCP: gcloud iam service-accounts keys disable", "gcloud iam service-accounts keys disable " + "a" * 40 in pb2)

# сравнение с основния клон + история
subprocess.run(["git", "init", "-q", "."])
subprocess.run(["git", "config", "user.email", "a@b"])
subprocess.run(["git", "config", "user.name", "t"])
shutil.copy(S + "clean.png", "logo.png")
subprocess.run(["git", "add", "logo.png"])
subprocess.run(["git", "commit", "-qm", "base"])
base = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
shutil.copy(S + "stego_lsb.png", "logo.png")
subprocess.run(["git", "add", "logo.png"])
subprocess.run(["git", "commit", "-qm", "new logo"])
bl = baseline.compare(["logo.png"], base=base)
check("baseline comparison detects change", {f["analyzer"] for f in bl} >= {"baseline_size"})
subprocess.run(["git", "rm", "-q", "logo.png"])
subprocess.run(["git", "commit", "-qm", "remove"])
h = history.scan_history(cfg)
check("history finds deleted infected file", any(f["file"] == "logo.png" for f in h["findings"]))

# --- демо файлове ---
subprocess.run([sys.executable, os.path.join(ROOT, "tests", "make_demo.py")], check=True, capture_output=True)
dres = engine.run(["demo_files/" + f for f in sorted(os.listdir("demo_files")) if f[0].isdigit()], cfg)
dflag = {os.path.basename(f["file"]) for f in dres["findings"]}
infected = {"02_logo_infected_lsb.png", "03_logo_infected_trailing.png", "04_logo_infected_chunk.png", "06_photo_infected.jpg",
            "08_report_infected.pdf", "10_users_infected.sql", "12_audio_infected.wav"}
clean = {"01_logo_clean.png", "05_photo_clean.jpg", "07_report_clean.pdf", "09_users_clean.sql", "11_audio_clean.wav"}
check("all 7 infected demo files are caught", infected <= dflag)
check("all 5 clean demo files are clean", not (clean & dflag))
from core.explain import explain
ex = explain("demo_files/08_report_infected.pdf")
check("explain shows evidence and independent verification", "EmbeddedFile" in ex and "Verify independently" in ex and "AKIAFAKE" not in ex)
# --- honeytokens ---
from core import honeytokens as H
import re, numpy as np
from PIL import Image
for p in [".env.backup", "config/legacy-credentials.json", "config/maps_api.txt", "scripts/.deploy-token", H.DEFAULT_FILE]:
    if os.path.exists(p):
        os.remove(p) if os.path.isfile(p) else shutil.rmtree(p)
made = H.init(".", "demo-proj")
check("created 4 baits", len(made) == 4)
check("registry stores only hashes", "AKIA" not in open(H.DEFAULT_FILE).read())
tok = re.search(r"AWS_ACCESS_KEY_ID=(AKIA[0-9A-Z]+)", open(".env.backup").read()).group(1).encode()
arr = np.array(Image.open(S + "clean.png").convert("RGB")); flat = arr[:, :, 0].ravel()
bits = np.unpackbits(np.frombuffer(tok, dtype=np.uint8)); flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
arr[:, :, 0] = flat.reshape(arr.shape[:2]); Image.fromarray(arr).save("lsb_token.png")
shutil.copy(S + "clean.png", "tail_token.png"); open("tail_token.png", "ab").write(b"x" + tok)
open("zw_token.sql", "w", encoding="utf-8").write("-- ok" + "".join("\u200c" if b == "1" else "\u200b" for c in tok for b in f"{c:08b}"))
open("notes_token.txt", "wb").write(b"temp: " + tok)
hres = engine.run(["lsb_token.png", "tail_token.png", "zw_token.sql", "notes_token.txt", ".env.backup", "config/legacy-credentials.json", S + "clean.png"], cfg)
hit = {f["file"] for f in hres["findings"] if f["analyzer"] == "honeytoken"}
check("honeytoken in invisible Unicode chars", "zw_token.sql" in hit)
check("honeytoken copied to ordinary file", "notes_token.txt" in hit)
check("baits and clean files do not trigger", not ({".env.backup", "config/legacy-credentials.json", S + "clean.png"} & hit))
check("finding does not reveal bait value", tok.decode() not in str(hres["findings"]))

class FakeLogger:
    def __init__(self): self.rows = []
    def log_struct(self, payload, severity=None): self.rows.append((payload, severity))
class FakeClient:
    def __init__(self): self.lg = FakeLogger()
    def logger(self, name): return self.lg
from integrations import gcp_logging
fc = FakeClient()
sent = gcp_logging.log_findings(res["findings"], {"project": "demo"}, client=fc)
check("Cloud Logging receives all findings", sent == len(res["findings"]))
check("severities mapped (CRITICAL/ERROR)", {s for _, s in fc.lg.rows} <= {"CRITICAL", "ERROR", "WARNING"} and any(s == "CRITICAL" for _, s in fc.lg.rows))
check("no secrets in logs", "AKIAFAKE" not in str(fc.lg.rows))
page = generate("public")
check("dashboard is generated", "PurrGuard" in open(page, encoding="utf-8").read())
print("\nВСИЧКО МИНАВА" if ok else "\nИМА ГРЕШКИ")
sys.exit(0 if ok else 1)
