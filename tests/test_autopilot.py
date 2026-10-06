"""Тест на hands-off цикъла (ротация), MCP сървъра, резервния режим и структурата на flows/CI. Само ФАЛШИВИ тайни и фалшив GitLab API."""
import base64
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
for v in ("CI_MERGE_REQUEST_DIFF_BASE_SHA", "STEGOOPS_KMS_KEY", "GITLAB_API_TOKEN", "ANTHROPIC_API_KEY", "STEGOOPS_MANIFEST"):
    os.environ.pop(v, None)
os.environ["PURRGUARD_MOCK"] = "1"
os.environ["CI_DEFAULT_BRANCH"] = "main"
work = tempfile.mkdtemp()
os.chdir(work)

import yaml

from stegoops import autorotate, crypto, vault
from stegoops.__main__ import make_logo

ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


class Resp:
    def __init__(self, code, data=None):
        self.status_code, self._d = code, data if data is not None else {}

    def json(self):
        return self._d


class FakeGitLab:
    """Минимален фалшив GitLab API: записва заявките, пази issue-та."""
    def __init__(self, automerge_fail_first=0):
        self.calls, self.issues, self.fail = [], [], automerge_fail_first

    def request(self, method, url, headers=None, timeout=None, **kw):
        path = url.split("/projects/1", 1)[1]
        self.calls.append((method, path, kw))
        assert headers["PRIVATE-TOKEN"] == "fake-token"
        if method == "GET" and path == "/issues":
            return Resp(200, [i for i in self.issues if kw["params"]["labels"] in i["labels"]])
        if method == "POST" and path == "/issues":
            i = {"iid": 7, "web_url": "https://gl/issues/7", "labels": [kw["json"]["labels"]], **kw["json"]}
            self.issues.append(i)
            return Resp(201, i)
        if path.startswith("/repository/branches"):
            return Resp(201, {})
        if path.startswith("/repository/commits"):
            return Resp(201, {"id": "abc"})
        if method == "POST" and path == "/merge_requests":
            return Resp(201, {"iid": 9, "web_url": "https://gl/mr/9"})
        if method == "PUT" and path.endswith("/merge"):
            if self.fail:
                self.fail -= 1
                return Resp(405)
            return Resp(200, {})
        return Resp(404)


kek = crypto.generate_kek()
os.environ["STEGOOPS_KEK"] = kek
prov = crypto.EnvProvider(kek)
SECRETS = {"DB_PASSWORD": "FAKE-db-pass-123456", "API_TOKEN": "FAKE-token-abcdef987654"}
make_logo("app_logo.png")
vault.seal("app_logo.png", SECRETS, prov, env="staging", ttl_days=3)       # изтича след 3 дни
make_logo("far.png")
vault.seal("far.png", {"X": "FAKE-far-token-0000"}, prov, env="prod", ttl_days=90)

# --- наближаващ срок ---
exp = autorotate.expiring(within_days=7)
check("expiring: само носителят с близък срок", [e["path"] for e in exp] == ["app_logo.png"])
check("expiring: показва имена, не стойности", exp[0]["names"] == ["API_TOKEN", "DB_PASSWORD"] and "FAKE" not in json.dumps(exp))
out = subprocess.run([sys.executable, "-m", "stegoops", "verify", "--warn-days", "7", "--json"], capture_output=True, text=True,
                     env={**os.environ, "PYTHONPATH": ROOT})
j = json.loads(out.stdout)
check("verify --json: ok и expiring", j["ok"] and len(j["expiring"]) == 1)

# --- watch: issue се отваря веднъж ---
gl = autorotate.GitLab("https://gl/api/v4", "1", "fake-token", session=FakeGitLab())
issue, items = autorotate.watch(7, gl)
issue2, _ = autorotate.watch(7, gl)
check("watch: отваря issue с етикет", issue["iid"] == 7 and len(gl.s.issues) == 1)
check("watch: няма дубликат при втори опит", len(gl.s.issues) == 1 and issue2["iid"] == 7)
check("watch: описанието не съдържа стойности на тайни", "FAKE" not in json.dumps(gl.s.issues[0]))

# --- ротация -> branch -> commit -> MR -> auto-merge ---
old = vault.load_manifest()["carriers"]
old_loc = {e["path"]: e["locator"] for e in old}
fake = FakeGitLab(automerge_fail_first=2)
gl = autorotate.GitLab("https://gl/api/v4", "1", "fake-token", session=fake)
res = autorotate.rotate_and_open_mr(7, crypto.get_provider, 30, gl, sleep=lambda s: None)
check("rotate: върнат е MR и auto-merge е зададен (след повторни опити)", res and res["iid"] == 9 and res["auto_merge"])
check("rotate: auto-merge е опитан 3 пъти (2 пъти 405)", sum(1 for c in fake.calls if c[0] == "PUT") == 3)
commit = next(c for c in fake.calls if c[1].startswith("/repository/commits"))[2]["json"]
paths = sorted(a["file_path"] for a in commit["actions"])
check("commit: само носителят и манифестът", paths == [".stegoops/manifest.json", "app_logo.png"])
png = base64.b64decode(next(a for a in commit["actions"] if a["file_path"] == "app_logo.png")["content"])
m = vault.load_manifest()
e = vault.find_entry(m, path="app_logo.png")
check("commit: съдържанието съвпада с новия хеш в манифеста", vault._sha(png) == e["sha256"])
check("ротация: нов локатор, тайните са същите", e["locator"] != old_loc["app_logo.png"] and vault.open_bytes(png, e, prov) == SECRETS)
check("ротация: наближаващите срокове изчезват", autorotate.expiring(within_days=7) == [])
check("rotate: далечният носител не е пипнат", vault.find_entry(m, path="far.png")["locator"] == old_loc["far.png"])
mr = next(c for c in fake.calls if c[1] == "/merge_requests")[2]["json"]
check("MR: Closes #issue, етикет и клон stegoops/rotate-*", "Closes #7" in mr["description"] and mr["source_branch"].startswith("stegoops/rotate-"))
check("rotate: втори път няма какво да прави", autorotate.rotate_and_open_mr(7, crypto.get_provider, 30, gl, sleep=lambda s: None) is None)
check("auto-merge: безкраен 405 -> False, не срив", not autorotate.GitLab("https://gl/api/v4", "1", "fake-token", session=FakeGitLab(99)).automerge(9, retries=3, sleep=lambda s: None))

# --- guard-rotation (истински git репо) ---
def git(*a):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], capture_output=True, text=True, check=True).stdout.strip()


git("init", "-q"); git("add", "-A"); git("commit", "-qm", "base")
base = git("rev-parse", "HEAD")
vault.rotate("far.png", prov, 30)
git("add", "-A"); git("commit", "-qm", "rot")
check("guard-rotation: само носители/манифест -> OK", autorotate.guard_rotation(base) == [])
open("evil.py", "w").write("print(1)\n")
git("add", "-A"); git("commit", "-qm", "evil")
check("guard-rotation: допълнителен файл -> нарушение", autorotate.guard_rotation(base) == ["evil.py"])
r = subprocess.run([sys.executable, "-m", "stegoops", "guard-rotation", "--base", base], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ROOT})
check("CLI guard-rotation връща 1 при нарушение", r.returncode == 1 and "evil.py" in r.stdout)

# --- резервен режим (--fallback-local) ---
env = {**os.environ, "PYTHONPATH": ROOT, "CI_JOB_TOKEN": "x"}
code = "import os;print('got', sorted(k for k in ('DB_PASSWORD','API_TOKEN') if os.environ.get(k)))"
r = subprocess.run([sys.executable, "-m", "stegoops", "exec", "--from-image", "127.0.0.1:1/x/y:z", "--path", "app_logo.png", "--fallback-local", "--", sys.executable, "-c", code],
                   capture_output=True, text=True, env=env, timeout=60)
check("fallback-local: registry недостъпен -> тайните пак се зареждат от пинатия локален носител", r.returncode == 0 and "API_TOKEN" in r.stdout and "FAKE" not in r.stdout + r.stderr)
r = subprocess.run([sys.executable, "-m", "stegoops", "exec", "--from-image", "127.0.0.1:1/x/y:z", "--path", "app_logo.png", "--", sys.executable, "-c", code],
                   capture_output=True, text=True, env=env, timeout=60)
check("без --fallback-local грешката не се замазва", r.returncode != 0)

# --- MCP сървър ---
msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "stegoops_verify", "arguments": {"warn_days": 7}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "nope"}}]
p = subprocess.run([sys.executable, "-m", "stegoops.mcp_server"], input="\n".join(json.dumps(x) for x in msgs) + "\n", capture_output=True, text=True,
                   env={**os.environ, "PYTHONPATH": ROOT})
rs = [json.loads(x) for x in p.stdout.strip().split("\n")]
check("MCP: 4 отговора (нотификацията няма отговор)", [r["id"] for r in rs] == [1, 2, 3, 4])
check("MCP: tools/list съдържа 3 инструмента", len(rs[1]["result"]["tools"]) == 3)
check("MCP: verify връща данни без стойности на тайни", "FAKE" not in p.stdout and json.loads(rs[2]["result"]["content"][0]["text"])["ok"] is not None)
check("MCP: непознат инструмент -> JSON-RPC грешка", rs[3]["error"]["code"] == -32602)

# --- структура на flows и CI ---
for f in ("stegoops-deploy-sentinel", "stegoops-mr-guardian"):
    d = yaml.safe_load(open(f"{ROOT}/duo/flows/{f}.yaml"))
    comps = {c["name"]: c for c in d["components"]}
    prompts = {p["prompt_id"] for p in d["prompts"]}
    schemas = {s["schema_id"]: set(s["definition"]["properties"]) for s in d["response_schemas"]}
    bad = []
    for c in comps.values():
        if c["type"] == "AgentComponent" and c["prompt_id"] not in prompts:
            bad.append(("prompt", c["name"]))
        for i in c.get("inputs", []):
            ref = i["from"].split(":", 1)[1]
            if ref.count(".") == 2:  # component.final_answer.field
                comp, _, fld = ref.split(".")
                if comp not in comps or fld not in schemas.get(comps[comp].get("response_schema_id"), set()):
                    bad.append(("input", ref))
    for r in d["routers"]:
        targets = [r["to"]] if "to" in r else list(r["condition"]["routes"].values())
        bad += [("route", t) for t in targets if t != "end" and t not in comps]
        if r["from"] not in comps:
            bad.append(("from", r["from"]))
    check(f"flow {f}: всички prompt/input/route референции съществуват", not bad)
    if bad:
        print("   ", bad)
ci = yaml.safe_load(open(f"{ROOT}/.gitlab-ci.yml"))
jobs = {k: v for k, v in ci.items() if isinstance(v, dict) and "stage" in v}
check("CI: всички етапи на задачите са декларирани", all(j["stage"] in ci["stages"] for j in jobs.values()))
check("CI: needs сочат към съществуващи задачи", all(n in jobs for j in jobs.values() for n in j.get("needs", [])))
check("CI: ключовите задачи са налични", {"rotate-secrets", "expiry-watch", "rotation-guard", "deploy-cloudrun", "deploy-staging"} <= set(jobs))
check("CI: KEK не е записан в pipeline файла (идва само от защитената променлива)", "STEGOOPS_KEK" not in json.dumps(ci))

print("\nВСИЧКО МИНАВА" if ok else "\nИМА ГРЕШКИ")
sys.exit(0 if ok else 1)
