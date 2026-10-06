"""Deploy smoke test: starts the app with secrets loaded, checks /health, and verifies logs do not contain values.
Run via: python -m stegoops exec --from-image ... --path app/assets/logo.png -- python deploy/smoke.py"""
import json
import os
import subprocess
import sys
import time
import urllib.request

REQUIRED = ["DEMO_DB_PASSWORD", "DEMO_API_TOKEN"]
missing = [n for n in REQUIRED if not os.environ.get(n)]
if missing:
    sys.exit(f"Missing secrets: {missing}")
env = {**os.environ, "PORT": "18080"}
srv = subprocess.Popen([sys.executable, "app/server.py"], env=env)
try:
    for _ in range(30):
        try:
            data = json.load(urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=1))
            break
        except Exception:
            time.sleep(0.2)
    else:
        sys.exit("Application failed to start")
    assert sorted(data["secrets_loaded"]) == sorted(REQUIRED), data
    print("Smoke OK: environment up with", len(data["secrets_loaded"]), "secrets (names only):", data["secrets_loaded"])
    # deliberate exfiltration attempt: the scrubber must hide it in the pipeline logs
    print("canary (should be ***):", os.environ["DEMO_API_TOKEN"])
finally:
    srv.terminate()
