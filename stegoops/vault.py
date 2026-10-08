"""seal / open / verify / rotate / exec. Revealed secrets live only in memory and the child process environment."""
import base64
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from . import crypto, lsb
from .scrub import Scrubber

MANIFEST = ".stegoops/manifest.json"
# The child process must not receive anything that can push to the registry/repo or
# decrypt carriers. GOOGLE_APPLICATION_CREDENTIALS stays: the deploy step itself needs it.
SECRET_ENV_BLOCKLIST = {"STEGOOPS_KEK", "STEGOOPS_KMS_KEY", "GITLAB_API_TOKEN", "GCP_SA_KEY_JSON",
                        "ANTHROPIC_API_KEY", "CI_JOB_TOKEN", "CI_REPOSITORY_URL"}


class VaultError(Exception):
    pass


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_manifest(path=MANIFEST):
    if not os.path.exists(path):
        return {"version": 1, "carriers": []}
    return json.load(open(path))


def _atomic_write(path, data):
    """Write through a temporary file and os.replace, so a crash can never
    leave a half-written carrier or manifest on disk."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_manifest(m, path=MANIFEST):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    _atomic_write(path, (json.dumps(m, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))


def find_entry(m, path=None, cid=None):
    for e in m["carriers"]:
        if (path and os.path.normpath(e["path"]) == os.path.normpath(path)) or (cid and e["id"] == cid):
            return e
    raise VaultError(f"No manifest entry for {path or cid}")


def _aad(entry_id: str) -> bytes:
    return b"stegoops:v1:" + entry_id.encode()


def _seal_bytes(png, secrets: dict, provider, entry_id: str, env, ttl_days, path) -> tuple:
    """Encrypts secrets and hides them in the carrier bytes. Returns (sealed_bytes, entry)."""
    expires = (_now() + dt.timedelta(days=ttl_days)).isoformat(timespec="seconds")
    plain = json.dumps({"v": 1, "env": env, "expires_at": expires, "secrets": secrets}, sort_keys=True).encode()
    blob = crypto.encrypt(plain, provider, _aad(entry_id))
    seed = os.urandom(32)
    sealed = lsb.embed(png, seed, blob)
    entry = {"id": entry_id, "path": Path(path).as_posix(), "sha256": _sha(sealed), "env": env,
             "names": sorted(secrets), "created": _now().isoformat(timespec="seconds"), "expires_at": expires,
             "provider": provider.name, "locator": base64.b64encode(provider.wrap(seed, _aad(entry_id))).decode(),
             "payload_bytes": len(blob)}
    if getattr(provider, "key_name", None):
        entry["kms_key"] = provider.key_name  # not a secret
    return sealed, entry


def seal(carrier_path, secrets: dict, provider, env="staging", ttl_days=30, out_path=None, manifest_path=MANIFEST):
    """Encrypts secrets and hides them in the carrier. Returns manifest entry (no secrets)."""
    if not secrets:
        raise VaultError("No secrets to seal")
    out_path = out_path or carrier_path
    png = open(carrier_path, "rb").read()
    entry_id = f"{env}:{Path(out_path).as_posix()}"
    sealed, entry = _seal_bytes(png, secrets, provider, entry_id, env, ttl_days, out_path)
    _atomic_write(out_path, sealed)
    m = load_manifest(manifest_path)
    m["carriers"] = [e for e in m["carriers"] if e["id"] != entry_id] + [entry]
    save_manifest(m, manifest_path)
    return entry


def open_bytes(png: bytes, entry: dict, provider, allow_expired=False) -> dict:
    """Decrypts entirely in memory. Verifies carrier hash against manifest (supply chain integrity)."""
    if _sha(png) != entry["sha256"]:
        raise VaultError("Carrier does not match manifest (SHA-256) - tampered or corrupted file")
    aad = _aad(entry["id"])
    seed = provider.unwrap(base64.b64decode(entry["locator"]), aad)
    try:
        blob = lsb.extract(png, seed)
    except lsb.StegoError as e:
        raise VaultError(str(e)) from e
    data = json.loads(crypto.decrypt(blob, provider, aad))
    exp = dt.datetime.fromisoformat(data["expires_at"])
    if not allow_expired and _now() > exp:
        raise VaultError(f"Package expired on {data['expires_at']} - re-seal (rotate)")
    return data["secrets"]


def verify(manifest_path=MANIFEST):
    """Checks without key: hashes, missing files, expiry. Returns problems list (empty = OK)."""
    problems = []
    for e in load_manifest(manifest_path)["carriers"]:
        p = Path(e["path"])
        if not p.exists():
            problems.append(f"{e['path']}: file missing")
            continue
        if _sha(p.read_bytes()) != e["sha256"]:
            problems.append(f"{e['path']}: SHA-256 does not match manifest")
        if _now() > dt.datetime.fromisoformat(e["expires_at"]):
            problems.append(f"{e['path']}: package expired ({e['expires_at']})")
    return problems


def rotate(carrier_path, provider, ttl_days=30, manifest_path=MANIFEST):
    """New DEK, new seed (new positions), new TTL. Old positions are overwritten with random bits so
    old ciphertext does not remain in the image. The carrier is replaced in a single atomic write:
    if anything fails, the original (still valid) carrier stays on disk - the secrets are never destroyed."""
    m = load_manifest(manifest_path)
    e = find_entry(m, path=carrier_path)
    png = open(carrier_path, "rb").read()
    secrets = open_bytes(png, e, provider, allow_expired=True)
    old_seed = provider.unwrap(base64.b64decode(e["locator"]), _aad(e["id"]))
    wiped = lsb.wipe(png, old_seed)  # in memory only: nothing touches the disk until the new carrier is ready
    sealed, entry = _seal_bytes(wiped, secrets, provider, e["id"], e["env"], ttl_days, carrier_path)
    _atomic_write(carrier_path, sealed)
    m["carriers"] = [x for x in m["carriers"] if x["id"] != e["id"]] + [entry]
    save_manifest(m, manifest_path)
    return entry


def _pump(src, dst, scrubber, log):
    for line in iter(src.readline, b""):
        clean = scrubber.scrub(line)
        dst.write(clean)
        dst.flush()
        if log:
            log.write(clean)


def run_with_secrets(secrets: dict, cmd, scrub=True, log_path=None, report_path=None) -> int:
    """Runs cmd with secrets only in its environment. Output passes through scrubber. KEK/tokens are not passed.
    report_path: JSON for audit (counters and names only, never values) - read by the Duo agent."""
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV_BLOCKLIST}
    env.update(secrets)
    scrubber = Scrubber(secrets.values()) if scrub else Scrubber([])
    log = open(log_path, "wb") if log_path else None
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    t = [threading.Thread(target=_pump, args=(p.stdout, sys.stdout.buffer, scrubber, log)),
         threading.Thread(target=_pump, args=(p.stderr, sys.stderr.buffer, scrubber, log))]
    [x.start() for x in t]
    rc = p.wait()
    [x.join() for x in t]
    if log:
        log.close()
    if report_path:
        from core.analyzers import SECRET_RE  # same patterns as PurrGuard
        residual = len(SECRET_RE.findall(open(log_path, "rb").read())) if log_path else 0
        json.dump({"exit_code": rc, "secrets_loaded": sorted(secrets), "scrubbed_occurrences": scrubber.hits,
                   "residual_secret_patterns_in_log": residual, "verdict": "clean" if residual == 0 else "leak",
                   "finished": _now().isoformat(timespec="seconds")}, open(report_path, "w"), indent=2)
    return rc


def make_decoy(carrier_path, honeytoken_value: str, out_path=None):
    """Decoy carrier: sequential LSB with honeytoken (what ordinary tools like zsteg find)."""
    out_path = out_path or carrier_path
    data = lsb.embed_plain(open(carrier_path, "rb").read(), honeytoken_value.encode())  # read first, then write
    _atomic_write(out_path, data)
    return out_path
