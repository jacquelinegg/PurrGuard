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
SECRET_ENV_BLOCKLIST = {"STEGOOPS_KEK", "STEGOOPS_KMS_KEY", "GITLAB_API_TOKEN", "GCP_SA_KEY_JSON", "ANTHROPIC_API_KEY"}


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


def save_manifest(m, path=MANIFEST):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    json.dump(m, open(path, "w"), indent=2, ensure_ascii=False, sort_keys=True)
    open(path, "a").write("\n")


def find_entry(m, path=None, cid=None):
    for e in m["carriers"]:
        if (path and os.path.normpath(e["path"]) == os.path.normpath(path)) or (cid and e["id"] == cid):
            return e
    raise VaultError(f"No manifest entry for {path or cid}")


def _aad(entry_id: str) -> bytes:
    return b"stegoops:v1:" + entry_id.encode()


def seal(carrier_path, secrets: dict, provider, env="staging", ttl_days=30, out_path=None, manifest_path=MANIFEST):
    """Encrypts secrets and hides them in the carrier. Returns manifest entry (no secrets)."""
    if not secrets:
        raise VaultError("No secrets to seal")
    out_path = out_path or carrier_path
    png = open(carrier_path, "rb").read()
    entry_id = f"{env}:{Path(out_path).as_posix()}"
    expires = (_now() + dt.timedelta(days=ttl_days)).isoformat(timespec="seconds")
    plain = json.dumps({"v": 1, "env": env, "expires_at": expires, "secrets": secrets}, sort_keys=True).encode()
    blob = crypto.encrypt(plain, provider, _aad(entry_id))
    seed = os.urandom(32)
    sealed = lsb.embed(png, seed, blob)
    open(out_path, "wb").write(sealed)
    entry = {"id": entry_id, "path": Path(out_path).as_posix(), "sha256": _sha(sealed), "env": env,
             "names": sorted(secrets), "created": _now().isoformat(timespec="seconds"), "expires_at": expires,
             "provider": provider.name, "locator": base64.b64encode(provider.wrap(seed, _aad(entry_id))).decode(),
             "payload_bytes": len(blob)}
    if getattr(provider, "key_name", None):
        entry["kms_key"] = provider.key_name  # не е тайна
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
    """New DEK, new seed (new positions), new TTL. Old positions are overwritten with random bits so old ciphertext does not remain in the image."""
    m = load_manifest(manifest_path)
    e = find_entry(m, path=carrier_path)
    png = open(carrier_path, "rb").read()
    secrets = open_bytes(png, e, provider, allow_expired=True)
    old_seed = provider.unwrap(base64.b64decode(e["locator"]), _aad(e["id"]))
    open(carrier_path, "wb").write(lsb.wipe(png, old_seed))
    return seal(carrier_path, secrets, provider, env=e["env"], ttl_days=ttl_days, manifest_path=manifest_path)


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
        from core.analyzers import SECRET_RE  # същите шаблони като PurrGuard
        residual = len(SECRET_RE.findall(open(log_path, "rb").read())) if log_path else 0
        json.dump({"exit_code": rc, "secrets_loaded": sorted(secrets), "scrubbed_occurrences": scrubber.hits,
                   "residual_secret_patterns_in_log": residual, "verdict": "clean" if residual == 0 else "leak",
                   "finished": _now().isoformat(timespec="seconds")}, open(report_path, "w"), indent=2)
    return rc


def make_decoy(carrier_path, honeytoken_value: str, out_path=None):
    """Decoy носител: последователен LSB с honeytoken (какъвто намират обикновени инструменти като zsteg)."""
    out_path = out_path or carrier_path
    data = lsb.embed_plain(open(carrier_path, "rb").read(), honeytoken_value.encode())  # първо четем, после пишем
    open(out_path, "wb").write(data)
    return out_path
