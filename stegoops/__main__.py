"""python -m stegoops <command>. Never prints secret values."""
import argparse
import json
import os
import sys

import numpy as np
import requests
from PIL import Image, ImageDraw

from . import crypto, registry, vault

DEMO_SECRETS = {"DEMO_DB_PASSWORD": "demo-FAKE-db-pass-9f3a1c", "DEMO_API_TOKEN": "demo-FAKE-token-77b2e4d9a1"}
LOGO = "app/assets/logo.png"


def make_logo(path=LOGO, size=512):
    """Demo logo with fine noise (like film grain). Flat images are poor LSB carriers."""
    y, x = np.mgrid[0:size, 0:size]
    base = 70 + 0.12 * x + 0.08 * y + 25 * np.sin(x / 41) * np.cos(y / 57)
    rng = np.random.default_rng(7)
    img = np.stack([base * 0.9, base * 0.75, base * 1.1], -1) + rng.normal(0, 6, (size, size, 3))
    im = Image.fromarray(np.clip(img, 0, 255).astype(np.uint8))
    d, c = ImageDraw.Draw(im), size // 2
    d.ellipse([c - 120, c - 90, c + 120, c + 130], fill=(235, 190, 120))
    d.polygon([(c - 120, c - 40), (c - 90, c - 190), (c - 30, c - 85)], fill=(235, 190, 120))
    d.polygon([(c + 120, c - 40), (c + 90, c - 190), (c + 30, c - 85)], fill=(235, 190, 120))
    d.ellipse([c - 60, c - 30, c - 30, c], fill=(30, 30, 30)); d.ellipse([c + 30, c - 30, c + 60, c], fill=(30, 30, 30))
    d.polygon([(c - 12, c + 20), (c + 12, c + 20), (c, c + 38)], fill=(200, 90, 100))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    arr = np.array(im, dtype=np.int16) + rng.integers(-2, 3, (size, size, 3))  # final grain over the figure
    Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8)).save(path)
    return path


def _collect_secrets(a):
    s = {}
    if a.json:
        s.update(json.load(sys.stdin if a.json == "-" else open(a.json)))
    for n in a.from_env or []:
        if n not in os.environ:
            sys.exit(f"Missing environment variable {n}")
        s[n] = os.environ[n]
    for kv in a.secret or []:
        k, _, v = kv.partition("=")
        s[k] = v
    return s


def _entry_and_png(a, m):
    if a.from_image:
        e = vault.find_entry(m, path=a.path)
        try:
            return e, registry.fetch_file(a.from_image, a.path)
        except (registry.RegistryError, requests.RequestException) as err:
            if not (getattr(a, "fallback_local", False) and os.path.isfile(a.path)):
                raise
            print(f"WARNING: registry unreachable ({err}); using local carrier - SHA-256 pin still verified", file=sys.stderr)
            return e, open(a.path, "rb").read()
    e = vault.find_entry(m, path=a.carrier)
    return e, open(a.carrier, "rb").read()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd_tail = []
    if "--" in argv:
        i = argv.index("--")
        argv, cmd_tail = argv[:i], argv[i + 1:]
    p = argparse.ArgumentParser(prog="stegoops")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("init-demo")
    v = sub.add_parser("verify"); v.add_argument("--warn-days", type=int); v.add_argument("--json", action="store_true")
    w = sub.add_parser("watch"); w.add_argument("--within", type=int, default=7)
    ar = sub.add_parser("autorotate"); ar.add_argument("--within", type=int, default=7); ar.add_argument("--ttl-days", type=int, default=30)
    g = sub.add_parser("guard-rotation"); g.add_argument("--base", required=True)
    s = sub.add_parser("seal"); s.add_argument("--carrier", required=True); s.add_argument("--out")
    s.add_argument("--env", default="staging"); s.add_argument("--ttl-days", type=int, default=30)
    s.add_argument("--json"); s.add_argument("--from-env", nargs="*"); s.add_argument("--secret", nargs="*")
    for n in ("inspect", "exec", "rotate"):
        x = sub.add_parser(n); x.add_argument("--carrier"); x.add_argument("--from-image"); x.add_argument("--path")
        x.add_argument("--ttl-days", type=int, default=30)
        x.add_argument("--log-file"); x.add_argument("--report")
        x.add_argument("--fallback-local", action="store_true", help="if registry is unreachable, use --path from checkout (hash still verified)")
    d = sub.add_parser("decoy"); d.add_argument("--carrier", required=True); d.add_argument("--out")
    a = p.parse_args(argv)
    manifest = os.environ.get("STEGOOPS_MANIFEST", vault.MANIFEST)

    try:
        if a.cmd == "keygen":
            print(crypto.generate_kek())
            print("^ save as masked + protected CI variable STEGOOPS_KEK. Do not commit.", file=sys.stderr)
        elif a.cmd == "init-demo":
            kek = crypto.generate_kek()
            make_logo()
            e = vault.seal(LOGO, DEMO_SECRETS, crypto.EnvProvider(kek), env="staging", manifest_path=manifest)
            print(f"Sealed {len(e['names'])} FAKE secrets in {LOGO} (manifest: {manifest})")
            print("export STEGOOPS_KEK=" + kek)
        elif a.cmd == "seal":
            sec = _collect_secrets(a)
            e = vault.seal(a.carrier, sec, crypto.get_provider(), a.env, a.ttl_days, a.out, manifest)
            print(f"OK: {len(sec)} secrets -> {e['path']} | valid until {e['expires_at']} | SHA-256 {e['sha256'][:12]}...")
        elif a.cmd == "verify":
            from . import autorotate
            probs = vault.verify(manifest)
            warn = autorotate.expiring(manifest, a.warn_days) if a.warn_days is not None else []
            if a.json:
                print(json.dumps({"ok": not probs, "problems": probs, "expiring": warn}, ensure_ascii=False))
            else:
                print("\n".join(probs) if probs else "OK: all carriers match manifest")
                for it in warn:
                    print(f"WARNING: {it['path']} expires in {it['days_left']} days")
            return 1 if probs else 0
        elif a.cmd == "watch":
            from . import autorotate
            issue, items = autorotate.watch(a.within, manifest_path=manifest)
            print(json.dumps({"expiring": items, "issue": issue and issue.get("web_url")}, ensure_ascii=False))
        elif a.cmd == "autorotate":
            from . import autorotate
            res = autorotate.rotate_and_open_mr(a.within, crypto.get_provider, a.ttl_days, manifest_path=manifest)
            print(json.dumps(res or {"rotated": False, "reason": "no nearing expiry"}, ensure_ascii=False))
        elif a.cmd == "guard-rotation":
            from . import autorotate
            bad = autorotate.guard_rotation(a.base, manifest)
            print("ERROR: rotation MR touches forbidden files: " + ", ".join(bad) if bad else "OK: only carriers and manifest changed")
            return 1 if bad else 0
        elif a.cmd == "decoy":
            from core import honeytokens as H
            tok = H.GEN["aws_access_key"]()
            out = vault.make_decoy(a.carrier, tok, a.out)
            tid = H.add("aws_access_key", tok, os.path.normpath(out))
            print(f"Decoy carrier: {out} (registered honeytoken {tid}; value not shown)")
        else:
            m = vault.load_manifest(manifest)
            e, png = _entry_and_png(a, m)
            if a.cmd == "rotate":
                ne = vault.rotate(a.carrier, crypto.get_provider(e["provider"]), a.ttl_days, manifest)
                print(f"Rotated: {ne['path']} | new valid until {ne['expires_at']}")
                return 0
            secrets = vault.open_bytes(png, e, crypto.get_provider(e["provider"]))
            if a.cmd == "inspect":
                print(json.dumps({"id": e["id"], "names": sorted(secrets), "expires_at": e["expires_at"]}, indent=2))
            else:
                if not cmd_tail:
                    sys.exit("Missing command after --")
                return vault.run_with_secrets(secrets, cmd_tail, log_path=a.log_file, report_path=a.report)
    except (crypto.CryptoError, vault.VaultError, registry.RegistryError) as err:
        print("ERROR:", err, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
