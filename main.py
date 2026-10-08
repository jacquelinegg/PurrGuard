"""CLI: python main.py [scan|history|report|honey|explain|sanitize <files>|allow <file>]"""
import hashlib
import sys

sys.stdout.reconfigure(encoding="utf-8")

from agent.agent import analyze
from core.engine import load_config, run
from integrations import fixer, gcp_logging, gitlab_client as gl, notify, rotation


def cmd_scan(cfg):
    results = run(cfg=cfg)
    print("=^..^=  PurrGuard")
    print(f"Files scanned: {results['files_scanned']} | findings: {len(results['findings'])} | risk: {results['max_severity']}")
    if results.get("authorized_carriers"):
        print(f"Stego-Ops: {len(results['authorized_carriers'])} authorized carrier(s) (hash matches manifest): {', '.join(results['authorized_carriers'])}")
    gcp_logging.log_findings(results["findings"])
    if not results["threat_detected"]:
        print("OK: no threats above threshold.")
        return 0
    playbook = rotation.playbook(results["findings"])
    audit, plan = analyze(results, playbook)
    fix_url = None
    if cfg.get("auto_fix", True):
        fixed = fixer.build_fixes(results["findings"])
        fix_url = fixer.open_fix_mr(fixed, "Automatic cleanup by PurrGuard. Review changes before merging.")
    body = f"## PurrGuard: threat detected ({results['max_severity']})\n\n{audit}\n\n### Recommended actions\n{plan}"
    if fix_url:
        body += f"\n\nAutomatic fix prepared: {fix_url}"
    body += "\n\n_False alarm? Add the file's SHA-256 to `allowlist_sha256` (`python main.py allow <file>`)._"
    print(body)
    gl.post_mr_comment(body)
    gl.create_security_issue(f"[PurrGuard] Possible secret exfiltration ({results['max_severity']})", body)
    notify.slack(f":cat: :rotating_light: PurrGuard blocked MR ({results['max_severity']}): {len(results['findings'])} findings")
    return 1


def cmd_history(cfg):
    from core.history import scan_history
    h = scan_history(cfg)
    print(f"History versions: {h['blobs_scanned']} | findings: {len(h['findings'])}")
    for f in h["findings"]:
        print(f"  [{f['severity']}] {f['file']}@{f['commit']}: {f['detail']}")
    gcp_logging.log_findings(h["findings"])
    if h["findings"]:
        notify.slack(f":mag: PurrGuard found {len(h['findings'])} suspicious versions in history")
    return 1 if any(f["severity"] in ("HIGH", "CRITICAL") for f in h["findings"]) else 0


def main():
    cfg = load_config()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if cmd == "history":
        return cmd_history(cfg)
    if cmd == "report":
        from dashboard.generate_report import generate
        print("Dashboard:", generate())
        return 0
    if cmd == "honey":
        from core import honeytokens as H
        sub = sys.argv[2] if len(sys.argv) > 2 else "init"
        if sub == "init":
            made = H.init(".", sys.argv[3] if len(sys.argv) > 3 else "demo-project", cfg["honeytokens_file"])
            print("Decoys created:", made or "none (already exist)", f"\nCommit them and {cfg['honeytokens_file']} (contains only hashes).")
        elif sub == "add" and len(sys.argv) > 5:
            print("Registered decoy:", H.add(sys.argv[3], sys.argv[4], sys.argv[5], cfg["honeytokens_file"]))
        elif sub == "list":
            for t in H.load(cfg["honeytokens_file"])["tokens"]:
                print(t["id"], t["kind"], t["decoy"])
        else:
            print("honey init [project] | honey add <type> <value> <file> | honey list")
        return 0
    if cmd == "explain" and len(sys.argv) > 2:
        from core.explain import explain
        for p in sys.argv[2:]:
            print(explain(p, cfg), "\n" + "-" * 60)
        return 0
    if cmd == "sanitize" and len(sys.argv) > 2:  # used by Duo flow after approval; does not touch authorized carriers
        from core import carriers
        from core.sanitize import sanitize
        car = carriers.Carriers(cfg["carrier_manifest"])
        for pth in sys.argv[2:]:
            if car.status(pth) == "ok":
                print(f"skipped (authorized carrier): {pth}")
                continue
            data = sanitize(pth)
            if data is not None:
                open(pth, "wb").write(data)
                print(f"sanitized: {pth}")
        return 0
    if cmd == "allow" and len(sys.argv) > 2:
        print(f'  - "{hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()}"   # {sys.argv[2]}  (add under allowlist_sha256)')
        return 0
    return cmd_scan(cfg)


if __name__ == "__main__":
    sys.exit(main())
