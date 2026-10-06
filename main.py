"""CLI: python main.py [scan|history|report|honey|explain|sanitize <файлове>|allow <файл>]"""
import hashlib
import sys

from agent.agent import analyze
from core.engine import load_config, run
from integrations import fixer, gcp_logging, gitlab_client as gl, notify, rotation


def cmd_scan(cfg):
    results = run(cfg=cfg)
    print("=^..^=  PurrGuard")
    print(f"Сканирани файлове: {results['files_scanned']} | находки: {len(results['findings'])} | риск: {results['max_severity']}")
    if results.get("authorized_carriers"):
        print(f"Stego-Ops: {len(results['authorized_carriers'])} авторизиран(и) носител(и) (хешът съвпада с манифеста): {', '.join(results['authorized_carriers'])}")
    gcp_logging.log_findings(results["findings"])
    if not results["threat_detected"]:
        print("OK: няма заплахи над прага. 😺")
        return 0
    playbook = rotation.playbook(results["findings"])
    audit, plan = analyze(results, playbook)
    fix_url = None
    if cfg.get("auto_fix", True):
        fixed = fixer.build_fixes(results["findings"])
        fix_url = fixer.open_fix_mr(fixed, "Автоматично изчистване от PurrGuard. Прегледай промените преди сливане.")
    body = f"## 🐾 PurrGuard: котката надуши заплаха ({results['max_severity']})\n\n{audit}\n\n### Препоръчани действия\n{plan}"
    if fix_url:
        body += f"\n\n🔧 Подготвен е автоматичен fix: {fix_url}"
    body += "\n\n_Фалшива тревога? Добави SHA-256 на файла в `allowlist_sha256` (`python main.py allow <файл>`)._"
    print(body)
    gl.post_mr_comment(body)
    gl.create_security_issue(f"[PurrGuard] Възможно изтичане на тайни ({results['max_severity']})", body)
    notify.slack(f":cat: :rotating_light: PurrGuard блокира MR ({results['max_severity']}): {len(results['findings'])} находки")
    return 1


def cmd_history(cfg):
    from core.history import scan_history
    h = scan_history(cfg)
    print(f"Версии от историята: {h['blobs_scanned']} | находки: {len(h['findings'])}")
    for f in h["findings"]:
        print(f"  [{f['severity']}] {f['file']}@{f['commit']}: {f['detail']}")
    gcp_logging.log_findings(h["findings"])
    if h["findings"]:
        notify.slack(f":mag: PurrGuard намери {len(h['findings'])} подозрителни версии в историята")
    return 1 if any(f["severity"] in ("HIGH", "CRITICAL") for f in h["findings"]) else 0


def main():
    cfg = load_config()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "scan"
    if cmd == "history":
        return cmd_history(cfg)
    if cmd == "report":
        from dashboard.generate_report import generate
        print("Табло:", generate())
        return 0
    if cmd == "honey":
        from core import honeytokens as H
        sub = sys.argv[2] if len(sys.argv) > 2 else "init"
        if sub == "init":
            made = H.init(".", sys.argv[3] if len(sys.argv) > 3 else "demo-project", cfg["honeytokens_file"])
            print("Създадени примамки:", made or "няма (вече съществуват)", f"\nКомитни ги и {cfg['honeytokens_file']} (съдържа само хешове).")
        elif sub == "add" and len(sys.argv) > 5:
            print("Регистрирана примамка:", H.add(sys.argv[3], sys.argv[4], sys.argv[5], cfg["honeytokens_file"]))
        elif sub == "list":
            for t in H.load(cfg["honeytokens_file"])["tokens"]:
                print(t["id"], t["kind"], t["decoy"])
        else:
            print("honey init [проект] | honey add <вид> <стойност> <файл> | honey list")
        return 0
    if cmd == "explain" and len(sys.argv) > 2:
        from core.explain import explain
        for p in sys.argv[2:]:
            print(explain(p, cfg), "\n" + "-" * 60)
        return 0
    if cmd == "sanitize" and len(sys.argv) > 2:  # използва се от Duo flow след одобрение; не пипа авторизирани носители
        from core import carriers
        from core.sanitize import sanitize
        car = carriers.Carriers(cfg["carrier_manifest"])
        for pth in sys.argv[2:]:
            if car.status(pth) == "ok":
                print(f"пропуснат (авторизиран носител): {pth}")
                continue
            data = sanitize(pth)
            if data is not None:
                open(pth, "wb").write(data)
                print(f"изчистен: {pth}")
        return 0
    if cmd == "allow" and len(sys.argv) > 2:
        print(f'  - "{hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()}"   # {sys.argv[2]}  (добави под allowlist_sha256)')
        return 0
    return cmd_scan(cfg)


if __name__ == "__main__":
    sys.exit(main())
