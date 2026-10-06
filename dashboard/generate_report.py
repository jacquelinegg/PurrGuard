"""Static HTML dashboard for GitLab Pages: public/index.html"""
import html
import json
import os

COLORS = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#d4ac0d", "LOW": "#7f8c8d"}


def _load(p, default):
    try:
        return json.load(open(p))
    except (OSError, json.JSONDecodeError):
        return default


def _log():
    try:
        return [json.loads(l) for l in open(".purrguard_log/log.jsonl") if l.strip()]
    except OSError:
        return []


def generate(outdir="public"):
    scan, hist, log = _load("scan_results.json", {"findings": [], "files_scanned": 0}), _load("history_results.json", {"findings": [], "blobs_scanned": 0}), _log()
    allf = scan["findings"] + hist["findings"]
    counts = {k: sum(f["severity"] == k for f in allf) for k in COLORS}
    mx = max(counts.values()) or 1
    bars = "".join(
        f'<g transform="translate(0,{i * 34})"><text x="0" y="20" class="l">{k}</text>'
        f'<rect x="90" y="4" width="{int(counts[k] / mx * 300)}" height="22" fill="{COLORS[k]}" rx="3"/>'
        f'<text x="{98 + int(counts[k] / mx * 300)}" y="21" class="l">{counts[k]}</text></g>' for i, k in enumerate(COLORS))
    rows = "".join(
        f"<tr><td><span class='b' style='background:{COLORS[f['severity']]}'>{f['severity']}</span></td>"
        f"<td>{html.escape(f['file'])}</td><td>{html.escape(f.get('commit', 'MR'))}</td>"
        f"<td>{html.escape(f['analyzer'])}</td><td>{html.escape(f['detail'])}</td></tr>"
         for f in sorted(allf, key=lambda f: list(COLORS).index(f["severity"]))) or "<tr><td colspan=5>No findings - the cat is sleeping peacefully 😺</td></tr>"
    tl = "".join(f"<tr><td>{html.escape(e['ts'])}</td><td>MR !{html.escape(str(e['mr']))}</td><td>{e['scanned']}</td>"
                 f"<td>{e['findings']}</td><td>{html.escape(e['max'])}</td></tr>" for e in reversed(log[-15:])) or "<tr><td colspan=5>No scans yet</td></tr>"
    page = f"""<!doctype html><html lang="bg"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
 <title>PurrGuard dashboard</title><style>
:root{{--bg:#fff8f0;--fg:#3b2a1e;--card:#ffeedd;--bd:#f0cfae;--ac:#e8833a}}
@media(prefers-color-scheme:dark){{:root{{--bg:#241a14;--fg:#f6e9dc;--card:#33251c;--bd:#5a4130}}}}
body{{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:1000px;margin:auto;padding:16px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap}}.c{{background:var(--card);border:2px solid var(--bd);border-radius:18px;padding:14px 18px;flex:1;min-width:140px}}
.c b{{font-size:28px;display:block;color:var(--ac)}}header{{display:flex;align-items:center;gap:14px}}h1{{margin:0}}.sub{{margin:2px 0 0;opacity:.75}}h2{{border-bottom:2px dashed var(--bd);padding-bottom:4px}}.foot{{text-align:center;opacity:.6;margin:28px 0 8px}}table{{border-collapse:collapse;width:100%;font-size:14px}}td,th{{border-bottom:1px solid var(--bd);padding:6px;text-align:left}}
.w{{overflow-x:auto}}.b{{color:#fff;border-radius:4px;padding:2px 7px;font-size:12px}}.l{{fill:var(--fg);font-size:13px}}</style>
 <header><div class="logo"><svg viewBox="0 0 64 56" width="64" height="56" aria-label="PurrGuard cat"><path d="M8 24 L10 4 L26 14 Z M56 24 L54 4 L38 14 Z" fill="#e8833a"/><ellipse cx="32" cy="34" rx="26" ry="20" fill="#f39c4a"/><path d="M10 9 L13 17 L20 13 Z M54 9 L51 17 L44 13 Z" fill="#f7c9a0"/><ellipse cx="22" cy="31" rx="3.5" ry="5" fill="#2b1d12"/><ellipse cx="42" cy="31" rx="3.5" ry="5" fill="#2b1d12"/><circle cx="23" cy="29" r="1.2" fill="#fff"/><circle cx="43" cy="29" r="1.2" fill="#fff"/><path d="M29 40 L35 40 L32 44 Z" fill="#d35c5c"/><path d="M32 44 Q28 48 24 45 M32 44 Q36 48 40 45" stroke="#2b1d12" stroke-width="1.5" fill="none"/><path d="M4 36 L18 38 M4 43 L18 42 M60 36 L46 38 M60 43 L46 42" stroke="#2b1d12" stroke-width="1.2"/></svg></div><div><h1>PurrGuard</h1><p class="sub">The cat that sees the invisible 🐾</p></div></header><div class="cards">
 <div class="c"><b>{scan['files_scanned']}</b>files in the last scan</div>
 <div class="c"><b>{hist['blobs_scanned']}</b>history versions</div>
 <div class="c"><b>{len(allf)}</b>total findings</div>
 <div class="c"><b>{counts['CRITICAL'] + counts['HIGH']}</b>critical and high</div></div>
 <h2>Findings by severity</h2><svg viewBox="0 0 480 140" width="100%" style="max-width:480px">{bars}</svg>
 <h2>Findings</h2><div class="w"><table><tr><th>Level</th><th>File</th><th>Where</th><th>Analyzer</th><th>Detail</th></tr>{rows}</table></div>
 <h2>Recent scans</h2><div class="w"><table><tr><th>Time (UTC)</th><th>MR</th><th>Files</th><th>Findings</th><th>Max level</th></tr>{tl}</table></div><p class="foot">🐾 🐾 🐾 PurrGuard guards your repo</p></html>"""
    os.makedirs(outdir, exist_ok=True)
    open(os.path.join(outdir, "index.html"), "w", encoding="utf-8").write(page)
    return os.path.join(outdir, "index.html")
