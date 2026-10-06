"""Minimal MCP server (stdio, JSON-RPC one message per line). READ-ONLY.
Tools: stegoops_verify, stegoops_expiry, purrguard_scan. Does not open carriers, has no key access,
returns only file names, finding types, and expiry dates - never secret values."""
import json
import os
import sys

PROTOCOL = "2024-11-05"
TOOLS = [
    {"name": "stegoops_verify", "description": "Проверява SHA-256 на Stego-Ops носителите спрямо манифеста и сроковете (без ключ).",
     "inputSchema": {"type": "object", "properties": {"warn_days": {"type": "integer", "description": "предупреди за срок под N дни"}}}},
    {"name": "stegoops_expiry", "description": "Носители, чийто срок изтича в следващите N дни (само пътища, имена на тайни, срок).",
     "inputSchema": {"type": "object", "properties": {"within_days": {"type": "integer"}}}},
    {"name": "purrguard_scan", "description": "Сканира проследяваните файлове за скрита ексфилтрация; връща само файл/вид/тежест.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def call_tool(name, args):
    from stegoops import autorotate, vault
    if name == "stegoops_verify":
        probs = vault.verify()
        warn = autorotate.expiring(within_days=int(args["warn_days"])) if args.get("warn_days") is not None else []
        return {"ok": not probs, "problems": probs, "expiring": warn}
    if name == "stegoops_expiry":
        return {"expiring": autorotate.expiring(within_days=int(args.get("within_days", 7)))}
    if name == "purrguard_scan":
        from core.engine import load_config, run
        res = run(cfg=load_config())
        return {"files_scanned": res["files_scanned"], "max_severity": res["max_severity"],
                "findings": [{"file": f.get("file"), "analyzer": f["analyzer"], "severity": f["severity"]} for f in res["findings"]]}
    raise KeyError(name)


def handle(msg):
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid is None:  # нотификации (напр. notifications/initialized) не получават отговор
        return None
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion", PROTOCOL), "capabilities": {"tools": {}},
                  "serverInfo": {"name": "purrguard", "version": "1.0.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        try:
            out = call_tool(params.get("name"), params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}], "isError": False}
        except KeyError:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "непознат инструмент"}}
        except Exception as e:  # грешките се връщат като резултат, не като срив
            result = {"content": [{"type": "text", "text": f"грешка: {type(e).__name__}"}], "isError": True}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "непознат метод"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main():
    sys.path.insert(0, os.getcwd())
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            resp = handle(json.loads(line))
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "невалиден JSON"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
