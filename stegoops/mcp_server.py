"""Minimal MCP server (stdio, JSON-RPC one message per line). READ-ONLY.
Tools: stegoops_verify, stegoops_expiry, purrguard_scan. Does not open carriers, has no key access,
returns only file names, finding types, and expiry dates - never secret values."""
import json
import os
import sys

PROTOCOL = "2024-11-05"
TOOLS = [
    {"name": "stegoops_verify", "description": "Verifies SHA-256 of Stego-Ops carriers against manifest and expiry dates (no key).",
     "inputSchema": {"type": "object", "properties": {"warn_days": {"type": "integer", "description": "warn if expiry is within N days"}}}},
    {"name": "stegoops_expiry", "description": "Carriers expiring in the next N days (only paths, secret names, expiry).",
     "inputSchema": {"type": "object", "properties": {"within_days": {"type": "integer"}}}},
    {"name": "purrguard_scan", "description": "Scans tracked files for hidden exfiltration; returns only file/type/severity.",
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
    if mid is None:  # notifications (e.g. notifications/initialized) do not receive a response
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
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        except Exception as e:  # errors are returned as results, not as crashes
            result = {"content": [{"type": "text", "text": f"error: {type(e).__name__}"}], "isError": True}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown method"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main():
    sys.path.insert(0, os.getcwd())
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            resp = handle(json.loads(line))
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
