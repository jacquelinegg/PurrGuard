"""Mini demo app. Shows loaded secret NAMES only, never values."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

NAMES = [n for n in ("DEMO_DB_PASSWORD", "DEMO_API_TOKEN") if os.environ.get(n)]


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/logo.png":
            body, ct = open(os.path.join(os.path.dirname(__file__), "assets", "logo.png"), "rb").read(), "image/png"
        else:
            body, ct = json.dumps({"status": "ok", "secrets_loaded": NAMES}).encode(), "application/json"
        self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
