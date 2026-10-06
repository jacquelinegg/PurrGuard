"""Скрубер на логове: заменя стойностите на тайните (и често срещани кодирания) с ***."""
import base64
import json
import urllib.parse

MIN_LEN = 6


class Scrubber:
    def __init__(self, values):
        pats = set()
        for v in values:
            if not v or len(v) < MIN_LEN:
                continue
            raw = v.encode()
            for variant in (raw, base64.b64encode(raw), base64.urlsafe_b64encode(raw), raw.hex().encode(),
                            urllib.parse.quote(v, safe="").encode(), json.dumps(v)[1:-1].encode()):
                pats.add(variant)
            for line in v.splitlines():  # многоредови тайни (PEM) - редовете се скрубват поотделно
                if len(line.strip()) >= 8:
                    pats.add(line.strip().encode())
        self._pats = sorted(pats, key=len, reverse=True)
        self.hits = 0

    def scrub(self, data: bytes) -> bytes:
        for p in self._pats:
            if p in data:
                self.hits += data.count(p)
                data = data.replace(p, b"***")
        return data
