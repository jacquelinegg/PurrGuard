"""Statistical analyzers. No API calls, fully local."""
import re
import struct
import wave

import numpy as np
from PIL import Image
from scipy.stats import chi2

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_END = b"IEND\xaeB`\x82"
STD_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB",
              b"iCCP", b"sBIT", b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"eXIf"}
TEXT_CHUNKS = {b"tEXt", b"zTXt", b"iTXt"}
ZW_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
ZW_RE = re.compile(f"[{ZW_CHARS}]")
BIDI_CONTROLS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"  # Trojan Source (CVE-2021-42574)
TAG_CHARS = "".join(chr(c) for c in range(0xE0000, 0xE0080))  # invisible Unicode TAG characters
SECRET_RE = re.compile(
    rb"(AKIA[0-9A-Z]{16,}|AIza[0-9A-Za-z_\-]{35}|glpat-[0-9A-Za-z_\-]{20}|"
    rb"sk-ant-[0-9A-Za-z_\-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"(?i:(?:api[_-]?key|secret|password|token)\s*[=:]\s*\S{8,}))")


def finding(analyzer, severity, detail, score=None, secrets=None):
    f = {"analyzer": analyzer, "severity": severity, "detail": detail, "score": score}
    if secrets:
        f["secrets"] = secrets
    return f


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    p = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256) / len(data)
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum() / 8)  # normalized 0..1


def _png_end(data):
    """Offset just after the first IEND chunk, walking the chunk structure."""
    pos = 8
    while pos + 12 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        if ctype == b"IEND":
            return pos + 12
        if length > len(data) - pos - 12:  # corrupt chunk: the structure cannot be walked
            return -1
        pos += 12 + length
    return -1


def _jpeg_end(data):
    """Offset just after the EOI marker, walking the segment structure (so an EOI
    inside an EXIF thumbnail, which lives in a length-prefixed APP segment, does
    not end the file)."""
    if data[:2] != b"\xff\xd8":
        return -1
    pos, n = 2, len(data)
    while pos + 1 < n:
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker == 0xD9:  # EOI
            return pos + 2
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:  # byte stuffing / restart marker
            pos += 2
            continue
        if pos + 3 >= n:
            return -1
        seg_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        pos += 2 + seg_len
        if marker == 0xDA:  # SOS: entropy-coded data follows, scan it for the next marker
            while pos + 1 < n:
                if data[pos] != 0xFF:
                    pos += 1
                    continue
                if data[pos + 1] == 0x00 or 0xD0 <= data[pos + 1] <= 0xD7:
                    pos += 2
                    continue
                break
    return -1


def trailing_bytes(path):
    """Data after the real PNG (IEND) or JPEG (EOI) end, located by parsing the
    file structure - a payload followed by a fake end marker cannot hide it."""
    data = open(path, "rb").read()
    if data.startswith(PNG_SIG):
        i = _png_end(data)
        if i == -1:  # malformed structure: fall back to the first IEND signature
            j = data.find(PNG_END)
            i = j + len(PNG_END) if j != -1 else -1
        tail = data[i:] if i != -1 else b""
    elif data.startswith(b"\xff\xd8"):
        i = _jpeg_end(data)
        if i == -1:  # malformed structure: fall back to the first EOI marker
            j = data.find(b"\xff\xd9")
            i = j + 2 if j != -1 else -1
        tail = data[i:] if i != -1 else b""
    else:
        return []
    tail = tail.strip(b"\x00\r\n ")
    if not tail:
        return []
    sev = "CRITICAL" if SECRET_RE.search(tail) else ("HIGH" if len(tail) > 16 else "MEDIUM")
    return [finding("trailing_bytes", sev,
                    f"{len(tail)} bytes after end of file (entropy {_shannon(tail):.2f})"
                    + ("; contains secret pattern" if sev == "CRITICAL" else ""),
                    len(tail), classify_secret(tail))]


def png_chunks(path):
    """Non-standard chunks and secrets in text chunks (catches small payloads)."""
    data = open(path, "rb").read()
    if not data.startswith(PNG_SIG):
        return []
    out, pos = [], 8
    while pos + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        name = ctype.decode("latin1")
        if SECRET_RE.search(body):
            out.append(finding("png_chunks", "CRITICAL", f"Secret pattern in chunk {name}", None, classify_secret(body)))
        elif ctype in TEXT_CHUNKS and length > 256:
            out.append(finding("png_chunks", "MEDIUM", f"Unusually large text chunk {name} ({length} B)"))
        elif ctype not in STD_CHUNKS and ctype not in TEXT_CHUNKS:
            out.append(finding("png_chunks", "MEDIUM", f"Non-standard chunk {name} ({length} B)"))
        if ctype == b"IEND":
            break
        pos += 12 + length
    return out


def _pov_pvalue(vals):
    """Westfeld pairs-of-values test. p close to 1 => likely LSB embedding."""
    counts = np.bincount(vals, minlength=256).astype(float)
    if len(counts) % 2:
        counts = np.append(counts, 0)
    even, odd = counts[0::2], counts[1::2]
    exp = (even + odd) / 2
    m = exp >= 5
    if m.sum() < 20:
        return None
    stat = (((even - odd)[m]) ** 2 / (even + odd)[m]).sum()  # = sum per pair (o-e)^2/e
    return float(1 - chi2.cdf(stat, m.sum() - 1))


def _prefix_scan(vals, threshold, name, what):
    best, hits = 0.0, 0
    for frac in (0.05, 0.1, 0.2, 0.4, 0.7, 1.0):
        n = int(len(vals) * frac)
        if n < 5000:
            continue
        p = _pov_pvalue(vals[:n])
        if p is not None:
            best = max(best, p)
            hits += p > threshold
    if hits >= 2:
        return [finding(name, "HIGH", f"{what}: LSB distribution is statistically uniform (p={best:.4f})", best)]
    return []


def chi_square_png(path, threshold=0.05):
    if not open(path, "rb").read(8).startswith(PNG_SIG):
        return []
    arr = np.array(Image.open(path).convert("RGB"), dtype=np.uint8)
    out = []
    for ch, name in enumerate("RGB"):
        out += _prefix_scan(arr[:, :, ch].ravel(), threshold, "chi_square_lsb", f"PNG channel {name}")
    return out[:1]


WAV_OK = {b"fmt ", b"data", b"LIST", b"fact", b"bext", b"cue ", b"smpl", b"iXML", b"id3 ", b"ID3 "}


def wav_structure(path):
    """Non-standard RIFF chunks and data past declared size (LSB in noisy 16-bit samples is not statistically distinguishable)."""
    data = open(path, "rb").read()
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return []
    out, pos = [], 12
    riff_end = min(len(data), struct.unpack("<I", data[4:8])[0] + 8)
    while pos + 8 <= riff_end:
        cid, size = data[pos:pos + 4], struct.unpack("<I", data[pos + 4:pos + 8])[0]
        body = data[pos + 8:pos + 8 + size]
        name = cid.decode("latin1")
        if SECRET_RE.search(body):
            out.append(finding("wav_structure", "CRITICAL", f"Secret pattern in WAV chunk '{name}'", None, classify_secret(body)))
        elif cid not in WAV_OK:
            out.append(finding("wav_structure", "MEDIUM", f"Non-standard WAV chunk '{name}' ({size} B)", size))
        pos += 8 + size + (size & 1)
    tail = data[riff_end:].strip(b"\x00")
    if tail:
        out.append(finding("wav_structure", "CRITICAL" if SECRET_RE.search(tail) else "HIGH",
                            f"{len(tail)} bytes after end of RIFF data", len(tail), classify_secret(tail)))
    return out


def mp3_trailing(path):
    data = open(path, "rb").read()
    i = data.rfind(b"TAG")
    tail = data[i + 128:] if i != -1 else b""
    return [finding("trailing_bytes", "MEDIUM", f"{len(tail)} bytes after ID3v1 tag")] if len(tail.strip(b"\x00")) > 16 else []


def zero_width(path, min_chars=1):
    try:
        text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        return []
    if text.startswith("\ufeff"):
        text = text[1:]  # legitimate BOM
    chars = ZW_RE.findall(text)
    if len(chars) < min_chars:
        return []
    bits = "".join("1" if c == "\u200c" else "0" for c in chars if c in "\u200b\u200c")
    decoded = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
    secret = bool(SECRET_RE.search(decoded))
    sev = "CRITICAL" if secret else ("HIGH" if len(chars) >= 8 else "MEDIUM")
    return [finding("zero_width", sev,
                    f"{len(chars)} invisible Unicode chars" + ("; decoded content looks like a secret" if secret else ""),
                    len(chars), classify_secret(decoded) if secret else None)]


def invisible_unicode(path, min_chars=1):
    """TAG characters (U+E0000-U+E007F) encode raw bytes invisibly; bidi controls
    (Trojan Source, CVE-2021-42574) reverse or isolate the display order of text.
    Both are invisible to reviewers and to AI agents reading the file."""
    try:
        text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        return []
    out = []
    tags = [c for c in text if c in TAG_CHARS]
    if len(tags) >= min_chars:
        decoded = bytes(ord(c) - 0xE0000 for c in tags)
        secret = bool(SECRET_RE.search(decoded))
        out.append(finding("invisible_tag", "CRITICAL" if secret else "HIGH",
                           f"{len(tags)} invisible Unicode TAG characters"
                           + ("; decoded content looks like a secret" if secret else ""),
                           len(tags), classify_secret(decoded) if secret else None))
    bidi = [c for c in text if c in BIDI_CONTROLS]
    if len(bidi) >= min_chars:
        out.append(finding("invisible_bidi", "MEDIUM",
                           f"{len(bidi)} bidi control characters (Trojan Source: text display order can be manipulated)",
                           len(bidi)))
    return out


def classify_secret(b: bytes):
    """Classifies secret type for rotation planning. Never returns the secret itself."""
    out = []
    if re.search(rb"AKIA[0-9A-Z]{16}", b):
        out.append({"type": "aws_access_key"})
    if re.search(rb"AIza[0-9A-Za-z_\-]{35}", b):
        out.append({"type": "gcp_api_key"})
    kid = re.search(rb'"private_key_id"\s*:\s*"([0-9a-f]{40})"', b)
    if kid or b'"type": "service_account"' in b:
        mail = re.search(rb'"client_email"\s*:\s*"([^"]+)"', b)
        out.append({"type": "gcp_service_account",
                    "key_id": kid.group(1).decode() if kid else "KEY_ID",
                    "email": mail.group(1).decode() if mail else "SA_EMAIL"})
    if re.search(rb"glpat-[0-9A-Za-z_\-]{20}", b):
        out.append({"type": "gitlab_token"})
    if re.search(rb"sk-ant-[0-9A-Za-z_\-]{20,}", b):
        out.append({"type": "anthropic_key"})
    if b"PRIVATE KEY-----" in b:
        out.append({"type": "private_key"})
    if not out and SECRET_RE.search(b):
        out.append({"type": "generic_secret"})
    return out


def _best_p(vals):
    best = 0.0
    for frac in (0.05, 0.1, 0.2, 0.4, 0.7, 1.0):
        n = int(len(vals) * frac)
        if n >= 5000:
            best = max(best, _pov_pvalue(vals[:n]) or 0.0)
    return best


def lsb_score_png(path):
    arr = np.array(Image.open(path).convert("RGB"), dtype=np.uint8)
    return max(_best_p(arr[:, :, c].ravel()) for c in range(3))


def pdf_structure(path):
    """PDF: data after last %%EOF, embedded files, scripts, plaintext secrets."""
    data = open(path, "rb").read()
    if not data.startswith(b"%PDF"):
        return []
    out = []
    secret = bool(SECRET_RE.search(data))
    i = data.rfind(b"%%EOF")
    tail = data[i + 5:].strip(b"\x00\r\n ") if i != -1 else b""
    if tail:
        out.append(finding("pdf_structure", "CRITICAL" if SECRET_RE.search(tail) else "HIGH",
                           f"{len(tail)} bytes after last %%EOF", len(tail), classify_secret(tail)))
    if b"/EmbeddedFile" in data:
        out.append(finding("pdf_structure", "CRITICAL" if secret else "MEDIUM",
                           "Embedded file in PDF" + ("; contains secret pattern" if secret else ""), None,
                           classify_secret(data) if secret else None))
    if re.search(rb"/(JavaScript|JS|Launch)\b", data):
        out.append(finding("pdf_structure", "MEDIUM", "PDF contains script or open action (/JavaScript, /Launch)"))
    if secret and not out:
        out.append(finding("pdf_structure", "CRITICAL", "Plaintext secret pattern in PDF", None, classify_secret(data)))
    return out
