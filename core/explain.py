"""Finding evidence: where the anomaly is + how to verify it independently with basic tools."""
import hashlib
import re
import struct

from . import analyzers as A
from .engine import load_config, scan_file

HINTS = {
    ".png": ["tail -c 64 FILE | xxd        # should be end of IEND, not text", "strings FILE | grep -iE 'key|secret|AKIA'"],
    ".jpg": ["tail -c 64 FILE | xxd        # after FF D9 there should be nothing"],
    ".jpeg": ["tail -c 64 FILE | xxd        # after FF D9 there should be nothing"],
    ".pdf": ["tail -c 120 FILE              # after last %%EOF there should be nothing",
             "strings FILE | grep -E 'EmbeddedFile|JavaScript|AKIA|api_key'"],
    ".sql": ["grep -nP '[\\x{200B}-\\x{200D}\\x{2060}\\x{FEFF}]' FILE   # lines with invisible chars",
             "cat -A FILE | head                # invisible chars show as M-bM-^@M-^K"],
    ".wav": ["xxd FILE | tail -5            # data after end of audio"],
}


def _mask(b, keep=6):
    t = "".join(chr(c) if 32 <= c < 127 else "." for c in b)
    return f"{t[:keep]}••• ({len(b)} B, the rest is hidden)"


def _evidence(path, data, f):
    a, out = f["analyzer"], []
    if a == "trailing_bytes":
        if data.startswith(A.PNG_SIG):
            i = data.rfind(A.PNG_END) + len(A.PNG_END)
        else:
            i = data.rfind(b"\xff\xd9") + 2
        out.append(f"Image end marker at byte {i}, file length {len(data)} bytes.")
        extra = data[i:].strip(b' \x00\r\n')
        out.append(f"Extra data from byte {i}: hex {data[i:i + 16].hex(' ')} | text {_mask(extra)}")
    elif a == "png_chunks":
        m, pos = re.search(r"chunk (\w{4})", f["detail"]), 8
        while m and pos + 8 <= len(data):
            ln, ct = struct.unpack(">I4s", data[pos:pos + 8])
            if ct.decode("latin1") == m.group(1):
                out.append(f"Chunk {m.group(1)} at offset {pos}, size {ln} B, start: {_mask(data[pos + 8:pos + 8 + ln])}")
                break
            pos += 12 + ln
    elif a == "zero_width":
        text, hits = data.decode("utf-8", "replace"), []
        for n, line in enumerate(text.splitlines(), 1):
            for c, ch in enumerate(line, 1):
                if ch in A.ZW_CHARS:
                    hits.append(f"line {n}, column {c}: U+{ord(ch):04X}")
        out.append(f"First positions: {'; '.join(hits[:4])} ({len(hits)} total). On screen the line looks normal.")
    elif a == "chi_square_lsb":
        out.append(f"p-value {A.lsb_score_png(path):.3f}. Natural images are usually close to 0.")
    elif a == "pdf_structure":
        out.append(f"Last %%EOF at byte {data.rfind(b'%%EOF')}; file length {len(data)}. "
                   f"/EmbeddedFile: {data.count(b'/EmbeddedFile')}, /JavaScript: {data.count(b'/JavaScript')}.")
    elif a == "wav_structure":
        out.append("See RIFF chunk structure: data outside these chunks is not part of the audio.")
    return out


def explain(path, cfg=None):
    cfg, data = cfg or load_config(), open(path, "rb").read()
    lines = [f"File: {path} ({len(data)} B)", f"SHA-256: {hashlib.sha256(data).hexdigest()[:16]}…"]
    findings = scan_file(path, cfg)
    if not findings:
        return "\n".join(lines + ["Result: no findings ✅"])
    for f in findings:
        lines += [f"\n[{f['severity']}] {f['analyzer']}: {f['detail']}"] + ["  evidence: " + e for e in _evidence(path, data, f)]
    ext = path[path.rfind("."):].lower() if "." in path else ""
    if ext in HINTS:
        lines += ["\nVerify independently with basic tools:"] + ["  " + h.replace("FILE", path) for h in HINTS[ext]]
    return "\n".join(lines)
