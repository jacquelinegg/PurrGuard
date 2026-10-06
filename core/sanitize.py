"""File sanitization: returns cleaned content (bytes) or None."""
import io
import wave
from pathlib import Path

import numpy as np
from PIL import Image

from .analyzers import PNG_END, PNG_SIG, ZW_CHARS


def sanitize(path):
    ext = Path(path).suffix.lower()
    if ext == ".png":
        img = Image.open(path)
        img = img.convert("RGBA" if img.mode in ("RGBA", "LA", "PA") else "RGB")
        arr = np.array(img, dtype=np.uint8) & 0xFE  # нулиране на LSB равнината
        buf = io.BytesIO()
        Image.fromarray(arr, img.mode).save(buf, "PNG")  # нов файл: без чънкове и без данни след края
        return buf.getvalue()
    if ext in (".jpg", ".jpeg"):
        data = open(path, "rb").read()
        i = data.rfind(b"\xff\xd9")
        return data[:i + 2] if i != -1 else None
    if ext == ".pdf":  # маха само данните след края; вградени файлове и скриптове се чистят ръчно
        data = open(path, "rb").read()
        i = data.rfind(b"%%EOF")
        return data[:i + 5] + b"\n" if i != -1 else None
    if ext == ".mp3":
        data = open(path, "rb").read()
        i = data.rfind(b"TAG")
        return data[:i + 128] if i != -1 else None
    if ext == ".wav":
        with wave.open(path, "rb") as w:
            params, raw = w.getparams(), w.readframes(w.getnframes())
        if params.sampwidth == 2:
            a = (np.frombuffer(raw, dtype="<i2") & ~1).astype("<i2")
        elif params.sampwidth == 1:
            a = np.frombuffer(raw, dtype=np.uint8) & 0xFE
        else:
            return None
        buf = io.BytesIO()
        with wave.open(buf, "wb") as w:
            w.setparams(params)
            w.writeframes(a.tobytes())
        return buf.getvalue()
    try:  # текстови файлове
        text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        return None
    lead = "\ufeff" if text.startswith("\ufeff") else ""
    return (lead + text.lstrip("\ufeff").translate({ord(c): None for c in ZW_CHARS})).encode("utf-8")
