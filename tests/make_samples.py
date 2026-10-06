"""Generates test files with FAKE keys. Run: python tests/make_samples.py"""
import os
import struct
import wave
import zlib

import numpy as np
from PIL import Image

FAKE = b"api_key=AKIAFAKEFAKEFAKE1234 FAKE-DEMO-ONLY"
out = "tests/samples"
os.makedirs(out, exist_ok=True)
rng = np.random.default_rng(1)


def base_image():
    y, x = np.mgrid[0:512, 0:512]
    img = (60 + 0.2 * x + 0.1 * y + 40 * np.sin(x / 37) * np.cos(y / 53))[..., None] * np.array([1, 0.9, 0.7])
    img[150:300, 100:380] = [200, 60, 60]
    return np.clip(img, 0, 255).astype(np.uint8)


def bits(b):
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8))


img = base_image()
Image.fromarray(img).save(f"{out}/clean.png")

# 1) LSB: secret + random (encrypted) padding on 40% of the channel
stego = img.copy()
flat = stego[:, :, 0].ravel()
payload = np.concatenate([bits(FAKE), rng.integers(0, 2, int(len(flat) * 0.4), dtype=np.uint8)])
flat[:len(payload)] = (flat[:len(payload)] & 0xFE) | payload
stego[:, :, 0] = flat.reshape(stego.shape[:2])
Image.fromarray(stego).save(f"{out}/stego_lsb.png")

# 2) data after IEND
Image.fromarray(img).save(f"{out}/trailing.png")
open(f"{out}/trailing.png", "ab").write(FAKE)

# 3) secret in a text PNG chunk
raw = open(f"{out}/clean.png", "rb").read()
cd = b"Comment\x00" + FAKE
chunk = struct.pack(">I", len(cd)) + b"tEXt" + cd + struct.pack(">I", zlib.crc32(b"tEXt" + cd))
i = raw.rfind(b"IEND") - 4
open(f"{out}/chunk.png", "wb").write(raw[:i] + chunk + raw[i:])

# 4) Zero-width in SQL
msg = "".join("\u200c" if b == "1" else "\u200b" for byte in FAKE for b in f"{byte:08b}")
open(f"{out}/migration.sql", "w", encoding="utf-8").write(f"-- add users table{msg}\nCREATE TABLE users(id INT);\n")
open(f"{out}/clean.sql", "w").write("-- add users table\nCREATE TABLE users(id INT);\n")

# 5) WAV: clean and with hidden chunk after data
t = np.arange(44100 * 3) / 44100
noise = np.convolve(rng.normal(0, 1, t.size), np.ones(25) / 25, mode="same")
audio = (noise / noise.std() * 4000 + 2000 * np.sin(2 * np.pi * 220 * t) + rng.normal(0, 40, t.size)).astype("<i2")
with wave.open(f"{out}/clean.wav", "wb") as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(44100); w.writeframes(audio.tobytes())
raw = bytearray(open(f"{out}/clean.wav", "rb").read())
extra = b"xtra" + struct.pack("<I", len(FAKE)) + FAKE + (b"\x00" if len(FAKE) % 2 else b"")
raw += extra
raw[4:8] = struct.pack("<I", len(raw) - 8)
open(f"{out}/stego.wav", "wb").write(bytes(raw))
print("Done:", sorted(os.listdir(out)))
