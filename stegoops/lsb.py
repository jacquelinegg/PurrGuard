"""LSB embedding in PNG with key-derived (pseudorandom) positions.

Positions come from SHAKE-256(seed) + partial Fisher-Yates - deterministic and numpy-version independent.
Seed is secret (wrapped with KEK in manifest), so without the key you don't know where to read.
IMPORTANT: this is camouflage, not cryptography. LSB data is already encrypted (see crypto.py).
"""
import hashlib
import io
import os

import numpy as np
from PIL import Image

HEADER_BITS = 32
MAX_SUBPIXELS = 40_000_000


class StegoError(Exception):
    pass


def positions(seed: bytes, total: int, n: int) -> np.ndarray:
    if n > total:
        raise StegoError("The carrier is too small for this payload")
    stream = hashlib.shake_256(b"stegoops-pos-v1" + seed).digest(8 * n)
    swap, out = {}, np.empty(n, dtype=np.int64)
    for i in range(n):
        j = i + int.from_bytes(stream[8 * i:8 * i + 8], "little") % (total - i)
        vi, vj = swap.get(i, i), swap.get(j, j)
        swap[j], swap[i] = vi, vj
        out[i] = vj
    return out


def _load(png: bytes):
    img = Image.open(io.BytesIO(png))
    img.load()
    img = img.convert("RGBA" if img.mode in ("RGBA", "LA", "PA") else "RGB")
    arr = np.array(img, dtype=np.uint8)
    rgb = np.ascontiguousarray(arr[..., :3])
    if rgb.size > MAX_SUBPIXELS:
        raise StegoError("The carrier is too large (over 40M sub-pixels)")
    return img.mode, arr, rgb


def capacity_bytes(png: bytes) -> int:
    _, _, rgb = _load(png)
    return (rgb.size - HEADER_BITS) // 8


def embed(png: bytes, seed: bytes, payload: bytes) -> bytes:
    mode, arr, rgb = _load(png)
    if len(payload) > (rgb.size - HEADER_BITS) // 8:
        raise StegoError(f"Payload {len(payload)} B does not fit (capacity {(rgb.size - HEADER_BITS) // 8} B)")
    data = len(payload).to_bytes(4, "big") + payload
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    pos = positions(seed, rgb.size, len(bits))
    flat = rgb.reshape(-1)
    flat[pos] = (flat[pos] & 0xFE) | bits
    arr[..., :3] = flat.reshape(rgb.shape)
    buf = io.BytesIO()
    Image.fromarray(arr, mode).save(buf, "PNG")
    return buf.getvalue()


def extract(png: bytes, seed: bytes) -> bytes:
    _, _, rgb = _load(png)
    flat = rgb.reshape(-1)
    head = np.packbits(flat[positions(seed, rgb.size, HEADER_BITS)] & 1).tobytes()
    n = int.from_bytes(head, "big")
    if n == 0 or n > (rgb.size - HEADER_BITS) // 8:
        raise StegoError("No payload (wrong position key or clean file)")
    pos = positions(seed, rgb.size, HEADER_BITS + 8 * n)
    return np.packbits(flat[pos[HEADER_BITS:]] & 1).tobytes()


def embed_plain(png: bytes, payload: bytes) -> bytes:
    """Sequential LSB (what ordinary tools find) - for decoy carriers with honeytoken."""
    mode, arr, rgb = _load(png)
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    if len(bits) > rgb.size:
        raise StegoError("The carrier is too small")
    flat = rgb.reshape(-1)
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    arr[..., :3] = flat.reshape(rgb.shape)
    buf = io.BytesIO()
    Image.fromarray(arr, mode).save(buf, "PNG")
    return buf.getvalue()


def wipe(png: bytes, seed: bytes) -> bytes:
    """Overwrites old payload positions with random bits (destroys old ciphertext during rotation)."""
    mode, arr, rgb = _load(png)
    flat = rgb.reshape(-1)
    n = int.from_bytes(np.packbits(flat[positions(seed, rgb.size, HEADER_BITS)] & 1).tobytes(), "big")
    if n == 0 or n > (rgb.size - HEADER_BITS) // 8:
        raise StegoError("No payload to delete")
    pos = positions(seed, rgb.size, HEADER_BITS + 8 * n)
    flat[pos] = (flat[pos] & 0xFE) | np.frombuffer(os.urandom(len(pos)), dtype=np.uint8) & 1
    arr[..., :3] = flat.reshape(rgb.shape)
    buf = io.BytesIO()
    Image.fromarray(arr, mode).save(buf, "PNG")
    return buf.getvalue()
