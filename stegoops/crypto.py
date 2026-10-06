"""Envelope encryption. Security comes from AES-256-GCM and the KEK, NOT from steganography.

Scheme: random DEK encrypts data; DEK is wrapped with KEK. KEK comes from:
  - env     : STEGOOPS_KEK (32 bytes base64) - for CI variable (masked + protected)
  - gcp-kms : Cloud KMS key (STEGOOPS_KMS_KEY) - KEK never leaves KMS (not tested here)
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC, VERSION = b"SOPS", 1


class CryptoError(Exception):
    pass


def generate_kek() -> str:
    return base64.b64encode(os.urandom(32)).decode()


class EnvProvider:
    name = "env"

    def __init__(self, kek_b64=None):
        raw = kek_b64 or os.environ.get("STEGOOPS_KEK")
        if not raw:
            raise CryptoError("Missing STEGOOPS_KEK (generate with: python -m stegoops keygen)")
        try:
            self._kek = base64.b64decode(raw, validate=True)
        except Exception as e:
            raise CryptoError("STEGOOPS_KEK is not valid base64") from e
        if len(self._kek) != 32:
            raise CryptoError("STEGOOPS_KEK must be exactly 32 bytes")

    def wrap(self, data: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._kek).encrypt(nonce, data, aad)

    def unwrap(self, blob: bytes, aad: bytes) -> bytes:
        try:
            return AESGCM(self._kek).decrypt(blob[:12], blob[12:], aad)
        except Exception as e:
            raise CryptoError("Decryption failed: wrong key, tampered carrier, or different identifier") from e


class KmsProvider:
    """Google Cloud KMS. Requires google-cloud-kms and permissions cloudkms.cryptoKeyVersions.useToEncrypt/Decrypt."""
    name = "gcp-kms"

    def __init__(self, key_name=None, client=None):
        self.key_name = key_name or os.environ.get("STEGOOPS_KMS_KEY")
        if not self.key_name:
            raise CryptoError("Missing STEGOOPS_KMS_KEY (projects/P/locations/L/keyRings/R/cryptoKeys/K)")
        if client is None:
            from google.cloud import kms  # lazy: optional
            client = kms.KeyManagementServiceClient()
        self._c = client

    def wrap(self, data, aad):
        return self._c.encrypt(request={"name": self.key_name, "plaintext": data,
                                        "additional_authenticated_data": aad}).ciphertext

    def unwrap(self, blob, aad):
        try:
            return self._c.decrypt(request={"name": self.key_name, "ciphertext": blob,
                                            "additional_authenticated_data": aad}).plaintext
        except Exception as e:
            raise CryptoError("KMS refused decryption") from e


def get_provider(name=None):
    name = name or ("gcp-kms" if os.environ.get("STEGOOPS_KMS_KEY") else "env")
    return KmsProvider() if name == "gcp-kms" else EnvProvider()


def encrypt(plaintext: bytes, provider, aad: bytes) -> bytes:
    """MAGIC|ver|len(wrapped_dek)|wrapped_dek|nonce|ciphertext"""
    dek, nonce = os.urandom(32), os.urandom(12)
    wrapped = provider.wrap(dek, aad)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return MAGIC + bytes([VERSION]) + len(wrapped).to_bytes(2, "big") + wrapped + nonce + ct


def decrypt(blob: bytes, provider, aad: bytes) -> bytes:
    if blob[:4] != MAGIC or blob[4] != VERSION:
        raise CryptoError("Invalid format (wrong position key or no payload)")
    n = int.from_bytes(blob[5:7], "big")
    wrapped, rest = blob[7:7 + n], blob[7 + n:]
    dek = provider.unwrap(wrapped, aad)
    try:
        return AESGCM(dek).decrypt(rest[:12], rest[12:], aad)
    except Exception as e:
            raise CryptoError("Integrity violated (GCM tag does not match)") from e
