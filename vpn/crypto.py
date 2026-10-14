"""Static/ephemeral X25519 keys, Noise-style key derivation and AEAD helpers.

Every node has a long-term X25519 key pair. Handshakes combine static and
ephemeral Diffie-Hellman results (the Noise IK pattern, as used by WireGuard)
so each side is authenticated by its static key and every session gets fresh,
forward-secret transport keys.
"""

import base64
import binascii
import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_LEN = 32
TAG_LEN = 16


class CryptoError(Exception):
    pass


class KeyPair:
    def __init__(self, private: X25519PrivateKey) -> None:
        self._private = private
        self.public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "KeyPair":
        return cls(X25519PrivateKey.from_private_bytes(raw))

    def private_bytes(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )

    def dh(self, peer_public: bytes) -> bytes:
        try:
            return self._private.exchange(X25519PublicKey.from_public_bytes(peer_public))
        except ValueError:  # low-order point yielding an all-zero shared secret
            raise CryptoError("invalid public key") from None


def encode_key(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def decode_key(text: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except binascii.Error:
        raise ValueError("key is not valid base64") from None
    if len(raw) != KEY_LEN:
        raise ValueError(f"key must decode to {KEY_LEN} bytes")
    return raw


def load_private_key(path: str) -> KeyPair:
    with open(path, "r", encoding="ascii") as f:
        return KeyPair.from_bytes(decode_key(f.read()))


def hash_(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def kdf(chaining_key: bytes, input_material: bytes, outputs: int) -> list[bytes]:
    """HKDF as used by Noise: extract with the chaining key, then expand `outputs` blocks."""
    prk = _hmac(chaining_key, input_material)
    result, prev = [], b""
    for i in range(1, outputs + 1):
        prev = _hmac(prk, prev + bytes([i]))
        result.append(prev)
    return result


class Cipher:
    """ChaCha20-Poly1305 with a 64-bit counter nonce."""

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")

    def encrypt(self, counter: int, plaintext: bytes, aad: bytes) -> bytes:
        return self._aead.encrypt(self._nonce(counter), plaintext, aad)

    def decrypt(self, counter: int, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return self._aead.decrypt(self._nonce(counter), ciphertext, aad)
        except InvalidTag:
            raise CryptoError("authentication failed") from None
