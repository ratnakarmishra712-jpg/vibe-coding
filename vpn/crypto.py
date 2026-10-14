"""Handshake key agreement and authenticated packet encryption.

Each session starts with an ephemeral X25519 exchange (forward secrecy). Both
handshake messages are authenticated with an HMAC keyed from a pre-shared key,
and the PSK is also mixed into the session key derivation, so a peer without
the PSK can neither complete a handshake nor read traffic.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PSK_LEN = 32
PUBKEY_LEN = 32
MAC_LEN = 32
TAG_LEN = 16
PROTOCOL_LABEL = b"vibe-vpn v1"


def generate_psk() -> bytes:
    return os.urandom(PSK_LEN)


def load_psk(path: str) -> bytes:
    with open(path, "r", encoding="ascii") as f:
        psk = bytes.fromhex(f.read().strip())
    if len(psk) != PSK_LEN:
        raise ValueError(f"PSK must be {PSK_LEN} bytes ({PSK_LEN * 2} hex chars)")
    return psk


def mac_key(psk: bytes) -> bytes:
    return hashlib.sha256(PROTOCOL_LABEL + b" mac" + psk).digest()


def compute_mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_mac(key: bytes, data: bytes, mac: bytes) -> bool:
    return hmac.compare_digest(compute_mac(key, data), mac)


class Ephemeral:
    """A one-shot X25519 key pair used for a single handshake."""

    def __init__(self) -> None:
        self._private = X25519PrivateKey.generate()
        self.public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def exchange(self, peer_public: bytes) -> bytes:
        return self._private.exchange(X25519PublicKey.from_public_bytes(peer_public))


def derive_keys(psk: bytes, shared: bytes, init_pub: bytes, resp_pub: bytes) -> tuple[bytes, bytes]:
    """Return (initiator->responder key, responder->initiator key)."""
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=psk,
        info=PROTOCOL_LABEL + b" keys" + init_pub + resp_pub,
    ).derive(shared)
    return okm[:32], okm[32:]


class Cipher:
    """ChaCha20-Poly1305 with a 64-bit counter nonce, carried in the packet header."""

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")

    def encrypt(self, counter: int, plaintext: bytes, aad: bytes) -> bytes:
        return self._aead.encrypt(self._nonce(counter), plaintext, aad)

    def decrypt(self, counter: int, ciphertext: bytes, aad: bytes) -> bytes:
        return self._aead.decrypt(self._nonce(counter), ciphertext, aad)
