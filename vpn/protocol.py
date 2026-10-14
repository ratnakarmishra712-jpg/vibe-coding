"""Wire format and session state.

Messages (all integers big-endian unless noted):

  INIT     type=1 | sender_idx(4) | eph_pub(32) | enc(static_pub)(32+16) | enc(timestamp_ns)(8+16)
           | mac1(16) | mac2(16)
  RESPONSE type=2 | sender_idx(4) | receiver_idx(4) | eph_pub(32) | enc(empty)(16)
  DATA     type=3 | receiver_idx(4) | counter(8) | ciphertext+tag
  COOKIE   type=4 | receiver_idx(4) | nonce(12) | enc(cookie)(16+16)

The handshake follows the Noise IK pattern (`-> e, es, s, ss` / `<- e, ee, se`):
the initiator's static key travels encrypted, every encryption is bound to the
running transcript hash, and only the holders of the expected static private
keys can derive the session keys. DATA headers are authenticated as AEAD
associated data. An empty DATA payload is a keepalive.

mac1/mac2 are the WireGuard-style DoS defence (see `vpn.dos`): mac1 is keyed by
the responder's public key and lets it discard junk without doing any DH; mac2
is keyed by a cookie the responder hands out when under load, proving the
sender can receive traffic at its claimed source address.
"""

import hashlib

import hmac
import ipaddress
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from . import crypto

MSG_INIT = 1
MSG_RESPONSE = 2
MSG_DATA = 3
MSG_COOKIE = 4

_INIT_HDR = struct.Struct("!BI")
_RESP_HDR = struct.Struct("!BII")
_DATA_HDR = struct.Struct("!BIQ")
_ENC_STATIC_LEN = crypto.KEY_LEN + crypto.TAG_LEN
_ENC_TS_LEN = 8 + crypto.TAG_LEN
_COOKIE_HDR = struct.Struct("!BI")
MAC_LEN = 16
COOKIE_NONCE_LEN = 12

CONSTRUCTION = b"vibe-vpn v2 Noise_IK_25519_ChaChaPoly_SHA256"
INIT_BODY_LEN = _INIT_HDR.size + crypto.KEY_LEN + _ENC_STATIC_LEN + _ENC_TS_LEN
INIT_LEN = INIT_BODY_LEN + 2 * MAC_LEN
COOKIE_LEN = _COOKIE_HDR.size + COOKIE_NONCE_LEN + MAC_LEN + crypto.TAG_LEN
RESP_LEN = _RESP_HDR.size + crypto.KEY_LEN + crypto.TAG_LEN
DATA_HDR_LEN = _DATA_HDR.size

# Handshakes older than this (or from the future by more than this) are rejected.
MAX_CLOCK_SKEW_NS = 60 * 1_000_000_000
REPLAY_WINDOW = 2048
# Stop using a session well before the 64-bit counter could ever wrap.
REKEY_AFTER_MESSAGES = 2**60


class ProtocolError(Exception):
    pass


def new_index() -> int:
    return int.from_bytes(os.urandom(4), "big")


def message_type(packet: bytes) -> int:
    if not packet:
        raise ProtocolError("empty packet")
    return packet[0]


class ReplayWindow:
    """Sliding-window anti-replay filter (RFC 6479 style, bitmap as an int)."""

    def __init__(self, size: int = REPLAY_WINDOW) -> None:
        self.size = size
        self.highest = -1
        self.bitmap = 0

    def check(self, counter: int) -> bool:
        if counter > self.highest:
            return True
        offset = self.highest - counter
        if offset >= self.size:
            return False
        return not (self.bitmap >> offset) & 1

    def update(self, counter: int) -> None:
        if counter > self.highest:
            shift = counter - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            self.highest = counter
        else:
            self.bitmap |= 1 << (self.highest - counter)


@dataclass
class Session:
    local_idx: int
    remote_idx: int
    send_cipher: crypto.Cipher
    recv_cipher: crypto.Cipher
    send_counter: int = 0
    replay: ReplayWindow = field(default_factory=ReplayWindow)
    last_received: float = field(default_factory=time.monotonic)
    last_sent: float = field(default_factory=time.monotonic)

    def seal(self, payload: bytes) -> bytes:
        if self.send_counter >= REKEY_AFTER_MESSAGES:
            raise ProtocolError("session exhausted; reconnect")
        header = _DATA_HDR.pack(MSG_DATA, self.remote_idx, self.send_counter)
        self.send_counter += 1
        self.last_sent = time.monotonic()
        return header + self.send_cipher.encrypt(self.send_counter - 1, payload, header)

    def open(self, packet: bytes) -> bytes:
        if len(packet) < DATA_HDR_LEN + crypto.TAG_LEN:
            raise ProtocolError("short data packet")
        header = packet[:DATA_HDR_LEN]
        _, _, counter = _DATA_HDR.unpack(header)
        if not self.replay.check(counter):
            raise ProtocolError("replayed or too-old packet")
        try:
            payload = self.recv_cipher.decrypt(counter, packet[DATA_HDR_LEN:], header)
        except crypto.CryptoError as e:
            raise ProtocolError(str(e)) from None
        # Only advance the window after authentication succeeds.
        self.replay.update(counter)
        self.last_received = time.monotonic()
        return payload


def data_receiver_index(packet: bytes) -> int:
    if len(packet) < DATA_HDR_LEN:
        raise ProtocolError("short data packet")
    return _DATA_HDR.unpack_from(packet)[1]


# --- Handshake (Noise IK: initiator knows the responder's static key) ------


@dataclass
class _Symmetric:
    """Noise chaining key `ck` and transcript hash `h`."""

    ck: bytes
    h: bytes

    @classmethod
    def initial(cls, responder_static: bytes) -> "_Symmetric":
        ck = crypto.hash_(CONSTRUCTION)
        return cls(ck, crypto.hash_(ck, responder_static))

    def mix_hash(self, data: bytes) -> None:
        self.h = crypto.hash_(self.h, data)

    def mix_key(self, material: bytes) -> bytes:
        self.ck, key = crypto.kdf(self.ck, material, 2)
        return key

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        ct = crypto.Cipher(key).encrypt(0, plaintext, self.h)
        self.mix_hash(ct)
        return ct

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        pt = crypto.Cipher(key).decrypt(0, ciphertext, self.h)
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[bytes, bytes]:
        k_i2r, k_r2i = crypto.kdf(self.ck, b"", 2)
        return k_i2r, k_r2i


@dataclass
class PendingInit:
    """Initiator-side state while waiting for a RESPONSE."""

    local_idx: int
    ephemeral: crypto.KeyPair
    state: _Symmetric
    packet: bytes


@dataclass
class InitInfo:
    """A decrypted, authenticated INIT. The caller must still check `static_public` is a known peer."""

    sender_idx: int
    ephemeral_public: bytes
    static_public: bytes
    timestamp_ns: int
    state: _Symmetric


def create_init(static: crypto.KeyPair, responder_public: bytes, now_ns: int | None = None,
                cookie: bytes | None = None) -> PendingInit:
    st = _Symmetric.initial(responder_public)
    eph = crypto.KeyPair.generate()
    idx = new_index()
    ts = time.time_ns() if now_ns is None else now_ns
    try:
        st.mix_hash(eph.public)
        st.mix_key(eph.public)
        enc_static = st.encrypt(st.mix_key(eph.dh(responder_public)), static.public)   # es, s
        enc_ts = st.encrypt(st.mix_key(static.dh(responder_public)), struct.pack("!Q", ts))  # ss
    except crypto.CryptoError as e:
        raise ProtocolError(str(e)) from None
    body = _INIT_HDR.pack(MSG_INIT, idx) + eph.public + enc_static + enc_ts
    m1 = mac(mac1_key(responder_public), body)
    m2 = mac(cookie, body + m1) if cookie else bytes(MAC_LEN)
    return PendingInit(idx, eph, st, body + m1 + m2)


def parse_init(static: crypto.KeyPair, packet: bytes, now_ns: int | None = None) -> InitInfo:
    if len(packet) != INIT_LEN:
        raise ProtocolError("bad init length")
    _, idx = _INIT_HDR.unpack_from(packet)
    off = _INIT_HDR.size
    eph_pub = packet[off : off + 32]
    enc_static = packet[off + 32 : off + 32 + _ENC_STATIC_LEN]
    enc_ts = packet[off + 32 + _ENC_STATIC_LEN : INIT_BODY_LEN]
    st = _Symmetric.initial(static.public)
    try:
        st.mix_hash(eph_pub)
        st.mix_key(eph_pub)
        peer_static = st.decrypt(st.mix_key(static.dh(eph_pub)), enc_static)
        (ts,) = struct.unpack("!Q", st.decrypt(st.mix_key(static.dh(peer_static)), enc_ts))
    except crypto.CryptoError as e:
        raise ProtocolError(f"init rejected: {e}") from None
    now = time.time_ns() if now_ns is None else now_ns
    if abs(now - ts) > MAX_CLOCK_SKEW_NS:
        raise ProtocolError("init timestamp outside allowed skew")
    return InitInfo(idx, eph_pub, peer_static, ts, st)


def respond(init: InitInfo) -> tuple[bytes, Session]:
    st = init.state
    eph = crypto.KeyPair.generate()
    idx = new_index()
    try:
        st.mix_hash(eph.public)
        st.mix_key(eph.public)
        st.mix_key(eph.dh(init.ephemeral_public))  # ee
        key = st.mix_key(eph.dh(init.static_public))  # se
    except crypto.CryptoError as e:
        raise ProtocolError(str(e)) from None
    packet = _RESP_HDR.pack(MSG_RESPONSE, idx, init.sender_idx) + eph.public + st.encrypt(key, b"")
    k_i2r, k_r2i = st.split()
    return packet, Session(idx, init.sender_idx, crypto.Cipher(k_r2i), crypto.Cipher(k_i2r))


def complete(static: crypto.KeyPair, pending: PendingInit, packet: bytes) -> Session:
    if len(packet) != RESP_LEN:
        raise ProtocolError("bad response length")
    _, idx, receiver_idx = _RESP_HDR.unpack_from(packet)
    if receiver_idx != pending.local_idx:
        raise ProtocolError("response for unknown handshake")
    eph_pub = packet[_RESP_HDR.size : _RESP_HDR.size + 32]
    # Work on a copy so a forged response can't corrupt state needed for the genuine one.
    st = _Symmetric(pending.state.ck, pending.state.h)
    try:
        st.mix_hash(eph_pub)
        st.mix_key(eph_pub)
        st.mix_key(pending.ephemeral.dh(eph_pub))  # ee
        st.decrypt(st.mix_key(static.dh(eph_pub)), packet[_RESP_HDR.size + 32 :])  # se
    except crypto.CryptoError as e:
        raise ProtocolError(f"response rejected: {e}") from None
    k_i2r, k_r2i = st.split()
    return Session(pending.local_idx, idx, crypto.Cipher(k_i2r), crypto.Cipher(k_r2i))


# --- mac1 / mac2 / cookie replies ------------------------------------------


def mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=MAC_LEN).digest()


def mac1_key(responder_public: bytes) -> bytes:
    return crypto.hash_(b"mac1----", responder_public)


def cookie_key(responder_public: bytes) -> bytes:
    return crypto.hash_(b"cookie--", responder_public)


def init_sender_index(packet: bytes) -> int:
    return _INIT_HDR.unpack_from(packet)[1]


def init_mac1(packet: bytes) -> bytes:
    return packet[INIT_BODY_LEN : INIT_BODY_LEN + MAC_LEN]


def verify_mac1(key: bytes, packet: bytes) -> bool:
    if len(packet) != INIT_LEN:
        return False
    return hmac.compare_digest(mac(key, packet[:INIT_BODY_LEN]), init_mac1(packet))


def verify_mac2(cookie: bytes, packet: bytes) -> bool:
    end = INIT_BODY_LEN + MAC_LEN
    return hmac.compare_digest(mac(cookie, packet[:end]), packet[end:])


def seal_cookie(key: bytes, init_packet: bytes, cookie: bytes) -> bytes:
    """Encrypt `cookie` for the sender of `init_packet`, bound to that packet's mac1."""
    nonce = os.urandom(COOKIE_NONCE_LEN)
    header = _COOKIE_HDR.pack(MSG_COOKIE, init_sender_index(init_packet))
    return header + nonce + ChaCha20Poly1305(key).encrypt(nonce, cookie, init_mac1(init_packet))


def open_cookie(responder_public: bytes, pending: PendingInit, packet: bytes) -> bytes:
    if len(packet) != COOKIE_LEN:
        raise ProtocolError("bad cookie reply length")
    _, receiver_idx = _COOKIE_HDR.unpack_from(packet)
    if receiver_idx != pending.local_idx:
        raise ProtocolError("cookie reply for unknown handshake")
    nonce = packet[_COOKIE_HDR.size : _COOKIE_HDR.size + COOKIE_NONCE_LEN]
    try:
        return ChaCha20Poly1305(cookie_key(responder_public)).decrypt(
            nonce, packet[_COOKIE_HDR.size + COOKIE_NONCE_LEN :], init_mac1(pending.packet))
    except InvalidTag:
        raise ProtocolError("cookie reply authentication failed") from None


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# version -> (minimum header length, source offset, destination offset, address length, address class)
_IP_LAYOUT = {
    4: (20, 12, 16, 4, ipaddress.IPv4Address),
    6: (40, 8, 24, 16, ipaddress.IPv6Address),
}


def _ip_field(packet: bytes, which: int) -> IPAddress | None:
    if not packet:
        return None
    layout = _IP_LAYOUT.get(packet[0] >> 4)
    if layout is None or len(packet) < layout[0]:
        return None
    off, length, cls = layout[which], layout[3], layout[4]
    return cls(packet[off : off + length])


def ip_source(packet: bytes) -> IPAddress | None:
    """Source address of an IPv4 or IPv6 packet, or None if it isn't one."""
    return _ip_field(packet, 1)


def ip_destination(packet: bytes) -> IPAddress | None:
    """Destination address of an IPv4 or IPv6 packet, or None if it isn't one."""
    return _ip_field(packet, 2)
