"""Wire format and session state.

Messages (all integers big-endian unless noted):

  INIT     type=1 | sender_idx(4) | eph_pub(32) | enc(static_pub)(32+16) | enc(timestamp_ns)(8+16)
  RESPONSE type=2 | sender_idx(4) | receiver_idx(4) | eph_pub(32) | enc(empty)(16)
  DATA     type=3 | receiver_idx(4) | counter(8) | ciphertext+tag

The handshake follows the Noise IK pattern (`-> e, es, s, ss` / `<- e, ee, se`):
the initiator's static key travels encrypted, every encryption is bound to the
running transcript hash, and only the holders of the expected static private
keys can derive the session keys. DATA headers are authenticated as AEAD
associated data. An empty DATA payload is a keepalive.
"""

import ipaddress
import os
import struct
import time
from dataclasses import dataclass, field

from . import crypto

MSG_INIT = 1
MSG_RESPONSE = 2
MSG_DATA = 3

_INIT_HDR = struct.Struct("!BI")
_RESP_HDR = struct.Struct("!BII")
_DATA_HDR = struct.Struct("!BIQ")
_ENC_STATIC_LEN = crypto.KEY_LEN + crypto.TAG_LEN
_ENC_TS_LEN = 8 + crypto.TAG_LEN

CONSTRUCTION = b"vibe-vpn v2 Noise_IK_25519_ChaChaPoly_SHA256"
INIT_LEN = _INIT_HDR.size + crypto.KEY_LEN + _ENC_STATIC_LEN + _ENC_TS_LEN
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


def create_init(static: crypto.KeyPair, responder_public: bytes, now_ns: int | None = None) -> PendingInit:
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
    packet = _INIT_HDR.pack(MSG_INIT, idx) + eph.public + enc_static + enc_ts
    return PendingInit(idx, eph, st, packet)


def parse_init(static: crypto.KeyPair, packet: bytes, now_ns: int | None = None) -> InitInfo:
    if len(packet) != INIT_LEN:
        raise ProtocolError("bad init length")
    _, idx = _INIT_HDR.unpack_from(packet)
    off = _INIT_HDR.size
    eph_pub = packet[off : off + 32]
    enc_static = packet[off + 32 : off + 32 + _ENC_STATIC_LEN]
    enc_ts = packet[off + 32 + _ENC_STATIC_LEN :]
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


def ipv4_source(packet: bytes) -> ipaddress.IPv4Address | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    return ipaddress.IPv4Address(packet[12:16])


def ipv4_destination(packet: bytes) -> ipaddress.IPv4Address | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    return ipaddress.IPv4Address(packet[16:20])
