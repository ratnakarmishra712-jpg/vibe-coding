"""Wire format and session state.

Messages (all integers big-endian unless noted):

  INIT     type=1 | sender_idx(4) | eph_pub(32) | timestamp_ns(8) | tunnel_ip(4) | mac(32)
  RESPONSE type=2 | sender_idx(4) | receiver_idx(4) | eph_pub(32) | mac(32)
  DATA     type=3 | receiver_idx(4) | counter(8) | ciphertext+tag

The INIT mac covers the message; the RESPONSE mac covers the response plus the
full INIT it answers, binding the two together. DATA headers are authenticated
as AEAD associated data. An empty DATA payload is a keepalive.
"""

import ipaddress
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from . import crypto

MSG_INIT = 1
MSG_RESPONSE = 2
MSG_DATA = 3

_INIT_BODY = struct.Struct("!BI32sQ4s")
_RESP_BODY = struct.Struct("!BII32s")
_DATA_HDR = struct.Struct("!BIQ")

INIT_LEN = _INIT_BODY.size + crypto.MAC_LEN
RESP_LEN = _RESP_BODY.size + crypto.MAC_LEN
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
        except InvalidTag:
            raise ProtocolError("authentication failed") from None
        # Only advance the window after authentication succeeds.
        self.replay.update(counter)
        self.last_received = time.monotonic()
        return payload


def data_receiver_index(packet: bytes) -> int:
    if len(packet) < DATA_HDR_LEN:
        raise ProtocolError("short data packet")
    return _DATA_HDR.unpack_from(packet)[1]


# --- Handshake ------------------------------------------------------------


@dataclass
class PendingInit:
    """Initiator-side state while waiting for a RESPONSE."""

    local_idx: int
    ephemeral: crypto.Ephemeral
    packet: bytes


@dataclass
class InitInfo:
    sender_idx: int
    eph_pub: bytes
    timestamp_ns: int
    tunnel_ip: ipaddress.IPv4Address
    packet: bytes


def create_init(psk: bytes, tunnel_ip: ipaddress.IPv4Address, now_ns: int | None = None) -> PendingInit:
    eph = crypto.Ephemeral()
    idx = new_index()
    ts = time.time_ns() if now_ns is None else now_ns
    body = _INIT_BODY.pack(MSG_INIT, idx, eph.public, ts, tunnel_ip.packed)
    packet = body + crypto.compute_mac(crypto.mac_key(psk), body)
    return PendingInit(idx, eph, packet)


def parse_init(psk: bytes, packet: bytes, now_ns: int | None = None) -> InitInfo:
    if len(packet) != INIT_LEN:
        raise ProtocolError("bad init length")
    body, mac = packet[: _INIT_BODY.size], packet[_INIT_BODY.size :]
    if not crypto.verify_mac(crypto.mac_key(psk), body, mac):
        raise ProtocolError("init mac mismatch")
    _, idx, eph_pub, ts, ip = _INIT_BODY.unpack(body)
    now = time.time_ns() if now_ns is None else now_ns
    if abs(now - ts) > MAX_CLOCK_SKEW_NS:
        raise ProtocolError("init timestamp outside allowed skew")
    return InitInfo(idx, eph_pub, ts, ipaddress.IPv4Address(ip), packet)


def respond(psk: bytes, init: InitInfo) -> tuple[bytes, Session]:
    eph = crypto.Ephemeral()
    idx = new_index()
    body = _RESP_BODY.pack(MSG_RESPONSE, idx, init.sender_idx, eph.public)
    packet = body + crypto.compute_mac(crypto.mac_key(psk), body + init.packet)
    k_i2r, k_r2i = crypto.derive_keys(psk, eph.exchange(init.eph_pub), init.eph_pub, eph.public)
    session = Session(idx, init.sender_idx, crypto.Cipher(k_r2i), crypto.Cipher(k_i2r))
    return packet, session


def complete(psk: bytes, pending: PendingInit, packet: bytes) -> Session:
    if len(packet) != RESP_LEN:
        raise ProtocolError("bad response length")
    body, mac = packet[: _RESP_BODY.size], packet[_RESP_BODY.size :]
    if not crypto.verify_mac(crypto.mac_key(psk), body + pending.packet, mac):
        raise ProtocolError("response mac mismatch")
    _, idx, receiver_idx, eph_pub = _RESP_BODY.unpack(body)
    if receiver_idx != pending.local_idx:
        raise ProtocolError("response for unknown handshake")
    k_i2r, k_r2i = crypto.derive_keys(psk, pending.ephemeral.exchange(eph_pub), pending.ephemeral.public, eph_pub)
    return Session(pending.local_idx, idx, crypto.Cipher(k_i2r), crypto.Cipher(k_r2i))


def ipv4_source(packet: bytes) -> ipaddress.IPv4Address | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    return ipaddress.IPv4Address(packet[12:16])


def ipv4_destination(packet: bytes) -> ipaddress.IPv4Address | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    return ipaddress.IPv4Address(packet[16:20])
