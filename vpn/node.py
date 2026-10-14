"""Server and client state machines, independent of real sockets/TUN for testability.

Both classes take two callbacks: `send(data, addr)` to transmit a UDP datagram and
`tun_write(packet)` to deliver a decrypted IP packet to the local TUN device.
"""

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Callable

from . import protocol
from .protocol import ProtocolError

log = logging.getLogger(__name__)

Addr = tuple[str, int]
SendFn = Callable[[bytes, Addr], None]
TunWriteFn = Callable[[bytes], None]

KEEPALIVE_INTERVAL = 25.0
SESSION_TIMEOUT = 180.0
HANDSHAKE_RETRY = 5.0
REKEY_INTERVAL = 600.0


@dataclass
class _ServerPeer:
    tunnel_ip: ipaddress.IPv4Address
    session: protocol.Session
    addr: Addr
    last_init_ts: int


class Server:
    def __init__(self, psk: bytes, interface: ipaddress.IPv4Interface, send: SendFn, tun_write: TunWriteFn) -> None:
        self.psk = psk
        self.interface = interface
        self.send = send
        self.tun_write = tun_write
        self.peers: dict[ipaddress.IPv4Address, _ServerPeer] = {}
        self.by_index: dict[int, _ServerPeer] = {}
        # Highest handshake timestamp seen per tunnel IP, kept even after a session expires
        # so a captured INIT can never be replayed to hijack an address.
        self.last_init_ts: dict[ipaddress.IPv4Address, int] = {}

    def handle_datagram(self, data: bytes, addr: Addr) -> None:
        try:
            kind = protocol.message_type(data)
            if kind == protocol.MSG_INIT:
                self._handle_init(data, addr)
            elif kind == protocol.MSG_DATA:
                self._handle_data(data, addr)
            else:
                raise ProtocolError(f"unexpected message type {kind}")
        except ProtocolError as e:
            log.debug("dropping datagram from %s: %s", addr, e)

    def _handle_init(self, data: bytes, addr: Addr) -> None:
        init = protocol.parse_init(self.psk, data)
        ip = init.tunnel_ip
        if ip not in self.interface.network or ip in (self.interface.ip, self.interface.network.network_address,
                                                       self.interface.network.broadcast_address):
            raise ProtocolError(f"tunnel IP {ip} not allowed")
        if init.timestamp_ns <= self.last_init_ts.get(ip, -1):
            raise ProtocolError("stale or replayed init")
        packet, session = protocol.respond(self.psk, init)
        self._drop(ip)
        peer = _ServerPeer(ip, session, addr, init.timestamp_ns)
        self.peers[ip] = peer
        self.by_index[session.local_idx] = peer
        self.last_init_ts[ip] = init.timestamp_ns
        self.send(packet, addr)
        log.info("peer %s connected from %s:%d", ip, *addr)

    def _handle_data(self, data: bytes, addr: Addr) -> None:
        peer = self.by_index.get(protocol.data_receiver_index(data))
        if peer is None:
            raise ProtocolError("unknown session")
        payload = peer.session.open(data)
        peer.addr = addr  # authenticated packet: follow the peer if it roams
        if not payload:
            return  # keepalive
        if protocol.ipv4_source(payload) != peer.tunnel_ip:
            raise ProtocolError(f"spoofed source from peer {peer.tunnel_ip}")
        self.tun_write(payload)

    def handle_tun(self, packet: bytes) -> None:
        dst = protocol.ipv4_destination(packet)
        peer = self.peers.get(dst) if dst else None
        if peer is None:
            return
        self.send(peer.session.seal(packet), peer.addr)

    def tick(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        for ip, peer in list(self.peers.items()):
            if now - peer.session.last_received > SESSION_TIMEOUT:
                log.info("peer %s timed out", ip)
                self._drop(ip)

    def _drop(self, ip: ipaddress.IPv4Address) -> None:
        peer = self.peers.pop(ip, None)
        if peer is not None:
            self.by_index.pop(peer.session.local_idx, None)


class Client:
    def __init__(self, psk: bytes, tunnel_ip: ipaddress.IPv4Address, server: Addr,
                 send: SendFn, tun_write: TunWriteFn) -> None:
        self.psk = psk
        self.tunnel_ip = tunnel_ip
        self.server = server
        self.send = send
        self.tun_write = tun_write
        self.session: protocol.Session | None = None
        # Kept briefly after a rekey so packets already in flight still decrypt.
        self.previous: protocol.Session | None = None
        self.pending: protocol.PendingInit | None = None
        self.last_init_sent = float("-inf")
        self.session_started = 0.0

    @property
    def connected(self) -> bool:
        return self.session is not None

    def start_handshake(self, now: float | None = None) -> None:
        self.pending = protocol.create_init(self.psk, self.tunnel_ip)
        self.last_init_sent = time.monotonic() if now is None else now
        self.send(self.pending.packet, self.server)

    def handle_datagram(self, data: bytes, addr: Addr) -> None:
        if addr != self.server:
            return
        try:
            kind = protocol.message_type(data)
            if kind == protocol.MSG_RESPONSE:
                self._handle_response(data)
            elif kind == protocol.MSG_DATA:
                self._handle_data(data)
            else:
                raise ProtocolError(f"unexpected message type {kind}")
        except ProtocolError as e:
            log.debug("dropping datagram: %s", e)

    def _handle_response(self, data: bytes) -> None:
        if self.pending is None:
            raise ProtocolError("no handshake in progress")
        session = protocol.complete(self.psk, self.pending, data)
        self.pending = None
        self.previous, self.session = self.session, session
        self.session_started = time.monotonic()
        log.info("handshake complete with %s:%d", *self.server)
        # Confirm the session right away so the server sees traffic on it.
        self.send(session.seal(b""), self.server)

    def _handle_data(self, data: bytes) -> None:
        idx = protocol.data_receiver_index(data)
        for session in (self.session, self.previous):
            if session is not None and session.local_idx == idx:
                payload = session.open(data)
                if payload:
                    self.tun_write(payload)
                return
        raise ProtocolError("unknown session")

    def handle_tun(self, packet: bytes) -> None:
        if self.session is not None:
            self.send(self.session.seal(packet), self.server)

    def tick(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        s = self.session
        if s is not None and now - s.last_received > SESSION_TIMEOUT:
            log.warning("session timed out, reconnecting")
            self.session = self.previous = None
            s = None
        needs_handshake = s is None or now - self.session_started > REKEY_INTERVAL
        if needs_handshake and now - self.last_init_sent > HANDSHAKE_RETRY:
            self.start_handshake(now)
        if s is not None and now - s.last_sent > KEEPALIVE_INTERVAL:
            self.send(s.seal(b""), self.server)
