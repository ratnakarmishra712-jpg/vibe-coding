"""Server and client state machines, independent of real sockets/TUN for testability.

Both classes take two callbacks: `send(data, addr)` to transmit a UDP datagram and
`tun_write(packet)` to deliver a decrypted IP packet to the local TUN device.
Addresses are socket address tuples as returned by `recvfrom`: `(host, port)` for
IPv4 or `(host, port, flowinfo, scope_id)` for IPv6.
"""

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Callable

from . import crypto, dos, protocol
from .protocol import ProtocolError

log = logging.getLogger(__name__)

Addr = tuple  # (host, port) or (host, port, flowinfo, scope_id)
IPInterface = ipaddress.IPv4Interface | ipaddress.IPv6Interface
SendFn = Callable[[bytes, Addr], None]
TunWriteFn = Callable[[bytes], None]

def format_addr(addr: Addr) -> str:
    host, port = addr[0], addr[1]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _reserved(iface: IPInterface) -> set:
    net = iface.network
    if net.version == 4 and net.prefixlen < 31:
        return {iface.ip, net.network_address, net.broadcast_address}
    return {iface.ip, net.network_address}  # IPv6 subnet-router anycast address


KEEPALIVE_INTERVAL = 25.0
SESSION_TIMEOUT = 180.0
HANDSHAKE_RETRY = 5.0
REKEY_INTERVAL = 600.0


@dataclass
class _ServerPeer:
    public_key: bytes
    addresses: frozenset[protocol.IPAddress]
    session: protocol.Session | None = None
    addr: Addr | None = None
    # Highest handshake timestamp accepted, kept after a session expires so a
    # captured INIT can never be replayed to hijack the peer.
    last_init_ts: int = -1

    @property
    def name(self) -> str:
        return ",".join(sorted(map(str, self.addresses), key=lambda a: (":" in a, a)))


class Server:
    def __init__(self, static: crypto.KeyPair, interfaces: list[IPInterface],
                 peers: dict[bytes, list[protocol.IPAddress]], send: SendFn, tun_write: TunWriteFn,
                 load_threshold: int = dos.DEFAULT_LOAD_THRESHOLD, clock: dos.Clock = time.monotonic) -> None:
        self.static = static
        self.clock = clock
        self.cookies = dos.CookieChecker(static.public)
        self.load = dos.LoadMonitor(load_threshold)
        self.limiter = dos.RateLimiter()
        self.interfaces = interfaces
        self.send = send
        self.tun_write = tun_write
        self.peers: dict[bytes, _ServerPeer] = {}
        self.by_ip: dict[protocol.IPAddress, _ServerPeer] = {}
        for key, addresses in peers.items():
            if not addresses:
                raise ValueError(f"peer {crypto.encode_key(key)} has no addresses")
            peer = self.peers[key] = _ServerPeer(key, frozenset(addresses))
            for ip in addresses:
                if not any(ip.version == i.version and ip in i.network and ip not in _reserved(i)
                           for i in interfaces):
                    raise ValueError(f"peer address {ip} is not usable in any tunnel subnet")
                if ip in self.by_ip:
                    raise ValueError(f"peer address {ip} assigned twice")
                self.by_ip[ip] = peer
        self.by_index: dict[int, _ServerPeer] = {}

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
        # Everything up to parse_init is cheap; parse_init does two DH operations.
        if not self.cookies.check_mac1(data):
            raise ProtocolError("bad mac1")
        now = self.clock()
        if self.load.record(now):
            if not self.cookies.check_mac2(data, addr, now):
                self.send(self.cookies.reply(data, addr, now), addr)
                return
            if not self.limiter.allow(addr[0], now):
                raise ProtocolError("handshake rate limit exceeded")
        init = protocol.parse_init(self.static, data)
        peer = self.peers.get(init.static_public)
        if peer is None:
            raise ProtocolError(f"unknown peer key {crypto.encode_key(init.static_public)}")
        if init.timestamp_ns <= peer.last_init_ts:
            raise ProtocolError("stale or replayed init")
        packet, session = protocol.respond(init)
        self._end_session(peer)
        peer.session, peer.addr, peer.last_init_ts = session, addr, init.timestamp_ns
        self.by_index[session.local_idx] = peer
        self.send(packet, addr)
        log.info("peer %s (%s) connected from %s", peer.name, crypto.encode_key(peer.public_key), format_addr(addr))

    def _handle_data(self, data: bytes, addr: Addr) -> None:
        peer = self.by_index.get(protocol.data_receiver_index(data))
        if peer is None or peer.session is None:
            raise ProtocolError("unknown session")
        payload = peer.session.open(data)
        peer.addr = addr  # authenticated packet: follow the peer if it roams
        if not payload:
            return  # keepalive
        if protocol.ip_source(payload) not in peer.addresses:
            raise ProtocolError(f"spoofed source from peer {peer.name}")
        self.tun_write(payload)

    def handle_tun(self, packet: bytes) -> None:
        dst = protocol.ip_destination(packet)
        peer = self.by_ip.get(dst) if dst else None
        if peer is None or peer.session is None:
            return
        self.send(peer.session.seal(packet), peer.addr)

    def tick(self, now: float | None = None) -> None:
        now = self.clock() if now is None else now
        self.limiter.prune(now)
        for peer in self.peers.values():
            if peer.session is not None and now - peer.session.last_received > SESSION_TIMEOUT:
                log.info("peer %s timed out", peer.name)
                self._end_session(peer)

    def _end_session(self, peer: _ServerPeer) -> None:
        if peer.session is not None:
            self.by_index.pop(peer.session.local_idx, None)
            peer.session = None


class Client:
    def __init__(self, static: crypto.KeyPair, server_public: bytes, server: Addr,
                 send: SendFn, tun_write: TunWriteFn) -> None:
        self.static = static
        self.server_public = server_public
        self.server = server
        self.cookies = dos.CookieJar()
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
        self.pending = protocol.create_init(self.static, self.server_public, cookie=self.cookies.current())
        self.last_init_sent = time.monotonic() if now is None else now
        self.send(self.pending.packet, self.server)

    def handle_datagram(self, data: bytes, addr: Addr) -> None:
        if addr[:2] != self.server[:2]:
            return
        try:
            kind = protocol.message_type(data)
            if kind == protocol.MSG_RESPONSE:
                self._handle_response(data)
            elif kind == protocol.MSG_DATA:
                self._handle_data(data)
            elif kind == protocol.MSG_COOKIE:
                self._handle_cookie(data)
            else:
                raise ProtocolError(f"unexpected message type {kind}")
        except ProtocolError as e:
            log.debug("dropping datagram: %s", e)

    def _handle_response(self, data: bytes) -> None:
        if self.pending is None:
            raise ProtocolError("no handshake in progress")
        session = protocol.complete(self.static, self.pending, data)
        self.pending = None
        self.previous, self.session = self.session, session
        self.session_started = time.monotonic()
        log.info("handshake complete with %s", format_addr(self.server))
        # Confirm the session right away so the server sees traffic on it.
        self.send(session.seal(b""), self.server)

    def _handle_cookie(self, data: bytes) -> None:
        if self.pending is None:
            raise ProtocolError("no handshake in progress")
        self.cookies.store(protocol.open_cookie(self.server_public, self.pending, data))
        # Like WireGuard, wait for the normal retry timer rather than resending at once,
        # so a busy server isn't hit with an immediate burst of retries.
        log.info("server is under load; got a cookie, will retry handshake")

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
        dst = protocol.ip_destination(packet)
        # The kernel emits IPv6 neighbour/router discovery and MLD on the TUN device;
        # there is no link layer to resolve, so don't waste tunnel traffic on them.
        if dst is None or dst.is_multicast:
            return
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
