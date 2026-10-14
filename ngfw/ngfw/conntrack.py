"""
conntrack.py — connection tracking. This is what makes the firewall STATEFUL.

A plain (stateless) packet filter judges each packet alone. A stateful firewall
remembers flows it has seen, so it can:
  * allow the RETURN traffic of a connection you started, automatically, without
    poking a permanent inbound hole, and
  * spot "out-of-state" packets (e.g. an ACK or data packet for a connection
    that was never opened) — a classic scan / spoofing tell.

We identify a flow by a CANONICAL key so both directions map to one entry:
    (proto, endpoint_low, endpoint_high)   where endpoint = (ip, port)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .packet import Packet, Proto

# How long an idle flow lives before we forget it (seconds).
TCP_IDLE = 600
UDP_IDLE = 60
ICMP_IDLE = 30


def _key(pkt: Packet):
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return (pkt.proto, lo, hi)


@dataclass
class Connection:
    proto: Proto
    tcp_state: str = "NEW"          # NEW -> SYN_SENT -> ESTABLISHED -> CLOSING
    opener: tuple = ()              # (ip, port) of the side that sent the first packet
    packets: int = 0
    last_seen: float = field(default_factory=time.monotonic)


class ConnTracker:
    def __init__(self, clock=time.monotonic):
        self._t: dict = {}
        self._clock = clock

    def _idle_limit(self, proto: Proto) -> float:
        return {Proto.TCP: TCP_IDLE, Proto.UDP: UDP_IDLE}.get(proto, ICMP_IDLE)

    def classify(self, pkt: Packet) -> str:
        """Classify a packet relative to known flows, BEFORE the rule check:
          * 'established' - matches a flow we're already tracking (incl. the
            reply/handshake packets of a connection we started).
          * 'new'         - a legitimate connection opener (e.g. a TCP SYN, or
            the first UDP/ICMP packet of a flow).
          * 'invalid'     - a TCP packet that is NOT a SYN but matches no known
            flow (a bare ACK/FIN/RST out of nowhere) - a scan/spoofing tell."""
        self._expire()
        conn = self._t.get(_key(pkt))
        if conn is not None:
            return "established"
        if pkt.proto == Proto.TCP and not pkt.flags.syn:
            return "invalid"
        return "new"

    def update(self, pkt: Packet) -> Connection:
        """Record/advance state for a packet the engine decided to ALLOW."""
        k = _key(pkt)
        conn = self._t.get(k)
        if conn is None:
            conn = Connection(proto=pkt.proto, opener=(pkt.src_ip, pkt.src_port))
            self._t[k] = conn

        if pkt.proto == Proto.TCP:
            f = pkt.flags
            if f.rst:
                self._t.pop(k, None)
                return conn
            if f.syn and not f.ack:
                conn.tcp_state = "SYN_SENT"
            elif f.syn and f.ack:
                conn.tcp_state = "SYN_RECV"
            elif f.ack and conn.tcp_state in ("SYN_RECV", "SYN_SENT"):
                conn.tcp_state = "ESTABLISHED"
            elif f.fin:
                conn.tcp_state = "CLOSING"
        else:
            # UDP/ICMP have no handshake; treat as established once seen.
            conn.tcp_state = "ESTABLISHED"

        conn.packets += 1
        conn.last_seen = self._clock()
        return conn

    def _expire(self) -> None:
        now = self._clock()
        dead = [k for k, c in self._t.items()
                if now - c.last_seen > self._idle_limit(c.proto)]
        for k in dead:
            del self._t[k]

    def __len__(self) -> int:
        return len(self._t)
