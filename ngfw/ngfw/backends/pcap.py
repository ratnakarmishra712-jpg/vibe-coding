"""
pcap.py — read REAL packets from a capture file and feed the same engine.

This is Stage 2. Nothing about the firewall brain changes: we just translate
scapy packets into our portable `Packet` and hand them to `Firewall.evaluate`.
Still observe-only (we don't drop anything) — that comes with the NFQUEUE
backend in Stage 3.

Direction problem
-----------------
A capture file has no built-in notion of "inbound" vs "outbound" — it's just
packets on a wire. So you tell the backend which address(es) are "home" (your
host or network). A packet whose SOURCE is home is OUTbound; everything else is
treated as INbound. That mirrors how a host firewall sees its own traffic.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterator

from ..packet import Direction, Packet, Proto, TcpFlags
from .base import Backend

try:
    from scapy.all import ICMP, IP, TCP, UDP, rdpcap
    _SCAPY_OK = True
except Exception as _e:  # pragma: no cover - only hit when scapy is missing
    _SCAPY_OK = False
    _IMPORT_ERR = _e

# TCP flag bit positions (RFC 793), used to read scapy's flags field robustly.
_FIN, _SYN, _RST, _ACK = 0x01, 0x02, 0x04, 0x10


def _parse_home(home) -> list:
    """Accept a CIDR string, a comma list, or a list; return ip_network objects."""
    if isinstance(home, str):
        home = home.split(",")
    return [ipaddress.ip_network(h.strip(), strict=False) for h in home if str(h).strip()]


def _is_home(ip: str, home_nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in home_nets)


def from_scapy(sp, home_nets: list) -> Packet | None:
    """Convert one scapy packet to our portable Packet, or None if we skip it
    (non-IPv4 for now — IPv6 is a later enhancement)."""
    if IP not in sp:
        return None
    ip = sp[IP]
    src, dst = ip.src, ip.dst

    sport = dport = 0
    flags = TcpFlags()
    if TCP in sp:
        proto = Proto.TCP
        t = sp[TCP]
        sport, dport = int(t.sport), int(t.dport)
        fl = int(t.flags)
        flags = TcpFlags(syn=bool(fl & _SYN), ack=bool(fl & _ACK),
                         fin=bool(fl & _FIN), rst=bool(fl & _RST))
    elif UDP in sp:
        proto = Proto.UDP
        u = sp[UDP]
        sport, dport = int(u.sport), int(u.dport)
    elif ICMP in sp:
        proto = Proto.ICMP
    else:
        proto = Proto.OTHER

    direction = Direction.OUT if _is_home(src, home_nets) else Direction.IN
    return Packet(direction, proto, src, dst, sport, dport, flags, length=len(sp))


class PcapBackend(Backend):
    def __init__(self, firewall, path: str, home="10.0.0.5/32"):
        super().__init__(firewall)
        if not _SCAPY_OK:
            raise RuntimeError(
                "the pcap backend needs scapy: pip install scapy "
                f"(import failed: {_IMPORT_ERR})"
            )
        self.path = path
        self.home_nets = _parse_home(home)

    def packets(self) -> Iterator[Packet]:
        for sp in rdpcap(self.path):
            pkt = from_scapy(sp, self.home_nets)
            if pkt is not None:
                yield pkt
