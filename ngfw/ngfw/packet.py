"""
packet.py — a portable, backend-agnostic representation of a network packet.

The whole firewall reasons about THIS object, never about raw bytes or a
specific OS API. That is the key design idea: whether a packet came from a live
capture (pcap), from Linux NFQUEUE, or from the simulator, every backend builds
one of these and hands it to the engine. Swap the backend, keep the brain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Direction(str, Enum):
    IN = "in"      # arriving from the outside toward us
    OUT = "out"    # leaving us toward the outside


class Proto(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


# TCP flags we care about for connection tracking.
@dataclass(frozen=True)
class TcpFlags:
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False

    def __str__(self) -> str:
        on = [n for n, v in (("SYN", self.syn), ("ACK", self.ack),
                             ("FIN", self.fin), ("RST", self.rst)) if v]
        return "|".join(on) if on else "-"


@dataclass
class Packet:
    """One packet, as the firewall sees it (Layer 3 + Layer 4 fields)."""
    direction: Direction
    proto: Proto
    src_ip: str
    dst_ip: str
    src_port: int = 0          # 0 for ICMP / protocols without ports
    dst_port: int = 0
    flags: TcpFlags = field(default_factory=TcpFlags)
    length: int = 0            # payload size, for logging/stats
    # L7 hints (filled in later by app-ID / DPI layers; empty for now)
    meta: dict = field(default_factory=dict)

    def five_tuple(self) -> tuple:
        """The classic identity of a flow: proto + both endpoints."""
        return (self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def __str__(self) -> str:
        p = f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
        if self.proto == Proto.ICMP:
            p = f"{self.src_ip} -> {self.dst_ip}"
        return f"[{self.direction.value:>3}] {self.proto.value:<4} {p} {self.flags}"
