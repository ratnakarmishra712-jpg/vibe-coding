"""
rules.py — the policy: a human-readable rule file and the matcher.

Rule file format (one rule per line, '#' starts a comment):

    action  direction  proto  src            dst            dport     state
    allow   out        any    any            any            any       any
    allow   in         tcp    any            any            22        new,established
    allow   in         udp    any            any            53        any
    deny    in         any    any            any            any       any

Fields:
  action     allow | deny | reject
  direction  in | out | any
  proto      tcp | udp | icmp | any
  src, dst   an IP, a CIDR (e.g. 10.0.0.0/8), or 'any'
  dport      a port, or 'any'
  state      comma list of: new, established, any   (stateful matching)

Rules are evaluated top-to-bottom; the FIRST match wins. If nothing matches,
the engine applies its default policy (deny).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

from .packet import Direction, Packet, Proto


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"        # drop silently
    REJECT = "reject"    # drop and tell the sender (TCP RST / ICMP unreachable)


def _match_host(spec: str, ip: str) -> bool:
    if spec == "any":
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return spec == ip


@dataclass
class Rule:
    action: Action
    direction: str          # 'in' | 'out' | 'any'
    proto: str              # 'tcp' | 'udp' | 'icmp' | 'any'
    src: str                # ip / cidr / 'any'
    dst: str                # ip / cidr / 'any'
    dport: str              # port number as str, or 'any'
    states: frozenset       # subset of {'new','established'} or {'any'}
    raw: str = ""           # original line, for logging
    lineno: int = 0

    def matches(self, pkt: Packet, conn_state: str) -> bool:
        if self.direction != "any" and self.direction != pkt.direction.value:
            return False
        if self.proto != "any" and self.proto != pkt.proto.value:
            return False
        if self.dport != "any" and str(pkt.dst_port) != self.dport:
            return False
        if not _match_host(self.src, pkt.src_ip):
            return False
        if not _match_host(self.dst, pkt.dst_ip):
            return False
        if "any" not in self.states and conn_state not in self.states:
            return False
        return True


class RuleSet:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def first_match(self, pkt: Packet, conn_state: str) -> Rule | None:
        for r in self.rules:
            if r.matches(pkt, conn_state):
                return r
        return None

    # ---- parsing ----------------------------------------------------------
    @classmethod
    def parse(cls, text: str) -> "RuleSet":
        rules: list[Rule] = []
        for i, line in enumerate(text.splitlines(), start=1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 7:
                raise ValueError(
                    f"rule line {i}: expected 7 fields "
                    f"(action direction proto src dst dport state), got {len(parts)}: {line!r}"
                )
            action, direction, proto, src, dst, dport, state = parts
            rules.append(Rule(
                action=Action(action.lower()),
                direction=direction.lower(),
                proto=proto.lower(),
                src=src,
                dst=dst,
                dport=dport.lower(),
                states=frozenset(s.strip() for s in state.lower().split(",")),
                raw=line,
                lineno=i,
            ))
        return cls(rules)

    @classmethod
    def load(cls, path: str) -> "RuleSet":
        with open(path, "r", encoding="utf-8") as f:
            return cls.parse(f.read())
