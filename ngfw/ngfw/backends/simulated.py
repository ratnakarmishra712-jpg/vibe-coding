"""
simulated.py — a scripted data plane for learning.

It emits a small, readable story of packets so you can watch the engine make
stateful decisions. No root, no real network, totally safe. This is the backend
you experiment in first.

The scenario is designed to show the one thing that separates a real firewall
from a dumb ACL: STATE. Notice that the reply traffic for a connection we
started is allowed by the 'established' rule, even though there is NO inbound
'new' rule that would let a stranger start that same connection.
"""
from __future__ import annotations

from collections.abc import Iterator

from ..packet import Direction, Packet, Proto, TcpFlags
from .base import Backend

SYN = TcpFlags(syn=True)
SYNACK = TcpFlags(syn=True, ack=True)
ACK = TcpFlags(ack=True)


def default_scenario() -> list[Packet]:
    me = "10.0.0.5"          # our host
    dns = "1.1.1.1"
    web = "93.184.216.34"
    attacker = "203.0.113.9"
    return [
        # 1) We look up a name: outbound UDP/53 -> allowed by the outbound rule.
        Packet(Direction.OUT, Proto.UDP, me, dns, 40000, 53, length=40),
        # 2) The DNS reply comes back INbound, but it's ESTABLISHED (return of
        #    the flow we started) -> allowed WITHOUT any inbound 'new' rule.
        Packet(Direction.IN, Proto.UDP, dns, me, 53, 40000, length=120),

        # 3) We open a web connection (TCP handshake). The SYN is outbound-new;
        #    every reply is inbound-established thanks to conntrack.
        Packet(Direction.OUT, Proto.TCP, me, web, 50001, 443, SYN, 60),
        Packet(Direction.IN, Proto.TCP, web, me, 443, 50001, SYNACK, 60),    # reply: established
        Packet(Direction.OUT, Proto.TCP, me, web, 50001, 443, ACK, 52),
        Packet(Direction.IN, Proto.TCP, web, me, 443, 50001, ACK, 1400),     # data reply: established

        # 4) A stranger tries to SSH into us: inbound NEW to :22.
        #    Allowed ONLY because our rules explicitly permit new inbound SSH.
        Packet(Direction.IN, Proto.TCP, attacker, me, 51000, 22, SYN, 60),

        # 5) The same stranger tries Telnet (:23): inbound NEW, no rule -> DENY.
        Packet(Direction.IN, Proto.TCP, attacker, me, 51001, 23, SYN, 60),

        # 6) Out-of-state attack: a bare ACK to a high port with NO prior flow.
        #    Not 'established' (we never saw a handshake) and no 'new' rule -> DENY.
        Packet(Direction.IN, Proto.TCP, attacker, me, 51002, 50505, ACK, 40),
    ]


class SimulatedBackend(Backend):
    def __init__(self, firewall, scenario: list[Packet] | None = None):
        super().__init__(firewall)
        self.scenario = scenario if scenario is not None else default_scenario()

    def packets(self) -> Iterator[Packet]:
        yield from self.scenario
