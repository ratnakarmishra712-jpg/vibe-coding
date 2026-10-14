"""
base.py — the Backend interface (the "plumbing").

A backend's job is only to (1) produce Packets from somewhere and (2) carry out
the engine's Verdict. The engine/brain never changes; only the backend does:

  * SimulatedBackend  -> packets from a script, verdict just printed   (this kit)
  * PcapBackend       -> packets from a .pcap or live sniff            (next)
  * NfqueueBackend    -> packets from Linux netfilter, verdict ENFORCED (later)

Keeping this seam clean is what lets a beginner learn the logic safely now and
"switch to real traffic" later without rewriting anything.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from ..engine import Firewall
from ..packet import Packet
from ..rules import Action


class Backend(ABC):
    def __init__(self, firewall: Firewall):
        self.fw = firewall

    @abstractmethod
    def packets(self) -> Iterator[Packet]:
        """Yield packets from this backend's source."""
        raise NotImplementedError

    def enforce(self, pkt: Packet, action: Action) -> None:
        """Carry out the verdict. The simulated/pcap backends only observe, so
        the default is a no-op; NfqueueBackend will override this to really drop."""

    def run(self, on_verdict=None) -> Firewall:
        for pkt in self.packets():
            verdict = self.fw.evaluate(pkt)
            self.enforce(pkt, verdict.action)
            if on_verdict:
                on_verdict(pkt, verdict)
        return self.fw
