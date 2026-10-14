"""
nfqueue.py — Stage 3: INLINE ENFORCEMENT on Linux via netfilter's NFQUEUE.

This is the first backend that actually *acts*: instead of only observing, it
returns a verdict to the kernel so a packet is really ACCEPTed or DROPped.

How it fits together
--------------------
  1. You add an iptables/nftables rule that sends packets to a queue, e.g.
         iptables -I INPUT -j NFQUEUE --queue-num 0 --queue-bypass
     ('--queue-bypass' = fail OPEN: if no program is listening, packets pass —
      so a crash can't silently cut your network.)
  2. The kernel hands each queued packet to this backend over a netlink socket.
  3. We parse it (scapy), run the SAME engine, and call accept()/drop().

Requirements: Linux, root, the `netfilterqueue` Python package (which needs
libnetfilter_queue). None of that is needed to UNIT-TEST the decision logic:
`decide()` and `_handle()` work with a plain payload, so the engine behaviour is
verified without root or a live queue. See nfqueue_setup.sh and the README.

SAFETY: the backend is OBSERVE-ONLY by default (enforce=False) — it logs the
verdict it *would* apply but accepts every packet. Pass enforce=True (CLI:
--enforce) only when you're ready to actually drop traffic, and never test it on
the same SSH session you'd be dropping.
"""
from __future__ import annotations

from collections.abc import Iterator

from ..packet import Packet
from .base import Backend
from .pcap import _parse_home, from_scapy

try:
    from scapy.all import IP
    _SCAPY_OK = True
except Exception as _e:  # pragma: no cover
    _SCAPY_OK = False
    _SCAPY_ERR = _e

try:
    from netfilterqueue import NetfilterQueue
    _NFQ_OK = True
except Exception as _e:  # pragma: no cover - absent unless libnetfilter_queue is installed
    _NFQ_OK = False
    _NFQ_ERR = _e


class NfqueueBackend(Backend):
    def __init__(self, firewall, queue_num: int = 0, home="10.0.0.5/32",
                 enforce: bool = False):
        super().__init__(firewall)
        if not _SCAPY_OK:
            raise RuntimeError(f"nfqueue backend needs scapy: pip install scapy ({_SCAPY_ERR})")
        self.queue_num = queue_num
        self.home_nets = _parse_home(home)
        self.enforce = enforce
        self.on_verdict = None

    # ---- pure decision logic (no root / no queue needed; fully testable) ----
    def decide(self, payload: bytes):
        """Parse raw IP bytes from the kernel and run the engine.
        Returns (Packet, Verdict), or (None, None) for traffic we don't parse."""
        sp = IP(payload)
        pkt = from_scapy(sp, self.home_nets)
        if pkt is None:
            return None, None
        return pkt, self.fw.evaluate(pkt)

    def _handle(self, nfpkt) -> None:
        """NetfilterQueue callback: decide, then ACCEPT or DROP the real packet."""
        pkt, verdict = self.decide(nfpkt.get_payload())

        if verdict is None:
            nfpkt.accept()                      # don't break traffic we can't parse
            return

        # Enforce only when asked; otherwise observe (accept) but still report.
        if self.enforce and not verdict.allowed:
            nfpkt.drop()
        else:
            nfpkt.accept()

        if self.on_verdict:
            self.on_verdict(pkt, verdict)

    # ---- live run (needs root + netfilterqueue) -----------------------------
    def packets(self) -> Iterator[Packet]:  # pragma: no cover - not used
        raise NotImplementedError("nfqueue is event-driven; call run(), not packets()")

    def run(self, on_verdict=None):
        if not _NFQ_OK:
            raise RuntimeError(
                "the nfqueue backend needs the 'netfilterqueue' package (Linux + root + "
                f"libnetfilter_queue): {_NFQ_ERR}"
            )
        self.on_verdict = on_verdict
        nfq = NetfilterQueue()
        nfq.bind(self.queue_num, self._handle)
        try:
            nfq.run()                           # blocks, delivering packets to _handle
        except KeyboardInterrupt:
            pass
        finally:
            nfq.unbind()
        return self.fw
