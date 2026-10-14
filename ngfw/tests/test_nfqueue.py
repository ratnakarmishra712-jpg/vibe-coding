"""
Tests for the nfqueue backend's DECISION logic — no root, no live queue.

We can't bind a real netfilter queue in CI, but we don't need to: the backend
splits "decide what to do" from "tell the kernel". We feed raw IP bytes (exactly
what the kernel hands over) to decide()/_handle() and check the verdict, using a
fake queue-packet that records accept()/drop().

Skipped if scapy is missing. netfilterqueue is NOT required for these tests.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

try:
    from scapy.all import IP, TCP
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

from ngfw.engine import Firewall
from ngfw.rules import Action, RuleSet

POLICY = """
allow out any any any any any
allow in  any any any any established
allow in  tcp any any 22  new
deny  in  any any any any any
"""
HOME = "10.0.0.5/32"


class FakeNfPkt:
    """Stands in for a netfilterqueue packet: carries bytes, records the verdict."""
    def __init__(self, payload: bytes):
        self._payload = payload
        self.verdict = None

    def get_payload(self) -> bytes:
        return self._payload

    def accept(self):
        self.verdict = "accept"

    def drop(self):
        self.verdict = "drop"


def _raw(scapy_pkt) -> bytes:
    return bytes(scapy_pkt)


@unittest.skipUnless(HAVE_SCAPY, "scapy not installed")
class TestNfqueueDecision(unittest.TestCase):
    def _backend(self, enforce):
        from ngfw.backends.nfqueue import NfqueueBackend
        fw = Firewall(RuleSet.parse(POLICY), default=Action.DENY)
        return NfqueueBackend(fw, queue_num=0, home=HOME, enforce=enforce)

    def test_decide_denies_inbound_telnet(self):
        b = self._backend(enforce=True)
        raw = _raw(IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=5000, dport=23, flags="S"))
        pkt, verdict = b.decide(raw)
        self.assertFalse(verdict.allowed)
        self.assertEqual(pkt.dst_port, 23)

    def test_decide_allows_inbound_ssh(self):
        b = self._backend(enforce=True)
        raw = _raw(IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=5000, dport=22, flags="S"))
        _, verdict = b.decide(raw)
        self.assertTrue(verdict.allowed)

    def test_enforce_drops_denied_packet(self):
        b = self._backend(enforce=True)
        nfp = FakeNfPkt(_raw(IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=5000, dport=23, flags="S")))
        b._handle(nfp)
        self.assertEqual(nfp.verdict, "drop")

    def test_observe_mode_never_drops(self):
        """Same denied packet, but observe-only (enforce=False) -> accepted."""
        b = self._backend(enforce=False)
        nfp = FakeNfPkt(_raw(IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=5000, dport=23, flags="S")))
        b._handle(nfp)
        self.assertEqual(nfp.verdict, "accept")

    def test_enforce_accepts_allowed_packet(self):
        b = self._backend(enforce=True)
        nfp = FakeNfPkt(_raw(IP(src="10.0.0.5", dst="1.1.1.1") / TCP(sport=50000, dport=443, flags="S")))
        b._handle(nfp)
        self.assertEqual(nfp.verdict, "accept")


if __name__ == "__main__":
    unittest.main(verbosity=2)
