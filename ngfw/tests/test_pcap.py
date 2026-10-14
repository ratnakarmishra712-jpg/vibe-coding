"""
Tests for the pcap backend: the scapy -> portable Packet converter, and an
end-to-end run of a real capture through the engine.

Skipped automatically if scapy isn't installed, so the suite still runs on a
machine without it.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

try:
    from scapy.all import ARP, IP, TCP, UDP, wrpcap
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

from ngfw.engine import Firewall
from ngfw.packet import Direction, Proto
from ngfw.rules import Action, RuleSet

POLICY = """
allow out any any any any any
allow in  any any any any established
allow in  tcp any any 22  new
deny  in  any any any any any
"""
HOME = "10.0.0.5/32"   # raw; PcapBackend parses it


@unittest.skipUnless(HAVE_SCAPY, "scapy not installed")
class TestConverter(unittest.TestCase):
    def setUp(self):
        from ngfw.backends.pcap import _parse_home, from_scapy
        self.conv = from_scapy
        self.nets = _parse_home(HOME)   # converter expects parsed networks

    def test_outbound_tcp_syn(self):
        p = self.conv(IP(src="10.0.0.5", dst="1.1.1.1") / TCP(sport=5000, dport=443, flags="S"), self.nets)
        self.assertEqual(p.direction, Direction.OUT)   # src is home
        self.assertEqual(p.proto, Proto.TCP)
        self.assertTrue(p.flags.syn and not p.flags.ack)
        self.assertEqual(p.dst_port, 443)

    def test_inbound_synack(self):
        p = self.conv(IP(src="1.1.1.1", dst="10.0.0.5") / TCP(sport=443, dport=5000, flags="SA"), self.nets)
        self.assertEqual(p.direction, Direction.IN)     # src not home
        self.assertTrue(p.flags.syn and p.flags.ack)

    def test_udp_mapping(self):
        p = self.conv(IP(src="10.0.0.5", dst="1.1.1.1") / UDP(sport=40000, dport=53), self.nets)
        self.assertEqual(p.proto, Proto.UDP)
        self.assertEqual(p.dst_port, 53)

    def test_non_ip_skipped(self):
        self.assertIsNone(self.conv(ARP(), self.nets))


@unittest.skipUnless(HAVE_SCAPY, "scapy not installed")
class TestEndToEnd(unittest.TestCase):
    def test_same_verdicts_as_simulated(self):
        from ngfw.backends.pcap import PcapBackend

        pkts = [
            IP(src="10.0.0.5", dst="1.1.1.1") / UDP(sport=40000, dport=53),
            IP(src="1.1.1.1", dst="10.0.0.5") / UDP(sport=53, dport=40000),
            IP(src="10.0.0.5", dst="9.9.9.9") / TCP(sport=50001, dport=443, flags="S"),
            IP(src="9.9.9.9", dst="10.0.0.5") / TCP(sport=443, dport=50001, flags="SA"),
            IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=51000, dport=22, flags="S"),   # allowed (ssh)
            IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=51001, dport=23, flags="S"),   # denied (telnet)
            IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=51002, dport=5555, flags="A"), # invalid
        ]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.pcap")
            wrpcap(path, pkts)
            fw = Firewall(RuleSet.parse(POLICY), default=Action.DENY)
            PcapBackend(fw, path, home=HOME).run()

        self.assertEqual(fw.stats["seen"], 7)
        self.assertEqual(fw.stats["allow"], 5)   # 2 udp + 2 tcp handshake + ssh
        self.assertEqual(fw.stats["deny"], 2)    # telnet + invalid ack


if __name__ == "__main__":
    unittest.main(verbosity=2)
