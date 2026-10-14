"""
Tests for Stage 4: Layer-7 app identification and host-based rules.
Pure Python — no scapy, no root needed.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from ngfw.engine import Firewall
from ngfw.l7 import (build_client_hello, build_dns_query, build_http_get,
                     identify, parse_dns_qname, parse_http_host, parse_tls_sni)
from ngfw.packet import Direction, Packet, Proto, TcpFlags
from ngfw.rules import Action, RuleSet, _match_name

DATA = TcpFlags(ack=True)

# Block a tracker by name; allow everything else outbound.
POLICY = """
deny  out tcp any any 443 any *.doubleclick.net
deny  out udp any any 53  any *.doubleclick.net
allow out any any any any any
allow in  any any any any established
deny  in  any any any any any
"""


class TestParsers(unittest.TestCase):
    def test_tls_sni_roundtrip(self):
        self.assertEqual(parse_tls_sni(build_client_hello("ads.doubleclick.net")), "ads.doubleclick.net")

    def test_http_host_roundtrip(self):
        self.assertEqual(parse_http_host(build_http_get("tracker.example.com")), "tracker.example.com")

    def test_dns_qname_roundtrip(self):
        self.assertEqual(parse_dns_qname(build_dns_query("news.example.org")), "news.example.org")

    def test_parsers_reject_garbage(self):
        self.assertIsNone(parse_tls_sni(b"\x16\x03\x01not-tls"))
        self.assertIsNone(parse_http_host(b"\x00\x01\x02random"))
        self.assertIsNone(parse_dns_qname(b"\x00"))

    def test_identify_dispatch(self):
        p = Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "1.1.1.1", 5000, 443, DATA,
                   payload=build_client_hello("example.com"))
        self.assertEqual(identify(p), {"app": "tls", "host": "example.com"})


class TestNameMatch(unittest.TestCase):
    def test_wildcard_matches_subdomain_and_apex(self):
        self.assertTrue(_match_name("*.doubleclick.net", "ads.doubleclick.net"))
        self.assertTrue(_match_name("*.doubleclick.net", "doubleclick.net"))

    def test_wildcard_rejects_lookalike(self):
        self.assertFalse(_match_name("*.doubleclick.net", "notdoubleclick.net"))
        self.assertFalse(_match_name("*.doubleclick.net", "doubleclick.net.evil.com"))

    def test_concrete_requires_known_host(self):
        self.assertFalse(_match_name("example.com", ""))      # unidentified flow
        self.assertTrue(_match_name("any", ""))               # 'any' always matches


class TestEngineAppAware(unittest.TestCase):
    def _fw(self):
        return Firewall(RuleSet.parse(POLICY), default=Action.DENY)

    def test_tracker_sni_blocked_on_443(self):
        v = self._fw().evaluate(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "142.250.1.1",
                                       50101, 443, DATA, payload=build_client_hello("ads.doubleclick.net")))
        self.assertFalse(v.allowed)

    def test_good_sni_allowed_on_443(self):
        v = self._fw().evaluate(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "93.184.216.34",
                                       50100, 443, DATA, payload=build_client_hello("example.com")))
        self.assertTrue(v.allowed)

    def test_host_remembered_for_whole_flow(self):
        """A later packet with NO payload still inherits the flow's SNI from
        conntrack. Proven by a policy where the host flips the verdict: only
        example.com is allowed on 443, everything else on 443 is denied."""
        policy = RuleSet.parse(
            "allow out tcp any any 443 any example.com\n"
            "deny  out tcp any any 443 any any\n"
        )
        fw = Firewall(policy, default=Action.DENY)

        # ClientHello identifies example.com -> matches the allow, host stored.
        ch = fw.evaluate(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "9.9.9.9", 50200, 443, DATA,
                                payload=build_client_hello("example.com")))
        self.assertTrue(ch.allowed)

        # A bare ACK on the SAME flow has no payload, yet inherits example.com
        # from conntrack -> still matches the host-specific allow.
        same_pkt = Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "9.9.9.9", 50200, 443, DATA)
        same = fw.evaluate(same_pkt)          # evaluate fills same_pkt.meta in place
        self.assertEqual(same_pkt.meta.get("host"), "example.com")
        self.assertTrue(same.allowed)

        # Control: a packet on a DIFFERENT flow with no host matches neither the
        # host-specific allow nor anything else -> denied. (Inheritance is what
        # saved the first flow, not luck.)
        other = fw.evaluate(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "8.8.8.8", 50300, 443, DATA))
        self.assertFalse(other.allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
