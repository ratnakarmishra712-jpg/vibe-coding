"""
Tests for Stage 5: IDS/IPS — signatures, anomaly detectors, and IPS override.
Pure Python; anomaly detectors use a fake clock so bursts are instant.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from ngfw.engine import Firewall
from ngfw.ids import (IDS, PortScanDetector, SynFloodDetector, Signature,
                      load_signatures, parse_signature)
from ngfw.packet import Direction, Packet, Proto, TcpFlags
from ngfw.rules import Action, RuleSet

SYN = TcpFlags(syn=True)
DATA = TcpFlags(ack=True)


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def _in_syn(src, dport, dst="10.0.0.5"):
    return Packet(Direction.IN, Proto.TCP, src, dst, 40000, dport, SYN, 60)


class TestSignatureParsing(unittest.TestCase):
    def test_parse_content_and_action(self):
        s = parse_signature('drop tcp 80 content:"../../etc/passwd" msg:"LFI" sid:1')
        self.assertEqual((s.action, s.proto, s.dport, s.sid), ("drop", "tcp", "80", 1))
        self.assertEqual(s.content, b"../../etc/passwd")

    def test_parse_hex_escape(self):
        s = parse_signature('drop tcp any content:"\\x90\\x90" msg:"nop" sid:2')
        self.assertEqual(s.content, b"\x90\x90")

    def test_parse_regex_nocase(self):
        s = parse_signature('alert tcp any regex:"union\\s+select" msg:"sqli" sid:3 nocase')
        self.assertIsNotNone(s.regex)
        self.assertTrue(s.nocase)

    def test_comment_and_blank_return_none(self):
        self.assertIsNone(parse_signature("# a comment"))
        self.assertIsNone(parse_signature("   "))

    def test_bad_line_raises(self):
        with self.assertRaises(ValueError):
            parse_signature("alert tcp 80 nomatchfield msg:x sid:1")

    def test_load_example_file(self):
        path = os.path.join(os.path.dirname(__file__), os.pardir, "signatures.example.rules")
        sigs = load_signatures(path)
        self.assertGreater(len(sigs), 0)


class TestSignatureMatch(unittest.TestCase):
    def test_content_match_respects_proto_and_port(self):
        s = Signature(1, "LFI", "alert", proto="tcp", dport="80", content=b"../../etc/passwd")
        hit = Packet(Direction.IN, Proto.TCP, "1.2.3.4", "10.0.0.5", 5000, 80, DATA,
                     payload=b"GET /../../etc/passwd HTTP/1.1")
        miss_port = Packet(Direction.IN, Proto.TCP, "1.2.3.4", "10.0.0.5", 5000, 81, DATA,
                           payload=b"GET /../../etc/passwd HTTP/1.1")
        self.assertTrue(s.matches(hit))
        self.assertFalse(s.matches(miss_port))

    def test_nocase(self):
        s = Signature(1, "m", "alert", content=b"malware", nocase=True)
        p = Packet(Direction.IN, Proto.TCP, "1.2.3.4", "10.0.0.5", 1, 1, DATA, payload=b"MALWARE here")
        self.assertTrue(s.matches(p))

    def test_empty_payload_never_matches(self):
        s = Signature(1, "m", "alert", content=b"x")
        self.assertFalse(s.matches(Packet(Direction.IN, Proto.TCP, "a", "b", 1, 1, DATA)))


class TestAnomalyDetectors(unittest.TestCase):
    def test_port_scan_fires_on_distinct_ports(self):
        clock = FakeClock()
        d = PortScanDetector(window=10, threshold=5, clock=clock)
        results = [d.update(_in_syn("9.9.9.9", p)) for p in (10, 20, 30, 40, 50)]
        self.assertIsNone(results[3])            # only 4 distinct ports so far
        self.assertIsNotNone(results[4])         # 5th distinct port -> alert
        self.assertEqual(results[4].action, "drop")

    def test_port_scan_window_expiry(self):
        clock = FakeClock()
        d = PortScanDetector(window=10, threshold=3, clock=clock)
        d.update(_in_syn("9.9.9.9", 10))
        d.update(_in_syn("9.9.9.9", 20))
        clock.advance(11)                        # first two age out of the window
        self.assertIsNone(d.update(_in_syn("9.9.9.9", 30)))  # only 1 in-window now

    def test_syn_flood_fires_on_volume(self):
        clock = FakeClock()
        d = SynFloodDetector(window=5, threshold=4, clock=clock)
        out = [d.update(_in_syn("9.9.9.9", 80)) for _ in range(4)]
        self.assertIsNone(out[2])
        self.assertIsNotNone(out[3])

    def test_detectors_ignore_outbound_and_non_syn(self):
        d = PortScanDetector(threshold=1)
        self.assertIsNone(d.update(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "x", 1, 2, SYN)))
        self.assertIsNone(d.update(Packet(Direction.IN, Proto.TCP, "x", "10.0.0.5", 1, 2, DATA)))


class TestEngineIPS(unittest.TestCase):
    POLICY = "allow in any any any any established\nallow out any any any any any\ndeny in any any any any any\n"
    NOP = Signature(2001, "NOP sled", "drop", content=b"\x90" * 8)

    def _fw(self, ips):
        # pre-establish a flow so the NOP packet is 'established' (policy-allowed)
        fw = Firewall(RuleSet.parse(self.POLICY), default=Action.DENY,
                      ids=IDS([self.NOP], anomaly=False), ips=ips)
        fw.evaluate(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "9.9.9.9", 50001, 443, SYN))
        return fw

    def _nop_pkt(self):
        return Packet(Direction.IN, Proto.TCP, "9.9.9.9", "10.0.0.5", 443, 50001, DATA,
                      payload=b"\x90" * 8 + b"payload")

    def test_ids_mode_alerts_but_allows(self):
        v = self._fw(ips=False).evaluate(self._nop_pkt())
        self.assertTrue(v.allowed)               # policy allows established...
        self.assertEqual(len(v.alerts), 1)       # ...but the IDS flagged it

    def test_ips_mode_drops(self):
        v = self._fw(ips=True).evaluate(self._nop_pkt())
        self.assertFalse(v.allowed)              # IPS overrode the allow
        self.assertEqual(v.rule_line, -1)        # -1 marks an IPS decision


if __name__ == "__main__":
    unittest.main(verbosity=2)
