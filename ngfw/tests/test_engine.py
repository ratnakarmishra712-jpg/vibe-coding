"""
Tests for the stateful engine. Run with:  python -m pytest   (or)  python -m unittest
These lock in the core behaviours so future changes can't silently break them.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from ngfw.conntrack import ConnTracker
from ngfw.engine import Firewall
from ngfw.packet import Direction, Packet, Proto, TcpFlags
from ngfw.rules import Action, RuleSet

POLICY = """
allow out any any any any any
allow in  any any any any established
allow in  tcp any any 22  new
deny  in  any any any any any
"""


def fw():
    return Firewall(RuleSet.parse(POLICY), default=Action.DENY, conntrack=ConnTracker())


class TestStateful(unittest.TestCase):
    def test_outbound_new_allowed(self):
        v = fw().evaluate(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "8.8.8.8",
                                 50000, 443, TcpFlags(syn=True)))
        self.assertTrue(v.allowed)
        self.assertEqual(v.state, "new")

    def test_return_traffic_is_established_and_allowed(self):
        f = fw()
        f.evaluate(Packet(Direction.OUT, Proto.TCP, "10.0.0.5", "8.8.8.8", 50000, 443, TcpFlags(syn=True)))
        reply = f.evaluate(Packet(Direction.IN, Proto.TCP, "8.8.8.8", "10.0.0.5", 443, 50000,
                                  TcpFlags(syn=True, ack=True)))
        self.assertEqual(reply.state, "established")
        self.assertTrue(reply.allowed)

    def test_unsolicited_inbound_denied(self):
        v = fw().evaluate(Packet(Direction.IN, Proto.TCP, "203.0.113.9", "10.0.0.5",
                                 51001, 23, TcpFlags(syn=True)))
        self.assertFalse(v.allowed)

    def test_explicit_inbound_ssh_allowed(self):
        v = fw().evaluate(Packet(Direction.IN, Proto.TCP, "203.0.113.9", "10.0.0.5",
                                 51000, 22, TcpFlags(syn=True)))
        self.assertTrue(v.allowed)

    def test_out_of_state_ack_is_invalid(self):
        v = fw().evaluate(Packet(Direction.IN, Proto.TCP, "203.0.113.9", "10.0.0.5",
                                 51002, 50505, TcpFlags(ack=True)))
        self.assertEqual(v.state, "invalid")
        self.assertFalse(v.allowed)

    def test_default_deny(self):
        empty = Firewall(RuleSet.parse("allow out any any any any any"), default=Action.DENY)
        v = empty.evaluate(Packet(Direction.IN, Proto.UDP, "1.2.3.4", "10.0.0.5", 1234, 9999))
        self.assertFalse(v.allowed)
        self.assertEqual(v.rule_line, 0)  # decided by default policy


if __name__ == "__main__":
    unittest.main(verbosity=2)
