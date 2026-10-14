"""
Tests for connection-tracking expiry, using a FAKE clock.

conntrack forgets a flow after it has been idle longer than the per-protocol
timeout (UDP_IDLE = 60s). We don't want a test that actually sleeps 60 seconds —
so we exploit ConnTracker's injectable `clock`: we hand it a clock we control and
"fast-forward" time instantly. This is exactly why `__init__` takes
`clock=time.monotonic` instead of calling the real clock directly.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from ngfw.conntrack import UDP_IDLE, ConnTracker
from ngfw.engine import Firewall
from ngfw.packet import Direction, Packet, Proto
from ngfw.rules import Action, RuleSet

POLICY = """
allow out any any any any any
allow in  any any any any established
deny  in  any any any any any
"""


class FakeClock:
    """A clock we drive by hand. Calling it returns 'now'; advance() moves time."""
    def __init__(self, start=1000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def _fw(clock):
    ct = ConnTracker(clock=clock)
    return Firewall(RuleSet.parse(POLICY), default=Action.DENY, conntrack=ct), ct


# A DNS query we send out, and the reply coming back on the same flow.
QUERY = Packet(Direction.OUT, Proto.UDP, "10.0.0.5", "1.1.1.1", 40000, 53)
REPLY = Packet(Direction.IN, Proto.UDP, "1.1.1.1", "10.0.0.5", 53, 40000)


class TestExpiry(unittest.TestCase):
    def test_flow_expires_after_idle_timeout(self):
        clock = FakeClock()
        fw, ct = _fw(clock)

        # 1. Open the flow. It is 'new', allowed, and now tracked.
        v = fw.evaluate(QUERY)
        self.assertTrue(v.allowed)
        self.assertEqual(v.state, "new")
        self.assertEqual(len(ct), 1)

        # 2. A reply 30s later (< 60s timeout) is still 'established' -> allowed.
        clock.advance(30)
        v = fw.evaluate(REPLY)
        self.assertEqual(v.state, "established")
        self.assertTrue(v.allowed)

        # 3. Fast-forward past the UDP timeout (last activity was at +30s).
        clock.advance(UDP_IDLE + 1)
        v = fw.evaluate(REPLY)
        # The flow was forgotten, so the reply now looks brand new (unsolicited)
        # and is denied by the catch-all. conntrack is empty again.
        self.assertEqual(v.state, "new")
        self.assertFalse(v.allowed)
        self.assertEqual(len(ct), 0)

    def test_activity_refreshes_the_idle_timer(self):
        """Traffic on a flow resets its timer, so a busy flow never expires even
        though total elapsed time exceeds the timeout."""
        clock = FakeClock()
        fw, ct = _fw(clock)

        fw.evaluate(QUERY)                 # t+0   : tracked, last_seen = 0
        clock.advance(40)
        v = fw.evaluate(QUERY)             # t+40  : activity refreshes last_seen
        self.assertTrue(v.allowed)
        self.assertEqual(len(ct), 1)

        clock.advance(40)                  # t+80 total, but only 40s since last_seen
        v = fw.evaluate(REPLY)
        self.assertEqual(v.state, "established")  # still alive: 40s < 60s
        self.assertTrue(v.allowed)
        self.assertEqual(len(ct), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
