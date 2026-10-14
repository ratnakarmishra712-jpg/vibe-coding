"""
engine.py — the firewall "brain". Backend-agnostic.

For every packet, in order:
  1. Ask conntrack whether this belongs to a known flow (new vs established).
  2. Find the first matching rule given that state.
  3. No rule matched  -> apply the DEFAULT policy (deny — "default-deny" is the
     safe industry default: anything not explicitly allowed is blocked).
  4. Run the IDS (if configured): signatures + anomaly detectors. In IPS mode a
     'drop' alert overrides an allow.
  5. If the verdict is ALLOW, update conntrack so the flow's return traffic and
     later packets are recognised as 'established'.

The engine returns a Verdict (what to do + why, plus any IDS alerts). Backends
turn that into a real action (drop the packet, print a line, etc.).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .conntrack import ConnTracker
from .ids import IDS
from .l7 import identify
from .packet import Packet
from .rules import Action, RuleSet


@dataclass
class Verdict:
    action: Action
    reason: str
    state: str            # 'new' | 'established'
    rule_line: int = 0    # which rule decided it (0 = default policy, -1 = IPS)
    alerts: list = field(default_factory=list)   # IDS/IPS findings for this packet

    @property
    def allowed(self) -> bool:
        return self.action == Action.ALLOW


class Firewall:
    def __init__(self, ruleset: RuleSet, default: Action = Action.DENY,
                 conntrack: ConnTracker | None = None,
                 ids: IDS | None = None, ips: bool = False):
        self.rules = ruleset
        self.default = default
        # Use `is None`, not `or`: ConnTracker defines __len__, so an *empty*
        # tracker is falsy and `conntrack or ConnTracker()` would discard it.
        self.ct = conntrack if conntrack is not None else ConnTracker()
        self.ids = ids          # optional intrusion detection
        self.ips = ips          # if True, a 'drop' alert overrides an allow
        self.stats = {"allow": 0, "deny": 0, "reject": 0, "seen": 0, "alerts": 0, "ips_drops": 0}

    def evaluate(self, pkt: Packet) -> Verdict:
        self.stats["seen"] += 1
        state = self.ct.classify(pkt)

        # Layer 7: identify this packet's app/host from its payload, then inherit
        # whatever was already identified for the flow (SNI rides only the first
        # packet, so later packets of the flow get it from conntrack memory).
        pkt.meta.update(identify(pkt))
        app, host = self.ct.flow_app_host(pkt)
        if app and "app" not in pkt.meta:
            pkt.meta["app"] = app
        if host and "host" not in pkt.meta:
            pkt.meta["host"] = host

        rule = self.rules.first_match(pkt, state)
        if rule is None:
            verdict = Verdict(self.default, "no rule matched -> default policy", state, 0)
        else:
            verdict = Verdict(rule.action, f"rule#{rule.lineno}: {rule.raw}", state, rule.lineno)

        # Stage 5: intrusion detection runs regardless of the policy verdict.
        if self.ids is not None:
            alerts = self.ids.inspect(pkt)
            if alerts:
                verdict.alerts = alerts
                self.stats["alerts"] += len(alerts)
                # IPS: a 'drop' alert turns an allowed packet into a deny.
                if self.ips and verdict.allowed and any(a.action == "drop" for a in alerts):
                    trigger = next(a for a in alerts if a.action == "drop")
                    verdict = Verdict(Action.DENY, f"IPS {trigger}", state, -1, alerts)
                    self.stats["ips_drops"] += 1

        if verdict.allowed:
            self.ct.update(pkt)

        self.stats[verdict.action.value] += 1
        return verdict
