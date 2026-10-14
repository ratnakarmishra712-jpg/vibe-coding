"""
ids.py — Stage 5: intrusion detection / prevention.

The firewall (Stages 1-4) decides allow/deny from policy. The IDS/IPS asks a
different question: does this traffic look like an *attack*, even if policy would
allow it? Two classic, complementary techniques:

  * SIGNATURES  — match known-bad byte/string patterns in payloads
                  (Snort/Suricata-style content rules). Good for known threats.
  * ANOMALIES   — spot abnormal *behaviour* from state we already track:
                  port scans (one source probing many ports) and SYN floods
                  (a burst of half-open connections). Good for novel threats.

IDS vs IPS:
  * IDS mode  = detect and ALERT (never changes the verdict).
  * IPS mode  = detect and ACT: an alert whose action is 'drop' forces the
                engine to DENY the packet, even if policy allowed it.

Signatures load from a .rules file; see signatures.example.rules. Anomaly
detectors use an injectable clock (like conntrack) so they're testable.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .packet import Direction, Packet, Proto


@dataclass
class Alert:
    sid: int
    msg: str
    action: str          # 'alert' | 'drop'
    kind: str            # 'signature' | 'anomaly'

    def __str__(self) -> str:
        return f"[{self.kind}:{self.sid} {self.action}] {self.msg}"


# --------------------------------------------------------------------------- #
#  Signatures
# --------------------------------------------------------------------------- #
def _decode_content(s: str) -> bytes:
    r"""Turn a rule's content string into bytes, interpreting \xHH escapes."""
    try:
        return s.encode("latin1", "ignore").decode("unicode_escape").encode("latin1", "ignore")
    except UnicodeError:
        return s.encode("latin1", "ignore")


@dataclass
class Signature:
    sid: int
    msg: str
    action: str                 # 'alert' | 'drop'
    proto: str = "any"
    dport: str = "any"
    content: bytes = b""        # literal match (empty if using regex)
    regex: "re.Pattern | None" = None
    nocase: bool = False

    def matches(self, pkt: Packet) -> bool:
        if self.proto != "any" and pkt.proto.value != self.proto:
            return False
        if self.dport != "any" and str(pkt.dst_port) != self.dport:
            return False
        data = pkt.payload
        if not data:
            return False
        if self.regex is not None:
            return self.regex.search(data) is not None
        hay = data.lower() if self.nocase else data
        needle = self.content.lower() if self.nocase else self.content
        return bool(needle) and needle in hay


_SIG_RE = {
    "content": re.compile(r'content:"(.*?)"'),
    "regex": re.compile(r'regex:"(.*?)"'),
    "msg": re.compile(r'msg:"(.*?)"'),
    "sid": re.compile(r"sid:(\d+)"),
}


def parse_signature(line: str) -> Signature | None:
    """Parse one rule line:
        <action> <proto> <dport> content:"..."|regex:"..." msg:"..." sid:N [nocase]
    Returns None for blank/comment lines."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    head = line.split(None, 3)
    if len(head) < 4:
        raise ValueError(f"signature needs at least: action proto dport match — got {line!r}")
    action, proto, dport, rest = head
    if action not in ("alert", "drop"):
        raise ValueError(f"signature action must be alert|drop, got {action!r}")

    nocase = bool(re.search(r"\bnocase\b", rest))
    content, regex = b"", None
    m = _SIG_RE["content"].search(rest)
    if m:
        content = _decode_content(m.group(1))
    else:
        m = _SIG_RE["regex"].search(rest)
        if m:
            flags = re.IGNORECASE if nocase else 0
            # Regex has its OWN escape semantics (\s, \d, ...); pass it through
            # as bytes without unicode-escape decoding (which would mangle them).
            regex = re.compile(m.group(1).encode("latin1", "ignore"), flags)
        else:
            raise ValueError(f"signature needs content:\"..\" or regex:\"..\" — got {line!r}")
    msg_m = _SIG_RE["msg"].search(rest)
    sid_m = _SIG_RE["sid"].search(rest)
    return Signature(
        sid=int(sid_m.group(1)) if sid_m else 0,
        msg=msg_m.group(1) if msg_m else "(no msg)",
        action=action, proto=proto.lower(), dport=dport.lower(),
        content=content, regex=regex, nocase=nocase,
    )


def load_signatures(path: str) -> list[Signature]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            try:
                sig = parse_signature(line)
            except ValueError as e:
                raise ValueError(f"{path}:{i}: {e}") from None
            if sig:
                out.append(sig)
    return out


# --------------------------------------------------------------------------- #
#  Anomaly detectors (behavioural, windowed, clock-injectable)
# --------------------------------------------------------------------------- #
def _is_inbound_syn(pkt: Packet) -> bool:
    return (pkt.direction == Direction.IN and pkt.proto == Proto.TCP
            and pkt.flags.syn and not pkt.flags.ack)


class PortScanDetector:
    """One source hitting many DISTINCT destination ports within a window."""
    def __init__(self, window=10.0, threshold=5, clock=time.monotonic):
        self.window, self.threshold, self.clock = window, threshold, clock
        self._hits: dict = defaultdict(deque)   # src_ip -> deque[(t, dport)]

    def update(self, pkt: Packet) -> Alert | None:
        if not _is_inbound_syn(pkt):
            return None
        now = self.clock()
        dq = self._hits[pkt.src_ip]
        dq.append((now, pkt.dst_port))
        while dq and now - dq[0][0] > self.window:
            dq.popleft()
        distinct = len({p for _, p in dq})
        if distinct >= self.threshold:
            return Alert(9001, f"port scan from {pkt.src_ip} "
                               f"({distinct} ports/{self.window:.0f}s)", "drop", "anomaly")
        return None


class SynFloodDetector:
    """A burst of SYNs to one destination within a window (half-open flood)."""
    def __init__(self, window=5.0, threshold=10, clock=time.monotonic):
        self.window, self.threshold, self.clock = window, threshold, clock
        self._hits: dict = defaultdict(deque)   # dst_ip -> deque[t]

    def update(self, pkt: Packet) -> Alert | None:
        if not _is_inbound_syn(pkt):
            return None
        now = self.clock()
        dq = self._hits[pkt.dst_ip]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold:
            return Alert(9002, f"possible SYN flood to {pkt.dst_ip} "
                               f"({len(dq)} SYN/{self.window:.0f}s)", "drop", "anomaly")
        return None


# --------------------------------------------------------------------------- #
#  The IDS: run every signature + anomaly detector over a packet
# --------------------------------------------------------------------------- #
class IDS:
    def __init__(self, signatures=None, anomaly=True, clock=time.monotonic):
        self.signatures = list(signatures or [])
        self.detectors = []
        if anomaly:
            self.detectors = [PortScanDetector(clock=clock), SynFloodDetector(clock=clock)]

    def inspect(self, pkt: Packet) -> list[Alert]:
        alerts = [Alert(s.sid, s.msg, s.action, "signature")
                  for s in self.signatures if s.matches(pkt)]
        for d in self.detectors:
            a = d.update(pkt)
            if a:
                alerts.append(a)
        return alerts
