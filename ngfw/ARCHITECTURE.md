# ngfw — Architecture

A complete tour of how this firewall is built, stage by stage. It explains the
design, the code, the changes each stage introduced, and — honestly — what each
part does **not** do. Technical terms are defined in (parentheses) the first
time they appear.

> **Audience:** someone who has written Python but is new to networking/firewalls.
> If a term looks like jargon, its meaning is in the brackets right after it.

---

## 1. The one big idea: brain vs. plumbing

A firewall has to answer one question for every packet: **allow or drop?** That
decision logic is the *brain*. Separately, packets have to physically *arrive*
from somewhere, and a verdict has to be *carried out* somewhere — that's the
*plumbing* (the "data plane" — the part of a network device that actually moves
and acts on packets).

This project keeps those two things strictly apart:

```
        PLUMBING (swappable)                    BRAIN (never changes)
  ┌───────────────────────────┐        ┌────────────────────────────────┐
  │  Backend                   │        │  Firewall engine               │
  │   • simulated (scripted)   │        │   conntrack → L7 → rules → IDS  │
  │   • pcap (capture file)    │ ─────▶ │          → Verdict             │
  │   • nfqueue (live, Linux)  │  Packet└────────────────────────────────┘
  └───────────────────────────┘ (portable          │
                                  object)           ▼
                                            allow / drop / alert
```

Everything flows through one portable `Packet` object. A backend's only jobs are
(1) produce `Packet`s and (2) enact the verdict. Because of this seam, the
project added **five** different ways to get packets and one real enforcement
path **without ever rewriting the decision code**. That is the single most
important property of the design, and every stage below is an exercise in
preserving it.

---

## 2. Repository map

```
ngfw/
├── ngfw/
│   ├── packet.py        Portable packet model — the common language
│   ├── rules.py         Policy file + first-match matcher (L3/L4 + L7 host)
│   ├── conntrack.py     Connection tracking (state) + L7 flow memory
│   ├── l7.py            Layer-7 app identification (TLS SNI, HTTP, DNS)
│   ├── ids.py           IDS/IPS: signatures + anomaly detectors
│   ├── engine.py        The brain: ties the above into one decision loop
│   ├── __main__.py      CLI: wires a backend + policy + IDS together
│   └── backends/
│       ├── base.py      The Backend interface (the swappable seam)
│       ├── simulated.py Scripted packets (Stage 1, no deps)
│       ├── pcap.py      Real packets from a capture (Stage 2, scapy)
│       └── nfqueue.py   Live inline enforcement (Stage 3, Linux+root)
├── rules.example.conf        Example policy
├── signatures.example.rules  Example IDS signatures
├── make_sample_pcap.py       Builds sample.pcap for the pcap backend
├── nfqueue_setup.sh          Safe iptables setup/teardown for nfqueue
└── tests/                    44 unit tests (one file per concern)
```

Roughly 1,250 lines of library code. Each file has a single responsibility.

---

## 3. The data model: `Packet` (`packet.py`)

Every layer reasons about this object, never raw bytes or an OS-specific
structure. (L3 = "Layer 3", the network layer = IP addresses; L4 = "Layer 4",
the transport layer = TCP/UDP ports; L7 = "Layer 7", the application layer =
HTTP/TLS/DNS content.)

```python
@dataclass
class Packet:
    direction: Direction      # IN (arriving) or OUT (leaving)
    proto: Proto              # TCP / UDP / ICMP / OTHER
    src_ip: str; dst_ip: str
    src_port: int; dst_port: int
    flags: TcpFlags           # SYN/ACK/FIN/RST booleans (TCP control bits)
    length: int               # packet size, for stats
    payload: bytes            # L4 payload, for L7 inspection (added in Stage 4)
    meta: dict                # L7 findings, e.g. {'app':'tls','host':'x.com'}
```

- **TCP flags** (TcpFlags) are the control bits that drive a TCP connection:
  `SYN` (synchronise — "I want to start talking"), `ACK` (acknowledge — "got it"),
  `FIN` (finish — "I'm done"), `RST` (reset — "abort").
- `five_tuple()` returns `(proto, src_ip, src_port, dst_ip, dst_port)` — the
  classic identity of a (flow) (one conversation between two endpoints).

**Why a shared model matters:** the three backends build this same object from
wildly different sources (a Python script, a scapy packet, kernel bytes). The
brain never knows or cares which.

---

## 4. The decision pipeline (the brain, `engine.py`)

`Firewall.evaluate(pkt)` runs this pipeline for every packet and returns a
`Verdict` (the decision + why + any IDS alerts):

```
            ┌─────────────────────────────────────────────────────────┐
  Packet ──▶│ 1. conntrack.classify(pkt)                               │
            │      → state: new | established | invalid                │
            ├─────────────────────────────────────────────────────────┤
            │ 2. L7 identify(pkt)  →  pkt.meta{app,host}               │
            │      + inherit app/host remembered on the flow           │
            ├─────────────────────────────────────────────────────────┤
            │ 3. rules.first_match(pkt, state)                         │
            │      first matching rule wins; none → default policy     │
            │      → Verdict(ALLOW | DENY | REJECT)                    │
            ├─────────────────────────────────────────────────────────┤
            │ 4. ids.inspect(pkt)  (if enabled)                        │
            │      signatures + anomalies → alerts                     │
            │      IPS mode: a 'drop' alert overrides an ALLOW          │
            ├─────────────────────────────────────────────────────────┤
            │ 5. if ALLOW: conntrack.update(pkt)                       │
            │      remember the flow (+ its L7 identity)               │
            └─────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                        Verdict{action, reason, state, alerts}
```

Note the ordering is deliberate: state is known **before** rules (so rules can
match on it), L7 is identified **before** rules (so rules can match a hostname),
and the IDS runs **after** the policy verdict (so it can override an allow).
conntrack is updated **last and only on allow**, so denied traffic never leaves
state behind.

---

## 5. Stage 1 — Stateful L3/L4 core

**Goal:** a real stateful (connection-aware) packet filter: match on IP/port and
*remember connections*.

### Files added
`packet.py`, `rules.py`, `conntrack.py`, `engine.py`, `backends/base.py`,
`backends/simulated.py`, `rules.example.conf`, `tests/`.

### 5.1 Policy (`rules.py`)

A policy is a text file; each line is a rule. Rules are evaluated top-to-bottom
and the **first match wins** (the same model iptables/pf use). Format:

```
action  direction  proto  src   dst   dport  state  [host]
allow   out        any    any   any   any    any
allow   in         any    any   any   any    established
allow   in         tcp    any   any   22     new
deny    in         any    any   any   any    any
```

- **action**: `allow`, `deny` (drop silently), or `reject` (drop and notify sender).
- **state**: `new`, `established`, or `any` — this is what makes rules *stateful*.
- A rule compiles to a `Rule` dataclass; `Rule.matches(pkt, state)` checks each
  field in turn. CIDR (Classless Inter-Domain Routing — an IP range like
  `10.0.0.0/8`) matching is done with Python's `ipaddress` module.
- The `[host]` field is Stage 4; it defaults to `any` and is explained there.

If no rule matches, the engine applies its **default policy**, which is `deny`.
This is **default-deny** (the safe industry norm: anything not explicitly
permitted is blocked).

### 5.2 Connection tracking (`conntrack.py`) — the heart of "stateful"

A stateless filter judges each packet alone; to allow replies you'd have to
leave inbound ports permanently open. A **stateful** firewall remembers flows,
so the reply traffic of a connection *you* started is allowed automatically.

The trick is the **canonical key** (a direction-independent flow identifier):

```python
def _key(pkt):
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)   # sort the two endpoints
    return (pkt.proto, lo, hi)
```

By sorting the two endpoints, the outbound packet `A→B` and its reply `B→A`
produce the **same** key, so the reply finds the entry the request created.

`classify(pkt)` labels a packet before the rule check:

```
   known flow in table?  ──yes──▶ "established"
            │no
   TCP packet without SYN? ──yes──▶ "invalid"   (a bare ACK/FIN/RST from nowhere
            │no                                   — a scan/spoofing tell)
            └──────────────────▶ "new"
```

`update(pkt)` (called only when the engine ALLOWS a packet) advances a small TCP
state machine:

```
   SYN        → SYN_SENT
   SYN+ACK    → SYN_RECV
   ACK (mid-handshake) → ESTABLISHED
   FIN        → CLOSING
   RST        → entry deleted
   (UDP/ICMP have no handshake → ESTABLISHED on first sight)
```

Idle flows are evicted after a per-protocol timeout (TCP 600 s, UDP 60 s, ICMP
30 s) by `_expire()`, called at the top of `classify`. The clock is
**injectable** (`clock=time.monotonic` by default) so tests can fast-forward
time instead of sleeping.

### 5.3 The backend seam (`backends/base.py`)

```python
class Backend(ABC):
    def packets(self) -> Iterator[Packet]: ...   # produce packets
    def enforce(self, pkt, action): ...          # carry out the verdict (no-op by default)
    def run(self, on_verdict=None):
        for pkt in self.packets():
            verdict = self.fw.evaluate(pkt)
            self.enforce(pkt, verdict.action)
            if on_verdict: on_verdict(pkt, verdict)
```

`SimulatedBackend` just yields a scripted list of `Packet`s telling a story
(DNS lookup, a web handshake, an SSH attempt, a blocked Telnet, an out-of-state
ACK). No dependencies, no root (administrator privileges), totally safe.

### 5.4 Stage 1 flow

```
  scripted Packet ─▶ engine.evaluate ─▶ classify ─▶ first_match ─▶ Verdict ─▶ printed
                                            │                          │
                                     (updates conntrack on allow) ◀────┘
```

### 5.5 Limitations of Stage 1
- **Observe-only:** nothing is actually blocked — verdicts are just printed.
- **Fake packets:** the simulator's traffic is hand-written, not real.
- **Simplified TCP state machine:** it tracks states but doesn't *enforce*
  sequence/ACK-number correctness, so it can't detect sophisticated
  out-of-order or injection attacks. Only the SYN/no-SYN distinction is used by
  rules (`new`/`established`/`invalid`).
- **No reassembly:** each packet is judged alone; no notion of TCP streams yet.
- **`_expire` scans the whole table** every packet — fine for a demo, too slow
  for millions of flows (real conntrack uses timer structures).

---

## 6. Stage 2 — pcap backend (real packets)

**Goal:** feed the exact same engine with **real** packets from a capture file,
proving the brain is independent of the packet source.

### Files added/changed
Added `backends/pcap.py`, `make_sample_pcap.py`, `requirements.txt`,
`tests/test_pcap.py`. The engine, conntrack, and rules were **not touched.**

### 6.1 How it works

A pcap (packet capture — the `.pcap`/`.pcapng` file format produced by
`tcpdump`/Wireshark) is read with **scapy** (a Python packet library). Each
scapy packet is translated to our `Packet` by `from_scapy()`:

```
  scapy IP/TCP/UDP packet
        │  read src/dst, ports, TCP flags (bitmask), L4 payload bytes
        ▼
  our portable Packet ──▶ (same engine as Stage 1)
```

### 6.2 The new concept: direction

A capture file has **no built-in notion of inbound vs outbound** — it's just
packets seen on a wire. So the backend takes a `--home` address/CIDR: a packet
whose **source** is "home" is OUTbound; everything else is INbound. That mirrors
how a host firewall sees its own traffic.

```python
direction = Direction.OUT if _is_home(src, home_nets) else Direction.IN
```

### 6.3 Payoff
Running the sample capture produces **verdicts identical to the simulator** — same
brain, different plumbing. Point `--pcap` at any real capture to audit it offline.

### 6.4 Limitations of Stage 2
- **Still observe-only** — reading a file can't block anything live.
- **Direction is heuristic:** it depends on you naming `--home` correctly; a
  capture from a router/forwarding position (not an endpoint) doesn't fit the
  "src is me = outbound" assumption.
- **IPv4 only:** `from_scapy` skips IPv6 (`IPv6` has a different header; a later
  enhancement). (IP = Internet Protocol; IPv6 is its newer addressing scheme.)
- **No reassembly / decryption:** payloads are per-packet and, for TLS, encrypted
  (only the unencrypted handshake is readable — see Stage 4).
- **Requires scapy**, a sizeable dependency (Stage 1 had none).

---

## 7. Stage 3 — nfqueue backend (live inline enforcement)

**Goal:** stop observing and actually **allow/drop live packets** on Linux. This
is the first "real" firewall.

### Files added/changed
Added `backends/nfqueue.py`, `nfqueue_setup.sh`, `tests/test_nfqueue.py`;
`__main__.py` gained `--nfqueue`/`--enforce`. Engine untouched.

### 7.1 How it works

NFQUEUE (a Linux netfilter feature — netfilter is the kernel's packet-filtering
framework, the machinery behind `iptables`) lets a userspace (outside-the-kernel)
program decide the fate of packets. An iptables rule hands matching packets to a
numbered queue; our program reads each one, runs the engine, and returns a
verdict to the kernel.

```
   kernel netfilter ──(packet)──▶ NFQUEUE n ──▶ nfqueue backend
                                                     │ from_scapy(raw bytes)
                                                     ▼
                                                engine.evaluate
                                                     │
        kernel ◀── ACCEPT / DROP (verdict) ◀─────────┘
```

The code splits cleanly into **decision** and **kernel I/O** so the logic is
testable without root:

```python
def decide(self, payload: bytes):      # pure: bytes → (Packet, Verdict)
    sp = IP(payload); pkt = from_scapy(sp, self.home_nets)
    return (pkt, self.fw.evaluate(pkt)) if pkt else (None, None)

def _handle(self, nfpkt):              # kernel callback: apply the verdict
    pkt, verdict = self.decide(nfpkt.get_payload())
    if self.enforce and verdict and not verdict.allowed:
        nfpkt.drop()
    else:
        nfpkt.accept()
```

### 7.2 Safety (the important part)

A live packet filter can lock you out of a machine. Three rails:

1. **Observe-only by default.** Without `--enforce`, every packet is `accept()`ed;
   you only *see* the verdict it would apply. Validate policy before trusting it.
2. **Fail-open rule.** `nfqueue_setup.sh` adds the iptables rule with
   `--queue-bypass` (if no program is listening on the queue, packets pass
   normally), so a crash can't silently cut the network.
3. **Narrow scope by default.** The setup script queues only one test port;
   you widen it deliberately.

### 7.3 Interface note
NFQUEUE is **event-driven** (the kernel calls us), not pull-based, so
`NfqueueBackend` overrides `run()` instead of using the base `packets()`
generator. This is the one place a backend legitimately diverges from the base
loop shape.

### 7.4 Limitations of Stage 3
- **Linux + root + `libnetfilter_queue`** only; nothing to run on macOS/Windows,
  and it couldn't run in this project's CI sandbox (so only `decide()` is tested).
- **`reject` is treated as `drop`:** we don't yet send a TCP RST / ICMP
  unreachable back to the sender (a true "reject").
- **Per-packet userspace round-trip** is far slower than in-kernel filtering;
  real high-throughput firewalls push the fast path into the kernel (eBPF/XDP).
- **No fragment handling:** IP fragments (a packet split across several frames)
  aren't reassembled before inspection.

---

## 8. Stage 4 — Layer-7 application identification (the "next-gen" leap)

**Goal:** judge traffic by the **application/domain**, not just the port. A
classic firewall sees "443 = allow"; port 443 could be your bank or a tracker. An
NGFW (Next-Generation Firewall) looks *inside* the first packets to learn which.

### Files added/changed
Added `l7.py`, `tests/test_l7.py`. Changed `packet.py` (added `payload`),
`rules.py` (optional `host` field), `conntrack.py` (remember app/host per flow),
`engine.py` (identify + inherit before matching), both file backends (carry
payload), `rules.example.conf`, `make_sample_pcap.py`.

### 8.1 App identification (`l7.py`)

`identify(pkt)` returns `{'app': ..., 'host': ...}` by parsing the payload:

- **TLS SNI** (Transport Layer Security — the encryption behind HTTPS; SNI =
  Server Name Indication, the destination hostname sent **unencrypted** in the
  opening `ClientHello` message). This is the headline: even though the traffic
  is encrypted, the domain is readable.
- **HTTP Host** header (for plaintext HTTP).
- **DNS** (Domain Name System — turns names into IP addresses) query name.

Every parser is **defensive**: it parses untrusted bytes and returns `None` on
anything malformed rather than raising. `l7.py` also ships tiny *builders*
(`build_client_hello`, `build_http_get`, `build_dns_query`) so the simulator and
tests can produce realistic protocol bytes without a TLS stack.

### 8.2 Host-aware rules

The rule DSL (Domain-Specific Language — the mini rule syntax) gained an optional
8th field:

```
deny out tcp any any 443 any *.doubleclick.net
```

`_match_name()` supports exact names and `*.suffix` wildcards (where `*.x`
matches both `x` and `sub.x`). A rule that names a host but meets a flow with no
identified host does **not** match (so host-rules only bite identified traffic).

### 8.3 The flow-memory subtlety (reuses conntrack)

SNI appears **only in the first packet** (the ClientHello). For a host-rule to
apply to the *whole* flow, the identified host must be remembered. So
`conntrack` now stores `app`/`host` on the `Connection`, and the engine inherits
it onto later packets:

```
  packet 1 (ClientHello)  ─▶ identify() finds host ─▶ matched ─▶ (if allowed) stored on flow
  packet 2..n (no SNI)    ─▶ identify() finds nothing ─▶ inherit host from conntrack ─▶ matched
```

This is exactly how real NGFWs behave: identify on the first packets, apply the
verdict to the flow.

```
         ┌── identify(pkt) from payload ──┐
 Packet ─┤                                 ├─▶ pkt.meta{app,host} ─▶ rules (host-aware)
         └── else inherit from conntrack ──┘
```

### 8.4 The demonstration
The demo opens a connection to a tracker on port 443: the **SYN is allowed**
(nothing to identify yet), then its **ClientHello is dropped** by the SNI rule —
on the *same port 443* that `example.com` is allowed on. A port-only firewall
cannot do this.

### 8.5 Limitations of Stage 4
- **SNI only because it's unencrypted.** This does **not** decrypt TLS; it reads
  the cleartext handshake. **Encrypted SNI / ECH** (Encrypted Client Hello — a
  newer standard that hides the SNI) would defeat it, as would DoH/DoT
  (DNS-over-HTTPS/TLS — encrypted DNS).
- **First-packet assumption / no reassembly.** If a ClientHello is split across
  multiple TCP segments (TCP segmentation), our per-packet parser may miss the
  SNI. Real NGFWs reassemble the stream first.
- **Shallow DPI** (Deep Packet Inspection — examining payload content). We parse
  three protocols with hand-written, minimal parsers; no general protocol engine.
- **Spoofable:** a client can lie in its SNI/Host header; name-based control is a
  policy tool, not a security guarantee against a determined adversary.
- **Host stored only on ALLOW.** If the identifying packet is denied, the host
  isn't persisted (fine for our use, but worth knowing).

---

## 9. Stage 5 — IDS/IPS (signatures + anomaly detection)

**Goal:** detect *attacks*, even inside traffic policy would allow. IDS =
Intrusion Detection System (detect and alert); IPS = Intrusion Prevention
System (detect and block).

### Files added/changed
Added `ids.py`, `signatures.example.rules`, `tests/test_ids.py`. Changed
`engine.py` (run the IDS, let IPS override an allow; `Verdict` gained `alerts`),
`__main__.py` (flags + output), `simulated.py` (attack packets).

### 9.1 Two detection techniques

**Signatures** — match known-bad byte/string patterns in payloads
(Snort/Suricata-lite; Snort and Suricata are well-known open-source IDS engines).
A signature file:

```
alert tcp 80  content:"../../etc/passwd"  msg:"LFI probe" sid:1001
alert tcp any regex:"(?i)union\s+select"  msg:"SQLi"      sid:1002
drop  tcp any content:"\x90\x90\x90\x90\x90\x90\x90\x90" msg:"NOP sled" sid:2001
```

- `content:"..."` is a literal match (supporting `\xHH` byte escapes);
  `regex:"..."` is a pattern (regular expression).
- These examples are *detection patterns* — an LFI (Local File Inclusion — a web
  attack reading server files like `/etc/passwd`), SQLi (SQL Injection — smuggling
  database commands via input), XSS (Cross-Site Scripting — injecting
  `<script>`), and a NOP sled (a run of `\x90` "do-nothing" CPU instructions, a
  hallmark of memory-corruption exploits). They describe what to *spot*, not how
  to attack.

**Anomaly detectors** — behavioural, using state we already track:

- `PortScanDetector`: one source hitting many **distinct** destination ports
  within a time window (a scan — probing to find open services).
- `SynFloodDetector`: a burst of SYNs to one host (a SYN flood — a
  denial-of-service that exhausts half-open connection slots).

Both use windowed counters with the same **injectable clock** as conntrack, so
tests fast-forward time to trigger bursts instantly.

### 9.2 IDS vs IPS in the engine

```
  policy verdict (ALLOW/DENY) ─▶ ids.inspect(pkt) → alerts
                                        │
                   ┌────────────────────┴────────────────────┐
             IDS mode:                               IPS mode (--ips):
             attach alerts, verdict unchanged        a 'drop' alert on an ALLOW
             (detect + log)                          → DENY (rule_line = -1)
```

The headline demo: a NOP sled arrives on an **established, policy-allowed** web
flow. IDS mode → `ALLOW` + alert. IPS mode → `DENY`. That's prevention catching
malware hidden inside permitted traffic.

### 9.3 Limitations of Stage 5
- **No stream reassembly:** a signature split across two packets is missed
  (same per-packet limit as Stage 4). Real IDS engines reassemble first.
- **Can't see into encryption:** signatures match cleartext only; TLS payloads
  are opaque.
- **Naive matching cost:** every signature is tested against every packet
  linearly; production engines use multi-pattern automata (e.g. Aho-Corasick).
- **Fixed-threshold anomalies:** simple windows, easy to evade (slow scans) or
  false-positive (a busy legitimate client); no learned baselines.
- **Regex on attacker-controlled input** can be a denial-of-service vector
  (catastrophic backtracking) — our patterns are simple, but it's a real risk.
- **No alert de-duplication/correlation:** the scan detector re-alerts on each
  packet over threshold.

---

## 10. End-to-end example (what a single packet experiences)

A tracker's TLS ClientHello arriving on an allowed port, under `--ips`:

```
 raw bytes / scripted Packet
        ▼
 backend builds Packet{OUT, TCP, 10.0.0.5:50101→142.250.1.1:443, payload=ClientHello}
        ▼
 engine.evaluate:
   1 classify    → "established" (handshake already tracked)
   2 identify    → {'app':'tls','host':'ads.doubleclick.net'}  (+inherit)
   3 first_match → rule "deny out tcp any any 443 any *.doubleclick.net"  → DENY
   4 ids.inspect → (no signature/anomaly hit here)
   5 (not allowed → conntrack not updated)
        ▼
 Verdict{DENY, reason="rule#…", state="established", alerts=[]}
        ▼
 backend: nfqueue drops it / simulator prints it
```

---

## 11. Testing strategy

44 unit tests, one file per concern (`tests/test_*.py`). Principles:

- **The brain is tested without plumbing:** `decide()` (nfqueue) and
  `identify()` (L7) are pure functions, tested with crafted bytes — no root, no
  live queue, no network.
- **Time is injectable:** conntrack expiry and the anomaly detectors take a
  `clock` parameter, so tests fast-forward instead of sleeping.
- **Behaviour is proven, not assumed:** e.g. the flow-memory test flips a verdict
  (allowed → denied) to prove host inheritance actually happened, rather than
  just checking a field.
- **Optional deps degrade gracefully:** scapy-dependent tests `skipUnless`
  scapy is installed, so the core suite runs anywhere.

A bug this discipline caught: `Firewall(conntrack=...)` used `or` for
defaulting, and because `ConnTracker` defines `__len__`, an *empty* tracker is
falsy — so a passed-in tracker was silently discarded. The fix was `is None`. A
second: regex signatures were run through `unicode_escape` decoding, mangling
`\s`/`\d`; regex now passes through untouched.

---

## 12. Cross-cutting limitations & where this would go next

**Project-wide limitations** (beyond the per-stage lists):

- **No TCP stream reassembly** anywhere — the single biggest gap for serious L7
  inspection and signature evasion resistance.
- **IPv4 only.**
- **Single-threaded, per-packet Python** — fine for learning and offline
  analysis, not for line-rate (full-speed link) traffic.
- **Name/signature controls are evadable** — they raise the bar, they are not
  cryptographic guarantees.
- **No logging/alerting pipeline** (syslog/JSON), **no config hot-reload**, **no
  high-availability/failover.**

**Natural next steps** (each sits on the existing seam without a rewrite):
1. TCP stream reassembly as a layer before L7/IDS.
2. A true `reject` (emit RST/ICMP) in the enforcing backend.
3. IPv6 support in `from_scapy` and the packet model.
4. Multi-pattern signature matching (Aho-Corasick) for speed.
5. Structured logging + an alert feed.
6. A Go port of the hot path for throughput (the language trade-off discussed
   when the project started).

---

## 13. Why the architecture held

Five stages, five very different capabilities, and the core decision loop
(`conntrack → L7 → rules → IDS → verdict`) only ever grew — it was never
rewritten. New packet sources (pcap, nfqueue) plugged into the `Backend` seam;
new intelligence (L7, IDS) plugged into `evaluate()` as ordered steps. The
portable `Packet` and the brain/plumbing split are what made that possible, and
they are the lesson worth carrying to any protocol-processing system.
```
  Stage 1 ──▶ Stage 2 ──▶ Stage 3 ──▶ Stage 4 ──▶ Stage 5
  stateful    real pkts   live drop   app-ID      IDS/IPS
   core       (pcap)      (nfqueue)   (SNI)       (sig+anomaly)
     └───────── one unchanged engine throughout ──────────┘
```
