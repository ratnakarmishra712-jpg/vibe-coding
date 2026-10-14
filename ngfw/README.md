# ngfw — a from-scratch stateful firewall (built for learning)

A tiny, readable firewall you can **run, read, and modify today**, designed to
grow — layer by layer — toward a Next-Generation Firewall (NGFW). It's built so a
beginner can learn the real concepts safely, with no root and no risk to your
network.

```
                 ┌─────────────────────────────────────────┐
  packets  ─────▶│  BACKEND (plumbing)                       │
  from...        │   simulated │ pcap │ nfqueue (later)       │
                 └───────────────┬──────────────────────────┘
                                 │  Packet (portable)
                                 ▼
                 ┌─────────────────────────────────────────┐
                 │  ENGINE (the brain) — same for every      │
                 │  backend:  conntrack → rules → verdict     │
                 └─────────────────────────────────────────┘
```

The big idea: **the brain never changes, only the plumbing does.** Learn the
logic in the safe simulator now; switch to real traffic later without a rewrite.

## Run it

```bash
cd ngfw
python3 -m ngfw --demo                 # built-in scenario (no deps, no root)
python3 -m ngfw --rules rules.example.conf
python3 -m unittest discover -s tests  # the test suite

# Stage 2: feed REAL captured packets through the same engine (needs scapy)
pip install -r requirements.txt
python3 make_sample_pcap.py            # writes sample.pcap
python3 -m ngfw --pcap sample.pcap --home 10.0.0.5/32
```

`--home` tells the pcap backend which address(es) are *yours*: packets from
there are outbound, everything else inbound (a capture file has no built-in
direction). Point `--pcap` at any `.pcap`/`.pcapng` you captured with
`tcpdump`/Wireshark to audit real traffic against your policy.

### Stage 3 — live enforcement (Linux, root)

This actually drops/allows real packets. **Do this on a throwaway VM, not a box
you'd hate to lock yourself out of.**

```bash
pip install netfilterqueue              # needs libnetfilter_queue (apt: libnetfilter-queue-dev)
sudo ./nfqueue_setup.sh up 0            # feed a NARROW slice (tcp :9999) to queue 0, fail-open
sudo python3 -m ngfw --nfqueue 0 --home <your-ip>/32           # OBSERVE only — drops nothing
sudo python3 -m ngfw --nfqueue 0 --home <your-ip>/32 --enforce # now it really DROPS denied packets
sudo ./nfqueue_setup.sh down 0          # ALWAYS tear the rule down when finished
```

Safety rails baked in:
- **Observe-only by default.** Without `--enforce`, every packet is accepted; you
  only *see* the verdict it would apply. Trust your policy before enforcing.
- **Fail-open rule.** `nfqueue_setup.sh` uses `--queue-bypass`, so if ngfw isn't
  running, traffic passes — a crash can't silently cut your network.
- **Narrow scope.** The setup script queues only one test port by default; widen
  it on purpose by editing `TEST_MATCH`.
- Never enforce on the port carrying your SSH session.

Each line of output shows: the **verdict**, the **connection state** conntrack
assigned (`new` / `established` / `invalid`), the packet, and **which rule
decided it** — so you can watch the firewall think.

## What's here (and what each file teaches)

| File | Concept |
|------|---------|
| `ngfw/packet.py` | A portable packet model — the common language every backend speaks. |
| `ngfw/rules.py` | A human-readable policy file + matcher. First-match-wins, like real firewalls. |
| `ngfw/conntrack.py` | **Connection tracking** — the difference between a dumb ACL and a *stateful* firewall. |
| `ngfw/engine.py` | The decision loop: conntrack → rules → verdict, with **default-deny**. |
| `ngfw/l7.py` | **Stage 4:** app-ID — parses TLS SNI / HTTP Host / DNS names from payloads (defensively), plus builders for realistic test bytes. |
| `ngfw/backends/base.py` | The backend interface (the swappable plumbing). |
| `ngfw/backends/simulated.py` | A scripted, safe data plane to experiment in. |
| `ngfw/backends/pcap.py` | **Stage 2:** reads real packets from a capture via scapy and converts them to our `Packet`. |
| `ngfw/backends/nfqueue.py` | **Stage 3:** inline enforcement on Linux — returns ACCEPT/DROP to the kernel via NFQUEUE. Observe-only unless `--enforce`. |
| `nfqueue_setup.sh` | Safely adds/removes the iptables rule (fail-open, narrow scope) for the nfqueue backend. |
| `make_sample_pcap.py` | Generates `sample.pcap` so the pcap backend runs out of the box. |
| `rules.example.conf` | A commented starter policy. Edit it and re-run. |
| `tests/` | Behaviour locked in so you can refactor fearlessly. |

## The one concept to take away first: **state**

A stateless filter judges each packet alone. A **stateful** firewall remembers
flows, so the reply traffic of a connection *you* started is allowed
automatically — without leaving a permanent inbound hole for strangers. In the
demo, watch the DNS reply and the TCP handshake replies come back in as
`established` even though the only inbound "new" rule is for SSH.

## Try this (learning exercises)

1. In `rules.example.conf`, delete the `established` rule (#2) and re-run — watch
   all your return traffic break. That's *why* conntrack exists.
2. Change the SSH rule port from `22` to `443` and see inbound rules shift.
3. Add a rule to allow inbound ICMP (ping) and craft a packet for it.
4. Flip the default policy to `allow` in `__main__.py` and see why default-deny
   is the safe industry norm.
5. **App-aware (Stage 4):** add `deny out tcp any any 443 any *.example.com` above
   the allow-out rule, then watch the demo block the `example.com` TLS flow by its
   SNI while leaving other 443 traffic alone. Change the port to see that app-ID,
   not the port, is doing the work.

## Roadmap — how this grows into a NGFW

Each stage adds a layer *on top of* the same engine. We'll do them one at a time.

- [x] **Stage 1 — Stateful L3/L4 core** (this): 5-tuple rules, conntrack (TCP
      state machine + UDP/ICMP), default-deny, logging, tests.
- [x] **Stage 2 — Real packets (pcap backend):** read a `.pcap` with `scapy`,
      convert to our `Packet`, feed the *same* engine. Real data, still
      observe-only. (Live sniff is a small add-on; it needs root.)
- [x] **Stage 3 — Inline enforcement (NFQUEUE backend):** on Linux, actually
      drop/allow live packets via netfilter. Observe-only by default; `--enforce`
      to really drop. First "real" firewall.
- [x] **Stage 4 — Layer 7 app-ID:** parse TLS SNI, HTTP Host, and DNS names from
      payloads; remember the host on the flow (conntrack); match rules on an
      optional 8th `host` field (exact or `*.suffix`). Block `*.doubleclick.net`
      on port 443 while allowing other 443 traffic.
- [ ] **Stage 5 — IDS/IPS:** signature engine (Suricata-style rules) + simple
      anomaly checks (port-scan, SYN-flood detection).
- [ ] **Stage 6 — NGFW extras:** TLS/SNI policy, GeoIP, logging to JSON/syslog,
      a config/reload story, and a Go port of the hot path for throughput.

## Scope & ethics

A firewall is a defensive tool. This project is for learning and for protecting
systems you own or are authorized to defend.
