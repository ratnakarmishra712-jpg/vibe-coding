#!/usr/bin/env python3
"""
Generate sample.pcap — a REAL capture file telling the same story as the
simulated demo, so you can exercise the pcap backend out of the box.

    python3 make_sample_pcap.py          # writes sample.pcap next to this file
    python3 -m ngfw --pcap sample.pcap --home 10.0.0.5/32

Requires scapy (pip install scapy).
"""
import os

from scapy.all import IP, TCP, UDP, wrpcap

ME = "10.0.0.5"
DNS = "1.1.1.1"
WEB = "93.184.216.34"
ATTACKER = "203.0.113.9"


def build():
    return [
        # DNS query out, reply back
        IP(src=ME, dst=DNS) / UDP(sport=40000, dport=53),
        IP(src=DNS, dst=ME) / UDP(sport=53, dport=40000),
        # HTTPS handshake we initiate, with replies
        IP(src=ME, dst=WEB) / TCP(sport=50001, dport=443, flags="S"),
        IP(src=WEB, dst=ME) / TCP(sport=443, dport=50001, flags="SA"),
        IP(src=ME, dst=WEB) / TCP(sport=50001, dport=443, flags="A"),
        IP(src=WEB, dst=ME) / TCP(sport=443, dport=50001, flags="A") / (b"x" * 1400),
        # Inbound SSH attempt (allowed by explicit rule), Telnet (denied),
        # and an out-of-state ACK (invalid).
        IP(src=ATTACKER, dst=ME) / TCP(sport=51000, dport=22, flags="S"),
        IP(src=ATTACKER, dst=ME) / TCP(sport=51001, dport=23, flags="S"),
        IP(src=ATTACKER, dst=ME) / TCP(sport=51002, dport=50505, flags="A"),
    ]


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.pcap")
    pkts = build()
    wrpcap(out, pkts)
    print(f"wrote {len(pkts)} packets to {out}")
