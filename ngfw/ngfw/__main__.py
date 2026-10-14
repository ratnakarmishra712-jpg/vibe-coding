"""
Command-line entry point:  python -m ngfw [options]

    python -m ngfw --demo                 run the built-in scenario (default)
    python -m ngfw --rules rules.conf     use a specific policy file

It prints one line per packet: the verdict, the connection state conntrack
assigned, and which rule decided it — so you can see the brain think.
"""
from __future__ import annotations

import argparse
import os
import sys

from .backends.simulated import SimulatedBackend
from .engine import Firewall
from .rules import Action, RuleSet

# ANSI colours (disabled when output isn't a terminal).
_C = sys.stdout.isatty()
GREEN = "\033[32m" if _C else ""
RED = "\033[31m" if _C else ""
YELLOW = "\033[33m" if _C else ""
DIM = "\033[2m" if _C else ""
RESET = "\033[0m" if _C else ""

_DEFAULT_RULES = os.path.join(os.path.dirname(__file__), os.pardir, "rules.example.conf")


def _print_verdict(pkt, verdict) -> None:
    colour = {Action.ALLOW: GREEN, Action.DENY: RED, Action.REJECT: YELLOW}[verdict.action]
    tag = f"{colour}{verdict.action.value.upper():<6}{RESET}"
    state = f"{DIM}{verdict.state:<11}{RESET}"
    l7 = ""
    if pkt.meta.get("host"):
        l7 = f"  {YELLOW}{pkt.meta.get('app', 'app')}:{pkt.meta['host']}{RESET}"
    print(f"{tag} {state} {pkt}{l7}   {DIM}# {verdict.reason}{RESET}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ngfw", description="learning stateful firewall")
    ap.add_argument("--rules", default=_DEFAULT_RULES, help="policy file (default: rules.example.conf)")
    ap.add_argument("--demo", action="store_true", help="run the built-in scenario (default action)")
    ap.add_argument("--pcap", metavar="FILE", help="read real packets from a .pcap capture instead of the simulator")
    ap.add_argument("--nfqueue", type=int, metavar="N",
                    help="(Linux, root) enforce live on netfilter queue N; set up the rule with nfqueue_setup.sh")
    ap.add_argument("--enforce", action="store_true",
                    help="with --nfqueue: actually DROP denied packets (default: observe only, drop nothing)")
    ap.add_argument("--home", default="10.0.0.5/32",
                    help="your IP/CIDR(s), comma-separated: packets FROM here are outbound (pcap/nfqueue)")
    args = ap.parse_args(argv)

    try:
        ruleset = RuleSet.load(args.rules)
    except (OSError, ValueError) as e:
        print(f"error loading rules: {e}", file=sys.stderr)
        return 2

    fw = Firewall(ruleset, default=Action.DENY)
    if args.nfqueue is not None:
        from .backends.nfqueue import NfqueueBackend  # lazy: needs netfilterqueue
        try:
            backend = NfqueueBackend(fw, queue_num=args.nfqueue, home=args.home, enforce=args.enforce)
        except RuntimeError as e:
            print(f"error starting nfqueue backend: {e}", file=sys.stderr)
            return 2
        mode = f"{RED}ENFORCING (will DROP denied){RESET}" if args.enforce else f"{YELLOW}observe-only (drops nothing){RESET}"
        source = f"nfqueue {args.nfqueue}  (home={args.home})  mode: {mode}"
        if args.enforce:
            print(f"{RED}!! live enforcement on — do NOT run this on the port carrying your session !!{RESET}",
                  file=sys.stderr)
    elif args.pcap:
        from .backends.pcap import PcapBackend  # lazy: only needs scapy when used
        try:
            backend = PcapBackend(fw, args.pcap, home=args.home)
        except (RuntimeError, OSError) as e:
            print(f"error opening pcap: {e}", file=sys.stderr)
            return 2
        source = f"pcap: {args.pcap}  (home={args.home})"
    else:
        backend = SimulatedBackend(fw)
        source = "simulated scenario"

    print(f"{DIM}policy: {args.rules}  ({len(ruleset.rules)} rules, default={fw.default.value})"
          f"\nsource: {source}{RESET}\n")
    try:
        backend.run(on_verdict=_print_verdict)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    s = fw.stats
    print(f"\n{DIM}--- summary ---{RESET}")
    print(f"packets: {s['seen']}   {GREEN}allow:{s['allow']}{RESET}   "
          f"{RED}deny:{s['deny']}{RESET}   {YELLOW}reject:{s['reject']}{RESET}   "
          f"tracked flows: {len(fw.ct)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
