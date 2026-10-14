"""Command-line entry point: `python -m vpn {genkey,pubkey,server,client}`."""

import argparse
import ipaddress
import logging
import selectors
import socket
import sys

from . import crypto, dos
from .node import Client, Server
from .tun import Tun

DEFAULT_PORT = 51820
DEFAULT_MTU = 1420  # 1500 - IPv4(20) - UDP(8) - our header(13) - tag(16), rounded down


def _parse_hostport(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep:
        return value, DEFAULT_PORT
    return host.strip("[]"), int(port)


def _run(node, sock: socket.socket, tun: Tun) -> None:
    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ, "udp")
    sel.register(tun, selectors.EVENT_READ, "tun")
    while True:
        for key, _ in sel.select(timeout=1.0):
            if key.data == "udp":
                data, addr = sock.recvfrom(65535)
                node.handle_datagram(data, addr[:2])
            else:
                try:
                    node.handle_tun(tun.read())
                except BlockingIOError:
                    pass
        node.tick()


def load_peers(path: str | None, inline: list[str]) -> dict[bytes, ipaddress.IPv4Address]:
    """Read `<public-key> <tunnel-ip>` lines (from a file and/or --peer KEY=IP flags)."""
    entries: list[tuple[str, str]] = []
    if path:
        with open(path, encoding="ascii") as f:
            for lineno, line in enumerate(f, 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    raise ValueError(f"{path}:{lineno}: expected '<public-key> <tunnel-ip>'")
                entries.append((parts[0], parts[1]))
    for item in inline:
        key, sep, ip = item.rpartition("=")
        if not sep:
            raise ValueError(f"--peer expects KEY=IP, got {item!r}")
        entries.append((key, ip))
    peers: dict[bytes, ipaddress.IPv4Address] = {}
    for key_text, ip_text in entries:
        key = crypto.decode_key(key_text)
        if key in peers:
            raise ValueError(f"duplicate peer key {key_text}")
        peers[key] = ipaddress.IPv4Address(ip_text)
    return peers


def cmd_genkey(_: argparse.Namespace) -> None:
    print(crypto.encode_key(crypto.KeyPair.generate().private_bytes()))


def cmd_pubkey(_: argparse.Namespace) -> None:
    print(crypto.encode_key(crypto.KeyPair.from_bytes(crypto.decode_key(sys.stdin.read())).public))


def cmd_server(args: argparse.Namespace) -> None:
    static = crypto.load_private_key(args.private_key_file)
    iface = ipaddress.IPv4Interface(args.address)
    peers = load_peers(args.peers_file, args.peer)
    if not peers:
        raise SystemExit("no peers configured: use --peers-file and/or --peer KEY=IP")
    host, port = _parse_hostport(args.listen)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    tun = Tun(args.dev)
    tun.configure(str(iface), args.mtu)
    server = Server(static, iface, peers, lambda d, a: sock.sendto(d, a), tun.write,
                    load_threshold=args.load_threshold)
    logging.info("listening on %s:%d, tunnel %s on %s, %d peer(s), public key %s",
                 host, port, iface, tun.name, len(peers), crypto.encode_key(static.public))
    _run(server, sock, tun)


def cmd_client(args: argparse.Namespace) -> None:
    static = crypto.load_private_key(args.private_key_file)
    server_public = crypto.decode_key(args.server_public_key)
    iface = ipaddress.IPv4Interface(args.address)
    host, port = _parse_hostport(args.server)
    server_addr = (socket.gethostbyname(host), port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tun = Tun(args.dev)
    tun.configure(str(iface), args.mtu)
    client = Client(static, server_public, server_addr, lambda d, a: sock.sendto(d, a), tun.write)
    logging.info("connecting to %s:%d as %s on %s, public key %s",
                 *server_addr, iface, tun.name, crypto.encode_key(static.public))
    client.start_handshake()
    _run(client, sock, tun)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="vpn", description="Minimal UDP/TUN VPN")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("genkey", help="print a new private key").set_defaults(func=cmd_genkey)
    sub.add_parser("pubkey", help="read a private key on stdin, print its public key").set_defaults(func=cmd_pubkey)

    for name, func, endpoint_flag, endpoint_help in (
        ("server", cmd_server, "--listen", f"bind address (default 0.0.0.0:{DEFAULT_PORT})"),
        ("client", cmd_client, "--server", "server host[:port]"),
    ):
        sp = sub.add_parser(name)
        sp.set_defaults(func=func)
        sp.add_argument("--private-key-file", required=True, help="file containing this node's private key")
        sp.add_argument("--address", required=True, help="tunnel address in CIDR form, e.g. 10.8.0.1/24")
        sp.add_argument("--dev", default="vpn%d", help="TUN device name (default vpn%%d)")
        sp.add_argument("--mtu", type=int, default=DEFAULT_MTU)
        if name == "server":
            sp.add_argument(endpoint_flag, default=f"0.0.0.0:{DEFAULT_PORT}", help=endpoint_help)
            sp.add_argument("--peers-file", help="file of '<public-key> <tunnel-ip>' lines")
            sp.add_argument("--peer", action="append", default=[], metavar="KEY=IP",
                            help="allow a client public key with the given tunnel IP (repeatable)")
            sp.add_argument("--load-threshold", type=int, default=dos.DEFAULT_LOAD_THRESHOLD, metavar="N",
                            help="handshakes per second before requiring cookies "
                                 f"(default {dos.DEFAULT_LOAD_THRESHOLD})")
        else:
            sp.add_argument(endpoint_flag, required=True, help=endpoint_help)
            sp.add_argument("--server-public-key", required=True, help="the server's public key")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
