"""Command-line entry point: `python -m vpn {genkey,server,client}`."""

import argparse
import ipaddress
import logging
import selectors
import socket
import sys

from . import crypto
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


def cmd_genkey(_: argparse.Namespace) -> None:
    print(crypto.generate_psk().hex())


def cmd_server(args: argparse.Namespace) -> None:
    psk = crypto.load_psk(args.psk_file)
    iface = ipaddress.IPv4Interface(args.address)
    host, port = _parse_hostport(args.listen)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    tun = Tun(args.dev)
    tun.configure(str(iface), args.mtu)
    server = Server(psk, iface, lambda d, a: sock.sendto(d, a), tun.write)
    logging.info("listening on %s:%d, tunnel %s on %s", host, port, iface, tun.name)
    _run(server, sock, tun)


def cmd_client(args: argparse.Namespace) -> None:
    psk = crypto.load_psk(args.psk_file)
    iface = ipaddress.IPv4Interface(args.address)
    host, port = _parse_hostport(args.server)
    server_addr = (socket.gethostbyname(host), port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tun = Tun(args.dev)
    tun.configure(str(iface), args.mtu)
    client = Client(psk, iface.ip, server_addr, lambda d, a: sock.sendto(d, a), tun.write)
    logging.info("connecting to %s:%d as %s on %s", *server_addr, iface, tun.name)
    client.start_handshake()
    _run(client, sock, tun)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="vpn", description="Minimal UDP/TUN VPN")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("genkey", help="print a new random pre-shared key").set_defaults(func=cmd_genkey)

    for name, func, endpoint_flag, endpoint_help in (
        ("server", cmd_server, "--listen", f"bind address (default 0.0.0.0:{DEFAULT_PORT})"),
        ("client", cmd_client, "--server", "server host[:port]"),
    ):
        sp = sub.add_parser(name)
        sp.set_defaults(func=func)
        sp.add_argument("--psk-file", required=True, help="file containing the hex pre-shared key")
        sp.add_argument("--address", required=True, help="tunnel address in CIDR form, e.g. 10.8.0.1/24")
        sp.add_argument("--dev", default="vpn%d", help="TUN device name (default vpn%%d)")
        sp.add_argument("--mtu", type=int, default=DEFAULT_MTU)
        if name == "server":
            sp.add_argument(endpoint_flag, default=f"0.0.0.0:{DEFAULT_PORT}", help=endpoint_help)
        else:
            sp.add_argument(endpoint_flag, required=True, help=endpoint_help)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
