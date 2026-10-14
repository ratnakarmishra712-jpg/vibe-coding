"""Command-line entry point: `python -m vpn {genkey,pubkey,server,client}`."""

import argparse
import ipaddress
import logging
import selectors
import socket
import sys

from . import crypto, dos
from .node import Client, Server, format_addr
from .tun import Tun

DEFAULT_PORT = 51820
DEFAULT_MTU = 1420  # 1500 - IPv6(40) - UDP(8) - our header(13) - tag(16), rounded down


def parse_hostport(value: str) -> tuple[str, int]:
    """Parse `host`, `host:port`, `[v6addr]`, `[v6addr]:port` or a bare IPv6 literal."""
    if value.startswith("["):
        host, sep, rest = value[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError(f"malformed address {value!r}")
        return host, int(rest[1:]) if rest else DEFAULT_PORT
    if value.count(":") > 1:  # bare IPv6 literal, no port
        return value, DEFAULT_PORT
    host, sep, port = value.partition(":")
    return host, int(port) if sep else DEFAULT_PORT


def parse_interfaces(values: list[str]) -> list:
    interfaces = [ipaddress.ip_interface(v) for v in values]
    for version in (4, 6):
        if sum(i.version == version for i in interfaces) > 1:
            raise ValueError(f"at most one IPv{version} --address is supported")
    return interfaces


def server_socket(host: str | None, port: int) -> socket.socket:
    """Bind a UDP socket. With no host, listen on both IPv6 and IPv4 where possible."""
    error: OSError | None = None
    for candidate in [host] if host else ["::", "0.0.0.0"]:
        try:
            family, _, _, _, sockaddr = socket.getaddrinfo(
                candidate, port, type=socket.SOCK_DGRAM, flags=socket.AI_PASSIVE)[0]
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError as e:  # e.g. IPv6 disabled on this host
            error = e
            continue
        if family == socket.AF_INET6:
            # On the wildcard address also accept IPv4, seen as ::ffff:a.b.c.d.
            wildcard = ipaddress.ip_address(sockaddr[0].split("%")[0]).is_unspecified
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if wildcard else 1)
        try:
            sock.bind(sockaddr)
        except OSError as e:
            sock.close()
            error = e
            continue
        return sock
    assert error is not None
    raise error


def client_socket(host: str, port: int, family: int) -> tuple[socket.socket, tuple]:
    family, _, _, _, sockaddr = socket.getaddrinfo(host, port, family=family, type=socket.SOCK_DGRAM)[0]
    return socket.socket(family, socket.SOCK_DGRAM), sockaddr


def _run(node, sock: socket.socket, tun: Tun) -> None:
    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ, "udp")
    sel.register(tun, selectors.EVENT_READ, "tun")
    while True:
        for key, _ in sel.select(timeout=1.0):
            if key.data == "udp":
                data, addr = sock.recvfrom(65535)
                node.handle_datagram(data, addr)
            else:
                try:
                    node.handle_tun(tun.read())
                except BlockingIOError:
                    pass
        node.tick()


def load_peers(path: str | None, inline: list[str]) -> dict[bytes, list]:
    """Read `<public-key> <allowed>[,<allowed>...]` lines (from a file and/or --peer flags).

    Each allowed entry is a tunnel address (`10.8.0.2`, `fd00:8::2`) or a subnet
    routed through that peer (`192.168.20.0/24`).
    """
    entries: list[tuple[str, str]] = []
    if path:
        with open(path, encoding="ascii") as f:
            for lineno, line in enumerate(f, 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    raise ValueError(f"{path}:{lineno}: expected '<public-key> <ip-or-subnet>[,...]'")
                entries.append((parts[0], parts[1]))
    for item in inline:
        key, sep, ip = item.rpartition("=")
        if not sep:
            raise ValueError(f"--peer expects KEY=IP[,IP-OR-SUBNET...], got {item!r}")
        entries.append((key, ip))
    peers: dict[bytes, list] = {}
    for key_text, ips_text in entries:
        key = crypto.decode_key(key_text)
        if key in peers:
            raise ValueError(f"duplicate peer key {key_text}")
        # strict: reject "192.168.20.1/24" (host bits set) rather than silently widening it
        peers[key] = [ipaddress.ip_network(item, strict=True) for item in ips_text.split(",") if item]
    return peers


def cmd_genkey(_: argparse.Namespace) -> None:
    print(crypto.encode_key(crypto.KeyPair.generate().private_bytes()))


def cmd_pubkey(_: argparse.Namespace) -> None:
    print(crypto.encode_key(crypto.KeyPair.from_bytes(crypto.decode_key(sys.stdin.read())).public))


def cmd_server(args: argparse.Namespace) -> None:
    static = crypto.load_private_key(args.private_key_file)
    ifaces = parse_interfaces(args.address)
    peers = load_peers(args.peers_file, args.peer)
    if not peers:
        raise SystemExit("no peers configured: use --peers-file and/or --peer KEY=IP")
    host, port = parse_hostport(args.listen) if args.listen else (None, DEFAULT_PORT)
    sock = server_socket(host, port)
    tun = Tun(args.dev)
    server = Server(static, ifaces, peers, lambda d, a: sock.sendto(d, a), tun.write,
                    load_threshold=args.load_threshold)
    tun.configure(ifaces, args.mtu)
    routed = server.routed_networks()
    tun.add_routes(routed)
    if routed:
        logging.info("routing peer subnets: %s", ", ".join(map(str, routed)))
    logging.info("listening on %s, tunnel %s on %s, %d peer(s), public key %s",
                 format_addr(sock.getsockname()), ", ".join(map(str, ifaces)), tun.name, len(peers),
                 crypto.encode_key(static.public))
    _run(server, sock, tun)


def cmd_client(args: argparse.Namespace) -> None:
    static = crypto.load_private_key(args.private_key_file)
    server_public = crypto.decode_key(args.server_public_key)
    ifaces = parse_interfaces(args.address)
    host, port = parse_hostport(args.server)
    sock, server_addr = client_socket(host, port, args.family)
    tun = Tun(args.dev)
    tun.configure(ifaces, args.mtu)
    tun.add_routes(args.route)
    client = Client(static, server_public, server_addr, lambda d, a: sock.sendto(d, a), tun.write)
    logging.info("connecting to %s as %s on %s, public key %s", format_addr(server_addr),
                 ", ".join(map(str, ifaces)), tun.name, crypto.encode_key(static.public))
    client.start_handshake()
    _run(client, sock, tun)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="vpn", description="Minimal UDP/TUN VPN")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("genkey", help="print a new private key").set_defaults(func=cmd_genkey)
    sub.add_parser("pubkey", help="read a private key on stdin, print its public key").set_defaults(func=cmd_pubkey)

    for name, func, endpoint_flag, endpoint_help in (
        ("server", cmd_server, "--listen",
         f"bind address, e.g. 0.0.0.0:{DEFAULT_PORT} or [::]:{DEFAULT_PORT} "
         f"(default: IPv6 and IPv4 on port {DEFAULT_PORT})"),
        ("client", cmd_client, "--server", "server host[:port] or [ipv6]:port"),
    ):
        sp = sub.add_parser(name)
        sp.set_defaults(func=func)
        sp.add_argument("--private-key-file", required=True, help="file containing this node's private key")
        sp.add_argument("--address", required=True, action="append",
                        help="tunnel address in CIDR form, e.g. 10.8.0.1/24 or fd00:8::1/64; "
                             "give once per IP version")
        sp.add_argument("--dev", default="vpn%d", help="TUN device name (default vpn%%d)")
        sp.add_argument("--mtu", type=int, default=DEFAULT_MTU)
        if name == "server":
            sp.add_argument(endpoint_flag, help=endpoint_help)
            sp.add_argument("--peers-file",
                            help="file of '<public-key> <ip-or-subnet>[,<ip-or-subnet>...]' lines")
            sp.add_argument("--peer", action="append", default=[], metavar="KEY=IP[,IP-OR-SUBNET...]",
                            help="allow a client public key with the given tunnel addresses and "
                                 "routed subnets (repeatable)")
            sp.add_argument("--load-threshold", type=int, default=dos.DEFAULT_LOAD_THRESHOLD, metavar="N",
                            help="handshakes per second before requiring cookies "
                                 f"(default {dos.DEFAULT_LOAD_THRESHOLD})")
        else:
            sp.add_argument(endpoint_flag, required=True, help=endpoint_help)
            sp.add_argument("--server-public-key", required=True, help="the server's public key")
            sp.add_argument("--route", action="append", default=[], type=ipaddress.ip_network,
                            metavar="SUBNET", help="send traffic for SUBNET through the tunnel, e.g. a "
                                                   "LAN behind the server (repeatable)")
            fam = sp.add_mutually_exclusive_group()
            fam.add_argument("-4", dest="family", action="store_const", const=socket.AF_INET,
                             help="reach the server over IPv4 only")
            fam.add_argument("-6", dest="family", action="store_const", const=socket.AF_INET6,
                             help="reach the server over IPv6 only")
            sp.set_defaults(family=socket.AF_UNSPEC)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit(0)
    except (OSError, RuntimeError, ValueError) as e:
        if args.verbose:
            raise
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
