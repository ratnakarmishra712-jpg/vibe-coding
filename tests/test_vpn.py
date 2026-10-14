import ipaddress
import os
import socket
import struct
import tempfile
import time
import unittest
from unittest import mock

from vpn import crypto, dos, protocol
from vpn.routing import RoutingTable
from vpn.__main__ import load_peers, parse_hostport, parse_interfaces, server_socket
from vpn.node import SESSION_TIMEOUT, Client, Server

SERVER_KEY = crypto.KeyPair.generate()
ALICE = crypto.KeyPair.generate()
BOB = crypto.KeyPair.generate()
MALLORY = crypto.KeyPair.generate()
net = ipaddress.ip_network
ALICE_IP = net("10.8.0.2/32")
ALICE_IP6 = net("fd00:8::2/128")
BOB_IP = net("10.8.0.3/32")
SERVER_ADDR = ("192.0.2.1", 51820)
PEERS = {ALICE.public: [ALICE_IP, ALICE_IP6], BOB.public: [BOB_IP]}
SERVER_IFACES = [ipaddress.ip_interface("10.8.0.1/24"), ipaddress.ip_interface("fd00:8::1/64")]


def ipv4_packet(src: str, dst: str, payload: bytes = b"hello") -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 17, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + payload


def ipv6_packet(src: str, dst: str, payload: bytes = b"hello") -> bytes:
    header = struct.pack("!IHBB16s16s", 6 << 28, len(payload), 17, 64,
                         ipaddress.IPv6Address(src).packed, ipaddress.IPv6Address(dst).packed)
    return header + payload


class Network:
    """Wires a Server and any number of Clients together through an in-memory queue."""

    def __init__(self, load_threshold=dos.DEFAULT_LOAD_THRESHOLD):
        self.wire: list[tuple[bytes, tuple, tuple]] = []  # (data, src, dst)
        self.server_tun: list[bytes] = []
        self.now = 1000.0
        self.server = Server(SERVER_KEY, SERVER_IFACES, PEERS,
                             lambda d, a: self.wire.append((d, SERVER_ADDR, a)), self.server_tun.append,
                             load_threshold=load_threshold, clock=lambda: self.now)
        self.clients: dict[tuple, Client] = {}
        self.client_tun: dict[tuple, list[bytes]] = {}

    def add_client(self, key, addr, server_public=SERVER_KEY.public) -> Client:
        self.client_tun[addr] = []
        client = Client(key, server_public, SERVER_ADDR,
                        lambda d, a: self.wire.append((d, addr, a)), self.client_tun[addr].append)
        self.clients[addr] = client
        return client

    def deliver(self):
        delivered = []
        while self.wire:
            data, src, dst = self.wire.pop(0)
            delivered.append(data)
            node = self.server if dst == SERVER_ADDR else self.clients.get(dst)
            if node is not None:
                node.handle_datagram(data, src)
        return delivered

    def connect(self, client):
        client.start_handshake()
        return self.deliver()


class ReplayWindowTest(unittest.TestCase):
    def test_rejects_duplicates_and_old(self):
        w = protocol.ReplayWindow(size=64)
        for c in (0, 1, 5, 3):
            self.assertTrue(w.check(c))
            w.update(c)
        self.assertFalse(w.check(3))
        self.assertFalse(w.check(5))
        self.assertTrue(w.check(4))
        w.update(100)
        self.assertFalse(w.check(36))  # fell out of the window
        self.assertTrue(w.check(37))


class HandshakeTest(unittest.TestCase):
    def handshake(self):
        pending = protocol.create_init(ALICE, SERVER_KEY.public)
        info = protocol.parse_init(SERVER_KEY, pending.packet)
        resp, server_session = protocol.respond(info)
        return info, server_session, protocol.complete(ALICE, pending, resp)

    def test_keys_match_and_identity_revealed(self):
        info, server_session, client_session = self.handshake()
        self.assertEqual(info.static_public, ALICE.public)
        self.assertEqual(server_session.open(client_session.seal(b"ping")), b"ping")
        self.assertEqual(client_session.open(server_session.seal(b"pong")), b"pong")

    def test_static_key_not_sent_in_clear(self):
        pending = protocol.create_init(ALICE, SERVER_KEY.public)
        self.assertNotIn(ALICE.public, pending.packet)

    def test_init_for_other_server_rejected(self):
        pending = protocol.create_init(ALICE, MALLORY.public)
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_init(SERVER_KEY, pending.packet)

    def test_stale_timestamp_rejected(self):
        pending = protocol.create_init(ALICE, SERVER_KEY.public, now_ns=0)
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_init(SERVER_KEY, pending.packet)

    def test_response_from_impostor_server_rejected(self):
        pending = protocol.create_init(ALICE, SERVER_KEY.public)
        # Mallory can't decrypt the init, so the best they can do is answer with their own keys.
        fake = protocol.InitInfo(protocol._INIT_HDR.unpack_from(pending.packet)[1], pending.ephemeral.public,
                                 ALICE.public, 0, protocol._Symmetric.initial(MALLORY.public))
        resp, _ = protocol.respond(fake)
        with self.assertRaises(protocol.ProtocolError):
            protocol.complete(ALICE, pending, resp)

    def test_tampered_data_rejected(self):
        _, server_session, client_session = self.handshake()
        pkt = bytearray(client_session.seal(b"secret"))
        pkt[-1] ^= 1
        with self.assertRaises(protocol.ProtocolError):
            server_session.open(bytes(pkt))


class EndToEndTest(unittest.TestCase):
    def test_traffic_flows_both_ways(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000))
        net.connect(alice)
        self.assertTrue(alice.connected)

        out = ipv4_packet("10.8.0.2", "10.8.0.1")
        alice.handle_tun(out)
        net.deliver()
        self.assertEqual(net.server_tun, [out])

        back = ipv4_packet("10.8.0.1", "10.8.0.2", b"world")
        net.server.handle_tun(back)
        net.deliver()
        self.assertEqual(net.client_tun[("198.51.100.7", 40000)], [back])

    def test_two_clients_routed_separately(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000))
        bob = net.add_client(BOB, ("198.51.100.8", 40000))
        net.connect(alice)
        net.connect(bob)
        to_bob = ipv4_packet("10.8.0.1", "10.8.0.3")
        net.server.handle_tun(to_bob)
        net.deliver()
        self.assertEqual(net.client_tun[("198.51.100.8", 40000)], [to_bob])
        self.assertEqual(net.client_tun[("198.51.100.7", 40000)], [])

    def test_unknown_key_rejected(self):
        net = Network()
        mallory = net.add_client(MALLORY, ("203.0.113.66", 1234))
        net.connect(mallory)
        self.assertFalse(mallory.connected)
        self.assertEqual(net.server.by_index, {})

    def test_cannot_impersonate_with_only_public_key(self):
        net = Network()
        impostor = crypto.KeyPair.from_bytes(MALLORY.private_bytes())
        impostor.public = ALICE.public  # claims Alice's identity without her private key
        client = net.add_client(impostor, ("203.0.113.66", 1234))
        net.connect(client)
        self.assertFalse(client.connected)
        self.assertEqual(net.server.by_index, {})

    def test_wrong_server_key_never_connects(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000), server_public=MALLORY.public)
        net.connect(alice)
        self.assertFalse(alice.connected)

    def test_peer_cannot_use_another_peers_ip(self):
        net = Network()
        bob = net.add_client(BOB, ("198.51.100.8", 40000))
        net.connect(bob)
        bob.handle_tun(ipv4_packet("10.8.0.2", "10.8.0.1"))  # Bob pretends to be Alice
        net.deliver()
        self.assertEqual(net.server_tun, [])

    def test_replayed_data_dropped(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000))
        net.connect(alice)
        alice.handle_tun(ipv4_packet("10.8.0.2", "10.8.0.1"))
        [data] = net.deliver()
        net.server.handle_datagram(data, ("198.51.100.7", 40000))
        self.assertEqual(len(net.server_tun), 1)

    def test_replayed_init_cannot_hijack(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000))
        init, *_ = net.connect(alice)
        net.server.handle_datagram(init, ("203.0.113.66", 1234))
        self.assertEqual(net.server.peers[ALICE.public].addr, ("198.51.100.7", 40000))

    def test_forged_response_does_not_break_handshake(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000))
        alice.start_handshake()
        idx = alice.pending.local_idx
        alice.handle_datagram(struct.pack("!BII", protocol.MSG_RESPONSE, 1, idx) + os.urandom(48), SERVER_ADDR)
        net.deliver()
        self.assertTrue(alice.connected)

    def test_rekey_keeps_traffic_flowing(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000))
        net.connect(alice)
        first = alice.session
        net.connect(alice)
        self.assertIsNot(alice.session, first)
        back = ipv4_packet("10.8.0.1", "10.8.0.2")
        net.server.handle_tun(back)
        net.deliver()
        self.assertEqual(net.client_tun[("198.51.100.7", 40000)], [back])

    def test_server_expires_idle_peer(self):
        net = Network()
        alice = net.add_client(ALICE, ("198.51.100.7", 40000))
        net.connect(alice)
        peer = net.server.peers[ALICE.public]
        net.server.tick(now=peer.session.last_received + SESSION_TIMEOUT + 1)
        self.assertIsNone(peer.session)
        self.assertEqual(net.server.by_index, {})


class DosTest(unittest.TestCase):
    ALICE_ADDR = ("198.51.100.7", 40000)

    def flood(self, net, count, base="203.0.113."):
        """Send `count` well-formed INITs (valid mac1, unknown key) from distinct addresses."""
        for i in range(count):
            init = protocol.create_init(MALLORY, SERVER_KEY.public).packet
            net.server.handle_datagram(init, (base + str(i % 250 + 1), 1000 + i))

    def sent_types(self, net):
        types = [d[0] for d, src, _ in net.wire if src == SERVER_ADDR]
        net.wire.clear()
        return types

    def test_bad_mac1_dropped_before_any_dh(self):
        net = Network()
        init = bytearray(protocol.create_init(ALICE, SERVER_KEY.public).packet)
        init[protocol.INIT_BODY_LEN] ^= 1
        with mock.patch.object(protocol, "parse_init") as parse:
            net.server.handle_datagram(bytes(init), self.ALICE_ADDR)
            net.server.handle_datagram(b"\x01" + os.urandom(protocol.INIT_LEN - 1), self.ALICE_ADDR)
        parse.assert_not_called()
        self.assertEqual(net.wire, [])

    def test_no_cookie_needed_when_idle(self):
        net = Network(load_threshold=5)
        self.flood(net, 3)
        self.assertNotIn(protocol.MSG_COOKIE, self.sent_types(net))

    def test_under_load_replies_with_cookie_instead_of_handshake(self):
        net = Network(load_threshold=5)
        self.flood(net, 5)
        with mock.patch.object(protocol, "parse_init", wraps=protocol.parse_init) as parse:
            self.flood(net, 20, base="192.0.2.")
        parse.assert_not_called()
        types = self.sent_types(net)
        self.assertEqual(types[-20:], [protocol.MSG_COOKIE] * 20)
        self.assertLess(protocol.COOKIE_LEN, protocol.INIT_LEN)  # no amplification

    def test_legit_client_connects_under_load_with_cookie(self):
        net = Network(load_threshold=5)
        alice = net.add_client(ALICE, self.ALICE_ADDR)
        self.flood(net, 10)
        net.wire.clear()
        net.connect(alice)
        self.assertFalse(alice.connected)
        self.assertIsNotNone(alice.cookies.current())
        alice.tick(now=time.monotonic() + 6)  # handshake retry timer fires
        net.deliver()
        self.assertTrue(alice.connected)

    def test_load_subsides(self):
        net = Network(load_threshold=5)
        alice = net.add_client(ALICE, self.ALICE_ADDR)
        self.flood(net, 10)
        net.wire.clear()
        net.now += 5
        net.connect(alice)
        self.assertTrue(alice.connected)

    def test_cookie_bound_to_source_address(self):
        net = Network(load_threshold=0)
        cookie = net.server.cookies.cookie_for(self.ALICE_ADDR, net.now)
        init = protocol.create_init(ALICE, SERVER_KEY.public, cookie=cookie).packet
        net.server.handle_datagram(init, ("203.0.113.9", 40000))
        self.assertEqual(self.sent_types(net), [protocol.MSG_COOKIE])
        net.server.handle_datagram(init, self.ALICE_ADDR)
        self.assertEqual(self.sent_types(net), [protocol.MSG_RESPONSE])

    def test_cookie_expires_when_secret_rotates(self):
        net = Network(load_threshold=0)
        cookie = net.server.cookies.cookie_for(self.ALICE_ADDR, net.now)
        net.now += dos.COOKIE_SECRET_LIFETIME + 1
        init = protocol.create_init(ALICE, SERVER_KEY.public, cookie=cookie).packet
        net.server.handle_datagram(init, self.ALICE_ADDR)
        self.assertEqual(self.sent_types(net), [protocol.MSG_COOKIE])

    def test_per_ip_rate_limit_with_valid_cookie(self):
        net = Network(load_threshold=0)
        addr = ("203.0.113.9", 4000)
        cookie = net.server.cookies.cookie_for(addr, net.now)
        with mock.patch.object(protocol, "parse_init", side_effect=protocol.ProtocolError("x")) as parse:
            for _ in range(50):
                net.server.handle_datagram(
                    protocol.create_init(MALLORY, SERVER_KEY.public, cookie=cookie).packet, addr)
        self.assertEqual(parse.call_count, int(dos.PER_IP_BURST))

    def test_forged_cookie_reply_rejected(self):
        net = Network()
        alice = net.add_client(ALICE, self.ALICE_ADDR)
        alice.start_handshake()
        # An attacker who doesn't see Alice's INIT can't produce a reply bound to its mac1.
        other = protocol.create_init(ALICE, SERVER_KEY.public).packet
        forged = bytearray(protocol.seal_cookie(protocol.cookie_key(SERVER_KEY.public), other, os.urandom(16)))
        forged[1:5] = struct.pack("!I", alice.pending.local_idx)
        alice.handle_datagram(bytes(forged), SERVER_ADDR)
        self.assertIsNone(alice.cookies.current())

    def test_client_cookie_expires(self):
        clock = [0.0]
        jar = dos.CookieJar(clock=lambda: clock[0])
        jar.store(b"c" * 16)
        self.assertEqual(jar.current(), b"c" * 16)
        clock[0] += dos.COOKIE_LIFETIME
        self.assertIsNone(jar.current())

    def test_rate_limiter_refills_and_prunes(self):
        rl = dos.RateLimiter(rate=1.0, burst=2.0)
        self.assertTrue(rl.allow("a", 0.0))
        self.assertTrue(rl.allow("a", 0.0))
        self.assertFalse(rl.allow("a", 0.0))
        self.assertTrue(rl.allow("a", 1.0))
        rl.prune(10.0)
        self.assertEqual(rl._buckets, {})


class IPv6Test(unittest.TestCase):
    ALICE_ADDR = ("2001:db8::7", 40000, 0, 0)  # outer transport over IPv6 too

    def connected(self):
        net = Network()
        alice = net.add_client(ALICE, self.ALICE_ADDR)
        net.connect(alice)
        self.assertTrue(alice.connected)
        return net, alice

    def test_ip_header_parsing(self):
        v4, v6 = ipv4_packet("10.8.0.2", "10.8.0.1"), ipv6_packet("fd00:8::2", "fd00:8::1")
        self.assertEqual(protocol.ip_source(v4), ipaddress.ip_address("10.8.0.2"))
        self.assertEqual(protocol.ip_destination(v4), ipaddress.ip_address("10.8.0.1"))
        self.assertEqual(protocol.ip_source(v6), ipaddress.ip_address("fd00:8::2"))
        self.assertEqual(protocol.ip_destination(v6), ipaddress.ip_address("fd00:8::1"))
        for junk in (b"", v6[:39], v4[:19], b"\x50" + v4[1:]):
            self.assertIsNone(protocol.ip_source(junk))
            self.assertIsNone(protocol.ip_destination(junk))

    def test_ipv6_traffic_flows_both_ways(self):
        net, alice = self.connected()
        out = ipv6_packet("fd00:8::2", "fd00:8::1")
        alice.handle_tun(out)
        net.deliver()
        self.assertEqual(net.server_tun, [out])
        back = ipv6_packet("fd00:8::1", "fd00:8::2", b"world")
        net.server.handle_tun(back)
        net.deliver()
        self.assertEqual(net.client_tun[self.ALICE_ADDR], [back])

    def test_dual_stack_peer_uses_both_families(self):
        net, alice = self.connected()
        packets = [ipv4_packet("10.8.0.2", "10.8.0.1"), ipv6_packet("fd00:8::2", "fd00:8::1")]
        for p in packets:
            alice.handle_tun(p)
        net.deliver()
        self.assertEqual(net.server_tun, packets)

    def test_ipv6_spoofing_dropped(self):
        net = Network()
        bob = net.add_client(BOB, ("198.51.100.8", 40000))
        net.connect(bob)
        bob.handle_tun(ipv6_packet("fd00:8::2", "fd00:8::1"))  # Alice's IPv6 address
        bob.handle_tun(ipv6_packet("fd00:8::99", "fd00:8::1"))  # unassigned address
        net.deliver()
        self.assertEqual(net.server_tun, [])

    def test_client_drops_multicast_and_non_ip(self):
        net, alice = self.connected()
        net.wire.clear()
        alice.handle_tun(ipv6_packet("fe80::1", "ff02::2"))  # router solicitation
        alice.handle_tun(b"\x00" * 40)
        self.assertEqual(net.wire, [])

    def test_cookie_for_ipv6_and_v4_mapped_sources(self):
        net = Network(load_threshold=0)
        for addr in (self.ALICE_ADDR, ("::ffff:198.51.100.7", 40000, 0, 0)):
            cookie = net.server.cookies.cookie_for(addr, net.now)
            init = protocol.create_init(ALICE, SERVER_KEY.public, cookie=cookie).packet
            net.server.handle_datagram(init, addr)
            self.assertEqual(net.wire.pop()[0][0], protocol.MSG_RESPONSE)
            net.now += 1  # handshake timestamps must increase per peer

    def test_server_rejects_bad_ipv6_peer_config(self):
        for addrs in (["fd00:8::1"], ["fd00:8::"], ["fd00:8::/120"], []):
            with self.assertRaises(ValueError):
                Server(SERVER_KEY, SERVER_IFACES, {ALICE.public: [net(a) for a in addrs]},
                       lambda d, a: None, lambda p: None)

    def test_dual_stack_socket_accepts_ipv4(self):
        try:
            sock = server_socket(None, 0)
        except OSError as e:
            self.skipTest(f"cannot bind: {e}")
        with sock, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            if sock.family != socket.AF_INET6:
                self.skipTest("IPv6 unavailable on this host")
            sock.settimeout(2)
            sender.sendto(b"x", ("127.0.0.1", sock.getsockname()[1]))
            data, addr = sock.recvfrom(16)
            self.assertEqual((data, addr[0]), (b"x", "::ffff:127.0.0.1"))


class RoutingTableTest(unittest.TestCase):
    def test_longest_prefix_match(self):
        rt = RoutingTable()
        rt.insert(net("0.0.0.0/0"), "default")
        rt.insert(net("10.0.0.0/8"), "ten")
        rt.insert(net("10.1.0.0/16"), "ten-one")
        rt.insert(net("10.1.2.3/32"), "host")
        rt.insert(net("2001:db8::/32"), "v6")
        ip = ipaddress.ip_address
        self.assertEqual(rt.lookup(ip("10.1.2.3")), "host")
        self.assertEqual(rt.lookup(ip("10.1.2.4")), "ten-one")
        self.assertEqual(rt.lookup(ip("10.2.0.1")), "ten")
        self.assertEqual(rt.lookup(ip("192.0.2.1")), "default")
        self.assertEqual(rt.lookup(ip("2001:db8::1")), "v6")
        self.assertIsNone(rt.lookup(ip("2001:db9::1")))
        self.assertIsNone(rt.lookup(None))


class SiteToSiteTest(unittest.TestCase):
    """Alice is a gateway for 192.168.20.0/24 and 2001:db8:20::/48 behind her."""

    ALICE_ADDR = ("198.51.100.7", 40000)
    ALICE_LAN = [net("192.168.20.0/24"), net("2001:db8:20::/48")]

    def setUp(self):
        peers = {ALICE.public: [ALICE_IP, *self.ALICE_LAN], BOB.public: [BOB_IP, net("192.168.30.0/24")]}
        self.net = Network()
        self.net.server = Server(SERVER_KEY, SERVER_IFACES, peers,
                                 lambda d, a: self.net.wire.append((d, SERVER_ADDR, a)), self.net.server_tun.append,
                                 clock=lambda: self.net.now)
        self.alice = self.net.add_client(ALICE, self.ALICE_ADDR)
        self.net.connect(self.alice)

    def test_server_routes_lan_traffic_to_gateway(self):
        packets = [ipv4_packet("192.168.10.5", "192.168.20.9"), ipv6_packet("2001:db8:10::5", "2001:db8:20:1::9")]
        for p in packets:
            self.net.server.handle_tun(p)
        self.net.deliver()
        self.assertEqual(self.net.client_tun[self.ALICE_ADDR], packets)

    def test_gateway_forwards_lan_hosts_traffic(self):
        p = ipv4_packet("192.168.20.9", "192.168.10.5")
        self.alice.handle_tun(p)
        self.net.deliver()
        self.assertEqual(self.net.server_tun, [p])

    def test_gateway_cannot_claim_other_sites(self):
        for src in ("192.168.30.9", "192.168.21.9", "10.8.0.3"):
            self.alice.handle_tun(ipv4_packet(src, "192.168.10.5"))
        self.net.deliver()
        self.assertEqual(self.net.server_tun, [])

    def test_routed_networks_excludes_tunnel_hosts(self):
        self.assertEqual(sorted(map(str, self.net.server.routed_networks())),
                         ["192.168.20.0/24", "192.168.30.0/24", "2001:db8:20::/48"])


class ConfigTest(unittest.TestCase):
    def test_parse_hostport(self):
        cases = {
            "vpn.example.com": ("vpn.example.com", 51820),
            "192.0.2.1:1234": ("192.0.2.1", 1234),
            "[2001:db8::1]:1234": ("2001:db8::1", 1234),
            "[2001:db8::1]": ("2001:db8::1", 51820),
            "2001:db8::1": ("2001:db8::1", 51820),
        }
        for text, expected in cases.items():
            self.assertEqual(parse_hostport(text), expected, text)
        for bad in ("[2001:db8::1", "[::1]x"):
            with self.assertRaises(ValueError):
                parse_hostport(bad)

    def test_parse_interfaces(self):
        self.assertEqual(parse_interfaces(["10.8.0.1/24", "fd00:8::1/64"]), SERVER_IFACES)
        with self.assertRaises(ValueError):
            parse_interfaces(["10.8.0.1/24", "10.9.0.1/24"])

    def test_key_roundtrip(self):
        self.assertEqual(crypto.decode_key(crypto.encode_key(ALICE.public)), ALICE.public)
        with self.assertRaises(ValueError):
            crypto.decode_key("abcd")

    def test_load_peers(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(f"# comment\n{crypto.encode_key(ALICE.public)} 10.8.0.2,fd00:8::2\n\n")
        try:
            peers = load_peers(f.name, [f"{crypto.encode_key(BOB.public)}=10.8.0.3,192.168.30.0/24"])
        finally:
            os.unlink(f.name)
        self.assertEqual(peers, {**PEERS, BOB.public: [BOB_IP, net("192.168.30.0/24")]})
        with self.assertRaises(ValueError):  # host bits set
            load_peers(None, [f"{crypto.encode_key(BOB.public)}=192.168.30.1/24"])

    def test_server_rejects_bad_peer_config(self):
        for peers in ({ALICE.public: [net("10.8.0.1/32")]},          # the server's own address
                      {ALICE.public: [net("10.8.0.255/32")]},        # broadcast
                      {ALICE.public: [net("10.8.0.0/28")]},          # subnet inside the tunnel subnet
                      {ALICE.public: [net("10.0.0.0/8")]},           # subnet covering the tunnel subnet
                      {ALICE.public: [ALICE_IP], BOB.public: [ALICE_IP]},
                      {ALICE.public: [ALICE_IP, net("192.168.0.0/16")],
                       BOB.public: [BOB_IP, net("192.168.20.0/24")]},  # overlapping routed subnets
                      {ALICE.public: []}):
            with self.assertRaises(ValueError):
                Server(SERVER_KEY, SERVER_IFACES, peers, lambda d, a: None, lambda p: None)


if __name__ == "__main__":
    unittest.main()
