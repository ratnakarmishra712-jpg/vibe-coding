import ipaddress
import os
import struct
import tempfile
import unittest

from vpn import crypto, protocol
from vpn.__main__ import load_peers
from vpn.node import SESSION_TIMEOUT, Client, Server

SERVER_KEY = crypto.KeyPair.generate()
ALICE = crypto.KeyPair.generate()
BOB = crypto.KeyPair.generate()
MALLORY = crypto.KeyPair.generate()
ALICE_IP = ipaddress.IPv4Address("10.8.0.2")
BOB_IP = ipaddress.IPv4Address("10.8.0.3")
SERVER_ADDR = ("192.0.2.1", 51820)
PEERS = {ALICE.public: ALICE_IP, BOB.public: BOB_IP}


def ipv4_packet(src: str, dst: str, payload: bytes = b"hello") -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 17, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + payload


class Network:
    """Wires a Server and any number of Clients together through an in-memory queue."""

    def __init__(self):
        self.wire: list[tuple[bytes, tuple, tuple]] = []  # (data, src, dst)
        self.server_tun: list[bytes] = []
        self.server = Server(SERVER_KEY, ipaddress.IPv4Interface("10.8.0.1/24"), PEERS,
                             lambda d, a: self.wire.append((d, SERVER_ADDR, a)), self.server_tun.append)
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
            node = self.server if dst == SERVER_ADDR else self.clients[dst]
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


class ConfigTest(unittest.TestCase):
    def test_key_roundtrip(self):
        self.assertEqual(crypto.decode_key(crypto.encode_key(ALICE.public)), ALICE.public)
        with self.assertRaises(ValueError):
            crypto.decode_key("abcd")

    def test_load_peers(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(f"# comment\n{crypto.encode_key(ALICE.public)} 10.8.0.2\n\n")
        try:
            peers = load_peers(f.name, [f"{crypto.encode_key(BOB.public)}=10.8.0.3"])
        finally:
            os.unlink(f.name)
        self.assertEqual(peers, PEERS)

    def test_server_rejects_bad_peer_config(self):
        iface = ipaddress.IPv4Interface("10.8.0.1/24")
        for peers in ({ALICE.public: ipaddress.IPv4Address("10.9.0.2")},
                      {ALICE.public: ipaddress.IPv4Address("10.8.0.1")},
                      {ALICE.public: ALICE_IP, BOB.public: ALICE_IP}):
            with self.assertRaises(ValueError):
                Server(SERVER_KEY, iface, peers, lambda d, a: None, lambda p: None)


if __name__ == "__main__":
    unittest.main()
