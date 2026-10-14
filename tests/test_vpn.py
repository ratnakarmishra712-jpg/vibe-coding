import ipaddress
import struct
import unittest

from vpn import crypto, protocol
from vpn.node import SESSION_TIMEOUT, Client, Server

PSK = bytes(range(32))
SERVER_ADDR = ("192.0.2.1", 51820)
CLIENT_ADDR = ("198.51.100.7", 40000)


def ipv4_packet(src: str, dst: str, payload: bytes = b"hello") -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 17, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + payload


class Harness:
    """Wires a Server and Client together through in-memory queues."""

    def __init__(self, client_ip="10.8.0.2", client_psk=PSK):
        self.wire: list[tuple[bytes, tuple, tuple]] = []  # (data, src, dst)
        self.server_tun: list[bytes] = []
        self.client_tun: list[bytes] = []
        self.server = Server(PSK, ipaddress.IPv4Interface("10.8.0.1/24"),
                             lambda d, a: self.wire.append((d, SERVER_ADDR, a)), self.server_tun.append)
        self.client = Client(client_psk, ipaddress.IPv4Address(client_ip), SERVER_ADDR,
                             lambda d, a: self.wire.append((d, CLIENT_ADDR, a)), self.client_tun.append)

    def deliver(self):
        delivered = []
        while self.wire:
            data, src, dst = self.wire.pop(0)
            delivered.append(data)
            node = self.server if dst == SERVER_ADDR else self.client
            node.handle_datagram(data, src)
        return delivered

    def connect(self):
        self.client.start_handshake()
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
    def test_keys_match(self):
        pending = protocol.create_init(PSK, ipaddress.IPv4Address("10.8.0.2"))
        info = protocol.parse_init(PSK, pending.packet)
        resp, server_session = protocol.respond(PSK, info)
        client_session = protocol.complete(PSK, pending, resp)
        self.assertEqual(server_session.open(client_session.seal(b"ping")), b"ping")
        self.assertEqual(client_session.open(server_session.seal(b"pong")), b"pong")

    def test_wrong_psk_rejected(self):
        pending = protocol.create_init(bytes(32), ipaddress.IPv4Address("10.8.0.2"))
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_init(PSK, pending.packet)

    def test_stale_timestamp_rejected(self):
        pending = protocol.create_init(PSK, ipaddress.IPv4Address("10.8.0.2"), now_ns=0)
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_init(PSK, pending.packet)

    def test_tampered_data_rejected(self):
        pending = protocol.create_init(PSK, ipaddress.IPv4Address("10.8.0.2"))
        resp, server_session = protocol.respond(PSK, protocol.parse_init(PSK, pending.packet))
        client_session = protocol.complete(PSK, pending, resp)
        pkt = bytearray(client_session.seal(b"secret"))
        pkt[-1] ^= 1
        with self.assertRaises(protocol.ProtocolError):
            server_session.open(bytes(pkt))


class EndToEndTest(unittest.TestCase):
    def test_traffic_flows_both_ways(self):
        h = Harness()
        h.connect()
        self.assertTrue(h.client.connected)

        out = ipv4_packet("10.8.0.2", "10.8.0.1")
        h.client.handle_tun(out)
        h.deliver()
        self.assertEqual(h.server_tun, [out])

        back = ipv4_packet("10.8.0.1", "10.8.0.2", b"world")
        h.server.handle_tun(back)
        h.deliver()
        self.assertEqual(h.client_tun, [back])

    def test_replayed_data_dropped(self):
        h = Harness()
        h.connect()
        h.client.handle_tun(ipv4_packet("10.8.0.2", "10.8.0.1"))
        [data] = h.deliver()
        h.server.handle_datagram(data, CLIENT_ADDR)
        self.assertEqual(len(h.server_tun), 1)

    def test_replayed_init_cannot_hijack(self):
        h = Harness()
        init, *_ = h.connect()
        attacker = ("203.0.113.66", 1234)
        h.server.handle_datagram(init, attacker)
        self.assertEqual(h.server.peers[ipaddress.IPv4Address("10.8.0.2")].addr, CLIENT_ADDR)

    def test_spoofed_inner_source_dropped(self):
        h = Harness()
        h.connect()
        h.client.handle_tun(ipv4_packet("10.8.0.99", "10.8.0.1"))
        h.deliver()
        self.assertEqual(h.server_tun, [])

    def test_wrong_psk_never_connects(self):
        h = Harness(client_psk=bytes(32))
        h.connect()
        self.assertFalse(h.client.connected)
        self.assertEqual(h.server.peers, {})

    def test_ip_outside_subnet_rejected(self):
        h = Harness(client_ip="10.9.0.2")
        h.connect()
        self.assertFalse(h.client.connected)

    def test_rekey_keeps_traffic_flowing(self):
        h = Harness()
        h.connect()
        first = h.client.session
        h.connect()
        self.assertIsNot(h.client.session, first)
        back = ipv4_packet("10.8.0.1", "10.8.0.2")
        h.server.handle_tun(back)
        h.deliver()
        self.assertEqual(h.client_tun, [back])

    def test_server_expires_idle_peer(self):
        h = Harness()
        h.connect()
        peer = h.server.peers[ipaddress.IPv4Address("10.8.0.2")]
        h.server.tick(now=peer.session.last_received + SESSION_TIMEOUT + 1)
        self.assertEqual(h.server.peers, {})
        self.assertEqual(h.server.by_index, {})


class CryptoTest(unittest.TestCase):
    def test_load_psk_validates_length(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("abcd\n")
        try:
            with self.assertRaises(ValueError):
                crypto.load_psk(f.name)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
