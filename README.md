# vibe-vpn

A small point-to-point VPN in Python for learning purposes, modeled loosely on WireGuard.
It carries IPv4 packets from a Linux TUN device inside encrypted UDP datagrams.

## How it works

- **Handshake:** the client sends `INIT` with an ephemeral X25519 public key, a timestamp and its tunnel IP.
  The server replies with `RESPONSE` and its own ephemeral key. An HMAC keyed from the
  **pre-shared key (PSK)** authenticates both messages, and the response is bound to the init it answers.
- **Keys:** `HKDF-SHA256(salt=PSK, ikm=X25519 shared secret)` produces one key per direction.
  Fresh ephemeral keys on every handshake give forward secrecy.
- **Data:** ChaCha20-Poly1305. The header (type, receiver index, 64-bit counter) is authenticated as associated data.
  A 2048-packet sliding window rejects replayed packets.
- **Hardening:**
  - Replayed or stale `INIT`s are rejected, using a ±60s clock-skew window plus a per-IP timestamp that only moves forward.
  - The server drops packets whose inner source IP doesn't match the sender's tunnel IP.
  - Clients rekey every 10 minutes and send a keepalive every 25s. Idle sessions expire after 3 minutes.
  - Clients can roam to a new address: the server follows the last authenticated source address.

Code layout: `vpn/crypto.py` (primitives), `vpn/protocol.py` (wire format, sessions, replay window),
`vpn/node.py` (server/client state machines, socket-free), `vpn/tun.py`, `vpn/__main__.py` (CLI + event loop).

## Usage

Requires Linux, root (or `CAP_NET_ADMIN`), `iproute2`, and `pip install -r requirements.txt`.

```sh
python3 -m vpn genkey > vpn.psk          # copy this file securely to both machines

# server
sudo python3 -m vpn server --psk-file vpn.psk --address 10.8.0.1/24 --listen 0.0.0.0:51820

# client (each client needs a unique address in the subnet)
sudo python3 -m vpn client --psk-file vpn.psk --address 10.8.0.2/24 --server vpn.example.com:51820

ping 10.8.0.1
```

To send *all* client traffic through the server, enable forwarding and NAT on the server:

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
```

On the client, add a host route to the server via your normal gateway. Then route `0.0.0.0/1` and `128.0.0.0/1` through the TUN device.

## Tests

```sh
python3 -m unittest -v
```

The tests run the full client/server protocol through in-memory transports, so they need no root.

## Limitations (it's a learning project)

- **Shared-key authentication only.** Anyone holding the PSK can act as any client.
  Real deployments should use per-peer static keys (as in WireGuard's Noise IK).
- **IPv4 only.** The server does no handshake rate limiting or cookie-based DoS protection.
- **Python throughput.** Speed is limited by Python itself. Don't expect line-rate performance.
- **Unaudited.** Use WireGuard for anything real.
