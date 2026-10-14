# vibe-vpn

A small point-to-point VPN in Python for learning purposes, modeled loosely on WireGuard.
It carries IPv4 packets from a Linux TUN device inside encrypted UDP datagrams.

## How it works

- **Identity:** every node has its own X25519 key pair. The server has a list of allowed client public keys, each pinned to one tunnel IP. Each client is configured with the server's public key.
- **Handshake:** the handshake follows the [Noise](https://noiseprotocol.org/) `IK` pattern, the one WireGuard uses:
  - `INIT` carries the client's ephemeral key. It also carries the client's static key and a timestamp, both encrypted to the server's static key.
  - `RESPONSE` carries the server's ephemeral key and an authentication tag.
  - Keys come from four Diffie-Hellman results (`es`, `ss`, `ee`, `se`), so only the real client and server can finish a handshake.
  - Fresh ephemeral keys give forward secrecy, and the client's identity is never sent in the clear.
- **Data:** ChaCha20-Poly1305 with one key per direction. The header (type, receiver index, 64-bit counter) is authenticated as associated data.
  A 2048-packet sliding window rejects replayed packets.
- **Hardening:**
  - Replayed `INIT`s are rejected, using a ±60s clock-skew window plus a per-peer timestamp that only moves forward.
  - The server drops packets whose inner source IP isn't the sender's assigned tunnel IP, so a client can't pose as another client.
  - Clients rekey every 10 minutes and send a keepalive every 25s. Idle sessions expire after 3 minutes.
  - Clients can roam to a new address: the server follows the last authenticated source address.
- **Handshake-flood (DoS) protection:** this follows WireGuard's cookie mechanism (`vpn/dos.py`).
  - **mac1:** every `INIT` carries a MAC keyed by the server's public key. Junk and packets aimed at the wrong server are dropped without any Diffie-Hellman work.
  - **Cookies:** when the server sees more than `--load-threshold` handshakes per second (default 50), it stops doing handshakes for `INIT`s without a valid mac2. Instead it sends a small encrypted `COOKIE` reply.
    - The cookie is a MAC of the sender's IP:port under a secret that rotates every 2 minutes.
    - The client stores it, and its next retry carries a mac2 keyed with it. That proves it can receive packets at the address it sent from, so spoofed-source floods are filtered out.
    - Cookie replies are smaller than `INIT`s, so they can't be used to amplify traffic.
    - Cookie replies are bound to the `INIT`'s mac1, so off-path attackers can't inject fake ones.
  - **Rate limit:** while under load, handshakes that do carry a valid cookie are also limited to 5/s per source IP, with bursts of up to 10.

Code layout: `vpn/crypto.py` (primitives), `vpn/protocol.py` (wire format, sessions, replay window),
`vpn/dos.py` (cookies, load detection, rate limiting), `vpn/node.py` (server/client state machines, socket-free), `vpn/tun.py`, `vpn/__main__.py` (CLI + event loop).

## Usage

Requires Linux, root (or `CAP_NET_ADMIN`), `iproute2`, and `pip install -r requirements.txt`.

```sh
# on every machine: create a private key and print its public key
python3 -m vpn genkey > node.key && chmod 600 node.key
python3 -m vpn pubkey < node.key

# server: list each client's public key and the tunnel IP it may use
cat > peers.txt <<'PEERS'
# <client public key>                          <tunnel ip>
u7REOW0IHzYjAk3+kaghy8nj9ZmEjd7R0GeuRy2kfnQ=   10.8.0.2
PEERS
sudo python3 -m vpn server --private-key-file node.key --address 10.8.0.1/24 --peers-file peers.txt
#   (or pass peers inline: --peer <key>=10.8.0.2 --peer <key>=10.8.0.3)

# client: use the IP the server assigned to this key
sudo python3 -m vpn client --private-key-file node.key --address 10.8.0.2/24 \
    --server vpn.example.com:51820 --server-public-key <server public key>

ping 10.8.0.1
```

Only public keys ever leave a machine. To revoke a client, remove its line from the peers file and restart the server.

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

- **IPv4 only, one address per peer.** Peer config is static: changing it needs a server restart.
- **Single-threaded event loop.** The DoS defences cap the expensive work, but a large enough
  raw packet flood can still saturate the loop. Put a firewall in front of anything exposed.
- **Python throughput.** Speed is limited by Python itself. Don't expect line-rate performance.
- **Unaudited.** Use WireGuard for anything real.
