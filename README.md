# vibe-vpn

A small point-to-point VPN in Python for learning purposes, modeled loosely on WireGuard.
It carries IPv4 and IPv6 packets from a Linux TUN device inside encrypted UDP datagrams,
and the UDP transport itself can run over IPv4 or IPv6.

## How it works

- **Identity:** every node has its own X25519 key pair. The server has a list of allowed client public keys, each pinned to its own tunnel addresses (one IPv4, one IPv6, or both). Each client is configured with the server's public key.
- **Handshake:** the handshake follows the [Noise](https://noiseprotocol.org/) `IK` pattern, the one WireGuard uses:
  - `INIT` carries the client's ephemeral key. It also carries the client's static key and a timestamp, both encrypted to the server's static key.
  - `RESPONSE` carries the server's ephemeral key and an authentication tag.
  - Keys come from four Diffie-Hellman results (`es`, `ss`, `ee`, `se`), so only the real client and server can finish a handshake.
  - Fresh ephemeral keys give forward secrecy, and the client's identity is never sent in the clear.
- **Data:** ChaCha20-Poly1305 with one key per direction. The header (type, receiver index, 64-bit counter) is authenticated as associated data.
  A 2048-packet sliding window rejects replayed packets.
- **Hardening:**
  - Replayed `INIT`s are rejected, using a ±60s clock-skew window plus a per-peer timestamp that only moves forward.
  - The server drops packets whose inner source IP isn't one of the sender's assigned tunnel addresses, so a client can't pose as another client.
  - Clients rekey every 10 minutes and send a keepalive every 25s. Idle sessions expire after 3 minutes.
  - Clients can roam to a new address: the server follows the last authenticated source address.
- **IPv6:**
  - Inside the tunnel, the server routes each packet to a peer by its IPv4 or IPv6 destination.
  - On the transport side, the server listens on `[::]` by default, accepting both IPv6 and IPv4 (as v4-mapped addresses). It falls back to `0.0.0.0` on hosts without IPv6.
  - Clients resolve the server name and use whichever family it returns first. Pass `-4` or `-6` to force one.
  - The handshake carries no tunnel addresses, so the wire format is the same for both families.
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

# server: list each client's public key and the tunnel addresses it may use
cat > peers.txt <<'PEERS'
# <client public key>                          <tunnel ips, comma-separated>
u7REOW0IHzYjAk3+kaghy8nj9ZmEjd7R0GeuRy2kfnQ=   10.8.0.2,fd00:8::2
kmo6eGE/3MuJ7zqjRl95DD9VMgcf/f2K8MZWV77SzG0=   10.8.0.3
PEERS
sudo python3 -m vpn server --private-key-file node.key \
    --address 10.8.0.1/24 --address fd00:8::1/64 --peers-file peers.txt
#   (or pass peers inline: --peer <key>=10.8.0.2,fd00:8::2 --peer <key>=10.8.0.3)
#   (default listen is IPv6+IPv4 on port 51820; e.g. --listen 0.0.0.0:51820 for IPv4 only)

# client: use the addresses the server assigned to this key
sudo python3 -m vpn client --private-key-file node.key --address 10.8.0.2/24 --address fd00:8::2/64 \
    --server vpn.example.com:51820 --server-public-key <server public key>
#   (an IPv6 server address goes in brackets: --server [2001:db8::1]:51820)

ping 10.8.0.1
ping fd00:8::1
```

Only public keys ever leave a machine. To revoke a client, remove its line from the peers file and restart the server.

To send *all* client traffic through the server, enable forwarding and NAT on the server:

```sh
sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
iptables  -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -s fd00:8::/64 -o eth0 -j MASQUERADE
```

On the client, add a host route to the server via your normal gateway. Then route `0.0.0.0/1` and `128.0.0.0/1` through the TUN device. For IPv6, also route `::/1` and `8000::/1` through it.

## Tests

```sh
python3 -m unittest -v
```

The tests run the full client/server protocol through in-memory transports, so they need no root.

## Limitations (it's a learning project)

- **One address per IP family per peer.** Peers get host addresses only, not routed subnets, so there's no site-to-site setup.
  Peer config is static: changing it needs a server restart.
- **Single-threaded event loop.** The DoS defences cap the expensive work, but a large enough
  raw packet flood can still saturate the loop. Put a firewall in front of anything exposed.
- **Python throughput.** Speed is limited by Python itself. Don't expect line-rate performance.
- **Unaudited.** Use WireGuard for anything real.
