# vibe-vpn

A small point-to-point VPN in Python for learning purposes, modeled loosely on WireGuard.
It carries IPv4 and IPv6 packets from a Linux TUN device inside encrypted UDP datagrams,
and the UDP transport itself can run over IPv4 or IPv6.

## How it works

- **Identity:** every node has its own X25519 key pair. The server has a list of allowed client public keys. Each key is pinned to its "allowed IPs": its tunnel addresses (one IPv4, one IPv6, or both) plus any subnets routed through it. Each client is configured with the server's public key.
- **Handshake:** the handshake follows the [Noise](https://noiseprotocol.org/) `IK` pattern, the one WireGuard uses:
  - `INIT` carries the client's ephemeral key. It also carries the client's static key and a timestamp, both encrypted to the server's static key.
  - `RESPONSE` carries the server's ephemeral key and an authentication tag.
  - Keys come from four Diffie-Hellman results (`es`, `ss`, `ee`, `se`), so only the real client and server can finish a handshake.
  - Fresh ephemeral keys give forward secrecy, and the client's identity is never sent in the clear.
- **Data:** ChaCha20-Poly1305 with one key per direction. The header (type, receiver index, 64-bit counter) is authenticated as associated data.
  A 2048-packet sliding window rejects replayed packets.
- **Hardening:**
  - Replayed `INIT`s are rejected, using a ±60s clock-skew window plus a per-peer timestamp that only moves forward.
  - The server drops packets whose inner source IP isn't within the sender's allowed IPs, so a client can't pose as another client or another site.
  - Clients rekey every 10 minutes and send a keepalive every 25s. Idle sessions expire after 3 minutes.
  - Clients can roam to a new address: the server follows the last authenticated source address.
- **IPv6:**
  - Inside the tunnel, the server routes each packet to a peer by its IPv4 or IPv6 destination.
  - On the transport side, the server listens on `[::]` by default, accepting both IPv6 and IPv4 (as v4-mapped addresses). It falls back to `0.0.0.0` on hosts without IPv6.
  - Clients resolve the server name and use whichever family it returns first. Pass `-4` or `-6` to force one.
  - The handshake carries no tunnel addresses, so the wire format is the same for both families.
- **Routing:** the server keeps a longest-prefix-match table of all peers' allowed IPs (`vpn/routing.py`). It's used both to pick the peer for an outgoing packet and to check incoming sources. Allowed IPs may not overlap between peers, so every address belongs to exactly one peer.
- **Handshake-flood (DoS) protection:** this follows WireGuard's cookie mechanism (`vpn/dos.py`).
  - **mac1:** every `INIT` carries a MAC keyed by the server's public key. Junk and packets aimed at the wrong server are dropped without any Diffie-Hellman work.
  - **Cookies:** when the server sees more than `--load-threshold` handshakes per second (default 50), it stops doing handshakes for `INIT`s without a valid mac2. Instead it sends a small encrypted `COOKIE` reply.
    - The cookie is a MAC of the sender's IP:port under a secret that rotates every 2 minutes.
    - The client stores it, and its next retry carries a mac2 keyed with it. That proves it can receive packets at the address it sent from, so spoofed-source floods are filtered out.
    - Cookie replies are smaller than `INIT`s, so they can't be used to amplify traffic.
    - Cookie replies are bound to the `INIT`'s mac1, so off-path attackers can't inject fake ones.
  - **Rate limit:** while under load, handshakes that do carry a valid cookie are also limited to 5/s per source IP, with bursts of up to 10.

Code layout: `vpn/crypto.py` (primitives), `vpn/protocol.py` (wire format, sessions, replay window),
`vpn/dos.py` (cookies, load detection, rate limiting), `vpn/routing.py` (longest-prefix match), `vpn/node.py` (server/client state machines, socket-free), `vpn/tun.py`, `vpn/__main__.py` (CLI + event loop).

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

## Site-to-site

A client can act as the gateway for a whole network behind it, and LANs behind the server can be reached through the tunnel.
For example, to connect office A (`192.168.20.0/24`, behind client `gw-a`) with office B (`192.168.10.0/24`, behind the server):

```sh
# server (office B gateway): give the client its subnet as well as its tunnel address
#   peers.txt:  <gw-a public key>   10.8.0.2,192.168.20.0/24
sudo sysctl -w net.ipv4.ip_forward=1
sudo python3 -m vpn server --private-key-file node.key --address 10.8.0.1/24 --peers-file peers.txt
#   -> adds "192.168.20.0/24 dev vpn0" automatically

# client gw-a (office A gateway): route office B's subnet into the tunnel
sudo sysctl -w net.ipv4.ip_forward=1
sudo python3 -m vpn client --private-key-file node.key --address 10.8.0.2/24 \
    --route 192.168.10.0/24 --server vpn.example.com --server-public-key <server public key>
```

Hosts on each LAN need a route to the other LAN via their local VPN gateway. If the gateway is already their default router, nothing else is needed.
No NAT is involved, so hosts see each other's real addresses.
The rules for allowed IPs:
- Inside the tunnel subnet, a peer may only hold single host addresses.
- Outside it, a peer may hold any subnet, as long as it doesn't overlap the tunnel subnet or another peer's networks.
- A plain address outside the tunnel subnet is a single routed host (`/32` or `/128`).

IPv6 subnets work the same way, e.g. `2001:db8:20::/48` in the peers file and `--route 2001:db8:10::/48` on the client.

## Tests

```sh
python3 -m unittest -v
```

The tests run the full client/server protocol through in-memory transports, so they need no root.

## Limitations (it's a learning project)

- **Hub and spoke only.** Clients talk to the server, not directly to each other. Traffic between two client sites goes through the server, and their `--route`s must cover it.
  Peer config is static: changing it needs a server restart.
- **No full-tunnel peer on the server side.** A peer can't hold `0.0.0.0/0`, because that would overlap the tunnel subnet. Use the client-side `0.0.0.0/1` + `128.0.0.0/1` routes described above instead.
- **Single-threaded event loop.** The DoS defences cap the expensive work, but a large enough
  raw packet flood can still saturate the loop. Put a firewall in front of anything exposed.
- **Python throughput.** Speed is limited by Python itself. Don't expect line-rate performance.
- **Unaudited.** Use WireGuard for anything real.
