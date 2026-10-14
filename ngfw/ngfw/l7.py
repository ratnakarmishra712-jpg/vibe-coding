"""
l7.py — Layer-7 application identification (the "next-gen" part).

A classic firewall stops at ports: "443 = allow". But 443 could be your bank or a
tracker. An NGFW looks *inside* the first packets of a flow to learn the
application and the destination host, so policy can say "block *.doubleclick.net"
regardless of port.

`identify(pkt)` returns a dict like {'app': 'tls', 'host': 'example.com'} (or {}).
It inspects only what's cheaply and safely parseable from the payload:
  * TLS ClientHello  -> Server Name Indication (SNI)   -> the domain, unencrypted
  * HTTP request     -> the Host: header
  * DNS query        -> the queried name

We also expose tiny builders (build_client_hello / build_http_get /
build_dns_query) so the simulator and tests can produce realistic bytes without
pulling in a TLS stack.

Everything here parses UNTRUSTED input, so every parser is defensive: it returns
None on anything malformed rather than raising.
"""
from __future__ import annotations

import struct

from .packet import Packet, Proto


# --------------------------------------------------------------------------- #
#  Parsers
# --------------------------------------------------------------------------- #
def parse_tls_sni(data: bytes) -> str | None:
    """Extract the SNI host from a TLS ClientHello record, or None."""
    try:
        # TLS record header: type(1)=0x16 handshake, version(2), length(2)
        if len(data) < 5 or data[0] != 0x16:
            return None
        pos = 5
        # Handshake header: type(1)=0x01 ClientHello, length(3)
        if data[pos] != 0x01:
            return None
        pos += 4
        pos += 2          # client_version
        pos += 32         # random
        # session_id
        sid_len = data[pos]; pos += 1 + sid_len
        # cipher_suites
        cs_len = struct.unpack("!H", data[pos:pos + 2])[0]; pos += 2 + cs_len
        # compression_methods
        comp_len = data[pos]; pos += 1 + comp_len
        # extensions
        pos += 2          # extensions total length
        while pos + 4 <= len(data):
            ext_type, ext_len = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000:       # server_name extension
                # server_name_list length(2), name_type(1)=0, name_len(2), name
                p = pos + 2 + 1
                name_len = struct.unpack("!H", data[p:p + 2])[0]
                p += 2
                # SNI is transmitted as ASCII (punycode for IDNs), so decode ascii.
                return data[p:p + name_len].decode("ascii", "ignore") or None
            pos += ext_len
        return None
    except (IndexError, struct.error, UnicodeError):
        return None


def parse_http_host(data: bytes) -> str | None:
    """Return the Host header of an HTTP/1.x request, or None."""
    try:
        if not data[:8].split(b" ", 1)[0] in (
            b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT"
        ):
            return None
        for line in data.split(b"\r\n")[1:]:
            if line == b"":
                break
            if line[:5].lower() == b"host:":
                return line[5:].strip().decode("ascii", "ignore").split(":")[0] or None
        return None
    except (IndexError, UnicodeError):
        return None


def parse_dns_qname(data: bytes) -> str | None:
    """Return the queried name from a DNS query, or None."""
    try:
        if len(data) < 12:
            return None
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount < 1:
            return None
        pos = 12
        labels = []
        while True:
            n = data[pos]; pos += 1
            if n == 0:
                break
            labels.append(data[pos:pos + n].decode("ascii", "ignore"))
            pos += n
            if len(labels) > 127:
                return None
        return ".".join(labels) or None
    except (IndexError, UnicodeError):
        return None


def identify(pkt: Packet) -> dict:
    """Best-effort app-ID from a packet's payload. Returns {} if nothing found."""
    data = pkt.payload
    if not data:
        return {}

    if pkt.proto == Proto.TCP:
        sni = parse_tls_sni(data)
        if sni:
            return {"app": "tls", "host": sni}
        host = parse_http_host(data)
        if host:
            return {"app": "http", "host": host}
    elif pkt.proto == Proto.UDP and (pkt.dst_port == 53 or pkt.src_port == 53):
        name = parse_dns_qname(data)
        if name:
            return {"app": "dns", "host": name}
    return {}


# --------------------------------------------------------------------------- #
#  Builders (for the simulator and tests — realistic bytes, no TLS stack)
# --------------------------------------------------------------------------- #
def build_client_hello(sni: str) -> bytes:
    """Minimal but structurally valid TLS ClientHello carrying one SNI."""
    host = sni.encode("idna")
    server_name = b"\x00" + struct.pack("!H", len(host)) + host          # type host_name + name
    sn_list = struct.pack("!H", len(server_name)) + server_name
    ext = struct.pack("!HH", 0x0000, len(sn_list)) + sn_list             # server_name extension
    body = (
        b"\x03\x03"                      # client_version TLS 1.2
        + b"\x00" * 32                   # random
        + b"\x00"                        # session_id length 0
        + struct.pack("!H", 2) + b"\x00\x2f"   # cipher suites (1 suite)
        + b"\x01\x00"                    # compression methods (1 = null)
        + struct.pack("!H", len(ext)) + ext    # extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body        # ClientHello + 3-byte len
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def build_http_get(host: str, path: str = "/") -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ngfw-demo\r\n\r\n").encode()


def build_dns_query(name: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)          # 1 question
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + q + struct.pack("!HH", 1, 1)                          # QTYPE=A QCLASS=IN
