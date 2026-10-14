"""Linux TUN device helpers."""

import fcntl
import ipaddress
import os
import struct
import subprocess

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def _ip(*args: str) -> None:
    result = subprocess.run(["ip", *args], capture_output=True, text=True)
    if result.returncode != 0:
        hint = ""
        if any(":" in a for a in args):  # an IPv6 address
            hint = " (is IPv6 enabled on this host?)"
        raise RuntimeError(f"`ip {' '.join(args)}` failed: {result.stderr.strip()}{hint}")


class Tun:
    def __init__(self, name: str = "vpn%d") -> None:
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
        result = fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        self.name = result[:16].rstrip(b"\x00").decode()
        os.set_blocking(self.fd, False)

    def configure(self, addresses: list[ipaddress.IPv4Interface | ipaddress.IPv6Interface], mtu: int) -> None:
        """Assign addresses and bring the interface up. Requires CAP_NET_ADMIN."""
        # Set the MTU first: the kernel refuses IPv6 addresses on links with MTU < 1280.
        _ip("link", "set", "dev", self.name, "mtu", str(mtu))
        for address in addresses:
            # Skip duplicate address detection: nothing else is on a point-to-point TUN link,
            # and DAD would leave the address unusable ("tentative") for a second or so.
            extra = ["nodad"] if address.version == 6 else []
            _ip("addr", "add", str(address), "dev", self.name, *extra)
        _ip("link", "set", "dev", self.name, "up")

    def add_routes(self, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> None:
        """Route `networks` into the tunnel. Requires CAP_NET_ADMIN."""
        for net in networks:
            _ip("route", "add", str(net), "dev", self.name)

    def fileno(self) -> int:
        return self.fd

    def read(self, size: int = 65535) -> bytes:
        return os.read(self.fd, size)

    def write(self, packet: bytes) -> None:
        os.write(self.fd, packet)

    def close(self) -> None:
        os.close(self.fd)
