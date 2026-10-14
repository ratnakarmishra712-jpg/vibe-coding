"""Linux TUN device helpers."""

import fcntl
import os
import struct
import subprocess

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class Tun:
    def __init__(self, name: str = "vpn%d") -> None:
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
        result = fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        self.name = result[:16].rstrip(b"\x00").decode()
        os.set_blocking(self.fd, False)

    def configure(self, address: str, mtu: int) -> None:
        """Assign an address (CIDR) and bring the interface up. Requires CAP_NET_ADMIN."""
        subprocess.run(["ip", "addr", "add", address, "dev", self.name], check=True)
        subprocess.run(["ip", "link", "set", "dev", self.name, "mtu", str(mtu), "up"], check=True)

    def fileno(self) -> int:
        return self.fd

    def read(self, size: int = 65535) -> bytes:
        return os.read(self.fd, size)

    def write(self, packet: bytes) -> None:
        os.write(self.fd, packet)

    def close(self) -> None:
        os.close(self.fd)
