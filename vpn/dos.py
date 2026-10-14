"""Handshake flood protection, modeled on WireGuard's cookie mechanism.

Normally every INIT with a valid mac1 is processed. Once the server sees more
than `load_threshold` INITs in a second it considers itself under load, and
until the flood subsides:

* An INIT without a valid mac2 gets a cheap COOKIE reply instead of the two DH
  operations a real handshake costs. The cookie is a MAC of the sender's
  IP:port under a secret that rotates every two minutes, so it is only useful
  to someone who can actually receive packets at that address.
* INITs that do carry a valid mac2 are rate-limited per source IP.

Cookie replies are smaller than the INITs that trigger them, so they can't be
used for amplification, and are encrypted to the INIT's mac1 so an off-path
attacker can't inject fake cookies.
"""

import ipaddress
import os
import time
from collections import deque
from typing import Callable

from . import protocol

COOKIE_SECRET_LIFETIME = 120.0
# Clients stop using a cookie a little before the server rotates its secret.
COOKIE_LIFETIME = COOKIE_SECRET_LIFETIME - 5.0
UNDER_LOAD_HOLD = 1.0
DEFAULT_LOAD_THRESHOLD = 50
PER_IP_RATE = 5.0
PER_IP_BURST = 10.0

Clock = Callable[[], float]


def _addr_bytes(addr: tuple[str, int]) -> bytes:
    return ipaddress.ip_address(addr[0]).packed + addr[1].to_bytes(2, "big")


class CookieChecker:
    """Server side: verifies mac1/mac2 and issues cookies."""

    def __init__(self, static_public: bytes) -> None:
        self._mac1_key = protocol.mac1_key(static_public)
        self._cookie_key = protocol.cookie_key(static_public)
        self._secret = os.urandom(32)
        self._secret_born = float("-inf")

    def _current_secret(self, now: float) -> bytes:
        if now - self._secret_born >= COOKIE_SECRET_LIFETIME:
            self._secret, self._secret_born = os.urandom(32), now
        return self._secret

    def cookie_for(self, addr: tuple[str, int], now: float) -> bytes:
        return protocol.mac(self._current_secret(now), _addr_bytes(addr))

    def check_mac1(self, packet: bytes) -> bool:
        return protocol.verify_mac1(self._mac1_key, packet)

    def check_mac2(self, packet: bytes, addr: tuple[str, int], now: float) -> bool:
        return protocol.verify_mac2(self.cookie_for(addr, now), packet)

    def reply(self, packet: bytes, addr: tuple[str, int], now: float) -> bytes:
        return protocol.seal_cookie(self._cookie_key, packet, self.cookie_for(addr, now))


class LoadMonitor:
    """Counts handshakes over a one-second sliding window."""

    def __init__(self, threshold: int = DEFAULT_LOAD_THRESHOLD) -> None:
        self.threshold = threshold
        self._recent: deque[float] = deque()
        self._last_overload = float("-inf")

    def record(self, now: float) -> bool:
        """Record one handshake attempt; return whether the server is under load."""
        self._recent.append(now)
        while self._recent and now - self._recent[0] > 1.0:
            self._recent.popleft()
        if len(self._recent) > self.threshold:
            self._last_overload = now
        return now - self._last_overload < UNDER_LOAD_HOLD


class RateLimiter:
    """Per-IP token bucket."""

    def __init__(self, rate: float = PER_IP_RATE, burst: float = PER_IP_BURST) -> None:
        self.rate, self.burst = rate, burst
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last update)

    def allow(self, ip: str, now: float) -> bool:
        tokens, last = self._buckets.get(ip, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        allowed = tokens >= 1.0
        self._buckets[ip] = (tokens - 1.0 if allowed else tokens, now)
        return allowed

    def prune(self, now: float) -> None:
        """Forget IPs whose bucket has refilled completely."""
        full_after = self.burst / self.rate
        for ip, (_, last) in list(self._buckets.items()):
            if now - last > full_after:
                del self._buckets[ip]


class CookieJar:
    """Client side: remembers the most recent cookie from the server."""

    def __init__(self, clock: Clock = time.monotonic) -> None:
        self.clock = clock
        self._cookie: bytes | None = None
        self._received = float("-inf")

    def store(self, cookie: bytes) -> None:
        self._cookie, self._received = cookie, self.clock()

    def current(self) -> bytes | None:
        if self._cookie is not None and self.clock() - self._received < COOKIE_LIFETIME:
            return self._cookie
        return None
