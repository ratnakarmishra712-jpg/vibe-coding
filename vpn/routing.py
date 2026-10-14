"""Longest-prefix-match routing table for IPv4 and IPv6 networks."""

import ipaddress
from typing import Generic, TypeVar

T = TypeVar("T")
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class RoutingTable(Generic[T]):
    """Maps networks to values. Lookups return the value of the most specific matching network.

    One hash table per (version, prefix length); a lookup masks the address at each
    prefix length in use, longest first. That's at most 33 (IPv4) or 129 (IPv6)
    dictionary probes, and far fewer in practice since only used lengths are tried.
    """

    def __init__(self) -> None:
        self._tables: dict[int, dict[int, dict[int, T]]] = {4: {}, 6: {}}  # version -> prefixlen -> net -> value
        self._order: dict[int, list[int]] = {4: [], 6: []}

    def insert(self, network: IPNetwork, value: T) -> None:
        by_len = self._tables[network.version]
        if network.prefixlen not in by_len:
            by_len[network.prefixlen] = {}
            self._order[network.version] = sorted(by_len, reverse=True)
        by_len[network.prefixlen][int(network.network_address)] = value

    def lookup(self, address: IPAddress | None) -> T | None:
        if address is None:
            return None
        bits = address.max_prefixlen
        value = int(address)
        by_len = self._tables[address.version]
        for prefixlen in self._order[address.version]:
            mask = ((1 << prefixlen) - 1) << (bits - prefixlen) if prefixlen else 0
            hit = by_len[prefixlen].get(value & mask)
            if hit is not None:
                return hit
        return None
