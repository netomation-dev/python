#!/usr/bin/env python3

"""ipv6.py - A dedicated module for handling IPv6 prefixes
"""

from socket import inet_pton, inet_ntop, AF_INET6
from struct import pack

class Prefix:
    """A class for handling IPv6 prefixes
    """
    def parse(self, prefix):
        """Parse and check the IPv6 prefix for correctness
        """
        try:
            self.host_mask, self.cidr_mask = prefix.split('/')
        except (ValueError, OSError):
            return False

        try:
            self.p_hmask = inet_pton(AF_INET6, self.host_mask)
        except (ValueError, OSError):
            return False

        try:
            self.cidr_mask = (0xffffffffffffffffffffffffffffffff << 128 - int(self.cidr_mask)) & 0xffffffffffffffffffffffffffffffff
        except (ValueError, OSError):
            return False

    def to_bytes(self, i, padding=0):
        """Converts a integer to bytes in network order
        """
        nmask = []
        p_nmask = bytes()

        while i:
            nmask.append(chr(i & 0xff))
            i >>= 8

        if padding:
            for _ in range(16 - len(nmask)):
                nmask.append('\x00')

        while nmask:
            p_nmask += pack('!B', ord(nmask.pop()))

        return p_nmask

    def from_bytes(self, s):
        """Reproduce the integer from bytes
        """
        ret = 0
        for c in s:
            ret = (ret << 8) | c

        return ret

    def network_lower(self):
        """Prints the IPv6 network address
        """
        ret = self.from_bytes(self.p_hmask) & self.cidr_mask
        network_lower = inet_ntop(AF_INET6, self.to_bytes(ret))

        return network_lower

    def network_mask(self):
        """Prints the IPv6 network mask
        """
        network_mask = inet_ntop(AF_INET6, self.to_bytes(self.cidr_mask))

        return network_mask

    def wildcard_mask(self):
        """Prints the IPv6 wildcard mask
        """
        ret = 0xffffffffffffffffffffffffffffffff ^ self.cidr_mask
        wildcard_mask = inet_ntop(AF_INET6, self.to_bytes(ret, 1))

        return wildcard_mask

    def network_upper(self):
        """Prints the last IPv6 address
        """
        ret = self.from_bytes(self.p_hmask) | self.from_bytes(inet_pton(AF_INET6, self.wildcard_mask()))
        network_upper = inet_ntop(AF_INET6, self.to_bytes(ret))

        return network_upper

    def print_range(self):
        """Prints out the whole IPv6 prefix range
        """
        self.lower = self.from_bytes(self.p_hmask) & self.cidr_mask
        self.upper = self.from_bytes(self.p_hmask) | self.from_bytes(inet_pton(AF_INET6, self.wildcard_mask()))

        while self.lower < self.upper + 1:
            yield inet_ntop(AF_INET6, self.to_bytes(self.lower))
            self.lower += 1
