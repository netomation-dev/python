#!/usr/bin/env python3

"""icmpv4.py - Construct a packed ICMPv4 dgram (RFC 792)
"""

from struct import pack
from random import getrandbits
from .checksum import checksum

def pack_echo_dgram(id=0, seq=1, length=64):
    """Construct a packed ICMPv4 echo request with random bits
    inserted for ID when not specified. DATA is padded with 
    random bits up to LENGTH.
    """
    type, code, check = 8, 0, 0

    if id == 0: id = getrandbits(16)
    elif id > 0 and id <= 65535: id = int(id)
    else: id = 0

    data = bytes()

    while length != len(data):
        data += (pack('!B', (getrandbits(8))))

    if length % 2 == 1:
        data += (pack('!B', 0))

    construct = pack('!BBHHH', type, code, check, id, seq) + data
    check = checksum(construct)
    header = pack('!BBHHH', type, code, check, id, seq) + data

    return header
