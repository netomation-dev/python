#!/usr/bin/env python3

"""ipv4.py - Construct a packed IPv4 dgram (RFC 791)
"""

from struct import pack
from random import getrandbits
from socket import AF_INET, inet_pton

def pack_dgram(proto, src, dst, ihl=5, tos=0, flag=2, ttl=64):
    """Construct a packed IPv4 header
    """
    version, length, id, frag, options, check = 4, 0, 0, 0, 0, 0

    try:
        src = inet_pton(AF_INET, src)
        dst = inet_pton(AF_INET, dst)
    except:
        return False

    if id == 0: id = getrandbits(16)
    elif id > 0 and id <= 65535: id = int(id)
    else: id = 0

    construct = pack('!BBHHHBBH', (version << 4 | ihl), tos, length,
                                    id, (flag << 13 | frag),
                                    ttl, proto, check)

    header = construct + src + dst

    return header
