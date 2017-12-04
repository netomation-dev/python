#!/usr/bin/env python3

"""checksum.py - Computing the Internet Checksum (RFC 1071)
"""

def checksum(dgram):
    """Expects a packed dgram and returns the 16-bit checksum.
    """ 
    calc = 0
    length = len(dgram)

    if length >= 2 and length <= 65534:
        for x in range(0, length, 2): 
            calc += (dgram[x] << 8) + dgram[x+1]
    else:
        return False

    calc += calc >> 16
    sum = ~ calc & 0xffff

    return sum
