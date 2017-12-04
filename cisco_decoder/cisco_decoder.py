#!/usr/bin/env python3

__author__ = "Michiel Kranenburg"
__email__ = "michiel@kranenburg.io"

import sys

if __name__ == '__main__':
    constant = 'tfd;kfoA,.iyewrkldJKD'

    try:
        hash = sys.argv[1]
        hash = [hash[i:i+2] for i in range(0, len(hash), 2)]
        index = int(hash.pop(0))
    except:
        print("No valid input specified. Expecting a type 7 encoded Cisco hash.\n")
        sys.exit(1)

    def decode(x):
        global index
        x = chr(int(x, 16) ^ ord(constant[index-1]))
        index += 1
        return x

    print(''.join(list(map(decode, hash))))
