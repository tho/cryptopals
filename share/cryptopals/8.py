#!/usr/bin/env python3
"""
Set 1 Challenge 8 - Detect AES in ECB mode.

Quick and dirty script to verify result of 8-detect-aes-in-ecb-mode.c.
https://cryptopals.com/sets/1/challenges/8
"""

import binascii
import collections

AES_BLOCK_SIZE = 16

with open('./8.txt', 'r') as f:
    for nl, line in enumerate(f, 1):
        data = binascii.unhexlify(line.rstrip('\n'))
        blocks = [data[i:i+AES_BLOCK_SIZE]
                  for i in range(0, len(data), AES_BLOCK_SIZE)]
        blocks = [k for k, v in collections.Counter(blocks).items() if v > 1]
        if blocks:
            print('{0:3}: {1}'.format(nl, list(map(binascii.hexlify, blocks))))
