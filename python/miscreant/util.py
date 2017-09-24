"""util.py: Utility functions"""

import sys
from struct import (pack, unpack)

# Lookup table for the number of trailing zeroes in a byte
CTZ_TABLE = [
    8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
]

def ct_select(subject, result_if_one, result_if_zero):
    """Perform a constant time(-ish) branch operation"""
    return (~(subject - 1) & result_if_one) | ((subject - 1) & result_if_zero)


def ctz(value):
    """Count the number of trailing zeros in a given 8-bit integer"""
    return CTZ_TABLE[value]


def dbl(value):
    """Perform a doubling operation as described in the CMAC and SIV papers"""
    overflow = 0
    words = unpack(b"!LLLL", value)
    output_words = []

    for word in reversed(words):
        new_word = (word << 1) & 0xFFFFFFFF
        new_word |= overflow
        overflow = int((word & 0x80000000) >= 0x80000000)
        output_words.append(new_word)

    result = bytearray(pack(b"!LLLL", *reversed(output_words)))
    result[-1] ^= ct_select(overflow, 0x87, 0)

    return bytes(result)


def xor(a, b):
    """Perform an xor on arbitrary bytestrings"""
    length = min(len(a), len(b))
    output = bytearray(length)

    if sys.version_info >= (3, 0):
        for i in range(length):
            output[i] = a[i] ^ b[i]
    else:
        for i in range(length):
            output[i] = ord(a[i]) ^ ord(b[i])

    return bytes(output)


def xorend(a, b):
    """XOR the second value into the end of the first"""
    difference = len(a) - len(b)

    left = a[:difference]
    right = a[difference:]

    return left + xor(right, b)


def pad(value, length):
    """Pad a value up to the given length"""
    difference = length - len(value) - 1
    return value + b"\x80" + (b"\0" * difference)


def zero_iv_bits(iv):
    """Zero out the top bits in the last 32-bit words of the IV"""
    # "We zero-out the top bit in each of the last two 32-bit words
    # of the IV before assigning it to Ctr"
    # -- http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    iv = bytearray(iv)
    iv[8] = iv[8] & 0x7f
    iv[12] = iv[12] & 0x7f
    return bytes(iv)
